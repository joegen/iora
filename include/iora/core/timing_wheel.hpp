// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

namespace iora {
namespace core {

using TimerId = std::uint64_t;
inline constexpr TimerId InvalidTimerId = 0;

/// \brief Lifecycle state. Legal transitions (all serialized by _lifecycleMutex):
///   start(): CREATED->RUNNING, RESET->RUNNING (NO STOPPED->RUNNING edge — a
///            restart requires reset() first).
///   drain(): ->DRAINING->STOPPED.  stop(): ->STOPPED.  reset(): STOPPED->RESET.
/// stop() and drain() are IDEMPOTENT quiescers: they transition to STOPPED from
/// ANY source state (CREATED/RUNNING/STOPPED), which is intentional (a stop() on
/// a never-started or already-stopped wheel is a safe no-op-equivalent). reset()
/// and start() are the only guarded (CAS'd) transitions and reject other sources.
enum class TimingWheelState
{
  CREATED,
  RUNNING,
  DRAINING,
  STOPPED,
  RESET
};

struct DrainStats
{
  std::size_t fired = 0;
  std::size_t remaining = 0;
  std::size_t cancelled = 0;
  std::chrono::milliseconds elapsed{0};
};

/// \brief Abstract timer service interface.
class ITimerService
{
public:
  virtual ~ITimerService() = default;
  virtual TimerId schedule(std::chrono::milliseconds delay,
                           std::function<void()> callback) = 0;
  virtual bool cancel(TimerId id) = 0;
  virtual bool reschedule(TimerId id, std::chrono::milliseconds newDelay) = 0;

  /// \brief Tick granularity of the backing scheduler, or 0 if unknown.
  ///
  /// NON-PURE with a safe 0-sentinel default so the 30+ existing implementers
  /// (iora core, iora_sip production + test mocks, iora_media) keep compiling
  /// unchanged; a TimingWheel-backed adapter overrides it with the real tick.
  /// A returned value of 0 means "granularity unknown" — a consumer that needs
  /// to reason about the scheduler's floor MUST fail closed on 0 rather than
  /// divide by it.
  virtual std::chrono::milliseconds tickDuration() const noexcept
  {
    return std::chrono::milliseconds{0};
  }
};

/// \brief Hierarchical timing wheel for O(1) timer insert/cancel.
///
/// All entry mutations serialized under _wheelMutex. Callbacks fire
/// OUTSIDE the lock (collect-then-fire). Internal free-list for entry
/// pooling. Tick drift catch-up processes multiple ticks if behind.
/// Optional callback dispatcher for ThreadPool integration.
class TimingWheel
{
public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;
  using Callback = std::function<void()>;
  using ErrorCallback = std::function<void(TimerId, std::exception_ptr)>;
  using Dispatcher = std::function<void(Callback)>;

  /// \param tickDuration Time per tick (e.g., 10ms)
  /// \param ticksPerWheel Slots per wheel level (must be power of two)
  /// \param numWheels Number of wheel levels
  /// \param dispatcher Optional: if set, callbacks are dispatched via this
  ///                   (e.g., [&pool](auto cb) { pool.enqueue(std::move(cb)); })
  TimingWheel(std::chrono::milliseconds tickDuration,
              std::size_t ticksPerWheel,
              std::size_t numWheels,
              Dispatcher dispatcher = nullptr)
    : _tickDuration(tickDuration)
    , _ticksPerWheel(ticksPerWheel)
    , _tickMask(ticksPerWheel - 1)
    , _numWheels(numWheels)
    , _dispatcher(std::move(dispatcher))
    , _nextId{1}
    , _state{TimingWheelState::CREATED}
    , _accepting{false}
    , _running{false}
  {
    // ticksPerWheel must be a power of two AND >= 2: a single-slot wheel
    // (_tickMask == 0) collapses every bucket onto one slot, which defeats the
    // over-range furthest-bucket clamp (the forced slot would equal the current
    // bucket) and makes bucketing meaningless. No production config or test uses
    // a 1-slot wheel (SIP uses 64; tests use 4/16/32/64).
    assert(ticksPerWheel >= 2 && (ticksPerWheel & (ticksPerWheel - 1)) == 0);
    assert(numWheels > 0);
    // tickDuration must be positive: insertEntry()/advance() divide by it.
    assert(tickDuration.count() > 0);
    _wheels.resize(numWheels);
    for (auto& w : _wheels)
    {
      w.buckets.resize(ticksPerWheel);
      w.currentTick = 0;
    }
  }

  ~TimingWheel()
  {
    // Contract (tracker 2026-09-10-7 R6): NO lifecycle call may be in flight at
    // destruction (the standard C++ object-model rule — concurrent destruction +
    // any member call is UB regardless). The dtor therefore takes no
    // _lifecycleMutex; stopTickThread() is idempotent (joinable()-gated).
    stopTickThread(); // idempotent (joinable()-gated) — unconditional, like stop()/drain()
    auto toDestroy = collectAllEntries(); // destroyed at scope end, outside locks
    (void)toDestroy;
    drainFreeList();
  }

  TimingWheel(const TimingWheel&) = delete;
  TimingWheel& operator=(const TimingWheel&) = delete;
  TimingWheel(TimingWheel&&) = delete;
  TimingWheel& operator=(TimingWheel&&) = delete;

  /// \brief Time per tick, fixed at construction. Lock-free: _tickDuration is
  /// const-after-construction, so no _wheelMutex is taken (a scheduling-path
  /// consumer must not be coupled to the wheel lock to read the granularity).
  std::chrono::milliseconds tickDuration() const noexcept
  {
    return _tickDuration;
  }

  // ── Schedule / Cancel / Reschedule ─────────────────────────────────────

  TimerId schedule(std::chrono::milliseconds delay, Callback callback)
  {
    // Fast-path accept gate (lock-free). This acquire load pairs with the
    // _accepting.store(false, release) that drain()/stop() perform BEFORE they
    // acquire _wheelMutex — the store-before-lock ordering the re-check below
    // depends on (tracker 2026-09-10-6 R3). Do NOT weaken these to relaxed.
    if (!_accepting.load(std::memory_order_acquire))
    {
      return InvalidTimerId;
    }

    auto id = _nextId.fetch_add(1, std::memory_order_relaxed);
    auto deadline = Clock::now() + delay;

#ifdef IORA_TIMING_WHEEL_TEST_HOOKS
    // Test-only: pause a schedule() that has PASSED the fast-path gate but not
    // yet taken _wheelMutex, so a test can deterministically drive the
    // post-collection orphan window. Compiled out in production builds.
    if (_testScheduleGate)
    {
      _testScheduleGate();
    }
#endif

    std::lock_guard lock(_wheelMutex);
    // Re-check the accept gate UNDER _wheelMutex, BEFORE allocEntry (tracker
    // 2026-09-10-6). drain()/stop() flip _accepting=false before acquiring
    // _wheelMutex, so a schedule() that wins the lock only AFTER their
    // collection completed observes false here and inserts no orphan; one that
    // won the lock first is collected normally. A declined schedule allocates
    // nothing (the burned _nextId leaves a harmless monotonic gap).
    if (!_accepting.load(std::memory_order_acquire))
    {
      return InvalidTimerId;
    }
    auto* entry = allocEntry(); // alloc under _wheelMutex to prevent ABBA with _poolMutex
    entry->id = id;
    entry->callback = std::move(callback);
    entry->deadline = deadline;
    insertEntry(entry, delay);
    _entryMap[id] = entry;
    return id;
  }

  bool cancel(TimerId id)
  {
    std::lock_guard lock(_wheelMutex);
    auto it = _entryMap.find(id);
    if (it == _entryMap.end())
    {
      return false;
    }
    auto* entry = it->second;
    unlinkEntry(entry);
    _entryMap.erase(it);
    freeEntry(entry);
    return true;
  }

  bool reschedule(TimerId id, std::chrono::milliseconds newDelay)
  {
    std::lock_guard lock(_wheelMutex);
    auto it = _entryMap.find(id);
    if (it == _entryMap.end())
    {
      return false;
    }
    auto* entry = it->second;
    unlinkEntry(entry);
    entry->deadline = Clock::now() + newDelay;
    insertEntry(entry, newDelay);
    return true;
  }

  // ── Advance ────────────────────────────────────────────────────────────

  /// \brief Process expired timers. Handles tick drift by processing
  /// multiple ticks if behind. Returns number of callbacks fired.
  /// \note TEST-ONLY entry point. In production advance() is driven solely by
  /// the internal tick thread (startTickThread). It is memory-safe under
  /// concurrent invocation (serialized by _wheelMutex) but two concurrent calls
  /// logically double-advance the wheel (early/desynced firings); it must NOT be
  /// called while the tick thread is running (tracker 2026-09-10-7 T3/R8).
  std::size_t advance()
  {
#ifdef IORA_TIMING_WHEEL_TEST_HOOKS
    // Test-only observability: lets a test detect a live/zombie tick thread by
    // watching whether advance() keeps being called. Compiled out in production.
    _testAdvanceCount.fetch_add(1, std::memory_order_relaxed);
#endif
    auto now = Clock::now();
    std::vector<std::pair<TimerId, Callback>> toFire;

    {
      std::lock_guard lock(_wheelMutex);

      // Tick drift catch-up: compute how many ticks we should process
      std::size_t ticksToProcess = 1;
      if (_lastAdvanceTime != TimePoint{})
      {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          now - _lastAdvanceTime);
        auto elapsedTicks = elapsed.count() / _tickDuration.count();
        if (elapsedTicks > 1)
        {
          ticksToProcess = static_cast<std::size_t>(elapsedTicks);
        }
      }
      _lastAdvanceTime = now;

      // Not-yet-due entries encountered while collecting/cascading are staged
      // here and re-inserted AFTER the whole advance() pass (all tick iterations
      // + the full cascadeDown recursion). Re-inserting inline could place an
      // entry back into a bucket still being traversed -> re-process within one
      // pass -> hang under _wheelMutex. Scope is the whole advance() invocation
      // (the tick-drift loop shares one captured `now`); it is a LOCAL passed by
      // reference exactly like `toFire`, never a member.
      std::vector<TimerEntry*> deferred;

      for (std::size_t t = 0; t < ticksToProcess; ++t)
      {
        auto& level0 = _wheels[0];
        auto& bucket = level0.buckets[level0.currentTick & _tickMask];
        collectFromBucket(bucket, now, toFire, deferred);
        level0.currentTick++;

        if ((level0.currentTick & _tickMask) == 0)
        {
          cascadeDown(1, now, toFire, deferred);
        }
      }

      // Drain deferred re-insertions under _wheelMutex, before releasing. Parked
      // entries stayed in _entryMap (they are live timers) and were not freed;
      // insertEntry only re-links them. currentTick now corresponds to `now`, so
      // remaining = deadline - now places each entry at its true future bucket.
      for (auto* e : deferred)
      {
        auto remaining = std::max(std::chrono::milliseconds(0),
          std::chrono::duration_cast<std::chrono::milliseconds>(e->deadline - now));
        insertEntry(e, remaining);
      }
    }

    // Fire outside lock
    for (auto& [id, cb] : toFire)
    {
      fireCallback(id, std::move(cb));
    }

    return toFire.size();
  }

  // ── Lifecycle ──────────────────────────────────────────────────────────

  void start()
  {
    // Whole body under _lifecycleMutex (tracker 2026-09-10-7 R5): the _state CAS,
    // the _accepting/_lastAdvanceTime writes, AND startTickThread()'s _tickThread
    // assignment are serialized against every other lifecycle call, so no
    // concurrent stop()/drain() can leave a zombie tick thread or race the
    // std::thread object. Legal source states are CREATED and RESET only — there
    // is no STOPPED->RUNNING edge; a restart requires reset() first (R11).
    std::lock_guard lifecycle(_lifecycleMutex);
    auto expected = TimingWheelState::CREATED;
    if (!_state.compare_exchange_strong(expected, TimingWheelState::RUNNING))
    {
      expected = TimingWheelState::RESET;
      if (!_state.compare_exchange_strong(expected, TimingWheelState::RUNNING))
      {
        return;
      }
    }
    _accepting.store(true, std::memory_order_release);
    {
      std::lock_guard lock(_wheelMutex);
      _lastAdvanceTime = Clock::now();
    }
    startTickThread();
  }

  /// \brief Drain the timing wheel: fire expired timers in deadline order,
  /// cancel future ones. Stops the tick thread first, collects all entries,
  /// sorts by deadline, fires them in order. If the timeout is exceeded, the
  /// remaining timers are cancelled (not fired) and counted in
  /// DrainStats.remaining.
  /// \note When a Dispatcher is set, expired callbacks are posted to the
  ///       dispatcher (e.g., a thread pool) and may still be in-flight when
  ///       drain() returns. The caller must drain the dispatcher separately
  ///       to ensure all callbacks have completed before destroying targets.
  DrainStats drain(std::chrono::milliseconds timeoutMs = std::chrono::milliseconds(30000))
  {
    DrainStats stats;
    auto startTime = Clock::now();

    // Entries to fire (populated under the locks, fired AFTER releasing them —
    // no user callback runs under _lifecycleMutex or _wheelMutex, tracker
    // 2026-09-10-7 R4).
    std::vector<std::pair<TimerId, Callback>> toFire;
    {
      // Cancelled callbacks are destroyed at the end of THIS block — outside
      // both _wheelMutex and _lifecycleMutex — so their destructors (which may
      // release shared_ptr captures, or re-enter cancel()/a lifecycle method)
      // never run under a lock (tracker 2026-09-10-7 M-1 / L-3).
      std::vector<Callback> toDiscard;
      {
        // Whole collection under _lifecycleMutex (R5): the _accepting/_state
        // transitions, stopTickThread()'s join (R9: never called while
        // _wheelMutex is held), and the entry collection are serialized against
        // every other lifecycle call. Released BEFORE the fire loop below (R4).
        std::lock_guard lifecycle(_lifecycleMutex);
        // R3 INVARIANT: _accepting=false is stored (release) BEFORE _wheelMutex
        // is acquired below — schedule()'s under-lock re-check depends on this
        // store-before-lock ordering to observe false and decline an orphan. Do
        // NOT reorder the store after the _wheelMutex acquire (tracker -6 R3).
        _accepting.store(false, std::memory_order_release);
        _state.store(TimingWheelState::DRAINING, std::memory_order_release);
        stopTickThread();

        std::lock_guard lock(_wheelMutex);

        // Gather entries with their deadlines for sorting
        struct DrainEntry
        {
          TimerId id;
          Callback callback;
          TimePoint deadline;
        };
        std::vector<DrainEntry> entries;
        entries.reserve(_entryMap.size());

        for (auto& w : _wheels)
        {
          for (auto& b : w.buckets)
          {
            auto* entry = b.head;
            while (entry)
            {
              auto* next = entry->next;
              b.unlink(entry);
              entries.push_back({entry->id, std::move(entry->callback), entry->deadline});
              freeEntry(entry);
              entry = next;
            }
          }
        }
        _entryMap.clear();

        // Sort by deadline (earliest first)
        std::sort(entries.begin(), entries.end(),
          [](const DrainEntry& a, const DrainEntry& b)
          {
            return a.deadline < b.deadline;
          });

        // Only fire timers whose deadline has passed. Timers scheduled for the
        // future are cancelled — firing them would execute callbacks at
        // unexpected times, risking use-after-free on targets that expect the
        // timer to fire much later (or never, if cancelled before then).
        // INVARIANT: EVERY entry's callback MUST be moved out here (into toFire
        // or toDiscard) before this block closes — `entries` is destroyed while
        // _wheelMutex/_lifecycleMutex are still held, so any callback left in it
        // would run a user destructor under a lock (a future early-`continue`
        // that skips a callback would regress the no-user-code-under-lock rule).
        auto now = Clock::now();
        for (auto& e : entries)
        {
          if (e.deadline <= now)
          {
            toFire.emplace_back(e.id, std::move(e.callback));
          }
          else
          {
            toDiscard.push_back(std::move(e.callback));
            ++stats.cancelled;
          }
        }
      } // _wheelMutex + _lifecycleMutex released here
    }   // toDiscard destroyed here, outside every lock

    // Fire expired timers in deadline order, respecting timeout. Runs with NO
    // lock held: a callback may safely call schedule/cancel/reschedule, and a
    // reentrant lifecycle call (contract-discouraged) no-ops via the DRAINING
    // state gate below rather than self-deadlocking on _lifecycleMutex.
    for (auto& [id, cb] : toFire)
    {
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - startTime);
      if (elapsed >= timeoutMs)
      {
        stats.remaining = toFire.size() - stats.fired;
        stats.elapsed = elapsed;
        publishDrainStopped();
        return stats;
      }

      fireCallback(id, std::move(cb));
      ++stats.fired;
    }

    stats.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      Clock::now() - startTime);
    publishDrainStopped();
    return stats;
  }

  void stop()
  {
    // Whole body under _lifecycleMutex (R5) EXCEPT the destruction of collected
    // callbacks (M-1): a captured-resource destructor may re-enter a lifecycle
    // method, which would self-deadlock on the non-recursive _lifecycleMutex.
    std::vector<Callback> toDestroy;
    {
      std::lock_guard lifecycle(_lifecycleMutex);
      // R3 INVARIANT: _accepting=false stored (release) BEFORE collectAllEntries
      // takes _wheelMutex — schedule()'s under-lock re-check depends on this
      // store-before-lock ordering to decline an orphan (tracker -6 R3).
      _accepting.store(false, std::memory_order_release);
      stopTickThread(); // R9: _wheelMutex not held here
      toDestroy = collectAllEntries();
      _state.store(TimingWheelState::STOPPED, std::memory_order_release);
    }
    // toDestroy destroyed here, outside _lifecycleMutex and _wheelMutex (M-1)
  }

  void reset()
  {
    // Whole body under _lifecycleMutex (R5/H2) so no concurrent start()
    // (RESET->RUNNING) can interleave mid-teardown. The former debug-only assert
    // is replaced by an unconditional CAS: a non-STOPPED reset SILENTLY NO-OPS
    // (R1), so under NDEBUG it can no longer corrupt logical state while RUNNING.
    std::vector<Callback> toDestroy;
    {
      std::lock_guard lifecycle(_lifecycleMutex);
      auto expected = TimingWheelState::STOPPED;
      if (!_state.compare_exchange_strong(expected, TimingWheelState::RESET))
      {
        return; // not STOPPED -> no-op (consistent with start()'s failed CAS)
      }
      // STOPPED implies _entryMap is already empty (stop()/drain() cleared it),
      // so collectAllEntries() returns an empty vector in-contract and no
      // callback destructor runs; the assignment is a defensive net.
      toDestroy = collectAllEntries();
      {
        std::lock_guard lock(_wheelMutex);
        for (auto& w : _wheels)
        {
          w.currentTick = 0;
        }
        _lastAdvanceTime = TimePoint{};
      }
      drainFreeList();
      // _nextId is deliberately NOT reset — it stays MONOTONIC across resets
      // (tracker 2026-09-10-7 H-1). schedule() fetches its id (fetch_add) BEFORE
      // taking _wheelMutex, so a schedule() preempted across a stop()->reset()->
      // start() restart holds an already-issued id; zeroing the counter here
      // would let a post-restart schedule re-issue that same id -> _entryMap
      // overwrite (leaked entry) + TimerId aliasing (cancel/reschedule hit the
      // wrong timer). TimerIds are opaque handles, so monotonicity is the
      // correct invariant; the stale in-flight timer simply fires in the
      // restarted wheel (a valid, non-orphan outcome per -6 R1).
      // _state is already RESET (set by the CAS above) — no redundant store.
    }
    // toDestroy destroyed here, outside every lock (defensive; empty in-contract)
  }

  void shutdown(std::chrono::milliseconds timeout = std::chrono::milliseconds(30000))
  {
    drain(timeout);
  }

  TimingWheelState getState() const noexcept
  {
    return _state.load(std::memory_order_relaxed);
  }

  std::size_t pendingCount() const
  {
    std::lock_guard lock(_wheelMutex);
    return _entryMap.size();
  }

  std::size_t getInFlightCount() const
  {
    return pendingCount();
  }

  /// \brief Set error callback. Thread-safe (uses atomic shared_ptr).
  void setErrorCallback(ErrorCallback cb)
  {
    auto sp = std::make_shared<ErrorCallback>(std::move(cb));
    std::atomic_store(&_errorCallback, std::move(sp));
  }

private:
  struct TimerEntry
  {
    TimerId id = InvalidTimerId;
    Callback callback;
    TimePoint deadline;
    TimerEntry* prev = nullptr;
    TimerEntry* next = nullptr;
    std::size_t wheelLevel = 0;
    std::size_t bucketIndex = 0;
    bool thenReschedule = false; // reserved for future schedulePeriodic support
  };

  struct Bucket
  {
    TimerEntry* head = nullptr;
    TimerEntry* tail = nullptr;

    void pushBack(TimerEntry* e)
    {
      e->prev = tail;
      e->next = nullptr;
      if (tail) { tail->next = e; }
      else { head = e; }
      tail = e;
    }

    void unlink(TimerEntry* e)
    {
      if (e->prev) { e->prev->next = e->next; }
      else { head = e->next; }
      if (e->next) { e->next->prev = e->prev; }
      else { tail = e->prev; }
      e->prev = nullptr;
      e->next = nullptr;
    }
  };

  struct WheelLevel
  {
    std::vector<Bucket> buckets;
    std::size_t currentTick = 0;
  };

  void drainFreeList()
  {
    std::lock_guard lock(_poolMutex);
    while (_freeListHead)
    {
      auto* next = _freeListHead->next;
      delete _freeListHead;
      _freeListHead = next;
    }
  }

  // ── Entry Pool (free-list) ───────────────────────────────────────────

  TimerEntry* allocEntry()
  {
    std::lock_guard lock(_poolMutex);
    if (_freeListHead)
    {
      auto* entry = _freeListHead;
      _freeListHead = _freeListHead->next;
      entry->prev = nullptr;
      entry->next = nullptr;
      entry->id = InvalidTimerId;
      entry->callback = nullptr;
      entry->wheelLevel = 0;
      entry->bucketIndex = 0;
      return entry;
    }
    return new TimerEntry();
  }

  void freeEntry(TimerEntry* entry)
  {
    entry->callback = nullptr; // release callback resources
    entry->id = InvalidTimerId;
    std::lock_guard lock(_poolMutex);
    entry->next = _freeListHead;
    entry->prev = nullptr;
    _freeListHead = entry;
  }

  // ── Wheel Operations ─────────────────────────────────────────────────

  /// \brief Insert an entry into the correct wheel bucket.
  /// If the deadline has already passed or the computed bucket is behind
  /// currentTick (heavy load / scheduling during advance), the entry is
  /// placed in the CURRENT bucket of level 0 so it fires on the very
  /// next advance() call. If the delay exceeds the wheel's representable span
  /// (over-range), the entry is FORCED into the furthest representable bucket
  /// with entry->deadline preserved, so the collectFromBucket/cascadeDown
  /// deadline gate re-defers it (never masks it into an earlier bucket → early
  /// misfire / cascade hang).
  void insertEntry(TimerEntry* entry, std::chrono::milliseconds delay)
  {
    auto ticks = delay.count() / _tickDuration.count();

    // Deadline already passed or zero delay → fire on next advance
    if (ticks <= 0)
    {
      auto& wheel = _wheels[0];
      auto idx = wheel.currentTick & _tickMask;
      entry->wheelLevel = 0;
      entry->bucketIndex = idx;
      wheel.buckets[idx].pushBack(entry);
      return;
    }

    std::size_t level = 0;
    auto levelCap = static_cast<std::int64_t>(_ticksPerWheel);
    while (level < _numWheels - 1 && ticks >= levelCap)
    {
      ticks /= levelCap; // levelCap == int64_t(_ticksPerWheel)
      ++level;
    }

    auto& wheel = _wheels[level];
    std::size_t idx;
    if (ticks >= levelCap)
    {
      // Over-range: even at the top level the delay still exceeds this wheel's
      // span (ticks >= _ticksPerWheel). Masking (currentTick + ticks) &
      // _tickMask would silently fold it into an EARLIER bucket -> early misfire
      // at numWheels==1 (collectFromBucket has no cascade) and a same-bucket
      // cascade re-insert -> hang at numWheels>=2. Instead FORCE the furthest
      // representable bucket and keep entry->deadline intact; the deadline gate
      // in collectFromBucket/cascadeDown re-defers the entry (via advance()'s
      // scratch list) until `remaining` is in range. Forcing the furthest bucket
      // (never idx from over-range ticks) guarantees idx != currentTick for
      // _ticksPerWheel >= 2, so a re-insert never lands in a bucket being
      // traversed. Overflow-safe: `ticks` is already divided down by the
      // promotion loop, so this never materializes ticksPerWheel^numWheels.
      idx = (wheel.currentTick + (_ticksPerWheel - 1)) & _tickMask;
    }
    else
    {
      // In-range. At level 0, idx == currentTick & _tickMask means the entry is
      // processed on the next advance() (current bucket) — correct.
      idx = (wheel.currentTick + static_cast<std::size_t>(ticks)) & _tickMask;
    }

    entry->wheelLevel = level;
    entry->bucketIndex = idx;
    wheel.buckets[idx].pushBack(entry);
  }

  void unlinkEntry(TimerEntry* entry)
  {
    _wheels[entry->wheelLevel].buckets[entry->bucketIndex].unlink(entry);
  }

  /// \brief Drain one bucket: for each entry, FIRE it (if isDue) or DEFER it.
  /// Shared by collectFromBucket and cascadeDown so the fire/defer bookkeeping —
  /// and its ordering invariant (move the callback out BEFORE freeEntry(), which
  /// nulls it) — lives in exactly one place. A fired entry is erased from
  /// _entryMap and freed; a deferred (not-yet-due) entry is staged in `deferred`
  /// but KEPT in _entryMap and NOT freed (it is a live timer; cancel() must still
  /// find it), to be re-inserted at the end of the advance() pass. `isDue` is the
  /// only semantic difference between the two callers.
  template <typename DuePred>
  void drainBucket(Bucket& bucket, DuePred isDue,
                   std::vector<std::pair<TimerId, Callback>>& toFire,
                   std::vector<TimerEntry*>& deferred)
  {
    auto* entry = bucket.head;
    while (entry)
    {
      auto* next = entry->next;
      bucket.unlink(entry);
      if (isDue(entry))
      {
        _entryMap.erase(entry->id);
        toFire.emplace_back(entry->id, std::move(entry->callback));
        freeEntry(entry); // MUST follow the move: freeEntry nulls callback
      }
      else
      {
        deferred.push_back(entry);
      }
      entry = next;
    }
  }

  /// \brief Collect due entries from the current level-0 bucket for firing.
  /// This is the terminal firing path (level 0 has no cascade below it), shared
  /// by every geometry including numWheels==1. Deadline gate: an entry fires
  /// only when it is due within tick granularity (remaining < _tickDuration);
  /// an entry a hair (< one tick) in the future still fires — you cannot fire
  /// more precisely than a tick, which preserves the original tick-granularity
  /// contract. An entry more than one tick in the future is a CLAMPED over-range
  /// timer (insertEntry forced it into this bucket far before its real deadline
  /// to avoid masking/misfire); it is re-deferred (staged to `deferred`, kept in
  /// _entryMap, not freed) and re-inserted at the end of the advance() pass.
  void collectFromBucket(Bucket& bucket, TimePoint now,
                         std::vector<std::pair<TimerId, Callback>>& toFire,
                         std::vector<TimerEntry*>& deferred)
  {
    drainBucket(bucket,
      [&](TimerEntry* e) { return e->deadline - now < _tickDuration; },
      toFire, deferred);
  }

  void cascadeDown(std::size_t level, TimePoint now,
                   std::vector<std::pair<TimerId, Callback>>& toFire,
                   std::vector<TimerEntry*>& deferred)
  {
    if (level >= _numWheels)
    {
      return;
    }

    auto& wheel = _wheels[level];
    auto& bucket = wheel.buckets[wheel.currentTick & _tickMask];

    // A not-yet-due entry is DEFERRED (staged), never re-inserted inline: an
    // inline insertEntry could re-enter this very bucket (an aligned over-range
    // remainder) and be re-processed within this pass -> ping-pong -> hang under
    // _wheelMutex. The terminal drain in advance() re-inserts it.
    drainBucket(bucket,
      [&](TimerEntry* e) { return e->deadline <= now; },
      toFire, deferred);

    wheel.currentTick++;
    if ((wheel.currentTick & _tickMask) == 0)
    {
      cascadeDown(level + 1, now, toFire, deferred);
    }
  }

  void fireCallback(TimerId id, Callback cb)
  {
    auto fire = [this, id, cb = std::move(cb)]()
    {
      try
      {
        if (cb)
        {
          cb();
        }
      }
      catch (...)
      {
        auto handler = std::atomic_load(&_errorCallback);
        if (handler && *handler)
        {
          (*handler)(id, std::current_exception());
        }
      }
    };

    if (_dispatcher)
    {
      _dispatcher(std::move(fire));
    }
    else
    {
      fire();
    }
  }

  /// \brief Unlink+free every entry under _wheelMutex and RETURN their callbacks
  /// so the CALLER destroys them outside every lock. A moved-out callback's
  /// captured-resource destructor may re-enter cancel() or a lifecycle method,
  /// so it must run under neither _wheelMutex NOR _lifecycleMutex (tracker
  /// 2026-09-10-7 M-1). Callers (stop/reset/dtor) keep the returned vector alive
  /// until after releasing _lifecycleMutex.
  [[nodiscard]] std::vector<Callback> collectAllEntries()
  {
    std::vector<Callback> toDestroy;
    std::lock_guard lock(_wheelMutex);
    toDestroy.reserve(_entryMap.size());
    for (auto& [id, entry] : _entryMap)
    {
      if (entry->callback)
      {
        toDestroy.push_back(std::move(entry->callback));
      }
      freeEntry(entry);
    }
    _entryMap.clear();
    for (auto& w : _wheels)
    {
      for (auto& b : w.buckets)
      {
        b.head = nullptr;
        b.tail = nullptr;
      }
    }
    return toDestroy;
  }

  void startTickThread()
  {
    _running.store(true, std::memory_order_release);
    _tickThread = std::thread([this]()
    {
      while (_running.load(std::memory_order_acquire))
      {
        {
          std::unique_lock lock(_tickCvMutex);
          _tickCv.wait_for(lock, _tickDuration, [this]()
          {
            return !_running.load(std::memory_order_acquire);
          });
        }
        // _tickCvMutex released before advance(): advance() fires callbacks
        // (collect-then-fire) and takes _wheelMutex, neither of which may run
        // under the CV wait-mutex (no callback under a lock; avoids a nested
        // _tickCvMutex -> _wheelMutex ordering), and a long drift-catch-up
        // advance() must not delay stopTickThread()'s notify wakeup.
        if (_running.load(std::memory_order_acquire))
        {
          advance();
        }
      }
    });
  }

  void stopTickThread()
  {
    _running.store(false, std::memory_order_release);
    // notify_all is INTENTIONALLY issued without holding _tickCvMutex (tracker
    // 2026-09-10-7 L-1): the tick loop's wait_for(lock, _tickDuration, pred)
    // re-checks !_running after a bounded timeout, so there is no permanent lost
    // wakeup and join() is bounded by <= one tick. (Contrast the no-timeout
    // completion-counter case in reference_cv_notify_under_lock, which DID need
    // notify-under-lock.) Idempotent: after a join the thread is non-joinable,
    // so a second call (stop/drain/dtor across a restart cycle) is a safe no-op.
    _tickCv.notify_all();
    if (_tickThread.joinable())
    {
      _tickThread.join();
    }
  }

  /// \brief Publish drain()'s terminal STOPPED transition WITHOUT clobbering a
  /// concurrent stop()+reset() that advanced _state past DRAINING during the
  /// fire window (tracker 2026-09-10-7 R10). Runs outside _lifecycleMutex (post
  /// fire loop), so a conditional CAS lets the concurrent transition win. A
  /// fresh `expected` is used per call (compare_exchange mutates it on failure);
  /// success=release, failure=relaxed (never release) — coherence on the single
  /// enum suffices (LT-2: the mix with start()/reset()'s CAS is intentional).
  void publishDrainStopped()
  {
    auto expected = TimingWheelState::DRAINING;
    _state.compare_exchange_strong(expected, TimingWheelState::STOPPED,
      std::memory_order_release, std::memory_order_relaxed);
  }

  // Configuration (immutable after construction)
  const std::chrono::milliseconds _tickDuration;
  const std::size_t _ticksPerWheel;
  const std::size_t _tickMask;
  const std::size_t _numWheels;
  const Dispatcher _dispatcher;

  // Lifecycle serialization. Lock ordering (outermost -> innermost):
  //   _lifecycleMutex -> _wheelMutex -> _poolMutex   (_tickCvMutex is a LEAF)
  // _lifecycleMutex serializes start/stop/drain/reset among themselves so the
  // _tickThread object is never raced (joinable/join/move/assignment) and no
  // concurrent transition leaves a zombie tick thread. It MUST NOT be acquired
  // by the tick thread, advance(), any user callback, or any callback-resource
  // destructor (tracker 2026-09-10-7 R3/R4/R9) — the join() taken under it would
  // otherwise deadlock, and a callback re-entering a lifecycle method would
  // self-deadlock on this non-recursive mutex. Hot paths (schedule/cancel/
  // reschedule/advance/pendingCount) take only _wheelMutex, never this.
  std::mutex _lifecycleMutex;

  // Wheel structure
  std::vector<WheelLevel> _wheels;
  std::unordered_map<TimerId, TimerEntry*> _entryMap;
  mutable std::mutex _wheelMutex; // Lock ordering: after _lifecycleMutex, before _poolMutex
  TimePoint _lastAdvanceTime{};

  // Entry pool (free-list)
  TimerEntry* _freeListHead = nullptr;
  std::mutex _poolMutex; // Lock ordering: innermost (after _wheelMutex)

  // State
  std::atomic<TimerId> _nextId;
  std::atomic<TimingWheelState> _state;
  std::atomic<bool> _accepting;
  std::atomic<bool> _running;

  // Tick thread. Lock ordering: _tickCvMutex is a LEAF — it is only ever held
  // by the tick loop across _tickCv.wait_for and is released BEFORE advance()
  // (so it never nests over _wheelMutex/_poolMutex and no callback runs under it).
  std::thread _tickThread;
  std::mutex _tickCvMutex;
  std::condition_variable _tickCv;

  // Error handling (thread-safe via atomic shared_ptr)
  std::shared_ptr<ErrorCallback> _errorCallback;

#ifdef IORA_TIMING_WHEEL_TEST_HOOKS
public:
  // Test-only injection seam (compiled out in production). See schedule():
  // parks a caller in the post-accept-check / pre-_wheelMutex orphan window.
  std::function<void()> _testScheduleGate;
  // Monotonic count of advance() calls — a live/zombie tick thread keeps
  // incrementing it; a properly stopped one leaves it frozen.
  std::atomic<std::uint64_t> _testAdvanceCount{0};
  std::uint64_t testAdvanceCount() const
  {
    return _testAdvanceCount.load(std::memory_order_relaxed);
  }
private:
#endif
};

/// \brief Adapter wrapping TimingWheel with ITimerService interface.
class TimingWheelAdapter : public ITimerService
{
public:
  explicit TimingWheelAdapter(TimingWheel& wheel) : _wheel(wheel) {}

  TimerId schedule(std::chrono::milliseconds delay,
                   std::function<void()> callback) override
  {
    return _wheel.schedule(delay, std::move(callback));
  }

  bool cancel(TimerId id) override { return _wheel.cancel(id); }
  bool reschedule(TimerId id, std::chrono::milliseconds newDelay) override
  {
    return _wheel.reschedule(id, newDelay);
  }

  std::chrono::milliseconds tickDuration() const noexcept override
  {
    return _wheel.tickDuration();
  }

private:
  TimingWheel& _wheel;
};

} // namespace core
} // namespace iora
