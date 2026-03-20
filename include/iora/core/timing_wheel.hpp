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
    assert(ticksPerWheel > 0 && (ticksPerWheel & (ticksPerWheel - 1)) == 0);
    assert(numWheels > 0);
    _wheels.resize(numWheels);
    for (auto& w : _wheels)
    {
      w.buckets.resize(ticksPerWheel);
      w.currentTick = 0;
    }
  }

  ~TimingWheel()
  {
    if (_running.load(std::memory_order_relaxed))
    {
      stopTickThread();
    }
    clearAllEntries();
    drainFreeList();
  }

  TimingWheel(const TimingWheel&) = delete;
  TimingWheel& operator=(const TimingWheel&) = delete;
  TimingWheel(TimingWheel&&) = delete;
  TimingWheel& operator=(TimingWheel&&) = delete;

  // ── Schedule / Cancel / Reschedule ─────────────────────────────────────

  TimerId schedule(std::chrono::milliseconds delay, Callback callback)
  {
    if (!_accepting.load(std::memory_order_relaxed))
    {
      return InvalidTimerId;
    }

    auto id = _nextId.fetch_add(1, std::memory_order_relaxed);
    auto deadline = Clock::now() + delay;

    std::lock_guard lock(_wheelMutex);
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
  std::size_t advance()
  {
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

      for (std::size_t t = 0; t < ticksToProcess; ++t)
      {
        auto& level0 = _wheels[0];
        auto& bucket = level0.buckets[level0.currentTick & _tickMask];
        collectFromBucket(bucket, toFire);
        level0.currentTick++;

        if ((level0.currentTick & _tickMask) == 0)
        {
          cascadeDown(1, now, toFire);
        }
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
    auto expected = TimingWheelState::CREATED;
    if (!_state.compare_exchange_strong(expected, TimingWheelState::RUNNING))
    {
      expected = TimingWheelState::RESET;
      if (!_state.compare_exchange_strong(expected, TimingWheelState::RUNNING))
      {
        return;
      }
    }
    _accepting.store(true, std::memory_order_relaxed);
    {
      std::lock_guard lock(_wheelMutex);
      _lastAdvanceTime = Clock::now();
    }
    startTickThread();
  }

  /// \brief Drain all pending timers, firing them in deadline order.
  /// Stops the tick thread first, collects all entries, sorts by deadline,
  /// fires them in order. If timeout is exceeded, remaining timers are
  /// cancelled (not fired) and counted in DrainStats.remaining.
  DrainStats drain(std::chrono::milliseconds timeoutMs = std::chrono::milliseconds(30000))
  {
    _accepting.store(false, std::memory_order_relaxed);
    _state.store(TimingWheelState::DRAINING, std::memory_order_relaxed);
    stopTickThread();

    DrainStats stats;
    auto startTime = Clock::now();

    // Collect ALL pending entries from all buckets, sorted by deadline
    std::vector<std::pair<TimerId, Callback>> toFire;
    {
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

      for (auto& e : entries)
      {
        toFire.emplace_back(e.id, std::move(e.callback));
      }
    }

    // Fire in deadline order, respecting timeout
    for (auto& [id, cb] : toFire)
    {
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - startTime);
      if (elapsed >= timeoutMs)
      {
        stats.remaining = toFire.size() - stats.fired;
        stats.elapsed = elapsed;
        _state.store(TimingWheelState::STOPPED, std::memory_order_relaxed);
        return stats;
      }

      fireCallback(id, std::move(cb));
      ++stats.fired;
    }

    stats.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      Clock::now() - startTime);
    _state.store(TimingWheelState::STOPPED, std::memory_order_relaxed);
    return stats;
  }

  void stop()
  {
    _accepting.store(false, std::memory_order_relaxed);
    stopTickThread();
    clearAllEntries();
    _state.store(TimingWheelState::STOPPED, std::memory_order_relaxed);
  }

  void reset()
  {
    assert(_state.load(std::memory_order_relaxed) == TimingWheelState::STOPPED);
    clearAllEntries();
    {
      std::lock_guard lock(_wheelMutex);
      for (auto& w : _wheels)
      {
        w.currentTick = 0;
      }
      _lastAdvanceTime = TimePoint{};
    }
    drainFreeList();
    _nextId.store(1, std::memory_order_relaxed);
    _state.store(TimingWheelState::RESET, std::memory_order_relaxed);
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
  /// next advance() call.
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
      ticks /= static_cast<std::int64_t>(_ticksPerWheel);
      ++level;
    }

    auto& wheel = _wheels[level];
    auto idx = (wheel.currentTick + static_cast<std::size_t>(ticks)) & _tickMask;

    // If the computed bucket index equals the current tick's bucket,
    // and we're at level > 0, this means the delay fits exactly at
    // the boundary — place it so it fires when this bucket is processed.
    // At level 0, if idx == currentTick & _tickMask, the entry will be
    // processed on the next advance() call (current bucket). This is correct.

    entry->wheelLevel = level;
    entry->bucketIndex = idx;
    wheel.buckets[idx].pushBack(entry);
  }

  void unlinkEntry(TimerEntry* entry)
  {
    _wheels[entry->wheelLevel].buckets[entry->bucketIndex].unlink(entry);
  }

  /// \brief Collect ALL entries from the current bucket for firing.
  /// All entries in a level-0 bucket are due to fire when that bucket's
  /// tick arrives — the deadline check is a safety net but should not
  /// skip entries that were placed correctly. Entries whose deadline
  /// is slightly in the future (placed between ticks) still fire —
  /// this matches the tick-granularity contract.
  void collectFromBucket(Bucket& bucket,
                         std::vector<std::pair<TimerId, Callback>>& toFire)
  {
    auto* entry = bucket.head;
    while (entry)
    {
      auto* next = entry->next;
      bucket.unlink(entry);
      _entryMap.erase(entry->id);
      toFire.emplace_back(entry->id, std::move(entry->callback));
      freeEntry(entry);
      entry = next;
    }
  }

  void cascadeDown(std::size_t level, TimePoint now,
                   std::vector<std::pair<TimerId, Callback>>& toFire)
  {
    if (level >= _numWheels)
    {
      return;
    }

    auto& wheel = _wheels[level];
    auto& bucket = wheel.buckets[wheel.currentTick & _tickMask];

    auto* entry = bucket.head;
    while (entry)
    {
      auto* next = entry->next;
      bucket.unlink(entry);

      if (entry->deadline <= now)
      {
        _entryMap.erase(entry->id);
        toFire.emplace_back(entry->id, std::move(entry->callback));
        freeEntry(entry);
      }
      else
      {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
          entry->deadline - now);
        insertEntry(entry, remaining);
      }
      entry = next;
    }

    wheel.currentTick++;
    if ((wheel.currentTick & _tickMask) == 0)
    {
      cascadeDown(level + 1, now, toFire);
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

  void clearAllEntries()
  {
    std::lock_guard lock(_wheelMutex);
    for (auto& [id, entry] : _entryMap)
    {
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
  }

  void startTickThread()
  {
    _running.store(true, std::memory_order_relaxed);
    _tickThread = std::thread([this]()
    {
      while (_running.load(std::memory_order_relaxed))
      {
        std::unique_lock lock(_tickCvMutex);
        _tickCv.wait_for(lock, _tickDuration, [this]()
        {
          return !_running.load(std::memory_order_relaxed);
        });
        if (_running.load(std::memory_order_relaxed))
        {
          advance();
        }
      }
    });
  }

  void stopTickThread()
  {
    _running.store(false, std::memory_order_relaxed);
    _tickCv.notify_all();
    if (_tickThread.joinable())
    {
      _tickThread.join();
    }
  }

  // Configuration (immutable after construction)
  const std::chrono::milliseconds _tickDuration;
  const std::size_t _ticksPerWheel;
  const std::size_t _tickMask;
  const std::size_t _numWheels;
  const Dispatcher _dispatcher;

  // Wheel structure
  std::vector<WheelLevel> _wheels;
  std::unordered_map<TimerId, TimerEntry*> _entryMap;
  mutable std::mutex _wheelMutex;
  TimePoint _lastAdvanceTime{};

  // Entry pool (free-list)
  TimerEntry* _freeListHead = nullptr;
  std::mutex _poolMutex;

  // State
  std::atomic<TimerId> _nextId;
  std::atomic<TimingWheelState> _state;
  std::atomic<bool> _accepting;
  std::atomic<bool> _running;

  // Tick thread
  std::thread _tickThread;
  std::mutex _tickCvMutex;
  std::condition_variable _tickCv;

  // Error handling (thread-safe via atomic shared_ptr)
  std::shared_ptr<ErrorCallback> _errorCallback;
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

private:
  TimingWheel& _wheel;
};

} // namespace core
} // namespace iora
