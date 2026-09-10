# Iora TimingWheel -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 3.0 |
| **Date** | 2026-09-10 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/core/timing_wheel.hpp` |
| **Namespace** | `iora::core` |
| **Dependencies** | Standard library only -- `<algorithm>`, `<atomic>`, `<cassert>`, `<chrono>`, `<condition_variable>`, `<cstdint>`, `<exception>`, `<functional>`, `<memory>`, `<mutex>`, `<thread>`, `<unordered_map>`, `<vector>`. Header-only; no compiled unit, no external/third-party dependencies. |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-03-20 | Initial implementation. |
| 1.2 | 2026-03-20 | Added `drain()` with deadline sorting, `Dispatcher` integration, `ITimerService` adapter. |
| 2.0 | 2026-03-20 | Full architecture guide: hierarchical cascade mechanics, entry pooling internals, tick drift catch-up, mutex serialization analysis, lifecycle state machine. |
| 3.0 | 2026-09-10 | Migrated into the iora doc-wiki at `docs/core/timing_wheel.md` and restructured to the 12-section guide template. Re-verified every claim against the current `include/iora/core/timing_wheel.hpp` (763 lines) and against the production consumers (`storage/kvstore.hpp`, `core/rate_limiter.hpp`). Corrected stale claims: the `ITimerService` interface and `TimingWheelAdapter` now expose `tickDuration()`; the memory ordering of `_accepting`/`_running` is acquire/release (not relaxed); and the executive-summary motivation was re-based against the *actual* sibling `TimerService` (a single-`timerfd` min-heap, not a timerfd-per-timer). Scope narrowed to `TimingWheel`, `TimingWheelAdapter`, and the `ITimerService` seam -- the epoll/`timerfd` `TimerService` (`core/timer.hpp`) is a separate component; see `docs/core/timer.md`. |

---

## 1. Executive Summary

### Problem

A SIP proxy or media relay handling tens of thousands of concurrent sessions arms two or three timers per transaction -- retransmission (T1/T2), transaction timeout (Timer B/F), session refresh. That is a very high *churn* workload: timers are armed and, more often than not, cancelled before they ever fire (the response arrives first). The scheduler is on the hot path of every message.

iora's other timer engine, `core::TimerService` (`core/timer.hpp`), is a single-threaded epoll + single-`timerfd` service backed by a binary min-heap keyed on deadline. It is excellent for a moderate number of long-lived timers, but each arm/cancel is an `O(log n)` heap operation and every change to the earliest deadline costs a `timerfd_settime` syscall. Under transaction-timer churn those costs dominate, and the heap's `O(log n)` insert/cancel scales poorly as `n` grows into the tens of thousands.

`TimingWheel` and `TimerService` are two **independent** engines -- neither is built on, uses, or is backed by the other. Choose `TimerService` for a moderate number of long-lived timers where a syscall per re-arm is negligible; choose `TimingWheel` for high-churn `O(1)` arm/cancel with no file descriptors.

### Solution

`iora::core::TimingWheel` is a hierarchical (multi-level) timing wheel that manages every timer with a single userspace background thread and **zero file descriptors**:

- **`O(1)` insert, cancel, and reschedule** -- `TimingWheel::schedule` computes a bucket index by integer division and a bitmask, then links a `TimerEntry` into a doubly-linked list; `TimingWheel::cancel` unlinks it. No heap, no tree rebalancing, no syscall.
- **One thread replaces every kernel timer** -- a single tick thread sleeps for `tickDuration` on a `std::condition_variable`, then calls `TimingWheel::advance()`. No `timerfd`, no `epoll`.
- **Hierarchical cascade** -- delays that exceed a level's span are held in higher wheel levels and *cascade down* into finer-grained levels as time advances (the Varghese-Lauck scheme).
- **Collect-then-fire** -- `advance()` collects expired callbacks into a vector under `_wheelMutex`, then fires them *after* releasing the lock, so a callback may safely call back into `schedule()` / `cancel()` / `reschedule()` without deadlock.
- **Entry pooling** -- freed `TimerEntry` objects go onto an intrusive free-list rather than being `delete`d, so steady-state operation is allocation-free.
- **`ITimerService` seam** -- `TimingWheelAdapter` wraps a `TimingWheel` behind the abstract `ITimerService` interface, so code written against the seam can be backed by a wheel or by any other implementer.

### Technical Impact

- N concurrent timers use **0 file descriptors** (versus one `timerfd` + one `epoll` fd for `TimerService`, regardless of N).
- Insert / cancel / reschedule are **`O(1)`** with no heap operations and no per-operation syscall.
- **Tick-granularity contract:** a timer fires within one `tickDuration` of its deadline (at the tick boundary at or after the deadline). Sub-tick precision is not offered.
- `drain()` fires all *already-expired* pending timers in strict deadline order during graceful shutdown, and cancels those still in the future.
- An optional `Dispatcher` routes callbacks to an external thread pool, keeping the tick thread unblocked by slow callbacks.

---

## 2. System Architecture

### 2.1 Component relationships

```
iora::core (namespace)
|
|-- ITimerService                         (abstract seam; 30+ implementers ecosystem-wide)
|     |-- schedule / cancel / reschedule  (pure virtual)
|     `-- tickDuration()                  (NON-pure; default returns 0ms "unknown" sentinel)
|
|-- TimingWheel                           (the engine; non-copyable, non-movable)
|   |-- Configuration (const after construction)
|   |     |-- _tickDuration               (std::chrono::milliseconds per tick)
|   |     |-- _ticksPerWheel              (slots per level; MUST be power of two)
|   |     |-- _tickMask = _ticksPerWheel - 1   (bitmask replaces modulo)
|   |     |-- _numWheels                  (number of hierarchical levels)
|   |     `-- _dispatcher                 (optional std::function<void(Callback)>)
|   |
|   |-- Wheel structure  (guarded by _wheelMutex)
|   |     |-- _wheels: std::vector<WheelLevel>
|   |     |     `-- WheelLevel { std::vector<Bucket> buckets; std::size_t currentTick; }
|   |     |           `-- Bucket { TimerEntry* head; TimerEntry* tail; }  (doubly-linked)
|   |     |-- _entryMap: std::unordered_map<TimerId, TimerEntry*>   (O(1) cancel/reschedule)
|   |     `-- _lastAdvanceTime: TimePoint                            (tick-drift catch-up)
|   |
|   |-- Entry pool  (guarded by _poolMutex)
|   |     `-- _freeListHead: TimerEntry*   (intrusive singly-linked free-list via ->next)
|   |
|   |-- Tick thread
|   |     |-- _tickThread: std::thread
|   |     `-- _tickCvMutex + _tickCv       (condition variable; wakes on stop)
|   |
|   |-- State (all atomic)
|   |     |-- _state: atomic<TimingWheelState>
|   |     |-- _accepting: atomic<bool>     (schedule gate)
|   |     |-- _running:   atomic<bool>     (tick-thread gate)
|   |     `-- _nextId:    atomic<TimerId>
|   |
|   `-- _errorCallback: std::shared_ptr<ErrorCallback>   (atomic_load / atomic_store)
|
`-- TimingWheelAdapter : public ITimerService
      `-- TimingWheel& _wheel            (holds a reference; wheel MUST outlive adapter)
```

### 2.2 Data flow -- schedule then fire

```mermaid
sequenceDiagram
  participant App as Application
  participant TW as TimingWheel
  participant Pool as Entry pool
  participant Wheel as Wheel levels

  App->>TW: schedule(500ms, callback)
  Note over TW: _accepting.load(acquire) -- true?
  TW->>TW: id = _nextId.fetch_add(1, relaxed)
  TW->>TW: deadline = Clock::now() + 500ms
  TW->>TW: lock_guard(_wheelMutex)
  TW->>Pool: allocEntry() [locks _poolMutex under _wheelMutex]
  Pool-->>TW: TimerEntry* (recycled or new)
  TW->>TW: insertEntry(entry, 500ms)
  Note over TW: ticks = 500 / tickDuration; pick level; idx = (currentTick + ticks) & _tickMask
  TW->>Wheel: buckets[idx].pushBack(entry)
  TW->>TW: _entryMap[id] = entry
  TW-->>App: TimerId

  Note over TW: ... tick thread wakes, calls advance() ...

  TW->>TW: lock_guard(_wheelMutex)
  TW->>Wheel: collectFromBucket(current level-0 bucket) -> toFire
  TW->>Pool: freeEntry(entry) [recycle onto free-list]
  TW->>TW: unlock _wheelMutex
  loop for each (id, cb) in toFire
    alt dispatcher set
      TW->>App: dispatcher(wrappedCallback)
    else no dispatcher
      TW->>App: callback() inline on tick thread
    end
  end
```

### 2.3 Threading model

| Thread | Responsibility |
|---|---|
| Application thread(s) | Call `schedule()` / `cancel()` / `reschedule()` / `pendingCount()`. Each takes `_wheelMutex` (and, for alloc/free, `_poolMutex` nested under it). |
| Tick thread (internal, one per wheel) | Spawned by `start()`. Sleeps `tickDuration` on `_tickCv`, then calls `advance()`. Fires callbacks inline unless a `Dispatcher` is set. |
| Dispatcher thread pool (optional, external) | If a `Dispatcher` is supplied, expired callbacks execute here rather than on the tick thread. Ordering across pool threads is not guaranteed. |
| Lifecycle thread (whoever calls `start`/`stop`/`drain`/`reset`) | Drives state transitions and joins the tick thread. `drain()` / `stop()` fire or discard remaining callbacks on the calling thread. |

---

## 3. Component Deep Dive

### 3.1 `TimingWheel` construction and immutable layout

```cpp
TimingWheel(std::chrono::milliseconds tickDuration,
            std::size_t ticksPerWheel,
            std::size_t numWheels,
            Dispatcher dispatcher = nullptr);
```

The constructor asserts `ticksPerWheel > 0 && (ticksPerWheel & (ticksPerWheel - 1)) == 0` (power of two) and `numWheels > 0`, then allocates `numWheels` `WheelLevel`s, each with `ticksPerWheel` empty `Bucket`s. `_tickMask` is precomputed as `ticksPerWheel - 1` so every "modulo `ticksPerWheel`" in the hot path becomes a single bitwise-and. All five configuration members (`_tickDuration`, `_ticksPerWheel`, `_tickMask`, `_numWheels`, `_dispatcher`) are `const` -- fixed at construction, never mutated, so they are read lock-free.

The type is **non-copyable and non-movable** (all four special members are `= delete`): it owns a running thread and raw `TimerEntry*` pointers threaded through intrusive lists and a map. Consumers that need to store one hold it by `std::unique_ptr` -- exactly what `KVStore` does for its TTL wheel.

### 3.2 Hierarchical cascade -- UP on insert, DOWN on advance

**Insert (promote UP).** `insertEntry(entry, delay)` converts the delay to ticks (`delay.count() / _tickDuration.count()`). A delay of zero or one that rounds to `<= 0` ticks is placed directly in level 0's *current* bucket so it fires on the very next `advance()`. Otherwise the entry is promoted upward while it does not fit in the current level:

```cpp
std::size_t level = 0;
auto levelCap = static_cast<std::int64_t>(_ticksPerWheel);
while (level < _numWheels - 1 && ticks >= levelCap)
{
  ticks /= static_cast<std::int64_t>(_ticksPerWheel);
  ++level;
}
auto& wheel = _wheels[level];
auto idx = (wheel.currentTick + static_cast<std::size_t>(ticks)) & _tickMask;
entry->wheelLevel = level;
entry->bucketIndex = idx;
wheel.buckets[idx].pushBack(entry);
```

The entry also records its absolute `deadline` (`Clock::now() + delay`). The lower-order bits discarded by the repeated division are *not* lost information -- they are recovered from `deadline` when the entry cascades down.

**Advance (cascade DOWN).** `advance()` processes level 0's current bucket, increments `currentTick`, and when level 0 completes a full revolution (`(currentTick & _tickMask) == 0`) it calls `cascadeDown(1, now, toFire)`. `cascadeDown` walks the current bucket of the given level and, for each entry:

- if `entry->deadline <= now`, collects it for firing;
- otherwise re-inserts it via `insertEntry(entry, deadline - now)` -- i.e. by *remaining* time, so it lands in the correct finer-grained bucket even if the cascade ran slightly late.

After processing, the level's `currentTick` is incremented, and if *that* level completes a revolution the cascade recurses to `level + 1`. `cascadeDown` returns immediately once `level >= _numWheels`.

### 3.3 Single-mutex serialization (collect-then-fire)

Every mutation of wheel structure (`insertEntry`, `unlinkEntry`, `collectFromBucket`, `cascadeDown`, and all `_entryMap` writes) is serialized under one `std::mutex _wheelMutex`. `advance()` embodies the collect-then-fire pattern:

```cpp
std::vector<std::pair<TimerId, Callback>> toFire;
{
  std::lock_guard lock(_wheelMutex);
  // ... tick-drift catch-up + collectFromBucket + cascadeDown into toFire ...
}
// Fire OUTSIDE the lock:
for (auto& [id, cb] : toFire)
{
  fireCallback(id, std::move(cb));
}
```

Two properties follow:

1. **No re-entrancy deadlock.** Because `_wheelMutex` is not held while callbacks run, a callback may call `schedule()`, `cancel()`, or `reschedule()` -- the recurring-timer idiom depends on this.
2. **Minimal lock hold time.** The lock covers only `O(1)`-per-entry pointer manipulation, never arbitrary user code.

### 3.4 Two mutexes, one lock order

`_wheelMutex` guards the wheel and map; a *separate* `_poolMutex` guards the free-list. The declared invariant (comment at the `_wheelMutex` and `_poolMutex` declarations) is **`_wheelMutex` BEFORE `_poolMutex`**. In every hot path `allocEntry()` / `freeEntry()` (which take `_poolMutex`) are called while `_wheelMutex` is already held -- `schedule`, `cancel`, `drain`, `clearAllEntries`, `collectFromBucket`. The one path that takes `_poolMutex` alone is `drainFreeList()`, called only from `reset()` and the destructor, when the wheel is already stopped and no other thread holds `_wheelMutex` -- so the ordering is never inverted.

### 3.5 Entry pooling (intrusive free-list)

`allocEntry()` pops the free-list head if non-empty (resetting its fields), else `new TimerEntry()`. `freeEntry()` nulls the callback first -- releasing any captured `shared_ptr`s / strings promptly -- then pushes the entry onto the free-list head:

```cpp
void freeEntry(TimerEntry* entry)
{
  entry->callback = nullptr; // release captured resources now, not at re-alloc
  entry->id = InvalidTimerId;
  std::lock_guard lock(_poolMutex);
  entry->next = _freeListHead;
  entry->prev = nullptr;
  _freeListHead = entry;
}
```

The pool grows monotonically -- entries are never `delete`d during normal operation, only recycled -- and is emptied (`drainFreeList()`) only on `reset()` and destruction. After warm-up, steady-state scheduling performs zero heap allocations.

### 3.6 Tick-drift catch-up

`advance()` computes how many ticks have elapsed since the previous call and processes all of them in one pass, so a delayed tick thread (GC pause, scheduler jitter, process suspension) does not starve timers:

```cpp
std::size_t ticksToProcess = 1;
if (_lastAdvanceTime != TimePoint{})
{
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - _lastAdvanceTime);
  auto elapsedTicks = elapsed.count() / _tickDuration.count();
  if (elapsedTicks > 1)
  {
    ticksToProcess = static_cast<std::size_t>(elapsedTicks);
  }
}
_lastAdvanceTime = now;
for (std::size_t t = 0; t < ticksToProcess; ++t) { /* advance level 0, cascade as needed */ }
```

The trade-off: if the thread falls far behind (e.g. the process was suspended for seconds), a single `advance()` fires a burst of callbacks. Collect-then-fire keeps that burst off the lock.

### 3.7 `fireCallback` -- error isolation and optional dispatch

Every callback is wrapped in a try/catch that routes exceptions to the (optional) error callback, so one throwing timer never kills the tick thread or aborts the remaining `toFire` batch:

```cpp
void fireCallback(TimerId id, Callback cb)
{
  auto fire = [this, id, cb = std::move(cb)]()
  {
    try { if (cb) { cb(); } }
    catch (...)
    {
      auto handler = std::atomic_load(&_errorCallback);
      if (handler && *handler) { (*handler)(id, std::current_exception()); }
    }
  };
  if (_dispatcher) { _dispatcher(std::move(fire)); }
  else { fire(); }
}
```

With no dispatcher, `fire()` runs inline on the tick thread -- a slow callback delays every later timer. With a dispatcher, the wrapped closure is handed to the pool and the tick thread returns immediately, at the cost of any cross-callback ordering.

### 3.8 `setErrorCallback` -- lock-free swap

The error callback is stored as `std::shared_ptr<ErrorCallback>` and swapped with `std::atomic_store` / read with `std::atomic_load`, so it can be set at any time from any thread with no mutex.

### 3.9 `ITimerService` and `TimingWheelAdapter`

`ITimerService` is the abstract timer seam used across the iora ecosystem. Its scheduling methods are pure virtual, but `tickDuration()` is **non-pure** with a `0ms` "unknown" sentinel default:

```cpp
virtual std::chrono::milliseconds tickDuration() const noexcept
{
  return std::chrono::milliseconds{0};
}
```

The rationale (documented in the header): a non-pure default keeps the 30+ existing implementers (iora core, iora_sip production and test mocks, iora_media) compiling unchanged, while a wheel-backed adapter overrides it with the real tick. A consumer that reasons about the scheduler's granularity floor **must fail closed on a returned `0`** rather than divide by it.

`TimingWheelAdapter` forwards all four methods to a referenced `TimingWheel`, including the `tickDuration()` override:

```cpp
class TimingWheelAdapter : public ITimerService
{
public:
  explicit TimingWheelAdapter(TimingWheel& wheel) : _wheel(wheel) {}
  TimerId schedule(std::chrono::milliseconds delay, std::function<void()> cb) override
  { return _wheel.schedule(delay, std::move(cb)); }
  bool cancel(TimerId id) override { return _wheel.cancel(id); }
  bool reschedule(TimerId id, std::chrono::milliseconds newDelay) override
  { return _wheel.reschedule(id, newDelay); }
  std::chrono::milliseconds tickDuration() const noexcept override
  { return _wheel.tickDuration(); }
private:
  TimingWheel& _wheel;
};
```

The adapter holds a *reference* -- the `TimingWheel` must outlive it. Note that `ITimerService` deliberately exposes **no lifecycle** (`start`/`drain`/`reset`); those live on the concrete `TimingWheel` and are the wiring layer's responsibility.

### 3.10 Relationship to `TimerService` (the sibling)

`TimingWheel` and `core::TimerService` are two **independent** engines: `TimingWheel` is not built on, does not use, and is not backed by `TimerService` (they share only the `drain()` vocabulary and the `ITimerService` seam). For when to choose which, see section 1; `TimerService` is documented in [`docs/core/timer.md`](timer.md).

---

## 4. Lifecycle State Machine

`TimingWheelState` has five values and `getState()` returns the current one (`memory_order_relaxed` load):

```
CREATED --start()--> RUNNING --drain()--> DRAINING --(completes)--> STOPPED
                       |                                               |
                       +--stop()---------------------------------> STOPPED
                                                                       |
                                                     reset() (asserts STOPPED)
                                                                       |
                                                                       v
                                                     RESET --start()--> RUNNING
```

| State | `_accepting` | `_running` | `schedule()` returns |
|---|---|---|---|
| `CREATED` | false | false | `InvalidTimerId` |
| `RUNNING` | true | true | valid `TimerId` |
| `DRAINING` | false | (thread stopped) | `InvalidTimerId` |
| `STOPPED` | false | false | `InvalidTimerId` |
| `RESET` | false | false | `InvalidTimerId` |

- **`start()`** -- `compare_exchange_strong` from `CREATED` (else retried from `RESET`); any other current state is a silent no-op (returns without starting). On success sets `_accepting = true` (release), records `_lastAdvanceTime` under `_wheelMutex`, spawns the tick thread. Because acceptance is guarded by `_accepting`, `schedule()` before `start()` returns `InvalidTimerId`.
- **`drain(timeoutMs = 30000ms)`** -- sets `_accepting = false`, transitions to `DRAINING`, stops the tick thread, then under the lock collects every pending entry across all levels, sorts by deadline, and fires those already due in order while respecting the timeout. Future-dated entries are cancelled (see 3-b in section 7). Ends in `STOPPED` and returns `DrainStats`.
- **`stop()`** -- sets `_accepting = false`, stops the tick thread, `clearAllEntries()` (discards pending callbacks *without* firing), transitions to `STOPPED`.
- **`reset()`** -- **asserts** the current state is `STOPPED`, then clears entries, zeroes each level's `currentTick`, clears `_lastAdvanceTime`, drains the free-list, resets `_nextId` to 1, transitions to `RESET`. In an `NDEBUG` build the assert is compiled out (see Known Limitations).
- **`shutdown(timeout = 30000ms)`** -- a thin alias that calls `drain(timeout)`.

`clearAllEntries()` uses the same off-lock destruction discipline as `drain()`: it moves each pending callback into a local `toDestroy` vector under `_wheelMutex`, empties the map and buckets, releases the lock, and only then lets `toDestroy` (and any captured resources) destruct -- so a callback's destructor that re-enters the wheel cannot deadlock.

---

## 5. Capacity, Cascade, and Sizing

### 5.1 Capacity formula

Each additional level multiplies the reachable span by `ticksPerWheel`:

```
Level N span = ticksPerWheel^(N+1) * tickDuration
Max schedulable delay = ticksPerWheel^numWheels * tickDuration
```

Example -- `tickDuration = 10ms`, `ticksPerWheel = 64`, `numWheels = 3`:

| Level | Span |
|---|---|
| 0 | 64 * 10ms = 640 ms |
| 1 | 64^2 * 10ms = 40,960 ms (~41 s) |
| 2 | 64^3 * 10ms = 2,621,440 ms (~43.7 min) |

### 5.2 Sizing guidance

| Scenario | `tickDuration` | `ticksPerWheel` | `numWheels` | Max delay |
|---|---|---|---|---|
| SIP retransmission (T1 = 500ms) | 10ms | 64 | 2 | ~41 s |
| SIP registration expiry | 10ms | 64 | 3 | ~44 min |
| HTTP request timeout | 100ms | 16 | 2 | ~25.6 s |
| KVStore TTL eviction | (per `KVStore::Config`) | (per config) | (per config) | per config |
| Fine-grained (1ms resolution) | 1ms | 256 | 2 | ~65.5 s |

Rule of thumb: `tickDuration` sets resolution; `ticksPerWheel^numWheels * tickDuration` sets the maximum schedulable delay. `ticksPerWheel` **must** be a power of two (asserted in the constructor). Scheduling a delay beyond the maximum span silently misfires -- see section 12.

---

## 6. Usage Guide

### 6.1 Basic one-shot scheduling

```cpp
#include "iora/core/timing_wheel.hpp"

using namespace iora::core;
using namespace std::chrono_literals;

// 10ms tick, 64 slots per level, 3 levels: covers 10ms to ~44min.
TimingWheel tw(10ms, 64, 3);
tw.start();

TimerId id = tw.schedule(500ms, []() { handleTimeout(); });

bool cancelled = tw.cancel(id);              // true if still pending
tw.reschedule(id, 1000ms);                   // preserves the TimerId
```

### 6.2 Recurring timer (self-reschedule from the callback)

This is the pattern `RateLimiterMap` uses for periodic idle-bucket cleanup -- safe because `_wheelMutex` is not held during firing:

```cpp
#include "iora/core/timing_wheel.hpp"

using namespace iora::core;
using namespace std::chrono_literals;

TimingWheel tw(10ms, 64, 3);
tw.start();

// Self-holding idiom: the callback holds a shared handle to itself, so the
// re-arm never dangles. Both `tw` and `tick` must outlive every fire.
auto tick = std::make_shared<std::function<void()>>();
*tick = [&tw, tick]()
{
  doPeriodicWork();
  tw.schedule(5s, *tick);   // re-arm from inside the callback
};
tw.schedule(5s, *tick);
```

### 6.3 Offloading callbacks to a thread pool (the `Dispatcher`)

This mirrors `KVStore`, which constructs its TTL wheel with a *push-only* dispatcher that enqueues the fired callback onto a dedicated eviction worker, keeping the tick thread free:

```cpp
#include "iora/core/timing_wheel.hpp"

using namespace iora::core;
using namespace std::chrono_literals;

// dispatcher: TimingWheel::Callback -> enqueue onto your own worker/pool.
auto dispatcher = [](TimingWheel::Callback cb) { myWorkQueue.push(std::move(cb)); };

TimingWheel tw(10ms, 64, 3, dispatcher);
tw.start();

tw.schedule(1s, []() { doExpensiveWork(); });   // runs on the worker, not the tick thread
```

### 6.4 The `ITimerService` seam

```cpp
#include "iora/core/timing_wheel.hpp"

using namespace iora::core;
using namespace std::chrono_literals;

void armSessionTimeout(ITimerService& svc, const std::string& callId)
{
  svc.schedule(32s, [callId]() { handleSipTimeout(callId); });
}

TimingWheel tw(10ms, 64, 3);
tw.start();
TimingWheelAdapter adapter(tw);   // adapter must NOT outlive tw
armSessionTimeout(adapter, "call-123");
```

### 6.5 Error handling and graceful drain

```cpp
#include "iora/core/timing_wheel.hpp"
#include <exception>
#include <string>

using namespace iora::core;
using namespace std::chrono_literals;

tw.setErrorCallback([](TimerId id, std::exception_ptr ep)
{
  try { std::rethrow_exception(ep); }
  catch (const std::exception& e)
  {
    logError("timer " + std::to_string(id) + " threw: " + e.what());
  }
});

DrainStats stats = tw.drain(30s);   // fire all already-due timers in deadline order
// stats.fired / stats.remaining / stats.cancelled / stats.elapsed
tw.reset();                         // valid only from STOPPED
tw.start();                         // reuse the wheel
```

### 6.6 Anti-patterns

- **Do NOT call `advance()` while the tick thread is running.** `advance()` is public for testing only. A concurrent external call is memory-safe -- `_wheelMutex` serializes it against the tick thread -- but it logically *double-advances* the wheel: the second caller computes ~0 elapsed since `_lastAdvanceTime` yet still advances one tick, so timers fire early and the cascade desyncs. There is no internal guard against a second caller (`tasks/iora/backlog/2026-09-10-7_timing-wheel-lifecycle-transition-guards_P1.json`).
- **Do NOT call `reset()` outside `STOPPED`.** It asserts in debug builds and is undefined behavior in release (the assert is compiled out under `NDEBUG`).
- **Do NOT let a `TimingWheelAdapter` outlive its `TimingWheel`.** The adapter holds a bare reference.
- **Do NOT schedule delays beyond `ticksPerWheel^numWheels * tickDuration`.** There is no range check; the bitmask wraps the entry into an earlier bucket and it fires at the wrong (earlier) time. For `numWheels >= 2` there is an added hazard: because entries re-insert by *remaining* time, `cascadeDown` can land the entry back in the bucket it is actively traversing, so it may be processed more than once per pass. Tracked in `tasks/iora/backlog/2026-09-10-1_timing-wheel-insertentry-max-delay-misfire_P0.json`.
- **Do NOT block in a callback when no `Dispatcher` is set.** A slow inline callback stalls the tick thread and delays every other timer, compounding drift.
- **Do NOT assume `drain()` completion means dispatched callbacks finished.** With a `Dispatcher`, `drain()` returns after *posting* callbacks; drain your dispatcher separately before destroying their targets (header contract on `drain`).

---

## 7. Call Flow / Sequence Reference

### 7.1 `schedule()` (success path)

| Step | Actor | Action | Lock state |
|---|---|---|---|
| 1 | Caller | `schedule(delay, cb)` | none |
| 2 | `schedule` | `_accepting.load(acquire)`; if false, return `InvalidTimerId` | none |
| 3 | `schedule` | `id = _nextId.fetch_add(1, relaxed)`; `deadline = now + delay` | none |
| 4 | `schedule` | `lock_guard(_wheelMutex)` | `_wheelMutex` held |
| 5 | `schedule` | `allocEntry()` -> takes/releases `_poolMutex` | `_wheelMutex` + `_poolMutex` nested |
| 6 | `schedule` | populate entry; `insertEntry(entry, delay)`; `_entryMap[id] = entry` | `_wheelMutex` held |
| 7 | `schedule` | lock released on scope exit; return `id` | released |

### 7.2 `schedule()` before `start()` (rejection path)

| Step | Actor | Action | Result |
|---|---|---|---|
| 1 | Caller | `schedule(delay, cb)` | -- |
| 2 | `schedule` | `_accepting.load(acquire)` is false (CREATED/STOPPED/DRAINING/RESET) | returns `InvalidTimerId`, no lock taken, no entry created |

### 7.3 `advance()` (tick, with cascade)

| Step | Actor | Action | Lock state |
|---|---|---|---|
| 1 | Tick thread | `now = Clock::now()` | none |
| 2 | `advance` | `lock_guard(_wheelMutex)` | `_wheelMutex` held |
| 3 | `advance` | compute `ticksToProcess` from `now - _lastAdvanceTime`; set `_lastAdvanceTime = now` | `_wheelMutex` held |
| 4 | `advance` | for each tick: `collectFromBucket(level0 current)` -> `toFire`; `currentTick++` | `_wheelMutex` held |
| 5 | `advance` | on level-0 revolution: `cascadeDown(1, now, toFire)` (recurses on higher revolutions) | `_wheelMutex` held |
| 6 | `advance` | lock released | released |
| 7 | `advance` | `fireCallback(id, cb)` for each in `toFire` (inline or via dispatcher) | **no lock held** |

### 7.4 `drain()` (shutdown, with timeout)

| Step | Actor | Action | Lock state |
|---|---|---|---|
| 1 | Caller | `drain(timeoutMs)` | none |
| 2 | `drain` | `_accepting = false` (release); state `-> DRAINING`; `stopTickThread()` (join) | none |
| 3 | `drain` | `lock_guard(_wheelMutex)`; walk all levels/buckets, move each entry into `entries`, `freeEntry`, clear `_entryMap` | `_wheelMutex` held |
| 3-b | `drain` | sort `entries` by deadline; split: due (`deadline <= now`) -> `toFire`; future -> `toDiscard`, `++cancelled` | `_wheelMutex` held |
| 4 | `drain` | lock released; `toDiscard` destructs off-lock | released |
| 5 | `drain` | fire `toFire` in order; before each, if `elapsed >= timeoutMs`: set `remaining`, state `STOPPED`, return early | no lock held |
| 6 | `drain` | set `elapsed`; state `-> STOPPED`; return `DrainStats` | none |

---

## 8. Thread Safety Model

| Operation | Synchronization | Notes |
|---|---|---|
| `schedule(delay, cb)` | `_wheelMutex`, then `_poolMutex` (nested) | `_accepting` checked lock-free first (`acquire`). `allocEntry()` runs under `_wheelMutex`. Lock order: wheel -> pool. |
| `cancel(id)` | `_wheelMutex`, then `_poolMutex` (nested via `freeEntry`) | Returns `false` if `id` absent. Valid in any state (no `_accepting` gate). |
| `reschedule(id, delay)` | `_wheelMutex` | Unlink + recompute deadline + re-insert. No `_accepting` gate; returns `false` if `id` absent. |
| `advance()` | `_wheelMutex` (collect phase only) | Callbacks fire outside the lock (collect-then-fire). Tick-drift catch-up runs under the same lock. **A concurrent external call is memory-safe (serialized by `_wheelMutex`) but logically double-advances the wheel -- do not call while the tick thread runs.** |
| `pendingCount()` / `getInFlightCount()` | `_wheelMutex` | `getInFlightCount()` is an alias returning `_entryMap.size()`. |
| `drain()` | `_wheelMutex` (collect), `_poolMutex` (freeEntry) | Tick thread stopped first. Firing and `toDiscard` destruction happen off-lock. |
| `stop()` | `_wheelMutex` (via `clearAllEntries`) | Tick thread stopped first; callbacks discarded without firing, destructed off-lock. |
| `reset()` | `_wheelMutex`, then `_poolMutex` (via `drainFreeList`) | Asserts `STOPPED`. Zeroes ticks, drains pool, resets `_nextId`. |
| `start()` | `_wheelMutex` (brief, for `_lastAdvanceTime`) | `compare_exchange_strong` on `_state`; sets `_accepting` (release); spawns tick thread. |
| `setErrorCallback(cb)` | none (`atomic_store` on `shared_ptr`) | Safe from any thread at any time. |
| `tickDuration()` | none | Reads `const _tickDuration`; lock-free by design (scheduling-path consumers must not couple to `_wheelMutex`). |
| `_accepting` / `_running` | atomic, `acquire`/`release` | Advisory gates; the wheel lock provides the actual mutual exclusion for entry state. |
| `_state` | atomic; `seq_cst` CAS in `start()`; `release` store in `drain()`/`stop()`, but `relaxed` store for `reset()`'s terminal transition to `RESET`; `relaxed` load elsewhere | `getState()` and `reset()`'s assert load use `relaxed`. Note `reset()` publishes `RESET` with a `relaxed` (not `release`) store. |
| `_nextId` | atomic, `relaxed` | Monotonic id source; `relaxed` suffices (uniqueness, not ordering). |

**Lock ordering.** Exactly one edge exists: `_wheelMutex -> _poolMutex`. It is honored in `schedule`/`cancel`/`drain`/`clearAllEntries`/`collectFromBucket` (all take `_poolMutex` under `_wheelMutex`); `drainFreeList()` takes `_poolMutex` alone but only when the wheel is stopped, so there is no reverse edge and no cycle.

**Callback re-entry.** `schedule()`, `cancel()`, and `reschedule()` are safe to call from inside a firing callback because `_wheelMutex` is never held during firing.

**Concurrent `advance()` and drain-time race.** Two hazards the header does not guard against, documented here for honesty: (1) calling `advance()` externally while the tick thread runs is memory-safe -- both callers serialize on `_wheelMutex` -- but logically *double-advances* the wheel: the second call computes ~0 elapsed since `_lastAdvanceTime` yet still advances one tick, so timers fire early and the cascade desyncs (`tasks/iora/backlog/2026-09-10-7_timing-wheel-lifecycle-transition-guards_P1.json`); (2) a `schedule()` that passes the `_accepting` check just as `drain()`/`stop()` flips `_accepting` and stops the thread can insert an entry after the drain collection has run -- it is then neither fired nor counted, and is reclaimed only at the next `stop()`/`reset()`/destruction (`tasks/iora/backlog/2026-09-10-6_timing-wheel-schedule-drain-toctou-orphan_P1.json`). Both are noted again in section 12.

---

## 9. Configuration Reference

### 9.1 Constructor parameters

| Parameter | Type | Default | Constraints | Meaning |
|---|---|---|---|---|
| `tickDuration` | `std::chrono::milliseconds` | (required) | must be `> 0` (used as a divisor) | Time per tick; sets resolution. |
| `ticksPerWheel` | `std::size_t` | (required) | power of two, `> 0` (asserted) | Slots per level; capacity multiplier. |
| `numWheels` | `std::size_t` | (required) | `> 0` (asserted) | Number of hierarchical levels. |
| `dispatcher` | `Dispatcher` (`std::function<void(Callback)>`) | `nullptr` | nullable | If set, fired callbacks are routed here instead of running inline. |

### 9.2 Method defaults

| Method | Parameter default |
|---|---|
| `drain(timeoutMs)` | `std::chrono::milliseconds(30000)` |
| `shutdown(timeout)` | `std::chrono::milliseconds(30000)` |

### 9.3 Constants and enums

| Name | Type / Value | Meaning |
|---|---|---|
| `TimerId` | `std::uint64_t` | Opaque timer handle. |
| `InvalidTimerId` | `constexpr TimerId = 0` | Returned by `schedule()` when the wheel is not accepting. |
| `TimingWheelState` | enum: `CREATED`, `RUNNING`, `DRAINING`, `STOPPED`, `RESET` | Lifecycle state (section 4). |

### 9.4 `DrainStats`

| Field | Type | Meaning |
|---|---|---|
| `fired` | `std::size_t` (init 0) | Callbacks invoked (or, with a dispatcher, posted) during drain. |
| `remaining` | `std::size_t` (init 0) | Due timers not fired because the timeout was exceeded mid-drain. |
| `cancelled` | `std::size_t` (init 0) | Future-dated timers discarded without firing. |
| `elapsed` | `std::chrono::milliseconds` (init 0) | Wall-clock duration of the drain. |

There are no runtime-tunable parameters beyond construction; the wheel layout is immutable for a given instance.

---

## 10. API Reference

```cpp
namespace iora
{
namespace core
{

using TimerId = std::uint64_t;
inline constexpr TimerId InvalidTimerId = 0;

enum class TimingWheelState { CREATED, RUNNING, DRAINING, STOPPED, RESET };

struct DrainStats
{
  std::size_t fired = 0;
  std::size_t remaining = 0;
  std::size_t cancelled = 0;
  std::chrono::milliseconds elapsed{0};
};

class ITimerService
{
public:
  virtual ~ITimerService() = default;
  virtual TimerId schedule(std::chrono::milliseconds delay,
                           std::function<void()> callback) = 0;
  virtual bool cancel(TimerId id) = 0;
  virtual bool reschedule(TimerId id, std::chrono::milliseconds newDelay) = 0;
  virtual std::chrono::milliseconds tickDuration() const noexcept;  // default: 0ms (unknown)
};

class TimingWheel
{
public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;
  using Callback = std::function<void()>;
  using ErrorCallback = std::function<void(TimerId, std::exception_ptr)>;
  using Dispatcher = std::function<void(Callback)>;

  TimingWheel(std::chrono::milliseconds tickDuration,
              std::size_t ticksPerWheel,
              std::size_t numWheels,
              Dispatcher dispatcher = nullptr);
  ~TimingWheel();

  TimingWheel(const TimingWheel&) = delete;             // non-copyable
  TimingWheel& operator=(const TimingWheel&) = delete;
  TimingWheel(TimingWheel&&) = delete;                  // non-movable
  TimingWheel& operator=(TimingWheel&&) = delete;

  std::chrono::milliseconds tickDuration() const noexcept;

  // Schedule / cancel / reschedule
  TimerId schedule(std::chrono::milliseconds delay, Callback callback);
  bool cancel(TimerId id);
  bool reschedule(TimerId id, std::chrono::milliseconds newDelay);

  // Advance (public for testing; do NOT call while the tick thread runs)
  std::size_t advance();

  // Lifecycle
  void start();
  DrainStats drain(std::chrono::milliseconds timeoutMs = std::chrono::milliseconds(30000));
  void stop();
  void reset();
  void shutdown(std::chrono::milliseconds timeout = std::chrono::milliseconds(30000));

  // Queries
  TimingWheelState getState() const noexcept;
  std::size_t pendingCount() const;
  std::size_t getInFlightCount() const;   // alias for pendingCount()

  // Error handling
  void setErrorCallback(ErrorCallback cb);
};

class TimingWheelAdapter : public ITimerService
{
public:
  explicit TimingWheelAdapter(TimingWheel& wheel);
  TimerId schedule(std::chrono::milliseconds delay,
                   std::function<void()> callback) override;
  bool cancel(TimerId id) override;
  bool reschedule(TimerId id, std::chrono::milliseconds newDelay) override;
  std::chrono::milliseconds tickDuration() const noexcept override;
};

} // namespace core
} // namespace iora
```

---

## 11. Design Decisions

| Decision | Rationale |
|---|---|
| **Single `_wheelMutex` for all wheel mutations** | Eliminates races between `schedule`/`cancel`/`reschedule`/`advance`. The lock covers only `O(1)`-per-entry pointer work, so contention stays low without per-bucket locking. |
| **Collect-then-fire** | Callbacks run after the lock is released, so they may re-enter `schedule`/`cancel`/`reschedule` (recurring-timer idiom) without deadlock, and slow callbacks never hold the lock. |
| **Separate `_poolMutex`, order `_wheelMutex` -> `_poolMutex`** | Decouples free-list contention from wheel contention; the single documented lock edge prevents ABBA deadlock (the header even allocates under `_wheelMutex` explicitly to avoid it). |
| **Intrusive singly-linked free-list, monotonic growth** | Recycled `TimerEntry`s eliminate per-timer heap churn; the pool empties only on `reset()`/destruction, so steady state is allocation-free. |
| **`callback = nullptr` on free** | Releases captured `shared_ptr`s/strings at free time, not at re-allocation, bounding resource lifetime. |
| **Power-of-two `ticksPerWheel`** | Enables `& _tickMask` in place of modulo on every hot-path index computation; enforced by constructor assert. |
| **Hierarchical wheel with deadline-based cascade** | `O(1)` insert/cancel across a huge dynamic range; cascading by `deadline - now` self-corrects placement even under drift. |
| **Tick-drift catch-up in `advance()`** | Processes all elapsed ticks in one pass so a delayed tick thread does not starve timers. |
| **`drain()` sorts by deadline, cancels the future** | Deterministic, in-order shutdown of due work; future-dated timers are cancelled to avoid firing callbacks at unexpected times (use-after-free risk on targets). |
| **Optional `Dispatcher`, immutable after construction** | Lets slow callbacks run on a pool instead of the tick thread; being `const` removes any synchronization concern for the function object itself. |
| **`setErrorCallback` via atomic `shared_ptr`** | Thread-safe swap with no mutex; one throwing callback can never kill the tick thread. |
| **`condition_variable::wait_for` for the tick sleep** | `stop()`/`drain()` set `_running = false` and `notify_all()`, so the thread wakes immediately for clean shutdown instead of sleeping out the full tick. |
| **`_accepting`/`_running` acquire-release; `_state` CAS** | Advisory gates published with release / observed with acquire; `start()` uses a `compare_exchange_strong` so only one caller wins the `CREATED`/`RESET` -> `RUNNING` transition. |
| **`ITimerService::tickDuration()` non-pure with 0 sentinel** | Keeps 30+ existing implementers source-compatible; a `0` return means "granularity unknown" and consumers must fail closed rather than divide by it. |
| **Non-copyable, non-movable** | The wheel owns a live thread and raw intrusive pointers; consumers hold it by `unique_ptr` (e.g. `KVStore`). |

---

## 12. Known Limitations

- **Maximum schedulable delay is unchecked.** A delay exceeding `ticksPerWheel^numWheels * tickDuration` is masked by `& _tickMask` into an earlier bucket and fires at the wrong (earlier) time. There is no runtime range check or error return -- a silent misfire. For `numWheels >= 2` there is an additional traversal-over-mutated-list hazard: because entries re-insert by *remaining* time, `cascadeDown` can re-insert an over-max-delay entry into the very bucket it is actively traversing, so that entry may be processed more than once in a single pass (theoretical non-termination while `_wheelMutex` is held). Tracked in `tasks/iora/backlog/2026-09-10-1_timing-wheel-insertentry-max-delay-misfire_P0.json` (`insertEntry` computes the top-level index without detecting the wraparound, plus the multi-level cascade hazard).
- **`advance()` is public but not safe under the tick thread.** It is intended for tests. Calling it externally while `start()` has spawned the tick thread is memory-safe -- `_wheelMutex` serializes both callers -- but logically *double-advances* the wheel: the second call computes ~0 elapsed since `_lastAdvanceTime` yet still advances one tick, so timers fire early and the cascade desyncs. There is no internal guard. Tracked (with the `_tickThread` concurrent-lifecycle race and the debug-only `reset()` guard) in `tasks/iora/backlog/2026-09-10-7_timing-wheel-lifecycle-transition-guards_P1.json`.
- **`schedule()` racing `drain()`/`stop()` can orphan a timer.** Because `_accepting` is checked before `_wheelMutex` is taken, a `schedule()` that observes `_accepting == true` immediately before a concurrent `drain()`/`stop()` flips it may insert an entry after the drain/stop collection has run. That entry never fires and is not counted in `DrainStats`; it is reclaimed only at the next `stop()`/`reset()`/destruction. Tracked in `tasks/iora/backlog/2026-09-10-6_timing-wheel-schedule-drain-toctou-orphan_P1.json`.
- **No periodic-timer primitive.** Repeating timers must re-schedule from inside the callback (section 6.2). `TimerEntry::thenReschedule` exists but is explicitly "reserved for future schedulePeriodic support" and is not implemented.
- **`drain()` timeout drops due callbacks silently.** Once the global elapsed time reaches `timeoutMs`, remaining *due* timers are counted in `DrainStats.remaining` but their callbacks are never invoked (they were already unlinked and freed). A single slow callback consumes the budget for those after it.
- **`drain()` completion does not imply dispatched callbacks finished.** With a `Dispatcher`, `drain()` counts callbacks as `fired` when *posted*, not completed. The header requires the caller to drain the dispatcher separately before destroying callback targets.
- **Free-list grows monotonically.** A burst of N timers that all fire leaves N pooled entries resident until `reset()` or destruction; there is no automatic shrink.
- **Tick precision is bounded by `condition_variable::wait_for`.** On hosts with coarse clock/scheduler resolution the actual tick interval jitters by several milliseconds; the wheel is unsuitable for sub-millisecond precision.
- **`reset()` guard is a debug-only `assert`.** Calling `reset()` outside `STOPPED` asserts in debug builds but is undefined behavior under `NDEBUG` (the assert is compiled out). Tracked (with the concurrent-lifecycle `_tickThread` race and the unguarded `advance()`) in `tasks/iora/backlog/2026-09-10-7_timing-wheel-lifecycle-transition-guards_P1.json`.
- **`drain()`/`stop()` have no state guards.** Unlike `start()` (which CAS-guards its transition), `drain()` and `stop()` execute unconditionally from any state -- stopping an already-stopped thread and draining empty buckets are harmless no-ops, but there is no rejection of a misordered call.
- **`atomic_load`/`atomic_store` on `shared_ptr` is deprecated in C++20.** `setErrorCallback` and `fireCallback` use the free-function overloads, deprecated in favor of `std::atomic<std::shared_ptr<T>>`. Correct under C++17 (this project's standard); a forward-compatibility note.
- **This guide documents `TimingWheel` only.** The sibling `core::TimerService` (epoll + `timerfd` + min-heap) is a separate engine; see `docs/core/timer.md`.
