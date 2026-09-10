# Iora ThreadPool -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 2.0 |
| **Date** | 2026-09-10 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/core/thread_pool.hpp` |
| **Compiled unit** | `src/core/iora_core.cpp` (defines the `blockingIoPool()` and `generalAsyncPool()` process-wide singletons, compiled once into `libiora_core.so`) |
| **Namespace** | `iora::core` (internal seam in `iora::core::detail`) |
| **Dependencies** | Standard library only -- `<atomic>`, `<cassert>`, `<chrono>`, `<condition_variable>`, `<exception>`, `<functional>`, `<future>`, `<list>`, `<memory>`, `<mutex>`, `<queue>`, `<thread>`, `<tuple>`, `<type_traits>`, `<unordered_map>`, `<vector>` (and others) -- plus two intra-Iora headers, `iora/core/logger.hpp` (shutdown trace/warning lines) and `iora/common/i_lifecycle_managed.hpp` (the `ILifecycleManaged` base). No external/third-party dependencies. |

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-07 | Original guide, published as `coding_trackers/docs/iora/async_pool.md`, titled *Async Pool (`iora::core::async` / `PooledFuture<R>`)*. Documented `generalAsyncPool()`, `PooledFuture<R>`, `async()` overloads, `detail::submitTo`, `AsyncRejectedError`, and the `HttpClient` retrofit. |
| 2.0 | 2026-09-10 | **Renamed and re-scoped** to `docs/core/thread_pool.md` and re-titled for the class it mirrors, `iora::core::ThreadPool`. The pool class -- worker model, dynamic scaling, the `ILifecycleManaged` lifecycle (`start`/`drain`/`stop`/`reset`), and the five-phase shutdown sequence -- is now the headline; `iora::core::async` / `PooledFuture<R>` remains a prominent section (5) rather than the title. Every claim re-verified against the post-async-pool-rewrite `include/iora/core/thread_pool.hpp` (1368 lines) and the singleton definitions in `src/core/iora_core.cpp`; stale claims from the 1.0 guide corrected against the current source, and every remaining behavioral caveat routed to a concrete backlog tracker under `tasks/iora/backlog/`. Restructured to the 12-section guide template with contiguous numbered sections. |

---

## 1. Executive Summary

### Problem

Iora is a threaded C++17 framework: an HTTP server dispatches request handlers, an HTTP client issues asynchronous calls, name resolution runs blocking `::getaddrinfo` off the event loop, and plugins run background work. Spawning a fresh `std::thread` (or a `std::async` OS thread) per unit of work pays a stack-allocation + TLS-init + join-on-teardown cost on every call, and gives no back-pressure, no bound on concurrency, and no orderly drain at shutdown.

Two distinct needs sit on top of that:

1. **A general worker pool** that accepts both fire-and-forget (`void`) and result-returning callables, grows and shrinks with load, bounds its queue, reports task exceptions, and shuts down cleanly -- the `ThreadPool` class.
2. **A memory-safe `std::async` drop-in.** `std::async(std::launch::async, ...)` carries a guarantee ordinary pool-backed futures do not: per `[futures.async]/5`, the *last* future referring to the async task's shared state blocks in its destructor until the task completes. A `std::future<R>` from a plain `std::packaged_task` has ordinary, non-blocking destruction, so an abandoned pool-backed future lets a worker run the task later against captures (often a raw `this`) that may already be destroyed -- a use-after-free.

### Solution

`include/iora/core/thread_pool.hpp` provides both, with the pool singletons defined once in `src/core/iora_core.cpp`:

- **`iora::core::ThreadPool`** -- a dynamic pool. Threads grow on demand up to `maxSize` and idle threads beyond `initialSize` exit after `idleTimeout`. `enqueue`/`enqueueWithResult`/`tryEnqueue` submit work; the pool implements `iora::common::ILifecycleManaged` (`start`/`drain`/`stop`/`reset`) and a five-phase destructor shutdown that closes a `condition_variable`-destruction race.
- **`iora::core::generalAsyncPool()`** -- a process-wide, immortal, **fixed-size** `ThreadPool&` (`initialSize == maxSize == hardware_concurrency() * 4`) backing `iora::core::async`.
- **`iora::core::blockingIoPool()`** -- a process-wide, immortal, hard-capped, reject-fast `ThreadPool&` (`2 .. 16` workers, `maxQueueSize == 128`) reserved for blocking, uncancellable syscalls (`::getaddrinfo`).
- **`iora::core::PooledFuture<R>`** -- a move-only wrapper around `std::future<R>` whose destructor *and* move-assignment `wait()` on a `valid()` future, replicating `std::async`'s join-on-destruction over a `packaged_task`-backed future.
- **`iora::core::async(...)`** (two overloads) + the internal **`detail::submitTo`** seam -- build a `packaged_task` in place, dispatch onto `generalAsyncPool()`, and return a `PooledFuture<R>`.
- **`iora::core::AsyncRejectedError`** -- a distinct exception carried by the returned future (never thrown at the call site) when the pool cannot accept a task at all.

### Technical Impact

- **Bounded, pre-warmed concurrency.** Work runs on a fixed or bounded worker set instead of an unbounded thread-per-call fan-out; the queue provides back-pressure (`enqueue` throws / `tryEnqueue` returns `false` at `maxQueueSize`).
- **Orderly shutdown.** The five-phase destructor waits for in-flight tasks, barriers on worker exit from `wait_for` (so `_condition` is never destroyed with a thread still parked in it), then joins.
- **Graceful drain.** `ILifecycleManaged` lets a supervisor stop accepting new work, wait for in-flight work with a timeout, then stop and (optionally) reset -- and report `DrainStats`.
- **Memory-safe async.** `iora::core::async` is safe against all four future-abandonment paths via `PooledFuture`, at zero added cost on the consume path.

---

## 2. System Architecture

### 2.1 Component relationships

```
iora::core (thread_pool.hpp / iora_core.cpp)
|
|-- ThreadPool : iora::common::ILifecycleManaged
|   |-- enqueue(F, Args...)                    fire-and-forget (void), internal try/catch -> onTaskError
|   |-- enqueueWithResult(F, Args...)          returns std::future<R> (uses std::bind; lvalue-invoke)
|   |-- tryEnqueue(F, Args...)                  non-throwing; returns false when full/draining/shutdown
|   |-- start() / drain(ms) / stop() / reset()  ILifecycleManaged lifecycle
|   |-- shutdown()                             explicit blocking join (idempotent)
|   |-- getPendingTaskCount / getActiveThreadCount / getTotalThreadCount / getInFlightCount
|   |-- getQueueUtilization / isUnderHighLoad
|   |-- ShutdownMode { IMMEDIATE, GRACEFUL, DETACHED }
|   `-- ~ThreadPool()  ->  phase1..phase5 shutdown sequence
|
|-- blockingIoPool()   -> ThreadPool&   immortal singleton  new ThreadPool(2, 16, 30s, 128)
|-- generalAsyncPool() -> ThreadPool&   immortal singleton  new ThreadPool(hc*4, hc*4, 30s, 1024) [hc==0 -> 4]
|
|-- AsyncRejectedError : std::runtime_error   carried by the future on enqueue rejection
|-- PooledFuture<R>                            move-only wrapper over std::future<R>
|   |-- _future (std::future<R>)               sole data member
|   |-- ~PooledFuture()                        wait() if valid()  (join-on-destruction)
|   `-- operator=(PooledFuture&&)              wait() the OLD future, THEN move in the new one
|-- detail::submitTo(ThreadPool&, F, Args...) -> PooledFuture<R>
|   |-- builds std::packaged_task<R()> IN PLACE (decay-copy tuple + apply + invoke(move...))
|   |-- pool.enqueue([task]{ (*task)(); })
|   `-- on enqueue throw: returns an already-ready PooledFuture carrying AsyncRejectedError
`-- async(F, Args...) / async(std::launch, F, Args...)
    `-- forwards to detail::submitTo(generalAsyncPool(), ...)

Consumers (outside this component; shown for context):
  IoraService::configureThreadPool()   --owns a per-service--> std::unique_ptr<ThreadPool>  (include/iora/iora.hpp)
  HttpClient::getAsync / postJsonAsync  --dispatch via-->       iora::core::async  (include/iora/network/http_client.hpp)
  NameResolver                          --tryEnqueue onto-->    blockingIoPool()   (include/iora/network/name_resolver.hpp)
```

### 2.2 Worker model

`ThreadPool` keeps its workers in a `std::unordered_map<std::thread::id, std::thread> _threads` and its work in a `std::queue<std::function<void()>> _tasks`, both guarded by a single `std::mutex _mutex` with one `std::condition_variable _condition`. Each worker runs the loop in `spawnWorker()`:

1. Under `_mutex`, increment `_waitingThreads`, then `_condition.wait_for(lock, _idleTimeout, pred)` where `pred == (_shutdown || !_tasks.empty())`; decrement `_waitingThreads` on wake.
2. If `wait_for` timed out (returned `false`) and worker-scaling is enabled, atomically claim an exit slot via CAS on `_threadsExited` -- but only if the live worker count would stay `> _initialSize`; on claiming, detach and erase self from `_threads` and return. Otherwise `continue`.
3. If `_shutdown && _tasks.empty()`, increment `_threadsExited` and return.
4. Otherwise pop one task, increment `_busyThreads`, release the lock, increment `_activeThreads`, run the task (catching exceptions into `onTaskError`), **destroy the task functor** (releasing captures) *before* decrementing `_activeThreads`, then decrement `_busyThreads`.

New workers are spawned on demand by `enqueueImpl`/`tryEnqueueImpl` whenever `_threads.size() < _maxSize`, outside the lock.

### 2.3 Data flow -- enqueue then execute

```mermaid
sequenceDiagram
  participant App as Caller thread
  participant Pool as ThreadPool
  participant Q as _tasks (under _mutex)
  participant W as Worker thread

  App->>Pool: enqueue(func, args...)
  Note over Pool: wrap func in a void() lambda<br/>with try/catch -> onTaskError
  Pool->>Q: lock _mutex; check !_shutdown && size < maxQueueSize; _tasks.emplace(task)
  Note over Pool: if _threads.size() < _maxSize: shouldSpawn = true
  Pool->>Pool: unlock; spawnWorker() if shouldSpawn; _condition.notify_one()
  Pool-->>App: return (throws if shutting down / draining / queue full)
  W->>Q: wake from wait_for; lock _mutex; pop task; ++_busyThreads
  W->>W: unlock; ++_activeThreads; task(); destroy task; --_activeThreads; --_busyThreads
```

### 2.4 Threading model (summary)

| Thread | Responsibility |
|---|---|
| Caller / application thread | Calls `enqueue`/`enqueueWithResult`/`tryEnqueue`, the lifecycle methods, and `iora::core::async`; owns any returned `std::future`/`PooledFuture`. |
| Worker thread (`_threads`) | Runs the `spawnWorker` loop: waits on `_condition`, pops and runs tasks, self-exits on idle timeout (when scaling), or exits on shutdown. |
| Thread destroying the pool / calling `shutdown()` / `stop()` | Runs the five-phase shutdown (or the explicit `shutdown()` join loop) and blocks until all workers have exited. |
| First caller of `generalAsyncPool()` / `blockingIoPool()` | Performs the one-time C++11 magic-static construction of that singleton. |

Full detail, lock ordering, and the shutdown race analysis are in section 8.

---

## 3. Component Deep Dive -- `ThreadPool`

### 3.1 Construction

```cpp
ThreadPool(std::size_t initialSize = std::thread::hardware_concurrency(),
           std::size_t maxSize = std::thread::hardware_concurrency() * 4,
           std::chrono::milliseconds idleTimeout = std::chrono::seconds(30),
           std::size_t maxQueueSize = 1024,
           std::function<void(std::exception_ptr)> onTaskError = nullptr,
           ShutdownMode shutdownMode = ShutdownMode::IMMEDIATE);
```

The constructor stores the parameters (`_initialSize`, `_maxSize`, `_idleTimeout`, `_maxQueueSize` are `const`), sets `_accepting = true`, transitions `_lifecycleState` to `Running`, then spawns the initial worker set. Because the private `_workerScaling` flag is `true` (see 3.9), the initial count is `_initialSize`.

`initialSize`, `maxSize`, `idleTimeout`, and `maxQueueSize` all have defaults; the defaults are stated in section 9. Copy and move are deleted -- a pool owns live threads and is neither copyable nor movable.

### 3.2 `enqueue` -- fire-and-forget (`void`)

```cpp
template <typename F, typename... Args> void enqueue(F &&func, Args &&...args);
```

`std::bind`s the callable and arguments, wraps the call in a lambda whose `try/catch(...)` forwards any escaping exception to `onTaskError` (copied under `_configMutex`) or, if no handler is installed, prints `"[ThreadPool] Unhandled exception in void task"` to `std::cerr`. The wrapped lambda is submitted via the private `enqueueImpl`, which:

- throws `std::runtime_error("ThreadPool is draining and not accepting new work")` if `_accepting` is `false`;
- throws `std::runtime_error("ThreadPool is shutting down")` if `_shutdown`;
- throws `std::runtime_error("ThreadPool task queue is full")` if `_tasks.size() >= _maxQueueSize`;
- otherwise emplaces the task, marks `shouldSpawn` if `_threads.size() < _maxSize`, releases the lock, spawns a worker if needed, and notifies one waiter.

### 3.3 `enqueueWithResult` -- value-returning

```cpp
template <typename F, typename... Args>
auto enqueueWithResult(F &&func, Args &&...args)
  -> std::future<std::invoke_result_t<F, Args...>>;
```

Wraps the callable in a `std::make_shared<std::packaged_task<R()>>` (via `std::bind`), captures its `get_future()`, enqueues `[task]{ (*task)(); }`, and returns the future. The task's exception (if any) is captured in the shared state and rethrown from `future.get()` -- it does **not** route through `onTaskError`.

> **Note (move-only arguments).** `enqueueWithResult` computes the result type on the *non-decayed* argument types and binds via `std::bind`, which stores decay-copies but always *lvalue-invokes* them. A move-only argument (e.g. `std::unique_ptr`) cannot be moved out on invocation, and a callable with an rvalue-ref-qualified `operator()` can mis-dispatch. `iora::core::async` (section 5) deliberately bypasses this helper for exactly this reason.

### 3.4 `tryEnqueue` -- non-throwing submission

```cpp
template <typename F, typename... Args> bool tryEnqueue(F &&func, Args &&...args);
```

Same wrapping and exception forwarding as `enqueue`, but returns `false` instead of throwing when the pool is not accepting work, is shutting down, or the queue is full. This is the primitive `NameResolver` uses to apply local back-pressure against `blockingIoPool()`.

### 3.5 Monitoring accessors

| Method | Returns | Lock |
|---|---|---|
| `getPendingTaskCount()` | `_tasks.size()` | `_mutex` |
| `getQueueUtilization()` | `pending / maxQueueSize * 100.0` (0 when `maxQueueSize == 0`) | `_mutex` |
| `getActiveThreadCount()` | `_activeThreads.load()` (tasks currently executing) | atomic |
| `getTotalThreadCount()` | `_threads.size()` | `_mutex` |
| `isUnderHighLoad()` | `getQueueUtilization() > 80.0` | `_mutex` (via `getQueueUtilization`) |
| `getInFlightCount()` | `pending + _activeThreads` (override) | `_mutex` + atomic |

### 3.6 `ShutdownMode`

```cpp
enum class ShutdownMode { IMMEDIATE, GRACEFUL, DETACHED };
```

- **`IMMEDIATE`** (default) -- join workers as soon as their lambda returns; fastest.
- **`GRACEFUL`** -- documented as waiting for pthread cleanup before join (extra latency, avoids a pthread-cleanup race).
- **`DETACHED`** -- detach workers instead of joining; near-instant, but resources leak until the workers exit.

The mode is read/written under `_configMutex` via `getShutdownMode()` / `setShutdownMode(mode)` and consulted only by shutdown **Phase 4** (3.8). Changing the mode while a shutdown is in progress is documented as undefined behavior.

> **Behavioral note.** In the current implementation, `GRACEFUL` and `IMMEDIATE` take the identical join branch in Phase 4 -- both call `movedThread.join()`. Only `DETACHED` diverges (it calls `detach()`). `GRACEFUL`'s documented "wait for pthread cleanup before join" is not a separate code path (the mode is effectively vacuous); tracked in `tasks/iora/backlog/2026-09-10-3_thread-pool-graceful-shutdown-mode-vacuous_P1.json`.

### 3.7 `ILifecycleManaged` lifecycle (`start`/`drain`/`stop`/`reset`)

`ThreadPool` overrides `iora::common::ILifecycleManaged`. The state machine is `Created -> Running -> Draining -> Stopped -> Reset -> Running`, tracked in `std::atomic<LifecycleState> _lifecycleState`.

- **`start()`** -- from `Created` it is a no-op that reports `Running` (the constructor already started the pool). From `Reset` it clears `_shutdown`, sets `_accepting = true`, transitions to `Running`, and re-spawns the initial worker set. Any other state is rejected.
- **`drain(std::uint32_t timeoutMs = 30000)`** -- only valid from `Running`. Transitions to `Draining`, sets `_accepting = false` (new `enqueue` now throws, `tryEnqueue` returns `false`), and polls until `_activeThreads == 0 && pending == 0` or the timeout elapses (a `timeoutMs` of `0` means wait up to one hour). Returns a `LifecycleResult` carrying `DrainStats(inFlightAtStart, remaining, 0, completed)`.
- **`stop()`** -- valid from `Running` or `Draining`. If still `Running`, it drains first (with the default 30 s timeout); then it calls `shutdown()` to join every worker and transitions to `Stopped`.
- **`reset()`** -- only valid from `Stopped`. Clears the task queue and the (already-joined) `_threads` map, zeroes every counter (`_activeThreads`, `_busyThreads`, `_threadsCreated`, `_threadsStarted`, `_threadsExited`, `_waitingThreads`), and transitions to `Reset` so a subsequent `start()` can restart the pool.
- **`getState()`** / **`getInFlightCount()`** -- lock-free-ish observers (the latter takes `_mutex` for the pending count).

### 3.8 The five-phase shutdown (`~ThreadPool`)

The destructor runs five private, unit-testable phases. Each returns a small `ShutdownPhaseNResult` struct (public nested types) recording what it observed:

```mermaid
sequenceDiagram
  participant Dtor as ~ThreadPool
  participant W as Worker threads
  Dtor->>Dtor: Phase 1 -- SignalShutdown: set _shutdown; notify_all()
  Note over Dtor: if already shut down, return early
  Dtor->>W: Phase 2 -- SynchronizationBarrier
  Note over Dtor,W: spin (100us x <=2000) until _waitingThreads==0<br/>AND _threadsExited >= _threadsCreated, then 5ms grace
  Dtor->>W: Phase 3 -- DrainTasks
  Note over Dtor,W: poll (50ms) up to 5000ms until _activeThreads==0 && pending==0
  Dtor->>W: Phase 4 -- JoinThreads
  Note over Dtor,W: per ShutdownMode: join (IMMEDIATE/GRACEFUL) or detach (DETACHED)<br/>move each thread out of _threads under lock, act off-lock
  Dtor->>Dtor: Phase 5 -- Validate: all threads non-joinable && _tasks empty
```

- **Phase 1 -- `shutdownPhase1_SignalShutdown`.** Sets `_shutdown = true` under `_mutex`; `notify_all()`. If already shut down (e.g. an explicit `shutdown()` ran), returns `wasAlreadyShutdown = true` and the destructor returns immediately.
- **Phase 2 -- `shutdownPhase2_SynchronizationBarrier`.** The critical fix: spins (100 us intervals, up to ~200 ms) until `_waitingThreads == 0` **and** `_threadsExited >= _threadsCreated`, plus a 5 ms grace. This is a timeout-bounded best-effort aimed at ensuring no worker is still inside `_condition.wait_for` before `_condition` is destroyed, narrowing the `"double free or corruption (!prev)"` race window (see 8.4 for how Phase 4's `join()` supplies the real guarantee for `_threads`-tracked workers).
- **Phase 3 -- `shutdownPhase3_DrainTasks`.** Polls (50 ms) up to 5000 ms for `_activeThreads == 0 && pending == 0`; records `timedOut` on failure.
- **Phase 4 -- `shutdownPhase4_JoinThreads`.** Reads `ShutdownMode` under `_configMutex`, then repeatedly moves one joinable thread out of `_threads` under `_mutex`, erases the slot, releases the lock, and joins (IMMEDIATE/GRACEFUL) or detaches (DETACHED) the moved-out thread off-lock -- so no thread is joined while `_mutex` is held.
- **Phase 5 -- `shutdownPhase5_Validate`.** Under `_mutex`, checks that every remaining thread is non-joinable and `_tasks` is empty.

### 3.9 The explicit `shutdown()` method

`shutdown()` is a public, idempotent, blocking join callable before destruction (it is also what `stop()` invokes). It sets `_shutdown` under `_mutex`, `notify_all()`s, waits up to 5000 ms for `_activeThreads == 0 && pending == 0` (logging progress every 500 ms), then performs a **"P0-3" double-check**: a 10 ms sleep followed by a re-read of the active/pending counts, and, if a straggler is found, a second bounded wait (up to 1000 ms). Finally it drains `_threads` by moving each joinable thread out under `_mutex` and joining it off-lock. The active-task wait exists so a task accessing objects being torn down cannot outlive them (a use-after-free guard).

### 3.10 Worker-scaling flag (`_workerScaling`)

`_workerScaling` is a private `bool` initialized to `true` with no setter and no constructor parameter, so it is effectively always `true` in production. It gates the initial worker count (`_workerScaling ? _initialSize : _maxSize`, in both the constructor and `start()`) and the idle-exit CAS block in the worker loop. With a fixed-size pool (`initialSize == maxSize`) the idle-exit branch never fires because the CAS refuses to drop the live count to or below `_initialSize`. The `? _maxSize` alternative and the "scaling disabled" behavior are unreachable through the current public API; the dead knob is tracked in `tasks/iora/backlog/2026-09-10-4_thread-pool-dead-canary-scaffolding-and-workerscaling_P1.json`.

---

## 4. Usage Guide -- `ThreadPool`

### 4.1 Fire-and-forget work

```cpp
#include <iora/core/thread_pool.hpp>
#include <atomic>

void example()
{
  iora::core::ThreadPool pool(2, 8, std::chrono::seconds(30), 256);

  std::atomic<int> counter{0};
  pool.enqueue([&counter]() { counter.fetch_add(1); });

  // pool's destructor drains and joins; counter is 1 by the time it returns.
}
```

### 4.2 Result-returning work

```cpp
#include <iora/core/thread_pool.hpp>
#include <future>

void example()
{
  iora::core::ThreadPool pool;                 // header defaults (see section 9)
  std::future<int> f = pool.enqueueWithResult([](int x) { return x * x; }, 7);
  int result = f.get();                        // 49; rethrows the task's exception if it threw
}
```

### 4.3 Back-pressure with `tryEnqueue`

```cpp
#include <iora/core/thread_pool.hpp>

bool submitOrShed(iora::core::ThreadPool &pool)
{
  // Returns false immediately if the queue is full / pool draining / shutting down,
  // instead of throwing. This is how NameResolver rate-limits blockingIoPool().
  return pool.tryEnqueue([]() { /* ... */ });
}
```

### 4.4 Installing a task-exception handler

```cpp
#include <iora/core/thread_pool.hpp>
#include <exception>

void example()
{
  auto onError = [](std::exception_ptr ep)
  {
    try
    {
      if (ep)
      {
        std::rethrow_exception(ep);
      }
    }
    catch (const std::exception &e)
    {
      // log e.what()
    }
  };

  iora::core::ThreadPool pool(2, 8, std::chrono::seconds(30), 256, onError);
  pool.enqueue([]() { throw std::runtime_error("boom"); }); // routed to onError
}
```

> The handler applies to `enqueue`/`tryEnqueue` (void) tasks. Exceptions from `enqueueWithResult` tasks are captured in the future and rethrown from `get()` instead.

### 4.5 Graceful lifecycle (drain then stop)

```cpp
#include <iora/core/thread_pool.hpp>
#include <iora/common/i_lifecycle_managed.hpp>

void example()
{
  iora::core::ThreadPool pool(4, 16);

  // ... submit work ...

  auto drainResult = pool.drain(5000);           // stop accepting; wait up to 5s
  if (!drainResult.success)
  {
    // drainResult.message + drainResult.drainStats describe what remained
  }
  pool.stop();                                    // join all workers; state -> Stopped
}
```

### 4.6 Anti-patterns

| Do | Don't |
|---|---|
| Treat `enqueue` as able to throw (`ThreadPool is shutting down` / `draining` / `queue is full`) and handle it, or use `tryEnqueue`. | Assume `enqueue` always succeeds -- it throws under back-pressure and at shutdown. |
| Consume `enqueueWithResult` futures on a non-worker thread. | Block a worker on another task submitted to the *same* pool -- under saturation that deadlocks a fixed-size pool. |
| Let `onTaskError` handle void-task exceptions; let `get()` surface `enqueueWithResult` exceptions. | Expect `onTaskError` to fire for `enqueueWithResult` tasks -- their exceptions go to the future. |
| Call `stop()` before `reset()`; call `start()` only from `Created`/`Reset`. | Call `reset()`/`drain()` from the wrong lifecycle state -- they return a failed `LifecycleResult`. |
| Pass move-only arguments through `iora::core::async` (section 5). | Pass move-only arguments through `enqueueWithResult` -- `std::bind` lvalue-invokes them. |

---

## 5. `iora::core::async` and `PooledFuture\<R\>` -- the `std::async` drop-in

This section documents the async layer built on top of `ThreadPool`. It is the second reason the header exists and is the primary interface most callers use for one-off asynchronous work.

### 5.1 `generalAsyncPool()` and `blockingIoPool()`

Both are process-wide, immortal (deliberately leaked) `ThreadPool&` singletons *declared* in `thread_pool.hpp` and *defined exactly once* in `src/core/iora_core.cpp`. A header-inlined function-local static would give each `RTLD_LOCAL`-loaded plugin its own copy (and thus its own pool), defeating the "one process-wide pool" guarantee; the cross-`.so` identity test `tests/core/iora_test_async_pool_crossso.cpp` verifies `&generalAsyncPool()` resolves to the same address from a `dlopen`ed plugin and the host.

```cpp
ThreadPool &blockingIoPool()
{
  static ThreadPool *pool = new ThreadPool(2, 16, std::chrono::seconds(30), 128);
  return *pool;
}

ThreadPool &generalAsyncPool()
{
  static ThreadPool *pool = []
  {
    unsigned hc = std::thread::hardware_concurrency();
    if (hc == 0) { hc = 4; }
    return new ThreadPool(hc * 4, hc * 4, std::chrono::seconds(30), 1024);
  }();
  return *pool;
}
```

- **`blockingIoPool()`** -- reserved for blocking, uncancellable syscalls (`::getaddrinfo`) that must never run on an event-loop thread. Hard-capped (`maxSize == 16`) and reject-fast (`NameResolver` uses `tryEnqueue`, so a full `128`-slot queue sheds load rather than blocking). A stuck resolver worker cannot starve unrelated work.
- **`generalAsyncPool()`** -- hosts general, non-blocking async work (HTTP requests today) behind `iora::core::async`. **Fixed-size** (`initialSize == maxSize == hc*4`, `hc` clamped to 4 if 0). The fixed size is load-bearing: it pins `_threads.size()` at `maxSize`, so `enqueueImpl`'s post-commit `spawnWorker()` branch (`_threads.size() < _maxSize`) is dead, making enqueue **all-or-nothing** -- a throw from `enqueue` always means the task was *not* committed. The `hc == 0` clamp is safety-critical: a 0-worker fixed-size pool would never run a task, so a blocking `~PooledFuture` would wait forever.

Immortality (raw `new`, never `delete`d) mirrors the `LoggerData` precedent: an in-flight task at process exit could otherwise hang `ThreadPool`'s join during static destruction. Exit-time memory safety comes from `PooledFuture`'s per-future join, not from the leak.

> The `idleTimeout` of 30 s passed to `generalAsyncPool()` is inert **for the idle-shrink path only**: with `initialSize == maxSize` the idle-exit CAS never fires (section 3.10), so no worker is ever reaped for idleness. The value is not otherwise dead, however -- it is still the `_condition.wait_for` wake interval, so each idle worker wakes every 30 s to re-check the predicate and (finding nothing) loops back to wait again. It affects only that idle re-check cadence, not the pool's steady-state size.

### 5.2 `PooledFuture\<R\>`

```cpp
template <typename R> class PooledFuture
{
public:
  PooledFuture() noexcept = default;
  explicit PooledFuture(std::future<R> future) noexcept : _future(std::move(future)) {}

  PooledFuture(PooledFuture &&) noexcept = default;
  PooledFuture &operator=(PooledFuture &&other) noexcept
  {
    if (this != &other)
    {
      if (_future.valid()) { _future.wait(); }   // JOIN the overwritten future first
      _future = std::move(other._future);
    }
    return *this;
  }

  PooledFuture(const PooledFuture &) = delete;
  PooledFuture &operator=(const PooledFuture &) = delete;

  ~PooledFuture() { if (_future.valid()) { _future.wait(); } }   // join-on-destruction

  R get() { return _future.get(); }
  void wait() const { _future.wait(); }

  template <typename Rep, typename Period>
  std::future_status wait_for(const std::chrono::duration<Rep, Period> &timeout) const;

  template <typename Clock, typename Duration>
  std::future_status wait_until(const std::chrono::time_point<Clock, Duration> &deadline) const;

  bool valid() const noexcept { return _future.valid(); }

private:
  std::future<R> _future;
};
```

**Why a wrapper.** `std::async`'s join-on-destruction is a property of its *shared state*, not of `std::future<R>` as a type; a `packaged_task`-backed `std::future<R>` has ordinary, non-blocking destruction. A true drop-in that also joins on destruction therefore cannot itself be `std::future<R>` -- the guarantee lives in `PooledFuture`'s destructor (and move-assignment).

**Four abandonment paths, one mechanism.** (1) a discarded temporary, (2) store-then-drop, (3) early return / exception unwind, and (4) move-assigning over a still-unconsumed future. The destructor covers (1)-(3); move-assignment covers (4) by `wait()`ing on the current future *before* overwriting it -- a defaulted `= default` move-assign would silently abandon the in-flight task, reopening the use-after-free.

**Consume path costs nothing.** After `get()` (or a move-from), `_future.valid()` is `false`, so both the destructor and move-assign are no-ops. The join cost is paid only by genuinely abandoned futures.

**No `share()`, no implicit `operator std::future\<R\>()`.** Both are intentionally omitted -- either would hand out a bare, non-blocking future and silently defeat the guarantee. Move-only with `noexcept` moves (load-bearing for the strong exception guarantee when relocating a `std::vector<PooledFuture>`).

### 5.3 `detail::submitTo` and `async(...)`

```cpp
namespace detail
{
template <typename F, typename... Args>
auto submitTo(ThreadPool &pool, F &&func, Args &&...args)
  -> PooledFuture<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>;
}

template <typename F, typename... Args>
auto async(F &&func, Args &&...args)
  -> PooledFuture<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>
{ return detail::submitTo(generalAsyncPool(), std::forward<F>(func), std::forward<Args>(args)...); }

template <typename F, typename... Args>
auto async(std::launch policy, F &&func, Args &&...args)
  -> PooledFuture<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>
{
  assert(policy != std::launch::deferred && "iora::core::async cannot honor std::launch::deferred");
  (void)policy;
  return detail::submitTo(generalAsyncPool(), std::forward<F>(func), std::forward<Args>(args)...);
}
```

`submitTo` decay-copies the callable and a `std::tuple` of decayed arguments into a capturing lambda, invokes via `std::apply` + `std::invoke(std::move(func), ...)` (move-invoke parity with `std::async`, unlike `enqueueWithResult`'s `std::bind` lvalue-invoke), wraps it in a `std::make_shared<std::packaged_task<R()>>`, and enqueues `[task]{ (*task)(); }` via `pool.enqueue`. The success return is written **outside** the `try` block: once `enqueue` returns normally the task is committed, so the caller always receives the real, joinable future -- never a synthesized rejection for a task that will run.

**Result type.** `R = std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>` -- the identical decayed-type rule `std::async` uses -- computed once and used for the `packaged_task`, the rejection `promise`, and the returned `PooledFuture`.

**`async(std::launch, ...)` overload.** Accepts the policy for literal call-site symmetry with `std::async` but ignores it (always pool-async). `std::launch::deferred` trips the `assert` in debug and is treated as async in release (never silently dropped or hung).

### 5.4 `AsyncRejectedError` and the reject path

```cpp
class AsyncRejectedError : public std::runtime_error
{
public:
  using std::runtime_error::runtime_error;
};
```

If `pool.enqueue` throws (queue full, draining, or shutting down -- the only three pre-commit throw sites for the fixed-size pool), `submitTo`'s `catch` arms build a fresh `std::promise<R>`, set an `AsyncRejectedError` into it (preserving the `ThreadPool` message when the throw is a `std::exception`, else a fixed fallback message), and return a `PooledFuture<R>` wrapping the already-satisfied exceptional future. The task's callable is never invoked on this path. `AsyncRejectedError` lets a caller distinguish "never attempted" (retry-safe) from "attempted and threw" (any other exception type, propagated verbatim through `get()`).

### 5.5 Usage

```cpp
#include <iora/core/thread_pool.hpp>

int computeSomething(int x) { return x * x; }

void example()
{
  // Same call shape as std::async, but runs on generalAsyncPool() instead of
  // spawning a fresh OS thread per call.
  auto f = iora::core::async(computeSomething, 6);
  int result = f.get(); // 36
}
```

```cpp
#include <iora/core/thread_pool.hpp>
#include <memory>

void moveOnlyArg()
{
  auto owned = std::make_unique<int>(7);
  auto f = iora::core::async([](std::unique_ptr<int> p) { return *p; }, std::move(owned));
  int value = f.get(); // 7 -- move-invoke parity; would fail through std::bind
}
```

```cpp
#include <iora/core/thread_pool.hpp>

void declareThenAssign()
{
  iora::core::PooledFuture<int> f;   // default-constructed, !valid()
  f = iora::core::async([]() { return 11; });
  int v = f.get();                    // 11
}
```

```cpp
#include <iora/network/http_client.hpp>
#include <chrono>

void httpAsync()
{
  // getAsync/postJsonAsync dispatch onto the shared, bounded generalAsyncPool.
  // Both totalRequestTimeout AND leaseAcquireTimeout MUST be finite or the
  // returned future carries AsyncRejectedError instead of running.
  iora::network::HttpClient::Config config;
  config.totalRequestTimeout = std::chrono::milliseconds(5000);
  config.leaseAcquireTimeout = std::chrono::milliseconds(5000);
  iora::network::HttpClient client(config);

  auto future = client.getAsync("http://example.invalid/api");
  auto response = future.get();      // PooledFuture<HttpClient::Response>
}
```

### 5.6 async anti-patterns

- **Do NOT** consume/abandon/move-assign-over a `generalAsyncPool()`-backed `PooledFuture` from *inside* a `generalAsyncPool()` worker -- each blocking operation parks a worker and, on a fixed-size pool, steps toward deadlock. Consume from application threads only.
- **Do NOT** give a `PooledFuture` `static`/`thread_local` storage duration when its task captures non-immortal state -- join-on-destruction only protects a *live* capture from being run against later, not a capture that dies first (same footgun as `std::async`).
- **Do NOT** reach for `share()` or a conversion to `std::future<R>` -- neither exists, deliberately.
- **Do NOT** expect `iora::core::async(std::launch::deferred, f)` to be lazy -- the policy is accepted for symmetry only.

---

## 6. Call Flow / Sequence Reference

### 6.1 `enqueue` success

| Step | Actor | Action |
|---|---|---|
| 1 | Caller | `enqueue(func, args...)`. |
| 2 | `enqueue` | `std::bind`s and wraps in a try/catch lambda; calls `enqueueImpl`. |
| 3 | `enqueueImpl` | Checks `_accepting`; locks `_mutex`; checks `_shutdown` and `_tasks.size() < _maxQueueSize`. |
| 4 | `enqueueImpl` | `_tasks.emplace(task)`; sets `shouldSpawn` if `_threads.size() < _maxSize`. |
| 5 | `enqueueImpl` | Unlocks; `spawnWorker()` if `shouldSpawn`; `_condition.notify_one()`. |
| 6 | Worker | Wakes from `wait_for`; locks; pops task; `++_busyThreads`; unlocks. |
| 7 | Worker | `++_activeThreads`; runs task; destroys task functor; `--_activeThreads`; `--_busyThreads`. |

### 6.2 `iora::core::async(f, args...)` -> `get()`

| Step | Actor | Action |
|---|---|---|
| 1 | Caller | `iora::core::async(f, args...)`. |
| 2 | `async` | Forwards to `detail::submitTo(generalAsyncPool(), f, args...)`. |
| 3 | `generalAsyncPool()` | Returns the process-wide singleton (magic-static construct on first call). |
| 4 | `submitTo` | Decay-copies `f` + `args` into a lambda; wraps in a shared `packaged_task`; grabs `future`. |
| 5 | `submitTo` | `pool.enqueue([task]{ (*task)(); })` inside a `try`. |
| 6 | `submitTo` | On normal return, `return PooledFuture<R>(std::move(future))` -- outside the `try`. |
| 7 | Worker | Dequeues; `(*task)()` runs `f` and stores the result/exception in the shared state. |
| 8 | Caller | `future.get()` blocks until ready; returns the result or rethrows the task exception. |

### 6.3 async enqueue rejection

| Step | Actor | Action |
|---|---|---|
| 1-5 | as 6.2 | but `enqueueImpl` throws pre-commit (`!_accepting`, `_shutdown`, or `_tasks.size() >= _maxQueueSize`). |
| 6 | `submitTo` | `catch (const std::exception&)` (or `catch (...)`) builds `promise<R>`, sets `AsyncRejectedError`. |
| 7 | `submitTo` | Returns a `PooledFuture<R>` wrapping the already-ready exceptional future; task never runs. |
| 8 | Caller | `future.get()` immediately rethrows `AsyncRejectedError` (no blocking). |

### 6.4 Pool destruction (five phases)

| Step | Phase | Action |
|---|---|---|
| 1 | Phase 1 | `_shutdown = true`; `notify_all()`. Early-return if already shut down. |
| 2 | Phase 2 | Barrier: spin until `_waitingThreads == 0 && _threadsExited >= _threadsCreated` (+5 ms grace). |
| 3 | Phase 3 | Poll (50 ms) up to 5000 ms for `_activeThreads == 0 && pending == 0`. |
| 4 | Phase 4 | Per `ShutdownMode`: move each thread out of `_threads` under `_mutex`, then join/detach off-lock. |
| 5 | Phase 5 | Validate all threads non-joinable and `_tasks` empty. |

### 6.5 Graceful drain then stop

| Step | Actor | Action |
|---|---|---|
| 1 | Caller | `drain(timeoutMs)`. |
| 2 | `drain` | `Running -> Draining`; `_accepting = false`; captures `inFlightAtStart`. |
| 3 | `drain` | Polls (50 ms) up to `timeoutMs` (or 1 h if 0) for `_activeThreads == 0 && pending == 0`. |
| 4 | `drain` | Returns `LifecycleResult` with `DrainStats`; `success == false` on timeout. |
| 5 | Caller | `stop()` -> (drains if still Running) -> `shutdown()` join loop -> `Stopped`. |

---

## 7. Lifetime, Drain & Abandonment Safety Invariants

Three mechanisms combine into one teardown-and-async safety contract, each specified in full at its own site and only synthesized here: **(1)** a worker destroys each task functor -- releasing its captures -- *before* decrementing `_activeThreads`, and the join-backed teardown paths then wait for `_activeThreads == 0 && pending == 0` (section 3.8); **(2)** the Phase-2 barrier keeps `_condition` alive until every waiter has left `wait_for`, backstopped by Phase 4's `join()` (section 8.4); and **(3)** `PooledFuture`'s join-on-destruction keeps `iora::core::async` from abandoning a running task (section 5.2). What follows is only what those sections do *not* already say.

**One scope caveat on (1).** "By the time the pool considers itself drained no captured variable is still alive on a worker" holds for the `~ThreadPool` / `shutdown()` / `stop()` paths -- there the Phase-4 `join()` backstops the counter wait, so a worker is confirmed *gone*, not merely *observed idle*. It does **not** hold for the standalone `drain()` lifecycle call, which has no `join()`: `drain()` polls the same counters but can report "drained" during the decrement-then-observe window while a just-popped task is still executing against its captures. A successful `drain()` is therefore not proof that every capture has been released; only the join-backed paths give that. This premature-"drained" / use-after-free quiescence race is tracked in `tasks/iora/backlog/2026-09-09-7_threadpool-drain-quiescence-race-uaf-and-timing-heuristics_P0.json`.

**The one guarantee this component does not give:** it does not bound *how long* a task runs. A hung task occupies its worker indefinitely; on a fixed-size pool that is starvation (section 12). Time-bounding is a caller obligation (`HttpClient` enforces it at its own boundary via finite timeouts). The residual `PooledFuture` caller obligations under (3) -- a capture that dies *before* the wrapper joins; `static`/`thread_local` storage over non-immortal captures; blocking on pooled work *from* a pool worker -- are the same preconditions `std::async` itself imposes (not something the wrapper can detect) and are listed in sections 5.6 and 12.



---

## 8. Thread Safety Model

### 8.1 Synchronization primitives

| Primitive | Name | Guards |
|---|---|---|
| `std::mutex` | `_mutex` (mutable) | `_threads`, `_tasks`, and the `_condition` wait predicate. |
| `std::condition_variable` | `_condition` | Worker wake-up (predicate `_shutdown || !_tasks.empty()`), `_idleTimeout` wait. |
| `std::mutex` | `_configMutex` (mutable) | `_onTaskError` and `_shutdownMode` (read in const methods, hence `mutable`). |
| `std::atomic<bool>` | `_shutdown` | Shutdown-signalled flag (also written under `_mutex` in some paths). |
| `std::atomic<bool>` | `_accepting` | Drain gate; checked lock-free at the top of `enqueueImpl`/`tryEnqueueImpl`. |
| `std::atomic<std::size_t>` | `_activeThreads`, `_busyThreads` | Tasks executing / picked-up; read with `memory_order_acquire` in drain/shutdown. |
| `std::atomic<int>` | `_threadsCreated`, `_threadsStarted`, `_threadsExited`, `_waitingThreads` | Worker lifecycle counters (drive the Phase-2 barrier and the idle-exit CAS). |
| `std::atomic<LifecycleState>` | `_lifecycleState` | `ILifecycleManaged` state, acquire/release. |

### 8.2 Operation-by-operation

| Operation | Synchronization | Notes |
|---|---|---|
| `enqueue` / `tryEnqueue` | lock-free `_accepting` check, then `_mutex` for the queue push + `_threads.size()` check; `spawnWorker()` and `notify_one()` outside the lock | `enqueue` throws under back-pressure; `tryEnqueue` returns `false`. The task functor's own try/catch reads `_onTaskError` under `_configMutex`. |
| `enqueueWithResult` | as `enqueue` (submits `[task]{ (*task)(); }`) | Exception captured in the future, not routed to `onTaskError`. |
| Worker loop | `_mutex` around `wait_for` + queue pop; task **run with no lock held**; task functor destroyed before `--_activeThreads` | The task destroy-before-decrement is the use-after-free guard the shutdown drain relies on. |
| Idle-exit | `_mutex` held; CAS on `_threadsExited`; self-`detach()` + `_threads.erase(self)` under lock | Only when scaling and the live count would stay `> _initialSize`. |
| `shutdown()` | `_mutex` to set `_shutdown` + `notify_all`; polling waits off-lock; join loop moves threads out under `_mutex`, joins off-lock | Idempotent. Includes the P0-3 10 ms re-check. |
| Phase 1-5 (`~ThreadPool`) | see 3.8 | Phase 2 barrier ensures no worker is in `wait_for` before `_condition` is destroyed. |
| `drain` / `stop` / `reset` / `start` | `_lifecycleState` acquire/release; `_mutex` for queue/threads mutation in `reset`/`start` | State-guarded; wrong-state calls return a failed `LifecycleResult`. |
| `PooledFuture` methods | none beyond the delegated `std::future<R>` shared-state synchronization | Each instance owns a distinct future; `~PooledFuture`/move-assign block only the destroying/assigning thread when `valid()`. |
| `detail::submitTo` / `async` | relies on `ThreadPool`'s internal locking for `enqueue` | Header-only templates; no shared mutable state beyond the pool. |

### 8.3 Lock ordering

`_mutex` and `_configMutex` are never held simultaneously in a way that forms a cycle: the worker takes `_configMutex` (to copy `_onTaskError`) only *after* releasing `_mutex` and running the task; Phase 4 takes `_configMutex` (to read `ShutdownMode`) and `_mutex` in disjoint scopes. No user callback runs while `_mutex` is held -- tasks execute after the pop unlocks, and `onTaskError` is invoked from the worker with no pool lock held. Threads are always joined/detached *off* `_mutex` (moved out of the map first). `_condition` is destroyed only after the Phase-2 barrier best-effort-confirms `_waitingThreads == 0` (timeout-bounded; 8.4).

### 8.4 The `condition_variable`-destruction race (why Phase 2 exists)

Destroying a `std::condition_variable` while a thread is still blocked inside its `wait_for` is undefined behavior and manifested as `"double free or corruption (!prev)"` during pthread TLS cleanup. Phase 2 spins on `_waitingThreads` (incremented immediately before `wait_for`, decremented immediately after) and `_threadsExited >= _threadsCreated`, aiming to keep the destructor from proceeding to member teardown while a worker is parked in `_condition`. The barrier is a **timeout-bounded best-effort**, not a proof: the spin runs at most ~200 ms (100 us x 2000) and on timeout *conservatively assumes success* and proceeds. It is what protects a **self-detached** idle-exit worker (which is no longer in `_threads` and so cannot be joined). For threads still tracked in `_threads`, the actual "the worker has left `wait_for` and finished" guarantee is delivered by Phase 4's `join()`, not by the barrier -- the barrier only narrows the window ahead of it.

### 8.5 The enqueue-rejection / all-or-nothing path

`iora::core::async`'s rejection safety depends on `generalAsyncPool()` being fixed-size (section 5.1). For a *general* `ThreadPool` with `initialSize < maxSize`, `enqueueImpl` emplaces the task **before** the possible `spawnWorker()` (which can throw `std::system_error` from `std::thread` construction) -- so an exception can escape after the task is already committed. This is not generically all-or-nothing; a robust `ThreadPool`-level fix is tracked in `tasks/iora/backlog/2026-09-06-11_threadpool-enqueue-all-or-nothing_P2.json`.

### 8.6 Exception propagation

- **`enqueue`/`tryEnqueue` (void):** the task lambda's `try/catch(...)` forwards to `onTaskError` (copied under `_configMutex`) or prints to `std::cerr`; the worker loop has a second identical catch as a backstop.
- **`enqueueWithResult`:** the `packaged_task` stores the exception; it rethrows from `std::future<R>::get()`.
- **`iora::core::async`:** a task exception is stored in the shared state and rethrown from `PooledFuture::get()`; an *enqueue* rejection is delivered as an `AsyncRejectedError`-carrying already-ready future (never thrown at the call site).

---

## 9. Configuration Reference

There is no runtime/env-var configuration; sizing is fixed at construction. **Defaults below are cited from the header's constructor signature** (`include/iora/core/thread_pool.hpp`), which is authoritative.

### 9.1 `ThreadPool` constructor defaults (from the header)

| Parameter | Type | Default (header) | Meaning |
|---|---|---|---|
| `initialSize` | `std::size_t` | `std::thread::hardware_concurrency()` | Minimum worker count, always maintained. |
| `maxSize` | `std::size_t` | `std::thread::hardware_concurrency() * 4` | Hard cap on workers. |
| `idleTimeout` | `std::chrono::milliseconds` | `std::chrono::seconds(30)` | Idle duration after which a worker beyond `initialSize` may exit. |
| `maxQueueSize` | `std::size_t` | `1024` | Queued-task cap; `enqueue` throws / `tryEnqueue` returns `false` at this bound. |
| `onTaskError` | `std::function<void(std::exception_ptr)>` | `nullptr` | Optional handler for uncaught void-task exceptions. |
| `shutdownMode` | `ShutdownMode` | `ShutdownMode::IMMEDIATE` | Join / graceful / detach at shutdown. |

> **Divergence to be aware of (not a header default).** `IoraService` constructs its *own* per-service `ThreadPool` with different fallbacks -- `minThreads = 1`, `maxThreads = hardware_concurrency()` (or `4` if `0`), `queueSize = maxThreads * 2`, `idleTimeout = 60 s` -- and `src/iora.cpp`'s `--help` text hand-duplicates *those* values (`--threadpool-min` default `1`, `--threadpool-max` default "hardware concurrency, or 4", `--threadpool-queue` default "2 x max threads", `--threadpool-idle-timeout` default `60`). These are `IoraService`'s policy defaults, **not** the `ThreadPool` constructor defaults in the table above; the two sets do not match. When documenting or reasoning about a bare `ThreadPool`, use the header table; when reasoning about the framework-owned pool, use `IoraService`'s values.

### 9.2 The immortal singletons (`src/core/iora_core.cpp`)

| Singleton | `initialSize` | `maxSize` | `idleTimeout` | `maxQueueSize` | Purpose |
|---|---|---|---|---|---|
| `blockingIoPool()` | `2` | `16` | `30 s` | `128` | Blocking, uncancellable syscalls (`::getaddrinfo`); reject-fast via `tryEnqueue`. |
| `generalAsyncPool()` | `hc * 4` (`hc = hardware_concurrency()`, clamped to `4` if `0`) | same as `initialSize` (fixed-size) | `30 s` (idle-shrink inert; still the `wait_for` wake interval -- see 5.1) | `1024` | Backs `iora::core::async`. Fixed size is load-bearing for all-or-nothing enqueue. |

Neither pool installs an `onTaskError` handler or overrides `ShutdownMode` (both use `ThreadPool`'s defaults), and neither is ever destroyed (immortal by design).

### 9.3 Tests and build gating

`ThreadPool` and the async layer are exercised by (test target names / source under `tests/core/`):

| Target | Source | Coverage |
|---|---|---|
| `iora_test_threadpool` | `iora_test_threadpool.cpp` | Basic execution, futures, scaling up/down, queue overflow, exception handling (with/without handler), destruction-completes-pending, rapid enqueue+shutdown, back-pressure. |
| `iora_test_threadpool_lifecycle` | `iora_test_threadpool_lifecycle.cpp` | `start`/`drain`/`stop`/`reset` transitions, drain timeout/stats, `getInFlightCount`, full cycle, `tryEnqueue` vs drain. |
| `iora_test_threadpool_cleanup` | `iora_test_threadpool_cleanup.cpp` | Idle-timeout shrink, no-zombie-threads, concurrent idle timeouts, counters-match-map, `_initialSize` floor, scaling-disabled, leak stress. |
| `iora_test_async_pool` | `iora_test_async_pool.cpp` | `async` value/void/move-only, `PooledFuture` join/move-assign/default-then-assign, reject-when-full, task-exception vs `AsyncRejectedError`, launch-policy overload, `wait_for`/`wait_until`. |
| `iora_test_async_pool_crossso` | `iora_test_async_pool_crossso.cpp` (+ `core_test_async_pool_plugin`) | `&generalAsyncPool()` identity across an `RTLD_LOCAL` plugin boundary. |

Run with `ctest -j1` (the repository-wide port/parallelism convention). For sanitizer runs, prefix `setarch $(uname -m) -R`.

---

## 10. API Reference

```cpp
namespace iora
{
namespace core
{

class ThreadPool : public iora::common::ILifecycleManaged
{
public:
  enum class ShutdownMode { IMMEDIATE, GRACEFUL, DETACHED };

  // Public shutdown-phase result structs (unit-test hooks):
  struct ShutdownPhase1Result { bool wasAlreadyShutdown; bool success; };
  struct ShutdownPhase2Result { bool allThreadsAcknowledged; int waitTimeMs; bool success; };
  struct ShutdownPhase3Result { std::size_t finalActiveCount; std::size_t finalPendingCount;
                                int drainTimeMs; bool timedOut; bool success; };
  struct ShutdownPhase4Result { int threadsJoined; bool success; };
  struct ShutdownPhase5Result { bool allThreadsDestroyed; bool queueEmpty; bool success; };

  ThreadPool(std::size_t initialSize = std::thread::hardware_concurrency(),
             std::size_t maxSize = std::thread::hardware_concurrency() * 4,
             std::chrono::milliseconds idleTimeout = std::chrono::seconds(30),
             std::size_t maxQueueSize = 1024,
             std::function<void(std::exception_ptr)> onTaskError = nullptr,
             ShutdownMode shutdownMode = ShutdownMode::IMMEDIATE);
  ~ThreadPool();

  ThreadPool(const ThreadPool &) = delete;
  ThreadPool &operator=(const ThreadPool &) = delete;
  ThreadPool(ThreadPool &&) = delete;
  ThreadPool &operator=(ThreadPool &&) = delete;

  // Submission
  template <typename F, typename... Args> void enqueue(F &&func, Args &&...args);
  template <typename F, typename... Args>
  auto enqueueWithResult(F &&func, Args &&...args) -> std::future<std::invoke_result_t<F, Args...>>;
  template <typename F, typename... Args> bool tryEnqueue(F &&func, Args &&...args);

  // Monitoring
  std::size_t getPendingTaskCount() const;
  double      getQueueUtilization() const;      // 0..100
  std::size_t getActiveThreadCount() const;
  std::size_t getTotalThreadCount() const;
  bool        isUnderHighLoad() const;          // utilization > 80%

  // Shutdown mode
  void         setShutdownMode(ShutdownMode mode);
  ShutdownMode getShutdownMode() const;

  // Explicit blocking shutdown (idempotent)
  void shutdown();

  // ILifecycleManaged
  iora::common::LifecycleResult start() override;
  iora::common::LifecycleResult drain(std::uint32_t timeoutMs = 30000) override;
  iora::common::LifecycleResult stop() override;
  iora::common::LifecycleResult reset() override;
  iora::common::LifecycleState  getState() const override;
  std::uint32_t                 getInFlightCount() const override;   // pending + active
};

// ---- Process-wide immortal pools (declared here, defined in src/core/iora_core.cpp) ----
ThreadPool &blockingIoPool();     // 2..16 workers, queue 128; blocking uncancellable syscalls
ThreadPool &generalAsyncPool();   // fixed hc*4 workers, queue 1024; backs iora::core::async

// ---- Async drop-in ----
class AsyncRejectedError : public std::runtime_error
{
public:
  using std::runtime_error::runtime_error;
};

template <typename R> class PooledFuture
{
public:
  PooledFuture() noexcept;
  explicit PooledFuture(std::future<R> future) noexcept;
  PooledFuture(PooledFuture &&) noexcept;
  PooledFuture &operator=(PooledFuture &&other) noexcept;   // joins the overwritten future first
  PooledFuture(const PooledFuture &) = delete;
  PooledFuture &operator=(const PooledFuture &) = delete;
  ~PooledFuture();                                          // joins if valid()

  R    get();
  void wait() const;
  template <typename Rep, typename Period>
  std::future_status wait_for(const std::chrono::duration<Rep, Period> &timeout) const;
  template <typename Clock, typename Duration>
  std::future_status wait_until(const std::chrono::time_point<Clock, Duration> &deadline) const;
  bool valid() const noexcept;
};

namespace detail
{
template <typename F, typename... Args>
auto submitTo(ThreadPool &pool, F &&func, Args &&...args)
  -> PooledFuture<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>;
} // namespace detail

// std::async(std::launch::async, ...) drop-in, dispatched onto generalAsyncPool().
template <typename F, typename... Args>
auto async(F &&func, Args &&...args)
  -> PooledFuture<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>;

// std::launch-accepting overload; policy accepted for symmetry but ignored;
// std::launch::deferred asserts in debug, runs async in release.
template <typename F, typename... Args>
auto async(std::launch policy, F &&func, Args &&...args)
  -> PooledFuture<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>;

} // namespace core
} // namespace iora
```

---

## 11. Design Decisions

| ID | Decision | Rationale |
|---|---|---|
| DP-1 | One `std::mutex` + one `std::condition_variable` guard both `_threads` and `_tasks`. | A single monitor keeps the wake predicate (`_shutdown || !_tasks.empty()`) and the spawn/queue checks coherent without lock-ordering hazards. |
| DP-2 | Five-phase destructor with an explicit `_waitingThreads`/`_threadsExited` barrier (Phase 2). | Destroying `_condition` with a worker still in `wait_for` is UB (`"double free or corruption (!prev)"`). The Phase-2 barrier is a timeout-bounded best-effort that narrows the window (and is what covers a self-detached idle-exit worker); for `_threads`-tracked workers the actual guarantee comes from Phase 4's `join()`. See 8.4. |
| DP-3 | Task functor destroyed *before* `--_activeThreads`; `shutdown()` waits for `_activeThreads == 0`. | A task's captured state must not outlive the objects it references during teardown -- prevents a use-after-free at shutdown. |
| DP-4 | Idle-exit uses a CAS on `_threadsExited` guarded by `> _initialSize`, and the worker detaches + erases *itself*. | Prevents multiple idle workers racing below `_initialSize`, and avoids the destructor joining a self-cleaned thread (an earlier `detach()`/`erase()` from the destructor side caused heap corruption). |
| DP-5 | `enqueue`/`tryEnqueue` are the only submission paths; `enqueue` throws under back-pressure while `tryEnqueue` returns `false`. | Callers choose fail-loud vs shed-load; `NameResolver` needs non-throwing back-pressure against `blockingIoPool()`. |
| DP-6 | `ILifecycleManaged` (`start`/`drain`/`stop`/`reset` + `DrainStats`). | Lets a supervisor stop intake, wait out in-flight work with a timeout, and restart -- graceful lifecycle beyond a bare destructor. |
| DP-7 | `generalAsyncPool()` is fixed-size (`initialSize == maxSize`). | Load-bearing for correctness: pins the worker count so `enqueue` never spawns post-commit, making enqueue all-or-nothing -- which lets `submitTo` synthesize a rejection future without orphaning a committed task. |
| DP-8 | `generalAsyncPool()` / `blockingIoPool()` are immortal, deliberately leaked singletons defined once in `iora_core.cpp`. | Avoids a join-hang at process exit; a header-inline static would fork one pool per `RTLD_LOCAL` plugin, breaking the process-wide-pool guarantee. |
| DP-9 | `hc == 0` clamped to `4` in `generalAsyncPool()`. | A 0-worker fixed-size pool would never run a task, hanging any blocking `~PooledFuture` forever. |
| DP-10 | `PooledFuture<R>` wrapper instead of returning `std::future<R>`. | `std::async`'s join-on-destruction lives in the *shared state*, unexpressible as a plain `packaged_task`-backed `std::future<R>`; abandoning one would run the task against destroyed captures. |
| DP-11 | `PooledFuture` move-assignment joins the overwritten future before replacing it; no `share()`, no implicit `std::future<R>` conversion. | A defaulted move-assign or a handed-out bare future would silently reopen the abandonment use-after-free. |
| DP-12 | `submitTo` builds the `packaged_task` in place (decay-copy + `std::apply` + `std::invoke(std::move(func), ...)`) instead of `enqueueWithResult`. | `enqueueWithResult` uses a non-decayed result type and `std::bind` lvalue-invoke, which breaks move-only arguments and ref-qualified callables. |
| DP-13 | Enqueue rejection returns an already-ready `AsyncRejectedError` future rather than throwing at the call site; distinct exception type. | Matches `std::async`'s contract (the call does not throw) and lets callers distinguish "never attempted" (retry-safe) from "attempted and threw". |
| DP-14 | `async(std::launch, ...)` accepts but ignores the policy; `deferred` asserts in debug. | Preserves literal `s/std::async/iora::core::async/` migration without misrepresenting lazy-evaluation semantics the pool cannot provide. |

---

## 12. Known Limitations

- **`ThreadPool` enqueue is not *generically* all-or-nothing.** For a scaling pool (`initialSize < maxSize`), `enqueueImpl` commits the task to `_tasks` *before* a possible post-commit `spawnWorker()` that can throw `std::system_error`. `generalAsyncPool()` sidesteps this by being fixed-size; a `ThreadPool`-level fix (making a scaling spawn failure non-fatal to an already-committed enqueue) is tracked separately (`tasks/iora/backlog/2026-09-06-11_threadpool-enqueue-all-or-nothing_P2.json`).
- **Default-constructed `ThreadPool` is zero-worker when `hardware_concurrency() == 0`.** The header defaults `initialSize = hardware_concurrency()` and `maxSize = hardware_concurrency() * 4`; when the platform reports `0`, the pool starts with 0 workers and, because `enqueueImpl` only spawns while `_threads.size() < _maxSize == 0`, never spawns one -- tasks are queued and never run. `generalAsyncPool()` guards this locally (`hc == 0 -> 4`); the shared-header root fix is tracked (`tasks/iora/backlog/2026-09-06-10_threadpool-zero-worker-hardware-concurrency_P1.json`).
- **`ShutdownMode::GRACEFUL` is not a distinct code path.** Phase 4 takes the identical `join()` branch for `IMMEDIATE` and `GRACEFUL`; only `DETACHED` diverges. The documented "wait for pthread cleanup before join" behavior is not implemented (tracked in `tasks/iora/backlog/2026-09-10-3_thread-pool-graceful-shutdown-mode-vacuous_P1.json`).
- **`_workerScaling` is a dead configuration knob.** It is hard-coded `true` with no setter or constructor parameter, so the `? _maxSize` branch and the "scaling disabled" mode are unreachable through the public API. A cleanup pool test explicitly notes "`_workerScaling` is not configurable at runtime." Tracked in `tasks/iora/backlog/2026-09-10-4_thread-pool-dead-canary-scaffolding-and-workerscaling_P1.json`.
- **Timing-based shutdown/drain waits.** `shutdown()`, `drain()`, and Phase 2/3 use bounded polling with fixed sleeps (a 10 ms P0-3 re-check, 50 ms drain polls, 100 us barrier spins). On a badly overloaded host a straggling task can still exceed the 5000 ms drain cap, in which case shutdown "proceeds anyway" with a logged warning; correctness then depends on DP-3's task-functor-destroy-before-decrement rather than on the wait completing.
- **Leftover corruption-detection instrumentation in the worker hot loop.** Each worker carries a `volatile uint32_t canary` and a `VALIDATE_CANARY()` macro that `std::abort()`s on mismatch, threaded through the loop. This is debugging scaffolding, not a functional guard (the canary can only change under prior UB); tracked, together with the dead `_workerScaling` knob, in `tasks/iora/backlog/2026-09-10-4_thread-pool-dead-canary-scaffolding-and-workerscaling_P1.json`.
- **Shared-pool starvation for `generalAsyncPool()` consumers.** One process-wide pool of `hardware_concurrency() * 4` workers serves `libiora_core.so` and every plugin; a slow/hung consumer can occupy all workers and (past 1024 queued) cause `AsyncRejectedError` for unrelated work. Mitigated at the `HttpClient` boundary by its finite-timeout gate; any *other* `iora::core::async` consumer must independently keep its work time-bounded (not enforced by the pool).
- **DP-8 blocking-from-a-worker deadlock is documented, not enforced.** A callable running on a `generalAsyncPool()` worker that blocks on another pooled `PooledFuture` (`get`/`wait`/abandon/move-assign-over) can deadlock the fixed-size pool under saturation. Nothing checks this at runtime.
- **`PooledFuture` cannot protect a capture that dies before it joins.** Join-on-destruction only protects a live capture from a later run, not a capture (e.g. raw `this`) whose lifetime already ended -- the same footgun `std::async` has.
- **No runtime/env-var pool tuning.** All sizing is fixed at construction (and, for the singletons, at compile time in `iora_core.cpp`). Changing it requires a source edit and rebuild (deliberate, YAGNI).
</content>
</invoke>
