// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <exception>
#include <functional>
#include <future>
#include <iostream>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <iora/core/logger.hpp>
#include <iora/common/i_lifecycle_managed.hpp>

namespace iora
{
namespace core
{

namespace detail
{
/// Empty base for the production thread pool: the test seam contributes zero
/// bytes (empty-base optimization) and zero hot-path cost.
struct ThreadPoolNoSeam
{
};

/// Test-only park-point state. Present ONLY in the ThreadPoolT<true>
/// instantiation used by the drain-quiescence regression test: it lets a worker
/// be parked in the window between releasing _mutex after popping a task and
/// incrementing _activeThreads, reproducing the busy-but-not-active state the
/// quiescence gate must observe. Never instantiated in production
/// (ThreadPoolT<false> uses ThreadPoolNoSeam).
struct ThreadPoolTestSeam
{
  std::atomic<bool> armed{false};    ///< One-shot: park the next worker at the seam.
  std::atomic<bool> parked{false};   ///< A worker is currently parked at the seam.
  std::atomic<bool> release{false};  ///< Release the parked worker.
};
} // namespace detail

/// A dynamic thread pool that accepts void or result-returning lambdas with
/// arbitrary arguments. Threads grow and shrink based on load and idle
/// timeout. Exceptions in tasks can be reported.
///
/// Implements ILifecycleManaged for graceful shutdown and reset capabilities.
///
/// \tparam EnableTestSeam Compile-time flag that adds a test-only park point in
///   the worker loop (see detail::ThreadPoolTestSeam). Defaults to false; the
///   `ThreadPool` alias below pins it to false so production code and every
///   consumer see an ordinary class. Tests instantiate ThreadPoolT<true>.
template <bool EnableTestSeam = false>
class ThreadPoolT
  : public iora::common::ILifecycleManaged,
    private std::conditional_t<EnableTestSeam, detail::ThreadPoolTestSeam,
                               detail::ThreadPoolNoSeam>
{
public:
  // ═══════════════════════════════════════════════════════════════════
  // Shutdown Phase Result Structures
  // ═══════════════════════════════════════════════════════════════════

  /// Result of Phase 1: Signal Shutdown
  struct ShutdownPhase1Result
  {
    bool wasAlreadyShutdown;  ///< True if shutdown was already signaled
    bool success;              ///< True if phase completed successfully

    ShutdownPhase1Result() : wasAlreadyShutdown(false), success(false) {}
  };

  /// Result of Phase 2: Synchronization Barrier
  struct ShutdownPhase2Result
  {
    bool allThreadsAcknowledged;  ///< True if all threads exited wait_for()
    int waitTimeMs;               ///< Time spent waiting (milliseconds)
    bool success;                 ///< True if phase completed successfully

    ShutdownPhase2Result() : allThreadsAcknowledged(false), waitTimeMs(0), success(false) {}
  };

  /// Result of Phase 3: Drain Tasks
  struct ShutdownPhase3Result
  {
    std::size_t finalActiveCount;   ///< Final active thread count
    std::size_t finalPendingCount;  ///< Final pending task count
    int drainTimeMs;                ///< Time spent draining (milliseconds)
    bool timedOut;                  ///< True if drain timed out
    bool success;                   ///< True if phase completed successfully

    ShutdownPhase3Result()
      : finalActiveCount(0), finalPendingCount(0), drainTimeMs(0),
        timedOut(false), success(false) {}
  };

  /// Result of Phase 4: Join Threads
  struct ShutdownPhase4Result
  {
    int threadsJoined;  ///< Number of threads successfully joined
    bool success;       ///< True if phase completed successfully

    ShutdownPhase4Result() : threadsJoined(0), success(false) {}
  };

  /// Result of Phase 5: Validate Final State
  struct ShutdownPhase5Result
  {
    bool allThreadsDestroyed;  ///< True if all threads are non-joinable
    bool queueEmpty;           ///< True if task queue is empty
    bool success;              ///< True if validation passed

    ShutdownPhase5Result()
      : allThreadsDestroyed(false), queueEmpty(false), success(false) {}
  };

  /// Shutdown mode for controlling thread lifecycle management
  enum class ShutdownMode
  {
    /// IMMEDIATE: Join every worker once it returns (the default).
    /// - Fast shutdown (10-50ms).
    /// - The pthread-cleanup race is NOT a risk of this mode: teardown safety
    ///   comes from the mode-independent drain+join (waitForQuiescence then
    ///   join), NOT from any per-mode behavior; the destructor's Phase-2
    ///   synchronization barrier is only a best-effort backstop.
    /// - Default: YES.
    IMMEDIATE,

    /// DETACHED: Detach threads instead of joining
    /// - Instant shutdown (<1ms)
    /// - Warning: Resources leaked until threads exit
    /// - Use: Emergency shutdown, testing only
    /// - Default: NO
    DETACHED
  };

public:
  /// Constructs the thread pool.
  ///
  /// @param initialSize       Minimum number of threads (always maintained).
  /// @param maxSize           Maximum number of threads (hard limit).
  /// @param idleTimeout       Duration after which idle threads beyond
  /// initial count will exit.
  /// @param maxQueueSize      Maximum number of queued tasks before enqueue
  /// throws.
  /// @param onTaskError       Optional handler for uncaught exceptions in
  /// tasks.
  /// @param shutdownMode      Shutdown mode (IMMEDIATE, DETACHED).
  /// Default: IMMEDIATE (backward compatible).
  ThreadPoolT(std::size_t initialSize = std::thread::hardware_concurrency(),
              std::size_t maxSize = std::thread::hardware_concurrency() * 4,
              std::chrono::milliseconds idleTimeout = std::chrono::seconds(30),
              std::size_t maxQueueSize = 1024,
              std::function<void(std::exception_ptr)> onTaskError = nullptr,
              ShutdownMode shutdownMode = ShutdownMode::IMMEDIATE)
      : _initialSize(clampInitial(initialSize)),
        _maxSize(maxSize >= _initialSize ? maxSize : _initialSize),
        _idleTimeout(idleTimeout),
        _maxQueueSize(maxQueueSize), _shutdown(false), _activeThreads(0), _busyThreads(0),
        _onTaskError(std::move(onTaskError)), _shutdownMode(shutdownMode)
  {
    // Start accepting work and transition to Running state
    _accepting.store(true, std::memory_order_release);
    _lifecycleState.store(iora::common::LifecycleState::Running, std::memory_order_release);

    for (std::size_t i = 0; i < _initialSize; ++i)
    {
      spawnWorker();
    }
  }

  ~ThreadPoolT()
  {
    // Execute shutdown sequence using phased methods

    // Phase 1: Signal Shutdown
    auto phase1 = shutdownPhase1_SignalShutdown();
    if (phase1.wasAlreadyShutdown)
    {
      return;
    }

    // Phase 2: Synchronization Barrier
    // CRITICAL FIX: This prevents the "double free or corruption (!prev)" race condition
    shutdownPhase2_SynchronizationBarrier();

    // Phase 3: Drain Tasks
    shutdownPhase3_DrainTasks();

    // Phase 4: Join Threads
    shutdownPhase4_JoinThreads();

    // Phase 5: Validate
    shutdownPhase5_Validate();
  }

  ThreadPoolT(const ThreadPoolT &) = delete;
  ThreadPoolT &operator=(const ThreadPoolT &) = delete;
  ThreadPoolT(ThreadPoolT &&) = delete;
  ThreadPoolT &operator=(ThreadPoolT &&) = delete;

  /// Enqueue a fire-and-forget task (void-returning) with arguments.
  template <typename F, typename... Args> void enqueue(F &&func, Args &&...args)
  {
    // Avoid std::packaged_task<void()>
    auto bound = std::bind(std::forward<F>(func), std::forward<Args>(args)...);
    enqueueImpl(
      [bound = std::move(bound), this]()
      {
        try
        {
          bound(); // if this throws, catch below
        }
        catch (...)
        {
          reportTaskException(std::current_exception(), "void task");
        }
      });
  }

  /// Enqueue a task that returns a value and get a future for it.
  template <typename F, typename... Args>
  auto enqueueWithResult(F &&func, Args &&...args) -> std::future<std::invoke_result_t<F, Args...>>
  {
    using ResultType = std::invoke_result_t<F, Args...>;
    auto task = std::make_shared<std::packaged_task<ResultType()>>(
      std::bind(std::forward<F>(func), std::forward<Args>(args)...));
    auto future = task->get_future();
    enqueueImpl([task]() { (*task)(); });
    return future;
  }

  /// Get the number of pending tasks in the queue.
  std::size_t getPendingTaskCount() const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    return _tasks.size();
  }

  /// Get queue utilization as a percentage (0-100).
  double getQueueUtilization() const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    return _maxQueueSize > 0 ? (static_cast<double>(_tasks.size()) / _maxQueueSize) * 100.0 : 0.0;
  }

  /// Get the number of active worker threads.
  std::size_t getActiveThreadCount() const { return _activeThreads.load(); }

  /// Get the total number of worker threads.
  std::size_t getTotalThreadCount() const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    return _threads.size();
  }

  /// Check if the thread pool is under high load (queue > 80% capacity).
  bool isUnderHighLoad() const { return getQueueUtilization() > 80.0; }

  /// Set the shutdown mode (can be changed at runtime)
  /// @param mode The desired shutdown mode
  /// @warning Changing mode while threads are shutting down may cause undefined behavior
  void setShutdownMode(ShutdownMode mode)
  {
    std::lock_guard<std::mutex> lock(_configMutex);
    _shutdownMode = mode;
  }

  /// Get the current shutdown mode
  /// @return The current shutdown mode
  ShutdownMode getShutdownMode() const
  {
    std::lock_guard<std::mutex> lock(_configMutex);
    return _shutdownMode;
  }

  /// Shutdown the thread pool and wait for all threads to complete.
  /// This is a blocking call that ensures all worker threads have fully exited.
  /// Call this explicitly before destroying the pool to ensure clean shutdown.
  void shutdown()
  {
    iora::core::Logger::debug("ThreadPool::shutdown() - Starting explicit shutdown");
    {
      std::unique_lock<std::mutex> lock(_mutex);
      if (_shutdown)
      {
        iora::core::Logger::debug("ThreadPool::shutdown() - Already shut down");
        return; // Already shut down
      }
      _shutdown = true;
    }
    _condition.notify_all();

    // Wait for all in-flight work to complete BEFORE joining threads. This
    // prevents use-after-free when a task accesses objects being torn down.
    // The gate is the accurate single-critical-section getInFlightCount()==0 read
    // (queue depth + _busyThreads under one lock); with that primary predicate the
    // former P0-3 "sleep 10ms then re-check" race window is redundant and has been
    // removed. shutdown()'s join below is safe by construction.
    iora::core::Logger::debug("ThreadPool::shutdown() - Waiting for in-flight tasks to complete...");
    if (!waitForQuiescence(5000))
    {
      iora::core::Logger::warning("ThreadPool::shutdown() - Task completion timeout after "
                                  "5000ms - proceeding anyway");
    }

    // P0-CRITICAL FIX: Join threads directly in the map without moving or erasing
    // After join() completes, the thread object becomes non-joinable but remains safe in the map.
    // The _threads map will be destroyed via RAII when shutdown() completes or destructor runs.
    iora::core::Logger::debug("ThreadPool::shutdown() - Waiting for all threads to exit");

    int joinCount = 0;
    while (true)
    {
      std::thread movedThread;
      std::thread::id threadId;
      bool found = false;

      {
        std::lock_guard<std::mutex> lock(_mutex);

        for (auto it = _threads.begin(); it != _threads.end(); ++it)
        {
          if (it->second.joinable())
          {
            // Move the thread out of the map and erase the entry under lock.
            movedThread = std::move(it->second);
            threadId = it->first;
            _threads.erase(it);
            found = true;
            break;
          }
        }
      }

      if (!found)
      {
        break; // No more joinable threads
      }

      // Join the moved thread OUTSIDE the lock to prevent deadlock
      std::ostringstream oss;
      oss << threadId;
      iora::core::Logger::debug("ThreadPool::shutdown() - Joining thread " + oss.str());
      if (movedThread.joinable())
      {
        movedThread.join();
        iora::core::Logger::debug("ThreadPool::shutdown() - Thread " + oss.str() + " joined");
        joinCount++;
      }
    }

    iora::core::Logger::debug("ThreadPool::shutdown() - All " + std::to_string(joinCount) +
                              " threads joined, shutdown complete");
  }

  /// Try to enqueue a task, returning false if queue is full instead of
  /// throwing.
  template <typename F, typename... Args> bool tryEnqueue(F &&func, Args &&...args)
  {
    auto bound = std::bind(std::forward<F>(func), std::forward<Args>(args)...);
    return tryEnqueueImpl(
      [bound = std::move(bound), this]()
      {
        try
        {
          bound();
        }
        catch (...)
        {
          reportTaskException(std::current_exception(), "void task");
        }
      });
  }

  // ═══════════════════════════════════════════════════════════════════
  // ILifecycleManaged Interface Implementation
  // ═══════════════════════════════════════════════════════════════════

  /// Start the thread pool (Created/Reset → Running)
  /// @return Result indicating success and new state
  iora::common::LifecycleResult start() override
  {
    using iora::common::LifecycleState;
    using iora::common::LifecycleResult;

    // Serialize lifecycle transitions: start/drain/stop/reset take _lifecycleMutex
    // for their whole body, so concurrent callers cannot interleave check-then-act
    // on _lifecycleState (e.g. two start()s both spawning _initialSize workers).
    // Lock order is ALWAYS _lifecycleMutex -> _mutex; workers never take
    // _lifecycleMutex, so drain's quiescence wait cannot deadlock against them.
    std::lock_guard<std::mutex> lifecycleLock(_lifecycleMutex);

    auto currentState = _lifecycleState.load(std::memory_order_acquire);

    if (auto refusal = refuseIfDetached(currentState, "start"))
    {
      return *refusal;
    }

    // If already running, it's a no-op (idempotent)
    if (currentState == LifecycleState::Running)
    {
      return LifecycleResult(true, LifecycleState::Running, "Already running");
    }

    // Can only start from Created or Reset state
    if (currentState != LifecycleState::Created && currentState != LifecycleState::Reset)
    {
      return LifecycleResult(false, currentState,
                             "Can only start from Created or Reset state");
    }

    // If already have threads from constructor, just mark as running
    if (currentState == LifecycleState::Created)
    {
      // Already started in constructor
      return LifecycleResult(true, LifecycleState::Running, "Already running");
    }

    // Reset → Running: restart the pool
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _shutdown.store(false, std::memory_order_release);
    }

    _accepting.store(true, std::memory_order_release);
    _lifecycleState.store(LifecycleState::Running, std::memory_order_release);

    // Spawn initial threads if needed
    for (std::size_t i = 0; i < _initialSize; ++i)
    {
      spawnWorker();
    }

    return LifecycleResult(true, LifecycleState::Running, "ThreadPool started");
  }

  /// Begin graceful drain (Running → Draining).
  /// @param timeoutMs Maximum time to wait for in-flight work, in milliseconds.
  ///   A value of 0 waits up to a bounded cap of one hour (NOT truly unbounded --
  ///   the cap keeps the held _lifecycleMutex from blocking other transitions
  ///   indefinitely). Prefer a finite timeout: this call holds _lifecycleMutex for
  ///   its whole duration, so a concurrent stop()/reset()/start() -- including a
  ///   stop() meant to force-abort a stuck drain -- blocks until this drain returns.
  /// @return Result with drain statistics.
  iora::common::LifecycleResult drain(std::uint32_t timeoutMs = 30000) override
  {
    std::lock_guard<std::mutex> lifecycleLock(_lifecycleMutex);
    return drainImpl(timeoutMs);
  }

private:
  /// Drain body; the caller MUST hold _lifecycleMutex (public drain() and stop()).
  iora::common::LifecycleResult drainImpl(std::uint32_t timeoutMs)
  {
    using iora::common::LifecycleState;
    using iora::common::LifecycleResult;
    using iora::common::DrainStats;

    auto currentState = _lifecycleState.load(std::memory_order_acquire);

    // Can only drain from Running state
    if (currentState != LifecycleState::Running)
    {
      return LifecycleResult(false, currentState,
                             "Can only drain from Running state");
    }

    // Transition to Draining and stop accepting new work
    _lifecycleState.store(LifecycleState::Draining, std::memory_order_release);
    _accepting.store(false, std::memory_order_release);

    // Capture initial in-flight count (exact single-critical-section read).
    std::uint32_t inFlightAtStart = getInFlightCount();

    // Wait for all in-flight work to complete. The predicate is the accurate
    // getInFlightCount()==0 gate (queue depth + _busyThreads under one lock) --
    // never a two-sample (_activeThreads then a separate getPendingTaskCount())
    // read, which admits the pop->++_activeThreads TOCTOU this task fixes.
    const int maxWaitMs = (timeoutMs == 0) ? 3600000 : static_cast<int>(timeoutMs); // 1 hour if 0
    bool timedOut = !waitForQuiescence(maxWaitMs);

    // remaining is another exact read. On the success path _accepting is already
    // false, so no task can be admitted after quiescence -- remaining stays 0 and
    // completed == inFlightAtStart. On the timeout path a task admitted after the
    // inFlightAtStart snapshot can make remaining exceed it, so clamp the
    // subtraction to avoid a std::uint32_t underflow.
    std::uint32_t remaining = getInFlightCount();
    std::uint32_t completed = (inFlightAtStart >= remaining) ? (inFlightAtStart - remaining) : 0;

    DrainStats stats(inFlightAtStart, remaining, 0, completed);

    if (timedOut)
    {
      return LifecycleResult(false, LifecycleState::Draining,
                             "Drain timed out with " + std::to_string(remaining) +
                             " tasks remaining", stats);
    }

    return LifecycleResult(true, LifecycleState::Draining,
                           "Drain completed, all " + std::to_string(completed) +
                           " tasks finished", stats);
  }

public:
  /// Stop the thread pool (Draining → Stopped)
  /// @return Result indicating success and new state
  iora::common::LifecycleResult stop() override
  {
    using iora::common::LifecycleState;
    using iora::common::LifecycleResult;

    std::lock_guard<std::mutex> lifecycleLock(_lifecycleMutex);

    auto currentState = _lifecycleState.load(std::memory_order_acquire);

    if (auto refusal = refuseIfDetached(currentState, "stop"))
    {
      return *refusal;
    }

    // Can stop from Running or Draining state
    if (currentState != LifecycleState::Running && currentState != LifecycleState::Draining)
    {
      return LifecycleResult(false, currentState,
                             "Can only stop from Running or Draining state");
    }

    // Give in-flight work a bounded chance to finish.
    //  - From Running: drainImpl() (its own timeout) is the drain window.
    //  - From Draining: the caller already drained; check current quiescence.
    bool quiesced;
    if (currentState == LifecycleState::Running)
    {
      quiesced = drainImpl(30000).success;
    }
    else
    {
      quiesced = (getInFlightCount() == 0);
    }

    if (!quiesced)
    {
      // D2: a task is still in flight after the drain window. shutdown()'s join
      // loop ignores the shutdown mode and would HANG on the stuck task, so do
      // NOT call it. Signal shutdown, detach every worker (never join), and mark
      // the pool terminally detached so start()/reset()/stop() refuse to restart
      // over a ghost worker whose late --_busyThreads/--_activeThreads would
      // underflow a restarted pool's counters. Destroying a pool while a genuinely
      // stuck task is still running remains undefined behaviour (documented).
      forceDetachWorkers();
      _lifecycleState.store(LifecycleState::Stopped, std::memory_order_release);
      return LifecycleResult(false, LifecycleState::Stopped,
                             "ThreadPool stop timed out draining; workers detached "
                             "(forced stop, in-flight tasks abandoned)");
    }

    // Quiescent: shutdown()'s join is bounded and safe by construction.
    shutdown();

    _lifecycleState.store(LifecycleState::Stopped, std::memory_order_release);

    return LifecycleResult(true, LifecycleState::Stopped, "ThreadPool stopped");
  }

  /// Reset to clean state (Stopped → Reset)
  /// @return Result indicating success and new state
  iora::common::LifecycleResult reset() override
  {
    using iora::common::LifecycleState;
    using iora::common::LifecycleResult;

    std::lock_guard<std::mutex> lifecycleLock(_lifecycleMutex);

    auto currentState = _lifecycleState.load(std::memory_order_acquire);

    if (auto refusal = refuseIfDetached(currentState, "reset"))
    {
      return *refusal;
    }

    // Can only reset from Stopped state
    if (currentState != LifecycleState::Stopped)
    {
      return LifecycleResult(false, currentState,
                             "Can only reset from Stopped state");
    }

    // Clear any remaining tasks
    {
      std::lock_guard<std::mutex> lock(_mutex);
      while (!_tasks.empty())
      {
        _tasks.pop();
      }
      _threads.clear();
    }

    // Reset counters
    _activeThreads.store(0, std::memory_order_release);
    _busyThreads.store(0, std::memory_order_release);
    _threadsCreated.store(0, std::memory_order_release);
    _threadsExited.store(0, std::memory_order_release);
    _waitingThreads.store(0, std::memory_order_release);

    _lifecycleState.store(LifecycleState::Reset, std::memory_order_release);

    return LifecycleResult(true, LifecycleState::Reset, "ThreadPool reset");
  }

  /// Get current lifecycle state
  /// @return Current lifecycle state
  iora::common::LifecycleState getState() const override
  {
    return _lifecycleState.load(std::memory_order_acquire);
  }

  /// Get in-flight work count (for monitoring during drain)
  /// @return Number of tasks in queue + actively executing
  std::uint32_t getInFlightCount() const override
  {
    // Single critical section: read the queue depth and the in-flight counter
    // under ONE _mutex hold. _busyThreads is incremented atomic-with-the-pop
    // under _mutex (see the worker loop), so a _mutex holder can never observe a
    // dequeued-but-uncounted task -- closing the pop->++_activeThreads gap that a
    // two-sample (_activeThreads + separate getPendingTaskCount()) read left open.
    // acquire on _busyThreads pairs with the seq_cst --_busyThreads that is
    // sequenced-after the task functor's destruction, so ==0 proves every functor
    // released.
    std::lock_guard<std::mutex> lock(_mutex);
    const std::size_t inFlight = _tasks.size() + _busyThreads.load(std::memory_order_acquire);
    // Saturate to the ILifecycleManaged uint32_t contract. A >4G in-flight count is
    // physically unreachable (each queued task is dozens of bytes), but avoid a
    // silent narrowing truncation rather than assert the impossible.
    return inFlight > 0xFFFFFFFFull ? 0xFFFFFFFFu : static_cast<std::uint32_t>(inFlight);
  }

  // ═══════════════════════════════════════════════════════════════════
  // Test seam accessors (no-ops unless EnableTestSeam; see the worker loop)
  // ═══════════════════════════════════════════════════════════════════

  /// Arm the one-shot worker park point. Test-only (no-op in production).
  void testSeamArm()
  {
    if constexpr (EnableTestSeam)
    {
      seam().armed.store(true, std::memory_order_release);
    }
  }

  /// True while a worker is parked at the seam. Test-only (always false in production).
  bool testSeamParked() const
  {
    if constexpr (EnableTestSeam)
    {
      return seam().parked.load(std::memory_order_acquire);
    }
    return false;
  }

  /// Release a worker parked at the seam. Test-only (no-op in production).
  void testSeamRelease()
  {
    if constexpr (EnableTestSeam)
    {
      seam().release.store(true, std::memory_order_release);
    }
  }

  /// True once every spawned worker has returned from its lambda. Test-only
  /// (always false in production): lets the forced-detach test prove the detached
  /// worker has exited before the pool is destroyed, rather than timing it.
  bool testWorkersExited() const
  {
    if constexpr (EnableTestSeam)
    {
      return _threadsExited.load(std::memory_order_acquire) >=
             _threadsCreated.load(std::memory_order_acquire);
    }
    return false;
  }

private:
  /// Shared lifecycle guard: if a forced stop left the pool terminally detached,
  /// return the standard refusal for `verb`; otherwise std::nullopt. Callers hold
  /// _lifecycleMutex.
  std::optional<iora::common::LifecycleResult>
  refuseIfDetached(iora::common::LifecycleState currentState, const char *verb) const
  {
    if (_detachedTerminal.load(std::memory_order_acquire))
    {
      return iora::common::LifecycleResult(
        false, currentState,
        std::string("ThreadPool terminally detached after a forced stop; cannot ") + verb);
    }
    return std::nullopt;
  }

  /// Copy-then-invoke the task-error handler (or log to std::cerr). Copies
  /// _onTaskError under _configMutex, then calls it with NO lock held (the
  /// copy-then-invoke rule -- never hold a lock across a user callback).
  void reportTaskException(std::exception_ptr ep, const char *what) const
  {
    std::function<void(std::exception_ptr)> handlerCopy;
    {
      std::lock_guard<std::mutex> lock(_configMutex);
      handlerCopy = _onTaskError;
    }
    if (handlerCopy)
    {
      handlerCopy(ep);
    }
    else
    {
      std::cerr << "[ThreadPool] Unhandled exception in " << what << std::endl;
    }
  }

  /// Cast to the test-seam base. Only valid — and only instantiated — when
  /// EnableTestSeam; every call site is inside an `if constexpr (EnableTestSeam)`,
  /// so ThreadPoolT<false> never instantiates this ill-formed cast.
  detail::ThreadPoolTestSeam &seam() noexcept
  {
    return static_cast<detail::ThreadPoolTestSeam &>(*this);
  }
  const detail::ThreadPoolTestSeam &seam() const noexcept
  {
    return static_cast<const detail::ThreadPoolTestSeam &>(*this);
  }

  /// Poll until in-flight work reaches zero or the budget is exhausted. Returns
  /// true iff quiescent (getInFlightCount()==0) within maxWaitMs. Delegates to the
  /// accurate single-critical-section getInFlightCount() and never holds _mutex
  /// across the sleep (getInFlightCount takes and releases it internally).
  bool waitForQuiescence(int maxWaitMs, int *elapsedMsOut = nullptr)
  {
    int waitMs = 0;
    while (getInFlightCount() != 0)
    {
      if (waitMs >= maxWaitMs)
      {
        if (elapsedMsOut)
        {
          *elapsedMsOut = waitMs;
        }
        return false;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      waitMs += 50;
    }
    if (elapsedMsOut)
    {
      *elapsedMsOut = waitMs;
    }
    return true;
  }

  /// Forced-stop path (drain timeout): signal shutdown and DETACH every worker
  /// instead of joining -- shutdown()'s join loop ignores the shutdown mode and
  /// would hang on a stuck task. Marks the pool terminally detached so
  /// start()/reset()/stop() refuse to restart over a ghost worker whose late
  /// counter decrement would underflow a restarted pool. Destroying the pool while
  /// a genuinely stuck task is still running is undefined behaviour (documented).
  void forceDetachWorkers()
  {
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _shutdown.store(true, std::memory_order_release);
    }
    _condition.notify_all();

    {
      std::lock_guard<std::mutex> lock(_mutex);
      for (auto it = _threads.begin(); it != _threads.end();)
      {
        if (it->second.joinable())
        {
          it->second.detach();
        }
        it = _threads.erase(it);
      }
    }

    _detachedTerminal.store(true, std::memory_order_release);
  }

  void enqueueImpl(std::function<void()> f)
  {
    // Check if accepting new work (for graceful drain support)
    if (!_accepting.load(std::memory_order_acquire))
    {
      throw std::runtime_error("ThreadPool is draining and not accepting new work");
    }

    bool shouldSpawn = false;
    {
      std::unique_lock<std::mutex> lock(_mutex);
      if (_shutdown)
      {
        throw std::runtime_error("ThreadPool is shutting down");
      }

      if (_tasks.size() >= _maxQueueSize)
      {
        throw std::runtime_error("ThreadPool task queue is full");
      }

      _tasks.emplace(std::move(f));

      // Check if we should spawn a new thread
      if (_threads.size() < _maxSize)
      {
        shouldSpawn = true;
      }
    } // Release mutex here

    // Spawn outside of the lock to avoid deadlock
    if (shouldSpawn)
    {
      spawnWorker();
    }

    _condition.notify_one();
  }

  bool tryEnqueueImpl(std::function<void()> f)
  {
    // Check if accepting new work (for graceful drain support)
    if (!_accepting.load(std::memory_order_acquire))
    {
      return false; // Draining, reject task
    }

    bool shouldSpawn = false;
    {
      std::unique_lock<std::mutex> lock(_mutex);
      if (_shutdown)
      {
        return false; // Shutting down, reject task
      }

      if (_tasks.size() >= _maxQueueSize)
      {
        return false; // Queue full, reject task
      }

      _tasks.emplace(std::move(f));

      // Check if we should spawn a new thread
      if (_threads.size() < _maxSize)
      {
        shouldSpawn = true;
      }
    } // Release mutex here

    // Spawn outside of the lock to avoid deadlock
    if (shouldSpawn)
    {
      spawnWorker();
    }

    _condition.notify_one();
    return true;
  }

  void spawnWorker()
  {
    std::thread t(
      [this]()
      {
        // Lifecycle tracking: thread created
        _threadsCreated.fetch_add(1, std::memory_order_relaxed);

        while (true)
        {
          std::function<void()> task;

          {
            std::unique_lock<std::mutex> lock(_mutex);

            // Track waiting threads to allow shutdown barrier to detect when
            // all threads have exited wait_for() and avoid destroying
            // condition_variable while threads are still waiting inside it.
            _waitingThreads.fetch_add(1, std::memory_order_relaxed);
            bool waitResult = _condition.wait_for(lock, _idleTimeout,
                                     [this]() { return _shutdown || !_tasks.empty(); });
            _waitingThreads.fetch_sub(1, std::memory_order_relaxed);

            if (!waitResult)
            {
              // Idle timeout: claim an exit slot via CAS (below), then self-detach and
              // erase our own _threads entry under the held _mutex before returning.

              // Use atomic CAS to safely claim exit slot - prevents race where multiple
              // threads simultaneously decide to exit and drop below _initialSize
              int currentExited = _threadsExited.load(std::memory_order_acquire);
              bool claimedExitSlot = false;

              while (true)
              {
                std::size_t workerCount = static_cast<std::size_t>(
                  _threadsCreated.load(std::memory_order_acquire) - currentExited);
                if (workerCount <= _initialSize)
                {
                  // Would drop to or below minimum - don't exit
                  break;
                }
                // Try to atomically claim this exit slot
                // If another thread beats us, currentExited is updated and we retry
                if (_threadsExited.compare_exchange_weak(
                      currentExited,
                      currentExited + 1,
                      std::memory_order_acq_rel,
                      std::memory_order_acquire))
                {
                  claimedExitSlot = true;
                  break;
                }
                // CAS failed - currentExited has been updated, loop will recalculate
              }

              if (claimedExitSlot)
              {
                // Worker thread exits cleanly - clean up _threads map entry.
                // _threadsExited already incremented by CAS above.

                // Clean up our entry in the _threads map
                // We already hold _mutex from the unique_lock above
                auto myId = std::this_thread::get_id();
                auto it = _threads.find(myId);
                if (it != _threads.end())
                {
                  // Detach the thread so it can exit without being joined
                  // This is safe - a thread can detach itself
                  if (it->second.joinable())
                  {
                    it->second.detach();
                  }
                  _threads.erase(it);
                }

                return;
              }
              continue;
            }

            if (_shutdown && _tasks.empty())
            {
              _threadsExited.fetch_add(1, std::memory_order_relaxed);
              return;
            }

            if (!_tasks.empty())
            {
              task = std::move(_tasks.front());
              _tasks.pop();
              ++_busyThreads; // Thread has picked up work
            }
          }

          if (task)
          {
            // Test seam (compiled out of production via if constexpr): park the
            // worker HERE -- _mutex released, task popped, _busyThreads already
            // incremented, but _activeThreads not yet -- to exercise the
            // busy-but-not-active window the quiescence gate must observe. No lock
            // is held across the park (getInFlightCount()/drain() stay live).
            if constexpr (EnableTestSeam)
            {
              auto &s = seam();
              if (s.armed.load(std::memory_order_acquire))
              {
                s.armed.store(false, std::memory_order_release);   // one-shot
                s.parked.store(true, std::memory_order_release);
                while (!s.release.load(std::memory_order_acquire))
                {
                  std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
                s.release.store(false, std::memory_order_release);  // re-arm for reuse
                s.parked.store(false, std::memory_order_release);   // clear parked after release
              }
            }

            ++_activeThreads; // Thread is now executing (for monitoring)
            try
            {
              task();
            }
            catch (...)
            {
              reportTaskException(std::current_exception(), "task");
            }

            // CRITICAL: destroy the task functor (releasing its captured variables)
            // BEFORE decrementing the in-flight counters -- in particular before
            // --_busyThreads, the quiescence decrement getInFlightCount() gates on.
            // Sequencing the destroy before the seq_cst --_busyThreads is what makes
            // _busyThreads==0 (read under _mutex, acquire) prove every functor -- and
            // its captures -- released, preventing a use-after-free during drain/teardown.
            task = std::function<void()>{};

            --_activeThreads; // Thread finished executing (monitoring accessor only)
            --_busyThreads;   // Quiescence decrement -- MUST stay after the functor destroy
          }
        }

      });

    std::lock_guard<std::mutex> lock(_mutex);
    auto threadId = t.get_id();
    _threads.emplace(threadId, std::move(t));
  }

private:
  // ═══════════════════════════════════════════════════════════════════
  // Shutdown Phase Methods (Unit-Testable)
  // ═══════════════════════════════════════════════════════════════════

  /// Phase 1: Signal shutdown to all worker threads
  /// Sets _shutdown flag and notifies all waiting threads
  ShutdownPhase1Result shutdownPhase1_SignalShutdown()
  {
    ShutdownPhase1Result result;

    {
      std::unique_lock<std::mutex> lock(_mutex);
      if (_shutdown)
      {
        result.wasAlreadyShutdown = true;
        result.success = true;
        return result;
      }
      _shutdown = true;
    }

    _condition.notify_all();

    result.wasAlreadyShutdown = false;
    result.success = true;
    return result;
  }

  /// Phase 2: Synchronization barrier - wait for all threads to exit condition_variable::wait_for()
  /// CRITICAL FIX: This prevents the race condition where _condition is destroyed while
  /// threads are still inside wait_for(), causing "double free or corruption (!prev)"
  ShutdownPhase2Result shutdownPhase2_SynchronizationBarrier()
  {
    ShutdownPhase2Result result;
    auto startTime = std::chrono::steady_clock::now();

    // CRITICAL FIX: Explicit barrier to ensure worker threads have left condition_variable
    // wait and progressed to either executing tasks or exiting. Rely on two counters:
    //  - _waitingThreads: number of threads currently blocked in wait_for()
    //  - _threadsExited/_threadsCreated: number of threads that have fully returned
    // Wait until either there are no waiting threads and all started threads have exited,
    // or until we hit a conservative timeout.
    const int checkIntervalUs = 100; // 100 microseconds
    const int maxIterations = 2000;  // ~200ms at 100us per iteration
    int iterations = 0;

    while (iterations < maxIterations)
    {
      std::this_thread::sleep_for(std::chrono::microseconds(checkIntervalUs));
      iterations++;

      // If no threads are currently waiting on the condition variable
      // and the number of exited threads equals the number of threads created,
      // it's safe to proceed (all threads have left wait_for and returned).
      if (_waitingThreads.load(std::memory_order_acquire) == 0 &&
          _threadsExited.load(std::memory_order_acquire) >= _threadsCreated.load(std::memory_order_acquire))
      {
        // Small grace period to ensure any in-flight transitions complete
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        // Observed quiescence before the timeout. Diagnostic only; the default-init
        // leaves this false on the ~200ms timeout path, and success stays true
        // either way (best-effort backstop; see docs/core/thread_pool.md §8.4 / DP-2).
        result.allThreadsAcknowledged = true;
        break;
      }
    }

    auto endTime = std::chrono::steady_clock::now();
    result.waitTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    result.success = true;

    return result;
  }

  /// Phase 3: Drain all active tasks
  /// Waits for all enqueued and executing tasks to complete
  ShutdownPhase3Result shutdownPhase3_DrainTasks()
  {
    ShutdownPhase3Result result;

    // Quiescence gate: the accurate single-critical-section getInFlightCount()==0
    // read via waitForQuiescence (never a two-sample check). The finalActive/
    // finalPending fields on timeout are diagnostic only.
    int elapsedMs = 0;
    if (waitForQuiescence(5000, &elapsedMs))
    {
      result.finalActiveCount = 0;
      result.finalPendingCount = 0;
      result.drainTimeMs = elapsedMs;
      result.timedOut = false;
      result.success = true;
    }
    else
    {
      // Timeout occurred (diagnostic snapshot).
      result.finalActiveCount = _activeThreads.load(std::memory_order_acquire);
      result.finalPendingCount = getPendingTaskCount();
      result.drainTimeMs = elapsedMs;
      result.timedOut = true;
      result.success = false;  // Timeout is considered failure
    }
    return result;
  }

  /// Phase 4: Join all worker threads
  /// Waits for all threads to exit their worker loops
  /// Supports IMMEDIATE (join) and DETACHED (detach) shutdown modes
  ShutdownPhase4Result shutdownPhase4_JoinThreads()
  {
    ShutdownPhase4Result result;

    // Read shutdown mode (thread-safe)
    ShutdownMode mode;
    {
      std::lock_guard<std::mutex> lock(_configMutex);
      mode = _shutdownMode;
    }

    int joinCount = 0;
    while (true)
    {
      std::thread movedThread;
      std::thread::id threadId;
      bool found = false;

      {
        std::lock_guard<std::mutex> lock(_mutex);

        for (auto it = _threads.begin(); it != _threads.end(); ++it)
        {
          if (it->second.joinable())
          {
            // Move the thread out of the map and erase the entry under lock.
            movedThread = std::move(it->second);
            threadId = it->first;
            _threads.erase(it);
            found = true;
            break;
          }
        }
      }

      if (!found)
      {
        break; // No more joinable threads
      }

      // Handle shutdown based on mode (operate on movedThread)
      if (mode == ShutdownMode::DETACHED)
      {
        if (movedThread.joinable())
        {
          movedThread.detach();
        }
        joinCount++;
      }
      else
      {
        if (movedThread.joinable())
        {
          movedThread.join();
          joinCount++;
        }
      }
    }

    result.threadsJoined = joinCount;
    result.success = true;
    return result;
  }

  /// Phase 5: Validate final state
  /// Checks that all threads are properly cleaned up and queue is empty
  ShutdownPhase5Result shutdownPhase5_Validate()
  {
    ShutdownPhase5Result result;

    // Check that all threads are non-joinable (either joined or detached)
    {
      std::lock_guard<std::mutex> lock(_mutex);

      bool allNonJoinable = true;
      for (const auto& pair : _threads)
      {
        if (pair.second.joinable())
        {
          allNonJoinable = false;
          break;
        }
      }

      result.allThreadsDestroyed = allNonJoinable;
      result.queueEmpty = _tasks.empty();
    }

    result.success = result.allThreadsDestroyed && result.queueEmpty;
    return result;
  }

private:
  std::unordered_map<std::thread::id, std::thread> _threads;
  std::queue<std::function<void()>> _tasks;
  mutable std::mutex _mutex;
  std::condition_variable _condition;

  /// Clamp a worker count to >=1 (hardware_concurrency() may return 0 -> 0-worker hang).
  static constexpr std::size_t clampInitial(std::size_t n) { return n ? n : 1; }

  const std::size_t _initialSize;
  const std::size_t _maxSize;
  const std::chrono::milliseconds _idleTimeout;
  const std::size_t _maxQueueSize;

  std::atomic<bool> _shutdown;
  std::atomic<std::size_t> _activeThreads; // Threads actively executing tasks
  std::atomic<std::size_t> _busyThreads;   // Threads that have picked up work

  // Thread-lifecycle counters (idle-shrink CAS + shutdown quiescence barrier)
  std::atomic<int> _threadsCreated{0};   // Total threads spawned
  std::atomic<int> _threadsExited{0};    // Total threads that returned from lambda
  std::atomic<int> _waitingThreads{0};   // Number of threads currently blocked on condition_variable

  mutable std::mutex _configMutex;  // mutable: allows locking in const methods
  std::function<void(std::exception_ptr)> _onTaskError;

  // Serializes ILifecycleManaged transitions (start/drain/stop/reset) so concurrent
  // callers cannot interleave check-then-act on _lifecycleState. Always acquired
  // BEFORE _mutex (workers never take it), so the drain quiescence wait -- which
  // takes _mutex internally via getInFlightCount() -- cannot deadlock against it.
  // getState()/getInFlightCount() are lock-free of it (observers stay responsive).
  std::mutex _lifecycleMutex;

  // Shutdown mode configuration (IMMEDIATE=join, DETACHED=detach)
  ShutdownMode _shutdownMode{ShutdownMode::IMMEDIATE};  // Default

  // ═══════════════════════════════════════════════════════════════════
  // ILifecycleManaged Interface Members
  // ═══════════════════════════════════════════════════════════════════
  std::atomic<iora::common::LifecycleState> _lifecycleState{iora::common::LifecycleState::Created};
  std::atomic<bool> _accepting{false};  // Flag to control acceptance of new work during drain

  // Set by forceDetachWorkers() when stop() times out draining and detaches its
  // workers. Terminal: start()/reset()/stop() refuse to restart the pool while it
  // is set, so a ghost worker's late --_busyThreads/--_activeThreads cannot
  // underflow a restarted pool's counters.
  std::atomic<bool> _detachedTerminal{false};
};

/// The production thread pool: an ordinary class to every consumer. The test-seam
/// template parameter is pinned to false here so the seam contributes zero bytes
/// (empty-base optimization) and zero runtime cost. Tests instantiate
/// ThreadPoolT<true> to exercise the drain-quiescence park point.
using ThreadPool = ThreadPoolT<false>;

/// \brief Process-wide, immortal, hard-capped, reject-fast pool for BLOCKING I/O
///        (e.g. ::getaddrinfo) that must NEVER run on an event-loop thread.
///
/// The FIRST global ThreadPool accessor in iora::core. Dedicated to blocking,
/// uncancellable syscalls: a stuck worker (a hung resolver) must not starve
/// unrelated work, so the pool is hard-capped (maxSize=16) and reject-fast
/// (tryEnqueue returns false at maxQueueSize=128 rather than blocking). It is
/// a deliberately-leaked function-local static (LoggerData precedent) because
/// an uncancellable getaddrinfo worker may still be parked at process exit;
/// joining it would hang teardown, so the pool is never destroyed. Defined in
/// src/core/iora_core.cpp. See architecture/iora/transport_dns_resolve.json (C3).
ThreadPool &blockingIoPool();

/// \brief Process-wide, immortal, general-purpose async pool (the SECOND global
///        ThreadPool accessor in iora::core, after blockingIoPool).
///
/// Backs iora::core::async -- a reusable std::async(std::launch::async, ...)
/// drop-in that dispatches onto this shared pool instead of spawning an OS
/// thread per call. Distinct from blockingIoPool (reserved for blocking,
/// uncancellable syscalls like ::getaddrinfo): this pool hosts general,
/// non-blocking-syscall async work (HTTP requests today). It is FIXED-SIZE
/// (initialSize == maxSize == hardware_concurrency()*4): pinning the worker
/// count is load-bearing for correctness -- it guarantees the enqueue path never
/// spawns a worker post-commit, so a throw from enqueue always means the task
/// was NOT committed (all-or-nothing enqueue), which iora::core::async relies on
/// to synthesize a rejection future without orphaning a running task.
/// Deliberately leaked / immortal (blockingIoPool precedent) so an in-flight
/// task at process exit cannot hang teardown's join. Defined once in
/// src/core/iora_core.cpp. See architecture/iora/async_pool.json (C1).
ThreadPool &generalAsyncPool();

/// \brief Carried in the returned future when iora::core::async cannot enqueue
///        (pool draining/shutting down, or its queue is full).
///
/// Distinct from a task-internal exception: an AsyncRejectedError means the task
/// was NEVER attempted (relevant for retry / idempotency reasoning). See
/// architecture/iora/async_pool.json (DP-5a).
class AsyncRejectedError : public std::runtime_error
{
public:
  using std::runtime_error::runtime_error;
};

/// \brief Move-only future wrapper that replicates std::async's
///        [futures.async]/5 join-on-destruction over a pool-backed future.
///
/// A std::future from a std::packaged_task has ordinary, non-blocking
/// destruction, so abandoning it would let the task run later against destroyed
/// captures (use-after-free). PooledFuture's destructor -- AND its move
/// assignment -- wait() on the shared state when valid(), so an abandoned future
/// joins exactly as std::async's does. The consume path (get()/wait() leaves the
/// future !valid()) pays nothing. share() and an implicit conversion to
/// std::future<R> are intentionally omitted: either would move the guarantee out
/// to a bare, non-blocking future. The move operations are noexcept
/// (load-bearing for std::vector<PooledFuture> relocation of a move-only type).
/// See architecture/iora/async_pool.json (C3, DP-3 / DP-3a / DP-3b / DP-3c).
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
      if (_future.valid())
      {
        _future.wait();
      }
      _future = std::move(other._future);
    }
    return *this;
  }

  PooledFuture(const PooledFuture &) = delete;
  PooledFuture &operator=(const PooledFuture &) = delete;

  ~PooledFuture()
  {
    if (_future.valid())
    {
      _future.wait();
    }
  }

  R get() { return _future.get(); }
  void wait() const { _future.wait(); }

  template <typename Rep, typename Period>
  std::future_status wait_for(const std::chrono::duration<Rep, Period> &timeout) const
  {
    return _future.wait_for(timeout);
  }

  template <typename Clock, typename Duration>
  std::future_status wait_until(const std::chrono::time_point<Clock, Duration> &deadline) const
  {
    return _future.wait_until(deadline);
  }

  bool valid() const noexcept { return _future.valid(); }

private:
  std::future<R> _future;
};

namespace detail
{
/// Build a packaged_task in place (move-invoke parity with std::async; bypasses
/// ThreadPool::enqueueWithResult's std::bind lvalue-invoke), enqueue it on
/// \p pool, and return a PooledFuture. On enqueue failure (pool draining /
/// shutting down / queue full) return a PooledFuture carrying AsyncRejectedError
/// rather than throwing at the call site. See DP-5 / DP-5a / DP-10a.
template <typename F, typename... Args>
auto submitTo(ThreadPool &pool, F &&func, Args &&...args)
  -> PooledFuture<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>
{
  using ResultType = std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>;
  auto bound = [func = std::forward<F>(func),
                argsTuple = std::make_tuple(std::forward<Args>(args)...)]() mutable -> ResultType
  {
    return std::apply(
      [&func](auto &&...unpacked) -> ResultType
      { return std::invoke(std::move(func), std::forward<decltype(unpacked)>(unpacked)...); },
      std::move(argsTuple));
  };
  auto task = std::make_shared<std::packaged_task<ResultType()>>(std::move(bound));
  std::future<ResultType> future = task->get_future();
  // Already-ready exception-carrying future for the enqueue-reject path
  // (DP-5/DP-5a); shared by both catch arms.
  auto makeRejected = [](std::string message) -> PooledFuture<ResultType>
  {
    std::promise<ResultType> rejected;
    rejected.set_exception(std::make_exception_ptr(AsyncRejectedError(std::move(message))));
    return PooledFuture<ResultType>(rejected.get_future());
  };
  try
  {
    pool.enqueue([task]() { (*task)(); });
  }
  catch (const std::exception &ex)
  {
    return makeRejected(ex.what());
  }
  catch (...)
  {
    return makeRejected("iora::core::async enqueue rejected");
  }
  // Return OUTSIDE the try: once the task is committed, the caller must always
  // receive a joinable future -- never a synthesized rejection for a task that
  // will run. See DP-5 / round-3 L-R3-1.
  return PooledFuture<ResultType>(std::move(future));
}
} // namespace detail

/// \brief A general, reusable, memory-safe drop-in for
///        std::async(std::launch::async, f, args...).
///
/// Runs \p func on the process-wide generalAsyncPool() instead of spawning an OS
/// thread per call, returning a PooledFuture<R> with std::async's
/// join-on-destruction semantics. On enqueue rejection the returned future
/// carries AsyncRejectedError (the call itself does not throw). See
/// architecture/iora/async_pool.json (C2, DP-5).
template <typename F, typename... Args>
auto async(F &&func, Args &&...args)
  -> PooledFuture<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>
{
  return detail::submitTo(generalAsyncPool(), std::forward<F>(func), std::forward<Args>(args)...);
}

/// \brief std::launch-accepting overload for literal call-site symmetry with
///        std::async. The policy is ACCEPTED but IGNORED (always pool-async);
///        std::launch::deferred is rejected (asserted in debug, treated as async
///        in release). See DP-4.
template <typename F, typename... Args>
auto async(std::launch policy, F &&func, Args &&...args)
  -> PooledFuture<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>
{
  assert(policy != std::launch::deferred && "iora::core::async cannot honor std::launch::deferred");
  (void)policy;
  return detail::submitTo(generalAsyncPool(), std::forward<F>(func), std::forward<Args>(args)...);
}

} // namespace core
} // namespace iora
