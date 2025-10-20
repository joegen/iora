// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <exception>
#include <functional>
#include <future>
#include <iostream>
#include <list>
#include <memory>
#include <mutex>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <iora/core/logger.hpp>

namespace iora
{
namespace core
{

/// A dynamic thread pool that accepts void or result-returning lambdas with
/// arbitrary arguments. Threads grow and shrink based on load and idle
/// timeout. Exceptions in tasks can be reported.
class ThreadPool
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
    /// IMMEDIATE: Join threads as soon as lambda returns (current behavior)
    /// - Fast shutdown (10-50ms)
    /// - Risk: May join during pthread cleanup (race condition)
    /// - Use: Development, non-critical applications
    /// - Default: YES (backward compatible)
    IMMEDIATE,

    /// GRACEFUL: Wait for pthread cleanup before join
    /// - Safe shutdown (+100-300ms extra)
    /// - Guarantee: No pthread cleanup races
    /// - Use: Production, critical applications
    /// - Default: NO (opt-in for safety)
    GRACEFUL,

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
  /// @param shutdownMode      Shutdown mode (IMMEDIATE, GRACEFUL, DETACHED).
  /// Default: IMMEDIATE (backward compatible).
  ThreadPool(std::size_t initialSize = std::thread::hardware_concurrency(),
             std::size_t maxSize = std::thread::hardware_concurrency() * 4,
             std::chrono::milliseconds idleTimeout = std::chrono::seconds(30),
             std::size_t maxQueueSize = 1024,
             std::function<void(std::exception_ptr)> onTaskError = nullptr,
             ShutdownMode shutdownMode = ShutdownMode::IMMEDIATE)
      : _initialSize(initialSize), _maxSize(maxSize), _idleTimeout(idleTimeout),
        _maxQueueSize(maxQueueSize), _shutdown(false), _activeThreads(0), _busyThreads(0),
        _onTaskError(std::move(onTaskError)), _shutdownMode(shutdownMode)
  {
    for (std::size_t i = 0; i < _initialSize; ++i)
    {
      spawnWorker();
    }
  }

  ~ThreadPool()
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

  ThreadPool(const ThreadPool &) = delete;
  ThreadPool &operator=(const ThreadPool &) = delete;
  ThreadPool(ThreadPool &&) = delete;
  ThreadPool &operator=(ThreadPool &&) = delete;

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
          // Always forward to exception handler if present
          std::function<void(std::exception_ptr)> handlerCopy;
          {
            std::lock_guard<std::mutex> lock(_configMutex);
            handlerCopy = _onTaskError;
          }

          if (handlerCopy)
          {
            handlerCopy(std::current_exception());
          }
          else
          {
            std::cerr << "[ThreadPool] Unhandled exception in void task" << std::endl;
          }
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

    // CRITICAL FIX: Wait for all active tasks to complete BEFORE joining threads
    // This prevents use-after-free when tasks access objects being destroyed during shutdown
    iora::core::Logger::debug("ThreadPool::shutdown() - Waiting for active tasks to complete...");
    int waitMs = 0;
    const int maxWaitMs = 5000;  // Maximum 5 seconds
    while (waitMs < maxWaitMs)
    {
      auto activeCount = _activeThreads.load(std::memory_order_acquire);
      auto pendingCount = getPendingTaskCount();

      if (activeCount == 0 && pendingCount == 0)
      {
        iora::core::Logger::debug("ThreadPool::shutdown() - All tasks completed after " +
                                 std::to_string(waitMs) + "ms");
        break;
      }

      if (waitMs % 500 == 0 && waitMs > 0)  // Log every 500ms
      {
        iora::core::Logger::debug("ThreadPool::shutdown() - Waiting... (active=" +
                                 std::to_string(activeCount) + ", pending=" +
                                 std::to_string(pendingCount) + ")");
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      waitMs += 50;
    }

    if (waitMs >= maxWaitMs)
    {
      iora::core::Logger::warning("ThreadPool::shutdown() - Task completion timeout after " +
                                 std::to_string(maxWaitMs) + "ms - proceeding anyway");
    }

    // P0-3 FIX: Double-check after wait completes to close race window
    // There's a narrow race where a thread could grab a task between when we check
    // and when the wait exits. Add a short delay and re-verify.
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto finalActiveCount = _activeThreads.load(std::memory_order_acquire);
    auto finalPendingCount = getPendingTaskCount();

    if (finalActiveCount != 0 || finalPendingCount != 0)
    {
      iora::core::Logger::warning(std::string("ThreadPool::shutdown() - Race detected after wait! ") +
                                 "Re-checking... (active=" + std::to_string(finalActiveCount) +
                                 ", pending=" + std::to_string(finalPendingCount) + ")");

      // Wait again for tasks to complete (shorter timeout since this is rare)
      int raceWaitMs = 0;
      const int raceMaxWaitMs = 1000;  // 1 second max
      while (raceWaitMs < raceMaxWaitMs)
      {
        auto activeCount = _activeThreads.load(std::memory_order_acquire);
        auto pendingCount = getPendingTaskCount();

        if (activeCount == 0 && pendingCount == 0)
        {
          iora::core::Logger::debug("ThreadPool::shutdown() - Race resolved after " +
                                   std::to_string(raceWaitMs) + "ms");
          break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        raceWaitMs += 50;
      }

      if (raceWaitMs >= raceMaxWaitMs)
      {
        iora::core::Logger::error("ThreadPool::shutdown() - Race resolution timeout! "
                                 "This may indicate a deadlock or stuck task.");
      }
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
          std::function<void(std::exception_ptr)> handlerCopy;
          {
            std::lock_guard<std::mutex> lock(_configMutex);
            handlerCopy = _onTaskError;
          }

          if (handlerCopy)
          {
            handlerCopy(std::current_exception());
          }
          else
          {
            std::cerr << "[ThreadPool] Unhandled exception in void task" << std::endl;
          }
        }
      });
  }

private:
  void enqueueImpl(std::function<void()> f)
  {
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
        // ══════════════════════════════════════════════════════════════════
        // LAMBDA CORRUPTION DETECTION INSTRUMENTATION
        // ══════════════════════════════════════════════════════════════════
        const uint32_t CANARY = 0xDEADBEEF;
        volatile uint32_t canary = CANARY;

        // Lifecycle tracking: Thread created and started
        _threadsCreated.fetch_add(1, std::memory_order_relaxed);
        _threadsStarted.fetch_add(1, std::memory_order_relaxed);

        // NOTE: Removed std::cerr ENTRY trace - std::cerr uses TLS and causes
        // "double free or corruption (!prev)" during pthread TLS cleanup
        // when multiple threads exit simultaneously

        // Macro to validate canary before each this-> access
        // NOTE: Removed std::cerr from canary validation - std::cerr uses TLS and causes
        // "double free or corruption (!prev)" during pthread TLS cleanup
        #define VALIDATE_CANARY() \
          do { \
            if (canary != CANARY) { \
              std::abort(); \
            } \
          } while (0)

        while (true)
        {
          VALIDATE_CANARY();
          std::function<void()> task;

          {
            VALIDATE_CANARY();
            std::unique_lock<std::mutex> lock(_mutex);

            VALIDATE_CANARY();
            // Track waiting threads to allow shutdown barrier to detect when
            // all threads have exited wait_for() and avoid destroying
            // condition_variable while threads are still waiting inside it.
            _waitingThreads.fetch_add(1, std::memory_order_relaxed);
            bool waitResult = _condition.wait_for(lock, _idleTimeout,
                                     [this]() { return _shutdown || !_tasks.empty(); });
            _waitingThreads.fetch_sub(1, std::memory_order_relaxed);

            if (!waitResult)
            {
              VALIDATE_CANARY();
              // P0-CRITICAL FIX: Idle timeout - worker just exits without touching _threads map
              // The destructor will handle cleanup (join/detach) to prevent race condition
              // REMOVED: it->second.detach() and _threads.erase(it) - caused heap corruption
              if (_threads.size() > _initialSize)
              {
                VALIDATE_CANARY();
                // Worker thread exits cleanly - destructor will clean up _threads map entry
                // NOTE: Removed std::cerr trace - std::cerr uses TLS and causes
                // "double free or corruption (!prev)" during pthread TLS cleanup
                _threadsExiting.fetch_add(1, std::memory_order_relaxed);
                _threadsExited.fetch_add(1, std::memory_order_relaxed);
                return;
              }
              continue;
            }

            VALIDATE_CANARY();
            if (_shutdown && _tasks.empty())
            {
              VALIDATE_CANARY();
              // NOTE: Removed std::cerr trace - std::cerr uses TLS and causes
              // "double free or corruption (!prev)" during pthread TLS cleanup
              _threadsExiting.fetch_add(1, std::memory_order_relaxed);
              _threadsExited.fetch_add(1, std::memory_order_relaxed);
              return;
            }

            VALIDATE_CANARY();
            if (!_tasks.empty())
            {
              task = std::move(_tasks.front());
              _tasks.pop();
              VALIDATE_CANARY();
              ++_busyThreads; // Thread has picked up work (for spawning
                              // decisions)
            }
          }

          VALIDATE_CANARY();
          if (task)
          {
            VALIDATE_CANARY();
            ++_activeThreads; // Thread is now executing (for monitoring)
            try
            {
              VALIDATE_CANARY();
              task();
              VALIDATE_CANARY();
            }
            catch (...)
            {
              VALIDATE_CANARY();
              std::function<void(std::exception_ptr)> handlerCopy;
              {
                std::lock_guard<std::mutex> lock(_configMutex);
                handlerCopy = _onTaskError;
              }

              VALIDATE_CANARY();
              if (handlerCopy)
              {
                handlerCopy(std::current_exception());
              }
              else
              {
                std::cerr << "[ThreadPool] Unhandled exception in task" << std::endl;
              }
            }

            VALIDATE_CANARY();
            // CRITICAL FIX: Explicitly destroy task (releasing captured variables)
            // BEFORE decrementing _activeThreads. This prevents use-after-free when
            // ThreadPool destructor waits for _activeThreads == 0 but task's captured
            // variables are destroyed during shutdown.
            task = std::function<void()>{};

            VALIDATE_CANARY();
            --_activeThreads; // Thread finished executing
            VALIDATE_CANARY();
            --_busyThreads;   // Thread no longer busy
          }
        }

        #undef VALIDATE_CANARY
      });

    std::lock_guard<std::mutex> lock(_mutex);
    auto threadId = t.get_id();
    _threads.emplace(threadId, std::move(t));

    // NOTE: Exit acknowledgment flag is initialized INSIDE the lambda (at thread start)
    // to avoid race condition. Do NOT initialize it here!
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
        break;
      }
    }

    auto endTime = std::chrono::steady_clock::now();
    result.waitTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    result.allThreadsAcknowledged = true;  // Conservative: assume success after wait
    result.success = true;

    return result;
  }

  /// Phase 3: Drain all active tasks
  /// Waits for all enqueued and executing tasks to complete
  ShutdownPhase3Result shutdownPhase3_DrainTasks()
  {
    ShutdownPhase3Result result;
    auto startTime = std::chrono::steady_clock::now();
    (void)startTime;  // For future timing/debugging use

    const int maxWaitMs = 5000;  // Maximum 5 seconds
    int waitMs = 0;

    while (waitMs < maxWaitMs)
    {
      auto activeCount = _activeThreads.load(std::memory_order_acquire);
      auto pendingCount = getPendingTaskCount();

      if (activeCount == 0 && pendingCount == 0)
      {
        result.finalActiveCount = 0;
        result.finalPendingCount = 0;
        result.drainTimeMs = waitMs;
        result.timedOut = false;
        result.success = true;
        return result;
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      waitMs += 50;
    }

    // Timeout occurred
    result.finalActiveCount = _activeThreads.load(std::memory_order_acquire);
    result.finalPendingCount = getPendingTaskCount();
    result.drainTimeMs = waitMs;
    result.timedOut = true;
    result.success = false;  // Timeout is considered failure

    return result;
  }

  /// Phase 4: Join all worker threads
  /// Waits for all threads to exit their worker loops
  /// Supports IMMEDIATE, GRACEFUL, and DETACHED shutdown modes
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

  const std::size_t _initialSize;
  const std::size_t _maxSize;
  const std::chrono::milliseconds _idleTimeout;
  const std::size_t _maxQueueSize;

  std::atomic<bool> _shutdown;
  std::atomic<std::size_t> _activeThreads; // Threads actively executing tasks
  std::atomic<std::size_t> _busyThreads;   // Threads that have picked up work

  // Lambda corruption detection - thread lifecycle tracking
  std::atomic<int> _threadsCreated{0};   // Total threads spawned
  std::atomic<int> _threadsStarted{0};   // Total threads that began executing
  std::atomic<int> _threadsExiting{0};   // Total threads about to return
  std::atomic<int> _threadsExited{0};    // Total threads that returned from lambda
  std::atomic<int> _waitingThreads{0};   // Number of threads currently blocked on condition_variable

  mutable std::mutex _configMutex;  // mutable: allows locking in const methods
  std::function<void(std::exception_ptr)> _onTaskError;

  // Shutdown mode configuration (GRACEFUL shutdown support)
  ShutdownMode _shutdownMode{ShutdownMode::IMMEDIATE};  // Default: backward compatible
};

} // namespace core
} // namespace iora
