#pragma once

#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <list>
#include <functional>
#include <future>
#include <chrono>
#include <atomic>
#include <stdexcept>
#include <memory>
#include <exception>
#include <iostream>

namespace iora {
namespace core {

/// A dynamic thread pool that accepts void or result-returning lambdas with arbitrary arguments.
/// Threads grow and shrink based on load and idle timeout. Exceptions in tasks can be reported.
class ThreadPool
{
public:
  /// Constructs the thread pool.
  ///
  /// @param initialSize       Minimum number of threads (always maintained).
  /// @param maxSize           Maximum number of threads (hard limit).
  /// @param idleTimeout       Duration after which idle threads beyond initial count will exit.
  /// @param maxQueueSize      Maximum number of queued tasks before enqueue throws.
  /// @param onTaskError       Optional handler for uncaught exceptions in tasks.
  ThreadPool(std::size_t initialSize = std::thread::hardware_concurrency(),
           std::size_t maxSize = std::thread::hardware_concurrency() * 4,
           std::chrono::milliseconds idleTimeout = std::chrono::seconds(30),
           std::size_t maxQueueSize = 1024,
           std::function<void(std::exception_ptr)> onTaskError = nullptr)
    : _initialSize(initialSize),
        _maxSize(maxSize),
        _idleTimeout(idleTimeout),
        _maxQueueSize(maxQueueSize),
        _shutdown(false),
        _activeThreads(0),
        _onTaskError(std::move(onTaskError))
  {
    for (std::size_t i = 0; i < _initialSize; ++i)
    {
        spawnWorker();
    }
  }

  ~ThreadPool()
  {
    {
      std::unique_lock<std::mutex> lock(_mutex);
      _shutdown = true;
    }
    _condition.notify_all();
    for (auto& [id, thread] : _threads)
    {
      if (thread.joinable())
      {
        thread.join();
      }
    }
  }

  ThreadPool(const ThreadPool&) = delete;
  ThreadPool& operator=(const ThreadPool&) = delete;
  ThreadPool(ThreadPool&&) = delete;
  ThreadPool& operator=(ThreadPool&&) = delete;

  /// Enqueue a fire-and-forget task (void-returning) with arguments.
  template <typename F, typename... Args>
  void enqueue(F&& func, Args&&... args)
  {
    // Avoid std::packaged_task<void()>
    auto bound = std::bind(std::forward<F>(func), std::forward<Args>(args)...);
    enqueueImpl([bound = std::move(bound), this]()
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
  auto enqueueWithResult(F&& func, Args&&... args)
      -> std::future<std::invoke_result_t<F, Args...>>
  {
    using ResultType = std::invoke_result_t<F, Args...>;
    auto task = std::make_shared<std::packaged_task<ResultType()>>(
        std::bind(std::forward<F>(func), std::forward<Args>(args)...));
    auto future = task->get_future();
    enqueueImpl([task]() { (*task)(); });
    return future;
  }

private:
  void enqueueImpl(std::function<void()> f)
  {
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

      if (_activeThreads >= _threads.size() && _threads.size() < _maxSize)
      {
        spawnWorker();
      }
    }

    _condition.notify_one();
  }

  void spawnWorker()
  {
    std::thread t([this]()
    {
      const std::thread::id tid = std::this_thread::get_id();

      while (true)
      {
        std::function<void()> task;

        {
          std::unique_lock<std::mutex> lock(_mutex);

          if (!_condition.wait_for(lock, _idleTimeout, [this]()
                                   { return _shutdown || !_tasks.empty(); }))
          {
            // Idle timeout — remove and exit if over minimum size
            if (_threads.size() > _initialSize)
            {
              auto it = _threads.find(tid);
              if (it != _threads.end())
              {
                // thread has exited
                it->second.detach(); // ensure no join needed
                _threads.erase(it);
              }
              return;
            }
            continue;
          }

          if (_shutdown && _tasks.empty())
          {
            return;
          }

          if (!_tasks.empty())
          {
            task = std::move(_tasks.front());
            _tasks.pop();
            ++_activeThreads; // Safe due to atomic
          }
        }

        if (task)
        {
          try
          {
            task();
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
              std::cerr << "[ThreadPool] Unhandled exception in task" << std::endl;
            }
          }

          --_activeThreads; // Safe due to atomic
        }
      }
    });

    std::lock_guard<std::mutex> lock(_mutex);
    _threads.emplace(t.get_id(), std::move(t));
  }

private:
  std::unordered_map<std::thread::id, std::thread> _threads;
  std::queue<std::function<void()>> _tasks;
  std::mutex _mutex;
  std::condition_variable _condition;

  const std::size_t _initialSize;
  const std::size_t _maxSize;
  const std::chrono::milliseconds _idleTimeout;
  const std::size_t _maxQueueSize;

  std::atomic<bool> _shutdown;
  std::atomic<std::size_t> _activeThreads;

  std::mutex _configMutex;
  std::function<void(std::exception_ptr)> _onTaskError;
};

} } // namespace iora
