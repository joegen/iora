// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <iora/common/i_lifecycle_managed.hpp>

namespace iora
{
namespace core
{

// Forward declarations
class TimerService;
class TimerServicePool;

/// \brief Timer error codes for enhanced error handling.
enum class TimerError
{
  None,
  SystemError,
  InvalidTimeout,
  ServiceStopped,
  HandlerException,
  ResourceExhausted,
  ConfigurationError
};

/// \brief Timer exception with error codes.
class TimerException : public std::exception
{
public:
  TimerException(TimerError code, const std::string &msg, int errno_val = 0)
      : _code(code), _message(msg), _errno(errno_val)
  {
    if (errno_val != 0)
    {
      _message +=
        " (errno: " + std::to_string(errno_val) + " - " + std::string(strerror(errno_val)) + ")";
    }
  }

  TimerError code() const { return _code; }
  int getErrno() const { return _errno; }
  const char *what() const noexcept override { return _message.c_str(); }

private:
  TimerError _code;
  std::string _message;
  int _errno;
};

/// \brief Statistics for timer service monitoring and debugging.
struct TimerStats
{
  std::atomic<std::uint64_t> timersScheduled{0};
  std::atomic<std::uint64_t> timersCanceled{0};
  std::atomic<std::uint64_t> timersExecuted{0};
  std::atomic<std::uint64_t> timersExpired{0};
  std::atomic<std::uint64_t> periodicTimersActive{0};
  std::atomic<std::uint64_t> exceptionsSwallowed{0};
  std::atomic<std::uint64_t> systemErrors{0};
  std::atomic<std::uint64_t> heapOperations{0};
  std::atomic<std::uint64_t> epollWaits{0};
  std::atomic<std::uint64_t> eventfdWakeups{0};
  std::atomic<std::uint64_t> timerfdTriggers{0};

  // Performance metrics
  std::atomic<std::uint64_t> totalHandlerExecutionTimeNs{0};
  std::atomic<std::uint64_t> maxHandlerExecutionTimeNs{0};
  std::atomic<std::uint64_t> avgHandlerExecutionTimeNs{0};

  std::chrono::steady_clock::time_point startTime{std::chrono::steady_clock::now()};

  void reset()
  {
    timersScheduled.store(0);
    timersCanceled.store(0);
    timersExecuted.store(0);
    timersExpired.store(0);
    periodicTimersActive.store(0);
    exceptionsSwallowed.store(0);
    systemErrors.store(0);
    heapOperations.store(0);
    epollWaits.store(0);
    eventfdWakeups.store(0);
    timerfdTriggers.store(0);
    totalHandlerExecutionTimeNs.store(0);
    maxHandlerExecutionTimeNs.store(0);
    avgHandlerExecutionTimeNs.store(0);
    startTime = std::chrono::steady_clock::now();
  }

  double getUptimeSeconds() const
  {
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime);
    return duration.count() / 1000.0;
  }
};

/// \brief Resource limits to prevent exhaustion.
struct TimerLimits
{
  std::size_t maxConcurrentTimers{10000};
  std::chrono::milliseconds maxTimeout{std::chrono::hours(24)};
  std::chrono::milliseconds maxHandlerExecutionTime{std::chrono::seconds(30)};
  std::size_t maxHeapSize{50000};
  std::size_t maxPeriodicTimers{1000};
};

/// \brief Configuration for enhanced timer service.
struct TimerServiceConfig
{
  int maxEpollEvents{16};                     ///< Maximum events per epoll_wait
  bool throwOnSystemError{false};             ///< Throw vs. log system errors
  std::chrono::milliseconds epollTimeout{-1}; ///< epoll_wait timeout (-1 = infinite)
  std::size_t initialHeapCapacity{256};       ///< Pre-allocate heap capacity
  bool enableStatistics{true};                ///< Enable performance statistics
  bool enableDetailedLogging{false};          ///< Enable verbose logging
  TimerLimits limits;                         ///< Resource limits

  // Thread configuration
  bool setThreadPriority{false};          ///< Set real-time thread priority
  int threadPriority{0};                  ///< Thread priority (if enabled)
  std::string threadName{"TimerService"}; ///< Thread name for debugging
};

/// \brief Enhanced error and event logging interface.
class TimerLogger
{
public:
  enum class Level
  {
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
    Critical = 4
  };

  virtual ~TimerLogger() = default;
  virtual void log(Level level, const std::string &message, TimerError error = TimerError::None,
                   int errno_val = 0) = 0;

  // Convenience methods
  void debug(const std::string &msg) { log(Level::Debug, msg); }
  void info(const std::string &msg) { log(Level::Info, msg); }
  void warning(const std::string &msg) { log(Level::Warning, msg); }
  void error(const std::string &msg, TimerError err = TimerError::None, int errno_val = 0)
  {
    log(Level::Error, msg, err, errno_val);
  }
  void critical(const std::string &msg, TimerError err = TimerError::None, int errno_val = 0)
  {
    log(Level::Critical, msg, err, errno_val);
  }
};

/// \brief Default console logger implementation.
class ConsoleTimerLogger : public TimerLogger
{
public:
  explicit ConsoleTimerLogger(Level minLevel = Level::Info) : _minLevel(minLevel) {}

  void log(Level level, const std::string &message, TimerError error = TimerError::None,
           int errno_val = 0) override
  {
    if (level < _minLevel)
      return;

    std::string levelStr;
    switch (level)
    {
    case Level::Debug:
      levelStr = "DEBUG";
      break;
    case Level::Info:
      levelStr = "INFO";
      break;
    case Level::Warning:
      levelStr = "WARN";
      break;
    case Level::Error:
      levelStr = "ERROR";
      break;
    case Level::Critical:
      levelStr = "CRITICAL";
      break;
    }

    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);

    std::printf("[%04d-%02d-%02d %02d:%02d:%02d] [%s] %s", tm.tm_year + 1900, tm.tm_mon + 1,
                tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, levelStr.c_str(), message.c_str());

    if (error != TimerError::None)
    {
      std::printf(" (error: %d)", static_cast<int>(error));
    }

    if (errno_val != 0)
    {
      std::printf(" (errno: %d - %s)", errno_val, strerror(errno_val));
    }

    std::printf("\n");
    std::fflush(stdout);
  }

private:
  Level _minLevel;
};

/// \brief Linux epoll-based timer service.
class TimerService : public iora::common::ILifecycleManaged
{
public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;
  using Duration = Clock::duration;
  /// \brief Type-erased handler that supports move-only types.
  class Handler
  {
  public:
    template <typename F>
    Handler(F &&f) : _impl(std::make_unique<Model<std::decay_t<F>>>(std::forward<F>(f)))
    {
    }

    Handler(const Handler &) = delete;
    Handler &operator=(const Handler &) = delete;

    Handler(Handler &&) = default;
    Handler &operator=(Handler &&) = default;

    void operator()() const
    {
      if (_impl)
        _impl->call();
    }

    explicit operator bool() const { return static_cast<bool>(_impl); }

  private:
    struct Concept
    {
      virtual ~Concept() = default;
      virtual void call() = 0;
    };

    template <typename F> struct Model : Concept
    {
      F _f;
      explicit Model(F f) : _f(std::move(f)) {}
      void call() override { _f(); }
    };

    std::unique_ptr<Concept> _impl;
  };

  /// \brief Enhanced error handler with context.
  using ErrorHandler =
    std::function<void(TimerError error, const std::string &message, int errno_val)>;

  /// \brief Start the service with configuration.
  explicit TimerService(const TimerServiceConfig &config = {})
      : _config(config), _logger(std::make_shared<ConsoleTimerLogger>())
  {
    _heap.reserve(_config.initialHeapCapacity);
    initialize();
  }

  /// \brief Start the service with custom logger.
  TimerService(const TimerServiceConfig &config, std::shared_ptr<TimerLogger> logger)
      : _config(config), _logger(std::move(logger))
  {
    _heap.reserve(_config.initialHeapCapacity);
    initialize();
  }

  /// \brief Stop the service and join the thread.
  ~TimerService() { stop(); }

  TimerService(const TimerService &) = delete;
  TimerService &operator=(const TimerService &) = delete;

  /// \brief Schedule handler at absolute time with perfect forwarding.
  template <typename Handler> std::uint64_t scheduleAt(TimePoint tp, Handler &&handler)
  {
    static_assert(std::is_invocable_v<Handler>, "Handler must be callable with no arguments");

    // Check if service is accepting new timers
    if (!_accepting.load(std::memory_order_acquire))
    {
      handleError(TimerError::ServiceStopped, "Timer service is draining and not accepting new timers", 0);
      return 0;
    }

    if (!isValidTimeout(tp))
    {
      handleError(TimerError::InvalidTimeout, "Timeout exceeds maximum allowed", 0);
      return 0;
    }

    std::lock_guard<std::mutex> lock(_mutex);

    if (_records.size() >= _config.limits.maxConcurrentTimers)
    {
      handleError(TimerError::ResourceExhausted, "Maximum concurrent timers exceeded", 0);
      return 0;
    }

    std::uint64_t id = ++_nextId;
    _records.emplace(id, Record{tp, std::forward<Handler>(handler), false, false});
    _heap.emplace_back(HeapItem{tp, id});
    siftUp(_heap.size() - 1);

    if (_config.enableStatistics)
    {
      _stats.timersScheduled.fetch_add(1, std::memory_order_relaxed);
      _stats.heapOperations.fetch_add(1, std::memory_order_relaxed);
    }

    poke();

    if (_config.enableDetailedLogging)
    {
      _logger->debug("Timer " + std::to_string(id) + " scheduled");
    }

    return id;
  }

  /// \brief Schedule handler after duration with perfect forwarding.
  template <typename Handler> std::uint64_t scheduleAfter(Duration d, Handler &&handler)
  {
    return scheduleAt(Clock::now() + d, std::forward<Handler>(handler));
  }

  /// \brief Schedule periodic timer (simplified implementation).
  template <typename F> std::uint64_t schedulePeriodic(Duration interval, F &&handler)
  {
    if (_periodicTimers.size() >= _config.limits.maxPeriodicTimers)
    {
      handleError(TimerError::ResourceExhausted, "Maximum periodic timers exceeded", 0);
      return 0;
    }

    std::uint64_t id = ++_nextId;

    {
      std::lock_guard<std::mutex> lock(_mutex);
      _periodicTimers.emplace(id, PeriodicTimer{id, interval, Clock::now() + interval, false});
    }

    if (_config.enableStatistics)
    {
      _stats.periodicTimersActive.fetch_add(1, std::memory_order_relaxed);
    }

    // Simple implementation: just schedule once for now
    // For a full implementation, you'd want a proper periodic scheduling
    // mechanism
    return scheduleAt(Clock::now() + interval, std::forward<F>(handler));
  }

  /// \brief Cancel a scheduled timer; returns true if existed.
  bool cancel(std::uint64_t id)
  {
    std::lock_guard<std::mutex> lock(_mutex);

    // Check regular timers
    auto it = _records.find(id);
    if (it != _records.end())
    {
      it->second.canceled = true;
      poke();

      if (_config.enableStatistics)
      {
        _stats.timersCanceled.fetch_add(1, std::memory_order_relaxed);
      }

      if (_config.enableDetailedLogging)
      {
        _logger->debug("Timer " + std::to_string(id) + " canceled");
      }

      return true;
    }

    // Check periodic timers
    auto periodicIt = _periodicTimers.find(id);
    if (periodicIt != _periodicTimers.end())
    {
      periodicIt->second.canceled = true;

      if (_config.enableStatistics)
      {
        _stats.periodicTimersActive.fetch_sub(1, std::memory_order_relaxed);
      }

      return true;
    }

    return false;
  }

  /// \brief Get current statistics.
  const TimerStats &getStats() const { return _stats; }

  /// \brief Reset statistics.
  void resetStats()
  {
    _stats.reset();
    _logger->info("Timer statistics reset");
  }

  /// \brief Get current configuration.
  const TimerServiceConfig &getConfig() const { return _config; }

  /// \brief Set error handler.
  void setErrorHandler(ErrorHandler handler)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _errorHandler = std::move(handler);
  }

  /// \brief Set logger.
  void setLogger(std::shared_ptr<TimerLogger> logger)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _logger = std::move(logger);
  }

  // ═══════════════════════════════════════════════════════════════════
  // ILifecycleManaged Interface Implementation
  // ═══════════════════════════════════════════════════════════════════

  /// Start the timer service (Created/Reset → Running)
  /// @return Result indicating success and new state
  iora::common::LifecycleResult start() override
  {
    using iora::common::LifecycleState;
    using iora::common::LifecycleResult;

    auto currentState = _lifecycleState.load(std::memory_order_acquire);

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

    // If in Created state, already started in constructor
    if (currentState == LifecycleState::Created)
    {
      return LifecycleResult(true, LifecycleState::Running, "Already running");
    }

    // Reset → Running: restart the service
    try
    {
      initialize();
      return LifecycleResult(true, LifecycleState::Running, "Timer service started");
    }
    catch (const TimerException &e)
    {
      return LifecycleResult(false, currentState, std::string("Start failed: ") + e.what());
    }
  }

  /// Begin graceful drain (Running → Draining)
  /// @param timeoutMs Maximum time to wait for in-flight timers (0 = wait indefinitely)
  /// @return Result with drain statistics
  iora::common::LifecycleResult drain(std::uint32_t timeoutMs = 30000) override
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

    // Transition to Draining and stop accepting new timers
    _lifecycleState.store(LifecycleState::Draining, std::memory_order_release);
    _accepting.store(false, std::memory_order_release);

    // Capture initial in-flight count
    std::uint32_t inFlightAtStart = getInFlightCount();

    _logger->info("Draining timer service, in-flight timers: " + std::to_string(inFlightAtStart));

    // Wait for all in-flight timers to complete
    int waitMs = 0;
    const int maxWaitMs = (timeoutMs == 0) ? 3600000 : static_cast<int>(timeoutMs); // 1 hour if 0

    std::uint32_t remaining = inFlightAtStart;
    bool timedOut = false;

    while (waitMs < maxWaitMs)
    {
      remaining = getInFlightCount();

      if (remaining == 0)
      {
        break;
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      waitMs += 10;
    }

    if (waitMs >= maxWaitMs && remaining > 0)
    {
      timedOut = true;
    }

    std::uint32_t completed = inFlightAtStart - remaining;

    DrainStats stats(inFlightAtStart, remaining, 0, completed);

    std::string message = timedOut
      ? "Drain timed out with " + std::to_string(remaining) + " timers remaining"
      : "Drain completed successfully";

    _logger->info(message);

    return LifecycleResult(!timedOut, LifecycleState::Draining, message, stats);
  }

  /// Stop the timer service (Running/Draining → Stopped)
  /// @return Result indicating success and new state
  iora::common::LifecycleResult stop() override
  {
    using iora::common::LifecycleState;
    using iora::common::LifecycleResult;

    auto currentState = _lifecycleState.load(std::memory_order_acquire);

    // Can't stop from Stopped or Reset state
    if (currentState == LifecycleState::Stopped || currentState == LifecycleState::Reset)
    {
      return LifecycleResult(false, currentState,
                             "Cannot stop from Stopped or Reset state");
    }

    // If in Running state, drain first
    if (currentState == LifecycleState::Running)
    {
      auto drainResult = drain(5000); // 5 second drain timeout
      if (!drainResult.success)
      {
        _logger->warning("Drain failed during stop, forcing shutdown");
      }
    }

    // Now transition to Stopped
    bool expected = true;
    if (_running.compare_exchange_strong(expected, false, std::memory_order_acq_rel))
    {
      _logger->info("Stopping timer service");
      poke();

      if (_thread.joinable())
      {
        _thread.join();
      }

      cleanup();
      _lifecycleState.store(LifecycleState::Stopped, std::memory_order_release);
      _logger->info("Timer service stopped");

      return LifecycleResult(true, LifecycleState::Stopped, "Timer service stopped");
    }

    // Already stopped
    _lifecycleState.store(LifecycleState::Stopped, std::memory_order_release);
    return LifecycleResult(true, LifecycleState::Stopped, "Already stopped");
  }

  /// Reset to clean state (Stopped → Reset)
  /// @return Result indicating success and new state
  iora::common::LifecycleResult reset() override
  {
    using iora::common::LifecycleState;
    using iora::common::LifecycleResult;

    auto currentState = _lifecycleState.load(std::memory_order_acquire);

    // Can only reset from Stopped state
    if (currentState != LifecycleState::Stopped)
    {
      return LifecycleResult(false, currentState,
                             "Can only reset from Stopped state");
    }

    // Clear all state
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _records.clear();
      _periodicTimers.clear();
      _heap.clear();
      _nextId = 0;
    }

    // Reset statistics
    _stats.reset();

    _lifecycleState.store(LifecycleState::Reset, std::memory_order_release);
    _logger->info("Timer service reset to clean state");

    return LifecycleResult(true, LifecycleState::Reset, "Timer service reset");
  }

  /// Get current lifecycle state
  /// @return Current lifecycle state
  iora::common::LifecycleState getState() const override
  {
    return _lifecycleState.load(std::memory_order_acquire);
  }

  /// Get in-flight timer count (scheduled + periodic timers)
  /// @return Number of in-flight timers
  std::uint32_t getInFlightCount() const override
  {
    std::lock_guard<std::mutex> lock(_mutex);

    // Count non-canceled timers in _records
    std::uint32_t activeTimers = 0;
    for (const auto &pair : _records)
    {
      if (!pair.second.canceled)
      {
        activeTimers++;
      }
    }

    // Count non-canceled periodic timers
    for (const auto &pair : _periodicTimers)
    {
      if (!pair.second.canceled)
      {
        activeTimers++;
      }
    }

    return activeTimers;
  }

private:
  struct Record
  {
    TimePoint tp;
    Handler handler;
    bool canceled{false};
    bool periodic{false};
  };

  struct HeapItem
  {
    TimePoint tp;
    std::uint64_t id;
  };

  struct PeriodicTimer
  {
    std::uint64_t id;
    Duration interval;
    TimePoint nextExecution;
    bool canceled{false};
  };

  static bool less(const HeapItem &a, const HeapItem &b)
  {
    return a.tp < b.tp || (a.tp == b.tp && a.id < b.id);
  }

  void initialize()
  {
    try
    {
      _epollFd = ::epoll_create1(EPOLL_CLOEXEC);
      if (_epollFd < 0)
      {
        throw TimerException(TimerError::SystemError, "epoll_create1 failed", errno);
      }

      _timerFd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
      if (_timerFd < 0)
      {
        ::close(_epollFd);
        throw TimerException(TimerError::SystemError, "timerfd_create failed", errno);
      }

      _eventFd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
      if (_eventFd < 0)
      {
        ::close(_timerFd);
        ::close(_epollFd);
        throw TimerException(TimerError::SystemError, "eventfd create failed", errno);
      }

      addEpollFd(_timerFd, EPOLLIN);
      addEpollFd(_eventFd, EPOLLIN);

      _running.store(true, std::memory_order_release);
      _thread = std::thread([this]() { this->runLoop(); });

      // Set thread name and priority if configured
      configureThread();

      // Set lifecycle state to Running
      _accepting.store(true, std::memory_order_release);
      _lifecycleState.store(iora::common::LifecycleState::Running, std::memory_order_release);

      _logger->info("Timer service started successfully");
    }
    catch (const TimerException &e)
    {
      handleError(e.code(), e.what(), e.getErrno());
      if (_config.throwOnSystemError)
      {
        throw;
      }
    }
  }

  void configureThread()
  {
#ifdef __linux__
    if (_config.setThreadPriority)
    {
      struct sched_param param;
      param.sched_priority = _config.threadPriority;
      if (pthread_setschedparam(_thread.native_handle(), SCHED_FIFO, &param) != 0)
      {
        _logger->warning("Failed to set thread priority");
      }
    }

    if (!_config.threadName.empty())
    {
      pthread_setname_np(_thread.native_handle(), _config.threadName.c_str());
    }
#endif
  }

  void cleanup()
  {
    if (_eventFd >= 0)
    {
      ::close(_eventFd);
      _eventFd = -1;
    }
    if (_timerFd >= 0)
    {
      ::close(_timerFd);
      _timerFd = -1;
    }
    if (_epollFd >= 0)
    {
      ::close(_epollFd);
      _epollFd = -1;
    }
  }

  bool isValidTimeout(TimePoint tp) const
  {
    auto now = Clock::now();
    auto duration = tp - now;
    return duration <= _config.limits.maxTimeout;
  }

  void handleError(TimerError error, const std::string &message, int errno_val)
  {
    if (_config.enableStatistics && error == TimerError::SystemError)
    {
      _stats.systemErrors.fetch_add(1, std::memory_order_relaxed);
    }

    _logger->error(message, error, errno_val);

    if (_errorHandler)
    {
      try
      {
        _errorHandler(error, message, errno_val);
      }
      catch (...)
      {
        _logger->critical("Error handler threw exception");
      }
    }
  }

  void siftUp(std::size_t idx)
  {
    while (idx > 0)
    {
      std::size_t parent = (idx - 1) / 2;
      if (!less(_heap[idx], _heap[parent]))
      {
        break;
      }
      std::swap(_heap[idx], _heap[parent]);
      idx = parent;
    }
  }

  void siftDown(std::size_t idx)
  {
    for (;;)
    {
      std::size_t left = idx * 2 + 1;
      std::size_t right = left + 1;
      std::size_t smallest = idx;
      if (left < _heap.size() && less(_heap[left], _heap[smallest]))
      {
        smallest = left;
      }
      if (right < _heap.size() && less(_heap[right], _heap[smallest]))
      {
        smallest = right;
      }
      if (smallest == idx)
      {
        break;
      }
      std::swap(_heap[idx], _heap[smallest]);
      idx = smallest;
    }
  }

  std::optional<HeapItem> heapTop() const
  {
    if (_heap.empty())
    {
      return std::nullopt;
    }
    return _heap.front();
  }

  void heapPop()
  {
    if (_heap.empty())
    {
      return;
    }
    std::swap(_heap.front(), _heap.back());
    _heap.pop_back();
    if (!_heap.empty())
    {
      siftDown(0);
    }

    if (_config.enableStatistics)
    {
      _stats.heapOperations.fetch_add(1, std::memory_order_relaxed);
    }
  }

  void programTimerfd(std::optional<TimePoint> nextDue)
  {
    itimerspec its{};
    if (nextDue.has_value())
    {
      TimePoint now = Clock::now();
      auto delta = (nextDue.value() > now) ? (nextDue.value() - now) : Duration::zero();
      auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(delta).count();

      its.it_value.tv_sec = static_cast<time_t>(ns / 1000000000LL);
      its.it_value.tv_nsec = static_cast<long>(ns % 1000000000LL);

      if (its.it_value.tv_sec == 0 && its.it_value.tv_nsec == 0)
      {
        its.it_value.tv_nsec = 1;
      }
    }

    if (::timerfd_settime(_timerFd, 0, &its, nullptr) != 0)
    {
      handleError(TimerError::SystemError, "timerfd_settime failed", errno);
      if (_config.throwOnSystemError)
      {
        throw TimerException(TimerError::SystemError, "timerfd_settime failed", errno);
      }
    }
  }

  void poke()
  {
    std::uint64_t one = 1;
    ssize_t n = ::write(_eventFd, &one, sizeof(one));
    if (n < 0 && errno != EAGAIN)
    {
      handleError(TimerError::SystemError, "eventfd write failed", errno);
    }
  }

  void drainEventfd()
  {
    std::uint64_t val = 0;
    while (true)
    {
      ssize_t n = ::read(_eventFd, &val, sizeof(val));
      if (n < 0)
      {
        if (errno == EAGAIN)
        {
          break;
        }
        break;
      }
      if (n < static_cast<ssize_t>(sizeof(val)))
      {
        break;
      }
    }

    if (_config.enableStatistics)
    {
      _stats.eventfdWakeups.fetch_add(1, std::memory_order_relaxed);
    }
  }

  void drainTimerfd()
  {
    std::uint64_t expirations = 0;
    (void)::read(_timerFd, &expirations, sizeof(expirations));

    if (_config.enableStatistics)
    {
      _stats.timerfdTriggers.fetch_add(1, std::memory_order_relaxed);
    }
  }

  void addEpollFd(int fd, std::uint32_t events)
  {
    epoll_event ev{};
    ev.events = events;
    ev.data.fd = fd;
    if (::epoll_ctl(_epollFd, EPOLL_CTL_ADD, fd, &ev) != 0)
    {
      throw TimerException(TimerError::SystemError, "epoll_ctl(ADD) failed", errno);
    }
  }

  void collectDueLocked(TimePoint now, std::vector<Handler> &out)
  {
    while (!_heap.empty())
    {
      const HeapItem &top = _heap.front();
      if (top.tp > now)
      {
        break;
      }

      auto it = _records.find(top.id);
      heapPop();

      if (it == _records.end())
      {
        continue;
      }

      Record rec = std::move(it->second);
      _records.erase(it);

      if (!rec.canceled)
      {
        out.push_back(std::move(rec.handler));

        if (_config.enableStatistics)
        {
          _stats.timersExpired.fetch_add(1, std::memory_order_relaxed);
        }
      }
    }
  }

  void safeRun(const Handler &h)
  {
    if (!static_cast<bool>(h))
      return;

    auto start = std::chrono::steady_clock::now();

    try
    {
      h();

      if (_config.enableStatistics)
      {
        _stats.timersExecuted.fetch_add(1, std::memory_order_relaxed);

        auto end = std::chrono::steady_clock::now();
        auto duration = static_cast<std::uint64_t>(
          std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());

        _stats.totalHandlerExecutionTimeNs.fetch_add(duration, std::memory_order_relaxed);

        // Update max execution time
        auto currentMax = _stats.maxHandlerExecutionTimeNs.load(std::memory_order_relaxed);
        while (duration > currentMax && !_stats.maxHandlerExecutionTimeNs.compare_exchange_weak(
                                          currentMax, duration, std::memory_order_relaxed))
        {
        }

        // Update average (simple moving average)
        auto totalExecuted = _stats.timersExecuted.load(std::memory_order_relaxed);
        auto totalTime = _stats.totalHandlerExecutionTimeNs.load(std::memory_order_relaxed);
        _stats.avgHandlerExecutionTimeNs.store(totalTime / totalExecuted,
                                               std::memory_order_relaxed);
      }
    }
    catch (...)
    {
      if (_config.enableStatistics)
      {
        _stats.exceptionsSwallowed.fetch_add(1, std::memory_order_relaxed);
      }
      handleError(TimerError::HandlerException, "Timer handler threw exception", 0);
    }
  }

  void runLoop()
  {
    _logger->info("Timer service loop started");

    std::vector<epoll_event> events(_config.maxEpollEvents);

    for (;;)
    {
      std::optional<TimePoint> nextDue;
      std::vector<Handler> ready;

      {
        std::lock_guard<std::mutex> lock(_mutex);

        if (!_running.load(std::memory_order_acquire))
        {
          TimePoint now = Clock::now();
          collectDueLocked(now, ready);
          programTimerfd(std::nullopt);
          for (auto &h : ready)
          {
            safeRun(h);
          }
          break;
        }

        if (auto top = heapTop())
        {
          nextDue = top->tp;
        }

        programTimerfd(nextDue);
      }

      for (auto &h : ready)
      {
        safeRun(h);
      }
      ready.clear();

      int timeout =
        _config.epollTimeout.count() >= 0 ? static_cast<int>(_config.epollTimeout.count()) : -1;
      int rc = ::epoll_wait(_epollFd, events.data(), _config.maxEpollEvents, timeout);

      if (_config.enableStatistics)
      {
        _stats.epollWaits.fetch_add(1, std::memory_order_relaxed);
      }

      if (rc < 0)
      {
        if (errno == EINTR)
        {
          continue;
        }
        handleError(TimerError::SystemError, "epoll_wait failed", errno);
        if (_config.throwOnSystemError)
        {
          break;
        }
        continue;
      }

      bool timerTriggered = false;
      bool woke = false;

      for (int i = 0; i < rc; ++i)
      {
        int fd = events[i].data.fd;
        std::uint32_t ev = events[i].events;

        if ((ev & (EPOLLERR | EPOLLHUP)) != 0)
        {
          _logger->warning("epoll error on fd " + std::to_string(fd));
        }

        if (fd == _timerFd && (ev & EPOLLIN))
        {
          timerTriggered = true;
        }
        else if (fd == _eventFd && (ev & EPOLLIN))
        {
          woke = true;
        }
      }

      if (woke)
      {
        drainEventfd();
      }
      if (timerTriggered)
      {
        drainTimerfd();
      }

      {
        std::lock_guard<std::mutex> lock(_mutex);
        TimePoint now = Clock::now();
        collectDueLocked(now, ready);
      }

      for (auto &h : ready)
      {
        safeRun(h);
      }
    }

    _logger->info("Timer service loop finished");
  }

private:
  // Configuration and logging
  TimerServiceConfig _config;
  std::shared_ptr<TimerLogger> _logger;
  ErrorHandler _errorHandler;

  // Statistics
  mutable TimerStats _stats;

  // Timer bookkeeping
  mutable std::mutex _mutex;
  std::unordered_map<std::uint64_t, Record> _records;
  std::unordered_map<std::uint64_t, PeriodicTimer> _periodicTimers;
  std::vector<HeapItem> _heap;
  std::uint64_t _nextId{0};

  // Threading and fds
  std::atomic<bool> _running{false};
  std::thread _thread;
  int _epollFd{-1};
  int _timerFd{-1};
  int _eventFd{-1};

  // Lifecycle management
  std::atomic<iora::common::LifecycleState> _lifecycleState{iora::common::LifecycleState::Created};
  std::atomic<bool> _accepting{false};
};

/// \brief Enhanced ASIO-like timer bound to TimerService.
class SteadyTimer
{
public:
  using Clock = TimerService::Clock;
  using TimePoint = TimerService::TimePoint;
  using Duration = TimerService::Duration;
  using Handler = TimerService::Handler;

  explicit SteadyTimer(TimerService &svc) : _svc(svc) {}

  ~SteadyTimer()
  {
    cancel();
    _shared.reset();
  }

  void expiresAt(TimePoint tp) { _expiry = tp; }

  void expiresAfter(Duration d) { _expiry = Clock::now() + d; }

  /// \brief Arm the timer with perfect forwarding.
  template <typename Handler> void asyncWait(Handler &&handler)
  {
    cancel();
    _shared = std::make_shared<Shared>();
    TimePoint tp = _expiry.value_or(Clock::now());
    std::weak_ptr<Shared> w = _shared;

    _token = _svc.scheduleAt(tp,
                             [w, h = std::forward<Handler>(handler)]() mutable
                             {
                               if (auto s = w.lock())
                               {
                                 if (!s->canceled.load(std::memory_order_acquire))
                                 {
                                   try
                                   {
                                     h();
                                   }
                                   catch (...)
                                   {
                                     // Exception handling is done in the service
                                   }
                                 }
                               }
                             });
  }

  bool cancel()
  {
    if (_shared)
    {
      _shared->canceled.store(true, std::memory_order_release);
    }
    if (_token)
    {
      bool ok = _svc.cancel(*_token);
      _token.reset();
      return ok;
    }
    return false;
  }

  /// \brief Get the underlying service.
  TimerService &getService() { return _svc; }
  const TimerService &getService() const { return _svc; }

private:
  struct Shared
  {
    std::atomic<bool> canceled{false};
  };

  TimerService &_svc;
  std::optional<TimePoint> _expiry;
  std::optional<std::uint64_t> _token;
  std::shared_ptr<Shared> _shared;
};

/// \brief Timer service pool for high-load scenarios.
class TimerServicePool
{
public:
  /// \brief Create pool with specified number of services.
  explicit TimerServicePool(std::size_t numServices = std::thread::hardware_concurrency(),
                            const TimerServiceConfig &config = {})
      : _config(config)
  {
    if (numServices == 0)
    {
      numServices = 1;
    }

    _services.reserve(numServices);
    for (std::size_t i = 0; i < numServices; ++i)
    {
      auto serviceConfig = _config;
      serviceConfig.threadName = _config.threadName + "_" + std::to_string(i);
      _services.emplace_back(std::make_unique<TimerService>(serviceConfig));
    }

    _logger = std::make_shared<ConsoleTimerLogger>();
    _logger->info("Timer service pool created with " + std::to_string(numServices) + " services");
  }

  /// \brief Create pool with custom logger.
  TimerServicePool(std::size_t numServices, const TimerServiceConfig &config,
                   std::shared_ptr<TimerLogger> logger)
      : _config(config), _logger(std::move(logger))
  {
    if (numServices == 0)
    {
      numServices = 1;
    }

    _services.reserve(numServices);
    for (std::size_t i = 0; i < numServices; ++i)
    {
      auto serviceConfig = _config;
      serviceConfig.threadName = _config.threadName + "_" + std::to_string(i);
      _services.emplace_back(std::make_unique<TimerService>(serviceConfig, _logger));
    }

    _logger->info("Timer service pool created with " + std::to_string(numServices) + " services");
  }

  ~TimerServicePool() { stop(); }

  /// \brief Get next service using round-robin selection.
  TimerService &getService()
  {
    std::size_t index = _nextIndex.fetch_add(1, std::memory_order_relaxed) % _services.size();
    return *_services[index];
  }

  /// \brief Get service with least load (based on active timers).
  TimerService &getLeastLoadedService()
  {
    if (_services.empty())
    {
      throw TimerException(TimerError::ConfigurationError, "No services available in pool", 0);
    }

    auto *bestService = _services[0].get();
    std::uint64_t minLoad = bestService->getStats().timersScheduled.load() -
                            bestService->getStats().timersExecuted.load();

    for (std::size_t i = 1; i < _services.size(); ++i)
    {
      auto *service = _services[i].get();
      std::uint64_t load =
        service->getStats().timersScheduled.load() - service->getStats().timersExecuted.load();
      if (load < minLoad)
      {
        minLoad = load;
        bestService = service;
      }
    }

    return *bestService;
  }

  /// \brief Get number of services in pool.
  std::size_t size() const { return _services.size(); }

  /// \brief Stop all services.
  void stop()
  {
    _logger->info("Stopping timer service pool");
    for (auto &service : _services)
    {
      service->stop();
    }
    _logger->info("Timer service pool stopped");
  }

  /// \brief Get aggregated statistics from all services.
  void getAggregatedStats(TimerStats &aggregated) const
  {
    aggregated.reset();

    for (const auto &service : _services)
    {
      const auto &stats = service->getStats();
      aggregated.timersScheduled.store(aggregated.timersScheduled.load() +
                                         stats.timersScheduled.load(),
                                       std::memory_order_relaxed);
      aggregated.timersCanceled.store(
        aggregated.timersCanceled.load() + stats.timersCanceled.load(), std::memory_order_relaxed);
      aggregated.timersExecuted.store(
        aggregated.timersExecuted.load() + stats.timersExecuted.load(), std::memory_order_relaxed);
      aggregated.timersExpired.store(aggregated.timersExpired.load() + stats.timersExpired.load(),
                                     std::memory_order_relaxed);
      aggregated.periodicTimersActive.store(aggregated.periodicTimersActive.load() +
                                              stats.periodicTimersActive.load(),
                                            std::memory_order_relaxed);
      aggregated.exceptionsSwallowed.store(aggregated.exceptionsSwallowed.load() +
                                             stats.exceptionsSwallowed.load(),
                                           std::memory_order_relaxed);
      aggregated.systemErrors.store(aggregated.systemErrors.load() + stats.systemErrors.load(),
                                    std::memory_order_relaxed);
      aggregated.heapOperations.store(
        aggregated.heapOperations.load() + stats.heapOperations.load(), std::memory_order_relaxed);
      aggregated.epollWaits.store(aggregated.epollWaits.load() + stats.epollWaits.load(),
                                  std::memory_order_relaxed);
      aggregated.eventfdWakeups.store(
        aggregated.eventfdWakeups.load() + stats.eventfdWakeups.load(), std::memory_order_relaxed);
      aggregated.timerfdTriggers.store(aggregated.timerfdTriggers.load() +
                                         stats.timerfdTriggers.load(),
                                       std::memory_order_relaxed);
    }
  }

  /// \brief Reset statistics for all services.
  void resetStats()
  {
    for (auto &service : _services)
    {
      service->resetStats();
    }
  }

private:
  TimerServiceConfig _config;
  std::shared_ptr<TimerLogger> _logger;
  std::vector<std::unique_ptr<TimerService>> _services;
  std::atomic<std::size_t> _nextIndex{0};
};

/// \brief Convenience builder for timer configuration.
class TimerConfigBuilder
{
public:
  TimerConfigBuilder &maxEpollEvents(int events)
  {
    _config.maxEpollEvents = events;
    return *this;
  }
  TimerConfigBuilder &throwOnSystemError(bool enable)
  {
    _config.throwOnSystemError = enable;
    return *this;
  }
  TimerConfigBuilder &epollTimeout(std::chrono::milliseconds timeout)
  {
    _config.epollTimeout = timeout;
    return *this;
  }
  TimerConfigBuilder &initialHeapCapacity(std::size_t capacity)
  {
    _config.initialHeapCapacity = capacity;
    return *this;
  }
  TimerConfigBuilder &enableStatistics(bool enable)
  {
    _config.enableStatistics = enable;
    return *this;
  }
  TimerConfigBuilder &enableDetailedLogging(bool enable)
  {
    _config.enableDetailedLogging = enable;
    return *this;
  }
  TimerConfigBuilder &maxConcurrentTimers(std::size_t max)
  {
    _config.limits.maxConcurrentTimers = max;
    return *this;
  }
  TimerConfigBuilder &maxTimeout(std::chrono::milliseconds timeout)
  {
    _config.limits.maxTimeout = timeout;
    return *this;
  }
  TimerConfigBuilder &threadPriority(bool enable, int priority = 0)
  {
    _config.setThreadPriority = enable;
    _config.threadPriority = priority;
    return *this;
  }
  TimerConfigBuilder &threadName(const std::string &name)
  {
    _config.threadName = name;
    return *this;
  }

  TimerServiceConfig build() const { return _config; }

private:
  TimerServiceConfig _config;
};

} // namespace core
} // namespace iora