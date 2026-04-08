#define CATCH_CONFIG_MAIN
#include "iora/core/timer.hpp"
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

using namespace iora::core;
using namespace std::chrono_literals;

// Custom test logger for testing
class TestTimerLogger : public TimerLogger
{
public:
  struct LogEntry
  {
    Level level;
    std::string message;
    TimerError error;
    int errno_val;
  };

  void log(Level level, const std::string &message, TimerError error = TimerError::None,
           int errno_val = 0) override
  {
    std::lock_guard<std::mutex> lock(_mtx);
    _entries.push_back({level, message, error, errno_val});
  }

  void clear()
  {
    std::lock_guard<std::mutex> lock(_mtx);
    _entries.clear();
  }

  size_t count() const
  {
    std::lock_guard<std::mutex> lock(_mtx);
    return _entries.size();
  }

  bool hasMessage(const std::string &msg) const
  {
    std::lock_guard<std::mutex> lock(_mtx);
    for (const auto &entry : _entries)
    {
      if (entry.message.find(msg) != std::string::npos)
      {
        return true;
      }
    }
    return false;
  }

private:
  mutable std::mutex _mtx;
  std::vector<LogEntry> _entries;
};

TEST_CASE("TimerService basic functionality", "[enhanced_timer][basic]")
{
  SECTION("Service initialization and shutdown")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).threadName("TestTimer").build();

    TimerService service(config);

    // Service should start successfully
    REQUIRE_NOTHROW(service.scheduleAfter(1ms, []() {}));

    // Wait briefly for any scheduled timers
    std::this_thread::sleep_for(10ms);

    const auto &stats = service.getStats();
    REQUIRE(stats.timersScheduled.load() == 1);
  }

  SECTION("Basic timer execution")
  {
    TimerService service;
    std::atomic<bool> executed{false};

    service.scheduleAfter(50ms, [&executed]() { executed = true; });

    // Timer should not have executed yet
    REQUIRE(executed.load() == false);

    // Wait for execution
    std::this_thread::sleep_for(100ms);

    // Timer should have executed
    REQUIRE(executed.load() == true);
  }

  SECTION("Multiple timers execution order")
  {
    TimerService service;
    std::vector<int> execution_order;
    std::mutex order_mutex;

    // Schedule timers in reverse order of execution
    service.scheduleAfter(100ms,
                          [&]()
                          {
                            std::lock_guard<std::mutex> lock(order_mutex);
                            execution_order.push_back(3);
                          });

    service.scheduleAfter(50ms,
                          [&]()
                          {
                            std::lock_guard<std::mutex> lock(order_mutex);
                            execution_order.push_back(2);
                          });

    service.scheduleAfter(25ms,
                          [&]()
                          {
                            std::lock_guard<std::mutex> lock(order_mutex);
                            execution_order.push_back(1);
                          });

    std::this_thread::sleep_for(250ms);

    REQUIRE(execution_order.size() == 3);
    REQUIRE(execution_order[0] == 1);
    REQUIRE(execution_order[1] == 2);
    REQUIRE(execution_order[2] == 3);
  }
}

TEST_CASE("TimerService statistics", "[enhanced_timer][stats]")
{
  SECTION("Basic statistics tracking")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).build();

    TimerService service(config);

    // Schedule some timers
    service.scheduleAfter(10ms, []() {});
    service.scheduleAfter(20ms, []() {});
    service.scheduleAfter(30ms, []() {});

    // Wait for execution
    std::this_thread::sleep_for(50ms);

    const auto &stats = service.getStats();
    REQUIRE(stats.timersScheduled.load() == 3);
    REQUIRE(stats.timersExecuted.load() == 3);
    REQUIRE(stats.timersCanceled.load() == 0);
  }

  SECTION("Cancellation statistics")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).build();

    TimerService service(config);

    // Schedule and cancel a timer
    auto id = service.scheduleAfter(100ms, []() {});
    bool canceled = service.cancel(id);

    REQUIRE(canceled == true);

    std::this_thread::sleep_for(150ms);

    const auto &stats = service.getStats();
    REQUIRE(stats.timersScheduled.load() == 1);
    REQUIRE(stats.timersExecuted.load() == 0);
    REQUIRE(stats.timersCanceled.load() == 1);
  }
}

TEST_CASE("TimerService error handling", "[enhanced_timer][errors]")
{
  SECTION("Exception handling in timer callbacks")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).throwOnSystemError(false).build();

    auto logger = std::make_shared<TestTimerLogger>();
    TimerService service(config, logger);

    // Schedule timer that throws
    service.scheduleAfter(10ms, []() { throw std::runtime_error("Test exception"); });

    std::this_thread::sleep_for(50ms);

    const auto &stats = service.getStats();
    REQUIRE(stats.exceptionsSwallowed.load() == 1);
    REQUIRE(logger->hasMessage("Timer handler threw exception"));
  }

  SECTION("Custom error handler")
  {
    TimerService service;
    std::string last_error;
    TimerError last_error_code = TimerError::None;

    service.setErrorHandler(
      [&](TimerError error, const std::string &message, int errno_val)
      {
        last_error = message;
        last_error_code = error;
      });

    // Schedule timer that throws
    service.scheduleAfter(10ms, []() { throw std::logic_error("Logic error test"); });

    std::this_thread::sleep_for(50ms);

    REQUIRE(last_error_code == TimerError::HandlerException);
    REQUIRE(last_error.find("Timer handler threw exception") != std::string::npos);
  }
}

TEST_CASE("TimerService periodic timers", "[enhanced_timer][periodic]")
{
  SECTION("Basic periodic timer")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).build();

    TimerService service(config);
    std::atomic<int> tick_count{0};

    auto id = service.schedulePeriodic(20ms, [&tick_count]() { tick_count++; });

    // Let it run for a while
    std::this_thread::sleep_for(100ms);

    // Cancel the periodic timer
    service.cancel(id);

    int final_count = tick_count.load();
    REQUIRE(final_count >= 1); // Should have ticked at least once
    REQUIRE(final_count <= 8); // But not too many times

    // Wait a bit more and ensure it doesn't tick again
    std::this_thread::sleep_for(50ms);
    REQUIRE(tick_count.load() == final_count);
  }
}

TEST_CASE("TimerService periodic timer unified ID", "[enhanced_timer][periodic]")
{
  SECTION("cancel(id) cancels periodic timer and updates stats")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).build();
    TimerService service(config);
    std::atomic<int> fired{0};

    auto id = service.schedulePeriodic(500ms, [&fired]() { fired++; });
    REQUIRE(id != 0);

    // Immediately cancel — the timer should not fire
    bool cancelled = service.cancel(id);
    REQUIRE(cancelled);

    // Verify stats
    REQUIRE(service.getStats().periodicTimersActive.load() == 0);
    REQUIRE(service.getStats().timersCanceled.load() == 1);

    // Wait past the scheduled interval
    std::this_thread::sleep_for(700ms);
    REQUIRE(fired.load() == 0);

    // Double cancel should return false and not corrupt stats
    REQUIRE_FALSE(service.cancel(id));
    REQUIRE(service.getStats().periodicTimersActive.load() == 0);
  }

  SECTION("getInFlightCount does not double-count periodic timer")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).build();
    TimerService service(config);

    auto id = service.schedulePeriodic(500ms, []() {});
    REQUIRE(id != 0);

    // A single schedulePeriodic should contribute exactly 1 to in-flight count
    auto count = service.getInFlightCount();
    REQUIRE(count == 1);

    service.cancel(id);
    count = service.getInFlightCount();
    REQUIRE(count == 0);
  }

  SECTION("getInFlightCount after periodic fire reflects rescheduling")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).build();
    TimerService service(config);
    std::atomic<bool> fired{false};

    // Use a large interval so there's no race with a second fire
    auto id = service.schedulePeriodic(200ms, [&fired]() { fired = true; });
    REQUIRE(id != 0);
    REQUIRE(service.getInFlightCount() == 1);

    // Wait for the first fire
    std::this_thread::sleep_for(300ms);
    REQUIRE(fired.load());

    // After firing, the periodic timer is rescheduled — still in-flight
    REQUIRE(service.getInFlightCount() == 1);
    REQUIRE(service.getStats().periodicTimersActive.load() == 1);

    // After cancel, counts should drop to 0
    service.cancel(id);
    REQUIRE(service.getInFlightCount() == 0);
    REQUIRE(service.getStats().periodicTimersActive.load() == 0);
  }
}

TEST_CASE("TimerService periodic rescheduling", "[enhanced_timer][periodic]")
{
  SECTION("Periodic timer fires multiple times")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).build();
    TimerService service(config);
    std::atomic<int> fireCount{0};

    auto id = service.schedulePeriodic(20ms, [&fireCount]() { fireCount++; });

    std::this_thread::sleep_for(100ms);
    service.cancel(id);

    int count = fireCount.load();
    REQUIRE(count >= 3);
    REQUIRE(count <= 8);

    // Verify stats: timersScheduled = 1 (initial) + count (reschedules for each fire)
    // timersExpired = count (each fire increments expired)
    const auto &stats = service.getStats();
    REQUIRE(stats.timersScheduled.load() == static_cast<std::uint64_t>(count + 1));
    REQUIRE(stats.timersExpired.load() == static_cast<std::uint64_t>(count));
  }

  SECTION("Cancel periodic timer after first fire")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).build();
    TimerService service(config);
    std::atomic<int> fireCount{0};

    auto id = service.schedulePeriodic(100ms, [&fireCount]() { fireCount++; });

    // Poll for first fire with timeout
    for (int i = 0; i < 500 && fireCount.load() == 0; ++i)
    {
      std::this_thread::sleep_for(1ms);
    }
    REQUIRE(fireCount.load() >= 1);

    // Cancel immediately — then verify no further fires
    service.cancel(id);
    int countAtCancel = fireCount.load();

    std::this_thread::sleep_for(200ms);
    REQUIRE(fireCount.load() == countAtCancel);
  }

  SECTION("Drain stops periodic timer rescheduling")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).build();
    TimerService service(config);
    std::atomic<int> fireCount{0};

    service.schedulePeriodic(20ms, [&fireCount]() { fireCount++; });

    // Wait for at least one fire
    for (int i = 0; i < 500 && fireCount.load() == 0; ++i)
    {
      std::this_thread::sleep_for(1ms);
    }
    REQUIRE(fireCount.load() >= 1);

    // Drain the service
    auto result = service.drain(5000);
    REQUIRE(result.success);

    int countAtDrain = fireCount.load();

    // Wait and verify no further fires after drain
    std::this_thread::sleep_for(100ms);
    REQUIRE(fireCount.load() == countAtDrain);

    REQUIRE(service.getInFlightCount() == 0);
    REQUIRE(service.getStats().periodicTimersActive.load() == 0);
    REQUIRE(service.getStats().timersCanceled.load() == 1);
  }
}

TEST_CASE("TimerService perfect forwarding", "[enhanced_timer][forwarding]")
{
  SECTION("Move-only handler types")
  {
    class MoveOnlyHandler
    {
    public:
      MoveOnlyHandler(std::string msg) : _message(std::move(msg)) {}
      MoveOnlyHandler(const MoveOnlyHandler &) = delete;
      MoveOnlyHandler &operator=(const MoveOnlyHandler &) = delete;
      MoveOnlyHandler(MoveOnlyHandler &&) = default;
      MoveOnlyHandler &operator=(MoveOnlyHandler &&) = default;

      void operator()() const
      {
        executed = true;
        message_copy = _message;
      }

      mutable bool executed = false;
      mutable std::string message_copy;

    private:
      std::string _message;
    };

    TimerService service;
    std::atomic<bool> ran{false};

    MoveOnlyHandler handler("test message");
    service.scheduleAfter(10ms,
      [h = std::move(handler), &ran]() mutable
      {
        h();
        ran.store(true, std::memory_order_release);
      });

    std::this_thread::sleep_for(50ms);
    REQUIRE(ran.load(std::memory_order_acquire) == true);
  }

  SECTION("Lambda with move capture")
  {
    TimerService service;
    std::atomic<bool> executed{false};

    std::string captured = "captured string";
    service.scheduleAfter(10ms,
                          [captured = std::move(captured), &executed]()
                          {
                            executed = true;
                            // Use captured string to ensure it was moved properly
                            REQUIRE(captured == "captured string");
                          });

    std::this_thread::sleep_for(50ms);
    REQUIRE(executed.load() == true);
  }
}

TEST_CASE("TimerServicePool functionality", "[enhanced_timer][pool]")
{
  SECTION("Load distribution across pool")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).build();

    TimerServicePool pool(3, config);
    std::atomic<int> total_executed{0};

    // Schedule timers across the pool
    for (int i = 0; i < 9; ++i)
    {
      auto &service = pool.getService();
      service.scheduleAfter(10ms, [&total_executed]() { total_executed++; });
    }

    std::this_thread::sleep_for(50ms);

    REQUIRE(total_executed.load() == 9);

    // Check aggregated statistics
    TimerStats aggregated;
    pool.getAggregatedStats(aggregated);
    REQUIRE(aggregated.timersScheduled.load() == 9);
    REQUIRE(aggregated.timersExecuted.load() == 9);
  }
}

TEST_CASE("SteadyTimer compatibility", "[enhanced_timer][steady]")
{
  SECTION("Basic steady timer functionality")
  {
    TimerService service;
    SteadyTimer timer(service);

    std::atomic<bool> executed{false};

    timer.expiresAfter(25ms);
    timer.asyncWait([&executed]() { executed = true; });

    // Should not have executed yet
    std::this_thread::sleep_for(10ms);
    REQUIRE(executed.load() == false);

    // Should execute after the delay
    std::this_thread::sleep_for(30ms);
    REQUIRE(executed.load() == true);
  }

  SECTION("Timer cancellation")
  {
    TimerService service;
    SteadyTimer timer(service);

    std::atomic<bool> executed{false};

    timer.expiresAfter(50ms);
    timer.asyncWait([&executed]() { executed = true; });

    // Cancel before execution
    std::this_thread::sleep_for(10ms);
    bool canceled = timer.cancel();
    REQUIRE(canceled == true);

    // Wait past the original expiry time
    std::this_thread::sleep_for(60ms);
    REQUIRE(executed.load() == false);
  }
}

TEST_CASE("Timer configuration options", "[enhanced_timer][config]")
{
  SECTION("Configuration builder pattern")
  {
    auto config = TimerConfigBuilder()
                    .enableStatistics(true)
                    .enableDetailedLogging(true)
                    .maxConcurrentTimers(500)
                    .threadName("CustomTimer")
                    .throwOnSystemError(false)
                    .build();

    REQUIRE(config.enableStatistics == true);
    REQUIRE(config.enableDetailedLogging == true);
    REQUIRE(config.limits.maxConcurrentTimers == 500);
    REQUIRE(config.threadName == "CustomTimer");
    REQUIRE(config.throwOnSystemError == false);
  }

  SECTION("Service with custom configuration")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).maxConcurrentTimers(100).build();

    auto logger = std::make_shared<TestTimerLogger>();

    REQUIRE_NOTHROW(
      [&]()
      {
        TimerService service(config, logger);
        service.scheduleAfter(1ms, []() {});
        std::this_thread::sleep_for(10ms);
      }());
  }
}

TEST_CASE("TimerService thread safety: F4a scheduleAt TOCTOU", "[enhanced_timer][thread_safety]")
{
  SECTION("No timer inserted after drain begins")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).build();
    TimerService service(config);
    std::atomic<bool> drainStarted{false};

    // Schedule some timers so drain has work to do
    for (int i = 0; i < 10; ++i)
    {
      service.scheduleAfter(500ms, []() {});
    }

    // Thread A: drain the service
    std::thread drainer(
      [&]()
      {
        drainStarted.store(true, std::memory_order_release);
        service.drain(5000);
      });

    // Thread B: try to schedule after drain starts
    while (!drainStarted.load(std::memory_order_acquire))
    {
      std::this_thread::yield();
    }

    // Attempt many scheduleAt calls — some may race and succeed before
    // drain sets _accepting=false, but drain will cancel them
    for (int i = 0; i < 100; ++i)
    {
      service.scheduleAfter(1ms, []() {});
    }

    drainer.join();

    // After drain completes, no timers should be in-flight
    REQUIRE(service.getInFlightCount() == 0);

    // After drain has fully completed, _accepting is false — all new
    // scheduleAt calls must be rejected (return 0)
    auto postDrainId = service.scheduleAfter(1ms, []() {});
    REQUIRE(postDrainId == 0);
  }
}

TEST_CASE("TimerService thread safety: F3 inFlightAtStart accuracy", "[enhanced_timer][thread_safety]")
{
  SECTION("drain inFlightAtStart matches actual count")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).build();
    TimerService service(config);

    // Schedule known number of far-future timers
    const int numTimers = 5;
    for (int i = 0; i < numTimers; ++i)
    {
      service.scheduleAfter(10s, []() {});
    }

    REQUIRE(service.getInFlightCount() == numTimers);

    // Drain — all far-future timers should be cancelled
    auto result = service.drain(1000);
    REQUIRE(result.success);
    REQUIRE(service.getInFlightCount() == 0);
  }
}

TEST_CASE("TimerService thread safety: F2 poke outside lock", "[enhanced_timer][thread_safety]")
{
  SECTION("Concurrent scheduling does not deadlock")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).build();
    TimerService service(config);
    std::atomic<int> scheduled{0};
    const int numThreads = 4;
    const int timersPerThread = 50;

    std::vector<std::thread> threads;
    for (int t = 0; t < numThreads; ++t)
    {
      threads.emplace_back(
        [&]()
        {
          for (int i = 0; i < timersPerThread; ++i)
          {
            auto id = service.scheduleAfter(10ms, []() {});
            if (id != 0)
            {
              scheduled.fetch_add(1, std::memory_order_relaxed);
            }
          }
        });
    }

    for (auto &t : threads)
    {
      t.join();
    }

    REQUIRE(scheduled.load() == numThreads * timersPerThread);

    // Wait for all to fire
    std::this_thread::sleep_for(100ms);
    REQUIRE(service.getStats().timersExecuted.load() == static_cast<std::uint64_t>(numThreads * timersPerThread));
  }
}

TEST_CASE("TimerService thread safety: F1+F6 concurrent setErrorHandler/setLogger", "[enhanced_timer][thread_safety]")
{
  SECTION("Concurrent setErrorHandler with timer callbacks")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).throwOnSystemError(false).build();
    TimerService service(config);
    std::atomic<bool> done{false};

    // Schedule timers that throw — triggers handleError from safeRun
    for (int i = 0; i < 20; ++i)
    {
      service.scheduleAfter(std::chrono::milliseconds(5 * i + 5),
        []() { throw std::runtime_error("test"); });
    }

    // Concurrently swap error handler many times
    std::thread swapper(
      [&]()
      {
        while (!done.load(std::memory_order_acquire))
        {
          service.setErrorHandler(
            [](TimerError, const std::string&, int) {});
          service.setErrorHandler(nullptr);
        }
      });

    std::this_thread::sleep_for(200ms);
    done.store(true, std::memory_order_release);
    swapper.join();

    // No crash = success. Verify some exceptions were caught.
    REQUIRE(service.getStats().exceptionsSwallowed.load() > 0);
  }

  SECTION("Concurrent setLogger with timer callbacks")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).throwOnSystemError(false).build();
    auto logger1 = std::make_shared<TestTimerLogger>();
    auto logger2 = std::make_shared<TestTimerLogger>();
    TimerService service(config, logger1);
    std::atomic<bool> done{false};

    // Schedule timers that throw — triggers logger from handleError
    for (int i = 0; i < 20; ++i)
    {
      service.scheduleAfter(std::chrono::milliseconds(5 * i + 5),
        []() { throw std::runtime_error("test"); });
    }

    // Concurrently swap logger
    std::thread swapper(
      [&]()
      {
        while (!done.load(std::memory_order_acquire))
        {
          service.setLogger(logger2);
          service.setLogger(logger1);
        }
      });

    std::this_thread::sleep_for(200ms);
    done.store(true, std::memory_order_release);
    swapper.join();

    // No crash = success. Some messages should have been logged.
    REQUIRE((logger1->count() + logger2->count()) > 0);
  }
}

TEST_CASE("TimerService thread safety: concurrent drain CAS", "[enhanced_timer][thread_safety]")
{
  SECTION("Only one concurrent drain succeeds")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).build();
    TimerService service(config);

    // Schedule far-future timers so drain has work
    for (int i = 0; i < 5; ++i)
    {
      service.scheduleAfter(10s, []() {});
    }
    REQUIRE(service.getInFlightCount() == 5);

    std::atomic<int> successes{0};
    std::atomic<int> failures{0};

    auto drainFn = [&]()
    {
      auto result = service.drain(5000);
      if (result.success)
      {
        successes.fetch_add(1, std::memory_order_relaxed);
      }
      else
      {
        failures.fetch_add(1, std::memory_order_relaxed);
      }
    };

    std::thread t1(drainFn);
    std::thread t2(drainFn);

    t1.join();
    t2.join();

    // Exactly one should succeed, one should fail
    REQUIRE(successes.load() == 1);
    REQUIRE(failures.load() == 1);
    REQUIRE(service.getInFlightCount() == 0);
  }
}

TEST_CASE("TimerService thread safety: F5 drain promptness", "[enhanced_timer][thread_safety]")
{
  SECTION("drain completes promptly after last callback")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).build();
    TimerService service(config);

    // Schedule a single timer that fires quickly
    service.scheduleAfter(10ms, []() {});

    // Measure drain time — should complete well within timeout
    auto start = std::chrono::steady_clock::now();
    auto result = service.drain(5000);
    auto elapsed = std::chrono::steady_clock::now() - start;

    REQUIRE(result.success);
    // drain should complete within ~50ms (timer fires at 10ms + overhead),
    // not polling at 10ms intervals
    REQUIRE(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() < 200);
  }

  SECTION("drain with periodic timer completes promptly")
  {
    auto config = TimerConfigBuilder().enableStatistics(true).build();
    TimerService service(config);

    service.schedulePeriodic(20ms, []() {});

    // Let it fire once
    std::this_thread::sleep_for(30ms);

    auto start = std::chrono::steady_clock::now();
    auto result = service.drain(5000);
    auto elapsed = std::chrono::steady_clock::now() - start;

    REQUIRE(result.success);
    REQUIRE(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() < 200);
    REQUIRE(service.getInFlightCount() == 0);
  }
}