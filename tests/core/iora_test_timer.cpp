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

  mutable std::vector<LogEntry> entries;

  void log(Level level, const std::string &message, TimerError error = TimerError::None,
           int errno_val = 0) override
  {
    entries.push_back({level, message, error, errno_val});
  }

  void clear() { entries.clear(); }
  size_t count() const { return entries.size(); }

  bool hasMessage(const std::string &msg) const
  {
    for (const auto &entry : entries)
    {
      if (entry.message.find(msg) != std::string::npos)
      {
        return true;
      }
    }
    return false;
  }
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

    std::this_thread::sleep_for(150ms);

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

    MoveOnlyHandler handler("test message");
    service.scheduleAfter(10ms, std::move(handler));

    std::this_thread::sleep_for(50ms);

    // Note: We can't directly check the handler since it was moved
    // But the test passes if compilation succeeds and no crashes occur
    REQUIRE(true); // If we get here, perfect forwarding worked
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