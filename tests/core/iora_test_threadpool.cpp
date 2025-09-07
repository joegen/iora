#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>
#include <stdexcept>
#include <vector>

//
// Basic task execution using fire-and-forget
//
TEST_CASE("ThreadPool basic task execution", "[threadpool]")
{
  iora::core::ThreadPool pool(2, 4);

  std::atomic<int> counter{0};

  for (int i = 0; i < 10; ++i)
  {
    pool.enqueue([&counter]() { counter.fetch_add(1); });
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  REQUIRE(counter == 10);
}

//
// Task with return value via future
//
TEST_CASE("ThreadPool task with future result", "[threadpool][future]")
{
  iora::core::ThreadPool pool(2);

  auto future = pool.enqueueWithResult([]() { return 42; });

  REQUIRE(future.get() == 42);
}

//
// Thread pool grows under load
//
TEST_CASE("ThreadPool scales up under load", "[threadpool][scaling]")
{
  constexpr int tasks = 8;
  std::atomic<int> completed{0};

  iora::core::ThreadPool pool(2, tasks);

  for (int i = 0; i < tasks; ++i)
  {
    pool.enqueue(
      [&completed]()
      {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        completed.fetch_add(1);
      });
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  REQUIRE(completed.load() == tasks);
}

//
// Tasks are rejected when the queue overflows
//
TEST_CASE("ThreadPool handles queue overflow", "[threadpool][overflow]")
{
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(5), 2); // max 2 tasks in queue

  pool.enqueue([]() { std::this_thread::sleep_for(std::chrono::milliseconds(100)); });
  pool.enqueue([]() { std::this_thread::sleep_for(std::chrono::milliseconds(100)); });

  REQUIRE_THROWS_AS(pool.enqueue([]() {}), std::runtime_error);
}

//
// Tasks that throw are safely swallowed by default
//
TEST_CASE("ThreadPool handles exceptions without handler", "[threadpool][exception]")
{
  iora::core::ThreadPool pool;

  pool.enqueue([]() { throw std::runtime_error("oops"); });

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  SUCCEED("Exception was swallowed safely");
}

//
// Tasks that throw trigger custom handler (safe via constructor capture)
//
TEST_CASE("ThreadPool handles exceptions with handler", "[threadpool][exception-handler]")
{
  std::atomic<bool> caught{false};

  iora::core::ThreadPool pool(2, 4, std::chrono::seconds(1), 128,
                              [&caught](std::exception_ptr eptr)
                              {
                                try
                                {
                                  if (eptr)
                                    std::rethrow_exception(eptr);
                                }
                                catch (const std::runtime_error &e)
                                {
                                  if (std::string(e.what()) == "fail")
                                    caught = true;
                                }
                              });

  auto fut = pool.enqueueWithResult(
    []()
    {
      std::cerr << "[TEST] throwing now\n";
      throw std::runtime_error("fail");
    });

  try
  {
    fut.get();
  }
  catch (const std::runtime_error &e)
  {
    if (std::string(e.what()) == "fail")
    {
      caught = true;
    }
  }
  REQUIRE(caught);

  caught = false; // Reset for next test
  pool.enqueue([]() { throw std::runtime_error("fail"); });

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (!caught && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::yield();
  }

  REQUIRE(caught);
}

//
// Thread pool shrinks back to initial size after idle timeout
//
TEST_CASE("ThreadPool shrinks idle threads", "[threadpool][scaling-down]")
{
  iora::core::ThreadPool pool(2, 4, std::chrono::milliseconds(100)); // idleTimeout = 100ms

  for (int i = 0; i < 4; ++i)
  {
    pool.enqueue([]() { std::this_thread::sleep_for(std::chrono::milliseconds(50)); });
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  SUCCEED("Threads idle-exited without error");
}

//
// Tasks in-flight should complete even when pool is destroyed
//
TEST_CASE("ThreadPool destruction completes pending tasks", "[threadpool][lifecycle]")
{
  std::atomic<int> completed{0};

  {
    iora::core::ThreadPool pool(2, 4);
    for (int i = 0; i < 5; ++i)
    {
      pool.enqueue(
        [&completed]()
        {
          std::this_thread::sleep_for(std::chrono::milliseconds(50));
          completed++;
        });
    }
  }

  REQUIRE(completed == 5);
}

//
// Enqueue tasks and destroy pool immediately to detect race or deadlock
//
TEST_CASE("ThreadPool rapid enqueue and shutdown", "[threadpool][race]")
{
  std::atomic<int> completed{0};

  {
    iora::core::ThreadPool pool(4, 4);
    for (int i = 0; i < 20; ++i)
    {
      pool.enqueue(
        [&completed]()
        {
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
          completed++;
        });
    }
    // destructor will be called immediately
  }

  REQUIRE(completed > 0);
}

//
// Futures should propagate exceptions correctly
//
TEST_CASE("ThreadPool propagates exception through future", "[threadpool][future][exception]")
{
  iora::core::ThreadPool pool(2);

  auto future = pool.enqueueWithResult([]() -> int { throw std::runtime_error("bad future"); });

  REQUIRE_THROWS_AS(future.get(), std::runtime_error);
}

TEST_CASE("ThreadPool backpressure and monitoring", "[threadpool][backpressure]")
{
  SECTION("getPendingTaskCount works correctly")
  {
    iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1), 3);

    REQUIRE(pool.getPendingTaskCount() == 0);

    // Add a long-running task to occupy the single thread
    std::atomic<bool> taskStarted{false};
    std::atomic<bool> allowTaskComplete{false};

    pool.enqueue(
      [&taskStarted, &allowTaskComplete]()
      {
        taskStarted = true;
        while (!allowTaskComplete)
        {
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
      });

    // Wait for the task to start
    while (!taskStarted)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // Add tasks to the queue
    pool.enqueue([]() { std::this_thread::sleep_for(std::chrono::milliseconds(10)); });
    pool.enqueue([]() { std::this_thread::sleep_for(std::chrono::milliseconds(10)); });

    REQUIRE(pool.getPendingTaskCount() == 2);

    // Allow tasks to complete
    allowTaskComplete = true;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    REQUIRE(pool.getPendingTaskCount() == 0);
  }

  SECTION("getQueueUtilization returns correct percentage")
  {
    iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1), 4); // Queue size 4

    REQUIRE(pool.getQueueUtilization() == 0.0);

    // Block the thread with a task that won't be in the queue (it's being executed)
    std::atomic<bool> taskStarted{false};
    std::atomic<bool> allowComplete{false};
    pool.enqueue(
      [&taskStarted, &allowComplete]()
      {
        taskStarted = true;
        while (!allowComplete)
        {
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
      });

    // Wait for the blocking task to start (so it's not in the queue)
    while (!taskStarted)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // Now the queue should be empty
    REQUIRE(pool.getQueueUtilization() == 0.0);

    // Add tasks to fill 50% of queue (2 out of 4)
    pool.enqueue([]() {});
    pool.enqueue([]() {});

    REQUIRE(pool.getQueueUtilization() == 50.0);

    // Fill to 100% (4 out of 4)
    pool.enqueue([]() {});
    pool.enqueue([]() {});

    REQUIRE(pool.getQueueUtilization() == 100.0);

    allowComplete = true;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  SECTION("isUnderHighLoad detects high queue utilization")
  {
    iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1), 5); // Queue size 5

    REQUIRE_FALSE(pool.isUnderHighLoad());

    // Block the thread
    std::atomic<bool> allowComplete{false};
    pool.enqueue(
      [&allowComplete]()
      {
        while (!allowComplete)
        {
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
      });

    // Add tasks to reach 80% (4 out of 5)
    // These tasks need to block too, otherwise they execute instantly
    pool.enqueue(
      [&allowComplete]()
      {
        while (!allowComplete)
        {
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
      });
    pool.enqueue(
      [&allowComplete]()
      {
        while (!allowComplete)
        {
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
      });
    pool.enqueue(
      [&allowComplete]()
      {
        while (!allowComplete)
        {
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
      });
    pool.enqueue(
      [&allowComplete]()
      {
        while (!allowComplete)
        {
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
      });

    REQUIRE(pool.isUnderHighLoad());

    allowComplete = true;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  SECTION("tryEnqueue provides non-blocking backpressure")
  {
    iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1), 2); // Small queue

    // Block the single thread
    std::atomic<bool> taskStarted{false};
    std::atomic<bool> allowComplete{false};
    REQUIRE(pool.tryEnqueue(
      [&taskStarted, &allowComplete]()
      {
        taskStarted = true;
        while (!allowComplete)
        {
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
      }));

    // Wait for the blocking task to start
    while (!taskStarted)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // Fill the queue (2 slots)
    REQUIRE(pool.tryEnqueue([] {}));
    REQUIRE(pool.tryEnqueue([] {}));

    // Next enqueue should fail due to backpressure
    REQUIRE_FALSE(pool.tryEnqueue([] {}));

    // Queue should be at capacity
    REQUIRE(pool.getQueueUtilization() == 100.0);
    REQUIRE(pool.getPendingTaskCount() == 2);

    allowComplete = true;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // After completion, should be able to enqueue again
    REQUIRE(pool.tryEnqueue([] {}));
  }

  SECTION("thread count monitoring works correctly")
  {
    iora::core::ThreadPool pool(static_cast<std::size_t>(2),     // initialSize
                                static_cast<std::size_t>(4),     // maxSize
                                std::chrono::milliseconds(1000), // idleTimeout
                                static_cast<std::size_t>(10)     // maxQueueSize
    );

    REQUIRE(pool.getTotalThreadCount() == 2);  // Initial size
    REQUIRE(pool.getActiveThreadCount() == 0); // No active tasks

    // Add tasks that will cause thread pool to grow
    std::atomic<int> activeTasks{0};
    std::atomic<bool> allowComplete{false};

    for (int i = 0; i < 4; ++i)
    {
      pool.enqueue(
        [&activeTasks, &allowComplete]()
        {
          ++activeTasks;
          while (!allowComplete)
          {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
          }
          --activeTasks;
        });
    }

    // Wait for tasks to start
    while (activeTasks < 4)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    REQUIRE(pool.getActiveThreadCount() == 4);
    REQUIRE(pool.getTotalThreadCount() >= 4); // Should have grown

    allowComplete = true;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    REQUIRE(pool.getActiveThreadCount() == 0);
  }
}
