// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for ThreadPool worker thread cleanup after idle timeout
// These tests verify that threads are properly removed from the internal map
// when they exit due to idle timeout, preventing resource leaks.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>
#include <iora/core/thread_pool.hpp>

using namespace iora::core;

// ══════════════════════════════════════════════════════════════════════════
// Test: Thread Map Cleanup After Idle Timeout
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("ThreadPool cleanup: Thread map shrinks after idle timeout", "[threadpool][cleanup][idle-timeout]")
{
  // Create pool with short idle timeout
  // Initial: 2 threads, Max: 6 threads, Idle timeout: 100ms
  ThreadPool pool(2, 6, std::chrono::milliseconds(100));

  REQUIRE(pool.getTotalThreadCount() == 2);

  // Enqueue tasks to force pool to grow to max
  std::atomic<int> startedCount{0};
  std::atomic<bool> allowComplete{false};

  for (int i = 0; i < 6; ++i)
  {
    pool.enqueue([&startedCount, &allowComplete]()
                 {
                   startedCount.fetch_add(1, std::memory_order_relaxed);
                   while (!allowComplete.load(std::memory_order_relaxed))
                   {
                     std::this_thread::sleep_for(std::chrono::milliseconds(10));
                   }
                 });
  }

  // Wait for all tasks to start (pool should scale to 6 threads)
  iora::test::waitFor([&]() { return startedCount.load() >= 6; }, std::chrono::seconds(5));
  REQUIRE(startedCount.load() == 6);

  // Verify pool scaled up
  REQUIRE(pool.getTotalThreadCount() == 6);

  // Let tasks complete
  allowComplete.store(true, std::memory_order_relaxed);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  // Wait for idle timeout to trigger (100ms) + grace period
  // Threads should exit and be removed from map
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  // Thread map should shrink back to initial size
  auto finalCount = pool.getTotalThreadCount();
  INFO("Final thread count: " << finalCount);
  REQUIRE(finalCount == 2); // Should be back to _initialSize
}

TEST_CASE("ThreadPool cleanup: Multiple idle timeout cycles", "[threadpool][cleanup][cycles]")
{
  ThreadPool pool(2, 8, std::chrono::milliseconds(50));

  for (int cycle = 0; cycle < 3; ++cycle)
  {
    INFO("Cycle " << cycle);

    std::atomic<int> started{0};
    std::atomic<bool> complete{false};

    // Scale up
    for (int i = 0; i < 8; ++i)
    {
      pool.enqueue([&started, &complete]()
                   {
                     started.fetch_add(1);
                     while (!complete.load())
                     {
                       std::this_thread::sleep_for(std::chrono::milliseconds(5));
                     }
                   });
    }

    iora::test::waitFor([&]() { return started.load() >= 8; }, std::chrono::seconds(5));
    REQUIRE(pool.getTotalThreadCount() == 8);

    // Scale down
    complete.store(true);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // Wait for idle timeout

    // Map should shrink
    REQUIRE(pool.getTotalThreadCount() == 2);
  }
}

TEST_CASE("ThreadPool cleanup: No zombie threads in map", "[threadpool][cleanup][zombie]")
{
  ThreadPool pool(1, 4, std::chrono::milliseconds(50));

  std::atomic<int> taskCount{0};
  std::atomic<bool> allowComplete{false};

  // Scale up - keep tasks running to ensure scaling happens
  for (int i = 0; i < 4; ++i)
  {
    pool.enqueue([&taskCount, &allowComplete]()
                 {
                   taskCount.fetch_add(1);
                   while (!allowComplete.load())
                   {
                     std::this_thread::sleep_for(std::chrono::milliseconds(5));
                   }
                 });
  }

  // Wait for all tasks to start (pool will scale)
  iora::test::waitFor([&]() { return taskCount.load() >= 4; }, std::chrono::seconds(5));
  REQUIRE(taskCount.load() == 4);

  // Record size after scaling (should be at max or near max)
  auto peakSize = pool.getTotalThreadCount();
  INFO("Peak thread count: " << peakSize);
  REQUIRE(peakSize >= 2); // Should have scaled up

  // Let tasks complete
  allowComplete.store(true);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  // Wait for idle timeout
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  auto afterIdleSize = pool.getTotalThreadCount();
  INFO("After idle timeout: " << afterIdleSize);

  // Key assertion: map size should equal actual thread count
  // If threads exit but aren't removed, map would still show peakSize
  REQUIRE(afterIdleSize == 1); // Back to initial size
  REQUIRE(afterIdleSize < peakSize);
}

TEST_CASE("ThreadPool cleanup: Concurrent idle timeouts don't corrupt map", "[threadpool][cleanup][concurrent]")
{
  // Many threads timing out simultaneously
  ThreadPool pool(2, 20, std::chrono::milliseconds(100));

  std::atomic<int> started{0};
  std::atomic<bool> complete{false};

  // Scale to max
  for (int i = 0; i < 20; ++i)
  {
    pool.enqueue([&started, &complete]()
                 {
                   started.fetch_add(1);
                   while (!complete.load())
                   {
                     std::this_thread::sleep_for(std::chrono::milliseconds(10));
                   }
                 });
  }

  iora::test::waitFor([&]() { return started.load() >= 20; }, std::chrono::seconds(10));
  REQUIRE(pool.getTotalThreadCount() == 20);

  // Release all threads at once - they'll all hit idle timeout together
  complete.store(true);

  // Wait for idle timeout + cleanup
  std::this_thread::sleep_for(std::chrono::milliseconds(400));

  // All should cleanly exit except initial threads
  REQUIRE(pool.getTotalThreadCount() == 2);
}

TEST_CASE("ThreadPool cleanup: Thread counters match map size", "[threadpool][cleanup][counters]")
{
  ThreadPool pool(2, 6, std::chrono::milliseconds(50));

  std::atomic<int> started{0};
  std::atomic<bool> complete{false};

  // Scale up
  for (int i = 0; i < 6; ++i)
  {
    pool.enqueue([&started, &complete]()
                 {
                   started.fetch_add(1);
                   while (!complete.load())
                   {
                     std::this_thread::sleep_for(std::chrono::milliseconds(5));
                   }
                 });
  }

  iora::test::waitFor([&]() { return started.load() >= 6; }, std::chrono::seconds(5));

  auto mapSize = pool.getTotalThreadCount();
  REQUIRE(mapSize == 6);

  // Scale down
  complete.store(true);
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // After idle timeout, map size should match actual live threads
  auto finalMapSize = pool.getTotalThreadCount();
  auto activeCount = pool.getActiveThreadCount();

  INFO("Final map size: " << finalMapSize);
  INFO("Active thread count: " << activeCount);

  // Map should only contain live threads
  REQUIRE(finalMapSize == 2);
  REQUIRE(activeCount == 0); // No tasks running
}

TEST_CASE("ThreadPool cleanup: Partial scale down respects _initialSize", "[threadpool][cleanup][partial]")
{
  ThreadPool pool(3, 10, std::chrono::milliseconds(50));

  std::atomic<int> started{0};
  std::atomic<bool> complete{false};

  // Scale to 10 threads
  for (int i = 0; i < 10; ++i)
  {
    pool.enqueue([&started, &complete]()
                 {
                   started.fetch_add(1);
                   while (!complete.load())
                   {
                     std::this_thread::sleep_for(std::chrono::milliseconds(5));
                   }
                 });
  }

  iora::test::waitFor([&]() { return started.load() >= 10; }, std::chrono::seconds(5));
  REQUIRE(pool.getTotalThreadCount() == 10);

  complete.store(true);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  // Should scale down to exactly _initialSize (3), not below
  REQUIRE(pool.getTotalThreadCount() == 3);
}

TEST_CASE("ThreadPool cleanup: Rapid scale up/down doesn't leak", "[threadpool][cleanup][rapid]")
{
  ThreadPool pool(2, 8, std::chrono::milliseconds(30));

  // Rapid bursts of work
  for (int burst = 0; burst < 5; ++burst)
  {
    std::atomic<int> completed{0};

    // Quick burst of work
    for (int i = 0; i < 8; ++i)
    {
      pool.enqueue([&completed]()
                   {
                     std::this_thread::sleep_for(std::chrono::milliseconds(5));
                     completed.fetch_add(1);
                   });
    }

    // Wait for completion
    iora::test::waitFor([&]() { return completed.load() >= 8; }, std::chrono::seconds(5));

    // Brief pause for idle timeout
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Map should not grow indefinitely
    auto currentSize = pool.getTotalThreadCount();
    INFO("Burst " << burst << " map size: " << currentSize);
    REQUIRE(currentSize <= 8); // Never exceed max
    REQUIRE(currentSize >= 2); // Never below initial
  }

  // Final check after all bursts
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  REQUIRE(pool.getTotalThreadCount() == 2);
}

TEST_CASE("ThreadPool cleanup: Shutdown with zombie threads", "[threadpool][cleanup][shutdown]")
{
  {
    ThreadPool pool(2, 6, std::chrono::milliseconds(100));

    std::atomic<int> started{0};
    std::atomic<bool> complete{false};

    // Scale up
    for (int i = 0; i < 6; ++i)
    {
      pool.enqueue([&started, &complete]()
                   {
                     started.fetch_add(1);
                     while (!complete.load())
                     {
                       std::this_thread::sleep_for(std::chrono::milliseconds(10));
                     }
                   });
    }

    iora::test::waitFor([&]() { return started.load() >= 6; }, std::chrono::seconds(5));

    // Let some threads idle out
    complete.store(true);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // Now destroy the pool - should handle both live and zombie threads
    // (This tests that destructor can clean up properly)
  }

  // If we get here without hanging or crashing, cleanup worked
  SUCCEED("Pool destroyed cleanly with mixed live/idle threads");
}

TEST_CASE("ThreadPool cleanup: Worker scaling disabled prevents idle exit", "[threadpool][cleanup][scaling-disabled]")
{
  // When worker scaling is disabled, threads should NOT exit on idle timeout
  // This is a configuration test

  // Note: Currently _workerScaling is not configurable at runtime
  // This test documents expected behavior when scaling is disabled
  ThreadPool pool(4, 4, std::chrono::milliseconds(50));

  // Pool starts at initial size
  REQUIRE(pool.getTotalThreadCount() == 4);

  // Execute a task
  std::atomic<bool> done{false};
  pool.enqueue([&done]() { done.store(true); });

  iora::test::waitFor([&]() { return done.load(); }, std::chrono::seconds(2));

  // Wait longer than idle timeout
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // With initial == max, no scaling down should occur
  REQUIRE(pool.getTotalThreadCount() == 4);
}

TEST_CASE("ThreadPool cleanup: Stress test - memory leak detection", "[threadpool][cleanup][stress][.long]")
{
  // This is a longer stress test to detect memory leaks
  // Marked with [.long] tag so it's skipped by default

  ThreadPool pool(2, 16, std::chrono::milliseconds(20));

  auto initialMapSize = pool.getTotalThreadCount();
  REQUIRE(initialMapSize == 2);

  // Many cycles of scale up/down
  for (int cycle = 0; cycle < 50; ++cycle)
  {
    std::atomic<int> completed{0};

    for (int i = 0; i < 16; ++i)
    {
      pool.enqueue([&completed]()
                   {
                     completed.fetch_add(1);
                     std::this_thread::sleep_for(std::chrono::milliseconds(1));
                   });
    }

    iora::test::waitFor([&]() { return completed.load() >= 16; }, std::chrono::seconds(5));

    // Wait for scale down
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Verify no growth in map size beyond expected
    if (cycle % 10 == 9)
    {
      INFO("Cycle " << cycle << " map size: " << pool.getTotalThreadCount());
    }
  }

  // Final verification - map should be at initial size
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  REQUIRE(pool.getTotalThreadCount() == 2);
}
