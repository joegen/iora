// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for ThreadPool ILifecycleManaged interface implementation

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>
#include <iora/common/i_lifecycle_managed.hpp>
#include <iora/core/thread_pool.hpp>

using namespace iora::core;
using namespace iora::common;

// ══════════════════════════════════════════════════════════════════════════
// Test: Basic State Transitions
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("ThreadPool lifecycle: Initial state is Running", "[threadpool][lifecycle][state]")
{
  ThreadPool pool(2, 4);

  // ThreadPool starts in Running state (initialized in constructor)
  REQUIRE(pool.getState() == LifecycleState::Running);
}

TEST_CASE("ThreadPool lifecycle: start() from Running state", "[threadpool][lifecycle][start]")
{
  ThreadPool pool(2, 4);

  // Already in Running state
  auto result = pool.start();

  REQUIRE(result.success == true);
  REQUIRE(result.newState == LifecycleState::Running);
  REQUIRE(pool.getState() == LifecycleState::Running);
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Drain Functionality
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("ThreadPool lifecycle: drain() stops accepting new work", "[threadpool][lifecycle][drain]")
{
  ThreadPool pool(2, 4);

  // Enqueue a task before drain
  std::atomic<int> counter{0};
  pool.enqueue([&counter]() { counter.fetch_add(1); });

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter.load() == 1);

  // Drain the pool
  auto result = pool.drain(5000);

  REQUIRE(result.success == true);
  REQUIRE(result.newState == LifecycleState::Draining);
  REQUIRE(pool.getState() == LifecycleState::Draining);

  // Try to enqueue after drain - should throw
  REQUIRE_THROWS_AS(pool.enqueue([&counter]() { counter.fetch_add(1); }), std::runtime_error);

  // Counter should still be 1
  REQUIRE(counter.load() == 1);
}

TEST_CASE("ThreadPool lifecycle: drain() waits for in-flight tasks", "[threadpool][lifecycle][drain][inflight]")
{
  ThreadPool pool(2, 4);

  std::atomic<int> counter{0};
  std::atomic<bool> taskStarted{false};
  std::atomic<bool> taskFinished{false};

  // Enqueue a long-running task
  pool.enqueue([&]()
               {
                 taskStarted.store(true);
                 std::this_thread::sleep_for(std::chrono::milliseconds(500));
                 counter.fetch_add(1);
                 taskFinished.store(true);
               });

  // Wait for task to start
  iora::test::waitFor([&]() { return taskStarted.load(); }, std::chrono::seconds(2));
  REQUIRE(taskStarted.load() == true);

  // Drain the pool with enough timeout
  auto result = pool.drain(2000);

  REQUIRE(result.success == true);
  REQUIRE(result.newState == LifecycleState::Draining);
  REQUIRE(taskFinished.load() == true);
  REQUIRE(counter.load() == 1);

  // Verify drain statistics
  REQUIRE(result.drainStats.has_value());
  REQUIRE(result.drainStats->completed >= 1);
  REQUIRE(result.drainStats->remaining == 0);
}

TEST_CASE("ThreadPool lifecycle: drain() with timeout", "[threadpool][lifecycle][drain][timeout]")
{
  ThreadPool pool(2, 4);

  std::atomic<bool> taskStarted{false};

  // Enqueue a very long-running task
  pool.enqueue([&]()
               {
                 taskStarted.store(true);
                 std::this_thread::sleep_for(std::chrono::seconds(10)); // Very long
               });

  // Wait for task to start
  iora::test::waitFor([&]() { return taskStarted.load(); }, std::chrono::seconds(2));
  REQUIRE(taskStarted.load() == true);

  // Drain with short timeout - should timeout
  auto result = pool.drain(500);

  REQUIRE(result.success == false); // Timeout is considered failure
  REQUIRE(result.newState == LifecycleState::Draining);
  REQUIRE(pool.getState() == LifecycleState::Draining);

  // Verify drain statistics show remaining work
  REQUIRE(result.drainStats.has_value());
  REQUIRE(result.drainStats->remaining > 0);
}

TEST_CASE("ThreadPool lifecycle: drain() with no in-flight tasks", "[threadpool][lifecycle][drain][empty]")
{
  ThreadPool pool(2, 4);

  // Ensure pool is idle
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  auto result = pool.drain(5000);

  REQUIRE(result.success == true);
  REQUIRE(result.newState == LifecycleState::Draining);
  REQUIRE(pool.getState() == LifecycleState::Draining);

  // Verify drain statistics
  REQUIRE(result.drainStats.has_value());
  REQUIRE(result.drainStats->inFlightAtStart == 0);
  REQUIRE(result.drainStats->remaining == 0);
  REQUIRE(result.drainStats->completed == 0);
}

TEST_CASE("ThreadPool lifecycle: getInFlightCount() accuracy", "[threadpool][lifecycle][inflight]")
{
  ThreadPool pool(2, 4);

  // Initially should be 0
  REQUIRE(pool.getInFlightCount() == 0);

  std::atomic<int> startedCount{0};
  std::atomic<bool> tasksCanFinish{false};

  // Enqueue 3 tasks that wait
  for (int i = 0; i < 3; ++i)
  {
    pool.enqueue([&]()
                 {
                   startedCount.fetch_add(1);
                   while (!tasksCanFinish.load())
                   {
                     std::this_thread::sleep_for(std::chrono::milliseconds(10));
                   }
                 });
  }

  // Wait for tasks to start
  iora::test::waitFor([&]() { return startedCount.load() >= 2; }, std::chrono::seconds(2));

  // In-flight count should reflect pending + active tasks
  auto inFlight = pool.getInFlightCount();
  REQUIRE(inFlight >= 2);  // At least 2 tasks running
  REQUIRE(inFlight <= 3);  // At most 3 tasks total

  // Let tasks finish
  tasksCanFinish.store(true);
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // In-flight count should be 0 now
  REQUIRE(pool.getInFlightCount() == 0);
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Stop Functionality
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("ThreadPool lifecycle: stop() from Running state auto-drains", "[threadpool][lifecycle][stop]")
{
  ThreadPool pool(2, 4);

  std::atomic<int> counter{0};
  pool.enqueue([&counter]()
               {
                 std::this_thread::sleep_for(std::chrono::milliseconds(100));
                 counter.fetch_add(1);
               });

  // Stop from Running - should drain first
  auto result = pool.stop();

  REQUIRE(result.success == true);
  REQUIRE(result.newState == LifecycleState::Stopped);
  REQUIRE(pool.getState() == LifecycleState::Stopped);
  REQUIRE(counter.load() == 1); // Task should have completed
}

TEST_CASE("ThreadPool lifecycle: stop() from Draining state", "[threadpool][lifecycle][stop][draining]")
{
  ThreadPool pool(2, 4);

  // Drain first
  auto drainResult = pool.drain(5000);
  REQUIRE(drainResult.success == true);
  REQUIRE(pool.getState() == LifecycleState::Draining);

  // Now stop
  auto stopResult = pool.stop();

  REQUIRE(stopResult.success == true);
  REQUIRE(stopResult.newState == LifecycleState::Stopped);
  REQUIRE(pool.getState() == LifecycleState::Stopped);
}

TEST_CASE("ThreadPool lifecycle: stop() cannot be called from Stopped state", "[threadpool][lifecycle][stop][invalid]")
{
  ThreadPool pool(2, 4);

  // Stop once
  auto result1 = pool.stop();
  REQUIRE(result1.success == true);
  REQUIRE(pool.getState() == LifecycleState::Stopped);

  // Try to stop again
  auto result2 = pool.stop();
  REQUIRE(result2.success == false); // Can't stop from Stopped state
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Reset Functionality
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("ThreadPool lifecycle: reset() from Stopped state", "[threadpool][lifecycle][reset]")
{
  ThreadPool pool(2, 4);

  // Stop first
  auto stopResult = pool.stop();
  REQUIRE(stopResult.success == true);
  REQUIRE(pool.getState() == LifecycleState::Stopped);

  // Now reset
  auto resetResult = pool.reset();

  REQUIRE(resetResult.success == true);
  REQUIRE(resetResult.newState == LifecycleState::Reset);
  REQUIRE(pool.getState() == LifecycleState::Reset);
  REQUIRE(pool.getInFlightCount() == 0);
}

TEST_CASE("ThreadPool lifecycle: reset() cannot be called from Running state", "[threadpool][lifecycle][reset][invalid]")
{
  ThreadPool pool(2, 4);

  // Try to reset from Running state
  auto result = pool.reset();

  REQUIRE(result.success == false);
  REQUIRE(pool.getState() == LifecycleState::Running); // State unchanged
}

TEST_CASE("ThreadPool lifecycle: reset() clears task queue", "[threadpool][lifecycle][reset][clear]")
{
  ThreadPool pool(1, 1);

  // Enqueue tasks that will queue up
  std::atomic<bool> blockTask{true};
  pool.enqueue([&]()
               {
                 while (blockTask.load())
                 {
                   std::this_thread::sleep_for(std::chrono::milliseconds(10));
                 }
               });

  // Enqueue more tasks that will be queued
  for (int i = 0; i < 5; ++i)
  {
    pool.tryEnqueue([]() { std::this_thread::sleep_for(std::chrono::milliseconds(10)); });
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Should have pending tasks
  auto inFlight1 = pool.getInFlightCount();
  INFO("In-flight before stop: " << inFlight1);

  // Stop and reset
  blockTask.store(false);
  auto stopResult = pool.stop();
  REQUIRE(stopResult.success == true);

  auto resetResult = pool.reset();
  REQUIRE(resetResult.success == true);

  // After reset, in-flight count should be 0
  REQUIRE(pool.getInFlightCount() == 0);
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Full Lifecycle Cycle
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("ThreadPool lifecycle: Full cycle - Running → Draining → Stopped → Reset → Running", "[threadpool][lifecycle][full-cycle]")
{
  ThreadPool pool(2, 4);

  // 1. Initial state: Running
  REQUIRE(pool.getState() == LifecycleState::Running);

  std::atomic<int> counter{0};
  pool.enqueue([&counter]() { counter.fetch_add(1); });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter.load() == 1);

  // 2. Drain
  auto drainResult = pool.drain(5000);
  REQUIRE(drainResult.success == true);
  REQUIRE(pool.getState() == LifecycleState::Draining);

  // 3. Stop
  auto stopResult = pool.stop();
  REQUIRE(stopResult.success == true);
  REQUIRE(pool.getState() == LifecycleState::Stopped);

  // 4. Reset
  auto resetResult = pool.reset();
  REQUIRE(resetResult.success == true);
  REQUIRE(pool.getState() == LifecycleState::Reset);

  // 5. Start again
  auto startResult = pool.start();
  REQUIRE(startResult.success == true);
  REQUIRE(pool.getState() == LifecycleState::Running);

  // 6. Verify it works after restart
  pool.enqueue([&counter]() { counter.fetch_add(1); });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter.load() == 2);
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Edge Cases and Error Conditions
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("ThreadPool lifecycle: drain() from non-Running state fails", "[threadpool][lifecycle][drain][invalid]")
{
  ThreadPool pool(2, 4);

  // Stop the pool
  auto stopResult = pool.stop();
  REQUIRE(stopResult.success == true);
  REQUIRE(pool.getState() == LifecycleState::Stopped);

  // Try to drain from Stopped state
  auto drainResult = pool.drain(5000);
  REQUIRE(drainResult.success == false);
  REQUIRE(pool.getState() == LifecycleState::Stopped); // State unchanged
}

TEST_CASE("ThreadPool lifecycle: tryEnqueue() respects drain state", "[threadpool][lifecycle][tryenqueue]")
{
  ThreadPool pool(2, 4);

  // tryEnqueue should work in Running state
  bool enqueued1 = pool.tryEnqueue([]() {});
  REQUIRE(enqueued1 == true);

  // Drain the pool
  auto drainResult = pool.drain(5000);
  REQUIRE(drainResult.success == true);

  // tryEnqueue should return false (not throw) in Draining state
  bool enqueued2 = pool.tryEnqueue([]() {});
  REQUIRE(enqueued2 == false);
}

TEST_CASE("ThreadPool lifecycle: Multiple tasks drain correctly", "[threadpool][lifecycle][drain][multiple]")
{
  ThreadPool pool(4, 8);

  std::atomic<int> completed{0};

  // Enqueue 10 short tasks
  for (int i = 0; i < 10; ++i)
  {
    pool.enqueue([&completed]()
                 {
                   std::this_thread::sleep_for(std::chrono::milliseconds(50));
                   completed.fetch_add(1);
                 });
  }

  // Drain with enough timeout
  auto result = pool.drain(5000);

  REQUIRE(result.success == true);
  REQUIRE(completed.load() == 10);

  // Verify drain statistics
  REQUIRE(result.drainStats.has_value());
  REQUIRE(result.drainStats->completed >= 10);
  REQUIRE(result.drainStats->remaining == 0);
}

TEST_CASE("ThreadPool lifecycle: Drain statistics accuracy", "[threadpool][lifecycle][drain][stats]")
{
  ThreadPool pool(2, 4);

  std::atomic<bool> tasksCanFinish{false};

  // Enqueue 5 tasks
  for (int i = 0; i < 5; ++i)
  {
    pool.enqueue([&]()
                 {
                   while (!tasksCanFinish.load())
                   {
                     std::this_thread::sleep_for(std::chrono::milliseconds(10));
                   }
                 });
  }

  // Wait for some tasks to start
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Allow tasks to finish
  tasksCanFinish.store(true);

  // Drain
  auto result = pool.drain(5000);

  REQUIRE(result.success == true);
  REQUIRE(result.drainStats.has_value());

  auto& stats = result.drainStats.value();
  INFO("inFlightAtStart: " << stats.inFlightAtStart);
  INFO("completed: " << stats.completed);
  INFO("remaining: " << stats.remaining);

  // All tasks should complete
  REQUIRE(stats.remaining == 0);
  REQUIRE(stats.completed == stats.inFlightAtStart);
}
