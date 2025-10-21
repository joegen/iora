// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for TimerService ILifecycleManaged interface implementation

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>
#include <iora/common/i_lifecycle_managed.hpp>
#include <iora/core/timer.hpp>

using namespace iora::core;
using namespace iora::common;

// ══════════════════════════════════════════════════════════════════════════
// Test: Basic State Transitions
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("TimerService lifecycle: Initial state is Running", "[timer][lifecycle][state]")
{
  TimerService timer;

  // TimerService starts in Running state (initialized in constructor)
  REQUIRE(timer.getState() == LifecycleState::Running);
}

TEST_CASE("TimerService lifecycle: start() from Running state", "[timer][lifecycle][start]")
{
  TimerService timer;

  // Already in Running state
  auto result = timer.start();

  REQUIRE(result.success == true);
  REQUIRE(result.newState == LifecycleState::Running);
  REQUIRE(timer.getState() == LifecycleState::Running);
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Drain Functionality
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("TimerService lifecycle: drain() stops accepting new timers", "[timer][lifecycle][drain]")
{
  TimerService timer;

  // Schedule a timer before drain
  std::atomic<int> counter{0};
  auto id1 = timer.scheduleAfter(std::chrono::milliseconds(50), [&counter]() { counter.fetch_add(1); });
  REQUIRE(id1 != 0);

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter.load() == 1);

  // Drain the timer service
  auto result = timer.drain(5000);

  REQUIRE(result.success == true);
  REQUIRE(result.newState == LifecycleState::Draining);
  REQUIRE(timer.getState() == LifecycleState::Draining);

  // Try to schedule after drain - should return 0 (failed)
  auto id2 = timer.scheduleAfter(std::chrono::milliseconds(50), [&counter]() { counter.fetch_add(1); });
  REQUIRE(id2 == 0);

  // Counter should still be 1
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter.load() == 1);
}

TEST_CASE("TimerService lifecycle: drain() waits for in-flight timers", "[timer][lifecycle][drain][inflight]")
{
  TimerService timer;

  std::atomic<int> counter{0};
  std::atomic<bool> timerStarted{false};
  std::atomic<bool> timerFinished{false};

  // Schedule a timer with a quick callback
  timer.scheduleAfter(std::chrono::milliseconds(50),
                      [&]()
                      {
                        timerStarted.store(true);
                        counter.fetch_add(1);
                        timerFinished.store(true);
                      });

  // Give timer time to be scheduled
  std::this_thread::sleep_for(std::chrono::milliseconds(20));

  // Drain the timer service - should wait for scheduled timer to execute
  auto result = timer.drain(2000);

  REQUIRE(result.success == true);
  REQUIRE(result.newState == LifecycleState::Draining);
  REQUIRE(timerFinished.load() == true);
  REQUIRE(counter.load() == 1);

  // Verify drain statistics
  REQUIRE(result.drainStats.has_value());
  REQUIRE(result.drainStats->remaining == 0);
}

TEST_CASE("TimerService lifecycle: drain() with timeout", "[timer][lifecycle][drain][timeout]")
{
  TimerService timer;

  std::atomic<int> timerCount{0};

  // Schedule multiple timers with delays beyond the drain timeout
  for (int i = 0; i < 5; ++i)
  {
    timer.scheduleAfter(std::chrono::milliseconds(2000 + i * 100),
                        [&timerCount]()
                        {
                          timerCount.fetch_add(1);
                        });
  }

  // Immediately drain with short timeout - timers won't fire in time
  auto result = timer.drain(500);

  REQUIRE(result.success == false); // Timeout is considered failure
  REQUIRE(result.newState == LifecycleState::Draining);
  REQUIRE(timer.getState() == LifecycleState::Draining);

  // Verify drain statistics show remaining work
  REQUIRE(result.drainStats.has_value());
  REQUIRE(result.drainStats->remaining > 0);

  // Timers should not have executed
  REQUIRE(timerCount.load() == 0);
}

TEST_CASE("TimerService lifecycle: drain() with no in-flight timers", "[timer][lifecycle][drain][empty]")
{
  TimerService timer;

  // Ensure timer service is idle
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  auto result = timer.drain(5000);

  REQUIRE(result.success == true);
  REQUIRE(result.newState == LifecycleState::Draining);
  REQUIRE(timer.getState() == LifecycleState::Draining);

  // Verify drain statistics
  REQUIRE(result.drainStats.has_value());
  REQUIRE(result.drainStats->inFlightAtStart == 0);
  REQUIRE(result.drainStats->remaining == 0);
  REQUIRE(result.drainStats->completed == 0);
}

TEST_CASE("TimerService lifecycle: getInFlightCount() accuracy", "[timer][lifecycle][inflight]")
{
  TimerService timer;

  // Initially should be 0
  REQUIRE(timer.getInFlightCount() == 0);

  std::atomic<int> startedCount{0};
  std::atomic<bool> timersCanFinish{false};

  // Schedule 3 timers that will execute sequentially
  for (int i = 0; i < 3; ++i)
  {
    timer.scheduleAfter(std::chrono::milliseconds(50 + i * 10),
                        [&]()
                        {
                          startedCount.fetch_add(1);
                          while (!timersCanFinish.load())
                          {
                            std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                        });
  }

  // Wait a bit for timers to be scheduled
  std::this_thread::sleep_for(std::chrono::milliseconds(20));

  // In-flight count should show pending timers
  auto inFlight = timer.getInFlightCount();
  REQUIRE(inFlight == 3); // All 3 timers are scheduled but not yet executed

  // Let timers finish
  std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Wait for first timer to start
  timersCanFinish.store(true);
  std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Wait for all to complete

  // In-flight count should be 0 now
  REQUIRE(timer.getInFlightCount() == 0);
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Stop Functionality
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("TimerService lifecycle: stop() from Running state auto-drains", "[timer][lifecycle][stop]")
{
  TimerService timer;

  std::atomic<int> counter{0};
  timer.scheduleAfter(std::chrono::milliseconds(50),
                      [&counter]()
                      {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        counter.fetch_add(1);
                      });

  std::this_thread::sleep_for(std::chrono::milliseconds(80)); // Let timer start

  // Stop from Running - should drain first
  auto result = timer.stop();

  REQUIRE(result.success == true);
  REQUIRE(result.newState == LifecycleState::Stopped);
  REQUIRE(timer.getState() == LifecycleState::Stopped);
  REQUIRE(counter.load() == 1); // Timer should have completed
}

TEST_CASE("TimerService lifecycle: stop() from Draining state", "[timer][lifecycle][stop][draining]")
{
  TimerService timer;

  // Drain first
  auto drainResult = timer.drain(5000);
  REQUIRE(drainResult.success == true);
  REQUIRE(timer.getState() == LifecycleState::Draining);

  // Now stop
  auto stopResult = timer.stop();

  REQUIRE(stopResult.success == true);
  REQUIRE(stopResult.newState == LifecycleState::Stopped);
  REQUIRE(timer.getState() == LifecycleState::Stopped);
}

TEST_CASE("TimerService lifecycle: stop() cannot be called from Stopped state", "[timer][lifecycle][stop][invalid]")
{
  TimerService timer;

  // Stop once
  auto result1 = timer.stop();
  REQUIRE(result1.success == true);
  REQUIRE(timer.getState() == LifecycleState::Stopped);

  // Try to stop again
  auto result2 = timer.stop();
  REQUIRE(result2.success == false); // Can't stop from Stopped state
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Reset Functionality
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("TimerService lifecycle: reset() from Stopped state", "[timer][lifecycle][reset]")
{
  TimerService timer;

  // Stop first
  auto stopResult = timer.stop();
  REQUIRE(stopResult.success == true);
  REQUIRE(timer.getState() == LifecycleState::Stopped);

  // Now reset
  auto resetResult = timer.reset();

  REQUIRE(resetResult.success == true);
  REQUIRE(resetResult.newState == LifecycleState::Reset);
  REQUIRE(timer.getState() == LifecycleState::Reset);
  REQUIRE(timer.getInFlightCount() == 0);
}

TEST_CASE("TimerService lifecycle: reset() cannot be called from Running state", "[timer][lifecycle][reset][invalid]")
{
  TimerService timer;

  // Try to reset from Running state
  auto result = timer.reset();

  REQUIRE(result.success == false);
  REQUIRE(timer.getState() == LifecycleState::Running); // State unchanged
}

TEST_CASE("TimerService lifecycle: reset() clears timer state", "[timer][lifecycle][reset][clear]")
{
  TimerService timer;

  // Schedule some timers
  std::atomic<bool> blockTimers{true};
  timer.scheduleAfter(std::chrono::milliseconds(50),
                      [&]()
                      {
                        while (blockTimers.load())
                        {
                          std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        }
                      });

  for (int i = 0; i < 5; ++i)
  {
    timer.scheduleAfter(std::chrono::milliseconds(100 + i * 50), []() {});
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(80));

  // Should have timers scheduled
  auto inFlight1 = timer.getInFlightCount();
  INFO("In-flight before stop: " << inFlight1);

  // Stop and reset
  blockTimers.store(false);
  auto stopResult = timer.stop();
  REQUIRE(stopResult.success == true);

  auto resetResult = timer.reset();
  REQUIRE(resetResult.success == true);

  // After reset, in-flight count should be 0
  REQUIRE(timer.getInFlightCount() == 0);
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Full Lifecycle Cycle
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("TimerService lifecycle: Full cycle - Running → Draining → Stopped → Reset → Running", "[timer][lifecycle][full-cycle]")
{
  TimerService timer;

  // 1. Initial state: Running
  REQUIRE(timer.getState() == LifecycleState::Running);

  std::atomic<int> counter{0};
  timer.scheduleAfter(std::chrono::milliseconds(50), [&counter]() { counter.fetch_add(1); });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter.load() == 1);

  // 2. Drain
  auto drainResult = timer.drain(5000);
  REQUIRE(drainResult.success == true);
  REQUIRE(timer.getState() == LifecycleState::Draining);

  // 3. Stop
  auto stopResult = timer.stop();
  REQUIRE(stopResult.success == true);
  REQUIRE(timer.getState() == LifecycleState::Stopped);

  // 4. Reset
  auto resetResult = timer.reset();
  REQUIRE(resetResult.success == true);
  REQUIRE(timer.getState() == LifecycleState::Reset);

  // 5. Start again
  auto startResult = timer.start();
  REQUIRE(startResult.success == true);
  REQUIRE(timer.getState() == LifecycleState::Running);

  // 6. Verify it works after restart
  timer.scheduleAfter(std::chrono::milliseconds(50), [&counter]() { counter.fetch_add(1); });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter.load() == 2);
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Edge Cases and Error Conditions
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("TimerService lifecycle: drain() from non-Running state fails", "[timer][lifecycle][drain][invalid]")
{
  TimerService timer;

  // Stop the timer service
  auto stopResult = timer.stop();
  REQUIRE(stopResult.success == true);
  REQUIRE(timer.getState() == LifecycleState::Stopped);

  // Try to drain from Stopped state
  auto drainResult = timer.drain(5000);
  REQUIRE(drainResult.success == false);
  REQUIRE(timer.getState() == LifecycleState::Stopped); // State unchanged
}

TEST_CASE("TimerService lifecycle: Multiple timers drain correctly", "[timer][lifecycle][drain][multiple]")
{
  TimerService timer;

  std::atomic<int> completed{0};

  // Schedule 10 timers with quick callbacks
  for (int i = 0; i < 10; ++i)
  {
    timer.scheduleAfter(std::chrono::milliseconds(50 + i * 20),
                        [&completed]()
                        {
                          completed.fetch_add(1);
                        });
  }

  // Drain with enough timeout for all timers to fire and execute
  // Last timer fires at 50 + 9*20 = 230ms, so 2000ms is more than enough
  auto result = timer.drain(2000);

  REQUIRE(result.success == true);
  REQUIRE(completed.load() == 10);

  // Verify drain statistics
  REQUIRE(result.drainStats.has_value());
  REQUIRE(result.drainStats->remaining == 0);
}

TEST_CASE("TimerService lifecycle: Drain statistics accuracy", "[timer][lifecycle][drain][stats]")
{
  TimerService timer;

  std::atomic<bool> timersCanFinish{false};

  // Schedule 5 timers
  for (int i = 0; i < 5; ++i)
  {
    timer.scheduleAfter(std::chrono::milliseconds(50 + i * 10),
                        [&]()
                        {
                          while (!timersCanFinish.load())
                          {
                            std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                        });
  }

  // Wait for first timer to start
  std::this_thread::sleep_for(std::chrono::milliseconds(70));

  // Allow timers to finish
  timersCanFinish.store(true);

  // Drain
  auto result = timer.drain(5000);

  REQUIRE(result.success == true);
  REQUIRE(result.drainStats.has_value());

  auto& stats = result.drainStats.value();
  INFO("inFlightAtStart: " << stats.inFlightAtStart);
  INFO("completed: " << stats.completed);
  INFO("remaining: " << stats.remaining);

  // All timers should complete
  REQUIRE(stats.remaining == 0);
}

TEST_CASE("TimerService lifecycle: Cancel scheduled timer before drain", "[timer][lifecycle][cancel]")
{
  TimerService timer;

  std::atomic<int> counter{0};

  // Schedule a timer
  auto id = timer.scheduleAfter(std::chrono::milliseconds(100), [&counter]() { counter.fetch_add(1); });
  REQUIRE(id != 0);

  // Cancel it
  bool canceled = timer.cancel(id);
  REQUIRE(canceled == true);

  // Drain
  auto result = timer.drain(5000);
  REQUIRE(result.success == true);

  // Timer should not have executed
  REQUIRE(counter.load() == 0);
}
