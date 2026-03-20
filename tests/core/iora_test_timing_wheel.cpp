// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for TimingWheel

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/core/timing_wheel.hpp>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

using namespace iora::core;
using namespace std::chrono_literals;

// ══════════════════════════════════════════════════════════════════════════════
// Schedule + Advance
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TW: schedule and advance fires callback", "[timing_wheel]")
{
  TimingWheel tw(10ms, 16, 2);
  tw.start();

  bool fired = false;
  auto id = tw.schedule(15ms, [&]() { fired = true; });
  REQUIRE(id != InvalidTimerId);

  // Wait enough for the timer to fire
  std::this_thread::sleep_for(50ms);
  tw.stop();
  REQUIRE(fired);
}

TEST_CASE("TW: cancel prevents callback", "[timing_wheel]")
{
  TimingWheel tw(10ms, 16, 2);
  tw.start();

  bool fired = false;
  auto id = tw.schedule(50ms, [&]() { fired = true; });
  REQUIRE(tw.cancel(id));

  std::this_thread::sleep_for(100ms);
  tw.stop();
  REQUIRE_FALSE(fired);
}

TEST_CASE("TW: cancel returns false for unknown id", "[timing_wheel]")
{
  TimingWheel tw(10ms, 16, 2);
  tw.start();
  REQUIRE_FALSE(tw.cancel(999));
  tw.stop();
}

TEST_CASE("TW: reschedule changes delay", "[timing_wheel]")
{
  TimingWheel tw(10ms, 16, 2);
  tw.start();

  bool fired = false;
  auto id = tw.schedule(200ms, [&]() { fired = true; });

  // Reschedule to fire sooner
  REQUIRE(tw.reschedule(id, 15ms));

  std::this_thread::sleep_for(50ms);
  tw.stop();
  REQUIRE(fired);
}

TEST_CASE("TW: reschedule returns false for already-fired timer", "[timing_wheel]")
{
  TimingWheel tw(10ms, 16, 2);
  tw.start();

  std::atomic<bool> fired{false};
  auto id = tw.schedule(15ms, [&]() { fired.store(true); });

  // Wait for it to fire
  while (!fired.load()) std::this_thread::sleep_for(5ms);

  REQUIRE_FALSE(tw.reschedule(id, 100ms));
  tw.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// Pending Count
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TW: pendingCount tracks scheduled/cancelled/fired", "[timing_wheel]")
{
  TimingWheel tw(10ms, 16, 2);
  tw.start();

  REQUIRE(tw.pendingCount() == 0);

  auto id1 = tw.schedule(500ms, []() {});
  tw.schedule(500ms, []() {});
  REQUIRE(tw.pendingCount() == 2);

  tw.cancel(id1);
  REQUIRE(tw.pendingCount() == 1);

  tw.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// Lifecycle
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TW: lifecycle states", "[timing_wheel][lifecycle]")
{
  TimingWheel tw(10ms, 16, 2);
  REQUIRE(tw.getState() == TimingWheelState::CREATED);

  tw.start();
  REQUIRE(tw.getState() == TimingWheelState::RUNNING);

  tw.stop();
  REQUIRE(tw.getState() == TimingWheelState::STOPPED);

  tw.reset();
  REQUIRE(tw.getState() == TimingWheelState::RESET);

  tw.start();
  REQUIRE(tw.getState() == TimingWheelState::RUNNING);
  tw.stop();
}

TEST_CASE("TW: schedule returns InvalidTimerId before start", "[timing_wheel][lifecycle]")
{
  TimingWheel tw(10ms, 16, 2);
  auto id = tw.schedule(10ms, []() {});
  REQUIRE(id == InvalidTimerId);
}

TEST_CASE("TW: schedule returns InvalidTimerId after stop", "[timing_wheel][lifecycle]")
{
  TimingWheel tw(10ms, 16, 2);
  tw.start();
  tw.stop();
  auto id = tw.schedule(10ms, []() {});
  REQUIRE(id == InvalidTimerId);
}

TEST_CASE("TW: drain fires pending timers", "[timing_wheel][lifecycle]")
{
  TimingWheel tw(10ms, 16, 2);
  tw.start();

  int count = 0;
  tw.schedule(5ms, [&]() { ++count; });
  tw.schedule(5ms, [&]() { ++count; });

  tw.drain(5000ms);
  // Timers should have fired during drain
  REQUIRE(tw.pendingCount() == 0);
}

TEST_CASE("TW: shutdown convenience", "[timing_wheel][lifecycle]")
{
  TimingWheel tw(10ms, 16, 2);
  tw.start();
  tw.schedule(5ms, []() {});
  tw.shutdown(5000ms);
  REQUIRE(tw.getState() == TimingWheelState::STOPPED);
}

// ══════════════════════════════════════════════════════════════════════════════
// Exception Handling
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TW: exception in callback does not kill tick thread", "[timing_wheel][exception]")
{
  TimingWheel tw(10ms, 16, 2);
  tw.start();

  bool secondFired = false;
  tw.schedule(10ms, []() { throw std::runtime_error("boom"); });
  tw.schedule(20ms, [&]() { secondFired = true; });

  std::this_thread::sleep_for(100ms);
  tw.stop();
  REQUIRE(secondFired);
}

TEST_CASE("TW: error callback receives exception", "[timing_wheel][exception]")
{
  TimingWheel tw(10ms, 16, 2);
  std::atomic<bool> handlerCalled{false};

  tw.setErrorCallback([&](TimerId, std::exception_ptr)
  {
    handlerCalled.store(true);
  });

  tw.start();
  tw.schedule(10ms, []() { throw std::runtime_error("boom"); });

  std::this_thread::sleep_for(50ms);
  tw.stop();
  REQUIRE(handlerCalled.load());
}

// ══════════════════════════════════════════════════════════════════════════════
// ITimerService Adapter
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TW: TimingWheelAdapter delegates correctly", "[timing_wheel][adapter]")
{
  TimingWheel tw(10ms, 16, 2);
  tw.start();

  TimingWheelAdapter adapter(tw);

  bool fired = false;
  auto id = adapter.schedule(15ms, [&]() { fired = true; });
  REQUIRE(id != InvalidTimerId);

  std::this_thread::sleep_for(50ms);
  tw.stop();
  REQUIRE(fired);
}

TEST_CASE("TW: TimingWheelAdapter cancel", "[timing_wheel][adapter]")
{
  TimingWheel tw(10ms, 16, 2);
  tw.start();

  TimingWheelAdapter adapter(tw);
  bool fired = false;
  auto id = adapter.schedule(100ms, [&]() { fired = true; });
  REQUIRE(adapter.cancel(id));

  std::this_thread::sleep_for(150ms);
  tw.stop();
  REQUIRE_FALSE(fired);
}

// ══════════════════════════════════════════════════════════════════════════════
// Multiple Timers
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TW: multiple timers fire in order", "[timing_wheel]")
{
  TimingWheel tw(5ms, 16, 2);
  tw.start();

  std::vector<int> order;
  std::mutex orderMutex;

  tw.schedule(30ms, [&]() { std::lock_guard l(orderMutex); order.push_back(3); });
  tw.schedule(10ms, [&]() { std::lock_guard l(orderMutex); order.push_back(1); });
  tw.schedule(20ms, [&]() { std::lock_guard l(orderMutex); order.push_back(2); });

  std::this_thread::sleep_for(100ms);
  tw.stop();

  std::lock_guard l(orderMutex);
  REQUIRE(order.size() == 3);
  REQUIRE(order[0] == 1);
  REQUIRE(order[1] == 2);
  REQUIRE(order[2] == 3);
}

// ══════════════════════════════════════════════════════════════════════════════
// Concurrent Stress
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TW: timer with zero delay fires on next advance", "[timing_wheel]")
{
  TimingWheel tw(10ms, 16, 2);
  tw.start();

  std::atomic<bool> fired{false};
  tw.schedule(0ms, [&]() { fired.store(true); });

  std::this_thread::sleep_for(30ms);
  tw.stop();
  REQUIRE(fired.load());
}

TEST_CASE("TW: timer inserted during advance still fires", "[timing_wheel]")
{
  // Simulate heavy load: schedule timers with very short delays
  // while advance is running. All should eventually fire.
  TimingWheel tw(5ms, 16, 2);
  tw.start();

  constexpr int N = 50;
  std::atomic<int> fireCount{0};

  for (int i = 0; i < N; ++i)
  {
    tw.schedule(std::chrono::milliseconds(1 + (i % 10)),
      [&]() { fireCount.fetch_add(1); });
  }

  // Wait enough time for all timers to fire
  std::this_thread::sleep_for(200ms);
  tw.stop();

  REQUIRE(fireCount.load() == N);
}

TEST_CASE("TW: DrainStats returned from drain", "[timing_wheel][drain]")
{
  TimingWheel tw(5ms, 16, 2);
  tw.start();

  tw.schedule(5ms, []() {});
  tw.schedule(5ms, []() {});
  tw.schedule(5ms, []() {});

  auto stats = tw.drain(5000ms);
  REQUIRE(stats.fired >= 3);
  REQUIRE(stats.remaining == 0);
  REQUIRE(stats.elapsed.count() >= 0);
}

TEST_CASE("TW: drain timeout cancels remaining", "[timing_wheel][drain]")
{
  TimingWheel tw(10ms, 16, 2);
  tw.start();

  // Schedule many slow callbacks that each take time
  std::atomic<int> fired{0};
  for (int i = 0; i < 100; ++i)
  {
    tw.schedule(5ms, [&]()
    {
      fired.fetch_add(1);
      std::this_thread::sleep_for(5ms); // slow callback
    });
  }

  // Drain with very short timeout — should hit timeout during slow callbacks
  auto stats = tw.drain(20ms);
  // Verify drain completed and returned stats
  REQUIRE(tw.getState() == TimingWheelState::STOPPED);
  REQUIRE(tw.pendingCount() == 0); // all cleaned up
  REQUIRE(stats.fired + stats.remaining == 100);
}

TEST_CASE("TW: drain fires timers in deadline order", "[timing_wheel][drain]")
{
  TimingWheel tw(10ms, 16, 2);
  tw.start();

  std::vector<int> order;
  std::mutex orderMutex;

  // Schedule in non-deadline order
  tw.schedule(30ms, [&]() { std::lock_guard l(orderMutex); order.push_back(3); });
  tw.schedule(10ms, [&]() { std::lock_guard l(orderMutex); order.push_back(1); });
  tw.schedule(20ms, [&]() { std::lock_guard l(orderMutex); order.push_back(2); });

  // Drain should fire in deadline order (earliest first)
  tw.drain(5000ms);

  std::lock_guard l(orderMutex);
  REQUIRE(order.size() == 3);
  REQUIRE(order[0] == 1);
  REQUIRE(order[1] == 2);
  REQUIRE(order[2] == 3);
}

TEST_CASE("TW: cascade from level 1 to level 0", "[timing_wheel][cascade]")
{
  // 10ms tick, 4 slots per wheel, 2 levels
  // Level 0 covers 4 * 10ms = 40ms
  // A timer with 50ms delay overflows level 0 → placed in level 1
  TimingWheel tw(10ms, 4, 2);
  tw.start();

  std::atomic<bool> fired{false};
  tw.schedule(50ms, [&]() { fired.store(true); });

  // Wait for cascade to happen and timer to fire
  std::this_thread::sleep_for(200ms);
  tw.stop();
  REQUIRE(fired.load());
}

TEST_CASE("TW: dispatcher receives callbacks", "[timing_wheel][dispatch]")
{
  std::atomic<int> dispatchCount{0};
  auto dispatcher = [&](TimingWheel::Callback cb)
  {
    dispatchCount.fetch_add(1);
    cb(); // execute immediately but count the dispatch
  };

  TimingWheel tw(5ms, 16, 2, dispatcher);
  tw.start();

  tw.schedule(10ms, []() {});
  tw.schedule(10ms, []() {});

  std::this_thread::sleep_for(50ms);
  tw.stop();
  REQUIRE(dispatchCount.load() >= 2);
}

TEST_CASE("TW: adapter reschedule", "[timing_wheel][adapter]")
{
  TimingWheel tw(10ms, 16, 2);
  tw.start();

  TimingWheelAdapter adapter(tw);
  std::atomic<bool> fired{false};
  auto id = adapter.schedule(200ms, [&]() { fired.store(true); });

  REQUIRE(adapter.reschedule(id, 15ms));
  std::this_thread::sleep_for(50ms);
  tw.stop();
  REQUIRE(fired.load());
}

TEST_CASE("TW: concurrent schedule + cancel stress", "[timing_wheel][stress]")
{
  TimingWheel tw(5ms, 64, 2);
  tw.start();

  constexpr int numThreads = 4;
  constexpr int opsPerThread = 1000;
  std::atomic<int> fireCount{0};

  std::vector<std::thread> threads;
  for (int t = 0; t < numThreads; ++t)
  {
    threads.emplace_back([&]()
    {
      for (int i = 0; i < opsPerThread; ++i)
      {
        auto id = tw.schedule(std::chrono::milliseconds(5 + (i % 50)),
          [&]() { fireCount.fetch_add(1); });
        if (i % 3 == 0 && id != InvalidTimerId)
        {
          tw.cancel(id);
        }
      }
    });
  }

  for (auto& t : threads) t.join();

  // Wait for remaining timers to fire
  std::this_thread::sleep_for(200ms);
  tw.stop();

  // Verify: no crashes, pending count is 0
  REQUIRE(tw.pendingCount() == 0);
}
