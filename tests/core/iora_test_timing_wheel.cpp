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

TEST_CASE("TW: drain fires expired pending timers", "[timing_wheel][lifecycle]")
{
  // Use 2000ms tick so tick thread won't fire the 5ms timers before drain
  TimingWheel tw(2000ms, 16, 2);
  tw.start();

  int count = 0;
  tw.schedule(5ms, [&]() { ++count; });
  tw.schedule(5ms, [&]() { ++count; });

  // Sleep past the 5ms deadlines so drain sees them as expired
  std::this_thread::sleep_for(10ms);

  auto stats = tw.drain(5000ms);
  REQUIRE(tw.pendingCount() == 0);
  REQUIRE(count == 2);
  REQUIRE(stats.fired == 2);
  REQUIRE(stats.cancelled == 0);
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

TEST_CASE("TW: tickDuration exposes the configured tick (task-4.7c)",
          "[timing_wheel][adapter]")
{
  TimingWheel tw(10ms, 16, 2);
  CHECK(tw.tickDuration() == 10ms); // const-after-construction: valid pre-start.
  tw.start();
  CHECK(tw.tickDuration() == 10ms); // unchanged by lifecycle.
  tw.stop();

  TimingWheel tw4(4ms, 32, 3);
  CHECK(tw4.tickDuration() == 4ms); // reflects the ctor value, not a constant.

  TimingWheelAdapter adapter(tw);
  CHECK(adapter.tickDuration() == tw.tickDuration()); // forwards the wheel getter.
}

TEST_CASE("TW: ITimerService::tickDuration defaults to a 0 sentinel for a "
          "non-overriding implementer (task-4.7c standoff resolution)",
          "[timing_wheel][adapter]")
{
  // A minimal ITimerService overriding ONLY the pure virtuals — proving the new
  // tickDuration() is NON-pure with a safe 0 ("granularity unknown") default, so
  // the 30+ existing implementers keep compiling without any change.
  struct BareTimer : ITimerService
  {
    TimerId schedule(std::chrono::milliseconds, std::function<void()>) override
    {
      return InvalidTimerId;
    }
    bool cancel(TimerId) override { return false; }
    bool reschedule(TimerId, std::chrono::milliseconds) override { return false; }
  };
  BareTimer t;
  CHECK(t.tickDuration() == 0ms);
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
  // Use 2000ms tick so tick thread won't fire the 5ms timers before drain
  TimingWheel tw(2000ms, 16, 2);
  tw.start();

  tw.schedule(5ms, []() {});
  tw.schedule(5ms, []() {});
  tw.schedule(5ms, []() {});

  // Sleep past the 5ms deadlines so drain sees them as expired
  std::this_thread::sleep_for(10ms);

  auto stats = tw.drain(5000ms);
  REQUIRE(stats.fired == 3);
  REQUIRE(stats.remaining == 0);
  REQUIRE(stats.cancelled == 0);
  REQUIRE(stats.elapsed.count() >= 0);
}

TEST_CASE("TW: drain cancels future timers without firing", "[timing_wheel][drain]")
{
  TimingWheel tw(10ms, 16, 2);
  tw.start();

  std::atomic<int> fired{0};
  tw.schedule(60000ms, [&]() { fired.fetch_add(1); });
  tw.schedule(60000ms, [&]() { fired.fetch_add(1); });
  tw.schedule(60000ms, [&]() { fired.fetch_add(1); });

  auto stats = tw.drain(5000ms);
  REQUIRE(stats.fired == 0);
  REQUIRE(stats.cancelled == 3);
  REQUIRE(stats.remaining == 0);
  REQUIRE(fired.load() == 0);
}

TEST_CASE("TW: drain timeout cancels remaining", "[timing_wheel][drain]")
{
  // Use 2000ms tick so tick thread won't fire the 5ms timers before drain
  TimingWheel tw(2000ms, 16, 2);
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

  // Sleep past the 5ms deadlines so drain sees them as expired
  std::this_thread::sleep_for(10ms);

  // Drain with very short timeout — should hit timeout during slow callbacks.
  // 100 callbacks × 5ms each = 500ms total, so 20ms timeout must leave some unfinished.
  auto stats = tw.drain(20ms);
  // Verify drain completed and returned stats
  REQUIRE(tw.getState() == TimingWheelState::STOPPED);
  REQUIRE(tw.pendingCount() == 0); // all cleaned up
  REQUIRE(stats.cancelled == 0); // all were expired (slept past deadline)
  REQUIRE(stats.fired + stats.remaining == 100);
  REQUIRE(stats.remaining > 0); // timeout must have left some unfired
  REQUIRE(stats.fired > 0); // some should have fired before timeout
}

TEST_CASE("TW: drain fires expired timers in deadline order", "[timing_wheel][drain]")
{
  // Use 2000ms tick so tick thread won't fire the timers before drain
  TimingWheel tw(2000ms, 16, 2);
  tw.start();

  std::vector<int> order;
  std::mutex orderMutex;

  // Schedule in non-deadline order
  tw.schedule(30ms, [&]() { std::lock_guard l(orderMutex); order.push_back(3); });
  tw.schedule(10ms, [&]() { std::lock_guard l(orderMutex); order.push_back(1); });
  tw.schedule(20ms, [&]() { std::lock_guard l(orderMutex); order.push_back(2); });

  // Sleep past all deadlines so drain sees them as expired
  std::this_thread::sleep_for(40ms);

  // Drain should fire in deadline order (earliest first)
  auto stats = tw.drain(5000ms);

  std::lock_guard l(orderMutex);
  REQUIRE(order.size() == 3);
  REQUIRE(order[0] == 1);
  REQUIRE(order[1] == 2);
  REQUIRE(order[2] == 3);
  REQUIRE(stats.cancelled == 0);
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

// ══════════════════════════════════════════════════════════════════════════════
// Over-range (over-max-delay) handling — tracker 2026-09-10-1
//
// A delay exceeding the wheel's representable span (ticksPerWheel^numWheels
// ticks) must NOT fire early (numWheels==1) nor hang (numWheels>=2): insertEntry
// clamps it to the furthest bucket while preserving the real deadline, and the
// collectFromBucket/cascadeDown deadline gate re-defers it (via advance()'s
// scratch list) until it is in range. These tests fire on real steady_clock time
// and use generous margins with a pre-deadline "not fired yet" non-vacuity anchor.
// ══════════════════════════════════════════════════════════════════════════════

namespace
{
  inline long long elapsedMs(std::chrono::steady_clock::time_point t0)
  {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - t0).count();
  }
}

TEST_CASE("TW: over-range delay does not fire early (numWheels==1)",
          "[timing_wheel][overrange]")
{
  // span = 4 * 5ms = 20ms; 60ms is 3x over-range. Without the fix the masked
  // bucket fires within the first span (~5-20ms).
  TimingWheel tw(5ms, 4, 1);
  tw.start();

  std::atomic<bool> fired{false};
  std::atomic<long long> fireMs{-1};
  auto t0 = std::chrono::steady_clock::now();
  tw.schedule(60ms, [&]() { fireMs.store(elapsedMs(t0)); fired.store(true); });

  // Past the (buggy) misfire window but well before the true 60ms deadline.
  std::this_thread::sleep_for(38ms);
  CHECK_FALSE(fired.load()); // FAILS without the fix (fired at ~5-20ms).

  std::this_thread::sleep_for(55ms); // total ~93ms, past the true deadline
  tw.stop();
  REQUIRE(fired.load());
  CHECK(fireMs.load() >= 55); // fired near 60ms, not near 20ms (non-vacuity)
}

TEST_CASE("TW: over-range delay does not fire early (numWheels>=2)",
          "[timing_wheel][overrange]")
{
  // span = 4^2 * 5ms = 80ms; 240ms is 3x over-range.
  TimingWheel tw(5ms, 4, 2);
  tw.start();

  std::atomic<bool> fired{false};
  std::atomic<long long> fireMs{-1};
  auto t0 = std::chrono::steady_clock::now();
  tw.schedule(240ms, [&]() { fireMs.store(elapsedMs(t0)); fired.store(true); });

  std::this_thread::sleep_for(140ms); // past the 80ms span, before 240ms
  CHECK_FALSE(fired.load());

  std::this_thread::sleep_for(150ms); // total ~290ms
  tw.stop();
  REQUIRE(fired.load());
  CHECK(fireMs.load() >= 230);
}

TEST_CASE("TW: over-range entries do not hang or double-fire (ping-pong guard)",
          "[timing_wheel][overrange]")
{
  // Bounded-time hang probe: >=2 over-range entries in the same top-level bucket
  // are the ping-pong/hang scenario. Run on a worker thread; FAIL on timeout
  // (never raise the bound to mask a real hang). The shared flags are heap-owned
  // (shared_ptr captured BY VALUE) so that on the failure path — where we detach
  // a still-hung worker rather than join it — the worker never dereferences a
  // destroyed TEST_CASE stack frame.
  auto done = std::make_shared<std::atomic<bool>>(false);
  auto fireCount = std::make_shared<std::atomic<int>>(0);
  std::thread worker([done, fireCount]()
  {
    TimingWheel tw(2ms, 4, 2); // span = 4^2 * 2ms = 32ms
    tw.start();
    tw.schedule(200ms, [fireCount]() { fireCount->fetch_add(1); });
    tw.schedule(200ms, [fireCount]() { fireCount->fetch_add(1); });
    std::this_thread::sleep_for(260ms);
    tw.stop();
    done->store(true);
  });

  auto deadline = std::chrono::steady_clock::now() + 5s;
  while (!done->load() && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(10ms);
  }
  bool completed = done->load();
  if (completed) { worker.join(); }
  else { worker.detach(); } // hung: do not join (would hang the harness)

  REQUIRE(completed);              // timeout => hang => fail
  CHECK(fireCount->load() == 2);   // both fired exactly once (no double-fire)
}

TEST_CASE("TW: last in-range delay is not clamped (boundary)",
          "[timing_wheel][overrange]")
{
  // span = 4 * 10ms = 40ms; 35ms (raw ticks 3 < 4) is the last-in-range region
  // and must fire at its true deadline, not be deferred/clamped.
  TimingWheel tw(10ms, 4, 1);
  tw.start();

  std::atomic<bool> fired{false};
  std::atomic<long long> fireMs{-1};
  auto t0 = std::chrono::steady_clock::now();
  tw.schedule(35ms, [&]() { fireMs.store(elapsedMs(t0)); fired.store(true); });

  std::this_thread::sleep_for(90ms);
  tw.stop();
  REQUIRE(fired.load());
  CHECK(fireMs.load() >= 30); // not clamped early
  CHECK(fireMs.load() <= 65); // not deferred late
}

TEST_CASE("TW: multi-span over-range fires at true deadline (repeated re-clamp)",
          "[timing_wheel][overrange]")
{
  // span = 4 * 5ms = 20ms; 150ms is ~7.5x -> the entry re-clamps several times.
  TimingWheel tw(5ms, 4, 1);
  tw.start();

  std::atomic<bool> fired{false};
  std::atomic<long long> fireMs{-1};
  auto t0 = std::chrono::steady_clock::now();
  tw.schedule(150ms, [&]() { fireMs.store(elapsedMs(t0)); fired.store(true); });

  std::this_thread::sleep_for(100ms); // many span cycles, still before 150ms
  CHECK_FALSE(fired.load());

  std::this_thread::sleep_for(90ms); // total ~190ms
  tw.stop();
  REQUIRE(fired.load());
  CHECK(fireMs.load() >= 145);
}

TEST_CASE("TW: reschedule to an over-range delay honors the new deadline",
          "[timing_wheel][overrange]")
{
  // reschedule() routes through insertEntry, so the over-range guard covers it.
  TimingWheel tw(5ms, 4, 1); // span = 20ms
  tw.start();

  std::atomic<bool> fired{false};
  std::atomic<long long> fireMs{-1};
  auto t0 = std::chrono::steady_clock::now();
  auto id = tw.schedule(10ms, [&]() { fireMs.store(elapsedMs(t0)); fired.store(true); });
  REQUIRE(tw.reschedule(id, 80ms)); // over-range

  std::this_thread::sleep_for(50ms);
  CHECK_FALSE(fired.load()); // original 10ms would have fired; reschedule moved it out

  std::this_thread::sleep_for(60ms); // total ~110ms
  tw.stop();
  REQUIRE(fired.load());
  CHECK(fireMs.load() >= 72); // fired near the rescheduled 80ms deadline
}

TEST_CASE("TW: over-range schedule + cancel leaves no pending (no leak)",
          "[timing_wheel][overrange]")
{
  TimingWheel tw(5ms, 4, 2); // span = 80ms
  tw.start();

  auto id = tw.schedule(500ms, []() {}); // over-range (clamped, in _entryMap)
  REQUIRE(id != InvalidTimerId);
  REQUIRE(tw.pendingCount() == 1);
  REQUIRE(tw.cancel(id)); // must resolve via _entryMap despite the clamp
  REQUIRE(tw.pendingCount() == 0);

  tw.stop();
}

TEST_CASE("TW: in-range timer is not delayed by the deadline gate (R7)",
          "[timing_wheel][overrange]")
{
  // The collectFromBucket deadline gate must not add latency to normal timers:
  // a near-boundary in-range timer still fires within ~one tick of its deadline.
  TimingWheel tw(10ms, 16, 2);
  tw.start();

  std::atomic<bool> fired{false};
  std::atomic<long long> fireMs{-1};
  auto t0 = std::chrono::steady_clock::now();
  tw.schedule(50ms, [&]() { fireMs.store(elapsedMs(t0)); fired.store(true); });

  std::this_thread::sleep_for(120ms);
  tw.stop();
  REQUIRE(fired.load());
  CHECK(fireMs.load() >= 45); // not early
  CHECK(fireMs.load() <= 65); // sanity bound: a large over-range-style deferral
                              // would blow past this. (Wall-clock cannot cleanly
                              // isolate a one-tick-late regression from the wheel's
                              // own tick granularity, which overlap at ~60ms.)
}

TEST_CASE("TW: in-range multi-level cascade fires on time under drift",
          "[timing_wheel][overrange][cascade]")
{
  // Guards the stage-then-drain refactor of the NORMAL cascade path. A slow
  // callback stalls the tick thread so the next advance() catches up multiple
  // ticks in one call; the in-range 60ms timer (L1 -> L0 cascade) must still
  // fire near its deadline (neither dropped, nor early, nor a full cycle late).
  TimingWheel tw(5ms, 4, 2); // level-0 span 20ms, total span 80ms
  tw.start();

  std::atomic<bool> cascadeFired{false};
  std::atomic<long long> fireMs{-1};
  auto t0 = std::chrono::steady_clock::now();
  tw.schedule(5ms, [&]() { std::this_thread::sleep_for(40ms); }); // induce drift
  tw.schedule(60ms, [&]() { fireMs.store(elapsedMs(t0)); cascadeFired.store(true); });

  std::this_thread::sleep_for(170ms);
  tw.stop();
  REQUIRE(cascadeFired.load());
  CHECK(fireMs.load() >= 55);  // not early
  CHECK(fireMs.load() <= 115); // not a full-cycle-late / lost timer
}

TEST_CASE("TW: exact over-range boundary (ticks == ticksPerWheel) defers, not early",
          "[timing_wheel][overrange]")
{
  // span = 4 * 10ms = 40ms; delay 40ms => exactly 4 ticks == ticksPerWheel, the
  // FIRST over-range value. This pins CORRECT firing at the exact clamp boundary.
  // (Note: it does not discriminate a '>' vs '>=' off-by-one in the over-range
  // detection — the collectFromBucket deadline gate re-defers a boundary entry
  // regardless of which branch insertEntry took, making that off-by-one
  // behavior-invisible and, with the gate, behavior-equivalent.)
  TimingWheel tw(10ms, 4, 1);
  tw.start();

  std::atomic<bool> fired{false};
  std::atomic<long long> fireMs{-1};
  auto t0 = std::chrono::steady_clock::now();
  tw.schedule(40ms, [&]() { fireMs.store(elapsedMs(t0)); fired.store(true); });

  std::this_thread::sleep_for(30ms); // within the first span, before the 40ms deadline
  CHECK_FALSE(fired.load());          // exact boundary must not misfire in-span
  std::this_thread::sleep_for(45ms);  // total ~75ms
  tw.stop();
  REQUIRE(fired.load());
  CHECK(fireMs.load() >= 35); // fired near 40ms, not masked early
}

TEST_CASE("TW: minimum geometry (ticksPerWheel==2) schedules and fires",
          "[timing_wheel]")
{
  // Documents the tightened precondition ticksPerWheel>=2: a 1-slot wheel is
  // rejected by the constructor assert. Catch2 v2.13.10 has no death-test to
  // assert the abort, so this pins that the MINIMUM valid geometry works
  // end-to-end (across all 3 levels).
  TimingWheel tw(5ms, 2, 3); // ticksPerWheel==2, span = 2^3 * 5ms = 40ms
  tw.start();

  std::atomic<bool> fired{false};
  tw.schedule(15ms, [&]() { fired.store(true); });
  std::this_thread::sleep_for(60ms);
  tw.stop();
  REQUIRE(fired.load());
}

TEST_CASE("TW: numWheels==3 cascade depth fires in-range and over-range on time",
          "[timing_wheel][overrange][cascade][sip]")
{
  // Wall-clock-reachable 3-level geometry matching the SIP wheel's DEPTH:
  // tick=3ms, 2 slots, 3 wheels -> L0=6ms, L1=12ms, L2=24ms (span 24ms). The
  // production tw(10ms,64,3) cannot fire in a unit-test window; this exercises
  // the same 3-level cascade recursion. In-range 20ms forces a full L2->L1->L0
  // descent; over-range 60ms forces the L2 furthest-bucket clamp + repeated
  // re-defer through the 3-level cascade.
  TimingWheel tw(3ms, 2, 3);
  tw.start();

  std::atomic<bool> inRangeFired{false};
  std::atomic<bool> overFired{false};
  std::atomic<long long> inMs{-1};
  std::atomic<long long> overMs{-1};
  auto t0 = std::chrono::steady_clock::now();
  tw.schedule(20ms, [&]() { inMs.store(elapsedMs(t0)); inRangeFired.store(true); });
  tw.schedule(60ms, [&]() { overMs.store(elapsedMs(t0)); overFired.store(true); });

  std::this_thread::sleep_for(40ms); // past 20ms (in-range fired), before 60ms
  CHECK(inRangeFired.load());          // in-range descended L2->L1->L0 and fired
  CHECK_FALSE(overFired.load());       // over-range not early

  std::this_thread::sleep_for(50ms); // total ~90ms, past the 60ms deadline
  tw.stop();
  REQUIRE(overFired.load());
  CHECK(inMs.load() >= 15);   // in-range fired near 20ms
  CHECK(overMs.load() >= 55); // over-range fired near 60ms via the 3-level cascade
}

TEST_CASE("TW: many over-range timers keep advance() bounded (no hang)",
          "[timing_wheel][overrange]")
{
  // Bounded critical section: with hundreds of over-range timers, advance() must
  // stay responsive. If the fix ping-ponged/hung under _wheelMutex, the
  // pendingCount() below (which takes _wheelMutex) would block -> ctest timeout.
  TimingWheel tw(2ms, 8, 2); // span = 8^2 * 2ms = 128ms
  tw.start();

  std::atomic<int> fired{0};
  constexpr int N = 500;
  for (int i = 0; i < N; ++i)
  {
    tw.schedule(std::chrono::milliseconds(5000 + i), // all over-range (>> 128ms)
      [&]() { fired.fetch_add(1); });
  }
  REQUIRE(tw.pendingCount() == N);

  std::this_thread::sleep_for(120ms); // wheel keeps ticking; must stay responsive
  CHECK(fired.load() == 0);       // none misfired early
  CHECK(tw.pendingCount() == N);  // all still pending (clamped), consistent
  tw.stop();
}

TEST_CASE("TW: over-range entries survive tick-drift catch-up",
          "[timing_wheel][overrange]")
{
  // A slow callback stalls the tick thread so the next advance() catches up
  // multiple ticks in one call WITH an over-range entry present (the worst case
  // for the scratch-list scope + critical-section length).
  TimingWheel tw(5ms, 4, 2); // span = 80ms
  tw.start();

  std::atomic<bool> overFired{false};
  std::atomic<long long> fireMs{-1};
  auto t0 = std::chrono::steady_clock::now();
  tw.schedule(5ms, [&]() { std::this_thread::sleep_for(50ms); }); // induce drift
  tw.schedule(200ms, [&]() { fireMs.store(elapsedMs(t0)); overFired.store(true); });

  std::this_thread::sleep_for(120ms); // during/after the catch-up, before 200ms
  CHECK_FALSE(overFired.load());       // not misfired during the drift sweep

  std::this_thread::sleep_for(140ms); // total ~260ms, past the deadline
  tw.stop();
  REQUIRE(overFired.load());
  CHECK(fireMs.load() >= 190); // fired near 200ms
}

TEST_CASE("TW: SIP production geometry over-range does not misfire early or hang",
          "[timing_wheel][overrange][sip]")
{
  // Real iora_sip transaction backend geometry: tick=10ms, 64 slots, 3 wheels
  // -> span = 64^3 * 10ms = 2621.44s. Server binding-expiration (3,600,000 ms)
  // and client refresh (~3,231,000 ms) both over-range at this default config.
  // Their true deadlines (and even the masked misfire bucket, ~900s+ out) are not
  // wall-clock reachable in a unit test; the deadline-HONORING behavior is covered
  // by the small-geometry tests above (identical code path). Here we pin, ON THE
  // REAL GEOMETRY, that an over-range registration timer is accepted, does NOT
  // misfire in a short window, does not hang, stays live in _entryMap, and remains
  // cancellable despite the furthest-bucket clamp.
  TimingWheel tw(10ms, 64, 3);
  tw.start();

  std::atomic<int> overRangeFired{0};
  std::atomic<bool> inRangeFired{false};
  auto idServer = tw.schedule(3600000ms, [&]() { overRangeFired.fetch_add(1); }); // 3600s
  auto idClient = tw.schedule(3231000ms, [&]() { overRangeFired.fetch_add(1); }); // ~3231s
  // An IN-RANGE transaction-scale timer at the production geometry: it must fire
  // on time and be unperturbed by the two over-range clamps sharing the wheel.
  tw.schedule(50ms, [&]() { inRangeFired.store(true); });
  REQUIRE(idServer != InvalidTimerId);
  REQUIRE(idClient != InvalidTimerId);
  REQUIRE(tw.pendingCount() == 3);

  std::this_thread::sleep_for(200ms); // background ticks run; must not misfire/hang
  CHECK(inRangeFired.load());         // in-range timer fired within the window
  CHECK(overRangeFired.load() == 0);  // over-range did NOT misfire early
  CHECK(tw.pendingCount() == 2);      // the two over-range still pending (clamped)

  REQUIRE(tw.cancel(idServer));
  REQUIRE(tw.cancel(idClient));
  REQUIRE(tw.pendingCount() == 0); // cancellable despite the clamp
  tw.stop();
}

TEST_CASE("TW: concurrent over-range schedule/cancel/reschedule stress",
          "[timing_wheel][overrange][stress]")
{
  // Forces cascade + scratch-list under contention; run under TSan/ASan to
  // confirm the deferred-drain bookkeeping introduces no race and no leak.
  TimingWheel tw(2ms, 8, 2); // span = 8^2 * 2ms = 128ms
  tw.start();

  constexpr int numThreads = 4;
  constexpr int opsPerThread = 500;
  std::atomic<int> fireCount{0};

  std::vector<std::thread> threads;
  for (int t = 0; t < numThreads; ++t)
  {
    threads.emplace_back([&]()
    {
      for (int i = 0; i < opsPerThread; ++i)
      {
        auto id = tw.schedule(std::chrono::milliseconds(200 + (i % 50)), // all over-range
          [&]() { fireCount.fetch_add(1); });
        if (id == InvalidTimerId) { continue; }
        if (i % 3 == 0) { tw.cancel(id); }
        else if (i % 3 == 1) { tw.reschedule(id, std::chrono::milliseconds(150)); }
      }
    });
  }
  for (auto& t : threads) t.join();

  std::this_thread::sleep_for(50ms);
  tw.stop();
  REQUIRE(tw.pendingCount() == 0); // no leak / no dangling entries
}
