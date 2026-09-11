// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for TimerService ILifecycleManaged interface implementation

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>
#include <iora/common/i_lifecycle_managed.hpp>
#include <iora/core/timer.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <unistd.h>

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

TEST_CASE("TimerService lifecycle: drain() cancels far-future timers", "[timer][lifecycle][drain][timeout]")
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

  // Drain with short timeout — timers are beyond the drain deadline,
  // so they are cancelled (not waited for). Drain succeeds immediately.
  auto result = timer.drain(500);

  REQUIRE(result.success == true);
  REQUIRE(result.newState == LifecycleState::Draining);
  REQUIRE(timer.getState() == LifecycleState::Draining);

  // Verify drain statistics show cancelled timers
  REQUIRE(result.drainStats.has_value());
  REQUIRE(result.drainStats->remaining == 0);
  REQUIRE(result.drainStats->cancelled == 5);

  // Timers should not have executed (they were cancelled, not fired)
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

// ══════════════════════════════════════════════════════════════════════════
// Regression: drain(0) vs periodic timers (TM3 hang) + drain(0) vs concurrent
// stop() (H-1 shutdown-escape).
//   Tracker: tasks/iora/ongoing/2026-09-10-2_timer-drain-zero-hangs-with-periodic_P0
//
// drain(0) ("wait indefinitely") must terminate when a periodic timer is
// active (periodics re-arm on every fire and would otherwise keep drainDone
// unsatisfiable forever), must still wait for in-flight (executing) callbacks,
// must let pending one-shot timers fire naturally, and must not hang if a
// concurrent stop() truncates the run loop while it waits.
// ══════════════════════════════════════════════════════════════════════════

namespace
{
/// Runs timer.drain(timeoutMs) on a worker thread joined with a bounded wait.
/// Under the UNFIXED code drain(0) hangs forever with an active periodic; the
/// bounded wait turns that into a test FAILURE rather than a suite hang. On a
/// detected hang the worker is left detached (still blocked inside drain), so a
/// hang-sensitive caller MUST leak its TimerService (never destroy it while the
/// worker is inside drain) — see requireDrainedOrLeak.
struct BoundedDrain
{
  bool completed{false};
  LifecycleResult result;
};

BoundedDrain runBoundedDrain(TimerService &timer, std::uint32_t timeoutMs,
                             std::chrono::milliseconds bound)
{
  auto prom = std::make_shared<std::promise<LifecycleResult>>();
  auto fut = prom->get_future();
  std::thread worker([&timer, timeoutMs, prom]() { prom->set_value(timer.drain(timeoutMs)); });

  BoundedDrain out;
  if (fut.wait_for(bound) == std::future_status::ready)
  {
    out.completed = true;
    out.result = fut.get();
    worker.join();
  }
  else
  {
    out.completed = false;
    worker.detach(); // caller must leak `timer`
  }
  return out;
}

/// If the drain hung, leak the heap TimerService (its worker is still blocked
/// inside drain, so it must never be destroyed) and FAIL. Otherwise a no-op.
void requireDrainedOrLeak(BoundedDrain &bd, std::unique_ptr<TimerService> &timer, const char *what)
{
  if (!bd.completed)
  {
    timer.release(); // worker still inside drain(0) — leak, do not destroy
    FAIL(what);
  }
}

/// Runs drain() on a worker and signals `returned` (release) once it returns,
/// storing the result. Used by the mid-execution cases that cannot use
/// runBoundedDrain (they must observe the "did not return yet" state before
/// releasing the callback). The result/flag live in a heap State owned by a
/// shared_ptr captured BY VALUE into the worker lambda (never `this`), so a
/// detached worker after a non-permanent hang writes only to still-live memory.
struct DrainWorker
{
  struct State
  {
    std::atomic<bool> returned{false};
    LifecycleResult result;
  };
  std::shared_ptr<State> state{std::make_shared<State>()};
  std::thread worker;

  void start(TimerService &timer, std::uint32_t timeoutMs)
  {
    auto st = state; // shared_ptr copy — keeps State alive for a detached worker
    worker = std::thread(
      [st, &timer, timeoutMs]()
      {
        LifecycleResult r = timer.drain(timeoutMs);
        st->result = r;
        st->returned.store(true, std::memory_order_release);
      });
  }

  bool returnedNow() const { return state->returned.load(std::memory_order_acquire); }
  const LifecycleResult &result() const { return state->result; }

  bool waitReturned(std::chrono::milliseconds bound) const
  {
    auto deadline = std::chrono::steady_clock::now() + bound;
    while (!state->returned.load(std::memory_order_acquire))
    {
      if (std::chrono::steady_clock::now() >= deadline)
      {
        return false;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return true;
  }
};

/// RAII safety net for a DrainWorker driving a heap TimerService: on scope exit
/// (including an assertion-failure unwind) it joins the worker if drain has
/// returned, otherwise it detaches the worker and LEAKS the TimerService so the
/// still-blocked worker never touches freed memory. This prevents std::terminate
/// (a joinable thread destroyed during unwind) and a TimerService UAF. The
/// worker's DrainWorker::State is heap-owned via shared_ptr, so it too survives
/// a detach. The only stack state a detached worker could reference is a timer
/// handler's captures — safe here because in every hang-eligible case no such
/// handler is runnable at leak time (cases 2/2b release the callback before any
/// hang; case 9's one-shot never fires and stop() joins the run loop first).
struct DrainWorkerGuard
{
  DrainWorker &dw;
  std::unique_ptr<TimerService> &timer;
  ~DrainWorkerGuard()
  {
    if (dw.waitReturned(std::chrono::seconds(3)))
    {
      if (dw.worker.joinable())
      {
        dw.worker.join();
      }
    }
    else
    {
      dw.worker.detach();
      timer.release(); // leak: worker still inside drain
    }
  }
};
} // namespace

// (1) DISCRIMINATING: a long-interval periodic must not delay drain(0). A fix
// that only stops re-arming (leaving the live record uncancelled) would block
// up to one interval — the 2s bound would trip and FAIL.
TEST_CASE("TimerService drain(0): terminates promptly with a long-interval periodic",
          "[timer][lifecycle][drain][periodic][zero]")
{
  auto timer = std::make_unique<TimerService>();
  std::atomic<int> fires{0};
  auto id = timer->schedulePeriodic(std::chrono::seconds(30), [&fires]() { fires.fetch_add(1); });
  REQUIRE(id != 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(20));

  auto t0 = std::chrono::steady_clock::now();
  auto bd = runBoundedDrain(*timer, 0, std::chrono::milliseconds(2000));
  auto elapsed = std::chrono::steady_clock::now() - t0;

  requireDrainedOrLeak(bd, timer, "drain(0) hung with an active long-interval periodic (unfixed TM3)");
  REQUIRE(bd.result.success == true);
  REQUIRE(bd.result.drainStats.has_value());
  REQUIRE(bd.result.drainStats->remaining == 0);
  REQUIRE(elapsed < std::chrono::milliseconds(500)); // << 30s interval
  REQUIRE(fires.load() == 0);                        // never fired
}

// (2) NON-VACUOUS requirement (b), ONE-SHOT: drain(0) must not return while a
// one-shot callback is executing. Heap timer + DrainWorkerGuard so an
// assertion-failure unwind can never std::terminate or UAF.
TEST_CASE("TimerService drain(0): waits for an in-flight one-shot callback",
          "[timer][lifecycle][drain][inflight][zero]")
{
  auto timer = std::make_unique<TimerService>();
  std::promise<void> entered;
  std::atomic<bool> release{false};
  std::atomic<bool> handlerDone{false};

  auto id = timer->scheduleAfter(std::chrono::milliseconds(10),
                                 [&]()
                                 {
                                   entered.set_value();
                                   while (!release.load(std::memory_order_acquire))
                                   {
                                     std::this_thread::sleep_for(std::chrono::milliseconds(2));
                                   }
                                   handlerDone.store(true, std::memory_order_release);
                                 });
  REQUIRE(id != 0);
  entered.get_future().wait(); // handler is now executing

  DrainWorker dw;
  dw.start(*timer, 0);
  DrainWorkerGuard guard{dw, timer};

  // Must NOT return while the callback is blocked.
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  REQUIRE(dw.returnedNow() == false);
  REQUIRE(handlerDone.load() == false);

  release.store(true, std::memory_order_release);
  REQUIRE(dw.waitReturned(std::chrono::seconds(2)) == true);
  REQUIRE(dw.result().success == true);
  REQUIRE(handlerDone.load() == true);
}

// (2b) NON-VACUOUS requirement (b), PERIODIC mid-execution: drain(0) must wait
// for an executing periodic callback AND, after returning, the re-armed record
// must have been cancelled (no further fires).
TEST_CASE("TimerService drain(0): waits for an in-flight periodic and stops further fires",
          "[timer][lifecycle][drain][inflight][periodic][zero]")
{
  auto timer = std::make_unique<TimerService>();
  std::promise<void> entered;
  std::atomic<bool> release{false};
  std::atomic<int> fires{0};

  auto id = timer->schedulePeriodic(std::chrono::milliseconds(20),
                                    [&]()
                                    {
                                      int n = fires.fetch_add(1) + 1;
                                      if (n == 1)
                                      {
                                        entered.set_value();
                                        while (!release.load(std::memory_order_acquire))
                                        {
                                          std::this_thread::sleep_for(std::chrono::milliseconds(2));
                                        }
                                      }
                                    });
  REQUIRE(id != 0);
  entered.get_future().wait(); // periodic handler mid-execution on first fire

  DrainWorker dw;
  dw.start(*timer, 0);
  DrainWorkerGuard guard{dw, timer};

  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  REQUIRE(dw.returnedNow() == false);

  release.store(true, std::memory_order_release);
  REQUIRE(dw.waitReturned(std::chrono::seconds(2)) == true);
  REQUIRE(dw.result().success == true);

  int firesAtReturn = fires.load();
  std::this_thread::sleep_for(std::chrono::milliseconds(100)); // > several intervals
  REQUIRE(fires.load() == firesAtReturn);                      // no fire after drain
}

// (3) Pending one-shot fires naturally under drain(0) and is NOT cancelled.
TEST_CASE("TimerService drain(0): pending one-shot fires naturally, not cancelled",
          "[timer][lifecycle][drain][oneshot][zero]")
{
  auto timer = std::make_unique<TimerService>();
  std::atomic<bool> fired{false};
  auto id = timer->scheduleAfter(std::chrono::milliseconds(200),
                                 [&fired]() { fired.store(true, std::memory_order_release); });
  REQUIRE(id != 0);

  auto bd = runBoundedDrain(*timer, 0, std::chrono::seconds(2));
  requireDrainedOrLeak(bd, timer, "drain(0) hung with a pending one-shot");
  REQUIRE(bd.result.success == true);
  REQUIRE(fired.load() == true); // fired naturally
  REQUIRE(bd.result.drainStats.has_value());
  REQUIRE(bd.result.drainStats->cancelled == 0); // nothing cancelled
}

// (4) RACE: drain(0) concurrent with a rapidly-firing periodic (cancel sweep
// vs re-arm). Primarily a TSan target; bounded so a hang FAILS here too.
TEST_CASE("TimerService drain(0): concurrent with a firing periodic (race)",
          "[timer][lifecycle][drain][periodic][race][zero]")
{
  auto timer = std::make_unique<TimerService>();
  std::atomic<int> fires{0};
  auto id = timer->schedulePeriodic(std::chrono::milliseconds(5), [&fires]() { fires.fetch_add(1); });
  REQUIRE(id != 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(30)); // fire a few times first

  auto bd = runBoundedDrain(*timer, 0, std::chrono::seconds(2));
  requireDrainedOrLeak(bd, timer, "drain(0) hung racing a firing periodic");
  REQUIRE(bd.result.success == true);
  REQUIRE(bd.result.drainStats.has_value());
  REQUIRE(bd.result.drainStats->remaining == 0);
}

// (5) MIXED + fire-count discriminator: a predicate-only "drainable" fix would
// return fast but leave the periodic FIRING; assert the fire-count is constant
// after drain returns (proves real cancellation), the one-shot still fired, and
// the naturally-completing one-shot is counted in `completed`.
TEST_CASE("TimerService drain(0): mixed periodic + one-shot, periodic truly stops",
          "[timer][lifecycle][drain][mixed][zero]")
{
  auto timer = std::make_unique<TimerService>();
  std::atomic<int> pfires{0};
  std::atomic<bool> oneShotFired{false};
  auto pid = timer->schedulePeriodic(std::chrono::milliseconds(20), [&pfires]() { pfires.fetch_add(1); });
  auto oid = timer->scheduleAfter(std::chrono::milliseconds(50),
                                  [&oneShotFired]() { oneShotFired.store(true, std::memory_order_release); });
  REQUIRE(pid != 0);
  REQUIRE(oid != 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(20));

  auto bd = runBoundedDrain(*timer, 0, std::chrono::seconds(2));
  requireDrainedOrLeak(bd, timer, "drain(0) hung with mixed periodic + one-shot");
  REQUIRE(bd.result.success == true);
  REQUIRE(bd.result.drainStats.has_value());
  REQUIRE(bd.result.drainStats->cancelled == 1); // the periodic
  REQUIRE(bd.result.drainStats->completed >= 1); // the naturally-fired one-shot

  int atReturn = pfires.load();
  REQUIRE(oneShotFired.load() == true); // one-shot fired naturally

  std::this_thread::sleep_for(std::chrono::milliseconds(200)); // several intervals
  REQUIRE(pfires.load() == atReturn);                          // periodic really stopped
}

// (6) stop() REGRESSION: stop() auto-drains with a 5000ms budget (timeoutMs>0
// path). Confirm the fix did not disturb it — periodic cancelled, clean stop.
TEST_CASE("TimerService stop(): cancels an active periodic (timeoutMs>0 path regression)",
          "[timer][lifecycle][stop][periodic]")
{
  TimerService timer;
  std::atomic<int> fires{0};
  auto id = timer.schedulePeriodic(std::chrono::milliseconds(20), [&fires]() { fires.fetch_add(1); });
  REQUIRE(id != 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(30));

  auto result = timer.stop();
  REQUIRE(result.success == true);
  REQUIRE(result.newState == LifecycleState::Stopped);

  int atStop = fires.load();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(fires.load() == atStop); // no further fires
}

// (7) DrainStats accuracy for a cancelled periodic: remaining 0, cancelled 1,
// completed 0 (non-negative), and timersCanceled increments exactly once.
TEST_CASE("TimerService drain(0): DrainStats accounting for a cancelled periodic",
          "[timer][lifecycle][drain][stats][periodic][zero]")
{
  auto timer = std::make_unique<TimerService>();
  auto canceledBefore = timer->getStats().timersCanceled.load();
  auto id = timer->schedulePeriodic(std::chrono::seconds(30), []() {});
  REQUIRE(id != 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(20));

  auto bd = runBoundedDrain(*timer, 0, std::chrono::seconds(2));
  requireDrainedOrLeak(bd, timer, "drain(0) hung (stats case)");
  REQUIRE(bd.result.success == true);
  REQUIRE(bd.result.drainStats.has_value());
  auto &s = bd.result.drainStats.value();
  REQUIRE(s.remaining == 0);
  REQUIRE(s.cancelled == 1);
  REQUIRE(s.completed == 0);
  REQUIRE(timer->getStats().timersCanceled.load() == canceledBefore + 1);
}

// (8) drain(0) then stop() from the resulting Draining state terminates cleanly
// (stop()'s Running-only auto-drain is skipped from Draining).
TEST_CASE("TimerService drain(0) then stop() from Draining terminates cleanly",
          "[timer][lifecycle][drain][stop][zero]")
{
  auto timer = std::make_unique<TimerService>();
  auto id = timer->schedulePeriodic(std::chrono::seconds(30), []() {});
  REQUIRE(id != 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(20));

  auto bd = runBoundedDrain(*timer, 0, std::chrono::seconds(2));
  requireDrainedOrLeak(bd, timer, "drain(0) hung (drain-then-stop case)");
  REQUIRE(bd.result.success == true);
  REQUIRE(bd.result.newState == LifecycleState::Draining);

  auto sres = timer->stop();
  REQUIRE(sres.success == true);
  REQUIRE(sres.newState == LifecycleState::Stopped);
}

// (9) H-1 regression: a concurrent stop() while drain(0) is BLOCKED on a
// pending (not-yet-due) one-shot must not hang the drain(0) caller. Under the
// unfixed drainDone (no !_running escape) drain(0) waits forever because the
// run-loop shutdown fires only DUE timers, so `remaining` never reaches 0.
TEST_CASE("TimerService drain(0): concurrent stop() unblocks a drain waiting on a pending one-shot",
          "[timer][lifecycle][drain][stop][shutdown][zero]")
{
  auto timer = std::make_unique<TimerService>();
  std::atomic<bool> fired{false};
  auto id = timer->scheduleAfter(std::chrono::milliseconds(300),
                                 [&fired]() { fired.store(true, std::memory_order_release); });
  REQUIRE(id != 0);

  DrainWorker dw;
  dw.start(*timer, 0);        // blocks on the pending one-shot (remaining == 1)
  DrainWorkerGuard guard{dw, timer};

  std::this_thread::sleep_for(std::chrono::milliseconds(50)); // let drain(0) park in the wait
  REQUIRE(dw.returnedNow() == false);

  auto sres = timer->stop();  // concurrent stop() must wake the blocked drain(0)

  // FAILS (hangs -> bounded wait trips) under the unfixed code.
  REQUIRE(dw.waitReturned(std::chrono::seconds(2)) == true);
  REQUIRE(sres.success == true);
  // drain(0) was truncated by shutdown, not completed -> success == false.
  REQUIRE(dw.result().success == false);

  // M-1 guard: the service must be genuinely Stopped and refuse new timers.
  // Before this fix, a drain-timeout restore left _accepting==true,
  // so a Stopped service still accepted schedules onto a dead run loop.
  REQUIRE(timer->getState() == LifecycleState::Stopped);
  REQUIRE(timer->schedulePeriodic(std::chrono::seconds(1), []() {}) == 0);
  REQUIRE(timer->scheduleAfter(std::chrono::milliseconds(10), []() {}) == 0);
}

// (10) F-1 regression: timeoutMs>0 drain now cancels an active periodic
// SYMMETRICALLY with drain(0) — the near-term periodic must NOT fire one last
// time during the drain window, and it is counted as `cancelled`, not
// `completed`. (Human-approved relaxation of the original "must not alter the
// timeoutMs>0 path" requirement — see tracker decision_record.round2.F1.)
TEST_CASE("TimerService drain(N): cancels an active periodic without a final fire",
          "[timer][lifecycle][drain][periodic][timeout]")
{
  TimerService timer;
  std::atomic<int> fires{0};
  auto id = timer.schedulePeriodic(std::chrono::milliseconds(20), [&fires]() { fires.fetch_add(1); });
  REQUIRE(id != 0);
  // Let it arm but not necessarily fire; its next fire is within the drain
  // window (20ms << 1000ms), i.e. the near-term case the old code let fire.
  std::this_thread::sleep_for(std::chrono::milliseconds(5));

  auto result = timer.drain(1000);
  REQUIRE(result.success == true);
  REQUIRE(result.drainStats.has_value());
  REQUIRE(result.drainStats->remaining == 0);
  REQUIRE(result.drainStats->cancelled == 1); // counted cancelled, not completed
  REQUIRE(result.drainStats->completed == 0);

  int atReturn = fires.load();
  std::this_thread::sleep_for(std::chrono::milliseconds(150)); // several intervals
  REQUIRE(fires.load() == atReturn); // no fire after drain (cancelled, not fired)
}

// (11) M-1 (genuine-timeout variant) regression: when stop()'s internal
// drain(5000) TIMES OUT on a handler slower than its budget, drain's
// timeout-restore re-opens _accepting; stop() must still finalize Stopped with
// _accepting==false, so a Stopped service refuses new timers. Before the fix
// (stop() forcing _accepting=false at the terminal transition) this left
// Stopped + _accepting==true, silently accepting timers onto a dead run loop.
// NOTE: intentionally slow (~5s) — the restore path is only reachable when
// stop()'s hardcoded 5000ms drain budget is exceeded by an in-flight handler.
TEST_CASE("TimerService stop(): Stopped implies not-accepting even when the stop-drain times out",
          "[timer][lifecycle][stop][slow]")
{
  TimerService timer;
  std::atomic<bool> handlerRan{false};
  // Fires ~immediately, then blocks past stop()'s 5000ms drain budget so
  // stop()'s internal drain times out and takes the restore path.
  auto id = timer.scheduleAfter(std::chrono::milliseconds(10),
                                [&handlerRan]()
                                {
                                  std::this_thread::sleep_for(std::chrono::milliseconds(5200));
                                  handlerRan.store(true, std::memory_order_release);
                                });
  REQUIRE(id != 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(30)); // ensure it is in-flight

  auto result = timer.stop(); // internal drain(5000) times out on the slow handler
  REQUIRE(result.success == true);
  REQUIRE(result.newState == LifecycleState::Stopped);
  REQUIRE(handlerRan.load() == true); // stop() joined the run loop (handler finished)

  // The terminal invariant: Stopped => not accepting. A regression that leaves
  // _accepting==true would let these schedules succeed onto a dead run loop.
  REQUIRE(timer.getState() == LifecycleState::Stopped);
  REQUIRE(timer.scheduleAfter(std::chrono::milliseconds(10), []() {}) == 0);
  REQUIRE(timer.schedulePeriodic(std::chrono::seconds(1), []() {}) == 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// Null-logger safety (tracker 2026-09-10-5): the 2-arg TimerService ctor,
// TimerService::setLogger, and the 3-arg TimerServicePool ctor must not crash
// when handed a null shared_ptr<TimerLogger>; every downstream logger use
// (loggerSnapshot() readers, handleError()'s direct copy, the pool's direct
// _logger->, and the run-loop-thread lambda) must be null-safe by construction
// via the substituted silent ConsoleTimerLogger. Under the UNFIXED code every
// case below is a null-deref / crash.
// ═══════════════════════════════════════════════════════════════════════════
namespace
{
/// Capture everything written to stdout (where ConsoleTimerLogger prints via
/// std::printf + fflush) while `fn` runs, by redirecting fd 1 to a temp file.
/// Used to prove — non-vacuously, with a positive control — that the null
/// substitute is a *silent* (disabled) logger.
///
/// The restore/close/unlink runs from an RAII guard so that if `fn()` throws
/// (e.g. a REQUIRE inside the redirected region fails) the stack can unwind
/// without leaking fds or leaving fd 1 pointed at the deleted temp file — which
/// would otherwise silently swallow all later test output, including the Catch2
/// failure message itself.
template <typename Fn> std::string captureStdout(Fn &&fn)
{
  std::fflush(stdout);
  int saved = ::dup(::fileno(stdout));
  char tmpl[] = "/tmp/timer_null_logger_cap_XXXXXX";
  int fd = ::mkstemp(tmpl);
  REQUIRE(saved >= 0);
  REQUIRE(fd >= 0);

  struct Guard
  {
    int saved;
    int fd;
    const char *path;
    bool done{false};
    void cleanup()
    {
      if (done)
      {
        return;
      }
      done = true;
      std::fflush(stdout);
      ::dup2(saved, ::fileno(stdout)); // restore fd 1 first, always
      ::close(saved);
      ::close(fd);
      ::unlink(path);
    }
    ~Guard() { cleanup(); }
  } guard{saved, fd, tmpl};

  ::dup2(fd, ::fileno(stdout));
  std::forward<Fn>(fn)();

  // Read back the captured bytes while fd is still open, then restore + clean.
  std::fflush(stdout);
  ::lseek(fd, 0, SEEK_SET);
  std::string out;
  char buf[4096];
  ssize_t n;
  while ((n = ::read(fd, buf, sizeof(buf))) > 0)
  {
    out.append(buf, static_cast<std::size_t>(n));
  }
  guard.cleanup();
  return out;
}
} // namespace

// (a) 2-arg TimerService ctor with a null logger: construct, fire a one-shot,
// stop, destruct — no crash.
TEST_CASE("TimerService null logger: 2-arg ctor survives construct/fire/stop",
          "[timer][lifecycle][logger][null]")
{
  TimerService timer(TimerServiceConfig{}, std::shared_ptr<TimerLogger>{});
  std::atomic<bool> fired{false};
  auto id = timer.scheduleAfter(std::chrono::milliseconds(20),
                                [&fired]() { fired.store(true, std::memory_order_release); });
  REQUIRE(id != 0);
  REQUIRE(iora::test::waitFor([&]() { return fired.load(std::memory_order_acquire); },
                            std::chrono::milliseconds(1000)));
  auto r = timer.stop();
  REQUIRE(r.success == true);
}

// (b) setLogger(nullptr) is a CROSS-THREAD regression: it must not re-break the
// never-null invariant relied on by the run-loop thread. The cross-thread
// property comes EXCLUSIVELY from the run-loop thread's "Timer service loop
// finished" loggerSnapshot()->info() read during stop() (timer.hpp) — that read
// happens strictly after setLogger(nullptr), so under the unfixed code the
// run-loop thread would deref null. (enableDetailedLogging only adds extra
// _logger reads on the CALLER thread at schedule/cancel, not on the run-loop
// thread; do not rely on it for the cross-thread property — keep the stop().)
// Run on the TSan target to prove the cross-thread path, not single-thread.
TEST_CASE("TimerService null logger: setLogger(nullptr) is cross-thread safe",
          "[timer][lifecycle][logger][null][setlogger]")
{
  TimerServiceConfig cfg;
  cfg.enableDetailedLogging = true; // extra (caller-thread) _logger reads; not the cross-thread edge
  TimerService timer(cfg);          // starts with a valid default logger
  timer.setLogger(std::shared_ptr<TimerLogger>{}); // install null -> normalized to substitute

  std::atomic<bool> fired{false};
  auto id = timer.scheduleAfter(std::chrono::milliseconds(20),
                                [&fired]() { fired.store(true, std::memory_order_release); });
  REQUIRE(id != 0);
  REQUIRE(iora::test::waitFor([&]() { return fired.load(std::memory_order_acquire); },
                            std::chrono::milliseconds(1000)));
  // stop() forces the run-loop thread's "loop finished" loggerSnapshot()->info()
  // read strictly after setLogger(nullptr).
  auto r = timer.stop();
  REQUIRE(r.success == true);
}

// (c) handleError() reads _logger DIRECTLY (not via loggerSnapshot); force it
// under a null logger via ServiceStopped (schedule after stop) and
// InvalidTimeout (schedule beyond maxTimeout) — both must be null-safe.
TEST_CASE("TimerService null logger: handleError paths are null-safe",
          "[timer][lifecycle][logger][null][error]")
{
  TimerService timer(TimerServiceConfig{}, std::shared_ptr<TimerLogger>{});

  // InvalidTimeout -> handleError -> logger->error(...)
  auto tooFar = TimerService::Clock::now() + std::chrono::hours(48); // > 24h maxTimeout
  REQUIRE(timer.scheduleAt(tooFar, []() {}) == 0);

  // ServiceStopped -> handleError -> logger->error(...)
  auto r = timer.stop();
  REQUIRE(r.success == true);
  REQUIRE(timer.scheduleAfter(std::chrono::milliseconds(10), []() {}) == 0);
}

// (d) periodic fire under a null logger, then cancel and stop — no crash.
TEST_CASE("TimerService null logger: periodic fire/cancel/stop is null-safe",
          "[timer][lifecycle][logger][null][periodic]")
{
  TimerService timer(TimerServiceConfig{}, std::shared_ptr<TimerLogger>{});
  std::atomic<int> fires{0};
  auto id = timer.schedulePeriodic(std::chrono::milliseconds(20),
                                   [&fires]() { fires.fetch_add(1, std::memory_order_release); });
  REQUIRE(id != 0);
  auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
  while (fires.load(std::memory_order_acquire) < 1 &&
         std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  REQUIRE(fires.load(std::memory_order_acquire) >= 1);
  REQUIRE(timer.cancel(id) == true);
  auto r = timer.stop();
  REQUIRE(r.success == true);
}

// (e)/(f) direct drain()/stop() and resetStats() under a null logger — these
// exercise the many loggerSnapshot()->info() sites in drain()/stop()/resetStats.
TEST_CASE("TimerService null logger: drain/stop/resetStats are null-safe",
          "[timer][lifecycle][logger][null][drain]")
{
  TimerService timer(TimerServiceConfig{}, std::shared_ptr<TimerLogger>{});
  timer.resetStats(); // loggerSnapshot()->info("Timer statistics reset")
  auto d = timer.drain(200);
  REQUIRE(d.success == true);
  auto r = timer.stop();
  REQUIRE(r.success == true);
}

// (g) 3-arg TimerServicePool ctor with a null logger: the substitute must reach
// each CHILD TimerService (not just the pool's own _logger). Schedule on a child
// and fire it; then stop + destruct.
TEST_CASE("TimerServicePool null logger: children get a non-null substitute",
          "[timer][lifecycle][logger][null][pool]")
{
  TimerServicePool pool(2, TimerServiceConfig{}, std::shared_ptr<TimerLogger>{});
  REQUIRE(pool.size() == 2);
  std::atomic<bool> fired{false};
  auto &svc = pool.getService();
  auto id = svc.scheduleAfter(std::chrono::milliseconds(20),
                              [&fired]() { fired.store(true, std::memory_order_release); });
  REQUIRE(id != 0);
  REQUIRE(iora::test::waitFor([&]() { return fired.load(std::memory_order_acquire); },
                            std::chrono::milliseconds(1000)));
  pool.stop(); // _logger->info(...) at both ends — null-safe via substitute
}

// (h) POSITIVE-CONTROL + silence pairing: prove the substitute is a *silent*
// (disabled) logger, non-vacuously. First an explicitly ENABLED ConsoleTimerLogger
// must produce captured output (proves the stdout-capture harness works); then
// the null-substitute variant must produce NONE.
TEST_CASE("TimerService null logger: substitute is silent (with positive control)",
          "[timer][lifecycle][logger][null][silent]")
{
  // Positive control: an enabled logger DOES emit (validates the capture harness).
  std::string enabledOut = captureStdout(
    []()
    {
      auto enabled = std::make_shared<ConsoleTimerLogger>(TimerLogger::Level::Info, true);
      TimerService timer(TimerServiceConfig{}, enabled); // logs "started successfully"
      auto r = timer.stop();
      REQUIRE(r.success == true);
    });
  REQUIRE(enabledOut.find("Timer service started successfully") != std::string::npos);

  // Null substitute: MUST be silent (default ConsoleTimerLogger is disabled).
  std::string nullOut = captureStdout(
    []()
    {
      TimerService timer(TimerServiceConfig{}, std::shared_ptr<TimerLogger>{});
      std::atomic<bool> fired{false};
      timer.scheduleAfter(std::chrono::milliseconds(10),
                          [&fired]() { fired.store(true, std::memory_order_release); });
      (void)iora::test::waitFor([&]() { return fired.load(std::memory_order_acquire); },
                            std::chrono::milliseconds(1000));
      auto r = timer.stop();
      REQUIRE(r.success == true);
    });
  REQUIRE(nullOut.empty());
}
