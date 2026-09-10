// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for ThreadPool ILifecycleManaged interface implementation

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>
#include <iora/common/i_lifecycle_managed.hpp>
#include <iora/core/thread_pool.hpp>
#include <chrono>
#include <future>
#include <memory>
#include <thread>

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
  std::atomic<int> ran{0};  // independent count of task bodies that actually executed

  // Enqueue 5 tasks that block until released.
  for (int i = 0; i < 5; ++i)
  {
    pool.enqueue([&]()
                 {
                   while (!tasksCanFinish.load())
                   {
                     std::this_thread::sleep_for(std::chrono::milliseconds(1));
                   }
                   ran.fetch_add(1);
                 });
  }

  // Hold all 5 in-flight (executing + queued) so inFlightAtStart is pinned at 5.
  REQUIRE(iora::test::waitFor([&]() { return pool.getInFlightCount() == 5; },
                              std::chrono::seconds(2)));

  // Release the tasks only AFTER drain() has transitioned to Draining (and so has
  // already captured inFlightAtStart). The causal chain (observe Draining -> set
  // flag -> worker polls -> worker finishes) is milliseconds; inFlightAtStart is
  // captured nanoseconds after the Draining store, so it is deterministically 5.
  std::thread releaser(
    [&]()
    {
      if (iora::test::waitFor([&]() { return pool.getState() == LifecycleState::Draining; },
                              std::chrono::seconds(2)))
      {
        tasksCanFinish.store(true);
      }
    });
  struct Joiner { std::thread &t; ~Joiner() { if (t.joinable()) t.join(); } } joiner{releaser};

  auto result = pool.drain(5000);

  REQUIRE(result.success == true);
  REQUIRE(result.drainStats.has_value());

  auto &stats = result.drainStats.value();
  INFO("inFlightAtStart: " << stats.inFlightAtStart);
  INFO("completed: " << stats.completed);
  INFO("remaining: " << stats.remaining);

  // NON-VACUOUS: completed == inFlightAtStart is tautological on the success path
  // (completed := inFlightAtStart - remaining, remaining == 0). Pin inFlightAtStart
  // to the known count and cross-check against the independent execution counter so
  // the derived stat is tied to real task executions.
  REQUIRE(stats.remaining == 0);
  REQUIRE(stats.inFlightAtStart == 5);
  REQUIRE(stats.completed == 5);
  REQUIRE(stats.completed == stats.inFlightAtStart);
  REQUIRE(ran.load() == 5);
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Zero-worker guard (hardware_concurrency()==0 -> silent hang)
// Tracker 2026-09-06-10. The DISCRIMINATING case is (initialSize==0, maxSize==0):
// a (0, N>0) pool self-heals on first enqueue (lazy-spawn gate 0<N), so only (0,0)
// reproduces the hang. Waits are BOUNDED so a regression FAILS instead of hanging
// the suite.
// ══════════════════════════════════════════════════════════════════════════

// Submit a value-returning task and require it drains within a BOUNDED wait, so a
// 0-worker regression FAILS the assertion instead of hanging the suite.
static void requireDrainsWithin(ThreadPool &pool, int value)
{
  auto future = pool.enqueueWithResult([value]() { return value; });
  auto status = future.wait_for(std::chrono::seconds(5));
  REQUIRE(status == std::future_status::ready);
  REQUIRE(future.get() == value);
}

TEST_CASE("ThreadPool zero-worker: (0,0) pool has >=1 worker and drains a task",
          "[threadpool][lifecycle][zero-worker]")
{
  ThreadPool pool(0, 0); // clampInitial forces _initialSize=1, _maxSize>=1

  REQUIRE(pool.getTotalThreadCount() >= 1);
  requireDrainsWithin(pool, 42);
}

TEST_CASE("ThreadPool zero-worker: (0,0) pool re-spawns a worker after reset()->start()",
          "[threadpool][lifecycle][zero-worker][restart]")
{
  ThreadPool pool(0, 0);

  // Running -> Draining -> Stopped
  auto stopResult = pool.stop();
  REQUIRE(stopResult.success == true);
  REQUIRE(pool.getState() == LifecycleState::Stopped);

  // Stopped -> Reset
  auto resetResult = pool.reset();
  REQUIRE(resetResult.success == true);
  REQUIRE(pool.getState() == LifecycleState::Reset);

  // Reset -> Running (spawn loop at :497 reads the CONST clamped _initialSize)
  auto startResult = pool.start();
  REQUIRE(startResult.success == true);
  REQUIRE(pool.getState() == LifecycleState::Running);

  // A "clamp a local" fix would leave the restart spawn reading an unclamped 0 here.
  REQUIRE(pool.getTotalThreadCount() >= 1);
  requireDrainsWithin(pool, 7);
}

TEST_CASE("ThreadPool zero-worker: (0,0) pool destructs cleanly within a bound",
          "[threadpool][lifecycle][zero-worker][teardown]")
{
  // Heap-owned promise captured BY VALUE: if the pool hangs and this TEST_CASE
  // unwinds (REQUIRE fails), a detached runner must not write to a destroyed
  // stack promise (UAF). The shared_ptr keeps the shared state alive.
  auto donePromise = std::make_shared<std::promise<void>>();
  auto doneFuture = donePromise->get_future();

  std::thread runner(
    [donePromise]()
    {
      {
        ThreadPool pool(0, 0);
        auto future = pool.enqueueWithResult([]() { return 1; });
        (void)future.wait_for(std::chrono::seconds(5));
      } // ~ThreadPool: Phase-2 barrier + Phase-4 join on the forced worker
      donePromise->set_value();
    });

  // Bounded: if the forced worker leaves the pool unable to tear down, this FAILS
  // rather than hanging the suite (do NOT raise the timeout to pass).
  auto status = doneFuture.wait_for(std::chrono::seconds(10));
  if (status == std::future_status::ready)
  {
    runner.join();
  }
  else
  {
    runner.detach(); // avoid std::terminate on a joinable-thread dtor
  }
  REQUIRE(status == std::future_status::ready);
}

TEST_CASE("ThreadPool zero-worker: (initialSize>maxSize) is functional (maxSize invariant repair)",
          "[threadpool][lifecycle][zero-worker][invariant]")
{
  // _maxSize is repaired to >= clamped _initialSize, so a (2,1) pool is valid.
  ThreadPool pool(2, 1);

  REQUIRE(pool.getTotalThreadCount() >= 1);
  requireDrainsWithin(pool, 5);
}

// ══════════════════════════════════════════════════════════════════════════
// Test: drain-quiescence gate counts a popped-but-not-yet-active task
// (P0 2026-09-09-7). Uses the compiled-in test seam (ThreadPoolT<true>) to park
// a worker in the window between releasing _mutex after the pop and incrementing
// _activeThreads -- the busy-but-not-active state the OLD two-sample predicate
// (_activeThreads + a separate getPendingTaskCount()) misreported as "drained".
// A plain sleep in the task body cannot reproduce this: the body runs only after
// _activeThreads is already incremented. MUTATION TEST: revert getInFlightCount()
// to the _activeThreads-only read and this test FAILS (doneAtDrainReturn==false)
// and, under ASan, reports a heap-use-after-free on the captured object.
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("ThreadPool lifecycle: drain() gate counts a popped-but-not-active task (seam)",
          "[threadpool][lifecycle][drain][seam]")
{
  constexpr int kIterations = 25;
  for (int iter = 0; iter < kIterations; ++iter)
  {
    ThreadPoolT<true> pool(1, 1);  // single deterministic worker

    auto heapObj = std::make_unique<std::atomic<int>>(0);
    std::atomic<int> *raw = heapObj.get();
    std::atomic<bool> done{false};

    pool.testSeamArm();
    pool.enqueue([raw, &done]()
                 {
                   raw->fetch_add(1);  // in-flight read/write of the heap object
                   done.store(true, std::memory_order_release);
                 });

    // Release the parked worker WHILE drain() polls. Bounded so a hang FAILS
    // instead of wedging the suite (do NOT raise the timeout to pass).
    std::thread releaser(
      [&]()
      {
        if (iora::test::waitFor([&]() { return pool.testSeamParked(); }, std::chrono::seconds(5)))
        {
          pool.testSeamRelease();
        }
      });
    struct Joiner { std::thread &t; ~Joiner() { if (t.joinable()) t.join(); } } joiner{releaser};

    auto result = pool.drain(5000);

    // The instant drain() reports success, an accurate quiescence gate guarantees
    // the popped task already ran (done set before --_busyThreads). The broken
    // predicate reports success while the worker is still parked -> done==false.
    bool doneAtDrainReturn = done.load(std::memory_order_acquire);

    REQUIRE(result.success == true);
    REQUIRE(doneAtDrainReturn == true);  // NON-VACUOUS: fails against the unfixed predicate

    // Worker has completed; safe to release the heap object it read in-flight.
    REQUIRE(iora::test::waitFor([&]() { return done.load(); }, std::chrono::seconds(5)));
    heapObj.reset();
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Test: stop() on a drain timeout detaches workers and refuses restart (D2,
// P0 2026-09-09-7). A releasable "stuck" task (NOT an infinite loop) so the
// detached worker can exit before the pool is destroyed -- destroy-while-stuck
// is documented UB. stop() is driven on a worker thread under a bounded wait so a
// real hang FAILS the test instead of wedging the suite.
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("ThreadPool lifecycle: stop() on drain timeout detaches and refuses restart",
          "[threadpool][lifecycle][stop][detached]")
{
  auto release = std::make_shared<std::atomic<bool>>(false);
  auto pool = std::make_unique<ThreadPoolT<true>>(1, 1);  // <true>: exposes testWorkersExited()

  // Occupy the single worker with a releasable stuck task.
  std::atomic<bool> started{false};
  pool->enqueue([release, &started]()
                {
                  started.store(true, std::memory_order_release);
                  while (!release->load(std::memory_order_acquire))
                  {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                  }
                });
  REQUIRE(iora::test::waitFor([&]() { return started.load(); }, std::chrono::seconds(2)));

  // Reach Draining with the task still stuck (drain times out fast).
  auto drainResult = pool->drain(300);
  REQUIRE(drainResult.success == false);
  REQUIRE(pool->getState() == LifecycleState::Draining);

  // Drive stop() on a worker thread under a bounded wait: a real hang FAILS here.
  std::promise<iora::common::LifecycleResult> stopPromise;
  auto stopFuture = stopPromise.get_future();
  std::thread stopper([&]() { stopPromise.set_value(pool->stop()); });
  auto status = stopFuture.wait_for(std::chrono::seconds(5));
  REQUIRE(status == std::future_status::ready);
  stopper.join();

  auto stopResult = stopFuture.get();
  // Forced detach: bounded, no zombie Draining pool, terminal state Stopped.
  REQUIRE(stopResult.success == false);
  REQUIRE(pool->getState() == LifecycleState::Stopped);

  // _detachedTerminal refuses restart in all three directions.
  REQUIRE(pool->reset().success == false);
  REQUIRE(pool->start().success == false);
  REQUIRE(pool->stop().success == false);

  // Release the stuck task and wait (test-observable) for the formerly-detached
  // worker to fully RETURN from its lambda BEFORE destroying the pool -- destroy-
  // while-stuck is documented UB (removed later by follow-on 2026-09-10-8).
  // testWorkersExited() proves the exit (_threadsExited >= _threadsCreated),
  // replacing a fixed sleep that could flake under CI load.
  release->store(true, std::memory_order_release);
  REQUIRE(iora::test::waitFor([&]() { return pool->testWorkersExited(); },
                              std::chrono::seconds(5)));
  pool = nullptr;  // destroy the pool
}

// ══════════════════════════════════════════════════════════════════════════
// Test: concurrent lifecycle transitions are serialized (M-1). Without the
// _lifecycleMutex, threads racing start() from Reset each pass the check-then-act
// on _lifecycleState and every winner spawns _initialSize workers (2x+ over-
// spawn). With the mutex exactly one Reset->Running transition runs, so the pool
// holds exactly _initialSize workers.
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("ThreadPool lifecycle: concurrent start() from Reset does not over-spawn (M-1)",
          "[threadpool][lifecycle][concurrency]")
{
  constexpr std::size_t kInitial = 3;
  constexpr int kThreads = 16;
  constexpr int kRounds = 40;  // many rounds x barrier-aligned threads catch the narrow window

  ThreadPool pool(kInitial, kInitial);

  for (int round = 0; round < kRounds; ++round)
  {
    // Drive to Reset.
    REQUIRE(pool.stop().success == true);
    REQUIRE(pool.reset().success == true);
    REQUIRE(pool.getState() == LifecycleState::Reset);

    // Align all racers on a barrier so they hit the Reset->Running check-then-act
    // window simultaneously (maximizes the interleave a missing _lifecycleMutex
    // would expose). start() is idempotent from Running, so several may report
    // success, but only ONE transition may spawn workers.
    std::atomic<bool> go{false};
    std::atomic<int> ready{0};
    std::vector<std::thread> racers;
    for (int i = 0; i < kThreads; ++i)
    {
      racers.emplace_back(
        [&]()
        {
          ready.fetch_add(1, std::memory_order_release);
          while (!go.load(std::memory_order_acquire))
          {
            std::this_thread::yield();
          }
          (void)pool.start();
        });
    }
    while (ready.load(std::memory_order_acquire) < kThreads)
    {
      std::this_thread::yield();
    }
    go.store(true, std::memory_order_release);  // release all at once
    for (auto &t : racers)
    {
      t.join();
    }

    REQUIRE(pool.getState() == LifecycleState::Running);
    // The discriminator: exactly kInitial workers, not up to kThreads * kInitial.
    REQUIRE(pool.getTotalThreadCount() == kInitial);
  }
}
