// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Regression tests for Logger::init() vs teardown race paths (tracker 2026-07-23-2,
// reshaped for mechanism B by tracker 2026-07-23-1). Iteration 5 of tracker
// 2026-07-21-3 added production paths to init() and the worker-lifecycle protocol
// that were asserted only by code inspection. This suite exercises the ones that
// remain reachable via the public API under mechanism B, with bounded rendezvous so
// a regression FAILS (a bounded flag reads false) rather than wedging the suite.
//
// BOUNDED: every wait is strictly shorter than the production stall backstop
// (kStallReportInterval, 5s), so a hang manifests as a bounded FAILED CHECK, never a
// clock-luck pass rescued by the backstop. Handler bodies capture shared_ptr state
// BY VALUE so a wedged/detached path cannot dereference a destroyed stack object.

#define CATCH_CONFIG_MAIN
#include "logger_race_harness.hpp" // shared FlagPtr/CounterPtr + makeFlag/makeCounter
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/core/logger.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>

using iora::core::Logger;
using iora::test::makeCounter;
using iora::test::makeFlag;
using iora::test::waitFor;
using namespace std::chrono_literals;

namespace
{
// Bounded below the 5s production stall backstop so a hang FAILS instead of passing
// by clock luck when the backstop fires.
constexpr auto kBoundedWait = std::chrono::milliseconds(2500);
constexpr int kLoopIters = 100;

// Bounded spin on a seam handshake flag (acquire, so companion state published
// before the release is visible). Returns false on timeout so a regression FAILS.
bool spinFlag(std::atomic<bool> &flag,
              std::chrono::milliseconds timeout = std::chrono::milliseconds(2000))
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (flag.load(std::memory_order_acquire))
    {
      return true;
    }
    std::this_thread::sleep_for(1ms);
  }
  return false;
}
} // namespace

// ── (n2) init() ON THE WORKER THREAD during a pending teardown. A handler running
//    on the worker calls Logger::shutdown() (worker-self teardown: drains its own
//    frame, sets `exit`, detaches self) and then Logger::init() — still on the
//    worker thread, with `exit` set and `workerRunning` still true. init() MUST
//    take the worker-self branch: emit a diagnostic and RETURN WITHOUT clearing
//    `exit` (clearing it would cancel the stop and the worker would never break) and
//    WITHOUT waiting (it cannot wait for itself to exit). The handler then completes
//    and the worker publishes its exit.
//    MUTATION: delete init()'s worker-self early-return -> init() falls through to
//    waitForWorkerExitLocked and waits for the worker (itself) to exit -> the handler
//    never returns -> handlerCompleted stays false (bounded FAIL / self-wait hang).
TEST_CASE("(n2) init() on the worker thread during a pending teardown yields, no self-wait",
          "[logger][init_teardown][n2]")
{
  for (int i = 0; i < kLoopIters; ++i)
  {
    Logger::init(Logger::Level::Info, "", /*async=*/true);
    auto ran = makeFlag();               // only the first invocation drives the race
    auto handlerCompleted = makeFlag();  // set ONLY if init() returned on the worker

    Logger::setExternalHandler(
      [ran, handlerCompleted](Logger::Level, const std::string &, const std::string &)
      {
        if (!ran->exchange(true))
        {
          // On the worker thread: stop ourselves (sets exit, detaches self), then
          // re-init from the same worker frame — must yield to the pending stop.
          Logger::shutdown();
          Logger::init(Logger::Level::Info, "", /*async=*/true);
          handlerCompleted->store(true); // reached only if init() did NOT self-wait
        }
      });

    Logger::info("trigger"); // async: worker delivers -> handler runs shutdown()+init()
    const bool completed =
      waitFor([handlerCompleted] { return handlerCompleted->load(); }, kBoundedWait);
    CHECK(completed); // false => init() self-waited on the worker (regression)
    if (!completed)
    {
      break; // worker may be wedged; do not teardown (would hang) — FAIL recorded
    }

    // The worker-self teardown left the logger stopped; a fresh depth-0 init must
    // produce a working async logger again (a stale workerRunning would leave async
    // mode with no drainer).
    Logger::init(Logger::Level::Info, "", /*async=*/true);
    auto delivered = makeCounter();
    Logger::setExternalHandler([delivered](Logger::Level, const std::string &,
                                           const std::string &) { delivered->fetch_add(1); });
    Logger::info("after"); // NO flush(): only a worker delivery discriminates a live worker
    const bool workerAlive =
      waitFor([delivered] { return delivered->load() >= 1; }, kBoundedWait);
    CHECK(workerAlive);
    Logger::clearExternalHandler();
    Logger::shutdown();
    if (!workerAlive)
    {
      break;
    }
  }
}

// ── (n1) init() AT DEPTH>0 ON A NON-WORKER THREAD during a pending teardown must be
//    NON-WAITING (mechanism B, tracker 2026-07-23-1 F1). This state — exit set,
//    workerRunning true, a non-worker thread inside a handler frame — is UNREACHABLE
//    via the public API (setting exit nulls the gate and drains every in-flight
//    handler first), so init()'s depth>0-non-worker branch is a DEFENSIVE guard that
//    keeps the "≤ 1 depth>0 teardown parker" invariant. It is exercised here through
//    the compile-gated seams: a real worker is parked with exit set + workerRunning
//    still true, and a depth>0 init() is raced against it on a separate thread.
//    MUTATION: delete init()'s depth>0-non-worker early return -> init() falls to
//    waitForWorkerExitLocked and waits on the still-parked worker -> initReturned
//    stays false (bounded FAIL).
TEST_CASE("(n1) init() at depth>0 on a non-worker thread during a teardown is non-waiting",
          "[logger][init_teardown][n1]")
{
  auto &hooks = Logger::testHooks();
  hooks.reset();
  Logger::init(Logger::Level::Info, "", /*async=*/true); // spawns the worker

  hooks.pauseWorkerBeforeExitPublish.store(true, std::memory_order_relaxed);

  // Teardown on thread T: sets exit, notifies the worker, blocks in join() while the
  // worker parks at the seam (exit set, workerRunning still true).
  auto shutdownReturned = makeFlag();
  std::thread teardownThread([shutdownReturned] { Logger::shutdown(); shutdownReturned->store(true); });

  const bool parked = spinFlag(hooks.workerParkedBeforeExit);
  CHECK(parked);
  if (!parked)
  {
    hooks.workerExitProceed.store(true, std::memory_order_release);
    teardownThread.join();
    hooks.reset();
    return;
  }

  // Race a depth>0 init() on a NON-worker thread against the parked-but-alive worker.
  auto initReturned = makeFlag();
  std::thread initThread(
    [initReturned]
    {
      Logger::testInvokeAtHandlerDepth(
        [] { Logger::init(Logger::Level::Info, "", /*async=*/true); });
      initReturned->store(true);
    });

  const bool returnedBounded = spinFlag(*initReturned, std::chrono::milliseconds(2500));
  CHECK(returnedBounded); // false => init() waited (regression: depth>0 branch removed)

  // Release the worker so the teardown (and, if it waited, the init) can unwind.
  hooks.workerExitProceed.store(true, std::memory_order_release);
  const bool initJoined = spinFlag(*initReturned, std::chrono::milliseconds(2500));
  const bool teardownDone = spinFlag(*shutdownReturned, std::chrono::milliseconds(2500));
  CHECK(teardownDone);
  if (initJoined)
  {
    initThread.join();
  }
  else
  {
    initThread.detach();
  }
  if (teardownDone)
  {
    teardownThread.join();
  }
  else
  {
    teardownThread.detach();
  }
  hooks.reset();
  Logger::shutdown(); // idempotent cleanup (a mutated init() may have re-spawned)
}

// ── (n3) WORKER-GENERATION STAMPING: a teardown that has joined its worker must not
//    be stranded by a racing init() that spawns a NEW worker. The post-join wait is
//    keyed on the STOPPED worker's generation, so a newer worker (different
//    generation) satisfies it immediately. The seam parks the teardown after the
//    join, the test spawns a new worker, then releases the teardown.
//    MUTATION: revert the post-join predicate to the bare `!workerRunning` -> it
//    sees the NEW worker running and waits for one it never asked to stop -> hang.
TEST_CASE("(n3) teardown post-join wait returns when a racing init() spawned a new worker",
          "[logger][init_teardown][n3]")
{
  auto &hooks = Logger::testHooks();
  hooks.reset();
  Logger::init(Logger::Level::Info, "", /*async=*/true); // worker generation G

  hooks.pauseTeardownAfterJoin.store(true, std::memory_order_relaxed);

  auto teardownReturned = makeFlag();
  std::thread teardownThread([teardownReturned] { Logger::shutdown(); teardownReturned->store(true); });

  const bool atPostJoin = spinFlag(hooks.teardownAtPostJoin);
  CHECK(atPostJoin);
  if (!atPostJoin)
  {
    hooks.teardownPostJoinProceed.store(true, std::memory_order_release);
    teardownThread.join();
    hooks.reset();
    return;
  }

  // Old worker is joined (workerRunning false, generation still G). Spawn a NEW
  // worker (generation G+1, workerRunning true) BEFORE releasing the teardown.
  Logger::init(Logger::Level::Info, "", /*async=*/true);

  hooks.teardownPostJoinProceed.store(true, std::memory_order_release);
  const bool returnedBounded = spinFlag(*teardownReturned, std::chrono::milliseconds(2500));
  CHECK(returnedBounded); // false => the post-join wait blocked on the NEW worker (regression)
  if (returnedBounded)
  {
    teardownThread.join();
  }
  else
  {
    teardownThread.detach();
  }
  hooks.reset();
  Logger::shutdown(); // stop the newly spawned worker
}
