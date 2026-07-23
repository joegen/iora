// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Tests for Logger external-handler tear-out synchronization (tracker 2026-05-08-1).
// clearExternalHandler / setExternalHandler must DRAIN any in-flight async handler
// invocation (runWorker + concurrent flush()) before returning, so a handler that
// captures [this]/[obj] cannot have its captured object destroyed mid-invocation
// (use-after-free). Idempotent of the worker-vs-flush count (can exceed 1); a
// self-tearing invocation waits the LIVE predicate inflight==externalHandlerFrozen
// (drains every NON-frozen invocation, not its own pinned frames, and not peers
// equally parked in a tear-out — tracker 2026-07-21-3), while an external (depth-0)
// caller waits a genuine full drain inflight==0; a throwing handler is swallowed on
// the worker (no std::terminate) and rethrown by flush().
//
// FORCED RENDEZVOUS: every race test blocks the handler on a gate and drives the
// tear-out only after the handler has provably entered its window — never a timing
// tight-loop (which could pass without the fix and prove nothing). Catch2 macros
// run ONLY on the main thread; worker/flush threads record into atomics and the
// main thread asserts after join(). Run under TSan (setarch -R) and ASan
// (handle_segv=0) in two separate sanitized builds.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include "logger_race_harness.hpp"
#include <catch2/catch.hpp>

#include <iora/core/logger.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>

using iora::core::Logger;
using iora::test::CaptureTarget;
using iora::test::RaceCtl;
using iora::test::CounterPtr;
using iora::test::CtlPtr;
using iora::test::FlagPtr;
using iora::test::makeCounter;
using iora::test::makeCtl;
using iora::test::makeFlag;
using iora::test::makeTarget;
using iora::test::TargetPtr;
using namespace std::chrono_literals;

namespace
{

// CaptureTarget, RaceCtl and blockingHandlerBody now come from
// logger_race_harness.hpp (shared with iora_test_logger_self_clear_deadlock.cpp).
// blockingHandlerBody does touch/enter/wait-gate/touch/EXIT — callers must NOT
// signal onExit() again (double-counting `exited` silently weakens every
// `exitedCount() >= N` drain discriminator). A case that must record state
// between the gate and the exit inlines the body instead — see T9(b).
//
// LIFETIME (same rule as the sibling deadlock suite): every object a parked
// handler touches is heap-owned and captured BY VALUE, so a test frame unwound by
// a failing assertion cannot leave a handler dereferencing a destroyed stack
// object. Assertions taken while a std::thread is live are CHECK, never REQUIRE —
// a throw would destroy a joinable thread and call std::terminate, erasing the
// very failure being reported.

// The blocking handler used by most cases: park in the window, then signal exit.
Logger::ExternalHandler makeBlockingHandler(CtlPtr c, TargetPtr t)
{
  return [c, t](Logger::Level, const std::string &, const std::string &)
  {
    iora::test::blockingHandlerBody(*c, t.get());
  };
}

} // namespace

// ── T5: no in-flight -> clear returns immediately (no deadlock / bounded) ─────
TEST_CASE("clearExternalHandler with no in-flight returns immediately",
          "[logger_race][bounded]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  Logger::setExternalHandler([](Logger::Level, const std::string &, const std::string &) {});
  auto t0 = std::chrono::steady_clock::now();
  Logger::clearExternalHandler();
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now() - t0)
              .count();
  CHECK(ms < 1000);
  Logger::shutdown();
}

// ── T6: sync mode unchanged (handler invoked under lock; clear works) ─────────
TEST_CASE("sync-mode external handler still works and clears", "[logger_race][sync]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/false);
  auto calls = iora::test::makeCounter();
  Logger::setExternalHandler(
    [calls](Logger::Level, const std::string &, const std::string &) { calls->fetch_add(1); });
  Logger::info("a");
  Logger::info("b");
  CHECK(calls->load() == 2);
  Logger::clearExternalHandler();
  Logger::info("c"); // no handler now
  CHECK(calls->load() == 2);
  Logger::shutdown();
}

// ── T1 + T4 + T7: clear drains an in-flight WORKER invocation; returns only
//    after the handler completed; [obj]-capturing target freed safely after. ──
TEST_CASE("clearExternalHandler drains an in-flight worker invocation (no UAF)",
          "[logger_race][worker]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto target = makeTarget();
  auto ctl = makeCtl();

  Logger::setExternalHandler(makeBlockingHandler(ctl, target));

  Logger::info("trigger"); // worker picks it up and enters the handler window
  REQUIRE(ctl->waitEntered(1));

  auto handlerDoneAtClearReturn = iora::test::makeFlag(); // by-value: may be DETACHED
  std::thread clearThread(
    [handlerDoneAtClearReturn, ctl]
    {
      Logger::clearExternalHandler(); // must block until the handler exits
      handlerDoneAtClearReturn->store(ctl->exitedCount() >= 1);
    });

  std::this_thread::sleep_for(50ms); // clear should still be blocked (handler gated)
  ctl->releaseAll();                 // let the handler finish its post-gate access
  // Bounded: a drain regression must FAIL here, not hang the suite on join().
  const bool drained = ctl->waitExited(1);
  CHECK(drained);
  iora::test::joinOrDetach(drained, {&clearThread});
  if (!drained)
  {
    return;
  }

  // The drain guarantee: clearExternalHandler returned only AFTER the handler
  // completed its post-gate access (without the fix this is false).
  CHECK(handlerDoneAtClearReturn->load());
  CHECK(target->touches.load() == 2);
  CHECK(target->canary.load() == 0x5A5A);

  // The tear-out destroyed the handler and every in-flight copy, so the test now
  // holds the only reference — the captured object is provably free to destroy.
  CHECK(target.use_count() == 1);
  target.reset();
  Logger::shutdown();
}

// ── T2: setExternalHandler REPLACE drains the previous handler's in-flight ────
TEST_CASE("setExternalHandler replace drains the previous in-flight invocation",
          "[logger_race][replace]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto target = makeTarget();
  auto ctl = makeCtl();

  Logger::setExternalHandler(makeBlockingHandler(ctl, target));

  Logger::info("trigger");
  REQUIRE(ctl->waitEntered(1));

  auto handlerDoneAtSetReturn = iora::test::makeFlag();
  std::thread setThread(
    [handlerDoneAtSetReturn, ctl]
    {
      Logger::setExternalHandler(
        [](Logger::Level, const std::string &, const std::string &) {}); // handler B
      handlerDoneAtSetReturn->store(ctl->exitedCount() >= 1);
    });

  std::this_thread::sleep_for(50ms);
  ctl->releaseAll();
  const bool drained = ctl->waitExited(1);
  CHECK(drained);
  iora::test::joinOrDetach(drained, {&setThread});
  if (!drained)
  {
    return;
  }

  CHECK(handlerDoneAtSetReturn->load()); // replace waited for handler A to finish
  CHECK(target.use_count() == 1); // handler A and its in-flight copies are gone
  target.reset();
  Logger::shutdown();
}

// ── T10 (also subsumes tracker T3 "flush() drain concurrent with clear"): a
//    flush() invocation is in-flight (drained by flush(), not the worker) AND a
//    cross-thread clearExternalHandler must wait for it. Worker blocks on entry
//    "1"; a second entry is drained by flush() -> both in-flight (count==2). ──
TEST_CASE("clear waits for BOTH a worker and a concurrent flush invocation (count==2)",
          "[logger_race][concurrent][t3]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto target = makeTarget();
  auto ctl = makeCtl();

  Logger::setExternalHandler(makeBlockingHandler(ctl, target));

  Logger::info("1"); // worker enters handler #1 and blocks
  REQUIRE(ctl->waitEntered(1));

  Logger::info("2");                                       // queued; worker is busy
  std::thread flushThread([] { Logger::flush(); }); // flush drains "2" -> handler #2
  // CHECK + bail while a thread is live: a REQUIRE throw would destroy a joinable
  // std::thread and call std::terminate, erasing the failure report.
  const bool bothIn = ctl->waitEntered(2); // inflight == 2 now
  CHECK(bothIn);
  if (!bothIn)
  {
    ctl->releaseAll();
    flushThread.detach();
    return;
  }

  auto bothDoneAtClearReturn = iora::test::makeFlag();
  std::thread clearThread(
    [bothDoneAtClearReturn, ctl]
    {
      Logger::clearExternalHandler(); // waits inflight == 0
      bothDoneAtClearReturn->store(ctl->exitedCount() >= 2);
    });

  std::this_thread::sleep_for(50ms);
  ctl->releaseAll();
  const bool bothDrained = ctl->waitExited(2);
  CHECK(bothDrained);
  iora::test::joinOrDetach(bothDrained, {&flushThread, &clearThread});
  if (!bothDrained)
  {
    return;
  }

  CHECK(bothDoneAtClearReturn->load());        // clear drained BOTH invocations
  CHECK(target->touches.load() == 4);         // 2 invocations x 2 touches
  CHECK(target.use_count() == 1); // no handler copy survives the tear-out
  target.reset();
  Logger::shutdown();
}

// ── T10 N>2 variant: worker + TWO concurrent flush()es all in-flight (count==3)
TEST_CASE("clear waits for N>2 concurrent invocations (worker + 2 flushes)",
          "[logger_race][concurrent][n3]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto target = makeTarget();
  auto ctl = makeCtl();

  Logger::setExternalHandler(makeBlockingHandler(ctl, target));

  Logger::info("1"); // worker -> handler #1, blocks
  REQUIRE(ctl->waitEntered(1));

  Logger::info("2");
  Logger::info("3");
  std::thread f1([] { Logger::flush(); }); // drains one of "2"/"3"
  std::thread f2([] { Logger::flush(); }); // drains the other
  const bool allIn = ctl->waitEntered(3);  // inflight == 3
  CHECK(allIn);
  if (!allIn)
  {
    ctl->releaseAll();
    f1.detach();
    f2.detach();
    return;
  }

  auto allDoneAtClearReturn = iora::test::makeFlag();
  std::thread clearThread(
    [allDoneAtClearReturn, ctl]
    {
      Logger::clearExternalHandler();
      allDoneAtClearReturn->store(ctl->exitedCount() >= 3);
    });

  std::this_thread::sleep_for(50ms);
  ctl->releaseAll();
  const bool allDrained = ctl->waitExited(3);
  CHECK(allDrained);
  iora::test::joinOrDetach(allDrained, {&f1, &f2, &clearThread});
  if (!allDrained)
  {
    return;
  }

  CHECK(allDoneAtClearReturn->load());
  CHECK(target->touches.load() == 6);
  CHECK(target.use_count() == 1); // no handler copy survives the tear-out
  target.reset();
  Logger::shutdown();
}

// ── T8(a): flush() rethrows a throwing handler AND restores the counter so a
//    later clearExternalHandler is not stranded. The worker is blocked on a
//    first (non-throwing) entry so flush() is deterministically the invoker of
//    the throwing second entry. ─────────────────────────────────────────────
TEST_CASE("flush rethrows a throwing handler and does not strand the drain",
          "[logger_race][throw][flush]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto target = makeTarget();
  auto ctl = makeCtl();

  auto invocationCount = makeCounter();
  Logger::setExternalHandler(
    [target, ctl, invocationCount](Logger::Level, const std::string &, const std::string &)
    {
      if (invocationCount->fetch_add(1) == 0)
      {
        iora::test::blockingHandlerBody(*ctl, target.get()); // worker: occupy and block
      }
      else
      {
        throw std::runtime_error("boom"); // flush invocation: throw
      }
    });

  Logger::info("1"); // worker -> invocation 0, blocks
  REQUIRE(ctl->waitEntered(1));

  Logger::info("2"); // queued; worker busy
  auto flushRethrew = iora::test::makeFlag();
  std::thread flushThread(
    [flushRethrew]
    {
      try
      {
        Logger::flush(); // drains "2" -> invocation 1 throws -> flush rethrows
      }
      catch (const std::runtime_error &)
      {
        flushRethrew->store(true);
      }
    });
  // Bounded: a stranded drain must FAIL here, not hang the suite on join().
  const bool flushReturned = iora::test::waitFor([flushRethrew] { return flushRethrew->load(); });
  CHECK(flushReturned); // flush() propagated the handler exception to its caller
  iora::test::joinOrDetach(flushReturned, {&flushThread});
  if (!flushReturned)
  {
    return;
  }

  // Release the worker, then a clearExternalHandler must NOT hang (the throwing
  // flush invocation restored the in-flight counter before rethrowing).
  ctl->releaseAll();
  auto cleared = iora::test::makeFlag();
  std::thread clearThread(
    [cleared]
    {
      Logger::clearExternalHandler();
      cleared->store(true);
    });
  const bool clearReturned = iora::test::waitFor([cleared] { return cleared->load(); });
  CHECK(clearReturned);
  iora::test::joinOrDetach(clearReturned, {&clearThread});
  if (!clearReturned)
  {
    return;
  }
  CHECK(target.use_count() == 1); // no handler copy survives the tear-out
  target.reset();
  Logger::shutdown();
}

// ── T8(b): a throwing handler on the WORKER thread is swallowed (no terminate);
//    the worker survives and keeps delivering; the counter returns to 0. ───────
TEST_CASE("worker swallows a throwing handler and keeps running", "[logger_race][throw][worker]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);

  auto throwingCalls = iora::test::makeCounter();
  Logger::setExternalHandler(
    [throwingCalls](Logger::Level, const std::string &, const std::string &)
    {
      throwingCalls->fetch_add(1);
      throw std::runtime_error("boom-on-worker");
    });

  Logger::info("first");
  // Give the worker time to drain + throw + swallow.
  const bool threw = iora::test::waitFor([throwingCalls] { return throwingCalls->load() > 0; },
                                         400ms);
  CHECK(threw); // worker invoked it and did NOT terminate
  if (!threw)
  {
    // A wedged worker must not fall through to the unbounded teardown drain below,
    // or a bounded FAIL becomes a hung suite.
    return;
  }

  // The worker survived: install a non-throwing handler and confirm delivery.
  auto okCalls = iora::test::makeCounter();
  Logger::setExternalHandler(
    [okCalls](Logger::Level, const std::string &, const std::string &) { okCalls->fetch_add(1); });
  Logger::info("second");
  const bool delivered = iora::test::waitFor([okCalls] { return okCalls->load() > 0; }, 400ms);
  CHECK(delivered);
  if (!delivered)
  {
    return;
  }
  CHECK(okCalls->load() >= 1);

  Logger::clearExternalHandler(); // must not hang (counter not stranded)
  Logger::shutdown();
  SUCCEED();
}

// ── T9(a): worker self-call with no other in-flight -> no deadlock. ───────────
TEST_CASE("handler self-calling clearExternalHandler does not deadlock (sole in-flight)",
          "[logger_race][selfcall]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto selfClearReturned = iora::test::makeFlag();
  std::atomic<int> calls{0};

  Logger::setExternalHandler(
    [&](Logger::Level, const std::string &, const std::string &)
    {
      if (calls.fetch_add(1) == 0)
      {
        // Self-call on the worker thread: target == inflight (1, our own) ->
        // returns without deadlock.
        Logger::clearExternalHandler();
        selfClearReturned->store(true);
      }
    });

  Logger::info("trigger");
  const bool selfCleared = iora::test::waitFor([selfClearReturned]
                                              { return selfClearReturned->load(); });
  CHECK(selfCleared);
  if (!selfCleared)
  {
    return;
  }
  CHECK(selfClearReturned->load());
  Logger::shutdown();
}

// ── T9(b): worker self-call WHILE a concurrent flush invocation is live must
//    BLOCK until the flush invocation exits. The self-tearer waits the LIVE
//    predicate inflight==externalHandlerFrozen; the flush invocation is NOT
//    frozen (it never tears out), so it must be drained. With a skip-based fix
//    the self-call returns early and the assertion fails. ──────────────────────
TEST_CASE("worker self-call waits for a concurrent flush invocation to drain",
          "[logger_race][selfcall][concurrent]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto target = makeTarget();
  // SEPARATE gates so the self-clearer can be committed to its wait BEFORE the
  // flush invocation is allowed to exit. A single shared gate releases both at
  // once, which lets `flushExitedAtSelfClear` read true by luck even under a
  // skip-based (rejected) implementation — a non-discriminating test.
  auto selfCtl = makeCtl();
  auto flushCtl = makeCtl();
  auto which = makeCounter();
  auto flushExitedAtSelfClear = makeFlag();

  Logger::setExternalHandler(
    [target, selfCtl, flushCtl, which, flushExitedAtSelfClear](
      Logger::Level, const std::string &, const std::string &)
    {
      if (which->fetch_add(1) == 0)
      {
        // Worker invocation: enter, wait for the test to proceed, then self-clear.
        target->touch();
        selfCtl->onEnter();
        if (selfCtl->waitReleased())
        {
          Logger::clearExternalHandler(); // must drain the non-frozen flush invocation
          flushExitedAtSelfClear->store(flushCtl->exitedCount() >= 1);
        }
        selfCtl->onExit();
      }
      else
      {
        // flush invocation: a plain blocking body (never tears out -> not frozen).
        iora::test::blockingHandlerBody(*flushCtl, target.get());
      }
    });

  Logger::info("1"); // worker -> invocation 0, enters, waits on release
  REQUIRE(selfCtl->waitEntered(1));

  Logger::info("2");
  std::thread flushThread([] { Logger::flush(); }); // invocation 1 (flush), blocks
  const bool flushIn = flushCtl->waitEntered(1);    // inflight == 2
  CHECK(flushIn);
  if (!flushIn)
  {
    selfCtl->releaseAll();
    flushCtl->releaseAll();
    flushThread.detach();
    return;
  }

  // Release the self-clearer FIRST and give it time to commit to its drain wait,
  // then release the flush invocation: the self-clear must provably wait it out.
  selfCtl->releaseAll();
  std::this_thread::sleep_for(50ms);
  flushCtl->releaseAll();

  const bool flushDrained = flushCtl->waitExited(1);
  const bool selfDrained = selfCtl->waitExited(1);
  CHECK(flushDrained);
  CHECK(selfDrained);
  iora::test::joinOrDetach(flushDrained && selfDrained, {&flushThread});
  if (!(flushDrained && selfDrained))
  {
    return;
  }

  CHECK(flushExitedAtSelfClear->load()); // self-call observed the flush invocation drained
  CHECK(target.use_count() == 1); // no handler copy survives the tear-out
  target.reset();
  Logger::shutdown();
}
