// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Tests for Logger self-tear-out DEADLOCK under concurrent invocation (tracker
// 2026-07-21-3). The external-handler inflight-drain must remain deadlock-free
// AND use-after-free-free when a self-clearing/self-swapping handler runs
// concurrently on 2+ threads. A per-thread drain target (wait inflight==ownDepth)
// deadlocks when >=2 self-tearers each block waiting for the global in-flight
// count to fall to their own depth while the peers are equally pinned. The fix
// (Option 2, frozen-inflight accounting): self-tearers (depth>0) wait the LIVE
// predicate inflight==externalHandlerFrozen; external callers (depth==0) wait a
// genuine full drain inflight==0.
//
// FORCED RENDEZVOUS: every race test blocks the handler on a latch and drives the
// concurrent tear-out only after >=2 invocations have provably entered their
// window — never a timing tight-loop. Catch2 macros run ONLY on the main thread;
// worker/flush/log threads record into RaceCtl (its own mutex) and the main
// thread asserts after a BOUNDED wait. A hang manifests as the bounded
// waitExited() returning false => the CHECK fails; the timeout is NEVER raised to
// mask a hang. On a (regression) hang the wedged threads are detached rather than
// joined so the failure is reported instead of hanging the whole suite.
//
// LIFETIME: every object a handler body touches (RaceCtl, CaptureTarget, counters)
// is a shared_ptr captured BY VALUE into the handler. A detached wedged thread —
// or a test frame unwound by a failing REQUIRE — therefore cannot leave a handler
// pointing at a destroyed stack object; a regression stays a bounded FAIL instead
// of degenerating into a use-after-scope. Each case also clears the handler before
// it returns, so no handler outlives the objects it captured.
//
// Race-sensitive cases loop to raise the probability of hitting the
// register/self-catch/notify ordering. Run under TSan (setarch -R) and ASan
// (handle_segv=0) in two separate sanitized builds.

#define CATCH_CONFIG_MAIN
#include "logger_race_harness.hpp"
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/core/logger.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <thread>

using iora::core::Logger;
using iora::test::CaptureTarget;
using iora::test::joinOrDetach;
using iora::test::RaceCtl;
using iora::test::CounterPtr;
using iora::test::CtlPtr;
using iora::test::FlagPtr;
using iora::test::makeCounter;
using iora::test::makeCtl;
using iora::test::makeFlag;
using iora::test::makeTarget;
using iora::test::TargetPtr;
using iora::test::waitFor;
using namespace std::chrono_literals;

namespace
{

// Iterations for race-sensitive cases (tracker: >=100, target ~1000) to raise the
// probability of hitting the register/self-catch/notify interleaving.
constexpr int kLoopIters = 300;

// Cases carrying a 50ms commit delay inside the loop body use the tracker's >=100
// floor instead, to keep the wall-clock budget sane (100 * 50ms ~= 5s).
constexpr int kSlowLoopIters = 100;

// CtlPtr/TargetPtr/CounterPtr/FlagPtr and their factories come from the harness.
// Result flags written by TEST threads obey the same by-value rule as handler
// captures: those threads are DETACHED on the failure path, and a detached thread
// that later unblocks would write into a destroyed stack object.

// A self-CLEARING handler body: after the gate is released, it clears the handler
// from INSIDE itself (handlerReentryDepth()==1 -> the self-tearer drain path).
// On a release TIMEOUT it skips the self-clear and just exits, so a stuck test
// unwinds as a bounded failure rather than a wedged handler.
void selfClearingHandlerBody(const CtlPtr &c)
{
  c->onEnter();
  if (c->waitReleased())
  {
    Logger::clearExternalHandler(); // self-tear-out under concurrency
  }
  c->onExit();
}

// Tear the handler out from a depth-0 context and drop every queued entry, so no
// handler survives a test case holding captures. Safe to call unconditionally.
void teardownLogger()
{
  Logger::clearExternalHandler();
  Logger::shutdown();
}

} // namespace

// ── (a) canonical deadlock repro: TWO self-clears in flight (worker + concurrent
//    flush). Pre-fix both block at inflight==1 forever; post-fix both drain. ─────
TEST_CASE("two self-clearing invocations (worker + flush) both drain — no deadlock",
          "[logger][deadlock][a]")
{
  for (int i = 0; i < kLoopIters; ++i)
  {
    Logger::init(Logger::Level::Info, "", /*async=*/true);
    auto ctl = makeCtl();
    Logger::setExternalHandler([ctl](Logger::Level, const std::string &, const std::string &)
                               { selfClearingHandlerBody(ctl); });

    Logger::info("1"); // worker enters handler #1, blocks on the gate
    REQUIRE(ctl->waitEntered(1));
    Logger::info("2");                                // queued; worker busy
    std::thread flushThread([] { Logger::flush(); }); // flush drains "2" -> handler #2
    // CHECK + bail, never REQUIRE: a throw here would destroy a joinable
    // std::thread and call std::terminate, erasing the failure report.
    const bool bothIn = ctl->waitEntered(2); // inflight == 2, both self-clearers
    CHECK(bothIn);
    if (!bothIn)
    {
      ctl->releaseAll();
      joinOrDetach(false, {&flushThread});
      break;
    }

    ctl->releaseAll(); // both proceed to call clearExternalHandler() concurrently
    const bool drained = ctl->waitExited(2);
    CHECK(drained); // false => the self-clear deadlock regressed (bounded, no hang)

    joinOrDetach(drained, {&flushThread});
    if (!drained)
    {
      break;
    }
    teardownLogger();
  }
}

// ── (a2) the literal P0 symptom: shutdown() ITSELF is the concurrent drainer. Its
//    internal flush() delivers the second entry, so the worker invocation and the
//    shutdown-flush invocation both self-clear. Bounded so a regression FAILS. ───
TEST_CASE("shutdown() as the concurrent drainer: worker + shutdown-flush self-clears drain",
          "[logger][deadlock][a2]")
{
  for (int i = 0; i < kSlowLoopIters; ++i)
  {
    Logger::init(Logger::Level::Info, "", /*async=*/true);
    auto ctl = makeCtl();
    Logger::setExternalHandler([ctl](Logger::Level, const std::string &, const std::string &)
                               { selfClearingHandlerBody(ctl); });

    Logger::info("1"); // worker enters handler #1, blocks on the gate
    const bool firstIn = ctl->waitEntered(1);
    CHECK(firstIn); // CHECK, not REQUIRE: no thread is live yet, but keep it uniform
    Logger::info("2"); // queued for the shutdown-flush to deliver

    auto shutdownReturned = makeFlag(); // by-value: this thread may be DETACHED
    std::thread shutdownThread(
      [shutdownReturned]
      {
        Logger::shutdown(); // its flush() delivers "2" -> handler #2 (self-clearing)
        shutdownReturned->store(true);
      });

    const bool second = ctl->waitEntered(2); // inflight == 2, both self-clearers
    CHECK(second);
    ctl->releaseAll();
    const bool drained = ctl->waitExited(2);
    CHECK(drained);
    // The P0 report was "shutdown() hangs forever" — assert it RETURNS.
    const bool shutdownFinished =
      drained && waitFor([shutdownReturned] { return shutdownReturned->load(); });
    CHECK(shutdownFinished);

    joinOrDetach(shutdownFinished, {&shutdownThread});
    if (!shutdownFinished)
    {
      break;
    }
    Logger::clearExternalHandler();
  }
}

// ── (a3) the TWO CONCURRENT flush() CALLERS shape: exactly the two flush-driven
//    invocations self-tear, while the worker's invocation is a plain blocking body
//    that never tears out. That is a different frozen/non-frozen mix from (g)
//    (where all three self-tear): here the two parked self-tearers must ALSO drain
//    a third, NON-frozen invocation. A worker-free variant is unreachable through
//    the public API — async mode always starts the worker, and sync mode never
//    populates rawQueue, so flush() would have nothing to deliver. ──────────────
TEST_CASE("two concurrent flush() callers self-clear while a non-tearing worker invocation is live",
          "[logger][deadlock][a3]")
{
  for (int i = 0; i < kLoopIters; ++i)
  {
    Logger::init(Logger::Level::Info, "", /*async=*/true);
    auto workerCtl = makeCtl(); // the non-tearing worker invocation
    auto flushCtl = makeCtl();  // the two self-tearing flush invocations
    auto firstIsWorker = makeFlag(true);
    // Positive discriminator: each self-tearer records whether the NON-frozen
    // worker invocation had already exited when its own tear-out returned. A
    // skip-based drain would return early and score 0.
    auto waitedForWorker = makeCounter();

    Logger::setExternalHandler(
      [workerCtl, flushCtl, firstIsWorker, waitedForWorker](Logger::Level, const std::string &,
                                                            const std::string &)
      {
        if (firstIsWorker->exchange(false))
        {
          // Worker invocation: occupy an in-flight slot WITHOUT tearing out, so it
          // is a non-frozen invocation both self-tearers must wait for.
          iora::test::blockingHandlerBody(*workerCtl);
        }
        else
        {
          flushCtl->onEnter();
          if (flushCtl->waitReleased())
          {
            Logger::clearExternalHandler(); // must drain the non-frozen worker
            if (workerCtl->exitedCount() >= 1)
            {
              waitedForWorker->fetch_add(1);
            }
          }
          flushCtl->onExit();
        }
      });

    Logger::info("1");
    const bool workerIn = workerCtl->waitEntered(1); // worker parked, not tearing out
    CHECK(workerIn);
    Logger::info("2");
    Logger::info("3");
    std::thread f1([] { Logger::flush(); });
    std::thread f2([] { Logger::flush(); });
    const bool bothFlushesIn = flushCtl->waitEntered(2); // both self-tearers in flight
    CHECK(bothFlushesIn);

    // Release the two self-tearers FIRST and let them commit to their drain wait,
    // then release the non-frozen worker invocation they must wait for.
    flushCtl->releaseAll();
    std::this_thread::sleep_for(20ms);
    workerCtl->releaseAll();

    const bool workerDrained = workerCtl->waitExited(1);
    const bool drained = flushCtl->waitExited(2);
    CHECK(workerDrained);
    CHECK(drained);

    joinOrDetach(workerDrained && drained, {&f1, &f2});
    if (!(workerDrained && drained))
    {
      break;
    }
    // Both self-tearers must have waited out the non-frozen worker invocation.
    CHECK(waitedForWorker->load() == 2);
    teardownLogger();
  }
}

// ── (b) SYNC-mode two concurrent log() self-clears (no worker/flush). The handler
//    is invoked under runHandlerUnlocked on each logging thread. ────────────────
TEST_CASE("sync-mode two concurrent log() self-clears both drain — no deadlock",
          "[logger][deadlock][b][sync]")
{
  for (int i = 0; i < kLoopIters; ++i)
  {
    Logger::init(Logger::Level::Info, "", /*async=*/false);
    auto ctl = makeCtl();
    Logger::setExternalHandler([ctl](Logger::Level, const std::string &, const std::string &)
                               { selfClearingHandlerBody(ctl); });

    std::thread t1([] { Logger::info("a"); });
    std::thread t2([] { Logger::info("b"); });
    const bool bothIn = ctl->waitEntered(2); // inflight == 2 in sync mode
    CHECK(bothIn);
    if (!bothIn)
    {
      ctl->releaseAll();
      joinOrDetach(false, {&t1, &t2});
      break;
    }

    ctl->releaseAll();
    const bool drained = ctl->waitExited(2);
    CHECK(drained);

    joinOrDetach(drained, {&t1, &t2});
    if (!drained)
    {
      break;
    }
    teardownLogger();
  }
}

// ── (c) single-level self-clear (depth 1) with ONE concurrent non-self invocation
//    in flight. Exercises the depth-1 frozen path with a peer present. NOTE:
//    depth>=2 is UNREACHABLE (all dispatch sites gate handlerReentryDepth()==0),
//    so no depth>=2 test exists; the frozen+=depth generality is defensive-only. ─
TEST_CASE("single self-clear with a concurrent non-self invocation both drain",
          "[logger][deadlock][c]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto selfCtl = makeCtl();  // handler #1 self-clears
  auto otherCtl = makeCtl(); // handler #2 is a plain blocking invocation
  auto useSelf = makeFlag(true);

  // The single shared handler branches per-invocation on useSelf: the first
  // dispatched invocation (#1) self-clears; the second (#2) runs a plain blocking
  // body — a genuine non-self invocation whose drain the self-clearer must not
  // skip.
  Logger::setExternalHandler(
    [selfCtl, otherCtl, useSelf](Logger::Level, const std::string &, const std::string &)
    {
      if (useSelf->exchange(false))
      {
        selfClearingHandlerBody(selfCtl);
      }
      else
      {
        iora::test::blockingHandlerBody(*otherCtl);
      }
    });

  Logger::info("1"); // handler #1 (self-clearing) on the worker
  REQUIRE(selfCtl->waitEntered(1));
  Logger::info("2");
  std::thread flushThread([] { Logger::flush(); }); // handler #2 (non-self) via flush
  const bool otherIn = otherCtl->waitEntered(1);    // inflight == 2
  CHECK(otherIn);
  if (!otherIn)
  {
    selfCtl->releaseAll();
    otherCtl->releaseAll();
    joinOrDetach(false, {&flushThread});
    return;
  }

  selfCtl->releaseAll();
  otherCtl->releaseAll();
  const bool selfDrained = selfCtl->waitExited(1);
  const bool otherDrained = otherCtl->waitExited(1);
  CHECK(selfDrained);
  CHECK(otherDrained);

  joinOrDetach(selfDrained && otherDrained, {&flushThread});
  if (selfDrained && otherDrained)
  {
    teardownLogger();
  }
}

// ── (d) EXTERNAL clearExternalHandler (depth 0) racing an in-flight self-clear.
//    Discriminator for C-1: the self-tearer clears FIRST (so the gate is already
//    null) and is held in flight; only THEN does the depth-0 caller run. A
//    skip-based fix ("return if the gate is already null") returns immediately and
//    the post-gate touch has not happened => the CHECK fails. The correct fix
//    waits the genuine full drain inflight==0. ──────────────────────────────────
TEST_CASE("external clear (depth 0) racing an ALREADY-self-cleared in-flight invocation",
          "[logger][deadlock][d][uaf]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto target = makeTarget();
  auto ctl = makeCtl();      // gate 1: hold the invocation before it self-clears
  auto postClear = makeCtl(); // gate 2: hold it AFTER it self-cleared

  Logger::setExternalHandler(
    [target, ctl, postClear](Logger::Level, const std::string &, const std::string &)
    {
      target->touch();
      ctl->onEnter();
      if (ctl->waitReleased())
      {
        Logger::clearExternalHandler(); // self-tear-out: the gate is now NULL
        postClear->onEnter();           // tell the test the gate is already null
        postClear->waitReleased();      // ...and stay in flight while it acts
      }
      target->touch(); // post-gate access — must complete before ANY tear-out returns
      ctl->onExit();
    });

  Logger::info("trigger"); // worker enters the self-clearing handler, blocks
  REQUIRE(ctl->waitEntered(1));
  ctl->releaseAll();
  REQUIRE(postClear->waitEntered(1)); // the handler HAS self-cleared and is still running

  auto handlerDoneAtExternalClearReturn = makeFlag(); // by-value: may be DETACHED
  std::thread externalClear(
    [handlerDoneAtExternalClearReturn, ctl]
    {
      // Depth 0 with the gate ALREADY null: must still block until the in-flight
      // invocation exits (this is exactly what the rejected Option 1 would skip).
      Logger::clearExternalHandler();
      handlerDoneAtExternalClearReturn->store(ctl->exitedCount() >= 1);
    });

  std::this_thread::sleep_for(50ms); // external clear must still be blocked
  postClear->releaseAll();
  const bool drained = ctl->waitExited(1);
  CHECK(drained);

  if (drained)
  {
    externalClear.join();
    CHECK(handlerDoneAtExternalClearReturn->load()); // external clear waited full drain
    CHECK(target->touches.load() == 2);
    CHECK(target->canary.load() == 0x5A5A);
    teardownLogger();
  }
  else
  {
    externalClear.detach();
  }
}

// ── (e) self-clear racing a concurrent NON-self invocation on a 3rd thread. The
//    self-clearer MUST wait for the non-self invocation to drain (it contributes
//    to inflight but NOT to frozen). Discriminator for C-2 (a self-skip fix would
//    tear out while the non-self invocation is still dereferencing its capture). ─
TEST_CASE("self-clear waits for a concurrent non-self invocation to drain",
          "[logger][deadlock][e][uaf]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto target = makeTarget();
  auto selfCtl = makeCtl();
  auto otherCtl = makeCtl();
  auto useSelf = makeFlag(true);
  auto otherExitedAtSelfClearReturn = makeFlag();

  Logger::setExternalHandler(
    [target, selfCtl, otherCtl, useSelf, otherExitedAtSelfClearReturn](
      Logger::Level, const std::string &, const std::string &)
    {
      if (useSelf->exchange(false))
      {
        selfCtl->onEnter();
        if (selfCtl->waitReleased())
        {
          Logger::clearExternalHandler(); // self-tear-out: must drain the non-self peer
          otherExitedAtSelfClearReturn->store(otherCtl->exitedCount() >= 1);
        }
        selfCtl->onExit();
      }
      else
      {
        iora::test::blockingHandlerBody(*otherCtl, target.get());
      }
    });

  Logger::info("1"); // handler #1 self-clearing (worker)
  REQUIRE(selfCtl->waitEntered(1));
  Logger::info("2");
  std::thread flushThread([] { Logger::flush(); }); // handler #2 non-self
  const bool otherIn = otherCtl->waitEntered(1);    // inflight == 2 (frozen will be 1)
  CHECK(otherIn);
  if (!otherIn)
  {
    selfCtl->releaseAll();
    otherCtl->releaseAll();
    joinOrDetach(false, {&flushThread});
    return;
  }

  // Release the self-clearer and give it time to commit to its inflight==frozen
  // wait (frozen==1, inflight==2) BEFORE releasing the non-self peer, so the
  // self-clear must provably wait out the peer's drain (strengthens the C-2
  // discriminator; mirrors the 50ms commit delay in (d)/(h)).
  selfCtl->releaseAll();
  std::this_thread::sleep_for(50ms);
  otherCtl->releaseAll();
  const bool selfDrained = selfCtl->waitExited(1);
  const bool otherDrained = otherCtl->waitExited(1);
  CHECK(selfDrained);
  CHECK(otherDrained);

  joinOrDetach(selfDrained && otherDrained, {&flushThread});
  if (selfDrained && otherDrained)
  {
    CHECK(otherExitedAtSelfClearReturn->load()); // self-clear waited for the non-self peer
    CHECK(target->touches.load() == 2);
    teardownLogger();
  }
}

// ── (f) self-SWAP setExternalHandler concurrency: two in-flight invocations each
//    self-swap to a new handler B. Both drain (no deadlock) AND handler B is the
//    installed handler afterwards. Discriminator for H-1 (a skip-based set would
//    fail to install). ─────────────────────────────────────────────────────────
TEST_CASE("two self-swapping setExternalHandler invocations drain and install B",
          "[logger][deadlock][f]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto ctl = makeCtl();
  auto bCalls = makeCounter();
  auto handlerB = [bCalls](Logger::Level, const std::string &, const std::string &)
  { bCalls->fetch_add(1); };

  Logger::setExternalHandler(
    [ctl, handlerB](Logger::Level, const std::string &, const std::string &)
    {
      ctl->onEnter();
      if (ctl->waitReleased())
      {
        Logger::setExternalHandler(handlerB); // self-swap under concurrency
      }
      ctl->onExit();
    });

  Logger::info("1");
  REQUIRE(ctl->waitEntered(1));
  Logger::info("2");
  std::thread flushThread([] { Logger::flush(); });
  const bool bothIn = ctl->waitEntered(2); // inflight == 2, both self-swappers
  CHECK(bothIn);
  if (!bothIn)
  {
    ctl->releaseAll();
    joinOrDetach(false, {&flushThread});
    return;
  }

  ctl->releaseAll();
  const bool drained = ctl->waitExited(2);
  CHECK(drained);

  joinOrDetach(drained, {&flushThread});
  if (drained)
  {
    // Handler B must now be installed: log and drain, expect B invoked (delivery
    // is async — the worker may beat flush() to the entry, so bound-wait).
    bCalls->store(0);
    Logger::info("post-swap");
    Logger::flush();
    CHECK(waitFor([bCalls] { return bCalls->load() >= 1; }));
    teardownLogger();
  }
}

// ── (g) N>=3 concurrent self-clearers (worker + 2 flushes). Stresses the frozen-
//    count resolution for >2 parkers. ──────────────────────────────────────────
TEST_CASE("N=3 concurrent self-clearing invocations all drain — no deadlock",
          "[logger][deadlock][g]")
{
  for (int i = 0; i < kLoopIters; ++i)
  {
    Logger::init(Logger::Level::Info, "", /*async=*/true);
    auto ctl = makeCtl();
    Logger::setExternalHandler([ctl](Logger::Level, const std::string &, const std::string &)
                               { selfClearingHandlerBody(ctl); });

    Logger::info("1"); // worker -> handler #1
    REQUIRE(ctl->waitEntered(1));
    Logger::info("2");
    Logger::info("3");
    std::thread f1([] { Logger::flush(); });
    std::thread f2([] { Logger::flush(); });
    const bool allIn = ctl->waitEntered(3); // inflight == 3, three self-clearers
    CHECK(allIn);
    if (!allIn)
    {
      ctl->releaseAll();
      joinOrDetach(false, {&f1, &f2});
      break;
    }

    ctl->releaseAll();
    const bool drained = ctl->waitExited(3);
    CHECK(drained);

    joinOrDetach(drained, {&f1, &f2});
    if (!drained)
    {
      break;
    }
    teardownLogger();
  }
}

// ── (h) EXTERNAL setExternalHandler (depth 0) racing an in-flight invocation of
//    the PREVIOUS handler. The previous invocation MUST fully drain BEFORE the new
//    handler is installed (full-drain-before-install; distinct depth-0 UAF gate
//    from (d)). ─────────────────────────────────────────────────────────────────
TEST_CASE("external set (depth 0) racing an in-flight invocation drains before install",
          "[logger][deadlock][h][uaf]")
{
  for (int i = 0; i < kSlowLoopIters; ++i)
  {
    Logger::init(Logger::Level::Info, "", /*async=*/true);
    auto target = makeTarget();
    auto ctl = makeCtl();

    Logger::setExternalHandler(
      [target, ctl](Logger::Level, const std::string &, const std::string &)
      {
        iora::test::blockingHandlerBody(*ctl, target.get());
      });

    Logger::info("trigger"); // worker enters the PREVIOUS handler, blocks
    REQUIRE(ctl->waitEntered(1));

    auto prevDoneAtSetReturn = makeFlag(); // by-value: this thread may be DETACHED
    std::thread externalSet(
      [prevDoneAtSetReturn, ctl]
      {
        Logger::setExternalHandler(
          [](Logger::Level, const std::string &, const std::string &) {}); // handler B
        prevDoneAtSetReturn->store(ctl->exitedCount() >= 1);
      });

    std::this_thread::sleep_for(50ms); // external set should still be blocked draining
    ctl->releaseAll();
    const bool drained = ctl->waitExited(1);
    CHECK(drained);

    joinOrDetach(drained, {&externalSet});
    if (!drained)
    {
      break;
    }
    CHECK(prevDoneAtSetReturn->load()); // set waited full drain before installing B
    CHECK(target->touches.load() == 2);
    teardownLogger();
  }
}

// ── (i) concurrent clear vs set tear-out. Both invocations are in flight; the
//    CLEAR is released first and given time to commit to its park, so the SET
//    self-catches (frozen==inflight) and installs B without ever parking.
//    HANDLER B ALWAYS WINS, in either entry order — asserted unconditionally:
//      * set enters second -> it self-catches and installs B; the parked clear
//        nulled the gate at ENTRY (before registering frozen) and never re-nulls
//        on wake, so B survives.
//      * set enters first  -> the clear is the parked one, so the set's install is
//        the LAST write to externalHandler; B survives.
//    "Clear wins" would need the set to complete before the clear enters, which
//    needs the set not to park, which needs the clear already frozen —
//    contradiction. So a conditional assertion here would silently accept a
//    skip-based regression that never installs B.
TEST_CASE("concurrent self-clear vs self-set both drain and set's handler wins",
          "[logger][deadlock][i]")
{
  for (int i = 0; i < kSlowLoopIters; ++i)
  {
    Logger::init(Logger::Level::Info, "", /*async=*/true);
    auto clearCtl = makeCtl(); // the self-CLEARING invocation
    auto setCtl = makeCtl();   // the self-SETTING invocation
    auto bCalls = makeCounter();
    auto useClear = makeFlag(true);
    auto handlerB = [bCalls](Logger::Level, const std::string &, const std::string &)
    { bCalls->fetch_add(1); };

    Logger::setExternalHandler(
      [clearCtl, setCtl, useClear, handlerB](Logger::Level, const std::string &,
                                             const std::string &)
      {
        if (useClear->exchange(false))
        {
          clearCtl->onEnter();
          if (clearCtl->waitReleased())
          {
            Logger::clearExternalHandler();
          }
          clearCtl->onExit();
        }
        else
        {
          setCtl->onEnter();
          if (setCtl->waitReleased())
          {
            Logger::setExternalHandler(handlerB);
          }
          setCtl->onExit();
        }
      });

    Logger::info("1");
    const bool clearIn = clearCtl->waitEntered(1);
    CHECK(clearIn);
    if (!clearIn)
    {
      break;
    }
    Logger::info("2");
    std::thread flushThread([] { Logger::flush(); });
    const bool setIn = setCtl->waitEntered(1); // inflight == 2: both parked together
    CHECK(setIn);
    if (!setIn)
    {
      clearCtl->releaseAll();
      setCtl->releaseAll();
      joinOrDetach(false, {&flushThread});
      break;
    }

    // Release the CLEAR first and let it commit to its tear-out park (frozen==1,
    // inflight==2) before releasing the SET, so the set deterministically takes
    // the self-catch path. Same commit-delay idiom as (d)/(e)/(h).
    clearCtl->releaseAll();
    std::this_thread::sleep_for(50ms);
    setCtl->releaseAll();

    const bool clearDrained = clearCtl->waitExited(1);
    const bool setDrained = setCtl->waitExited(1);
    CHECK(clearDrained);
    CHECK(setDrained);

    const bool bothDrained = clearDrained && setDrained;
    joinOrDetach(bothDrained, {&flushThread});
    if (!bothDrained)
    {
      break;
    }

    // B must be live. A positive discriminator: assert B RECEIVES, and that the
    // original handler was not re-invoked (it would enter one of the controllers).
    const int clearEntries = clearCtl->enteredCount();
    const int setEntries = setCtl->enteredCount();
    bCalls->store(0);
    Logger::info("post");
    Logger::flush();
    CHECK(waitFor([bCalls] { return bCalls->load() >= 1; }));
    CHECK(clearCtl->enteredCount() == clearEntries); // original handler NOT re-invoked
    CHECK(setCtl->enteredCount() == setEntries);
    teardownLogger();
  }
}

// ── (k) DEPTH>0 TEARDOWN with a parked peer — the shape that deadlocked at
//    worker.join() when the teardown thread's frozen registration was released at
//    the end of its wait instead of being held across the join. The worker parks
//    in its own self-clear; a second invocation calls Logger::shutdown() from
//    INSIDE the handler (depth 1, its own frame pinned). shutdown() must RETURN. ─
TEST_CASE("shutdown() from inside a handler with a peer parked in its own tear-out returns",
          "[logger][deadlock][k][teardown]")
{
  for (int i = 0; i < kSlowLoopIters; ++i)
  {
    Logger::init(Logger::Level::Info, "", /*async=*/true);
    auto workerCtl = makeCtl();   // worker invocation: parks in its own self-clear
    auto teardownCtl = makeCtl(); // flush invocation: calls shutdown() from inside
    auto firstIsWorker = makeFlag(true);
    auto shutdownReturned = makeFlag();

    Logger::setExternalHandler(
      [workerCtl, teardownCtl, firstIsWorker, shutdownReturned](Logger::Level,
                                                                const std::string &,
                                                                const std::string &)
      {
        if (firstIsWorker->exchange(false))
        {
          selfClearingHandlerBody(workerCtl); // parks in its tear-out
        }
        else
        {
          teardownCtl->onEnter();
          if (teardownCtl->waitReleased())
          {
            Logger::shutdown(); // depth 1: our frame is pinned across its join
            shutdownReturned->store(true);
          }
          teardownCtl->onExit();
        }
      });

    Logger::info("1");
    const bool workerIn = workerCtl->waitEntered(1);
    CHECK(workerIn);
    if (!workerIn)
    {
      break;
    }
    Logger::info("2");
    std::thread flushThread([] { Logger::flush(); });
    const bool teardownIn = teardownCtl->waitEntered(1); // inflight == 2
    CHECK(teardownIn);
    if (!teardownIn)
    {
      workerCtl->releaseAll();
      teardownCtl->releaseAll();
      joinOrDetach(false, {&flushThread});
      break;
    }

    // Release the worker into its self-clear park FIRST, then let the peer call
    // shutdown() while the worker is parked — the deadlock shape.
    workerCtl->releaseAll();
    std::this_thread::sleep_for(20ms);
    const auto teardownStart = std::chrono::steady_clock::now();
    teardownCtl->releaseAll();

    // NOTE: kMaxTeardown is deliberately far BELOW the production stall backstop
    // (kStallReportInterval, 5s). If they were equal, a path that only unblocks
    // when the backstop fires would pass by clock luck and the test would MASK
    // the stall instead of exposing it — which is exactly what happened before the
    // park-site notify was added (every iteration silently cost 5.0s).
    constexpr auto kMaxTeardown = std::chrono::seconds(2);
    const bool teardownDrained = teardownCtl->waitExited(1, kMaxTeardown);
    CHECK(teardownDrained);
    CHECK(shutdownReturned->load()); // false/hung => the teardown join deadlock
    // Positive assertion that no backstop-timer rescue occurred: the whole
    // teardown must complete in well under kStallReportInterval.
    const auto teardownElapsed = std::chrono::steady_clock::now() - teardownStart;
    CHECK(teardownElapsed < kMaxTeardown);
    const bool workerDrained = workerCtl->waitExited(1, kMaxTeardown);
    CHECK(workerDrained);

    const bool ok = teardownDrained && workerDrained;
    joinOrDetach(ok, {&flushThread});
    if (!ok)
    {
      break;
    }
    Logger::clearExternalHandler();
  }
}

// ── (l) H-2 PROBE: a handler capture whose DESTRUCTOR logs. Every in-flight
//    handler copy must be destroyed in the UNLOCKED window — runHandlerUnlocked
//    re-acquires data.mutex before returning, so a copy left to die at scope exit
//    would run this destructor under the non-recursive mutex and self-deadlock on
//    the re-entrant log() call. Neither TSan nor ASan flags that shape, so it
//    needs an explicit probe. Bounded: a hang here is a FAILED CHECK.
namespace
{
// Logs from its destructor. Captured BY VALUE into the handler, so a copy rides
// along with every in-flight handler copy — and each copy is destroyed wherever
// the delivery path destroys it. That is the hazard: if a copy dies while
// data.mutex is held, this destructor's re-entrant log() self-deadlocks.
struct LoggingOnDestroy
{
  std::shared_ptr<std::atomic<int>> destructions;
  std::shared_ptr<std::atomic<bool>> armed;   // set only AFTER installation
  std::shared_ptr<std::atomic<int>> logBudget; // bounds the feedback loop
  ~LoggingOnDestroy()
  {
    if (!destructions)
    {
      return;
    }
    destructions->fetch_add(1);
    // ARMED-and-budgeted, deliberately. The temporary built at the
    // setExternalHandler call site is destroyed BEFORE arming, so it cannot
    // consume the budget — an earlier version let it, which made this probe
    // vacuous (it passed against a deliberately broken build). The budget stops
    // the feedback loop: a destructor log queues a message, whose delivery copies
    // the handler again, whose copy destruction would log again, forever.
    if (armed->load() && logBudget->fetch_sub(1) > 0)
    {
      Logger::info("capture destructor logging"); // re-enters the logger
    }
  }
};
} // namespace

// ── (l) capture destructor that LOGS. Under the shared_ptr handler model (tracker
//    2026-07-22-3) the per-dispatch copy is a refcount bump, so NO transient capture
//    is constructed/destroyed on the delivery path — destructions stays flat across
//    a delivery. The capture's SOLE instance is destroyed at UNINSTALL, at the
//    tear-out `doomed` destruction with data.mutex RELEASED; its re-entrant log()
//    must run there without self-deadlock. The uninstall is driven on a WORKER
//    thread behind a BOUNDED flag so a (regression) under-lock destruction that
//    self-deadlocks is a bounded FAIL, never a wedged main thread.
TEST_CASE("capture destructor may log — no per-delivery copy; runs unlocked once at uninstall",
          "[logger][deadlock][l][uaf]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto destructions = makeCounter();
  auto delivered = makeCounter();
  auto armed = makeFlag();
  auto logBudget = makeCounter(1);

  Logger::setExternalHandler(
    [probe = LoggingOnDestroy{destructions, armed, logBudget}, delivered](
      Logger::Level, const std::string &, const std::string &) { delivered->fetch_add(1); });
  // Arm AFTER installation so the construction-site temporary's (moved-from) dtor
  // cannot consume the budget.
  armed->store(true);

  const int beforeDelivery = destructions->load();
  Logger::info("one");
  Logger::flush();
  CHECK(waitFor([delivered] { return delivered->load() >= 1; }));
  // The delivery path constructs NO transient capture copy under the new model.
  CHECK(destructions->load() == beforeDelivery);

  // Uninstall on a worker thread behind a bounded flag. The logging capture dtor
  // runs at the `doomed` destruction (unlocked). A regression that destroyed it
  // under the lock would self-deadlock here → bounded FAIL, not a wedge.
  auto uninstallDone = makeFlag();
  std::thread uninstaller(
    [uninstallDone] { Logger::clearExternalHandler(); uninstallDone->store(true); });
  const bool done = waitFor([uninstallDone] { return uninstallDone->load(); });
  CHECK(done);
  joinOrDetach(done, {&uninstaller});
  if (!done)
  {
    return;
  }
  // The sole instance was destroyed exactly once, at uninstall (its log ran unlocked).
  CHECK(destructions->load() == beforeDelivery + 1);
  Logger::shutdown();
}

// ── (l2) SYNC-mode capture destructor that LOGS, destroyed at UNINSTALL. The
//    re-entrant log() takes the console path (handler already torn out) and must run
//    UNLOCKED and terminate — a regression that destroyed the capture under
//    data.mutex would self-deadlock on the non-recursive mutex (the sync log path
//    re-acquires it). Bounded on the uninstaller's own flag.
TEST_CASE("sync-mode capture destructor logging at uninstall runs unlocked and terminates",
          "[logger][deadlock][l2][uaf]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/false);
  auto destructions = makeCounter();
  auto armed = makeFlag();
  auto logBudget = makeCounter(1);
  Logger::setExternalHandler(
    [probe = LoggingOnDestroy{destructions, armed, logBudget}](Logger::Level, const std::string &,
                                                               const std::string &) {});
  armed->store(true);
  const int before = destructions->load();

  auto uninstallDone = makeFlag();
  std::thread uninstaller(
    [uninstallDone] { Logger::clearExternalHandler(); uninstallDone->store(true); });
  const bool done = waitFor([uninstallDone] { return uninstallDone->load(); });
  CHECK(done);
  joinOrDetach(done, {&uninstaller});
  if (!done)
  {
    return;
  }
  // Destroyed exactly once, at uninstall; its re-entrant log ran unlocked.
  CHECK(destructions->load() == before + 1);
  Logger::shutdown();
}

// ── (l3) capture destructor that CLEARS the handler. Under the shared_ptr handler
//    model the capture's sole instance is destroyed at whichever site drops the LAST
//    reference — and a clearing capture dtor there must never take the depth-0
//    external branch on its own pinned frame (inflight==0, unsatisfiable → hang).
//    That last-ref site is path-dependent, so it is covered by TWO cases:
//      (l3a) EXTERNAL tear-out: the clearer's `doomed` outlives every in-flight
//            dispatch copy, so the capture dtor runs at `doomed` destruction on the
//            clearer's thread at depth 0, unlocked, AFTER the drain; its re-entrant
//            clear finds the member already null and returns.
//      (l3b) SELF tear-out: the handler body self-clears first (nulling the member),
//            so the dispatch copy becomes last-ref and the dropper destroys the
//            capture at reentry-depth >= 1 — its re-entrant clear must take the
//            self-tearer branch (inflight==frozen).
//    Both are BOUNDED on the flag of the thread that can hang, so a regression is a
//    FAILED CHECK, never a wedged join.
namespace
{
struct ClearingOnDestroy
{
  std::shared_ptr<std::atomic<bool>> armed; // set only AFTER installation
  std::shared_ptr<std::atomic<bool>> cleared;
  ~ClearingOnDestroy()
  {
    // ARMED-gated: the temporary built at the setExternalHandler call site is
    // destroyed immediately after installation, and an unarmed version would tear
    // the handler out before anything could ever be delivered.
    if (armed && armed->load() && !cleared->exchange(true))
    {
      Logger::clearExternalHandler(); // re-entrant tear-out from a capture dtor
    }
  }
};
} // namespace

TEST_CASE("(l3a) capture destructor clears at the EXTERNAL tear-out (doomed, depth 0) — no deadlock",
          "[logger][deadlock][l3a][uaf]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto ctl = makeCtl();
  auto target = makeTarget();
  auto armed = makeFlag();
  auto cleared = makeFlag();

  // Handler parks in-window so a delivery is provably in flight (dispatch shared_ptr
  // copy alive) while the external clear runs; the capture clears in its dtor.
  Logger::setExternalHandler(
    [probe = ClearingOnDestroy{armed, cleared}, ctl, target](Logger::Level, const std::string &,
                                                             const std::string &)
    { blockingHandlerBody(*ctl, target.get()); });
  armed->store(true);

  Logger::info("trigger"); // worker enters the handler and parks
  const bool entered = ctl->waitEntered(1);
  CHECK(entered);
  if (!entered)
  {
    teardownLogger();
    return;
  }

  // External clear while the delivery is parked, on its OWN thread with its OWN
  // bounded completion flag: a wedged nested clear must FAIL bounded, not hang the
  // join. `clearDone` is a shared_ptr flag (by-value) so a DETACHED wedged thread
  // that later unblocks writes into a live object.
  auto clearDone = makeFlag();
  std::thread clearThread(
    [clearDone]
    {
      Logger::clearExternalHandler();
      clearDone->store(true);
    });

  ctl->releaseAll(); // let the parked delivery finish so the drain can complete
  const bool workerDrained = ctl->waitExited(1);
  const bool clearReturned = waitFor([clearDone] { return clearDone->load(); });
  CHECK(workerDrained);
  CHECK(clearReturned); // <- deadlock discriminator: false => nested clear wedged
  const bool finished = workerDrained && clearReturned;
  joinOrDetach(finished, {&clearThread});
  if (!finished)
  {
    return;
  }

  CHECK(cleared->load());                  // the clearing capture dtor really ran (once)
  CHECK(target->canary.load() == 0x5A5A);  // captured object not corrupted
  teardownLogger();
}

TEST_CASE("(l3b) capture destructor clears at the DROPPER (depth >= 1, self-tearer) — no deadlock",
          "[logger][deadlock][l3b][uaf]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto ctl = makeCtl();
  auto armed = makeFlag();
  auto cleared = makeFlag();
  auto handlerDone = makeFlag();

  // The BODY self-clears after release (depth 1) — nulling the member so the
  // dispatch copy becomes the last reference — AND the capture ALSO clears in its
  // dtor. On body return the dropper destroys the capture at depth >= 1; that
  // re-entrant clear must take the self-tearer branch (inflight==frozen), not the
  // depth-0 external branch on its own pinned frame.
  Logger::setExternalHandler(
    [probe = ClearingOnDestroy{armed, cleared}, ctl, handlerDone](Logger::Level,
                                                                  const std::string &,
                                                                  const std::string &)
    {
      ctl->onEnter();
      if (ctl->waitReleased())
      {
        Logger::clearExternalHandler(); // self-tear from the BODY (depth 1)
      }
      ctl->onExit();
      handlerDone->store(true);
    });
  armed->store(true);

  Logger::info("trigger");
  const bool entered = ctl->waitEntered(1);
  CHECK(entered);
  if (!entered)
  {
    teardownLogger();
    return;
  }
  ctl->releaseAll();

  // The capture dtor runs on the WORKER at the dropper AFTER the body returns; if it
  // took the wrong (depth-0) branch it would wait inflight==0 on its own pinned
  // frame and the worker would wedge — cleared never set. Bounded on the worker's
  // own effect (cleared), so a regression is a FAILED CHECK.
  const bool clearedRan = waitFor([cleared] { return cleared->load(); });
  const bool handlerReturned = waitFor([handlerDone] { return handlerDone->load(); });
  CHECK(handlerReturned); // body's own self-clear did not hang
  CHECK(clearedRan);      // capture dtor's clear at the dropper took the self-tearer branch
  if (!clearedRan || !handlerReturned)
  {
    return; // worker may be wedged; do NOT teardown (would hang) — FAIL already recorded
  }
  teardownLogger();
}

// ── (l4) shutdown() (NOT clearExternalHandler) as the uninstall path. The handler
//    capture is destroyed at teardownAndReapWorker's `doomed`, which ADDITIONALLY
//    sets exit, reroutes, and reaps the worker — a distinct code path from
//    clearExternalHandler. The LoggingOnDestroy dtor's re-entrant log must run
//    UNLOCKED (doomed destroyed after the lock is released) without deadlock, and the
//    sole instance must die exactly once. Bounded on the shutdown thread's own flag.
TEST_CASE("shutdown() destroys the handler capture unlocked (teardownAndReapWorker doomed)",
          "[logger][deadlock][l4][uaf]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto destructions = makeCounter();
  auto armed = makeFlag();
  auto logBudget = makeCounter(1);
  Logger::setExternalHandler(
    [probe = LoggingOnDestroy{destructions, armed, logBudget}](Logger::Level, const std::string &,
                                                               const std::string &) {});
  armed->store(true);
  const int before = destructions->load();

  // shutdown() on a worker thread behind a bounded flag: a regression that destroyed
  // the capture under data.mutex (its re-entrant log self-deadlocking) is a bounded
  // FAIL, not a wedged main thread.
  auto shutdownDone = makeFlag();
  std::thread shutter(
    [shutdownDone]
    {
      Logger::shutdown();
      shutdownDone->store(true);
    });
  const bool done = waitFor([shutdownDone] { return shutdownDone->load(); });
  CHECK(done);
  joinOrDetach(done, {&shutter});
  if (!done)
  {
    return;
  }
  // The sole instance was destroyed exactly once, at teardownAndReapWorker's doomed.
  CHECK(destructions->load() == before + 1);
}

// ── (m) WORKER LIFECYCLE: the workerRunning protocol. Covers the two shapes that
//    the iteration-2/3 fixes introduced and that had no regression test:
//    (1) init() after a shutdown() must produce a working async logger again — a
//        stale workerRunning would leave async mode with NO drainer, silently;
//    (2) a second shutdown() must return (not hang) and not double-join.
TEST_CASE("worker lifecycle: re-init after shutdown drains again; double shutdown returns",
          "[logger][deadlock][m][lifecycle]")
{
  for (int i = 0; i < 20; ++i)
  {
    Logger::init(Logger::Level::Info, "", /*async=*/true);
    auto delivered = makeCounter();
    Logger::setExternalHandler([delivered](Logger::Level, const std::string &, const std::string &)
                               { delivered->fetch_add(1); });
    // NO flush() here: flush() drains rawQueue on the CALLING thread, so it would
    // satisfy this check with or without a worker — vacuous for the property under
    // test. Only the worker may deliver.
    Logger::info("before");
    CHECK(waitFor([delivered] { return delivered->load() >= 1; }));

    Logger::clearExternalHandler();
    // Bounded: the property under test is that these RETURN. Running them on the
    // main thread would assert it by hanging the suite.
    auto shutdownsDone = makeFlag();
    std::thread shutdownThread(
      [shutdownsDone]
      {
        Logger::shutdown();
        Logger::shutdown(); // MUST return: no double-join, no wait on a dead worker
        shutdownsDone->store(true);
      });
    const bool returned = waitFor([shutdownsDone] { return shutdownsDone->load(); });
    CHECK(returned);
    joinOrDetach(returned, {&shutdownThread});
    if (!returned)
    {
      break;
    }

    // Re-init must spawn a fresh worker (the previous one published its exit).
    Logger::init(Logger::Level::Info, "", /*async=*/true);
    auto delivered2 = makeCounter();
    Logger::setExternalHandler([delivered2](Logger::Level, const std::string &,
                                            const std::string &) { delivered2->fetch_add(1); });
    // Again no flush(): a stale workerRunning would leave async mode with no
    // drainer, and only a worker-delivered message discriminates that.
    Logger::info("after");
    CHECK(waitFor([delivered2] { return delivered2->load() >= 1; }));

    Logger::clearExternalHandler();
    Logger::shutdown();
  }
}

// ── (j) THROWING self-tearer with a concurrent parked peer: the worker-driven
//    invocation self-clears then THROWS, exercising runHandlerUnlocked's catch
//    path (relock / --inflight / notify_all / rethrow). The catch-path decrement
//    must still release the concurrent (flush) self-clearer. The worker swallows
//    the exception (no std::terminate); the flush handler does NOT throw (flush()
//    would rethrow to the flush thread). ───────────────────────────────────────
TEST_CASE("throwing self-tearer still drains a concurrent parked peer (catch path)",
          "[logger][deadlock][j]")
{
  for (int i = 0; i < kLoopIters; ++i)
  {
    Logger::init(Logger::Level::Info, "", /*async=*/true);
    auto ctl = makeCtl();
    auto throwOnFirst = makeFlag(true);
    Logger::setExternalHandler(
      [ctl, throwOnFirst](Logger::Level, const std::string &, const std::string &)
      {
        const bool doThrow = throwOnFirst->exchange(false); // only the first (worker) throws
        ctl->onEnter();
        if (ctl->waitReleased())
        {
          Logger::clearExternalHandler(); // self-tear-out (both invocations)
        }
        ctl->onExit();
        if (doThrow)
        {
          throw std::runtime_error("self-tearer throws after clear");
        }
      });

    Logger::info("1"); // worker -> handler #1 (will throw after self-clear)
    REQUIRE(ctl->waitEntered(1));
    Logger::info("2");
    std::thread flushThread([] { Logger::flush(); }); // handler #2 (no throw)
    const bool bothIn = ctl->waitEntered(2);          // inflight == 2
    CHECK(bothIn);
    if (!bothIn)
    {
      ctl->releaseAll();
      joinOrDetach(false, {&flushThread});
      break;
    }

    ctl->releaseAll();
    const bool drained = ctl->waitExited(2); // both must drain despite the throw
    CHECK(drained);

    joinOrDetach(drained, {&flushThread});
    if (!drained)
    {
      break;
    }
    teardownLogger();
  }
}
