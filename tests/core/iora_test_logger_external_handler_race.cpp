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
// worker self-call waits inflight==1 (drains OTHERS, not itself); a throwing
// handler is swallowed on the worker (no std::terminate) and rethrown by flush().
//
// FORCED RENDEZVOUS: every race test blocks the handler on a gate and drives the
// tear-out only after the handler has provably entered its window — never a timing
// tight-loop (which could pass without the fix and prove nothing). Catch2 macros
// run ONLY on the main thread; worker/flush threads record into atomics and the
// main thread asserts after join(). Run under TSan (setarch -R) and ASan
// (handle_segv=0) in two separate sanitized builds.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
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
using namespace std::chrono_literals;

namespace
{

// Object captured by reference in a handler; destroying it during an in-flight
// handler call is the use-after-free under test. Heap-allocated so the test can
// free it precisely after the tear-out returns.
struct CaptureTarget
{
  std::atomic<int> touches{0};
  std::atomic<int> canary{0x5A5A};
  void touch() { touches.fetch_add(1); }
};

// Rendezvous controller shared between the test thread and handler invocations.
// Lives for the whole test (NOT the UAF target).
struct RaceCtl
{
  std::mutex m;
  std::condition_variable cv;
  int entered = 0;   // # handler invocations that reached their window
  int exited = 0;    // # handler invocations that completed
  bool released = false;

  void onEnter()
  {
    std::lock_guard<std::mutex> l(m);
    ++entered;
    cv.notify_all();
  }
  void onExit()
  {
    std::lock_guard<std::mutex> l(m);
    ++exited;
    cv.notify_all();
  }
  bool waitEntered(int n, std::chrono::milliseconds to = 5s)
  {
    std::unique_lock<std::mutex> l(m);
    return cv.wait_for(l, to, [&] { return entered >= n; });
  }
  void releaseAll()
  {
    std::lock_guard<std::mutex> l(m);
    released = true;
    cv.notify_all();
  }
  void waitReleased()
  {
    std::unique_lock<std::mutex> l(m);
    cv.wait(l, [&] { return released; });
  }
  int exitedCount()
  {
    std::lock_guard<std::mutex> l(m);
    return exited;
  }
};

// A blocking handler body: touch the captured target, signal entered, wait for
// the gate, touch again (the post-gate access that must complete before any
// tear-out returns), then signal exit.
void blockingHandlerBody(CaptureTarget *t, RaceCtl *c)
{
  t->touch();
  c->onEnter();
  c->waitReleased();
  t->touch(); // post-gate access — UAF if the target is freed before the drain
  c->onExit();
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
  std::atomic<int> calls{0};
  Logger::setExternalHandler(
    [&](Logger::Level, const std::string &, const std::string &) { calls.fetch_add(1); });
  Logger::info("a");
  Logger::info("b");
  CHECK(calls.load() == 2);
  Logger::clearExternalHandler();
  Logger::info("c"); // no handler now
  CHECK(calls.load() == 2);
  Logger::shutdown();
}

// ── T1 + T4 + T7: clear drains an in-flight WORKER invocation; returns only
//    after the handler completed; [obj]-capturing target freed safely after. ──
TEST_CASE("clearExternalHandler drains an in-flight worker invocation (no UAF)",
          "[logger_race][worker]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto target = std::make_unique<CaptureTarget>();
  RaceCtl ctl;

  Logger::setExternalHandler([t = target.get(), c = &ctl](Logger::Level, const std::string &,
                                                          const std::string &)
                             { blockingHandlerBody(t, c); });

  Logger::info("trigger"); // worker picks it up and enters the handler window
  REQUIRE(ctl.waitEntered(1));

  std::atomic<bool> handlerDoneAtClearReturn{false};
  std::thread clearThread(
    [&]
    {
      Logger::clearExternalHandler();            // must block until the handler exits
      handlerDoneAtClearReturn.store(ctl.exitedCount() >= 1);
    });

  std::this_thread::sleep_for(50ms); // clear should still be blocked (handler gated)
  ctl.releaseAll();                  // let the handler finish its post-gate access
  clearThread.join();

  // The drain guarantee: clearExternalHandler returned only AFTER the handler
  // completed its post-gate access (without the fix this is false).
  CHECK(handlerDoneAtClearReturn.load());
  CHECK(target->touches.load() == 2);
  CHECK(target->canary.load() == 0x5A5A);

  target.reset(); // safe: no invocation is in flight
  Logger::shutdown();
}

// ── T2: setExternalHandler REPLACE drains the previous handler's in-flight ────
TEST_CASE("setExternalHandler replace drains the previous in-flight invocation",
          "[logger_race][replace]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto target = std::make_unique<CaptureTarget>();
  RaceCtl ctl;

  Logger::setExternalHandler([t = target.get(), c = &ctl](Logger::Level, const std::string &,
                                                          const std::string &)
                             { blockingHandlerBody(t, c); });

  Logger::info("trigger");
  REQUIRE(ctl.waitEntered(1));

  std::atomic<bool> handlerDoneAtSetReturn{false};
  std::thread setThread(
    [&]
    {
      Logger::setExternalHandler(
        [](Logger::Level, const std::string &, const std::string &) {}); // handler B
      handlerDoneAtSetReturn.store(ctl.exitedCount() >= 1);
    });

  std::this_thread::sleep_for(50ms);
  ctl.releaseAll();
  setThread.join();

  CHECK(handlerDoneAtSetReturn.load()); // replace waited for handler A to finish
  target.reset();                       // safe: handler A fully drained
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
  auto target = std::make_unique<CaptureTarget>();
  RaceCtl ctl;

  Logger::setExternalHandler([t = target.get(), c = &ctl](Logger::Level, const std::string &,
                                                          const std::string &)
                             { blockingHandlerBody(t, c); });

  Logger::info("1"); // worker enters handler #1 and blocks
  REQUIRE(ctl.waitEntered(1));

  Logger::info("2");                                       // queued; worker is busy
  std::thread flushThread([] { Logger::flush(); });        // flush drains "2" -> handler #2
  REQUIRE(ctl.waitEntered(2));                             // inflight == 2 now

  std::atomic<bool> bothDoneAtClearReturn{false};
  std::thread clearThread(
    [&]
    {
      Logger::clearExternalHandler();                      // waits inflight == 0
      bothDoneAtClearReturn.store(ctl.exitedCount() >= 2);
    });

  std::this_thread::sleep_for(50ms);
  ctl.releaseAll();
  flushThread.join();
  clearThread.join();

  CHECK(bothDoneAtClearReturn.load());        // clear drained BOTH invocations
  CHECK(target->touches.load() == 4);         // 2 invocations x 2 touches
  target.reset();
  Logger::shutdown();
}

// ── T10 N>2 variant: worker + TWO concurrent flush()es all in-flight (count==3)
TEST_CASE("clear waits for N>2 concurrent invocations (worker + 2 flushes)",
          "[logger_race][concurrent][n3]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto target = std::make_unique<CaptureTarget>();
  RaceCtl ctl;

  Logger::setExternalHandler([t = target.get(), c = &ctl](Logger::Level, const std::string &,
                                                          const std::string &)
                             { blockingHandlerBody(t, c); });

  Logger::info("1"); // worker -> handler #1, blocks
  REQUIRE(ctl.waitEntered(1));

  Logger::info("2");
  Logger::info("3");
  std::thread f1([] { Logger::flush(); }); // drains one of "2"/"3"
  std::thread f2([] { Logger::flush(); }); // drains the other
  REQUIRE(ctl.waitEntered(3));             // inflight == 3

  std::atomic<bool> allDoneAtClearReturn{false};
  std::thread clearThread(
    [&]
    {
      Logger::clearExternalHandler();
      allDoneAtClearReturn.store(ctl.exitedCount() >= 3);
    });

  std::this_thread::sleep_for(50ms);
  ctl.releaseAll();
  f1.join();
  f2.join();
  clearThread.join();

  CHECK(allDoneAtClearReturn.load());
  CHECK(target->touches.load() == 6);
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
  auto target = std::make_unique<CaptureTarget>();
  RaceCtl ctl;
  std::atomic<int> invocation{0};

  Logger::setExternalHandler(
    [&, t = target.get(), c = &ctl](Logger::Level, const std::string &, const std::string &)
    {
      if (invocation.fetch_add(1) == 0)
      {
        blockingHandlerBody(t, c); // worker: occupy and block
      }
      else
      {
        throw std::runtime_error("boom"); // flush invocation: throw
      }
    });

  Logger::info("1"); // worker -> invocation 0, blocks
  REQUIRE(ctl.waitEntered(1));

  Logger::info("2"); // queued; worker busy
  std::atomic<bool> flushRethrew{false};
  std::thread flushThread(
    [&]
    {
      try
      {
        Logger::flush(); // drains "2" -> invocation 1 throws -> flush rethrows
      }
      catch (const std::runtime_error &)
      {
        flushRethrew.store(true);
      }
    });
  flushThread.join();
  CHECK(flushRethrew.load()); // flush() propagated the handler exception to its caller

  // Release the worker, then a clearExternalHandler must NOT hang (the throwing
  // flush invocation restored the in-flight counter before rethrowing).
  ctl.releaseAll();
  std::atomic<bool> cleared{false};
  std::thread clearThread(
    [&]
    {
      Logger::clearExternalHandler();
      cleared.store(true);
    });
  clearThread.join();
  CHECK(cleared.load());
  target.reset();
  Logger::shutdown();
}

// ── T8(b): a throwing handler on the WORKER thread is swallowed (no terminate);
//    the worker survives and keeps delivering; the counter returns to 0. ───────
TEST_CASE("worker swallows a throwing handler and keeps running", "[logger_race][throw][worker]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);

  std::atomic<int> throwingCalls{0};
  Logger::setExternalHandler(
    [&](Logger::Level, const std::string &, const std::string &)
    {
      throwingCalls.fetch_add(1);
      throw std::runtime_error("boom-on-worker");
    });

  Logger::info("first");
  // Give the worker time to drain + throw + swallow.
  for (int i = 0; i < 200 && throwingCalls.load() == 0; ++i)
  {
    std::this_thread::sleep_for(2ms);
  }
  CHECK(throwingCalls.load() >= 1); // worker invoked it and did NOT terminate

  // The worker survived: install a non-throwing handler and confirm delivery.
  std::atomic<int> okCalls{0};
  Logger::setExternalHandler(
    [&](Logger::Level, const std::string &, const std::string &) { okCalls.fetch_add(1); });
  Logger::info("second");
  for (int i = 0; i < 200 && okCalls.load() == 0; ++i)
  {
    std::this_thread::sleep_for(2ms);
  }
  CHECK(okCalls.load() >= 1);

  Logger::clearExternalHandler(); // must not hang (counter not stranded)
  Logger::shutdown();
  SUCCEED();
}

// ── T9(a): worker self-call with no other in-flight -> no deadlock. ───────────
TEST_CASE("handler self-calling clearExternalHandler does not deadlock (sole in-flight)",
          "[logger_race][selfcall]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  std::atomic<bool> selfClearReturned{false};
  std::atomic<int> calls{0};

  Logger::setExternalHandler(
    [&](Logger::Level, const std::string &, const std::string &)
    {
      if (calls.fetch_add(1) == 0)
      {
        // Self-call on the worker thread: target == inflight (1, our own) ->
        // returns without deadlock.
        Logger::clearExternalHandler();
        selfClearReturned.store(true);
      }
    });

  Logger::info("trigger");
  for (int i = 0; i < 500 && !selfClearReturned.load(); ++i)
  {
    std::this_thread::sleep_for(2ms);
  }
  CHECK(selfClearReturned.load());
  Logger::shutdown();
}

// ── T9(b): worker self-call WHILE a concurrent flush invocation is live must
//    BLOCK until the flush invocation exits (corrected inflight==1 predicate).
//    With an unconditional skip this returns early -> the assertion fails. ─────
TEST_CASE("worker self-call waits for a concurrent flush invocation to drain",
          "[logger_race][selfcall][concurrent]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto target = std::make_unique<CaptureTarget>();
  RaceCtl ctl;
  std::atomic<int> invocation{0};
  std::atomic<bool> flushExitedAtSelfClear{false};

  Logger::setExternalHandler(
    [&, t = target.get(), c = &ctl](Logger::Level, const std::string &, const std::string &)
    {
      int which = invocation.fetch_add(1);
      if (which == 0)
      {
        // Worker invocation: enter, wait for the test to proceed, then self-clear.
        t->touch();
        c->onEnter();
        c->waitReleased();
        Logger::clearExternalHandler(); // self-call: must wait inflight==1 (flush drained)
        flushExitedAtSelfClear.store(c->exitedCount() >= 1);
        c->onExit();
      }
      else
      {
        // flush invocation: a plain blocking body.
        blockingHandlerBody(t, c);
      }
    });

  Logger::info("1"); // worker -> invocation 0, enters, waits on release
  REQUIRE(ctl.waitEntered(1));

  Logger::info("2");
  std::thread flushThread([] { Logger::flush(); }); // invocation 1 (flush), blocks
  REQUIRE(ctl.waitEntered(2));                       // inflight == 2

  // Let the worker proceed to its self-clear; it must block until the flush
  // invocation exits. Release a moment later so the ordering is forced.
  ctl.releaseAll();
  flushThread.join();

  // Drain: wait for the worker's self-clear to have completed.
  for (int i = 0; i < 1000 && ctl.exitedCount() < 2; ++i)
  {
    std::this_thread::sleep_for(2ms);
  }
  CHECK(flushExitedAtSelfClear.load()); // self-call observed the flush invocation drained
  target.reset();
  Logger::shutdown();
}
