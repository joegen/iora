// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Lifecycle + schedule/drain-TOCTOU tests for TimingWheel.
// Trackers 2026-09-10-6 (schedule/drain orphan) and 2026-09-10-7 (lifecycle
// transition guards). Built with IORA_TIMING_WHEEL_TEST_HOOKS so the header's
// _testScheduleGate / testAdvanceCount() seams exist.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/core/timing_wheel.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <future>
#include <memory>
#include <thread>
#include <vector>

using namespace iora::core;
using namespace std::chrono_literals;

namespace
{
  // Run `fn` on a worker; if it does not finish within `bound` a deadlock
  // regression exists — ABORT with a diagnostic. We must NOT detach-and-return:
  // `fn` captures caller-scope locals (the wheel under test, promises, atomics)
  // by reference, so letting the TEST_CASE unwind and destroy them while the
  // hung worker still runs inside them is a use-after-free (thread-safety L-1).
  // std::abort() is the deterministic hard failure the harness reports (and it
  // never fires on a passing run — the worker joins and returns normally).
  template <typename Fn>
  void runBounded(Fn&& fn, std::chrono::milliseconds bound)
  {
    auto done = std::make_shared<std::atomic<bool>>(false);
    std::thread worker([done, fn = std::forward<Fn>(fn)]() mutable
    {
      fn();
      done->store(true);
    });
    auto deadline = std::chrono::steady_clock::now() + bound;
    while (!done->load() && std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::sleep_for(5ms);
    }
    if (done->load())
    {
      worker.join();
      return;
    }
    std::fprintf(stderr,
      "runBounded: deadlock regression — worker exceeded %lld ms; aborting\n",
      static_cast<long long>(bound.count()));
    std::fflush(stderr);
    std::abort(); // deterministic hard failure; no UAF from a detached worker
  }

  // An inline dispatcher (fires on the calling thread) — the Dispatcher-set
  // firing path that the -6 tests[] require alongside direct-fire.
  TimingWheel::Dispatcher inlineDispatcher()
  {
    return [](TimingWheel::Callback cb) { cb(); };
  }

  // -6 deterministic orphan probe (shared by the drain and stop paths, both
  // dispatcher configs). Parks a schedule() in the post-accept-check /
  // pre-_wheelMutex window via _testScheduleGate, runs `quiesce` while it is
  // parked, then releases it: the re-check under _wheelMutex must observe
  // _accepting==false and decline (no orphan).
  void runOrphanSeam(const std::function<void(TimingWheel&)>& quiesce,
                     TimingWheel::Dispatcher dispatcher)
  {
    TimingWheel tw(2000ms, 16, 2, std::move(dispatcher)); // slow tick: no interference
    tw.start();

    std::promise<void> reached;
    std::promise<void> release;
    auto reachedFut = reached.get_future(); // retrieved BEFORE the setter thread
    auto releaseFut = release.get_future();
    std::atomic<bool> reachedSet{false};
    tw._testScheduleGate = [&]()
    {
      if (!reachedSet.exchange(true)) { reached.set_value(); }
      releaseFut.wait();
    };

    std::atomic<TimerId> got{static_cast<TimerId>(-1)};
    std::thread t([&]() { got.store(tw.schedule(10ms, []() {})); });

    reachedFut.wait();  // schedule() is parked in the window
    quiesce(tw);         // collect+clear while it is parked
    release.set_value(); // now let it take _wheelMutex and re-check
    t.join();
    tw._testScheduleGate = nullptr; // clear only after the parked thread exited

    CHECK(got.load() == InvalidTimerId); // pre-fix: a valid id (orphan)
    CHECK(tw.pendingCount() == 0);        // pre-fix: an orphan leaves 1
  }

  // -6 orphan accounting under stress (both dispatcher configs). Whatever the
  // interleaving of schedule() vs `quiesce`, the wheel is fully drained: no
  // orphan survives and every returned id is accounted valid-or-invalid.
  void runOrphanStress(const std::function<void(TimingWheel&)>& quiesce,
                       TimingWheel::Dispatcher dispatcher)
  {
    TimingWheel tw(5ms, 64, 2, std::move(dispatcher));
    tw.start();

    std::atomic<int> valid{0};
    std::atomic<int> invalid{0};
    std::atomic<bool> go{false};
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t)
    {
      threads.emplace_back([&]()
      {
        while (!go.load()) { std::this_thread::yield(); }
        for (int i = 0; i < 500; ++i)
        {
          auto id = tw.schedule(std::chrono::milliseconds(1 + (i % 20)), []() {});
          (id == InvalidTimerId ? invalid : valid).fetch_add(1);
        }
      });
    }
    go.store(true);
    std::this_thread::sleep_for(3ms);
    quiesce(tw);
    for (auto& t : threads) { t.join(); }

    CHECK(tw.pendingCount() == 0);
    CHECK(valid.load() + invalid.load() == 4 * 500);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// -6: schedule/drain(stop) TOCTOU orphan — deterministic seam-driven
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TWL: schedule declined after drain collection leaves no orphan (-6)",
          "[timing_wheel][lifecycle][orphan]")
{
  SECTION("direct-fire")
  {
    runOrphanSeam([](TimingWheel& w) { w.drain(5000ms); }, nullptr);
  }
  SECTION("dispatcher-set")
  {
    runOrphanSeam([](TimingWheel& w) { w.drain(5000ms); }, inlineDispatcher());
  }
}

TEST_CASE("TWL: schedule declined after stop collection leaves no orphan (-6)",
          "[timing_wheel][lifecycle][orphan]")
{
  SECTION("direct-fire")
  {
    runOrphanSeam([](TimingWheel& w) { w.stop(); }, nullptr);
  }
  SECTION("dispatcher-set")
  {
    runOrphanSeam([](TimingWheel& w) { w.stop(); }, inlineDispatcher());
  }
}

TEST_CASE("TWL: schedule that wins the lock first is collected, not dropped (-6)",
          "[timing_wheel][lifecycle][orphan]")
{
  TimingWheel tw(2000ms, 16, 2);
  tw.start();
  auto id = tw.schedule(5ms, []() {});
  REQUIRE(id != InvalidTimerId);
  std::this_thread::sleep_for(10ms); // deadline passes -> drain fires it
  auto stats = tw.drain(5000ms);
  CHECK(stats.fired == 1);
  CHECK(tw.pendingCount() == 0);
}

TEST_CASE("TWL: no false rejection while RUNNING (-6 re-check does not over-reject)",
          "[timing_wheel][lifecycle][orphan]")
{
  TimingWheel tw(2000ms, 16, 2);
  tw.start();
  for (int i = 0; i < 200; ++i)
  {
    CHECK(tw.schedule(50ms, []() {}) != InvalidTimerId);
  }
  tw.stop();
}

TEST_CASE("TWL: schedule vs drain accounting — no orphan under stress (-6)",
          "[timing_wheel][lifecycle][orphan][stress]")
{
  SECTION("direct-fire") { runOrphanStress([](TimingWheel& w) { w.drain(5000ms); }, nullptr); }
  SECTION("dispatcher-set")
  {
    runOrphanStress([](TimingWheel& w) { w.drain(5000ms); }, inlineDispatcher());
  }
}

TEST_CASE("TWL: schedule vs stop accounting — no orphan under stress (-6)",
          "[timing_wheel][lifecycle][orphan][stress]")
{
  SECTION("direct-fire") { runOrphanStress([](TimingWheel& w) { w.stop(); }, nullptr); }
  SECTION("dispatcher-set")
  {
    runOrphanStress([](TimingWheel& w) { w.stop(); }, inlineDispatcher());
  }
}

TEST_CASE("TWL: stale in-flight id across restart does not alias or leak (H-1)",
          "[timing_wheel][lifecycle][orphan]")
{
  // A schedule() fetches its id BEFORE the lock, then is parked across a full
  // stop()->reset()->start() restart. Post-restart schedules must NOT re-issue
  // that id: with the fixed monotonic _nextId there is no collision, the parked
  // entry stays reachable in _entryMap and is freed on stop(). Under the bug
  // (_nextId.store(1) in reset), a post-restart schedule re-issues the parked id
  // -> _entryMap overwrite -> the parked entry (holding `sentinel`) is orphaned
  // in its bucket and LEAKS on stop() (collectAllEntries frees map-reachable
  // entries only). We detect that leak via a weak_ptr: it must expire.
  auto sentinel = std::make_shared<int>(0);
  std::weak_ptr<int> weak = sentinel;

  runBounded([&]()
  {
    TimingWheel tw(2000ms, 16, 2);
    tw.start();

    std::promise<void> reached;
    std::promise<void> release;
    auto reachedFut = reached.get_future();
    auto releaseFut = release.get_future();
    std::atomic<bool> reachedSet{false};
    tw._testScheduleGate = [&]()
    {
      if (!reachedSet.exchange(true)) { reached.set_value(); }
      releaseFut.wait();
    };

    // The parked callback captures `sentinel` BY VALUE.
    std::thread t([&]() { tw.schedule(50ms, [sentinel]() {}); });
    reachedFut.wait();

    tw.stop();
    tw.reset();
    tw.start();
    release.set_value();
    t.join();
    // Clear the gate ONLY after the parked thread has fully exited it — a
    // reassignment while it is still executing the std::function would be a race
    // (destroying a live callable). Post-join, no thread is in the gate.
    tw._testScheduleGate = nullptr;

    // Post-restart schedules. Under the bug the first of these re-issues the
    // parked id (counter reset to 1) and overwrites its _entryMap slot.
    for (int i = 0; i < 100; ++i) { tw.schedule(60000ms, []() {}); }

    tw.stop(); // frees _entryMap-reachable entries; an orphaned bucket node leaks
  }, 10s);

  sentinel.reset();
  CHECK(weak.expired()); // pre-fix: leaked parked callback keeps `sentinel` alive
}

// ══════════════════════════════════════════════════════════════════════════════
// -7: lifecycle transition guards
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TWL: drain terminal CAS does not clobber a concurrent reset (R10)",
          "[timing_wheel][lifecycle]")
{
  std::atomic<int> finalState{-1};
  std::atomic<bool> restartOk{false};

  // Bounded: a regression that re-held _lifecycleMutex across drain's fire loop
  // would block the concurrent stop() forever — FAIL, not hang.
  runBounded([&]()
  {
    TimingWheel tw(2000ms, 16, 2);
    tw.start();

    std::promise<void> inCallback;
    std::promise<void> releaseCallback;
    auto inFut = inCallback.get_future();
    auto releaseFut = releaseCallback.get_future();
    std::atomic<bool> inSet{false};
    tw.schedule(5ms, [&]()
    {
      if (!inSet.exchange(true)) { inCallback.set_value(); }
      releaseFut.wait();
    });
    std::this_thread::sleep_for(10ms); // deadline passes

    std::thread drainer([&]() { tw.drain(60000ms); });
    inFut.wait(); // drain is in the fire loop; _lifecycleMutex freed

    // Separate application thread (NOT a callback): stop() then reset() during
    // the fire window. Legal — drain released _lifecycleMutex before firing.
    tw.stop();
    tw.reset();

    releaseCallback.set_value();
    drainer.join();

    // R10: drain's terminal CAS(expected=DRAINING) fails against RESET.
    finalState.store(static_cast<int>(tw.getState()));
    tw.start(); // and the wheel is restartable
    restartOk.store(tw.getState() == TimingWheelState::RUNNING &&
                    tw.schedule(50ms, []() {}) != InvalidTimerId);
    tw.stop();
  }, 15s);

  CHECK(finalState.load() == static_cast<int>(TimingWheelState::RESET));
  CHECK(restartOk.load());
}

TEST_CASE("TWL: reentrant reset() from a drain fire-loop callback no-ops, no deadlock (R4)",
          "[timing_wheel][lifecycle]")
{
  auto run = [](TimingWheel::Dispatcher dispatcher)
  {
    std::atomic<bool> reentered{false};
    std::atomic<int> finalState{-1};
    // Bounded: a regression re-holding _lifecycleMutex across firing would make
    // the reentrant reset() self-deadlock -> FAIL, not hang.
    runBounded([&]()
    {
      TimingWheel tw(2000ms, 16, 2, dispatcher);
      tw.start();
      tw.schedule(5ms, [&]()
      {
        tw.reset(); // state==DRAINING -> CAS fails -> no-op, no deadlock
        reentered.store(true);
      });
      std::this_thread::sleep_for(10ms);
      tw.drain(5000ms);
      finalState.store(static_cast<int>(tw.getState()));
    }, 10s);
    CHECK(reentered.load());
    CHECK(finalState.load() == static_cast<int>(TimingWheelState::STOPPED));
  };

  SECTION("direct-fire") { run(nullptr); }
  SECTION("dispatcher-set") { run(inlineDispatcher()); }
}

TEST_CASE("TWL: a collected callback's dtor may call a lifecycle method during stop (M-1)",
          "[timing_wheel][lifecycle]")
{
  // A captured-resource destructor that re-enters a lifecycle method must not
  // self-deadlock — stop() releases _lifecycleMutex BEFORE destroying collected
  // callbacks. Bounded so the pre-fix (mutex-held-across-destruction) deadlock
  // becomes a FAIL, not a harness hang.
  struct ReentrantDtor
  {
    TimingWheel* tw;
    std::shared_ptr<std::atomic<bool>> flag;
    ~ReentrantDtor()
    {
      if (tw) { tw->stop(); flag->store(true); } // idempotent stop from a dtor
    }
  };

  auto flag = std::make_shared<std::atomic<bool>>(false);
  runBounded([&]()
  {
    TimingWheel tw(2000ms, 16, 2);
    tw.start();
    auto res = std::make_shared<ReentrantDtor>();
    res->tw = &tw;
    res->flag = flag;
    tw.schedule(60000ms, [res]() {}); // future timer; res captured BY VALUE
    res.reset();                       // wheel now holds the only ref
    tw.stop();                         // collect -> release lock -> destroy -> dtor runs
  }, 5s);

  CHECK(flag->load());       // the reentrant dtor actually ran
}

TEST_CASE("TWL: sequential stop then destroy is clean (R6)",
          "[timing_wheel][lifecycle]")
{
  runBounded([]()
  {
    TimingWheel tw(5ms, 16, 2);
    tw.start();
    tw.schedule(10ms, []() {});
    tw.stop();
    // tw destroyed at scope end: no double-join, no zombie, no leak.
  }, 5s);
}

TEST_CASE("TWL: restart cycle joins each tick thread — no zombie (R6 regression)",
          "[timing_wheel][lifecycle]")
{
  // start->stop->reset->start->stop->reset. reset() is INTERPOSED because
  // start() only accepts CREATED/RESET (no STOPPED->RUNNING edge, R11). The
  // advance-counter must resume after each start and FREEZE after each stop; a
  // once_flag-guarded teardown (the dropped mis-fix) would leave the 2nd thread
  // advancing after the 2nd stop -> the frozen-count assertions FAIL.
  TimingWheel tw(5ms, 16, 2);

  auto waitAdvance = [&](std::uint64_t from)
  {
    auto deadline = std::chrono::steady_clock::now() + 1s;
    while (tw.testAdvanceCount() <= from &&
           std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::sleep_for(5ms);
    }
    return tw.testAdvanceCount();
  };

  tw.start();
  auto c1 = waitAdvance(0);
  CHECK(c1 > 0);
  tw.stop();
  auto frozen1 = tw.testAdvanceCount();
  std::this_thread::sleep_for(40ms);
  CHECK(tw.testAdvanceCount() == frozen1); // 1st thread truly stopped

  tw.reset();
  tw.start();
  auto c2 = waitAdvance(frozen1);
  CHECK(c2 > frozen1);                      // a DISTINCT 2nd tick thread advancing
  tw.stop();
  auto frozen2 = tw.testAdvanceCount();
  std::this_thread::sleep_for(40ms);
  CHECK(tw.testAdvanceCount() == frozen2);  // 2nd thread truly stopped (no zombie)

  tw.reset();
}

TEST_CASE("TWL: concurrent lifecycle stress — no thread-object race, no zombie",
          "[timing_wheel][lifecycle][stress]")
{
  runBounded([]()
  {
    TimingWheel tw(3ms, 16, 2);
    std::atomic<bool> go{false};
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t)
    {
      threads.emplace_back([&]()
      {
        while (!go.load()) { std::this_thread::yield(); }
        for (int i = 0; i < 200; ++i)
        {
          switch (i % 4)
          {
            case 0: tw.start(); break;
            case 1: tw.stop(); break;
            case 2: tw.drain(1000ms); break;
            case 3: tw.reset(); break;
          }
        }
      });
    }
    go.store(true);
    for (auto& t : threads) { t.join(); }

    tw.stop();
    auto c = tw.testAdvanceCount();
    std::this_thread::sleep_for(40ms);
    CHECK(tw.testAdvanceCount() == c);
    CHECK(tw.getState() == TimingWheelState::STOPPED);
  }, 15s);
}

TEST_CASE("TWL: two threads racing stop()/drain() do not race the tick thread",
          "[timing_wheel][lifecycle][stress]")
{
  runBounded([]()
  {
    for (int rep = 0; rep < 50; ++rep)
    {
      TimingWheel tw(3ms, 16, 2);
      tw.start();
      for (int i = 0; i < 10; ++i) { tw.schedule(5ms, []() {}); }
      std::thread a([&]() { tw.stop(); });
      std::thread b([&]() { tw.drain(1000ms); });
      a.join();
      b.join();
      CHECK(tw.getState() == TimingWheelState::STOPPED);
    }
  }, 20s);
}

TEST_CASE("TWL: schedule vs full lifecycle (start revives accepting) — no orphan (-6/-7)",
          "[timing_wheel][lifecycle][orphan][stress]")
{
  auto run = [](TimingWheel::Dispatcher dispatcher)
  {
    runBounded([&]()
    {
      TimingWheel tw(5ms, 64, 2, dispatcher);
      tw.start();
      std::atomic<bool> go{false};
      std::vector<std::thread> threads;

      for (int t = 0; t < 3; ++t)
      {
        threads.emplace_back([&]()
        {
          while (!go.load()) { std::this_thread::yield(); }
          for (int i = 0; i < 400; ++i)
          {
            tw.schedule(std::chrono::milliseconds(1 + (i % 15)), []() {});
          }
        });
      }
      threads.emplace_back([&]()
      {
        while (!go.load()) { std::this_thread::yield(); }
        for (int i = 0; i < 100; ++i)
        {
          tw.drain(500ms);
          tw.reset();
          tw.start();
        }
      });

      go.store(true);
      for (auto& t : threads) { t.join(); }
      tw.stop();
      CHECK(tw.pendingCount() == 0); // no orphan survived, whatever the interleaving
    }, 20s);
  };

  SECTION("direct-fire") { run(nullptr); }
  SECTION("dispatcher-set") { run(inlineDispatcher()); }
}
