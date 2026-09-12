// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// reset()-while-RUNNING under NDEBUG (tracker 2026-09-10-7 T4/R1). This TU is
// built with -DNDEBUG so the former debug-only precondition assert is compiled
// out: the fix must reject a non-STOPPED reset via a runtime CAS (silent no-op),
// NOT rely on assert(). We assert the LOGICAL invariant (reset had no effect,
// pending timers intact) — NOT memory-cleanliness (per the corrected T4 trace a
// clean ASan/TSan run would be vacuous here). The CMake target also runs this
// under ASan/TSan as belt-and-suspenders.

#ifndef NDEBUG
#error "This TU must be compiled with -DNDEBUG (see tests/CMakeLists.txt)."
#endif

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/core/timing_wheel.hpp>

#include <atomic>
#include <chrono>
#include <thread>

using namespace iora::core;
using namespace std::chrono_literals;

TEST_CASE("TW-reset-ndebug: reset() while RUNNING no-ops and does not corrupt state",
          "[timing_wheel][lifecycle][reset]")
{
  TimingWheel tw(5ms, 16, 2);
  tw.start();
  REQUIRE(tw.getState() == TimingWheelState::RUNNING);

  // Live timers present while the tick thread runs.
  std::atomic<int> fired{0};
  for (int i = 0; i < 5; ++i)
  {
    tw.schedule(100ms, [&]() { fired.fetch_add(1); });
  }
  REQUIRE(tw.pendingCount() == 5);

  // reset() from RUNNING must be rejected (silent no-op) — the CAS expects
  // STOPPED. Under NDEBUG there is no assert to abort; the fix's CAS is the guard.
  tw.reset();

  // LOGICAL invariant: nothing changed. State still RUNNING, timers still queued.
  CHECK(tw.getState() == TimingWheelState::RUNNING);
  CHECK(tw.pendingCount() == 5);

  // And the wheel is still functional: the live timers fire.
  std::this_thread::sleep_for(200ms);
  tw.stop();
  CHECK(fired.load() == 5);
}

TEST_CASE("TW-reset-ndebug: reset() from STOPPED still works under NDEBUG",
          "[timing_wheel][lifecycle][reset]")
{
  TimingWheel tw(5ms, 16, 2);
  tw.start();
  tw.stop();
  REQUIRE(tw.getState() == TimingWheelState::STOPPED);
  tw.reset(); // legal transition
  CHECK(tw.getState() == TimingWheelState::RESET);
  tw.start(); // RESET -> RUNNING
  CHECK(tw.getState() == TimingWheelState::RUNNING);
  tw.stop();
}
