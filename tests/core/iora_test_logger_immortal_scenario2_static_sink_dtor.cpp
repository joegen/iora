// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Probe for tracker 2026-07-23-4, SCENARIO 2 (destroyed-singleton access from a
// later static destructor). This is a static-destruction-ORDER bug with NO
// concurrency, no handler dispatch, and no std::exit(): a namespace-scope static
// sink that does NOT touch the logger during its own construction completes
// construction BEFORE Logger::getData()'s LoggerData (which is first constructed
// only when the test logs from main()). [basic.start.term] then destroys
// LoggerData FIRST; the sink's destructor — running LATER — calls
// Logger::clearExternalHandler() (the guide's own recommended teardown, §4.2),
// which re-enters getData(). Pre-fix (Meyers singleton) that returns a reference
// to a DESTROYED function-local static and locks a destroyed std::mutex — UB.
// Under the fix (immortal getData(), tracker option C) getData() returns a
// live singleton and the sink destructor is safe.
//
// THE ASSERTION IS A CLEAN PROCESS EXIT. There is no in-test REQUIRE that can
// observe the bug: the sink's destructor runs during static destruction, AFTER
// Catch2's main() returns. The probe therefore asserts nothing at run time beyond
// "we logged"; the real gate is that the process exits 0 within the ctest TIMEOUT.
//
// NON-VACUITY (H-1): a "clean exit under a timeout + ASan" check passes under BOTH
// the fixed and the buggy build, because ASan does NOT poison a function-local
// static's storage after its destructor runs (the bytes stay addressable) and the
// process exits regardless. The deterministic discriminator is a MUTANT build that
// reverts getData() to a DESTROYED form and, ideally, poisons the object so the
// post-destruction lock is a hard failure. This probe is validated against such a
// mutant during implementation; see the tracker's test_requirements and the
// step-0 gate record. (The "sink that logs in its constructor" sibling — the old
// "safe direction" — is intentionally NOT included: under the immortal fix nothing
// is destroyed, so it discriminates nothing and must not be counted as coverage,
// per L-1.)

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/core/logger.hpp>

using iora::core::Logger;

namespace
{
// Namespace-scope static sink. Constructed during static INITIALIZATION and
// DELIBERATELY does not touch the logger in its constructor, so LoggerData's
// construction completes AFTER this object's — making LoggerData the first to be
// destroyed. The destructor runs the documented teardown (clearExternalHandler),
// re-entering getData() during static destruction: the exact scenario-2 path.
struct StaticSink
{
  StaticSink() = default; // MUST NOT log / touch the logger here (see above)
  ~StaticSink() { Logger::clearExternalHandler(); }
};

// This is the object whose destructor exercises the bug. Its storage duration is
// static; nothing here logs until main() runs.
StaticSink g_staticSink;
} // namespace

TEST_CASE("scenario 2: static sink clears the handler in its destructor after "
          "LoggerData — clean exit (immortal getData)",
          "[logger][immortal][scenario2]")
{
  // First logger touch happens HERE, in main(), so LoggerData is constructed
  // after g_staticSink and is therefore destroyed before it.
  Logger::init(Logger::Level::Info, "", /*async=*/false);
  Logger::setExternalHandler(
    [](Logger::Level, const std::string &, const std::string &) {});
  Logger::info("touch the logger from main so LoggerData constructs after the sink");

  // The real test is the clean exit during static destruction, when
  // g_staticSink.~StaticSink() calls clearExternalHandler(). Nothing to assert at
  // run time; SUCCEED documents intent and keeps Catch2 happy.
  SUCCEED("logged from main; the discriminating event is static destruction");
}

// SHUTDOWN-THEN-EXIT probe (L-9): an explicit Logger::shutdown() followed by the
// atexit reap (which runs when this executable exits) must not hang or double-flush.
// The double-reap is safe by the existing double-shutdown hardening (case (m): gate
// already null, inflight==0, workerRunning==false -> waitForWorkerExitLocked returns
// immediately), but the shutdown()+atexit-reap caller pairing is new under option C.
// The assertion is a clean exit under the ctest TIMEOUT (the atexit reap runs after
// this returns, on top of the already-completed shutdown()).
TEST_CASE("shutdown() then process exit: atexit reap after an explicit shutdown does "
          "not hang or double-flush",
          "[logger][immortal][shutdown_then_exit]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  Logger::setExternalHandler(
    [](Logger::Level, const std::string &, const std::string &) {});
  Logger::info("before explicit shutdown");
  Logger::shutdown(); // explicit teardown; the atexit reap will run again at exit
  SUCCEED("explicit shutdown returned; the atexit reap must also complete at exit");
}
