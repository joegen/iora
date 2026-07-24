// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Probe for tracker 2026-07-23-4, SCENARIO 1 (teardown destroys the sync
// primitives while a peer self-tearer is still parked/executing). At process exit
// the atexit handler (atexitReapNoDestroy -> teardownAndReapWorker) runs; pre-fix,
// ~LoggerData then destroyed data.mutex/data.cv/data.externalHandlerDone while a
// concurrent self-tearer was parked on externalHandlerDone — destroying a CV with
// a waiter / a mutex a live thread may still lock is UB. Under the fix (immortal
// getData(), tracker option C) nothing is destroyed, so the parked peer touches
// live primitives and the process exits cleanly.
//
// SHAPE (this is the (k) teardown shape, but the second participant calls
// std::exit() from INSIDE a handler instead of shutdown()):
//   * X = the WORKER invocation (the "exiter"). It parks in its handler keeping
//     itself in-flight, then calls std::exit(0). std::exit does NOT unwind
//     automatic objects, so X's HandlerInvocationScope stays alive and the atexit
//     reap runs at depth 1 on the worker thread (selfIsWorker -> detach, never a
//     self-join hang).
//   * S = a NON-worker peer thread that keeps LOCKING data.mutex by calling
//     Logger::* in a tight loop — the observable form of scenario 1's UB, "a
//     std::mutex a thread may still lock" while/after teardown destroys it.
//
// WHY AN ACTIVE MUTEX-LOCKER, NOT A SLEEPING PARKED PEER (M-1 / H-1, step-0
// iterations 2-3 — the non-vacuity crux): the literal "parked on
// externalHandlerDone" peer is a std::condition_variable waiter, i.e. a thread
// asleep in a kernel futex. Destroying (or freeing) the CV out from under it is UB,
// but the waiter never READS the freed user-space memory — it is reaped by _exit
// still asleep — so ASan cannot observe it and the probe passes vacuously (the
// case-(l) trap; empirically confirmed against the heap-delete mutant). The same UB
// class is observable with an ACTIVE peer: a thread spinning on Logger::info()
// locks data.mutex every iteration, so on a MUTANT build (getData() reverted to a
// destroyed, heap-freed singleton) its next lock after ~LoggerData frees the block
// dereferences freed memory and ASan reports a deterministic heap-use-after-free.
// On the FIXED build the mutex is immortal, so the peer spins harmlessly until the
// process exits.
//
// THE ASSERTION IS A CLEAN std::exit(0) UNDER THE ctest TIMEOUT. This probe's
// DETERMINISTIC, non-vacuous value is guarding the teardown-DEADLOCK regression
// class: if the exit-time reap ever reintroduced the circular wait this project
// spent six iterations removing (e.g. option A's depth>0 inflight==0 wait on the
// caller's own pinned frame), atexitReapNoDestroy would hang inside std::exit and
// the ctest TIMEOUT would fail this probe.
//
// NON-VACUITY AGAINST THE DESTROY MUTANT (honest note): against
// -DIORA_LOGGER_TEST_MUTANT_DESTROY + ASan this probe DOES surface the
// heap-use-after-free (S's post-free mutex lock), but only INTERMITTENTLY: X's
// std::exit(0) commits exit code 0 and _exit() races S's fault, so the ASan abort
// does not reliably win. The DESTROYED-SINGLETON UB class is therefore covered
// DETERMINISTICALLY by the sibling probe
// iora_test_logger_immortal_scenario2_static_sink_dtor (a later static destructor
// touches the freed singleton with no exit race), which shares the SAME mutant —
// so the mutant is proven to be a detectably-broken build. See the tracker
// test_requirements and the step-0 gate record for the recorded results.

#define CATCH_CONFIG_MAIN
#include "logger_race_harness.hpp"
#include <catch2/catch.hpp>

#include <iora/core/logger.hpp>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <thread>

using iora::core::Logger;
using iora::test::CtlPtr;
using iora::test::FlagPtr;
using iora::test::makeCtl;
using iora::test::makeFlag;
using namespace std::chrono_literals;

TEST_CASE("scenario 1: std::exit() from inside a handler with an external clear "
          "parked on externalHandlerDone — clean exit (immortal, no CV-with-waiter "
          "destroy)",
          "[logger][immortal][scenario1]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);

  auto xCtl = makeCtl(); // gate holding the worker invocation X before it exits

  Logger::setExternalHandler(
    [xCtl](Logger::Level, const std::string &, const std::string &)
    {
      // X: the worker invocation. Stay in-flight on the gate (so inflight never
      // reaches 0 for P below), then exit the whole process from inside the handler
      // at depth 1. Exit NON-ZERO on the release-wait timeout: if the setup broke
      // and X was never released, exiting 0 anyway would override the process exit
      // code and MASK a Catch2 failure from ctest (ts L-2).
      xCtl->onEnter();
      const bool released = xCtl->waitReleased();
      std::exit(released ? 0 : 42); // atexit -> atexitReapNoDestroy -> reap-without-destroy
    });

  Logger::info("1"); // worker delivers -> X, parks on xCtl (worker now in-flight)
  REQUIRE(xCtl->waitEntered(1));

  // S: a NON-worker peer that keeps LOCKING data.mutex via Logger::info() in a
  // tight loop. On the mutant, after ~LoggerData frees the singleton at exit, S's
  // next call dereferences freed memory -> ASan heap-use-after-free (deterministic,
  // because S is actively reading, not sleeping in a futex). On the fixed build the
  // mutex is immortal and S spins harmlessly until _exit.
  auto stop = makeFlag();
  std::thread locker(
    [stop]
    {
      while (!stop->load())
      {
        Logger::info("spin"); // locks data.mutex every iteration
      }
    });

  // Let the locker get into its steady loop before X exits.
  std::this_thread::sleep_for(100ms);

  // Never join the locker: it must still be touching data.mutex when X exits. Detach
  // so no joinable std::thread is destroyed if this frame were ever unwound (it is
  // not — std::exit does not unwind), and so main does not re-enter Catch2
  // concurrently with the exit.
  locker.detach();

  xCtl->releaseAll(); // X wakes and calls std::exit(0)

  // Block until X terminates the whole process. std::exit() does not unwind this
  // frame. If X fails to exit (a teardown deadlock or regression), the ctest
  // TIMEOUT fails this probe.
  std::this_thread::sleep_for(std::chrono::hours(1));
}
