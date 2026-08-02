// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.
//
// tracker 2026-07-26-2 PHASE 3 task-3.2 — self-destruct detection, and its
// per-Impl-isolation negative.
//
// Destroying a JsonRpcClient from INSIDE its own callback is a guaranteed
// permanent block: that worker thread's OwnerScope is registered in _owners and
// cannot be removed until the callback returns, while the destructor waits for
// exactly that. The quiesce STEP-1 latch detects it (this_thread in _owners) and
// calls std::terminate() with a fatal diagnostic — the honest analogue of
// Transport::stop() throwing for the isomorphic I/O-thread case (a destructor
// cannot throw). This is the ONLY std::terminate in the design, and _owners is
// per-Impl, so destroying a DIFFERENT client from inside a callback must NOT
// terminate.
//
// A std::terminate takes down the whole process, so this cannot live in the
// shared Catch2 pool binary — it is a STANDALONE executable with two scenarios
// selected by argv[1], each registered as a ctest expecting exit 0:
//   * "selfdestruct" (default): destroy the OWN client from its callback ->
//     terminate EXPECTED. set_terminate handler _Exit(0) = PASS; reaching the
//     end without terminating (detection regressed) -> return 1.
//   * "configurer" (PHASE 6, task-6.4b(y)): destroy the client from inside the
//     httpClientConfigurer, which since phase 6 runs on the CALLING thread in
//     acquire_'s unlocked construction window -> terminate EXPECTED.
//   * "otherclient": destroy a DIFFERENT idle client (sharing the ThreadPool)
//     from the first client's callback -> terminate FORBIDDEN. Reaching the end
//     cleanly -> return 0 = PASS; a terminate -> handler _Exit(3) = FAIL.
//
// The reset ordering is made DETERMINISTIC (cpp17 LOW-1): the callback waits on
// an atomic that main sets only AFTER dropping its own reference, so the
// callback's captured reference is provably the last one and ~JsonRpcClient runs
// on the worker (self-destruct scenario) — never on main.

#include "iora/iora.hpp"

#include "jsonrpc_client.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <future>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

using iora::modules::connectors::Config;
using iora::modules::connectors::JsonRpcClient;

namespace
{
// Whether a std::terminate is the EXPECTED outcome for the selected scenario.
// selfdestruct -> true (terminate == success, _Exit(0)); otherclient -> false
// (terminate == failure, _Exit(3)).
std::atomic<bool> g_expectTerminate{true};

// WHERE the scenario was when a terminate fired (cpp17 L-6). Without this the
// handler _Exit(0)s on ANY terminate — an uncaught exception, a throwing
// destructor, a terminate from a completely different subsystem — so a scenario
// could "pass" for a reason unrelated to what it tests. Each scenario sets this
// immediately before the reset that must terminate and clears it immediately
// after, and the handler echoes it; the ctest registrations then match on the
// specific stage via PASS_REGULAR_EXPRESSION, so a terminate from anywhere else
// carries the wrong stage and the test fails.
std::atomic<const char *> g_stage{"none"};

/// \brief Sets the stage for the duration of a scope, restoring "none" on exit
/// (only reached when the expected terminate did NOT fire).
struct StageScope
{
  explicit StageScope(const char *s) { g_stage.store(s); }
  ~StageScope() { g_stage.store("none"); }
};

iora::IoraService &testService()
{
  static bool initialized = false;
  if (!initialized)
  {
    iora::IoraService::Config config;
    config.features.server = false;
    config.log.file = "jsonrpc_quiesce_selfdestruct_test";
    config.log.level = "info";
    config.modules.autoLoad = false;
    iora::IoraService::init(config);
    initialized = true;
  }
  return iora::IoraService::instanceRef();
}

Config stubConfig()
{
  Config cfg;
  cfg.httpClientFactory = [](const std::string &)
  { return std::make_unique<iora::network::HttpClient>(); };
  cfg.maxRetries = 0; // fail fast so onError fires promptly on the worker
  return cfg;
}

// Positive: destroy the OWN client from inside its own onError. The worker is in
// this client's _owners, so quiesce STEP-1 must terminate.
int runSelfDestruct(iora::IoraService &svc)
{
  iora::core::ThreadPool pool(/*initial*/ 1, /*max*/ 1, std::chrono::seconds(1));
  auto client = std::make_shared<JsonRpcClient>(svc, pool, stubConfig());

  std::atomic<bool> mainDidReset{false};
  client->callAsync(
    "http://127.0.0.1:1/rpc", "ping", iora::parsers::Json::object(), {}, [](iora::parsers::Json) {},
    [client, &mainDidReset](std::exception_ptr) mutable
    {
      // Wait until main has dropped its reference so THIS captured copy is the
      // last one — then ~JsonRpcClient runs here, on the worker (in _owners).
      while (!mainDidReset.load())
      {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
      StageScope stage("own-callback");
      client.reset(); // destroy the client from inside its own callback
    });

  client.reset();           // drop main's reference (callback's copy remains)
  mainDidReset.store(true); // release the callback to destroy the last reference

  std::this_thread::sleep_for(std::chrono::seconds(3));
  std::cerr << "[selfdestruct] FAILURE: reached end without terminating "
               "(self-destruct detection regressed)\n";
  return 1;
}

// Positive (TS-5): self-destruct on the SYNCHRONOUS enqueue-failure delivery
// path. With the pool queue full, callAsync's enqueue throws and onError runs
// synchronously on THIS (the caller) thread; if that onError destroys the
// client, quiesce STEP-1 must detect the caller in _owners (the callAsync
// OwnerScope) and terminate — rather than deadlocking STEP-3 forever on a
// still-counted token pinned in the caller's frame.
int runEnqueueFailSelfDestruct(iora::IoraService &svc)
{
  // Queue cap 1; occupy the sole worker and fill the one slot so callAsync's
  // enqueue throws "task queue is full". The blocker parks forever — the process
  // terminates on success (_Exit), so the leaked wait is harmless; on the failure
  // path we release it below so ~ThreadPool can join.
  // Declared before `pool` so they outlive ~ThreadPool's worker join on the
  // (failure) path where we do not terminate.
  std::promise<void> blockerGate;
  std::future<void> blockerF = blockerGate.get_future();
  std::atomic<bool> blockerStarted{false};

  iora::core::ThreadPool pool(/*initial*/ 1, /*max*/ 1, std::chrono::seconds(1),
                              /*maxQueueSize*/ 1);
  auto client = std::make_shared<JsonRpcClient>(svc, pool, stubConfig());

  pool.enqueue(
    [&blockerStarted, &blockerF]()
    {
      blockerStarted.store(true);
      blockerF.wait();
    });
  while (!blockerStarted.load())
  {
    std::this_thread::yield();
  }
  pool.enqueue([]() {}); // fills the one queue slot

  JsonRpcClient *raw = client.get();
  // Move the ONLY facade reference into onError's capture, so its reset() inside
  // the synchronous enqueue-failure delivery is the LAST ref -> ~JsonRpcClient
  // runs here (the caller thread, registered as an owner by callAsync) -> STEP-1
  // terminate.
  raw->callAsync("http://unit.test/rpc", "ping", iora::parsers::Json::object(), {},
                 [](iora::parsers::Json) {},
                 [c = std::move(client)](std::exception_ptr) mutable
                 {
                   StageScope stage("enqueue-failure-delivery");
                   c.reset();
                 });

  // Only reached if detection regressed (no terminate). Release the blocker so
  // ~ThreadPool does not hang, then report failure.
  std::cerr << "[enqfail] FAILURE: reached end without terminating "
               "(synchronous-delivery self-destruct not detected — TS-5 regressed)\n";
  blockerGate.set_value();
  return 1;
}

// Positive (PHASE 6, task-6.4b case (y)) — a NEW self-destruct vector the CR-3
// fix creates, distinct from the onSuccess/onError site above. Since phase 6 the
// user httpClientConfigurer runs on the CALLING thread inside acquire_'s
// unlocked construction window, and call() has already registered that thread in
// _owners (its OwnerScope spans acquire_). So a configurer that drops the last
// reference to the client destroys it from INSIDE its own counted work: quiesce
// STEP-1 must detect this_thread in _owners and terminate, rather than STEP-3
// deadlocking on an _inFlight count only this thread can release.
//
// NAMED MUTATION: remove the calling-thread OwnerScope from call() -> the
// configurer's self-destruct goes undetected by STEP 1 and STEP 3 deadlocks (the
// destroying thread waits on its own still-counted call), so this scenario hangs
// to its ctest TIMEOUT instead of exiting 0.
//
// HOW THIS SCENARIO ACTUALLY FAILS (cpp17 L-6). Unlike `selfdestruct` — where
// the destroying thread is a worker and MAIN is still free to sleep and return 1
// — the destruction here happens INSIDE this frame's own call(). So a regression
// does NOT reach the `return 1` below: STEP 3 deadlocks in the configurer and the
// scenario hangs to the ctest TIMEOUT. The trailing return/diagnostic is
// therefore unreachable-on-regression and is kept only as a backstop for a
// hypothetical failure mode that skips the destruction entirely.
// That makes the exit code alone uninformative in the OTHER direction too: any
// terminate at all would exit 0. The ctest registration adds
// PASS_REGULAR_EXPRESSION on `stage=configurer-window`, so exiting 0 counts as a
// pass only when the terminate fired during the reset inside the window.
int runConfigurerSelfDestruct(iora::IoraService &svc)
{
  iora::core::ThreadPool pool(/*initial*/ 1, /*max*/ 1, std::chrono::seconds(1));

  // The SOLE facade reference. The configurer drops it while the construction
  // window is open, so ~JsonRpcClient runs on this thread, nested inside call().
  std::shared_ptr<JsonRpcClient> holder;
  Config cfg = stubConfig();
  cfg.httpClientConfigurer = [&holder](const std::string &, iora::network::HttpClient &)
  {
    StageScope stage("configurer-window");
    holder.reset();
  };

  holder = std::make_shared<JsonRpcClient>(svc, pool, cfg);
  JsonRpcClient *raw = holder.get();
  try
  {
    // Counted + owner-registered. acquire_ reserves, unlocks, and runs the
    // configurer above — which destroys the client from inside this frame.
    (void)raw->call("http://127.0.0.1:1/rpc", "ping");
  }
  catch (const std::exception &)
  {
    // Only reachable if the destruction did not terminate as it must.
  }

  std::cerr << "[configurer] FAILURE: reached end without terminating (a configurer "
               "self-destruct inside the construction window went undetected)\n";
  return 1;
}

// Negative: destroy a DIFFERENT idle client (sharing the ThreadPool) from inside
// the first client's onError. The worker is in the FIRST client's _owners, not
// the second's, so destroying the second must NOT terminate.
int runOtherClient(iora::IoraService &svc)
{
  iora::core::ThreadPool pool(/*initial*/ 1, /*max*/ 1, std::chrono::seconds(1));
  JsonRpcClient first(svc, pool, stubConfig());           // active; destroyed by main at end
  auto second = std::make_shared<JsonRpcClient>(svc, pool, stubConfig()); // idle, shares the pool

  std::atomic<bool> mainDidReset{false};
  std::atomic<bool> callbackDone{false};
  first.callAsync(
    "http://127.0.0.1:1/rpc", "ping", iora::parsers::Json::object(), {}, [](iora::parsers::Json) {},
    [second, &mainDidReset, &callbackDone](std::exception_ptr) mutable
    {
      while (!mainDidReset.load())
      {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
      second.reset(); // destroy the OTHER (idle) client from inside first's callback
      callbackDone.store(true);
    });

  second.reset();           // drop main's ref to the second client (callback holds the last)
  mainDidReset.store(true); // release the callback to destroy the second client

  // Wait for the callback to finish destroying the second client. If per-Impl
  // isolation regressed, quiesce would have terminated already (g_expectTerminate
  // is false here, so the handler would _Exit(3)).
  for (int i = 0; i < 3000 && !callbackDone.load(); ++i)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  if (!callbackDone.load())
  {
    std::cerr << "[otherclient] FAILURE: callback did not complete\n";
    return 4;
  }
  std::cerr << "[otherclient] destroyed a different idle client from a callback "
               "without terminating (per-Impl isolation holds)\n";
  return 0; // `first` quiesces cleanly here on main (drained, main not an owner)
}
} // namespace

int main(int argc, char **argv)
{
  const std::string scenario = argc > 1 ? argv[1] : "selfdestruct";
  const bool otherClient = (scenario == "otherclient");
  g_expectTerminate.store(!otherClient); // every scenario but otherclient expects terminate

  std::set_terminate(
    []()
    {
      if (g_expectTerminate.load())
      {
        std::cerr << "[quiesce-selfdestruct] std::terminate reached as expected "
                     "(self-destruct detected) stage="
                  << g_stage.load() << "\n";
        std::_Exit(0); // PASS: terminate was the expected outcome AT THIS STAGE
      }
      std::cerr << "[quiesce-selfdestruct] FAILURE: std::terminate fired when it must NOT "
                   "(per-Impl _owners isolation regressed)\n";
      std::_Exit(3); // FAIL: terminate must not fire in the otherclient scenario
    });

  try
  {
    auto &svc = testService();
    iora::IoraService::AutoServiceShutdown autoShutdown(svc);
    if (scenario == "otherclient")
    {
      return runOtherClient(svc);
    }
    if (scenario == "enqfail")
    {
      return runEnqueueFailSelfDestruct(svc);
    }
    if (scenario == "configurer")
    {
      return runConfigurerSelfDestruct(svc);
    }
    return runSelfDestruct(svc);
  }
  catch (const std::exception &e)
  {
    std::cerr << "[quiesce-selfdestruct] FAILURE: unexpected exception: " << e.what() << "\n";
    return 2;
  }
}
