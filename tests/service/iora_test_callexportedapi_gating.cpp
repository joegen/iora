// File: iora/tests/service/iora_test_callexportedapi_gating.cpp
//
// Regression tests for the callExportedApi in-flight drain gate (Slice B,
// tracker 2026-09-07-3, architecture/iora/callexportedapi_gating.json).
// Covers the UNLOAD/RELOAD drain: T1 (concurrent call vs unload, no UAF),
// T2 (rejection during the window, no invoke), T4/T9 (direct + transitive
// self-unload throw, no deadlock), T5 (getExportedApi escape out-of-scope),
// T6 (unloadAll independent drain), T7 (owner re-export race), T10 (host-owned
// return). The load-failure race (T8) is Slice C (tracker 2026-09-07-9).
#define CATCH_CONFIG_RUNNER
#include "test_helpers.hpp"
#include "../plugins/gating_control.hpp"
#include <atomic>
#include <catch2/catch.hpp>
#include <chrono>
#include <memory>
#include <thread>

using namespace iora::test;

// Global service instance for all tests (mirrors iora_test_plugin_drain.cpp).
static iora::IoraService *globalSvc = nullptr;

iora::IoraService &getTestService()
{
  if (!globalSvc)
  {
    throw std::runtime_error("Test service not initialized");
  }
  return *globalSvc;
}

namespace
{
std::string pluginPath(const std::string &name)
{
  return iora::util::getExecutableDir() + "/plugins/" + name;
}

// Ensure a clean module table on every exit path (Catch2 re-runs the body per
// SECTION leaf; a failed REQUIRE must not leave a module loaded).
struct UnloadAllOnExit
{
  iora::IoraService &svc;
  ~UnloadAllOnExit()
  {
    try
    {
      svc.unloadAllModules();
    }
    catch (...)
    {
    }
  }
};
} // namespace

using namespace std::chrono_literals;

// waitFor(pred, timeout) is provided by test_helpers.hpp (iora::test::waitFor):
// spins until pred() is true or the budget elapses; used to bound liveness so a
// deadlock bug fails the test instead of hanging the suite.

// Runs svc.callExportedApi<int>(api) on a WORKER thread and waits (bounded) for
// completion, so a self-unload/transitive-unload deadlock regression makes the
// test FAIL (completed==false) instead of hanging inside the call. waitFor cannot
// interrupt a blocking predicate, so the potentially-blocking call MUST run off
// the predicate thread (cpp17-1). On timeout the (deadlocked) worker is detached
// rather than joined so the suite does not hang; a ctest TIMEOUT is the backstop.
// Shared-ptr state so a detached worker never dangles a stack local.
struct BoundedIntCall
{
  bool completed = false;
  bool threw = false;
  int value = -999;
};
static BoundedIntCall runIntCallBounded(iora::IoraService &svc, const std::string &api,
                                        std::chrono::milliseconds budget = 5s)
{
  // One shared worker-state block (not three parallel atomics) captured by value,
  // so a detached-on-timeout worker keeps it alive and never dangles a stack local.
  struct State
  {
    std::atomic<bool> done{false};
    std::atomic<bool> threw{false};
    std::atomic<int> value{-999};
  };
  auto st = std::make_shared<State>();
  std::thread t(
    [&svc, api, st] // &svc: the global service outlives any detach
    {
      try
      {
        st->value.store(svc.callExportedApi<int>(api));
      }
      catch (const std::exception &)
      {
        st->threw.store(true);
      }
      st->done.store(true);
    });
  if (iora::test::waitFor([&] { return st->done.load(); }, budget))
  {
    t.join();
    return {true, st->threw.load(), st->value.load()};
  }
  t.detach(); // deadlocked within the budget — do not hang the suite at join
  return {false, false, -999};
}

// --- T1: concurrent callExportedApi vs unloadSingleModule -> no UAF ---------
// The unload must WAIT (drain) for the in-flight call to finish before it tears
// the plugin object down; the in-flight read of plugin state stays valid.
// Non-vacuity: under ASan a mutant that skips drainApiCalls faults on the
// plugin-object read; a mutant that skips the drain also completes the unload
// while the call is still spinning, which REQUIRE_FALSE(unloadDone) catches.
TEST_CASE("T1 concurrent call vs unloadSingleModule drains before teardown")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  REQUIRE(svc.loadSingleModule(pluginPath("slowapiplugin.so")));

  iora::test::SlowApiControl ctl;
  std::atomic<int> callReturn{-1};
  std::thread worker([&] { callReturn.store(svc.callExportedApi<int>("slowapi.call", &ctl)); });

  REQUIRE(waitFor([&] { return ctl.phase.load() >= 1; })); // call is in-flight

  std::atomic<bool> unloadDone{false};
  std::atomic<bool> unloadResult{false};
  std::thread unloader(
    [&]
    {
      unloadResult.store(svc.unloadSingleModule("slowapiplugin.so"));
      unloadDone.store(true);
    });

  // The unloader must BLOCK in the drain while the call is in-flight.
  std::this_thread::sleep_for(150ms);
  REQUIRE_FALSE(unloadDone.load());

  ctl.phase.store(2); // release the in-flight call
  worker.join();
  unloader.join();

  REQUIRE(unloadResult.load());
  REQUIRE(callReturn.load() == 0xABCD);               // return value intact
  REQUIRE(ctl.observedMagic.load() == 0xABCD);         // object alive at read
  REQUIRE_FALSE(ctl.unloadRanBeforeRead.load());       // teardown waited for the call
  REQUIRE_FALSE(svc.isModuleLoaded("slowapiplugin.so"));
}

// --- T1 (reload variant): concurrent call vs reloadModule ------------------
TEST_CASE("T1 concurrent call vs reloadModule drains before teardown")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  REQUIRE(svc.loadSingleModule(pluginPath("slowapiplugin.so")));

  iora::test::SlowApiControl ctl;
  std::thread worker([&] { (void)svc.callExportedApi<int>("slowapi.call", &ctl); });
  REQUIRE(waitFor([&] { return ctl.phase.load() >= 1; }));

  std::atomic<bool> reloadDone{false};
  std::thread reloader(
    [&]
    {
      (void)svc.reloadModule("slowapiplugin.so");
      reloadDone.store(true);
    });

  std::this_thread::sleep_for(150ms);
  REQUIRE_FALSE(reloadDone.load()); // reload's unload half blocks in the drain

  ctl.phase.store(2);
  worker.join();
  reloader.join();
  REQUIRE(reloadDone.load());
  REQUIRE(ctl.observedMagic.load() == 0xABCD);
  REQUIRE(svc.isModuleLoaded("slowapiplugin.so")); // reloaded
}

// --- T2: a call arriving during the drain window is rejected, never invokes -
TEST_CASE("T2 call during the drain window throws and never invokes")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  REQUIRE(svc.loadSingleModule(pluginPath("slowapiplugin.so")));

  iora::test::SlowApiControl ctl1;
  std::thread worker([&] { (void)svc.callExportedApi<int>("slowapi.call", &ctl1); });
  REQUIRE(waitFor([&] { return ctl1.phase.load() >= 1; }));

  std::atomic<bool> unloadDone{false};
  std::thread unloader(
    [&]
    {
      (void)svc.unloadSingleModule("slowapiplugin.so");
      unloadDone.store(true);
    });

  // Once the unloader is blocked in the drain (still not done), the module is
  // draining -> a fresh call must be rejected and never enter the lambda.
  std::this_thread::sleep_for(150ms);
  REQUIRE_FALSE(unloadDone.load());

  iora::test::SlowApiControl ctl2;
  REQUIRE_THROWS_AS(svc.callExportedApi<int>("slowapi.call", &ctl2), std::runtime_error);
  REQUIRE(ctl2.phase.load() == 0); // the callable never ran

  ctl1.phase.store(2);
  worker.join();
  unloader.join();
  REQUIRE(unloadDone.load());
}

// --- T4: direct self-unload throws, no deadlock, no leaked claim ------------
TEST_CASE("T4 direct self-unload throws and leaves the module usable")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  REQUIRE(svc.loadSingleModule(pluginPath("selfunloadplugin.so")));

  // Run the (potentially-deadlocking) call on a worker; a deadlock regression
  // makes r.completed==false -> the test FAILS here rather than hanging.
  auto r = runIntCallBounded(svc, "selfunload.trigger");
  REQUIRE(r.completed);
  REQUIRE(r.threw);
  // No leaked claim: still loaded and still callable (re-throws, not bricked).
  REQUIRE(svc.isModuleLoaded("selfunloadplugin.so"));
  REQUIRE_THROWS_AS(svc.callExportedApi<int>("selfunload.trigger"), std::runtime_error);
  REQUIRE(svc.isModuleLoaded("selfunloadplugin.so"));
  // And it can be unloaded normally from outside any of its calls.
  REQUIRE(svc.unloadSingleModule("selfunloadplugin.so"));
}

// --- T9: transitive self-unload throws, no deadlock -------------------------
TEST_CASE("T9 transitive self-unload (M.f -> N.g -> unload M) throws, no deadlock")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  REQUIRE(svc.loadSingleModule(pluginPath("transitiveouterplugin.so")));
  REQUIRE(svc.loadSingleModule(pluginPath("transitiveinnerplugin.so")));

  // Worker-thread bounded: a missed transitive detection deadlocks the call, so
  // r.completed==false FAILS the test instead of hanging the suite.
  auto r = runIntCallBounded(svc, "transouter.call");
  REQUIRE(r.completed);
  REQUIRE(r.threw);
  REQUIRE(svc.isModuleLoaded("transitiveouterplugin.so"));
  REQUIRE(svc.isModuleLoaded("transitiveinnerplugin.so"));
}

// --- M1: reentrant same-module multiplicity (multiset erase-one) ------------
// erase(key) would drop BOTH pushes on the inner leave, so the outer call's
// self-unload would miss and deadlock; erase(find) preserves the outer entry so
// the self-unload is caught (returns 1) within the bounded budget.
TEST_CASE("M1 reentrant same-module call preserves in-flight multiplicity")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  REQUIRE(svc.loadSingleModule(pluginPath("reentrantselfplugin.so")));

  // Worker-thread bounded: the erase(key) bug would deadlock the outer self-unload
  // -> r.completed==false FAILS the test instead of hanging the suite.
  auto r = runIntCallBounded(svc, "reenter.outer");
  REQUIRE(r.completed);
  REQUIRE(r.value == 1); // the outer-frame self-unload was still caught
  REQUIRE(svc.isModuleLoaded("reentrantselfplugin.so"));
}

// --- T6: unloadAllModules drains each module independently ------------------
TEST_CASE("T6 unloadAllModules drains an in-flight module before teardown")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  REQUIRE(svc.loadSingleModule(pluginPath("slowapiplugin.so")));
  REQUIRE(svc.loadSingleModule(pluginPath("testplugin.so")));

  iora::test::SlowApiControl ctl;
  std::thread worker([&] { (void)svc.callExportedApi<int>("slowapi.call", &ctl); });
  REQUIRE(waitFor([&] { return ctl.phase.load() >= 1; }));

  std::atomic<bool> allDone{false};
  std::thread unloader(
    [&]
    {
      (void)svc.unloadAllModules();
      allDone.store(true);
    });

  std::this_thread::sleep_for(150ms);
  REQUIRE_FALSE(allDone.load()); // blocked draining slowapiplugin

  ctl.phase.store(2);
  worker.join();
  unloader.join();
  REQUIRE(allDone.load());
  REQUIRE(ctl.observedMagic.load() == 0xABCD);
  REQUIRE_FALSE(svc.isModuleLoaded("slowapiplugin.so"));
  REQUIRE_FALSE(svc.isModuleLoaded("testplugin.so"));
}

// --- T7: reload race (copy-vs-teardown UAF surface) -------------------------
// Hammers callExportedApi while another thread reloads the module. Under
// ASan/TSan the copy-then-invoke-vs-unload UAF (and a dropped owner re-check)
// faults. NOTE: the exact C-1 owner-swap non-vacuity is defensive (DP-6) and
// hard to force deterministically -- enter-before-copy pins the module for the
// call's duration -- so this exercises the copy-vs-teardown surface broadly
// rather than injecting a single-step owner swap.
TEST_CASE("T7 concurrent calls vs repeated reload -> no UAF, no garbage")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  REQUIRE(svc.loadSingleModule(pluginPath("testplugin.so")));

  std::atomic<bool> stop{false};
  std::atomic<int> okCount{0};
  std::atomic<int> badCount{0};

  std::vector<std::thread> callers;
  for (int i = 0; i < 4; ++i)
  {
    callers.emplace_back(
      [&]
      {
        while (!stop.load())
        {
          try
          {
            const int r = svc.callExportedApi<int, int, int>("testplugin.add", 2, 3);
            if (r == 5)
            {
              okCount.fetch_add(1);
            }
            else
            {
              badCount.fetch_add(1); // a wrong value would signal a torn copy
            }
          }
          catch (const std::exception &)
          {
            // Expected during the reload window (not loaded / unloading).
          }
        }
      });
  }

  for (int i = 0; i < 40; ++i)
  {
    (void)svc.reloadModule("testplugin.so");
    std::this_thread::sleep_for(1ms);
  }
  stop.store(true);
  for (auto &t : callers)
  {
    t.join();
  }

  REQUIRE(badCount.load() == 0); // never a torn/garbage result
  REQUIRE(okCount.load() > 0);   // and real calls did get through
}

// --- T5: getExportedApi escaping function is out-of-scope (DP-9) ------------
TEST_CASE("T5 getExportedApi escaping function is documented-unsafe, unchanged")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  REQUIRE(svc.loadSingleModule(pluginPath("testplugin.so")));

  // getExportedApi hands back an escaping std::function the caller may hold
  // across unloads -- unsafe BY DESIGN (DP-9), NOT gated by the drain. We assert
  // only that basic retrieval is unchanged; holding it across unload is the
  // caller's documented hazard and is intentionally not exercised here.
  auto fn = svc.getExportedApi<int(int, int)>("testplugin.add");
  REQUIRE(fn(2, 3) == 5);
}

// --- T10: host-owned return value survives a concurrent unload --------------
TEST_CASE("T10 host-owned return value is intact across a concurrent unload")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  REQUIRE(svc.loadSingleModule(pluginPath("slowapiplugin.so")));

  iora::test::SlowApiControl ctl;
  std::atomic<int> ret{-1};
  std::thread worker([&] { ret.store(svc.callExportedApi<int>("slowapi.call", &ctl)); });
  REQUIRE(waitFor([&] { return ctl.phase.load() >= 1; }));

  std::thread unloader([&] { (void)svc.unloadSingleModule("slowapiplugin.so"); });
  std::this_thread::sleep_for(50ms);
  ctl.phase.store(2);
  worker.join();
  unloader.join();

  // int is host-owned: C++17 elision materializes it in this frame, so it is
  // valid after the module (and its .so) are gone. The converse — a plugin-.so-
  // resident return-type dtor running in the caller frame AFTER leaveApiCall — is
  // the DP-8 host-owned-return INVARIANT: unenforceable at compile time and
  // intentionally NOT exercised here (no in-repo caller returns a plugin-resident
  // type; see the callExportedApi doc + arch knownLimitations, cpp17-5/TS-4).
  REQUIRE(ret.load() == 0xABCD);
  REQUIRE_FALSE(svc.isModuleLoaded("slowapiplugin.so"));
}

int main(int argc, char *argv[])
{
  Catch::Session session;

  initializeTestLogging();

  iora::IoraService::Config config;
  config.server.port = 8133;
  config.state.file = "ioraservice_callexportedapi_gating_state.json";
  config.log.file = "ioraservice_callexportedapi_gating_log";
  config.modules.autoLoad = false;

  iora::IoraService::init(config);
  globalSvc = &iora::IoraService::instanceRef();

  int result = session.run(argc, argv);

  globalSvc->shutdown();
  iora::util::removeFilesContainingAny(
    {"ioraservice_callexportedapi_gating_log", "ioraservice_callexportedapi_gating_state.json"});

  return result;
}
