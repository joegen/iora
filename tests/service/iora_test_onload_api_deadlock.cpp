// File: iora/tests/service/iora_test_onload_api_deadlock.cpp
//
// Hang-safe red-first regression tests for the onLoad/onUnload callExportedApi
// self-deadlock (tracker 2026-09-24-9, architecture/iora/callexportedapi_gating.json,
// SD-1..SD-6 / DP-6b amended + DP-10c). Plugin code that calls callExportedApi (or
// an SD-2 loader entry point) while running under _loadModulesMutex must NOT
// re-lock the non-recursive mutex (origin/master 82df843 HANGS). After SD-1 the
// callExportedApi admission gate (_apiCallableModules + drain) is the single
// check — no _loadModulesMutex acquire — so an onLoad call to a loaded sibling
// SUCCEEDS, to its own not-yet-marked module reports "not loaded", and to a
// claimed (unloading) module reports "is unloading"; and every SD-2 loader entry
// point throws std::logic_error for an owner thread.
//
// HANG-SAFE DESIGN (task 1.2): each case's load/unload leg runs on a std::thread
// with a BOUNDED wait; on timeout the case tag is printed and std::_Exit(<code>)
// with NO service teardown — never detach-and-continue, never std::async. Each
// case is its OWN ctest add_test (per-case [case_x] tag, TIMEOUT 120), so a
// deadlock in one case fails THAT case via the timeout instead of wedging the
// suite; a whole-binary run would _Exit at the first hang and mask the rest.
#define CATCH_CONFIG_RUNNER
#include "test_helpers.hpp"
#include "../plugins/onload_api_control.hpp"

#include <atomic>
#include <catch2/catch.hpp>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <thread>

using namespace iora::test;
using namespace std::chrono_literals;

// Global service instance for all tests (mirrors iora_test_callexportedapi_gating.cpp).
static iora::IoraService *globalSvc = nullptr;
// The control block the CURRENT test has published; the host getter
// "test.onloadapictl" returns it to the probe's onLoad.
static std::atomic<OnLoadApiControl *> g_onLoadApiCtl{nullptr};

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
const std::string kProbe = "onloadapicallerplugin.so";
const std::string kBase = "baseplugin.so";
const std::string kDependent = "dependentplugin.so";

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

// Publish a control block for the duration of one case; clears on scope exit.
struct PublishCtl
{
  explicit PublishCtl(OnLoadApiControl &ctl) { g_onLoadApiCtl.store(&ctl); }
  ~PublishCtl() { g_onLoadApiCtl.store(nullptr); }
};

// Run `op` on a worker thread and wait up to `budget`, returning op()'s bool
// result. op() MUST contain NO Catch2 macros — Catch2 v2 is single-thread-only, so
// a REQUIRE on the worker would std::terminate on failure instead of failing
// cleanly; the CALLER REQUIREs the returned value on the MAIN thread. A throw from
// op() is caught and reported as false. On timeout, print the case tag and
// std::_Exit(code) with NO teardown — a real deadlock (a re-lock of the held
// _loadModulesMutex) never wedges the whole suite. The worker is a bare
// std::thread; on the _Exit path it is neither joined nor detached (the process
// dies), on the success path it is joined.
bool runBoundedOrExit(const char *tag, int exitCode, std::chrono::milliseconds budget,
                      const std::function<bool()> &op)
{
  auto done = std::make_shared<std::atomic<bool>>(false);
  auto result = std::make_shared<std::atomic<bool>>(false);
  std::thread t(
    [done, result, op]
    {
      try
      {
        result->store(op());
      }
      catch (...)
      {
        // left false; a caller that expects a throw checks module state instead
      }
      done->store(true);
    });
  if (iora::test::waitFor([&] { return done->load(); }, budget))
  {
    t.join();
    return result->load();
  }
  std::fprintf(stderr, "\n[HANG] onload-api-deadlock case %s exceeded %lld ms -> _Exit(%d)\n",
               tag, static_cast<long long>(budget.count()), exitCode);
  std::fflush(stderr);
  std::_Exit(exitCode);
}
} // namespace

// --- Case (a): onLoad -> loaded sibling (base.getVersion) SUCCEEDS -----------
TEST_CASE("case_a onLoad call to a loaded sibling succeeds", "[case_a]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  OnLoadApiControl ctl; // default member initializers establish the reset state
  ctl.onLoadOp.store(static_cast<int>(ProbeOp::CALL_SIBLING_GETVERSION));
  PublishCtl pub{ctl};

  REQUIRE(svc.loadSingleModule(pluginPath(kBase)));
  REQUIRE(runBoundedOrExit("a", 91, 10s,
                           [&] { return svc.loadSingleModule(pluginPath(kProbe)); }));

  REQUIRE(ctl.onLoadEntered.load() == 1); // reached onLoad (missing-.so is never red)
  REQUIRE(ctl.onLoadCall.ran.load() == 1);
  REQUIRE(ctl.onLoadCall.ok.load() == 1);
  REQUIRE(ctl.onLoadCall.threw.load() == 0);
}

// --- Case (b): onLoad -> own API throws "not loaded" -------------------------
// Kills a skip-the-gate / mark-before-onLoad mutant: the module is not yet a
// member of _apiCallableModules during its own onLoad.
TEST_CASE("case_b onLoad call to own not-yet-marked API reports not loaded", "[case_b]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  OnLoadApiControl ctl; // default member initializers establish the reset state
  ctl.onLoadOp.store(static_cast<int>(ProbeOp::CALL_OWN));
  PublishCtl pub{ctl};

  REQUIRE(runBoundedOrExit("b", 92, 10s,
                           [&] { return svc.loadSingleModule(pluginPath(kProbe)); }));

  REQUIRE(ctl.onLoadEntered.load() == 1);
  REQUIRE(ctl.onLoadCall.ran.load() == 1);
  REQUIRE(ctl.onLoadCall.threw.load() == 1);
  REQUIRE(ctl.onLoadCall.errClass.load() == static_cast<int>(ErrClass::NOT_LOADED));
}

// --- Case (c): onUnload (single) -> sibling base.setCounter SUCCEEDS ----------
TEST_CASE("case_c onUnload single-unload call to a sibling succeeds", "[case_c]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  OnLoadApiControl ctl; // default member initializers establish the reset state
  ctl.onUnloadOp.store(static_cast<int>(ProbeOp::CALL_SIBLING_SETCOUNTER));
  ctl.counterArg.store(42);
  PublishCtl pub{ctl};

  REQUIRE(svc.loadSingleModule(pluginPath(kBase)));
  REQUIRE(svc.loadSingleModule(pluginPath(kProbe)));
  REQUIRE(runBoundedOrExit("c", 93, 10s,
                           [&] { return svc.unloadSingleModule(kProbe); }));

  REQUIRE(ctl.onUnloadEntered.load() == 1);
  REQUIRE(ctl.onUnloadCall.ran.load() == 1);
  REQUIRE(ctl.onUnloadCall.ok.load() == 1);
  REQUIRE(ctl.onUnloadCall.threw.load() == 0);
  // The sibling was actually invoked: its counter now reads the arg.
  REQUIRE(svc.callExportedApi<int>("baseplugin.getCounter") == 42);
}

// --- Case (d): onUnload under unloadAllModules -------------------------------
// Every module is claimed before any onUnload runs, so an onUnload call to a
// sibling is rejected (never invoked, counter unchanged) and a call to self is
// deterministically 'is unloading'.
TEST_CASE("case_d onUnload under unloadAll: sibling rejected, own is-unloading", "[case_d]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  OnLoadApiControl ctl; // default member initializers establish the reset state
  ctl.onUnloadOp.store(static_cast<int>(ProbeOp::CALL_SIBLING_AND_OWN));
  ctl.counterArg.store(55);
  PublishCtl pub{ctl};

  REQUIRE(svc.loadSingleModule(pluginPath(kBase)));
  REQUIRE(svc.loadSingleModule(pluginPath(kProbe)));
  (void)runBoundedOrExit("d", 94, 10s, [&] { return svc.unloadAllModules(); });

  REQUIRE(ctl.onUnloadEntered.load() == 1);
  // Sibling leg: never invoked -> threw 'is unloading' (sibling still claimed) OR
  // 'API not found' (sibling torn down first). Either proves it was not invoked.
  REQUIRE(ctl.onUnloadCall.threw.load() == 1);
  const int sc = ctl.onUnloadCall.errClass.load();
  REQUIRE((sc == static_cast<int>(ErrClass::IS_UNLOADING) ||
           sc == static_cast<int>(ErrClass::API_NOT_FOUND)));
  // Own leg: deterministic 'is unloading' (this module is claimed+draining).
  REQUIRE(ctl.onUnloadOwnCall.threw.load() == 1);
  REQUIRE(ctl.onUnloadOwnCall.errClass.load() == static_cast<int>(ErrClass::IS_UNLOADING));
}

// --- Case (e): onUnload -> self reports 'is unloading' -----------------------
TEST_CASE("case_e onUnload call to self reports is-unloading", "[case_e]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  OnLoadApiControl ctl; // default member initializers establish the reset state
  ctl.onUnloadOp.store(static_cast<int>(ProbeOp::CALL_OWN));
  PublishCtl pub{ctl};

  REQUIRE(svc.loadSingleModule(pluginPath(kProbe)));
  (void)runBoundedOrExit("e", 95, 10s, [&] { return svc.unloadSingleModule(kProbe); });

  REQUIRE(ctl.onUnloadEntered.load() == 1);
  REQUIRE(ctl.onUnloadCall.threw.load() == 1);
  REQUIRE(ctl.onUnloadCall.errClass.load() == static_cast<int>(ErrClass::IS_UNLOADING));
}

// --- Case (f): onLoad call-then-throw fails the load; gate stays balanced -----
TEST_CASE("case_f onLoad call-then-throw fails the load, base still unloadable", "[case_f]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  OnLoadApiControl ctl; // default member initializers establish the reset state
  ctl.onLoadOp.store(static_cast<int>(ProbeOp::CALL_THEN_THROW));
  PublishCtl pub{ctl};

  REQUIRE(svc.loadSingleModule(pluginPath(kBase)));
  // runBoundedOrExit catches the onLoad-throw and reports false; the failure is
  // verified by the module-state checks below, not the return value.
  (void)runBoundedOrExit("f", 96, 10s,
                         [&] { return svc.loadSingleModule(pluginPath(kProbe)); });

  REQUIRE(ctl.onLoadCall.ok.load() == 1);      // the sibling call SUCCEEDED before the throw
  REQUIRE_FALSE(svc.isModuleLoaded(kProbe));   // the load failed
  // The gate is balanced (the failed call's LeaveGuard fired): base unloads within bound.
  REQUIRE(runBoundedOrExit("f", 96, 10s, [&] { return svc.unloadSingleModule(kBase); }));
}

// --- Case (g): reloadModule completes; a post-reload call succeeds ------------
TEST_CASE("case_g reloadModule with an onLoad sibling call completes", "[case_g]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  OnLoadApiControl ctl; // default member initializers establish the reset state
  ctl.onLoadOp.store(static_cast<int>(ProbeOp::CALL_SIBLING_GETVERSION));
  PublishCtl pub{ctl};

  REQUIRE(svc.loadSingleModule(pluginPath(kBase)));
  // The initial probe load also runs an onLoad sibling call under L, so bound it
  // too (on origin/master it deadlocks the caller thread here, before the reload).
  REQUIRE(runBoundedOrExit("g", 97, 10s, [&] { return svc.loadSingleModule(pluginPath(kProbe)); }));
  REQUIRE(runBoundedOrExit("g", 97, 10s, [&] { return svc.reloadModule(kProbe); }));

  REQUIRE(ctl.onLoadCall.ok.load() == 1); // the reload's load-half sibling call succeeded
  REQUIRE(svc.callExportedApi<int>("onloadcaller.ping") == 0x5A); // post-reload call succeeds
}

// --- Case (h): onLoad spawns a worker; worker->sibling ok, worker->own not-loaded
TEST_CASE("case_h onLoad worker: sibling succeeds, own not-loaded (no cross-thread deadlock)",
          "[case_h]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  OnLoadApiControl ctl; // default member initializers establish the reset state
  ctl.onLoadOp.store(static_cast<int>(ProbeOp::SPAWN_WORKER));
  PublishCtl pub{ctl};

  REQUIRE(svc.loadSingleModule(pluginPath(kBase)));
  REQUIRE(runBoundedOrExit("h", 98, 10s, [&] { return svc.loadSingleModule(pluginPath(kProbe)); }));

  REQUIRE(ctl.workerSibling.ran.load() == 1);
  REQUIRE(ctl.workerSibling.ok.load() == 1); // worker -> loaded sibling SUCCEEDS
  REQUIRE(ctl.workerOwn.ran.load() == 1);
  REQUIRE(ctl.workerOwn.threw.load() == 1);  // worker -> loading module's own API
  REQUIRE(ctl.workerOwn.errClass.load() == static_cast<int>(ErrClass::NOT_LOADED));
}

// --- Case (i): nested onLoad -> dependentplugin.useBase -> base --------------
TEST_CASE("case_i onLoad nested call through dependent to base succeeds", "[case_i]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  OnLoadApiControl ctl; // default member initializers establish the reset state
  ctl.onLoadOp.store(static_cast<int>(ProbeOp::CALL_DEPENDENT_USEBASE));
  PublishCtl pub{ctl};

  REQUIRE(svc.loadSingleModule(pluginPath(kBase)));
  REQUIRE(svc.loadSingleModule(pluginPath(kDependent)));
  REQUIRE(runBoundedOrExit("i", 99, 10s, [&] { return svc.loadSingleModule(pluginPath(kProbe)); }));

  REQUIRE(ctl.onLoadCall.ran.load() == 1);
  REQUIRE(ctl.onLoadCall.ok.load() == 1);
}

// --- Case (j): dependency-notification callbacks do not self-deadlock --------
// require() (already-loaded dep) fires onDependencyLoaded synchronously; a reload
// of the dependency fires onDependencyLoaded via notifyDependentsOfLoad and
// onDependencyUnloaded via the unload half; unloadAllModules fires NEITHER.
TEST_CASE("case_j dependency-notification calls do not self-deadlock", "[case_j]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  OnLoadApiControl ctl; // default member initializers establish the reset state
  ctl.requireBaseFirst.store(1);
  ctl.onDepLoadedOp.store(static_cast<int>(ProbeOp::CALL_SIBLING_GETVERSION));
  ctl.onDepUnloadedOp.store(static_cast<int>(ProbeOp::CALL_SIBLING_GETVERSION));
  PublishCtl pub{ctl};

  REQUIRE(svc.loadSingleModule(pluginPath(kBase)));
  // require(base) [loaded] fires onDependencyLoaded synchronously in onLoad.
  REQUIRE(runBoundedOrExit("j", 100, 10s, [&] { return svc.loadSingleModule(pluginPath(kProbe)); }));
  REQUIRE(ctl.onDepLoadedFired.load() >= 1);
  REQUIRE(ctl.depLoadedCall.ok.load() == 1); // dep API SUCCEEDS (mark precedes notify)
  REQUIRE(ctl.depLoadedCall.threw.load() == 0);

  const int loadedBefore = ctl.onDepLoadedFired.load();
  // reload base: unload-half fires onDependencyUnloaded (base draining -> is-unloading),
  // load-half fires onDependencyLoaded via notifyDependentsOfLoad (succeeds).
  REQUIRE(runBoundedOrExit("j", 100, 10s, [&] { return svc.reloadModule(kBase); }));
  REQUIRE(ctl.onDepUnloadedFired.load() >= 1);
  REQUIRE(ctl.depUnloadedCall.threw.load() == 1);
  REQUIRE(ctl.depUnloadedCall.errClass.load() == static_cast<int>(ErrClass::IS_UNLOADING));
  REQUIRE(ctl.onDepLoadedFired.load() > loadedBefore); // notifyDependentsOfLoad fired again

  // Leg 4: unloadAllModules passes notifyDependents=false -> no onDependencyUnloaded.
  const int unloadedBefore = ctl.onDepUnloadedFired.load();
  (void)runBoundedOrExit("j", 100, 10s, [&] { return svc.unloadAllModules(); });
  REQUIRE(ctl.onDepUnloadedFired.load() == unloadedBefore);
}

// --- Case (k): every SD-2 loader entry point throws logic_error from a hook ---
TEST_CASE("case_k SD-2 loader entry points throw logic_error under the loader lock", "[case_k]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  OnLoadApiControl ctl; // default member initializers establish the reset state
  ctl.onLoadOp.store(static_cast<int>(ProbeOp::CALL_SD2_ENTRYPOINTS));
  PublishCtl pub{ctl};

  REQUIRE(svc.loadSingleModule(pluginPath(kBase)));
  // A HOST-created SafeApiFunction (getExportedApiSafe rejects under L, so the
  // probe cannot make one); pass invokers through the control block.
  auto saf = svc.getExportedApiSafe<std::string()>("baseplugin.getVersion");
  std::function<void()> invoke = [saf] { (void)(*saf)(); };
  std::function<void()> avail = [saf] { (void)saf->isAvailable(); };
  ctl.safeApiInvoke.store(&invoke);
  ctl.safeApiIsAvailable.store(&avail);

  REQUIRE(runBoundedOrExit("k", 101, 10s, [&] { return svc.loadSingleModule(pluginPath(kProbe)); }));

  // 6 loader entry points (load/unload/reload/unloadAll/registerDependency/shutdown)
  // + operator() + isAvailable() = 8 must throw std::logic_error; none may misbehave.
  REQUIRE(ctl.sd2ThrewLogic.load() == 8);
  REQUIRE(ctl.sd2Misbehaved.load() == 0);
  REQUIRE(ctl.sd2IsModuleLoadedValue.load() == 0); // owner-aware: self not yet loaded
  REQUIRE(ctl.requireOffLThrewLogic.load() == 1);  // require() off L -> logic_error (2.3b)
  REQUIRE(ctl.requireOffLMisbehaved.load() == 0);
}

// --- Case (l): concurrent non-owner hammer vs repeated load/unload (TSan/ASan)-
TEST_CASE("case_l concurrent sibling hammer vs repeated probe load/unload", "[case_l]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  OnLoadApiControl ctl; // default member initializers establish the reset state; probe ops NONE
  PublishCtl pub{ctl};

  REQUIRE(svc.loadSingleModule(pluginPath(kBase)));
  std::atomic<bool> stop{false};
  std::atomic<long> hammerCalls{0};
  std::thread hammer(
    [&]
    {
      while (!stop.load())
      {
        try
        {
          (void)svc.callExportedApi<std::string>("baseplugin.getVersion");
        }
        catch (...)
        {
        }
        hammerCalls.fetch_add(1);
      }
    });

  (void)runBoundedOrExit("l", 102, 20s,
                         [&]
                         {
                           for (int i = 0; i < 40; ++i)
                           {
                             (void)svc.loadSingleModule(pluginPath(kProbe));
                             (void)svc.unloadSingleModule(kProbe);
                           }
                           return true;
                         });
  stop.store(true);
  hammer.join();
  REQUIRE(hammerCalls.load() > 0); // the hammer made progress; no crash/hang
}

// --- Case (m): concurrent hammer of the CYCLED module's OWN export ------------
// Mutant-killer: an invocation must never observe !ready (mark precedes ready=1
// on load; draining precedes ready=0 on unload). Green by design in the red run.
TEST_CASE("case_m concurrent own-export hammer during load/unload/reload", "[case_m]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  OnLoadApiControl ctl; // default member initializers establish the reset state
  ctl.onLoadOp.store(static_cast<int>(ProbeOp::RENDEZVOUS_ONLY));
  ctl.onUnloadOp.store(static_cast<int>(ProbeOp::RENDEZVOUS_ONLY));
  PublishCtl pub{ctl};

  std::atomic<bool> stop{false};
  std::thread hammer(
    [&]
    {
      while (!stop.load())
      {
        ctl.hammerAttempts.fetch_add(1); // counted even if the call blocks on L (old code)
        try
        {
          (void)svc.callExportedApi<int>("onloadcaller.ping");
        }
        catch (...)
        {
        }
      }
    });

  (void)runBoundedOrExit("m", 103, 20s,
                         [&]
                         {
                           for (int i = 0; i < 15; ++i)
                           {
                             ctl.hammerAttempts.store(0);
                             (void)svc.loadSingleModule(pluginPath(kProbe));
                             (void)svc.reloadModule(kProbe);
                             (void)svc.unloadSingleModule(kProbe);
                           }
                           return true;
                         });
  stop.store(true);
  hammer.join();
  REQUIRE(ctl.notReadyObservations.load() == 0); // never invoked while !ready
}

// --- Case (n): after a FAILED unload (onUnload throws) the module stays callable
TEST_CASE("case_n failed unload leaves the module loaded and callable", "[case_n]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  OnLoadApiControl ctl; // default member initializers establish the reset state
  ctl.onUnloadOp.store(static_cast<int>(ProbeOp::THROW_STD));
  PublishCtl pub{ctl};

  REQUIRE(svc.loadSingleModule(pluginPath(kProbe)));
  // onUnload throws -> teardown aborts (Option A) -> module stays loaded; the gate
  // is reopened (openGate), so a later call SUCCEEDS.
  (void)runBoundedOrExit("n", 104, 10s, [&] { return svc.unloadSingleModule(kProbe); });
  REQUIRE(ctl.onUnloadEntered.load() == 1);
  REQUIRE(svc.isModuleLoaded(kProbe));
  REQUIRE(svc.callExportedApi<int>("onloadcaller.ping") == 0x5A);
}

// --- Case (o): require() off the loader lock throws logic_error (2.3b) --------
TEST_CASE("case_o require off the loader lock throws logic_error", "[case_o]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  OnLoadApiControl ctl; // default member initializers establish the reset state
  ctl.onLoadOp.store(static_cast<int>(ProbeOp::REQUIRE_OFF_L));
  PublishCtl pub{ctl};

  REQUIRE(svc.loadSingleModule(pluginPath(kBase)));
  REQUIRE(runBoundedOrExit("o", 105, 10s, [&] { return svc.loadSingleModule(pluginPath(kProbe)); }));

  REQUIRE(ctl.onLoadCall.ran.load() == 1);
  REQUIRE(ctl.onLoadCall.threw.load() == 1);
  REQUIRE(ctl.onLoadCall.errClass.load() == static_cast<int>(ErrClass::LOGIC_ERROR));
  REQUIRE(ctl.onLoadCall.ok.load() == 0); // did NOT return without throwing
}

// --- Case (p): require(sameDep) from onDependencyLoaded fired by notify -------
// LIVENESS/NO-FAULT check (NOT a discriminating pin for 2.3c). A dependent
// re-requiring its OWN dependency from onDependencyLoaded is de-duplicated by 2.3f
// (registerDependencyLocked), so no push_back onto the iterated _dependents vector
// actually occurs — the 2.3c snapshot is therefore DEFENCE-IN-DEPTH, unreachable
// by construction given 2.3f + SD-2 (a NEW dependent cannot be added mid-notify
// because loadSingleModule throws for an owner thread). This case verifies the
// combined path is live and fault-free under ASan; it does not, and cannot, fail
// if 2.3c alone is reverted. Recorded as a known test-efficacy limitation in the
// arch doc (cpp17 R1 M-1, human-signed-off).
TEST_CASE("case_p require from onDependencyLoaded under notify does not fault", "[case_p]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  OnLoadApiControl ctl; // default member initializers establish the reset state
  ctl.requireBaseFirst.store(1);
  ctl.onDepLoadedOp.store(static_cast<int>(ProbeOp::REQUIRE_SELF));
  PublishCtl pub{ctl};

  REQUIRE(svc.loadSingleModule(pluginPath(kBase)));
  REQUIRE(svc.loadSingleModule(pluginPath(kProbe))); // edge base<-probe registered
  // Arm so ONLY the reload's notify-fired onDependencyLoaded re-requires base.
  ctl.reqSelfArmed.store(1);
  // reload base: notifyDependentsOfLoad iterates _dependents[base] (single entry)
  // while onDependencyLoaded -> require(base) push_backs onto it.
  REQUIRE(runBoundedOrExit("p", 106, 10s, [&] { return svc.reloadModule(kBase); }));
  REQUIRE(ctl.onDepLoadedFired.load() >= 1); // fired, no fault/hang
}

// --- Case (q): public registerDependency() with asserts live does not abort ---
// 2.3a: registerDependency uses LoadModulesGuard, so ownsLoadModulesMutex() is true
// when registerDependencyLocked's assert runs (built -UNDEBUG). A mutant keeping the
// old bare lock_guard would abort here.
TEST_CASE("case_q public registerDependency does not abort under live asserts", "[case_q]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};

  REQUIRE(svc.loadSingleModule(pluginPath(kBase)));
  // Host thread (owns==false): registers an edge; must complete, not abort.
  REQUIRE_NOTHROW(svc.registerDependency("case_q_dependent.so", kBase));
  SUCCEED("registerDependency returned without aborting the process");
}

// --- Case (r): a duplicate dependency edge does not fire onDependency* twice ----
// 2.3f de-duplicates the edge, so notifyDependentsOfLoad fires onDependencyLoaded
// exactly once per load even after the edge is registered twice.
TEST_CASE("case_r duplicate dependency edge fires onDependencyLoaded once", "[case_r]")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};
  OnLoadApiControl ctl; // default member initializers establish the reset state
  ctl.requireBaseFirst.store(1);
  ctl.onDepLoadedOp.store(static_cast<int>(ProbeOp::NONE)); // just count fires
  PublishCtl pub{ctl};

  REQUIRE(svc.loadSingleModule(pluginPath(kBase)));
  REQUIRE(svc.loadSingleModule(pluginPath(kProbe))); // require(base) registers edge + fires once
  // Register the SAME edge again from the host (duplicate).
  REQUIRE_NOTHROW(svc.registerDependency(kProbe, kBase));

  const int firedBefore = ctl.onDepLoadedFired.load();
  REQUIRE(runBoundedOrExit("r", 108, 10s, [&] { return svc.reloadModule(kBase); }));
  // notifyDependentsOfLoad iterates _dependents[base]; with the edge de-duplicated
  // it holds a single entry, so onDependencyLoaded fires EXACTLY once (not twice).
  REQUIRE(ctl.onDepLoadedFired.load() == firedBefore + 1);
}

int main(int argc, char *argv[])
{
  Catch::Session session;

  initializeTestLogging();

  iora::IoraService::Config config;
  config.server.port = 8139;
  config.state.file = "ioraservice_onload_api_deadlock_state.json";
  config.log.file = "ioraservice_onload_api_deadlock_log";
  config.modules.autoLoad = false;

  iora::IoraService::init(config);
  globalSvc = &iora::IoraService::instanceRef();

  // Export the control-block getter ONCE (no unexportApi exists). It returns
  // whatever the current test published in g_onLoadApiCtl.
  globalSvc->exportApi(std::string("test-harness"), "test.onloadapictl",
                       []() -> OnLoadApiControl * { return g_onLoadApiCtl.load(); });

  int result = session.run(argc, argv);

  globalSvc->shutdown();
  iora::util::removeFilesContainingAny(
    {"ioraservice_onload_api_deadlock_log", "ioraservice_onload_api_deadlock_state.json"});

  return result;
}
