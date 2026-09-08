// File: iora/tests/service/iora_test_unload_teardown_exception.cpp
//
// Tests for the UNLOAD-path teardown exception handling (trackers 2026-09-08-4
// P1 + 2026-09-08-3 P2, architecture/iora/callexportedapi_gating.json). The
// symmetric unload-side sibling of the O-2 load-path work (2026-09-08-1):
//   Step 1 (-4): notifyDependentsOfUnload's onDependencyUnloaded swallow widened
//                with a non-rethrowing catch(...) so a non-std throw is isolated
//                exactly like a std one (dependent-notify isolation is exception-
//                type-agnostic) — and later dependents are still notified.
//   Step 2 (-4): teardownModuleHostSideLocked's outer catch widened so a non-std
//                onUnload throw returns false (no rethrow), like the std case.
//   Step 3 (-3, Option A): the tracking prune is gated on `teardownThrew`, so a
//                module whose onUnload threw stays fully loaded AND fully tracked
//                (retry-able), not half-torn-down.
// Non-vacuity is proven by the MUT-U1/U2/U3 mutants described per case; each was
// run at implementation time and shown to flip its target assertion.
#define CATCH_CONFIG_RUNNER
#include "test_helpers.hpp"
#include "../plugins/unload_teardown_control.hpp"
#include <atomic>
#include <catch2/catch.hpp>

using namespace iora::test;

static iora::IoraService *globalSvc = nullptr;

// Host-owned control block for the current test; the host-exported
// "test.unloadctl" getter returns its address so each plugin's onLoad can cache
// it across the RTLD_LOCAL boundary. Each test points this at its own local
// block before loading plugins.
static std::atomic<iora::test::UnloadTeardownControl *> g_unloadCtl{nullptr};

namespace
{
std::string pluginPath(const std::string &name)
{
  return iora::util::getExecutableDir() + "/plugins/" + name;
}

// Non-discriminating load/unload wrappers: swallow any throw so a stray non-std
// from a MISCONFIGURED setup step cannot std::terminate the binary. NEVER route
// a DISCRIMINATING call through these — the fix-vs-mutant signal for FX-U3 is
// throw-vs-return, which a catch(...){return false;} wrapper would erase (H2).
bool tryLoad(iora::IoraService &svc, const std::string &path)
{
  try
  {
    return svc.loadSingleModule(path);
  }
  catch (...)
  {
    return false;
  }
}

// Ensure a clean module table on every exit path (a failed REQUIRE must not
// leave a module loaded for the next test).
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

// NOTE on local declaration ORDER in every fixture: the control block `ctl` is
// declared BEFORE `UnloadAllOnExit cleanup`, so at scope exit `cleanup` (declared
// last) destructs FIRST — its unloadAllModules() tears down any still-loaded
// module (whose onUnload dereferences its cached &ctl) while `ctl` is still
// alive — and `ctl` destructs last. Declaring `cleanup` first would destroy
// `ctl` before the teardown reads it (an after-lifetime read; steps-4-8 MEDIUM).

// --- FX-U1: non-std onDependencyUnloaded is isolated; later dependents notified -
// M = testplugin.so, with three dependents loaded in order D1s (throws STD from
// onDependencyUnloaded), D1 (throws NON-std), D2 (records), so
// _dependents[testplugin.so] = [D1s, D1, D2]. Unloading testplugin fires all
// three: D1s (std, isolated by the pre-existing std swallow) and D1 (non-std,
// isolated by the widened catch(...)) both continue the loop, so D2 IS notified.
// Discriminating: the unload SUCCEEDS (return true) AND D2 was notified
// (d2DepUnloaded == 1). MUT-U1 (revert the non-std swallow to std-only): D1s is
// still swallowed but D1's non-std escapes into the teardown outer catch(...) ->
// the unload returns FALSE and D2 (after D1) is never reached.
TEST_CASE("FX-U1 non-std/std onDependencyUnloaded isolated; later dependents still notified")
{
  iora::IoraService &svc = *globalSvc;

  iora::test::UnloadTeardownControl ctl;
  g_unloadCtl.store(&ctl);
  UnloadAllOnExit cleanup{svc};

  REQUIRE(tryLoad(svc, pluginPath("testplugin.so")));
  // Order matters: the throwing dependents (D1s std, D1 non-std) before the
  // recording D2, so under MUT-U1 the loop aborts at D1 and never reaches D2.
  REQUIRE(tryLoad(svc, pluginPath("unloaddepstdthrowplugin.so")));
  REQUIRE(tryLoad(svc, pluginPath("unloaddepnonstdthrowplugin.so")));
  REQUIRE(tryLoad(svc, pluginPath("unloaddeprecordplugin.so")));

  bool r = false;
  REQUIRE_NOTHROW(r = svc.unloadSingleModule("testplugin.so"));
  REQUIRE(r == true);                     // MUT-U1: escapes -> teardown returns false
  REQUIRE(ctl.d2DepUnloaded.load() == 1); // MUT-U1: loop aborts at D1 -> D2 not notified

  g_unloadCtl.store(nullptr);
}

// --- FX-U2: Option A — a failed onUnload leaves the module fully tracked --------
// M DEPENDS ON testplugin.so (M is a VALUE in _dependents[testplugin.so] — the
// edge pruneModuleTrackingLocked actually mutates). M.onUnload throws std once,
// so the first unloadSingleModule(M) returns false and M stays loaded. Option A
// leaves M's _dependents[testplugin.so] membership intact, so a later unload of
// testplugin still notifies M (mDepUnloadedFromB == 1). MUT-U3 (prune regardless):
// the failed unload prunes M from _dependents[testplugin.so] -> the later notify
// is silently lost (mDepUnloadedFromB == 0).
TEST_CASE("FX-U2 Option A: a thrown onUnload leaves the module fully tracked / retry-able")
{
  iora::IoraService &svc = *globalSvc;

  iora::test::UnloadTeardownControl ctl;
  ctl.armStdOnUnloadThrow.store(1); // M.onUnload throws std exactly once
  g_unloadCtl.store(&ctl);
  UnloadAllOnExit cleanup{svc};

  REQUIRE(tryLoad(svc, pluginPath("testplugin.so")));
  REQUIRE(tryLoad(svc, pluginPath("onunloadthrowstddeprecordplugin.so")));

  // First unload of M: onUnload throws (std) -> caught -> teardown returns false,
  // M stays loaded, its tracking is NOT pruned (Option A).
  bool rM = true;
  REQUIRE_NOTHROW(rM = svc.unloadSingleModule("onunloadthrowstddeprecordplugin.so"));
  REQUIRE(rM == false);
  REQUIRE(svc.isModuleLoaded("onunloadthrowstddeprecordplugin.so"));

  // Now unload the dependency; M (still tracked in _dependents[testplugin.so])
  // must be notified.
  REQUIRE(svc.unloadSingleModule("testplugin.so"));
  REQUIRE(ctl.mDepUnloadedFromB.load() == 1); // MUT-U3: 0 (M pruned from _dependents[B])

  g_unloadCtl.store(nullptr);
}

// --- FX-U3: non-std onUnload throw returns false, does not rethrow --------------
// M.onUnload throws a non-std once. The widened teardown outer catch(...) makes
// unloadSingleModule(M) return false WITHOUT rethrowing (identical to a std
// throw). The discriminating call must NOT go through tryUnload (a catch-all
// wrapper would collapse the mutant's throw and the fix's false to the same
// value): assert no-throw + return false directly. MUT-U2 (revert the teardown
// outer catch to std-only): the non-std escapes and unloadSingleModule THROWS ->
// REQUIRE_NOTHROW fails.
TEST_CASE("FX-U3 non-std onUnload throw returns false, does not rethrow")
{
  iora::IoraService &svc = *globalSvc;

  iora::test::UnloadTeardownControl ctl;
  ctl.armNonStdOnUnloadThrow.store(1); // M.onUnload throws non-std exactly once
  g_unloadCtl.store(&ctl);
  UnloadAllOnExit cleanup{svc};

  REQUIRE(tryLoad(svc, pluginPath("onunloadnonstdthrowplugin.so")));

  bool r = true;
  REQUIRE_NOTHROW(r = svc.unloadSingleModule("onunloadnonstdthrowplugin.so"));
  REQUIRE(r == false); // MUT-U2: non-std escapes -> unloadSingleModule THROWS

  g_unloadCtl.store(nullptr);
}

// --- FX-U4: unloadAllModules isolates a per-module onUnload throw ---------------
// Two INDEPENDENT modules: Ma (onUnload throws non-std once) and Mb (well-behaved,
// records its onUnload). unloadAllModules must isolate Ma's throw per-module (the
// widened teardown catch(...) makes Ma's teardown return false rather than escape
// and abort the batch), so it returns false yet STILL tears down Mb — Mb's
// onUnload runs (mbOnUnloadRan == 1) and Mb is no longer loaded. The batch call
// must not throw (REQUIRE_NOTHROW: under MUT-U2 Ma's non-std would escape to the
// unloadAllModules catch(...) and rethrow, aborting the batch).
TEST_CASE("FX-U4 unloadAllModules isolates a per-module onUnload throw")
{
  iora::IoraService &svc = *globalSvc;

  iora::test::UnloadTeardownControl ctl;
  ctl.armNonStdOnUnloadThrow.store(1); // Ma.onUnload throws non-std exactly once
  g_unloadCtl.store(&ctl);
  UnloadAllOnExit cleanup{svc};

  REQUIRE(tryLoad(svc, pluginPath("onunloadnonstdthrowplugin.so"))); // Ma (throws)
  REQUIRE(tryLoad(svc, pluginPath("onunloadrecordplugin.so")));      // Mb (records)

  bool r = true;
  REQUIRE_NOTHROW(r = svc.unloadAllModules());
  REQUIRE(r == false);                          // Ma's teardown returned false
  REQUIRE(ctl.mbOnUnloadRan.load() == 1);       // Mb was still torn down (isolated)
  REQUIRE(svc.isModuleLoaded("onunloadrecordplugin.so") == false);

  g_unloadCtl.store(nullptr);
}

int main(int argc, char *argv[])
{
  Catch::Session session;

  initializeTestLogging();

  iora::IoraService::Config config;
  config.server.port = 8139;
  config.state.file = "ioraservice_unload_teardown_exception_state.json";
  config.log.file = "ioraservice_unload_teardown_exception_log";
  config.modules.autoLoad = false;

  iora::IoraService::init(config);
  globalSvc = &iora::IoraService::instanceRef();

  // Export the control-block getter ONCE (no unexportApi exists). It returns
  // whatever the current test has published in g_unloadCtl.
  globalSvc->exportApi(std::string("test-harness"), "test.unloadctl",
                       []() -> iora::test::UnloadTeardownControl * { return g_unloadCtl.load(); });

  int result = session.run(argc, argv);

  globalSvc->shutdown();
  iora::util::removeFilesContainingAny(
    {"ioraservice_unload_teardown_exception_log", "ioraservice_unload_teardown_exception_state.json"});

  return result;
}
