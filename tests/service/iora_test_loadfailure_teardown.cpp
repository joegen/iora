// File: iora/tests/service/iora_test_loadfailure_teardown.cpp
//
// Tests for the load-failure teardown hardening (tracker 2026-09-07-9,
// architecture/iora/callexportedapi_gating.json).
//   F-4: the DP-10b monolithic-hold invariant — a concurrent callExportedApi is
//        serialized behind a blocking onLoad and, when the load fails, throws
//        without ever invoking (proves no in-flight copy against a failing
//        first-time load; trips if a mid-load release window is ever added).
//   S-2: the inner-catch cleanup runs the shared dependency/registry prune
//        (require-a-loaded-dep-then-throw) without crashing; reloadable after.
//   Regression: existing export-then-throw failures still clean up + reload.
#define CATCH_CONFIG_RUNNER
#include "test_helpers.hpp"
#include "../plugins/blocking_onload_control.hpp"
#include <algorithm>
#include <atomic>
#include <catch2/catch.hpp>
#include <chrono>
#include <thread>

using namespace iora::test;
using namespace std::chrono_literals;

static iora::IoraService *globalSvc = nullptr;

// Host-owned control block for the blocking-onLoad plugin; the host-exported
// "test.blockctl" getter returns its address so the plugin's onLoad can fetch it
// across the RTLD_LOCAL boundary without relying on cross-.so type identity.
static std::atomic<iora::test::BlockOnLoadControl *> g_blockCtl{nullptr};

namespace
{
std::string pluginPath(const std::string &name)
{
  return iora::util::getExecutableDir() + "/plugins/" + name;
}

// Attempt a load; returns loadSingleModule's result (false whether it returned
// false or threw). Never throws — the catch(...) arm is REQUIRED for the O-2
// non-std fixtures (tracker 2026-09-08-1): loadSingleModule now rethrows a
// NON-std::exception (`throw 42`) out of its outer catch(...), which a std-only
// catch here would let propagate to std::terminate and abort the whole binary.
bool tryLoad(iora::IoraService &svc, const std::string &path)
{
  try
  {
    return svc.loadSingleModule(path);
  }
  catch (...) // catches std AND the O-2 non-std throws; a std-only catch here
              // would let a rethrown non-std propagate to std::terminate.
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

// Assert a load FAILED cleanly and left no stale export: not loaded, the API
// name absent from the export table, and the name resolving to "not found" via
// the PUBLIC call path (resolveOwningModuleLocked is private and non-throwing).
// Shared by the S-1 dlclose-site tests and the export-then-throw regression.
void expectCleanFailedLoad(iora::IoraService &svc, const std::string &soName,
                           const std::string &api)
{
  REQUIRE(tryLoad(svc, pluginPath(soName)) == false);
  REQUIRE(svc.isModuleLoaded(soName) == false);
  auto names = svc.getExportedApiNames();
  REQUIRE(std::find(names.begin(), names.end(), api) == names.end());
  REQUIRE_THROWS_AS(svc.callExportedApi<int>(api, 1, 2), std::runtime_error);
}
} // namespace

// --- F-4: concurrent callExportedApi serializes behind a blocking onLoad ------
// A plugin's onLoad exports "blocking.call", then blocks holding _loadModulesMutex
// until the host releases it, then throws (the load fails). A concurrent host
// thread calling callExportedApi("blocking.call") must stay blocked on the
// is-loaded gate (which acquires _loadModulesMutex) for as long as onLoad holds
// the lock; once the load fails and unwinds, the call sees the module NOT loaded
// and throws WITHOUT invoking. This is the mechanized guard for DP-10b (the
// monolithic-hold invariant that makes a load-failure drain unnecessary): if a
// future edit introduces a mid-load release window, the concurrent caller would
// stop being blocked and this test's "still blocked" assertion fails.
TEST_CASE("F-4 concurrent callExportedApi serializes behind a blocking onLoad")
{
  iora::IoraService &svc = *globalSvc;
  UnloadAllOnExit cleanup{svc};

  iora::test::BlockOnLoadControl ctl;
  g_blockCtl.store(&ctl);

  std::thread loader;
  std::thread caller;

  // Status atomics the worker lambdas capture by reference. Declared BEFORE
  // threadGuard so they OUTLIVE it: locals destruct in reverse declaration
  // order, so threadGuard (declared last) destructs FIRST and joins the threads
  // while these are still alive. The threads write these on their way out, so
  // destroying them before the join would be a use-after-scope on the
  // REQUIRE-failure unwind path. All are set before their thread starts, so
  // declaring them up here is safe.
  std::atomic<bool> loadReturned{false};
  std::atomic<bool> loadResult{true};
  std::atomic<bool> callStarted{false};
  std::atomic<bool> callReturned{false};
  std::atomic<bool> callThrew{false};
  std::atomic<bool> callInvoked{false}; // true only if the callable actually ran
  std::atomic<int> callResult{-1};

  // RAII teardown, declared LAST so it destructs FIRST: on EVERY exit path
  // (including a REQUIRE-failure unwind) it wakes the blocked onLoad so the
  // loader can unwind and release _loadModulesMutex, then joins both threads (a
  // joinable std::thread destroyed during unwinding would std::terminate the
  // binary), then clears g_blockCtl. It references ctl/loader/caller (all
  // declared above) and joins while every atomic the workers write is still
  // alive.
  struct ThreadGuard
  {
    iora::test::BlockOnLoadControl &ctl;
    std::thread &loader;
    std::thread &caller;
    ~ThreadGuard()
    {
      ctl.release.store(1); // unblock onLoad so the loader can unwind
      if (caller.joinable())
      {
        caller.join();
      }
      if (loader.joinable())
      {
        loader.join();
      }
      g_blockCtl.store(nullptr);
    }
  } threadGuard{ctl, loader, caller};

  // Thread A: load the plugin. onLoad blocks (holding _loadModulesMutex) until
  // ctl.release is set, then throws -> loadSingleModule returns false.
  loader = std::thread(
    [&]
    {
      const bool ok = tryLoad(svc, pluginPath("blockingonloadplugin.so"));
      loadResult.store(ok);
      loadReturned.store(true);
    });

  // Wait until onLoad has exported "blocking.call" and is holding the lock.
  REQUIRE(waitFor([&] { return ctl.onLoadEntered.load() == 1; }, 5s));
  REQUIRE(loadReturned.load() == false); // load is genuinely blocked in onLoad

  // Thread B: call the exported API. resolve() (under _apiMutex) succeeds because
  // onLoad already published the export; the is-loaded gate (under
  // _loadModulesMutex) then blocks behind onLoad. (Its status atomics are
  // declared above, before threadGuard.)
  caller = std::thread(
    [&]
    {
      callStarted.store(true);
      try
      {
        int r = svc.callExportedApi<int>("blocking.call", 7);
        callResult.store(r);
        callInvoked.store(true); // reached only if the plugin lambda ran
      }
      catch (const std::exception &)
      {
        callThrew.store(true);
      }
      callReturned.store(true);
    });

  REQUIRE(waitFor([&] { return callStarted.load(); }, 5s));

  // DISCRIMINATING ASSERTION: while onLoad holds _loadModulesMutex, thread B's
  // is-loaded gate cannot proceed, so its call must NOT return. If a mid-load
  // release window were introduced, B would acquire the lock and return early,
  // failing this. Bounded wait (not perfectly deterministic, but a release-window
  // regression makes B return within it).
  std::this_thread::sleep_for(200ms);
  REQUIRE(callReturned.load() == false);
  REQUIRE(loadReturned.load() == false);

  // Release onLoad -> it throws -> load fails -> _loadModulesMutex released.
  ctl.release.store(1);

  REQUIRE(waitFor([&] { return loadReturned.load(); }, 5s));
  REQUIRE(loadResult.load() == false); // the load failed

  // Now B's is-loaded gate proceeds, sees the module NOT loaded, and throws
  // WITHOUT invoking the callable.
  REQUIRE(waitFor([&] { return callReturned.load(); }, 5s));
  REQUIRE(callThrew.load() == true);
  REQUIRE(callInvoked.load() == false);
  REQUIRE(callResult.load() == -1);

  // The failed module is not loaded and leaves no stale export. (threadGuard
  // joins both threads on scope exit.)
  REQUIRE(svc.isModuleLoaded("blockingonloadplugin.so") == false);
  auto names = svc.getExportedApiNames();
  REQUIRE(std::find(names.begin(), names.end(), "blocking.call") == names.end());
}

// --- S-2: inner-catch cleanup runs the shared dependency/registry prune --------
// A plugin whose onLoad require()s an ALREADY-LOADED dependency (registering a
// _dependents edge) then throws drives the inner catch through
// pruneModuleTrackingLocked. The internal map removal is not black-box observable
// (M-1); correctness is guaranteed by converging on the same helper the unload
// path uses. This test exercises the path (under ASan when enabled) and asserts
// the observable outcome: clean failure, no crash, dep still healthy, and the
// failed module name reusable (re-attempting the failing load fails cleanly
// again rather than bricking or hanging).
TEST_CASE("S-2 load-failure after require(loaded dep) cleans up without crashing")
{
  iora::IoraService &svc = *globalSvc;
  UnloadAllOnExit cleanup{svc};

  // The dependency must be loaded first (require() throws if it is not).
  REQUIRE(svc.loadSingleModule(pluginPath("testplugin.so")));
  REQUIRE(svc.isModuleLoaded("testplugin.so"));

  // Loading the requiring plugin fails in onLoad (after require registered the
  // _dependents edge) -> inner catch -> pruneModuleTrackingLocked.
  REQUIRE(tryLoad(svc, pluginPath("requiredepthenthrowplugin.so")) == false);
  REQUIRE(svc.isModuleLoaded("requiredepthenthrowplugin.so") == false);

  // The dependency is untouched and still loaded (its _dependents list no longer
  // references the vanished module — exercised, not asserted per M-1).
  REQUIRE(svc.isModuleLoaded("testplugin.so"));

  // The failed module name is reusable (not bricked): with the dependency loaded,
  // re-attempting the failing load fails cleanly AGAIN rather than hanging or
  // erroring differently.
  REQUIRE(tryLoad(svc, pluginPath("requiredepthenthrowplugin.so")) == false);
  REQUIRE(svc.isModuleLoaded("requiredepthenthrowplugin.so") == false);

  // Unload of the dependency must not crash or hang.
  REQUIRE(svc.unloadSingleModule("testplugin.so"));
}

// --- Regression: existing export-then-throw failures still clean up + reload ---
// The inner-catch path (onLoad exports then throws) must still unexport before
// the outer catch dlcloses, leave no stale _apiExports entry, and permit a
// subsequent load of the same name. Covers both the Plugin& overload
// (ExportThenThrowPlugin) and the identity-string overload
// (IdentityExportThenThrowPlugin).
TEST_CASE("regression export-then-throw inner-catch cleanup + reloadable")
{
  iora::IoraService &svc = *globalSvc;
  UnloadAllOnExit cleanup{svc};

  SECTION("Plugin& overload")
  {
    expectCleanFailedLoad(svc, "exportthenthrowplugin.so", "exportthenthrow.add");
    // Reloadable (the failed load did not brick the name).
    expectCleanFailedLoad(svc, "exportthenthrowplugin.so", "exportthenthrow.add");
  }

  SECTION("identity-string overload")
  {
    expectCleanFailedLoad(svc, "identityexportthenthrowplugin.so", "identityexportthenthrow.add");
    expectCleanFailedLoad(svc, "identityexportthenthrowplugin.so", "identityexportthenthrow.add");
  }
}

// --- S-1: unexport before EVERY dlclose site (tracker 2026-09-08-2) -----------
// Two coupled load-failure defects the inner catch never covered:
//   defect_2 (Option A): an export from a plugin CONSTRUCTOR / custom factory
//     runs before loadSingleModule assigns _name, keying _apiToModule on "" —
//     which removeExportsForModule(pluginName) (value-match) can never reclaim.
//     exportApi now REJECTS an empty identity, so such an export is never
//     inserted (FX-i).
//   defect_1 (cleanup): the null-instance branch (FX-ii) and the outer catch
//     (FX-iii) now run cleanupPartialLoadLocked(pluginName) before dlclose, so a
//     pluginName-keyed factory export is unexported before the .so is unmapped.
// Each test reloads the same failing module twice — the second attempt exercises
// the idempotent double-cleanup path (M2) and proves the name is not bricked.
TEST_CASE("S-1 empty-identity ctor export is rejected; null-instance branch leaves no stale export")
{
  iora::IoraService &svc = *globalSvc;
  UnloadAllOnExit cleanup{svc};
  // Option A: exportApi(*this=empty identity, ...) throws inside the ctor -> the
  // IORA_DECLARE_PLUGIN factory catches it -> nullptr -> null-instance branch.
  // Nothing was ever inserted, so there is no stale export to reclaim.
  expectCleanFailedLoad(svc, "ctorexportplugin.so", "ctorexport.add");
  expectCleanFailedLoad(svc, "ctorexportplugin.so", "ctorexport.add");
}

TEST_CASE("S-1 factory export at the null-instance branch is unexported before dlclose")
{
  iora::IoraService &svc = *globalSvc;
  UnloadAllOnExit cleanup{svc};
  // A hand-written factory exports a pluginName-keyed API then returns nullptr;
  // cleanupPartialLoadLocked at the null-instance branch removes it before dlclose.
  expectCleanFailedLoad(svc, "factorynullexportplugin.so", "factorynullexport.add");
  expectCleanFailedLoad(svc, "factorynullexportplugin.so", "factorynullexport.add");
}

TEST_CASE("S-1 factory export at the outer catch is unexported before dlclose")
{
  iora::IoraService &svc = *globalSvc;
  UnloadAllOnExit cleanup{svc};
  // A hand-written factory exports a pluginName-keyed API then throws (reaching
  // the outer catch, which the macro can never reach); cleanupPartialLoadLocked
  // at the outer catch removes it before dlclose.
  expectCleanFailedLoad(svc, "factorythrowexportplugin.so", "factorythrowexport.add");
  expectCleanFailedLoad(svc, "factorythrowexportplugin.so", "factorythrowexport.add");
}

// --- Option A boundary: exportApi rejects an empty identity directly ----------
// The S-1 load tests reach Option A only indirectly (via a ctor export driving
// the null-instance branch). This asserts the boundary itself: exportApi with an
// empty identity throws std::invalid_argument (mirroring the empty-name reject),
// so no ""-keyed export can ever be inserted to dangle past dlclose.
TEST_CASE("Option A exportApi rejects an empty plugin identity")
{
  iora::IoraService &svc = *globalSvc;
  REQUIRE_THROWS_AS(
    svc.exportApi(std::string(""), "optiona.reject.probe", [](int a, int b) { return a + b; }),
    std::invalid_argument);
  // The rejected export was never registered.
  auto names = svc.getExportedApiNames();
  REQUIRE(std::find(names.begin(), names.end(), "optiona.reject.probe") == names.end());
}

// --- O-2: non-std::exception escapes the std-only load-failure handlers -------
// (tracker 2026-09-08-1). loadSingleModule's inner (:1269) and outer (:1317)
// catches, and the two onDependencyLoaded swallows (notifyDependentsOfLoad :1768,
// Plugin::require() :2628), all caught only const std::exception&. A non-std
// throw (`throw 42`) from onLoad / a custom factory / onDependencyLoaded escaped
// them, leaving a load-path module's exports live + its .so mapped+registered
// (load path), or breaking dependent-notify isolation asymmetrically (dep path).
// Fix: an outer catch(...) in loadSingleModule (D2) + catch(...) on BOTH
// onDependencyLoaded swallows (D1). NOTE: this is NOT a UAF at shutdown
// (_apiExports.clear() precedes ~PluginManager's dlclose), so the discriminator
// is the RUNTIME registration probe (expectCleanFailedLoad) / the load return
// value, never an ASan fault.

// FX-A: onLoad exports then throws a non-std -> loadSingleModule outer catch(...)
// (via inner-miss) unexports before dlclose. Reloaded twice (idempotent cleanup,
// name not bricked). MUT-1 (remove the outer catch(...) body) leaves the export
// stale in getExportedApiNames() and bricks the name.
TEST_CASE("O-2 non-std onLoad throw is unexported before dlclose (outer catch(...))")
{
  iora::IoraService &svc = *globalSvc;
  UnloadAllOnExit cleanup{svc};
  expectCleanFailedLoad(svc, "nonstdonloadthrowplugin.so", "nonstdonload.add");
  expectCleanFailedLoad(svc, "nonstdonloadthrowplugin.so", "nonstdonload.add");
}

// FX-B: a hand-written factory exports then throws a non-std BEFORE the inner try
// -> reaches loadSingleModule's outer catch(...) directly.
TEST_CASE("O-2 non-std factory throw is unexported before dlclose (outer catch(...))")
{
  iora::IoraService &svc = *globalSvc;
  UnloadAllOnExit cleanup{svc};
  expectCleanFailedLoad(svc, "factorynonstdthrowexportplugin.so", "factorynonstdthrowexport.add");
  expectCleanFailedLoad(svc, "factorynonstdthrowexportplugin.so", "factorynonstdthrowexport.add");
}

// FX-C1 (D1, require() site :2628): a dependent whose onDependencyLoaded throws a
// non-std. onLoad require()s an already-loaded dep, firing onDependencyLoaded via
// Plugin::require(). The widened catch(...) at :2628 swallows the non-std, so the
// dependent load SUCCEEDS — dependent-notify isolation is exception-type-agnostic
// (a std throw is already isolated here today). MUT-2ii (revert :2628 to
// std-only) lets the non-std escape require() -> escape onLoad (pre-insert) ->
// loadSingleModule's std catches miss -> outer catch(...) fails the load, so the
// dependent would NOT be loaded.
TEST_CASE("O-2 D1: non-std onDependencyLoaded via require() is isolated; dependent still loads")
{
  iora::IoraService &svc = *globalSvc;
  UnloadAllOnExit cleanup{svc};

  // The dependency must be loaded first (require() throws if it is not).
  REQUIRE(svc.loadSingleModule(pluginPath("testplugin.so")));
  REQUIRE(svc.isModuleLoaded("testplugin.so"));

  // The dependent's require() fires onDependencyLoaded (throws non-std), which the
  // widened :2628 catch(...) swallows -> onLoad completes -> dependent LOADS.
  // (tryLoad so that under MUT-2ii a rethrown non-std fails this cleanly instead
  // of terminating the binary.)
  REQUIRE(tryLoad(svc, pluginPath("requiredepnonstdthrowplugin.so")) == true);
  REQUIRE(svc.isModuleLoaded("requiredepnonstdthrowplugin.so"));
  REQUIRE(svc.isModuleLoaded("testplugin.so"));
}

// FX-C2 (D1, notify site :1768): with the dependent loaded (FX-C1 state), unload
// then RELOAD the dep. The reload's notifyDependentsOfLoad re-fires
// onDependencyLoaded (throws non-std) on the still-loaded dependent
// (_dependents[dep] survives the unload). The widened catch(...) at :1768
// swallows it, so the RELOAD SUCCEEDS. DISCRIMINATOR = the reload RETURN VALUE
// (tryLoad(reload) == true): under MUT-2i (revert :1768 to std-only) the non-std
// escapes -> loadSingleModule's outer catch(...) tears down the dep and rethrows
// -> the reload returns false.
TEST_CASE("O-2 D1: non-std onDependencyLoaded via reload-notify is isolated; reload succeeds")
{
  iora::IoraService &svc = *globalSvc;
  UnloadAllOnExit cleanup{svc};

  REQUIRE(svc.loadSingleModule(pluginPath("testplugin.so")));
  REQUIRE(tryLoad(svc, pluginPath("requiredepnonstdthrowplugin.so")) == true);
  REQUIRE(svc.isModuleLoaded("requiredepnonstdthrowplugin.so"));

  // Unload the dep (the dependent stays loaded; onDependencyUnloaded is a no-op).
  REQUIRE(svc.unloadSingleModule("testplugin.so"));
  REQUIRE(svc.isModuleLoaded("testplugin.so") == false);

  // Reload the dep -> notifyDependentsOfLoad fires onDependencyLoaded (non-std) on
  // the still-loaded dependent -> :1768 catch(...) swallows -> reload SUCCEEDS.
  REQUIRE(tryLoad(svc, pluginPath("testplugin.so")) == true);
  REQUIRE(svc.isModuleLoaded("testplugin.so"));
  REQUIRE(svc.isModuleLoaded("requiredepnonstdthrowplugin.so"));
}

int main(int argc, char *argv[])
{
  Catch::Session session;

  initializeTestLogging();

  iora::IoraService::Config config;
  config.server.port = 8137;
  config.state.file = "ioraservice_loadfailure_teardown_state.json";
  config.log.file = "ioraservice_loadfailure_teardown_log";
  config.modules.autoLoad = false;

  iora::IoraService::init(config);
  globalSvc = &iora::IoraService::instanceRef();

  // Export the control-block getter ONCE (no unexportApi exists; re-exporting
  // would throw "already registered"). It returns whatever the current test has
  // published in g_blockCtl.
  globalSvc->exportApi(std::string("test-harness"), "test.blockctl",
                       []() -> iora::test::BlockOnLoadControl * { return g_blockCtl.load(); });

  int result = session.run(argc, argv);

  globalSvc->shutdown();
  iora::util::removeFilesContainingAny(
    {"ioraservice_loadfailure_teardown_log", "ioraservice_loadfailure_teardown_state.json"});

  return result;
}
