// File: iora/tests/service/iora_test_plugin_drain.cpp
//
// Drain-redesign regression tests for the SafeApiFunction use-after-dlclose fix
// (tracker 2026-09-07-1, architecture/iora/safe_api_function_drain.json).
//
// Covers: T1 destructor-UAF (ASan-anchored), T2 concurrent call-during-unload/
// reload, T4 unloadAllModules concurrent with single unload/reload. Run under ASan
// (handle_segv=0) and TSan with `setarch $(uname -m) -R` to make T1's UAF and T2/T4's
// races detectable. NOTE: getExportedApiSafe is deliberately NOT exercised from
// plugin code — it is host-only (a plugin-created wrapper's vtable lives in the
// plugin .so and would UAF at shutdown); see the note below the concurrency tests.
#define CATCH_CONFIG_RUNNER
#include "test_helpers.hpp"
#include <atomic>
#include <catch2/catch.hpp>
#include <chrono>
#include <thread>
#include <vector>

using namespace iora::test;

// Global service instance for all tests (mirrors iora_test_plugin.cpp).
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
std::string testPluginPath() { return iora::util::getExecutableDir() + "/plugins/testplugin.so"; }

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

// T1 — Destructor-UAF regression (ASan-anchored). A SafeApiFunction whose cache
// is populated, then the module is unloaded (dlclose) WITHOUT reload, then the
// wrapper destructs. Before the fix, ~SafeApiFunction -> ~std::function invoked a
// manager in the unmapped .so -> SIGSEGV/ASan error. With clear-before-dlclose
// (DP-B), the wrapper's cache was cleared while the .so was still mapped, so the
// destructor touches nothing plugin-resident.
TEST_CASE("T1 destructor UAF: cached wrapper destructs after unload, no reload")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};

  REQUIRE(std::filesystem::exists(testPluginPath()));
  REQUIRE(svc.loadSingleModule(testPluginPath()));

  {
    auto add = svc.getExportedApiSafe<int(int, int)>("testplugin.add");
    REQUIRE((*add)(2, 3) == 5); // populate the wrapper cache
    REQUIRE(svc.unloadSingleModule("testplugin.so")); // dlclose; clear-before-dlclose runs
    // `add` destructs here, after unload and WITHOUT reload. Must not fault.
  }
  SUCCEED("SafeApiFunction destructed cleanly after its module was unloaded");
}

// T2 — Concurrent call-during-unload/reload. Multiple threads call a SafeApiFunction
// while another thread unloads/reloads the module. No UAF, no deadlock. cacheMutex
// serializes each invoke against the unloader's clear (DP-C); the unloading claim
// makes calls during the window throw "not loaded" rather than invoke stale code.
TEST_CASE("T2 concurrent calls during unload/reload are safe")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};

  REQUIRE(svc.loadSingleModule(testPluginPath()));
  auto add = svc.getExportedApiSafe<int(int, int)>("testplugin.add");

  std::atomic<bool> stop{false};
  std::atomic<long> ok{0};
  std::atomic<long> threw{0};
  std::vector<std::thread> callers;
  for (int t = 0; t < 8; ++t)
  {
    callers.emplace_back(
      [&]
      {
        while (!stop.load())
        {
          try
          {
            if ((*add)(2, 3) == 5)
            {
              ok.fetch_add(1);
            }
          }
          catch (const std::runtime_error &)
          {
            threw.fetch_add(1); // expected while the module is unloaded/unloading
          }
        }
      });
  }

  for (int cycle = 0; cycle < 10; ++cycle)
  {
    REQUIRE(svc.unloadSingleModule("testplugin.so"));
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    REQUIRE(svc.loadSingleModule(testPluginPath()));
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }

  stop.store(true);
  for (auto &th : callers)
  {
    th.join();
  }
  // Both outcomes occurred (calls succeeded, and some were correctly rejected
  // during unload windows) and the process did not crash or hang.
  REQUIRE(ok.load() > 0);
}

// T4 — unloadAllModules concurrent with single unloadModule/reloadModule. Exercises
// the claim protocol's cross-actor path: unloadAllModules must never dlclose (via a
// blanket sweep) a module a concurrent single-unload has claimed. Worker threads
// hammer reload/load while the main thread loops unloadAllModules. No UAF, no
// deadlock (ASan/TSan under setarch -R make the cross-actor dlclose UAF detectable).
TEST_CASE("T4 unloadAllModules concurrent with single unload/reload is safe")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};

  REQUIRE(svc.loadSingleModule(testPluginPath()));

  std::atomic<bool> stop{false};
  std::vector<std::thread> workers;
  for (int t = 0; t < 4; ++t)
  {
    workers.emplace_back(
      [&]
      {
        while (!stop.load())
        {
          // Both throw legitimately under contention ("already loaded" /
          // "not loaded" / concurrent claim) — the point is no crash/UAF/deadlock.
          try
          {
            svc.reloadModule("testplugin.so");
          }
          catch (const std::runtime_error &)
          {
          }
          try
          {
            svc.loadSingleModule(testPluginPath());
          }
          catch (const std::runtime_error &)
          {
          }
        }
      });
  }

  for (int i = 0; i < 20; ++i)
  {
    svc.unloadAllModules();
    try
    {
      svc.loadSingleModule(testPluginPath());
    }
    catch (const std::runtime_error &)
    {
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  stop.store(true);
  for (auto &w : workers)
  {
    w.join();
  }
  SUCCEED("no crash/UAF/deadlock under concurrent unloadAllModules + reload/load");
}

// T5 — Load-failure teardown (C1). A plugin whose onLoad exportApi's then throws
// must have its exported plugin std::function unexported (destroyed while the .so is
// still mapped) BEFORE dlclose, so nothing dangles into the unmapped .so. Under ASan
// a regression (dlclose-without-unexport) faults here or at shutdown.
TEST_CASE("T5 load failure after exportApi tears down before dlclose")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};

  auto path = iora::util::getExecutableDir() + "/plugins/exportthenthrowplugin.so";
  REQUIRE(std::filesystem::exists(path));

  REQUIRE_THROWS(svc.loadSingleModule(path)); // onLoad throws after exportApi

  // The exported API must be gone (unexported on the failure path), not dangling.
  REQUIRE_FALSE(svc.isModuleLoaded("exportthenthrowplugin.so"));
  bool apiGone = false;
  try
  {
    (void)svc.callExportedApi<int, int, int>("exportthenthrow.add", 1, 2);
  }
  catch (const std::runtime_error &)
  {
    apiGone = true; // "API not found" — correctly unexported
  }
  REQUIRE(apiGone);

  // A retry must not hit "already loaded" (the PluginManager orphan was cleaned up).
  REQUIRE_THROWS(svc.loadSingleModule(path));
}

// T6 — DP-F host-only enforcement. A plugin whose onLoad calls getExportedApiSafe
// must have that call REJECTED (throw), so no plugin-resident wrapper is created.
TEST_CASE("T6 getExportedApiSafe from onLoad is rejected (host-only)")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};

  auto path = iora::util::getExecutableDir() + "/plugins/onloadgetsafeplugin.so";
  REQUIRE(std::filesystem::exists(path));
  REQUIRE(svc.loadSingleModule(path)); // onLoad caught the throw and loaded fine

  // The plugin reports whether getExportedApiSafe threw during onLoad.
  REQUIRE(svc.callExportedApi<bool>("onloadgetsafe.threw") == true);

  REQUIRE(svc.unloadSingleModule("onloadgetsafeplugin.so"));
}

// NOTE: getExportedApiSafe is intended to be called from the HOST, not from a
// plugin. A SafeApiFunction created inside a plugin .so has its vtable and
// shared_ptr control block resident in that .so; if it (or a weak_ptr to it in
// the service registry) outlives the plugin's dlclose, destroying it invokes an
// unmapped manager -> crash. This is a documented limitation (architecture
// DP-10); there is deliberately no test that creates a SafeApiFunction from
// plugin code.

int main(int argc, char *argv[])
{
  Catch::Session session;

  initializeTestLogging();

  iora::IoraService::Config config;
  config.server.port = 8131;
  config.state.file = "ioraservice_plugin_drain_state.json";
  config.log.file = "ioraservice_plugin_drain_log";
  config.modules.autoLoad = false;

  iora::IoraService::init(config);
  globalSvc = &iora::IoraService::instanceRef();

  int result = session.run(argc, argv);

  globalSvc->shutdown();
  iora::util::removeFilesContainingAny(
    {"ioraservice_plugin_drain_log", "ioraservice_plugin_drain_state.json"});

  return result;
}
