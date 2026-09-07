// File: iora/tests/service/iora_test_api_module_reverse_map.cpp
//
// Regression tests for the authoritative apiName -> owning-module reverse map
// (tracker 2026-09-07-8, architecture/iora/api_module_reverse_map.json).
// Covers A-T1 (resolution correctness, folds backlog -4), A-T2 (identity-
// overload teardown at both host-side sites, folds backlog -6), A-T3 (map
// maintenance), and A-T4 (owner-checked single atomic erase).
#define CATCH_CONFIG_RUNNER
#include "test_helpers.hpp"
#include <algorithm>
#include <catch2/catch.hpp>

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

// --- A-T1: resolution correctness (folds backlog -4) -----------------------

TEST_CASE("A-T1 resolves a normal <module>.<api> name to the correct module")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};

  REQUIRE(svc.loadSingleModule(pluginPath("testplugin.so")));

  auto w = svc.getExportedApiSafe<int(int, int)>("testplugin.add");
  REQUIRE(w->getModuleName() == "testplugin.so");
  REQUIRE((*w)(2, 3) == 5);
}

TEST_CASE("A-T1 resolves colliding-prefix module names to their own owner")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};

  // "collidepfx.so" is itself a filename-prefix of "collidepfxplus.so".
  REQUIRE(svc.loadSingleModule(pluginPath("collidepfxplugin.so")));
  REQUIRE(svc.loadSingleModule(pluginPath("collidepfxplusplugin.so")));

  auto w1 = svc.getExportedApiSafe<int()>("collidepfx.value");
  REQUIRE(w1->getModuleName() == "collidepfxplugin.so");
  REQUIRE((*w1)() == 111);

  auto w2 = svc.getExportedApiSafe<int()>("collidepfxplus.value");
  REQUIRE(w2->getModuleName() == "collidepfxplusplugin.so");
  REQUIRE((*w2)() == 222);
}

TEST_CASE("A-T1 resolves a non-<module>.<api>-convention name correctly")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};

  // Module "nonconventionplugin.so" exports "unrelated.thing" -- the api
  // prefix ("unrelated") bears no relation to the module's own filename. The
  // old prefix+".so" heuristic could never resolve this (it would guess a
  // nonexistent module "unrelated.so").
  REQUIRE(svc.loadSingleModule(pluginPath("nonconventionplugin.so")));

  auto w = svc.getExportedApiSafe<int()>("unrelated.thing");
  REQUIRE(w->getModuleName() == "nonconventionplugin.so");
  REQUIRE((*w)() == 333);
}

TEST_CASE("A-T1 an absent api name makes getExportedApiSafe throw, not guess a module")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};

  REQUIRE_THROWS_AS(svc.getExportedApiSafe<int()>("totally.absent.api"), std::runtime_error);
}

// --- A-T2: identity-overload teardown at BOTH host-side sites (folds -6) ---

TEST_CASE("A-T2a identity-overload export is torn down on normal unload")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};

  REQUIRE(svc.loadSingleModule(pluginPath("identityexportplugin.so")));
  REQUIRE(svc.callExportedApi<int>("identityexport.value") == 444);

  REQUIRE(svc.unloadSingleModule("identityexportplugin.so"));

  // Neither map may retain the entry: not callable, and getExportedApiNames
  // no longer lists it.
  REQUIRE_THROWS_AS(svc.callExportedApi<int>("identityexport.value"), std::runtime_error);
  auto names = svc.getExportedApiNames();
  REQUIRE(std::find(names.begin(), names.end(), "identityexport.value") == names.end());
}

TEST_CASE("A-T2a Plugin&-overload export is torn down exactly once on normal unload")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};

  REQUIRE(svc.loadSingleModule(pluginPath("testplugin.so")));
  REQUIRE(svc.callExportedApi<int, int, int>("testplugin.add", 2, 3) == 5);

  REQUIRE(svc.unloadSingleModule("testplugin.so"));
  REQUIRE_THROWS_AS((svc.callExportedApi<int, int, int>("testplugin.add", 2, 3)), std::runtime_error);

  // testplugin.so exports FOUR names (TestPlugin.cpp: add, greet,
  // toggleLoaded, isLoaded) -- removeExportsForModule must erase all of them
  // in its single pass, not just the one this test happens to call.
  static const char *kTestPluginApis[] = {"testplugin.add", "testplugin.greet",
                                          "testplugin.toggleLoaded", "testplugin.isLoaded"};
  auto names = svc.getExportedApiNames();
  for (const auto *api : kTestPluginApis)
  {
    REQUIRE(std::find(names.begin(), names.end(), std::string(api)) == names.end());
  }
  REQUIRE_THROWS_AS(svc.getExportedApiSafe<int(int, int)>("testplugin.add"), std::runtime_error);
  REQUIRE_THROWS_AS(svc.getExportedApiSafe<std::string(const std::string &)>("testplugin.greet"),
                    std::runtime_error);
  REQUIRE_THROWS_AS(svc.getExportedApiSafe<bool()>("testplugin.toggleLoaded"), std::runtime_error);
  REQUIRE_THROWS_AS(svc.getExportedApiSafe<bool()>("testplugin.isLoaded"), std::runtime_error);
}

TEST_CASE("A-T2a removeExportsForModule erases only the unloaded module's entries, "
          "leaving a second live module's exports intact")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};

  // testplugin.so is the multi-export module being torn down (4 names);
  // collidepfxplugin.so is the second, unrelated module that must survive
  // the single removeExportsForModule pass -- this exercises BOTH the erase
  // branch (it->second == module) and the skip branch (it->second != module)
  // of the same pass.
  REQUIRE(svc.loadSingleModule(pluginPath("testplugin.so")));
  REQUIRE(svc.loadSingleModule(pluginPath("collidepfxplugin.so")));
  REQUIRE(svc.callExportedApi<int, int, int>("testplugin.add", 2, 3) == 5);
  REQUIRE(svc.callExportedApi<int>("collidepfx.value") == 111);

  REQUIRE(svc.unloadSingleModule("testplugin.so"));

  static const char *kTestPluginApis[] = {"testplugin.add", "testplugin.greet",
                                          "testplugin.toggleLoaded", "testplugin.isLoaded"};
  auto names = svc.getExportedApiNames();
  for (const auto *api : kTestPluginApis)
  {
    REQUIRE(std::find(names.begin(), names.end(), std::string(api)) == names.end());
  }
  REQUIRE_THROWS_AS(svc.getExportedApiSafe<int(int, int)>("testplugin.add"), std::runtime_error);

  // collidepfxplugin.so was never named in that pass -- its entry must
  // survive untouched.
  REQUIRE(std::find(names.begin(), names.end(), std::string("collidepfx.value")) != names.end());
  REQUIRE(svc.callExportedApi<int>("collidepfx.value") == 111);
  auto w = svc.getExportedApiSafe<int()>("collidepfx.value");
  REQUIRE(w->getModuleName() == "collidepfxplugin.so");
}

TEST_CASE("A-T2b identity-overload export is torn down on load-failure (cpp17 H-1)")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};

  auto path = pluginPath("identityexportthenthrowplugin.so");
  REQUIRE(std::filesystem::exists(path));

  REQUIRE_THROWS(svc.loadSingleModule(path)); // onLoad exports, then throws

  REQUIRE_FALSE(svc.isModuleLoaded("identityexportthenthrowplugin.so"));
  REQUIRE_THROWS_AS((svc.callExportedApi<int, int, int>("identityexportthenthrow.add", 1, 2)),
                    std::runtime_error);

  // A retry must not hit "already loaded" (the PluginManager orphan entry was
  // cleaned up on the failure path).
  REQUIRE_THROWS(svc.loadSingleModule(path));
}

// --- A-T3: map maintenance --------------------------------------------------

TEST_CASE("A-T3 exportApi populates the reverse map; duplicate-name throw mutates neither map")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};

  REQUIRE(svc.loadSingleModule(pluginPath("testplugin.so")));

  // Exercise the identity overload directly (as a host would), using the
  // already-loaded module's own identity so removeExportsForModule
  // ("testplugin.so") tears this down together with the plugin's own
  // Plugin&-overload exports on unload -- no separate cleanup call needed.
  svc.exportApi(std::string("testplugin.so"), "maptest.value", []() { return 1; });

  auto w = svc.getExportedApiSafe<int()>("maptest.value");
  REQUIRE(w->getModuleName() == "testplugin.so");
  REQUIRE(svc.callExportedApi<int>("maptest.value") == 1);

  // Duplicate-name exportApi throws and must leave both maps exactly as they
  // were -- still resolving to the ORIGINAL owner, not the failed identity.
  REQUIRE_THROWS_AS(
    svc.exportApi(std::string("some.other.identity"), "maptest.value", []() { return 2; }),
    std::runtime_error);

  auto w2 = svc.getExportedApiSafe<int()>("maptest.value");
  REQUIRE(w2->getModuleName() == "testplugin.so");
  REQUIRE(svc.callExportedApi<int>("maptest.value") == 1);

  // Plugin&-overload export unaffected/coexisting.
  REQUIRE(svc.callExportedApi<int, int, int>("testplugin.add", 2, 3) == 5);
}

// --- A-T4: owner-checked single atomic erase (A-DP-4) -----------------------

TEST_CASE("A-T4 a same-named api re-bound to a different live module is not erased "
          "by a failed loader's teardown")
{
  iora::IoraService &svc = getTestService();
  UnloadAllOnExit cleanup{svc};

  REQUIRE(svc.loadSingleModule(pluginPath("ownerplugin.so")));
  REQUIRE(svc.callExportedApi<int>("reboundapi.value") == 555);

  // ownerconflictplugin.so's onLoad tries to export the SAME name while
  // ownerplugin.so still owns it -- exportApi's duplicate-name check throws,
  // driving loadSingleModule's load-failure cleanup with an identity
  // ("ownerconflictplugin.so") that never actually owned "reboundapi.value".
  auto conflictPath = pluginPath("ownerconflictplugin.so");
  REQUIRE(std::filesystem::exists(conflictPath));
  REQUIRE_THROWS(svc.loadSingleModule(conflictPath));

  // ownerplugin.so's live entry must be untouched: owner-checked erase.
  REQUIRE(svc.isModuleLoaded("ownerplugin.so"));
  REQUIRE(svc.callExportedApi<int>("reboundapi.value") == 555);
  auto w = svc.getExportedApiSafe<int()>("reboundapi.value");
  REQUIRE(w->getModuleName() == "ownerplugin.so");

  // The failed loader must not be left in a stale "already loaded" state.
  REQUIRE_FALSE(svc.isModuleLoaded("ownerconflictplugin.so"));
  REQUIRE_THROWS(svc.loadSingleModule(conflictPath));
}

int main(int argc, char *argv[])
{
  Catch::Session session;

  initializeTestLogging();

  iora::IoraService::Config config;
  config.server.port = 8132;
  config.state.file = "ioraservice_api_module_reverse_map_state.json";
  config.log.file = "ioraservice_api_module_reverse_map_log";
  config.modules.autoLoad = false;

  iora::IoraService::init(config);
  globalSvc = &iora::IoraService::instanceRef();

  int result = session.run(argc, argv);

  globalSvc->shutdown();
  iora::util::removeFilesContainingAny(
    {"ioraservice_api_module_reverse_map_log", "ioraservice_api_module_reverse_map_state.json"});

  return result;
}
