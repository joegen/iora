// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Cross-.so test for iora::ServiceRegistry. A test plugin registers an IFoo impl
// in onLoad; this core-process test retrieves it via get<IFoo>() and calls a
// virtual method across the .so boundary (proves storage-in-core C-4 unifies the
// foundation and plugin views — a header-inline-static registry would make
// get<IFoo>() return nullptr here). It then unloads the module and asserts the
// entry is gone (proves the core-driven unregister-on-unload, C-5).

#define CATCH_CONFIG_RUNNER
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/core/service_registry.hpp>

#include "web/registry_cross_so_iface.hpp"

#include <filesystem>

using namespace iora::test;

static iora::IoraService *globalSvc = nullptr;

TEST_CASE("ServiceRegistry cross-.so: plugin registers, core retrieves + virtual-dispatches "
          "(C-4/C-5)",
          "[service_registry][crossso]")
{
  iora::IoraService &svc = *globalSvc;

  const auto pluginPath =
    iora::util::getExecutableDir() + "/web_plugins/web_test_registry_plugin.so";
  REQUIRE(std::filesystem::exists(pluginPath));

  // Before load: no plugin has registered IFoo.
  REQUIRE(iora::ServiceRegistry::get<iora_web_crossso_test::IFoo>() == nullptr);

  REQUIRE(svc.loadSingleModule(pluginPath));

  // After load: the plugin's impl is retrievable from the core process and a
  // virtual call dispatches across the .so boundary to the plugin's override.
  {
    auto foo = iora::ServiceRegistry::get<iora_web_crossso_test::IFoo>();
    REQUIRE(foo != nullptr);
    REQUIRE(foo->magic() == 4242);
    REQUIRE(foo->name() == "from-plugin");
    // Drop our reference BEFORE unload (the drain-before-unload invariant, RD-7):
    // the impl's vtable lives in the plugin .so and is unmapped by dlclose.
  }

  // Unload: the authoritative core-driven unregisterModule(pluginName) removes
  // the registration before dlclose (C-5).
  REQUIRE(svc.unloadSingleModule("web_test_registry_plugin.so"));
  REQUIRE(iora::ServiceRegistry::get<iora_web_crossso_test::IFoo>() == nullptr);
}

int main(int argc, char *argv[])
{
  Catch::Session session;

  initializeTestLogging();

  iora::IoraService::Config config;
  // Distinct, high port to avoid colliding with other service tests' fixed ports
  // (e.g. the plugin-isolation test uses 8140). Web tests run -j1, so only this
  // process binds it at a time.
  config.server.port = 18141;
  config.state.file = "ioraservice_crossso_state.json";
  config.log.file = "ioraservice_crossso_log";
  config.modules.autoLoad = false;

  iora::IoraService::init(config);
  globalSvc = &iora::IoraService::instanceRef();

  int result = session.run(argc, argv);

  globalSvc->shutdown();
  iora::util::removeFilesContainingAny(
    {"ioraservice_crossso_log", "ioraservice_crossso_state.json"});

  return result;
}
