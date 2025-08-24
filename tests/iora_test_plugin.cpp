#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "test_helpers.hpp"

using namespace iora::test;

TEST_CASE("Dynamic loading of testplugin shared library")
{
  initializeTestLogging();

  // Setup IoraService config
  iora::IoraService::Config config;
  config.server.port = 8130;
  config.state.file = "ioraservice_plugin_state.json";
  config.log.file = "ioraservice_plugin_log";

  // Initialize service with config
  iora::IoraService::init(config);
  iora::IoraService& svc = iora::IoraService::instance();
  AutoServiceShutdown autoShutdown(svc);

  auto pluginPathOpt =
      iora::util::getExecutableDir() + "/plugins/testplugin.so";
  std::cout << "Plugin path: " << pluginPathOpt << std::endl;
  REQUIRE(std::filesystem::exists(pluginPathOpt));
  REQUIRE(svc.loadSingleModule(pluginPathOpt));

  SECTION("callExportedApi: add")
  {
    int sum = svc.callExportedApi<int, int, int>("testplugin.add", 2, 3);
    REQUIRE(sum == 5);
  }

  SECTION("callExportedApi: greet")
  {
    std::string greet = svc.callExportedApi<std::string, const std::string&>(
        "testplugin.greet", "World");
    REQUIRE(greet == "Hello, World!");
  }

  SECTION("callExportedApi: toggleLoaded and isLoaded")
  {
    bool loaded1 = svc.callExportedApi<bool>("testplugin.isLoaded");
    bool toggled = svc.callExportedApi<bool>("testplugin.toggleLoaded");
    bool loaded2 = svc.callExportedApi<bool>("testplugin.isLoaded");
    REQUIRE(loaded1 == true);
    REQUIRE(toggled == false);
    REQUIRE(loaded2 == false);
  }

  SECTION("getExportedApi: add")
  {
    auto addApi = svc.getExportedApi<int(int, int)>("testplugin.add");
    REQUIRE(addApi(10, 20) == 30);
  }

  SECTION("getExportedApi: greet")
  {
    auto greetApi =
        svc.getExportedApi<std::string(const std::string&)>("testplugin.greet");
    REQUIRE(greetApi("Iora") == "Hello, Iora!");
  }

  SECTION("Plugin reload: unload and reload shared library")
  {
    REQUIRE(svc.unloadSingleModule("testplugin.so"));

    bool threw = false;
    try
    {
      (void) svc.callExportedApi<int, int, int>("testplugin.add", 1, 1);
    }
    catch (...)
    {
      threw = true;
    }
    REQUIRE(threw);

    REQUIRE(svc.loadSingleModule(pluginPathOpt));
    REQUIRE(svc.callExportedApi<int, int, int>("testplugin.add", 7, 8) == 15);
    REQUIRE(svc.callExportedApi<std::string, const std::string&>(
                "testplugin.greet", "Reloaded") == "Hello, Reloaded!");
  }

  iora::util::removeFilesContainingAny(
      {"ioraservice_plugin_log", "ioraservice_plugin_state.json"});
}
