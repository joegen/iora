#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "test_helpers.hpp"
#include "iora/iora.hpp"

using AutoServiceShutdown = iora::IoraService::AutoServiceShutdown;

TEST_CASE("Simple chained dependencies test", "[simple]")
{
  // Get plugin paths
  auto basePluginPath = iora::util::getExecutableDir() + "/plugins/baseplugin.so";
  auto dependentPluginPath = iora::util::getExecutableDir() + "/plugins/dependentplugin.so";
  auto chainedPluginPath = iora::util::getExecutableDir() + "/plugins/chainedplugin.so";

  // Setup IoraService config 
  iora::IoraService::Config config;
  config.server.port = 8144;
  config.state.file = "simple_test_state.json";
  config.log.file = "simple_test_log";
  config.modules.autoLoad = false; // Disable automatic module loading

  // Initialize service with config
  iora::IoraService::init(config);
  iora::IoraService& svc = iora::IoraService::instanceRef();
  
  // Load all three plugins in correct order
  REQUIRE(svc.loadSingleModule(basePluginPath));
  REQUIRE(svc.loadSingleModule(dependentPluginPath));
  REQUIRE(svc.loadSingleModule(chainedPluginPath));
  
  // Verify chained plugin can access all dependencies
  std::string chainResult = svc.callExportedApi<std::string>("chainedplugin.useChain");
  REQUIRE(chainResult.find("BasePlugin v1.0") != std::string::npos);
  REQUIRE(chainResult.find("BasePlugin available") != std::string::npos);
  
  // Verify dependency status tracking
  std::string depStatus = svc.callExportedApi<std::string>("chainedplugin.getDependencyStatus");
  REQUIRE(depStatus == "BaseDep: 1, DependentDep: 1");
  
  // Test complex operation using multiple dependencies
  std::string complexResult = svc.callExportedApi<std::string>("chainedplugin.complexOperation");
  REQUIRE(complexResult.find("Complex operation result") != std::string::npos);
  REQUIRE(complexResult.find("counter: 3") != std::string::npos); // Should be 3 after 2 increments
  
  // Explicitly shutdown before section ends
  iora::IoraService::shutdown();
}