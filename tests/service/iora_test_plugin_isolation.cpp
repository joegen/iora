#define CATCH_CONFIG_RUNNER
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

using namespace iora::test;

static iora::IoraService *globalSvc = nullptr;

TEST_CASE("Singleton isolation: Logger and IoraService shared across plugin boundary")
{
  iora::IoraService &svc = *globalSvc;

  auto pluginPath = iora::util::getExecutableDir() + "/plugins/singletonprobe.so";
  REQUIRE(std::filesystem::exists(pluginPath));
  REQUIRE(svc.loadSingleModule(pluginPath));

  SECTION("Logger::getData address is identical in host and plugin")
  {
    auto hostAddr = reinterpret_cast<std::uint64_t>(&iora::core::Logger::getData);
    auto pluginAddr = svc.callExportedApi<std::uint64_t>("probe.loggerAddr");
    REQUIRE(hostAddr == pluginAddr);
  }

  SECTION("IoraService::getInstancePtr address is identical in host and plugin")
  {
    auto hostAddr = reinterpret_cast<std::uint64_t>(&iora::IoraService::getInstancePtr);
    auto pluginAddr = svc.callExportedApi<std::uint64_t>("probe.serviceAddr");
    REQUIRE(hostAddr == pluginAddr);
  }

  SECTION("Cross-boundary API calls work through shared IoraService")
  {
    auto loggerAddr = svc.callExportedApi<std::uint64_t>("probe.loggerAddr");
    REQUIRE(loggerAddr != 0);
    auto serviceAddr = svc.callExportedApi<std::uint64_t>("probe.serviceAddr");
    REQUIRE(serviceAddr != 0);
  }

  svc.unloadAllModules();
}

int main(int argc, char *argv[])
{
  Catch::Session session;

  initializeTestLogging();

  iora::IoraService::Config config;
  config.server.port = 8140;
  config.state.file = "ioraservice_isolation_state.json";
  config.log.file = "ioraservice_isolation_log";
  config.modules.autoLoad = false;

  iora::IoraService::init(config);
  globalSvc = &iora::IoraService::instanceRef();

  int result = session.run(argc, argv);

  globalSvc->shutdown();
  iora::util::removeFilesContainingAny(
    {"ioraservice_isolation_log", "ioraservice_isolation_state.json"});

  return result;
}
