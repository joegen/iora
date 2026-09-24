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

  // Catch2 re-runs this body once per SECTION leaf, so the module MUST be unloaded
  // on every exit path — including a leaf abandoned by a failed REQUIRE. Without
  // this, the next leaf dies at the load above with "Plugin already loaded",
  // masking the original failure (the same defect fixed in iora_test_plugin.cpp).
  struct UnloadOnExit
  {
    iora::IoraService &svc;
    ~UnloadOnExit()
    {
      // Destructors are implicitly noexcept; unloading may throw.
      try
      {
        svc.unloadSingleModule("singletonprobe.so");
      }
      catch (...)
      {
      }
    }
  } unloadOnExit{svc};

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

  SECTION("Logger::handlerReentryDepth resolves to ONE thread_local instance host<->plugin")
  {
    // R-12: the self-clear/self-swap DEFER-vs-DRAIN branch (mechanism B, tracker
    // 2026-07-23-1) selects on this thread_local's depth. A divergent copy in a
    // plugin would make its depth>0 self-clear misread depth==0, take the depth-0
    // DRAIN branch (wait inflight==0) instead of deferring, and self-deadlock on its
    // own pinned frame.
    //
    // Assert the INSTANCE, not the function symbol — it is the property the drain's
    // depth branch depends on, and it holds regardless of how the function is
    // emitted. handlerReentryDepth() is now an out-of-line singleton defined once
    // in iora_core.cpp (like getData), so the single-instance property is
    // build-enforced; the instance assertion additionally survives any future
    // re-inlining, which a function-symbol comparison would not (measured: while
    // it was header-inline, a Release build gave differing function addresses with
    // matching instances).
    auto hostInstance = reinterpret_cast<std::uint64_t>(&iora::core::Logger::handlerReentryDepth());
    auto pluginInstance =
      svc.callExportedApi<std::uint64_t>("probe.handlerReentryDepthInstanceAddr");
    REQUIRE(hostInstance == pluginInstance);
  }

  SECTION("ownsLoadModulesMutex resolves to ONE thread_local instance host<->plugin")
  {
    // SD-2 (tracker 2026-09-24-9): the callExportedApi self-deadlock fix and every
    // SD-2 owner-thread fail-fast select on this thread_local flag. A divergent
    // plugin-.so copy would make a plugin-code caller's owns==true be read as
    // owns==false in the host TU, re-opening the re-lock the fix removes. Defined
    // once in iora_core.cpp (PAT-3); assert the INSTANCE, read on the caller's
    // thread so both sides see the same thread's thread_local.
    auto hostInstance = reinterpret_cast<std::uint64_t>(&iora::IoraService::ownsLoadModulesMutex());
    auto pluginInstance =
      svc.callExportedApi<std::uint64_t>("probe.ownsLoadModulesMutexInstanceAddr");
    REQUIRE(hostInstance == pluginInstance);
  }

  SECTION("inFlightApiModules resolves to ONE thread_local instance host<->plugin")
  {
    // The self-unload guard's per-thread in-flight multiset (DP-7). A divergent
    // plugin copy would make the unloader's self-unload check miss an in-flight
    // call recorded in the caller's copy. Out-of-line singleton in iora_core.cpp.
    auto hostInstance = reinterpret_cast<std::uint64_t>(&iora::IoraService::inFlightApiModules());
    auto pluginInstance =
      svc.callExportedApi<std::uint64_t>("probe.inFlightApiModulesInstanceAddr");
    REQUIRE(hostInstance == pluginInstance);
  }

  SECTION("Cross-boundary API calls work through shared IoraService")
  {
    auto loggerAddr = svc.callExportedApi<std::uint64_t>("probe.loggerAddr");
    REQUIRE(loggerAddr != 0);
    auto serviceAddr = svc.callExportedApi<std::uint64_t>("probe.serviceAddr");
    REQUIRE(serviceAddr != 0);
  }

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
