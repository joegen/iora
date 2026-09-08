// File: iora/tests/plugins/UnloadDepNonStdThrowPlugin.cpp
//
// FX-U1 dependent D1 (tracker 2026-09-08-4). Depends on testplugin.so and throws
// a NON-std::exception (`throw 42`) from onDependencyUnloaded. When testplugin is
// unloaded, notifyDependentsOfUnload fires this callback; the widened catch(...)
// at the swallow site must isolate the non-std throw so (a) testplugin's unload
// still SUCCEEDS and (b) the remaining dependents (D2) are still notified. Under
// MUT-U1 (revert the swallow to std-only) the non-std escapes into
// teardownModuleHostSideLocked's outer catch(...), the unload returns false, and
// D2 (loaded after D1) is never notified.
#include "iora/iora.hpp"

class UnloadDepNonStdThrowPlugin : public iora::IoraService::Plugin
{
public:
  explicit UnloadDepNonStdThrowPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    (void)svc;
    // The dependency must already be loaded (require() throws otherwise); the
    // host loads testplugin.so first. This registers _dependents[testplugin.so].
    require("testplugin.so");
  }

  void onDependencyUnloaded(const std::string &moduleName) override
  {
    (void)moduleName;
    throw 42; // NON-std: isolated by the widened catch(...) at the swallow site
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(UnloadDepNonStdThrowPlugin)
