// File: iora/tests/plugins/OnLoadGetSafePlugin.cpp
//
// onLoad calls getExportedApiSafe — exercises DP-F host-only enforcement: a plugin
// calling getExportedApiSafe during load (this thread holds _loadModulesMutex) must
// be REJECTED with a throw (its wrapper's vtable would live in the plugin .so and
// use-after-dlclose). The plugin catches the throw and exports a bool API reporting
// it, so the test can assert the enforcement fired without relying on load failure.
#include "iora/iora.hpp"

class OnLoadGetSafePlugin : public iora::IoraService::Plugin
{
public:
  explicit OnLoadGetSafePlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    bool threw = false;
    try
    {
      auto w = svc->getExportedApiSafe<int(int)>("onloadgetsafe.noop");
      (void)w; // if DP-F regresses and this does NOT throw, threw stays false
    }
    catch (const std::exception &)
    {
      threw = true;
    }
    svc->exportApi(*this, "onloadgetsafe.threw", [threw]() { return threw; });
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(OnLoadGetSafePlugin)
