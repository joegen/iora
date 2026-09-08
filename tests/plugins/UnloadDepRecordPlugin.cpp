// File: iora/tests/plugins/UnloadDepRecordPlugin.cpp
//
// FX-U1 dependent D2 (tracker 2026-09-08-4). Well-behaved dependent of
// testplugin.so that RECORDS its onDependencyUnloaded(testplugin) firing in the
// host-owned control block. Loaded AFTER D1, so _dependents[testplugin.so] =
// [D1, D2]. With the swallow widened, D1's non-std throw is isolated and the
// loop continues, so D2 IS notified (d2DepUnloaded == 1). Under MUT-U1 the loop
// aborts at D1 and D2 is never notified (d2DepUnloaded == 0).
#include "iora/iora.hpp"

#include "unload_teardown_control.hpp"

class UnloadDepRecordPlugin : public iora::IoraService::Plugin
{
public:
  explicit UnloadDepRecordPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    // Fetch the host-owned control block via the host-exported getter.
    // getExportedApi takes only _apiMutex (never _loadModulesMutex), so calling
    // it here — while onLoad holds _loadModulesMutex — cannot deadlock. Cache it;
    // the teardown-time callback below must not call back into the service API.
    auto getCtl = svc->getExportedApi<iora::test::UnloadTeardownControl *()>("test.unloadctl");
    _ctl = getCtl();
    require("testplugin.so");
  }

  void onDependencyUnloaded(const std::string &moduleName) override
  {
    if (moduleName == "testplugin.so" && _ctl != nullptr)
    {
      _ctl->d2DepUnloaded.fetch_add(1);
    }
  }

  void onUnload() override {}

private:
  iora::test::UnloadTeardownControl *_ctl = nullptr;
};

IORA_DECLARE_PLUGIN(UnloadDepRecordPlugin)
