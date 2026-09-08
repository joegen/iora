// File: iora/tests/plugins/OnUnloadRecordPlugin.cpp
//
// FX-U4 module Mb (trackers 2026-09-08-4, cpp17 LOW-2 batch-isolation coverage).
// An independent, well-behaved module whose onUnload records that it ran in the
// host-owned control block. Paired in unloadAllModules with a sibling module
// whose onUnload throws: the widened teardown catch(...) isolates the throwing
// sibling per-module (teardown returns false, loop continues), so Mb is still
// torn down and its onUnload still runs — proving one module's onUnload throw
// does not abort the batch.
#include "iora/iora.hpp"

#include "unload_teardown_control.hpp"

class OnUnloadRecordPlugin : public iora::IoraService::Plugin
{
public:
  explicit OnUnloadRecordPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    auto getCtl = svc->getExportedApi<iora::test::UnloadTeardownControl *()>("test.unloadctl");
    _ctl = getCtl();
  }

  void onUnload() override
  {
    if (_ctl != nullptr)
    {
      _ctl->mbOnUnloadRan.fetch_add(1);
    }
  }

private:
  iora::test::UnloadTeardownControl *_ctl = nullptr;
};

IORA_DECLARE_PLUGIN(OnUnloadRecordPlugin)
