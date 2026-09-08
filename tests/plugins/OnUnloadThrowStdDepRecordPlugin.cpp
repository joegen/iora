// File: iora/tests/plugins/OnUnloadThrowStdDepRecordPlugin.cpp
//
// FX-U2 module M (trackers 2026-09-08-4 / -3). M DEPENDS ON testplugin.so (so it
// is a VALUE in _dependents[testplugin.so] — the edge pruneModuleTrackingLocked
// actually mutates). M's onUnload throws a std exception EXACTLY once (armed via
// the control block), so the first unloadSingleModule(M) returns false and M
// stays loaded. Option A leaves M's tracking intact, so a later unload of
// testplugin.so still notifies M via onDependencyUnloaded(testplugin) — recorded
// here (mDepUnloadedFromB == 1). Under MUT-U3 (prune-regardless) the failed
// unload prunes M from _dependents[testplugin.so], so the later notify is lost
// (mDepUnloadedFromB == 0).
#include "iora/iora.hpp"

#include "unload_teardown_control.hpp"

#include <stdexcept>

class OnUnloadThrowStdDepRecordPlugin : public iora::IoraService::Plugin
{
public:
  explicit OnUnloadThrowStdDepRecordPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    auto getCtl = svc->getExportedApi<iora::test::UnloadTeardownControl *()>("test.unloadctl");
    _ctl = getCtl();
    require("testplugin.so"); // M depends on B = testplugin.so
  }

  void onUnload() override
  {
    // Throw a std exception exactly once (while armed) so the first unload attempt
    // fails (M stays loaded) but the later cleanup unload succeeds.
    if (_ctl != nullptr && _ctl->armStdOnUnloadThrow.load() > 0)
    {
      _ctl->armStdOnUnloadThrow.fetch_sub(1);
      throw std::runtime_error("OnUnloadThrowStdDepRecordPlugin: intentional onUnload throw");
    }
  }

  void onDependencyUnloaded(const std::string &moduleName) override
  {
    if (moduleName == "testplugin.so" && _ctl != nullptr)
    {
      _ctl->mDepUnloadedFromB.fetch_add(1);
    }
  }

private:
  iora::test::UnloadTeardownControl *_ctl = nullptr;
};

IORA_DECLARE_PLUGIN(OnUnloadThrowStdDepRecordPlugin)
