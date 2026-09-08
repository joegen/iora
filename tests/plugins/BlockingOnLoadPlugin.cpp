// File: iora/tests/plugins/BlockingOnLoadPlugin.cpp
//
// DP-10b invariant probe (tracker 2026-09-07-9, F-4). Its onLoad exports an API
// (so a concurrent host caller can RESOLVE it and reach the is-loaded gate),
// then blocks holding _loadModulesMutex until the host releases it, then THROWS
// (the load fails). This lets the host prove that a concurrent callExportedApi
// is serialized behind the whole load (it must stay blocked on the is-loaded
// gate's _loadModulesMutex acquire until the failed load unwinds). If a future
// edit ever introduces a mid-load release window in loadSingleModule, the host's
// "concurrent caller stays blocked" assertion fails — the mechanized guard for
// the invariant that makes the load-failure drain unnecessary.
#include "iora/iora.hpp"

#include "blocking_onload_control.hpp"

#include <stdexcept>
#include <thread>

class BlockingOnLoadPlugin : public iora::IoraService::Plugin
{
public:
  explicit BlockingOnLoadPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    // Export first so a concurrent caller can resolve the name and reach the
    // is-loaded gate (step 1b of callExportedApi). Keyed by getIdentity()==_name,
    // which loadSingleModule set BEFORE onLoad — so it is cleaned by the
    // inner-catch removeExportsForModule when this load fails.
    svc->exportApi(*this, "blocking.call", [](int x) { return x; });

    // Fetch the host-owned control block via a host-exported getter.
    // getExportedApi takes only _apiMutex (never _loadModulesMutex), so calling
    // it here — while onLoad holds _loadModulesMutex — cannot deadlock.
    auto getCtl = svc->getExportedApi<iora::test::BlockOnLoadControl *()>("test.blockctl");
    iora::test::BlockOnLoadControl *ctl = getCtl();
    if (ctl == nullptr)
    {
      throw std::runtime_error("BlockingOnLoadPlugin: no control block registered");
    }

    ctl->onLoadEntered.store(1); // export visible + onLoad holds _loadModulesMutex
    while (ctl->release.load() == 0)
    {
      std::this_thread::yield();
    }
    // Intentional load failure AFTER the export, exercising the inner-catch
    // cleanup while a concurrent caller is (was) blocked on the is-loaded gate.
    throw std::runtime_error("BlockingOnLoadPlugin: intentional onLoad failure after unblock");
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(BlockingOnLoadPlugin)
