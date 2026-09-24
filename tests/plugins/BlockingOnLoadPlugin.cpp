// File: iora/tests/plugins/BlockingOnLoadPlugin.cpp
//
// Blocking-onLoad probe (tracker 2026-09-07-9 F-4, re-scoped for SD-1 tracker
// 2026-09-24-9). Its onLoad exports an API (so a concurrent host caller can
// RESOLVE it), then blocks holding _loadModulesMutex until the host releases it,
// then THROWS (the load fails). SD-1: callExportedApi no longer takes
// _loadModulesMutex, so a concurrent call is REJECTED "not loaded" PROMPTLY (the
// module is not yet markApiCallable'd) rather than serialized behind the load.
// The RETAINED DP-10b guard is a concurrent non-owner isModuleLoaded, which still
// takes _loadModulesMutex and so stays blocked until the failed load unwinds; if
// a future edit introduces a mid-load release window in loadSingleModule, that
// "stays blocked" assertion fails.
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
    // Export first so a concurrent caller can resolve the name (SD-1: the
    // admission gate then rejects it "not loaded" because the module is not yet
    // markApiCallable'd). Keyed by getIdentity()==_name, which loadSingleModule set
    // BEFORE onLoad — so it is cleaned by the inner-catch removeExportsForModule
    // when this load fails.
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
    // cleanup while a concurrent isModuleLoaded is (was) blocked on _loadModulesMutex
    // and a concurrent callExportedApi was rejected "not loaded".
    throw std::runtime_error("BlockingOnLoadPlugin: intentional onLoad failure after unblock");
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(BlockingOnLoadPlugin)
