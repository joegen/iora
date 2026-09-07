// File: iora/tests/plugins/OwnerConflictPlugin.cpp
//
// A-T4 owner-checked single atomic erase (tracker 2026-09-07-8, A-DP-4). See
// OwnerPlugin.cpp. Attempts to export the SAME api name ("reboundapi.value")
// via the identity overload; when OwnerPlugin is already loaded, exportApi's
// duplicate-name check throws here, driving loadSingleModule's load-failure
// cleanup with an identity that never actually owned the entry --
// removeExportsForModule must be a no-op for it, leaving OwnerPlugin's entry
// intact.
#include "iora/iora.hpp"

class OwnerConflictPlugin : public iora::IoraService::Plugin
{
public:
  explicit OwnerConflictPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    svc->exportApi(getIdentity(), "reboundapi.value", []() { return 666; });
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(OwnerConflictPlugin)
