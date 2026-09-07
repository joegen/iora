// File: iora/tests/plugins/OwnerPlugin.cpp
//
// A-T4 owner-checked single atomic erase (tracker 2026-09-07-8, A-DP-4).
// Exports "reboundapi.value" via the identity overload. Paired with
// OwnerConflictPlugin.cpp, whose load (while this module is still loaded)
// fails at the exportApi duplicate-name check -- that failure's
// removeExportsForModule(OwnerConflictPlugin's identity) must NOT erase this
// module's live entry for the same api name.
#include "iora/iora.hpp"

class OwnerPlugin : public iora::IoraService::Plugin
{
public:
  explicit OwnerPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    svc->exportApi(getIdentity(), "reboundapi.value", []() { return 555; });
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(OwnerPlugin)
