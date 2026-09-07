// File: iora/tests/plugins/NonConventionPlugin.cpp
//
// A-T1 non-convention-name regression (tracker 2026-09-07-8, backlog -4). The
// exported API name ("unrelated.thing") bears NO prefix relationship to the
// module's own filename ("nonconventionplugin.so"). The old prefix+".so"
// heuristic in findModuleNameForApi could never resolve this correctly (it
// would guess a nonexistent module "unrelated.so"); the _apiToModule
// reverse map resolves it directly by exported name.
#include "iora/iora.hpp"

class NonConventionPlugin : public iora::IoraService::Plugin
{
public:
  explicit NonConventionPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    svc->exportApi(*this, "unrelated.thing", []() { return 333; });
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(NonConventionPlugin)
