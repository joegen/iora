// File: iora/tests/plugins/SelfUnloadPlugin.cpp
//
// Direct self-unload probe (Slice B, tracker 2026-09-07-3, DP-7 / H-C).
// "selfunload.trigger" attempts to unload its OWN module from inside its own
// exported call. The drain-gate self-unload check (consulted before the unload
// claim) must throw — draining a module the calling thread has in-flight would
// deadlock. The throw propagates out of callExportedApi; the module must remain
// loaded (no leaked claim).
#include "iora/iora.hpp"

class SelfUnloadPlugin : public iora::IoraService::Plugin
{
public:
  explicit SelfUnloadPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    svc->exportApi(*this, "selfunload.trigger",
                   [this]() -> int
                   { return service()->unloadSingleModule(getIdentity()) ? 1 : 0; });
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(SelfUnloadPlugin)
