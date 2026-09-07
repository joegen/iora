// File: iora/tests/plugins/TransitiveOuterPlugin.cpp
//
// Transitive self-unload probe M (Slice B, tracker 2026-09-07-3, DP-7 / H-C).
// "transouter.call" (module M) calls into "transinner.call" (module N), which
// unloads M. M is held in-flight on this thread while N runs, so a depth counter
// or single-module marker would miss M; the thread-local MULTISET catches it and
// N's unload of M throws.
#include "iora/iora.hpp"

class TransitiveOuterPlugin : public iora::IoraService::Plugin
{
public:
  explicit TransitiveOuterPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    svc->exportApi(*this, "transouter.call",
                   [this]() -> int { return service()->callExportedApi<int>("transinner.call"); });
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(TransitiveOuterPlugin)
