// File: iora/tests/plugins/TransitiveInnerPlugin.cpp
//
// Transitive self-unload probe N (Slice B, tracker 2026-09-07-3, DP-7 / H-C).
// "transinner.call" unloads the OUTER module "transitiveouterplugin.so" while
// this thread is still inside that outer module's exported call. The drain-gate
// self-unload check must detect the outer module in this thread's in-flight
// multiset and throw.
#include "iora/iora.hpp"

class TransitiveInnerPlugin : public iora::IoraService::Plugin
{
public:
  explicit TransitiveInnerPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    svc->exportApi(*this, "transinner.call",
                   [this]() -> int
                   {
                     service()->unloadSingleModule("transitiveouterplugin.so");
                     return 0;
                   });
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(TransitiveInnerPlugin)
