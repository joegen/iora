// File: iora/tests/plugins/RequireDepThenThrowPlugin.cpp
//
// S-2 exercise (tracker 2026-09-07-9). onLoad require()s an ALREADY-LOADED
// dependency (registering a _dependents[dep] += this-module edge and, being
// loaded, NOT a _pendingDependencies entry) and THEN throws. This drives the
// load-failure inner catch through the new pruneModuleTrackingLocked step, which
// must remove this module from the dependency-tracking maps + prune its SafeApi
// registry (the cleanup teardownModuleHostSideLocked does on unload, previously
// omitted on the load-failure path). Run under ASan to catch a lock-order /
// iterator defect in the shared cleanup helper on the load path. The internal
// map effect is not black-box observable (see the tracker M-1 note); correctness
// of the removal is guaranteed by convergence on the same helper the unload path
// uses + code review.
#include "iora/iora.hpp"

#include <stdexcept>

class RequireDepThenThrowPlugin : public iora::IoraService::Plugin
{
public:
  explicit RequireDepThenThrowPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    (void)svc;
    // The dependency must already be loaded (require() throws immediately if it
    // is not). The host loads testplugin.so before loading this plugin.
    require("testplugin.so");
    throw std::runtime_error("RequireDepThenThrowPlugin: intentional onLoad failure after require");
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(RequireDepThenThrowPlugin)
