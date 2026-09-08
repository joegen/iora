// File: iora/tests/plugins/RequireDepNonStdThrowPlugin.cpp
//
// FX-C1 + FX-C2 (tracker 2026-09-08-1, O-2 / D1). A dependent whose
// onDependencyLoaded throws a NON-std::exception (`throw 42`). onLoad require()s
// an ALREADY-LOADED dependency (testplugin.so), which fires onDependencyLoaded
// synchronously via Plugin::require() (iora.hpp:2628) — the require() path every
// dependent uses (FX-C1). onDependencyLoaded is fired AGAIN on a later RELOAD of
// the dep via notifyDependentsOfLoad (:1768) (FX-C2). D1 widens BOTH std-only
// swallows to catch(...), so the non-std is swallowed at BOTH sites and the
// dependent load (FX-C1) and the dep reload (FX-C2) SUCCEED — dependent-notify
// failure is isolated regardless of exception type. Reverting either swallow
// (MUT-2ii at :2628 / MUT-2i at :1768) lets the non-std escape to
// loadSingleModule's outer catch(...), which tears down the loading module and
// rethrows, failing the respective load.
#include "iora/iora.hpp"

class RequireDepNonStdThrowPlugin : public iora::IoraService::Plugin
{
public:
  explicit RequireDepNonStdThrowPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    (void)svc;
    // The dependency must already be loaded (require() throws if it is not); the
    // host loads testplugin.so first. require() fires onDependencyLoaded below.
    require("testplugin.so");
  }

  void onDependencyLoaded(const std::string &moduleName) override
  {
    (void)moduleName;
    throw 42; // NON-std: swallowed by the widened catch(...) at :2628 and :1768
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(RequireDepNonStdThrowPlugin)
