// File: iora/tests/plugins/UnloadDepStdThrowPlugin.cpp
//
// FX-U1 dependent D1s (trackers 2026-09-08-4, cpp17 LOW-4 coverage). Depends on
// testplugin.so and throws a STD exception from onDependencyUnloaded. Loaded
// first in FX-U1, so the notify loop hits it before the non-std D1 and the
// recording D2 — exercising the pre-existing std-exception swallow's
// isolate-and-continue behavior (the std sibling of the widened non-std arm),
// which the non-std-only fixtures did not otherwise cover.
#include "iora/iora.hpp"

#include <stdexcept>

class UnloadDepStdThrowPlugin : public iora::IoraService::Plugin
{
public:
  explicit UnloadDepStdThrowPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    (void)svc;
    require("testplugin.so");
  }

  void onDependencyUnloaded(const std::string &moduleName) override
  {
    (void)moduleName;
    throw std::runtime_error("UnloadDepStdThrowPlugin: intentional std onDependencyUnloaded throw");
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(UnloadDepStdThrowPlugin)
