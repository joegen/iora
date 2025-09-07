// File: iora/tests/plugins/CyclePluginA.cpp
// Plugin A that creates a direct cycle with CyclePluginB (A→B, B→A)
#include "iora/iora.hpp"

class CyclePluginA : public iora::IoraService::Plugin
{
public:
  explicit CyclePluginA(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    // This should cause a cyclical dependency error if CyclePluginB also requires this plugin
    require("cyclepluginb.so"); // A depends on B

    svc->exportApi(*this, "cycleplugina.getValue",
                   [this]() -> std::string { return "CyclePluginA loaded"; });
  }

  void onUnload() override
  {
    // Nothing special to do
  }

  void onDependencyLoaded(const std::string &moduleName) override
  {
    // Handle dependency load
  }

  void onDependencyUnloaded(const std::string &moduleName) override
  {
    // Handle dependency unload
  }
};

IORA_DECLARE_PLUGIN(CyclePluginA)