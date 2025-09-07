// File: iora/tests/plugins/CyclePluginC.cpp
// Plugin C that creates an indirect cycle: A→B→C→A
#include "iora/iora.hpp"

class CyclePluginC : public iora::IoraService::Plugin
{
public:
  explicit CyclePluginC(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    // This completes the indirect cycle: A→B→C→A
    require("cycleplugina.so"); // C depends on A (completing the cycle)

    svc->exportApi(*this, "cyclepluginc.getValue",
                   [this]() -> std::string { return "CyclePluginC loaded"; });
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

IORA_DECLARE_PLUGIN(CyclePluginC)