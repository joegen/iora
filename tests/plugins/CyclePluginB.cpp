// File: iora/tests/plugins/CyclePluginB.cpp
// Plugin B that creates a direct cycle with CyclePluginA (B→A, A→B)
#include "iora/iora.hpp"

class CyclePluginB : public iora::IoraService::Plugin
{
public:
  explicit CyclePluginB(iora::IoraService* svc)
    : Plugin(svc)
  {
  }

  void onLoad(iora::IoraService* svc) override
  {
    // This creates the direct cyclical dependency: B depends on A, A already depends on B
    require("cycleplugina.so");  // B depends on A

    svc->exportApi(*this, "cyclepluginb.getValue",
      [this]() -> std::string
      { 
        return "CyclePluginB loaded";
      }
    );
  }

  void onUnload() override
  {
    // Nothing special to do
  }

  void onDependencyLoaded(const std::string& moduleName) override
  {
    // Handle dependency load
  }

  void onDependencyUnloaded(const std::string& moduleName) override
  {
    // Handle dependency unload  
  }
};

IORA_DECLARE_PLUGIN(CyclePluginB)