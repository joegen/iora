// File: iora/tests/plugins/IndirectCycleC.cpp
// Plugin C for indirect cycle: A→B→C→A
#include "iora/iora.hpp"

class IndirectCycleC : public iora::IoraService::Plugin
{
public:
  explicit IndirectCycleC(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    // C depends on A (completes the A→B→C→A cycle)
    require("indirectcyclea.so");

    svc->exportApi(*this, "indirectcyclec.getValue",
                   [this]() -> std::string { return "IndirectCycleC loaded"; });
  }

  void onUnload() override {}
  void onDependencyLoaded(const std::string &moduleName) override {}
  void onDependencyUnloaded(const std::string &moduleName) override {}
};

IORA_DECLARE_PLUGIN(IndirectCycleC)