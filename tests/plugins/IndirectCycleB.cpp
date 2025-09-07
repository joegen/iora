// File: iora/tests/plugins/IndirectCycleB.cpp
// Plugin B for indirect cycle: A→B→C→A
#include "iora/iora.hpp"

class IndirectCycleB : public iora::IoraService::Plugin
{
public:
  explicit IndirectCycleB(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    // B depends on C (middle of A→B→C→A chain)
    require("indirectcyclec.so");

    svc->exportApi(*this, "indirectcycleb.getValue",
                   [this]() -> std::string { return "IndirectCycleB loaded"; });
  }

  void onUnload() override {}
  void onDependencyLoaded(const std::string &moduleName) override {}
  void onDependencyUnloaded(const std::string &moduleName) override {}
};

IORA_DECLARE_PLUGIN(IndirectCycleB)