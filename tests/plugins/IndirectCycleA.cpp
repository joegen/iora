// File: iora/tests/plugins/IndirectCycleA.cpp
// Plugin A for indirect cycle: A→B→C→A
#include "iora/iora.hpp"

class IndirectCycleA : public iora::IoraService::Plugin
{
public:
  explicit IndirectCycleA(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    // A depends on B (start of A→B→C→A chain)
    require("indirectcycleb.so");

    svc->exportApi(*this, "indirectcyclea.getValue",
                   [this]() -> std::string { return "IndirectCycleA loaded"; });
  }

  void onUnload() override {}
  void onDependencyLoaded(const std::string &moduleName) override {}
  void onDependencyUnloaded(const std::string &moduleName) override {}
};

IORA_DECLARE_PLUGIN(IndirectCycleA)