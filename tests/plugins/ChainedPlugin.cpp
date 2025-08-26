// File: iora/tests/plugins/ChainedPlugin.cpp
// A plugin that depends on both BasePlugin and DependentPlugin (chained dependencies)
#include "iora/iora.hpp"

class ChainedPlugin : public iora::IoraService::Plugin
{
public:
  explicit ChainedPlugin(iora::IoraService* svc)
    : Plugin(svc), _service(svc), _baseDependencyCount(0), _dependentDependencyCount(0)
  {
  }

  void onLoad(iora::IoraService* svc) override
  {
    // Require both dependencies
    require("baseplugin.so");
    require("dependentplugin.so");

    // Export API that uses both dependencies
    svc->exportApi(*this, "chainedplugin.useChain",
      [this]() -> std::string
      { 
        try {
          auto baseVersion = _service->callExportedApi<std::string>("baseplugin.getVersion");
          auto dependentStatus = _service->callExportedApi<std::string>("dependentplugin.getStatus");
          auto baseCounter = _service->callExportedApi<int>("baseplugin.getCounter");
          
          return "ChainedPlugin using " + baseVersion + ", " + dependentStatus + ", counter: " + std::to_string(baseCounter);
        } catch (const std::exception& e) {
          return "Error in chain: " + std::string(e.what());
        }
      }
    );

    svc->exportApi(*this, "chainedplugin.getDependencyStatus",
      [this]() -> std::string
      { 
        return "BaseDep: " + std::to_string(_baseDependencyCount) + 
               ", DependentDep: " + std::to_string(_dependentDependencyCount);
      }
    );

    svc->exportApi(*this, "chainedplugin.complexOperation",
      [this]() -> std::string
      { 
        try {
          // Use BasePlugin to increment counter
          _service->callExportedApi<int>("baseplugin.increment");
          _service->callExportedApi<int>("baseplugin.increment");
          
          // Use DependentPlugin to get status
          auto dependentResult = _service->callExportedApi<std::string>("dependentplugin.useBase");
          
          // Get final counter value
          auto finalCounter = _service->callExportedApi<int>("baseplugin.getCounter");
          
          return "Complex operation result: " + dependentResult + ", final counter: " + std::to_string(finalCounter);
        } catch (const std::exception& e) {
          return "Complex operation failed: " + std::string(e.what());
        }
      }
    );
  }

  void onUnload() override
  {
    // Reset dependency tracking
    _baseDependencyCount = 0;
    _dependentDependencyCount = 0;
  }

  void onDependencyLoaded(const std::string& moduleName) override
  {
    if (moduleName == "baseplugin.so") {
      _baseDependencyCount++;
    } else if (moduleName == "dependentplugin.so") {
      _dependentDependencyCount++;
    }
  }

  void onDependencyUnloaded(const std::string& moduleName) override
  {
    if (moduleName == "baseplugin.so") {
      _baseDependencyCount--;
    } else if (moduleName == "dependentplugin.so") {
      _dependentDependencyCount--;
    }
  }

private:
  iora::IoraService* _service;
  int _baseDependencyCount;
  int _dependentDependencyCount;
};

IORA_DECLARE_PLUGIN(ChainedPlugin)