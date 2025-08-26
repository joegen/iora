// File: iora/tests/plugins/DependentPlugin.cpp  
// A plugin that depends on BasePlugin and demonstrates dependency handling
#include "iora/iora.hpp"

class DependentPlugin : public iora::IoraService::Plugin
{
public:
  explicit DependentPlugin(iora::IoraService* svc)
    : Plugin(svc), _service(svc), _basePluginAvailable(false), _loadNotifications(0), _unloadNotifications(0)
  {
  }

  void onLoad(iora::IoraService* svc) override
  {
    // Require BasePlugin as a dependency  
    require("baseplugin.so");

    // Export APIs that use BasePlugin functionality  
    svc->exportApi(*this, "dependentplugin.useBase",
      [this]() -> std::string
      { 
        if (!_basePluginAvailable) {
          return "BasePlugin not available";
        }
        
        try {
          auto baseVersion = _service->callExportedApi<std::string>("baseplugin.getVersion");
          auto counter = _service->callExportedApi<int>("baseplugin.increment");
          return "Using " + baseVersion + ", counter: " + std::to_string(counter);
        } catch (const std::exception& e) {
          return "Error using BasePlugin: " + std::string(e.what());
        }
      }
    );

    svc->exportApi(*this, "dependentplugin.getStatus",
      [this]() -> std::string
      { 
        return _basePluginAvailable ? "BasePlugin available" : "BasePlugin not available";
      }
    );

    svc->exportApi(*this, "dependentplugin.getNotificationCounts",
      [this]() -> std::string
      { 
        return "Load: " + std::to_string(_loadNotifications) + ", Unload: " + std::to_string(_unloadNotifications);
      }
    );
  }

  void onUnload() override
  {
    _basePluginAvailable = false;
  }

  void onDependencyLoaded(const std::string& moduleName) override
  {
    if (moduleName == "baseplugin.so") {
      _basePluginAvailable = true;
      _loadNotifications++;
    }
  }

  void onDependencyUnloaded(const std::string& moduleName) override  
  {
    if (moduleName == "baseplugin.so") {
      _basePluginAvailable = false;
      _unloadNotifications++;
    }
  }

private:
  iora::IoraService* _service;
  bool _basePluginAvailable;
  int _loadNotifications;
  int _unloadNotifications;
};

IORA_DECLARE_PLUGIN(DependentPlugin)