// File: iora/tests/plugins/BasePlugin.cpp
// A base plugin that provides basic services other plugins can depend on
#include "iora/iora.hpp"

class BasePlugin : public iora::IoraService::Plugin
{
public:
  explicit BasePlugin(iora::IoraService *svc) : Plugin(svc), _counter(0) {}

  void onLoad(iora::IoraService *svc) override
  {
    // Export basic APIs that other plugins can use
    svc->exportApi(*this, "baseplugin.getVersion",
                   [this]() -> std::string { return "BasePlugin v1.0"; });

    svc->exportApi(*this, "baseplugin.increment", [this]() -> int { return ++_counter; });

    svc->exportApi(*this, "baseplugin.getCounter", [this]() -> int { return _counter; });

    svc->exportApi(*this, "baseplugin.setCounter", [this](int value) -> void { _counter = value; });

    svc->exportApi(*this, "baseplugin.reset", [this]() -> void { _counter = 0; });
  }

  void onUnload() override
  {
    // Nothing special to do
  }

private:
  int _counter;
};

IORA_DECLARE_PLUGIN(BasePlugin)