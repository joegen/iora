// File: iora/tests/plugins/TestPlugin.cpp
#include "iora/iora.hpp"

class TestPlugin : public iora::IoraService::Plugin
{
public:
  explicit TestPlugin(iora::IoraService *svc) : Plugin(svc), loaded(false) {}

  void onLoad(iora::IoraService *svc) override
  {
    loaded = true;

    // Register a simple API: returns the sum of two integers
    svc->exportApi(*this, "testplugin.add", [this](int a, int b) { return a + b; });

    // Register an API: returns a greeting string
    svc->exportApi(*this, "testplugin.greet",
                   [this](const std::string &name) { return std::string("Hello, ") + name + "!"; });

    // Register an API: toggles and returns the loaded state
    svc->exportApi(*this, "testplugin.toggleLoaded",
                   [this]()
                   {
                     loaded = !loaded;
                     return loaded;
                   });

    // Register an API: returns the loaded state
    svc->exportApi(*this, "testplugin.isLoaded", [this]() { return loaded; });
  }

  void onUnload() override { loaded = false; }

  bool loaded;
};

IORA_DECLARE_PLUGIN(TestPlugin)
