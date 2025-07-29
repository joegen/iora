// File: iora/tests/plugins/TestPlugin.cpp
#include "iora/iora.hpp"

class TestPlugin : public iora::IoraService::Plugin
{
public:
  explicit TestPlugin(iora::IoraService* svc) : Plugin(svc), loaded(false) 
  {
  }

  void onLoad(iora::IoraService* svc) override
  {
    loaded = true;
    // Optionally register event handlers, etc.
  }

  void onUnload() override
  {
    loaded = false;
  }

  bool loaded;
};

IORA_DECLARE_PLUGIN(TestPlugin)
