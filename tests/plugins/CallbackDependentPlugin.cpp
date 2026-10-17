// File: iora/tests/plugins/CallbackDependentPlugin.cpp
//
// Callback-ownership attribution probe (tracker 2026-10-16-12). require()s the
// probe module and registers one EventQueue handler in each of onLoad,
// onDependencyLoaded and onDependencyUnloaded. The first onDependencyLoaded
// comes from require() (inside this module's onLoad); the second comes from
// notifyDependentsOfLoad when the probe is loaded again while this module stays
// loaded, and registers "dep.reloaded". All of them must be attributed to THIS
// module: they survive the probe's unload and are removed by this module's
// unload.
#include "iora/iora.hpp"

#include "callback_control.hpp"

#include <stdexcept>

using iora::test::CallbackControl;
using iora::test::DependentSlot;

class CallbackDependentPlugin : public iora::IoraService::Plugin
{
public:
  explicit CallbackDependentPlugin(iora::IoraService *svc) : Plugin(svc), _svc(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    auto getCtl = svc->getExportedApi<CallbackControl *()>("test.cbctl");
    CallbackControl *ctl = getCtl();
    if (ctl == nullptr)
    {
      throw std::runtime_error("CallbackDependentPlugin: no control block");
    }
    _slot = &ctl->dependent;
    svc->eventQueue().onEventName("dep.onload",
                                  [this](const iora::parsers::Json &)
                                  { _slot->onLoadHandler.fetch_add(1); });
    require("callbackprobeplugin.so");
  }

  void onUnload() override {}

  void onDependencyLoaded(const std::string &) override
  {
    ++_loadedCalls;
    if (_loadedCalls == 1)
    {
      _svc->eventQueue().onEventName("dep.loaded",
                                     [this](const iora::parsers::Json &)
                                     { _slot->depLoadedHandler.fetch_add(1); });
    }
    else if (_loadedCalls == 2)
    {
      _svc->eventQueue().onEventName("dep.reloaded",
                                     [this](const iora::parsers::Json &)
                                     { _slot->depReloadedHandler.fetch_add(1); });
    }
  }

  void onDependencyUnloaded(const std::string &) override
  {
    if (!_unloadedRegistered)
    {
      _unloadedRegistered = true;
      _svc->eventQueue().onEventName("dep.unloaded",
                                     [this](const iora::parsers::Json &)
                                     { _slot->depUnloadedHandler.fetch_add(1); });
    }
  }

private:
  iora::IoraService *_svc;
  DependentSlot *_slot = nullptr;
  int _loadedCalls = 0;
  bool _unloadedRegistered = false;
};

IORA_DECLARE_PLUGIN(CallbackDependentPlugin)
