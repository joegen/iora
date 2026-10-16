// File: iora/tests/plugins/CallbackProbePlugin.cpp
//
// Callback-ownership probe (tracker 2026-10-16-12). onLoad registers EventQueue
// handlers (by id / name / pattern, strings from its control slot), a JSON POST
// route via on().handleJson, and a GET route and a NAMED JSON GET route directly
// on webhookServer(). Every route path contains the module name, so two probe
// modules (two plugin targets built from this source) never share a route. Each
// callback captures `this`, counts invocations and, in SLOW mode, spins on the
// slot's phase, then calls isModuleLoaded(own name) (takes _loadModulesMutex for
// a non-owner, so a drain held under that lock deadlocks), then reads a member.
#include "iora/iora.hpp"

#include "callback_control.hpp"

#include <chrono>
#include <stdexcept>
#include <thread>

using iora::test::CallbackControl;
using iora::test::CallbackSlot;
using iora::test::ProbeMode;
using iora::test::SelfUnloadOp;
using iora::test::SelfUnloadResult;

namespace
{
void spinUntilPhase2(CallbackSlot *slot)
{
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (slot->phase.load() < 2 && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}
} // namespace

class CallbackProbePlugin : public iora::IoraService::Plugin
{
public:
  explicit CallbackProbePlugin(iora::IoraService *svc) : Plugin(svc), _svc(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    auto getCtl = svc->getExportedApi<CallbackControl *()>("test.cbctl");
    CallbackControl *ctl = getCtl();
    _slot = ctl ? ctl->slotFor(getIdentity()) : nullptr;
    if (_slot == nullptr)
    {
      throw std::runtime_error("CallbackProbePlugin: no control slot for " + getIdentity());
    }
    _self = getIdentity();

    auto &queue = svc->eventQueue();
    if (!_slot->eventId.empty())
    {
      queue.onEventId(_slot->eventId, [this](const iora::parsers::Json &) { hit(true); });
    }
    if (!_slot->eventName.empty())
    {
      queue.onEventName(_slot->eventName, [this](const iora::parsers::Json &) { hit(false); });
    }
    if (!_slot->eventPattern.empty())
    {
      queue.onEventNameMatches(_slot->eventPattern,
                               [this](const iora::parsers::Json &) { hit(false); });
    }

    const std::string base = "/" + _self;
    svc->on(base + "/post").handleJson(
      [this](const iora::parsers::Json &)
      {
        hit(false);
        return iora::parsers::Json::object();
      });
    svc->webhookServer()->onGet(base + "/get",
                                [this](const iora::network::HttpServer::Request &,
                                       iora::network::HttpServer::Response &res)
                                {
                                  hit(false);
                                  res.set_content("get", "text/plain");
                                });
    svc->webhookServer()->onJsonGet(base + "/named/:id",
                                    [this](const iora::parsers::Json &)
                                    {
                                      hit(false);
                                      return iora::parsers::Json::object();
                                    });

    const auto mode = static_cast<ProbeMode>(_slot->mode.load());
    if (mode == ProbeMode::THROW_AFTER_REGISTER)
    {
      throw std::runtime_error("CallbackProbePlugin: intentional onLoad failure after register");
    }
    if (mode == ProbeMode::BLOCK_IN_ONLOAD)
    {
      _slot->phase.store(1);
      spinUntilPhase2(_slot);
    }
  }

  void onUnload() override
  {
    _slot->unloadRan.store(true);
    switch (static_cast<ProbeMode>(_slot->mode.load()))
    {
    case ProbeMode::BLOCK_IN_ONUNLOAD:
      _slot->phase.store(1);
      spinUntilPhase2(_slot);
      break;
    case ProbeMode::THROW_IN_ONUNLOAD_ONCE:
      if (_slot->throwOnce.exchange(false))
      {
        throw std::runtime_error("CallbackProbePlugin: intentional onUnload failure");
      }
      break;
    case ProbeMode::REGISTER_IN_ONUNLOAD:
      _svc->eventQueue().onEventName(_slot->eventName + ".late",
                                     [this](const iora::parsers::Json &)
                                     { _slot->lateInvocations.fetch_add(1); });
      break;
    default:
      break;
    }
  }

private:
  void hit(bool fromIdHandler)
  {
    _slot->invocations.fetch_add(1);
    const auto mode = static_cast<ProbeMode>(_slot->mode.load());
    if (mode == ProbeMode::SLOW)
    {
      // Only the first callback arms the window (0 -> 1); later ones see 2.
      int idle = 0;
      _slot->phase.compare_exchange_strong(idle, 1);
      spinUntilPhase2(_slot);
      (void)_svc->isModuleLoaded(_self);
      _slot->unloadRanBeforeRead.store(_slot->unloadRan.load());
      _slot->observedMagic.store(_magic);
    }
    else if (mode == ProbeMode::SELF_UNLOAD && fromIdHandler && !_slot->selfUnloadDone.load())
    {
      selfUnload();
    }
  }

  void selfUnload()
  {
    SelfUnloadResult result = SelfUnloadResult::NONE;
    try
    {
      bool ok = false;
      switch (static_cast<SelfUnloadOp>(_slot->selfUnloadOp.load()))
      {
      case SelfUnloadOp::UNLOAD:
        ok = _svc->unloadSingleModule(_self);
        break;
      case SelfUnloadOp::RELOAD:
        ok = _svc->reloadModule(_self);
        break;
      case SelfUnloadOp::UNLOAD_ALL:
        ok = _svc->unloadAllModules();
        break;
      }
      result = ok ? SelfUnloadResult::RETURNED_TRUE : SelfUnloadResult::RETURNED_FALSE;
    }
    catch (const std::runtime_error &)
    {
      result = SelfUnloadResult::THREW;
    }
    _slot->selfUnloadResult.store(static_cast<int>(result));
    _slot->selfUnloadDone.store(true);
  }

  iora::IoraService *_svc;
  CallbackSlot *_slot = nullptr;
  std::string _self;
  int _magic = 0xC0FFEE;
};

IORA_DECLARE_PLUGIN(CallbackProbePlugin)
