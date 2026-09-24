// File: iora/tests/plugins/OnLoadApiCallerPlugin.cpp
//
// The primary configurable probe for the onLoad/onUnload callExportedApi
// self-deadlock tests (tracker 2026-09-24-9). Its lifecycle hooks
// (onLoad/onUnload/onDependencyLoaded/onDependencyUnloaded) run whatever
// operation the HOST-OWNED control block selects (a ProbeOp per hook), and record
// every call outcome into that host-owned block — so one .so covers cases a-r.
//
// WHY a host-owned block (not plugin members): the .so is RTLD_LOCAL, so its
// internal state is not observable across the boundary AND a mutant's
// post-~Plugin invocation of a stale export must stay defined; all observable
// state lives in the host block, reset per incarnation (R3 TS M-5 / cpp17 L-9).
//
// The probe exports its OWN API ("onloadcaller.ping") FIRST in onLoad — before
// any call to it or before spawning the case-(h) worker — so a call to the own
// API resolves and reports "not loaded" (mid-load, not yet marked) rather than
// "API not found" (R3 TS L-9 / cpp17 L-10).
#include "iora/iora.hpp"

#include "onload_api_control.hpp"

#include <chrono>
#include <stdexcept>
#include <system_error>
#include <thread>

using iora::test::CallResult;
using iora::test::ErrClass;
using iora::test::OnLoadApiControl;
using iora::test::ProbeOp;

class OnLoadApiCallerPlugin : public iora::IoraService::Plugin
{
public:
  explicit OnLoadApiCallerPlugin(iora::IoraService *svc) : Plugin(svc), _svc(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    _svc = svc;
    // Export the OWN API FIRST so a call to it (or the case-h worker's call)
    // resolves and reports "not loaded", never "API not found". The lambda reads
    // the host-owned block: it counts total invocations and those observing
    // !ready (the case-m oracle) — safe even after ~Plugin (host-owned memory).
    svc->exportApi(*this, "onloadcaller.ping",
                   [this]() -> int
                   {
                     if (_ctl != nullptr)
                     {
                       _ctl->ownExportInvocations.fetch_add(1);
                       if (_ctl->ready.load() == 0)
                       {
                         _ctl->notReadyObservations.fetch_add(1);
                       }
                     }
                     return 0x5A;
                   });
    svc->exportApi(*this, "onloadcaller.getVersion",
                   []() -> std::string { return "OnLoadApiCallerPlugin v1.0"; });

    // Fetch the host-owned control block. getExportedApi takes only _apiMutex
    // (never _loadModulesMutex), so calling it here — while onLoad holds
    // _loadModulesMutex — cannot deadlock.
    auto getCtl =
      svc->getExportedApi<OnLoadApiControl *()>("test.onloadapictl");
    _ctl = getCtl();
    if (_ctl == nullptr)
    {
      throw std::runtime_error("OnLoadApiCallerPlugin: no control block registered");
    }

    _ctl->onLoadEntered.store(1);
    // Optionally establish a dependency edge on base FIRST (case j): require()
    // is legal from onLoad (owns==true). If base is already loaded it fires
    // onDependencyLoaded synchronously here; otherwise a pending edge fires it
    // when base later loads (notifyDependentsOfLoad).
    if (_ctl->requireBaseFirst.load() != 0)
    {
      require("baseplugin.so");
    }
    doOp(static_cast<ProbeOp>(_ctl->onLoadOp.load()), _ctl->onLoadCall);
    boundedRendezvous(static_cast<ProbeOp>(_ctl->onLoadOp.load()));
    _ctl->ready.store(1); // LAST statement of onLoad
  }

  void onUnload() override
  {
    if (_ctl != nullptr)
    {
      _ctl->ready.store(0); // FIRST statement of onUnload
      _ctl->onUnloadEntered.store(1);
      doOp(static_cast<ProbeOp>(_ctl->onUnloadOp.load()), _ctl->onUnloadCall);
      boundedRendezvous(static_cast<ProbeOp>(_ctl->onUnloadOp.load()));
    }
  }

  void onDependencyLoaded(const std::string &) override
  {
    if (_ctl != nullptr)
    {
      _ctl->onDepLoadedFired.fetch_add(1);
      doOp(static_cast<ProbeOp>(_ctl->onDepLoadedOp.load()), _ctl->depLoadedCall);
    }
  }

  void onDependencyUnloaded(const std::string &) override
  {
    if (_ctl != nullptr)
    {
      _ctl->onDepUnloadedFired.fetch_add(1);
      doOp(static_cast<ProbeOp>(_ctl->onDepUnloadedOp.load()), _ctl->depUnloadedCall);
    }
  }

private:
  // Record the currently-in-flight exception (called from within a catch) into a
  // CallResult, classifying the type + message. Treats system_error(EDEADLK) — a
  // self re-lock — as a failure, never success.
  static void recordThrow(CallResult &r)
  {
    r.threw.store(1);
    try
    {
      throw;
    }
    catch (const std::system_error &e)
    {
      bool edeadlk = (e.code() == std::errc::resource_deadlock_would_occur);
      r.errClass.store(static_cast<int>(iora::test::classifyError(e.what(), false, edeadlk)));
    }
    catch (const std::logic_error &e)
    {
      r.errClass.store(static_cast<int>(iora::test::classifyError(e.what(), true, false)));
    }
    catch (const std::exception &e)
    {
      r.errClass.store(static_cast<int>(iora::test::classifyError(e.what(), false, false)));
    }
    catch (...)
    {
      r.errClass.store(static_cast<int>(ErrClass::OTHER));
    }
  }

  // Run one service call, recording ran/ok/threw+errClass into `r` (the shared
  // "record-and-classify" probe protocol; sibling of expectLogicThrow).
  template <typename F> void runAndRecord(CallResult &r, F &&fn)
  {
    r.ran.store(1);
    try
    {
      fn();
      r.ok.store(1);
    }
    catch (...)
    {
      recordThrow(r);
    }
  }

  void doOp(ProbeOp op, CallResult &r)
  {
    switch (op)
    {
    case ProbeOp::NONE:
      break;
    case ProbeOp::CALL_SIBLING_GETVERSION:
      runAndRecord(r, [&] { (void)_svc->callExportedApi<std::string>("baseplugin.getVersion"); });
      break;
    case ProbeOp::CALL_SIBLING_SETCOUNTER:
      runAndRecord(
        r, [&] { _svc->callExportedApi<void>("baseplugin.setCounter", _ctl->counterArg.load()); });
      break;
    case ProbeOp::CALL_OWN:
      runAndRecord(r, [&] { (void)_svc->callExportedApi<int>("onloadcaller.ping"); });
      break;
    case ProbeOp::CALL_THEN_THROW:
      runAndRecord(r, [&] { (void)_svc->callExportedApi<std::string>("baseplugin.getVersion"); });
      // Intentional load failure AFTER the successful call (case f): the load
      // fails; a subsequent unloadSingleModule(base) must still complete (the
      // gate's inFlight is balanced by the LeaveGuard).
      throw std::runtime_error("OnLoadApiCallerPlugin: intentional post-call onLoad failure");
    case ProbeOp::CALL_DEPENDENT_USEBASE:
      runAndRecord(r, [&] { (void)_svc->callExportedApi<std::string>("dependentplugin.useBase"); });
      break;
    case ProbeOp::SPAWN_WORKER:
      spawnWorker();
      break;
    case ProbeOp::CALL_SD2_ENTRYPOINTS:
      sd2Probe();
      break;
    case ProbeOp::RENDEZVOUS_ONLY:
      // handled by boundedRendezvous after doOp
      break;
    case ProbeOp::CALL_SIBLING_AND_OWN:
      // case d (onUnload under unloadAllModules): sibling setCounter is order-
      // dependent (throws 'is unloading' or 'API not found'; NEVER invoked, so the
      // counter is unchanged); the own-API leg is deterministic ('is unloading',
      // this module is claimed+draining). Sibling -> r; own -> onUnloadOwnCall.
      runAndRecord(
        r, [&] { _svc->callExportedApi<void>("baseplugin.setCounter", _ctl->counterArg.load()); });
      runAndRecord(_ctl->onUnloadOwnCall,
                   [&] { (void)_svc->callExportedApi<int>("onloadcaller.ping"); });
      break;
    case ProbeOp::THROW_STD:
      // case n: a failing onUnload. Record entry, then throw a std exception so
      // teardownModuleHostSideLocked aborts before erase (Option A: module stays
      // loaded), leaving a later callExportedApi into it able to SUCCEED.
      r.ran.store(1);
      throw std::runtime_error("OnLoadApiCallerPlugin: intentional onUnload failure");
    case ProbeOp::REQUIRE_OFF_L:
      // case o: require() on a WORKER thread (owns==false) must throw logic_error
      // (2.3b). On origin/master with -UNDEBUG it instead ABORTS via the try_lock
      // precondition assert in registerDependencyLocked.
      r.ran.store(1);
      {
        std::thread w(
          [this, &r]
          {
            try
            {
              require("baseplugin.so");
              r.ok.store(1); // returned without throwing -> misbehaved
            }
            catch (const std::logic_error &)
            {
              r.threw.store(1);
              r.errClass.store(static_cast<int>(ErrClass::LOGIC_ERROR));
            }
            catch (...)
            {
              r.threw.store(1);
              r.errClass.store(static_cast<int>(ErrClass::OTHER));
            }
          });
        w.join();
      }
      break;
    case ProbeOp::REQUIRE_SELF:
      // case p: require(base) from inside onDependencyLoaded(base) re-invokes
      // onDependencyLoaded and (without 2.3c) push_backs onto the _dependents
      // vector being iterated by notifyDependentsOfLoad -> iterator UAF (ASan).
      // Host-armed so ONLY the reload's notify-fired onDependencyLoaded requires
      // (the initial load's require-fired onDependencyLoaded must not consume it);
      // disarms itself so the re-invocation terminates.
      r.ran.store(1);
      if (_ctl->reqSelfArmed.exchange(0) != 0)
      {
        require("baseplugin.so");
      }
      r.ok.store(1);
      break;
    }
  }

  // Case h: spawn a worker (runs OFF _loadModulesMutex — owns==false) that calls a
  // loaded sibling (SUCCEEDS) and the loading module's OWN API (NOT_LOADED). onLoad
  // JOINS it (unbounded): on ORIGIN/master this deadlocks (the worker blocks on L
  // held by this onLoad) and the host watchdog _Exits; with SD-1 the worker never
  // touches L, so both calls return promptly.
  void spawnWorker()
  {
    OnLoadApiControl *ctl = _ctl;
    iora::IoraService *svc = _svc;
    std::thread worker(
      [ctl, svc]
      {
        ctl->workerSibling.ran.store(1);
        try
        {
          (void)svc->callExportedApi<std::string>("baseplugin.getVersion");
          ctl->workerSibling.ok.store(1);
        }
        catch (...)
        {
          recordThrow(ctl->workerSibling);
        }
        ctl->workerOwn.ran.store(1);
        try
        {
          (void)svc->callExportedApi<int>("onloadcaller.ping");
          ctl->workerOwn.ok.store(1);
        }
        catch (...)
        {
          recordThrow(ctl->workerOwn);
        }
      });
    worker.join();
  }

  // Case k / o: invoke every SD-2 loader entry point + require()-off-L from a
  // lifecycle hook (this thread holds L -> owns==true). Each loader entry point
  // must throw std::logic_error; isModuleLoaded(self) is owner-aware and RETURNS.
  void sd2Probe()
  {
    const std::string self = getIdentity();
    // isModuleLoaded(self): owner-aware, returns (does not throw).
    try
    {
      bool v = _svc->isModuleLoaded(self);
      _ctl->sd2IsModuleLoadedValue.store(v ? 1 : 0);
    }
    catch (...)
    {
      _ctl->sd2Misbehaved.fetch_add(1);
    }
    // Loader entry points: each must throw std::logic_error.
    expectLogicThrow([&] { (void)_svc->loadSingleModule("baseplugin.so"); });
    expectLogicThrow([&] { (void)_svc->unloadSingleModule("baseplugin.so"); });
    expectLogicThrow([&] { (void)_svc->reloadModule("baseplugin.so"); });
    expectLogicThrow([&] { _svc->unloadAllModules(); });
    // registerDependency() is now a PUBLIC SD-2 entry point (a plugin normally uses
    // require()); from a lifecycle hook (owns==true) it must throw logic_error too.
    expectLogicThrow([&] { _svc->registerDependency(self, "baseplugin.so"); });
    expectLogicThrow([&] { _svc->shutdown(); });
    // Host-created SafeApiFunction (getExportedApiSafe rejects under L, so the
    // HOST built it and passed invokers through the control block).
    if (auto *inv = _ctl->safeApiInvoke.load())
    {
      expectLogicThrow([&] { (*inv)(); });
    }
    if (auto *avail = _ctl->safeApiIsAvailable.load())
    {
      expectLogicThrow([&] { (*avail)(); });
    }
    // require() off L (case o): on a WORKER thread, require() throws logic_error
    // (!ownsLoadModulesMutex()). On this loader thread require() is legal; the
    // off-L check is what 2.3b adds.
    std::thread w(
      [this]
      {
        try
        {
          require("baseplugin.so");
          _ctl->requireOffLMisbehaved.fetch_add(1);
        }
        catch (const std::logic_error &)
        {
          _ctl->requireOffLThrewLogic.fetch_add(1);
        }
        catch (...)
        {
          _ctl->requireOffLMisbehaved.fetch_add(1);
        }
      });
    w.join();
  }

  template <typename F> void expectLogicThrow(F &&f)
  {
    try
    {
      f();
      _ctl->sd2Misbehaved.fetch_add(1); // returned without throwing
    }
    catch (const std::logic_error &)
    {
      _ctl->sd2ThrewLogic.fetch_add(1);
    }
    catch (...)
    {
      _ctl->sd2Misbehaved.fetch_add(1); // wrong exception type
    }
  }

  // Bounded rendezvous (case m): wait until the host has hammered the export at
  // least 3 times, or 50 ms elapses — so the concurrent hammer overlaps the
  // load/unload window without an unbounded wait.
  void boundedRendezvous(ProbeOp op)
  {
    if (op != ProbeOp::RENDEZVOUS_ONLY || _ctl == nullptr)
    {
      return;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
    while (_ctl->hammerAttempts.load() < 3 &&
           std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::yield();
    }
  }

  iora::IoraService *_svc;
  OnLoadApiControl *_ctl = nullptr;
};

IORA_DECLARE_PLUGIN(OnLoadApiCallerPlugin)
