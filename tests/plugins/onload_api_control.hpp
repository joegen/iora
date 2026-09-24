// File: iora/tests/plugins/onload_api_control.hpp
//
// Shared control block for the onLoad/onUnload callExportedApi self-deadlock
// tests (tracker 2026-09-24-9). Included by OnLoadApiCallerPlugin.cpp (the probe
// .so) and by tests/service/iora_test_onload_api_deadlock.cpp (the host), so both
// agree on the exact struct layout.
//
// The probe fetches a pointer to a HOST-OWNED instance via a host-exported getter
// ("test.onloadapictl", resolved with getExportedApi, which takes only _apiMutex
// and is therefore safe to call from within onLoad while _loadModulesMutex is
// held). ALL observable probe state lives in this host-owned block (atomics,
// reset per incarnation), NOT in the RTLD_LOCAL plugin .so: a mutant's
// post-~Plugin invocation of a stale export then stays defined (or faults under
// ASan) rather than touching unmapped .so state (R3 TS M-5 / cpp17 L-9).
//
// The probe NEVER swallows exceptions silently: for every service call it makes
// from a lifecycle hook it records ok / threw + a CLASSIFICATION of the message
// (classifyError below), and treats std::system_error(EDEADLK) from a re-lock as
// a failure, never success.
#pragma once

#include <atomic>
#include <functional>
#include <string>

namespace iora
{
namespace test
{

/// What a lifecycle hook (onLoad / onUnload / onDependency*) should do when it
/// runs. The host sets the op fields BEFORE the load/unload, so one probe .so
/// covers every case. NONE = do nothing (just record that the hook ran).
enum class ProbeOp : int
{
  NONE = 0,
  CALL_SIBLING_GETVERSION, // callExportedApi<std::string>("baseplugin.getVersion")
  CALL_SIBLING_SETCOUNTER, // callExportedApi<void>("baseplugin.setCounter", counterArg)
  CALL_OWN,                // callExportedApi<std::string>(own API) -> expect not-loaded / unloading
  CALL_THEN_THROW,         // CALL_SIBLING_GETVERSION, then throw std::runtime_error (case f)
  SPAWN_WORKER,            // spawn a worker that calls sibling + own, wait bounded (case h)
  CALL_DEPENDENT_USEBASE,  // callExportedApi<std::string>("dependentplugin.useBase") (case i)
  CALL_SD2_ENTRYPOINTS,    // invoke every SD-2 loader entry point; each must throw logic_error (case k)
  RENDEZVOUS_ONLY,         // bounded rendezvous with the host hammer, then set/clear ready (case m)
  CALL_SIBLING_AND_OWN,    // sibling setCounter (-> onUnloadCall) THEN own ping (-> onUnloadOwnCall) (case d)
  THROW_STD,               // record entry then throw std::runtime_error (a failing onUnload; case n)
  REQUIRE_OFF_L,           // spawn a worker that calls require("baseplugin.so") off L (case o)
  REQUIRE_SELF,            // require("baseplugin.so") from inside onDependencyLoaded, single-shot (case p)
};

/// Error-message classification. The probe cannot share std::string across the
/// .so boundary safely, so it classifies each caught message into these buckets
/// (host-owned atomics below hold the counts). Kept in the header so host and
/// probe agree on the substrings.
enum class ErrClass : int
{
  NONE = 0,
  NOT_LOADED,   // "not loaded"
  IS_UNLOADING, // "is unloading"
  API_NOT_FOUND,// "API not found" / "not found"
  LOGIC_ERROR,  // std::logic_error (SD-2 owner rejection)
  SELF_RELOCK,  // std::system_error EDEADLK (a self re-lock — a FAILURE, never success)
  OTHER,        // any other message
};

/// Classify a caught error into an ErrClass bucket. Header-inline so the probe
/// .so and the host share one definition. `isLogic`/`isSystemEdeadlk` are set by
/// the caller from the concrete exception type before the message match.
inline ErrClass classifyError(const std::string &what, bool isLogic, bool isSystemEdeadlk)
{
  if (isSystemEdeadlk)
  {
    return ErrClass::SELF_RELOCK;
  }
  if (isLogic)
  {
    return ErrClass::LOGIC_ERROR;
  }
  if (what.find("is unloading") != std::string::npos)
  {
    return ErrClass::IS_UNLOADING;
  }
  if (what.find("not loaded") != std::string::npos)
  {
    return ErrClass::NOT_LOADED;
  }
  if (what.find("not found") != std::string::npos)
  {
    return ErrClass::API_NOT_FOUND;
  }
  return ErrClass::OTHER;
}

/// One recorded call outcome. Atomic so a worker thread (case h) may write it and
/// the host may read it with acquire/release ordering.
struct CallResult
{
  std::atomic<int> ran{0};              // the hook/worker reached the call
  std::atomic<int> ok{0};               // the call returned normally
  std::atomic<int> threw{0};            // the call threw
  std::atomic<int> errClass{0};         // ErrClass of the caught error
  std::atomic<int> sawCounter{-1};      // for setCounter/getCounter observation

  void reset()
  {
    ran.store(0);
    ok.store(0);
    threw.store(0);
    errClass.store(0);
    sawCounter.store(-1);
  }
};

/// Host-owned observation + control block for the onLoad/onUnload API-call
/// probes. Reset per incarnation by the host.
struct OnLoadApiControl
{
  // --- op selectors (host sets before the load/unload) ---
  std::atomic<int> onLoadOp{0};       // ProbeOp for onLoad
  std::atomic<int> onUnloadOp{0};     // ProbeOp for onUnload
  std::atomic<int> onDepLoadedOp{0};  // ProbeOp for onDependencyLoaded
  std::atomic<int> onDepUnloadedOp{0};// ProbeOp for onDependencyUnloaded
  std::atomic<int> counterArg{7};     // argument for CALL_SIBLING_SETCOUNTER
  std::atomic<int> requireBaseFirst{0}; // if set, onLoad calls require("baseplugin.so") first (case j)
  std::atomic<int> reqSelfArmed{0};     // case p: when >0, the NEXT onDependencyLoaded requires base once (disarms)

  // --- readiness / rendezvous (case m) ---
  // ready is set true as the LAST statement of onLoad and false as the FIRST of
  // onUnload; the probe's own exported API counts invocations that observe
  // !ready (the case-m oracle). hammerAttempts is bumped by the host hammer; the
  // probe's onLoad/onUnload rendezvous waits (bounded) until it reaches >= 3.
  std::atomic<int> ready{0};
  std::atomic<int> hammerAttempts{0};
  std::atomic<int> notReadyObservations{0}; // own export saw !ready
  std::atomic<int> ownExportInvocations{0}; // total own-export invocations

  // --- lifecycle-hook "reached" flags (a missing-.so failure is never red) ---
  std::atomic<int> onLoadEntered{0};
  std::atomic<int> onUnloadEntered{0};
  std::atomic<int> onDepLoadedFired{0};
  std::atomic<int> onDepUnloadedFired{0};

  // --- recorded call outcomes ---
  CallResult onLoadCall;   // the call made from onLoad (ops CALL_*)
  CallResult onUnloadCall; // the call made from onUnload
  CallResult onUnloadOwnCall; // case d: the own-API call made from onUnload (2nd leg)
  CallResult workerSibling;// case h: worker -> loaded sibling
  CallResult workerOwn;    // case h: worker -> the loading module's own API
  CallResult depLoadedCall;// onDependencyLoaded call outcome
  CallResult depUnloadedCall;// onDependencyUnloaded call outcome

  // --- SD-2 entry-point probe (case k) ---
  // Each loader entry point invoked from a lifecycle hook must throw
  // std::logic_error. sd2ThrewLogic counts those that did; sd2Misbehaved counts
  // any that did NOT throw logic_error (returned, or threw the wrong type).
  std::atomic<int> sd2ThrewLogic{0};
  std::atomic<int> sd2Misbehaved{0};
  std::atomic<int> sd2IsModuleLoadedValue{-1}; // owner-aware isModuleLoaded(self) return

  // case k: host-provided invokers for a HOST-created SafeApiFunction (the probe
  // cannot create one — getExportedApiSafe rejects under L). Each invokes the
  // corresponding SafeApiFunction method (operator() / isAvailable) so the probe
  // can call them from a lifecycle hook and classify the throw, WITHOUT sharing
  // the SafeApiFunction type through this header. The std::function targets live
  // in the host TU; the probe only invokes them. Set by the host before the load;
  // a null pointer means "skip that sub-check". (These count into sd2ThrewLogic /
  // sd2Misbehaved alongside the loader entry points.)
  std::atomic<std::function<void()> *> safeApiInvoke{nullptr};
  std::atomic<std::function<void()> *> safeApiIsAvailable{nullptr};

  // --- require()-off-L probe (case o) ---
  std::atomic<int> requireOffLThrewLogic{0};
  std::atomic<int> requireOffLMisbehaved{0};

  void reset()
  {
    onLoadOp.store(0);
    onUnloadOp.store(0);
    onDepLoadedOp.store(0);
    onDepUnloadedOp.store(0);
    counterArg.store(7);
    requireBaseFirst.store(0);
    reqSelfArmed.store(0);
    ready.store(0);
    hammerAttempts.store(0);
    notReadyObservations.store(0);
    ownExportInvocations.store(0);
    onLoadEntered.store(0);
    onUnloadEntered.store(0);
    onDepLoadedFired.store(0);
    onDepUnloadedFired.store(0);
    onLoadCall.reset();
    onUnloadCall.reset();
    onUnloadOwnCall.reset();
    workerSibling.reset();
    workerOwn.reset();
    depLoadedCall.reset();
    depUnloadedCall.reset();
    sd2ThrewLogic.store(0);
    sd2Misbehaved.store(0);
    sd2IsModuleLoadedValue.store(-1);
    safeApiInvoke.store(nullptr);
    safeApiIsAvailable.store(nullptr);
    requireOffLThrewLogic.store(0);
    requireOffLMisbehaved.store(0);
  }
};

} // namespace test
} // namespace iora
