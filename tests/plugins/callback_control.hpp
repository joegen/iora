// File: iora/tests/plugins/callback_control.hpp
//
// Shared control block for the plugin callback-ownership tests (tracker
// 2026-10-16-12, architecture/iora/plugin_callback_ownership.json). Included by
// CallbackProbePlugin.cpp / CallbackDependentPlugin.cpp (the plugin .so's) and
// by tests/service/iora_test_plugin_callback_lifecycle.cpp (the host). The
// plugins fetch a pointer to the host-owned instance through the host-exported
// getter "test.cbctl" (getExportedApi takes only _apiMutex, so it is safe from
// onLoad). Each probe module reads and writes only the slot named after it.
#pragma once

#include <atomic>
#include <string>

namespace iora
{
namespace test
{

enum class ProbeMode : int
{
  NORMAL = 0,
  SLOW,                   // each callback: phase=1, spin to phase 2, isModuleLoaded(self), read member
  THROW_AFTER_REGISTER,   // onLoad throws after registering
  BLOCK_IN_ONLOAD,        // onLoad registers, phase=1, spins until phase 2, returns
  BLOCK_IN_ONUNLOAD,      // onUnload: phase=1, spins until phase 2
  THROW_IN_ONUNLOAD_ONCE, // onUnload throws once
  REGISTER_IN_ONUNLOAD,   // onUnload registers one more event handler
  SELF_UNLOAD             // the id event handler unloads its own module (selfUnloadOp)
};

enum class SelfUnloadOp : int
{
  UNLOAD = 1,
  RELOAD = 2,
  UNLOAD_ALL = 3
};

enum class SelfUnloadResult : int
{
  NONE = 0,
  THREW = 1,
  RETURNED_TRUE = 2,
  RETURNED_FALSE = 3
};

/// Per-module state. Strings are set by the test BEFORE the module loads.
struct CallbackSlot
{
  std::string moduleName;   // e.g. "callbackprobeplugin.so"
  std::string eventId;      // empty = no handler by id
  std::string eventName;    // empty = no handler by name
  std::string eventPattern; // empty = no handler by pattern
  std::atomic<int> mode{0};
  std::atomic<int> phase{0};
  std::atomic<int> invocations{0};
  std::atomic<int> lateInvocations{0}; // REGISTER_IN_ONUNLOAD handler
  std::atomic<bool> unloadRan{false};
  std::atomic<bool> unloadRanBeforeRead{false};
  std::atomic<int> observedMagic{0};
  std::atomic<bool> throwOnce{false};
  std::atomic<int> selfUnloadOp{0};
  std::atomic<int> selfUnloadResult{0};
  std::atomic<bool> selfUnloadDone{false};

  void reset(const std::string &name)
  {
    moduleName = name;
    eventId.clear();
    eventName.clear();
    eventPattern.clear();
    mode = 0;
    phase = 0;
    invocations = 0;
    lateInvocations = 0;
    unloadRan = false;
    unloadRanBeforeRead = false;
    observedMagic = 0;
    throwOnce = false;
    selfUnloadOp = 0;
    selfUnloadResult = 0;
    selfUnloadDone = false;
  }
};

/// Dependent-plugin counters: one per registration site.
struct DependentSlot
{
  std::atomic<int> onLoadHandler{0};
  std::atomic<int> depLoadedHandler{0};
  std::atomic<int> depUnloadedHandler{0};

  void reset()
  {
    onLoadHandler = 0;
    depLoadedHandler = 0;
    depUnloadedHandler = 0;
  }
};

struct CallbackControl
{
  static constexpr int SLOTS = 2;
  CallbackSlot probes[SLOTS];
  DependentSlot dependent;

  CallbackSlot *slotFor(const std::string &moduleName)
  {
    for (auto &s : probes)
    {
      if (s.moduleName == moduleName)
      {
        return &s;
      }
    }
    return nullptr;
  }
};

} // namespace test
} // namespace iora
