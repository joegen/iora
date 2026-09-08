// File: iora/tests/plugins/unload_teardown_control.hpp
//
// Shared control block for the unload/teardown exception tests (trackers
// 2026-09-08-4 + 2026-09-08-3). Included by the forcing-function plugin .so's
// and by tests/service/iora_test_unload_teardown_exception.cpp (the host), so
// both agree on the exact struct layout. Each plugin fetches a pointer to a
// host-owned instance via a host-exported getter ("test.unloadctl", resolved
// with getExportedApi, which takes only _apiMutex and is therefore safe to call
// from within onLoad while _loadModulesMutex is held). The plugin caches the
// pointer in onLoad and only reads/writes it from its onUnload /
// onDependencyUnloaded callbacks (which run under _loadModulesMutex during
// teardown) — never calling back into the service API there.
#pragma once

#include <atomic>

namespace iora
{
namespace test
{

/// Observation + control block for the unload-path teardown-exception fixtures.
/// The plugin .so's are RTLD_LOCAL, so their internal state is not observable
/// across the boundary; these host-owned atomics are the discriminating signals.
struct UnloadTeardownControl
{
  // FX-U1: incremented by the well-behaved dependent D2's onDependencyUnloaded,
  // proving one dependent's (D1's) non-std throw did not skip D2's notification.
  std::atomic<int> d2DepUnloaded{0};
  // FX-U2: incremented by M's onDependencyUnloaded(B), proving M was still in
  // _dependents[B] after M's own onUnload threw (Option A: prune skipped).
  std::atomic<int> mDepUnloadedFromB{0};
  // FX-U2 control: while > 0, M's onUnload decrements this and throws a std
  // exception (so it throws EXACTLY once — a later cleanup unload succeeds).
  std::atomic<int> armStdOnUnloadThrow{0};
  // FX-U3 control: while > 0, M's onUnload decrements this and throws a NON-std
  // exception (throws exactly once, so UnloadAllOnExit can still reclaim M).
  std::atomic<int> armNonStdOnUnloadThrow{0};
  // FX-U4: incremented by the well-behaved independent module Mb's onUnload,
  // proving a sibling module's onUnload throw did not abort the batch teardown.
  std::atomic<int> mbOnUnloadRan{0};
};

} // namespace test
} // namespace iora
