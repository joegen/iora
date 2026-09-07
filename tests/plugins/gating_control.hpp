// File: iora/tests/plugins/gating_control.hpp
//
// Shared control block for the callExportedApi drain-gate tests (Slice B,
// tracker 2026-09-07-3). Included by SlowApiPlugin.cpp (the plugin .so) and by
// tests/service/iora_test_callexportedapi_gating.cpp (the host), so both agree
// on the exact struct layout passed through callExportedApi<int, SlowApiControl*>.
#pragma once

#include <atomic>

namespace iora
{
namespace test
{

/// Drives a deterministically-widened in-flight callExportedApi window.
/// Protocol: the exported "slowapi.call" sets `phase=1` on entry (call is now
/// in-flight, inside the plugin lambda holding the plugin object) and spins
/// until the test sets `phase=2`. Before returning it reads the plugin object's
/// magic member — which the drain must keep alive — recording it in
/// `observedMagic`, and records whether the plugin's onUnload had already run
/// (`unloadRanBeforeRead`); with the drain that MUST be false (teardown waits
/// for the call).
struct SlowApiControl
{
  std::atomic<int> phase{0};                    // 0=not entered, 1=in-flight, 2=proceed
  std::atomic<bool> unloadRan{false};           // set by the plugin's onUnload
  std::atomic<bool> unloadRanBeforeRead{false}; // sampled at the object-state read
  std::atomic<int> observedMagic{0};            // plugin-object magic read under the gate
};

} // namespace test
} // namespace iora
