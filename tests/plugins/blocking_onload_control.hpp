// File: iora/tests/plugins/blocking_onload_control.hpp
//
// Shared control block for the load-failure teardown tests (tracker
// 2026-09-07-9, F-4). Included by BlockingOnLoadPlugin.cpp (the plugin .so) and
// by tests/service/iora_test_loadfailure_teardown.cpp (the host), so both agree
// on the exact struct layout. The plugin fetches a pointer to a host-owned
// instance of this struct via a host-exported getter ("test.blockctl", resolved
// with getExportedApi, which takes only _apiMutex and is therefore safe to call
// from within onLoad while _loadModulesMutex is held).
#pragma once

#include <atomic>

namespace iora
{
namespace test
{

/// Drives a blocking onLoad so the host can observe SD-1 admission behaviour: a
/// concurrent callExportedApi is REJECTED "not loaded" promptly (it no longer
/// takes _loadModulesMutex; the module is not yet markApiCallable'd), while a
/// concurrent non-owner isModuleLoaded — which still acquires _loadModulesMutex —
/// stays BLOCKED behind the monolithic load hold (the retained DP-10b guard).
/// Protocol: the plugin's onLoad exports its API, sets onLoadEntered=1 (the export
/// is now visible and onLoad is holding _loadModulesMutex), then spins until the
/// host sets release=1, then THROWS (the load fails). The isModuleLoaded thread
/// must stay blocked until release is set and the failed load unwinds.
struct BlockOnLoadControl
{
  std::atomic<int> onLoadEntered{0}; // set by the plugin once onLoad holds the lock + exported
  std::atomic<int> release{0};       // host sets to 1 to unblock onLoad (which then throws)
};

} // namespace test
} // namespace iora
