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

/// Drives a blocking onLoad so the host can observe that a concurrent
/// callExportedApi is serialized behind the load (DP-10b: loadSingleModule holds
/// _loadModulesMutex monolithically across onLoad; callExportedApi's is-loaded
/// gate acquires the same mutex). Protocol: the plugin's onLoad exports its API,
/// sets onLoadEntered=1 (the export is now visible and onLoad is holding
/// _loadModulesMutex), then spins until the host sets release=1, then THROWS
/// (the load fails). A concurrent host thread calling the exported API must stay
/// blocked on the is-loaded gate until release is set and the failed load
/// unwinds and releases the lock.
struct BlockOnLoadControl
{
  std::atomic<int> onLoadEntered{0}; // set by the plugin once onLoad holds the lock + exported
  std::atomic<int> release{0};       // host sets to 1 to unblock onLoad (which then throws)
};

} // namespace test
} // namespace iora
