// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Test plugin for the generalAsyncPool cross-.so identity test
// (architecture/iora/async_pool.json DP-9). Exports a plain C accessor that
// returns the address of iora::core::generalAsyncPool() as seen from inside a
// separately-loaded shared object. Because generalAsyncPool() is defined exactly
// once (in libiora_core.so), the host process and this RTLD_LOCAL plugin must
// resolve the same object -> the returned address equals the host's.

#include <iora/core/thread_pool.hpp>

extern "C" void *iora_test_async_pool_addr()
{
  return static_cast<void *>(&iora::core::generalAsyncPool());
}
