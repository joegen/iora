// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Cross-.so identity test for iora::core::generalAsyncPool()
// (architecture/iora/async_pool.json DP-9). generalAsyncPool() is declared in a
// header but DEFINED exactly once in libiora_core.so, so every translation unit
// -- the host process and any RTLD_LOCAL plugin -- must resolve the same pool
// instance. A header-inlined function-local static would instead give the plugin
// its OWN pool, defeating the process-wide guarantee. This test dlopen's a plugin
// RTLD_LOCAL and asserts the pool address it reports equals the host's.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/core/thread_pool.hpp>
#include <iora/util/filesystem.hpp>

#include <dlfcn.h>
#include <filesystem>
#include <string>

TEST_CASE("generalAsyncPool is one instance across an RTLD_LOCAL plugin boundary",
          "[async_pool][crossso]")
{
  const std::string pluginPath =
    iora::util::getExecutableDir() + "/core_plugins/core_test_async_pool_plugin.so";
  REQUIRE(std::filesystem::exists(pluginPath));

  void *handle = dlopen(pluginPath.c_str(), RTLD_NOW | RTLD_LOCAL);
  REQUIRE(handle != nullptr);

  using AddrFn = void *(*)();
  auto fn = reinterpret_cast<AddrFn>(dlsym(handle, "iora_test_async_pool_addr"));
  REQUIRE(fn != nullptr);

  void *fromPlugin = fn();
  void *fromCore = static_cast<void *>(&iora::core::generalAsyncPool());
  REQUIRE(fromPlugin == fromCore);

  dlclose(handle);
}
