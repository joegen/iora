// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Cross-.so identity test for EngineBase::nextProcessSessionId
// (architecture/iora/engine_session_id_and_reset_drain.json IP-1, row IP-T1(d)).
// The function is declared in engine_base.hpp and defined once in libiora_core.so,
// so the host and an RTLD_LOCAL plugin share one counter. Host, plugin, host must be
// strictly increasing: with two counters this order cannot pass, whatever their
// start values.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/network/detail/engine_base.hpp>
#include <iora/util/filesystem.hpp>

#include <dlfcn.h>
#include <filesystem>
#include <string>

TEST_CASE("nextProcessSessionId is one counter across an RTLD_LOCAL plugin boundary",
          "[session_id][crossso]")
{
  const std::string pluginPath =
    iora::util::getExecutableDir() + "/core_plugins/core_test_session_id_plugin.so";
  REQUIRE(std::filesystem::exists(pluginPath));

  void *handle = dlopen(pluginPath.c_str(), RTLD_NOW | RTLD_LOCAL);
  REQUIRE(handle != nullptr);

  using MintFn = std::uint64_t (*)();
  auto fn = reinterpret_cast<MintFn>(dlsym(handle, "iora_test_mint_session_id"));
  REQUIRE(fn != nullptr);

  const std::uint64_t hostFirst = iora::network::detail::EngineBase::nextProcessSessionId();
  const std::uint64_t fromPlugin = fn();
  const std::uint64_t hostSecond = iora::network::detail::EngineBase::nextProcessSessionId();

  REQUIRE(hostFirst < fromPlugin);
  REQUIRE(fromPlugin < hostSecond);

  dlclose(handle);
}
