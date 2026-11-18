// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Test plugin for the nextProcessSessionId cross-.so identity test
// (architecture/iora/engine_session_id_and_reset_drain.json IP-T1(d)). Mints one
// session id through EngineBase::nextProcessSessionId from inside a separately
// loaded shared object.

#include <iora/network/detail/engine_base.hpp>

#include <cstdint>

extern "C" std::uint64_t iora_test_mint_session_id()
{
  return iora::network::detail::EngineBase::nextProcessSessionId();
}
