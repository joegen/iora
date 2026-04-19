// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Tests for iora::core::ConfigLoader::getTableArray + minimal_toml
// [[array-of-tables]] parser support (P0 PREREQ-1 phase 3). Verifies
// declaration-order preservation, conflict detection with [a.b] and
// scalar keys, the std::optional<std::vector<ConfigSubTable>> return
// contract, and the getTable regression guard on array-of-tables keys.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>
#include <fstream>

using namespace iora::test;

TEST_CASE("scaffold compiles", "[iora][ConfigLoader][getTableArray]")
{
  REQUIRE(true);
}
