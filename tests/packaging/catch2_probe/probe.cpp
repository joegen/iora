// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0

#include <catch2/catch.hpp>

#ifndef IORA_PROBE_CATCH2_VIA_TARGET
#error "include dir not propagated from Catch2::Catch2WithMain"
#endif

TEST_CASE("synthesized Catch2WithMain supplies main", "[packaging]")
{
  REQUIRE(1 + 1 == 2);
}
