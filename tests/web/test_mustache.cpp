// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Unit tests for the iora::parsers Mustache engine (parsers/mustache.hpp).
// See architecture/iora/mustache_engine.json and tracker
// 2026-05-29-3_htmx-support_phase2b_mustache-engine_P2.json.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/parsers/mustache.hpp>

#include <iora/parsers/json.hpp>

#include <optional>
#include <string>
#include <string_view>

using iora::parsers::Json;
using iora::parsers::Mustache;
using iora::parsers::MustacheError;
using iora::parsers::PartialResolver;

// ---------------------------------------------------------------------------
// Scaffold placeholder (task-3.1). Replaced/expanded by tasks 3.2-3.8.
// ---------------------------------------------------------------------------

TEST_CASE("Mustache scaffold compiles and render() is callable", "[mustache][scaffold]")
{
  Json data;
  REQUIRE_NOTHROW(Mustache::render("", data));
  // render() callable with and without a PartialResolver argument (task-1.2).
  PartialResolver resolver = [](std::string_view) -> std::optional<std::string>
  { return std::nullopt; };
  REQUIRE_NOTHROW(Mustache::render("", data, resolver));
}
