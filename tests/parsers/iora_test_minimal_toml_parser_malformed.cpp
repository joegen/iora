// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Tests for iora::parsers::toml::parser termination on malformed input. A
// top-level line beginning with a character parseKey() cannot consume (e.g.
// '@', '=', a quote) previously left _pos unadvanced, spinning the outer
// parse() loop forever. The parser must now reject such lines instead.

#define CATCH_CONFIG_MAIN
#include "iora/parsers/minimal_toml.hpp"
#include <catch2/catch.hpp>
#include <string>

using namespace iora::parsers;

namespace
{

/// \brief Parse input; return true iff parse() threw (i.e. terminated with a
/// rejection rather than looping). A hang would never reach the assertion, so
/// reaching either branch already proves termination.
bool parseThrows(const std::string &input)
{
  try
  {
    toml::parse(input);
    return false;
  }
  catch (const std::exception &)
  {
    return true;
  }
}

} // namespace

TEST_CASE("TOML parser terminates on malformed leading characters",
          "[toml][malformed]")
{
  SECTION("line beginning with '@'")
  {
    REQUIRE(parseThrows("@foo = 1\n"));
  }

  SECTION("line beginning with '=' (missing key)")
  {
    REQUIRE(parseThrows("= 1\n"));
  }

  SECTION("quoted key (unsupported in the minimal subset)")
  {
    REQUIRE(parseThrows("\"quoted\" = 1\n"));
  }

  SECTION("malformed line after a valid section")
  {
    REQUIRE(parseThrows("[section]\nvalid = 1\n@bad = 2\n"));
  }

  SECTION("bare punctuation with no newline")
  {
    REQUIRE(parseThrows("@"));
  }
}

TEST_CASE("TOML parser still accepts well-formed input", "[toml][malformed]")
{
  SECTION("simple key/value")
  {
    toml::table t = toml::parse("name = \"value\"\n");
    REQUIRE(t.contains("name"));
    REQUIRE(t.at("name").as<std::string>() == "value");
  }

  SECTION("section with keys, comments, and blank lines")
  {
    toml::table t = toml::parse(
      "# comment\n\n[server]\nport = 8080\nhost = \"localhost\"\n");
    const toml::table *server = t.at("server").as_table();
    REQUIRE(server != nullptr);
    REQUIRE(server->at("port").as<int64_t>() == 8080);
    REQUIRE(server->at("host").as<std::string>() == "localhost");
  }
}
