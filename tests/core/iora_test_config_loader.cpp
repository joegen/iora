// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>
#include <limits>
#include <type_traits>

TEST_CASE("ConfigLoader basic operations", "[config][ConfigLoader]")
{
  const std::string cfgFile = "test_config.toml";
  {
    std::ofstream out(cfgFile);
    out << "[section]\n";
    out << "int_val = 42\n";
    out << "bool_val = true\n";
    out << "str_val = 'hello'\n";
    out << "[other]\n";
    out << "float_val = 3.14\n";
  }

  iora::core::ConfigLoader loader(cfgFile);

  SECTION("Reload and load returns table")
  {
    REQUIRE(loader.reload());
    const auto &tbl = loader.load();
    REQUIRE(tbl.contains("section"));
    REQUIRE(tbl.contains("other"));
  }

  SECTION("get<T> returns correct values")
  {
    loader.reload();
    REQUIRE(loader.get<int64_t>("section.int_val").value() == 42);
    REQUIRE(loader.get<bool>("section.bool_val").value());
    REQUIRE(loader.get<std::string>("section.str_val").value() == "hello");
    REQUIRE_FALSE(loader.get<int64_t>("section.missing").has_value());
  }

  SECTION("getInt, getBool, getString work as expected")
  {
    loader.reload();
    REQUIRE(loader.getInt("section.int_val").value() == 42);
    REQUIRE(loader.getBool("section.bool_val").value());
    REQUIRE(loader.getString("section.str_val").value() == "hello");
    REQUIRE_FALSE(loader.getInt("section.missing").has_value());
  }

  SECTION("table() returns the parsed table")
  {
    loader.reload();
    const auto &tbl = loader.table();
    REQUIRE(tbl.contains("section"));
    REQUIRE(tbl.at_path("section.int_val").is_value());
  }

  SECTION("load throws on missing file")
  {
    iora::core::ConfigLoader badLoader("does_not_exist.toml");
    badLoader.load();
    REQUIRE_FALSE(badLoader.isLoaded());
  }

  std::filesystem::remove(cfgFile);
}

TEST_CASE("ConfigLoader extended functionality", "[config][ConfigLoader]")
{
  const std::string cfgFile = "test_config_extended.toml";
  {
    std::ofstream out(cfgFile);
    out << "[section]\n";
    out << "int_val = 42\n";
    out << "bool_val = true\n";
    out << "str_val = 'hello'\n";
    out << "str_array = ['a', 'b', 'c']\n";
    out << "[other]\n";
    out << "float_val = 3.14\n";
  }

  iora::core::ConfigLoader loader(cfgFile);

  SECTION("getStringArray returns string vector if all elements are strings")
  {
    const std::string arrFile = "test_config_array.toml";
    {
      std::ofstream out(arrFile);
      out << "[section]\nstr_array = ['a', 'b', 'c']\n";
    }
    iora::core::ConfigLoader arrLoader(arrFile);
    arrLoader.reload();
    auto result = arrLoader.getStringArray("section.str_array");
    REQUIRE(result.has_value());
    REQUIRE(result->size() == 3);
    REQUIRE((*result)[0] == "a");
    REQUIRE((*result)[1] == "b");
    REQUIRE((*result)[2] == "c");
    std::filesystem::remove(arrFile);
  }

  SECTION("getStringArray returns std::nullopt if key is missing")
  {
    loader.reload();
    auto result = loader.getStringArray("section.missing_array");
    REQUIRE_FALSE(result.has_value());
  }

  SECTION("getStringArray throws if any element is not a string")
  {
    const std::string badArrFile = "test_config_badarray.toml";
    {
      std::ofstream out(badArrFile);
      out << "[section]\nmixed_array = ['x', 42, 'y']\n";
    }
    iora::core::ConfigLoader badArrLoader(badArrFile);
    badArrLoader.reload();
    REQUIRE_THROWS_AS(badArrLoader.getStringArray("section.mixed_array"), std::runtime_error);
    std::filesystem::remove(badArrFile);
  }

  std::filesystem::remove(cfgFile);
}
