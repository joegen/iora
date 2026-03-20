// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for StringUtils

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/core/string_utils.hpp>

#include <string>
#include <unordered_map>

using namespace iora::core;

// ══════════════════════════════════════════════════════════════════════════════
// split(char delimiter)
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("split(char): basic split", "[string_utils][split]")
{
  auto parts = StringUtils::split("a,b,c", ',');
  REQUIRE(parts.size() == 3);
  REQUIRE(parts[0] == "a");
  REQUIRE(parts[1] == "b");
  REQUIRE(parts[2] == "c");
}

TEST_CASE("split(char): empty input", "[string_utils][split]")
{
  auto parts = StringUtils::split("", ',');
  REQUIRE(parts.empty());
}

TEST_CASE("split(char): no delimiter found", "[string_utils][split]")
{
  auto parts = StringUtils::split("hello", ',');
  REQUIRE(parts.size() == 1);
  REQUIRE(parts[0] == "hello");
}

TEST_CASE("split(char): consecutive delimiters", "[string_utils][split]")
{
  auto parts = StringUtils::split("a,,b", ',');
  REQUIRE(parts.size() == 3);
  REQUIRE(parts[0] == "a");
  REQUIRE(parts[1] == "");
  REQUIRE(parts[2] == "b");
}

TEST_CASE("split(char): delimiter only", "[string_utils][split]")
{
  auto parts = StringUtils::split(",", ',');
  REQUIRE(parts.size() == 2);
  REQUIRE(parts[0] == "");
  REQUIRE(parts[1] == "");
}

TEST_CASE("split(char): SIP header params", "[string_utils][split]")
{
  auto parts = StringUtils::split("transport=udp;branch=z9hG4bK;rport", ';');
  REQUIRE(parts.size() == 3);
  REQUIRE(parts[0] == "transport=udp");
  REQUIRE(parts[1] == "branch=z9hG4bK");
  REQUIRE(parts[2] == "rport");
}

// ══════════════════════════════════════════════════════════════════════════════
// split(string_view delimiter)
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("split(string_view): basic split", "[string_utils][split]")
{
  auto parts = StringUtils::split("a::b::c", std::string_view("::"));
  REQUIRE(parts.size() == 3);
  REQUIRE(parts[0] == "a");
  REQUIRE(parts[1] == "b");
  REQUIRE(parts[2] == "c");
}

TEST_CASE("split(string_view): empty input", "[string_utils][split]")
{
  auto parts = StringUtils::split("", std::string_view("::"));
  REQUIRE(parts.empty());
}

TEST_CASE("split(string_view): empty delimiter returns input", "[string_utils][split]")
{
  auto parts = StringUtils::split("hello", std::string_view(""));
  REQUIRE(parts.size() == 1);
  REQUIRE(parts[0] == "hello");
}

TEST_CASE("split(string_view): delimiter only", "[string_utils][split]")
{
  auto parts = StringUtils::split(",", std::string_view(","));
  REQUIRE(parts.size() == 2);
  REQUIRE(parts[0] == "");
  REQUIRE(parts[1] == "");
}

TEST_CASE("split(string_view): consecutive delimiters", "[string_utils][split]")
{
  auto parts = StringUtils::split("a::::b", std::string_view("::"));
  REQUIRE(parts.size() == 3);
  REQUIRE(parts[0] == "a");
  REQUIRE(parts[1] == "");
  REQUIRE(parts[2] == "b");
}

// ══════════════════════════════════════════════════════════════════════════════
// trim / trimLeft / trimRight
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("trim: normal whitespace", "[string_utils][trim]")
{
  REQUIRE(StringUtils::trim("  hello  ") == "hello");
  REQUIRE(StringUtils::trim("\thello\n") == "hello");
  REQUIRE(StringUtils::trim(" \t\r\n hello \t\r\n ") == "hello");
}

TEST_CASE("trim: all whitespace returns empty", "[string_utils][trim]")
{
  REQUIRE(StringUtils::trim("   ") == "");
  REQUIRE(StringUtils::trim("\t\r\n") == "");
}

TEST_CASE("trim: empty input", "[string_utils][trim]")
{
  REQUIRE(StringUtils::trim("") == "");
}

TEST_CASE("trim: no whitespace", "[string_utils][trim]")
{
  REQUIRE(StringUtils::trim("hello") == "hello");
}

TEST_CASE("trimLeft: leading only", "[string_utils][trim]")
{
  REQUIRE(StringUtils::trimLeft("  hello  ") == "hello  ");
}

TEST_CASE("trimRight: trailing only", "[string_utils][trim]")
{
  REQUIRE(StringUtils::trimRight("  hello  ") == "  hello");
}

TEST_CASE("trimLeft/trimRight: all whitespace", "[string_utils][trim]")
{
  REQUIRE(StringUtils::trimLeft("   ") == "");
  REQUIRE(StringUtils::trimRight("   ") == "");
}

// ══════════════════════════════════════════════════════════════════════════════
// iequals
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("iequals: same case", "[string_utils][iequals]")
{
  REQUIRE(StringUtils::iequals("hello", "hello"));
}

TEST_CASE("iequals: different case", "[string_utils][iequals]")
{
  REQUIRE(StringUtils::iequals("Hello", "hELLO"));
  REQUIRE(StringUtils::iequals("Content-Type", "content-type"));
}

TEST_CASE("iequals: different lengths", "[string_utils][iequals]")
{
  REQUIRE_FALSE(StringUtils::iequals("hello", "hell"));
  REQUIRE_FALSE(StringUtils::iequals("hi", "hello"));
}

TEST_CASE("iequals: empty strings", "[string_utils][iequals]")
{
  REQUIRE(StringUtils::iequals("", ""));
  REQUIRE_FALSE(StringUtils::iequals("", "a"));
}

// ══════════════════════════════════════════════════════════════════════════════
// toLower / toUpper
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("toLower: basic conversion", "[string_utils][case]")
{
  REQUIRE(StringUtils::toLower("HELLO") == "hello");
  REQUIRE(StringUtils::toLower("Hello World") == "hello world");
}

TEST_CASE("toUpper: basic conversion", "[string_utils][case]")
{
  REQUIRE(StringUtils::toUpper("hello") == "HELLO");
  REQUIRE(StringUtils::toUpper("Hello World") == "HELLO WORLD");
}

TEST_CASE("toLower/toUpper: digits and punctuation unchanged", "[string_utils][case]")
{
  REQUIRE(StringUtils::toLower("ABC-123!@#") == "abc-123!@#");
  REQUIRE(StringUtils::toUpper("abc-123!@#") == "ABC-123!@#");
}

TEST_CASE("toLower/toUpper: empty input", "[string_utils][case]")
{
  REQUIRE(StringUtils::toLower("") == "");
  REQUIRE(StringUtils::toUpper("") == "");
}

// ══════════════════════════════════════════════════════════════════════════════
// CaseInsensitiveHash + CaseInsensitiveEqual
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("CaseInsensitiveHash: same hash for different case", "[string_utils][hash]")
{
  StringUtils::CaseInsensitiveHash hash;
  REQUIRE(hash("Hello") == hash("hello"));
  REQUIRE(hash("CONTENT-TYPE") == hash("content-type"));
  REQUIRE(hash("Content-Type") == hash("content-type"));
}

TEST_CASE("CaseInsensitiveEqual: different case compares equal", "[string_utils][hash]")
{
  StringUtils::CaseInsensitiveEqual eq;
  REQUIRE(eq("Hello", "hello"));
  REQUIRE(eq("Content-Type", "content-type"));
  REQUIRE_FALSE(eq("Hello", "World"));
}

TEST_CASE("Hash traits: use with unordered_map", "[string_utils][hash]")
{
  std::unordered_map<std::string, int,
    StringUtils::CaseInsensitiveHash,
    StringUtils::CaseInsensitiveEqual> headers;

  headers["Content-Type"] = 1;
  headers["Accept"] = 2;

  REQUIRE(headers["content-type"] == 1);
  REQUIRE(headers["ACCEPT"] == 2);
  REQUIRE(headers.count("CONTENT-TYPE") == 1);
}

TEST_CASE("Hash traits: is_transparent trait present", "[string_utils][hash]")
{
  // Verify the is_transparent typedef exists (enables heterogeneous lookup)
  using H = StringUtils::CaseInsensitiveHash::is_transparent;
  using E = StringUtils::CaseInsensitiveEqual::is_transparent;
  static_assert(std::is_same_v<H, void>);
  static_assert(std::is_same_v<E, void>);
  REQUIRE(true);
}

TEST_CASE("Hash traits: noexcept", "[string_utils][hash]")
{
  StringUtils::CaseInsensitiveHash hash;
  StringUtils::CaseInsensitiveEqual eq;
  static_assert(noexcept(hash("test")));
  static_assert(noexcept(eq("a", "b")));
  REQUIRE(true);
}

// ══════════════════════════════════════════════════════════════════════════════
// noexcept guarantees
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("StringUtils: noexcept on trim and iequals", "[string_utils]")
{
  static_assert(noexcept(StringUtils::trim("test")));
  static_assert(noexcept(StringUtils::trimLeft("test")));
  static_assert(noexcept(StringUtils::trimRight("test")));
  static_assert(noexcept(StringUtils::iequals("a", "b")));
  REQUIRE(true);
}
