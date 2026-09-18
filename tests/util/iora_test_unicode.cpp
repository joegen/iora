// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <cstdint>
#include <string>

#include <iora/util/unicode.hpp>

using iora::util::appendUtf8;
using iora::util::hexDigitValue;

namespace
{
std::string utf8Of(std::uint32_t cp)
{
  std::string out;
  REQUIRE(appendUtf8(out, cp));
  return out;
}
} // namespace

TEST_CASE("appendUtf8 encodes the 1-4 byte length boundaries", "[unicode]")
{
  // 1-byte (ASCII): U+0000..U+007F
  REQUIRE(utf8Of(0x00u) == std::string(1, '\0')); // NUL preserved
  REQUIRE(utf8Of(0x41u) == "A");
  REQUIRE(utf8Of(0x7Fu) == std::string("\x7F"));

  // 2-byte: U+0080..U+07FF
  REQUIRE(utf8Of(0x80u) == "\xC2\x80");
  REQUIRE(utf8Of(0x7FFu) == "\xDF\xBF");

  // 3-byte: U+0800..U+FFFF
  REQUIRE(utf8Of(0x800u) == "\xE0\xA0\x80");
  REQUIRE(utf8Of(0x20ACu) == "\xE2\x82\xAC"); // EURO SIGN
  REQUIRE(utf8Of(0xFFFFu) == "\xEF\xBF\xBF");

  // 4-byte: U+10000..U+10FFFF
  REQUIRE(utf8Of(0x10000u) == "\xF0\x90\x80\x80");
  REQUIRE(utf8Of(0x1F600u) == "\xF0\x9F\x98\x80"); // GRINNING FACE
  REQUIRE(utf8Of(0x10FFFFu) == "\xF4\x8F\xBF\xBF"); // last valid code point
}

TEST_CASE("appendUtf8 rejects surrogates and out-of-range, leaving out unchanged",
          "[unicode]")
{
  for (std::uint32_t cp : {0xD800u, 0xDABCu, 0xDFFFu, 0x110000u, 0xFFFFFFFFu})
  {
    std::string out = "seed";
    REQUIRE_FALSE(appendUtf8(out, cp));
    REQUIRE(out == "seed"); // unchanged on rejection
  }
  // The boundaries just outside the surrogate range ARE valid.
  REQUIRE(utf8Of(0xD7FFu) == "\xED\x9F\xBF");
  REQUIRE(utf8Of(0xE000u) == "\xEE\x80\x80");
}

TEST_CASE("appendUtf8 appends to existing content", "[unicode]")
{
  std::string out = "x=";
  REQUIRE(appendUtf8(out, 0x41u));
  REQUIRE(out == "x=A");
}

TEST_CASE("hexDigitValue decodes valid ASCII hex digits", "[unicode]")
{
  std::uint32_t v = 99;
  REQUIRE(hexDigitValue('0', v));
  REQUIRE(v == 0u);
  REQUIRE(hexDigitValue('9', v));
  REQUIRE(v == 9u);
  REQUIRE(hexDigitValue('a', v));
  REQUIRE(v == 10u);
  REQUIRE(hexDigitValue('f', v));
  REQUIRE(v == 15u);
  REQUIRE(hexDigitValue('A', v));
  REQUIRE(v == 10u);
  REQUIRE(hexDigitValue('F', v));
  REQUIRE(v == 15u);
}

TEST_CASE("hexDigitValue rejects non-hex characters, leaving out unchanged",
          "[unicode]")
{
  // Boundary chars just outside each hex sub-range: '/' (below '0'), ':' (above
  // '9'), '@' (below 'A'), 'G' (above 'F'), '`' (below 'a'), 'g' (above 'f').
  for (char c : {'/', ':', '@', 'G', '`', 'g', 'z', ' ', '\0', '\x80'})
  {
    std::uint32_t v = 0xABCDu;
    REQUIRE_FALSE(hexDigitValue(c, v));
    REQUIRE(v == 0xABCDu); // unchanged on rejection
  }
}
