// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>

#include <iora/util/crc32.hpp>

using iora::util::Crc32;

namespace
{
// All 256 byte values 0x00..0xFF — the >= 0x80 domain that a signed-char table
// index would corrupt (H1).
std::string allBytes()
{
  std::string s;
  s.reserve(256);
  for (int i = 0; i < 256; ++i)
  {
    s.push_back(static_cast<char>(static_cast<unsigned char>(i)));
  }
  return s;
}
} // namespace

TEST_CASE("crc32 known-answer vectors", "[crc32]")
{
  // Confirmed via:
  //   python3 -c "import zlib; print(hex(zlib.crc32(b'123456789')),
  //                                  hex(zlib.crc32(bytes(range(256)))))"
  //   -> 0xcbf43926 0x29058c73
  REQUIRE(Crc32::compute(std::string_view("123456789")) == 0xCBF43926u);

  // Empty input == 0 (init ^ final-XOR cancels with no bytes folded).
  REQUIRE(Crc32::compute(std::string_view("")) == 0x00000000u);

  // The >= 0x80 vector — proves unsigned-char table indexing (H1).
  REQUIRE(Crc32::compute(allBytes()) == 0x29058C73u);
}

TEST_CASE("crc32 ptr+len overload matches string_view overload", "[crc32]")
{
  const std::string s = allBytes();
  REQUIRE(Crc32::compute(s.data(), s.size()) ==
          Crc32::compute(std::string_view(s)));

  // Null data with zero length is well-defined and equals the empty CRC.
  REQUIRE(Crc32::compute(nullptr, 0) == 0x00000000u);
}

TEST_CASE("crc32 embedded NUL is not a terminator", "[crc32]")
{
  const std::string withNul("a\0b", 3);
  REQUIRE(withNul.size() == 3);
  // Differs from the truncated-at-NUL "a" — the NUL and trailing 'b' are folded.
  REQUIRE(Crc32::compute(std::string_view(withNul)) !=
          Crc32::compute(std::string_view("a")));
}

TEST_CASE("crc32 incremental in chunks equals one-shot", "[crc32]")
{
  const std::string data = allBytes();
  const std::uint32_t oneShot = Crc32::compute(std::string_view(data));

  SECTION("one byte at a time via update(ptr,len)")
  {
    Crc32::Incremental acc;
    for (char ch : data)
    {
      acc.update(&ch, 1);
    }
    REQUIRE(acc.value() == oneShot);
  }

  SECTION("odd-boundary chunks via update(string_view)")
  {
    Crc32::Incremental acc;
    std::string_view sv(data);
    const std::size_t step = 7; // odd boundary, not aligned to any word
    for (std::size_t i = 0; i < sv.size(); i += step)
    {
      acc.update(sv.substr(i, std::min(step, sv.size() - i)));
    }
    REQUIRE(acc.value() == oneShot);
  }

  SECTION("whole buffer in a single update")
  {
    Crc32::Incremental acc;
    acc.update(std::string_view(data));
    REQUIRE(acc.value() == oneShot);
  }
}

TEST_CASE("crc32 value() is non-mutating mid-stream (M1)", "[crc32]")
{
  const std::string first = "123456789";
  const std::string second = "abcdefghij";
  const std::uint32_t whole =
    Crc32::compute(std::string_view(first + second));

  Crc32::Incremental acc;
  acc.update(std::string_view(first));
  // Read the running CRC repeatedly; each read must leave the state intact so
  // the subsequent update() continues from the same point.
  const std::uint32_t mid1 = acc.value();
  const std::uint32_t mid2 = acc.value();
  REQUIRE(mid1 == mid2);
  REQUIRE(mid1 == Crc32::compute(std::string_view(first)));

  acc.update(std::string_view(second));
  const std::uint32_t after1 = acc.value();
  const std::uint32_t after2 = acc.value();
  REQUIRE(after1 == after2);
  REQUIRE(after1 == whole);
}
