// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.
//
// Encode-side known-answer coverage for util/base64.hpp. The strict DECODE
// contract is covered by tests/web/test_base64_decode.cpp; this file exercises
// Base64::encode and Base64Url::encode (RFC 4648 test vectors, the 1-/2-byte
// padding tails, the URL-safe alphabet, and encode/decode round-trips) which had
// no direct known-answer assertions before.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <cstdint>
#include <string>
#include <vector>

#include <iora/util/base64.hpp>

using iora::util::Base64;
using iora::util::Base64Url;

namespace
{
std::vector<std::uint8_t> bytes(const std::string &s)
{
  return std::vector<std::uint8_t>(s.begin(), s.end());
}
} // namespace

TEST_CASE("Base64::encode matches RFC 4648 test vectors (with padding)",
          "[base64][encode]")
{
  // RFC 4648 section 10 test vectors.
  REQUIRE(Base64::encode(bytes("")) == "");
  REQUIRE(Base64::encode(bytes("f")) == "Zg==");     // 1-byte tail -> "=="
  REQUIRE(Base64::encode(bytes("fo")) == "Zm8=");    // 2-byte tail -> "="
  REQUIRE(Base64::encode(bytes("foo")) == "Zm9v");   // full group, no pad
  REQUIRE(Base64::encode(bytes("foob")) == "Zm9vYg==");
  REQUIRE(Base64::encode(bytes("fooba")) == "Zm9vYmE=");
  REQUIRE(Base64::encode(bytes("foobar")) == "Zm9vYmFy");
}

TEST_CASE("Base64Url::encode is URL-safe and unpadded", "[base64][encode]")
{
  REQUIRE(Base64Url::encode(bytes("")) == "");
  REQUIRE(Base64Url::encode(bytes("f")) == "Zg");   // no padding
  REQUIRE(Base64Url::encode(bytes("fo")) == "Zm8"); // no padding
  REQUIRE(Base64Url::encode(bytes("foo")) == "Zm9v");
  REQUIRE(Base64Url::encode(bytes("foob")) == "Zm9vYg");
  REQUIRE(Base64Url::encode(bytes("fooba")) == "Zm9vYmE");
  REQUIRE(Base64Url::encode(bytes("foobar")) == "Zm9vYmFy");

  // A payload whose standard encoding uses '+' and '/': Base64 emits "+/8=",
  // Base64Url must emit '-' and '_' and drop padding.
  const std::vector<std::uint8_t> hi = {0xFBu, 0xFFu};
  REQUIRE(Base64::encode(hi) == "+/8=");
  REQUIRE(Base64Url::encode(hi) == "-_8");
}

TEST_CASE("Base64 encode/decode round-trips over all byte values",
          "[base64][encode]")
{
  std::vector<std::uint8_t> all;
  for (int i = 0; i < 256; ++i)
  {
    all.push_back(static_cast<std::uint8_t>(i));
  }
  const std::string encoded = Base64::encode(all);
  auto decoded = Base64::decode(encoded);
  REQUIRE(decoded.has_value());
  REQUIRE(*decoded == all);
}

TEST_CASE("Base64::encode ptr/len and vector overloads agree", "[base64][encode]")
{
  std::vector<std::uint8_t> v = bytes("Hello, Iora");
  v.push_back(0x00u); // embedded NUL (binary-safe)
  v.push_back(0xFEu);
  REQUIRE(Base64::encode(v) == Base64::encode(v.data(), v.size()));
  REQUIRE(Base64Url::encode(v) == Base64Url::encode(v.data(), v.size()));
}
