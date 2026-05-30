// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Unit tests for iora::util::Base64::decode / decodeToString (util/base64.hpp).
// Tracker: 2026-05-29-5 phase 4.2; architecture: http_basic_auth.json.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/util/base64.hpp>

#include <cstdint>
#include <string>
#include <vector>

using iora::util::Base64;

namespace
{
// Helper: bytes of a string literal.
std::vector<std::uint8_t> bytesOf(const std::string &s)
{
  return std::vector<std::uint8_t>(s.begin(), s.end());
}
} // namespace

// ---------------------------------------------------------------------------
// task-4.2.2 — known-answer vectors + padding-case output-length tests
// ---------------------------------------------------------------------------

TEST_CASE("decode known-answer vectors", "[base64][decode][kav]")
{
  REQUIRE(Base64::decode("TWFu") == bytesOf("Man"));
  REQUIRE(Base64::decode("TWE=") == bytesOf("Ma"));
  REQUIRE(Base64::decode("TQ==") == bytesOf("M"));
}

TEST_CASE("decode RFC 4648 'foobar' progression", "[base64][decode][rfc4648]")
{
  REQUIRE(Base64::decode("Zg==") == bytesOf("f"));
  REQUIRE(Base64::decode("Zm8=") == bytesOf("fo"));
  REQUIRE(Base64::decode("Zm9v") == bytesOf("foo"));
  REQUIRE(Base64::decode("Zm9vYg==") == bytesOf("foob"));
  REQUIRE(Base64::decode("Zm9vYmE=") == bytesOf("fooba"));
  REQUIRE(Base64::decode("Zm9vYmFy") == bytesOf("foobar"));
}

TEST_CASE("decode padding cases produce correct output lengths", "[base64][decode][padding]")
{
  // zero pad: full quantum -> 3 bytes
  auto zero = Base64::decode("Zm9v");
  REQUIRE(zero.has_value());
  REQUIRE(zero->size() == 3);

  // one '=' -> 2 output bytes for the final quantum
  auto one = Base64::decode("Zm8=");
  REQUIRE(one.has_value());
  REQUIRE(one->size() == 2);

  // two '==' -> 1 output byte
  auto two = Base64::decode("Zg==");
  REQUIRE(two.has_value());
  REQUIRE(two->size() == 1);
}

// ---------------------------------------------------------------------------
// task-4.2.3 — invalid-alphabet, misplaced-padding, wrong-length rejection
// ---------------------------------------------------------------------------

TEST_CASE("decode rejects non-alphabet bytes", "[base64][decode][reject]")
{
  // '-' and '_' are the Base64URL alphabet, not standard — rejected.
  REQUIRE(Base64::decode("ab-_") == std::nullopt);
  // '#' and other punctuation.
  REQUIRE(Base64::decode("ab#d") == std::nullopt);
  // embedded whitespace is a non-alphabet byte (whitespace policy D-1).
  REQUIRE(Base64::decode("ab d") == std::nullopt);
  REQUIRE(Base64::decode("ab\td") == std::nullopt);
  REQUIRE(Base64::decode("ab\nd") == std::nullopt);
  REQUIRE(Base64::decode("a'cd") == std::nullopt);
  // high-bit (>= 0x80) and NUL bytes: exercises the signed-char -> uint8_t
  // reverse-table indexing path (cpp17 L-4).
  REQUIRE(Base64::decode(std::string("ab\x80\x81")) == std::nullopt);
  REQUIRE(Base64::decode(std::string("ab\xFF""d")) == std::nullopt);
  REQUIRE(Base64::decode(std::string("ab\0d", 4)) == std::nullopt);
}

TEST_CASE("decode rejects misplaced padding", "[base64][decode][padding][reject]")
{
  REQUIRE(Base64::decode("=abc") == std::nullopt);
  REQUIRE(Base64::decode("a=bc") == std::nullopt);
  REQUIRE(Base64::decode("ab=c") == std::nullopt);
  REQUIRE(Base64::decode("A===") == std::nullopt);
}

TEST_CASE("decode rejects degenerate all-padding (web L-1)", "[base64][decode][padding][reject]")
{
  REQUIRE(Base64::decode("==") == std::nullopt);   // length 2, not multiple of 4
  REQUIRE(Base64::decode("====") == std::nullopt); // length 4, no data sextets
}

TEST_CASE("decode rejects wrong length", "[base64][decode][length][reject]")
{
  REQUIRE(Base64::decode("TWF") == std::nullopt);   // length 3
  REQUIRE(Base64::decode("TWFu5") == std::nullopt); // length 5
}

// ---------------------------------------------------------------------------
// task-4.2.4 — MANDATORY strict pad-bit rejection (RD-15 / D-4)
// ---------------------------------------------------------------------------

TEST_CASE("decode strict pad-bit rejection — '==' case (low 4 bits)", "[base64][decode][padbits]")
{
  // canonical 'M' (Q=16=010000, low 4 bits 0000)
  REQUIRE(Base64::decode("TQ==") == bytesOf("M"));
  // dirty sibling (R=17=010001, low 4 bits 0001 != 0) — differs ONLY in the
  // discarded pad bits.
  REQUIRE(Base64::decode("TR==") == std::nullopt);
}

TEST_CASE("decode strict pad-bit rejection — '=' case (low 2 bits)", "[base64][decode][padbits]")
{
  // canonical 'Ma' (E=4=000100, low 2 bits 00)
  REQUIRE(Base64::decode("TWE=") == bytesOf("Ma"));
  // dirty sibling (F=5=000101, low 2 bits 01 != 0) — differs ONLY in the
  // discarded pad bits.
  REQUIRE(Base64::decode("TWF=") == std::nullopt);
}

// ---------------------------------------------------------------------------
// task-4.2.5 — empty input, binary safety, round-trip, decodeToString
// ---------------------------------------------------------------------------

TEST_CASE("decode empty input -> present empty vector", "[base64][decode][empty]")
{
  auto e = Base64::decode("");
  REQUIRE(e.has_value());
  REQUIRE(e->empty());
}

TEST_CASE("decode binary safety preserves interior NUL (H-4)", "[base64][decode][binary]")
{
  const std::vector<std::uint8_t> buf{0x00, 0x01, 0xFF, 0x00};
  auto d = Base64::decode(Base64::encode(buf));
  REQUIRE(d.has_value());
  REQUIRE(d->size() == 4);
  REQUIRE((*d)[0] == 0x00);
  REQUIRE((*d)[1] == 0x01);
  REQUIRE((*d)[2] == 0xFF);
  REQUIRE((*d)[3] == 0x00);
}

TEST_CASE("decode round-trips the encoder for lengths 0..5", "[base64][decode][roundtrip]")
{
  for (std::size_t len = 0; len <= 5; ++len)
  {
    std::vector<std::uint8_t> buf;
    buf.reserve(len);
    for (std::size_t i = 0; i < len; ++i)
    {
      buf.push_back(static_cast<std::uint8_t>(i * 37 + 1));
    }
    auto round = Base64::decode(Base64::encode(buf));
    REQUIRE(round.has_value());
    REQUIRE(*round == buf);
  }
}

TEST_CASE("decodeToString convenience", "[base64][decode][tostring]")
{
  auto ok = Base64::decodeToString("dXNlcjpwYXNz");
  REQUIRE(ok.has_value());
  REQUIRE(*ok == "user:pass");

  REQUIRE(Base64::decodeToString("!!!notb64!!!") == std::nullopt);
}

TEST_CASE("decodeToString preserves embedded NUL length (M-1)", "[base64][decode][tostring][binary]")
{
  const std::vector<std::uint8_t> buf{'a', 0x00, 'b'};
  auto s = Base64::decodeToString(Base64::encode(buf));
  REQUIRE(s.has_value());
  REQUIRE(s->size() == 3);
  REQUIRE((*s)[0] == 'a');
  REQUIRE((*s)[1] == '\0');
  REQUIRE((*s)[2] == 'b');
}
