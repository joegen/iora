// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include <iora/crypto/secure_rng.hpp>

#include <openssl/err.h>

using iora::crypto::SecureRng;

namespace
{
template <std::size_t N> std::string toHex(const unsigned char (&b)[N])
{
  static constexpr char kHex[] = "0123456789abcdef";
  std::string s;
  for (std::size_t i = 0; i < N; ++i)
  {
    s.push_back(kHex[b[i] >> 4]);
    s.push_back(kHex[b[i] & 0x0F]);
  }
  return s;
}

bool allZero(const std::uint8_t *p, std::size_t n)
{
  return std::all_of(p, p + n, [](std::uint8_t c) { return c == 0; });
}
} // namespace

TEST_CASE("SecureRng::fill zero length is a no-op and a null buffer is rejected", "[secure_rng]")
{
  REQUIRE_NOTHROW(SecureRng::fill(nullptr, 0));
  REQUIRE_THROWS_AS(SecureRng::fill(nullptr, 1), std::invalid_argument);
  std::string empty;
  REQUIRE_NOTHROW(SecureRng::fill(empty));
}

TEST_CASE("SecureRng::fill writes the whole buffer", "[secure_rng]")
{
  std::array<std::uint8_t, 64> a{};
  SecureRng::fill(a);
  REQUIRE_FALSE(allZero(a.data(), a.size()));

  std::array<std::uint8_t, 64> b{};
  SecureRng::fill(b.data(), b.size());
  REQUIRE(a != b);

  std::string str(64, '\0');
  SecureRng::fill(str);
  REQUIRE_FALSE(allZero(reinterpret_cast<const std::uint8_t *>(str.data()), str.size()));

  std::vector<char> v(1 << 20, 0);
  SecureRng::fill(v);
  REQUIRE_FALSE(allZero(reinterpret_cast<const std::uint8_t *>(v.data()) + v.size() - 64, 64));
}

// Hidden (needs ~2 GiB): run with `iora_test_secure_rng "[.large]"`. Before the
// chunking fix, static_cast<int>(INT_MAX + 65) narrowed to a negative length
// and RAND_bytes failed; a length of 2^32 + k would have filled only k bytes.
TEST_CASE("SecureRng::fill above INT_MAX fills the tail", "[.large][secure_rng]")
{
  const std::size_t len = static_cast<std::size_t>(std::numeric_limits<int>::max()) + 65;
  std::vector<std::uint8_t> buf(len, 0);
  REQUIRE_NOTHROW(SecureRng::fill(buf.data(), buf.size()));
  REQUIRE_FALSE(allZero(buf.data() + len - 64, 64));
}

// Hidden (needs ~2 GiB): HMAC() takes the key length as int, so an oversized key
// must be rejected rather than narrowed.
TEST_CASE("SecureRng::hmacSha256 rejects a key longer than INT_MAX", "[.large][secure_rng]")
{
  const std::string key(static_cast<std::size_t>(std::numeric_limits<int>::max()) + 1, 'k');
  unsigned char out[32];
  REQUIRE_THROWS_AS(SecureRng::hmacSha256(key, "data", out), std::invalid_argument);
}

TEST_CASE("SecureRng::sha256 known-answer vectors", "[secure_rng]")
{
  unsigned char out[32];
  SecureRng::sha256("abc", out);
  REQUIRE(toHex(out) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  SecureRng::sha256("", out);
  REQUIRE(toHex(out) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  // Binary-safe: the embedded NUL is hashed, not treated as a terminator.
  SecureRng::sha256(std::string("a\0b", 3), out);
  REQUIRE(toHex(out) == "59b271ae1bbcb1d31d41929817f4b16fb439eb4f31520b5ad1d5ce98920a7138");
}

TEST_CASE("SecureRng::sha1 known-answer vectors", "[secure_rng]")
{
  unsigned char out[20];
  SecureRng::sha1("abc", out);
  REQUIRE(toHex(out) == "a9993e364706816aba3e25717850c26c9cd0d89d");
  // RFC 6455 section 1.3 Sec-WebSocket-Accept input.
  SecureRng::sha1("dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11", out);
  REQUIRE(toHex(out) == "b37a4f2cc0624f1690f64606cf385945b2bec4ea");
}

TEST_CASE("SecureRng::hmacSha256 RFC 4231 vectors", "[secure_rng]")
{
  unsigned char out[32];
  // RFC 4231 test case 2.
  SecureRng::hmacSha256("Jefe", "what do ya want for nothing?", out);
  REQUIRE(toHex(out) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  // RFC 4231 test case 1.
  SecureRng::hmacSha256(std::string(20, '\x0b'), "Hi There", out);
  REQUIRE(toHex(out) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

TEST_CASE("SecureRng::hmacSha256 rejects an empty key", "[secure_rng]")
{
  unsigned char out[32];
  REQUIRE_THROWS_AS(SecureRng::hmacSha256("", "data", out), std::invalid_argument);
}

TEST_CASE("SecureRng digest and HMAC reject a null output buffer", "[secure_rng]")
{
  REQUIRE_THROWS_AS(SecureRng::sha256("abc", nullptr), std::invalid_argument);
  REQUIRE_THROWS_AS(SecureRng::sha1("abc", nullptr), std::invalid_argument);
  // Without the guard HMAC() writes into OpenSSL's static buffer and succeeds.
  REQUIRE_THROWS_AS(SecureRng::hmacSha256("key", "data", nullptr), std::invalid_argument);
}

TEST_CASE("SecureRng leaves the caller's queued OpenSSL errors in place", "[secure_rng]")
{
  ERR_clear_error();
  ERR_raise(ERR_LIB_USER, 1); // an error the calling code has not read yet
  const unsigned long pending = ERR_peek_last_error();
  REQUIRE(pending != 0UL);

  std::array<std::uint8_t, 16> b{};
  SecureRng::fill(b);
  unsigned char out[32];
  SecureRng::sha256("abc", out);
  SecureRng::sha1("abc", out);
  SecureRng::hmacSha256("k", "d", out);

  REQUIRE(ERR_peek_last_error() == pending);
  ERR_clear_error();
}
