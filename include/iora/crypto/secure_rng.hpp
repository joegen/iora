// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

namespace iora
{
namespace crypto
{

/// \brief Cryptographically Secure Pseudo-Random Number Generator using OpenSSL RAND_bytes().
///
/// This class provides secure random number generation suitable for cryptographic purposes,
/// including token generation, session IDs, and other security-sensitive applications.
class SecureRng
{
public:
  /// \brief Fill a buffer with cryptographically secure random bytes.
  /// \param dst Destination buffer
  /// \param len Number of bytes to generate
  /// \throws std::runtime_error if RAND_bytes fails
  /// \throws std::invalid_argument if dst is null and len > 0
  static void fill(std::uint8_t *dst, std::size_t len)
  {
    if (dst == nullptr && len > 0)
    {
      throw std::invalid_argument("SecureRng: dst cannot be null");
    }
    // RAND_bytes takes an int length; chunk so a len above INT_MAX is never
    // truncated by the narrowing cast into a silent partial fill.
    while (len > 0)
    {
      const std::size_t chunk = len < kMaxIntLen ? len : kMaxIntLen;
      ERR_set_mark();
      if (RAND_bytes(dst, static_cast<int>(chunk)) != 1)
      {
        throw std::runtime_error("SecureRng: RAND_bytes failed: " + popErrorsToMark());
      }
      ERR_pop_to_mark();
      dst += chunk;
      len -= chunk;
    }
  }

  /// \brief Fill a container with cryptographically secure random bytes.
  /// \tparam Container Container type with byte-sized elements
  /// \param c Container to fill (must have data() and size() methods)
  /// \throws std::runtime_error if RAND_bytes fails
  template <typename Container> static void fill(Container &c)
  {
    static_assert(sizeof(typename Container::value_type) == 1, "byte container required");
    fill(reinterpret_cast<std::uint8_t *>(c.data()), c.size());
  }

  /// \brief Compute SHA-256 hash of input data.
  /// \param data Input data to hash
  /// \param out Output buffer (must be at least 32 bytes)
  /// \throws std::runtime_error if hashing fails
  /// \throws std::invalid_argument if out is null
  static void sha256(const std::string &data, unsigned char out[32])
  {
    if (out == nullptr)
    {
      throw std::invalid_argument("SecureRng/sha256: out cannot be null");
    }
    ERR_set_mark();
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
      throw std::runtime_error("SecureRng/sha256: EVP_MD_CTX_new failed: " + popErrorsToMark());
    }
    unsigned int len = 0;
    // Short-circuit: never run Update/Final on a context whose Init failed.
    const bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                    EVP_DigestUpdate(ctx, data.data(), data.size()) == 1 &&
                    EVP_DigestFinal_ex(ctx, out, &len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok || len != 32U)
    {
      throw std::runtime_error("SecureRng/sha256: EVP_Digest (SHA-256) failed: " + popErrorsToMark());
    }
    ERR_pop_to_mark();
  }

  /// \brief Compute SHA-1 hash of input data (20 bytes output).
  /// Used for WebSocket handshake (RFC 6455 Sec-WebSocket-Accept).
  /// \param data Input data to hash
  /// \param out Output buffer (must be at least 20 bytes)
  /// \throws std::runtime_error if hashing fails
  /// \throws std::invalid_argument if out is null
  static void sha1(const std::string &data, unsigned char out[20])
  {
    if (out == nullptr)
    {
      throw std::invalid_argument("SecureRng/sha1: out cannot be null");
    }
    ERR_set_mark();
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
      throw std::runtime_error("SecureRng/sha1: EVP_MD_CTX_new failed: " + popErrorsToMark());
    }
    unsigned int len = 0;
    // Short-circuit: never run Update/Final on a context whose Init failed.
    const bool ok = EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) == 1 &&
                    EVP_DigestUpdate(ctx, data.data(), data.size()) == 1 &&
                    EVP_DigestFinal_ex(ctx, out, &len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok || len != 20U)
    {
      throw std::runtime_error("SecureRng/sha1: EVP_Digest (SHA-1) failed: " + popErrorsToMark());
    }
    ERR_pop_to_mark();
  }

  /// \brief Compute HMAC-SHA256 of input data with a secret key.
  ///
  /// This provides authenticated keyed hashing suitable for temporary GRUU
  /// generation and other security-sensitive applications where message
  /// authentication with a shared secret is required.
  ///
  /// \param key Secret key for HMAC
  /// \param data Input data to authenticate
  /// \param out Output buffer (must be at least 32 bytes)
  /// \throws std::runtime_error if HMAC computation fails
  /// \throws std::invalid_argument if out is null, or key is empty or longer than INT_MAX bytes
  static void hmacSha256(const std::string &key, const std::string &data, unsigned char out[32])
  {
    if (out == nullptr)
    {
      // HMAC() would otherwise write into OpenSSL's shared static buffer.
      throw std::invalid_argument("SecureRng/hmacSha256: out cannot be null");
    }
    if (key.empty())
    {
      throw std::invalid_argument("SecureRng/hmacSha256: key cannot be empty");
    }
    if (key.size() > kMaxIntLen)
    {
      throw std::invalid_argument("SecureRng/hmacSha256: key longer than INT_MAX");
    }

    ERR_set_mark();
    unsigned int len = 0;
    unsigned char *result = HMAC(
      EVP_sha256(),
      key.data(),
      static_cast<int>(key.size()),
      reinterpret_cast<const unsigned char *>(data.data()),
      data.size(),
      out,
      &len);

    if (result == nullptr || len != 32U)
    {
      throw std::runtime_error("SecureRng/hmacSha256: HMAC failed: " + popErrorsToMark());
    }
    ERR_pop_to_mark();
  }

private:
  /// Largest length OpenSSL's int-typed length parameters accept.
  static constexpr std::size_t kMaxIntLen = static_cast<std::size_t>(std::numeric_limits<int>::max());

  /// \brief Describe the newest OpenSSL error raised since the caller's
  /// ERR_set_mark(), then pop back to that mark: errors the calling thread had
  /// queued before the SecureRng call are left in place.
  static std::string popErrorsToMark()
  {
    const unsigned long code = ERR_peek_last_error(); // NOLINT(google-runtime-int)
    ERR_pop_to_mark();
    // Unchanged top of queue after the pop: nothing was raised since the mark.
    if (code == 0UL || code == ERR_peek_last_error())
    {
      return "no OpenSSL error available";
    }
    char buf[256] = {0};
    ERR_error_string_n(code, buf, sizeof(buf));
    return std::string(buf);
  }
};

} // namespace crypto
} // namespace iora