// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

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
  static void fill(std::uint8_t *dst, std::size_t len)
  {
    if (len == 0)
    {
      return;
    }
    if (RAND_bytes(dst, static_cast<int>(len)) != 1)
    {
      auto error = lastError();
      std::string msg;
      msg.reserve(27 + error.size()); // "SecureRng: RAND_bytes failed: " = 27 chars
      msg += "SecureRng: RAND_bytes failed: ";
      msg += error;
      throw std::runtime_error(std::move(msg));
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
  static void sha256(const std::string &data, unsigned char out[32])
  {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
      throw std::runtime_error("SecureRng/sha256: EVP_MD_CTX_new failed");
    }
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    ok &= EVP_DigestUpdate(ctx, data.data(), data.size());
    unsigned int len = 0;
    ok &= EVP_DigestFinal_ex(ctx, out, &len);
    EVP_MD_CTX_free(ctx);
    if (!ok || len != 32U)
    {
      throw std::runtime_error("SecureRng/sha256: EVP_Digest (SHA-256) failed");
    }
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
  /// \throws std::invalid_argument if key is empty
  static void hmacSha256(const std::string &key, const std::string &data, unsigned char out[32])
  {
    if (key.empty())
    {
      throw std::invalid_argument("SecureRng/hmacSha256: key cannot be empty");
    }

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
      auto error = lastError();
      std::string msg;
      msg.reserve(32 + error.size());
      msg += "SecureRng/hmacSha256: HMAC failed: ";
      msg += error;
      throw std::runtime_error(std::move(msg));
    }
  }

private:
  /// \brief Get the last OpenSSL error as a string
  static std::string lastError()
  {
    unsigned long code = ERR_peek_last_error(); // NOLINT(google-runtime-int)
    if (code == 0UL)
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