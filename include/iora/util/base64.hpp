// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace iora
{
namespace util
{

/// \brief Base64URL encoder (RFC 4648) without padding.
///
/// Base64URL encoding uses URL-safe characters and omits padding,
/// making it suitable for use in URLs, filenames, and SIP tokens.
/// Uses '-' and '_' instead of '+' and '/'.
class Base64Url
{
public:
  /// \brief Encode binary data to Base64URL string (no padding).
  /// \param data Pointer to binary data
  /// \param len Number of bytes to encode
  /// \return Base64URL encoded string
  static std::string encode(const std::uint8_t *data, std::size_t len)
  {
    static constexpr char kTable[65] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    if (len == 0)
    {
      return {};
    }

    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    std::size_t i = 0;
    while (i + 3 <= len)
    {
      std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 16) |
                        (static_cast<std::uint32_t>(data[i + 1]) << 8) |
                        (static_cast<std::uint32_t>(data[i + 2]));
      out.push_back(kTable[(v >> 18) & 0x3F]);
      out.push_back(kTable[(v >> 12) & 0x3F]);
      out.push_back(kTable[(v >> 6) & 0x3F]);
      out.push_back(kTable[v & 0x3F]);
      i += 3;
    }

    // Handle remaining bytes (1 or 2)
    std::size_t rem = len - i;
    if (rem == 1)
    {
      std::uint32_t v = static_cast<std::uint32_t>(data[i]) << 16;
      out.push_back(kTable[(v >> 18) & 0x3F]);
      out.push_back(kTable[(v >> 12) & 0x3F]);
      // No padding in Base64URL
    }
    else if (rem == 2)
    {
      std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 16) |
                        (static_cast<std::uint32_t>(data[i + 1]) << 8);
      out.push_back(kTable[(v >> 18) & 0x3F]);
      out.push_back(kTable[(v >> 12) & 0x3F]);
      out.push_back(kTable[(v >> 6) & 0x3F]);
      // No padding in Base64URL
    }
    return out;
  }

  /// \brief Encode a vector of bytes to Base64URL string.
  /// \param bytes Vector containing binary data
  /// \return Base64URL encoded string
  static std::string encode(const std::vector<std::uint8_t> &bytes)
  {
    return encode(bytes.data(), bytes.size());
  }
};

/// \brief Standard Base64 encoder/decoder (RFC 4648) with padding.
///
/// Uses '+' and '/' with '=' padding. Required for WebSocket handshake
/// (Sec-WebSocket-Accept computation) and HTTP Basic auth credential decoding.
/// Encode and decode share a single alphabet definition (kStdAlphabet); the
/// decoder's reverse-lookup table is built as its inverse so the two can never
/// disagree.
class Base64
{
private:
  /// Single shared standard Base64 alphabet (RFC 4648). encode() indexes it
  /// directly; the decoder reverse table is its inverse.
  static constexpr char kStdAlphabet[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  /// Build the 256-entry reverse-lookup table as the inverse of kStdAlphabet:
  /// each alphabet byte maps to its 6-bit value, every other byte to -1.
  static constexpr std::array<std::int8_t, 256> makeRevTable()
  {
    std::array<std::int8_t, 256> t{};
    for (std::size_t i = 0; i < t.size(); ++i)
    {
      t[i] = -1;
    }
    for (std::int8_t i = 0; i < 64; ++i)
    {
      t[static_cast<std::uint8_t>(kStdAlphabet[i])] = i;
    }
    return t;
  }

public:
  /// \brief Encode binary data to standard Base64 string with padding.
  static std::string encode(const std::uint8_t *data, std::size_t len)
  {
    if (len == 0)
    {
      return {};
    }

    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    std::size_t i = 0;
    while (i + 3 <= len)
    {
      std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 16) |
                        (static_cast<std::uint32_t>(data[i + 1]) << 8) |
                        (static_cast<std::uint32_t>(data[i + 2]));
      out.push_back(kStdAlphabet[(v >> 18) & 0x3F]);
      out.push_back(kStdAlphabet[(v >> 12) & 0x3F]);
      out.push_back(kStdAlphabet[(v >> 6) & 0x3F]);
      out.push_back(kStdAlphabet[v & 0x3F]);
      i += 3;
    }

    std::size_t rem = len - i;
    if (rem == 1)
    {
      std::uint32_t v = static_cast<std::uint32_t>(data[i]) << 16;
      out.push_back(kStdAlphabet[(v >> 18) & 0x3F]);
      out.push_back(kStdAlphabet[(v >> 12) & 0x3F]);
      out.push_back('=');
      out.push_back('=');
    }
    else if (rem == 2)
    {
      std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 16) |
                        (static_cast<std::uint32_t>(data[i + 1]) << 8);
      out.push_back(kStdAlphabet[(v >> 18) & 0x3F]);
      out.push_back(kStdAlphabet[(v >> 12) & 0x3F]);
      out.push_back(kStdAlphabet[(v >> 6) & 0x3F]);
      out.push_back('=');
    }
    return out;
  }

  /// \brief Encode a vector of bytes to standard Base64 string.
  static std::string encode(const std::vector<std::uint8_t> &bytes)
  {
    return encode(bytes.data(), bytes.size());
  }

  /// \brief Decode a standard Base64 string (RFC 4648) to bytes.
  ///
  /// Binary-safe and strict: returns std::nullopt for any malformed input and a
  /// present (possibly-empty) vector for successfully decoded bytes. Rejects
  /// (never best-efforts) — any byte outside the standard alphabet (A-Z a-z 0-9
  /// '+' '/') and the '=' pad, including embedded whitespace, causes rejection.
  /// The caller (not this function) is responsible for trimming any surrounding
  /// whitespace before calling. Decoding rules:
  ///   - Empty input decodes to a present empty vector.
  ///   - Input length must be a multiple of 4 (else nullopt).
  ///   - '=' padding is valid only in the final quantum, as the last char
  ///     ('X=' -> 2 output bytes) or last two chars ('XX==' -> 1 output byte).
  ///   - Strict pad-bit rejection: the bits the padding discards MUST be zero
  ///     ('==' final quantum: low 4 bits of the 2nd sextet; '=' final quantum:
  ///     low 2 bits of the 3rd sextet), else nullopt — canonical-encoding
  ///     enforcement removes a malleability vector on auth paths.
  ///
  /// Does not throw on malformed input (returns nullopt); only std::bad_alloc
  /// may propagate from the output vector. Not constexpr (it allocates). The
  /// input view is not retained beyond the call — the caller must ensure its
  /// backing storage outlives this call (e.g. bind a by-value std::string getter
  /// result to a named variable before deriving a std::string_view).
  static std::optional<std::vector<std::uint8_t>> decode(std::string_view input)
  {
    const std::size_t n = input.size();
    if (n == 0)
    {
      return std::vector<std::uint8_t>{};
    }
    if (n % 4 != 0)
    {
      return std::nullopt;
    }

    // Built once at compile time as the inverse of kStdAlphabet; -1 marks any
    // non-alphabet byte.
    static constexpr std::array<std::int8_t, 256> kRevTable = makeRevTable();

    std::vector<std::uint8_t> out;
    out.reserve((n / 4) * 3);

    for (std::size_t i = 0; i < n; i += 4)
    {
      const bool lastQuantum = (i + 4 == n);
      const char c0 = input[i];
      const char c1 = input[i + 1];
      const char c2 = input[i + 2];
      const char c3 = input[i + 3];

      // The first two characters of every quantum must be alphabet bytes —
      // never '=' (rejecting '=abc', 'a=bc', 'A===', '====', etc.) and never
      // any non-alphabet byte (including embedded whitespace).
      const std::int8_t v0 = kRevTable[static_cast<std::uint8_t>(c0)];
      const std::int8_t v1 = kRevTable[static_cast<std::uint8_t>(c1)];
      if (v0 < 0 || v1 < 0)
      {
        return std::nullopt;
      }

      if (c2 == '=')
      {
        // '==' final quantum: 1 output byte. Padding only in the final quantum
        // and c3 must also be '='.
        if (!lastQuantum || c3 != '=')
        {
          return std::nullopt;
        }
        // Strict pad-bit: low 4 bits of the 2nd sextet must be zero.
        if ((v1 & 0x0F) != 0)
        {
          return std::nullopt;
        }
        out.push_back(static_cast<std::uint8_t>((v0 << 2) | (v1 >> 4)));
      }
      else
      {
        const std::int8_t v2 = kRevTable[static_cast<std::uint8_t>(c2)];
        if (v2 < 0)
        {
          return std::nullopt;
        }
        if (c3 == '=')
        {
          // '=' final quantum: 2 output bytes. Padding only in the final
          // quantum.
          if (!lastQuantum)
          {
            return std::nullopt;
          }
          // Strict pad-bit: low 2 bits of the 3rd sextet must be zero.
          if ((v2 & 0x03) != 0)
          {
            return std::nullopt;
          }
          out.push_back(static_cast<std::uint8_t>((v0 << 2) | (v1 >> 4)));
          out.push_back(
            static_cast<std::uint8_t>(((v1 & 0x0F) << 4) | (v2 >> 2)));
        }
        else
        {
          const std::int8_t v3 = kRevTable[static_cast<std::uint8_t>(c3)];
          if (v3 < 0)
          {
            return std::nullopt;
          }
          out.push_back(static_cast<std::uint8_t>((v0 << 2) | (v1 >> 4)));
          out.push_back(
            static_cast<std::uint8_t>(((v1 & 0x0F) << 4) | (v2 >> 2)));
          out.push_back(static_cast<std::uint8_t>(((v2 & 0x03) << 6) | v3));
        }
      }
    }
    return out;
  }

  /// \brief Decode a standard Base64 string, reinterpreting the bytes as text.
  ///
  /// Convenience over decode() for the common text case (e.g. HTTP Basic
  /// 'user:pass'). Returns nullopt iff decode() returns nullopt; otherwise the
  /// decoded bytes as a std::string. Binary-safe: an embedded NUL is preserved
  /// (the string is constructed from the byte range, not as a C string).
  /// \note Not intended for secret material: it makes an additional copy of the
  /// decoded bytes that is not scrubbed. For credentials, prefer decode() and
  /// wipe the result after use.
  static std::optional<std::string> decodeToString(std::string_view input)
  {
    auto bytes = decode(input);
    if (!bytes)
    {
      return std::nullopt;
    }
    return std::string(bytes->begin(), bytes->end());
  }
};

} // namespace util
} // namespace iora