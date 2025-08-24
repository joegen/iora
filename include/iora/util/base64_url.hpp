// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <cstdint>
#include <string>
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
    static std::string encode(const std::uint8_t* data, std::size_t len)
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
    static std::string encode(const std::vector<std::uint8_t>& bytes)
    {
      return encode(bytes.data(), bytes.size());
    }
  };

} // namespace util
} // namespace iora