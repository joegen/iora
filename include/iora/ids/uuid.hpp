// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <chrono>

#include "iora/crypto/secure_rng.hpp"

namespace iora
{
namespace ids
{

  /// \brief UUID generator supporting v4 (random) and v7 (time-ordered) variants.
  /// 
  /// Generates RFC 4122 compliant UUIDs:
  /// - v4: Fully random UUIDs for general use
  /// - v7: Time-ordered UUIDs for sortable identifiers (draft RFC)
  class Uuid
  {
  public:
    /// \brief Generate a version 4 (random) UUID.
    /// \return String representation of UUID (e.g., "550e8400-e29b-41d4-a716-446655440000")
    static std::string v4()
    {
      std::array<std::uint8_t, 16> b{};
      iora::crypto::SecureRng::fill(b);
      
      // Set version 4 (random)
      b[6] = static_cast<std::uint8_t>((b[6] & 0x0F) | 0x40);
      
      // Set variant bits (10xx)
      b[8] = static_cast<std::uint8_t>((b[8] & 0x3F) | 0x80);
      
      return toHexString(b);
    }

    /// \brief Generate a version 7 (time-ordered) UUID.
    /// \return String representation of time-ordered UUID
    /// 
    /// Version 7 UUIDs contain a timestamp in the most significant bits,
    /// making them naturally sortable by creation time while maintaining
    /// sufficient randomness for uniqueness.
    static std::string v7()
    {
      std::array<std::uint8_t, 16> b{};
      
      // Get current timestamp in milliseconds since Unix epoch
      const auto now = std::chrono::time_point_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now());
      std::uint64_t ms = static_cast<std::uint64_t>(now.time_since_epoch().count());

      // Pack timestamp into first 48 bits (6 bytes)
      b[0] = static_cast<std::uint8_t>((ms >> 40) & 0xFF);
      b[1] = static_cast<std::uint8_t>((ms >> 32) & 0xFF);
      b[2] = static_cast<std::uint8_t>((ms >> 24) & 0xFF);
      b[3] = static_cast<std::uint8_t>((ms >> 16) & 0xFF);
      b[4] = static_cast<std::uint8_t>((ms >> 8) & 0xFF);
      b[5] = static_cast<std::uint8_t>(ms & 0xFF);

      // Fill remaining 10 bytes with random data directly
      iora::crypto::SecureRng::fill(b.data() + 6, 10);

      // Set version 7 (time-ordered)
      b[6] = static_cast<std::uint8_t>((b[6] & 0x0F) | 0x70);
      
      // Set variant bits (10xx)
      b[8] = static_cast<std::uint8_t>((b[8] & 0x3F) | 0x80);
      
      return toHexString(b);
    }

  private:
    /// \brief Convert 16-byte array to standard UUID string format.
    /// \param b 16-byte UUID data
    /// \return Formatted UUID string with hyphens
    static std::string toHexString(const std::array<std::uint8_t, 16>& b)
    {
      // Pre-computed lookup table for byte-to-hex conversion (2 chars per byte)
      static constexpr char kHexPairs[256][2] = {
        {'0','0'}, {'0','1'}, {'0','2'}, {'0','3'}, {'0','4'}, {'0','5'}, {'0','6'}, {'0','7'},
        {'0','8'}, {'0','9'}, {'0','a'}, {'0','b'}, {'0','c'}, {'0','d'}, {'0','e'}, {'0','f'},
        {'1','0'}, {'1','1'}, {'1','2'}, {'1','3'}, {'1','4'}, {'1','5'}, {'1','6'}, {'1','7'},
        {'1','8'}, {'1','9'}, {'1','a'}, {'1','b'}, {'1','c'}, {'1','d'}, {'1','e'}, {'1','f'},
        {'2','0'}, {'2','1'}, {'2','2'}, {'2','3'}, {'2','4'}, {'2','5'}, {'2','6'}, {'2','7'},
        {'2','8'}, {'2','9'}, {'2','a'}, {'2','b'}, {'2','c'}, {'2','d'}, {'2','e'}, {'2','f'},
        {'3','0'}, {'3','1'}, {'3','2'}, {'3','3'}, {'3','4'}, {'3','5'}, {'3','6'}, {'3','7'},
        {'3','8'}, {'3','9'}, {'3','a'}, {'3','b'}, {'3','c'}, {'3','d'}, {'3','e'}, {'3','f'},
        {'4','0'}, {'4','1'}, {'4','2'}, {'4','3'}, {'4','4'}, {'4','5'}, {'4','6'}, {'4','7'},
        {'4','8'}, {'4','9'}, {'4','a'}, {'4','b'}, {'4','c'}, {'4','d'}, {'4','e'}, {'4','f'},
        {'5','0'}, {'5','1'}, {'5','2'}, {'5','3'}, {'5','4'}, {'5','5'}, {'5','6'}, {'5','7'},
        {'5','8'}, {'5','9'}, {'5','a'}, {'5','b'}, {'5','c'}, {'5','d'}, {'5','e'}, {'5','f'},
        {'6','0'}, {'6','1'}, {'6','2'}, {'6','3'}, {'6','4'}, {'6','5'}, {'6','6'}, {'6','7'},
        {'6','8'}, {'6','9'}, {'6','a'}, {'6','b'}, {'6','c'}, {'6','d'}, {'6','e'}, {'6','f'},
        {'7','0'}, {'7','1'}, {'7','2'}, {'7','3'}, {'7','4'}, {'7','5'}, {'7','6'}, {'7','7'},
        {'7','8'}, {'7','9'}, {'7','a'}, {'7','b'}, {'7','c'}, {'7','d'}, {'7','e'}, {'7','f'},
        {'8','0'}, {'8','1'}, {'8','2'}, {'8','3'}, {'8','4'}, {'8','5'}, {'8','6'}, {'8','7'},
        {'8','8'}, {'8','9'}, {'8','a'}, {'8','b'}, {'8','c'}, {'8','d'}, {'8','e'}, {'8','f'},
        {'9','0'}, {'9','1'}, {'9','2'}, {'9','3'}, {'9','4'}, {'9','5'}, {'9','6'}, {'9','7'},
        {'9','8'}, {'9','9'}, {'9','a'}, {'9','b'}, {'9','c'}, {'9','d'}, {'9','e'}, {'9','f'},
        {'a','0'}, {'a','1'}, {'a','2'}, {'a','3'}, {'a','4'}, {'a','5'}, {'a','6'}, {'a','7'},
        {'a','8'}, {'a','9'}, {'a','a'}, {'a','b'}, {'a','c'}, {'a','d'}, {'a','e'}, {'a','f'},
        {'b','0'}, {'b','1'}, {'b','2'}, {'b','3'}, {'b','4'}, {'b','5'}, {'b','6'}, {'b','7'},
        {'b','8'}, {'b','9'}, {'b','a'}, {'b','b'}, {'b','c'}, {'b','d'}, {'b','e'}, {'b','f'},
        {'c','0'}, {'c','1'}, {'c','2'}, {'c','3'}, {'c','4'}, {'c','5'}, {'c','6'}, {'c','7'},
        {'c','8'}, {'c','9'}, {'c','a'}, {'c','b'}, {'c','c'}, {'c','d'}, {'c','e'}, {'c','f'},
        {'d','0'}, {'d','1'}, {'d','2'}, {'d','3'}, {'d','4'}, {'d','5'}, {'d','6'}, {'d','7'},
        {'d','8'}, {'d','9'}, {'d','a'}, {'d','b'}, {'d','c'}, {'d','d'}, {'d','e'}, {'d','f'},
        {'e','0'}, {'e','1'}, {'e','2'}, {'e','3'}, {'e','4'}, {'e','5'}, {'e','6'}, {'e','7'},
        {'e','8'}, {'e','9'}, {'e','a'}, {'e','b'}, {'e','c'}, {'e','d'}, {'e','e'}, {'e','f'},
        {'f','0'}, {'f','1'}, {'f','2'}, {'f','3'}, {'f','4'}, {'f','5'}, {'f','6'}, {'f','7'},
        {'f','8'}, {'f','9'}, {'f','a'}, {'f','b'}, {'f','c'}, {'f','d'}, {'f','e'}, {'f','f'}
      };
      
      std::string s;
      s.resize(36); // 32 hex chars + 4 hyphens
      
      int p = 0;
      for (int i = 0; i < 16; ++i)
      {
        // Insert hyphens at standard positions
        if (i == 4 || i == 6 || i == 8 || i == 10)
        {
          s[p++] = '-';
        }
        const auto& hex = kHexPairs[b[i]];
        s[p++] = hex[0];
        s[p++] = hex[1];
      }
      return s;
    }
  };

} // namespace ids
} // namespace iora