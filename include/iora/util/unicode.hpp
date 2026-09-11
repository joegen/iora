// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include <cstdint>
#include <string>

namespace iora
{
namespace util
{

/// \brief Append a Unicode code point to out encoded as UTF-8.
///
/// Encodes cp as a 1- to 4-byte UTF-8 sequence. Rejects the UTF-16 surrogate
/// halves (U+D800..U+DFFF) and any value above U+10FFFF, returning false and
/// leaving out unchanged in those cases. This is the single shared encoder for
/// the iora parsers (JSON \uXXXX decoding, XML numeric character references).
inline bool appendUtf8(std::string &out, std::uint32_t cp)
{
  if ((cp >= 0xD800u && cp <= 0xDFFFu) || cp > 0x10FFFFu)
  {
    return false;
  }
  if (cp <= 0x7Fu)
  {
    out.push_back(static_cast<char>(cp));
  }
  else if (cp <= 0x7FFu)
  {
    out.push_back(static_cast<char>(0xC0u | ((cp >> 6) & 0x1Fu)));
    out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
  }
  else if (cp <= 0xFFFFu)
  {
    out.push_back(static_cast<char>(0xE0u | ((cp >> 12) & 0x0Fu)));
    out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
  }
  else
  {
    out.push_back(static_cast<char>(0xF0u | ((cp >> 18) & 0x07u)));
    out.push_back(static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
  }
  return true;
}

/// \brief Decode a single ASCII hex digit into its 0..15 value.
///
/// Returns false if c is not one of [0-9A-Fa-f], leaving out unchanged.
inline bool hexDigitValue(char c, std::uint32_t &out)
{
  if (c >= '0' && c <= '9')
  {
    out = static_cast<std::uint32_t>(c - '0');
  }
  else if (c >= 'a' && c <= 'f')
  {
    out = static_cast<std::uint32_t>(c - 'a' + 10);
  }
  else if (c >= 'A' && c <= 'F')
  {
    out = static_cast<std::uint32_t>(c - 'A' + 10);
  }
  else
  {
    return false;
  }
  return true;
}

} // namespace util
} // namespace iora
