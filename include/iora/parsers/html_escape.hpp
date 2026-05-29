// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <string>
#include <string_view>
#include <unordered_map>

#include <iora/core/string_utils.hpp>

namespace iora
{
namespace parsers
{

inline std::string escapeHtml(std::string_view in)
{
  std::string out;
  out.reserve(in.size());
  for (char c : in)
  {
    switch (c)
    {
      case '&':
        out += "&amp;";
        break;
      case '<':
        out += "&lt;";
        break;
      case '>':
        out += "&gt;";
        break;
      case '"':
        out += "&quot;";
        break;
      case '\'':
        out += "&#39;";
        break;
      default:
        out += c;
        break;
    }
  }
  return out;
}

namespace detail
{

inline int hexNibble(unsigned char c)
{
  if (c >= '0' && c <= '9')
  {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f')
  {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F')
  {
    return c - 'A' + 10;
  }
  return -1;
}

inline std::string percentDecode(std::string_view in, bool plusIsSpace)
{
  std::string out;
  out.reserve(in.size());
  const std::size_t n = in.size();
  std::size_t i = 0;
  while (i < n)
  {
    const char c = in[i];
    if (c == '%')
    {
      if (i + 2 < n)
      {
        const int hi = hexNibble(static_cast<unsigned char>(in[i + 1]));
        const int lo = hexNibble(static_cast<unsigned char>(in[i + 2]));
        if (hi >= 0 && lo >= 0)
        {
          out += static_cast<char>((hi << 4) | lo);
          i += 3;
          continue;
        }
      }
      out += '%';
      i += 1;
      continue;
    }
    if (plusIsSpace && c == '+')
    {
      out += ' ';
      i += 1;
      continue;
    }
    out += c;
    i += 1;
  }
  return out;
}

}  // namespace detail

inline std::string urlDecode(std::string_view in)
{
  return detail::percentDecode(in, false);
}

inline std::string formDecode(std::string_view in)
{
  return detail::percentDecode(in, true);
}

inline std::unordered_map<std::string, std::string> parseFormBody(std::string_view body)
{
  std::unordered_map<std::string, std::string> result;
  for (std::string_view seg : iora::core::StringUtils::split(body, '&'))
  {
    if (seg.empty())
    {
      continue;
    }
    const auto eq = seg.find('=');
    if (eq == std::string_view::npos)
    {
      result[formDecode(seg)] = std::string();
    }
    else
    {
      std::string key = formDecode(seg.substr(0, eq));
      std::string value = formDecode(seg.substr(eq + 1));
      result[std::move(key)] = std::move(value);
    }
  }
  return result;
}

}  // namespace parsers
}  // namespace iora
