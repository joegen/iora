// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <algorithm>
#include <cctype>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace iora {
namespace core {

/// \brief Whitespace characters used by trim functions.
inline constexpr std::string_view kWhitespace = " \t\r\n";

/// \brief String utility functions for protocol parsing.
///
/// All functions are static. Zero-copy where possible (split/trim return
/// string_view). The source string must outlive returned views.
struct StringUtils
{
  /// \brief Split a string_view on a single character delimiter.
  /// Empty input returns empty vector.
  /// Consecutive delimiters produce empty string_view elements.
  /// split(",", ',') returns {"", ""}.
  static std::vector<std::string_view> split(std::string_view input, char delimiter)
  {
    std::vector<std::string_view> result;
    if (input.empty())
    {
      return result;
    }
    std::size_t start = 0;
    while (true)
    {
      auto pos = input.find(delimiter, start);
      if (pos == std::string_view::npos)
      {
        result.push_back(input.substr(start));
        break;
      }
      result.push_back(input.substr(start, pos - start));
      start = pos + 1;
    }
    return result;
  }

  /// \brief Split a string_view on a string_view delimiter.
  /// Empty delimiter returns {input} as a single element.
  /// Empty input returns empty vector.
  /// Consecutive delimiters produce empty string_view elements.
  static std::vector<std::string_view> split(std::string_view input,
                                             std::string_view delimiter)
  {
    std::vector<std::string_view> result;
    if (input.empty())
    {
      return result;
    }
    if (delimiter.empty())
    {
      result.push_back(input);
      return result;
    }
    std::size_t start = 0;
    while (true)
    {
      auto pos = input.find(delimiter, start);
      if (pos == std::string_view::npos)
      {
        result.push_back(input.substr(start));
        break;
      }
      result.push_back(input.substr(start, pos - start));
      start = pos + delimiter.size();
    }
    return result;
  }

  /// \brief Strip leading and trailing whitespace.
  static std::string_view trim(std::string_view input) noexcept
  {
    auto start = input.find_first_not_of(kWhitespace);
    if (start == std::string_view::npos)
    {
      return {};
    }
    auto end = input.find_last_not_of(kWhitespace);
    return input.substr(start, end - start + 1);
  }

  /// \brief Strip leading whitespace.
  static std::string_view trimLeft(std::string_view input) noexcept
  {
    auto start = input.find_first_not_of(kWhitespace);
    if (start == std::string_view::npos)
    {
      return {};
    }
    return input.substr(start);
  }

  /// \brief Strip trailing whitespace.
  static std::string_view trimRight(std::string_view input) noexcept
  {
    auto end = input.find_last_not_of(kWhitespace);
    if (end == std::string_view::npos)
    {
      return {};
    }
    return input.substr(0, end + 1);
  }

  /// \brief Case-insensitive string comparison (ASCII only, locale-independent).
  /// Bytes >= 0x80 are compared verbatim, so the result is identical across
  /// processes/locales — safe for cross-site / cross-process agreement (e.g. a
  /// codec-name or User-Agent match that must be byte-identical between peers).
  static bool iequals(std::string_view a, std::string_view b) noexcept
  {
    if (a.size() != b.size())
    {
      return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i)
    {
      if (toLowerChar(a[i]) != toLowerChar(b[i]))
      {
        return false;
      }
    }
    return true;
  }

  /// \brief Convert string to lowercase (ASCII only, locale-independent).
  /// Bytes >= 0x80 pass through unchanged. Returns new string.
  static std::string toLower(std::string_view input)
  {
    std::string result;
    result.reserve(input.size());
    for (char c : input)
    {
      result += toLowerChar(c);
    }
    return result;
  }

  /// \brief Convert string to uppercase (ASCII only, locale-independent).
  /// Bytes >= 0x80 pass through unchanged. Returns new string.
  static std::string toUpper(std::string_view input)
  {
    std::string result;
    result.reserve(input.size());
    for (char c : input)
    {
      result += toUpperChar(c);
    }
    return result;
  }

  /// \brief Case-insensitive hash for use as unordered_map hash trait.
  /// Non-allocating: folds tolower into the hash loop.
  /// Supports heterogeneous lookup via is_transparent.
  struct CaseInsensitiveHash
  {
    using is_transparent = void;

    std::size_t operator()(std::string_view key) const noexcept
    {
      std::size_t h = 0;
      for (char c : key)
      {
        h = h * 31 + static_cast<std::size_t>(
          static_cast<unsigned char>(toLowerChar(c)));
      }
      return h;
    }
  };

  /// \brief Case-insensitive equality for use as unordered_map key_equal trait.
  /// Supports heterogeneous lookup via is_transparent.
  struct CaseInsensitiveEqual
  {
    using is_transparent = void;

    bool operator()(std::string_view a, std::string_view b) const noexcept
    {
      return iequals(a, b);
    }
  };

private:
  /// \brief Locale-independent ASCII lowercase. Bytes outside A-Z (incl. all
  /// bytes >= 0x80) pass through unchanged — deliberately NOT std::tolower,
  /// which is locale-dependent for bytes >= 0x80 and would make the "ASCII only"
  /// contract non-deterministic across processes/locales.
  static char toLowerChar(char c) noexcept
  {
    const auto u = static_cast<unsigned char>(c);
    return (u >= 'A' && u <= 'Z') ? static_cast<char>(u + 0x20) : c;
  }

  /// \brief Locale-independent ASCII uppercase (companion to toLowerChar).
  static char toUpperChar(char c) noexcept
  {
    const auto u = static_cast<unsigned char>(c);
    return (u >= 'a' && u <= 'z') ? static_cast<char>(u - 0x20) : c;
  }
};

} // namespace core
} // namespace iora
