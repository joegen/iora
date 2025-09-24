// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <iora/parsers/minimal_toml.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace iora
{
namespace core
{
/// \brief Loads and parses TOML configuration files for the application.
class ConfigLoader
{
public:
  /// \brief Constructs and loads a TOML configuration file.
  explicit ConfigLoader(const std::string &filename) : _filename(filename) { load(); }

  /// \brief Reloads the configuration from disk.
  bool reload()
  {
    try
    {
      _table = parsers::toml::parse_file(_filename);
      return true;
    }
    catch (...)
    {
      _table = parsers::toml::table{};
      return false;
    }
  }

  const parsers::toml::table &load()
  {
    if (_table.empty())
    {
      if (!reload())
      {
        throw std::runtime_error("Failed to load configuration file: " + _filename);
      }
    }
    return _table;
  }

  /// \brief Gets the full configuration table.
  const parsers::toml::table &table() const { return _table; }

  /// \brief Gets a typed value from the configuration.
  /// \tparam T Must be a TOML native type (int64_t, double, bool,
  /// std::string, etc.)
  template <typename T> std::optional<T> get(const std::string &dottedKey) const
  {
    auto node = _table.at_path(dottedKey);
    if (node && node.is_value())
    {
      if (auto val = node.as<T>())
      {
        return val;
      }
    }
    return std::nullopt;
  }

  /// \brief Gets an int value from the configuration.
  std::optional<int64_t> getInt(const std::string &key) const { return get<int64_t>(key); }

  /// \brief Gets a bool value from the configuration.
  std::optional<bool> getBool(const std::string &key) const { return get<bool>(key); }

  /// \brief Gets a string value from the configuration.
  std::optional<std::string> getString(const std::string &key) const
  {
    return get<std::string>(key);
  }

  /// \brief Gets an array of strings from the configuration.
  /// \param key Dotted key path to the array in the TOML config.
  /// \return std::optional<std::vector<std::string>> containing all string
  /// elements, or std::nullopt if not found. \throws std::runtime_error if
  /// the key is an array but any element is not a string.
  std::optional<std::vector<std::string>> getStringArray(const std::string &key) const
  {
    auto node = _table.at_path(key);
    if (!node)
    {
      return std::nullopt;
    }
    if (!node.is_array())
    {
      return std::nullopt;
    }
    std::vector<std::string> result;
    for (const auto &elem : *node.as_array())
    {
      if (auto *strVal = std::get_if<std::string>(&elem))
      {
        result.push_back(*strVal);
      }
      else
      {
        throw std::runtime_error("ConfigLoader: Array element at '" + key + "' is not a string");
      }
    }
    return result;
  }

private:
  std::string _filename;
  parsers::toml::table _table;
};

} // namespace core
} // namespace iora
