// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <iora/parsers/minimal_toml.hpp>
#include <iora/core/logger.hpp>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace iora
{
namespace core
{

/// \brief Typed view over a nested TOML sub-table.
///
/// A ConfigSubTable owns a std::shared_ptr<const parsers::toml::table>
/// extracted from the minimal_toml AST at the time ConfigLoader::getTable()
/// was called (the AST's variant alternative is non-const, but the
/// ConfigSubTable stores a const view to enforce read-only access through
/// this wrapper).
/// Because the underlying AST uses shared_ptr for every sub-table, a
/// ConfigSubTable remains valid even after the owning ConfigLoader is
/// reloaded or destroyed — the old sub-table memory co-owned by the
/// ConfigSubTable stays alive as long as the ConfigSubTable does.
///
/// Scalar getters return std::nullopt when the key is absent OR when the
/// stored value has a different TOML type than requested (type mismatch is
/// silent, mirroring ConfigLoader::get<T>).
///
/// This class is copyable and movable. Copies share the same underlying
/// sub-table via the shared_ptr; all copies see the same data.
///
/// Thread safety: ConfigSubTable inherits ConfigLoader's single-threaded
/// contract — do not read from a ConfigSubTable while another thread is
/// calling ConfigLoader::reload() on the owning loader.
class ConfigSubTable
{
public:
  /// \brief Default-constructs an empty ConfigSubTable. Every getter on a
  /// default-constructed instance returns std::nullopt. The default ctor
  /// exists to enable std::optional<ConfigSubTable> and container semantics;
  /// callers normally obtain instances via ConfigLoader::getTable (whose
  /// std::optional<> already signals presence). Prefer std::optional::has_value
  /// over valid() unless holding a stand-alone ConfigSubTable by value.
  ConfigSubTable() = default;
  explicit ConfigSubTable(std::shared_ptr<const parsers::toml::table> tbl)
      : _table(std::move(tbl))
  {
  }

  /// \brief True if this ConfigSubTable wraps a real sub-table; false after
  /// default construction or when the wrapped shared_ptr is null.
  bool valid() const { return static_cast<bool>(_table); }

  /// \brief Scalar getter — silent nullopt on missing key or type mismatch.
  template <typename T> std::optional<T> get(const std::string &dottedKey) const
  {
    if (!_table)
      return std::nullopt;
    auto n = _table->at_path(dottedKey);
    if (n && n.is_value())
    {
      if (auto v = n.as<T>())
        return v;
    }
    return std::nullopt;
  }

  std::optional<int64_t> getInt(const std::string &key) const { return get<int64_t>(key); }
  std::optional<bool> getBool(const std::string &key) const { return get<bool>(key); }
  std::optional<std::string> getString(const std::string &key) const
  {
    return get<std::string>(key);
  }

  /// \brief Array-of-strings getter. Returns nullopt on missing key, non-array
  /// values, OR when any element is not a string. This is deliberately the
  /// silent-nullopt contract shared with every other ConfigSubTable getter;
  /// it diverges from ConfigLoader::getStringArray which throws on non-string
  /// elements. Callers that want strict typing can inspect the raw AST via
  /// ConfigLoader::table() and check element types themselves.
  std::optional<std::vector<std::string>> getStringArray(const std::string &key) const
  {
    if (!_table)
      return std::nullopt;
    auto n = _table->at_path(key);
    if (!n || !n.is_array())
      return std::nullopt;
    std::vector<std::string> result;
    for (const auto &elem : *n.as_array())
    {
      if (auto *s = std::get_if<std::string>(&elem))
        result.push_back(*s);
      else
        return std::nullopt; // silent nullopt on non-string element (contract)
    }
    return result;
  }

  /// \brief Nested sub-table accessor. Returns nullopt when the key does not
  /// exist or does not name a sub-table (i.e., the key is a scalar or array).
  std::optional<ConfigSubTable> getTable(const std::string &dottedKey) const
  {
    if (!_table)
      return std::nullopt;
    auto n = _table->at_path(dottedKey);
    if (!n || !n.is_table())
      return std::nullopt;
    // n.is_table() guarantees the variant holds shared_ptr<table>.
    auto *p = std::get_if<std::shared_ptr<parsers::toml::table>>(&n.get_value());
    return ConfigSubTable{*p};
  }

private:
  std::shared_ptr<const parsers::toml::table> _table;
};

/// \brief Loads and parses TOML configuration files for the application.
///
/// Thread safety: ConfigLoader is SINGLE-THREADED BY CONTRACT. Callers MUST
/// NOT invoke reload() concurrently with ANY accessor (existing scalar
/// getters, new getTable, or any future accessor). Intended usage is:
/// construct once at startup, optionally call reload() serially, query via
/// getXxx/getTable during initialization, then leave untouched. This matches
/// the edge_proxy decision D-11 (no hot reload in v1 — restart to apply
/// configuration changes). ConfigSubTable instances obtained via getTable
/// remain valid across reload() because the AST uses shared_ptr for every
/// sub-table.
class ConfigLoader
{
public:
  /// \brief Constructs and loads a TOML configuration file.
  explicit ConfigLoader(const std::string &filename) : _filename(filename), _isLoaded(false) { load(); }

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
        // throw std::runtime_error("Failed to load configuration file: " + _filename);
        IORA_LOG_WARN("ConfigLoader: Failed to load configuration file: " << _filename);
        _isLoaded = false;
      }
      else
      {
        _isLoaded = true;
      }
    }
    return _table;
  }

  /// \brief Gets the full configuration table.
  const parsers::toml::table &table() const { return _table; }

  /// \brief Checks if the configuration was loaded successfully.
  bool isLoaded() const { return _isLoaded; }

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

  /// \brief Retrieves a nested TOML sub-table by dotted path.
  ///
  /// Returns std::nullopt when the key does not resolve to a sub-table
  /// (missing, scalar, or array). Otherwise returns a ConfigSubTable that
  /// owns a shared_ptr to the sub-table; see ConfigSubTable docs for the
  /// ownership / lifetime guarantee across reload().
  std::optional<ConfigSubTable> getTable(const std::string &dottedKey) const
  {
    auto n = _table.at_path(dottedKey);
    if (!n || !n.is_table())
      return std::nullopt;
    // n.is_table() guarantees the variant holds shared_ptr<table>.
    auto *p = std::get_if<std::shared_ptr<parsers::toml::table>>(&n.get_value());
    return ConfigSubTable{*p};
  }

  /// \brief Retrieves a TOML [[array-of-tables]] as a vector of sub-tables.
  ///
  /// Each element of the returned vector wraps one [[dottedKey]] entry, in
  /// declaration order. Returns std::nullopt when the key is absent OR when
  /// the key exists but is not an array-of-tables (scalar, named sub-table,
  /// or array of non-table elements) - this silent-nullopt-on-wrong-type
  /// contract mirrors getTable and allows callers to distinguish absent
  /// from wrong-type only by the presence of the optional.
  std::optional<std::vector<ConfigSubTable>>
  getTableArray(const std::string &dottedKey) const
  {
    auto n = _table.at_path(dottedKey);
    if (!n || !n.is_array())
      return std::nullopt;
    std::vector<ConfigSubTable> result;
    for (const auto &elem : *n.as_array())
    {
      auto *p = std::get_if<std::shared_ptr<parsers::toml::table>>(&elem);
      if (!p)
        return std::nullopt;
      result.push_back(ConfigSubTable{*p});
    }
    return result;
  }

private:
  std::string _filename;
  parsers::toml::table _table;
  bool _isLoaded;
};

} // namespace core
} // namespace iora
