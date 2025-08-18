// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once
#include <unordered_map>
#include <string>
#include <mutex>
#include <vector>
#include <algorithm>
#include <functional>
#include <optional>
#include "iora/core/logger.hpp"

namespace iora
{
namespace storage
{

  /// \brief In-memory key-value store for string data with basic get/set
  /// operations.
  struct CaseInsensitiveHash
  {
    std::size_t operator()(const std::string& key) const
    {
      std::string lowered = key;
      std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                     ::tolower);
      return std::hash<std::string>{}(lowered);
    }
  };

  struct CaseInsensitiveEqual
  {
    bool operator()(const std::string& lhs, const std::string& rhs) const
    {
      return std::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end(),
                        [](char a, char b)
                        { return std::tolower(a) == std::tolower(b); });
    }
  };

  class ConcreteStateStore
  {
  public:
    /// \brief Sets a key-value pair in the store.
    void set(const std::string& key, const std::string& value)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      bool isUpdate = _store.find(key) != _store.end();
      _store[key] = value;
      iora::core::Logger::debug(
          std::string("ConcreteStateStore: ") +
          (isUpdate ? "Updated" : "Added") + " key '" + key +
          "' (total keys: " + std::to_string(_store.size()) + ")");
    }

    /// \brief Gets a value by key from the store.
    std::optional<std::string> get(const std::string& key) const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      auto it = _store.find(key);
      if (it != _store.end())
      {
        iora::core::Logger::debug(
            "ConcreteStateStore: Retrieved value for key '" + key +
            "' (length: " + std::to_string(it->second.length()) + " chars)");
        return it->second;
      }
      iora::core::Logger::debug("ConcreteStateStore: Key '" + key +
                                "' not found");
      return std::nullopt;
    }

    /// \brief Removes a key from the store.
    bool remove(const std::string& key)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      auto result = _store.erase(key) > 0;
      if (result)
      {
        iora::core::Logger::debug(
            "ConcreteStateStore: Removed key '" + key +
            "' (remaining keys: " + std::to_string(_store.size()) + ")");
      }
      else
      {
        iora::core::Logger::debug(
            "ConcreteStateStore: Attempted to remove non-existent key '" + key +
            "'");
      }
      return result;
    }

    /// \brief Checks if a key exists in the store.
    bool contains(const std::string& key) const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      return _store.find(key) != _store.end();
    }

    /// \brief Returns all keys in the store.
    std::vector<std::string> keys() const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      std::vector<std::string> result;
      result.reserve(_store.size());
      for (const auto& [k, _] : _store)
      {
        result.push_back(k);
      }
      return result;
    }

    /// \brief Returns the number of entries in the store.
    std::size_t size() const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      return _store.size();
    }

    /// \brief Returns true if the store is empty.
    bool empty() const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      return _store.empty();
    }

    /// \brief Finds all keys with the given prefix.
    std::vector<std::string> findKeysWithPrefix(const std::string& prefix) const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      std::vector<std::string> result;
      for (const auto& [key, _] : _store)
      {
        if (key.rfind(prefix, 0) == 0) // key starts with prefix
        {
          result.push_back(key);
        }
      }
      iora::core::Logger::debug("ConcreteStateStore: Found " +
                                std::to_string(result.size()) +
                                " keys with prefix '" + prefix + "'");
      return result;
    }

    /// \brief Finds all keys whose values match the provided value.
    std::vector<std::string> findKeysByValue(const std::string& value) const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      std::vector<std::string> result;
      for (const auto& [key, val] : _store)
      {
        if (val == value)
        {
          result.push_back(key);
        }
      }
      iora::core::Logger::debug("ConcreteStateStore: Found " +
                                std::to_string(result.size()) +
                                " keys with matching value (length: " +
                                std::to_string(value.length()) + " chars)");
      return result;
    }

    /// \brief Finds all keys satisfying a custom matcher.
    std::vector<std::string>
    findKeysMatching(std::function<bool(const std::string&)> matcher) const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      std::vector<std::string> result;
      for (const auto& [key, _] : _store)
      {
        try
        {
          if (matcher(key))
          {
            result.push_back(key);
          }
        }
        catch (const std::exception& e)
        {
          iora::core::Logger::error(
              "ConcreteStateStore: Matcher function threw exception for key '" +
              key + "': " + e.what());
        }
      }
      iora::core::Logger::debug("ConcreteStateStore: Found " +
                                std::to_string(result.size()) +
                                " keys matching custom criteria");
      return result;
    }

  private:
    mutable std::mutex _mutex;
    std::unordered_map<std::string, std::string, CaseInsensitiveHash,
                       CaseInsensitiveEqual>
        _store;
  };

} // namespace storage
} // namespace iora