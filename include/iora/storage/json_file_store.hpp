// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once
#include <fstream>
#include <mutex>
#include <set>
#include <thread>
#include <condition_variable>
#include "iora/parsers/json.hpp"
#include "iora/core/logger.hpp"

namespace iora
{
namespace storage
{

  /// \brief Thread-safe key-value store backed by a JSON file with background
  /// flushing and persistence.
  class JsonFileStore
  {
  public:
    /// \brief Construct and load JSON file if it exists
    explicit JsonFileStore(std::string filename)
      : _filename(std::move(filename)), _dirty(false)
    {
      iora::core::Logger::info("JsonFileStore: Initializing with file: " +
                               _filename);
      std::ifstream file(_filename);
      if (file)
      {
        try
        {
          file >> _store;
          iora::core::Logger::info("JsonFileStore: Loaded existing data with " +
                                   std::to_string(_store.size()) +
                                   " keys from: " + _filename);
        }
        catch (const std::exception& e)
        {
          iora::core::Logger::error(
              "JsonFileStore: Failed to parse JSON from " + _filename + ": " +
              e.what() + " - starting with empty store");
          _store = parsers::Json::object();
        }
      }
      else
      {
        iora::core::Logger::info("JsonFileStore: File " + _filename +
                                 " does not exist, starting with empty store");
        _store = parsers::Json::object();
      }

      registerStore();
    }

    /// \brief Destructor unregisters the store
    ~JsonFileStore()
    {
      iora::core::Logger::debug("JsonFileStore: Destructor called for " +
                                _filename);
      unregisterStore();
      flush();
      iora::core::Logger::debug("JsonFileStore: Cleanup completed for " +
                                _filename);
    }

    /// \brief Set a key to a value and mark store dirty
    template <typename T> void set(const std::string& key, const T& value)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      bool isUpdate = _store.contains(key);
      _store[key] = value;
      _dirty = true;
      iora::core::Logger::debug(
          std::string("JsonFileStore: ") + (isUpdate ? "Updated" : "Added") +
          " key '" + key + "' in " + _filename +
          " (total keys: " + std::to_string(_store.size()) + ")");
    }

    /// \brief Specialization for std::string
    void set(const std::string& key, const std::string& value)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      bool isUpdate = _store.contains(key);
      _store[key] = value;
      _dirty = true;
      iora::core::Logger::debug(
          std::string("JsonFileStore: ") + (isUpdate ? "Updated" : "Added") +
          " string key '" + key + "' in " + _filename +
          " (value length: " + std::to_string(value.length()) +
          " chars, total keys: " + std::to_string(_store.size()) + ")");
    }

    /// \brief Get a value from the store
    template <typename T> std::optional<T> get(const std::string& key) const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (_store.contains(key))
      {
        try
        {
          auto val = _store[key].get<T>();
          iora::core::Logger::debug("JsonFileStore: Retrieved value for key '" +
                                    key + "' from " + _filename);
          return val;
        }
        catch (const std::exception& e)
        {
          iora::core::Logger::error(
              "JsonFileStore: Type conversion failed for key '" + key +
              "' in " + _filename + ": " + e.what());
          return std::nullopt;
        }
      }
      iora::core::Logger::debug("JsonFileStore: Key '" + key +
                                "' not found in " + _filename);
      return std::nullopt;
    }

    /// \brief Specialization for std::string
    std::optional<std::string> get(const std::string& key) const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (_store.contains(key))
      {
        try
        {
          auto val = _store[key].get<std::string>();
          iora::core::Logger::debug(
              "JsonFileStore: Retrieved string value for key '" + key +
              "' from " + _filename +
              " (length: " + std::to_string(val.length()) + " chars)");
          return val;
        }
        catch (const std::exception& e)
        {
          iora::core::Logger::error(
              "JsonFileStore: String conversion failed for key '" + key +
              "' in " + _filename + ": " + e.what());
          return std::nullopt;
        }
      }
      iora::core::Logger::debug("JsonFileStore: String key '" + key +
                                "' not found in " + _filename);
      return std::nullopt;
    }

    /// \brief Remove a key from the store and mark dirty
    void remove(const std::string& key)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      auto it = _store.find(key);
      if (it != _store.endObject())
      {
        _store.erase(it);
        _dirty = true;
        iora::core::Logger::debug(
            "JsonFileStore: Removed key '" + key + "' from " + _filename +
            " (remaining keys: " + std::to_string(_store.size()) + ")");
      }
      else
      {
        iora::core::Logger::debug(
            "JsonFileStore: Attempted to remove non-existent key '" + key +
            "' from " + _filename);
      }
    }

    /// \brief Immediately write the store to disk
    void flush()
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (_dirty)
      {
        iora::core::Logger::debug("JsonFileStore: Flushing " +
                                  std::to_string(_store.size()) + " keys to " +
                                  _filename);
        saveToFile();
        _dirty = false;
        iora::core::Logger::debug("JsonFileStore: Flush completed for " +
                                  _filename);
      }
      else
      {
        iora::core::Logger::debug("JsonFileStore: No changes to flush for " +
                                  _filename);
      }
    }

    /// \brief Configure the background flush interval (in milliseconds)
    static std::set<JsonFileStore*>& registry()
    {
      static std::set<JsonFileStore*> s;
      return s;
    }
    static std::mutex& registryMutex()
    {
      static std::mutex m;
      return m;
    }
    static std::thread& flushThread()
    {
      static std::thread t;
      return t;
    }
    static std::chrono::milliseconds& flushInterval()
    {
      static std::chrono::milliseconds ms{2000};
      return ms;
    }
    static std::condition_variable& terminationCv()
    {
      static std::condition_variable cv;
      return cv;
    }
    static std::mutex& terminateCvMutex()
    {
      static std::mutex m;
      return m;
    }
    static std::atomic<bool>& shouldExit()
    {
      static std::atomic<bool> flag{false};
      return flag;
    }
    static void setFlushInterval(std::chrono::milliseconds interval)
    {
      flushInterval() = interval;
    }

  private:
    void saveToFile() const
    {
      try
      {
        std::ofstream file(_filename);
        if (file)
        {
          std::string jsonData = _store.dump(2);
          file << jsonData;
          iora::core::Logger::debug("JsonFileStore: Wrote " +
                                    std::to_string(jsonData.length()) +
                                    " bytes to " + _filename);
        }
        else
        {
          iora::core::Logger::error("JsonFileStore: Failed to open " +
                                    _filename + " for writing");
        }
      }
      catch (const std::exception& e)
      {
        iora::core::Logger::error("JsonFileStore: Failed to write to " +
                                  _filename + ": " + e.what());
      }
    }

    void tryFlushIfDirty()
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (_dirty)
      {
        iora::core::Logger::debug(
            "JsonFileStore: Background flush triggered for " + _filename);
        saveToFile();
        _dirty = false;
      }
    }

    void registerStore()
    {
      std::lock_guard<std::mutex> lock(registryMutex());
      registry().insert(this);
      if (registry().size() == 1)
      {
        shouldExit() = false;
        flushThread() = std::thread(flushThreadFunc);
      }
    }

    void unregisterStore()
    {
      std::lock_guard<std::mutex> lock(registryMutex());
      registry().erase(this);
      if (registry().empty())
      {
        IORA_LOG_INFO("No more stores registered, stopping flush thread");
        shouldExit() = true;
        terminationCv().notify_all();
        if (flushThread().joinable())
        {
          flushThread().join();
        }
        flushThread() = std::thread(); // Reset thread
        IORA_LOG_INFO("Flush thread stopped");
      }
    }

    static void flushThreadFunc()
    {
      while (!shouldExit())
      {
        {
          std::unique_lock<std::mutex> lock(terminateCvMutex());
          if (terminationCv().wait_for(lock, flushInterval()) !=
              std::cv_status::timeout)
          {
            // Notified - check if we should exit
            if (shouldExit())
            {
              break;
            }
          }
        }
        
        // Check again after waking up
        if (shouldExit())
        {
          break;
        }
        
        // Copy the registry under lock to avoid race conditions
        std::set<JsonFileStore*> storesToFlush;
        {
          std::lock_guard<std::mutex> lock(registryMutex());
          if (shouldExit())
          {
            break;
          }
          storesToFlush = registry();
        }
        
        // Now iterate over the copy without holding the registry lock
        for (auto* store : storesToFlush)
        {
          if (shouldExit())
          {
            break;
          }
          store->tryFlushIfDirty();
        }
      }
    }

    const std::string _filename;
    mutable std::mutex _mutex;
    parsers::Json _store;
    bool _dirty;
    // All statics are now function-local for safe destruction order
  };

} // namespace storage
} // namespace iora