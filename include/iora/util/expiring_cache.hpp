// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <chrono>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <optional>
#include "iora/core/logger.hpp"

namespace iora
{
namespace util
{
  // Forward declaration for friend accessor
  template <typename K, typename V> struct ExpiringCacheTestAccessor;

  /// \brief Thread-safe expiring cache with time-to-live (TTL) and automatic
  /// purging of stale entries.
  template <typename K, typename V> class ExpiringCache
  {
  public:
    /// \brief Callback function type for cache evictions
    using EvictionCallback = std::function<void(const K& key, const V& value)>;

    ExpiringCache() : _ttl(std::chrono::seconds(60)), _stop(false)
    {
      iora::core::Logger::info(
          "ExpiringCache: Initializing with default TTL of 60 seconds");
      startPurgeThread();
    }

    explicit ExpiringCache(std::chrono::seconds ttl) : _ttl(ttl), _stop(false)
    {
      iora::core::Logger::info("ExpiringCache: Initializing with TTL of " +
                               std::to_string(ttl.count()) + " seconds");
      startPurgeThread();
    }

    /// \brief Constructor with TTL and eviction callback
    explicit ExpiringCache(std::chrono::seconds ttl, EvictionCallback callback) 
      : _ttl(ttl), _stop(false), _evictionCallback(callback)
    {
      iora::core::Logger::info("ExpiringCache: Initializing with TTL of " +
                               std::to_string(ttl.count()) + " seconds and eviction callback");
      startPurgeThread();
    }

    ~ExpiringCache()
    {
      iora::core::Logger::debug("ExpiringCache: Starting shutdown process");
      {
        std::lock_guard<std::mutex> lock(_mutex);
        _stop = true;
      }
      if (_purgeThread.joinable())
      {
        _purgeThread.join();
      }
      iora::core::Logger::debug("ExpiringCache: Shutdown completed");
    }

    /// \brief Sets a key-value pair in the cache.
    void set(const K& key, const V& value,
             std::chrono::seconds customTtl = std::chrono::seconds(0))
    {
      auto expiration = std::chrono::steady_clock::now() +
                        (customTtl.count() > 0 ? customTtl : _ttl);
      std::lock_guard<std::mutex> lock(_mutex);
      bool isUpdate = _cache.find(key) != _cache.end();
      _cache[key] = {value, expiration};
      iora::core::Logger::debug(
          std::string("ExpiringCache: ") + (isUpdate ? "Updated" : "Added") +
          " cache entry (total entries: " + std::to_string(_cache.size()) +
          ")");
    }

    /// \brief Gets a value by key from the cache.
    std::optional<V> get(const K& key)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      auto it = _cache.find(key);
      if (it != _cache.end())
      {
        if (it->second.expiration > std::chrono::steady_clock::now())
        {
          iora::core::Logger::debug("ExpiringCache: Cache hit for key");
          return it->second.value;
        }
        else
        {
          iora::core::Logger::debug(
              "ExpiringCache: Cache miss - entry expired for key");
          // Invoke eviction callback before removing
          if (_evictionCallback)
          {
            _evictionCallback(it->first, it->second.value);
          }
          _cache.erase(it); // Remove expired entry
        }
      }
      else
      {
        iora::core::Logger::debug("ExpiringCache: Cache miss - key not found");
      }
      return std::nullopt;
    }

    /// \brief Removes a key from the cache.
    void remove(const K& key)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      auto it = _cache.find(key);
      if (it != _cache.end())
      {
        // Invoke eviction callback before removing
        if (_evictionCallback)
        {
          _evictionCallback(it->first, it->second.value);
        }
        _cache.erase(it);
        iora::core::Logger::debug(
            "ExpiringCache: Removed cache entry (remaining entries: " +
            std::to_string(_cache.size()) + ")");
      }
      else
      {
        iora::core::Logger::debug(
            "ExpiringCache: Attempted to remove non-existent key");
      }
    }

    /// \brief Get current cache size (number of entries)
    /// \return Current number of entries in cache
    std::size_t size() const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      return _cache.size();
    }

    // Friend accessor for unit testing
    friend struct ExpiringCacheTestAccessor<K, V>;

  private:
    struct CacheEntry
    {
      V value;
      std::chrono::steady_clock::time_point expiration;
    };

    std::unordered_map<K, CacheEntry> _cache;
    std::chrono::seconds _ttl;
    mutable std::mutex _mutex;
    std::thread _purgeThread;
    bool _stop;
    EvictionCallback _evictionCallback;

    void startPurgeThread()
    {
      iora::core::Logger::debug(
          "ExpiringCache: Starting background purge thread");
      _purgeThread = std::thread(
          [this]()
          {
            iora::core::Logger::debug("ExpiringCache: Purge thread running");
            while (true)
            {
              std::size_t purgedCount = 0;
              {
                std::lock_guard<std::mutex> lock(_mutex);
                if (_stop)
                {
                  iora::core::Logger::debug(
                      "ExpiringCache: Purge thread stopping");
                  break;
                }
                auto now = std::chrono::steady_clock::now();
                std::size_t beforeSize = _cache.size();
                for (auto it = _cache.begin(); it != _cache.end();)
                {
                  if (it->second.expiration <= now)
                  {
                    // Invoke eviction callback before removing
                    if (_evictionCallback)
                    {
                      _evictionCallback(it->first, it->second.value);
                    }
                    it = _cache.erase(it);
                    purgedCount++;
                  }
                  else
                  {
                    ++it;
                  }
                }
                if (purgedCount > 0)
                {
                  iora::core::Logger::debug(
                      "ExpiringCache: Purged " + std::to_string(purgedCount) +
                      " expired entries (" + std::to_string(beforeSize) +
                      " -> " + std::to_string(_cache.size()) + ")");
                }
              }
              std::this_thread::sleep_for(std::chrono::seconds(5));
            }
          });
    }
  };

  /// \brief Provides unit test access to internal state of ExpiringCache.
  template <typename K, typename V> struct ExpiringCacheTestAccessor
  {
    static std::size_t mapSize(ExpiringCache<K, V>& cache)
    {
      std::lock_guard<std::mutex> lock(cache._mutex);
      return cache._cache.size();
    }
  };
} // namespace util
} // namespace iora