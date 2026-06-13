// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include "iora/core/logger.hpp"
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

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
  using EvictionCallback = std::function<void(const K &key, const V &value)>;

  ExpiringCache() : _ttl(std::chrono::seconds(60)), _stop(false)
  {
    iora::core::Logger::info("ExpiringCache: Initializing with default TTL of 60 seconds");
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
    // P0 FIX: Wake up purge thread immediately instead of waiting for 5-second sleep
    _stopCondition.notify_one();
    if (_purgeThread.joinable())
    {
      _purgeThread.join();
    }
    iora::core::Logger::debug("ExpiringCache: Shutdown completed");
  }

  /// \brief Sets a key-value pair in the cache.
  void set(const K &key, const V &value, std::chrono::seconds customTtl = std::chrono::seconds(0))
  {
    auto expiration = std::chrono::steady_clock::now() + (customTtl.count() > 0 ? customTtl : _ttl);
    std::lock_guard<std::mutex> lock(_mutex);
    bool isUpdate = _cache.find(key) != _cache.end();
    _cache[key] = {value, expiration};
    iora::core::Logger::debug(std::string("ExpiringCache: ") + (isUpdate ? "Updated" : "Added") +
                              " cache entry (total entries: " + std::to_string(_cache.size()) +
                              ")");
  }

  /// \brief Gets a value by key from the cache.
  std::optional<V> get(const K &key)
  {
    // HR-3 (copy-then-invoke): capture the evicted entry under the lock, erase,
    // release the lock, then fire the eviction callback. Invoking a user callback
    // while _mutex is held deadlocks if the callback re-enters get/set/remove.
    std::optional<std::pair<K, V>> evicted;
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
          iora::core::Logger::debug("ExpiringCache: Cache miss - entry expired for key");
          if (_evictionCallback)
          {
            evicted.emplace(it->first, it->second.value);
          }
          _cache.erase(it); // Remove expired entry
        }
      }
      else
      {
        iora::core::Logger::debug("ExpiringCache: Cache miss - key not found");
      }
    }
    if (evicted)
    {
      _evictionCallback(evicted->first, evicted->second);
    }
    return std::nullopt;
  }

  /// \brief Removes a key from the cache.
  void remove(const K &key)
  {
    // HR-3 (copy-then-invoke): erase under the lock, fire the eviction callback
    // after release so a re-entrant callback cannot deadlock on _mutex.
    std::optional<std::pair<K, V>> evicted;
    {
      std::lock_guard<std::mutex> lock(_mutex);
      auto it = _cache.find(key);
      if (it != _cache.end())
      {
        if (_evictionCallback)
        {
          evicted.emplace(it->first, it->second.value);
        }
        _cache.erase(it);
        iora::core::Logger::debug("ExpiringCache: Removed cache entry (remaining entries: " +
                                  std::to_string(_cache.size()) + ")");
      }
      else
      {
        iora::core::Logger::debug("ExpiringCache: Attempted to remove non-existent key");
      }
    }
    if (evicted)
    {
      _evictionCallback(evicted->first, evicted->second);
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
  std::condition_variable _stopCondition; // P0 FIX: Wake up purge thread on shutdown

  void startPurgeThread()
  {
    iora::core::Logger::debug("ExpiringCache: Starting background purge thread");
    _purgeThread = std::thread(
      [this]()
      {
        iora::core::Logger::debug("ExpiringCache: Purge thread running");
        while (true)
        {
          // HR-3 (copy-then-invoke): collect evicted entries under the lock, then
          // fire the eviction callbacks AFTER releasing _mutex so a re-entrant
          // callback cannot deadlock and the purge does not hold the lock across
          // arbitrary user code.
          std::vector<std::pair<K, V>> evicted;
          // P0 FIX: Wait first, then purge
          // Use condition variable wait instead of sleep_for for immediate shutdown
          {
            std::unique_lock<std::mutex> lock(_mutex);
            if (_stopCondition.wait_for(lock, std::chrono::seconds(5), [this]() { return _stop; }))
            {
              // Woken up by shutdown signal
              iora::core::Logger::debug("ExpiringCache: Purge thread stopping");
              break;
            }
            // Timeout expired, time to purge (mutex still held)
            auto now = std::chrono::steady_clock::now();
            std::size_t beforeSize = _cache.size();
            std::size_t purgedCount = 0;
            for (auto it = _cache.begin(); it != _cache.end();)
            {
              if (it->second.expiration <= now)
              {
                if (_evictionCallback)
                {
                  evicted.emplace_back(it->first, it->second.value);
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
              iora::core::Logger::debug("ExpiringCache: Purged " + std::to_string(purgedCount) +
                                        " expired entries (" + std::to_string(beforeSize) + " -> " +
                                        std::to_string(_cache.size()) + ")");
            }
          }
          // Mutex released here. Fire eviction callbacks outside the lock.
          // Guard against a throwing user callback: this runs on the purge thread,
          // which has no caller — an escaping exception would call std::terminate
          // and abort the process. Log and continue.
          for (auto &kv : evicted)
          {
            try
            {
              _evictionCallback(kv.first, kv.second);
            }
            catch (const std::exception &e)
            {
              iora::core::Logger::error(std::string("ExpiringCache: eviction callback threw: ") +
                                        e.what());
            }
            catch (...)
            {
              iora::core::Logger::error("ExpiringCache: eviction callback threw a non-std exception");
            }
          }
        }
      });
  }
};

/// \brief Provides unit test access to internal state of ExpiringCache.
template <typename K, typename V> struct ExpiringCacheTestAccessor
{
  static std::size_t mapSize(ExpiringCache<K, V> &cache)
  {
    std::lock_guard<std::mutex> lock(cache._mutex);
    return cache._cache.size();
  }
};
} // namespace util
} // namespace iora