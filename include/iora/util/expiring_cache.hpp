#pragma once

#include <chrono>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <optional>

namespace iora {
namespace util {
  // Forward declaration for friend accessor
  template <typename K, typename V> struct ExpiringCacheTestAccessor;
  
  /// \brief Thread-safe expiring cache with time-to-live (TTL) and automatic
  /// purging of stale entries.
  template <typename K, typename V> class ExpiringCache
  {
  public:
    ExpiringCache() : _ttl(std::chrono::seconds(60)), _stop(false)
    {
      startPurgeThread();
    }

    explicit ExpiringCache(std::chrono::seconds ttl) : _ttl(ttl), _stop(false)
    {
      startPurgeThread();
    }

    ~ExpiringCache()
    {
      {
        std::lock_guard<std::mutex> lock(_mutex);
        _stop = true;
      }
      if (_purgeThread.joinable())
      {
        _purgeThread.join();
      }
    }

    /// \brief Sets a key-value pair in the cache.
    void set(const K& key, const V& value,
             std::chrono::seconds customTtl = std::chrono::seconds(0))
    {
      auto expiration = std::chrono::steady_clock::now() +
                        (customTtl.count() > 0 ? customTtl : _ttl);
      std::lock_guard<std::mutex> lock(_mutex);
      _cache[key] = {value, expiration};
    }

    /// \brief Gets a value by key from the cache.
    std::optional<V> get(const K& key)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      auto it = _cache.find(key);
      if (it != _cache.end() &&
          it->second.expiration > std::chrono::steady_clock::now())
      {
        return it->second.value;
      }
      return std::nullopt;
    }

    /// \brief Removes a key from the cache.
    void remove(const K& key)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _cache.erase(key);
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
    std::mutex _mutex;
    std::thread _purgeThread;
    bool _stop;

    void startPurgeThread()
    {
      _purgeThread = std::thread(
          [this]()
          {
            while (true)
            {
              {
                std::lock_guard<std::mutex> lock(_mutex);
                if (_stop)
                {
                  break;
                }
                auto now = std::chrono::steady_clock::now();
                for (auto it = _cache.begin(); it != _cache.end();)
                {
                  if (it->second.expiration <= now)
                  {
                    it = _cache.erase(it);
                  }
                  else
                  {
                    ++it;
                  }
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
} } // namespace iora::util