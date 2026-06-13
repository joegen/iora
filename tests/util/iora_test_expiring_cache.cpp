
// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <algorithm>
#include <atomic>
#include <catch2/catch.hpp>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

TEST_CASE("ExpiringCache basic operations")
{
  iora::util::ExpiringCache<std::string, int> cache;
  cache.set("key1", 42, std::chrono::seconds(1));
  REQUIRE(cache.get("key1").value() == 42);
  std::this_thread::sleep_for(std::chrono::seconds(2));
  REQUIRE(!cache.get("key1").has_value());
  cache.set("key2", 100, std::chrono::seconds(1));
  std::this_thread::sleep_for(std::chrono::seconds(2));
  REQUIRE(!cache.get("key2").has_value());
}

TEST_CASE("ExpiringCache expiration")
{
  iora::util::ExpiringCache<std::string, int> cache;
  cache.set("key3", 200, std::chrono::seconds(1));
  std::this_thread::sleep_for(std::chrono::seconds(2));
  REQUIRE(!cache.get("key3").has_value());
}

TEST_CASE("ExpiringCache concurrency")
{
  iora::util::ExpiringCache<int, int> cache;
  std::vector<std::thread> threads;
  for (int i = 0; i < 10; ++i)
  {
    threads.emplace_back([&cache, i]() { cache.set(i, i * 10, std::chrono::seconds(1)); });
  }
  for (auto &t : threads)
  {
    t.join();
  }
  std::this_thread::sleep_for(std::chrono::seconds(2));
  for (int i = 0; i < 10; ++i)
  {
    REQUIRE(!cache.get(i).has_value());
  }
}

TEST_CASE("ExpiringCache purging and permanent deletion")
{
  using Cache = iora::util::ExpiringCache<std::string, int>;
  using Accessor = iora::util::ExpiringCacheTestAccessor<std::string, int>;
  Cache cache;
  cache.set("purge", 123, std::chrono::seconds(1));
  REQUIRE(cache.get("purge").has_value());
  REQUIRE(Accessor::mapSize(cache) == 1);
  std::this_thread::sleep_for(std::chrono::seconds(7));
  REQUIRE(!cache.get("purge").has_value());
  REQUIRE(Accessor::mapSize(cache) == 0);
}

// Regression: the eviction callback must be invoked OUTSIDE the cache mutex
// (HR-3 copy-then-invoke). The callback re-enters the cache via size() — which
// re-acquires the non-recursive _mutex. Before the fix the callback fired while
// _mutex was held, so this re-acquire DEADLOCKED; a deadlock hangs the test until
// the ctest timeout, so completion proves the callback fires unlocked. Each
// eviction site is pinned to a distinct key so the assertions verify that site's
// callback fired specifically (not merely that some running total was reached):
//   "g" -> get() lazy-expiry path, "r" -> remove() path, "p" -> purge-thread path.
TEST_CASE("ExpiringCache eviction callback fires outside the lock (no re-entrant deadlock)")
{
  using Cache = iora::util::ExpiringCache<std::string, int>;
  std::mutex evictedMutex;
  std::vector<std::string> evictedKeys;
  std::unique_ptr<Cache> cache;
  auto onEvict = [&](const std::string &key, int /*value*/)
  {
    // Re-enter the cache from within the eviction callback. size() re-acquires
    // _mutex (the genuine re-entrancy probe — deadlocked pre-fix). get() likewise
    // re-acquires _mutex and returns a miss for the already-erased key.
    (void)cache->size();
    (void)cache->get(key);
    std::lock_guard<std::mutex> lk(evictedMutex);
    evictedKeys.push_back(key);
  };
  cache = std::make_unique<Cache>(std::chrono::seconds(1), onEvict);

  auto wasEvicted = [&](const std::string &key)
  {
    std::lock_guard<std::mutex> lk(evictedMutex);
    return std::find(evictedKeys.begin(), evictedKeys.end(), key) != evictedKeys.end();
  };

  // (1) get()-path eviction: "g" expires, then is evicted on access at t~2s —
  // well before the first purge sweep (5s), so this pins the get() path.
  cache->set("g", 1, std::chrono::seconds(1));
  std::this_thread::sleep_for(std::chrono::seconds(2));
  REQUIRE_FALSE(cache->get("g").has_value());
  REQUIRE(wasEvicted("g"));

  // (2) remove()-path eviction: "r" is live (60s TTL) and removed explicitly, so
  // only remove() can evict it — pins the remove() path.
  cache->set("r", 2, std::chrono::seconds(60));
  cache->remove("r");
  REQUIRE(wasEvicted("r"));

  // (3) purge-thread-path eviction: "p" expires but is never get()/remove()'d, so
  // only the background sweeper (every 5s) can evict it — pins the purge path.
  cache->set("p", 3, std::chrono::seconds(1));
  std::this_thread::sleep_for(std::chrono::seconds(7));
  REQUIRE(wasEvicted("p"));
}
