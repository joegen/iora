
// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

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
