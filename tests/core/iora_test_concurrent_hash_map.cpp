// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for ConcurrentHashMap

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/core/concurrent_hash_map.hpp>
#include <iora/core/string_utils.hpp>

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace iora::core;

// Small shard count for testing (still power of two)
using TestMap = ConcurrentHashMap<std::string, int, std::hash<std::string>,
                                  std::equal_to<std::string>, 4>;

// ══════════════════════════════════════════════════════════════════════════════
// Insert / Find / Contains
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("CHM: insert and find", "[chm]")
{
  TestMap map;
  REQUIRE(map.insert("key1", 42));
  auto val = map.find("key1");
  REQUIRE(val.has_value());
  REQUIRE(*val == 42);
}

TEST_CASE("CHM: insert duplicate returns false", "[chm]")
{
  TestMap map;
  REQUIRE(map.insert("key1", 1));
  REQUIRE_FALSE(map.insert("key1", 2));
  REQUIRE(*map.find("key1") == 1); // original value preserved
}

TEST_CASE("CHM: find missing returns nullopt", "[chm]")
{
  TestMap map;
  REQUIRE_FALSE(map.find("missing").has_value());
}

TEST_CASE("CHM: contains", "[chm]")
{
  TestMap map;
  REQUIRE_FALSE(map.contains("key1"));
  map.insert("key1", 1);
  REQUIRE(map.contains("key1"));
}

// ══════════════════════════════════════════════════════════════════════════════
// InsertOrAssign
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("CHM: insertOrAssign insert then assign", "[chm]")
{
  TestMap map;
  REQUIRE(map.insertOrAssign("key1", 1));    // inserted
  REQUIRE_FALSE(map.insertOrAssign("key1", 2)); // assigned
  REQUIRE(*map.find("key1") == 2);
}

TEST_CASE("CHM: insertOrAssign move overload", "[chm]")
{
  ConcurrentHashMap<std::string, std::string, std::hash<std::string>,
                    std::equal_to<std::string>, 4> map;
  std::string val = "hello";
  map.insertOrAssign("key", std::move(val));
  REQUIRE(map.find("key").value() == "hello");
  // val may be moved-from — don't check its content
}

// ══════════════════════════════════════════════════════════════════════════════
// Erase / EraseIf
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("CHM: erase", "[chm]")
{
  TestMap map;
  map.insert("key1", 1);
  REQUIRE(map.erase("key1"));
  REQUIRE_FALSE(map.contains("key1"));
  REQUIRE_FALSE(map.erase("key1")); // already gone
}

TEST_CASE("CHM: eraseIf predicate true", "[chm]")
{
  TestMap map;
  map.insert("key1", 42);
  REQUIRE(map.eraseIf("key1", [](const std::string&, int v) { return v == 42; }));
  REQUIRE_FALSE(map.contains("key1"));
}

TEST_CASE("CHM: eraseIf predicate false — entry persists", "[chm]")
{
  TestMap map;
  map.insert("key1", 42);
  REQUIRE_FALSE(map.eraseIf("key1", [](const std::string&, int v) { return v == 99; }));
  REQUIRE(map.contains("key1"));
  REQUIRE(*map.find("key1") == 42);
}

TEST_CASE("CHM: eraseIf missing key", "[chm]")
{
  TestMap map;
  REQUIRE_FALSE(map.eraseIf("missing", [](const std::string&, int) { return true; }));
}

// ══════════════════════════════════════════════════════════════════════════════
// FindOrInsert
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("CHM: findOrInsert creates when absent", "[chm]")
{
  TestMap map;
  auto val = map.findOrInsert("key1", []() { return 42; });
  REQUIRE(val == 42);
  REQUIRE(*map.find("key1") == 42);
}

TEST_CASE("CHM: findOrInsert returns existing", "[chm]")
{
  TestMap map;
  map.insert("key1", 10);
  auto val = map.findOrInsert("key1", []() { return 99; });
  REQUIRE(val == 10); // factory not called
}

TEST_CASE("CHM: findOrInsert concurrent — factory called once", "[chm][concurrent]")
{
  ConcurrentHashMap<std::string, int, std::hash<std::string>,
                    std::equal_to<std::string>, 4> map;
  std::atomic<int> factoryCalls{0};
  constexpr int numThreads = 16;
  std::vector<int> results(numThreads);

  std::vector<std::thread> threads;
  for (int i = 0; i < numThreads; ++i)
  {
    threads.emplace_back([&, i]()
    {
      results[i] = map.findOrInsert("shared_key", [&]()
      {
        factoryCalls.fetch_add(1);
        return 42;
      });
    });
  }
  for (auto& t : threads) t.join();

  REQUIRE(factoryCalls.load() == 1);
  for (int i = 0; i < numThreads; ++i)
  {
    REQUIRE(results[i] == 42);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// FindAndModify / FindAndDo
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("CHM: findAndModify", "[chm]")
{
  TestMap map;
  map.insert("key1", 10);
  REQUIRE(map.findAndModify("key1", [](int& v) { v += 5; }));
  REQUIRE(*map.find("key1") == 15);
}

TEST_CASE("CHM: findAndModify missing returns false", "[chm]")
{
  TestMap map;
  REQUIRE_FALSE(map.findAndModify("missing", [](int& v) { v = 0; }));
}

TEST_CASE("CHM: findAndDo", "[chm]")
{
  TestMap map;
  map.insert("key1", 42);
  int observed = 0;
  REQUIRE(map.findAndDo("key1", [&](const int& v) { observed = v; }));
  REQUIRE(observed == 42);
}

TEST_CASE("CHM: findAndDo missing returns false", "[chm]")
{
  TestMap map;
  bool called = false;
  REQUIRE_FALSE(map.findAndDo("missing", [&](const int&) { called = true; }));
  REQUIRE_FALSE(called);
}

// ══════════════════════════════════════════════════════════════════════════════
// ForEach
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("CHM: forEach visits all entries", "[chm]")
{
  TestMap map;
  map.insert("a", 1);
  map.insert("b", 2);
  map.insert("c", 3);

  int sum = 0;
  int count = 0;
  map.forEach([&](const std::string&, int v)
  {
    sum += v;
    ++count;
  });
  REQUIRE(count == 3);
  REQUIRE(sum == 6);
}

// ══════════════════════════════════════════════════════════════════════════════
// Size / Empty / Clear
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("CHM: size and empty", "[chm]")
{
  TestMap map;
  REQUIRE(map.size() == 0);
  REQUIRE(map.empty());

  map.insert("a", 1);
  map.insert("b", 2);
  REQUIRE(map.size() == 2);
  REQUIRE_FALSE(map.empty());
}

TEST_CASE("CHM: clear", "[chm]")
{
  TestMap map;
  map.insert("a", 1);
  map.insert("b", 2);
  map.clear();
  REQUIRE(map.size() == 0);
  REQUIRE(map.empty());
}

// ══════════════════════════════════════════════════════════════════════════════
// Move-Only Values
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("CHM: move-only values with findAndDo", "[chm][move]")
{
  ConcurrentHashMap<std::string, std::shared_ptr<int>,
    std::hash<std::string>, std::equal_to<std::string>, 4> map;

  map.insert("key1", std::make_shared<int>(42));

  auto val = map.find("key1");
  REQUIRE(val.has_value());
  REQUIRE(**val == 42);
}

TEST_CASE("CHM: insert move overload avoids copy", "[chm][move]")
{
  struct MoveCounter
  {
    int value;
    int moves = 0;
    int copies = 0;
    MoveCounter(int v) : value(v) {}
    MoveCounter(const MoveCounter& o) : value(o.value), moves(o.moves), copies(o.copies + 1) {}
    MoveCounter(MoveCounter&& o) noexcept : value(o.value), moves(o.moves + 1), copies(o.copies) { o.value = -1; }
    MoveCounter& operator=(const MoveCounter&) = default;
    MoveCounter& operator=(MoveCounter&&) = default;
  };

  ConcurrentHashMap<std::string, MoveCounter, std::hash<std::string>,
                    std::equal_to<std::string>, 4> map;
  MoveCounter mc(42);
  map.insert("key1", std::move(mc));

  map.findAndDo("key1", [](const MoveCounter& v)
  {
    REQUIRE(v.value == 42);
    // At least one move happened (into the map), zero copies from the move path
    REQUIRE(v.copies == 0);
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// CaseInsensitive KeyEqual
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("CHM: case-insensitive hash and equal", "[chm][ci]")
{
  ConcurrentHashMap<std::string, int,
    StringUtils::CaseInsensitiveHash,
    StringUtils::CaseInsensitiveEqual, 4> map;

  map.insert("Content-Type", 1);
  REQUIRE(map.contains("content-type"));
  REQUIRE(map.contains("CONTENT-TYPE"));
  REQUIRE(*map.find("content-type") == 1);

  // insertOrAssign with different case overwrites
  map.insertOrAssign("CONTENT-TYPE", 2);
  REQUIRE(*map.find("Content-Type") == 2);
}

// ══════════════════════════════════════════════════════════════════════════════
// Concurrent Stress Test
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("CHM: insert move-only type (unique_ptr) with findAndDo", "[chm][move]")
{
  ConcurrentHashMap<std::string, std::unique_ptr<int>,
    std::hash<std::string>, std::equal_to<std::string>, 4> map;

  map.insert("key1", std::make_unique<int>(42));
  map.findAndDo("key1", [](const std::unique_ptr<int>& v)
  {
    REQUIRE(*v == 42);
  });
}

TEST_CASE("CHM: concurrent findAndModify + find", "[chm][concurrent]")
{
  ConcurrentHashMap<int, int, std::hash<int>, std::equal_to<int>, 4> map;
  map.insert(1, 0);

  constexpr int numThreads = 8;
  constexpr int opsPerThread = 10000;

  std::vector<std::thread> threads;
  // Writers: increment via findAndModify
  for (int i = 0; i < numThreads / 2; ++i)
  {
    threads.emplace_back([&]()
    {
      for (int j = 0; j < opsPerThread; ++j)
      {
        map.findAndModify(1, [](int& v) { ++v; });
      }
    });
  }
  // Readers: find concurrently
  for (int i = 0; i < numThreads / 2; ++i)
  {
    threads.emplace_back([&]()
    {
      for (int j = 0; j < opsPerThread; ++j)
      {
        auto val = map.find(1);
        REQUIRE(val.has_value());
        REQUIRE(*val >= 0);
      }
    });
  }
  for (auto& t : threads) t.join();

  REQUIRE(*map.find(1) == (numThreads / 2) * opsPerThread);
}

TEST_CASE("CHM: concurrent eraseIf + insert", "[chm][concurrent]")
{
  ConcurrentHashMap<int, int, std::hash<int>, std::equal_to<int>, 4> map;
  constexpr int numThreads = 4;
  constexpr int opsPerThread = 5000;

  std::vector<std::thread> threads;
  // Inserters
  for (int i = 0; i < numThreads; ++i)
  {
    threads.emplace_back([&, i]()
    {
      for (int j = 0; j < opsPerThread; ++j)
      {
        map.insertOrAssign(i * opsPerThread + j, j);
      }
    });
  }
  // Erasers with predicate
  for (int i = 0; i < numThreads; ++i)
  {
    threads.emplace_back([&, i]()
    {
      for (int j = 0; j < opsPerThread; ++j)
      {
        map.eraseIf(i * opsPerThread + j,
          [](const int&, int v) { return v % 2 == 0; });
      }
    });
  }
  for (auto& t : threads) t.join();

  // No crashes, map in valid state
  REQUIRE(map.size() <= static_cast<std::size_t>(numThreads * opsPerThread));
}

TEST_CASE("CHM: concurrent stress — readers and writers", "[chm][stress]")
{
  ConcurrentHashMap<int, int, std::hash<int>, std::equal_to<int>, 16> map;
  constexpr int numWriters = 4;
  constexpr int numReaders = 4;
  constexpr int opsPerThread = 10000;

  std::vector<std::thread> threads;

  // Writers: insert and erase
  for (int w = 0; w < numWriters; ++w)
  {
    threads.emplace_back([&, w]()
    {
      for (int i = 0; i < opsPerThread; ++i)
      {
        int key = w * opsPerThread + i;
        map.insert(key, i);
        if (i % 3 == 0)
        {
          map.erase(key);
        }
      }
    });
  }

  // Readers: find and forEach
  for (int r = 0; r < numReaders; ++r)
  {
    threads.emplace_back([&, r]()
    {
      for (int i = 0; i < opsPerThread; ++i)
      {
        map.find(r * opsPerThread + i);
        map.contains(r * opsPerThread + i);
        if (i % 100 == 0)
        {
          int count = 0;
          map.forEach([&](const int&, const int&) { ++count; });
        }
      }
    });
  }

  for (auto& t : threads) t.join();

  // Just verify no crashes and map is in a valid state
  REQUIRE(map.size() <= static_cast<std::size_t>(numWriters * opsPerThread));
}
