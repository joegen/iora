// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include "iora/storage/kvstore.hpp"

// Use namespaced types
using iora::storage::KVStore;
using iora::storage::KVStoreConfig;
using iora::storage::KVStoreException;
using iora::storage::MAX_KEY_LENGTH;
using iora::storage::MAX_VALUE_LENGTH;
#include <atomic>
#include <catch2/catch.hpp>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace
{
std::vector<uint8_t> randomBytes(size_t n)
{
  std::vector<uint8_t> v(n);
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, 255);
  for (size_t i = 0; i < n; ++i)
  {
    v[i] = static_cast<uint8_t>(dis(gen));
  }
  return v;
}
} // namespace

TEST_CASE("KVStore basic set/get/remove", "[kvstore]")
{
  const std::string file = "test_kvstore.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
  KVStore store(file);

  std::string key = "foo";
  std::vector<uint8_t> value = {1, 2, 3, 4};
  store.set(key, value);
  auto got = store.get(key);
  REQUIRE(got.has_value());
  REQUIRE(got.value() == value);

  store.remove(key);
  REQUIRE_FALSE(store.get(key).has_value());
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

TEST_CASE("KVStore batch set/get", "[kvstore][batch]")
{
  const std::string file = "test_kvstore_batch.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
  KVStore store(file);

  std::unordered_map<std::string, std::vector<uint8_t>> batch;
  for (int i = 0; i < 10; ++i)
  {
    batch["key" + std::to_string(i)] = randomBytes(16);
  }
  store.setBatch(batch);
  auto keys = std::vector<std::string>{};
  for (const auto &[k, _] : batch)
  {
    keys.push_back(k);
  }
  auto result = store.getBatch(keys);
  REQUIRE(result.size() == batch.size());
  for (const auto &[k, v] : batch)
  {
    REQUIRE(result[k] == v);
  }
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

TEST_CASE("KVStore persistence and reload", "[kvstore][persistence]")
{
  const std::string file = "test_kvstore_persist.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
  {
    KVStore store(file);
    store.set("persist", {9, 8, 7, 6});
  }
  {
    KVStore store(file);
    auto got = store.get("persist");
    REQUIRE(got.has_value());
    REQUIRE(got.value() == std::vector<uint8_t>({9, 8, 7, 6}));
  }
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

TEST_CASE("KVStore handles large values and compaction", "[kvstore][large][compact]")
{
  const std::string file = "test_kvstore_large.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
  KVStoreConfig cfg;
  cfg.maxLogSizeBytes = 1024 * 10; // force compaction quickly
  KVStore store(file, cfg);

  std::string key = "big";
  auto value = randomBytes(4096);
  store.set(key, value);
  REQUIRE(store.get(key).value() == value);
  // Overwrite to grow log
  for (int i = 0; i < 10; ++i)
  {
    auto v = randomBytes(4096);
    store.set(key, v);
  }
  store.forceCompact();
  REQUIRE(store.get(key).has_value());
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

TEST_CASE("KVStore handles invalid operations", "[kvstore][invalid]")
{
  const std::string file = "test_kvstore_invalid.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
  KVStore store(file);
  REQUIRE_THROWS_AS(store.set("", {1, 2, 3}), KVStoreException);
  REQUIRE_THROWS_AS(store.set(std::string(MAX_KEY_LENGTH + 1, 'x'), {1, 2, 3}), KVStoreException);
  REQUIRE_THROWS_AS(store.set("ok", std::vector<uint8_t>(MAX_VALUE_LENGTH + 1, 1)),
                    KVStoreException);
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

TEST_CASE("KVStore cache and size", "[kvstore][cache]")
{
  const std::string file = "test_kvstore_cache.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
  KVStoreConfig cfg;
  cfg.maxCacheSize = 2;
  KVStore store(file, cfg);
  store.set("a", {1});
  store.set("b", {2});
  store.set("c", {3});
  REQUIRE(store.size() == 3);
  REQUIRE(store.exists("a"));
  REQUIRE(store.exists("b"));
  REQUIRE(store.exists("c"));
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

// EXTENDED TESTS - Persistence and Recovery Edge Cases
TEST_CASE("KVStore persistence with mixed operations", "[kvstore][persistence][extended]")
{
  const std::string file = "test_kvstore_mixed_persist.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());

  // Phase 1: Create data with mixed operations
  {
    KVStore store(file);
    store.set("key1", {1, 2, 3});
    store.set("key2", {4, 5, 6});
    store.remove("key1"); // Remove then re-add
    store.set("key1", {7, 8, 9});
    store.set("key3", {10, 11, 12});
    store.remove("key2"); // Remove permanently
    store.flush();
  }

  // Phase 2: Verify persistence after restart
  {
    KVStore store(file);
    REQUIRE(store.size() == 2);
    REQUIRE(store.get("key1").value() == std::vector<uint8_t>({7, 8, 9}));
    REQUIRE_FALSE(store.get("key2").has_value());
    REQUIRE(store.get("key3").value() == std::vector<uint8_t>({10, 11, 12}));
  }

  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

TEST_CASE("KVStore recovery from empty files", "[kvstore][persistence][edge]")
{
  const std::string file = "test_kvstore_empty.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());

  // Create empty log file only (no snapshot)
  std::ofstream(file + ".log").close();

  // Should handle empty log file gracefully
  KVStore store(file);
  REQUIRE(store.size() == 0);
  store.set("test", {1, 2, 3});
  REQUIRE(store.get("test").value() == std::vector<uint8_t>({1, 2, 3}));

  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

// Log File Integrity and Corruption Tests
TEST_CASE("KVStore handles truncated log file", "[kvstore][corruption][log]")
{
  const std::string file = "test_kvstore_truncated.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());

  // Create store with some data
  {
    KVStore store(file);
    store.set("key1", {1, 2, 3, 4, 5});
    store.set("key2", {6, 7, 8, 9, 10});
    store.flush();
  }

  // Truncate the log file (simulate corruption)
  {
    std::ofstream logFile(file + ".log", std::ios::binary | std::ios::trunc);
    logFile.write("corrupt", 7); // Write invalid data
  }

  // Store should recover gracefully
  {
    KVStore store(file);
    REQUIRE_NOTHROW(store.size()); // Should not crash
    store.set("recovery_test", {99});
    REQUIRE(store.get("recovery_test").value() == std::vector<uint8_t>({99}));
  }

  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

TEST_CASE("KVStore handles corrupted snapshot file", "[kvstore][corruption][snapshot]")
{
  const std::string file = "test_kvstore_corrupt_snapshot.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());

  // Create a corrupted snapshot file
  {
    std::ofstream corrupt(file, std::ios::binary);
    corrupt.write("BADMAGIC", 8); // Invalid magic number
  }

  // Should throw exception for corrupted snapshot
  REQUIRE_THROWS_AS(KVStore(file), KVStoreException);

  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

// Compaction Verification Tests
TEST_CASE("KVStore compaction reduces file size", "[kvstore][compaction][size]")
{
  const std::string file = "test_kvstore_compaction_size.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());

  KVStoreConfig cfg;
  cfg.maxLogSizeBytes = 1024;             // Small log to force compaction
  cfg.enableBackgroundCompaction = false; // Manual control

  std::vector<uint8_t> finalValue;

  {
    KVStore store(file, cfg);

    // Fill store with data that will be overwritten
    std::string key = "overwrite_me";
    for (int i = 0; i < 10; ++i)
    {
      auto data = randomBytes(50);
      store.set(key, data);
      if (i == 9)
      {
        finalValue = data; // Remember the final value
      }
    }

    // Force compaction
    store.forceCompact();

    // Data should still be accessible
    REQUIRE(store.get(key).value() == finalValue);
  } // Destructor releases locks

  // Verify log file was reset
  std::error_code ec;
  if (std::filesystem::exists(file + ".log", ec) && !ec)
  {
    auto logSize = std::filesystem::file_size(file + ".log", ec);
    if (!ec)
    {
      REQUIRE(logSize == 0); // Should be empty after compaction
    }
  }

  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

TEST_CASE("KVStore compaction preserves all data", "[kvstore][compaction][integrity]")
{
  const std::string file = "test_kvstore_compaction_integrity.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());

  KVStoreConfig cfg;
  cfg.enableBackgroundCompaction = false;
  KVStore store(file, cfg);

  // Create test data
  std::unordered_map<std::string, std::vector<uint8_t>> testData;
  for (int i = 0; i < 50; ++i)
  {
    std::string key = "key_" + std::to_string(i);
    auto value = randomBytes(50 + (i % 100));
    testData[key] = value;
    store.set(key, value);
  }

  // Remove some keys to create gaps
  for (int i = 0; i < 50; i += 3)
  {
    std::string key = "key_" + std::to_string(i);
    store.remove(key);
    testData.erase(key);
  }

  // Force compaction
  store.forceCompact();

  // Verify all remaining data is intact
  for (const auto &[key, expectedValue] : testData)
  {
    auto actualValue = store.get(key);
    REQUIRE(actualValue.has_value());
    REQUIRE(actualValue.value() == expectedValue);
  }

  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

// Cache Behavior Tests
TEST_CASE("KVStore cache eviction with LRU", "[kvstore][cache][lru]")
{
  const std::string file = "test_kvstore_cache_lru.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());

  KVStoreConfig cfg;
  cfg.maxCacheSize = 3; // Small cache
  KVStore store(file, cfg);

  // Fill cache beyond capacity
  store.set("a", {1});
  store.set("b", {2});
  store.set("c", {3});
  store.set("d", {4}); // Should evict oldest
  store.set("e", {5}); // Should evict next oldest

  // All keys should still be retrievable (from disk if not in cache)
  REQUIRE(store.get("a").value() == std::vector<uint8_t>({1}));
  REQUIRE(store.get("b").value() == std::vector<uint8_t>({2}));
  REQUIRE(store.get("c").value() == std::vector<uint8_t>({3}));
  REQUIRE(store.get("d").value() == std::vector<uint8_t>({4}));
  REQUIRE(store.get("e").value() == std::vector<uint8_t>({5}));

  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

// Concurrency Tests
TEST_CASE("KVStore concurrent read operations", "[kvstore][concurrency][reads]")
{
  const std::string file = "test_kvstore_concurrent_reads.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());

  KVStore store(file);

  // Populate with test data
  const int numKeys = 100;
  for (int i = 0; i < numKeys; ++i)
  {
    std::string key = "key_" + std::to_string(i);
    std::vector<uint8_t> value = {static_cast<uint8_t>(i), static_cast<uint8_t>(i + 1)};
    store.set(key, value);
  }

  // Concurrent read test
  const int numThreads = 4;
  std::vector<std::thread> threads;
  std::atomic<int> successCount(0);

  for (int t = 0; t < numThreads; ++t)
  {
    threads.emplace_back(
      [&store, &successCount, numKeys, t]()
      {
        for (int i = t; i < numKeys; i += 4)
        { // Interleaved access
          std::string key = "key_" + std::to_string(i);
          auto result = store.get(key);
          if (result.has_value() && result.value()[0] == static_cast<uint8_t>(i))
          {
            successCount++;
          }
        }
      });
  }

  for (auto &thread : threads)
  {
    thread.join();
  }

  REQUIRE(successCount == numKeys);

  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

TEST_CASE("KVStore concurrent mixed operations", "[kvstore][concurrency][mixed]")
{
  const std::string file = "test_kvstore_concurrent_mixed.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());

  KVStore store(file);
  std::atomic<int> operationCount(0);
  std::mutex errorMutex;
  std::vector<std::string> errors;

  std::vector<std::thread> threads;

  // Writer thread
  threads.emplace_back(
    [&store, &operationCount, &errors, &errorMutex]()
    {
      try
      {
        for (int i = 0; i < 50; ++i)
        {
          std::string key = "write_" + std::to_string(i);
          std::vector<uint8_t> value = randomBytes(10);
          store.set(key, value);
          operationCount++;
        }
      }
      catch (const std::exception &e)
      {
        std::lock_guard<std::mutex> lock(errorMutex);
        errors.push_back(std::string("Writer: ") + e.what());
      }
    });

  // Reader thread
  threads.emplace_back(
    [&store, &operationCount, &errors, &errorMutex]()
    {
      try
      {
        for (int i = 0; i < 100; ++i)
        {
          std::string key = "write_" + std::to_string(i % 50);
          auto result = store.get(key);
          operationCount++;
        }
      }
      catch (const std::exception &e)
      {
        std::lock_guard<std::mutex> lock(errorMutex);
        errors.push_back(std::string("Reader: ") + e.what());
      }
    });

  // Deleter thread
  threads.emplace_back(
    [&store, &operationCount, &errors, &errorMutex]()
    {
      try
      {
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Let some writes happen first
        for (int i = 0; i < 25; ++i)
        {
          std::string key = "write_" + std::to_string(i * 2);
          store.remove(key);
          operationCount++;
        }
      }
      catch (const std::exception &e)
      {
        std::lock_guard<std::mutex> lock(errorMutex);
        errors.push_back(std::string("Deleter: ") + e.what());
      }
    });

  for (auto &thread : threads)
  {
    thread.join();
  }

  // Should complete without errors
  REQUIRE(errors.empty());
  REQUIRE(operationCount > 0);

  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

// Exception Safety Tests
TEST_CASE("KVStore handles write failures gracefully", "[kvstore][exceptions][write]")
{
  const std::string file = "/dev/null/impossible_path/test.bin"; // Invalid path

  // Should throw during construction when trying to create log file
  REQUIRE_THROWS_AS(KVStore(file), KVStoreException);
}

TEST_CASE("KVStore batch operation rollback on failure", "[kvstore][exceptions][batch]")
{
  const std::string file = "test_kvstore_batch_rollback.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());

  KVStore store(file);

  // Set initial state
  store.set("existing", {1, 2, 3});

  // Create batch with one invalid entry
  std::unordered_map<std::string, std::vector<uint8_t>> batch;
  batch["valid1"] = {4, 5, 6};
  batch["valid2"] = {7, 8, 9};
  batch[""] = {10, 11, 12}; // Invalid empty key

  // Batch should fail and not modify store
  REQUIRE_THROWS_AS(store.setBatch(batch), KVStoreException);

  // Original data should be intact
  REQUIRE(store.get("existing").value() == std::vector<uint8_t>({1, 2, 3}));
  REQUIRE_FALSE(store.get("valid1").has_value());
  REQUIRE_FALSE(store.get("valid2").has_value());

  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

// Boundary Condition Tests
TEST_CASE("KVStore handles maximum key length", "[kvstore][boundary][key]")
{
  const std::string file = "test_kvstore_max_key.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());

  KVStore store(file);

  // Test exactly at the limit
  std::string maxKey(MAX_KEY_LENGTH, 'x');
  std::vector<uint8_t> value = {1, 2, 3};

  REQUIRE_NOTHROW(store.set(maxKey, value));
  REQUIRE(store.get(maxKey).value() == value);

  // Test one byte over the limit
  std::string overKey(MAX_KEY_LENGTH + 1, 'y');
  REQUIRE_THROWS_AS(store.set(overKey, value), KVStoreException);

  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

TEST_CASE("KVStore handles maximum value length", "[kvstore][boundary][value]")
{
  const std::string file = "test_kvstore_max_value.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());

  KVStore store(file);

  std::string key = "test";

  // Test with large but valid value (smaller than max for practical testing)
  std::vector<uint8_t> largeValue(1024 * 1024, 42); // 1MB
  REQUIRE_NOTHROW(store.set(key, largeValue));
  REQUIRE(store.get(key).value() == largeValue);

  // Test empty value
  std::vector<uint8_t> emptyValue;
  REQUIRE_NOTHROW(store.set("empty", emptyValue));
  REQUIRE(store.get("empty").value() == emptyValue);

  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

TEST_CASE("KVStore rapid insert/remove cycles", "[kvstore][boundary][cycles]")
{
  const std::string file = "test_kvstore_rapid_cycles.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());

  KVStore store(file);

  std::string key = "cycle_key";
  std::vector<uint8_t> value = {1, 2, 3};

  // Rapid insert/remove cycles
  for (int i = 0; i < 100; ++i)
  {
    store.set(key, value);
    REQUIRE(store.get(key).has_value());
    store.remove(key);
    REQUIRE_FALSE(store.get(key).has_value());
  }

  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

// Performance/Stress Tests
TEST_CASE("KVStore stress test with many entries", "[kvstore][stress][large]")
{
  const std::string file = "test_kvstore_stress.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());

  KVStoreConfig cfg;
  cfg.enableBackgroundCompaction = true; // Test background compaction
  KVStore store(file, cfg);

  const int numEntries = 1000;
  std::unordered_map<std::string, std::vector<uint8_t>> testData;

  // Insert many entries
  for (int i = 0; i < numEntries; ++i)
  {
    std::string key = "stress_key_" + std::to_string(i);
    auto value = randomBytes(20 + (i % 100));
    testData[key] = value;
    store.set(key, value);
  }

  // Verify all entries
  for (const auto &[key, expectedValue] : testData)
  {
    auto actualValue = store.get(key);
    REQUIRE(actualValue.has_value());
    REQUIRE(actualValue.value() == expectedValue);
  }

  // Test persistence after restart
  store.flush();
  {
    KVStore newStore(file, cfg);
    REQUIRE(newStore.size() == numEntries);

    // Verify random subset
    for (int i = 0; i < 100; i += 10)
    {
      std::string key = "stress_key_" + std::to_string(i);
      REQUIRE(newStore.get(key).has_value());
    }
  }

  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

// File Cleanup Tests
TEST_CASE("KVStore properly cleans up temporary files", "[kvstore][cleanup][temp]")
{
  const std::string file = "test_kvstore_cleanup.bin";
  const std::string tempFile = file + ".tmp";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
  std::remove(tempFile.c_str());

  {
    KVStore store(file);
    store.set("test", {1, 2, 3});
    store.forceCompact(); // This creates and should clean up temp files
  }

  // Temporary file should not exist after compaction
  REQUIRE_FALSE(std::filesystem::exists(tempFile));

  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

TEST_CASE("KVStore handles shutdown and cleanup", "[kvstore][cleanup][shutdown]")
{
  const std::string file = "test_kvstore_shutdown.bin";
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());

  {
    KVStoreConfig cfg;
    cfg.enableBackgroundCompaction = true;
    KVStore store(file, cfg);

    // Add some data
    for (int i = 0; i < 10; ++i)
    {
      store.set("key_" + std::to_string(i), randomBytes(100));
    }

    // Explicit shutdown
    store.shutdown();
  } // Destructor should handle cleanup gracefully

  // Files should exist (data was persisted)
  bool filesExist = std::filesystem::exists(file) || std::filesystem::exists(file + ".log");
  REQUIRE(filesExist);

  // Should be able to reopen
  {
    KVStore newStore(file);
    REQUIRE_NOTHROW(newStore.size());
  }

  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

// ===========================================================================
// TTL (native per-key auto-expiry) test suite
// Architecture: architecture/iora/kvstore_ttl.json (KTP-1..11)
// ===========================================================================

namespace ttltest
{
using sysclock = std::chrono::system_clock;

// A fast, manual-compaction config so active-eviction timing is deterministic
// (small tick, wait >= 2x tick), per the architecture's ctestNote.
inline KVStoreConfig fastConfig(int tickMs = 20)
{
  KVStoreConfig c;
  c.ttlTickDuration = std::chrono::milliseconds(tickMs);
  c.enableBackgroundCompaction = false;
  return c;
}

// Large tick so the active timer does NOT fire during a sub-second test (only
// the lazy-read backstop applies). Fewer wheels keep WHEEL_MAX_RANGE (~7.6 days)
// well under the validated ceiling while a 10s tick guarantees no active fire.
inline KVStoreConfig noFireConfig()
{
  KVStoreConfig c;
  c.ttlTickDuration = std::chrono::milliseconds(10000);
  c.ttlTicksPerWheel = 256;
  c.ttlNumWheels = 2;
  c.enableBackgroundCompaction = false;
  return c;
}

inline void cleanup(const std::string &file)
{
  std::remove(file.c_str());
  std::remove((file + ".log").c_str());
}

// Absolute epoch-ms for now()+seconds, for crafting log/snapshot expiry fields.
inline int64_t toFutureMs(int seconds)
{
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             (sysclock::now() + std::chrono::seconds(seconds)).time_since_epoch())
      .count();
}

// CRC32 identical to KVStore's, for crafting log/snapshot bytes in tests.
inline uint32_t crc32(const std::vector<uint8_t> &data)
{
  if (data.empty())
    return 0;
  uint32_t crc = 0xFFFFFFFF;
  for (uint8_t b : data)
  {
    crc ^= b;
    for (int i = 0; i < 8; ++i)
    {
      crc = (crc & 1) ? ((crc >> 1) ^ 0xEDB88320) : (crc >> 1);
    }
  }
  return ~crc;
}

template <typename T> inline void appendRaw(std::vector<uint8_t> &buf, T v)
{
  const auto *p = reinterpret_cast<const uint8_t *>(&v);
  buf.insert(buf.end(), p, p + sizeof(T));
}

// Build a framed log entry [totalLen][payload][crc]. truncateTo, if > 0, writes
// only that many bytes of the framed record (simulating a torn write).
inline std::vector<uint8_t> buildLogEntry(char op, const std::string &key, int64_t expiry,
                                          const std::vector<uint8_t> &value,
                                          bool corruptCrc = false)
{
  const bool hasExpiry = (op == 'E' || op == 'X');
  const bool hasValue = (op == 'E' || op == 'S');
  std::vector<uint8_t> payload;
  payload.push_back(static_cast<uint8_t>(op));
  appendRaw(payload, static_cast<uint32_t>(key.size()));
  payload.insert(payload.end(), key.begin(), key.end());
  if (hasExpiry)
    appendRaw(payload, expiry);
  if (hasValue)
  {
    appendRaw(payload, static_cast<uint32_t>(value.size()));
    payload.insert(payload.end(), value.begin(), value.end());
  }
  uint32_t crc = crc32(payload);
  if (corruptCrc)
    crc ^= 0xA5A5A5A5;

  std::vector<uint8_t> framed;
  appendRaw(framed, static_cast<uint32_t>(payload.size() + 4));
  framed.insert(framed.end(), payload.begin(), payload.end());
  appendRaw(framed, crc);
  return framed;
}

inline void appendToLog(const std::string &file, const std::vector<uint8_t> &bytes,
                        size_t truncateTo = 0)
{
  std::ofstream out(file + ".log", std::ios::binary | std::ios::app);
  size_t n = (truncateTo > 0 && truncateTo < bytes.size()) ? truncateTo : bytes.size();
  out.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(n));
}

// Run f on a worker; return false (and detach) if it does not finish in time, so
// a lost-wakeup/deadlock regression manifests as a failed REQUIRE rather than a
// hung suite. f must own all state it touches.
inline bool runWithWatchdog(std::function<void()> f, std::chrono::milliseconds timeout)
{
  auto done = std::make_shared<std::atomic<bool>>(false);
  std::thread t(
      [f, done]()
      {
        f();
        done->store(true);
      });
  auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline && !done->load())
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  if (done->load())
  {
    t.join();
    return true;
  }
  t.detach();
  return false;
}
} // namespace ttltest

TEST_CASE("KVStore TTL unit semantics", "[kvstore][ttl][unit]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_unit.bin";
  cleanup(file);
  KVStore store(file, fastConfig());

  SECTION("ttl<=0 throws (set/setString/setBatch)")
  {
    REQUIRE_THROWS_AS(store.set("k", {1}, std::chrono::seconds(0)), KVStoreException);
    REQUIRE_THROWS_AS(store.set("k", {1}, std::chrono::seconds(-5)), KVStoreException);
    REQUIRE_THROWS_AS(store.setString("k", "v", std::chrono::seconds(0)), KVStoreException);
    std::unordered_map<std::string, std::vector<uint8_t>> b{{"a", {1}}};
    REQUIRE_THROWS_AS(store.setBatch(b, std::chrono::seconds(0)), KVStoreException);
  }

  SECTION("set+ttl arms and ttl() reports remaining")
  {
    store.set("k", {1, 2}, std::chrono::seconds(100));
    auto t = store.ttl("k");
    REQUIRE(t.has_value());
    REQUIRE(t.value() <= std::chrono::seconds(100));
    REQUIRE(t.value() >= std::chrono::seconds(98));
    REQUIRE(store.get("k").has_value());
  }

  SECTION("ttl() nullopt for permanent / absent; 0s for <1s remaining")
  {
    store.set("perm", {1});
    REQUIRE_FALSE(store.ttl("perm").has_value()); // permanent
    REQUIRE_FALSE(store.ttl("missing").has_value()); // absent
    store.expireAt("perm", sysclock::now() + std::chrono::milliseconds(500));
    auto t = store.ttl("perm");
    REQUIRE(t.has_value());
    REQUIRE(t.value() == std::chrono::seconds(0)); // <1s remaining
  }

  SECTION("expireAt set/replace on existing key; silent no-op on absent")
  {
    store.set("k", {1});
    REQUIRE_FALSE(store.ttl("k").has_value());
    store.expireAt("k", sysclock::now() + std::chrono::seconds(50));
    REQUIRE(store.ttl("k").has_value());
    store.expireAt("k", sysclock::now() + std::chrono::seconds(200));
    REQUIRE(store.ttl("k").value() >= std::chrono::seconds(150));
    REQUIRE_NOTHROW(store.expireAt("absent", sysclock::now() + std::chrono::seconds(10)));
    REQUIRE_FALSE(store.exists("absent"));
  }

  SECTION("persist clears expiry + key survives past old deadline")
  {
    store.set("k", {7}, std::chrono::seconds(100));
    REQUIRE(store.ttl("k").has_value());
    store.persist("k");
    REQUIRE_FALSE(store.ttl("k").has_value());
    REQUIRE(store.get("k").has_value());
    REQUIRE_NOTHROW(store.persist("missing")); // no-op absent
    store.set("perm", {1});
    REQUIRE_NOTHROW(store.persist("perm")); // no-op already-permanent
  }

  SECTION("plain set / setBatch clears existing ttl (Redis-style)")
  {
    store.set("k", {1}, std::chrono::seconds(100));
    REQUIRE(store.ttl("k").has_value());
    store.set("k", {2}); // plain overwrite clears ttl
    REQUIRE_FALSE(store.ttl("k").has_value());

    store.set("b", {1}, std::chrono::seconds(100));
    std::unordered_map<std::string, std::vector<uint8_t>> batch{{"b", {9}}};
    store.setBatch(batch); // plain batch clears ttl
    REQUIRE_FALSE(store.ttl("b").has_value());
  }

  SECTION("setBatch+ttl arms all keys")
  {
    std::unordered_map<std::string, std::vector<uint8_t>> batch{
        {"x", {1}}, {"y", {2}}, {"z", {3}}};
    store.setBatch(batch, std::chrono::seconds(100));
    REQUIRE(store.ttl("x").has_value());
    REQUIRE(store.ttl("y").has_value());
    REQUIRE(store.ttl("z").has_value());
  }

  SECTION("remove cancels timer and clears expiry")
  {
    store.set("k", {1}, std::chrono::seconds(100));
    store.remove("k");
    REQUIRE_FALSE(store.exists("k"));
    REQUIRE_FALSE(store.ttl("k").has_value());
  }

  cleanup(file);
}

TEST_CASE("KVStore TTL lazy-read backstop (all 6 readers)", "[kvstore][ttl][unit][lazy]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_lazy.bin";
  cleanup(file);
  // Large tick so the active timer does NOT fire during the test — only the
  // lazy-read backstop hides the expired key.
  KVStore store(file, noFireConfig());

  // expireAt with a past timestamp => immediately eligible, but no read/tick yet.
  store.set("k", {1, 2, 3});
  store.getString("k"); // warm the cache
  store.expireAt("k", sysclock::now() - std::chrono::seconds(1));

  SECTION("get hides expired (and corrects the warm cache)")
  {
    REQUIRE_FALSE(store.get("k").has_value());
  }
  SECTION("getString hides expired")
  {
    REQUIRE_FALSE(store.getString("k").has_value());
  }
  SECTION("exists hides expired")
  {
    REQUIRE_FALSE(store.exists("k"));
  }
  SECTION("keys hides expired")
  {
    REQUIRE(store.keys().empty());
  }
  SECTION("keysWithPrefix hides expired")
  {
    REQUIRE(store.keysWithPrefix("k").empty());
  }
  SECTION("getBatch hides expired")
  {
    auto r = store.getBatch({"k"});
    REQUIRE(r.find("k") == r.end());
  }
  SECTION("size() and exists() agree after expiry")
  {
    store.set("alive", {9});
    REQUIRE(store.size() == 1); // only 'alive' counts; 'k' expired
    REQUIRE(store.exists("alive"));
    REQUIRE_FALSE(store.exists("k"));
  }

  cleanup(file);
}

TEST_CASE("KVStore TTL cache returns expired-then-corrected", "[kvstore][ttl][unit][cache]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_cache.bin";
  cleanup(file);
  KVStore store(file, noFireConfig()); // no active fire during test

  // Cached key past its embedded deadline reads absent.
  store.set("k", {5});
  store.expireAt("k", sysclock::now() + std::chrono::milliseconds(40));
  REQUIRE(store.get("k").has_value()); // warms cache with embedded expiry
  std::this_thread::sleep_for(std::chrono::milliseconds(80));
  REQUIRE_FALSE(store.get("k").has_value()); // time-lapsed cache entry → absent

  // Cached key after persist reads present (cache corrected).
  store.set("k2", {6});
  store.expireAt("k2", sysclock::now() + std::chrono::milliseconds(40));
  REQUIRE(store.get("k2").has_value());
  store.persist("k2"); // invalidates the cache entry
  std::this_thread::sleep_for(std::chrono::milliseconds(80));
  REQUIRE(store.get("k2").has_value()); // still present (now permanent)

  cleanup(file);
}

TEST_CASE("KVStore TTL active eviction fires without a read", "[kvstore][ttl][active]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_active.bin";
  cleanup(file);

  {
    KVStore store(file, fastConfig(20));
    store.set("k", {1, 2, 3}, std::chrono::seconds(1)); // smallest positive ttl
    // expireAt with a near-future absolute deadline for a tighter active test.
    store.expireAt("k", sysclock::now() + std::chrono::milliseconds(40));
    // Do NOT read. Wait past the deadline + several ticks.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    REQUIRE_FALSE(store.exists("k")); // actively evicted
  }
  // Eviction wrote a 'D' — the key must be gone on reload too.
  {
    KVStore store(file, fastConfig(20));
    REQUIRE_FALSE(store.exists("k"));
  }
  cleanup(file);
}

TEST_CASE("KVStore TTL generation guard", "[kvstore][ttl][active][generation]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_gen.bin";
  cleanup(file);
  KVStore store(file, fastConfig(20));

  SECTION("expireAt-extend before stale fire does not evict")
  {
    store.expireAt("k", sysclock::now()); // absent → no-op
    store.set("k", {1});
    store.expireAt("k", sysclock::now() + std::chrono::milliseconds(30));
    store.expireAt("k", sysclock::now() + std::chrono::seconds(100)); // cancels old, fresh id
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    REQUIRE(store.exists("k")); // old timer (if it fired) was stale → no evict
    REQUIRE(store.ttl("k").value() >= std::chrono::seconds(90));
  }

  SECTION("persist before stale fire does not evict")
  {
    store.set("k", {1});
    store.expireAt("k", sysclock::now() + std::chrono::milliseconds(30));
    store.persist("k");
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    REQUIRE(store.exists("k"));
    REQUIRE_FALSE(store.ttl("k").has_value());
  }

  SECTION("remove before stale fire is a clean no-op")
  {
    store.set("k", {1}, std::chrono::seconds(1));
    store.expireAt("k", sysclock::now() + std::chrono::milliseconds(30));
    store.remove("k");
    store.set("k", {2}); // re-create permanent
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    REQUIRE(store.exists("k")); // stale timer must not evict the re-created key
    REQUIRE_FALSE(store.ttl("k").has_value());
  }

  cleanup(file);
}

TEST_CASE("KVStore TTL staged re-arm (clamped far-future)", "[kvstore][ttl][active][rearm]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_rearm.bin";
  cleanup(file);
  // WHEEL_MAX_RANGE = 20ms * 2^1 = 40ms, so a 250ms TTL clamps and must re-arm
  // several times (intermediate fires) before evicting.
  KVStoreConfig cfg = fastConfig(20);
  cfg.ttlTicksPerWheel = 2;
  cfg.ttlNumWheels = 1;
  KVStore store(file, cfg);

  store.set("k", {1});
  store.expireAt("k", sysclock::now() + std::chrono::milliseconds(250));
  // Past the clamp window but before the real deadline: must still be present.
  std::this_thread::sleep_for(std::chrono::milliseconds(120));
  REQUIRE(store.exists("k")); // intermediate fires re-armed, did not evict
  // After the real deadline + a few ticks: evicted.
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  REQUIRE_FALSE(store.exists("k"));

  cleanup(file);
}

TEST_CASE("KVStore TTL clear cancels all timers", "[kvstore][ttl][active][clear]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_clear.bin";
  cleanup(file);
  {
    KVStore store(file, fastConfig(20));
    store.set("a", {1}, std::chrono::seconds(100));
    store.set("b", {2}, std::chrono::seconds(100));
    store.expireAt("a", sysclock::now() + std::chrono::milliseconds(40));
    store.clear();
    REQUIRE(store.size() == 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    REQUIRE(store.size() == 0); // no leaked timer re-populates / crashes
  }
  {
    KVStore store(file, fastConfig(20));
    REQUIRE(store.size() == 0); // reload shows empty
  }
  cleanup(file);
}

TEST_CASE("KVStore TTL persistence across restart", "[kvstore][ttl][persistence]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_persist.bin";
  cleanup(file);

  SECTION("TTL survives restart with the same absolute deadline")
  {
    {
      KVStore store(file, noFireConfig());
      store.set("k", {1, 2}, std::chrono::seconds(3600));
    }
    {
      KVStore store(file, noFireConfig());
      REQUIRE(store.exists("k"));
      auto t = store.ttl("k");
      REQUIRE(t.has_value());
      REQUIRE(t.value() > std::chrono::seconds(3500));
    }
  }

  SECTION("already-expired entry dropped on load")
  {
    {
      KVStore store(file, noFireConfig());
      store.set("k", {1});
      store.expireAt("k", sysclock::now() + std::chrono::milliseconds(50));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    {
      KVStore store(file, noFireConfig());
      REQUIRE_FALSE(store.exists("k")); // expired-on-load → dropped
    }
  }

  SECTION("persist (X INT64_MIN) and expireAt (X) replay; D replay")
  {
    {
      KVStore store(file, noFireConfig());
      store.set("p", {1}, std::chrono::seconds(3600));
      store.persist("p"); // 'X' INT64_MIN
      store.set("e", {2});
      store.expireAt("e", sysclock::now() + std::chrono::seconds(3600)); // 'X'
      store.set("d", {3}, std::chrono::seconds(3600));
      store.remove("d"); // 'D'
    }
    {
      KVStore store(file, noFireConfig());
      REQUIRE(store.exists("p"));
      REQUIRE_FALSE(store.ttl("p").has_value()); // persisted → permanent
      REQUIRE(store.exists("e"));
      REQUIRE(store.ttl("e").has_value()); // expireAt survived
      REQUIRE_FALSE(store.exists("d")); // removed
    }
  }

  cleanup(file);
}

TEST_CASE("KVStore TTL compaction drops expired survivors (v2)", "[kvstore][ttl][persistence][compaction]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_compact.bin";
  cleanup(file);
  {
    KVStore store(file, noFireConfig());
    store.set("alive", {1}, std::chrono::seconds(3600));
    store.set("perm", {2});
    store.set("expired", {3});
    store.expireAt("expired", sysclock::now() + std::chrono::milliseconds(40));
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    store.forceCompact(); // survivors = {alive, perm}; expired dropped + cache-erased
    REQUIRE(store.exists("alive"));
    REQUIRE(store.exists("perm"));
    REQUIRE_FALSE(store.exists("expired"));
    REQUIRE(store.size() == 2);
  }
  {
    KVStore store(file, noFireConfig());
    REQUIRE(store.exists("alive"));
    REQUIRE(store.ttl("alive").has_value()); // v2 per-entry expiry round-trips
    REQUIRE(store.exists("perm"));
    REQUIRE_FALSE(store.ttl("perm").has_value());
    REQUIRE_FALSE(store.exists("expired"));
  }
  cleanup(file);
}

TEST_CASE("KVStore TTL v1 snapshot loads as eternal", "[kvstore][ttl][persistence][v1]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_v1.bin";
  cleanup(file);

  // Craft a v1 snapshot: magic, version=1, count, then [keyLen][key][valLen][value].
  {
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    uint32_t magic = 0xB1A2C3D4;
    uint32_t version = 1;
    uint32_t count = 1;
    out.write(reinterpret_cast<const char *>(&magic), 4);
    out.write(reinterpret_cast<const char *>(&version), 4);
    out.write(reinterpret_cast<const char *>(&count), 4);
    std::string key = "old";
    std::vector<uint8_t> value = {9, 9};
    uint32_t keyLen = key.size();
    uint32_t valLen = value.size();
    out.write(reinterpret_cast<const char *>(&keyLen), 4);
    out.write(key.data(), keyLen);
    out.write(reinterpret_cast<const char *>(&valLen), 4);
    out.write(reinterpret_cast<const char *>(value.data()), valLen);
  }

  KVStore store(file, noFireConfig());
  REQUIRE(store.exists("old"));
  REQUIRE(store.get("old").value() == std::vector<uint8_t>({9, 9}));
  REQUIRE_FALSE(store.ttl("old").has_value()); // v1 → eternal

  cleanup(file);
}

TEST_CASE("KVStore TTL log corruption + sentinel handling", "[kvstore][ttl][persistence][corruption]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_corrupt.bin";

  SECTION("E with INT64_MIN expiry is dropped as corrupt")
  {
    cleanup(file);
    appendToLog(file, buildLogEntry('E', "bad", std::numeric_limits<int64_t>::min(), {1}));
    KVStore store(file, noFireConfig());
    REQUIRE_FALSE(store.exists("bad"));
  }

  SECTION("out-of-window (absurd) expiry rejected")
  {
    cleanup(file);
    appendToLog(file, buildLogEntry('E', "future", 99999999999999LL, {1})); // > year ~2300
    KVStore store(file, noFireConfig());
    REQUIRE_FALSE(store.exists("future"));
  }

  SECTION("corrupt CRC entry skipped")
  {
    cleanup(file);
    appendToLog(file, buildLogEntry('S', "good", 0, {1}));
    appendToLog(file, buildLogEntry('E', "bad", toFutureMs(3600), {2}, /*corruptCrc=*/true));
    KVStore store(file, noFireConfig());
    REQUIRE(store.exists("good"));
    REQUIRE_FALSE(store.exists("bad")); // CRC mismatch → skipped
  }

  SECTION("truncated E/X/D entries bounds-rejected (no over-read)")
  {
    for (char op : {'E', 'X', 'D'})
    {
      cleanup(file);
      appendToLog(file, buildLogEntry('S', "good", 0, {1}));
      auto entry = buildLogEntry(op, "k", toFutureMs(3600), {2, 3, 4});
      appendToLog(file, entry, /*truncateTo=*/entry.size() - 3); // tear the tail
      KVStore store(file, noFireConfig());
      REQUIRE_NOTHROW(store.size()); // must not crash / over-read
      REQUIRE(store.exists("good"));
    }
    cleanup(file);
  }

  SECTION("orphan X (no matching key) ignored")
  {
    cleanup(file);
    appendToLog(file, buildLogEntry('X', "ghost", toFutureMs(3600), {}));
    KVStore store(file, noFireConfig());
    REQUIRE_FALSE(store.exists("ghost"));
  }

  SECTION("interior-field overrun rejected (honest totalLen, short interior)")
  {
    // Craft a framed 'E' whose declared totalLen is internally consistent (so it
    // passes the outer framing read + CRC) but whose keyLen claims more bytes
    // than remain for the expiry/value/CRC — exercising the interior ptr+N>end
    // bounds branches rather than the outer framing reject.
    cleanup(file);
    appendToLog(file, buildLogEntry('S', "good", 0, {1}));
    std::vector<uint8_t> payload;
    payload.push_back(static_cast<uint8_t>('E'));
    appendRaw(payload, static_cast<uint32_t>(1000)); // keyLen far exceeds payload
    payload.push_back('k');                          // only 1 key byte present
    uint32_t crc = crc32(payload);
    std::vector<uint8_t> framed;
    appendRaw(framed, static_cast<uint32_t>(payload.size() + 4));
    framed.insert(framed.end(), payload.begin(), payload.end());
    appendRaw(framed, crc);
    appendToLog(file, framed);
    KVStore store(file, noFireConfig());
    REQUIRE_NOTHROW(store.size()); // no over-read / crash
    REQUIRE(store.exists("good"));
  }

  cleanup(file);
}

TEST_CASE("KVStore TTL config validation", "[kvstore][ttl][config]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_cfg.bin";
  cleanup(file);

  auto mk = [&](KVStoreConfig c) { KVStore s(file, c); };

  KVStoreConfig c;
  c.ttlTickDuration = std::chrono::milliseconds(0);
  REQUIRE_THROWS_AS(mk(c), KVStoreException);

  c = KVStoreConfig{};
  c.ttlNumWheels = 0;
  REQUIRE_THROWS_AS(mk(c), KVStoreException);

  c = KVStoreConfig{};
  c.ttlTicksPerWheel = 100; // not a power of two
  REQUIRE_THROWS_AS(mk(c), KVStoreException);

  c = KVStoreConfig{};
  c.ttlTicksPerWheel = 0;
  REQUIRE_THROWS_AS(mk(c), KVStoreException);

  c = KVStoreConfig{};
  c.ttlTickDuration = std::chrono::milliseconds(1000);
  c.ttlTicksPerWheel = 65536;
  c.ttlNumWheels = 8; // WHEEL_MAX_RANGE overflows the supported maximum
  REQUIRE_THROWS_AS(mk(c), KVStoreException);

  REQUIRE_NOTHROW(mk(KVStoreConfig{})); // defaults are valid
  cleanup(file);
}

TEST_CASE("KVStore TTL post-shutdown contract", "[kvstore][ttl][shutdown]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_postshutdown.bin";
  cleanup(file);
  KVStore store(file, fastConfig(20));
  store.set("k", {1});
  store.shutdown();

  // set/setString/setBatch/expireAt throw post-shutdown.
  REQUIRE_THROWS_AS(store.set("a", {1}), KVStoreException);
  REQUIRE_THROWS_AS(store.set("a", {1}, std::chrono::seconds(5)), KVStoreException);
  REQUIRE_THROWS_AS(store.setString("a", "v"), KVStoreException);
  std::unordered_map<std::string, std::vector<uint8_t>> b{{"a", {1}}};
  REQUIRE_THROWS_AS(store.setBatch(b), KVStoreException);
  REQUIRE_THROWS_AS(store.setBatch(b, std::chrono::seconds(5)), KVStoreException);
  REQUIRE_THROWS_AS(store.expireAt("k", sysclock::now() + std::chrono::seconds(5)),
                    KVStoreException);

  // remove/persist are no-ops post-shutdown (do NOT throw).
  REQUIRE_NOTHROW(store.remove("k"));
  REQUIRE_NOTHROW(store.persist("k"));

  // Double shutdown is a no-op.
  REQUIRE_NOTHROW(store.shutdown());
  cleanup(file);
}

TEST_CASE("KVStore TTL lifecycle: never-armed + parked-worker shutdown", "[kvstore][ttl][shutdown][lifecycle]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_lifecycle.bin";

  SECTION("never-armed store shuts down promptly (skips drain/join)")
  {
    cleanup(file);
    REQUIRE(runWithWatchdog(
        [file]()
        {
          KVStore store(file, fastConfig(20));
          store.set("k", {1}); // no TTL ever → no wheel/worker
        },
        std::chrono::seconds(5)));
  }

  SECTION("parked-worker shutdown returns promptly (no lost-wakeup hang)")
  {
    cleanup(file);
    REQUIRE(runWithWatchdog(
        [file]()
        {
          KVStore store(file, fastConfig(20));
          store.set("k", {1}, std::chrono::seconds(3600)); // armed, not due → worker parks
          std::this_thread::sleep_for(std::chrono::milliseconds(60));
          store.shutdown(); // must wake the parked worker and join
        },
        std::chrono::seconds(5)));
  }

  cleanup(file);
}

TEST_CASE("KVStore TTL concurrency (atomic + assert-after-join)", "[kvstore][ttl][concurrency]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_concurrent.bin";
  cleanup(file);

  std::atomic<bool> sawException{false};
  std::atomic<int> opCount{0};

  {
    KVStore store(file, fastConfig(20));

    std::vector<std::thread> threads;
    // Writers set TTL keys; readers get; an extender keeps moving deadlines.
    for (int t = 0; t < 4; ++t)
    {
      threads.emplace_back(
          [&store, &sawException, &opCount, t]()
          {
            try
            {
              for (int i = 0; i < 200; ++i)
              {
                std::string key = "k" + std::to_string((t * 200 + i) % 50);
                store.set(key, {static_cast<uint8_t>(i)}, std::chrono::seconds(1));
                (void)store.get(key);
                if (i % 3 == 0)
                {
                  store.expireAt(key, sysclock::now() + std::chrono::milliseconds(30));
                }
                if (i % 7 == 0)
                {
                  store.persist(key);
                }
                opCount.fetch_add(1);
              }
            }
            catch (...)
            {
              sawException.store(true);
            }
          });
    }
    for (auto &th : threads)
    {
      th.join();
    }
    // Let active eviction churn against ongoing reads.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    (void)store.size();
  }

  REQUIRE_FALSE(sawException.load());
  REQUIRE(opCount.load() == 800);

  // Reload must be consistent (no crash / over-read after concurrent eviction).
  {
    KVStore store(file, fastConfig(20));
    REQUIRE_NOTHROW(store.size());
  }
  cleanup(file);
}

// ── Extended concurrency / lifecycle coverage (testStrategy.concurrency_tsan) ──

TEST_CASE("KVStore TTL N-threads one lazy-start", "[kvstore][ttl][concurrency][lazystart]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_nstart.bin";
  cleanup(file);
  std::atomic<bool> sawException{false};
  {
    KVStore store(file, fastConfig(20));
    std::vector<std::thread> threads;
    // Many threads racing to be the first TTL key → exactly one lazy-start.
    for (int t = 0; t < 8; ++t)
    {
      threads.emplace_back(
          [&store, &sawException, t]()
          {
            try
            {
              store.set("k" + std::to_string(t), {static_cast<uint8_t>(t)},
                        std::chrono::seconds(3600));
            }
            catch (...)
            {
              sawException.store(true);
            }
          });
    }
    for (auto &th : threads)
      th.join();
    REQUIRE_FALSE(sawException.load());
    // All keys armed (schedule() returned a valid id → wheel.start() ran).
    for (int t = 0; t < 8; ++t)
    {
      REQUIRE(store.ttl("k" + std::to_string(t)).has_value());
    }
  }
  cleanup(file);
}

TEST_CASE("KVStore TTL cache fast-path racing eviction (no UAF)", "[kvstore][ttl][concurrency][cache]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_cacherace.bin";
  cleanup(file);
  std::atomic<bool> sawException{false};
  {
    KVStore store(file, fastConfig(20));
    std::atomic<bool> stop{false};
    // Readers hammer the cache fast path while keys actively evict + re-set.
    std::vector<std::thread> readers;
    for (int r = 0; r < 4; ++r)
    {
      readers.emplace_back(
          [&store, &stop, &sawException]()
          {
            try
            {
              while (!stop.load())
              {
                for (int i = 0; i < 20; ++i)
                {
                  auto v = store.get("k" + std::to_string(i));
                  (void)v; // returned BY VALUE — must never dangle vs an erase
                }
              }
            }
            catch (...)
            {
              sawException.store(true);
            }
          });
    }
    for (int round = 0; round < 200; ++round)
    {
      for (int i = 0; i < 20; ++i)
      {
        store.set("k" + std::to_string(i), {static_cast<uint8_t>(i)}, std::chrono::seconds(1));
        store.expireAt("k" + std::to_string(i),
                       std::chrono::system_clock::now() + std::chrono::milliseconds(25));
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    stop.store(true);
    for (auto &th : readers)
      th.join();
  }
  REQUIRE_FALSE(sawException.load());
  cleanup(file);
}

TEST_CASE("KVStore TTL eviction racing compact()", "[kvstore][ttl][concurrency][compact]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_evictcompact.bin";
  cleanup(file);
  std::atomic<bool> sawException{false};
  REQUIRE(runWithWatchdog(
      [file, &sawException]()
      {
        KVStore store(file, fastConfig(20));
        std::atomic<bool> stop{false};
        std::thread compactor(
            [&store, &stop, &sawException]()
            {
              try
              {
                while (!stop.load())
                {
                  store.forceCompact(); // public compact() → compactLocked, no recursive lock
                  std::this_thread::sleep_for(std::chrono::milliseconds(3));
                }
              }
              catch (...)
              {
                sawException.store(true);
              }
            });
        for (int round = 0; round < 150; ++round)
        {
          for (int i = 0; i < 10; ++i)
          {
            store.set("k" + std::to_string(i), {static_cast<uint8_t>(i)},
                      std::chrono::seconds(1));
            store.expireAt("k" + std::to_string(i),
                           std::chrono::system_clock::now() + std::chrono::milliseconds(20));
          }
          std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        stop.store(true);
        compactor.join();
      },
      std::chrono::seconds(20)));
  REQUIRE_FALSE(sawException.load());
  // Reload is consistent (no over-read / corruption from concurrent compaction).
  {
    KVStore store(file, fastConfig(20));
    REQUIRE_NOTHROW(store.size());
  }
  cleanup(file);
}

TEST_CASE("KVStore TTL eviction with background-compaction disabled (no recursive lock)",
          "[kvstore][ttl][concurrency][recursive]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_norecurse.bin";
  cleanup(file);
  REQUIRE(runWithWatchdog(
      [file]()
      {
        KVStoreConfig cfg = fastConfig(20);
        cfg.enableBackgroundCompaction = false; // maybeCompact → compactLocked inline
        cfg.maxLogSizeBytes = 2048;              // force frequent inline compaction
        KVStore store(file, cfg);
        for (int i = 0; i < 300; ++i)
        {
          store.set("k" + std::to_string(i % 20), randomBytes(64), std::chrono::seconds(1));
          store.expireAt("k" + std::to_string(i % 20),
                         std::chrono::system_clock::now() + std::chrono::milliseconds(15));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(120)); // let evictions churn
        (void)store.size();
      },
      std::chrono::seconds(20))); // a recursive-lock deadlock would time out here
  cleanup(file);
}

TEST_CASE("KVStore TTL concurrent flush()", "[kvstore][ttl][concurrency][flush]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_flush.bin";
  cleanup(file);
  std::atomic<bool> sawException{false};
  {
    KVStore store(file, fastConfig(20));
    std::atomic<bool> stop{false};
    std::vector<std::thread> flushers;
    for (int f = 0; f < 4; ++f)
    {
      flushers.emplace_back(
          [&store, &stop, &sawException]()
          {
            try
            {
              while (!stop.load())
              {
                store.flush();
              }
            }
            catch (...)
            {
              sawException.store(true);
            }
          });
    }
    for (int i = 0; i < 500; ++i)
    {
      store.set("k" + std::to_string(i % 30), {static_cast<uint8_t>(i)}, std::chrono::seconds(60));
    }
    stop.store(true);
    for (auto &th : flushers)
      th.join();
  }
  REQUIRE_FALSE(sawException.load());
  cleanup(file);
}

TEST_CASE("KVStore TTL shutdown drains enqueued evictions (no lost 'D')", "[kvstore][ttl][concurrency][drain]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_drain.bin";
  cleanup(file);
  {
    // Large tick: the active tick thread will NOT fire before shutdown, so the
    // due timers are fired by wheel.drain() at shutdown (isolates the drain path).
    KVStore store(file, noFireConfig());
    for (int i = 0; i < 40; ++i)
    {
      store.set("k" + std::to_string(i), {static_cast<uint8_t>(i)}, std::chrono::seconds(3600));
      // Make each due now so drain() fires + evicts it.
      store.expireAt("k" + std::to_string(i),
                     std::chrono::system_clock::now() - std::chrono::milliseconds(1));
    }
    store.shutdown(); // step 2 drain enqueues all due → worker evicts → durable 'D'
    REQUIRE(store.ttlEvictionWriteErrorCount() == 0); // every 'D' was journalled
  }
  // None of the drained-and-evicted keys survive reload.
  {
    KVStore store(file, noFireConfig());
    REQUIRE(store.size() == 0);
  }
  cleanup(file);
}

TEST_CASE("KVStore TTL shutdown during clamped re-arm window (bounded drain, no hang)",
          "[kvstore][ttl][concurrency][rearmdrain]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_rearmdrain.bin";
  cleanup(file);
  REQUIRE(runWithWatchdog(
      [file]()
      {
        KVStoreConfig cfg = fastConfig(20);
        cfg.ttlTicksPerWheel = 2;
        cfg.ttlNumWheels = 1; // WHEEL_MAX_RANGE = 40ms → long TTLs re-arm repeatedly
        KVStore store(file, cfg);
        for (int i = 0; i < 20; ++i)
        {
          store.set("k" + std::to_string(i), {static_cast<uint8_t>(i)},
                    std::chrono::seconds(3600)); // clamps → intermediate fires → RE-ARM
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(60)); // mid re-arm churn
        // shutdown drains: a RE-ARM closure run during drain hits a non-accepting
        // schedule() → InvalidTimerId → does NOT enqueue → drain terminates.
        store.shutdown();
      },
      std::chrono::seconds(10)));
  // Reload: the (still-future) keys survive with their persisted deadlines.
  {
    KVStoreConfig cfg = fastConfig(20);
    cfg.ttlTicksPerWheel = 2;
    cfg.ttlNumWheels = 1;
    KVStore store(file, cfg);
    REQUIRE(store.size() == 20);
  }
  cleanup(file);
}

TEST_CASE("KVStore TTL same-second mass-expiry herd at shutdown", "[kvstore][ttl][concurrency][herd]")
{
  using namespace ttltest;
  const std::string file = "test_kvstore_ttl_herd.bin";
  cleanup(file);
  REQUIRE(runWithWatchdog(
      [file]()
      {
        KVStore store(file, noFireConfig());
        for (int i = 0; i < 200; ++i)
        {
          store.set("k" + std::to_string(i), {static_cast<uint8_t>(i % 256)},
                    std::chrono::seconds(3600));
          store.expireAt("k" + std::to_string(i),
                         std::chrono::system_clock::now()); // all due at once
        }
        store.shutdown(); // drain fires the whole herd; must complete (bounded)
      },
      std::chrono::seconds(20)));
  // Reload consistent: all herd keys are gone (evicted or dropped-as-expired).
  {
    KVStore store(file, noFireConfig());
    REQUIRE(store.size() == 0);
  }
  cleanup(file);
}
