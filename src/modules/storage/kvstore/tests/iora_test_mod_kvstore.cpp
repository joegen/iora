// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#include "kvstore.hpp"
#include <catch2/catch.hpp>
#include <random>
#include <string>
#include <vector>
#include <cstdio>
#include <thread>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <atomic>
#include <mutex>
#include "iora/iora.hpp"
#include <dlfcn.h>

namespace {
std::vector<uint8_t> randomBytes(size_t n) {
  std::vector<uint8_t> v(n);
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, 255);
  for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(dis(gen));
  return v;
}
}

TEST_CASE("KVStore basic set/get/remove", "[kvstore]") {
  const std::string file = "test_kvstore.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  KVStore store(file);

  std::string key = "foo";
  std::vector<uint8_t> value = {1,2,3,4};
  store.set(key, value);
  auto got = store.get(key);
  REQUIRE(got.has_value());
  REQUIRE(got.value() == value);

  store.remove(key);
  REQUIRE_FALSE(store.get(key).has_value());
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
}

TEST_CASE("KVStore batch set/get", "[kvstore][batch]") {
  const std::string file = "test_kvstore_batch.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  KVStore store(file);

  std::unordered_map<std::string, std::vector<uint8_t>> batch;
  for (int i = 0; i < 10; ++i) {
    batch["key"+std::to_string(i)] = randomBytes(16);
  }
  store.setBatch(batch);
  auto keys = std::vector<std::string>{};
  for (const auto& [k, _] : batch) keys.push_back(k);
  auto result = store.getBatch(keys);
  REQUIRE(result.size() == batch.size());
  for (const auto& [k, v] : batch) {
    REQUIRE(result[k] == v);
  }
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
}

TEST_CASE("KVStore persistence and reload", "[kvstore][persistence]") {
  const std::string file = "test_kvstore_persist.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  {
    KVStore store(file);
    store.set("persist", {9,8,7,6});
  }
  {
    KVStore store(file);
    auto got = store.get("persist");
    REQUIRE(got.has_value());
    REQUIRE(got.value() == std::vector<uint8_t>({9,8,7,6}));
  }
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
}

TEST_CASE("KVStore handles large values and compaction", "[kvstore][large][compact]") {
  const std::string file = "test_kvstore_large.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  KVStoreConfig cfg;
  cfg.maxLogSizeBytes = 1024*10; // force compaction quickly
  KVStore store(file, cfg);

  std::string key = "big";
  auto value = randomBytes(4096);
  store.set(key, value);
  REQUIRE(store.get(key).value() == value);
  // Overwrite to grow log
  for (int i = 0; i < 10; ++i) {
    auto v = randomBytes(4096);
    store.set(key, v);
  }
  store.forceCompact();
  REQUIRE(store.get(key).has_value());
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
}

TEST_CASE("KVStore handles invalid operations", "[kvstore][invalid]") {
  const std::string file = "test_kvstore_invalid.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  KVStore store(file);
  REQUIRE_THROWS_AS(store.set("", {1,2,3}), KVStoreException);
  REQUIRE_THROWS_AS(store.set(std::string(MAX_KEY_LENGTH + 1, 'x'), {1,2,3}), KVStoreException);
  REQUIRE_THROWS_AS(store.set("ok", std::vector<uint8_t>(MAX_VALUE_LENGTH + 1, 1)), KVStoreException);
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
}

TEST_CASE("KVStore cache and size", "[kvstore][cache]") {
  const std::string file = "test_kvstore_cache.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
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
  std::remove((file+".log").c_str());
}

// EXTENDED TESTS - Persistence and Recovery Edge Cases
TEST_CASE("KVStore persistence with mixed operations", "[kvstore][persistence][extended]") {
  const std::string file = "test_kvstore_mixed_persist.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  
  // Phase 1: Create data with mixed operations
  {
    KVStore store(file);
    store.set("key1", {1,2,3});
    store.set("key2", {4,5,6});
    store.remove("key1"); // Remove then re-add
    store.set("key1", {7,8,9});
    store.set("key3", {10,11,12});
    store.remove("key2"); // Remove permanently
    store.flush();
  }
  
  // Phase 2: Verify persistence after restart
  {
    KVStore store(file);
    REQUIRE(store.size() == 2);
    REQUIRE(store.get("key1").value() == std::vector<uint8_t>({7,8,9}));
    REQUIRE_FALSE(store.get("key2").has_value());
    REQUIRE(store.get("key3").value() == std::vector<uint8_t>({10,11,12}));
  }
  
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
}

TEST_CASE("KVStore recovery from empty files", "[kvstore][persistence][edge]") {
  const std::string file = "test_kvstore_empty.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  
  // Create empty log file only (no snapshot)
  std::ofstream(file+".log").close();
  
  // Should handle empty log file gracefully
  KVStore store(file);
  REQUIRE(store.size() == 0);
  store.set("test", {1,2,3});
  REQUIRE(store.get("test").value() == std::vector<uint8_t>({1,2,3}));
  
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
}

// Log File Integrity and Corruption Tests
TEST_CASE("KVStore handles truncated log file", "[kvstore][corruption][log]") {
  const std::string file = "test_kvstore_truncated.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  
  // Create store with some data
  {
    KVStore store(file);
    store.set("key1", {1,2,3,4,5});
    store.set("key2", {6,7,8,9,10});
    store.flush();
  }
  
  // Truncate the log file (simulate corruption)
  {
    std::ofstream logFile(file+".log", std::ios::binary | std::ios::trunc);
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
  std::remove((file+".log").c_str());
}

TEST_CASE("KVStore handles corrupted snapshot file", "[kvstore][corruption][snapshot]") {
  const std::string file = "test_kvstore_corrupt_snapshot.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  
  // Create a corrupted snapshot file
  {
    std::ofstream corrupt(file, std::ios::binary);
    corrupt.write("BADMAGIC", 8); // Invalid magic number
  }
  
  // Should throw exception for corrupted snapshot
  REQUIRE_THROWS_AS(KVStore(file), KVStoreException);
  
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
}

// Compaction Verification Tests
TEST_CASE("KVStore compaction reduces file size", "[kvstore][compaction][size]") {
  const std::string file = "test_kvstore_compaction_size.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  
  KVStoreConfig cfg;
  cfg.maxLogSizeBytes = 1024; // Small log to force compaction
  cfg.enableBackgroundCompaction = false; // Manual control
  
  std::vector<uint8_t> finalValue;
  
  {
    KVStore store(file, cfg);
    
    // Fill store with data that will be overwritten
    std::string key = "overwrite_me";
    for (int i = 0; i < 10; ++i) {
      auto data = randomBytes(50);
      store.set(key, data);
      if (i == 9) finalValue = data; // Remember the final value
    }
    
    // Force compaction
    store.forceCompact();
    
    // Data should still be accessible
    REQUIRE(store.get(key).value() == finalValue);
  } // Destructor releases locks
  
  // Verify log file was reset
  std::error_code ec;
  if (std::filesystem::exists(file + ".log", ec) && !ec) {
    auto logSize = std::filesystem::file_size(file + ".log", ec);
    if (!ec) {
      REQUIRE(logSize == 0); // Should be empty after compaction
    }
  }
  
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
}

TEST_CASE("KVStore compaction preserves all data", "[kvstore][compaction][integrity]") {
  const std::string file = "test_kvstore_compaction_integrity.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  
  KVStoreConfig cfg;
  cfg.enableBackgroundCompaction = false;
  KVStore store(file, cfg);
  
  // Create test data
  std::unordered_map<std::string, std::vector<uint8_t>> testData;
  for (int i = 0; i < 50; ++i) {
    std::string key = "key_" + std::to_string(i);
    auto value = randomBytes(50 + (i % 100));
    testData[key] = value;
    store.set(key, value);
  }
  
  // Remove some keys to create gaps
  for (int i = 0; i < 50; i += 3) {
    std::string key = "key_" + std::to_string(i);
    store.remove(key);
    testData.erase(key);
  }
  
  // Force compaction
  store.forceCompact();
  
  // Verify all remaining data is intact
  for (const auto& [key, expectedValue] : testData) {
    auto actualValue = store.get(key);
    REQUIRE(actualValue.has_value());
    REQUIRE(actualValue.value() == expectedValue);
  }
  
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
}

// Cache Behavior Tests
TEST_CASE("KVStore cache eviction with LRU", "[kvstore][cache][lru]") {
  const std::string file = "test_kvstore_cache_lru.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  
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
  std::remove((file+".log").c_str());
}

// Concurrency Tests
TEST_CASE("KVStore concurrent read operations", "[kvstore][concurrency][reads]") {
  const std::string file = "test_kvstore_concurrent_reads.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  
  KVStore store(file);
  
  // Populate with test data
  const int numKeys = 100;
  for (int i = 0; i < numKeys; ++i) {
    std::string key = "key_" + std::to_string(i);
    std::vector<uint8_t> value = {static_cast<uint8_t>(i), static_cast<uint8_t>(i+1)};
    store.set(key, value);
  }
  
  // Concurrent read test
  const int numThreads = 4;
  std::vector<std::thread> threads;
  std::atomic<int> successCount(0);
  
  for (int t = 0; t < numThreads; ++t) {
    threads.emplace_back([&store, &successCount, numKeys, t]() {
      for (int i = t; i < numKeys; i += 4) { // Interleaved access
        std::string key = "key_" + std::to_string(i);
        auto result = store.get(key);
        if (result.has_value() && result.value()[0] == static_cast<uint8_t>(i)) {
          successCount++;
        }
      }
    });
  }
  
  for (auto& thread : threads) {
    thread.join();
  }
  
  REQUIRE(successCount == numKeys);
  
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
}

TEST_CASE("KVStore concurrent mixed operations", "[kvstore][concurrency][mixed]") {
  const std::string file = "test_kvstore_concurrent_mixed.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  
  KVStore store(file);
  std::atomic<int> operationCount(0);
  std::mutex errorMutex;
  std::vector<std::string> errors;
  
  std::vector<std::thread> threads;
  
  // Writer thread
  threads.emplace_back([&store, &operationCount, &errors, &errorMutex]() {
    try {
      for (int i = 0; i < 50; ++i) {
        std::string key = "write_" + std::to_string(i);
        std::vector<uint8_t> value = randomBytes(10);
        store.set(key, value);
        operationCount++;
      }
    } catch (const std::exception& e) {
      std::lock_guard<std::mutex> lock(errorMutex);
      errors.push_back(std::string("Writer: ") + e.what());
    }
  });
  
  // Reader thread
  threads.emplace_back([&store, &operationCount, &errors, &errorMutex]() {
    try {
      for (int i = 0; i < 100; ++i) {
        std::string key = "write_" + std::to_string(i % 50);
        auto result = store.get(key);
        operationCount++;
      }
    } catch (const std::exception& e) {
      std::lock_guard<std::mutex> lock(errorMutex);
      errors.push_back(std::string("Reader: ") + e.what());
    }
  });
  
  // Deleter thread
  threads.emplace_back([&store, &operationCount, &errors, &errorMutex]() {
    try {
      std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Let some writes happen first
      for (int i = 0; i < 25; ++i) {
        std::string key = "write_" + std::to_string(i * 2);
        store.remove(key);
        operationCount++;
      }
    } catch (const std::exception& e) {
      std::lock_guard<std::mutex> lock(errorMutex);
      errors.push_back(std::string("Deleter: ") + e.what());
    }
  });
  
  for (auto& thread : threads) {
    thread.join();
  }
  
  // Should complete without errors
  REQUIRE(errors.empty());
  REQUIRE(operationCount > 0);
  
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
}

// Exception Safety Tests
TEST_CASE("KVStore handles write failures gracefully", "[kvstore][exceptions][write]") {
  const std::string file = "/dev/null/impossible_path/test.bin"; // Invalid path
  
  // Should throw during construction when trying to create log file
  REQUIRE_THROWS_AS(KVStore(file), KVStoreException);
}

TEST_CASE("KVStore batch operation rollback on failure", "[kvstore][exceptions][batch]") {
  const std::string file = "test_kvstore_batch_rollback.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  
  KVStore store(file);
  
  // Set initial state
  store.set("existing", {1,2,3});
  
  // Create batch with one invalid entry
  std::unordered_map<std::string, std::vector<uint8_t>> batch;
  batch["valid1"] = {4,5,6};
  batch["valid2"] = {7,8,9};
  batch[""] = {10,11,12}; // Invalid empty key
  
  // Batch should fail and not modify store
  REQUIRE_THROWS_AS(store.setBatch(batch), KVStoreException);
  
  // Original data should be intact
  REQUIRE(store.get("existing").value() == std::vector<uint8_t>({1,2,3}));
  REQUIRE_FALSE(store.get("valid1").has_value());
  REQUIRE_FALSE(store.get("valid2").has_value());
  
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
}

// Boundary Condition Tests
TEST_CASE("KVStore handles maximum key length", "[kvstore][boundary][key]") {
  const std::string file = "test_kvstore_max_key.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  
  KVStore store(file);
  
  // Test exactly at the limit
  std::string maxKey(MAX_KEY_LENGTH, 'x');
  std::vector<uint8_t> value = {1,2,3};
  
  REQUIRE_NOTHROW(store.set(maxKey, value));
  REQUIRE(store.get(maxKey).value() == value);
  
  // Test one byte over the limit
  std::string overKey(MAX_KEY_LENGTH + 1, 'y');
  REQUIRE_THROWS_AS(store.set(overKey, value), KVStoreException);
  
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
}

TEST_CASE("KVStore handles maximum value length", "[kvstore][boundary][value]") {
  const std::string file = "test_kvstore_max_value.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  
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
  std::remove((file+".log").c_str());
}

TEST_CASE("KVStore rapid insert/remove cycles", "[kvstore][boundary][cycles]") {
  const std::string file = "test_kvstore_rapid_cycles.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  
  KVStore store(file);
  
  std::string key = "cycle_key";
  std::vector<uint8_t> value = {1,2,3};
  
  // Rapid insert/remove cycles
  for (int i = 0; i < 100; ++i) {
    store.set(key, value);
    REQUIRE(store.get(key).has_value());
    store.remove(key);
    REQUIRE_FALSE(store.get(key).has_value());
  }
  
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
}

// Performance/Stress Tests
TEST_CASE("KVStore stress test with many entries", "[kvstore][stress][large]") {
  const std::string file = "test_kvstore_stress.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  
  KVStoreConfig cfg;
  cfg.enableBackgroundCompaction = true; // Test background compaction
  KVStore store(file, cfg);
  
  const int numEntries = 1000;
  std::unordered_map<std::string, std::vector<uint8_t>> testData;
  
  // Insert many entries
  for (int i = 0; i < numEntries; ++i) {
    std::string key = "stress_key_" + std::to_string(i);
    auto value = randomBytes(20 + (i % 100));
    testData[key] = value;
    store.set(key, value);
  }
  
  // Verify all entries
  for (const auto& [key, expectedValue] : testData) {
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
    for (int i = 0; i < 100; i += 10) {
      std::string key = "stress_key_" + std::to_string(i);
      REQUIRE(newStore.get(key).has_value());
    }
  }
  
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
}

// File Cleanup Tests
TEST_CASE("KVStore properly cleans up temporary files", "[kvstore][cleanup][temp]") {
  const std::string file = "test_kvstore_cleanup.bin";
  const std::string tempFile = file + ".tmp";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  std::remove(tempFile.c_str());
  
  {
    KVStore store(file);
    store.set("test", {1,2,3});
    store.forceCompact(); // This creates and should clean up temp files
  }
  
  // Temporary file should not exist after compaction
  REQUIRE_FALSE(std::filesystem::exists(tempFile));
  
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
}

TEST_CASE("KVStore handles shutdown and cleanup", "[kvstore][cleanup][shutdown]") {
  const std::string file = "test_kvstore_shutdown.bin";
  std::remove(file.c_str());
  std::remove((file+".log").c_str());
  
  {
    KVStoreConfig cfg;
    cfg.enableBackgroundCompaction = true;
    KVStore store(file, cfg);
    
    // Add some data
    for (int i = 0; i < 10; ++i) {
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
  std::remove((file+".log").c_str());
}


TEST_CASE("KVStore plugin API set/get via IoraService (full integration)", "[kvstore][plugin][api][integration]")
{
  // Setup IoraService config
  iora::IoraService::Config config;
  config.server.port = 8131;
  config.state.file = "ioraservice_kvstore_state.json";
  config.log.file = "ioraservice_kvstore_log";

  // Initialize service with CLI args
  iora::IoraService::init(config);
  iora::IoraService& svc = iora::IoraService::instance();
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);

  auto pluginPathOpt = iora::util::resolveRelativePath(iora::util::getExecutableDir(), "../") + "/mod_kvstore.so";
  std::cout << "Plugin path: " << pluginPathOpt << std::endl;
  REQUIRE(std::filesystem::exists(pluginPathOpt));
  REQUIRE(svc.loadSingleModule(pluginPathOpt));


  SECTION("callExportedApi: set/get")
  {
    std::string key = "plugin_key";
    std::vector<uint8_t> value = {42, 43, 44};
    svc.callExportedApi<void, const std::string&, const std::vector<uint8_t>&>("kvstore.set", key, value);
    auto got = svc.callExportedApi<std::optional<std::vector<uint8_t>>, const std::string&>("kvstore.get", key);
    REQUIRE(got.has_value());
    REQUIRE(got.value() == value);
  }

  SECTION("Plugin reload: unload and reload shared library, data persists")
  {
    std::string key = "reload_key";
    std::vector<uint8_t> value = {99, 100, 101};
    svc.callExportedApi<void, const std::string&, const std::vector<uint8_t>&>("kvstore.set", key, value);
    REQUIRE(svc.unloadSingleModule("mod_kvstore.so"));
    REQUIRE(svc.loadSingleModule(pluginPathOpt));
    auto got = svc.callExportedApi<std::optional<std::vector<uint8_t>>, const std::string&>("kvstore.get", key);
    REQUIRE(got.has_value());
    REQUIRE(got.value() == value);
  }

  iora::util::removeFilesContainingAny({"ioraservice_kvstore_log", "ioraservice_kvstore_state.json", "test_kvstore_plugin_api.bin", "test_kvstore_plugin_api.bin.log"});
}

