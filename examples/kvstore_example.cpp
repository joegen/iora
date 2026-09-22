// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file kvstore_example.cpp
/// \brief Flagship, CI-built example for iora::storage::KVStore (docs/storage/kvstore.md).
///        Exercises the headline paths: in-memory + persistent stores, per-key TTL,
///        expireAt/ttl/persist, binary values, batch set/get, prefix ops, and shutdown.

#include "iora/storage/kvstore.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using iora::storage::KVStore;

namespace
{

/// Always-active check (NOT assert): asserts compile out under -DNDEBUG, which
/// is the project's default Release build, so this example must verify with a
/// check that survives NDEBUG and fails the process on a regression.
void check(bool cond, const char *what)
{
  if (!cond)
  {
    throw std::runtime_error(std::string("check failed: ") + what);
  }
}

void demoInMemory()
{
  std::cout << "== in-memory store ==\n";

  // An EMPTY path selects in-memory mode: no file I/O, non-persistent, isolated.
  KVStore store("");

  store.setString("user:1", "alice");
  store.setString("user:2", "bob");

  auto alice = store.getString("user:1");
  check(alice.has_value() && *alice == "alice", "user:1 == alice");
  std::cout << "user:1 = " << *alice << "\n";

  // Prefix scan.
  auto users = store.keysWithPrefix("user:");
  std::cout << "user keys: " << users.size() << "\n";
  check(users.size() == 2, "two user keys");

  // Remove one.
  store.remove("user:2");
  check(!store.exists("user:2"), "user:2 removed");
  check(store.size() == 1, "size == 1 after remove");
}

void demoTtl()
{
  std::cout << "== per-key TTL ==\n";

  KVStore store("");

  // Set with a relative TTL, then read back before it expires.
  store.setString("session:abc", "token-xyz", std::chrono::seconds(3600));
  auto ttl = store.ttl("session:abc");
  check(ttl.has_value(), "ttl present for session:abc");
  std::cout << "session:abc ttl seconds ~= " << ttl->count() << "\n";

  // Cap the absolute lifetime.
  store.expireAt("session:abc", std::chrono::system_clock::now() + std::chrono::hours(8));

  // Make it permanent again (clears the TTL, keeps the value).
  store.persist("session:abc");
  check(!store.ttl("session:abc").has_value(), "no expiry after persist"); // no expiry -> nullopt
  check(store.getString("session:abc").has_value(), "value survives persist");
  std::cout << "session:abc is now permanent\n";
}

void demoBinaryAndBatch()
{
  std::cout << "== binary values + batch ==\n";

  KVStore store("");

  std::vector<std::uint8_t> blob{0x00, 0x01, 0x02, 0xFF};
  store.set("obj:42", blob);
  auto got = store.get("obj:42");
  check(got.has_value() && *got == blob, "binary blob round-trip");

  // Batch set with one batch-wide TTL, then batch get.
  std::unordered_map<std::string, std::vector<std::uint8_t>> batch{
    {"cfg:a", {1, 2, 3}},
    {"cfg:b", {4, 5, 6}},
  };
  store.setBatch(batch, std::chrono::seconds(60));

  auto fetched = store.getBatch({"cfg:a", "cfg:b", "cfg:missing"});
  std::cout << "batch fetched: " << fetched.size() << " (missing key omitted)\n";
  check(fetched.size() == 2, "batch fetched two present keys");
}

void demoPersistentRoundTrip()
{
  std::cout << "== persistent round-trip ==\n";

  const auto path =
    (std::filesystem::temp_directory_path() / "iora_kvstore_example_store").string();

  // Remove the store, its log, and any temp file (deterministic across runs).
  auto cleanup = [&path]
  {
    std::error_code ec;
    std::filesystem::remove(path, ec);
    std::filesystem::remove(path + ".log", ec);
    std::filesystem::remove(path + ".tmp", ec);
  };

  cleanup();

  {
    KVStore store(path);
    store.setString("persist:key", "durable-value");
    store.flush();
  } // destructor runs the idempotent shutdown()

  {
    KVStore reopened(path);
    auto v = reopened.getString("persist:key");
    check(v.has_value() && *v == "durable-value", "value persisted across reopen");
    std::cout << "reopened persist:key = " << *v << "\n";
  }

  cleanup();
}

} // namespace

int main()
{
  try
  {
    demoInMemory();
    demoTtl();
    demoBinaryAndBatch();
    demoPersistentRoundTrip();
  }
  catch (const std::exception &e)
  {
    std::cerr << "kvstore_example failed: " << e.what() << "\n";
    return 1;
  }

  std::cout << "kvstore_example: OK\n";
  return 0;
}
