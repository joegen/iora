// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <cstddef>
#include <functional>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <unordered_map>
#include <utility>

namespace iora {
namespace core {

/// \brief Lock-striped concurrent hash map for high-concurrency read-heavy
/// workloads. Fixed number of shards, each protected by a std::shared_mutex.
///
/// Thread safety: read operations (find, contains, findAndDo, forEach) take
/// shared_lock. Write operations (insert, erase, clear) take unique_lock.
/// Each operation locks exactly one shard (except forEach/size/clear which
/// lock shards sequentially in index order — no deadlock risk).
template<
  typename K,
  typename V,
  typename Hash = std::hash<K>,
  typename KeyEqual = std::equal_to<K>,
  std::size_t ShardCount = 64>
class ConcurrentHashMap
{
  static_assert(ShardCount > 0 && (ShardCount & (ShardCount - 1)) == 0,
    "ShardCount must be a positive power of two");

  static constexpr std::size_t kMask = ShardCount - 1;

public:
  ConcurrentHashMap() = default;

  // Non-copyable, non-movable (contains shared_mutex)
  ConcurrentHashMap(const ConcurrentHashMap&) = delete;
  ConcurrentHashMap& operator=(const ConcurrentHashMap&) = delete;
  ConcurrentHashMap(ConcurrentHashMap&&) = delete;
  ConcurrentHashMap& operator=(ConcurrentHashMap&&) = delete;

  // ── Write Operations (unique_lock) ───────────────────────────────────────

  /// \brief Insert a key-value pair. Returns false if key already exists.
  bool insert(const K& key, const V& value)
  {
    auto& shard = shardFor(key);
    std::unique_lock lock(shard.mutex);
    auto [it, inserted] = shard.map.emplace(key, value);
    return inserted;
  }

  bool insert(const K& key, V&& value)
  {
    auto& shard = shardFor(key);
    std::unique_lock lock(shard.mutex);
    auto [it, inserted] = shard.map.emplace(key, std::move(value));
    return inserted;
  }

  /// \brief Insert or update. Returns true if inserted, false if assigned.
  bool insertOrAssign(const K& key, const V& value)
  {
    auto& shard = shardFor(key);
    std::unique_lock lock(shard.mutex);
    auto [it, inserted] = shard.map.insert_or_assign(key, value);
    return inserted;
  }

  bool insertOrAssign(const K& key, V&& value)
  {
    auto& shard = shardFor(key);
    std::unique_lock lock(shard.mutex);
    auto [it, inserted] = shard.map.insert_or_assign(key, std::move(value));
    return inserted;
  }

  /// \brief Erase a key. Returns true if found and erased.
  bool erase(const K& key)
  {
    auto& shard = shardFor(key);
    std::unique_lock lock(shard.mutex);
    return shard.map.erase(key) > 0;
  }

  /// \brief Erase if predicate(key, value) returns true. Returns true if erased.
  template<typename P>
  bool eraseIf(const K& key, P&& predicate)
  {
    auto& shard = shardFor(key);
    std::unique_lock lock(shard.mutex);
    auto it = shard.map.find(key);
    if (it == shard.map.end())
    {
      return false;
    }
    if (!predicate(it->first, it->second))
    {
      return false;
    }
    shard.map.erase(it);
    return true;
  }

  /// \brief Clear all entries.
  void clear()
  {
    for (std::size_t i = 0; i < ShardCount; ++i)
    {
      std::unique_lock lock(_shards[i].mutex);
      _shards[i].map.clear();
    }
  }

  // ── Read Operations (shared_lock) ────────────────────────────────────────

  /// \brief Find a key. Returns a copy of the value, or nullopt.
  std::optional<V> find(const K& key) const
  {
    auto& shard = shardFor(key);
    std::shared_lock lock(shard.mutex);
    auto it = shard.map.find(key);
    if (it == shard.map.end())
    {
      return std::nullopt;
    }
    return it->second;
  }

  /// \brief Check if a key exists.
  bool contains(const K& key) const
  {
    auto& shard = shardFor(key);
    std::shared_lock lock(shard.mutex);
    return shard.map.find(key) != shard.map.end();
  }

  /// \brief Read-only access to a value under shared_lock.
  /// Returns false if key not found.
  template<typename F>
  bool findAndDo(const K& key, F&& readCallback) const
  {
    auto& shard = shardFor(key);
    std::shared_lock lock(shard.mutex);
    auto it = shard.map.find(key);
    if (it == shard.map.end())
    {
      return false;
    }
    readCallback(it->second);
    return true;
  }

  /// \brief Approximate total size (sum of shard sizes).
  std::size_t size() const
  {
    std::size_t total = 0;
    for (std::size_t i = 0; i < ShardCount; ++i)
    {
      std::shared_lock lock(_shards[i].mutex);
      total += _shards[i].map.size();
    }
    return total;
  }

  /// \brief True if all shards are empty.
  bool empty() const
  {
    for (std::size_t i = 0; i < ShardCount; ++i)
    {
      std::shared_lock lock(_shards[i].mutex);
      if (!_shards[i].map.empty())
      {
        return false;
      }
    }
    return true;
  }

  /// \brief Iterate all entries. Locks one shard at a time (shared_lock).
  /// Not a global snapshot — concurrent modifications to other shards are visible.
  template<typename F>
  void forEach(F&& fn) const
  {
    for (std::size_t i = 0; i < ShardCount; ++i)
    {
      std::shared_lock lock(_shards[i].mutex);
      for (const auto& [key, value] : _shards[i].map)
      {
        fn(key, value);
      }
    }
  }

  // ── Compound Operations ──────────────────────────────────────────────────

  /// \brief Get or create. If key exists, returns copy. If not, calls factory(),
  /// inserts result, returns copy. Uses double-checked locking: shared_lock
  /// first, then unique_lock with re-check if not found.
  template<typename F>
  V findOrInsert(const K& key, F&& factory)
  {
    auto& shard = shardFor(key);

    // Fast path: shared_lock read
    {
      std::shared_lock lock(shard.mutex);
      auto it = shard.map.find(key);
      if (it != shard.map.end())
      {
        return it->second;
      }
    }

    // Slow path: unique_lock, re-check, then insert
    {
      std::unique_lock lock(shard.mutex);
      auto it = shard.map.find(key);
      if (it != shard.map.end())
      {
        return it->second;
      }
      auto [inserted_it, ok] = shard.map.emplace(key, factory());
      return inserted_it->second;
    }
  }

  /// \brief Exclusive access to modify a value in-place.
  /// Returns false if key not found.
  template<typename F>
  bool findAndModify(const K& key, F&& modifier)
  {
    auto& shard = shardFor(key);
    std::unique_lock lock(shard.mutex);
    auto it = shard.map.find(key);
    if (it == shard.map.end())
    {
      return false;
    }
    modifier(it->second);
    return true;
  }

private:
  struct Shard
  {
    mutable std::shared_mutex mutex;
    std::unordered_map<K, V, Hash, KeyEqual> map;
  };

  Shard& shardFor(const K& key)
  {
    return _shards[Hash{}(key) & kMask];
  }

  const Shard& shardFor(const K& key) const
  {
    return _shards[Hash{}(key) & kMask];
  }

  Shard _shards[ShardCount];
};

} // namespace core
} // namespace iora
