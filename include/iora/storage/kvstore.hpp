// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file kvstore.hpp
/// \brief A robust binary persistent key-value store with atomic operations,
///        concurrent reads, background compaction, and native per-key TTL.

#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <queue>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "iora/core/timing_wheel.hpp"

#ifdef __unix__
#include <fcntl.h>
#include <unistd.h>
#endif

namespace iora
{
namespace storage
{

/// @brief Maximum length for keys in KVStore
/// This is set to 65535 bytes, which is the maximum length for a key in the KVStore.
/// Keys longer than this will throw an exception.
/// Values can be up to 100 * 1024 * 1024 bytes in size.
static constexpr size_t MAX_KEY_LENGTH = 65535;
static constexpr size_t MAX_VALUE_LENGTH = 100 * 1024 * 1024;

/// Configuration options for KVStore
struct KVStoreConfig
{
  uint32_t magicNumber = 0xB1A2C3D4;
  uint32_t version = 2;
  uint32_t maxLogSizeBytes = 10 * 1024 * 1024;
  uint32_t maxCacheSize = 1000;
  bool enableBackgroundCompaction = true;
  std::chrono::milliseconds compactionInterval{30000};

  // Native per-key TTL (auto-expiry) — drives the internal core::TimingWheel.
  // All three are validated in the ctor (KTP-11); invalid values throw
  // KVStoreException rather than tripping a release-stripped wheel assert.
  std::chrono::milliseconds ttlTickDuration{1000};
  std::size_t ttlTicksPerWheel = 256;
  std::size_t ttlNumWheels = 4;
};

/// Exception thrown for KVStore-specific errors
class KVStoreException : public std::runtime_error
{
public:
  explicit KVStoreException(const std::string &msg) : std::runtime_error(msg) {}
};

/// \brief A robust binary persistent key-value store with atomic operations, concurrent reads,
/// background compaction, and native per-key auto-expiry (TTL).
class KVStore
{
public:
  explicit KVStore(const std::string &path, const KVStoreConfig &config = {})
      : _config(config), _path(path), _logPath(path + ".log"), _tempPath(path + ".tmp"),
        _shutdown(false), _ttlWheelMaxRange(computeAndValidateTtlRange(config)),
        _evictionStop(false), _ttlStarted(false), _evictionWriteErrors(0)
  {
    try
    {
      load();
      openLogFile();
      if (_config.enableBackgroundCompaction)
      {
        _compactionThread = std::thread(&KVStore::compactionWorker, this);
      }
      // End-of-ctor arming (KTP-7 / postLoadArming): after every fallible step
      // above has succeeded, lazily start the wheel + worker and arm the TTL
      // survivors replayed by load(). If any step throws, the catch below routes
      // through the idempotent shutdown() (with _mutex released) to join every
      // started thread — a throwing ctor runs no destructor.
      postLoadArm();
    }
    catch (const std::exception &e)
    {
      shutdown();
      throw KVStoreException("Failed to initialize KVStore: " + std::string(e.what()));
    }
  }

  ~KVStore()
  {
    try
    {
      shutdown();
    }
    catch (...)
    {
      // Destructor should not throw
    }
  }

  void setString(const std::string &key, const std::string &value)
  {
    set(key, std::vector<std::uint8_t>(value.begin(), value.end()));
  }

  void setString(const std::string &key, const std::string &value, std::chrono::seconds ttl)
  {
    set(key, std::vector<std::uint8_t>(value.begin(), value.end()), ttl);
  }

  std::optional<std::string> getString(const std::string &key)
  {
    auto binary = get(key);
    if (binary.has_value())
    {
      return std::string(binary->begin(), binary->end());
    }
    return std::nullopt;
  }

  void set(const std::string &key, const std::vector<std::uint8_t> &value)
  {
    validateKeyValue(key, value);

    std::unique_lock<std::shared_mutex> lock(_mutex);
    if (_shutdown.load())
    {
      throw KVStoreException("KVStore is shut down");
    }

    // Plain set clears any existing expiry (Redis-style overwrite, KTP-10/DQ-2).
    cancelTimerLocked(key);
    _expiry.erase(key);
    _kv[key] = value;
    updateCache(key, value, kNoExpiry());

    try
    {
      writeLogEntry('S', key, value);
    }
    catch (const std::exception &e)
    {
      _kv.erase(key);
      _expiry.erase(key);
      {
        std::unique_lock<std::shared_mutex> cacheLock(_cacheMutex);
        _cache.erase(key);
      }
      throw KVStoreException("Failed to write log entry: " + std::string(e.what()));
    }

    maybeCompact();
  }

  /// \brief Set a key with a relative time-to-live. ttl must be > 0 (KTP-11).
  /// The key auto-expires at now()+ttl, persisted as an 'E' log entry (KTP-1/2).
  void set(const std::string &key, const std::vector<std::uint8_t> &value,
           std::chrono::seconds ttl)
  {
    if (ttl.count() <= 0)
    {
      throw KVStoreException("TTL must be greater than zero");
    }
    validateKeyValue(key, value);

    const auto expiry = std::chrono::system_clock::now() + ttl;

    std::unique_lock<std::shared_mutex> lock(_mutex);
    if (_shutdown.load())
    {
      throw KVStoreException("KVStore is shut down");
    }
    startTtlOrCleanup(lock);

    cancelTimerLocked(key);
    const core::TimerId id = armTimerLocked(key, expiry);
    _kv[key] = value;
    _expiry[key] = ExpiryEntry{expiry, id};
    updateCache(key, value, expiry);

    try
    {
      writeLogEntry('E', key, value, toEpochMs(expiry));
    }
    catch (const std::exception &e)
    {
      if (id != core::InvalidTimerId && _wheel)
      {
        _wheel->cancel(id);
      }
      _kv.erase(key);
      _expiry.erase(key);
      {
        std::unique_lock<std::shared_mutex> cacheLock(_cacheMutex);
        _cache.erase(key);
      }
      throw KVStoreException("Failed to write log entry: " + std::string(e.what()));
    }

    maybeCompact();
  }

  std::optional<std::vector<std::uint8_t>> get(const std::string &key)
  {
    if (key.empty())
    {
      return std::nullopt;
    }

    // Cache fast path (KTP-10): a hit checks the embedded absolute expiry and
    // returns a VALUE COPY under _cacheMutex (no reference/iterator escapes — a
    // concurrent eviction may erase the entry). expiry<=now => treat as absent
    // and fall through to the authoritative _kv path.
    {
      std::shared_lock<std::shared_mutex> cacheLock(_cacheMutex);
      auto cacheIt = _cache.find(key);
      if (cacheIt != _cache.end())
      {
        if (cacheIt->second.expiry > std::chrono::system_clock::now())
        {
          return cacheIt->second.value;
        }
        // else: time-lapsed cache entry — fall through.
      }
    }

    std::shared_lock<std::shared_mutex> lock(_mutex);
    auto it = _kv.find(key);
    if (it != _kv.end())
    {
      auto eit = _expiry.find(key);
      if (eit != _expiry.end() && eit->second.expiry <= std::chrono::system_clock::now())
      {
        return std::nullopt; // lazy-read backstop: expired-not-yet-evicted
      }
      const auto cacheExpiry = (eit != _expiry.end()) ? eit->second.expiry : kNoExpiry();
      updateCache(key, it->second, cacheExpiry);
      return it->second;
    }
    return std::nullopt;
  }

  void remove(const std::string &key)
  {
    if (key.empty())
    {
      return;
    }

    std::unique_lock<std::shared_mutex> lock(_mutex);
    if (_shutdown.load())
    {
      return; // no-op post-shutdown (KTP-7 postShutdownContract: remove does not throw)
    }
    if (_kv.find(key) != _kv.end())
    {
      cancelTimerLocked(key);
      _kv.erase(key);
      _expiry.erase(key);
      {
        std::unique_lock<std::shared_mutex> cacheLock(_cacheMutex);
        _cache.erase(key);
      }

      try
      {
        writeLogEntry('D', key, {});
      }
      catch (const std::exception &e)
      {
        throw KVStoreException("Failed to write delete log entry: " + std::string(e.what()));
      }

      maybeCompact();
    }
  }

  // Batch operations for better performance
  void setBatch(const std::unordered_map<std::string, std::vector<std::uint8_t>> &batch)
  {
    if (batch.empty())
      return;

    for (const auto &[key, value] : batch)
    {
      if (key.empty() || key.size() > MAX_KEY_LENGTH || value.size() > MAX_VALUE_LENGTH)
      {
        throw KVStoreException("Invalid key or value in batch operation");
      }
    }

    std::unique_lock<std::shared_mutex> lock(_mutex);
    if (_shutdown.load())
    {
      throw KVStoreException("KVStore is shut down");
    }

    // Apply all changes to memory first (plain batch clears any existing expiry).
    for (const auto &[key, value] : batch)
    {
      cancelTimerLocked(key);
      _expiry.erase(key);
      _kv[key] = value;
      updateCache(key, value, kNoExpiry());
    }

    // Then write to log
    try
    {
      for (const auto &[key, value] : batch)
      {
        writeLogEntry('S', key, value);
      }
    }
    catch (const std::exception &e)
    {
      // Rollback memory changes
      for (const auto &[key, value] : batch)
      {
        _kv.erase(key);
        _expiry.erase(key);
        {
          std::unique_lock<std::shared_mutex> cacheLock(_cacheMutex);
          _cache.erase(key);
        }
      }
      throw KVStoreException("Failed to write batch log entries: " + std::string(e.what()));
    }

    maybeCompact();
  }

  /// \brief Batch set with a single batch-wide TTL applied to every key (DQ-4).
  void setBatch(const std::unordered_map<std::string, std::vector<std::uint8_t>> &batch,
                std::chrono::seconds ttl)
  {
    if (ttl.count() <= 0)
    {
      throw KVStoreException("TTL must be greater than zero");
    }
    if (batch.empty())
      return;

    for (const auto &[key, value] : batch)
    {
      if (key.empty() || key.size() > MAX_KEY_LENGTH || value.size() > MAX_VALUE_LENGTH)
      {
        throw KVStoreException("Invalid key or value in batch operation");
      }
    }

    const auto expiry = std::chrono::system_clock::now() + ttl;

    std::unique_lock<std::shared_mutex> lock(_mutex);
    if (_shutdown.load())
    {
      throw KVStoreException("KVStore is shut down");
    }
    startTtlOrCleanup(lock);

    for (const auto &[key, value] : batch)
    {
      cancelTimerLocked(key);
      const core::TimerId id = armTimerLocked(key, expiry);
      _kv[key] = value;
      _expiry[key] = ExpiryEntry{expiry, id};
      updateCache(key, value, expiry);
    }

    try
    {
      for (const auto &[key, value] : batch)
      {
        writeLogEntry('E', key, value, toEpochMs(expiry));
      }
    }
    catch (const std::exception &e)
    {
      for (const auto &[key, value] : batch)
      {
        cancelTimerLocked(key);
        _kv.erase(key);
        _expiry.erase(key);
        {
          std::unique_lock<std::shared_mutex> cacheLock(_cacheMutex);
          _cache.erase(key);
        }
      }
      throw KVStoreException("Failed to write batch log entries: " + std::string(e.what()));
    }

    maybeCompact();
  }

  std::unordered_map<std::string, std::vector<std::uint8_t>>
  getBatch(const std::vector<std::string> &keys)
  {
    std::unordered_map<std::string, std::vector<std::uint8_t>> result;
    std::shared_lock<std::shared_mutex> lock(_mutex);
    const auto now = std::chrono::system_clock::now();

    for (const auto &key : keys)
    {
      if (!key.empty())
      {
        auto it = _kv.find(key);
        if (it != _kv.end())
        {
          auto eit = _expiry.find(key);
          if (eit != _expiry.end() && eit->second.expiry <= now)
          {
            continue; // expired-not-yet-evicted
          }
          result[key] = it->second;
        }
      }
    }

    return result;
  }

  /// \brief Set/replace the absolute expiry of an EXISTING key without rewriting
  /// its value (KTP-10). Silent no-op if the key is absent (DQ-5). A past 'when'
  /// makes the key immediately eligible for eviction (armed with delay 0).
  void expireAt(const std::string &key, std::chrono::system_clock::time_point when)
  {
    if (key.empty())
    {
      return;
    }

    std::unique_lock<std::shared_mutex> lock(_mutex);
    if (_shutdown.load())
    {
      throw KVStoreException("KVStore is shut down");
    }
    if (_kv.find(key) == _kv.end())
    {
      return; // silent no-op on absent key
    }
    startTtlOrCleanup(lock);

    cancelTimerLocked(key);
    const core::TimerId id = armTimerLocked(key, when);
    _expiry[key] = ExpiryEntry{when, id};
    invalidateCache(key);

    try
    {
      writeLogEntry('X', key, {}, toEpochMs(when));
    }
    catch (const std::exception &e)
    {
      throw KVStoreException("Failed to write expiry log entry: " + std::string(e.what()));
    }
  }

  /// \brief Remaining time-to-live for a key, truncated toward zero seconds.
  /// nullopt = no expiry OR absent OR expired-not-yet-evicted; 0s = <1s remaining.
  std::optional<std::chrono::seconds> ttl(const std::string &key) const
  {
    if (key.empty())
    {
      return std::nullopt;
    }
    std::shared_lock<std::shared_mutex> lock(_mutex);
    if (_kv.find(key) == _kv.end())
    {
      return std::nullopt; // absent
    }
    auto eit = _expiry.find(key);
    if (eit == _expiry.end())
    {
      return std::nullopt; // permanent
    }
    const auto now = std::chrono::system_clock::now();
    if (eit->second.expiry <= now)
    {
      return std::nullopt; // expired-not-yet-evicted
    }
    auto remaining =
        std::chrono::duration_cast<std::chrono::seconds>(eit->second.expiry - now);
    if (remaining < std::chrono::seconds(0))
    {
      remaining = std::chrono::seconds(0);
    }
    return remaining;
  }

  /// \brief Clear a key's expiry (keep its value): cancel its timer + write an
  /// 'X' INT64_MIN entry (KTP-10). Silent no-op if absent or already permanent
  /// (DQ-5); no-op post-shutdown (does not throw, KTP-7).
  void persist(const std::string &key)
  {
    if (key.empty())
    {
      return;
    }
    std::unique_lock<std::shared_mutex> lock(_mutex);
    if (_shutdown.load())
    {
      return; // no-op post-shutdown
    }
    if (_kv.find(key) == _kv.end())
    {
      return; // absent
    }
    if (_expiry.find(key) == _expiry.end())
    {
      return; // already permanent
    }

    cancelTimerLocked(key);
    _expiry.erase(key);
    invalidateCache(key);

    try
    {
      writeLogEntry('X', key, {}, NO_EXPIRY_SENTINEL);
    }
    catch (const std::exception &e)
    {
      throw KVStoreException("Failed to write persist log entry: " + std::string(e.what()));
    }
  }

  void flush()
  {
    // Exclusive lock: flush() MUTATES _logStream (flush + fsync), so a shared
    // lock would let two concurrent flush() callers race on the stream. Not on
    // a hot path — durability already comes from the per-write flush (KTP-8).
    // No _mutex-holder calls flush() (KTP-9), so this cannot self-deadlock.
    std::unique_lock<std::shared_mutex> lock(_mutex);
    if (_logStream.is_open())
    {
      _logStream.flush();
#ifdef __unix__
      int fd = open(_logPath.c_str(), O_WRONLY | O_APPEND);
      if (fd != -1)
      {
        fsync(fd);
        close(fd);
      }
#endif
    }
  }

  void compact()
  {
    std::unique_lock<std::shared_mutex> lock(_mutex);
    compactLocked();
  }

  // Statistics and utility methods
  /// \brief Number of live (non-expired) keys. This is a point-in-time snapshot
  /// taken under a shared lock; under wall-clock skew it may momentarily differ
  /// from a concurrent get()/eviction view (the absolute-expiry comparison,
  /// KTP-2, governs eventual correctness).
  size_t size() const
  {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    if (_expiry.empty())
    {
      return _kv.size();
    }
    const auto now = std::chrono::system_clock::now();
    size_t expired = 0;
    for (const auto &[key, entry] : _expiry)
    {
      if (entry.expiry <= now)
      {
        ++expired;
      }
    }
    return _kv.size() - expired;
  }

  bool exists(const std::string &key) const
  {
    if (key.empty())
      return false;
    std::shared_lock<std::shared_mutex> lock(_mutex);
    auto it = _kv.find(key);
    if (it == _kv.end())
    {
      return false;
    }
    auto eit = _expiry.find(key);
    if (eit != _expiry.end() && eit->second.expiry <= std::chrono::system_clock::now())
    {
      return false; // expired-not-yet-evicted
    }
    return true;
  }

  void forceCompact() { compact(); }

  /// \brief Count of TTL evictions whose durable 'D' write threw and was
  /// swallowed by the wheel's error callback (KTP-5). Diagnostic: a nonzero
  /// value means some evicted keys were not journalled and will reappear on
  /// reload until their persisted expiry re-drops them.
  std::size_t ttlEvictionWriteErrorCount() const
  {
    return _evictionWriteErrors.load(std::memory_order_relaxed);
  }

  // Shutdown method for proper cleanup (idempotent, six-step — KTP-8).
  void shutdown()
  {
    // (1) Stop accepting / signal new TTL writes to throw.
    _shutdown.store(true);

    // (2) Drain the wheel: fires due timers (enqueued synchronously), cancels
    //     future ones. Holds no _mutex (drained closures take _mutex).
    if (_wheel)
    {
      try
      {
        _wheel->drain();
      }
      catch (...)
      {
        // drain must not prevent the rest of teardown
      }
    }

    // (3) Signal the eviction worker under the QUEUE mutex (unbounded cv.wait
    //     wakeup discipline, KTP-5/H-1-new), then notify.
    {
      std::lock_guard<std::mutex> qlock(_evictionMutex);
      _evictionStop = true;
    }
    _evictionCv.notify_all();

    // (4) Worker drains its remaining queue to completion, then exits — join it.
    if (_evictionWorker.joinable())
    {
      _evictionWorker.join();
    }

    // (5) Notify + join the background compaction thread (L-1: notify under
    //     _compactionMutex for lost-wakeup safety).
    {
      std::lock_guard<std::mutex> clock(_compactionMutex);
      _compactionCV.notify_all();
    }
    if (_compactionThread.joinable())
    {
      _compactionThread.join();
    }

    // (6) Flush + close the log. No 'D'/'E'/'X' write occurs after this.
    flush();
    _logStream.close();
  }

  /// \brief Get all (non-expired) keys in the store
  std::vector<std::string> keys() const
  {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    const auto now = std::chrono::system_clock::now();
    std::vector<std::string> result;
    result.reserve(_kv.size());
    for (const auto &[key, value] : _kv)
    {
      auto eit = _expiry.find(key);
      if (eit != _expiry.end() && eit->second.expiry <= now)
      {
        continue; // expired-not-yet-evicted
      }
      result.push_back(key);
    }
    return result;
  }

  /// \brief Get all (non-expired) keys matching a prefix
  std::vector<std::string> keysWithPrefix(const std::string &prefix) const
  {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    const auto now = std::chrono::system_clock::now();
    std::vector<std::string> result;
    for (const auto &[key, value] : _kv)
    {
      if (key.size() >= prefix.size() && key.compare(0, prefix.size(), prefix) == 0)
      {
        auto eit = _expiry.find(key);
        if (eit != _expiry.end() && eit->second.expiry <= now)
        {
          continue; // expired-not-yet-evicted
        }
        result.push_back(key);
      }
    }
    return result;
  }

  /// \brief Remove all keys matching a prefix
  /// \return Number of keys removed
  size_t removeWithPrefix(const std::string &prefix)
  {
    auto keysToRemove = keysWithPrefix(prefix);
    for (const auto &key : keysToRemove)
    {
      remove(key);
    }
    return keysToRemove.size();
  }

  /// \brief Clear all entries from the store
  void clear()
  {
    std::unique_lock<std::shared_mutex> lock(_mutex);
    if (_shutdown.load())
    {
      return; // no-op post-shutdown (do not reopen a closed log via maybeCompact)
    }

    // Write delete entries for all keys to the log (best effort).
    for (const auto &[key, value] : _kv)
    {
      try
      {
        writeLogEntry('D', key, {});
      }
      catch (...)
      {
        // Continue even if log write fails — in-memory teardown must not be
        // skipped on a log failure (KTP-10).
      }
    }

    // Cancel every armed timer so the wheel does not leak entries (KTP-10).
    if (_wheel)
    {
      for (const auto &[key, entry] : _expiry)
      {
        if (entry.timerId != core::InvalidTimerId)
        {
          _wheel->cancel(entry.timerId);
        }
      }
    }

    _kv.clear();
    _expiry.clear();

    {
      std::unique_lock<std::shared_mutex> cacheLock(_cacheMutex);
      _cache.clear();
    }

    maybeCompact();
  }

  KVStore(const KVStore &) = delete;
  KVStore &operator=(const KVStore &) = delete;
  KVStore(KVStore &&) = delete;
  KVStore &operator=(KVStore &&) = delete;

private:
  // ── TTL support types ──────────────────────────────────────────────────
  /// Cache entry: value plus the key's ABSOLUTE expiry (KTP-10/H-2). Non-TTL
  /// keys carry kNoExpiry() so the embedded-expiry check never trips for them.
  struct CacheEntry
  {
    std::vector<std::uint8_t> value;
    std::chrono::system_clock::time_point expiry;
  };

  /// Parallel expiry metadata for TTL keys only (KTP-3). timerId ==
  /// InvalidTimerId means present-but-not-actively-armed (a replay placeholder
  /// or a failed/non-accepting schedule) — lazy-read-only, never actively evicted.
  struct ExpiryEntry
  {
    std::chrono::system_clock::time_point expiry;
    core::TimerId timerId = core::InvalidTimerId;
  };

  // INT64_MIN is the no-expiry sentinel (KTP-2). 0 is the legitimate epoch
  // 1970-01-01T00:00:00Z, so it cannot be used.
  static constexpr std::int64_t NO_EXPIRY_SENTINEL = std::numeric_limits<std::int64_t>::min();

  // Upper bound (~200 years in ms) for the validated TTL wheel range, chosen so
  // steady_clock arithmetic (now + delay, in ns) cannot overflow int64 (KTP-11).
  static constexpr std::int64_t kMaxTtlRangeMs = 6'311'520'000'000LL;

  // Plausibility window for a decoded absolute expiry (epoch ms). Values outside
  // it are treated as corruption on replay (KTP-11 sanity bound). The ceiling is
  // year ~2300; the floor rejects non-positive timestamps.
  static constexpr std::int64_t kMaxPlausibleEpochMs = 10'413'792'000'000LL;

  static std::chrono::system_clock::time_point kNoExpiry()
  {
    return std::chrono::system_clock::time_point::max();
  }

  static std::int64_t toEpochMs(std::chrono::system_clock::time_point tp)
  {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
  }

  static std::chrono::system_clock::time_point fromEpochMs(std::int64_t ms)
  {
    return std::chrono::system_clock::time_point(std::chrono::milliseconds(ms));
  }

  static bool isPlausibleEpochMs(std::int64_t ms)
  {
    return ms != NO_EXPIRY_SENTINEL && ms > 0 && ms <= kMaxPlausibleEpochMs;
  }

  /// \brief Validate the TTL wheel config and return WHEEL_MAX_RANGE (KTP-11).
  /// Static so it can run from the ctor initializer list, before any file I/O.
  static std::chrono::milliseconds computeAndValidateTtlRange(const KVStoreConfig &cfg)
  {
    if (cfg.ttlTickDuration.count() <= 0)
    {
      throw KVStoreException("KVStoreConfig.ttlTickDuration must be > 0");
    }
    if (cfg.ttlNumWheels == 0)
    {
      throw KVStoreException("KVStoreConfig.ttlNumWheels must be > 0");
    }
    if (cfg.ttlTicksPerWheel == 0 ||
        (cfg.ttlTicksPerWheel & (cfg.ttlTicksPerWheel - 1)) != 0)
    {
      throw KVStoreException("KVStoreConfig.ttlTicksPerWheel must be a nonzero power of two");
    }

    // WHEEL_MAX_RANGE = ttlTickDuration * ttlTicksPerWheel ^ ttlNumWheels,
    // computed iteratively in int64 ms with a pre-multiply overflow/ceiling check.
    const std::int64_t ticks = static_cast<std::int64_t>(cfg.ttlTicksPerWheel);
    std::int64_t range = cfg.ttlTickDuration.count();
    for (std::size_t i = 0; i < cfg.ttlNumWheels; ++i)
    {
      if (range > kMaxTtlRangeMs / ticks)
      {
        throw KVStoreException("KVStoreConfig TTL wheel range overflows the supported maximum");
      }
      range *= ticks;
    }
    return std::chrono::milliseconds(range);
  }

  void validateKeyValue(const std::string &key, const std::vector<std::uint8_t> &value) const
  {
    if (key.empty())
    {
      throw KVStoreException("Key cannot be empty");
    }
    if (key.size() > MAX_KEY_LENGTH)
    {
      throw KVStoreException("Key too large");
    }
    if (value.size() > MAX_VALUE_LENGTH)
    {
      throw KVStoreException("Value too large");
    }
  }

  // ── TTL active eviction: wheel + worker + leaf-lock queue ───────────────

  /// \brief Compute the clamped relative wheel delay from an absolute expiry
  /// (KTP-2): clamp(max(0, expiry - now), 0, WHEEL_MAX_RANGE), overflow-safe.
  std::chrono::milliseconds clampDelay(std::chrono::system_clock::time_point expiry) const
  {
    const auto now = std::chrono::system_clock::now();
    if (expiry <= now)
    {
      return std::chrono::milliseconds(0);
    }
    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(expiry - now);
    if (remaining < std::chrono::milliseconds(0))
    {
      remaining = std::chrono::milliseconds(0);
    }
    if (remaining > _ttlWheelMaxRange)
    {
      remaining = _ttlWheelMaxRange;
    }
    return remaining;
  }

  /// \brief Lazily construct + start the wheel and the dedicated worker, exactly
  /// once (KTP-7). Caller MUST hold _mutex (unique). Performs NO schedule() — the
  /// eviction queue is provably empty if any step throws, so cleanup is safe.
  /// All throwable steps precede setting _ttlStarted; on throw the worker may be
  /// running and the caller routes cleanup through the idempotent shutdown().
  void ensureTtlStarted()
  {
    if (_ttlStarted)
    {
      return;
    }
    // (1) Construct the wheel with a synchronous push-only dispatcher. Held as a
    //     unique_ptr because core::TimingWheel deletes copy and move (R-MEM-2).
    _wheel = std::make_unique<core::TimingWheel>(
        _config.ttlTickDuration, _config.ttlTicksPerWheel, _config.ttlNumWheels,
        [this](core::TimingWheel::Callback cb) { enqueueEviction(std::move(cb)); });
    // Observe (don't terminate on) a swallowed 'D'-write failure in the closure.
    _wheel->setErrorCallback(
        [this](core::TimerId, std::exception_ptr)
        { _evictionWriteErrors.fetch_add(1, std::memory_order_relaxed); });
    // (2) Start the worker so a fired callback always has a consumer.
    _evictionWorker = std::thread(&KVStore::evictionWorker, this);
    // (3) Start the wheel — sets _accepting and spawns the tick thread. Without
    //     this, schedule() returns InvalidTimerId and eviction is silently off.
    _wheel->start();
    _ttlStarted = true;
  }

  /// \brief ensureTtlStarted() with arm-failure cleanup (KTP-7). Caller holds the
  /// passed unique_lock on _mutex. On failure the lock is RELEASED before the
  /// idempotent shutdown() runs (its _compactionThread.join() would otherwise
  /// deadlock against compact()'s _mutex re-acquire), then the error propagates.
  void startTtlOrCleanup(std::unique_lock<std::shared_mutex> &lock)
  {
    if (_ttlStarted)
    {
      return;
    }
    try
    {
      ensureTtlStarted();
    }
    catch (...)
    {
      // KTP-7-mandated: route arm-failure cleanup through the idempotent
      // shutdown() with _mutex RELEASED first (its _compactionThread.join()
      // would otherwise deadlock against compact()'s _mutex re-acquire). This
      // permanently shuts the store down — a thread-spawn/bad_alloc failure here
      // is catastrophic resource exhaustion, and the architecture deliberately
      // fails hard rather than running with eviction silently disabled.
      lock.unlock();
      shutdown();
      throw;
    }
  }

  /// \brief Synchronous push-only dispatcher: enqueue a fired closure. Predicate
  /// state mutated under the QUEUE mutex, then notify (KTP-5 CV discipline).
  void enqueueEviction(std::function<void()> cb)
  {
    {
      std::lock_guard<std::mutex> qlock(_evictionMutex);
      _evictionQueue.push(std::move(cb));
    }
    // notify_one is correct ONLY because there is exactly one eviction worker
    // (single consumer). The shutdown stop-path uses notify_all. If this ever
    // grows to multiple workers, revisit both notify calls.
    _evictionCv.notify_one();
  }

  /// \brief The single dedicated eviction worker. Unbounded wait; drains the
  /// queue to completion on stop before exiting (KTP-5).
  void evictionWorker()
  {
    for (;;)
    {
      std::function<void()> job;
      {
        std::unique_lock<std::mutex> qlock(_evictionMutex);
        _evictionCv.wait(qlock, [this] { return _evictionStop || !_evictionQueue.empty(); });
        if (_evictionQueue.empty())
        {
          return; // _evictionStop && empty => drain complete
        }
        job = std::move(_evictionQueue.front());
        _evictionQueue.pop();
      }
      if (job)
      {
        job(); // runs evictionCallback, which takes _mutex (queue mutex released)
      }
    }
  }

  /// \brief Arm a fresh timer for key→expiry and return its id (KTP-4). Caller
  /// holds _mutex and has started TTL. A schedule() during drain / non-accepting
  /// returns InvalidTimerId; the entry then becomes lazy-read-only. NEVER uses
  /// reschedule() (which would preserve the id and defeat the generation guard).
  core::TimerId armTimerLocked(const std::string &key,
                               std::chrono::system_clock::time_point expiry)
  {
    const auto delay = clampDelay(expiry);
    auto idHolder = std::make_shared<core::TimerId>(core::InvalidTimerId);
    std::string keyCopy = key;
    const core::TimerId id = _wheel->schedule(
        delay, [this, keyCopy, idHolder]() { evictionCallback(keyCopy, idHolder); });
    *idHolder = id; // published under _mutex; the closure reads it only under _mutex
    return id;
  }

  void cancelTimerLocked(const std::string &key)
  {
    auto eit = _expiry.find(key);
    if (eit != _expiry.end() && eit->second.timerId != core::InvalidTimerId && _wheel)
    {
      _wheel->cancel(eit->second.timerId);
    }
  }

  /// \brief Eviction closure body (runs on the worker thread). Three outcomes
  /// guarded by the generation token (KTP-4): STALE / EVICT / RE-ARM.
  void evictionCallback(const std::string &key, const std::shared_ptr<core::TimerId> &idHolder)
  {
    std::unique_lock<std::shared_mutex> lock(_mutex);
    // Read the captured id UNDER _mutex (it was published under _mutex in
    // armTimerLocked) — reading it at the call site would race that write.
    const core::TimerId capturedId = *idHolder;
    auto it = _expiry.find(key);
    // STALE: gone, replaced by a newer timer, or never actively armed.
    if (it == _expiry.end() || capturedId == core::InvalidTimerId ||
        it->second.timerId != capturedId)
    {
      return;
    }

    const auto now = std::chrono::system_clock::now();
    if (it->second.expiry > now)
    {
      // RE-ARM: a clamped far-future timer fired early — schedule a fresh id for
      // the remaining delay. A non-accepting schedule() yields InvalidTimerId
      // (entry becomes lazy-read-only, NOT re-enqueued) to keep drain bounded.
      // armTimerLocked does not touch the _expiry map, so `it` stays valid.
      const core::TimerId newId = armTimerLocked(key, it->second.expiry);
      it->second.timerId = newId; // InvalidTimerId during drain → lazy-read-only
      return;
    }

    // EVICT: erase in-memory state FIRST so a thrown 'D' write cannot leave the
    // key resident (KTP-5/C-1). The 'D' write self-flushes via writeLogEntry's
    // internal _logStream.flush() — NEVER the public flush() (recursive shared
    // mutex, KTP-9). On throw, `lock` unwinds (releasing _mutex) before the
    // exception reaches fireCallback's catch, so _errorCallback runs lock-free.
    _kv.erase(key);
    _expiry.erase(key);
    {
      std::unique_lock<std::shared_mutex> cacheLock(_cacheMutex);
      _cache.erase(key);
    }
    writeLogEntry('D', key, {});
  }

  /// \brief End-of-ctor arming (KTP-7/postLoadArming). Starts TTL and arms each
  /// replayed survivor iff there is at least one. Runs under _mutex; on throw the
  /// lock unwinds and the ctor catch invokes shutdown() with _mutex released.
  void postLoadArm()
  {
    std::unique_lock<std::shared_mutex> lock(_mutex);
    if (_expiry.empty())
    {
      return; // no TTL survivors — leave the once-flag unset, spawn no wheel
    }
    ensureTtlStarted();
    for (auto &entry : _expiry)
    {
      const core::TimerId id = armTimerLocked(entry.first, entry.second.expiry);
      entry.second.timerId = id;
    }
  }

  // ── Helper methods for atomic operations ────────────────────────────────
  bool writeHeader(std::ofstream &out) const
  {
    uint32_t version = 2; // KVStore always writes snapshot v2
    return out.write(reinterpret_cast<const char *>(&_config.magicNumber),
                     sizeof(_config.magicNumber)) &&
           out.write(reinterpret_cast<const char *>(&version), sizeof(version));
  }

  bool writeKeyValue(std::ofstream &out, const std::string &key, int64_t expiryMs,
                     const std::vector<std::uint8_t> &value) const
  {
    uint32_t keyLen = static_cast<uint32_t>(key.size());
    uint32_t valLen = static_cast<uint32_t>(value.size());

    return out.write(reinterpret_cast<const char *>(&keyLen), sizeof(keyLen)) &&
           out.write(key.data(), keyLen) &&
           out.write(reinterpret_cast<const char *>(&expiryMs), sizeof(expiryMs)) &&
           out.write(reinterpret_cast<const char *>(&valLen), sizeof(valLen)) &&
           out.write(reinterpret_cast<const char *>(value.data()), valLen);
  }

  void openLogFile()
  {
    _logStream.open(_logPath, std::ios::binary | std::ios::app);
    if (!_logStream.is_open())
    {
      throw KVStoreException("Failed to open log file: " + _logPath);
    }
  }

  // Background compaction worker
  void compactionWorker()
  {
    while (!_shutdown.load())
    {
      std::unique_lock<std::mutex> lock(_compactionMutex);
      _compactionCV.wait_for(lock, _config.compactionInterval, [this] { return _shutdown.load(); });

      if (_shutdown.load())
        break;

      try
      {
        if (shouldCompact())
        {
          compact();
        }
      }
      catch (const std::exception &e)
      {
        // Log error but continue - don't crash the background thread
      }
    }
  }

  bool shouldCompact() const
  {
    std::error_code ec;
    return std::filesystem::exists(_logPath, ec) && !ec &&
           std::filesystem::file_size(_logPath, ec) > _config.maxLogSizeBytes && !ec;
  }

  void maybeCompact()
  {
    if (!_config.enableBackgroundCompaction && shouldCompact())
    {
      compactLocked();
    }
  }

  /// \brief Compaction body assuming _mutex is already held (KTP-9). The public
  /// compact()/forceCompact() and the background compactionWorker() take _mutex
  /// then call this; maybeCompact() (already under _mutex) calls it directly. No
  /// _mutex-holder may call the public compact()/flush() (non-recursive mutex).
  void compactLocked()
  {
    try
    {
      const auto now = std::chrono::system_clock::now();

      // Stable survivor set computed under the held _mutex (M-3): a concurrent
      // eviction cannot mutate _kv/_expiry between compute and write.
      std::vector<std::string> survivors;
      std::vector<std::string> dropped;
      survivors.reserve(_kv.size());
      for (const auto &[key, value] : _kv)
      {
        auto eit = _expiry.find(key);
        if (eit == _expiry.end() || eit->second.expiry > now)
        {
          survivors.push_back(key);
        }
        else
        {
          dropped.push_back(key); // expired-not-yet-evicted
        }
      }

      {
        std::ofstream out(_tempPath, std::ios::binary | std::ios::trunc);
        if (!out.is_open())
        {
          throw KVStoreException("Failed to open temp file for compaction: " + _tempPath);
        }

        if (!writeHeader(out))
        {
          throw KVStoreException("Failed to write header during compaction");
        }

        uint32_t count = static_cast<uint32_t>(survivors.size());
        if (!out.write(reinterpret_cast<const char *>(&count), sizeof(count)))
        {
          throw KVStoreException("Failed to write count during compaction");
        }

        for (const auto &key : survivors)
        {
          auto eit = _expiry.find(key);
          const int64_t expiryMs =
              (eit != _expiry.end()) ? toEpochMs(eit->second.expiry) : NO_EXPIRY_SENTINEL;
          if (!writeKeyValue(out, key, expiryMs, _kv.at(key)))
          {
            throw KVStoreException("Failed to write key-value pair during compaction");
          }
        }

        out.flush();
        if (!out.good())
        {
          throw KVStoreException("Stream error during compaction");
        }
      }

      // Atomic rename operation
      std::error_code ec;
      std::filesystem::rename(_tempPath, _path, ec);
      if (ec)
      {
        std::filesystem::remove(_tempPath, ec); // Cleanup
        throw KVStoreException("Failed to rename temp file: " + ec.message());
      }

      // Reset log file
      _logStream.close();
      {
        std::ofstream clearLog(_logPath, std::ios::trunc);
        if (!clearLog.is_open())
        {
          throw KVStoreException("Failed to clear log file");
        }
      }

      openLogFile();

      // Drop expired survivors from the in-memory model + cache (KTP-10) and
      // cancel their armed timers. Done only after the snapshot is durably in
      // place so a compaction failure leaves the in-memory state untouched.
      for (const auto &key : dropped)
      {
        cancelTimerLocked(key);
        _kv.erase(key);
        _expiry.erase(key);
      }
      if (!dropped.empty())
      {
        std::unique_lock<std::shared_mutex> cacheLock(_cacheMutex);
        for (const auto &key : dropped)
        {
          _cache.erase(key);
        }
      }
    }
    catch (const std::exception &e)
    {
      std::error_code ec;
      std::filesystem::remove(_tempPath, ec); // Cleanup on failure
      throw;
    }
  }

  // Enhanced CRC32 with input validation
  uint32_t crc32(const std::vector<std::uint8_t> &data) const
  {
    if (data.empty())
      return 0;

    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t b : data)
    {
      crc ^= b;
      for (int i = 0; i < 8; ++i)
      {
        if (crc & 1)
          crc = (crc >> 1) ^ 0xEDB88320;
        else
          crc >>= 1;
      }
    }
    return ~crc;
  }

  // Enhanced corruption detection
  bool validateLogEntry(const std::vector<std::uint8_t> &buffer, size_t expectedSize) const
  {
    if (buffer.size() < 10)
      return false; // Minimum size check
    if (buffer.size() != expectedSize)
      return false;

    return true;
  }

  void load()
  {
    const auto now = std::chrono::system_clock::now();

    // Load snapshot with robust error handling
    std::ifstream snapshot(_path, std::ios::binary);
    if (snapshot.is_open())
    {
      uint32_t magic = 0;
      if (!snapshot.read(reinterpret_cast<char *>(&magic), sizeof(magic)) ||
          magic != _config.magicNumber)
      {
        throw KVStoreException("Invalid or corrupted snapshot file: bad magic number");
      }

      uint32_t version = 0;
      if (!snapshot.read(reinterpret_cast<char *>(&version), sizeof(version)) ||
          (version != 1 && version != 2))
      {
        throw KVStoreException("Unsupported snapshot version: " + std::to_string(version));
      }

      uint32_t count = 0;
      if (!snapshot.read(reinterpret_cast<char *>(&count), sizeof(count)))
      {
        throw KVStoreException("Failed to read entry count from snapshot");
      }

      if (count > 10000000) // Sanity check
      {
        throw KVStoreException("Unreasonable entry count in snapshot: " + std::to_string(count));
      }

      for (uint32_t i = 0; i < count; ++i)
      {
        uint32_t keyLen = 0;
        if (!snapshot.read(reinterpret_cast<char *>(&keyLen), sizeof(keyLen)) || keyLen == 0 ||
            keyLen > 65536)
        {
          throw KVStoreException("Invalid key length in snapshot at entry " + std::to_string(i));
        }

        std::string key(keyLen, '\0');
        if (!snapshot.read(&key[0], keyLen))
        {
          throw KVStoreException("Failed to read key in snapshot at entry " + std::to_string(i));
        }

        int64_t expiryMs = NO_EXPIRY_SENTINEL;
        if (version == 2)
        {
          if (!snapshot.read(reinterpret_cast<char *>(&expiryMs), sizeof(expiryMs)))
          {
            throw KVStoreException("Failed to read expiry in snapshot at entry " +
                                   std::to_string(i));
          }
        }

        uint32_t valLen = 0;
        if (!snapshot.read(reinterpret_cast<char *>(&valLen), sizeof(valLen)) ||
            valLen > 100 * 1024 * 1024)
        {
          throw KVStoreException("Invalid value length in snapshot at entry " + std::to_string(i));
        }

        std::vector<std::uint8_t> value(valLen);
        if (!snapshot.read(reinterpret_cast<char *>(value.data()), valLen))
        {
          throw KVStoreException("Failed to read value in snapshot at entry " + std::to_string(i));
        }

        if (version == 2)
        {
          if (expiryMs == NO_EXPIRY_SENTINEL)
          {
            _kv[std::move(key)] = std::move(value); // eternal key
          }
          else if (isPlausibleEpochMs(expiryMs))
          {
            const auto exp = fromEpochMs(expiryMs);
            if (exp > now)
            {
              _kv[key] = std::move(value);
              _expiry[key] = ExpiryEntry{exp, core::InvalidTimerId};
            }
            // else: already expired at load — drop the entry entirely.
          }
          // else: implausible (corrupt) expiry — drop the entry, mirroring the
          // 'E' log op's sanity-bound rejection (KTP-11). NOT kept as eternal.
        }
        else
        {
          // v1 snapshot carries no expiry → eternal key.
          _kv[std::move(key)] = std::move(value);
        }
      }
    }

    // Load log with enhanced error handling and corruption detection
    std::ifstream log(_logPath, std::ios::binary);
    if (!log.is_open())
      return; // No log file yet

    while (log.peek() != EOF)
    {
      uint32_t totalLen = 0;
      if (!log.read(reinterpret_cast<char *>(&totalLen), sizeof(totalLen)) || totalLen < 10 ||
          totalLen > 100 * 1024 * 1024)
      {
        break; // Invalid or corrupted entry
      }

      std::vector<std::uint8_t> buffer(totalLen);
      if (!log.read(reinterpret_cast<char *>(buffer.data()), totalLen))
      {
        break; // Incomplete entry
      }

      if (!validateLogEntry(buffer, totalLen))
      {
        continue; // Skip corrupted entry
      }

      // Uniform CRC verification for ALL ops (incl. 'D', KTP-11). writeLogEntry
      // appends a CRC for every op, so the trailing 4 bytes are always the CRC
      // over buffer[0 .. size-4]. A mismatch (or too-small buffer) skips the entry.
      if (buffer.size() < 5)
      {
        continue;
      }
      uint32_t storedCrc = 0;
      std::memcpy(&storedCrc, buffer.data() + buffer.size() - 4, 4);
      {
        std::vector<std::uint8_t> payload(buffer.begin(), buffer.end() - 4);
        if (crc32(payload) != storedCrc)
        {
          continue; // CRC mismatch
        }
      }

      const char *base = reinterpret_cast<const char *>(buffer.data());
      const char *end = base + buffer.size();
      const char *ptr = base;
      char op = *ptr++;

      if (op != 'S' && op != 'D' && op != 'E' && op != 'X')
      {
        continue; // Unknown operation
      }

      uint32_t keyLen = 0;
      if (ptr + 4 > end)
      {
        continue;
      }
      std::memcpy(&keyLen, ptr, 4);
      ptr += 4;

      if (keyLen == 0 || keyLen > 65536 || ptr + keyLen > end)
      {
        continue; // Invalid key length
      }
      std::string key(ptr, keyLen);
      ptr += keyLen;

      if (op == 'S')
      {
        uint32_t valLen = 0;
        if (ptr + 4 > end)
        {
          continue;
        }
        std::memcpy(&valLen, ptr, 4);
        ptr += 4;
        if (valLen > 100 * 1024 * 1024 || ptr + valLen + 4 > end)
        {
          continue;
        }
        std::vector<std::uint8_t> value(valLen);
        std::memcpy(value.data(), ptr, valLen);
        _kv[key] = std::move(value);
        _expiry.erase(key); // plain set clears any prior expiry (Redis-style)
      }
      else if (op == 'E')
      {
        int64_t expiryMs = 0;
        if (ptr + 8 + 4 > end) // expiry(8) + valLen(4)
        {
          continue;
        }
        std::memcpy(&expiryMs, ptr, 8);
        ptr += 8;
        uint32_t valLen = 0;
        std::memcpy(&valLen, ptr, 4);
        ptr += 4;
        if (valLen > 100 * 1024 * 1024 || ptr + valLen + 4 > end)
        {
          continue;
        }
        if (!isPlausibleEpochMs(expiryMs)) // INT64_MIN is illegal in 'E'
        {
          continue; // corrupt → drop
        }
        std::vector<std::uint8_t> value(valLen);
        std::memcpy(value.data(), ptr, valLen);
        const auto exp = fromEpochMs(expiryMs);
        if (exp > now)
        {
          _kv[key] = std::move(value);
          _expiry[key] = ExpiryEntry{exp, core::InvalidTimerId};
        }
        else
        {
          _kv.erase(key); // already expired → drop
          _expiry.erase(key);
        }
      }
      else if (op == 'X')
      {
        int64_t expiryMs = 0;
        if (ptr + 8 + 4 > end) // expiry(8) + crc(4)
        {
          continue;
        }
        std::memcpy(&expiryMs, ptr, 8);
        if (_kv.find(key) == _kv.end())
        {
          continue; // orphan 'X' — ignore
        }
        if (expiryMs == NO_EXPIRY_SENTINEL)
        {
          _expiry.erase(key); // persist → clear expiry
        }
        else if (isPlausibleEpochMs(expiryMs))
        {
          const auto exp = fromEpochMs(expiryMs);
          if (exp > now)
          {
            _expiry[key] = ExpiryEntry{exp, core::InvalidTimerId};
          }
          else
          {
            _kv.erase(key); // expiry already past → drop the key
            _expiry.erase(key);
          }
        }
        // implausible expiry → ignore
      }
      else // op == 'D'
      {
        _kv.erase(key);
        _expiry.erase(key);
      }
    }
  }

  void writeLogEntry(char op, const std::string &key, const std::vector<std::uint8_t> &value,
                     int64_t expiryMs = 0)
  {
    if (!_logStream.is_open())
    {
      throw KVStoreException("Log stream is not open");
    }

    const bool hasExpiry = (op == 'E' || op == 'X');
    const bool hasValue = (op == 'E' || op == 'S');

    std::vector<std::uint8_t> buffer;
    buffer.reserve(1 + 4 + key.size() + (hasExpiry ? 8 : 0) +
                   (hasValue ? 4 + value.size() : 0));

    buffer.push_back(static_cast<uint8_t>(op));
    uint32_t keyLen = static_cast<uint32_t>(key.size());
    appendRaw(buffer, &keyLen, 4);
    buffer.insert(buffer.end(), key.begin(), key.end());

    if (hasExpiry)
    {
      appendRaw(buffer, &expiryMs, 8);
    }
    if (hasValue)
    {
      uint32_t valLen = static_cast<uint32_t>(value.size());
      appendRaw(buffer, &valLen, 4);
      buffer.insert(buffer.end(), value.begin(), value.end());
    }

    uint32_t checksum = crc32(buffer);
    uint32_t totalLen = static_cast<uint32_t>(buffer.size()) + 4; // +4 for checksum

    if (!_logStream.write(reinterpret_cast<const char *>(&totalLen), 4) ||
        !_logStream.write(reinterpret_cast<const char *>(buffer.data()), buffer.size()) ||
        !_logStream.write(reinterpret_cast<const char *>(&checksum), 4))
    {
      throw KVStoreException("Failed to write log entry");
    }

    _logStream.flush();
  }

  static void appendRaw(std::vector<std::uint8_t> &buffer, const void *data, size_t n)
  {
    const auto *bytes = reinterpret_cast<const std::uint8_t *>(data);
    buffer.insert(buffer.end(), bytes, bytes + n);
  }

  // Cache management
  void updateCache(const std::string &key, const std::vector<std::uint8_t> &value,
                   std::chrono::system_clock::time_point expiry) const
  {
    std::unique_lock<std::shared_mutex> lock(_cacheMutex);
    if (_cache.size() >= _config.maxCacheSize)
    {
      // Simple LRU eviction - remove first element
      _cache.erase(_cache.begin());
    }
    _cache[key] = CacheEntry{value, expiry};
  }

  void invalidateCache(const std::string &key) const
  {
    std::unique_lock<std::shared_mutex> lock(_cacheMutex);
    _cache.erase(key);
  }

  // Configuration and paths
  const KVStoreConfig _config;
  const std::string _path;
  const std::string _logPath;
  const std::string _tempPath;

  // File streams
  std::ofstream _logStream;

  // Data storage
  std::unordered_map<std::string, std::vector<std::uint8_t>> _kv;
  mutable std::unordered_map<std::string, CacheEntry> _cache;

  // Threading and synchronization
  mutable std::shared_mutex _mutex;
  mutable std::shared_mutex _cacheMutex;
  std::mutex _compactionMutex;
  std::condition_variable _compactionCV;
  std::thread _compactionThread;

  // State management
  std::atomic<bool> _shutdown;

  // ── TTL (native per-key auto-expiry) members — declared LAST so reverse-order
  //    destruction tears down the eviction worker/wheel BEFORE _compactionThread
  //    and its primitives (KTP-7/L-2). shutdown() is the join guarantee. ──
  const std::chrono::milliseconds _ttlWheelMaxRange;
  std::unordered_map<std::string, ExpiryEntry> _expiry; // guarded by _mutex
  std::queue<std::function<void()>> _evictionQueue;     // guarded by _evictionMutex (leaf)
  std::mutex _evictionMutex;
  std::condition_variable _evictionCv;
  bool _evictionStop; // guarded by _evictionMutex
  std::unique_ptr<core::TimingWheel> _wheel;
  std::thread _evictionWorker;
  bool _ttlStarted; // guarded by _mutex (once-flag)
  std::atomic<std::size_t> _evictionWriteErrors;
};

} // namespace storage
} // namespace iora
