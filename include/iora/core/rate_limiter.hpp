// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include "iora/core/concurrent_hash_map.hpp"
#include "iora/core/timing_wheel.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace iora {
namespace core {

/// \brief Token bucket rate limiter with lazy replenishment.
///
/// Non-copyable, movable. No internal synchronization — access is
/// serialized by ConcurrentHashMap::findAndModify when used in
/// RateLimiterMap.
class TokenBucket
{
public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  TokenBucket(double rate, double burstCapacity)
    : _rate(rate)
    , _burstCapacity(burstCapacity)
    , _tokens(burstCapacity)
    , _lastRefill(Clock::now())
    , _lastAccess(Clock::now())
  {
  }

  // Non-copyable (prevents findOrInsert copy bug at compile time)
  TokenBucket(const TokenBucket&) = delete;
  TokenBucket& operator=(const TokenBucket&) = delete;

  // Movable
  TokenBucket(TokenBucket&&) = default;
  TokenBucket& operator=(TokenBucket&&) = default;

  /// \brief Try to consume tokens. Returns false if insufficient.
  /// Only updates _lastAccess on success (denied requests don't
  /// refresh idle timer — allows cleanup of keys under sustained flood).
  bool tryConsume(double tokens = 1.0)
  {
    replenish();
    if (_tokens >= tokens)
    {
      _tokens -= tokens;
      _lastAccess = Clock::now();
      return true;
    }
    return false;
  }

  /// \brief Available tokens (read-only, does not mutate state).
  double availableTokens() const
  {
    auto now = Clock::now();
    auto elapsed = std::chrono::duration<double>(now - _lastRefill).count();
    return std::min(_tokens + _rate * elapsed, _burstCapacity);
  }

  /// \brief Time until the requested tokens are available.
  /// Returns 0ms if already available. Rounds up to milliseconds.
  std::chrono::milliseconds timeUntilAvailable(double tokens = 1.0) const
  {
    double available = availableTokens();
    if (available >= tokens)
    {
      return std::chrono::milliseconds(0);
    }
    double deficit = tokens - available;
    double seconds = deficit / _rate;
    auto ms = static_cast<std::int64_t>(std::ceil(seconds * 1000.0));
    return std::chrono::milliseconds(ms);
  }

  /// \brief Last time this bucket was accessed (for idle cleanup).
  TimePoint lastAccess() const { return _lastAccess; }

  double rate() const { return _rate; }
  double burstCapacity() const { return _burstCapacity; }

private:
  void replenish()
  {
    auto now = Clock::now();
    auto elapsed = std::chrono::duration<double>(now - _lastRefill).count();
    _tokens = std::min(_tokens + _rate * elapsed, _burstCapacity);
    _lastRefill = now;
  }

  double _rate;           // tokens per second
  double _burstCapacity;  // max tokens
  double _tokens;         // current tokens
  TimePoint _lastRefill;
  TimePoint _lastAccess;
};

/// \brief Sliding window rate counter for strict rate enforcement.
///
/// "No more than N requests in any T-second window." No burst allowance.
/// Thread-safe via internal mutex.
class SlidingWindowCounter
{
public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  SlidingWindowCounter(std::size_t maxRequests, std::chrono::seconds window)
    : _maxRequests(maxRequests)
    , _window(window)
  {
  }

  /// \brief Try to acquire a slot. Returns false if window is full.
  bool tryAcquire()
  {
    std::lock_guard<std::mutex> lock(_mutex);
    auto now = Clock::now();
    evictExpired(now);

    if (_timestamps.size() >= _maxRequests)
    {
      return false;
    }
    _timestamps.push_back(now);
    return true;
  }

  /// \brief Remaining slots in the current window.
  std::size_t remaining() const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    auto now = Clock::now();
    // Count non-expired entries
    std::size_t active = 0;
    for (const auto& ts : _timestamps)
    {
      if (now - ts < _window)
      {
        ++active;
      }
    }
    return _maxRequests > active ? _maxRequests - active : 0;
  }

  /// \brief Time until a slot becomes available.
  /// Returns 0ms if a slot is available now.
  std::chrono::milliseconds timeUntilAvailable() const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    auto now = Clock::now();

    if (_timestamps.size() < _maxRequests)
    {
      return std::chrono::milliseconds(0);
    }

    // Find the oldest non-expired timestamp
    for (const auto& ts : _timestamps)
    {
      auto age = now - ts;
      if (age < _window)
      {
        // This is the oldest active entry — it will expire at ts + _window
        auto remaining = _window - age;
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(remaining);
        return ms + std::chrono::milliseconds(1); // round up
      }
    }
    return std::chrono::milliseconds(0);
  }

private:
  void evictExpired(TimePoint now)
  {
    while (!_timestamps.empty() && (now - _timestamps.front()) >= _window)
    {
      _timestamps.pop_front();
    }
  }

  std::size_t _maxRequests;
  std::chrono::seconds _window;
  std::deque<TimePoint> _timestamps;
  mutable std::mutex _mutex;
};

/// \brief Per-key rate limiter using ConcurrentHashMap + TokenBucket.
///
/// Each key gets its own TokenBucket. Buckets are created on demand
/// with the default rate. cleanup() evicts idle buckets.
template<typename K, typename Hash = std::hash<K>,
         typename KeyEqual = std::equal_to<K>>
class RateLimiterMap
{
public:
  using Clock = std::chrono::steady_clock;

  /// \param defaultRate Tokens per second for new buckets
  /// \param defaultBurst Maximum burst capacity for new buckets
  /// \param cleanupWheel Optional TimingWheel for auto-cleanup scheduling
  /// \param cleanupInterval Interval for auto-cleanup (default 60s)
  /// \param maxIdle Max idle time before a bucket is evicted (default 300s)
  RateLimiterMap(double defaultRate, double defaultBurst,
                 TimingWheel* cleanupWheel = nullptr,
                 std::chrono::seconds cleanupInterval = std::chrono::seconds(60),
                 std::chrono::seconds maxIdle = std::chrono::seconds(300))
    : _defaultRate(defaultRate)
    , _defaultBurst(defaultBurst)
    , _maxIdle(maxIdle)
  {
    if (cleanupWheel)
    {
      scheduleAutoCleanup(*cleanupWheel, cleanupInterval);
    }
  }

  /// \brief Try to consume tokens for a key. Auto-creates bucket if needed.
  bool tryConsume(const K& key, double tokens = 1.0)
  {
    // Fast path: try to modify existing bucket (avoids constructing throwaway)
    bool consumed = false;
    bool found = _buckets.findAndModify(key, [&](TokenBucket& bucket)
    {
      consumed = bucket.tryConsume(tokens);
    });

    if (found)
    {
      return consumed;
    }

    // Slow path: bucket doesn't exist — create and consume. Read the (rate, burst)
    // defaults as ONE unit under _defaultsMutex so a concurrent setDefaultRate cannot
    // hand this new bucket a torn (newRate, oldBurst) pair (2026-06-04-1).
    double defRate, defBurst;
    {
      std::lock_guard<std::mutex> lk(_defaultsMutex);
      defRate = _defaultRate;
      defBurst = _defaultBurst;
    }
    // Create-and-consume atomically under one shard lock: a separate insert() then
    // findAndModify() has a gap in which a concurrent removeKey()/cleanup() could
    // erase the just-created bucket, making findAndModify miss and spuriously deny a
    // legitimate first request (2026-09-29-2).
    _buckets.findOrInsertAndModify(
      key, [&] { return TokenBucket(defRate, defBurst); },
      [&](TokenBucket& bucket) { consumed = bucket.tryConsume(tokens); });
    return consumed;
  }

  /// \brief Set default rate for new buckets. Does not affect existing.
  /// Thread-safe: the (rate, burst) pair is published together under _defaultsMutex,
  /// so a concurrent bucket creation never observes a torn (newRate, oldBurst) pair.
  void setDefaultRate(double rate, double burst)
  {
    std::lock_guard<std::mutex> lk(_defaultsMutex);
    _defaultRate = rate;
    _defaultBurst = burst;
  }

  /// \brief Override rate for a specific key.
  void setKeyRate(const K& key, double rate, double burst)
  {
    // Atomic replace via insertOrAssign (single shard lock acquisition)
    _buckets.insertOrAssign(key, TokenBucket(rate, burst));
  }

  /// \brief Read a key's current (rate, burst); nullopt if the key has no bucket.
  /// Thread-safe (shared-lock read); symmetric with setKeyRate.
  std::optional<std::pair<double, double>> getKeyRate(const K& key) const
  {
    std::optional<std::pair<double, double>> out;
    _buckets.findAndDo(key, [&](const TokenBucket& bucket)
    {
      out = std::make_pair(bucket.rate(), bucket.burstCapacity());
    });
    return out;
  }

  /// \brief Remove a key's bucket.
  void removeKey(const K& key)
  {
    _buckets.erase(key);
  }

  /// \brief Evict idle buckets (not accessed within maxIdle).
  /// Two-pass: collect under shared_lock, erase under unique_lock.
  void cleanup(std::chrono::seconds maxIdle)
  {
    auto now = Clock::now();
    std::vector<K> toEvict;

    // Pass 1: collect idle keys (forEach uses shared_lock per shard)
    auto maxIdleMs = std::chrono::duration_cast<std::chrono::milliseconds>(maxIdle);
    _buckets.forEach([&](const K& key, const TokenBucket& bucket)
    {
      auto idle = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - bucket.lastAccess());
      if (idle > maxIdleMs)
      {
        toEvict.push_back(key);
      }
    });

    // Pass 2: erase collected keys (erase uses unique_lock per shard)
    for (const auto& key : toEvict)
    {
      _buckets.erase(key);
    }
  }

  /// \brief Number of active buckets.
  std::size_t size() const { return _buckets.size(); }

private:
  void scheduleAutoCleanup(TimingWheel& wheel, std::chrono::seconds interval)
  {
    // Schedule recurring cleanup via TimingWheel
    // We capture `this` — the RateLimiterMap must outlive the TimingWheel.
    auto scheduleNext = [this, &wheel, interval]()
    {
      cleanup(_maxIdle);
      // Reschedule
      wheel.schedule(
        std::chrono::duration_cast<std::chrono::milliseconds>(interval),
        [this, &wheel, interval]() { scheduleAutoCleanup(wheel, interval); });
    };
    wheel.schedule(
      std::chrono::duration_cast<std::chrono::milliseconds>(interval),
      scheduleNext);
  }

  // _defaultRate and _defaultBurst are ONE logical (rate, burst) invariant, so they
  // are published together under _defaultsMutex rather than as two independent atomics:
  // two independent atomics let a bucket-creating thread observe a TORN pair
  // (newRate, oldBurst) mid-setDefaultRate and bake it into a new bucket for its
  // lifetime (2026-06-04-1).
  // LOCK ORDERING: _defaultsMutex is a LEAF lock — it is never held while a shard lock
  // is acquired, and no shard lock is ever held while it is acquired. The slow path
  // copies the defaults to locals under _defaultsMutex, RELEASES it, then does the
  // shard-locked insert; keep it that way (never nest _defaultsMutex with a shard lock).
  std::mutex _defaultsMutex;
  double _defaultRate;
  double _defaultBurst;
  std::chrono::seconds _maxIdle;
  ConcurrentHashMap<K, TokenBucket, Hash, KeyEqual> _buckets;
};

} // namespace core
} // namespace iora
