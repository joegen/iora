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
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <deque>
#include <functional>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace iora {
namespace core {

namespace detail {

/// \brief Throws std::invalid_argument unless rate is finite and > 0 and
/// burstCapacity is finite and >= 0.
inline void requireValidTokenBucketParams(double rate, double burstCapacity)
{
  if (!(std::isfinite(rate) && rate > 0.0))
  {
    throw std::invalid_argument("rate limiter: rate must be finite and > 0");
  }
  if (!(std::isfinite(burstCapacity) && burstCapacity >= 0.0))
  {
    throw std::invalid_argument("rate limiter: burst capacity must be finite and >= 0");
  }
}

} // namespace detail

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

  /// \throws std::invalid_argument if rate is not finite and > 0, or
  /// burstCapacity is not finite and >= 0.
  TokenBucket(double rate, double burstCapacity)
    : _rate(rate)
    , _burstCapacity(burstCapacity)
    , _tokens(burstCapacity)
    , _lastRefill(Clock::now())
    , _lastAccess(Clock::now())
  {
    detail::requireValidTokenBucketParams(rate, burstCapacity);
  }

  // Non-copyable (prevents findOrInsert copy bug at compile time)
  TokenBucket(const TokenBucket&) = delete;
  TokenBucket& operator=(const TokenBucket&) = delete;

  // Movable
  TokenBucket(TokenBucket&&) = default;
  TokenBucket& operator=(TokenBucket&&) = default;

  /// \brief Try to consume tokens. Returns false without changing any state if
  /// tokens is negative or NaN. Otherwise replenishes, then returns false if the
  /// balance is insufficient.
  /// Only updates _lastAccess on success (denied requests don't
  /// refresh idle timer — allows cleanup of keys under sustained flood).
  bool tryConsume(double tokens = 1.0)
  {
    if (!(tokens >= 0.0))
    {
      return false;
    }
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
  /// Returns std::chrono::milliseconds::max() if the request can never
  /// succeed (tokens negative, NaN, or above burstCapacity) or the wait does
  /// not fit; callers must not add that value to a time_point unchecked.
  std::chrono::milliseconds timeUntilAvailable(double tokens = 1.0) const
  {
    if (!(tokens >= 0.0) || tokens > _burstCapacity)
    {
      return std::chrono::milliseconds::max();
    }
    double available = availableTokens();
    if (available >= tokens)
    {
      return std::chrono::milliseconds(0);
    }
    double ms = std::ceil((tokens - available) / _rate * 1000.0);
    if (!(ms < static_cast<double>(std::chrono::milliseconds::max().count())))
    {
      return std::chrono::milliseconds::max();
    }
    return std::chrono::milliseconds(static_cast<std::chrono::milliseconds::rep>(ms));
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
    auto active =
      static_cast<std::size_t>(std::distance(firstActive(Clock::now()), _timestamps.cend()));
    return _maxRequests > active ? _maxRequests - active : 0;
  }

  /// \brief Time until a slot becomes available.
  /// Returns 0ms if a slot is available now. If maxRequests is 0 (deny all),
  /// returns the window length: a bounded back-off, never
  /// std::chrono::milliseconds::max().
  std::chrono::milliseconds timeUntilAvailable() const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    if (_maxRequests == 0)
    {
      return std::chrono::duration_cast<std::chrono::milliseconds>(_window);
    }
    auto now = Clock::now();
    auto oldestActive = firstActive(now);
    if (static_cast<std::size_t>(std::distance(oldestActive, _timestamps.cend())) < _maxRequests)
    {
      return std::chrono::milliseconds(0);
    }
    // The oldest active entry expires at *oldestActive + _window
    auto ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(_window - (now - *oldestActive));
    return ms + std::chrono::milliseconds(1); // round up
  }

private:
  /// The only place the expiry rule is written. The deque is non-decreasing
  /// (timestamps are read and pushed under _mutex).
  std::deque<TimePoint>::const_iterator firstActive(TimePoint now) const
  {
    return std::find_if(_timestamps.cbegin(), _timestamps.cend(),
                        [&](TimePoint ts) { return now - ts < _window; });
  }

  void evictExpired(TimePoint now)
  {
    _timestamps.erase(_timestamps.cbegin(), firstActive(now));
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
///
/// Auto-cleanup concurrency model: the buckets live in a shared State. The
/// cleanup timer captures only a weak_ptr to it, never `this`, so a pass that
/// is pending, collected or running when the map is destroyed never touches
/// freed memory; a running pass keeps State alive until it returns. The
/// weak_ptr is the memory-safety mechanism. The `stopping` flag is the
/// termination guard: on a multi-thread Dispatcher a fire can overlap a running
/// pass and lock() the State through that pass's reference after the map is
/// destroyed, and only `stopping` stops it from re-arming. It is load-bearing;
/// do not remove it as redundant with the weak_ptr.
template<typename K, typename Hash = std::hash<K>,
         typename KeyEqual = std::equal_to<K>>
class RateLimiterMap
{
public:
  using Clock = std::chrono::steady_clock;

  /// \param defaultRate Tokens per second for new buckets
  /// \param defaultBurst Maximum burst capacity for new buckets
  /// \param cleanupWheel Optional TimingWheel for auto-cleanup scheduling. It
  /// must be RUNNING. Stopping, draining or resetting it later ends
  /// auto-cleanup; do not rely on a restart to re-arm it: build a new map, or
  /// call cleanup() yourself. The wheel and the map
  /// may be destroyed in either order. If the wheel has a Dispatcher, drain the
  /// dispatcher before destroying the wheel.
  /// \param cleanupInterval Interval for auto-cleanup (default 60s): one
  /// cleanup(maxIdle) pass starts per interval
  /// \param maxIdle Max idle time before a bucket is evicted (default 300s)
  /// \throws std::invalid_argument if defaultRate is not finite and > 0, or
  /// defaultBurst is not finite and >= 0.
  /// \throws std::runtime_error if cleanupWheel is given but not running.
  RateLimiterMap(double defaultRate, double defaultBurst,
                 TimingWheel* cleanupWheel = nullptr,
                 std::chrono::seconds cleanupInterval = std::chrono::seconds(60),
                 std::chrono::seconds maxIdle = std::chrono::seconds(300))
    : _defaultRate(defaultRate)
    , _defaultBurst(defaultBurst)
    , _state(std::make_shared<State>())
  {
    detail::requireValidTokenBucketParams(defaultRate, defaultBurst);
    if (cleanupWheel)
    {
      auto id =
        armCleanup(*cleanupWheel, _state,
                   std::chrono::duration_cast<std::chrono::milliseconds>(cleanupInterval), maxIdle);
      if (id == InvalidTimerId)
      {
        throw std::runtime_error("rate limiter: cleanup wheel is not running");
      }
    }
  }

  /// \brief Never blocks and never calls into the cleanup wheel. Cleanup
  /// passes that already started may still finish on the wheel or dispatcher
  /// thread after this returns: with no Dispatcher or a single-thread one, at
  /// most one; with a multi-thread Dispatcher, more than one. The bucket state
  /// is destroyed on whichever thread finishes last. At most one already-armed
  /// wheel entry stays pending until it fires once and does nothing. Do not
  /// call other methods concurrently with it.
  ~RateLimiterMap()
  {
    _state->stopping.store(true, std::memory_order_release);
  }

  RateLimiterMap(const RateLimiterMap&) = delete;
  RateLimiterMap& operator=(const RateLimiterMap&) = delete;
  RateLimiterMap(RateLimiterMap&&) = delete;
  RateLimiterMap& operator=(RateLimiterMap&&) = delete;

  /// \brief Try to consume tokens for a key. Auto-creates bucket if needed.
  bool tryConsume(const K& key, double tokens = 1.0)
  {
    // Fast path: try to modify existing bucket (avoids constructing throwaway)
    bool consumed = false;
    bool found = _state->buckets.findAndModify(key, [&](TokenBucket& bucket)
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
    _state->buckets.findOrInsertAndModify(
      key, [&] { return TokenBucket(defRate, defBurst); },
      [&](TokenBucket& bucket) { consumed = bucket.tryConsume(tokens); });
    return consumed;
  }

  /// \brief Set default rate for new buckets. Does not affect existing.
  /// Thread-safe: the (rate, burst) pair is published together under _defaultsMutex,
  /// so a concurrent bucket creation never observes a torn (newRate, oldBurst) pair.
  /// \throws std::invalid_argument if rate is not finite and > 0, or burst is
  /// not finite and >= 0; the previous defaults are kept.
  void setDefaultRate(double rate, double burst)
  {
    detail::requireValidTokenBucketParams(rate, burst);
    std::lock_guard<std::mutex> lk(_defaultsMutex);
    _defaultRate = rate;
    _defaultBurst = burst;
  }

  /// \brief Override rate for a specific key.
  /// \throws std::invalid_argument if rate is not finite and > 0, or burst is
  /// not finite and >= 0; the key's bucket is unchanged.
  void setKeyRate(const K& key, double rate, double burst)
  {
    // Atomic replace via insertOrAssign (single shard lock acquisition)
    _state->buckets.insertOrAssign(key, TokenBucket(rate, burst));
  }

  /// \brief Read a key's current (rate, burst); nullopt if the key has no bucket.
  /// Thread-safe (shared-lock read); symmetric with setKeyRate.
  std::optional<std::pair<double, double>> getKeyRate(const K& key) const
  {
    std::optional<std::pair<double, double>> out;
    _state->buckets.findAndDo(key, [&](const TokenBucket& bucket)
    {
      out = std::make_pair(bucket.rate(), bucket.burstCapacity());
    });
    return out;
  }

  /// \brief Remove a key's bucket.
  void removeKey(const K& key)
  {
    _state->buckets.erase(key);
  }

  /// \brief Evict idle buckets (not accessed within maxIdle).
  /// Two-pass: collect under shared_lock, then erase under unique_lock only if
  /// the bucket is still idle as of pass 1's time. A bucket refreshed,
  /// re-created or replaced (setKeyRate) between the passes is kept.
  void cleanup(std::chrono::seconds maxIdle)
  {
    cleanupState(*_state, maxIdle);
  }

  /// \brief Number of active buckets.
  std::size_t size() const { return _state->buckets.size(); }

private:
  struct State
  {
    ConcurrentHashMap<K, TokenBucket, Hash, KeyEqual> buckets;
    std::atomic<bool> stopping{false};
  };

  static void cleanupState(State& s, std::chrono::seconds maxIdle)
  {
    auto now = Clock::now();
    auto maxIdleMs = std::chrono::duration_cast<std::chrono::milliseconds>(maxIdle);
    auto isIdle = [&](const TokenBucket& bucket)
    {
      return std::chrono::duration_cast<std::chrono::milliseconds>(now - bucket.lastAccess()) >
             maxIdleMs;
    };
    std::vector<K> toEvict;

    // Pass 1: collect idle keys (forEach uses shared_lock per shard)
    s.buckets.forEach([&](const K& key, const TokenBucket& bucket)
    {
      if (isIdle(bucket))
      {
        toEvict.push_back(key);
      }
    });

    // Pass 2: re-check and erase under one unique_lock per key
    for (const auto& key : toEvict)
    {
      s.buckets.eraseIf(key, [&](const K&, const TokenBucket& bucket) { return isIdle(bucket); });
    }
  }

  /// Schedules one self-re-arming cleanup fire. The callback captures only a
  /// weak_ptr to State (never `this`, never a strong reference). It re-arms
  /// before the pass, so a throwing pass cannot end the chain; a re-arm that
  /// returns InvalidTimerId (wheel stopped, draining or reset) ends it.
  static TimerId armCleanup(TimingWheel& wheel, std::weak_ptr<State> weak,
                            std::chrono::milliseconds interval, std::chrono::seconds maxIdle)
  {
    return wheel.schedule(interval,
                          [&wheel, weak, interval, maxIdle]()
                          {
                            auto s = weak.lock();
                            if (!s || s->stopping.load(std::memory_order_acquire))
                            {
                              return;
                            }
                            armCleanup(wheel, weak, interval, maxIdle);
                            cleanupState(*s, maxIdle);
                          });
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
  std::shared_ptr<State> _state;
};

} // namespace core
} // namespace iora
