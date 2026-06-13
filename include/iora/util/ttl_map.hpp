// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <type_traits>
#include <unordered_map>
#include <utility>

#include <iora/core/timer.hpp>

namespace iora
{
namespace util
{

/// \brief Bounded TTL + approximate-LRU cache for read-heavy workloads.
///
/// A header-only cache template providing per-entry TTL, an LRU-bounded
/// capacity (\c maxEntries), lazy expiry on get(), a periodic sweeper running
/// on an injected iora::core::TimerService, and lock-free stats.
///
/// Concurrency model (see architecture/iora/ttl_map.json):
///   - One mutable std::shared_mutex (in State). get()/stats() take a SHARED
///     lock; put/invalidate/clear/eviction/sweep take the EXCLUSIVE lock.
///   - get() is READ-ONLY on structure under the shared lock: it writes only a
///     per-entry relaxed atomic recency stamp and atomic hit/miss counters. It
///     NEVER splices the LRU list or erases an entry (a structural mutation
///     under a shared lock is a data race). Expired entries return a miss and
///     are physically reaped by the next exclusive op or the sweeper.
///   - All shared state lives in a heap State held by std::shared_ptr; the
///     sweep handler captures a std::weak_ptr<State> and locks it on fire, so
///     an in-flight sweep keeps State alive for its whole critical section even
///     if *this is being destroyed concurrently. This weak_ptr guard — NOT the
///     TimerService drain barrier — is the use-after-free correctness mechanism.
///
/// LIFETIME CONTRACT: the injected TimerService is NOT owned; it MUST outlive
/// *this AND be drained/stopped before ~TtlMap (do not rely on member
/// declaration order). The constructor schedules the periodic sweeper as its
/// final action and THROWS if scheduling fails (no silent sweeper-less mode).
/// Public methods (put/get/invalidate/clear/stats) MUST NOT be called
/// concurrently with ~TtlMap: the weak_ptr<State> guard protects only the
/// in-flight sweep handler against a racing destructor, NOT external callers
/// (the non-atomic _state member is not synchronized against _state.reset()).
template <typename K, typename V, typename Hash = std::hash<K>,
          typename KeyEqual = std::equal_to<K>>
class TtlMap
{
  static_assert(std::is_copy_constructible_v<V>,
                "iora::util::TtlMap requires V to be copy-constructible: get() "
                "returns a copy of V under the lock and the periodic sweep "
                "handler stored by the TimerService must be CopyConstructible. "
                "A whole Node/State is never copied or assigned.");

public:
  /// \brief Cache configuration. \c maxEntries==0 disables the cache (put() is
  /// a no-op, get() always misses); \c maxEntries==1 means every new distinct
  /// key evicts the prior one.
  struct Config
  {
    std::chrono::seconds defaultTtl;
    std::size_t maxEntries;
    std::chrono::seconds sweepInterval{std::chrono::seconds{60}};
  };

  /// \brief Eventually-consistent metrics snapshot (read lock-free).
  struct Stats
  {
    std::uint64_t hits;
    std::uint64_t misses;
    std::uint64_t evictions;
    std::size_t size;
  };

  /// \brief Construct the cache and schedule its periodic sweeper.
  /// \param cfg    Cache configuration.
  /// \param timers Injected timer service (NOT owned; must outlive *this and be
  ///               drained/stopped before destruction).
  /// \throws std::runtime_error if TimerService::schedulePeriodic returns 0
  ///         (service draining or periodic-timer limit reached).
  TtlMap(Config cfg, iora::core::TimerService &timers)
      : _cfg(cfg), _timers(timers), _state(std::make_shared<State>())
  {
    // CONSTRUCTION ORDER (mandatory): State is fully initialized above
    // (make_shared default-inits every member; stopping=false). Capture a
    // weak_ptr<State> into the handler, then schedulePeriodic LAST — a periodic
    // tick can fire on the TimerService thread before this constructor returns,
    // so State must be complete first.
    std::weak_ptr<State> weak = _state;
    std::uint64_t id = _timers.schedulePeriodic(
        _cfg.sweepInterval,
        // REENTRANCY CONTRACT (load-bearing — do not break): this handler must
        // touch ONLY State, reached through the locked shared_ptr below, and
        // NEVER any TtlMap member. ~TtlMap may run concurrently — even
        // reentrantly, on this very TimerService thread, since
        // TimerService::cancel() is non-blocking (collect-then-fire) — and
        // destroy *this while this handler frame is live. The locked
        // shared_ptr keeps State (mutex + containers) alive for the whole
        // critical section, but it does NOT keep the TtlMap object alive. That
        // is why the body captures only a weak_ptr<State> (also making it
        // CopyConstructible, as schedulePeriodic requires) and dispatches to
        // the STATIC sweepState(State&): it is structurally incapable of
        // dereferencing a possibly-destroyed TtlMap.
        [weak]()
        {
          auto s = weak.lock();
          if (!s || s->stopping.load(std::memory_order_acquire))
          {
            return;
          }
          sweepState(*s);
        });
    if (id == 0)
    {
      throw std::runtime_error(
          "iora::util::TtlMap: TimerService::schedulePeriodic failed (service "
          "draining or periodic-timer limit reached)");
    }
    _sweepId = id;
    // NO throwing operation may follow this successful schedule (it would leak
    // the timer + fire against a never-fully-constructed object). If a future
    // change adds post-schedule work, the ctor must cancel(id) in a catch path.
  }

  ~TtlMap()
  {
    // Teardown: signal the fast-path no-op hint, cancel the periodic timer,
    // then drop the State anchor LAST. State + its mutex survive until the last
    // in-flight handler's locked shared_ptr drops (the weak_ptr<State> guard is
    // the correctness mechanism; cancel() is collect-then-fire / best-effort).
    // The destructor body must touch no member after _state.reset().
    _state->stopping.store(true, std::memory_order_release);
    if (_sweepId != 0)
    {
      _timers.cancel(_sweepId);
    }
    _state.reset();
  }

  TtlMap(const TtlMap &) = delete;
  TtlMap &operator=(const TtlMap &) = delete;
  TtlMap(TtlMap &&) = delete;
  TtlMap &operator=(TtlMap &&) = delete;

  /// \brief Insert or refresh an entry (EXCLUSIVE lock). Uses \c defaultTtl when
  /// \c ttl is omitted. On an existing key the node is mutated IN PLACE (value,
  /// expiry, recency) and spliced to the LRU front — never whole-Node assigned.
  void put(const K &key, V value, std::optional<std::chrono::seconds> ttl = {})
  {
    if (_cfg.maxEntries == 0)
    {
      return; // cache disabled
    }

    State &s = *_state;
    std::unique_lock<std::shared_mutex> lock(s.mutex);

    const auto now = std::chrono::steady_clock::now();
    const auto expiresAt = now + (ttl ? *ttl : _cfg.defaultTtl);
    const std::int64_t stamp = recencyStamp(now);

    auto it = s.index.find(key);
    if (it != s.index.end())
    {
      // EXISTING key: in-place refresh + move-to-front. NEVER insert_or_assign
      // or whole-Node assign (Node holds an atomic and is non-assignable).
      auto nodeIt = it->second;
      nodeIt->value = std::move(value);
      nodeIt->expiresAt = expiresAt;
      nodeIt->lastAccess.store(stamp, std::memory_order_relaxed);
      s.lru.splice(s.lru.begin(), s.lru, nodeIt);
      return;
    }

    // NEW key: emplace at the LRU front (std::list never relocates nodes, so
    // the stored iterator stays valid).
    s.lru.emplace_front(key, std::move(value), expiresAt, stamp);
    s.index.emplace(key, s.lru.begin());
    const std::size_t newSize =
        s.size.fetch_add(1, std::memory_order_relaxed) + 1;

    if (newSize > _cfg.maxEntries)
    {
      evictOne(s, now);
    }
  }

  /// \brief Look up an entry (SHARED lock). Returns nullopt on miss OR expired
  /// (deferred reap — no erase/splice under the shared lock). Updates the
  /// relaxed recency stamp and the hit/miss counters.
  std::optional<V> get(const K &key)
  {
    State &s = *_state;
    std::shared_lock<std::shared_mutex> lock(s.mutex);

    auto it = s.index.find(key);
    if (it == s.index.end())
    {
      s.misses.fetch_add(1, std::memory_order_relaxed);
      return std::nullopt;
    }

    auto nodeIt = it->second;
    const auto now = std::chrono::steady_clock::now();
    if (nodeIt->expiresAt <= now)
    {
      // Expired: miss + deferred reap. No structural mutation under the shared
      // lock; the node is physically reaped by the next exclusive op / sweeper.
      s.misses.fetch_add(1, std::memory_order_relaxed);
      return std::nullopt;
    }

    nodeIt->lastAccess.store(recencyStamp(now), std::memory_order_relaxed);
    s.hits.fetch_add(1, std::memory_order_relaxed);
    return nodeIt->value; // copied while the shared lock is held (writers excluded)
  }

  /// \brief Remove an entry if present (EXCLUSIVE lock).
  void invalidate(const K &key)
  {
    State &s = *_state;
    std::unique_lock<std::shared_mutex> lock(s.mutex);
    auto it = s.index.find(key);
    if (it != s.index.end())
    {
      removeNode(s, it->second);
    }
  }

  /// \brief Empty the cache (EXCLUSIVE lock). Resets size to 0; the cumulative
  /// hit/miss/eviction counters are left monotonic.
  void clear()
  {
    State &s = *_state;
    std::unique_lock<std::shared_mutex> lock(s.mutex);
    s.index.clear();
    s.lru.clear();
    s.size.store(0, std::memory_order_relaxed);
  }

  /// \brief Snapshot the metrics. FULLY lock-free (relaxed atomic loads).
  Stats stats() const
  {
    const State &s = *_state;
    return Stats{s.hits.load(std::memory_order_relaxed),
                 s.misses.load(std::memory_order_relaxed),
                 s.evictions.load(std::memory_order_relaxed),
                 s.size.load(std::memory_order_relaxed)};
  }

private:
  struct Node
  {
    K key;
    V value;
    std::chrono::steady_clock::time_point expiresAt;
    std::atomic<std::int64_t> lastAccess;

    Node(const K &k, V v, std::chrono::steady_clock::time_point exp,
         std::int64_t la)
        : key(k), value(std::move(v)), expiresAt(exp), lastAccess(la)
    {
    }
  };

  using NodeList = std::list<Node>;
  using NodeIter = typename NodeList::iterator;

  /// \brief The single canonical recency-stamp unit (steady_clock native rep).
  /// Used by both the get()/put() store and the eviction threshold so the
  /// second-chance comparison can never silently mismatch units.
  static std::int64_t
  recencyStamp(std::chrono::steady_clock::time_point tp) noexcept
  {
    return tp.time_since_epoch().count();
  }

  struct State
  {
    mutable std::shared_mutex mutex;
    NodeList lru; // front = most-recently-written, back = LRU tail
    std::unordered_map<K, NodeIter, Hash, KeyEqual> index;
    std::atomic<std::uint64_t> hits{0};
    std::atomic<std::uint64_t> misses{0};
    std::atomic<std::uint64_t> evictions{0};
    std::atomic<std::size_t> size{0};
    std::atomic<bool> stopping{false};
  };

  /// \brief Erase one node from both the index and the LRU list and decrement
  /// size. Caller holds the exclusive lock. Does NOT touch the eviction counter
  /// (eviction is capacity-driven; this is shared by invalidate/sweep/evict).
  static void removeNode(State &s, NodeIter it)
  {
    s.index.erase(it->key); // read it->key while the node is still alive
    s.lru.erase(it);
    s.size.fetch_sub(1, std::memory_order_relaxed);
  }

  /// \brief Approximate-LRU capacity eviction (caller holds the exclusive lock,
  /// size just exceeded maxEntries by one). Scans from the LRU tail for the
  /// first NOT-recent victim (RECENT == lastAccess >= now - sweepInterval),
  /// bounded to kMaxHops second-chance hops. TERMINATION: if the budget is
  /// exhausted (or the head is reached) with every candidate recent, evict the
  /// strict LRU tail unconditionally — never leave size > maxEntries.
  void evictOne(State &s, std::chrono::steady_clock::time_point now)
  {
    constexpr int kMaxHops = 8;
    const std::int64_t recentThreshold = recencyStamp(now - _cfg.sweepInterval);

    NodeIter tail = std::prev(s.lru.end()); // strict LRU tail
    NodeIter victim = tail;
    for (int hops = 0; hops < kMaxHops; ++hops)
    {
      if (victim->lastAccess.load(std::memory_order_relaxed) < recentThreshold)
      {
        // Not recent -> evict this victim. The relaxed load is correct: the
        // shared->exclusive transition on the same shared_mutex establishes
        // happens-before (the mutex synchronizes; the atomic carries no
        // companion data).
        removeNode(s, victim);
        s.evictions.fetch_add(1, std::memory_order_relaxed);
        return;
      }
      if (victim == s.lru.begin())
      {
        break; // cannot hop further toward the front
      }
      victim = std::prev(victim);
    }
    // Budget exhausted (or head reached) with all candidates recent: evict the
    // strict LRU tail unconditionally (liveness / termination guarantee).
    removeNode(s, tail);
    s.evictions.fetch_add(1, std::memory_order_relaxed);
  }

  /// \brief Periodic sweep: physically reap expired entries in bounded batches
  /// (<=kBatch erases per exclusive-lock acquisition), releasing the lock
  /// between batches so readers progress. Re-checks \c stopping at the top of
  /// each batch and bails early (liveness — a teardown-in-progress sweep must
  /// stop promptly so drain() is not delayed). STATIC by contract: it operates
  /// ONLY on the State reached via the handler's locked shared_ptr and must
  /// never touch a TtlMap member, because *this may be destroyed concurrently
  /// (see the REENTRANCY CONTRACT at the handler in the constructor).
  static void sweepState(State &s)
  {
    constexpr std::size_t kBatch = 512;
    for (;;)
    {
      if (s.stopping.load(std::memory_order_acquire))
      {
        return; // per-batch stopping re-check (liveness)
      }
      // Re-sample now per batch: the lock is released between batches, so a
      // multi-batch sweep of a large map still reaps entries that cross their
      // expiry mid-sweep (no one-tick deferral).
      const auto now = std::chrono::steady_clock::now();
      std::size_t reaped = 0;
      {
        std::unique_lock<std::shared_mutex> lock(s.mutex);
        auto it = s.lru.begin();
        while (it != s.lru.end() && reaped < kBatch)
        {
          if (it->expiresAt <= now)
          {
            auto next = std::next(it);
            s.index.erase(it->key);
            s.lru.erase(it);
            s.size.fetch_sub(1, std::memory_order_relaxed);
            it = next;
            ++reaped;
          }
          else
          {
            ++it;
          }
        }
      }
      if (reaped < kBatch)
      {
        return; // a non-full batch means no expired entries remain this pass
      }
      // Full batch: lock released above so readers progress; loop for the next.
    }
  }

  Config _cfg;
  iora::core::TimerService &_timers;
  std::shared_ptr<State> _state;
  std::uint64_t _sweepId{0};
};

} // namespace util
} // namespace iora
