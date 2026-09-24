# Iora TtlMap \& ExpiringCache -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.1 |
| **Date** | 2026-09-18 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/util/ttl_map.hpp`, `include/iora/util/expiring_cache.hpp` |
| **Namespace** | `iora::util` |
| **Public classes** | `TtlMap<K, V, Hash, KeyEqual>`, `ExpiringCache<K, V>` |
| **Dependencies** | `ttl_map.hpp`: `iora/core/timer.hpp` (`iora::core::TimerService`, injected) plus `<atomic>`, `<chrono>`, `<cstdint>`, `<functional>`, `<list>`, `<memory>`, `<optional>`, `<shared_mutex>`, `<stdexcept>`, `<type_traits>`, `<unordered_map>`, `<utility>`. `expiring_cache.hpp`: `iora/core/logger.hpp` (`iora::core::Logger`, static) plus `<chrono>`, `<condition_variable>`, `<functional>`, `<mutex>`, `<optional>`, `<thread>`, `<unordered_map>`, `<utility>`, `<vector>`. No external/third-party dependencies. |

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.1 | 2026-09-18 | Re-synced against the hardened `ttl_map.hpp`: `sweepState()` now bounds both nodes scanned (`kScanBudget = 4096`) and erasures (`kReapBatch = 512`) per exclusive-lock acquisition, with a `State::sweepResume` resume-by-key cursor and a per-invocation visit ceiling; `get()` is now `const`; the `V`-assignability requirement is now enforced by a second `static_assert`. Removed the three Known Limitations bullets these fixes resolved (sweep O(n)-under-lock, incomplete `static_assert`, non-`const` `get()`); corrected the ThreadSanitizer bullet to PASS (`tasks/iora/completed/2026-06-13-1_ttl-map-tsan-soak-run_P1.json`). Added the genuine `ExpiringCache` purge-lock-hold limitation (tracked as `tasks/iora/backlog/2026-09-18-2_expiring-cache-purge-unbounded-lock-hold_P1.json`) and a tracker citation for the consolidation follow-up (`tasks/iora/backlog/2026-09-18-3_ttlmap-expiringcache-consolidation-eval_P2.json`). |
| 1.0 | 2026-09-18 | Initial Architecture & Programmer's Guide, authored directly against `include/iora/util/ttl_map.hpp` and `include/iora/util/expiring_cache.hpp`, cross-checked against `architecture/iora/ttl_map.json` and `tests/util/iora_test_ttl_map.cpp` / `tests/util/iora_test_expiring_cache.cpp`. |

---

## 1. Executive Summary

### Problem

`iora::util` has shipped a thread-safe expiring cache, `ExpiringCache<K, V>`, since before this guide existed. It solves "expire an entry after N seconds" correctly, but it has three structural limits that matter for a hot read path: `get()` takes an **exclusive** `std::mutex` even though a lookup never mutates the map's shape (only which entry it returns), there is **no capacity bound** (a misbehaving producer can grow the map without limit), and reclamation runs on a **self-owned background thread with a fixed, hardcoded 5-second poll** -- there is no way to tune the sweep cadence or to share a scheduler with the rest of an application.

`tmc_edge_proxy`'s route cache and AI-registration caches -- and, by extension, any future Iora consumer with a similar shape -- need a **bounded**, **read-heavy**, per-entry-TTL cache: ~100k entries, ~600s TTL, sub-10ms `get()` under concurrent readers, and a way to bound memory when a source floods it with distinct keys. `ExpiringCache`'s exclusive-lock `get()` serializes every reader against every other reader, and its unbounded map has no answer for a key-cardinality flood.

### Solution

Two distinct, coexisting caching primitives in `iora::util`:

- **`ExpiringCache<K, V>`** (`expiring_cache.hpp`) -- the older, simpler cache. TTL-only, no capacity bound, no LRU. Owns a dedicated purge `std::thread` that wakes every 5 seconds (or immediately on shutdown via a condition variable) and sweeps the whole map under one `std::mutex`. An optional `EvictionCallback` fires for both TTL-driven and explicit removals, always **outside** the lock. Remains in place for its existing consumers; nothing about it changed to make room for `TtlMap`.
- **`TtlMap<K, V, Hash, KeyEqual>`** (`ttl_map.hpp`) -- the newer, read-optimized cache. Bounded by `Config::maxEntries` with approximate-LRU eviction, backed by a `std::shared_mutex` so concurrent `get()` calls run under a **shared** lock and never contend with each other. It owns no thread: its periodic sweeper is scheduled on an **injected** `iora::core::TimerService`, with a `std::weak_ptr`-guarded handler that keeps the cache lifetime-safe even if the map is destroyed while a sweep is in flight. Lock-free `stats()`.

They are **additive siblings, not a replacement relationship** -- `TtlMap` did not retire `ExpiringCache`; consolidating the two remains an open, separate follow-up (see Section 10).

### Technical Impact

- **Non-contending concurrent reads.** `TtlMap::get()` takes a `std::shared_lock`; N readers proceed in parallel. `ExpiringCache::get()` takes a `std::lock_guard` (exclusive); readers serialize against each other and against writers/the purge thread.
- **Bounded memory under key-cardinality fan-out.** `TtlMap::Config::maxEntries` caps the map at a fixed size via approximate-LRU eviction; `ExpiringCache` has no such bound -- it can only shrink via TTL expiry or explicit `remove()`.
- **Deferred, lock-cheap expiry.** `TtlMap::get()` on an expired entry returns a miss without any structural mutation under its shared lock -- the node is reaped later by a writer or the sweeper. `ExpiringCache::get()` erases an expired entry immediately, under its exclusive lock, on the calling thread.
- **No dedicated thread per `TtlMap` instance.** `TtlMap`'s sweeper reuses a caller-supplied `iora::core::TimerService`; `ExpiringCache` spins up its own `std::thread` per instance.
- **Lock-free `TtlMap::stats()`.** Hit/miss/eviction/size counters are `std::atomic`, read with relaxed loads and no lock at all. `ExpiringCache::size()` takes the exclusive mutex.

---

## 2. System Architecture

### 2.1 Component relationships

```
iora::util
|
|-- TtlMap<K, V, Hash, KeyEqual>            (public; non-copyable, non-movable)
|     |-- Config                            (public nested: defaultTtl, maxEntries, sweepInterval)
|     |-- Stats                             (public nested: hits, misses, evictions, size)
|     |-- Node                              (private: key, value, expiresAt, atomic<int64_t> lastAccess)
|     |-- State                             (private, heap-allocated, held by shared_ptr<State>)
|     |     |-- mutable std::shared_mutex mutex
|     |     |-- std::list<Node> lru               (front = MRU, back = LRU tail)
|     |     |-- std::unordered_map<K, NodeIter, Hash, KeyEqual> index
|     |     |-- std::atomic<uint64_t> hits, misses, evictions
|     |     |-- std::atomic<size_t> size
|     |     `-- std::atomic<bool> stopping
|     |-- Config _cfg
|     |-- iora::core::TimerService& _timers       (INJECTED -- not owned)
|     |-- std::shared_ptr<State> _state           (the sweep handler's weak_ptr anchor)
|     `-- std::uint64_t _sweepId                  (from _timers.schedulePeriodic)
|
`-- ExpiringCache<K, V>                     (public; thread-safe via internal mutex)
      |-- EvictionCallback                  (public: std::function<void(const K&, const V&)>)
      |-- CacheEntry                        (private: V value, steady_clock::time_point expiration)
      |-- std::unordered_map<K, CacheEntry> _cache
      |-- std::chrono::seconds _ttl
      |-- mutable std::mutex _mutex
      |-- std::thread _purgeThread                 (OWNED -- one per instance)
      |-- bool _stop
      |-- EvictionCallback _evictionCallback
      `-- std::condition_variable _stopCondition    (wakes the purge thread immediately on shutdown)

ExpiringCacheTestAccessor<K, V>             (public; friend of ExpiringCache; test-only mapSize() peek)

Collaborator (TtlMap only, not owned):
  iora::core::TimerService  --schedulePeriodic--> periodic sweep callback (captures weak_ptr<State>)
                             (TtlMap does NOT own this service; it MUST outlive every TtlMap
                              instance that references it, and be drained/stopped before that
                              TtlMap is destroyed -- see Section 6.)
```

`TtlMap` **owns** its `State` (via `shared_ptr`) but only **borrows** the `TimerService` it schedules on. `ExpiringCache` owns everything it touches, including its purge thread.

### 2.2 Data flow -- `TtlMap::get()` vs `TtlMap::put()`

```mermaid
sequenceDiagram
  participant App as Caller (any thread)
  participant Map as TtlMap
  participant State as State (shared_mutex)

  App->>Map: get(key)
  Map->>State: shared_lock(mutex)
  alt key present and NOT expired
    State-->>Map: copy Node::value; store lastAccess (relaxed); hits++
    Map-->>App: optional<V> (has value)
  else key present but EXPIRED
    State-->>Map: misses++ (NO erase, NO splice -- deferred reap)
    Map-->>App: nullopt
  else key absent
    State-->>Map: misses++
    Map-->>App: nullopt
  end
  Note over State: shared_lock released

  App->>Map: put(key, value)
  Map->>State: unique_lock(mutex)
  alt key exists
    State-->>State: mutate value/expiresAt/lastAccess in place; splice to LRU front
  else new key
    State-->>State: emplace_front; index.emplace; size++
    opt size > maxEntries
      State-->>State: evictOne() -- approximate-LRU tail scan, bounded 8 hops
    end
  end
  Note over State: unique_lock released
```

### 2.3 Data flow -- `ExpiringCache::get()` and the purge thread

```mermaid
sequenceDiagram
  participant App as Caller (any thread)
  participant Cache as ExpiringCache
  participant Mtx as _mutex
  participant Purge as _purgeThread

  App->>Cache: get(key)
  Cache->>Mtx: lock_guard(_mutex)
  alt entry present and live
    Mtx-->>Cache: return copy of value (lock released by RAII on return)
  else entry present but EXPIRED
    Cache->>Cache: capture {key, value} if callback set; _cache.erase(it)
    Mtx-->>Cache: unlock
    Cache->>Cache: fire EvictionCallback(key, value) OUTSIDE the lock
    Cache-->>App: nullopt
  else entry absent
    Mtx-->>Cache: unlock
    Cache-->>App: nullopt
  end

  loop every 5s (or immediate wake on shutdown)
    Purge->>Mtx: unique_lock + wait_for(5s, pred: _stop)
    alt _stop signaled
      Purge->>Purge: break loop (thread exits)
    else timeout (normal purge tick)
      Purge->>Purge: scan _cache; erase every expired entry; collect evicted pairs
      Mtx-->>Purge: lock released at end of block
      Purge->>Purge: fire EvictionCallback for each evicted pair, wrapped in try/catch
    end
  end
```

### 2.4 Threading model

| Thread | `TtlMap` responsibility | `ExpiringCache` responsibility |
|---|---|---|
| **Any caller thread** | `put`/`get`/`invalidate`/`clear`/`stats` -- all safe to call concurrently with each other (subject to the constructor/destructor ordering contract in Section 6). | `set`/`get`/`remove`/`size` -- all safe to call concurrently with each other and with the purge thread. |
| **Injected `iora::core::TimerService`'s timer thread** (not owned by `TtlMap`) | Fires the periodic sweep handler (`schedulePeriodic`); the handler locks a `std::weak_ptr<State>` and, if still alive, runs `sweepState` under `State::mutex` in bounded batches. | N/A |
| **`ExpiringCache`'s own `_purgeThread`** (owned, one per instance) | N/A | Wakes every 5 seconds (or immediately when `_stopCondition` is notified at shutdown), sweeps `_cache` for expired entries under `_mutex`, then fires `EvictionCallback` for each evicted entry outside the lock. |

---

## 3. Component Deep Dive

### 3.1 `TtlMap<K, V, Hash, KeyEqual>`

#### 3.1.1 `Config`, `Stats`, and the `V` requirement

```cpp
struct Config
{
  std::chrono::seconds defaultTtl;
  std::size_t maxEntries;
  std::chrono::seconds sweepInterval{std::chrono::seconds{60}};
};

struct Stats
{
  std::uint64_t hits;
  std::uint64_t misses;
  std::uint64_t evictions;
  std::size_t size;
};
```

`maxEntries == 0` disables the cache entirely: `put()` becomes a no-op (checked at the top of `put()`), and because nothing is ever inserted, `get()` naturally always misses -- `get()` has no explicit `maxEntries == 0` branch of its own. `maxEntries == 1` means every distinct new key evicts the prior one (verified in Section 3.1.4: the second distinct `put()` always pushes size to 2, which exceeds `maxEntries == 1` and triggers `evictOne()`).

Two class-level `static_assert`s document and enforce the requirements on `V`:

```cpp
static_assert(std::is_copy_constructible_v<V>,
              "iora::util::TtlMap requires V to be copy-constructible: get() "
              "returns a copy of V under the lock and the periodic sweep "
              "handler stored by the TimerService must be CopyConstructible.");
static_assert(std::is_move_assignable_v<V> || std::is_copy_assignable_v<V>,
              "iora::util::TtlMap requires V to be move- or copy-assignable: "
              "put() on an existing key refreshes the stored value in place via "
              "`node->value = std::move(value)`. A whole Node/State is never "
              "copied or assigned, but the stored V is move-assigned on refresh.");
```

The first documents that `get()` returns a copy of `V` under the lock, and that the periodic sweep handler captured by the `TimerService` must itself be `CopyConstructible`. The second checks that `V` is move- or copy-assignable, because `put()`'s existing-key path refreshes the stored value via `node->value = std::move(value)`. A `V` that is copy-constructible but not assignable now fails to compile at class-template instantiation with this second assertion's message, rather than surfacing a deep, non-obvious error the first time an existing-key `put()` is instantiated.

#### 3.1.2 `State` -- the heap-allocated shared anchor

All mutable cache state lives in a private `State` struct, allocated once via `std::make_shared<State>()` in the constructor and held by `TtlMap::_state`:

```cpp
struct State
{
  mutable std::shared_mutex mutex;
  NodeList lru;                                          // front = MRU, back = LRU tail
  std::unordered_map<K, NodeIter, Hash, KeyEqual> index;
  std::atomic<std::uint64_t> hits{0};
  std::atomic<std::uint64_t> misses{0};
  std::atomic<std::uint64_t> evictions{0};
  std::atomic<std::size_t> size{0};
  std::atomic<bool> stopping{false};
  std::optional<K> sweepResume;                          // sweep resume cursor, by KEY
};
```

`sweepResume` is the periodic sweep's resume cursor -- the key of the next node `sweepState` should examine on its next lock acquisition. It is read and written only by `sweepState`, always under the exclusive `mutex`, so it needs no separate synchronization. It stores a **key**, not a `std::list` iterator, deliberately: an iterator saved across a released lock could dangle if a concurrent `put`/`invalidate`/`evictOne`/`clear` erased its node in the meantime, whereas a key re-found via `index` cannot -- if the key is gone, the sweep safely restarts from the LRU front. See Section 3.1.7.

`Node` (the `std::list<Node>` element type) holds `K key; V value; std::chrono::steady_clock::time_point expiresAt; std::atomic<std::int64_t> lastAccess;`. The `std::atomic` member makes `Node` non-copyable and non-movable -- this is deliberate and harmless: `State` lives on the heap behind a `shared_ptr`, and `std::list` never relocates its nodes (`splice` only relinks pointers), so the map's stored `NodeIter` values and every `Node`'s atomics stay valid across the object's entire life.

Indirecting all state through `shared_ptr<State>` (rather than storing it directly as `TtlMap` members) is the mechanism that makes the periodic sweeper lifetime-safe -- see Section 3.1.6 and Section 6.

#### 3.1.3 Construction -- mandatory ordering, and why the constructor can throw

```cpp
TtlMap(Config cfg, iora::core::TimerService &timers)
    : _cfg(cfg), _timers(timers), _state(std::make_shared<State>())
{
  std::weak_ptr<State> weak = _state;
  std::uint64_t id = _timers.schedulePeriodic(_cfg.sweepInterval,
      [weak]()
      {
        auto s = weak.lock();
        if (!s || s->stopping.load(std::memory_order_acquire)) { return; }
        sweepState(*s);
      });
  if (id == 0)
  {
    throw std::runtime_error("iora::util::TtlMap: TimerService::schedulePeriodic failed ...");
  }
  _sweepId = id;
}
```

The ordering is load-bearing, not stylistic:

1. `State` is allocated and **fully** default-initialized (`make_shared` default-inits every member; `stopping` starts `false`) as part of the member-initializer list, **before** the constructor body runs.
2. The sweep handler captures only a `std::weak_ptr<State>` -- never a `TtlMap*`, never `this` -- and dispatches to the **static** `sweepState(State&)`.
3. `schedulePeriodic` is called **last**. A periodic tick can fire on the `TimerService`'s own thread before this constructor returns (the timer thread is independent and may already be running), so `State` must be complete before the handler is registered.
4. If `schedulePeriodic` returns `0` (the service is draining, or `TimerLimits::maxPeriodicTimers` is reached -- see [`docs/core/timer.md`](../core/timer.md) Section 9.2), the constructor **throws `std::runtime_error`**. There is no silent "sweeper-less" fallback mode: a `TtlMap` that could never expire cold entries would be a slow-motion memory leak.

The header comments this explicitly: **no throwing operation may follow a successful `schedulePeriodic`** -- doing so would leak the scheduled timer and let it fire against a partially-destroyed object. If a future change adds post-schedule work, it must `cancel(id)` on the exception path.

#### 3.1.4 `put()` -- single critical section, in-place mutation

```cpp
void put(const K &key, V value, std::optional<std::chrono::seconds> ttl = {})
{
  if (_cfg.maxEntries == 0) { return; }

  State &s = *_state;
  std::unique_lock<std::shared_mutex> lock(s.mutex);
  const auto now = std::chrono::steady_clock::now();
  const auto expiresAt = now + (ttl ? *ttl : _cfg.defaultTtl);
  const std::int64_t stamp = recencyStamp(now);

  auto it = s.index.find(key);
  if (it != s.index.end())
  {
    auto nodeIt = it->second;
    nodeIt->value = std::move(value);
    nodeIt->expiresAt = expiresAt;
    nodeIt->lastAccess.store(stamp, std::memory_order_relaxed);
    s.lru.splice(s.lru.begin(), s.lru, nodeIt);
    return;
  }

  s.lru.emplace_front(key, std::move(value), expiresAt, stamp);
  s.index.emplace(key, s.lru.begin());
  const std::size_t newSize = s.size.fetch_add(1, std::memory_order_relaxed) + 1;
  if (newSize > _cfg.maxEntries) { evictOne(s, now); }
}
```

For an **existing** key the node is mutated **in place** (value, expiry, recency) and spliced to the LRU front -- never `insert_or_assign`'d or whole-`Node`-assigned (a `Node` is not assignable; it holds an atomic). For a **new** key, the node is emplaced at the LRU front and, only if the post-insert size now exceeds `maxEntries`, exactly one victim is evicted. The whole operation -- index mutation, LRU relink, size/counter update, and any resulting eviction -- runs inside one `unique_lock` acquisition with no intermediate release, so a concurrent `get()` can never observe a half-written node.

#### 3.1.5 `get()` -- shared lock, read-only on structure, deferred reap

```cpp
std::optional<V> get(const K &key) const
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
    s.misses.fetch_add(1, std::memory_order_relaxed);
    return std::nullopt;               // deferred reap -- no erase/splice here
  }

  nodeIt->lastAccess.store(recencyStamp(now), std::memory_order_relaxed);
  s.hits.fetch_add(1, std::memory_order_relaxed);
  return nodeIt->value;                // copied under the shared lock
}
```

An expired entry returns a miss but is **not** erased under the shared lock -- a structural mutation (an `erase`/`splice`) while other readers hold the same lock in shared mode would be a data race. The stale node is physically reaped later, either by the next exclusive operation that happens to touch it or by the periodic sweeper. `get()` writes exactly two things under the shared lock: the per-node `lastAccess` atomic (relaxed) and one of the two atomic counters (`hits`/`misses`) -- nothing else about the map's shape changes. `get()` is `const`-qualified: it mutates only atomics inside `State`, reached through `*_state`, whose constness does not propagate to the pointee, so it is consistent with `stats() const`. A caller holding only a `const TtlMap&` can call `get()`.

#### 3.1.6 `evictOne()` -- bounded second-chance approximate LRU

```cpp
void evictOne(State &s, std::chrono::steady_clock::time_point now)
{
  constexpr int kMaxHops = 8;
  const std::int64_t recentThreshold = recencyStamp(now - _cfg.sweepInterval);

  NodeIter tail = std::prev(s.lru.end());
  NodeIter victim = tail;
  for (int hops = 0; hops < kMaxHops; ++hops)
  {
    if (victim->lastAccess.load(std::memory_order_relaxed) < recentThreshold)
    {
      removeNode(s, victim);
      s.evictions.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    if (victim == s.lru.begin()) { break; }
    victim = std::prev(victim);
  }
  removeNode(s, tail);                 // budget exhausted / head reached: evict unconditionally
  s.evictions.fetch_add(1, std::memory_order_relaxed);
}
```

Strict LRU would require moving every accessed node to the front on every `get()`, which is incompatible with `get()`'s shared-lock, read-only design (see Section 6). Instead, the LRU **list order** is maintained only by writers (`put()` splicing to the front), while each node independently tracks `lastAccess` as a relaxed atomic that readers update under the shared lock. Eviction scans from the LRU tail for the first node that is **not "recent"**, where "recent" means `lastAccess >= now - sweepInterval` -- reusing the sweep interval as the recency window. The scan is capped at `kMaxHops = 8` second-chance hops; if every candidate in that budget looks recent (or the list head is reached), the strict tail is evicted unconditionally. This termination guarantee is what prevents eviction from ever returning with `size > maxEntries`.

The relaxed load of `lastAccess` at eviction time is correct without a stronger memory order because the shared-to-exclusive transition on the same `shared_mutex` establishes happens-before between any reader's earlier relaxed store and this reader-turned-writer's later relaxed load -- the mutex is what synchronizes; the atomic itself carries no companion data.

#### 3.1.7 `sweepState()` -- the periodic reaper

```cpp
static void sweepState(State &s)
{
  constexpr std::size_t kReapBatch = 512;   // max erasures per lock acquisition
  constexpr std::size_t kScanBudget = 4096; // max nodes VISITED per acquisition
  static_assert(kReapBatch <= kScanBudget,
                "kReapBatch must not exceed kScanBudget: erasures are a subset "
                "of the nodes visited per lock acquisition");

  const std::size_t visitCeiling =
      s.size.load(std::memory_order_relaxed) + kScanBudget;
  std::size_t totalScanned = 0;

  for (;;)
  {
    if (s.stopping.load(std::memory_order_acquire)) { return; }
    const auto now = std::chrono::steady_clock::now();
    std::size_t reaped = 0;
    std::size_t scanned = 0;
    bool reachedEnd = false;
    {
      std::unique_lock<std::shared_mutex> lock(s.mutex);
      NodeIter it;
      if (s.sweepResume)
      {
        auto ri = s.index.find(*s.sweepResume);
        it = (ri != s.index.end()) ? ri->second : s.lru.begin();
      }
      else
      {
        it = s.lru.begin();
      }
      while (it != s.lru.end() && reaped < kReapBatch && scanned < kScanBudget)
      {
        ++scanned;
        if (it->expiresAt <= now)
        {
          NodeIter next = std::next(it);
          removeNode(s, it);
          it = next;
          ++reaped;
        }
        else { ++it; }
      }
      if (it == s.lru.end())
      {
        reachedEnd = true;
        s.sweepResume.reset();     // full pass complete; next tick starts fresh
      }
      else
      {
        s.sweepResume = it->key;   // remember where to resume next chunk
      }
    }
    totalScanned += scanned;
    if (reachedEnd || totalScanned >= visitCeiling) { return; }
  }
}
```

`sweepState` is `static` **by contract**: it is reached only through the sweep handler's locked `shared_ptr<State>`, and it must never touch a `TtlMap` member, because the owning `TtlMap` may be concurrently destroyed while this handler frame is live (see Section 6).

**Two independent bounds per lock acquisition, not one.** Each `std::unique_lock` acquisition inside the loop visits (scans) at most `kScanBudget = 4096` nodes **and** erases at most `kReapBatch = 512` of them, whichever limit is hit first, then releases the lock -- this bounds the worst-case reader/writer stall per acquisition to O(`kScanBudget`) regardless of map size or expiry distribution. `kReapBatch` alone (the erasure-only bound) is not sufficient: a sparse-expiry or high-hit-rate map -- the stated target workload -- would otherwise let the scan walk the entire live list under one continuous exclusive lock before finding `kReapBatch` expired entries to erase.

**Safe resume by key.** The loop carries its position across lock releases in `State::sweepResume`, a `std::optional<K>`, never a `std::list` iterator: on re-acquiring the lock, it resumes at the node for the saved key if `index` still finds it, or restarts from the LRU front if that key was erased by a concurrent writer meanwhile (a redundant re-scan of the already-swept prefix, never a skip of a live entry). `now` is re-sampled per chunk, so a multi-chunk sweep of a large map still reaps entries that cross their expiry mid-sweep.

**Per-invocation visit ceiling -- the termination guard.** `visitCeiling` is computed once, at the top of the call, as the map's size at entry plus one `kScanBudget` chunk. The outer `for (;;)` loop bails once `totalScanned` reaches that ceiling (or a chunk reaches the true end of the list), independent of whether the resume cursor keeps surviving. This guarantees termination even under an adversarial writer that repeatedly erases exactly the resume key during every released window while keeping the live prefix larger than `kScanBudget`: without the ceiling, the restart-from-front path could re-scan that prefix indefinitely and monopolize the `TimerService` thread. Forward progress does not rely on the list only shrinking (`put()` grows it at the front); it rests on the cursor advancing when the resume key survives, and on this ceiling when it does not.

The loop re-checks `stopping` at the top of every chunk (a liveness measure so a teardown-in-progress sweep bails promptly).

#### 3.1.8 `invalidate()`, `clear()`, `stats()`

`invalidate(key)` takes the exclusive lock and, if the key is present, calls the shared `removeNode` helper (erases from both `index` and `lru`, decrements `size`; does **not** touch the eviction counter, since this is not a capacity eviction). `clear()` takes the exclusive lock and empties `index` and `lru` and resets `size` to `0` -- the cumulative `hits`/`misses`/`evictions` counters are deliberately left monotonic. `stats()` is `const` and **fully lock-free**: it returns a `Stats` value built from four independent relaxed atomic loads, so it is an eventually-consistent snapshot, not a synchronized point-in-time total.

#### 3.1.9 Destruction

```cpp
~TtlMap()
{
  _state->stopping.store(true, std::memory_order_release);
  if (_sweepId != 0) { _timers.cancel(_sweepId); }
  _state.reset();
}
```

Three steps, in this order: publish the fast-path "stop soon" hint; ask the (borrowed) `TimerService` to cancel the periodic timer (best-effort -- see Section 6 on why `cancel()` alone is not the correctness mechanism); then drop this instance's `shared_ptr<State>` anchor **last**. `State` and its mutex survive for as long as any other `shared_ptr<State>` is alive -- specifically, for the duration of any sweep handler invocation that had already `lock()`'d the `weak_ptr` before this destructor ran. The destructor touches no member after `_state.reset()`.

`TtlMap` is explicitly non-copyable and non-movable (all four special members deleted) -- a `shared_ptr<State>` plus a `TimerService&` reference member make copy semantically ambiguous and move would leave a dangling registered sweep handler pointing at a relocated-but-not-really object.

### 3.2 `ExpiringCache<K, V>`

#### 3.2.1 Construction and the eviction callback

```cpp
ExpiringCache();                                                  // _ttl = 60s
explicit ExpiringCache(std::chrono::seconds ttl);
explicit ExpiringCache(std::chrono::seconds ttl, EvictionCallback callback);
```

All three constructors log an `info`-level line via the static `iora::core::Logger` and then call the private `startPurgeThread()`, which spawns `_purgeThread` immediately -- there is no separate "start" step. `EvictionCallback` is `std::function<void(const K&, const V&)>`; when supplied, it is invoked for **both** TTL-driven expiry (from `get()` or from the purge thread) **and** explicit `remove()` calls -- "eviction" here is not limited to automatic expiry.

#### 3.2.2 `set()` -- unconditional overwrite, no in-place mutation

```cpp
void set(const K &key, const V &value, std::chrono::seconds customTtl = std::chrono::seconds(0))
{
  auto expiration = std::chrono::steady_clock::now() + (customTtl.count() > 0 ? customTtl : _ttl);
  std::lock_guard<std::mutex> lock(_mutex);
  bool isUpdate = _cache.find(key) != _cache.end();
  _cache[key] = {value, expiration};
  ...
}
```

`customTtl` defaults to `0s`, which is used as a **sentinel** meaning "use the instance TTL" -- `customTtl.count() > 0` is the only branch that honors an override; a zero or negative `customTtl` silently falls back to `_ttl` rather than producing an immediately-expiring entry or an error (see Section 10). Unlike `TtlMap::put()`'s in-place mutation of an existing node, `ExpiringCache::set()` always replaces the whole `CacheEntry` via `operator[]` assignment.

#### 3.2.3 `get()` -- copy-then-invoke on expiry

```cpp
std::optional<V> get(const K &key)
{
  std::optional<std::pair<K, V>> evicted;
  {
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _cache.find(key);
    if (it != _cache.end())
    {
      if (it->second.expiration > std::chrono::steady_clock::now())
      {
        return it->second.value;                    // hit: returned while the lock is still held
      }
      if (_evictionCallback) { evicted.emplace(it->first, it->second.value); }
      _cache.erase(it);
    }
  }
  if (evicted) { _evictionCallback(evicted->first, evicted->second); }
  return std::nullopt;
}
```

On a hit, the value is returned directly from inside the `lock_guard`'s scope -- the lock is released as part of normal RAII stack unwinding on the `return`, not before it. On an expired entry, the entry is captured and erased **under** the lock, then the callback fires **after** the lock is released -- the same copy-then-invoke discipline used throughout Iora to avoid deadlocking a caller whose callback re-enters `get`/`set`/`remove`. Because `get()` runs on an arbitrary caller thread (which has a caller of its own), an exception thrown by the callback here is allowed to propagate normally -- there is no `try`/`catch` around this particular invocation (contrast with the purge thread, Section 3.2.5).

#### 3.2.4 `remove()` and `size()`

`remove(key)` mirrors `get()`'s copy-then-invoke discipline: erase under the lock, capture the evicted pair if a callback is set, then fire the callback after the lock is released. `size() const` takes `_mutex` (declared `mutable`) and returns `_cache.size()`.

#### 3.2.5 The purge thread

```cpp
void startPurgeThread()
{
  _purgeThread = std::thread([this]()
  {
    while (true)
    {
      std::vector<std::pair<K, V>> evicted;
      {
        std::unique_lock<std::mutex> lock(_mutex);
        if (_stopCondition.wait_for(lock, std::chrono::seconds(5), [this]() { return _stop; }))
        {
          break;                                     // woken by shutdown
        }
        auto now = std::chrono::steady_clock::now();
        for (auto it = _cache.begin(); it != _cache.end();)
        {
          if (it->second.expiration <= now)
          {
            if (_evictionCallback) { evicted.emplace_back(it->first, it->second.value); }
            it = _cache.erase(it);
          }
          else { ++it; }
        }
      }
      for (auto &kv : evicted)
      {
        try { _evictionCallback(kv.first, kv.second); }
        catch (const std::exception &e) { iora::core::Logger::error(...); }
        catch (...) { iora::core::Logger::error(...); }
      }
    }
  });
}
```

The wait uses `_stopCondition.wait_for(lock, 5s, predicate)`, which returns `true` either when the predicate (`_stop`) is already satisfied or becomes satisfied before the 5-second timeout -- so shutdown wakes the thread **immediately** rather than waiting out the remainder of the poll interval. On a normal (non-shutdown) timeout, the entire cache is scanned once for expired entries under the held lock, then the lock is released and every evicted entry's callback fires, wrapped in `try`/`catch`. This guard exists because the purge thread has **no caller** -- an exception escaping it would call `std::terminate` and abort the process; here it is logged and the loop continues.

#### 3.2.6 Destruction

```cpp
~ExpiringCache()
{
  { std::lock_guard<std::mutex> lock(_mutex); _stop = true; }
  _stopCondition.notify_one();
  if (_purgeThread.joinable()) { _purgeThread.join(); }
}
```

Setting `_stop` under the lock and then notifying **after** releasing it (the `lock_guard`'s scope ends first) avoids notifying while the mutex is still held; the purge thread's `wait_for` predicate check picks up `_stop == true` and exits immediately, rather than waiting for the next natural 5-second tick.

#### 3.2.7 `ExpiringCacheTestAccessor`

```cpp
template <typename K, typename V> struct ExpiringCacheTestAccessor
{
  static std::size_t mapSize(ExpiringCache<K, V> &cache);   // friend; peeks _cache.size() under _mutex
};
```

A `friend struct`, declared as a forward-declared friend inside `ExpiringCache`, used only by the test suite to observe internal map size without going through the public `size()` API (which is behaviorally identical here but exists as a distinct symbol for tests that want to assert on internal state rather than the public contract).

---

## 4. Usage Guide

### 4.1 Which to use when

| Need | Use |
|---|---|
| Bounded memory under a high-cardinality key space (per-source-IP, per-call-ID, ...) | `TtlMap` (`Config::maxEntries`) |
| Read-heavy hot path with many concurrent lookups | `TtlMap` (`get()` is a shared lock; readers never contend with each other) |
| You already run an `iora::core::TimerService` you can inject | `TtlMap` |
| A quick TTL cache with no capacity concerns, in a context with no `TimerService` handy | `ExpiringCache` |
| You need `hits`/`misses`/`evictions`/`size` observability with zero extra locking | `TtlMap::stats()` |
| An existing `ExpiringCache` consumer with no current pain point | Leave it as `ExpiringCache` -- there is no forced migration (see Section 1) |

### 4.2 `TtlMap` -- basic bounded cache with an injected `TimerService`

```cpp
#include "iora/core/timer.hpp"
#include "iora/util/ttl_map.hpp"
#include <string>

using namespace iora::core;
using namespace iora::util;

TimerService timers;                                    // owned by the application; outlives the map

TtlMap<std::string, std::string>::Config cfg{
    std::chrono::seconds(600),   // defaultTtl
    100000,                      // maxEntries
    std::chrono::seconds(60)};   // sweepInterval

TtlMap<std::string, std::string> routeCache(cfg, timers);

void onInvite(const std::string &callId, const std::string &route)
{
  routeCache.put(callId, route);
}

std::optional<std::string> lookupRoute(const std::string &callId)
{
  return routeCache.get(callId);
}

// Teardown, in this order (see Section 6):
//   1. destroy/reset every TtlMap that references `timers`
//   2. THEN drain()/stop() `timers` (or let its destructor run)
```

### 4.3 `TtlMap` -- per-call TTL override and observability

```cpp
TtlMap<int, std::int64_t>::Config cfg{std::chrono::seconds(30), 5000};
TimerService timers;
TtlMap<int, std::int64_t> cache(cfg, timers);

cache.put(42, 100);                              // uses defaultTtl (30s)
cache.put(43, 200, std::chrono::seconds(5));      // this entry expires in 5s instead

auto stats = cache.stats();
std::cout << "hits=" << stats.hits << " misses=" << stats.misses
          << " evictions=" << stats.evictions << " size=" << stats.size << "\n";
```

### 4.4 `TtlMap` -- mandatory teardown ordering (worker owns a `shared_ptr<TtlMap>`)

```cpp
#include <memory>

TimerService timers;
auto cache = std::make_unique<TtlMap<std::string, int>>(
    TtlMap<std::string, int>::Config{std::chrono::seconds(60), 10000}, timers);

// ... use *cache across worker threads ...

cache.reset();          // ~TtlMap runs FIRST: stopping=true, cancel(sweepId), _state.reset()
timers.drain(3000);     // THEN drain/stop the TimerService the map was injected with
timers.stop();
```

### 4.5 `ExpiringCache` -- TTL-only cache with an eviction callback

```cpp
#include "iora/util/expiring_cache.hpp"
#include <string>

using namespace iora::util;

ExpiringCache<std::string, std::string> sessionCache(
    std::chrono::seconds(120),
    [](const std::string &key, const std::string &value)
    {
      // Fired outside any internal lock -- safe to call back into the cache here.
      logSessionExpired(key, value);
    });

sessionCache.set("session-abc", "active");
sessionCache.set("session-def", "active", std::chrono::seconds(10)); // this one: 10s override

if (auto v = sessionCache.get("session-abc"))
{
  // use *v
}

sessionCache.remove("session-def");   // ALSO fires the eviction callback -- not TTL-only
```

### 4.6 Anti-patterns

- **Do NOT destroy the `iora::core::TimerService` before every `TtlMap` that references it.** The service is injected, not owned; a `TtlMap` outliving its `TimerService` leaves a dangling reference the moment `put`/`get`/the destructor touches `_timers`.
- **Do NOT call `put`/`get`/`invalidate`/`clear`/`stats` concurrently with a `TtlMap`'s own destructor.** The `weak_ptr<State>` guard protects only the in-flight sweep handler against a racing destructor -- it does **not** protect an external caller racing `~TtlMap`, because the non-atomic `_state` member itself is not synchronized against `_state.reset()` (see Section 6).
- **Do NOT assume `ExpiringCache::set(key, value, std::chrono::seconds(0))` creates an immediately-expiring entry.** `0` (or any non-positive value) is the "no override" sentinel and silently falls back to the instance's default TTL.
- **Do NOT treat `ExpiringCache`'s `EvictionCallback` as TTL-only.** It also fires for explicit `remove()` calls; if your callback assumes "this only happens because the TTL elapsed," it will be wrong for manually removed entries.
- **Do NOT rely on `TtlMap::get()` to reclaim memory promptly for an expired entry.** It performs a deferred reap (no erase under the shared lock); physical reclamation happens on the next writer touching that node, or the next sweep. If you need bounded memory under sparse reads, size `maxEntries` and rely on the LRU eviction path, not on `get()`-driven expiry.
- **Do NOT instantiate `TtlMap<K, V>` with a `V` that is copy-constructible but not (copy- or move-)assignable.** `put()` on an **existing** key performs `nodeIt->value = std::move(value)`, which requires `V` to be assignable. The class now checks this directly: a second `static_assert(std::is_move_assignable_v<V> || std::is_copy_assignable_v<V>, ...)` fails the build with an explicit message at class-template instantiation, rather than deep-erroring the first time an existing-key `put()` call is instantiated.

---

## 5. Call Flow / Sequence Reference

### 5.1 `TtlMap::put` -- new key that triggers eviction

| Step | Actor | Action | Lock state |
|---|---|---|---|
| 1 | Caller | `put(key, value)`; `_cfg.maxEntries != 0` so proceed. | no lock |
| 2 | `put` | Acquire `s.mutex` exclusively. | `unique_lock` held |
| 3 | `put` | `s.index.find(key)` misses -> new-key path. | `unique_lock` held |
| 4 | `put` | `s.lru.emplace_front(...)`; `s.index.emplace(...)`; `size.fetch_add(1)`. | `unique_lock` held |
| 5 | `put` | `newSize > maxEntries` -> `evictOne(s, now)`: scan from LRU tail up to 8 hops for a non-recent victim, else evict the tail unconditionally; `evictions.fetch_add(1)`. | `unique_lock` held |
| 6 | `put` | Release `s.mutex`; return. | released |

### 5.2 `TtlMap::get` -- hit vs. expired-miss

| Step | Actor | Action | Lock state |
|---|---|---|---|
| 1 | Caller | `get(key)`; acquire `s.mutex` shared. | `shared_lock` held |
| 2 | `get` | `s.index.find(key)` hits; dereference `NodeIter`. | `shared_lock` held |
| 3a | `get` (live) | `expiresAt > now` -> store `lastAccess` (relaxed); `hits.fetch_add(1)`; copy `value`. | `shared_lock` held |
| 3b | `get` (expired) | `expiresAt <= now` -> `misses.fetch_add(1)`; **no erase, no splice**. | `shared_lock` held |
| 4 | `get` | Release `s.mutex`; return `optional<V>`. | released |

### 5.3 `TtlMap` periodic sweep tick

| Step | Actor | Action | Lock state |
|---|---|---|---|
| 1 | `TimerService` timer thread | Periodic tick fires the registered lambda; `weak.lock()`. | no lock |
| 2 | lambda | If `!s` (State destroyed) or `s->stopping`: return early -- no-op. | no lock |
| 3 | `sweepState` | Compute `visitCeiling = size-at-entry + kScanBudget`. Re-check `stopping`. | no lock |
| 4 | `sweepState` | Acquire `s.mutex` exclusively; resume at `sweepResume`'s node if that key is still in `index`, else from the LRU front. | `unique_lock` held |
| 5 | `sweepState` | Scan forward, erasing entries with `expiresAt <= now`, until either `kReapBatch = 512` erasures or `kScanBudget = 4096` nodes visited, whichever comes first. | `unique_lock` held |
| 6 | `sweepState` | If the scan reached `s.lru.end()`: clear `sweepResume` (full pass complete). Otherwise: set `sweepResume` to the current node's key. | `unique_lock` held |
| 7 | `sweepState` | Release `s.mutex`; add this chunk's scanned count to `totalScanned`. | released |
| 8 | `sweepState` | If the scan reached the end, or `totalScanned >= visitCeiling`: return. Otherwise loop to step 3 (re-check `stopping`, re-sample `now`, re-acquire the lock for the next chunk). | varies |

### 5.4 `TtlMap` construction / destruction ordering (with the injected `TimerService`)

| Phase | Actor | Action |
|---|---|---|
| Construct | `TtlMap(cfg, timers)` | `State` fully built (member-init list) -> weak_ptr captured -> `timers.schedulePeriodic(...)` called LAST -> throws `std::runtime_error` on `id == 0`. |
| Steady state | any caller / timer thread | `put`/`get`/... from callers; periodic sweeps from the timer thread; all safe to interleave. |
| Destroy | `~TtlMap()` | `stopping.store(true)` -> `timers.cancel(sweepId)` (best-effort; collect-then-fire dispatch may still run an already-collected handler) -> `_state.reset()` (State survives until every `weak_ptr::lock()`'d copy elsewhere drops). |
| Prerequisite | application | The injected `TimerService` must still be running (not yet destroyed) when `~TtlMap` runs, and must be drained/stopped only **after** every `TtlMap` referencing it has been destroyed. |

### 5.5 `ExpiringCache::get` -- expired entry, callback set

| Step | Actor | Action | Lock state |
|---|---|---|---|
| 1 | Caller | `get(key)`; acquire `_mutex`. | `lock_guard` held |
| 2 | `get` | `_cache.find(key)` hits; `expiration <= now`. | `lock_guard` held |
| 3 | `get` | Capture `{key, value}` into `evicted` (callback is set); `_cache.erase(it)`. | `lock_guard` held |
| 4 | `get` | End of block -> `lock_guard` destructor releases `_mutex`. | released |
| 5 | `get` | `_evictionCallback(evicted->first, evicted->second)` invoked with no lock held. | no lock |
| 6 | `get` | Return `std::nullopt`. | no lock |

### 5.6 `ExpiringCache` purge tick

| Step | Actor | Action | Lock state |
|---|---|---|---|
| 1 | `_purgeThread` | `wait_for(lock, 5s, pred)` acquires `_mutex` as part of taking the `unique_lock`. | `unique_lock` held (via CV wait) |
| 2 | `_purgeThread` | Predicate `_stop` false and timeout elapses -> proceed to purge. | `unique_lock` held |
| 3 | `_purgeThread` | Scan `_cache`; erase every entry with `expiration <= now`; collect evicted pairs into a local `vector` if a callback is set. | `unique_lock` held |
| 4 | `_purgeThread` | End of block -> lock released. | released |
| 5 | `_purgeThread` | For each evicted pair: invoke `_evictionCallback` inside `try`/`catch`; log and continue on any exception. | no lock |
| 6 | `_purgeThread` | Loop back to step 1. | -- |

### 5.7 `ExpiringCache` destruction

| Step | Actor | Action | Lock state |
|---|---|---|---|
| 1 | `~ExpiringCache` | Acquire `_mutex`; set `_stop = true`. | `lock_guard` held |
| 2 | `~ExpiringCache` | End of block -> release `_mutex`. | released |
| 3 | `~ExpiringCache` | `_stopCondition.notify_one()`. | no lock |
| 4 | `~ExpiringCache` | If `_purgeThread.joinable()`, `join()` -- blocks until the purge thread observes `_stop` and exits its loop. | no lock (caller thread blocks in `join`) |

---

## 6. Thread Safety Model

### 6.1 `TtlMap`

| Operation | Synchronization | Notes |
|---|---|---|
| `put` | `std::unique_lock<std::shared_mutex>` on `State::mutex`. | Single critical section: index + LRU + counters + any eviction, no intermediate release. |
| `get` | `std::shared_lock<std::shared_mutex>` on `State::mutex`. | **Read-only on structure.** Writes only `Node::lastAccess` (relaxed atomic) and one of `hits`/`misses` (relaxed atomic). Never splices or erases. `const`-qualified. |
| `invalidate` | `std::unique_lock` on `State::mutex`. | Calls the shared `removeNode` helper; does not touch `evictions`. |
| `clear` | `std::unique_lock` on `State::mutex`. | Resets `index`/`lru`/`size`; leaves `hits`/`misses`/`evictions` monotonic. |
| `stats` | **None.** | Four independent relaxed atomic loads (`hits`, `misses`, `evictions`, `size`). Eventually consistent, not a synchronized snapshot. |
| Periodic sweep (`sweepState`) | `std::unique_lock` on `State::mutex`, reacquired once per chunk. | Genuinely bounded per acquisition: at most `kScanBudget = 4096` nodes visited AND at most `kReapBatch = 512` erased, whichever limit is hit first. Releases the lock between chunks so readers/writers progress. Resumes by key (`State::sweepResume`) across releases; a per-invocation visit ceiling (size-at-entry + `kScanBudget`) guarantees termination. Re-checks `stopping` at the top of each chunk. |

**Mutex/atomic inventory (from source):**

- `State::mutex` (`mutable std::shared_mutex`) -- the map's only lock. `get()`/`stats()`-style reads take it shared (`stats()` in fact takes no lock at all); `put`/`invalidate`/`clear`/eviction/sweep take it exclusive. One mutex, no lock-ordering concern.
- `Node::lastAccess` (`std::atomic<std::int64_t>`) -- relaxed load/store; the approximate-recency signal. Correct under relaxed ordering because it "guards" no other memory -- the shared/exclusive transition on `State::mutex` is what establishes happens-before for the eviction-time read.
- `State::hits` / `State::misses` / `State::evictions` (`std::atomic<std::uint64_t>`) -- relaxed `fetch_add`, read via `stats()`'s relaxed loads.
- `State::size` (`std::atomic<std::size_t>`) -- relaxed `fetch_add`/`fetch_sub`, maintained only under the exclusive lock (readers never touch it).
- `State::stopping` (`std::atomic<bool>`) -- release store in `~TtlMap`; acquire loads in the sweep handler and at the top of every `sweepState` chunk. This is the release/acquire pair that makes "destructor asked to stop" visible to the sweep handler without requiring `State::mutex`.
- `State::sweepResume` (`std::optional<K>`, plain, not atomic) -- read and written only inside `sweepState`, always under the exclusive `State::mutex`, so it needs no independent synchronization. Storing a key rather than a `std::list` iterator is what makes the cursor safe to carry across the lock release between chunks.

**The lifetime-safety mechanism -- `std::weak_ptr<State>`, not `TimerService::cancel()`.** The sweep handler captures `std::weak_ptr<State> weak` (not `this`, not a raw `State*`). On fire, it calls `weak.lock()`; a successful lock produces a `shared_ptr<State>` that keeps `State` (its mutex and containers) alive for the **entire** critical section of that invocation, even if `~TtlMap` is running concurrently on another thread. `TimerService::cancel()` is a **best-effort, non-blocking** ("collect-then-fire") request: if the run loop has already collected this handler for the current tick before `cancel()` is observed, that already-collected handler still fires. The `weak_ptr` guard is what makes that fire safe rather than a use-after-free -- `cancel()` alone is not the correctness mechanism, only an optimization that reduces (not eliminates) how often a post-destruction sweep tick actually runs `sweepState`.

**The public-API-vs-destructor contract.** `_state` itself is a plain (non-atomic) `std::shared_ptr<State>` member of `TtlMap`. `~TtlMap`'s `_state.reset()` is **not synchronized** against a concurrent caller thread reading `_state` inside `put`/`get`/`invalidate`/`clear`/`stats` -- there is no mutex guarding the `TtlMap` object itself, only the `State` it points to. Consequently: **public methods must not be called concurrently with `~TtlMap`.** This is a hard caller obligation, not something the class enforces internally; the `weak_ptr` guard protects only the *sweep handler's* access path, which is structurally incapable of touching `TtlMap` members in the first place (see Section 3.1.7).

**Lifetime contract with the injected `TimerService`.** The `TimerService&` is not owned. It must outlive every `TtlMap` constructed with it, and it must be drained/stopped only **after** the last such `TtlMap` is destroyed -- relying on member-declaration order between a `TimerService` and a `TtlMap` inside some enclosing owner is explicitly called out in the header as insufficient; the header recommends an explicit `timers.stop()`/`drain()` call sequenced after every dependent `TtlMap`'s destruction.

### 6.2 `ExpiringCache`

| Operation | Synchronization | Notes |
|---|---|---|
| `set` | `std::lock_guard<std::mutex>` on `_mutex`. | Whole-`CacheEntry` replace via `operator[]`; no in-place field mutation. |
| `get` | `std::lock_guard<std::mutex>` on `_mutex`; copy-then-invoke for the expired-eviction callback. | Hit path returns from inside the lock's scope (released by RAII on return). Expired path: erase under lock, invoke callback after release. No `try`/`catch` around this callback invocation -- it runs on the caller's thread, which has its own caller to catch an exception. |
| `remove` | `std::lock_guard<std::mutex>` on `_mutex`; copy-then-invoke. | Fires the callback for **any** removal, not only expiry-driven ones. |
| `size` | `std::lock_guard<std::mutex>` on `mutable _mutex`. | `const`; single lock/unlock around `_cache.size()`. |
| Purge thread body | `std::unique_lock<std::mutex>` on `_mutex`, held across the CV wait and the full-map scan; released before firing callbacks. | Collect-then-invoke: evicted pairs are gathered under the lock into a local `vector`, callbacks fire after release, each wrapped in `try`/`catch` (see below). |
| Destructor | `std::lock_guard<std::mutex>` to set `_stop`; `notify_one()` **after** the lock is released; `join()` outside any lock. | The notify-after-unlock ordering means the purge thread's `wait_for` predicate check reliably observes `_stop == true` without a lost-wakeup window. |

**Mutex/CV inventory (from source):**

- `_mutex` (`mutable std::mutex`) -- guards `_cache` and `_stop`. Every public method and the purge thread take it.
- `_stopCondition` (`std::condition_variable`) -- the purge thread's `wait_for(lock, 5s, [this]{ return _stop; })` normally times out and purges; `notify_one()` in the destructor wakes it immediately instead of waiting up to 5 seconds for the natural tick.

**Copy-then-invoke discipline.** Every path that can fire `EvictionCallback` (`get()`'s expired branch, `remove()`, the purge thread's sweep) captures the evicted key/value pair(s) **while holding `_mutex`**, releases the lock, and only then invokes the callback. This is what allows a callback to safely call back into the same `ExpiringCache` (e.g. `set()` a replacement, or `remove()` a related key) without deadlocking on `_mutex`.

**Exception safety asymmetry.** Only the purge thread's callback invocation is wrapped in `try`/`catch` (catching `std::exception` and `...`, logging and continuing). `get()`'s and `remove()`'s callback invocations are **not** wrapped -- an exception there propagates to the calling thread's own caller, which is the normal, expected behavior for code running on a thread with a call stack. The purge thread has no such caller; an unguarded exception there would call `std::terminate`.

---

## 7. Configuration Reference

### 7.1 `TtlMap::Config`

| Field | Type | Default | Units | Notes |
|---|---|---|---|---|
| `defaultTtl` | `std::chrono::seconds` | **(required -- no default)** | seconds | TTL applied by `put()` when its `ttl` argument is omitted. |
| `maxEntries` | `std::size_t` | **(required -- no default)** | count | `0` disables the cache (`put()` no-op; `get()` always misses because nothing is ever inserted). `1` means every new distinct key evicts the prior entry. |
| `sweepInterval` | `std::chrono::seconds` | `60` | seconds | Cadence of the periodic sweep scheduled on the injected `TimerService`. **Also** used as the approximate-LRU "recent" threshold in `evictOne()` (`lastAccess >= now - sweepInterval`) -- these are two different concerns sharing one field; see Section 10. |

### 7.2 `TtlMap` internal constants (not configurable)

| Constant | Value | Location | Meaning |
|---|---|---|---|
| `kMaxHops` | `8` | `evictOne()` | Maximum second-chance hops from the LRU tail before an unconditional tail eviction. |
| `kReapBatch` | `512` | `sweepState()` | Maximum number of erasures performed per `State::mutex` acquisition during a sweep tick. Renamed from `kBatch`; `static_assert(kReapBatch <= kScanBudget)` enforces that erasures are a subset of nodes visited. |
| `kScanBudget` | `4096` | `sweepState()` | Maximum number of nodes **visited** (scanned, not necessarily erased) per `State::mutex` acquisition during a sweep tick -- the bound that caps the worst-case reader/writer stall regardless of map size or expiry sparsity. |

### 7.3 `ExpiringCache`

| Parameter | Type | Default | Units | Notes |
|---|---|---|---|---|
| `ttl` (constructor) | `std::chrono::seconds` | `60` | seconds | Instance-wide default TTL, used by `set()` whenever `customTtl` is not a positive value. |
| `customTtl` (per-`set()` override) | `std::chrono::seconds` | `0` | seconds | `0` (or negative) is the "no override" sentinel -- falls back to the instance `ttl`. There is no way to request an immediately-expiring entry through this parameter. |
| `callback` (constructor) | `EvictionCallback` | none (empty `std::function`) | -- | Fires (copy-then-invoke) for expiry via `get()`, the purge thread's sweep, **and** explicit `remove()`. |
| Purge interval | -- | `5` seconds | seconds | Hardcoded in `startPurgeThread()`'s `wait_for` call; not exposed as a constructor parameter. |

---

## 8. API Reference

```cpp
namespace iora
{
namespace util
{

template <typename K, typename V, typename Hash = std::hash<K>,
          typename KeyEqual = std::equal_to<K>>
class TtlMap
{
public:
  struct Config
  {
    std::chrono::seconds defaultTtl;
    std::size_t maxEntries;
    std::chrono::seconds sweepInterval{std::chrono::seconds{60}};
  };

  struct Stats
  {
    std::uint64_t hits;
    std::uint64_t misses;
    std::uint64_t evictions;
    std::size_t size;
  };

  TtlMap(Config cfg, iora::core::TimerService &timers);   // throws std::runtime_error on schedule failure
  ~TtlMap();

  TtlMap(const TtlMap &) = delete;
  TtlMap &operator=(const TtlMap &) = delete;
  TtlMap(TtlMap &&) = delete;
  TtlMap &operator=(TtlMap &&) = delete;

  void put(const K &key, V value, std::optional<std::chrono::seconds> ttl = {});
  std::optional<V> get(const K &key) const;
  void invalidate(const K &key);
  void clear();
  Stats stats() const;
};

template <typename K, typename V> class ExpiringCache
{
public:
  using EvictionCallback = std::function<void(const K &key, const V &value)>;

  ExpiringCache();
  explicit ExpiringCache(std::chrono::seconds ttl);
  explicit ExpiringCache(std::chrono::seconds ttl, EvictionCallback callback);
  ~ExpiringCache();

  void set(const K &key, const V &value,
           std::chrono::seconds customTtl = std::chrono::seconds(0));
  std::optional<V> get(const K &key);
  void remove(const K &key);
  std::size_t size() const;

  friend struct ExpiringCacheTestAccessor<K, V>;
};

template <typename K, typename V> struct ExpiringCacheTestAccessor
{
  static std::size_t mapSize(ExpiringCache<K, V> &cache);
};

} // namespace util
} // namespace iora
```

---

## 9. Design Decisions

| ID | Decision | Rationale |
|---|---|---|
| D-1 | `TtlMap` and `ExpiringCache` coexist as **additive siblings**; `TtlMap` did not replace `ExpiringCache`. | `ExpiringCache` predates `TtlMap` and has existing consumers with no current pain point. Consolidating/deprecating it is an explicit, separate follow-up (see Section 10), not part of `TtlMap`'s scope. |
| D-2 | `TtlMap::get()` takes a **shared** lock and never mutates structure. | The primary target workload (route/registration caches, ~100k entries, hot lookups) needs concurrent readers that never contend with each other; a strict-LRU or eager-erase `get()` would require a write under that lock. |
| D-3 | Approximate LRU via a per-node relaxed `lastAccess` atomic, list order maintained by writers only. | Strict LRU needs a move-to-front on every read, incompatible with a shared-lock `get()`. Bounded second-chance eviction trades exact recency for read-path cheapness. |
| D-4 | Lazy expiry with **deferred** physical reap in `get()`. | `std::shared_mutex` has no atomic upgrade in C++17; erasing on an expired `get()` would require dropping and reacquiring the lock exclusively, reopening a race window. Deferral to the next writer or sweep is simpler and correct. |
| D-5 | Sweeper runs on an **injected** `iora::core::TimerService`; `TtlMap` owns no thread. | Reuses whatever scheduling infrastructure the application already runs, instead of spending one OS thread per cache instance. |
| D-6 | Sweep handler captures `std::weak_ptr<State>`, dispatches to a `static` function, never touches `TtlMap` members. | `TimerService::cancel()` is best-effort/non-blocking; an already-collected handler can still fire after `~TtlMap` begins. The `weak_ptr` (backed by `State` living on the heap via `shared_ptr`) is what makes that late fire a safe no-op instead of a use-after-free. |
| D-7 | `Config::sweepInterval` doing double duty as both sweep cadence and LRU recency threshold. | Reuses one existing "how stale is stale" notion instead of introducing a second tunable; the trade-off is a coupling a caller must understand (see Section 10). |
| D-8 | `ExpiringCache` owns a dedicated purge `std::thread` per instance, woken by a `condition_variable` rather than a fixed `sleep_for`. | Predates `TimerService`-based scheduling in this codebase; the CV wake-on-shutdown fix (`_stopCondition`) avoids the earlier failure mode of waiting out a full 5-second sleep during teardown. |
| D-9 | `ExpiringCache`'s `EvictionCallback` fires for explicit `remove()` as well as TTL expiry. | A single callback path covers "this key is gone" regardless of cause, at the cost of the name implying TTL-only semantics (see Section 10). |
| D-10 | Both classes use copy-then-invoke for any user-supplied callback (`ExpiringCache::EvictionCallback`) or user handler (`TtlMap`'s sweep, dispatched through `TimerService`). | Prevents deadlock if a callback re-enters the cache, and keeps arbitrary-duration user code from running under an internal lock. |
| D-11 | `TtlMap` is non-copyable and non-movable; `ExpiringCache` is likewise never copied/moved (no copy/move members declared, and both hold non-movable synchronization primitives). | Both hold either a live thread/timer registration or a `shared_ptr` anchor tied to a specific registered callback; copying or moving would either double-register or leave a stale reference. |
| D-12 | `sweepState()` bounds nodes **scanned** per lock acquisition (`kScanBudget = 4096`), not just erasures (`kReapBatch = 512`), and carries its position across lock releases as a resume-by-**key** cursor (`State::sweepResume`), plus a per-invocation visit ceiling. | An erasure-only bound left a sparse-expiry or high-hit-rate map -- the stated target workload -- free to walk the entire list under one continuous exclusive lock, stalling every hot-path `get()`. A key survives a released lock where a `std::list` iterator could dangle to a concurrent erase; the visit ceiling guarantees termination even if an adversarial writer keeps re-invalidating the resume key. |
| D-13 | `TtlMap::get()` is `const`-qualified. | `get()` only mutates atomics inside `State`, reached through `*_state` (whose constness does not propagate to the pointee) -- it performs no structural mutation. Matching `stats() const` lets a caller holding only a `const TtlMap&` still look up entries. |

---

## 10. Known Limitations

Per this project's code-defect honesty rule, every item below is reported as a finding regardless of when the code was written or how deliberate it looks; disposition is the human's call, not this guide's.

- **`Config::sweepInterval` is overloaded to mean two different things.** It sets both the periodic sweep's cadence (how often expired entries are physically reaped) and the approximate-LRU "recent" threshold in `evictOne()` (`lastAccess >= now - sweepInterval`). A caller tuning one concern (e.g. shortening the sweep interval to reclaim memory faster) unavoidably also tightens the LRU recency window, making eviction behave closer to strict LRU; lengthening it for a lighter sweep load makes almost every candidate look "recent," pushing eviction toward "always evict the strict tail" (the second-chance loop degenerates to its unconditional fallback). This coupling is not called out anywhere as a caveat for the caller, only as an internal implementation note.
- **`TtlMap`'s public methods have no internal guard against being called concurrently with `~TtlMap`.** This is stated explicitly in the header as a caller obligation (the `weak_ptr<State>` guard protects only the sweep handler, not external callers, because `_state` itself is an unsynchronized plain member), but it means a single missed synchronization point in a consuming application is a live use-after-free with no diagnostic. There is no assertion, no debug-mode check, and no `shared_from_this`-style safety net for this specific path.
- **`ExpiringCache::set()`'s `customTtl` sentinel silently discards zero and negative values.** `customTtl.count() > 0 ? customTtl : _ttl` means a caller cannot express "expire immediately" via this parameter, and a negative duration (which is arguably caller error) is treated identically to "no override" rather than rejected or clamped.
- **`ExpiringCache`'s `EvictionCallback` name implies TTL-only semantics but also fires on explicit `remove()`.** A consumer who wires up eviction handling assuming it only ever fires for expiry (e.g., to emit an "expired" metric) will also see it fire for ordinary, intentional removals, with no way to distinguish the two causes from the callback's arguments alone.
- **`ExpiringCache`'s purge interval (5 seconds) is a compile-time constant with no constructor parameter.** An application needing a shorter or longer sweep cadence than 5 seconds cannot configure `ExpiringCache` to provide it; the only lever is the TTL itself.
- **`ExpiringCache`'s purge thread holds `_mutex` across a full O(n) scan every 5 seconds.** `expiring_cache.hpp`'s `startPurgeThread()` takes `_mutex` for the CV wait and keeps it held through the entire `for (auto it = _cache.begin(); ...)` scan-and-erase over the whole `_cache` map, releasing only at the end of that block. Because `_mutex` is the single lock guarding `set`/`get`/`remove`/`size`, every caller blocks for the full duration of the purge scan once per 5 seconds -- the `ExpiringCache` analogue of the `sweepState` defect `TtlMap` fixed (see Design Decision D-12), except `ExpiringCache`'s `std::unordered_map` backing cannot safely adopt the same resume-by-key chunking (a saved iterator can dangle on erase, and `set()` can rehash and invalidate every iterator, so a bounded chunked scan would need a new expiry-ordered auxiliary structure). Tracked as `tasks/iora/backlog/2026-09-18-2_expiring-cache-purge-unbounded-lock-hold_P1.json`.
- **Consolidating `TtlMap` and `ExpiringCache` remains an open, unscheduled follow-up.** The `TtlMap` architecture document (`architecture/iora/ttl_map.json`) records this explicitly as `out_of_scope` for `TtlMap`'s initial delivery: "once `TtlMap` ships, evaluate consolidating/superseding `ExpiringCache` to avoid two TTL caches." Tracked as `tasks/iora/backlog/2026-09-18-3_ttlmap-expiringcache-consolidation-eval_P2.json`.
- **`TtlMap`'s concurrency correctness IS now verified under ThreadSanitizer.** The TSan soak ran to completion and PASSED: 79 assertions across 19 test cases, including the architecture-mandated 100-thread x 100k-op self-validating concurrency soak and the teardown/UAF tests, with 0 TSan warnings (no data races, no deadlocks) -- run on x86_64 WSL2 via `setarch -R` to work around the ASLR/`personality()` restriction that had blocked the run in an earlier sandbox. See `tasks/iora/completed/2026-06-13-1_ttl-map-tsan-soak-run_P1.json` (status `DONE`, resolution "PASS - 0 TSan warnings"). This is no longer an outstanding gap; retained here, corrected, for continuity with the prior revision of this guide, which listed it as unverified.
