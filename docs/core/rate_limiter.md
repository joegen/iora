# Iora TokenBucket, SlidingWindowCounter & RateLimiterMap -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 2.0 |
| **Date** | 2026-09-10 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/core/rate_limiter.hpp` |
| **Namespace** | `iora::core` |
| **Public classes** | `TokenBucket`, `SlidingWindowCounter`, `RateLimiterMap\<K\>` |
| **Dependencies** | Two intra-Iora headers -- `iora/core/concurrent_hash_map.hpp` (`ConcurrentHashMap`, the sharded per-key store) and `iora/core/timing_wheel.hpp` (`TimingWheel`, optional auto-cleanup scheduling). Standard library: `<algorithm>`, `<chrono>`, `<cmath>`, `<deque>`, `<mutex>`, `<vector>` (and, transitively via `ConcurrentHashMap`, `<atomic>`/`<shared_mutex>`). No external/third-party dependencies. |

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-03-20 | Initial implementation. |
| 1.1 | 2026-03-20 | Fast-path `findAndModify`, atomic defaults, `insertOrAssign` for `setKeyRate`, `_lastAccess` only on success, `TimingWheel` auto-cleanup. |
| 2.0 | 2026-09-10 | **Migrated** into `docs/core/rate_limiter.md` for the iora v1 documentation-wiki (core:primitives CP-2) and **fully re-verified** line-by-line against `include/iora/core/rate_limiter.hpp` (333 lines) and `tests/core/iora_test_rate_limiter.cpp`. Restructured to the 12-section guide template with contiguous numbered sections and a `[Back to index]` link. Corrected a stale `SlidingWindowCounter::timeUntilAvailable()` limitation (the previous "all entries expired" characterization was imprecise -- see section 11), replaced a usage example that double-consumed a token when computing `Retry-After`, and routed every behavioral caveat to a concrete finding. Newly surfaced defects (division-by-zero at `rate == 0`, torn default-rate pair under relaxed atomics, cleanup-vs-consume race, spurious denial in the `tryConsume` slow path) are recorded in section 11 and cross-referenced to the open backlogs `tasks/iora/backlog/2026-06-04-1` and `2026-06-04-2`. |

---

## 1. Executive Summary

### Problem

Iora ships no built-in rate limiting. Without it, every deployment either hardcodes limits, leans on external infrastructure (nginx `limit_req`, iptables `hashlimit`), or re-invents a counter. The demanding case is per-source-IP protection against a SIP `REGISTER` flood: it needs thousands of independent counters keyed by source address, each cheap to look up under contention, with automatic reclamation of idle keys so a flood cannot grow memory without bound. A single global counter cannot express "5 requests per IP per minute"; a `std::map<IP, counter>` behind one mutex serializes every check across every source.

### Solution

Three composable primitives in `iora::core`:

- **`TokenBucket`** -- allows a burst up to a capacity, then enforces a steady refill rate. Lazy (on-demand) replenishment, no background timer, plain `double` arithmetic, no internal locking. Best for API-style limits where a short burst is acceptable.
- **`SlidingWindowCounter`** -- strict "no more than N requests in any T-second window", with **no** burst allowance. Self-contained and internally `std::mutex`-guarded. Best for flood protection where burst is unacceptable.
- **`RateLimiterMap\<K\>`** -- per-key rate limiting backed by `ConcurrentHashMap\<K, TokenBucket\>`. Each key (IP, user, trunk) gets its own `TokenBucket`, created on demand at the default rate. Optional idle-bucket eviction driven by a `TimingWheel`.

### Technical Impact

- **Per-key limiting with sharded, near-O(1) lookup.** `ConcurrentHashMap` shards by key hash, so distinct keys rarely contend on the same lock. The hot (existing-key) path takes exactly one shard lock.
- **No lock-free complexity in the bucket.** `TokenBucket` is plain `double` state serialized by the map's per-shard `unique_lock` (via `findAndModify`). No CAS loops, no ABA, no generation counters.
- **Idle reclamation.** `cleanup()` (manual or `TimingWheel`-scheduled) evicts buckets not accessed within `maxIdle`, bounding memory under per-IP fan-out.
- **Denied requests do not refresh the idle timer** (`TokenBucket::tryConsume` updates `_lastAccess` only on success), so a source that is continuously rate-limited still ages out and gets reclaimed.

---

## 2. System Architecture

### 2.1 Component relationships

```
iora::core
|-- TokenBucket                     (public; non-copyable, movable; plain doubles, NO lock)
|     |-- double _rate              (tokens/second)
|     |-- double _burstCapacity     (cap; also the initial token count)
|     |-- double _tokens            (current balance)
|     |-- TimePoint _lastRefill     (steady_clock; drives lazy replenish)
|     `-- TimePoint _lastAccess     (steady_clock; updated ONLY on a successful consume)
|
|-- SlidingWindowCounter            (public; standalone; NOT copyable/movable -- holds a mutex)
|     |-- std::size_t _maxRequests
|     |-- std::chrono::seconds _window
|     |-- std::deque<TimePoint> _timestamps   (one entry per live acquire; front-evicted)
|     `-- mutable std::mutex _mutex
|
`-- RateLimiterMap<K, Hash, KeyEqual>          (public; per-key)
      |-- std::atomic<double> _defaultRate      (relaxed load/store)
      |-- std::atomic<double> _defaultBurst     (relaxed load/store)
      |-- std::chrono::seconds _maxIdle         (used by auto-cleanup only)
      `-- ConcurrentHashMap<K, TokenBucket, Hash, KeyEqual> _buckets
            |-- N shards, each a std::shared_mutex + std::unordered_map
            |-- findAndModify  -> unique_lock (used by tryConsume)
            |-- insert/insertOrAssign/erase -> unique_lock
            `-- forEach/size   -> shared_lock (one shard at a time)

Optional collaborator (not owned):
  TimingWheel  --schedules--> RateLimiterMap::cleanup(_maxIdle) every cleanupInterval
               (RateLimiterMap captures `this`; it MUST outlive the TimingWheel)
```

`RateLimiterMap` **owns** its [`ConcurrentHashMap`](concurrent_hash_map.md). It does **not** own the optional [`TimingWheel`](timing_wheel.md) -- the wheel is passed by raw pointer and only borrowed; the map registers a recurring callback on it.

### 2.2 Data flow -- per-key `tryConsume`

```mermaid
sequenceDiagram
  participant App as Caller (any thread)
  participant Map as RateLimiterMap
  participant CHM as ConcurrentHashMap (sharded)
  participant Bucket as TokenBucket

  App->>Map: tryConsume("192.0.2.7", 1.0)
  Map->>CHM: findAndModify(key, modifier)  [fast path]
  alt Key exists
    CHM->>CHM: lock shard (unique_lock)
    CHM->>Bucket: modifier -> tryConsume(1.0)
    Bucket->>Bucket: replenish(): tokens = min(tokens + rate*elapsed, burst)
    Bucket-->>CHM: consumed = true/false
    CHM-->>Map: found = true (shard unlocked)
    Map-->>App: consumed
  else Key missing (found = false)
    Map->>CHM: insert(key, TokenBucket(defaultRate, defaultBurst))
    Note over CHM: separate shard lock; no-op if a peer already inserted
    Map->>CHM: findAndModify(key, modifier)  [second lookup]
    CHM->>Bucket: modifier -> tryConsume(1.0)
    Bucket-->>CHM: consumed = true/false
    CHM-->>Map: found (usually true)
    Map-->>App: consumed
  end
```

The **slow path crosses three independent shard-lock acquisitions** (missed `findAndModify`, then `insert`, then a second `findAndModify`); it is not one atomic read-modify-write. See sections 5.2, 7, and 11 for the consequences.

### 2.3 Threading model

| Thread | Responsibility |
|---|---|
| **Any caller thread** | Calls `TokenBucket::tryConsume` **only** through `RateLimiterMap` (which holds the shard `unique_lock`), or `SlidingWindowCounter::tryAcquire`/`remaining`/`timeUntilAvailable` (each self-locks), or `RateLimiterMap::tryConsume`/`setKeyRate`/`removeKey`/`setDefaultRate`/`size`. All of these are safe to call concurrently. |
| **TimingWheel tick thread** (optional) | If a `TimingWheel*` was supplied, the wheel's own dispatch thread invokes the scheduled `cleanup(_maxIdle)` callback and re-arms it. `cleanup` runs concurrently with caller `tryConsume` calls, synchronized through the same `ConcurrentHashMap` shard locks. |

A standalone `TokenBucket` used directly (outside a `RateLimiterMap`) has **no** internal synchronization and must be externally serialized by the caller.

---

## 3. Component Deep Dive

### 3.1 `TokenBucket` -- lazy replenishment, no locking

The bucket holds `_tokens` and lazily tops it up on each access rather than on a timer. `replenish()` (called at the top of `tryConsume`) computes the elapsed time since `_lastRefill` and adds `rate * elapsed` tokens, capped at `_burstCapacity`:

```cpp
void replenish()
{
  auto now = Clock::now();
  auto elapsed = std::chrono::duration<double>(now - _lastRefill).count();
  _tokens = std::min(_tokens + _rate * elapsed, _burstCapacity);
  _lastRefill = now;
}
```

`tryConsume` replenishes, then consumes only if the balance suffices:

```cpp
bool tryConsume(double tokens = 1.0)
{
  replenish();
  if (_tokens >= tokens)
  {
    _tokens -= tokens;
    _lastAccess = Clock::now();  // updated ONLY on success
    return true;
  }
  return false;
}
```

Key properties, all verified against source:

- **Clock.** `Clock = std::chrono::steady_clock` -- monotonic, immune to wall-clock jumps. `elapsed` is therefore never negative in normal operation.
- **Initial fill.** The constructor sets `_tokens = burstCapacity`, so a fresh bucket starts full (a new key can immediately burst up to capacity).
- **No underflow.** `_tokens -= tokens` runs only inside `if (_tokens >= tokens)`, so the balance never goes negative for a positive `tokens` argument. (A **negative** `tokens` argument is not validated and would *add* to the balance -- see section 11.)
- **`availableTokens() const`** is a pure read: it computes `min(_tokens + _rate * elapsed, _burstCapacity)` against `_lastRefill` **without** mutating `_tokens` or `_lastRefill`. Two consecutive calls with no intervening `tryConsume` return the (increasing) projected balance but leave state untouched.
- **`timeUntilAvailable(tokens = 1.0) const`** returns `0ms` if already available; otherwise `ceil((tokens - available) / _rate * 1000)` milliseconds. It **divides by `_rate`** -- a bucket constructed with `rate == 0` triggers a division by zero here (see section 11).
- **`_lastAccess` on success only.** A denied request does not refresh the idle timer. This is deliberate: a source that hammers the limiter and is continuously denied must still age out so `cleanup` can reclaim its bucket.
- **Copy/move.** Copy is `= delete`d; move is `= default`. Deleting copy prevents a subtle bug where a caller mutates a *copy* of the stored bucket (e.g. via a hypothetical `findOrInsert` that returns a copy) and silently loses the write. Move enables inserting a freshly constructed bucket into the map.

### 3.2 `SlidingWindowCounter` -- strict window, internally locked

Enforces "at most `_maxRequests` in any trailing `_window`" with no burst credit. Storage is a `std::deque<TimePoint>`; each successful `tryAcquire` appends `now`, and expired entries are popped from the front:

```cpp
bool tryAcquire()
{
  std::lock_guard<std::mutex> lock(_mutex);
  auto now = Clock::now();
  evictExpired(now);                       // pop_front while (now - front) >= window
  if (_timestamps.size() >= _maxRequests)
  {
    return false;
  }
  _timestamps.push_back(now);
  return true;
}
```

- **Thread safety.** A single `mutable std::mutex _mutex` guards every method, including the `const` accessors. The counter is therefore self-synchronizing but, because it holds a mutex, is **neither copyable nor movable** -- it cannot be stored by value in a `ConcurrentHashMap` (which is why the per-key facility uses `TokenBucket`, not this class).
- **Eviction is lazy and only in `tryAcquire`.** `remaining()` and `timeUntilAvailable()` **do not** evict; they walk the deque counting non-expired entries. Between acquires, expired timestamps accumulate. This creates observable inconsistencies among the three methods -- documented precisely in section 11.
- **`remaining() const`** counts entries with `now - ts < _window` and returns `_maxRequests - active` (floored at 0).
- **`timeUntilAvailable() const`** returns `0ms` when `_timestamps.size() < _maxRequests` (raw size, *including* expired entries); otherwise it scans for the oldest still-active entry and returns its time-to-expiry plus 1ms (round-up). If every entry is expired it falls through to `0ms`.

### 3.3 `RateLimiterMap\<K\>` -- per-key buckets

Template over the key type plus the usual `Hash`/`KeyEqual` (defaulting to `std::hash\<K\>` / `std::equal_to\<K\>`). It composes a `ConcurrentHashMap\<K, TokenBucket\>` with atomic default parameters. `RateLimiterMap` is itself non-copyable and non-movable -- it holds the non-movable `ConcurrentHashMap` plus `std::atomic` members.

**`tryConsume` (fast path).** Call `findAndModify(key, modifier)` first. `findAndModify` takes the shard `unique_lock`, and if the key exists runs `modifier` (which calls `bucket.tryConsume(tokens)`) in place, then returns `true`. On an existing key this is a single lock acquisition and no `TokenBucket` is constructed.

**`tryConsume` (slow path).** If `findAndModify` returns `false`, the key is absent: construct a `TokenBucket(defaultRate, defaultBurst)`, `insert` it (a no-op if a peer inserted first), then call `findAndModify` **again** to consume. This path acquires three shard locks and is **not** atomic across them (sections 5.2, 11).

**`setDefaultRate(rate, burst)`.** Stores both into `std::atomic\<double\>` members with `memory_order_relaxed`. Affects only **future** bucket creation, never existing buckets. Because the two stores and the two slow-path loads are independent relaxed operations, a concurrent creator can observe a torn `(rate, burst)` pair (section 11).

**`setKeyRate(key, rate, burst)`.** `insertOrAssign(key, TokenBucket(rate, burst))` -- a single shard `unique_lock`, atomic replace. This **resets** the key's bucket to a full burst at the new parameters (any accumulated balance/deficit is discarded). Using `insertOrAssign` avoids the TOCTOU window an `erase`-then-`insert` pair would open.

**`removeKey(key)`.** `_buckets.erase(key)` -- one shard `unique_lock`.

**`cleanup(maxIdle)`.** Two passes, because `forEach` holds a **shared** lock and cannot erase:

```cpp
void cleanup(std::chrono::seconds maxIdle)
{
  auto now = Clock::now();
  std::vector<K> toEvict;
  auto maxIdleMs = std::chrono::duration_cast<std::chrono::milliseconds>(maxIdle);
  _buckets.forEach([&](const K& key, const TokenBucket& bucket)   // pass 1: shared_lock
  {
    auto idle = std::chrono::duration_cast<std::chrono::milliseconds>(
      now - bucket.lastAccess());
    if (idle > maxIdleMs)
    {
      toEvict.push_back(key);
    }
  });
  for (const auto& key : toEvict)                                 // pass 2: unique_lock
  {
    _buckets.erase(key);
  }
}
```

The `erase` in pass 2 is **unconditional** -- it does not re-check `lastAccess`. A key that becomes active again between the two passes is still evicted (a benign but real race; the bucket is simply recreated full on the next `tryConsume`). See section 11.

**Auto-cleanup.** If a `TimingWheel*` is supplied to the constructor, `scheduleAutoCleanup` registers a recurring callback that calls `cleanup(_maxIdle)` and re-arms itself every `cleanupInterval`. The callback captures `this` and `&wheel` by reference; there is **no** destructor that cancels it, so the map must outlive the wheel.

---

## 4. Usage Guide

### 4.1 Per-key API rate limiting

```cpp
#include "iora/core/rate_limiter.hpp"
#include <string>

using namespace iora::core;

// 100 tokens/sec steady, burst up to 50, per client key.
RateLimiterMap<std::string> limiter(100.0, 50.0);

bool admit(const std::string& clientIp)
{
  return limiter.tryConsume(clientIp);   // auto-creates a full bucket on first sight
}
```

Note: `RateLimiterMap` exposes **no** per-key `timeUntilAvailable`, so it cannot itself produce an exact `Retry-After`. Do **not** call `tryConsume` a second time to "peek" -- that consumes another token. If you need a precise retry hint, use a `TokenBucket`/`SlidingWindowCounter` you hold directly, or pick a fixed back-off. (This gap is recorded in section 11.)

### 4.2 A standalone `TokenBucket` (single caller serializes)

```cpp
#include "iora/core/rate_limiter.hpp"

using namespace iora::core;

TokenBucket bucket(10.0, 10.0);          // 10/sec, burst 10, starts full

if (bucket.tryConsume(1.0))
{
  // allowed
}
else
{
  auto wait = bucket.timeUntilAvailable(1.0);   // ms until 1 token is available
  // schedule a retry after `wait`
}
```

### 4.3 Strict SIP `REGISTER` flood protection (no burst)

```cpp
#include "iora/core/rate_limiter.hpp"
#include <chrono>

using namespace iora::core;

// At most 5 REGISTERs per 60s from this source -- no burst credit.
SlidingWindowCounter counter(5, std::chrono::seconds(60));

if (!counter.tryAcquire())
{
  // reject the REGISTER (e.g. 503 Service Unavailable)
  return;
}
// process the REGISTER
```

### 4.4 Per-key limiting with `TimingWheel` auto-cleanup

See [timing_wheel.md](timing_wheel.md) for `TimingWheel` construction and scheduling semantics.

```cpp
#include "iora/core/rate_limiter.hpp"
#include "iora/core/timing_wheel.hpp"
#include <chrono>
#include <string>

using namespace iora::core;

TimingWheel wheel(std::chrono::milliseconds(100), 64, 3);   // tick=100ms, 64 ticks, 3 wheels
wheel.start();

// Auto-cleanup every 60s; evict buckets idle for more than 300s.
// IMPORTANT: `limiter` must outlive `wheel` (the cleanup callback captures `this`).
RateLimiterMap<std::string> limiter(100.0, 50.0, &wheel,
                                    std::chrono::seconds(60),
                                    std::chrono::seconds(300));

// ... serve traffic; limiter.tryConsume(ip) per request ...

// Teardown order matters: stop/destroy the wheel BEFORE the limiter.
```

### 4.5 Per-key overrides

```cpp
RateLimiterMap<std::string> limiter(10.0, 10.0);   // default 10/sec, burst 10

limiter.setKeyRate("trusted-trunk", 1000.0, 500.0);  // this key: 1000/sec, burst 500 (reset full)
limiter.setDefaultRate(20.0, 20.0);                  // future NEW keys: 20/sec, burst 20
                                                     // (existing keys unaffected)
```

### 4.6 Anti-patterns

- **Do NOT call `RateLimiterMap::tryConsume` twice to compute a wait/`Retry-After`.** The second call consumes another token. There is no non-consuming per-key query.
- **Do NOT let a `RateLimiterMap` with auto-cleanup be destroyed before its `TimingWheel`.** The recurring callback captures `this`; a late tick then dereferences a dangling pointer. Destroy/stop the wheel first.
- **Do NOT call `setDefaultRate` expecting existing buckets to change.** It affects only buckets created afterward. Use `setKeyRate` to change a live key.
- **Do NOT store a `SlidingWindowCounter` by value in a container that copies or moves it** (including `ConcurrentHashMap`). It holds a `std::mutex` and is non-copyable/non-movable; hold it via `std::unique_ptr` if you must.
- **Do NOT construct a `TokenBucket` (or `RateLimiterMap`) with `rate == 0`.** The bucket never refills, and `timeUntilAvailable` divides by the rate (section 11).
- **Do NOT rely on `SlidingWindowCounter::remaining()`/`timeUntilAvailable()` being consistent with `tryAcquire()` when the window has just rolled over** -- they do not evict expired entries (section 11).

---

## 5. Call Flow / Sequence Reference

### 5.1 `RateLimiterMap::tryConsume` -- existing key (fast path)

| Step | Actor | Action | Lock state |
|---|---|---|---|
| 1 | Caller | `tryConsume(key, tokens)`; `consumed = false`. | no lock |
| 2 | `findAndModify` | `shardFor(key)`; acquire shard `unique_lock`; `map.find(key)` hits. | shard `unique_lock` held |
| 3 | `modifier` | `consumed = bucket.tryConsume(tokens)` -> `replenish()` then maybe debit. | shard `unique_lock` held |
| 4 | `findAndModify` | Return `true`; release shard lock. | released |
| 5 | Caller | `found == true` -> return `consumed`. | no lock |

### 5.2 `RateLimiterMap::tryConsume` -- new key (slow path, non-atomic)

| Step | Actor | Action | Lock state |
|---|---|---|---|
| 1 | `findAndModify` | Miss -> `found = false`; `consumed` still `false`. | shard lock taken then released |
| 2 | `insert` | Construct `TokenBucket(defaultRate, defaultBurst)` (two relaxed atomic loads); acquire shard `unique_lock`; insert (no-op if a peer already inserted). | shard `unique_lock` (fresh acquisition) |
| 3 | `findAndModify` | Acquire shard `unique_lock` **again**; if key present, `consumed = bucket.tryConsume(tokens)`. | shard `unique_lock` (third acquisition) |
| 4 | Caller | Return `consumed`. | no lock |

**Failure/race note.** If another thread erases the key (via `cleanup`/`removeKey`) between steps 2 and 3, the step-3 `findAndModify` misses, the modifier never runs, and `consumed` stays `false` -- the caller is **denied without any token being consumed**, even though the request should have been admitted. Rare, self-correcting on the next call, but a real correctness gap (section 11; backlog `2026-06-04-2`).

### 5.3 `SlidingWindowCounter::tryAcquire`

| Step | Actor | Action | Lock state |
|---|---|---|---|
| 1 | Caller | `tryAcquire()`; acquire `_mutex`. | `_mutex` held |
| 2 | `evictExpired` | `pop_front` while `(now - front) >= window`. | `_mutex` held |
| 3 | Guard | If `_timestamps.size() >= _maxRequests` -> release, return `false`. | `_mutex` held/released |
| 4 | Admit | `_timestamps.push_back(now)`; release; return `true`. | `_mutex` released |

### 5.4 `RateLimiterMap::cleanup` (two-pass eviction)

| Step | Actor | Action | Lock state |
|---|---|---|---|
| 1 | `cleanup` | Snapshot `now`; empty `toEvict`. | no lock |
| 2 | `forEach` | For each shard: `shared_lock`, walk entries, collect keys with `idle > maxIdle`. | one shard `shared_lock` at a time |
| 3 | `forEach` | Release each shard lock as it advances. | released between shards |
| 4 | Erase loop | For each collected key: `erase` under that shard's `unique_lock` (**unconditional**, no `lastAccess` re-check). | one shard `unique_lock` per key |

---

## 6. Component Internals -- invariants and edge behavior

(Non-template section; folded content pending the initiative-wide section-numbering consistency pass.)

- **`TokenBucket` balance invariant.** `0 <= _tokens <= _burstCapacity` holds after every `replenish()`/`tryConsume` for non-negative arguments and `rate >= 0`. The `min(...)` clamps the upper bound; the `if (_tokens >= tokens)` guard preserves the lower bound.
- **`_lastRefill` monotonicity.** `replenish()` always advances `_lastRefill` to `now`; `availableTokens()`/`timeUntilAvailable()` never write it (they read against the last committed `_lastRefill`).
- **`SlidingWindowCounter` deque ordering.** Timestamps are appended in `tryAcquire` order and are therefore non-decreasing, so `pop_front`-until-not-expired is correct and O(k) in the number of expired entries.
- **`RateLimiterMap` size.** `size()` returns `_buckets.size()`, which sums per-shard sizes under `shared_lock` -- a point-in-time snapshot, not a synchronized total across all shards simultaneously.
- **Auto-cleanup recursion.** `scheduleAutoCleanup` re-arms by scheduling a lambda that calls `scheduleAutoCleanup` again, giving an unbounded chain of one-shot wheel timers at `cleanupInterval` spacing (not a single periodic timer).

---

## 7. Thread Safety Model

| Operation | Synchronization | Notes |
|---|---|---|
| `TokenBucket::tryConsume` / `availableTokens` / `timeUntilAvailable` / getters | **None internally.** | When used via `RateLimiterMap`, all mutation happens inside `findAndModify`'s shard `unique_lock`. A standalone `TokenBucket` must be serialized by the caller. |
| `SlidingWindowCounter::tryAcquire` | `std::lock_guard<std::mutex>` on `_mutex`. | Fully self-synchronizing. |
| `SlidingWindowCounter::remaining` / `timeUntilAvailable` | `std::lock_guard<std::mutex>` on `mutable _mutex`. | `const` but mutex-protected; do **not** evict (see section 11). |
| `RateLimiterMap::tryConsume` | Fast path: one `findAndModify` shard `unique_lock`. Slow path: `findAndModify` + `insert` + `findAndModify` = **three** independent shard-lock acquisitions. | Fast path is atomic. Slow path is **not** atomic across the three locks (sections 5.2, 11). |
| `RateLimiterMap::setDefaultRate` | Two `std::atomic<double>` stores, `memory_order_relaxed`. | No mutual exclusion between the two stores; a concurrent slow-path creator can read a torn pair (section 11). |
| `RateLimiterMap::setKeyRate` | `ConcurrentHashMap::insertOrAssign` -- one shard `unique_lock`. | Atomic replace; resets the bucket to full burst. |
| `RateLimiterMap::removeKey` | `ConcurrentHashMap::erase` -- one shard `unique_lock`. | |
| `RateLimiterMap::cleanup` | Pass 1 `forEach` (per-shard `shared_lock`); pass 2 `erase` (per-key `unique_lock`). | Not a single critical section; a key may be touched between passes and still be evicted (section 11). |
| `RateLimiterMap::size` | Per-shard `shared_lock` summed. | Snapshot. |

**Mutex/atomic inventory (from source):**

- `SlidingWindowCounter::_mutex` (`mutable std::mutex`) -- the counter's only lock.
- [`ConcurrentHashMap`](concurrent_hash_map.md)'s per-shard `std::shared_mutex` -- reached by every `RateLimiterMap` bucket operation (see `concurrent_hash_map.md` for full shard-locking semantics: which operations take `shared_lock` vs `unique_lock`).
- `RateLimiterMap::_defaultRate` / `_defaultBurst` (`std::atomic<double>`) -- relaxed load/store only.

**Callback-under-lock.** In `cleanup`, the `forEach` callback runs **while the shard `shared_lock` is held**. That is safe here because the callback only reads `bucket.lastAccess()` and pushes to a local `std::vector` -- it never re-enters the map or takes another lock. Do not add re-entrant work to that path.

**Lock ordering.** No operation holds two of these locks at once (the two-pass `cleanup` deliberately releases every shard lock before the erase pass), so there is no lock-ordering hazard between shards or between the map and the counter.

---

## 8. Configuration Reference

### 8.1 `TokenBucket`

| Parameter | Type | Default | Units | Notes |
|---|---|---|---|---|
| `rate` | `double` | (required) | tokens/second | Steady refill rate. Must be `> 0` (see section 11: `0` disables refill and breaks `timeUntilAvailable`). Not validated. |
| `burstCapacity` | `double` | (required) | tokens | Maximum balance **and** the initial balance (bucket starts full). Not validated. |

### 8.2 `SlidingWindowCounter`

| Parameter | Type | Default | Units | Notes |
|---|---|---|---|---|
| `maxRequests` | `std::size_t` | (required) | count | Max acquires per window. |
| `window` | `std::chrono::seconds` | (required) | seconds | Trailing window length. Second granularity only. |

### 8.3 `RateLimiterMap\<K\>`

| Parameter | Type | Default | Units | Notes |
|---|---|---|---|---|
| `defaultRate` | `double` | (required) | tokens/second | Rate for auto-created buckets. |
| `defaultBurst` | `double` | (required) | tokens | Burst for auto-created buckets. |
| `cleanupWheel` | `TimingWheel*` | `nullptr` | -- | If non-null, schedules recurring `cleanup(_maxIdle)`; the map must outlive the wheel. |
| `cleanupInterval` | `std::chrono::seconds` | `60` | seconds | Auto-cleanup cadence (ignored when `cleanupWheel == nullptr`). |
| `maxIdle` | `std::chrono::seconds` | `300` | seconds | Idle threshold used by **auto-cleanup**. The manual `cleanup(maxIdle)` overload takes its own argument and ignores the stored `_maxIdle`. |

---

## 9. API Reference

```cpp
namespace iora
{
namespace core
{

class TokenBucket
{
public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  TokenBucket(double rate, double burstCapacity);

  TokenBucket(const TokenBucket&) = delete;
  TokenBucket& operator=(const TokenBucket&) = delete;
  TokenBucket(TokenBucket&&) = default;
  TokenBucket& operator=(TokenBucket&&) = default;

  bool tryConsume(double tokens = 1.0);
  double availableTokens() const;
  std::chrono::milliseconds timeUntilAvailable(double tokens = 1.0) const;
  TimePoint lastAccess() const;
  double rate() const;
  double burstCapacity() const;
};

class SlidingWindowCounter
{
public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  SlidingWindowCounter(std::size_t maxRequests, std::chrono::seconds window);
  // Non-copyable and non-movable (holds a std::mutex).

  bool tryAcquire();
  std::size_t remaining() const;
  std::chrono::milliseconds timeUntilAvailable() const;
};

template <typename K, typename Hash = std::hash<K>,
          typename KeyEqual = std::equal_to<K>>
class RateLimiterMap
{
public:
  using Clock = std::chrono::steady_clock;

  RateLimiterMap(double defaultRate, double defaultBurst,
                 TimingWheel* cleanupWheel = nullptr,
                 std::chrono::seconds cleanupInterval = std::chrono::seconds(60),
                 std::chrono::seconds maxIdle = std::chrono::seconds(300));

  bool tryConsume(const K& key, double tokens = 1.0);
  void setDefaultRate(double rate, double burst);
  void setKeyRate(const K& key, double rate, double burst);
  void removeKey(const K& key);
  void cleanup(std::chrono::seconds maxIdle);
  std::size_t size() const;
};

} // namespace core
} // namespace iora
```

---

## 10. Design Decisions

| ID | Decision | Rationale |
|---|---|---|
| D-1 | Lazy replenishment in `TokenBucket` (no background timer). | Refilling on access needs no thread and no per-bucket timer; cost is amortized into the `tryConsume` the caller already makes. |
| D-2 | Plain `double` state, no atomics/CAS in `TokenBucket`. | The bucket is always mutated under a `ConcurrentHashMap` shard `unique_lock` (via `findAndModify`), so lock-free machinery would add complexity for zero benefit. |
| D-3 | `TokenBucket` non-copyable, movable. | Deleting copy makes "mutate a copy, lose the write" a compile error; movability lets a freshly built bucket be inserted into the map. |
| D-4 | `_lastAccess` refreshed only on a successful `tryConsume`. | A continuously-denied flood source still ages out, so `cleanup` can reclaim its bucket under sustained attack. |
| D-5 | `SlidingWindowCounter` for strict enforcement, separate from `TokenBucket`. | Some flows (SIP `REGISTER`) cannot tolerate any burst; a window counter expresses "N per T" exactly, which a token bucket cannot. |
| D-6 | `ConcurrentHashMap` (sharded) as the per-key store. | Sharding lets distinct keys proceed without contending on one lock -- essential for per-source-IP fan-out. |
| D-7 | Fast-path `findAndModify` before any insert in `tryConsume`. | The common case (existing key) is one lock and constructs no throwaway bucket. |
| D-8 | `insertOrAssign` for `setKeyRate`. | Single-lock atomic replace; an `erase`+`insert` pair would expose a TOCTOU window. |
| D-9 | `std::atomic<double>` defaults changeable at runtime. | `setDefaultRate` needs no mutex; buckets created afterward pick up the new values. (Relaxed ordering is a known weakness -- section 11.) |
| D-10 | Two-pass `cleanup` (collect under `shared_lock`, erase under `unique_lock`). | `forEach` cannot erase while iterating under a shared lock; collecting then erasing avoids upgrading the lock or invalidating iterators. |
| D-11 | Optional `TimingWheel` auto-cleanup rather than an owned thread. | Reuses the process-wide timing infrastructure; keeps `RateLimiterMap` free of its own thread. The captured-`this` lifetime coupling is the accepted cost (section 11). |

---

## 11. Known Limitations

Per the project's code-defect honesty rule, every deficiency below is reported as a finding regardless of when the code was written; disposition is the human's call.

- **`TokenBucket::timeUntilAvailable` divides by `_rate` -- division by zero at `rate == 0`.** `rate_limiter.hpp:84-85`: `double seconds = deficit / _rate; ... static_cast<std::int64_t>(std::ceil(seconds * 1000.0))`. With `_rate == 0`, `deficit / 0.0` is `+inf`, and `static_cast<std::int64_t>` of a non-representable `double` is undefined behavior. A `rate == 0` bucket also never refills (`replenish` adds `0 * elapsed`). No constructor validation rejects `rate <= 0`. **Impact:** UB / garbage wait value for a misconfigured limiter. (tracked: iora backlog 2026-09-10-14)
- **No input validation on `TokenBucket` arguments.** Negative `rate`/`burstCapacity` and a **negative** `tokens` argument to `tryConsume` are accepted. A negative `tokens` passes the `_tokens >= tokens` guard trivially and then *adds* `|tokens|` to the balance (`_tokens -= tokens`), letting a caller mint tokens. `rate_limiter.hpp:54-64`. **Impact:** silent limiter corruption on bad input. (tracked: iora backlog 2026-09-10-14)
- **`RateLimiterMap::tryConsume` slow path is not atomic across three shard locks, with a spurious-denial window.** `rate_limiter.hpp:232-256`: missed `findAndModify` -> `insert` -> second `findAndModify`. If a peer `cleanup`/`removeKey` erases the key between the `insert` and the second `findAndModify`, the modifier never runs and the method returns `false` **without consuming a token**, denying a request that should have been admitted. Concurrent first-touches of the same key do **not** over-admit: `ConcurrentHashMap::insert` is emplace-based, so whichever thread's `insert` loses the race is a no-op against the already-present bucket, and both threads' subsequent `findAndModify` calls debit the **same single bucket**, serialized under that shard's `unique_lock`. The only real defect in this path is the spurious-denial window above (key erased between `insert` and the second `findAndModify`), not over-admission. This is the subject of open backlog `tasks/iora/backlog/2026-06-04-2` (RateLimiterMap `tryConsume` TOCTOU). **Impact:** rare spurious denials / slightly weaker enforcement under create/evict races.
- **`std::atomic<double>` defaults use `memory_order_relaxed` and are read as two independent loads.** `rate_limiter.hpp:248-249` (slow-path construction) reads `_defaultRate` and `_defaultBurst` in two separate relaxed loads; `setDefaultRate` (`262-263`) writes them in two separate relaxed stores. A creator racing a `setDefaultRate` can observe a torn `(newRate, oldBurst)` pair. `std::atomic<double>` is not guaranteed lock-free on every platform in general, but on the supported 64-bit x86-64/ARM64 targets it **is** always lock-free -- so the live concern here is not lock-freedom, it is the torn `(rate, burst)` pair from two independent relaxed loads/stores. This is the subject of open backlog `tasks/iora/backlog/2026-06-04-1` (atomic-double lock-free assert). **Impact:** a briefly inconsistent default applied to a newly created bucket.
- **`RateLimiterMap::cleanup` pass-2 `erase` is unconditional.** `rate_limiter.hpp:298-303` erases every key collected in pass 1 without re-checking `lastAccess`. A key that becomes active between the two passes is still evicted; its bucket (and accumulated balance) is dropped and recreated full on the next `tryConsume`. **Impact:** an occasional burst-credit reset for a key that got busy exactly during cleanup. Benign but non-deterministic. (tracked: 2026-09-10-16)
- **Auto-cleanup captures `this` with no cancellation on destruction.** `rate_limiter.hpp:309-324`: the recurring wheel callback captures `this` and `&wheel`; `RateLimiterMap` has no destructor that cancels the scheduled timer. If the map is destroyed before the `TimingWheel`, a later tick dereferences a dangling `this`. **Impact:** use-after-free unless teardown order (wheel before map) is honored manually. (tracked: 2026-09-10-15)
- **`SlidingWindowCounter::remaining()` and `timeUntilAvailable()` never evict, so they disagree with `tryAcquire()` after a window rollover.** `rate_limiter.hpp:143-184`. `timeUntilAvailable`'s early-return guard tests the **raw** `_timestamps.size()` (including expired entries) against `_maxRequests`; when expired entries pad the deque to full size while the active count is below the limit, it reports a **non-zero** wait even though `tryAcquire()` would succeed immediately (it evicts first) and `remaining()` reports free slots. (When *every* entry is expired, `timeUntilAvailable` instead falls through to `0ms` -- correcting the previous guide's imprecise "all entries expired" wording.) Expired timestamps also accumulate in memory until the next `tryAcquire`. **Impact:** misleading retry hints and memory that is only reclaimed on the next acquire. (tracked: 2026-09-10-16)
- **`SlidingWindowCounter` is neither copyable nor movable.** It holds a `std::mutex`, so it cannot be stored by value in a `ConcurrentHashMap` or any container that copies/moves elements; hold it behind a `std::unique_ptr` for per-key window limiting.
- **`RateLimiterMap` offers no non-consuming per-key query.** There is no per-key `availableTokens`/`timeUntilAvailable`; callers cannot compute an exact `Retry-After` without consuming a token. **Impact:** downstream code must approximate back-off or hold buckets directly.
- **`window` is limited to `std::chrono::seconds` granularity.** Sub-second sliding windows are not expressible with `SlidingWindowCounter`.

### Test coverage cross-check

`tests/core/iora_test_rate_limiter.cpp` exercises the happy paths of all three classes (basic consume, burst exhaustion, time-based refill, `timeUntilAvailable`, non-copyable `static_assert`, window acquire/expiry/`remaining`, per-key independence, auto-create, `setKeyRate`/`setDefaultRate` semantics, `removeKey`, `cleanup(0s)`, and an 8-thread stress test). It does **not** cover any of the defects above: the slow-path erase race, torn default-rate reads, `rate == 0` division, negative `tokens`, the cleanup-vs-consume race, or the `SlidingWindowCounter` query/`tryAcquire` inconsistency are all untested. (Reported here as a coverage finding, not silently omitted; tracked: 2026-09-10-16.)
