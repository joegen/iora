# Iora KVStore -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 2.2 |
| **Date** | 2026-09-22 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/storage/kvstore.hpp` |
| **Namespace** | `iora::storage` |
| **Dependencies** | `iora/core/timing_wheel.hpp` (header-only; the only iora dependency) plus the C++17 standard library (`<shared_mutex>`, `<thread>`, `<condition_variable>`, `<filesystem>`, `<fstream>`, `<chrono>`) |

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | (pre-2026-06) | Binary append-log key-value store: snapshot + replayable log, background compaction, bounded read cache, `shared_mutex`. No expiry. |
| 2.0 | 2026-06-02 | **Native per-key TTL (auto-expiry).** Active eviction via an internal `core::TimingWheel` + dedicated worker, lazy-on-read backstop, absolute expiry persisted across restart (`'E'`/`'X'` log ops + snapshot v2, version `{1,2}` tolerance). In-scope `compact()`/`compactLocked()` split fixing a recursive `shared_mutex` re-lock. Six-step idempotent shutdown. Architecture: `architecture/iora/kvstore_ttl.json` (KTP-1..11). |
| 2.1 | 2026-09-11 | **In-memory mode (KVStore-IM-1).** An empty `path` selects a purely in-process store -- no snapshot/`.log`/`.tmp`, no background compaction, non-persistent, per-instance isolated (TTL/eviction still run). Closes the footgun where an empty path silently wrote `./.log` in the CWD (shared across instances/processes, causing test contamination). iora `ae8a9fd`. |
| 2.2 | 2026-09-22 | Migrated into the in-repo documentation set (`iora/docs/storage/`) with a full step-13 re-verification against current source. Lock-order description: the arm path's inner edge is `_mutex -> (wheel-internal mutex)` via `schedule()`/`cancel()`; `_evictionMutex` is a pure leaf (taken by the tick thread when it dispatches a fired closure, by the worker on pop, and by `shutdown()`), never nested under `_mutex` -- `TimingWheel::schedule()` never fires a callback synchronously, so an arm does not enqueue. Back-link added; no behavioral change. |

---

## 1. Executive Summary

### Problem

`iora::storage::KVStore` is a durable binary key-value store: an on-disk snapshot plus a replayable append-log, with background compaction and a read cache. Until v2 it had **no notion of expiry** -- keys lived until an explicit `remove()`/`clear()`. Consumers such as the web-middleware authentication layer need **session keys that expire** (idle timeout plus absolute lifetime), and re-implementing expiry on top of the store in every consumer would duplicate the hardest, most error-prone logic (the on-disk format, crash recovery, compaction, and the concurrency model) in each caller.

### Solution

Native per-key TTL was added **in place**, additive and backward-compatible:

- **API** -- `set`/`setString`/`setBatch` gain an optional `std::chrono::seconds ttl` overload; plus `expireAt(key, time_point)`, `ttl(key) -> optional<seconds>`, and `persist(key)`. A plain `set` (no TTL) **clears** any existing expiry (Redis-style).
- **Active eviction** -- an internal `core::TimingWheel` (lazily constructed and started) fires a fired-timer callback onto a **single dedicated worker thread** that performs the locked erase plus a durable `'D'` log write **off** the wheel's tick thread. A **generation-token guard** makes a stale, already-collected timer a provable no-op.
- **Lazy-on-read backstop** -- every reader treats `expiry <= now()` as absent, so a key is never observed alive past its deadline even in the sub-tick gap before the timer fires.
- **Durable across restart** -- the absolute expiry (`system_clock` epoch-ms) is persisted via two new log ops (`'E'` = set-with-expiry, `'X'` = expiry-only change) and a v2 snapshot; `load()` accepts version `{1,2}` so existing v1 stores open unchanged (all keys eternal).
- **Zero overhead for non-TTL keys** -- expiry metadata lives in a **parallel** `_expiry` map; a store that never sets a TTL spawns **no extra thread**.
- **In-memory mode** -- an empty `path` selects a purely in-process store: no file I/O at all, non-persistent, per-instance isolated. TTL/eviction still run.

### Technical Impact

- One tested implementation of expiry for every KVStore consumer; the auth session store rides it directly.
- Active eviction is `O(1)` schedule/cancel via the timing wheel; non-TTL keys are untouched.
- Crash-safe across a **process** crash: every TTL write is stream-flushed to the OS at write time (`_logStream.flush()`), so the absolute deadline survives a process crash and re-arms (or drops) on reload -- durability does **not** depend on a clean shutdown. (Power-loss / OS-crash durability needs an `fsync`, which only the explicit `flush()` performs; see Known Limitations.)
- Fixed a **pre-existing latent UB** at v2: `maybeCompact()` re-locked the non-recursive `_mutex` via `compact()` when background compaction was disabled. The `compact()`/`compactLocked()` split removes it.

---

## 2. System Architecture

### 2.1 Component relationships

```
iora::storage::KVStore
|-- _kv        : unordered_map<string, vector<uint8_t>>      (the data; guarded by _mutex)
|-- _expiry    : unordered_map<string, ExpiryEntry>          (TTL keys only; guarded by _mutex)
|                  ExpiryEntry { system_clock::time_point expiry; core::TimerId timerId; }
|-- _cache     : unordered_map<string, CacheEntry>           (read cache; guarded by _cacheMutex)
|                  CacheEntry { vector<uint8_t> value; system_clock::time_point expiry; }
|-- _logStream : append-only log file (snapshot at _path, log at _path + ".log")
|-- _compactionThread                                        (pre-existing background compactor)
`-- TTL active-eviction machinery (lazily started)
    |-- _wheel          : unique_ptr<core::TimingWheel>      (non-movable -> held by pointer)
    |-- _evictionQueue  : queue<function<void()>>            (guarded by _evictionMutex -- a LEAF)
    |-- _evictionCv / _evictionStop
    `-- _evictionWorker  : one dedicated std::thread
```

### 2.2 Data flow: a set-with-TTL and its later eviction

```mermaid
sequenceDiagram
    participant C as Caller
    participant K as KVStore
    participant W as TimingWheel (tick thread)
    participant E as Eviction worker
    C->>K: set(key, value, ttl)
    Note over K: unique_lock(_mutex)
    K->>K: startTtlOrCleanup (lazy wheel + worker)
    K->>K: cancelTimerLocked(key)
    K->>W: schedule(clampDelay(expiry)) -> id
    K->>K: _kv[key]=value; _expiry[key]={expiry,id}; updateCache
    K->>K: writeLogEntry('E') (flush)
    Note over K: unlock(_mutex)
    W-->>E: (later) timer fires -> enqueueEviction(closure)
    E->>K: closure(): unique_lock(_mutex)
    K->>K: STALE? / EVICT (erase _kv/_expiry/_cache, writeLogEntry('D')) / RE-ARM
```

### 2.3 Threading model

| Thread | Origin | Role | Locks taken |
|--------|--------|------|-------------|
| Caller thread(s) | user | All public API | `_mutex` (unique for writes, shared for reads), then `_cacheMutex`; a TTL arm also takes the wheel-internal mutex via `schedule()`/`cancel()` |
| Wheel tick thread | `core::TimingWheel::start()` | Advances the wheel each tick, fires due timers via the dispatcher | wheel-internal mutex (released before firing), then `_evictionMutex` (leaf) when it dispatches a fired closure via `enqueueEviction`; **never** `_mutex` |
| Eviction worker | first TTL key / end-of-ctor arming | Pops fired closures, runs the locked erase + durable `'D'` write | `_evictionMutex` (pop), then releases it, then `_mutex` |
| Compaction thread | ctor (if `enableBackgroundCompaction`) | Periodic compaction | `_compactionMutex` (CV), then `_mutex` via `compact()` |

The wheel's **synchronous, push-only dispatcher** (`enqueueEviction`) keeps the flushing `'D'` write off the tick thread (a flushing write there would stall every other timer) and serializes evictions through one worker.

### 2.4 On-disk format

**Log entry** (framed): `[totalLen u32][payload][crc32 u32]`, where `crc32` covers the whole payload (`op` through the last payload byte). Per-op payloads:

| Op | Payload | Meaning |
|----|---------|---------|
| `'S'` | `[op][keyLen u32][key][valLen u32][value]` | set, no expiry (clears any prior expiry on replay) |
| `'D'` | `[op][keyLen u32][key]` | delete (erases value **and** expiry) |
| `'E'` | `[op][keyLen u32][key][expiryEpochMs i64][valLen u32][value]` | set-with-expiry |
| `'X'` | `[op][keyLen u32][key][expiryEpochMs i64]` | expiry-only change (no value) |

**Snapshot v2**: `[magic u32][version u32 = 2][count u32]` then per survivor `[keyLen][key][expiryEpochMs i64][valLen][value]`. `count` is the **survivor** count (expired entries are dropped at compaction). A v1 snapshot omits the `expiryEpochMs` field; `load()` reads either.

`expiryEpochMs` is an **absolute** `system_clock` epoch in **milliseconds** (host byte order, inside the CRC payload). `INT64_MIN` is the **no-expiry sentinel** (`0` is a legitimate epoch and cannot be used); it is legal in `'X'` and the snapshot field, **illegal** in `'E'`.

---

## 3. Component Deep Dive

### 3.1 Absolute expiry vs. relative wheel delay (KTP-2)

Two clock domains are deliberately kept separate:

- **`system_clock` (absolute)** -- what is stored in `_expiry`, embedded in `CacheEntry`, and persisted on disk. All correctness decisions (lazy-read, the eviction-time check, `ttl()`) compare this absolute deadline to `system_clock::now()`. So correctness is governed by the absolute comparison **even under clock skew**; the wheel firing is only an optimization.
- **`steady_clock` (relative)** -- what the wheel arms with. Every arm derives `delay = clamp(max(0, expiry - system_clock::now()), 0, WHEEL_MAX_RANGE)` in overflow-safe `chrono` arithmetic (`clampDelay()`). The clamp prevents the wheel's far-future bucket-wrap from firing a timer early (and bounds `now + delay` away from int64-ns overflow).

`WHEEL_MAX_RANGE = ttlTickDuration x ttlTicksPerWheel ^ ttlNumWheels`, validated and capped (`kMaxTtlRangeMs`, ~200 years) in `computeAndValidateTtlRange()` from the constructor initializer list.

### 3.2 The parallel `_expiry` map (KTP-3)

Expiry metadata lives in a **separate** `unordered_map`, never in `_kv`'s value type -- so non-TTL keys carry zero overhead and `_kv`'s access sites are untouched. Only TTL keys appear in `_expiry`. `timerId == core::InvalidTimerId (0)` means *present but not actively armed* -- a load-replay placeholder, or a timer whose `schedule()` was refused (store draining). Such an entry is **lazy-read-only**: never actively evicted, but still hidden by the read filter once expired.

### 3.3 Active eviction: wheel + worker + leaf queue (KTP-5/6)

The wheel is constructed with a synchronous dispatcher `cb -> enqueueEviction(cb)` that pushes the *already-wrapped* fired closure onto `_evictionQueue` (under `_evictionMutex`) and notifies the worker. The worker:

```
loop:
  lock _evictionMutex
  wait until (_evictionStop || !_evictionQueue.empty())   // unbounded wait
  if queue empty -> return                                 // stop requested + drained
  pop job; unlock _evictionMutex
  job()                                                    // takes _mutex
```

The queue mutex is a **leaf**: it is never held while acquiring any other lock (the worker pops, releases, then the closure takes `_mutex`). Because the wait is **unbounded** (no timeout backstop), every predicate mutation -- both `enqueueEviction`'s push and every `_evictionStop` set -- happens under `_evictionMutex` before `notify`; otherwise a wakeup can be lost and shutdown's worker-join would hang. `enqueueEviction` uses `notify_one` (correct only because there is exactly one worker); the shutdown stop-path uses `notify_all`.

### 3.4 The generation-token guard (KTP-4)

`core::TimingWheel::cancel()` is **not a fire barrier** (a timer already collected into a fire batch fires even after `cancel()`), and `reschedule()` **preserves** the timer id. So KVStore **never** calls `reschedule()` and **never** calls `wheel.reset()` (the only thing that restarts the monotonic id counter). Every TTL mutation **cancels** the old timer and **schedules a fresh one** (a new, unique id) or erases the entry.

Each eviction closure captures `(key, idHolder)` where `idHolder` is a `shared_ptr<TimerId>` published under `_mutex` (after `schedule()` returns the id). The closure body (`evictionCallback`) runs under `_mutex` and takes exactly one of three outcomes:

- **STALE** -- `_expiry[key]` absent, or `timerId != captured`, or `captured == InvalidTimerId` -> no-op.
- **EVICT** -- match **and** `expiry <= now()` -> erase `_kv`/`_expiry`/`_cache` **first**, then `writeLogEntry('D')`.
- **RE-ARM** -- match **and** `expiry > now()` (a clamped far-future timer fired early) -> schedule a fresh id for the remaining delay; if `schedule()` is refused (draining), store `InvalidTimerId` and do **not** enqueue.

Because ids are unique for the store's lifetime, a stale collected-to-fire closure for an extended/persisted/removed key is a provable no-op.

### 3.5 Lazy-read backstop and the cache (KTP-10)

All readers (`get`, `getString`, `exists`, `keys`, `keysWithPrefix`, `getBatch`) treat `expiry <= now()` as **absent**. `size()` filters expired entries so it stays consistent with `get()`. Cache coherence needs **both** mechanisms:

1. **Embedded expiry** -- `CacheEntry` carries the key's absolute expiry; the lock-light cache fast path in `get()` checks it and falls through on expiry. This covers a key whose TTL lapses by mere passage of time (no intervening mutation) -- invalidation alone would serve it stale.
2. **Invalidation** -- every expiry mutation erases/updates the cache entry. This covers value/expiry changes.

`get()`'s cache hit returns the value **by value** (a copy taken under `_cacheMutex`), so a concurrent eviction `erase` can never dangle it.

### 3.6 Persistence, replay, and compaction (KTP-1/9/11)

`load()` reads the snapshot (v1 or v2) then replays the log. Replay populates `_expiry` with `{expiry, InvalidTimerId}` placeholders and **spawns no thread**. Every log op is CRC-verified uniformly (the trailing 4 bytes over the rest), and every field is bounds-checked before read so a truncated entry cannot over-read. Implausible or out-of-window expiry values (`isPlausibleEpochMs`) are rejected as corrupt and dropped -- identically in the snapshot and the `'E'` log paths. A **CRC mismatch on a well-framed entry** is skipped (the next entry is still replayed), but a **corrupt frame length or a short read stops replay** (`break`): the remainder of the log is discarded. This is the correct behavior for a torn tail (a partial trailing write), but it also means mid-log framing corruption truncates all subsequent (possibly valid) entries -- see Known Limitations.

`compact()` takes `_mutex` then calls the private `compactLocked()`; `maybeCompact()` (already under `_mutex`) calls `compactLocked()` **directly**. This split removes the pre-existing recursive `shared_mutex` re-lock. `compactLocked()` computes a stable survivor set (no expiry **or** `expiry > now`) under the held `_mutex`, writes the survivor count and a v2 snapshot to a temp file, atomically renames it over `_path`, resets the log, then drops the expired keys from `_kv`/`_expiry`/`_cache` and cancels their timers. In-memory mode short-circuits `compactLocked()` and `shouldCompact()` (nothing on disk to compact).

### 3.7 Lifecycle: lazy-start and six-step shutdown (KTP-7/8)

The wheel/worker are started **once** (`ensureTtlStarted`) -- at the end of the constructor via `postLoadArm()` (after `load()`/`openLogFile()` succeed, iff there is at least one TTL survivor) or on the first runtime TTL key (`startTtlOrCleanup`). The start sequence does all throwable steps (wheel construct, worker spawn, `wheel.start()`) **before** any `schedule()`, so the eviction queue is provably empty if anything throws; cleanup then routes through the idempotent `shutdown()` with `_mutex` **released** (its `_compactionThread.join()` would otherwise deadlock against `compact()`'s `_mutex` re-acquire). `shutdown()`:

1. set `_shutdown` (atomic) -- new TTL writes throw;
2. `wheel.drain()` -- fire due timers (synchronously enqueued), cancel future ones;
3. signal the worker `_evictionStop` + notify under the **queue** mutex;
4. join the worker (it drains the remaining queue first);
5. notify + join the compaction thread (notify under `_compactionMutex`);
6. flush + close the log.

No `_mutex` is held across the joins; no `'D'`/`'E'`/`'X'` write occurs after the log close. Durability comes from the per-write stream flush (to the OS, not an `fsync` -- process-crash safe, see Known Limitations), not from shutdown -- a drain timeout under a mass-expiry herd loses nothing (the absolute expiry re-arms or drops on reload). `shutdown()` is idempotent and the destructor invokes it. Members are declared so reverse-order destruction tears down the eviction worker/wheel before `_compactionThread` and its primitives.

---

## 4. Usage Guide

### 4.1 Quick start

```cpp
#include "iora/storage/kvstore.hpp"
using iora::storage::KVStore;

KVStore store("/var/lib/app/sessions");           // snapshot + .log alongside

store.setString("sess:abc", token, std::chrono::seconds(1800));  // 30-min TTL
if (auto v = store.getString("sess:abc"))
{
  // live
}

store.expireAt("sess:abc",
               std::chrono::system_clock::now() + std::chrono::hours(8)); // absolute cap
auto remaining = store.ttl("sess:abc");           // optional<seconds>
store.persist("sess:abc");                          // make permanent (clear TTL)
```

### 4.2 In-memory (non-persistent) store

```cpp
// An EMPTY path selects in-memory mode: no snapshot/.log/.tmp, no background
// compaction, per-instance isolated. The full API (TTL, eviction, batch) works.
KVStore cache("");
cache.setString("k", "v", std::chrono::seconds(5));
```

### 4.3 Binary values and batches

```cpp
std::vector<std::uint8_t> blob = loadBlob();
store.set("obj:42", blob);                              // no expiry
store.setBatch({{"a", {1, 2}}, {"b", {3, 4}}},
               std::chrono::seconds(60));                 // one batch-wide TTL
auto got = store.getBatch({"a", "b", "missing"});         // missing/expired keys omitted
```

### 4.4 Common patterns

- **Sliding idle session**: on each request, re-`set` the key with the idle TTL (a plain `set` would clear it, so always pass the TTL). Combine with a one-time `expireAt` for the absolute lifetime cap -- whichever deadline the wheel/lazy-read reaches first wins.
- **Sub-second precision is not provided**: the eviction granularity is one wheel tick (default 1s); the lazy-read backstop hides an expired key in the gap before the tick fires.

### 4.5 Anti-patterns

- **Do NOT** call a plain `set(k, v)` after `set(k, v, ttl)` and expect the TTL to survive -- a plain `set` clears any existing expiry (Redis-style). Use the TTL overload every time you want the key to keep expiring.
- **Do NOT** treat `ttl() == nullopt` as "absent". `nullopt` means permanent, absent, **or** expired-not-yet-evicted; `0s` means "<1s remaining" (still live). Use `exists()` to disambiguate.
- **Do NOT** call the public `compact()`/`forceCompact()`/`flush()` from inside a callback that already holds `_mutex` -- they self-lock the non-recursive `_mutex`. (No public API does this; it matters only if you extend the class.)
- **Do NOT** rely on writes after `shutdown()`: `set`/`setString`/`setBatch`/`expireAt` **throw**; `remove`/`persist`/`clear` are **no-ops**; reads still work from memory.
- **Do NOT** downgrade a v2 store to a pre-TTL binary: an old reader rejects the v2 snapshot version and skips `'E'`/`'X'` log ops as unknown.

---

## 5. Call Flow / Sequence Reference

**`set(key, value, ttl)`** -> validate `ttl > 0` + sizes (no lock) -> compute absolute expiry -> `unique_lock(_mutex)` -> throw if `_shutdown` -> `startTtlOrCleanup` (lazy-start) -> `cancelTimerLocked` old -> `armTimerLocked` fresh (id) -> write `_kv`/`_expiry`/`_cache` -> `writeLogEntry('E')` (rollback on throw) -> `maybeCompact()`.

**Active eviction** -> tick thread `advance()` collects the due timer -> `fireCallback` wraps the closure in try/catch -> dispatcher `enqueueEviction` (push under queue mutex + `notify_one`) -> worker pops, releases queue mutex, runs `evictionCallback` under `_mutex` -> STALE/EVICT/RE-ARM -> EVICT erases then `writeLogEntry('D')`.

**Lazy read** -> `get()` cache fast path (check embedded expiry under `_cacheMutex`, return copy or fall through) -> `_kv` path under `shared_lock(_mutex)` (check `_expiry`, treat `expiry <= now` as absent, else refill cache + return).

**`shutdown()`** -> set `_shutdown` -> `wheel.drain()` (fire due -> enqueue) -> signal worker + notify (queue mutex) -> join worker (drains queue) -> notify + join compaction -> flush + close log.

**`load()`** -> read snapshot (v1/v2) -> replay log (`'S'`/`'D'`/`'E'`/`'X'`, CRC + bounds, drop expired/corrupt, `_expiry` placeholders) -> (end of ctor, `postLoadArm`) arm each survivor, replacing placeholders.

---

## 6. Thread Safety Model

- **Lock inventory** -- `_mutex` (`shared_mutex`, main data guard, **non-recursive**), `_cacheMutex` (`shared_mutex`), `_compactionMutex` (`std::mutex`, CV), `_evictionMutex` (`std::mutex`, queue **leaf**), and the wheel-internal mutex inside `core::TimingWheel`.
- **Lock order** -- `_mutex -> _cacheMutex` (data mutation updates the warm cache under `_mutex`). A TTL arm under `_mutex` calls `_wheel->schedule()`/`cancel()`, which take the wheel-internal mutex (`_mutex -> wheel-internal mutex`). `_evictionMutex` is a **pure leaf**: `TimingWheel::schedule()` never fires a callback synchronously (a due/zero-delay timer fires on the next tick, and callbacks fire outside the wheel mutex), so an arm never enqueues -- `_evictionMutex` is reached only by the tick thread when it dispatches a fired closure, by the worker on pop, and by `shutdown()`, never nested under `_mutex`. `_compactionMutex` is likewise a leaf (the worker/compactor take only their own mutex and release it before taking `_mutex`). So no `_evictionMutex -> _mutex` or `_compactionMutex -> _mutex` inversion exists. The wheel's tick/fire path takes only the wheel-internal mutex and fires callbacks outside it.

| Operation | Synchronization | Notes |
|-----------|-----------------|-------|
| `set` / `setString` / `setBatch` (all overloads) | `unique_lock(_mutex)`, then `_cacheMutex` in `updateCache` | Throws if `_shutdown`. Log write self-flushes. |
| `remove` / `clear` / `expireAt` / `persist` | `unique_lock(_mutex)` | `remove`/`persist`/`clear` are no-ops post-shutdown; `expireAt` throws. |
| `get` / `getString` | `shared_lock(_cacheMutex)` fast path, then `shared_lock(_mutex)` | Cache hit returns a value copy. |
| `getBatch` / `exists` / `keys` / `keysWithPrefix` / `size` / `ttl` | `shared_lock(_mutex)` | Expired-not-yet-evicted keys filtered. |
| `flush` / `compact` / `forceCompact` | `unique_lock(_mutex)` | Non-recursive: no `_mutex`-holder may call these. |
| `shutdown` | atomic `_shutdown`, then `_evictionMutex` / `_compactionMutex` for CV signalling | Idempotent; holds no `_mutex` across joins. |
| eviction worker / tick thread | internal | Callers never interact with them directly. |

- **Generation safe-publication** -- a timer's captured id is written under `_mutex` (post-`schedule`) and read under `_mutex` (in `evictionCallback`). The eviction worker's `evictionCallback` therefore blocks on `_mutex` until the arm path's publication of the id (also under `_mutex`) completes -- so even a timer that becomes due immediately cannot observe an unpublished id.

---

## 7. Configuration Reference

| Field | Type | Default | Effect |
|-------|------|---------|--------|
| `magicNumber` | `uint32_t` | `0xB1A2C3D4` | Snapshot magic; mismatch -> ctor throws. |
| `version` | `uint32_t` | `2` | Vestigial: the store always writes v2 and `load()` accepts `{1,2}`. |
| `maxLogSizeBytes` | `uint32_t` | `10 * 1024 * 1024` (10 MiB) | Log size that triggers compaction. |
| `maxCacheSize` | `uint32_t` | `1000` | Read-cache capacity (simple eviction when full). |
| `enableBackgroundCompaction` | `bool` | `true` | Background compactor thread; if `false`, writes compact inline via `maybeCompact`. |
| `compactionInterval` | `std::chrono::milliseconds` | `30000` | Background compaction poll interval. |
| `ttlTickDuration` | `std::chrono::milliseconds` | `1000` | Wheel tick = eviction granularity. Must be `> 0`. |
| `ttlTicksPerWheel` | `std::size_t` | `256` | Slots per wheel level. Must be a **nonzero power of two**. |
| `ttlNumWheels` | `std::size_t` | `4` | Wheel levels. Must be `> 0`. Default `WHEEL_MAX_RANGE` ~= 136 years (validated cap ~= 200 years). |

Also fixed (not configurable): `MAX_KEY_LENGTH = 65535` and `MAX_VALUE_LENGTH = 100 * 1024 * 1024`; a key/value over these throws `KVStoreException`.

Invalid TTL config (non-positive tick, zero wheels, non-power-of-two ticks, or a `WHEEL_MAX_RANGE` that overflows / exceeds ~200 years) throws `KVStoreException` from the constructor -- **not** an assert (wheel asserts are release-stripped, and a zero tick is a division-by-zero in the wheel).

---

## 8. API Reference

```cpp
namespace iora { namespace storage {

struct KVStoreConfig
{
  uint32_t magicNumber = 0xB1A2C3D4;
  uint32_t version = 2;
  uint32_t maxLogSizeBytes = 10 * 1024 * 1024;
  uint32_t maxCacheSize = 1000;
  bool enableBackgroundCompaction = true;
  std::chrono::milliseconds compactionInterval{30000};
  std::chrono::milliseconds ttlTickDuration{1000};
  std::size_t ttlTicksPerWheel = 256;
  std::size_t ttlNumWheels = 4;
};

class KVStoreException : public std::runtime_error { /* ... */ };

class KVStore
{
public:
  // Construction. An EMPTY path selects in-memory mode (no file I/O, non-persistent,
  // per-instance isolated); a non-empty path is a persistent store (snapshot + .log).
  explicit KVStore(const std::string &path, const KVStoreConfig &config = {});
  ~KVStore();

  KVStore(const KVStore &) = delete;
  KVStore &operator=(const KVStore &) = delete;
  KVStore(KVStore &&) = delete;
  KVStore &operator=(KVStore &&) = delete;

  // Set (no expiry -- clears any existing TTL)
  void set(const std::string &key, const std::vector<std::uint8_t> &value);
  void setString(const std::string &key, const std::string &value);
  void setBatch(const std::unordered_map<std::string, std::vector<std::uint8_t>> &batch);

  // Set with relative TTL (ttl <= 0 throws)
  void set(const std::string &key, const std::vector<std::uint8_t> &value,
           std::chrono::seconds ttl);
  void setString(const std::string &key, const std::string &value, std::chrono::seconds ttl);
  void setBatch(const std::unordered_map<std::string, std::vector<std::uint8_t>> &batch,
                std::chrono::seconds ttl);

  // Expiry control
  void expireAt(const std::string &key, std::chrono::system_clock::time_point when);
  std::optional<std::chrono::seconds> ttl(const std::string &key) const;
  void persist(const std::string &key);

  // Reads (all filter expired keys)
  std::optional<std::vector<std::uint8_t>> get(const std::string &key);
  std::optional<std::string> getString(const std::string &key);
  std::unordered_map<std::string, std::vector<std::uint8_t>>
    getBatch(const std::vector<std::string> &keys);
  bool exists(const std::string &key) const;
  std::size_t size() const;
  std::vector<std::string> keys() const;
  std::vector<std::string> keysWithPrefix(const std::string &prefix) const;

  // Mutation / maintenance
  void remove(const std::string &key);
  std::size_t removeWithPrefix(const std::string &prefix); // returns matched count
  void clear();
  void flush();
  void compact();
  void forceCompact();
  void shutdown(); // idempotent; dtor-invoked

  // Diagnostics
  std::size_t ttlEvictionWriteErrorCount() const; // swallowed eviction 'D'-write failures
};

}} // namespace iora::storage
```

---
## 9. Design Decisions

| ID | Decision | Rationale |
|----|----------|-----------|
| DQ-1 | Dedicated single eviction worker + leaf-lock queue (synchronous wheel dispatcher) | Keeps the flushing `'D'` write off the tick thread; serializes evictions; one lazily-started thread. ThreadPool/tick-only-mark rejected. |
| DQ-2 | Plain `set` clears any existing TTL | Matches Redis `SET`; the session store re-sets the TTL on each touch (sliding idle). |
| DQ-3 | Library-only surface | The `mod_kvstore` module was dead (KVStore used directly) and was removed. |
| DQ-4 | `setBatch` takes one batch-wide TTL | Simpler; the session store sets one key at a time. |
| DQ-5 | `expireAt`/`persist` on an absent key are silent no-ops | Consistent with `remove()`. |
| DQ-6 | 1s tick / 256 ticks / 4 wheels (~1s granularity) | Ample for sessions/tokens; coarse tick minimizes wakeups; lazy-read covers sub-tick lateness. |
| CLOCK | Persist absolute `system_clock`-ms; arm with a clamped relative delay; `INT64_MIN` sentinel | Honors the wall-clock deadline across restart; the clamp avoids the wheel's far-future wrap; `INT64_MIN` avoids the legitimate epoch-0 collision. |
| GEN-GUARD | Generation token; always cancel + fresh schedule, never `reschedule` | `cancel()` is not a fire barrier and `reschedule()` preserves the id; a fresh monotonic id per mutation makes a stale collected fire a provable no-op. |
| COMPACT-SPLIT | `compact()`/`compactLocked()` split (in scope at v2) | Fixes the pre-existing `maybeCompact -> compact` recursive non-recursive-`_mutex` UB. |
| IM-1 | Empty path selects in-memory mode | Closes the empty-path-writes-`./.log`-in-CWD footgun; gives a first-class non-persistent store. |

---
## 10. Known Limitations

- **Eviction granularity is the wheel tick** (default 1s); sub-second TTLs round up to one tick, with the lazy-read backstop hiding the key in the gap. (DQ-6)
- **Per-write durability is a stream flush, not `fsync`**: `writeLogEntry` ends with `_logStream.flush()` (flush to the OS), so writes survive a **process** crash but can be lost on **power loss / OS crash**. Only the explicit `flush()` method issues an `fsync`.
- **Log framing corruption truncates replay**: `load()` skips a single CRC-mismatched entry (`continue`) but stops replaying on a corrupt frame length or short read (`break`). A torn trailing write is handled correctly, but mid-log framing corruption discards all subsequent (possibly valid) entries.
- **`removeWithPrefix` is not atomic**: it snapshots matching keys via `keysWithPrefix()` (shared lock) then `remove()`s each under separate unique locks, so a key inserted between the snapshot and the removals is not deleted; it returns the snapshot's matched count.
- **Clock skew**: a forward `system_clock` jump past a far-future deadline can evict early (governed by the absolute comparison + lazy-read); a backward jump delays the wheel fire but the absolute comparison keeps correctness. Persisted expiry is absolute, so a clock change between runs shifts deadlines. (KTP-2)
- **`ttl()` reports whole seconds**, truncated toward zero; `0s` means "<1s remaining", distinct from `nullopt`. (KTP-2)
- **`setBatch` applies one TTL to all keys** in the batch (no per-key TTL). (DQ-4)
- **Forward-incompatibility**: a v2 store cannot be read by an old (pre-TTL) iora binary; the store never downgrades. (KTP-1)
- **Same-second mass-expiry herd at shutdown**: `drain()` may time out and abandon due timers -- lossless (durable expiry re-arms/drops on reload) but those keys persist in memory until the next load. (KTP-8)
- **A runtime first-TTL-key arming failure** (thread-spawn `std::system_error` / `bad_alloc`) routes through the idempotent `shutdown()`, permanently disabling the store. This is intentional (KTP-7): such a failure is catastrophic resource exhaustion and the design fails hard rather than running with eviction silently disabled.
- **Read-cache eviction is not true LRU**: when full, `updateCache` erases `_cache.begin()` (an arbitrary bucket entry), not the least-recently-used one. Acceptable for a warm-read accelerator.
- **Test coverage**: two fault-injection scenarios (the ctor-arm-throw cleanup cases and a forced eviction `'D'`-write failure) require fault-injection infrastructure with no production seam and are tracked in backlog `tasks/iora/backlog/2026-06-02-5_kvstore-ttl-fault-injection-tests_P1.json`. Both underlying code paths were verified by code-review inspection; only the dedicated tests are deferred.

---
