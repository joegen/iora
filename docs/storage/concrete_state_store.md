# Iora ConcreteStateStore -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.1 |
| **Date** | 2026-09-22 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/storage/concrete_state_store.hpp` |
| **Namespace** | `iora::storage` |
| **Dependencies** | `iora/core/logger.hpp`, `iora/core/string_utils.hpp`; C++17 standard library (`<mutex>`, `<unordered_map>`, `<functional>`, `<optional>`, `<vector>`) |

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-09-22 | Initial guide, authored against source. |
| 1.1 | 2026-09-22 | Documents the storage-slice hardening: `findKeysMatching` now runs the caller predicate OUTSIDE the lock (copy-then-iterate), so a re-entrant predicate no longer deadlocks; the case-insensitive map traits are the shared, unsigned-char-safe `core::StringUtils::CaseInsensitiveHash/CaseInsensitiveEqual` (no more `tolower`-on-`char` UB). |

---

## 1. Executive Summary

### Problem

Many components need a small, thread-safe, **in-memory** string-to-string state map with a few query conveniences (prefix scan, value scan, custom predicate) -- but do **not** need persistence, TTL, binary values, or the on-disk machinery of `KVStore`. Re-deriving a locked `unordered_map` in each such site duplicates the same guard-every-access boilerplate.

### Solution

`iora::storage::ConcreteStateStore` is a single class wrapping a case-insensitive `std::unordered_map<std::string, std::string>` behind one `std::mutex`:

- **Core map operations** -- `set`, `get`, `remove`, `contains`, `size`, `empty`, `keys`.
- **Query helpers** -- `findKeysWithPrefix`, `findKeysByValue`, `findKeysMatching(predicate)`.
- **Case-insensitive keys** -- the map uses the shared `core::StringUtils::CaseInsensitiveHash` + `CaseInsensitiveEqual` traits, so `"Key"` and `"key"` address the same entry (ASCII-only, locale-independent, and `unsigned char`-safe).
- **Debug-logged** -- every operation emits a `core::Logger::debug` trace (errors from a user predicate are logged and skipped).

### Technical Impact

- One locked-map implementation for lightweight state, with query helpers callers otherwise hand-roll.
- Every public method is individually thread-safe; no external locking is required for a single call.
- The custom predicate in `findKeysMatching` runs outside the lock, so it may safely re-enter the store and cannot stall other callers.
- Zero persistence and zero background threads -- the store is pure process memory.

---

## 2. System Architecture

### 2.1 Component relationships

```
iora::storage::ConcreteStateStore
|-- _mutex : std::mutex (mutable; guards every access)
`-- _store : unordered_map<string, string,
                           core::StringUtils::CaseInsensitiveHash,
                           core::StringUtils::CaseInsensitiveEqual>
```

`ConcreteStateStore` owns its map outright; there is no sharing, no handle, and no other collaborator besides `core::Logger` for debug tracing and `core::StringUtils` for the key traits.

### 2.2 Threading model

| Thread | Responsibility |
|--------|----------------|
| Caller thread(s) | Every public method; each takes `_mutex` (the predicate in `findKeysMatching` runs after the lock is released) |

There are no internal threads. All concurrency is caller-driven and serialized by the single mutex.

---

## 3. Component Deep Dive

### 3.1 The single-mutex map

Every public method acquires `std::lock_guard<std::mutex> lock(_mutex)` for its body (with one deliberate exception in `findKeysMatching`, below), then delegates to the underlying `unordered_map`. Reads and writes are mutually exclusive -- there is no reader/writer distinction (contrast `KVStore`, which uses a `shared_mutex`). This is intentional for a small, low-contention state map where the simplicity outweighs read concurrency.

`get` returns `std::optional<std::string>` **by value** (a copy of the stored string taken under the lock), so the returned value can never dangle against a concurrent `remove`.

### 3.2 Case-insensitive keying

The map's hash and equality are the shared `core::StringUtils` traits:

```cpp
std::unordered_map<std::string, std::string,
                   iora::core::StringUtils::CaseInsensitiveHash,
                   iora::core::StringUtils::CaseInsensitiveEqual> _store;
```

These fold case via `StringUtils::toLowerChar`, which casts to `unsigned char` and lowercases only ASCII `A-Z` -- locale-independent and free of the `tolower`-on-negative-`char` undefined behavior a hand-rolled trait risks. So `set("User", ...)` followed by `get("user")` returns the value. The store preserves the **original** key casing used at insertion (that is what `keys()` returns and what the debug log records); only lookup and equality are case-folded.

### 3.3 Query helpers

- `findKeysWithPrefix(prefix)` -- returns every key for which `key.rfind(prefix, 0) == 0` (a genuine starts-with test), scanned under the lock. The prefix match is **case-sensitive** on the stored (original-cased) key, unlike key equality.
- `findKeysByValue(value)` -- returns every key whose value equals `value` exactly (case-sensitive), scanned under the lock.
- `findKeysMatching(predicate)` -- **copy-then-iterate**: it snapshots all keys into a local vector under the lock, **releases the lock**, then applies `predicate` to each snapshotted key. So the predicate runs with no lock held: it may safely re-enter the store, and a slow predicate does not block other operations. A predicate that throws a `std::exception` is caught per key, logged via `core::Logger::error`, and that key is skipped -- one bad key never aborts the scan (a non-`std::exception` throw propagates out of `findKeysMatching`). Because the keys are snapshotted, the result reflects a point-in-time view (consistent with `keys()`): a key removed concurrently may still be presented to the predicate.

---

## 4. Usage Guide

### 4.1 Quick start

```cpp
#include "iora/storage/concrete_state_store.hpp"
using iora::storage::ConcreteStateStore;

ConcreteStateStore store;
store.set("session:abc", "active");
store.set("Session:XYZ", "idle");            // distinct key ("session:xyz" != "session:abc")

if (auto v = store.get("SESSION:ABC"))       // case-insensitive lookup -> "active"
{
  // ...
}

store.remove("session:abc");
```

### 4.2 Scanning

```cpp
auto sessionKeys = store.findKeysWithPrefix("session:");   // starts-with
auto idleKeys    = store.findKeysByValue("idle");          // exact value match
auto longKeys    = store.findKeysMatching(
  [](const std::string &k) { return k.size() > 16; });
```

### 4.3 Anti-patterns

- **Do NOT** assume prefix/value scans are case-insensitive. Only key *equality/lookup* is case-folded; `findKeysWithPrefix` and `findKeysByValue` compare the stored (original-cased) strings exactly.
- **Do NOT** hold external state across two calls expecting atomicity -- e.g. `if (!store.contains(k)) store.set(k, v)` is a check-then-act race; another thread can insert between the two calls. There is no compare-and-set primitive; guard such sequences in your own layer.
- **Do NOT** use this for anything that must survive a restart or exceed process memory -- it is non-persistent and unbounded. Use `KVStore` or `JsonFileStore` for durability.
- **Do NOT** rely on a throwing predicate to abort `findKeysMatching` -- a `std::exception` is caught, logged, and the key skipped (a non-`std::exception` throw does propagate).

---

## 5. Call Flow / Sequence Reference

**`set(key, value)`** -> `lock_guard(_mutex)` -> probe `_store.find(key)` to classify add-vs-update (for the log) -> `_store[key] = value` -> `Logger::debug` -> unlock.

**`get(key)`** -> `lock_guard(_mutex)` -> `_store.find(key)` -> if found, `Logger::debug` + return a copy; else `Logger::debug` + return `nullopt` -> unlock.

**`findKeysMatching(predicate)`** -> `lock_guard(_mutex)` snapshot all keys into a vector -> **release lock** -> for each key: `try { if (predicate(key)) result.push_back(key); } catch (const std::exception &e) { Logger::error(...); }` -> `Logger::debug` count -> return.

---

## 6. Thread Safety Model

- **Lock inventory** -- one `mutable std::mutex _mutex`. No condition variables, no atomics, no internal threads.
- **Lock order** -- single lock; no ordering concerns and no possibility of deadlock from within the class.
- **Callback safety** -- `findKeysMatching` snapshots keys under `_mutex` and then invokes the caller's predicate **after releasing the lock** (copy-then-iterate). A predicate may therefore re-enter any `ConcreteStateStore` method without deadlocking, and a slow predicate does not block other operations.

| Operation | Synchronization | Notes |
|-----------|-----------------|-------|
| `set` | `lock_guard(_mutex)` | Whole body under the lock. |
| `get` | `lock_guard(_mutex)` | Returns a value copy. |
| `remove` | `lock_guard(_mutex)` | Returns whether a key was erased. |
| `contains` / `size` / `empty` | `lock_guard(_mutex)` | Point-in-time snapshot. |
| `keys` | `lock_guard(_mutex)` | Copies all keys into a vector. |
| `findKeysWithPrefix` / `findKeysByValue` | `lock_guard(_mutex)` | Full linear scan under the lock. |
| `findKeysMatching` | snapshot under `lock_guard(_mutex)`, predicate run lock-free | Re-entrant-safe; point-in-time snapshot. |

---

## 7. Configuration Reference

`ConcreteStateStore` has **no configuration**: no constructor parameters, no tunables, no defaults. It is default-constructed and starts empty.

---

## 8. API Reference

```cpp
namespace iora { namespace storage {

class ConcreteStateStore
{
public:
  void set(const std::string &key, const std::string &value);
  std::optional<std::string> get(const std::string &key) const;
  bool remove(const std::string &key);
  bool contains(const std::string &key) const;

  std::vector<std::string> keys() const;
  std::size_t size() const;
  bool empty() const;

  std::vector<std::string> findKeysWithPrefix(const std::string &prefix) const;
  std::vector<std::string> findKeysByValue(const std::string &value) const;
  std::vector<std::string> findKeysMatching(
    std::function<bool(const std::string &)> matcher) const;
};

}} // namespace iora::storage
```

The case-insensitive map traits are `iora::core::StringUtils::CaseInsensitiveHash` and `iora::core::StringUtils::CaseInsensitiveEqual` (see the string_utils guide); `ConcreteStateStore` no longer defines its own.

---
## 9. Design Decisions

| Decision | Rationale |
|----------|-----------|
| Single `std::mutex`, not `shared_mutex` | Small, low-contention state map; a plain mutex is simpler and the read/write asymmetry does not pay off here (contrast `KVStore`). |
| Shared `core::StringUtils` case-insensitive traits | Reuses the ASCII-only, `unsigned char`-safe foundation traits instead of a hand-rolled `tolower`-on-`char` version (which is UB for bytes >= 0x80). |
| Original key casing preserved in `keys()`/logs | The caller's spelling is more useful for diagnostics than a normalized form. |
| `get` returns `optional<string>` by value | Copy-under-lock guarantees the result cannot dangle against a concurrent `remove`. |
| `findKeysMatching` copy-then-iterate (predicate lock-free) | The caller predicate must not run under the store lock: that would deadlock a re-entrant predicate and let a slow predicate block every other operation. |
| Predicate errors in `findKeysMatching` are logged and skipped | One malformed key must not abort a whole scan. |
| No persistence, no TTL, no size cap | Deliberately the lightweight tier; `KVStore`/`JsonFileStore` cover durability. |

---
## 10. Known Limitations

- **Unbounded**: the map grows without limit; there is no eviction or size cap. A caller that inserts unboundedly must prune itself.
- **Non-persistent**: all state is lost on process exit.
- **No atomic read-modify-write**: no `setIfAbsent`/compare-and-set; check-then-act sequences across two calls are not atomic.
- **Prefix/value scans are O(n)** full scans under the exclusive lock; large maps with frequent scans will serialize all other access.
- **`findKeysMatching` snapshots keys**: on a very large map the key snapshot is an O(n) copy under the lock, and the predicate sees a point-in-time view (a concurrently-removed key may still be tested).
- **Case-folding is ASCII-only**: keys are folded via `StringUtils::toLowerChar`, which lowercases only ASCII `A-Z`; non-ASCII bytes pass through unchanged (compared case-sensitively) -- deterministic and locale-independent, but not Unicode-aware.

---
