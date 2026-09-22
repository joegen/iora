# Iora JsonFileStore -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.2 |
| **Date** | 2026-09-22 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/storage/json_file_store.hpp` |
| **Namespace** | `iora::storage` |
| **Dependencies** | `iora/core/logger.hpp`, `iora/parsers/json.hpp`; C++17 standard library (`<mutex>`, `<condition_variable>`, `<thread>`, `<fstream>`, `<set>`, `<vector>`, `<atomic>`) |

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-09-22 | Initial guide, authored against source. |
| 1.1 | 2026-09-22 | Documented the concurrency/persistence hardening (failed writes retry not drop; deadlock-free teardown; predicate-form CV wait; race-free interval). |
| 1.2 | 2026-09-22 | Flush I/O moved OFF `registryMutex` via a drain-handshake: the flush thread holds a new `flushCycleMutex` for a whole cycle (snapshot under `registryMutex`, then I/O with `registryMutex` released); `unregisterStore` erases then drains `flushCycleMutex` to close the use-after-free window. `registerStore` now rolls back its registry insert on a thread-spawn failure. Result: registration is never blocked by disk I/O; only destruction briefly waits out an in-flight cycle. |

---

## 1. Executive Summary

### Problem

Some components want a **human-readable, JSON-file-backed** key-value store with **typed values** (numbers, strings, nested objects) and automatic periodic persistence -- not the opaque binary log of `KVStore`, and not the string-only in-memory `ConcreteStateStore`. Writing a load-on-construct / flush-on-interval / flush-on-destruct store, correctly and thread-safely, in every such site duplicates fiddly file and thread lifecycle code.

### Solution

`iora::storage::JsonFileStore` wraps a `parsers::Json` object persisted to a single JSON file:

- **Typed API** -- `set<T>(key, value)` / `get<T>(key) -> optional<T>` via `parsers::Json` conversion, with `std::string` overloads.
- **Load on construct** -- reads and parses the file if it exists; a parse failure logs an error and starts from an empty object rather than throwing.
- **Background flushing** -- a **single shared** flush thread (across all live instances) writes every dirty store to disk on a configurable interval (default 2s), with the disk I/O performed **off** the registry lock; `flush()` forces an immediate write. A **failed write keeps the store dirty** so the next flush retries it (no silent drop).
- **Flush on destruct** -- the destructor unregisters (removing the instance from the shared registry and draining any in-flight flush cycle before any member is destroyed) and flushes, so a clean teardown persists pending changes.
- **Pretty-printed** -- the file is written with `dump(2)` (two-space indent), so it is diffable and hand-editable.

### Technical Impact

- One JSON-backed store for typed, human-readable configuration/state, with persistence handled automatically.
- A single background thread serves every instance (started on the first registration, stopped on the last), rather than one thread per store.
- The flush thread's disk I/O runs off `registryMutex`, so **constructing** a store is not blocked behind a flush; **destroying** one briefly drains an in-flight cycle (see Known Limitations). A drain-handshake guarantees the flusher can never dereference a destroyed instance.

---

## 2. System Architecture

### 2.1 Component relationships

```
iora::storage::JsonFileStore (per instance)
|-- _filename  : const string          (backing file path)
|-- _mutex     : std::mutex (mutable)  (guards _store + _dirty)
|-- _store     : parsers::Json         (the data, a JSON object)
`-- _dirty     : bool                  (unwritten changes present)

Shared, process-global (function-local statics):
|-- registry()       : set<JsonFileStore*>       (all live instances; guarded by registryMutex)
|-- registryMutex()  : std::mutex                (guards registry membership; held only briefly)
|-- lifecycleMutex() : std::mutex                (serializes the flush-thread spawn/join)
|-- flushCycleMutex(): std::mutex                (held by the flusher for a whole cycle; drained on unregister)
|-- flushThread()    : std::thread               (single background flusher)
|-- flushInterval()  : std::chrono::milliseconds (default 2000; setFlushInterval write + flush-thread read under terminateCvMutex; public read accessor is an unsynchronized config query)
|-- terminationCv()  : std::condition_variable   (wakes the flusher to exit / re-interval)
|-- terminateCvMutex(): std::mutex
`-- shouldExit()     : std::atomic<bool>
```

The shared state is exposed through **function-local static accessors** so their construction/destruction order is well-defined (each is constructed on first use and destroyed in reverse order at process exit) -- avoiding the static-initialization-order fiasco a set of namespace-scope statics would risk. In a shared-library build (`IORA_CORE_SHARED` / `IORA_CORE_BUILDING`) these accessors are declared in the header and defined once in the core translation unit so there is a single instance across the shared boundary; otherwise they are inline function-local statics.

### 2.2 Data flow: construct, mutate, background flush

```mermaid
sequenceDiagram
    participant C as Caller
    participant S as JsonFileStore
    participant R as registry (shared)
    participant F as flush thread (shared)
    C->>S: JsonFileStore("state.json")
    S->>S: load file (or empty object on parse error)
    S->>R: registerStore() (lifecycleMutex; start thread if first)
    C->>S: set("k", 42)
    Note over S: lock _mutex; _store["k"]=42; _dirty=true
    loop every flushInterval
        F->>F: acquire flushCycleMutex (whole cycle)
        F->>R: snapshot registry under registryMutex (released)
        F->>S: tryFlushIfDirty() per store (I/O, registryMutex released)
        Note over S: lock _mutex; if _dirty and saveToFile() ok -> _dirty=false
    end
    C->>S: ~JsonFileStore()
    S->>R: unregisterStore() (erase under registryMutex; drain flushCycleMutex; stop+join if last)
    S->>S: flush()
```

### 2.3 Threading model

| Thread | Origin | Responsibility | Locks taken |
|--------|--------|----------------|-------------|
| Caller thread(s) | user | All public API on an instance | that instance's `_mutex`; ctor/dtor take `lifecycleMutex()`, then briefly `registryMutex()` / `terminateCvMutex()`, and (dtor) `flushCycleMutex()` to drain |
| Background flush thread | first `registerStore()` | Periodically flush every dirty store | `terminateCvMutex()` (wait), then `flushCycleMutex()` for the whole cycle, `registryMutex()` only to snapshot, then each store's `_mutex` for the write |

The single flush thread is started when the registry goes from empty to one member and stopped (signalled + joined) when it returns to empty.

---

## 3. Component Deep Dive

### 3.1 Construction and load

The constructor stores the filename, opens the file, and if present streams it into `_store` via `parsers::Json`'s `operator>>`. There are three empty-start paths, all logged and none throwing: a **missing file**; a **parse exception** (corrupt JSON); and a **file that parses to a non-object** (array/scalar), which is coerced to `parsers::Json::object()` because the whole API indexes by key (`set`/`get`/`remove`) and a non-object store would make `operator[]`/`erase` throw. After a successful object load, or any of these resets, the constructor calls `registerStore()`.

### 3.2 Typed set/get

```cpp
template <typename T> void set(const std::string &key, const T &value);   // + std::string overload
template <typename T> std::optional<T> get(const std::string &key) const; // + std::string overload
```

`set` assigns `value` into the JSON object (`_store[key] = value`) and marks the store dirty; the value type must be assignable to `parsers::Json`. `get<T>` returns `nullopt` if the key is absent, otherwise attempts `_store[key].get<T>()`; a conversion failure is logged and returns `nullopt` (never throws). The `std::string` overloads exist so string values take the direct path and produce clearer debug logs.

### 3.3 Persistence: dirty flag, immediate and background flush

Every mutation sets `_dirty = true`. Both the caller-driven `flush()` and the background `tryFlushIfDirty()` funnel through one private helper, `writeAndClearLocked()` (called with `_mutex` held after confirming `_dirty`): it calls `saveToFile()` and clears `_dirty` **only if the write succeeded**. `saveToFile()` returns `bool` -- it opens the file with truncation, writes the pretty-printed JSON, and returns `true` on success or `false` on any open/serialization/write failure (each logged). So a failed write leaves the store dirty and the next flush (background tick or explicit `flush()`) retries it -- a failed write is never silently dropped. There is no atomic-rename; the file is written in place (see Known Limitations).

### 3.4 Registry, drain-handshake, and the shared flush thread

`registerStore()` and `unregisterStore()` run under `lifecycleMutex()`, which serializes the whole spawn/join lifecycle. The flush thread **never** takes `lifecycleMutex()`, so holding it across `join()` cannot deadlock against the flush loop.

- `registerStore()` inserts `this` under `registryMutex()`; if it was the first member, it reaps any prior (already-joined) thread, clears `shouldExit()` under `terminateCvMutex()`, and spawns `flushThreadFunc`. If the `std::thread` construction throws, it **rolls back** the registry insert (erase `this`) and rethrows, so a failed construction leaves no dangling registry entry (which would otherwise permanently wedge the first-instance-spawns-the-thread pattern).
- `unregisterStore()` erases `this` under `registryMutex()`, then **drains** by acquiring+releasing `flushCycleMutex()`. If the registry becomes empty, it sets `shouldExit()` under `terminateCvMutex()`, notifies, and joins the thread -- holding only `lifecycleMutex()` (all other locks released), so `join()` cannot deadlock.

`flushThreadFunc` loops:

1. wait on `terminationCv()` for `flushInterval()` using the **predicate form** (`[]{ return shouldExit(); }`), reading `flushInterval()` under `terminateCvMutex()`;
2. break if `shouldExit()`;
3. acquire `flushCycleMutex()` for the **whole cycle**, snapshot the registry into a local vector under `registryMutex()` (then release `registryMutex()`), and call `tryFlushIfDirty()` on each snapshotted store -- each wrapped in try/catch -- performing the disk I/O with `registryMutex()` **released**.

**Why this is use-after-free-safe.** The flush thread holds `flushCycleMutex()` for the entire cycle. `unregisterStore()` erases `this` under `registryMutex()` and then blocks on `flushCycleMutex()`, so: a store present in the current cycle's snapshot cannot be destroyed until the cycle completes (its dtor's drain waits), and a store erased before the snapshot is not in it. The disk I/O therefore runs off `registryMutex()` (registration is not blocked by a flush; **destruction**, however, drains) while the drain still closes the lifetime window. The one coupling that remains is that **destruction** briefly waits out an in-flight cycle -- and, because `registerStore`/`unregisterStore` are serialized under `lifecycleMutex()` (held across the drain), a construction that races a currently-draining destruction is transitively blocked on `lifecycleMutex()` for up to that cycle.

---

## 4. Usage Guide

### 4.1 Quick start

```cpp
#include "iora/storage/json_file_store.hpp"
using iora::storage::JsonFileStore;

JsonFileStore store("app_state.json");        // loads existing file if present

store.set("retries", 3);                        // typed (int)
store.set("endpoint", std::string("h.example"));

// Brace-init builds a JSON ARRAY, so construct an object explicitly:
auto nested = iora::parsers::Json::object();
nested["a"] = 1;
nested["b"] = 2;
store.set("nested", nested);

auto retries  = store.get<int>("retries");      // optional<int> = 3
auto endpoint = store.get("endpoint");          // optional<string>

store.flush();                                   // force immediate write
```

### 4.2 Tuning the background interval

```cpp
// Static: affects the single shared flush thread for all instances.
JsonFileStore::setFlushInterval(std::chrono::milliseconds(500));
```

### 4.3 Lifecycle

```cpp
{
  JsonFileStore s("scratch.json");
  s.set("k", "v");
}   // destructor unregisters + flushes -> "scratch.json" now contains {"k":"v"}
```

### 4.4 Anti-patterns

- **Do NOT** rely on `get<T>` throwing on a type mismatch -- it logs and returns `nullopt`. Distinguish "absent" from "wrong type" yourself if you must (both yield `nullopt`).
- **Do NOT** assume a crash persists recent writes -- durability is only at the flush interval, an explicit `flush()`, or destruction. There is no per-write flush (unlike `KVStore`).
- **Do NOT** build a JSON object with brace-init: `iora::parsers::Json{{"a",1},{"b",2}}` builds an **array** `[["a",1],["b",2]]`, not an object. Use `Json::object()` and assign keys.
- **Do NOT** set `flushInterval` expecting it to be per-instance -- it is a single static shared by every store.
- **Do NOT** hand the same file to two `JsonFileStore` instances -- each flushes its own in-memory copy in place, so they will clobber each other's writes.
- **Do NOT** leak a `JsonFileStore` (never destroy it): the shared flush thread is joined only when the last instance unregisters, so a leaked instance leaves the thread joinable at process exit -> `std::terminate`.

### 4.5 Concurrency notes

Every instance method is individually thread-safe (guarded by the instance `_mutex`). Instances may be constructed and destroyed concurrently on different threads while the shared flush thread runs -- the registry/lifecycle/drain locking makes that safe (no use-after-free, no teardown deadlock).

---

## 5. Call Flow / Sequence Reference

**Construction** -> store `_filename` -> open + `operator>>` into `_store` (missing file, parse throw, or a non-object result all log and reset `_store = Json::object()`) -> `registerStore()` (lock `lifecycleMutex`; insert under `registryMutex`; if first, spawn `flushThreadFunc`, rolling back the insert on a spawn throw).

**`set<T>(key, value)`** -> `lock_guard(_mutex)` -> classify add-vs-update for the log -> `_store[key] = value` -> `_dirty = true` -> `Logger::debug` -> unlock.

**Background flush tick** -> `unique_lock(terminateCvMutex)` + predicate `wait_for(flushInterval())` -> break if `shouldExit()` -> `lock_guard(flushCycleMutex)` for the whole cycle -> snapshot registry under `registryMutex` (released) -> for each store `try { tryFlushIfDirty() } catch(...)` (`lock_guard(_mutex)`; if `_dirty` and `saveToFile()` ok, clear `_dirty`; else keep dirty).

**Destruction** -> `unregisterStore()` (lock `lifecycleMutex`; erase under `registryMutex`; drain `flushCycleMutex`; if empty: set `shouldExit` under `terminateCvMutex`, notify, `join()` holding only `lifecycleMutex`) -> `flush()`.

---

## 6. Thread Safety Model

- **Lock inventory** -- per-instance `mutable std::mutex _mutex` (guards `_store` + `_dirty`); shared `registryMutex()` (guards the registry set; held only briefly to insert/erase/snapshot); shared `lifecycleMutex()` (serializes flush-thread spawn/join); shared `flushCycleMutex()` (held by the flusher for a whole cycle; drained by `unregisterStore`); shared `terminateCvMutex()` + `terminationCv()` (flush-thread wakeup, and guards `flushInterval()` + `shouldExit()` transitions); shared `std::atomic<bool> shouldExit()`.
- **Lock order** -- `lifecycleMutex -> flushCycleMutex -> registryMutex -> _mutex`, and `lifecycleMutex -> terminateCvMutex`. The flush thread takes `flushCycleMutex` then `registryMutex` (snapshot, released) then per-store `_mutex`; `unregisterStore` releases `registryMutex` *before* taking `flushCycleMutex` (drain) and holds only `lifecycleMutex` across `join()`. So no path holds `registryMutex` while taking `flushCycleMutex`, and the flush thread never takes `lifecycleMutex` -- no lock-order inversion, no join deadlock.
- **Use-after-free safety** -- the flusher holds `flushCycleMutex` for the whole cycle; `unregisterStore` erases under `registryMutex` then drains `flushCycleMutex` before the instance's members are destroyed, so no cycle can dereference a destroyed instance.
- **CV discipline** -- `shouldExit()` is set under `terminateCvMutex()` before the notify, and the wait is predicate-form, so there is no lost-wakeup teardown stall.

| Operation | Synchronization | Notes |
|-----------|-----------------|-------|
| `set` (all overloads) | `lock_guard(_mutex)` | Sets `_dirty`. |
| `get` (all overloads) | `lock_guard(_mutex)` | Returns a value copy / `nullopt`. |
| `remove` | `lock_guard(_mutex)` | Sets `_dirty` if a key was erased. |
| `flush` | `lock_guard(_mutex)` | Clears `_dirty` only on a successful write. |
| ctor `registerStore` / dtor `unregisterStore` | `lifecycleMutex()`, then briefly `registryMutex()` / `terminateCvMutex()` / (dtor) `flushCycleMutex()` | Starts/stops the shared thread at the empty boundary; spawn rollback; drain on unregister; `join()` off all but `lifecycleMutex`. |
| `setFlushInterval` | `lock_guard(terminateCvMutex())` + notify | Race-free with the flush thread's interval read; new interval applies next cycle. |
| background `flushThreadFunc` | `terminateCvMutex()` (wait), then `flushCycleMutex()` (whole cycle), `registryMutex()` (snapshot only), then per-store `_mutex` | I/O off `registryMutex`; drain-protected. |

---

## 7. Configuration Reference

| Parameter | Type | Default | How set | Effect |
|-----------|------|---------|---------|--------|
| backing file | `std::string` | (required) | constructor argument | Path loaded on construct and written on flush. |
| flush interval | `std::chrono::milliseconds` | `2000` | `static setFlushInterval(...)` | Background flush period, shared by all instances (read/written under `terminateCvMutex`; takes effect next cycle). |

There is no other configuration; the store always pretty-prints with `dump(2)` and always writes in place.

---

## 8. API Reference

```cpp
namespace iora { namespace storage {

class JsonFileStore
{
public:
  explicit JsonFileStore(std::string filename);
  ~JsonFileStore();

  template <typename T> void set(const std::string &key, const T &value);
  void set(const std::string &key, const std::string &value);

  template <typename T> std::optional<T> get(const std::string &key) const;
  std::optional<std::string> get(const std::string &key) const;

  void remove(const std::string &key);
  void flush();

  static void setFlushInterval(std::chrono::milliseconds interval);
  static std::chrono::milliseconds &flushInterval(); // public read accessor (config query)

private:
  // Internal (NOT public API): the shared background-flush machinery is exposed
  // only as private static accessors (declared here, defined once in the core TU
  // in a shared-library build). Listed for completeness; do not call from outside
  // the class. Only setFlushInterval() and flushInterval() above are public.
  static std::set<JsonFileStore *> &registry();
  static std::mutex &registryMutex();
  static std::mutex &lifecycleMutex();
  static std::mutex &flushCycleMutex();
  static std::thread &flushThread();
  static std::condition_variable &terminationCv();
  static std::mutex &terminateCvMutex();
  static std::atomic<bool> &shouldExit();
};

}} // namespace iora::storage
```

---
## 9. Design Decisions

| Decision | Rationale |
|----------|-----------|
| JSON file with `dump(2)` | Human-readable, diffable, hand-editable persistence -- the point of this store vs `KVStore`'s binary log. |
| Typed `set<T>`/`get<T>` via `parsers::Json` | Callers store native types (ints, nested objects), not just strings. |
| Single shared background flush thread | One thread serves all instances (started/stopped at the registry's empty boundary) rather than one per store. |
| Function-local static shared state | Well-defined construction/destruction order (avoids the static-init-order fiasco); a shared-library define routes to a single definition. |
| Failed write keeps the store dirty | A transient write failure is retried on the next flush instead of silently dropping the change. |
| Drain-handshake: flush I/O off `registryMutex` | The flusher holds `flushCycleMutex` for a whole cycle and snapshots under `registryMutex`, then writes with `registryMutex` released; `unregisterStore` drains `flushCycleMutex`. Registration is not blocked by disk I/O, and the lifetime window stays closed without requiring `shared_ptr` ownership of instances. |
| `registerStore` rolls back on a spawn throw | A failed `std::thread` construction must not leave a dangling registry entry (which would wedge the first-instance-spawns pattern). |
| `lifecycleMutex` serializes spawn/join; `join()` off the other locks | Removes the teardown deadlock and any double-spawn/double-join race while keeping the flusher lock-free of the lifecycle mutex. |
| Predicate-form CV wait + interval under `terminateCvMutex` | No lost-wakeup teardown stall; no data race on the shared interval. |
| Parse failure starts empty, never throws | A corrupt or partially-written file must not brick construction; the error is logged. |
| Flush on interval + explicit + destruct (no per-write flush) | Amortizes disk writes for a config/state store; explicit `flush()` covers the must-persist-now case. |

---
## 10. Known Limitations

- **No per-write durability**: changes are persisted only at the flush interval, an explicit `flush()`, or destruction. A crash between flushes loses recent writes (the design amortizes writes for a config/state store).
- **In-place, non-atomic file write**: `saveToFile()` truncates and rewrites in place; a crash mid-write can leave a truncated/corrupt file (which the next construct will log and treat as empty). There is no temp-file-then-rename (contrast `KVStore` compaction).
- **Destruction briefly waits out an in-flight flush cycle**: `unregisterStore()` drains `flushCycleMutex`, so destroying an instance can block for the remainder of a flush cycle already in progress. Registration is not blocked, and the wait is bounded by one cycle's I/O.
- **Leaked instance -> `std::terminate` at exit**: the shared flush thread is joined only when the last instance unregisters, so an instance that is never destroyed leaves the `std::thread` static joinable at process teardown. Every `JsonFileStore` must be destroyed before process exit.
- **One writer per file**: two instances backing the same file each own an independent in-memory copy and flush in place, clobbering each other.
- **Whole-object rewrite**: every flush serializes and writes the entire object; large stores pay full-file I/O per flush.
- **Interval granularity**: a changed `flushInterval` takes effect on the next wait cycle (the running wait is notified but its timeout is not shortened).

---
