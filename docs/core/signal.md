# Iora Signal -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 2.2 |
| **Date** | 2026-09-10 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/core/signal.hpp` |
| **Namespace** | `iora::core` |
| **Dependencies** | Standard library only -- `<algorithm>`, `<atomic>`, `<cstdint>`, `<exception>`, `<functional>`, `<memory>`, `<mutex>`, `<utility>`, `<vector>`. Header-only; no intra-Iora and no external/third-party dependencies. (`<algorithm>` is included directly for `std::remove_if` -- see the Revision History entry below.) |

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-03-20 | Initial implementation. |
| 1.1 | 2026-03-20 | Added `weak_ptr` auto-disconnect, `ScopedConnection`, exception handler, `_needsPrune` deduplication. |
| 2.0 | 2026-03-20 | Rewritten as a full Architecture & Programmer's Guide (published as `coding_trackers/docs/iora/signal.md`). |
| 2.1 | 2026-09-10 | Migrated to `docs/core/signal.md` and **fully re-verified against `include/iora/core/signal.hpp` (294 lines) and `tests/core/iora_test_signal.cpp`.** Drift corrected: the COW slot list `_slots` and the `_exceptionHandler` are **plain `std::shared_ptr` members accessed through the `std::atomic_load`/`std::atomic_store` free-function overloads** (not `std::atomic<std::shared_ptr<...>>`), and those free functions are invoked with **no order argument, i.e. `memory_order_seq_cst`** -- the guide now states the actual ordering at each site rather than "relaxed/wait-free". Clarified that `emit()` holds no class mutex but the `shared_ptr` atomic free functions are not guaranteed lock-free (internal spinlock pool on libstdc++). Reformatted to the 12-section template with contiguous numbered sections and a dedicated COW / memory-ordering section (section 4). Flagged two candidate code defects in section 12: a missing `<algorithm>` include for `std::remove_if`, and a non-exception-safe `_needsPrune` reset that can permanently disable pruning on an allocation failure. |
| 2.2 | 2026-09-10 | CP-3 doc-review + code-fix sync: `<algorithm>` include + `_needsPrune` reset-on-throw resolved; terminate-on-OOM teardown documented as tracked (2026-09-10-27); noexcept/lock-free wording corrected. |

---

## 1. Executive Summary

### Problem

The Karoo codebase notifies interested parties of events through hand-rolled callback structs -- a record of five-to-seven `std::function` (or raw function-pointer) fields such as `onRegistered`, `onDeregistered`, `onExpired`, `onError`, `onTimeout`. This pattern has three recurring costs:

- **Single subscriber per event.** Each field holds exactly one callback. When two components need the same event, the producer must fan out by hand, or the second consumer must chain-wrap the first.
- **Schema churn.** Adding one event requires editing the struct, every producer that populates it, and every consumer that reads it.
- **Manual lifetime management.** If a subscriber is destroyed while the producer still holds its callback, the next invocation is undefined behavior. Nothing disconnects automatically.

### Solution

`signal.hpp` provides a single typed observer primitive in `iora::core`: **`Signal<Args...>`**, implementing a multi-subscriber signal/slot with:

- **Copy-on-write (COW) slot list** -- a `std::shared_ptr<std::vector<Slot>>` that is swapped atomically via the `std::atomic_load`/`std::atomic_store` free functions. Emission reads a snapshot; mutation clones the vector under a mutex and publishes a replacement.
- **Lock-free slot dispatch** -- `emit()`'s slot-dispatch path takes no class mutex: one `atomic_load` of the slot list, one `atomic_load` of the exception handler, then a linear scan of the snapshot. No heap allocation on that path. The prune path (entered only when expired `weak_ptr` slots are seen) does acquire `_mutex` to rebuild the list, so `emit()` is not wholly mutex-free.
- **`weak_ptr` auto-disconnect** -- slots connected via `connect(std::weak_ptr<T>, method)` are skipped when the target expires and pruned after the emission pass.
- **`ScopedConnection` RAII** -- a movable, non-copyable handle whose destructor disconnects.
- **Per-slot exception isolation** -- each slot invocation is wrapped in `try/catch`; an optional handler (stored as an atomic `shared_ptr`) receives the `std::exception_ptr` without stopping the remaining slots.

### Technical Impact

- **Many subscribers per signal**, replacing single-subscriber callback structs.
- **Lock-free slot dispatch**: the class `_mutex` is not acquired while dispatching slots, so emit may run concurrently with other emits and with `connect`/`disconnect`. The prune path (only when an expired `weak_ptr` slot is seen) does take `_mutex` to rebuild the slot list, so `emit()` is not unconditionally mutex-free. (Strict lock-freedom of even the dispatch path depends on the standard-library `shared_ptr` atomics -- see sections 4 and 12.)
- **Re-entrancy safe**: a slot may call `connect`/`disconnect`/`disconnectAll` on the same `Signal` from inside its own callback without deadlock, because the emitter holds no lock and iterates an immutable snapshot.
- **Automatic lifetime management** via `weak_ptr` and `ScopedConnection` eliminates the dangling-callback bug class.
- **Non-copyable, non-movable**, which keeps every `ScopedConnection`'s raw `Signal*` valid for the life of the `Signal`.

---

## 2. System Architecture

### 2.1 Component relationships

```
iora::core  (signal.hpp)
|
`-- Signal<Args...>                         (non-copyable, non-movable)
    |
    |-- Slot (private struct)
    |   |-- function   : std::function<void(const Args&...)>
    |   |-- weakRef    : std::weak_ptr<void>      (type-erased; default for plain slots)
    |   |-- id         : ConnectionId             (uint64_t, monotonic from 1)
    |   `-- hasWeakRef : bool                     (true ONLY for weak_ptr-connected slots)
    |
    |-- SlotList = std::vector<Slot>
    |
    |-- COW machinery
    |   |-- _slots  : std::shared_ptr<SlotList>   (swapped via atomic_load/atomic_store free fns)
    |   |-- _mutex  : std::mutex                  (serializes clone-and-swap in every writer)
    |   `-- cloneSlots() : atomic_load -> make_shared<SlotList>(*current)  (full copy)
    |
    |-- Prune machinery
    |   |-- _needsPrune : std::atomic<bool>       (compare_exchange gate, relaxed)
    |   `-- prune()     : mutex + clone + remove_if(expired) + atomic_store
    |
    |-- Exception handler
    |   `-- _exceptionHandler : std::shared_ptr<ExceptionHandler>  (atomic_load/atomic_store)
    |        where ExceptionHandler = std::function<void(std::exception_ptr)>
    |
    |-- ID generator
    |   `-- _nextId : std::atomic<ConnectionId>   (fetch_add, relaxed; starts at 1)
    |
    `-- ScopedConnection (public nested class)
        |-- _signal : Signal*                     (raw, non-owning pointer)
        |-- _id     : ConnectionId
        `-- movable, not copyable; destructor calls _signal->disconnect(_id)

using ConnectionId = std::uint64_t;             (namespace-scope alias; 0 = invalid/no-op)
```

`Signal` owns the slot list by value (through the `shared_ptr`) and owns the optional exception handler. `ScopedConnection` does **not** own the `Signal` -- it holds a non-owning raw pointer, which is the reason `Signal` is non-movable (section 3.6).

### 2.2 Data flow -- `emit()` (hot path, no class mutex)

```mermaid
sequenceDiagram
  participant Emitter as Emitter thread
  participant Slots as shared_ptr&lt;SlotList&gt; (_slots)
  participant Handler as _exceptionHandler

  Emitter->>Slots: atomic_load (seq_cst) -> snapshot
  Emitter->>Handler: atomic_load (seq_cst) -> exHandler
  loop each slot in *snapshot
    alt hasWeakRef && weakRef.expired()
      Emitter->>Emitter: skip; anyExpired = true
    else
      Emitter->>Emitter: try { slot.function(args...) }
      opt slot threw
        Emitter->>Handler: if exHandler && *exHandler: (*exHandler)(current_exception())
      end
    end
  end
  opt anyExpired
    Emitter->>Emitter: CAS _needsPrune false->true (relaxed)
    alt won the gate
      Emitter->>Slots: prune() [lock _mutex, clone, remove_if expired, atomic_store]
      Emitter->>Emitter: _needsPrune.store(false, relaxed)
    end
  end
```

### 2.3 Data flow -- `connect()` (mutation path, under mutex)

```mermaid
sequenceDiagram
  participant Caller as Caller thread
  participant Mutex as _mutex
  participant Slots as shared_ptr&lt;SlotList&gt; (_slots)

  Caller->>Mutex: lock_guard
  Caller->>Slots: cloneSlots(): atomic_load -> make_shared(*current)
  Caller->>Caller: id = _nextId.fetch_add(1, relaxed)
  Caller->>Caller: newList->push_back(Slot{fn, weakRef, id, hasWeakRef})
  Caller->>Slots: atomic_store(newList) (seq_cst) -- publish
  Caller->>Mutex: unlock
  Note over Slots: a concurrent emit() still iterates the OLD snapshot;<br/>the new slot is visible only on a subsequent emit().
```

### 2.4 Threading model

| Thread | Responsibility |
|---|---|
| **Emitter(s)** (any number) | Call `emit()`, `connectionCount()`, `empty()`. Read-only w.r.t. the slot list (`atomic_load` snapshot). Multiple emitters may run concurrently. The emitter that detects expired slots may also run `prune()` (which takes `_mutex`) after its iteration. |
| **Mutator(s)** (any number) | Call `connect()`, `disconnect()`, `disconnectAll()`. Each takes `_mutex`, clones, and publishes. Serialized against other mutators and against `prune()`. |
| **Any thread** | `setExceptionHandler()` -- `atomic_store` on the handler `shared_ptr`; no class mutex. |
| **Slot callbacks** | Run on the emitter thread, **outside** any class lock. A slot may re-enter the same `Signal` (`connect`/`disconnect`/`emit`) without deadlock; mutations land in a fresh snapshot and are invisible to the in-flight emission. |

---

## 3. Component Deep Dive

### 3.1 The COW slot list (`shared_ptr\<vector\<Slot\>\>` + `atomic_load`/`atomic_store`)

The slot list is a single `std::shared_ptr<SlotList>` member, `_slots`. The core invariant is: **the `shared_ptr` is only ever swapped atomically; the `vector` it points at is never mutated in place.**

- **Readers** (`emit`, `connectionCount`, `empty`) do `std::atomic_load(&_slots)` to obtain a snapshot. The returned `shared_ptr` keeps that vector alive for the whole read even if a writer publishes a replacement meanwhile. No mutex is taken.
- **Writers** (`connect`, `disconnect`, `disconnectAll`, `prune`) hold `_mutex`, call `cloneSlots()` (`atomic_load` then `make_shared<SlotList>(*current)` -- a full copy), mutate the clone, then `std::atomic_store(&_slots, newList)` to publish.

Because **every** writer holds `_mutex` across its clone-and-store, the read-modify-write of `_slots` is fully serialized among writers; there is no lost update. Readers need no mutex because publication is through the atomic `shared_ptr` store.

This yields **snapshot isolation**: an emitter iterating the slot list cannot observe a mutation made by a concurrent `connect`/`disconnect`. The mutation lands in a new vector that becomes visible only on the next `emit`.

> The header declares `std::shared_ptr<SlotList> _slots;` -- a **plain** `shared_ptr`, not `std::atomic<std::shared_ptr<...>>`. All concurrent access goes through the `std::atomic_load` / `std::atomic_store` **free-function overloads** that take a `std::shared_ptr*`. The header passes no memory-order argument, so each call uses the default, `std::memory_order_seq_cst` (section 4).
>
> **Forward-compatibility note.** These `std::atomic_load`/`std::atomic_store(std::shared_ptr*)` free functions are **deprecated in C++20 and removed in C++26**, superseded by `std::atomic<std::shared_ptr<...>>`. This is correct and fully functional for the current C++17 build; a future migration to a C++20/23 standard would replace the free-function overloads with `std::atomic<std::shared_ptr<SlotList>>` (and likewise for `_exceptionHandler`).

### 3.2 Lock-free slot dispatch

`emit()`'s slot-dispatch path performs, in order:

1. `std::atomic_load(&_slots)` -- bumps the control-block refcount; no allocation.
2. `std::atomic_load(&_exceptionHandler)` -- same, for the handler.
3. A range-`for` over `*snapshot` -- iterates the existing vector; no allocation.
4. For each slot, `slot.function(args...)` inside a `try` block -- invokes the pre-built `std::function`; no allocation.

No heap allocation occurs on this path, and the class `_mutex` is not acquired while dispatching slots. The only synchronization is the two `atomic_load`s (plus their refcount adjustments at scope exit). If -- and only if -- expired `weak_ptr` slots were seen, the post-loop `prune()` does take `_mutex` to rebuild the list, so the prune path is not lock-free.

### 3.3 `weak_ptr` auto-disconnect and the `hasWeakRef` flag

`connect(std::weak_ptr<T> instance, void (T::*method)(const Args&...))` stores a type-erased `std::weak_ptr<void>` in the slot, sets `hasWeakRef = true`, and wraps the call in a lambda that re-locks:

```cpp
std::weak_ptr<void> weakRef = instance;
auto fn = [instance, method](const Args&... args)
{
  if (auto sp = instance.lock())
  {
    (sp.get()->*method)(args...);
  }
};
```

During emit the slot is skipped when expired:

```cpp
if (slot.hasWeakRef)
{
  if (slot.weakRef.expired())
  {
    anyExpired = true;
    continue;
  }
}
```

**Why the `hasWeakRef` flag?** A default-constructed `std::weak_ptr<void>` (stored for plain-function slots) reports `expired() == true`. Without the flag, every plain-function slot would be treated as expired and skipped. The boolean distinguishes "connected via `weak_ptr`" from "connected via plain function."

**Why the double check (outer `expired()` plus inner `lock()`)?** The emitter's `expired()` read and the subsequent `slot.function(args...)` call are two separate steps; the object may be destroyed between them. The lambda's `instance.lock()` is the authoritative guard -- if the object is gone by then, the method is simply not invoked. The outer `expired()` is an optimization that avoids calling into a lambda that will do nothing, and that flags the slot for pruning.

### 3.4 `_needsPrune` deduplication gate

After an emit pass sets `anyExpired == true`, the signal wants to physically remove the expired slots. If several threads emit concurrently and all detect expiry, redundant prune passes would each pay a clone + `remove_if` + store. The `_needsPrune` atomic bool deduplicates:

```cpp
bool expected = false;
if (_needsPrune.compare_exchange_strong(expected, true, std::memory_order_relaxed))
{
  // Ensure the gate always clears, even if prune() throws.
  try
  {
    prune();
  }
  catch (...)
  {
    _needsPrune.store(false, std::memory_order_relaxed);
    throw;
  }
  _needsPrune.store(false, std::memory_order_relaxed);
}
```

Only the thread that wins the CAS (flips `false`->`true`) prunes; losers continue. `memory_order_relaxed` is sufficient because `prune()` is itself serialized by `_mutex` and the gate is a pure optimization, not a correctness mechanism. Functionally, expired slots are always skipped at emit time regardless of whether pruning has happened yet; pruning only reclaims the vector slot.

The `try`/`catch` matters for exception safety: `prune()` allocates in `cloneSlots()` -> `make_shared<SlotList>(...)`, which can throw `std::bad_alloc`. Resetting `_needsPrune` to `false` on the throwing path (and re-throwing) guarantees the gate cannot stick at `true`; otherwise a single allocation failure would permanently disable pruning for the life of the `Signal`. The reset-on-throw branch is not injectable in a unit test (allocation failure cannot be forced here), so it is currently unexercised by the test suite -- tracked in backlog `2026-09-10-27`.

### 3.5 `prune()`

`prune()` acquires `_mutex`, clones the current list, `remove_if`s slots that are both `hasWeakRef` and `expired()`, and publishes:

```cpp
void prune()
{
  std::lock_guard lock(_mutex);
  auto newList = cloneSlots();
  newList->erase(
    std::remove_if(newList->begin(), newList->end(),
      [](const Slot& s)
      {
        return s.hasWeakRef && s.weakRef.expired();
      }),
    newList->end());
  std::atomic_store(&_slots, std::move(newList));
}
```

It is safe to call from within `emit()` because `emit()` holds no lock when it calls `prune()` -- the for-loop has already completed. Being serialized with `connect`/`disconnect`/`disconnectAll` (all hold `_mutex`), it cannot race a concurrent mutation.

### 3.6 `ScopedConnection` (RAII auto-disconnect)

`ScopedConnection` holds a raw, non-owning `Signal*` and a `ConnectionId`. Its destructor calls `_signal->disconnect(_id)` when both are valid (non-null signal, non-zero id).

- **Movable, not copyable.** The move constructor transfers ownership and nulls the source; move assignment first disconnects its current connection, then takes the other's. Copy is deleted to prevent a double-disconnect.
- **`release()`** returns the `ConnectionId` and resets to the no-op state **without** disconnecting -- the caller takes manual control.
- **`reset()`** disconnects immediately and resets to no-op.
- **`id()`** returns the held `ConnectionId` (`0` when empty).
- **Default constructor** yields a no-op handle (`_signal == nullptr`, `_id == 0`) whose destruction does nothing.

**Lifetime constraint:** the raw `Signal*` is not checked for validity. If the `Signal` is destroyed while a `ScopedConnection` still references it, the destructor dereferences a dangling pointer. This is the direct reason `Signal` is non-movable (section 3.7).

### 3.7 Non-copyable, non-movable `Signal`

All four copy/move special members are `= delete`. `ScopedConnection` stores a raw `Signal*`; moving a `Signal` would leave every outstanding `ScopedConnection` pointing at the old address. Deleting move makes the address stable for the `Signal`'s lifetime. The trade-off is that a `Signal` cannot live in a container that relocates elements (e.g. `std::vector` growth) -- store it behind `std::unique_ptr<Signal<...>>` or in a node-stable container instead.

### 3.8 Exception handler via atomic `shared_ptr`

The handler is `std::shared_ptr<ExceptionHandler>` where `ExceptionHandler = std::function<void(std::exception_ptr)>`. It is accessed with the same atomic free-function pattern as `_slots`:

- **`setExceptionHandler(fn)`** wraps `fn` in a new `shared_ptr` and publishes with `std::atomic_store` -- no class mutex.
- **`emit()`** does `std::atomic_load(&_exceptionHandler)` once at the top, so the handler is consistent for the whole emission pass; a concurrent `setExceptionHandler` takes effect only on the next emit.

Wrapping in `shared_ptr` is required because `std::function` is not trivially copyable and cannot be stored directly in a `std::atomic`. When no handler is set, `_exceptionHandler` is a default-constructed (null) `shared_ptr`; `emit()` guards with `if (exHandler && *exHandler)`, so a thrown exception is silently swallowed and the next slot still fires.

---

## 4. COW & Memory Ordering Model

`Signal` coordinates emitters and mutators entirely through a `std::mutex` (writers only) and the atomic operations on three members: the `shared_ptr` `_slots`, the `shared_ptr` `_exceptionHandler`, and the two scalar atomics `_nextId` and `_needsPrune`. The table records the **actual** ordering at each site in the header.

| Site | Member | Operation | Ordering (actual) | Purpose |
|---|---|---|---|---|
| `emit`, `connectionCount`, `empty`, `cloneSlots` | `_slots` | `std::atomic_load(&_slots)` | **`seq_cst`** (default; no arg) | Take an immutable snapshot of the slot list. |
| `connect`, `disconnect`, `disconnectAll`, `prune` | `_slots` | `std::atomic_store(&_slots, ...)` | **`seq_cst`** (default; no arg) | Publish the mutated clone. Done under `_mutex`. |
| `emit` | `_exceptionHandler` | `std::atomic_load` | **`seq_cst`** (default) | One consistent handler for the whole pass. |
| `setExceptionHandler` | `_exceptionHandler` | `std::atomic_store` | **`seq_cst`** (default) | Publish a new handler; no class mutex. |
| `connect` (both overloads) | `_nextId` | `fetch_add(1, relaxed)` | `relaxed` | Unique, monotonically increasing ids. Order vs other ops is irrelevant. |
| `emit` | `_needsPrune` | `compare_exchange_strong(expected, true, relaxed)` | `relaxed` | Dedup gate; correctness comes from `_mutex` inside `prune()`. |
| `emit` | `_needsPrune` | `store(false, relaxed)` | `relaxed` | Release the gate after pruning. |

**Publication correctness.** A mutator builds the new vector fully, then does a `seq_cst` `atomic_store` of the `shared_ptr`. An emitter's `seq_cst` `atomic_load` that observes the new pointer also observes every write that constructed the new vector (the `shared_ptr` atomic store/load pair establishes the happens-before edge). Emitters never read a half-built slot list.

**Why `seq_cst` here and not acquire/release.** The header uses the no-argument `std::atomic_load`/`std::atomic_store` free-function overloads, which default to `memory_order_seq_cst`. This is stronger (and potentially slightly costlier on weakly-ordered ARM/POWER) than the acquire/release pair that would suffice for simple publication, but it is unambiguously correct. The scalar atomics that are pure optimizations (`_nextId`, `_needsPrune`) deliberately use `relaxed`.

**Lock-freedom caveat.** "Lock-free slot dispatch" means the class `_mutex` is not acquired while dispatching slots (the prune path does take it). Even so, it does **not** guarantee wait-freedom or lock-freedom at the hardware level: the `std::atomic_load`/`std::atomic_store` free-function overloads on `shared_ptr` are permitted to use an internal lock, and on common implementations (libstdc++) they use a pool of spinlocks keyed on the object address. Query `std::atomic_is_lock_free` on the target platform if strict lock-freedom matters (section 12).

**Re-entrancy under the model.** Because `emit()` holds no lock while invoking a slot, a slot that calls `connect`/`disconnect`/`disconnectAll` simply performs a normal mutator operation (takes `_mutex`, clones, publishes) and returns. The in-flight emission keeps iterating its own older snapshot, so the mutation neither deadlocks nor changes the set of slots being called in that pass.

---

## 5. Usage Guide

All examples compile against the real API (`#include <iora/core/signal.hpp>`, namespace `iora::core`).

### 5.1 Basic signal/slot

```cpp
#include <iora/core/signal.hpp>
#include <string>

using namespace iora::core;

Signal<int, std::string> onMessage;

ConnectionId id = onMessage.connect(
  [](const int& code, const std::string& text)
  {
    // log(std::to_string(code) + ": " + text);
  });

onMessage.emit(200, "OK");        // fires the lambda
onMessage.disconnect(id);         // manual disconnect
onMessage.emit(404, "Not Found"); // lambda does NOT fire
```

### 5.2 Zero-argument signal

```cpp
#include <iora/core/signal.hpp>

using namespace iora::core;

Signal<> onShutdown;
onShutdown.connect([]() { /* cleanup(); */ });
onShutdown.emit();
```

### 5.3 `ScopedConnection` (RAII)

```cpp
#include <iora/core/signal.hpp>

using namespace iora::core;

Signal<int> onUpdate;

{
  ConnectionId id = onUpdate.connect([](const int& v) { /* process(v); */ });
  Signal<int>::ScopedConnection sc(&onUpdate, id);
  onUpdate.emit(42); // fires
} // sc destroyed -> auto-disconnect

onUpdate.emit(99); // nothing fires
```

### 5.4 `weak_ptr` auto-disconnect (member function)

```cpp
#include <iora/core/signal.hpp>
#include <memory>
#include <string>

using namespace iora::core;

class Observer
{
public:
  void onNotify(const std::string& msg) { /* log(msg); */ }
};

Signal<std::string> onEvent;

auto observer = std::make_shared<Observer>();
onEvent.connect(std::weak_ptr<Observer>(observer), &Observer::onNotify);

onEvent.emit("hello"); // fires Observer::onNotify

observer.reset();      // destroy the Observer

onEvent.emit("world"); // slot skipped (weak_ptr expired), then pruned
```

### 5.5 Per-slot exception isolation

```cpp
#include <iora/core/signal.hpp>
#include <exception>
#include <stdexcept>
#include <string>

using namespace iora::core;

Signal<int> onData;

onData.setExceptionHandler(
  [](std::exception_ptr ep)
  {
    try
    {
      std::rethrow_exception(ep);
    }
    catch (const std::exception& e)
    {
      // log(std::string("slot error: ") + e.what());
    }
  });

onData.connect([](const int&) { throw std::runtime_error("oops"); });
onData.connect([](const int& v) { /* log("second slot: " + std::to_string(v)); */ });

onData.emit(42);
// First slot throws -> handler is invoked with the exception_ptr.
// Second slot still fires. Without a handler, the throw is silently swallowed.
```

### 5.6 Anti-patterns

- **Do NOT let a `ScopedConnection` outlive its `Signal`.** It holds a raw `Signal*` with no validity check; if the `Signal` dies first, the `ScopedConnection` destructor dereferences a dangling pointer.
- **Do NOT store a `Signal` in a relocating container.** `Signal` is non-movable; `std::vector<Signal<...>>` will not compile on growth. Use `std::unique_ptr<Signal<...>>`.
- **Do NOT rely on `connectionCount()` for a live-slot count.** It returns the snapshot size, which includes expired-but-unpruned `weak_ptr` slots; pruning is lazy (after emit).
- **Do NOT assume a slot connected during `emit` fires in that same emission.** The emitter iterates a snapshot taken before the mutation; the new slot appears on the next `emit`.
- **Do NOT assume a slot disconnected during `emit` will be skipped in that same emission.** Same snapshot semantics -- the old snapshot still contains it.
- **Do NOT use `Signal` across a DLL/plugin unload boundary while slots still point into the unloaded module.** The `std::function` targets would be invalidated; disconnect first.

---

## 6. Concurrency Semantics & Hazards

The snapshot model makes `emit()` cheap and re-entrant, but that same model has observable consequences a caller must understand -- they are semantics, not bugs.

**Snapshot isolation is per-emission, not per-call.** `emit()` binds its slot set and its exception handler once, at the top. Every mutation (`connect`, `disconnect`, `disconnectAll`, `setExceptionHandler`) performed during that emission -- by a slot or by another thread -- is invisible to it and takes effect only on a subsequent `emit`. A slot that disconnects itself still completes the current call; it just will not be called again.

**`connectionCount()` / `empty()` are snapshot sizes, not live counts.** They return `*snapshot.size()` and therefore include `weak_ptr` slots whose target has already expired but which have not yet been pruned. The test `Signal: connectionCount includes expired-but-unpruned weak_ptr` confirms: after the target is `reset()`, `connectionCount()` still returns `1` until the next `emit()` triggers `prune()`, after which it returns `0`. Do not use these for synchronization or precise accounting.

**Pruning is lazy and deduplicated.** Expired slots are physically removed only when an `emit()` both observes the expiry and wins the `_needsPrune` CAS. If a different thread currently holds the gate, the observing emitter skips pruning this pass; the expired slots are still functionally skipped and will be reclaimed by a later `emit()`. A `Signal` that stops emitting will never reclaim expired slots.

**Slot-ordering across threads is mutex-arbitration order.** Within one thread, `connect` order is preserved in the vector (and thus in emit order). Across threads, the final order depends on which thread won `_mutex` first; there is no global ordering guarantee.

**Emit runs callbacks outside every class lock.** This is what permits re-entrancy, but it also means slot code must itself be thread-safe if the signal is emitted from multiple threads concurrently -- `Signal` does not serialize slot bodies against each other.

---

## 7. Call Flow / Sequence Reference

### 7.1 `emit()` -- all slots live, no expiry

| Step | Actor | Action | Sync |
|---|---|---|---|
| 1 | Emitter | `snapshot = std::atomic_load(&_slots)` | seq_cst load |
| 2 | Emitter | `exHandler = std::atomic_load(&_exceptionHandler)` | seq_cst load |
| 3 | Emitter | For each `slot`: `hasWeakRef` false -> invoke | plain read |
| 4 | Emitter | `try { slot.function(args...); }` | no lock held |
| 5 | Emitter | `anyExpired` stays false -> skip prune block | -- |

### 7.2 `emit()` -- a slot throws

| Step | Actor | Action |
|---|---|---|
| 1-3 | Emitter | Load snapshot + handler; begin iterating. |
| 4 | Emitter | `slot.function(args...)` throws; `catch (...)` runs. |
| 5 | Emitter | `if (exHandler && *exHandler) (*exHandler)(std::current_exception());` else swallow. |
| 6 | Emitter | Continue loop -- the next slot still fires. |

### 7.3 `emit()` -- a `weak_ptr` slot has expired (prune path)

| Step | Actor | Action |
|---|---|---|
| 1-2 | Emitter | Load snapshot + handler. |
| 3 | Emitter | Slot has `hasWeakRef == true` and `weakRef.expired() == true` -> skip; set `anyExpired = true`. |
| 4 | Emitter | After loop, `compare_exchange_strong(expected=false, true, relaxed)`. |
| 5a | Emitter (won) | `prune()`: lock `_mutex`; clone; `remove_if` expired; `atomic_store`; unlock. |
| 5b | Emitter (won) | `_needsPrune.store(false, relaxed)`. |
| 5c | Emitter (lost) | Skip prune; a later `emit()` reclaims the slot. |

### 7.4 `connect()` -- add a slot (mutation path)

| Step | Actor | Action | Sync |
|---|---|---|---|
| 1 | Caller | `std::lock_guard lock(_mutex)` | acquire `_mutex` |
| 2 | Caller | `newList = cloneSlots()` (`atomic_load` + `make_shared` copy) | seq_cst load |
| 3 | Caller | `id = _nextId.fetch_add(1, relaxed)` | relaxed |
| 4 | Caller | `newList->push_back(Slot{...})` | plain write on clone |
| 5 | Caller | `std::atomic_store(&_slots, std::move(newList))` | seq_cst store (publish) |
| 6 | Caller | unlock; return `id` | release `_mutex` |

### 7.5 `disconnect(id)` -- remove one slot

| Step | Actor | Action |
|---|---|---|
| 1 | Caller | Lock `_mutex`. |
| 2 | Caller | `newList = cloneSlots()`. |
| 3 | Caller | `remove_if(s.id == id)` + `erase` on the clone (no-op if absent). |
| 4 | Caller | `atomic_store(&_slots, newList)`; unlock. |

### 7.6 `~ScopedConnection()` -- RAII disconnect

| Step | Actor | Action |
|---|---|---|
| 1 | Handle | If `_signal != nullptr && _id != 0` -> `_signal->disconnect(_id)` (flows through 7.5). |
| 2 | Handle | Otherwise no-op (default/moved-from/released/reset handle). |

---

## 8. Thread Safety Model

| Operation | Called by | Synchronization | Notes |
|---|---|---|---|
| `emit(const Args&...)` | Any thread(s) | No class mutex; two `seq_cst` `atomic_load`s on `shared_ptr`s | Multiple emitters may run concurrently. Slots run outside all class locks. May call `prune()` (takes `_mutex`) after the loop. |
| `connect(fn)` / `connect(weak_ptr, method)` | Any thread | `_mutex` + clone + `seq_cst` `atomic_store`; `_nextId.fetch_add` relaxed | Serialized with other mutators and `prune()`. |
| `disconnect(id)` | Any thread | `_mutex` + clone + `atomic_store` | No-op if id absent. |
| `disconnectAll()` | Any thread | `_mutex` + `atomic_store` of a fresh empty `SlotList` | Cheaper than clone-and-clear. |
| `connectionCount()` / `empty()` | Any thread | `seq_cst` `atomic_load` snapshot | Snapshot size; includes expired-but-unpruned slots (section 6). |
| `setExceptionHandler(h)` | Any thread | `seq_cst` `atomic_store` on `shared_ptr`; no class mutex | Effective on the next `emit`. |
| `prune()` (private) | Emitter that won the gate | `_mutex` + clone + `remove_if` + `atomic_store` | Triggered post-emit when expiry seen. |
| `_needsPrune` gate | Emitter | `compare_exchange_strong` / `store`, both `relaxed` | Dedup only; not a correctness barrier. |
| `_nextId` generation | `connect` | `fetch_add`, `relaxed` | Unique monotonic ids; uniqueness, not ordering, is required. |

**Lock inventory.** One `std::mutex` (`_mutex`), held only by the four writer paths (`connect`, `disconnect`, `disconnectAll`, `prune`). It is **never** held during slot invocation, which is what makes re-entrant `connect`/`disconnect` from a slot deadlock-free. There is a single lock, so there is no lock-ordering concern.

**Callback discipline.** The implementation follows copy-then-iterate: `emit()` holds a `shared_ptr` snapshot of the slot vector and iterates that immutable copy, so a slot disconnecting itself or others cannot invalidate the iteration. No user callback is ever invoked while `_mutex` is held (copy-then-invoke).

**Safe publication.** Writers fully construct the replacement vector before the `seq_cst` `atomic_store`; emitters that observe the new pointer observe the fully constructed vector. No torn or partial reads of the slot list are possible.

---

## 9. Configuration Reference

`Signal` has no runtime or environment configuration. Its only "configuration" is the compile-time template parameter list and the run-time-settable exception handler.

### 9.1 Template parameters

| Parameter | Kind | Meaning |
|---|---|---|
| `Args...` | type pack (zero or more) | Payload types. Slots receive `const Args&...`; `emit` takes `const Args&...`. Use `Signal<>` for a zero-argument signal. |

### 9.2 `ConnectionId`

| Property | Value |
|---|---|
| Type | `std::uint64_t` (alias `iora::core::ConnectionId`) |
| First value | `1` |
| Invalid / no-op sentinel | `0` |
| Generation | `_nextId.fetch_add(1, memory_order_relaxed)` per `Signal` instance |

### 9.3 Exception handler

| Property | Value |
|---|---|
| Type | `std::function<void(std::exception_ptr)>` (stored as `std::shared_ptr<...>`) |
| Default | Null -- exceptions from slots are silently swallowed |
| Set via | `setExceptionHandler(handler)` (thread-safe; effective next `emit`) |
| Scope | One snapshot per emission pass |

### 9.4 `Slot` (private record -- reference only)

| Field | Type | Meaning |
|---|---|---|
| `function` | `std::function<void(const Args&...)>` | Callable invoked on emit. |
| `weakRef` | `std::weak_ptr<void>` | Type-erased lifetime ref; default-constructed for plain slots. |
| `id` | `ConnectionId` | Disconnect key. |
| `hasWeakRef` | `bool` | `true` only for `weak_ptr`-connected slots; distinguishes them from plain slots (whose default `weak_ptr` reports `expired()`). |

---

## 10. API Reference

```cpp
namespace iora
{
namespace core
{

using ConnectionId = std::uint64_t;

template <typename... Args>
class Signal
{
public:
  class ScopedConnection;

  Signal();
  ~Signal() = default;

  // Non-copyable, non-movable.
  Signal(const Signal&) = delete;
  Signal& operator=(const Signal&) = delete;
  Signal(Signal&&) = delete;
  Signal& operator=(Signal&&) = delete;

  // Connect a callable slot. Returns a ConnectionId for disconnect.
  ConnectionId connect(std::function<void(const Args&...)> fn);

  // Connect a member function via weak_ptr. Auto-disconnects when the
  // target object is destroyed.
  template <typename T>
  ConnectionId connect(std::weak_ptr<T> instance,
                       void (T::*method)(const Args&...));

  // Disconnect a slot by ConnectionId. No-op if not found.
  void disconnect(ConnectionId id);

  // Disconnect all slots.
  void disconnectAll();

  // Number of connected slots (includes expired-but-unpruned weak_ptr slots).
  std::size_t connectionCount() const;

  // True if no slots connected.
  bool empty() const;

  // Emit the signal to all connected slots. Slot dispatch is lock-free (COW
  // snapshot); per-slot try/catch. If expired weak_ptr slots are seen, one
  // emitter then runs prune(), which acquires _mutex (prune path not lock-free).
  void emit(const Args&... args);

  // Set an exception handler for slot invocation failures. Thread-safe.
  // Default: exceptions are silently swallowed.
  void setExceptionHandler(std::function<void(std::exception_ptr)> handler);
};

template <typename... Args>
class Signal<Args...>::ScopedConnection
{
public:
  ScopedConnection() noexcept;                                 // no-op handle
  ScopedConnection(Signal* signal, ConnectionId id) noexcept;  // owning handle
  ~ScopedConnection();                                         // disconnect if owning

  // Movable.
  ScopedConnection(ScopedConnection&& other) noexcept;
  ScopedConnection& operator=(ScopedConnection&& other) noexcept;

  // Not copyable.
  ScopedConnection(const ScopedConnection&) = delete;
  ScopedConnection& operator=(const ScopedConnection&) = delete;

  // Release ownership without disconnecting. Caller takes manual control.
  ConnectionId release() noexcept;

  // Disconnect and reset to no-op state.
  void reset();

  // The held connection id (0 when empty).
  ConnectionId id() const noexcept;
};

} // namespace core
} // namespace iora
```

> Qualifier notes (verbatim from the header): the `Signal` query and mutation methods are **not** `noexcept`; `emit` is not `noexcept` (a slot throw is caught, but `prune()` may allocate). For `ScopedConnection`: the constructors, the move constructor, move-assignment, `release()`, and `id()` are all declared `noexcept`, and `~ScopedConnection` is **implicitly `noexcept`** (a C++ destructor is `noexcept` unless declared otherwise). `reset()` is the **only** member that is not `noexcept`. Note that `~ScopedConnection` and move-assignment both call `disconnect()`, which allocates in `cloneSlots()` and can throw `std::bad_alloc`; because those two paths are `noexcept`, a genuine OOM there calls `std::terminate()` -- see section 12.

---

## 11. Design Decisions

| ID | Decision | Rationale |
|---|---|---|
| D-1 | COW slot list (`shared_ptr<vector<Slot>>`). | Emit takes no allocation and no class mutex; readers and writers never touch the same vector instance. |
| D-2 | Access the `shared_ptr` through `std::atomic_load`/`atomic_store` free functions (default `seq_cst`). | Lock-free *publication* of the slot list and handler without holding `_mutex` on the emit path; `seq_cst` is the unambiguously-correct default of the no-arg overload. |
| D-3 | `const Args&...` slot signature. | Emitting to N slots passes the same const references -- no per-slot copy of the payload. |
| D-4 | `hasWeakRef` bool on `Slot`. | A default-constructed `weak_ptr<void>` reports `expired()`; the flag prevents plain-function slots from being wrongly skipped as expired. |
| D-5 | Double lifetime check for `weak_ptr` slots (`expired()` at emit, `lock()` in the lambda). | The lambda's `lock()` is authoritative against the destroy-between-check-and-call race; the outer `expired()` is an optimization and a prune trigger. |
| D-6 | `_needsPrune` CAS gate (relaxed). | Under concurrent emits that all see expiry, only one thread pays the prune; correctness is carried by `_mutex` inside `prune()`, so the gate can be relaxed. |
| D-7 | Prune after the emit loop, never during. | Pruning needs `_mutex`; taking it mid-iteration could deadlock with a slot that calls `connect`/`disconnect`. Deferring keeps emit lock-free and re-entrant. |
| D-8 | Exception handler as atomic `shared_ptr<function<...>>`. | `std::function` is not trivially copyable and cannot live in `std::atomic`; the `shared_ptr` box gives atomic publish/read from the emit path. |
| D-9 | Per-slot `try/catch` in emit. | One failing slot must not abort the fan-out; the exception goes to the handler (or is swallowed) and the remaining slots still fire. |
| D-10 | Non-copyable, non-movable `Signal`. | `ScopedConnection` holds a raw `Signal*`; moving the `Signal` would dangle every outstanding handle. |
| D-11 | `ScopedConnection` uses a raw `Signal*`. | Simplest correct design; a `weak_ptr`-to-`Signal` would add a control block and indirection for a constraint ("do not outlive the `Signal`") that is easy to honor. |
| D-12 | Monotonic `ConnectionId` via `fetch_add(relaxed)`, starting at 1. | Ids need uniqueness, not ordering; `0` is reserved as the invalid/no-op sentinel. |
| D-13 | `disconnectAll()` publishes a fresh empty vector. | `make_shared<SlotList>()` is cheaper than clone-then-clear of a possibly large list. |

---

## 12. Known Limitations

- **RESOLVED -- `#include <algorithm>` for `std::remove_if`.** `disconnect()` (`signal.hpp:93-102`) and `prune()` (`signal.hpp:287-299`) call `std::remove_if`, which is declared in `<algorithm>`. The header now includes `<algorithm>` directly (`signal.hpp:10`) instead of relying on transitive inclusion via `<vector>`/`<functional>`, so the dependency is explicit and portable across conforming standard libraries. (Previously flagged as a candidate defect; fixed this session.)
- **RESOLVED -- `_needsPrune` reset is now exception-safe.** In `emit()` the winner sets `_needsPrune = true`, calls `prune()`, then `store(false)`. `prune()` allocates via `cloneSlots()` -> `make_shared<SlotList>(...)`, which can throw `std::bad_alloc`. The emit prune block (`signal.hpp:160-181`) now wraps `prune()` in a `try`/`catch` that resets `_needsPrune` to `false` and re-throws on the throwing path (in addition to the normal-path `store(false)`). This guarantees the gate cannot stick at `true` after an allocation failure, so pruning is never permanently disabled. The reset-on-throw branch is **untested** -- allocation failure is not injectable at this site, so the path is currently unexercised by the suite; tracked in backlog `2026-09-10-27`. (Previously flagged as a candidate defect; fixed this session.)
- **Teardown can `std::terminate()` under genuine OOM (known limitation).** `~ScopedConnection` (`signal.hpp:207-213`, implicitly `noexcept`) and `ScopedConnection::operator=(ScopedConnection&&)` (`signal.hpp:223`, declared `noexcept`) both call `disconnect()`, which allocates in `cloneSlots()` -> `make_shared<SlotList>(...)` and can throw `std::bad_alloc`. Because both paths are `noexcept`, a `bad_alloc` escaping `disconnect()` there calls `std::terminate()`. A swallow-based fix was attempted and **reverted**: swallowing converted the terminate into a silent leave-connected state, i.e. a latent use-after-free once the slot target is destroyed -- strictly worse than a deterministic abort. The trigger is OOM-only; on mainstream targets it does not arise in practice. Tracked in backlog `2026-09-10-27`.
- **A slot must not destroy its own `Signal` during `emit()` (use-after-free).** The `shared_ptr` snapshot that `emit()` holds keeps the `SlotList` *vector* alive for the duration of the pass, but it does **not** keep the `Signal` *object* alive. If a slot (directly or transitively) deletes the `Signal` being emitted, the remainder of `emit()` -- the loop over `*snapshot`, the `anyExpired` prune block, and every member access -- runs against a destroyed object, which is undefined behavior. Ensure a `Signal` outlives any emission in progress; never free it from inside one of its own slots.
- **Slot dispatch is mutex-free, not guaranteed lock-free.** The class `_mutex` is not taken while `emit()` dispatches slots (the prune path does take it), but the `std::atomic_load`/`atomic_store` free-function overloads on `shared_ptr` are not guaranteed lock-free and use an internal spinlock pool on libstdc++. On platforms where `std::atomic_is_lock_free` is false for these operations, emit briefly contends that pool. On mainstream 64-bit targets the contention is negligible.
- **`connectionCount()` / `empty()` include expired-but-unpruned `weak_ptr` slots.** They return the snapshot size; pruning is lazy (after emit). Between emits (or on a `Signal` that has stopped emitting) expired slots are not reclaimed. Do not use for precise live-slot accounting.
- **A slot connected during `emit` does not fire in that emission; a slot disconnected during `emit` may still fire in it.** Snapshot isolation: the emitter iterates the pre-mutation snapshot; mutations apply on the next `emit`.
- **`ScopedConnection` holds a raw `Signal*` with no validity check.** If the `Signal` is destroyed first, the `ScopedConnection` destructor dereferences a dangling pointer. This is also why `Signal` is non-movable.
- **`Signal` is non-copyable and non-movable.** It cannot be stored in a relocating container (e.g. `std::vector<Signal<...>>`). Use `std::unique_ptr<Signal<...>>` or a node-stable container.
- **Exception handler is fixed per emission pass.** A `setExceptionHandler` call during an in-flight `emit` takes effect only on the next `emit`.
- **No cross-thread slot-ordering guarantee.** `connect` order is preserved within a single thread; across threads the vector order follows `_mutex` arbitration. There is no global emission-order guarantee.
- **No built-in signal chaining, filtering, or return-value aggregation.** Slots return `void` and cannot veto or transform the emission; forwarding one `Signal` to another must be done in user code (e.g. a forwarding lambda).
- **No overload to connect a member function by raw pointer or `shared_ptr`.** Member-function connection is only through the `std::weak_ptr<T>` overload; a plain-object member slot must be wrapped in a lambda by the caller.
