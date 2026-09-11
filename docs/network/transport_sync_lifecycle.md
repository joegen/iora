# Iora Transport Sync Lifecycle & Teardown Safety -- Architecture & Programmer's Guide

[Back to index](../../README.md)

**Parent guide: [transport.md](transport.md)** -- the Transport facade this deep-dive expands.
**Sibling deep-dive: [transport_dns_resolution.md](transport_dns_resolution.md)** -- the off-thread name-resolution path that precedes a connect.

This guide is an *aspect deep-dive*. It covers exactly one facet of `iora::network::Transport`: the blocking synchronous-I/O facade -- `connectSync`, `receiveSync`, `sendSync`, and the `setReadMode(Sync)` flush -- and the **teardown handshake** that keeps them safe. It expands what the hub guide's sync-operations section introduces at facade altitude; it does **not** re-document the whole Transport facade, the async data path, DNS resolution, or the engine internals.

| | |
|---|---|
| **Version** | 1.3 |
| **Date** | 2026-09-11 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/network/transport_impl.hpp` (part of the split transport header set -- the definitions TU; include in exactly one translation unit) |
| **Companion headers** | `include/iora/network/transport.hpp` (public `Transport` / `ITransport` API), `include/iora/network/transport_types.hpp` (`TransportConfig`, `ReadMode`, `TransportError`, the sync-timeout sentinels), `include/iora/network/detail/engine_base.hpp` / `detail/tcp_engine.hpp` / `detail/udp_engine.hpp` (the single-I/O-thread engine) |
| **Namespace** | `iora::network` |
| **Dependencies** | `iora::core::Result<T, E>`, `iora::core::BufferView`, `std::condition_variable`, `std::mutex`, `std::unordered_map`, `std::unordered_set`, `std::shared_ptr`, `std::unique_ptr` |

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-06-11 | Initial guide for the synchronous receive / connect / teardown buffer-lifecycle hardening: 3-counter teardown handshake, entry fences, GC gate, overflow surfacing, drain-before-close, dead-branch removal. |
| 1.1 | 2026-06-12 | **S-3 shared-ownership:** `operator=` / move ctor deleted (`~Transport` is the sole `_impl`-destroying exit); documented the I/O-thread deferred-self-destruct; the I/O-thread self-destruction UAF (formerly a known limitation) is RESOLVED and the C-1 concurrent case excluded structurally; usage example uses `std::shared_ptr`. |
| 1.2 | 2026-09-11 | **Migration to `docs/network/`.** Relocated into the consolidated `docs/network/` wiki as an aspect deep-dive under the `transport.md` hub; restructured to the guide template; corrected the API surface (TLS-options `connectSync` overload, `isOnIoThread()`, test-only `withEngine`). |
| 1.3 | 2026-09-11 | **Re-synced to the landed sync-op completion / read-gating change (`c7e7d3d`).** `sendSync` now BLOCKS until the engine signals send completion (new `SyncSendOp` / `pendingSends` / `nextSendOpId` / `activeSends`) -- the teardown gate is now **four** counters. Added the **concurrent parked-sync-op cap** (`config.maxPendingSyncOps`, `pendingSyncOps`, `syncCapReached()`, `PendingSyncGuard`) and its `TransportError::TooManyPendingSyncOps`, checked by `connectSync` / `receiveSync` / `sendSync`. Added the **timeout sentinels** (`kUseConfigSyncTimeout` = -1 ms, `kFallbackSyncTimeout` = 30000 ms) and `resolveSyncTimeout()`; primary sync ops now default to the sentinel (config-driven), the `*Cancellable` variants keep the literal fallback and clamp a negative caller value. **UDP `connectSync` now PARKS until `onConnect`** exactly like TCP -- the former UDP short-circuit was removed (F-1). Documented the **spurious-`onClose` suppression** (`syncOwnedSuppress`). `receiveSyncCancellable` is now a `do`/`while` (guarantees one poll at `timeout==0`). Documented the engine's **CF-H1 `sessionSendable` send validation** and its interaction with `sendSync` and connect-then-send ordering. `ReadMode::Disabled` now removes the fd from `EPOLLIN` on TCP (C5) -- the old "still incurs `recv()`" limitation is downgraded to the UDP-only fallback. Line-number citations replaced by symbol references. |

---

## 1. Executive Summary

### Problem

`Transport` offers a **synchronous** I/O facade -- `connectSync`, `receiveSync`, `sendSync`, and `setReadMode(Sync)` -- used by `HttpClient` (and any caller that wants blocking request/response semantics) on a worker thread, layered over the asynchronous, single-I/O-thread engine (`TcpEngine` / `UdpEngine`). The synchronous facade parks the caller on a condition variable while the I/O thread feeds it. This straddling of two threads created a family of buffer-lifecycle and teardown hazards:

- A parked `receiveSync` waiter could have its receive-buffer **map entry GC'd** by an *unrelated* session's close, dropping the not-yet-delivered tail of a response.
- Destroying a `Transport` while a `receiveSync`, `connectSync`, `sendSync`, or `setReadMode` flush was in flight **freed `_impl` (the mutex and maps) out from under the parked caller** -- a use-after-free, because `~Transport` joined only the I/O thread, never the external caller thread.
- A sync-buffer overflow **silently dropped data**, surfacing only as a caller-side timeout with no diagnostic.
- A spurious wake returned `ReceiveResult::ok(0)` ("retry") with an undocumented contract.
- `sendSync` **ignored its timeout** and returned the instant the bytes were enqueued -- it was not a true blocking send-completion.
- The sync ops **hardcoded a 30 s timeout** and ignored the configured (SIP-tuned) default; an unbounded number of concurrent parked sync ops could pile up with no back-pressure.
- A `connectSync` that timed out and closed its own session could still fire the **global `onClose`** for a sid the user never received.

### Solution

- **Four-counter teardown handshake** (`activeReceives` / `activeConnects` / `activeFlushes` / `activeSends`) -- `~Transport` blocks until every external thread parked in `receiveSync`, `connectSync`, `sendSync`, or mid-`setReadMode`-flush has exited, before `_impl` is destroyed (`performTeardown`, `teardownWaitOut`).
- **Blocking `sendSync`** -- issues the send via `sendAsync` and parks on a `SyncSendOp` CV until the engine's completion callback fires (or the timeout elapses), so the returned `SendResult` reflects engine acceptance, honoring the timeout.
- **Concurrent parked-sync-op cap** -- `config.maxPendingSyncOps` (`0` = unlimited) bounds how many `connectSync` / `receiveSync` / `sendSync` calls may be parked at once; the cap check (`syncCapReached()`) rejects the excess with `TransportError::TooManyPendingSyncOps`; a `PendingSyncGuard` RAII object maintains the `pendingSyncOps` counter.
- **Config-driven timeouts** -- the primary sync ops default their `timeout` argument to the `kUseConfigSyncTimeout` sentinel, which `resolveSyncTimeout()` maps to `config.defaultSyncTimeout` (floored to `kFallbackSyncTimeout` = 30 s if misconfigured non-positive). An explicit non-negative value (including `0` = non-blocking) is respected as-is.
- **Entry fence** (`shuttingDown`) -- once teardown begins, fresh sync calls reject at entry under the lock, so the handshake gate cannot be re-armed.
- **GC gate** -- the tombstone GC excludes any buffer with a parked waiter (`waiters > 0`) or in-progress flush (`flushing`), closing the orphan race.
- **Spurious-`onClose` suppression** -- a timed-out `connectSync` records its sid in `syncOwnedSuppress` before closing it, so `onClose` suppresses the global callback for a sid the user never received, even when a racing `onConnect` already consumed the `pendingConnects` entry.
- **Overflow surfaced** as a distinct `TransportError::BufferOverflow`; teardown surfaced as `TransportError::ShuttingDown`.
- **Drain-before-close preserved on teardown** -- the normal stop path lets the engine's `onClose` deliver and drain a parked waiter's tail before reporting EOF.
- **Shared-ownership model** -- `Transport` is `std::shared_ptr`-only (move + copy deleted; tag-gated ctors), so `~Transport` is the sole `_impl`-destroying exit, and the I/O-thread self-destruct case is handled by a deferred delete on the detached engine thread's post-`loop()` epilogue.

### Technical Impact

- Eliminates the parked-waiter use-after-free on destruction (ASan-verified; a negative control built with `IORA_DISABLE_SELFDESTRUCT_DEFERRAL` reproduces the heap-use-after-free).
- `receiveSync` returns only on data / `Timeout` / `PeerClosed` / `BufferOverflow` / `ShuttingDown` -- no spurious `ok(0)`, and the timeout is a true wall-clock deadline.
- `sendSync` is a true blocking send-completion bounded by the timeout; a masked send failure to an unknown/closed session is surfaced (CF-H1) instead of reported as false success.
- SIP presets can tune the sync-op timeout (Timer B/F = 32000 ms TCP, T1 = 500 ms UDP) via `defaultSyncTimeout` without touching call sites.
- Bounded, leak-free buffer lifecycle: tombstone GC reclaims only buffers with no live owner; the pending-sync-op cap bounds parked-op fan-out.

---

## 2. System Architecture

### 2.1 Component relationships

```
Transport (public facade, shared-ownership only: std::shared_ptr<Transport>)
|
|-- std::unique_ptr<Transport::Impl>  _impl        // freed by ~Transport (sole _impl-destroying exit)
    |-- std::unique_ptr<EngineBase>   engine        // TcpEngine / UdpEngine: the single I/O thread
    |-- std::mutex                    syncMutex      // Lock order 2: guards ALL sync + teardown state
    |-- unordered_map<SessionId, shared_ptr<SyncConnectOp>>     pendingConnects
    |-- unordered_set<SessionId>                                 syncOwnedSuppress // timed-out connectSync sids
    |-- unordered_map<uint64_t,  shared_ptr<SyncSendOp>>        pendingSends      // keyed by nextSendOpId
    |-- unordered_map<SessionId, ReadMode>                       readModes
    |-- unordered_map<SessionId, shared_ptr<SyncReceiveBuffer>>  receiveBuffers
    |     SyncReceiveBuffer { data, cv, hasData, closed, waiters, flushing, overflow }
    |     SyncConnectOp     { cv, done, result }
    |     SyncSendOp        { cv, done, result }
    |-- bool                          shuttingDown   // entry fence + teardown wake signal
    |-- std::size_t                   activeReceives // parked receiveSync waiters (aggregate)
    |-- std::size_t                   activeConnects // parked connectSync waiters
    |-- std::size_t                   activeFlushes  // in-progress setReadMode flushers
    |-- std::size_t                   activeSends    // parked sendSync waiters
    |-- std::size_t                   pendingSyncOps // in-flight parked sync ops (cap counter)
    `-- std::condition_variable       teardownCv     // signalled by each ParkGuard/FlushGuard dtor at the gate
```

All of `{data, hasData, closed, waiters, flushing, overflow}`, `{done, result}` (both op types), `syncOwnedSuppress`, and `{shuttingDown, activeReceives, activeConnects, activeFlushes, activeSends, pendingSyncOps}` are guarded by `syncMutex`. They are non-atomic by design -- every access is under the lock (INV-3).

The per-buffer `SyncReceiveBuffer::waiters` count and the `Impl`-level `activeReceives` aggregate are **two distinct counters bumped in lockstep**: `waiters` drives the GC gate (per session), `activeReceives` drives the teardown gate (across all sessions). `receiveSync` increments both under the lock via two `ParkGuard`s.

### 2.2 Data flow: a blocking HTTP request (HttpClient)

```mermaid
sequenceDiagram
    participant W as Worker thread (HttpClient)
    participant T as Transport (_impl)
    participant IO as I/O thread (TcpEngine)
    W->>T: connectSync(host, port, tls, timeout)
    Note over T: lock syncMutex; resolveSyncTimeout; entry-fence + cap check; engine->connect() enqueues; register pendingConnects; ++activeConnects; park on op->cv
    IO->>T: onConnect(sid) -> op->done = true, erase pendingConnects, notify (outside lock)
    T-->>W: ConnectResult::ok(sid)
    W->>T: setReadMode(sid, Sync)
    W->>T: sendSync(sid, request, timeout)
    Note over T: register pendingSends[opId]; ++activeSends; unlock; sendAsync(...); re-lock; wait_for(op->done||shuttingDown)
    IO->>T: send-complete callback -> op->result, op->done = true, notify (outside lock)
    T-->>W: SendResult::ok(n)
    W->>T: receiveSync(sid, buf, len, timeout)
    Note over T: lock syncMutex; cap check; ++waiters; ++activeReceives; wait_until(deadline, pred)
    IO->>T: onData(sid, bytes) -> append, hasData = true, notify
    T-->>W: ReceiveResult::ok(n) (drained bytes)
    IO->>T: onClose(sid) -> closed = true, notify_all
    W->>T: receiveSync(...) (drains remainder, then PeerClosed)
    T-->>W: ReceiveResult::err(PeerClosed)
```

### 2.3 Threading model

| Thread | Responsibility |
|---|---|
| **Worker / caller thread(s)** | Calls `connectSync`, `receiveSync`, `sendSync`, `setReadMode`; parks on `SyncConnectOp::cv` / `SyncSendOp::cv` / `SyncReceiveBuffer::cv` holding `syncMutex` (released atomically by the CV wait, or by an explicit unlock around an engine call). All four sync ops (plus `stop()` / `addListener()`) throw `std::logic_error` if called on the I/O thread. |
| **I/O thread (engine `_loop`)** | Runs `onConnect` / `onData` / `onClose` handlers and the `sendAsync` completion callback: appends data, sets flags, GCs tombstones, delivers connect/send/close results, and notifies CVs. Mutates state under `syncMutex`, then notifies **outside** the lock. Never parks on a sync CV. |
| **Teardown thread** | The (non-I/O) thread running `~Transport`. Runs `performTeardown`: sets `shuttingDown`, wakes parked CVs, and blocks on `teardownCv` until `activeReceives == activeConnects == activeFlushes == activeSends == 0`, then frees `_impl`. On the I/O thread, `~Transport` takes the deferred-self-destruct branch instead (see 4.6). |

---

## 3. System Invariants

These invariants are stated once here and referenced throughout. They are the load-bearing constraints the implementation defends.

- **INV-1 (`hasData` mirrors `data`).** `hasData == !data.empty()` at every observable point. Maintained at append (`hasData = true` in the `onData` handler), at drain (`hasData = !data.empty()` in `receiveSync`), asserted after drain.
- **INV-2 (map-entry survival).** A `SyncReceiveBuffer` **map entry** survives as long as a waiter is parked on it. The GC gate keys on the per-buffer `waiters` count, never on `shared_ptr::use_count()` (which is approximate under concurrency).
- **INV-3 (all-locked).** Every field named in 2.1 is accessed only under `syncMutex`; the counters are non-atomic because the lock already serializes them.
- **INV-5 / INV-7 (teardown gate).** Four classes of external thread park while holding `syncMutex` across a lock release; all four counters must reach zero (`activeReceives == activeConnects == activeFlushes == activeSends == 0`) before `_impl` is destroyed. The per-buffer `waiters` and the aggregate `activeReceives` must move in lockstep.
- **INV-6 (single waiter).** At most one `receiveSync` parks per session; a second concurrent call, or one overlapping an in-progress flush, is rejected with `TransportError::Cancelled`. (`sendSync` has no single-op-per-session constraint -- multiple sends may be in flight, keyed by `nextSendOpId`.)
- **INV-8 (entry fence).** `shuttingDown` is set as the *first* teardown action under the lock; every sync op re-checks it at entry and rejects, so a fresh waiter can never re-arm the gate after teardown began.

---

## 4. Component Deep Dive

### 4.1 `SyncReceiveBuffer` and the GC gate

```cpp
struct SyncReceiveBuffer
{
  std::vector<std::uint8_t> data;
  std::condition_variable   cv;
  bool        hasData{false};
  bool        closed{false};
  std::size_t waiters{0};    // parked receiveSync callers (GC gate, INV-2/INV-6)
  bool        flushing{false}; // an in-progress setReadMode Sync->Async flush owns this entry (C-1)
  bool        overflow{false}; // a Sync-mode append exceeded maxSyncReceiveBuffer (terminal)
};
```

The tombstone GC in the `onClose` handler reclaims a map entry only when all conditions hold:

```cpp
it->first != sid && it->second->closed && !it->second->hasData &&
it->second->waiters == 0 && !it->second->flushing
```

A parked `receiveSync` increments `waiters` under the lock *before* it parks, so the GC (which runs under the same `syncMutex`) can never erase the entry of a session with a parked waiter (INV-2). The `flushing` flag does the same for an in-progress `setReadMode` flush (C-1). The GC only runs when `receiveBuffers.size()` exceeds `config.syncBufferGcThreshold` (default 1024), bounding tombstone accumulation from async-only sessions that never call `receiveSync`.

**`overflow` is terminal.** Once a Sync-mode append would exceed `maxSyncReceiveBuffer`, the `onData` handler sets `overflow = true`, notifies, and returns *without* appending. The flag is never cleared: dropped bytes corrupt the stream irrecoverably, so a retry on the same session re-reports `BufferOverflow`. A closed overflow entry is still GC-reclaimable -- `overflow` does not appear in the GC gate.

### 4.2 `receiveSync`

`receiveSync` performs find-or-create, the entry checks, the parked wait, and the drain under **one** `std::unique_lock` (the CV wait releases/re-acquires it). No user callback runs here -- the drain is a `memcpy` -- so the no-callback-under-lock invariant (HR-6) holds.

Sequence under the held lock:

1. If on the I/O thread -> throw `std::logic_error` (would deadlock). The guard tests `std::this_thread::get_id() == engine->getIoThreadId()` on **thread identity alone** -- `getIoThreadId()` returns the default `std::thread::id` pre-start / post-detach, so a real off-I/O caller never matches.
2. **Resolve the timeout:** `timeout = resolveSyncTimeout(timeout)` (see 4.7) -- the `kUseConfigSyncTimeout` sentinel becomes `config.defaultSyncTimeout`.
3. **Entry fence (INV-8):** if `shuttingDown` -> return `ShuttingDown`.
4. **Cap check (C2):** if `syncCapReached()` -> return `TooManyPendingSyncOps`; otherwise construct a `PendingSyncGuard` (declared after the `unique_lock`, so it decrements under the still-held lock, outermost).
5. Find or create the buffer.
6. **Single-waiter / flush-overlap reject (INV-6):** if `waiters > 0` or `flushing` -> return `Cancelled` (with a message distinguishing the two).
7. Construct two `ParkGuard`s -- `bufGuard` for `buf->waiters` (GC gate) and `implGuard` for `activeReceives` (teardown gate). Both destruct (decrement + `teardownCv.notify_one()`) **under the still-held lock**. An `assert(buf->waiters == 1)` documents the single-waiter contract.
8. `cv.wait_until(lk, deadline, pred)` where `pred == hasData || closed || overflow || shuttingDown` and `deadline == steady_clock::now() + timeout`. The fixed deadline makes the timeout a wall-clock bound; a past deadline (e.g. `timeout == 0`) returns immediately with the predicate's current value. This **folds the spurious-wake case back into the loop** -- `receiveSync` never returns `ok(0)`.
9. On a *pure timeout* (`wait_until` returns `false`): return `Timeout` directly, leaving the buffer in the map for the `onClose` GC.
10. Otherwise, in order: **drain `data` first** -> `memcpy`, return `ok(n)` (drain-before-close); else `overflow` -> `BufferOverflow`; else `closed` -> erase the entry + `readModes[sid]`, return `PeerClosed`; else `shuttingDown` -> return `ShuttingDown` (do **not** erase -- teardown owns the maps).

### 4.3 `connectSync`

`connectSync` holds `syncMutex` **continuously** from before `engine->connect()` through entry into `op->cv.wait_for` (INV-8). This atomicity is load-bearing: a concurrent teardown either wins the lock first (and `connectSync` then hits the entry fence, never calling `engine->connect()`), or `connectSync` wins (registers in `pendingConnects` and is counted in `activeConnects` before teardown's notify) -- so a parked connect is never both uncounted and unreachable, and `engine->connect()` is never issued on a torn-down engine.

- **Timeout resolution:** `timeout = resolveSyncTimeout(timeout)` (4.7) before acquiring the lock.
- **UDP no longer short-circuits.** Both TCP and UDP park in `pendingConnects` and return only once the I/O thread's `onConnect` fires (after it inserts the session). This is the **F-1 fix**: a UDP `connectSync` that returned before the session was inserted would race the enqueue-time `sessionSendable` check (CF-H1, 4.8) on a subsequent `sendSync`, so the caller could get "session not connected" for a sid `connectSync` had just handed back. Parking until `onConnect` guarantees the returned sid is registered and immediately usable.
- **Entry fence** (`shuttingDown`) rejects before `engine->connect()` and before counting.
- **Cap check (C2):** `syncCapReached()` -> `TooManyPendingSyncOps`; otherwise a `PendingSyncGuard` is constructed (declared after `lk`, decrements under the lock through the final unlock/close/re-lock window).
- The `ParkGuard` for `activeConnects` is constructed **only on the success path**, after `pendingConnects[sid] = op` and before the wait. The synchronous-error early-return (defensive; unreachable for the current TCP engine, which reports failures asynchronously via `onClose`) is outside the guard scope, so a connect that never parks is never counted.
- The wait predicate is `op->done || shuttingDown`.
- On `op->done`: return `std::move(op->result)`.
- On a `shuttingDown` wake: return `ShuttingDown`, do **not** erase `pendingConnects`, and **skip** `engine->close(sid)` (the engine is being torn down).
- On **timeout**: insert `sid` into `syncOwnedSuppress` (4.4) **under the lock**, release the lock, `engine->close(sid)` (wrapped in `try/catch` that re-acquires the lock before rethrowing so the guards decrement under the lock), re-acquire the lock so the guard's decrement runs under it, then return `Timeout` (or `ShuttingDown` if teardown began in the unlock window). It **never returns `ok` after issuing the close** -- a connect that completes in the unlock window is reported as `Timeout`, not handed back as a live handle to a session being closed.

Every `sid` returned by `engine->connect()` always receives a terminal `onClose` -- every `doConnect` failure path (including `SSL_new` failure) fires `onClose`, and a successful connect's session is closed via the engine's `doClose`. The `onClose` handler reaps `pendingConnects[sid]` (and suppresses the global `onClose` for a sid the user never received), so there is no entry leak -- except under teardown, where `~Impl` reaps it.

### 4.4 Spurious-`onClose` suppression (`syncOwnedSuppress`)

`syncOwnedSuppress` is an `std::unordered_set<SessionId>` (guarded by `syncMutex`) recording sids owned by a **timed-out `connectSync` that has issued its own `engine->close(sid)`**. It exists because the global-`onClose` suppression normally keys on `pendingConnects[sid]`, but a connect that *succeeds* in the tiny window between the caller's timeout and its `close(sid)` lets `onConnect` erase that `pendingConnects` entry first -- so the close's `onClose` would no longer find it and would fire the **global `onClose` for a sid the user never received** (Finding 1).

- `connectSync` inserts `sid` into `syncOwnedSuppress` under the lock *before* releasing it to call `close(sid)`.
- The `onClose` handler resolves in two branches under the lock:
  - **`pendingConnects`-found path** -- delivers the error to the parked `connectSync`, erases `pendingConnects[sid]`, and also `syncOwnedSuppress.erase(sid)` (no marker leak).
  - **else-if `syncOwnedSuppress.erase(sid) > 0`** -- a racing `onConnect` already consumed `pendingConnects[sid]`; set `suppressOwned = true` and suppress the global `onClose` / observers / tombstone for this user-never-received sid.

The marker **survives `onConnect`** and is consumed by `onClose`, closing the race for both TCP and UDP.

### 4.5 `sendSync` (blocking send-completion)

`sendSync` **blocks until the engine signals send completion** (or the timeout elapses), honoring the timeout -- the former implementation ignored the timeout and returned as soon as the bytes were enqueued. "Completion" is whatever the engine's `SendCompleteCallback` signals: for the current TCP/UDP engines that is the synchronous, post-copy acceptance of the bytes into the engine (not wire transmission or a TLS flush), so today completion is effectively immediate and the timeout rarely elapses -- the parked-waiter machinery is forward-correct for a future engine that defers completion.

The flow mirrors `connectSync`:

1. I/O-thread guard (throw); `timeout = resolveSyncTimeout(timeout)`.
2. Acquire `syncMutex`. **Entry fence** (`shuttingDown` -> `ShuttingDown`). **Cap check** (`syncCapReached()` -> `TooManyPendingSyncOps`).
3. `const std::uint64_t opId = nextSendOpId++`; `pendingSends[opId] = op` (keyed by a monotonic id because multiple sends may be in flight on one session). Construct a `ParkGuard` on `activeSends` and a `PendingSyncGuard` on `pendingSyncOps` (both declared after `lk`, destruct under the lock).
4. **Unlock** and call `engine->sendAsync(sid, ...)` with a completion lambda that captures `op` (shared_ptr) and `this`. The lambda re-acquires `syncMutex`, sets `op->result` / `op->done = true` (once), then notifies `op->cv` **outside** the lock. Issuing the send without holding `syncMutex` is required because the engine may fire the completion **synchronously on this thread** (and the callback re-acquires the lock). The `try/catch` around `sendAsync` re-acquires the lock and erases `pendingSends[opId]` before rethrowing (`sendAsync` can throw e.g. `bad_alloc`, since `TcpEngine::send` allocates a `ByteBuffer` outside `enqueue`'s catch).
5. Re-lock; `op->cv.wait_for(lk, timeout, pred)` with `pred == op->done || shuttingDown`.
6. `pendingSends.erase(opId)`; return `std::move(op->result)` on `op->done`, else `ShuttingDown`, else `Timeout`.

Because `sendSync` has no buffered data to drain, its CV is **always** woken on teardown (both the fence and the wait-out), exactly like `connectSync`.

### 4.6 `setReadMode` flush (Sync -> Async)

Switching a session from `Sync` to `Async` drains any buffered data to the async `onData` callback before flipping the mode. Non-flush transitions (anything that is *not* Sync->Async) update `readModes` under a single `lock_guard` and return early; switching *to* Sync also lazily creates the receive buffer. Crossing the `Disabled` boundary toggles the fd's `EPOLLIN` registration via `engine->setReadEnabled(sid, ...)` (C5). Only the Sync->Async case flushes.

Because the flush releases `syncMutex` to invoke the user `onData` callback (HR-6), it is a **fourth class of external thread touching `_impl`**. It is protected by a `FlushGuard`:

- Constructed **under the fetch lock** (no window for GC to erase the entry before it is marked `flushing`); its constructor sets `buf->flushing = true` and `++activeFlushes`.
- Its destructor takes the lock itself (the flush loop holds no lock at scope exit) and clears `flushing` / decrements `activeFlushes` / notifies `teardownCv`. Increment and decrement are thus owned by one RAII object (no leak gap).
- The flush loop re-checks `shuttingDown` each iteration and bails (`return false`) if teardown began; the `FlushGuard` dtor then releases the flusher so the handshake can proceed.
- The mode stays `Sync` throughout the drain so the I/O thread keeps buffering data that arrives mid-flush; the switch to `Async` happens atomically under the lock once the buffer is empty.
- `setReadMode` on the I/O thread throws (TD-INV-5): a flush's `onData` could delete the `Transport` on the I/O thread, and the handshake would then wait on `activeFlushes == 0` for this thread's own flush -- self-deadlock. The throw precedes the `allowReadModeSwitch` check so it is reached regardless of config.

### 4.7 Timeout resolution (`resolveSyncTimeout`, sentinels)

Two constants in `transport_types.hpp`:

- `kUseConfigSyncTimeout` = `std::chrono::milliseconds{-1}` -- the sentinel default for the primary sync ops' `timeout` parameter. Any negative value means "use the configured default".
- `kFallbackSyncTimeout` = `std::chrono::milliseconds{30000}` -- the historical 30 s fallback: the `*Cancellable` variants' literal default, their negative-value clamp target, and `resolveSyncTimeout`'s floor.

```cpp
std::chrono::milliseconds resolveSyncTimeout(std::chrono::milliseconds t) const
{
  if (t < std::chrono::milliseconds::zero())
  {
    return config.defaultSyncTimeout > std::chrono::milliseconds::zero()
             ? config.defaultSyncTimeout
             : kFallbackSyncTimeout;   // floor a misconfigured non-positive default (F-2)
  }
  return t; // explicit non-negative (0 == non-blocking) respected as-is
}
```

- **Primary ops** (`connectSync`, `sendSync`, `receiveSync`, both `connectSync` overloads) default their `timeout` argument to `kUseConfigSyncTimeout` and resolve it at the top of each definition. `config.defaultSyncTimeout` defaults to 30000 ms; the SIP presets set it to 32000 ms (TCP, Timer B/F) and 500 ms (UDP, T1).
- **`*Cancellable` variants** are `ITransport` methods with **no config access**, so they default to and clamp a negative caller value to `kFallbackSyncTimeout` (the literal 30 s), never `config.defaultSyncTimeout`. Use the primary ops for config-tuned timeouts (F-3).

### 4.8 CF-H1 send validation (`sessionSendable`)

Both engines validate the target session synchronously in `send()` / `sendAsync()` via `sessionSendable(sid)` -- "present in `_sessions` **and** not `closed`", the same validity notion `doSend` uses, taken under the session read lock. If it fails, `sendAsync` fires the completion callback with `TransportError::Socket` ("session not connected") rather than enqueuing a Send command that `doSend` would silently drop while reporting false success (which would defeat SIP RFC 3263 failover).

Interaction with the sync facade:

- **`sendSync`** issues its send through `sendAsync`, so a send to an unknown/closed session resolves the `SyncSendOp` with the `Socket` error immediately -- the caller sees a truthful failure, not a false `ok`.
- **Connect-then-send ordering.** A caller must `await onConnect` before sending: for `connectSync`, parking until `onConnect` (4.3, including the UDP F-1 fix) guarantees the returned sid is registered in `_sessions`, so a subsequent `sendSync` passes `sessionSendable`. The check's residual close-racing-right-after window is the accepted narrow TOCTOU documented in the engine: it shrinks the false-OK window from "always" to a rare race and cannot be closed without holding `_sessionRwMutex` across enqueue+dispatch.

### 4.9 The teardown handshake (`performTeardown` / `teardownWaitOut`)

`~Transport` runs the handshake **unconditionally** when `_impl && _impl->engine` and the caller is **not** the I/O thread (gated on object *presence*, never on `isRunning()` -- a parked waiter can outlive `isRunning() == false`). Under the shared-ownership model the move ctor and `operator=` are **deleted** (`transport.hpp`), so `~Transport` is the sole `_impl`-destroying exit. `performTeardown` asserts it is not on the I/O thread.

`teardownWaitOut(notifyReceive)` sets `shuttingDown` under the lock, `notify_all`s every parked connectSync **and** sendSync CV (via `wakeConnectAndSendWaiters()`), and, if `notifyReceive`, every `receiveBuffers[*]->cv`, then:

```cpp
teardownCv.wait(lk, [this] {
  return activeReceives == 0 && activeConnects == 0 && activeFlushes == 0 && activeSends == 0;
});
```

`setTeardownFence()` is the lighter variant used on the normal path: it sets `shuttingDown` and wakes only the connectSync + sendSync CVs (`wakeConnectAndSendWaiters()`), leaving the receiveSync CVs for `engine->stop()`'s `onClose` to drain first.

**Per-path ordering** (`performTeardown`):

| Path | Condition | Ordering |
|---|---|---|
| **Already-stopped** | `!engine->isRunning()` | `teardownWaitOut(true)` only -- the prior external `stop()` already fired `onClose`; this wakes any straggler. No redundant `stop()`. |
| **Normal** | running, non-I/O thread | `setTeardownFence()` (fence + wake connectSync/sendSync only) -> `engine->stop()` *without* holding `syncMutex` (its `shutdownDrain` delivers final bytes and fires `onClose`, so parked `receiveSync` waiters drain their tail and return `PeerClosed`) -> `teardownWaitOut(false)` (do **not** re-notify receive CVs, preserving drain-before-close). |
| **I/O-thread self-destruct** | caller is the I/O thread (sole owner dropped its last `shared_ptr` in its own callback) | handled in `~Transport` directly, not `performTeardown` -- see 4.10. |

**Why `notifyReceive == false` on the normal path (H-1):** re-notifying the receive CVs after `stop()` would let a parked waiter wake on `shuttingDown` and skip its drain when `stop()` degenerated to a CAS no-op. The `onClose`-driven `closed` wake is what preserves drain-before-close. Correspondingly, the `onData` handler skips the append only when teardown is in progress *and* no waiter is parked (`if (shuttingDown && waiters == 0) return;`) -- if a waiter is parked it must still receive the final bytes.

### 4.10 The I/O-thread deferred-self-destruct

`~Transport` reaches the I/O thread only when a **sole** owner drops its last `shared_ptr<Transport>` inside one of its own callbacks (single-threaded; shared ownership makes the concurrent C-1 case structurally unreachable -- a concurrent stopper holds its own `shared_ptr` across the whole `onClose`, so this drop can never be the last reference while a stopper exists). It cannot free `_impl` synchronously -- the engine's dispatch is still unwinding on this stack. Instead it **defers**:

```cpp
_impl->teardownWaitOut(/*notifyReceive=*/true);   // wake + wait out other-thread waiters
Impl *raw = _impl.release();                       // ~Impl must NOT run now
raw->engine->scheduleSelfDestruct([raw] { delete raw; }); // run post-loop()
raw->engine->detachForTermination();
return;
```

The detached I/O thread runs the deleter in its post-`loop()` epilogue, after dispatch fully unwinds -- no use-after-free. Parked waiters on *other* threads decrement their counters independently, so `teardownWaitOut` does not self-deadlock.

This branch gates on **thread identity alone**, with **no `isRunning()` assert in either polarity**: `_running` is legitimately `false` here when reached via `shutdownDrain` (the `Shutdown` command clears it on the I/O thread before `onClose` fires) **and** legitimately `true` when reached via a peer-initiated `closeNow` while running -- so neither `assert(isRunning())` nor `assert(!isRunning())` would be valid. A build with `-D IORA_DISABLE_SELFDESTRUCT_DEFERRAL` replaces the deferral with a synchronous `~Impl` and is the retained negative control that ASan-faults, proving the deferral is what prevents the UAF.

---

## 5. Usage Guide

### 5.1 Blocking request/response over TCP

```cpp
#include <iora/network/transport.hpp>
#include <iora/network/transport_impl.hpp> // in exactly one TU

using namespace iora::network;
using namespace std::chrono_literals;

auto t = Transport::tcp(TransportConfig{}); // std::shared_ptr<Transport>
if (!t->start().isOk())
{
  return;
}

// timeout omitted -> kUseConfigSyncTimeout -> config.defaultSyncTimeout (30 s default).
auto conn = t->connectSync("example.com", 80, TlsMode::None);
if (conn.isErr())
{
  return; // Timeout, Connect, TLSHandshake, ShuttingDown, or TooManyPendingSyncOps
}
SessionId sid = conn.value(); // registered in the engine (parked until onConnect)

t->setReadMode(sid, ReadMode::Sync);

// sendSync blocks until the engine accepts the bytes (or the timeout elapses).
auto sent = t->sendSync(sid, BufferView{request.data(), request.size()});
if (sent.isErr())
{
  return; // Socket (session not connected, CF-H1), Timeout, ShuttingDown, TooManyPendingSyncOps
}

std::string response;
char buf[8192];
while (true)
{
  std::size_t len = sizeof(buf);
  auto r = t->receiveSync(sid, buf, len); // config-default timeout
  if (r.isOk()) // len > 0; ok(0) is never returned
  {
    response.append(buf, len);
    if (isComplete(response))
    {
      break;
    }
  }
  else if (r.error().code == TransportError::Timeout)
  {
    throw std::runtime_error("response timeout");
  }
  else if (r.error().code == TransportError::PeerClosed)
  {
    break; // server closed after responding; drained bytes already appended
  }
  else
  {
    throw std::runtime_error("transport error"); // BufferOverflow / ShuttingDown / TooManyPendingSyncOps
  }
}
```

### 5.2 Distinguishing the error codes

```cpp
auto r = t->receiveSync(sid, buf, len /*, timeout*/);
if (r.isErr())
{
  switch (r.error().code)
  {
  case TransportError::Timeout:               /* no data within the deadline */              break;
  case TransportError::PeerClosed:            /* clean EOF after a full drain */             break;
  case TransportError::BufferOverflow:        /* response exceeded maxSyncReceiveBuffer */   break;
  case TransportError::ShuttingDown:          /* transport is being torn down */             break;
  case TransportError::Cancelled:             /* a second waiter, or overlap with a flush */ break;
  case TransportError::TooManyPendingSyncOps: /* maxPendingSyncOps concurrent ops reached */ break;
  default:                                                                                   break;
  }
}
```

### 5.3 TLS with per-connection client identity

```cpp
// The second connectSync overload takes TlsClientOptions for a per-connection
// client certificate / SNI / verification identity.
TlsClientOptions opts;              // populate as needed
auto conn = t->connectSync("secure.example.com", 443, TlsMode::Client, opts, 10s);
```

### 5.4 Timeout policy

```cpp
// Config-tuned default (SIP TCP preset -> 32 s Timer B/F):
auto cfg = TransportConfig::forSipTcp();
auto t   = Transport::tcp(cfg);
auto c   = t->connectSync(host, port);            // uses cfg.defaultSyncTimeout (32 s)

// Explicit non-blocking poll (respected as-is; NOT floored):
std::size_t len = sizeof(buf);
auto r = t->receiveSync(sid, buf, len, 0ms);      // one poll, immediate return

// Cancellable variants ignore config.defaultSyncTimeout (no config access) and
// clamp a negative value to the 30 s literal fallback:
CancellationToken tok;
auto rc = t->receiveSyncCancellable(sid, buf, len, tok /*, timeout*/);
```

### 5.5 Anti-Patterns

- **Do NOT call `receiveSync` / `connectSync` / `sendSync` / `setReadMode` (or `stop()` / `addListener()`) from the I/O thread** (i.e. inside an `onData` / `onClose` / `onConnect` callback). They throw `std::logic_error` -- they would deadlock waiting on the thread that must feed them.
- **Do NOT issue two concurrent `receiveSync` calls on the same `sid`.** The second is rejected with `TransportError::Cancelled` (single-waiter contract, INV-6). Serialize per session. (Concurrent `sendSync` calls on one session are allowed.)
- **Do NOT call `setReadMode(sid, Async)` concurrently with a `receiveSync` on the same `sid`.** A `receiveSync` overlapping an in-progress flush is rejected with `Cancelled`.
- **Do NOT send before the connect completes.** Await `onConnect` (or a successful `connectSync` return) before `sendSync`/`send`; a send to a not-yet-registered or closed session fails `sessionSendable` (CF-H1) with `Socket` "session not connected".
- **Avoid destroying a `Transport` from inside one of its own I/O-thread callbacks.** The library now handles the *sole-owner* case safely via the deferred-self-destruct (4.10), and the concurrent case is structurally excluded by the shared-ownership model -- but relying on self-destruction is fragile; prefer keeping the `Transport`'s `shared_ptr` alive past all callbacks.
- **Do NOT treat `BufferOverflow` as recoverable.** It is terminal for the session's Sync read mode (dropped bytes corrupt the stream); close the session.

---

## 6. Call Flow / Sequence Reference

### 6.1 `receiveSync` -- success (drain) then `PeerClosed`

| Step | Thread | Action | Lock |
|---|---|---|---|
| 1 | Worker | Throw if on I/O thread; `resolveSyncTimeout(timeout)` | -- |
| 2 | Worker | Acquire `syncMutex` | **acquire** |
| 3 | Worker | Entry fence: `shuttingDown`? -> `ShuttingDown`; cap: `syncCapReached()`? -> `TooManyPendingSyncOps` (else `PendingSyncGuard`) | held |
| 4 | Worker | Find/create buffer; reject if `waiters > 0` / `flushing` -> `Cancelled` | held |
| 5 | Worker | `++buf->waiters`, `++activeReceives` (two `ParkGuard`s constructed) | held |
| 6 | Worker | `cv.wait_until(deadline, pred)` | **released while waiting** |
| 7 | I/O | `onData`: append, `hasData = true`, `notify_one` | acquire / release |
| 8 | Worker | Wake; `data` non-empty -> `memcpy`, `len = n`, return `ok(n)` | held |
| 9 | Worker | `ParkGuard` + `PendingSyncGuard` dtors: `--buf->waiters`, `--activeReceives`, `--pendingSyncOps`, `teardownCv.notify_one()` | held -> **release** |
| 10 | I/O | (later) `onClose`: `closed = true`, `notify_all`; tombstone GC if oversized | acquire / release |
| 11 | Worker | Next `receiveSync`: data empty, `closed` -> erase entry + `readModes`, return `PeerClosed` | held -> release |

### 6.2 `sendSync` -- blocking send-completion

| Step | Thread | Action | Lock |
|---|---|---|---|
| 1 | Worker | Throw if on I/O thread; `resolveSyncTimeout(timeout)` | -- |
| 2 | Worker | Acquire `syncMutex`; entry fence + cap check | **acquire** |
| 3 | Worker | `opId = nextSendOpId++`; `pendingSends[opId] = op`; `++activeSends`, `++pendingSyncOps` | held |
| 4 | Worker | **Unlock**; `engine->sendAsync(sid, ..., completionCb)` (may fire synchronously) | **released** |
| 5 | I/O (or same) | completion: lock, set `op->result`/`op->done`, unlock, `op->cv.notify_one()` | acquire / release |
| 6 | Worker | Re-lock; `op->cv.wait_for(timeout, op->done||shuttingDown)` | acquire / wait |
| 7 | Worker | `pendingSends.erase(opId)`; return `ok(n)` / `ShuttingDown` / `Timeout`; guards decrement | held -> release |

### 6.3 Teardown (normal path) -- destruction with a parked waiter

| Step | Thread | Action | Lock |
|---|---|---|---|
| 1 | Worker | Parked in `receiveSync` `wait_until` (`activeReceives == 1`, `buf->waiters == 1`) | released |
| 2 | Teardown | `~Transport` -> `performTeardown` (non-I/O, running -> normal path) | -- |
| 3 | Teardown | `setTeardownFence`: acquire, `shuttingDown = true`, wake connectSync + sendSync CVs only, release | acquire / release |
| 4 | Teardown | `engine->stop()` (NOT holding `syncMutex`) | -- |
| 5 | I/O | `shutdownDrain`: deliver pending `onData` (append; `waiters > 0` so not skipped), then `onClose` (`closed = true`, `notify_all`) | acquire / release |
| 6 | Worker | Wake; drain tail -> `ok(n)`; next call sees `closed`, empty -> `PeerClosed`; guard dtors `--activeReceives` / `--buf->waiters`, `teardownCv.notify_one()` | held -> release |
| 7 | Teardown | `teardownWaitOut(false)`: acquire, `shuttingDown = true`, wake connectSync + sendSync CVs, `teardownCv.wait` until all four counters == 0 | acquire, wait, release |
| 8 | Teardown | Predicate satisfied; return from `performTeardown`; `~Impl` frees `syncMutex` / maps (safe -- no parked caller remains) | -- |

---

## 7. Thread Safety Model

All sync + teardown state is guarded by a single `std::mutex syncMutex` (Lock order 2). At most one Transport-level lock is held at a time; no user callback is invoked while `syncMutex` is held (copy-then-invoke for callbacks; the `receiveSync` drain is a `memcpy`, not a callback; `sendSync` and the `setReadMode` flush release the lock before invoking the engine / user callback).

| Operation | Synchronization | Notes |
|---|---|---|
| `receiveSync` | one `unique_lock<syncMutex>` across find / park / drain | throws on I/O thread; `PendingSyncGuard` + two `ParkGuard`s (`buf->waiters`, `activeReceives`) decrement under the held lock |
| `connectSync` | continuous `unique_lock<syncMutex>` connect -> register -> wait; brief unlock around timeout-path `close(sid)` | throws on I/O thread; `PendingSyncGuard` + one `ParkGuard` for `activeConnects`; UDP parks like TCP (F-1); marks `syncOwnedSuppress` before close |
| `sendSync` | `unique_lock<syncMutex>` for register/park; **unlocked** across `engine->sendAsync` | throws on I/O thread; `PendingSyncGuard` + `ParkGuard` for `activeSends`; completion callback re-acquires the lock, notifies outside it |
| `setReadMode` (non-flush) | single `lock_guard<syncMutex>` | throws on I/O thread; toggles `EPOLLIN` at the Disabled boundary (C5) |
| `setReadMode` (Sync->Async flush) | `lock_guard` per iteration; `FlushGuard` set under the fetch lock | releases the lock for the `onData` callback (HR-6); `FlushGuard` owns `flushing` / `activeFlushes` |
| `getReadMode` | single `lock_guard<syncMutex>` (const) | -- |
| `stop()` / `addListener()` | none on `syncMutex` (delegate to engine) | throw on I/O thread by identity-alone guard (`get_id() == getIoThreadId()`), uniform with the sync ops |
| `onConnect` / `onData` / `onClose` / send-completion (I/O thread) | `lock_guard<syncMutex>` to mutate buffer/flags/op | set-then-notify: mutate under the lock, `notify` **outside** it; observer dispatch is copy-then-iterate |
| `~Transport` (non-I/O thread) | `performTeardown` -> `teardownCv.wait` under `syncMutex` | blocks until all four counters reach 0 |
| `~Transport` (I/O thread, sole owner) | deferred-self-destruct: `teardownWaitOut(true)` + `_impl.release()` + `scheduleSelfDestruct` + `detachForTermination` | `~Impl` runs on the detached I/O thread's post-`loop()` epilogue |

**Lock ordering.** The convention is `callbackMutex -> syncMutex -> observerMutex -> userDataMutex`, but in practice no path holds more than one Transport-level lock at a time (callbacks are copied under `callbackMutex` and released before `syncMutex` is taken, and vice-versa), so the order is a defensive convention, not a live constraint.

`shuttingDown` (like `closed` and each op's `done`) is set under `syncMutex` immediately before each `notify`, so the predicate re-check on wakeup cannot miss it -- no lost-wakeup window.

---

## 8. Configuration Reference

| Parameter (`TransportConfig`) | Default | Units | Effect |
|---|---|---|---|
| `maxPendingSyncOps` | `32` (SIP presets: `64`) | count | Ceiling on concurrently-parked sync ops (`connectSync` + `receiveSync` + `sendSync`). When reached, further sync ops fail with `TooManyPendingSyncOps`. `0` = unlimited. |
| `maxSyncReceiveBuffer` | `1024 * 1024` (1 MiB) | bytes | Cap on a Sync session's buffered data. An append that would exceed it sets `overflow` and surfaces `BufferOverflow` to the waiter (data is dropped, not appended). |
| `syncBufferGcThreshold` | `1024` | entries | When `receiveBuffers.size()` exceeds this, `onClose` GCs reclaimable tombstones (`closed && !hasData && waiters == 0 && !flushing`). |
| `defaultSyncTimeout` | `30000` (SIP TCP: `32000`; SIP UDP: `500`) | ms | Resolved by `resolveSyncTimeout` when a primary sync op's `timeout` is the `kUseConfigSyncTimeout` sentinel (any negative value). A non-positive config value is floored to `kFallbackSyncTimeout` (30 s). |
| `allowReadModeSwitch` | `true` | bool | If `false`, `setReadMode` returns `false` and the mode is fixed (checked *after* the I/O-thread throw). |
| `connectTimeout` | `30000` | ms | Engine-side connect-timeout timer (independent of the `connectSync` caller timeout). |
| `handshakeTimeout` | `30000` | ms | Engine-side TLS handshake-timeout timer. |

The primary sync methods default their `timeout` parameter to the `kUseConfigSyncTimeout` sentinel (`= -1 ms`); the `*Cancellable` variants default to `kFallbackSyncTimeout` (`= 30000 ms`) because they have no config access. These caller-side deadlines are independent of the engine-side timers above.

---

## 9. API Reference

```cpp
namespace iora::network {

enum class ReadMode { Async, Sync, Disabled };

enum class TransportError {
  None, Socket, Resolve, Bind, Listen, Accept, Connect, TLSHandshake, TLSIO,
  PeerClosed, WriteBackpressure, Config, GCClosed, Cancelled, Timeout,
  BufferOverflow, ShuttingDown, TooManyPendingSyncOps, Unknown
};

// transport_types.hpp -- sync-timeout sentinels
static constexpr std::chrono::milliseconds kUseConfigSyncTimeout{-1};    // "use config.defaultSyncTimeout"
static constexpr std::chrono::milliseconds kFallbackSyncTimeout{30000};  // 30 s literal fallback

class Transport final : public ITransport,
                        public std::enable_shared_from_this<Transport> {
public:
  // The only public construction surface -- return std::shared_ptr<Transport>
  // (shared-ownership model; ctors are private + tag-gated, move + copy deleted).
  static std::shared_ptr<Transport> tcp(TransportConfig config = {});
  static std::shared_ptr<Transport> udp(TransportConfig config = {});

  StartResult start();
  void        stop();                        // throws std::logic_error on the I/O thread
  bool        isRunning() const;
  bool        isOnIoThread() const noexcept;

  ConnectResult connectSync(const std::string &host, std::uint16_t port,
                            TlsMode tls = TlsMode::None,
                            std::chrono::milliseconds timeout = kUseConfigSyncTimeout) override;
  ConnectResult connectSync(const std::string &host, std::uint16_t port, TlsMode tls,
                            const TlsClientOptions &opts,
                            std::chrono::milliseconds timeout = kUseConfigSyncTimeout) override;

  SendResult    sendSync(SessionId sid, iora::core::BufferView data,
                         std::chrono::milliseconds timeout = kUseConfigSyncTimeout) override;
  ReceiveResult receiveSync(SessionId sid, void *buffer, std::size_t &len,
                            std::chrono::milliseconds timeout = kUseConfigSyncTimeout) override;

  bool setReadMode(SessionId sid, ReadMode mode) override;
  bool getReadMode(SessionId sid, ReadMode &mode) const override;

  ~Transport();
  Transport(Transport &&) = delete;             // shared-ownership only
  Transport &operator=(Transport &&) = delete;
  Transport(const Transport &) = delete;
  Transport &operator=(const Transport &) = delete;

private:
  static std::shared_ptr<Transport> withEngine(std::unique_ptr<detail::EngineBase> engine,
                                                TransportConfig config = {}); // test-only (fault injection)
};

// ITransport default implementations (no config access -> kFallbackSyncTimeout default + clamp):
//   connectSyncCancellable(host, port, token, tls, timeout = kFallbackSyncTimeout, opts)
//   sendSyncCancellable(sid, data, token, timeout = kFallbackSyncTimeout)
//   receiveSyncCancellable(sid, buffer, len, token, timeout = kFallbackSyncTimeout)

} // namespace iora::network
```

`ConnectResult`, `SendResult`, `ReceiveResult` are `Result<T, TransportErrorInfo>` aliases. `receiveSync` returns `ok(n)` with `len` set to the bytes copied (never `ok(0)`), or an error carrying one of `Timeout`, `PeerClosed`, `BufferOverflow`, `ShuttingDown`, `Cancelled`, `TooManyPendingSyncOps`. `sendSync` returns `ok(n)` once the engine accepts the bytes, or `Socket` (CF-H1 unknown/closed session), `Timeout`, `ShuttingDown`, or `TooManyPendingSyncOps`.

The `*Cancellable` wrappers poll the corresponding sync op in sub-intervals (100 ms) against a `CancellationToken`; they compose over the primitives documented here and share their buffer-lifecycle and teardown semantics. `receiveSyncCancellable` and `connectSyncCancellable` guarantee **at least one** poll (`receiveSyncCancellable` is a `do`/`while`), so an explicit `timeout == 0` still makes one non-blocking attempt.

---

## 10. Design Decisions

| Decision | Rationale |
|---|---|
| Single `syncMutex` for all sync + teardown state | At most one Transport-level lock held at a time -> no lock-order inversion; simple reasoning. |
| Four separate counters for the teardown gate | Four external-thread classes park while holding `syncMutex` (receiveSync, connectSync, sendSync waiters, setReadMode flushers). Counting each is the only way to wait them all out (INV-5/INV-7). |
| Per-buffer `waiters` **and** Impl-level `activeReceives` | The GC gate needs a per-buffer count; the teardown gate needs an aggregate. Both are bumped in lockstep by two `ParkGuard`s. |
| `sendSync` blocks on a `SyncSendOp` until engine completion | The old enqueue-and-return ignored the timeout and could not report a deferred send failure; parking on the completion callback makes the result truthful and honors the timeout, forward-correct for a deferred-completion engine. |
| Concurrent parked-sync-op cap (`maxPendingSyncOps`, `PendingSyncGuard`, `TooManyPendingSyncOps`) | Bounds parked-op fan-out under load; the cap check and increment share one lock so a race cannot exceed it. `0` preserves the unlimited legacy behavior. |
| Config-driven timeout via `kUseConfigSyncTimeout` sentinel + `resolveSyncTimeout` | Lets SIP presets tune the sync-op deadline (Timer B/F, T1) without touching call sites; a non-positive config is floored to 30 s so a sync op never silently degrades to a non-blocking poll (F-2). The `*Cancellable` variants keep the literal fallback (no config access, F-3). |
| UDP `connectSync` parks until `onConnect` (short-circuit removed) | An early UDP return raced the enqueue-time `sessionSendable` check (CF-H1) on a subsequent send; parking guarantees the returned sid is registered and immediately usable (F-1). |
| `syncOwnedSuppress` marker survives `onConnect`, consumed by `onClose` | A timed-out `connectSync` that closed its own session must not fire the global `onClose` for a sid the user never received, even when a racing `onConnect` already erased `pendingConnects[sid]` (Finding 1). |
| Explicit waiter counter, never `shared_ptr::use_count()` | `use_count()` is approximate under concurrency and not a synchronization primitive (INV-2). |
| `shuttingDown` is an entry fence set FIRST under the lock | Prevents a fresh sync call from re-arming the gate after teardown began; set-then-notify under the lock avoids lost wakeups (INV-8). |
| Normal-path teardown sets the fence but lets `stop()`'s `onClose` wake receiveSync waiters | Preserves drain-before-close: the engine delivers the final bytes before the waiter sees EOF (H-1). connectSync/sendSync waiters have no data to drain, so they are always woken by the fence. |
| `wait_until(deadline, pred)` fold-back | Eliminates the spurious `ok(0)` return and makes the timeout a true wall-clock bound. |
| Shared-ownership only (`std::shared_ptr`, move + copy deleted) | Makes `~Transport` the sole `_impl`-destroying exit and renders the concurrent I/O-thread self-destruct (C-1) structurally unreachable; removes the hazardous `operator=` teardown path entirely. |
| I/O-thread deferred-self-destruct gates on thread identity alone (no `isRunning()` assert in either polarity) | `~Transport` reaches the I/O thread with `isRunning() == false` via `shutdownDrain` and with `isRunning() == true` via peer-initiated `closeNow`. Both are legitimate; asserting on `_running` either way would misroute or spuriously abort a valid path. The four sync guards (and `stop()`/`addListener()`) throw on the I/O thread by identity alone -- `getIoThreadId()` is the default `std::thread::id` pre-start/post-detach, so a real off-I/O caller never matches. |
| CF-H1 `sessionSendable` synchronous send validation | Rejecting a send to an unknown/closed session (rather than enqueuing a Send that `doSend` silently drops as false success) preserves SIP RFC 3263 failover; the narrow close-racing TOCTOU is accepted (cannot close without holding the session lock across dispatch). |
| `BufferOverflow` is terminal for a session's Sync buffer | Dropped bytes corrupt the stream irrecoverably; surfacing a distinct error lets callers close the session instead of timing out blind. |
| Every `doConnect` failure path fires `onClose` | Guarantees every `connect()`-returned sid receives a terminal event, so `connectSync` never orphans a `pendingConnects` entry. |

---

## 11. Known Limitations

| Limitation | Impact |
|---|---|
| **I/O-thread self-destruction UAF -- RESOLVED (S-3, 2026-06-12).** Formerly: destroying a `Transport` from inside one of its own I/O-thread callbacks froze `~Impl` over the still-unwinding engine dispatch. | **Fixed.** The single-threaded sole-owner case takes the deferred-self-destruct (`scheduleSelfDestruct` runs `~Impl` on the detached I/O thread's post-`loop()` epilogue, 4.10); the concurrent case (finding C-1) is excluded **structurally** by the shared-ownership model. `operator=` deleted; interim `std::abort()` sites removed. Covered by `tests/network/transport_teardown_harness.cpp` with the `IORA_DISABLE_SELFDESTRUCT_DEFERRAL` negative control. |
| **CF-H1 send validation has a narrow TOCTOU.** `sessionSendable` checks presence-and-open under the session read lock; a close racing right after the check still enqueues a send that `doSend` drops. | Accepted: shrinks the false-OK window from "always" to a rare race; cannot be closed without holding `_sessionRwMutex` across enqueue + dispatch. |
| **`sendSync` completion is engine-acceptance, not wire delivery.** For the current TCP/UDP engines the `SendCompleteCallback` fires on post-copy acceptance, so the timeout rarely elapses. | The parked-waiter machinery is forward-correct for a future engine that defers completion (e.g. a TLS flush); today `sendSync` effectively returns immediately. |
| **TSan not run in CI for this work.** The container blocks the `personality(ADDR_NO_RANDOMIZE)` change ThreadSanitizer requires. | Verified with ASan + stress instead. Data-race coverage on the non-atomic counters relies on the lock discipline + ASan, not TSan. |
| **`ReadMode::Disabled` on UDP still drops data in user space.** TCP now removes the fd from `EPOLLIN` via `engine->setReadEnabled(sid, false)` (C5), so no further reads are scheduled; UDP's shared per-listener socket cannot disable read per session (`setReadEnabled` is a no-op there), so the `onData` callback-level drop remains the fallback (also for TCP bytes already in flight when read was disabled). | TCP no longer wastes `recv()` syscalls for a Disabled session; UDP does, but the drop is functionally correct. |
| **Test gaps (deterministic drain-before-teardown / TLS-connectSync terminal-event regression).** Not implemented as harness scenarios. | Need a `shutdownDrain` sleep hook / a TLS client fixture / an `SSL_new` injection seam. The behaviors are correct by construction and covered indirectly. |
