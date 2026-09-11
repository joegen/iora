# Iora Transport -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.7 |
| **Date** | 2026-09-11 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/network/transport.hpp` |
| **Namespace** | `iora::network` |
| **Dependencies** | Split-header set: `include/iora/network/transport_types.hpp` (config, stats, enums, callbacks, `TlsClientOptions`, `CancellationToken`, sync-timeout sentinels) and `include/iora/network/transport_impl.hpp` (all method definitions -- include in exactly one TU; pulls in `detail/tcp_engine.hpp`, `detail/udp_engine.hpp`, `detail/engine_base.hpp`). Shared helpers in `include/iora/network/sockaddr_utils.hpp` (`addressFromSockaddr`, `toSockaddr`, `applyDscpToFd`). Foundation types: `iora::core::Result<T,E>` (`include/iora/core/result.hpp`), `iora::core::BufferView` (`include/iora/core/buffer_view.hpp`), `iora::network::BatchProcessingStats` (`include/iora/network/event_batch_processor.hpp`). Linux-only (epoll/eventfd/timerfd). |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-03-21 | Initial implementation (Phase 1 transport refactor). |
| 1.1 | 2026-03-23 | Engine consolidation: `TcpEngine` and `UdpEngine` implement `EngineBase` directly. Class and file renames. `sync_async_transport.hpp` deleted. |
| 1.2 | 2026-03-23 | Engine improvements: address introspection with `shared_mutex`, callback-under-lock fix (copy-then-invoke at all sites), legacy type removal (engines use `TransportConfig`/`EngineBase::Callbacks` directly), `EventBatchProcessor` wired into engine loops. |
| 1.3 | 2026-06-12 | **S-3 shared-ownership model**: `Transport` is shared-ownership-only -- private `PrivateTag` ctors, `tcp()`/`udp()` return `std::shared_ptr<Transport>`, `enable_shared_from_this` base, move+copy deleted. Closes the C-1 concurrent-teardown use-after-free structurally. |
| 1.4 | 2026-06-14 | `TcpEngine _eventFd` teardown-race fix: enqueue eventfd wakeup-`write` serialized with the `shutdownDrain` eventfd `close` under `_cmdMutex`; command-queue teardown flag added. |
| 1.5 | 2026-06-14 | `UdpEngine _eventFd` teardown-race fix (sibling of 1.4), plus the UDP `connectViaListener()` closed-queue reject. |
| 1.6 | 2026-09-11 | **Migrated to `docs/network/` and re-verified against the current source.** Restructured toward the 12-section guide template (added a dedicated Call Flow / Sequence Reference section). Corrected stale claims: removed the deleted `autoHealthMonitoring` config field; removed `setDscp()` from the public facade (it is engine-internal -- DSCP is set at construction via `config.dscpValue`); moved `maxSessions` and `listenBacklog` to their real config sections with correct defaults; added the `resolveTimeout` and `syncBufferGcThreshold` config fields, the `BufferOverflow`/`ShuttingDown` `TransportError` values, the per-connection TLS-identity overloads and the `kHttpsHostFlags` constant, and the `isOnIoThread()` accessor. |
| 1.7 | 2026-09-11 | **Re-synced to landed source.** (1) Collapsed the duplicate System-Architecture and Component-Deep-Dive headers into the clean canonical 12-section order. (2) `sendSync` now **blocks** until send completion (was fire-and-forget), is gated by the concurrent-sync-op cap, and can return the new `TransportError::TooManyPendingSyncOps`; the teardown gate now counts `activeSends` as a fourth counter. (3) Documented the `kUseConfigSyncTimeout`/`kFallbackSyncTimeout` sync-timeout sentinels and `resolveSyncTimeout()`. (4) `ReadMode::Disabled` now suppresses reads at the fd level (`engine->setReadEnabled`, EPOLLIN removed) on TCP; UDP remains drop-at-callback. (5) Send validation (CF-H1): engines reject a `send` to a session not present-and-open (`sessionSendable`); connect-then-send must await `onConnect`. (6) UDP `connectSync` now parks like TCP (short-circuit removed). (7) Documented `dscpValue` at-creation application via the shared `applyDscpToFd` helper (IPV6_TCLASS primary + best-effort IP_TOS on dual-stack). |

---

## 1. Executive Summary

### Problem

Before the transport refactor, iora carried multiple overlapping transport abstractions: four separate config types, three stats types, and a `sync_async_transport.hpp` wrapper layered over raw engine classes. Consumers had to know which of several near-identical types a given API expected, and the sync/async split lived in a distinct wrapper class rather than in one coherent object. Higher layers (SIP, HTTP) had no single interface to mock, so tests reached for real sockets.

### Solution

`include/iora/network/transport.hpp` provides one interface and one concrete class:

- **`iora::network::ITransport`** -- a pure-virtual interface that is the entire public API contract; higher layers accept `ITransport&` so they can be tested against a `TestTransport` double.
- **`iora::network::Transport`** -- the concrete, `final`, shared-ownership-only implementation. It owns exactly one protocol engine (`detail::TcpEngine` for TCP/TLS, or `detail::UdpEngine` for UDP) behind `std::unique_ptr<detail::EngineBase>`; both engines derive from `EngineBase` directly, with no wrapper class between them and `Transport`.
- **`iora::network::TransportConfig`** -- one config struct covering timeouts, I/O tuning, socket options, TLS, batching, rate limiting, and sync-operation settings, with five factory presets (`forSipTcp`, `forSipUdp`, `forHighThroughput`, `forLowLatency`, `minimal`).
- **`iora::network::TransportStats`** -- one 16-field stats snapshot plus an optional `BatchProcessingStats`.
- **`Result<T, TransportErrorInfo>`** -- every fallible operation returns a `Result`, enabling composable, monadic error handling.

### Technical Impact

- **One type per concern.** One interface, one config, one stats, one error descriptor -- no adapter/wrapper indirection on the data path.
- **Zero-copy read path.** `DataCallback` receives an `iora::core::BufferView` over the engine's read buffer plus a `steady_clock` receive timestamp captured at the `recv()` call site (critical for RTP jitter), so downstream parsers work without a copy.
- **Structurally safe teardown.** Shared ownership guarantees any thread invoking a method co-owns the `Transport` for the call's duration, so `~Transport` can never race a concurrent call on the I/O thread (closes finding C-1).
- **Split-header isolation.** `transport.hpp` never leaks epoll/OpenSSL headers into consumers; the heavy definitions live in `transport_impl.hpp`, included in exactly one translation unit.

---

## 2. System Architecture

### 2.1 Component relationships

```
transport.hpp (public -- lightweight; forward-declares detail::EngineBase, no engine headers)
|
|-- #include "transport_types.hpp"
|     |-- TransportConfig            (timeouts, I/O, socket, sync, TLS, batching, rate limiting; 5 presets)
|     |-- TransportStats             (16 counter/gauge fields + optional BatchProcessingStats)
|     |-- TransportErrorInfo         (code + message + sysErrno + tlsError -- pure error descriptor)
|     |-- TlsClientOptions           (per-connection SNI + cert-identity verification; data-only)
|     |-- TransportAddress, TransportEvent, CancellationToken, ReadMode
|     |-- Protocol / TlsMode / TransportError / ErrorSeverity enums
|     |-- Result<T,E> aliases        (StartResult, ListenResult, ConnectResult, SendResult, ReceiveResult)
|     |-- Callback typedefs          (Accept/Connect/Data/Close/Error/SendComplete/SessionCleanup)
|     |-- SessionId / ListenerId / ObserverId aliases  (all std::uint64_t)
|     |-- kUseConfigSyncTimeout / kFallbackSyncTimeout   (sync-op timeout sentinels)
|     `-- kHttpsHostFlags / kSipHostFlags ...            (host-verification bitmask constants)
|
|-- ITransport (pure-virtual interface -- the entire public API contract)
|     |-- Lifecycle:      start, stop, isRunning, lastError
|     |-- Connection:     addListener, connect (2 overloads), connectViaListener, close
|     |-- Async data:     send(BufferView), sendAsync(BufferView, cb)   [+ raw-ptr default overloads]
|     |-- Sync ops:       connectSync (2 overloads), sendSync, receiveSync  [+ *Cancellable defaults]
|     |-- Read modes:     setReadMode, getReadMode
|     |-- Callbacks:      onAccept, onConnect, onData, onClose, onError
|     |-- Observers:      observe, unobserve
|     |-- Introspection:  getListenerAddress, getLocalAddress, getRemoteAddress
|     |-- User data:      setSessionData, getSessionData
|     `-- Stats:          getStats, getProtocol
|
`-- Transport final : public ITransport, public std::enable_shared_from_this<Transport>
      |-- struct PrivateTag                       (passkey: ctors callable only by the factories)
      |-- static tcp(config) / udp(config)        -> std::shared_ptr<Transport>   (only public ctor surface)
      |-- static withEngine(engine, config)       -> std::shared_ptr<Transport>   (private DI/test seam)
      |-- isOnIoThread()                          (Transport-specific; NOT on ITransport)
      `-- struct Impl (pimpl -- all internal state; see 3.13)

transport_impl.hpp (include in exactly ONE .cpp file)
|-- #include "transport.hpp" + detail/tcp_engine.hpp + detail/udp_engine.hpp
|-- Transport::Impl definition + setupEngineCallbacks()   (wires engine events -> Transport dispatch)
|-- Transport ctor/dtor/factory definitions (tcp/udp/withEngine)
|-- all Transport method definitions
`-- ITransport default implementations for the *Cancellable methods

detail/engine_base.hpp (internal -- not public API)
|-- detail::EngineBase (abstract): Callbacks struct, lifecycle, connection, data, stats,
|     address introspection, setDscp, setReadEnabled, getIoThreadId/isOnIoThread,
|     scheduleSelfDestruct/detachForTermination
|-- detail::TcpEngine : EngineBase     (TCP/TLS engine)
`-- detail::UdpEngine : EngineBase     (UDP engine)
```

### 2.2 Split-header pattern

The transport avoids leaking engine implementation headers (epoll, OpenSSL) into consumer code:

- **`transport.hpp`** -- `ITransport` + `Transport` declarations. Forward-declares `detail::EngineBase`. Safe to include broadly.
- **`transport_types.hpp`** -- all types, enums, config, stats, callbacks. OpenSSL-include-free (so non-TLS TUs can include it); included by `transport.hpp`.
- **`transport_impl.hpp`** -- all `Transport` method definitions; includes the engine headers. Must be included in exactly **one** translation unit per binary.

```cpp
// In your_app.cpp (exactly one TU):
#include <iora/network/transport_impl.hpp>

// In every other file:
#include <iora/network/transport.hpp>
```

### 2.3 Data flow

```mermaid
sequenceDiagram
  participant U as User thread
  participant E as Engine (epoll I/O thread)
  participant CB as Transport dispatch (setupEngineCallbacks)
  participant App as User callback

  U->>E: transport->send(sid, data)
  Note over E: sessionSendable(sid) check (CF-H1);<br/>enqueue on write queue; write eventfd to wake epoll
  E->>E: epoll_wait returns (writable): write to socket
  E->>E: epoll_wait returns (readable): recv();<br/>capture receiveTime = steady_clock::now()
  E->>CB: engine onData(sid, BufferView, receiveTime)
  Note over CB: check ReadMode under syncMutex
  alt ReadMode::Async
    CB->>CB: copy onDataCb under callbackMutex; release
    CB->>App: onDataCb(sid, data, receiveTime)  [no locks held]
  else ReadMode::Sync
    CB->>CB: append to SyncReceiveBuffer; notify parked receiveSync
  else ReadMode::Disabled
    CB->>CB: drop the data (TCP has already removed EPOLLIN via setReadEnabled)
  end
```

### 2.4 Threading model

| Thread | Responsibility |
|---|---|
| Caller / application thread | Calls the public API (`start`, `addListener`, `connect`, `send`, the sync ops, callback setters, `observe`, introspection). Sends enqueue a command to the I/O thread via eventfd; the rest acquire a Transport-level lock briefly. |
| Engine I/O thread (one per engine) | Runs the epoll loop, performs socket I/O, and fires the engine `Callbacks` into `Transport`'s dispatch handlers. Every user callback runs on this thread. |
| First caller of a sync op | Blocks on a `std::condition_variable` under `syncMutex` until the I/O thread signals completion (or timeout). `connectSync`, `receiveSync`, and now `sendSync` all park this way. |

### 2.5 `Result<T,E>` integration

All fallible `Transport` operations return `Result<T, TransportErrorInfo>` via these aliases:

| Alias | Expands to | Used by |
|-------|-----------|---------|
| `StartResult` | `Result<void, TransportErrorInfo>` | `start()` |
| `ListenResult` | `Result<ListenerId, TransportErrorInfo>` | `addListener()` |
| `ConnectResult` | `Result<SessionId, TransportErrorInfo>` | `connect()`, `connectSync()`, `connectViaListener()`, `connectSyncCancellable()` |
| `SendResult` | `Result<std::size_t, TransportErrorInfo>` | `sendSync()`, `SendCompleteCallback` |
| `ReceiveResult` | `Result<std::size_t, TransportErrorInfo>` | `receiveSync()`, `receiveSyncCancellable()` |

```cpp
transport->addListener("0.0.0.0", 5060)
  .map([](iora::network::ListenerId lid) { /* listening */ return lid; })
  .mapError([](const iora::network::TransportErrorInfo &err) { /* log err.message */ return err; });
```

### 2.6 Facade summary

`Transport` is a thin, thread-safe facade over one protocol engine:

- **Ownership:** `std::shared_ptr<Transport>` outer, `std::unique_ptr<Impl>` pimpl, `std::unique_ptr<detail::EngineBase>` engine. One protocol per instance; compose two `Transport` objects for a dual-stack (e.g. SIP over UDP + TCP).
- **Concurrency domains:** four independent Transport-level mutexes (`callbackMutex`, `syncMutex`, `observerMutex`, `userDataMutex`) plus the engine's internal locks, held only by the I/O thread. The two domains never nest in a way that forms a cycle (§6).
- **The one invariant that governs everything:** no user-facing lock is held while a user callback runs (copy-then-invoke / copy-then-iterate).

---

## 3. Component Deep Dive

### 3.1 `ITransport` -- the interface

`ITransport` is a single abstract class -- the entire public API contract. `Transport` (production) and `TestTransport` (test double, defined separately) both implement it; higher layers accept `ITransport&` for testability.

Core methods are pure virtual. A handful of convenience methods have **default implementations** in `transport_impl.hpp` that delegate to the pure-virtual core, so a test double need not reimplement them:

| Group | Pure virtual | Default implementations |
|-------|-------------|------------------------|
| Lifecycle | `start`, `stop`, `isRunning`, `lastError` | -- |
| Connection | `addListener`, `connect` (both overloads), `connectViaListener`, `close` | -- |
| Async data | `send(BufferView)`, `sendAsync(BufferView, cb)` | `send(void*, size)`, `sendAsync(void*, size, cb)` |
| Sync connect | `connectSync` (both overloads) | `connectSyncCancellable` |
| Sync data | `sendSync`, `receiveSync` | `sendSyncCancellable`, `receiveSyncCancellable` |
| Read modes | `setReadMode`, `getReadMode` | -- |
| Callbacks | `onAccept`, `onConnect`, `onData`, `onClose`, `onError` | -- |
| Observers | `observe`, `unobserve` | -- |
| Introspection | `getListenerAddress`, `getLocalAddress`, `getRemoteAddress`, `setSessionData`, `getSessionData` | -- |
| Stats | `getStats`, `getProtocol` | -- |

The raw-pointer send defaults wrap the pointer+length in a `BufferView` and delegate; the `*Cancellable` defaults check the token, then run a short sub-timeout loop around the core sync op so `CancellationToken::cancel()` is observed between iterations (see §5.4).

### 3.2 `Transport` -- the concrete class

`Transport` is `final` and **shared-ownership-only**: it is neither copyable nor movable, derives from `std::enable_shared_from_this<Transport>`, and exists **only** inside a `std::shared_ptr<Transport>`.

**Construction.** The only public construction surface is the two protocol factories, which return a `std::shared_ptr<Transport>` and never start or bind:

```cpp
static std::shared_ptr<Transport> tcp(TransportConfig config = {});
static std::shared_ptr<Transport> udp(TransportConfig config = {});
```

The constructors are tag-gated (a private `PrivateTag` passkey) so `std::make_shared` works -- a single allocation, `enable_shared_from_this`-compatible -- without exposing a public constructor. The chosen factory sets `config.protocol`, builds the matching engine, and calls `setupEngineCallbacks()`:

```cpp
if (_impl->config.protocol == Protocol::TCP)
{
  _impl->engine = std::make_unique<TcpEngine>(_impl->config);
}
else
{
  _impl->engine = std::make_unique<UdpEngine>(_impl->config);
}
_impl->setupEngineCallbacks();
```

A private `static std::shared_ptr<Transport> withEngine(std::unique_ptr<detail::EngineBase>, TransportConfig)` factory is the dependency-injection seam; engine-level fault-injection tests reach it through the `test::TransportEngineInjector` friend (whose definition lives only in a test-only header).

**Usage.** Because the handle is a `shared_ptr`, call through `->`:

```cpp
auto transport = iora::network::Transport::tcp();   // std::shared_ptr<Transport>
transport->start();
transport->connect("example.com", 443, iora::network::TlsMode::Client);
```

**Lifecycle invariant.** After construction, `isRunning()` returns `false`; the caller must call `start()` explicitly. The destructor runs the teardown handshake on a non-I/O thread, or the deferred-self-destruct on the I/O thread (a sole owner dropping its last reference from inside its own callback). The buffer-lifecycle mechanics of that handshake are owned by the sync-lifecycle deep dive.

> **Deep dive: [transport_sync_lifecycle.md](transport_sync_lifecycle.md)** -- the blocking sync facade's buffer lifecycle and teardown safety: `SyncReceiveBuffer` + the GC gate, `receiveSync`/`connectSync`/`sendSync` parking, and the four-counter (`activeReceives` / `activeConnects` / `activeFlushes` / `activeSends`) teardown handshake that the destructor and `performTeardown()` run before `_impl` is freed.

**Move/copy semantics: all deleted.** The move ctor, move assignment, copy ctor, and copy assignment are `= delete`. Ownership is shared by copying the `shared_ptr`, never by moving or copying the `Transport`. Deleting move-assignment also removes the former `operator=` teardown path -- the most hazardous teardown code.

#### 3.2.1 Why shared-ownership-only (S-3)

The old move-only value model permitted a use-after-free (finding **C-1**): a `Transport` destroyed from inside one of its own I/O-thread callbacks **while another thread concurrently calls `stop()`**. Making `std::shared_ptr<Transport>` the only ownership model closes this **structurally**: any thread invoking a method holds an owning `shared_ptr` for the call's duration, so an I/O-thread callback can never drop the **last** reference mid-call -- therefore `~Transport` never runs on the I/O thread concurrently with another thread's call. The lone remaining I/O-thread `~Transport` path is a *sole* owner dropping its last reference inside its own callback (single-threaded), handled by the deferred-self-destruct in the sync-lifecycle deep dive.

**Reference-cycle invariant (binds all consumers).** Because a `Transport` is shared and owns its engine which owns the callbacks, a callback (engine or user) must **never** capture an owning `std::shared_ptr<Transport>` of its own `Transport`, nor an owning `shared_ptr` of an object that owns that `Transport` -- either forms a cycle that never collects. Capture the raw `this`/`Impl*` (as the in-library dispatch does), or a `std::weak_ptr` promoted per-use where a callback must keep an owner alive across an async boundary (as `DnsTransport` does).

#### 3.2.2 `isOnIoThread()` -- a Transport-specific accessor

```cpp
bool isOnIoThread() const noexcept;
```

Returns `true` iff the calling thread is this transport's engine I/O thread. It reads an atomic stamped at loop entry and cleared at loop exit, so it is **race-free** and safe to call from any thread concurrently with `start()`/`stop()`; it returns `false` when there is no running I/O thread (pre-start, post-stop, post-detach). Higher layers (e.g. iora_sip) use it to refuse a lifecycle mutation that would otherwise execute on the I/O thread -- such as destroying a transport from within its own callback. This method is **not** part of `ITransport`; it is a `Transport`-only accessor.

### 3.3 `TransportConfig`

One config struct covering all protocol and feature settings; protocol-specific fields are simply ignored when not applicable. See §7 for the full field table with exact defaults. The logical sections are: Protocol, Timeouts, I/O, Socket, Sync operations, TLS, Batching, and Rate limiting, plus five factory presets.

### 3.4 `TransportStats`

A snapshot of engine statistics; all counters start at `0`. Sixteen fields (four connection counters, two TLS counters, two data counters, two engine counters, three GC counters, one backpressure counter, and two session gauges), plus `std::optional<BatchProcessingStats> batchingStats` -- populated when batching is enabled, `std::nullopt` otherwise. See §7.4 for the field-by-field table.

### 3.5 `TransportErrorInfo` and `TransportError`

`TransportErrorInfo` is a pure error descriptor -- it carries no success/failure state; success or failure is expressed structurally by which variant of `Result<T, TransportErrorInfo>` it sits in.

```cpp
struct TransportErrorInfo
{
  TransportError code{TransportError::Unknown};
  std::string message;
  int sysErrno{0};
  int tlsError{0};
};
```

`TransportError` enumerates error categories:

| Value | Meaning |
|-------|---------|
| `None` | No error |
| `Socket` | Socket creation/operation failure |
| `Resolve` | Host resolution failure |
| `Bind` | Bind failure (address in use, permission denied) |
| `Listen` | Listen failure |
| `Accept` | Accept failure |
| `Connect` | Connection refused or failed |
| `TLSHandshake` | TLS handshake failure |
| `TLSIO` | TLS read/write error |
| `PeerClosed` | Remote peer closed the connection |
| `WriteBackpressure` | Write queue overflow |
| `Config` | Configuration error (also returned by `lastError()` when the transport is uninitialized) |
| `GCClosed` | Closed by garbage collection (idle/age) |
| `Cancelled` | Operation cancelled via `CancellationToken`, or a rejected overlapping sync op |
| `Timeout` | Operation timed out |
| `BufferOverflow` | Sync receive buffer exceeded `maxSyncReceiveBuffer` (data dropped; terminal for that session's buffer) |
| `ShuttingDown` | Transport is being torn down; the sync op was released without completing |
| `TooManyPendingSyncOps` | The concurrent parked-sync-op cap (`config.maxPendingSyncOps`) was reached; the sync op (`connectSync`/`sendSync`/`receiveSync`) was rejected rather than parked |
| `Unknown` | Unclassified error |

### 3.6 Callback model

`Transport` uses five individual setter methods; each setter **replaces** the previous callback (there is no chaining on the global callbacks -- use observers for per-session multi-dispatch).

| Setter | Callback signature | Fires when |
|--------|-------------------|------------|
| `onAccept(cb)` | `void(SessionId, const TransportAddress&)` | New connection accepted (success only) |
| `onConnect(cb)` | `void(SessionId, const TransportAddress&)` | Outbound connection established (success only; **not** fired for `connectSync`) |
| `onData(cb)` | `void(SessionId, BufferView, steady_clock::time_point)` | Data received (`ReadMode::Async` only) |
| `onClose(cb)` | `void(SessionId, const TransportErrorInfo&)` | Session closed (all reasons; **not** fired for a `connectSync` session that never escaped to the user) |
| `onError(cb)` | `void(TransportError, const std::string&)` | Transport-level error with no `SessionId` |

Key points:

- **`onAccept`/`onConnect` fire only on success.** Failed accepts are engine-internal retries; failed connects surface via `onClose` (per-session) or `onError` (transport-level).
- **`onData` receives a `BufferView`** -- a non-owning, zero-copy view over the engine's read buffer, which is reused after the callback returns. Copy the data if you need it beyond the callback.
- **`onData` receives `receiveTime`** -- a `steady_clock::time_point` captured immediately after `recv()`/`recvfrom()`, before any peer lookup. Critical for RTP jitter.
- **`onError` carries no `SessionId`** -- it is for non-session transport-level errors (bind failure, epoll error, TLS context init). Per-session errors arrive through `onClose`.

**Copy-then-invoke (HR-6).** Every Transport dispatch handler acquires the relevant mutex only to copy the `std::function` (or observer vector), releases the lock, then invokes the copy -- so **no user callback is ever invoked while a Transport-level lock is held**:

```cpp
cbs.onAccept = [this](SessionId sid, const TransportAddress &addr)
{
  AcceptCallback cb;
  {
    std::lock_guard<std::mutex> lk(callbackMutex);
    cb = onAcceptCb;                 // copy under lock
  }
  if (cb)
  {
    cb(sid, addr);                   // invoke with NO locks held
  }
};
```

Because of this, a callback may safely re-enter the transport (`send`, `close`, `observe`, `unobserve`, `getStats`, `getSessionData`, `setSessionData`). The runtime-guarded exceptions -- `connectSync`/`sendSync`/`receiveSync`/`setReadMode`/`stop`/`addListener` -- are covered in §6.6.

### 3.7 Per-session observers

Observers solve the problem of multiple consumers sharing one session, each needing notification when it closes. The global `onClose` is a single slot; observers provide per-session multi-dispatch.

```cpp
ObserverId oid = transport->observe(sid, [](SessionId sid, const TransportErrorInfo &reason)
{
  // clean up resources tied to this session
});
transport->unobserve(oid);
```

Semantics:

- `observe()` returns a unique `ObserverId` (monotonically increasing, `std::atomic<ObserverId>` seeded at 1).
- Multiple observers may be registered per session.
- Observer callbacks fire **after** the global `onClose`, in registration order.
- All observers for a session are automatically removed when the session closes.
- `unobserve()` returns `true` if the observer existed and was removed.

**Close-flow ordering** (from the engine `onClose` dispatch handler):

1. `connectSync` check -- if `sid` is a pending sync connect, deliver the failure to the blocking caller and return; the global `onClose`, observers, and user-data cleanup are all suppressed (the session never escaped to the user).
2. Global `onClose` invoked (copy-then-invoke under `callbackMutex`).
3. Observer list copied and observer maps cleaned up under `observerMutex`; the lock is released.
4. Each observer invoked from the local copy (copy-then-iterate, HR-7).
5. Parked `receiveSync` (if any) woken via the buffer's `closed` flag; otherwise a tombstone buffer is left so a late `receiveSync` returns immediately. Stale tombstones are GC'd when the buffer map exceeds `syncBufferGcThreshold`.
6. `readModes[sid]` erased.
7. User-data cleanup callback invoked **last** (HR-11), after being extracted and removed under `userDataMutex`.

**Reentrant safety.** An observer that calls `close()` on the same session is a no-op (already closing); one that calls `unobserve()` on its own id is safe (copy-then-iterate); one that calls `close()`/`observe()` on a different session is safe (different observer list).

### 3.8 Session introspection and user data

**Address queries** delegate straight to the engine, which serves them under a `shared_lock` on its session/listener maps (the I/O thread takes a `unique_lock` only when inserting/removing entries), so introspection has near-zero contention:

```cpp
TransportAddress getListenerAddress(ListenerId lid) const;  // bound address of a listener
TransportAddress getLocalAddress(SessionId sid) const;      // local side of a connection
TransportAddress getRemoteAddress(SessionId sid) const;     // remote side of a connection
```

All three return an empty `TransportAddress{}` if the session/listener is unknown or its fd has been closed.

> **Note on DSCP.** There is **no** public per-session `setDscp()` on the facade. DSCP marking is configured once at construction via `TransportConfig::dscpValue` and applied by the engine **when the socket is created**, via the shared helper `iora::network::applyDscpToFd(fd, dscp)` (`sockaddr_utils.hpp`). The helper writes the DSCP value into the high 6 bits of the TOS / traffic-class byte: for `AF_INET6` it sets `IPV6_TCLASS` (the family-primary option) plus a best-effort `IP_TOS` so a dual-stack socket carrying an IPv4-mapped peer still marks the mapped-IPv4 egress; for `AF_INET` it sets `IP_TOS`. Both engines forward to this one helper (it was formerly a byte-identical private static in each). The engine also exposes a per-session `setDscp(SessionId, uint8_t)` internally, but that is not part of `ITransport`/`Transport`. (On WSL2, loopback does not deliver `IP_RECVTOS` ancillary data, so tests verify the mark with a local `getsockopt(fd, IP_TOS / IPV6_TCLASS)` readback rather than by observing a received packet.)

**User data** -- one `void*` slot per session with an optional cleanup callback:

```cpp
transport->setSessionData(sid, ctx, [](void *data) { delete static_cast<MyContext *>(data); });
auto *ctx = static_cast<MyContext *>(transport->getSessionData(sid));
```

- One slot per session; compose multiple libraries' data into one struct if needed.
- The cleanup callback fires when the session closes, **after** all observers (step 7 of the close flow).
- Calling `setSessionData` again **replaces** the slot without invoking the previous cleanup -- the caller must clean up the old value before replacing it.
- `getSessionData` returns `nullptr` if nothing was set or the session is unknown.

### 3.9 Sync operations (facade overview)

Synchronous operations are methods on `Transport`, not a separate wrapper layer. They block the calling thread on a `std::condition_variable` under `syncMutex`, and they **throw `std::logic_error` if called from the I/O thread** (they would deadlock waiting for the thread that signals them). Their internal buffer lifecycle and the teardown handshake that keeps a parked waiter from being freed out from under it are owned by the sync-lifecycle deep dive; this section covers only the facade-level contract.

**Timeout sentinels.** The primary sync ops (`connectSync`, `sendSync`, `receiveSync`) default their `timeout` parameter to the sentinel `kUseConfigSyncTimeout` (a `-1 ms` value defined in `transport_types.hpp`). At the top of each op, `Impl::resolveSyncTimeout()` maps any negative value to `config.defaultSyncTimeout` -- so the SIP presets' tuned timeouts (`forSipTcp` 32000 ms, `forSipUdp` 500 ms) apply by default. A misconfigured non-positive `defaultSyncTimeout` is floored to `kFallbackSyncTimeout` (30000 ms) so a sync op never silently degrades to a non-blocking poll; an explicit non-negative timeout (including `0` = non-blocking) is respected as-is. The `*Cancellable` variants are `ITransport` methods with no config access, so they default to the literal `kFallbackSyncTimeout` instead.

**`connectSync`** -- blocks until the TCP handshake (and optional TLS handshake) completes, or the timeout expires. It calls the async `connect()`, registers a pending operation in `pendingConnects`, and waits on a CV that the engine `onConnect` handler signals; the global `onConnect` is **not** fired. **UDP now parks in `pendingConnects` exactly like TCP** (the former short-circuit that returned immediately was removed): it returns only once the I/O thread has registered the session and fired `onConnect`, so the returned `sid` is immediately usable by a subsequent send and does not race the async session insert against the send-time `sessionSendable` check (below). On timeout the pending entry is retained so the eventual `onClose` reaps it and suppresses the spurious global `onClose`; the session is closed and `TransportError::Timeout` is returned. If teardown has begun, it returns `TransportError::ShuttingDown`; if the concurrent-sync-op cap is reached, `TransportError::TooManyPendingSyncOps`.

```cpp
ConnectResult connectSync(const std::string &host, std::uint16_t port,
                          TlsMode tls = TlsMode::None,
                          std::chrono::milliseconds timeout = kUseConfigSyncTimeout);
ConnectResult connectSync(const std::string &host, std::uint16_t port, TlsMode tls,
                          const TlsClientOptions &opts,
                          std::chrono::milliseconds timeout = kUseConfigSyncTimeout);
```

The four-argument-plus-timeout overload threads per-connection TLS client identity (see §3.11).

**`sendSync`** -- **blocks until the engine signals send completion** (or the timeout elapses) and returns the byte count on success. It registers a completion op under `syncMutex`, issues the async send (without holding the lock, since the engine may fire the completion synchronously on this thread), and parks on the op's CV that the engine's `SendCompleteCallback` signals; the parked sender is counted in the teardown gate via `activeSends`. It is gated by the concurrent-sync-op cap and returns `TransportError::TooManyPendingSyncOps` when `config.maxPendingSyncOps` parked sync ops are already in flight, and `TransportError::ShuttingDown` if teardown has begun. For the current TCP/UDP engines "completion" is the synchronous post-copy acceptance of the bytes into the engine (not wire transmission or a TLS flush), so completion is effectively immediate today (UDP always; TCP on enqueue) and the timeout rarely elapses -- the parked-waiter machinery is forward-correct for a future engine that defers completion.

**`receiveSync`** -- blocks until data is available in the session's sync receive buffer. The session must be in `ReadMode::Sync`. It copies available bytes into the caller's buffer, sets `len` to the actual count, and returns. It enforces a **single-waiter contract** per session (a second concurrent `receiveSync`, or overlap with a `Sync->Async` flush, returns `TransportError::Cancelled`). If the buffer overflowed it returns `TransportError::BufferOverflow` (terminal -- the caller must close the session); if the peer closed after draining, `TransportError::PeerClosed`; if teardown began, `TransportError::ShuttingDown`; if the concurrent-sync-op cap is reached, `TransportError::TooManyPendingSyncOps`.

> **Send validation (CF-H1).** Both engines reject a `send` to a session that is not currently present-and-open, via `sessionSendable(sid)`: `send()` returns `false` for an unknown or closing session instead of silently enqueuing a command the engine would later drop (which used to return `true`, masking a dead connection from SIP RFC 3263 failover). A connect-then-send consumer must therefore **await `onConnect`** (or use `connectSync`, which returns only a usable session) before sending -- FIFO command ordering between an async `connect` and a following `send` is no longer assumed. The mechanism detail lives in the [sync-lifecycle deep dive](transport_sync_lifecycle.md).

> **Deep dive: [transport_sync_lifecycle.md](transport_sync_lifecycle.md)** -- `SyncReceiveBuffer` fields and invariants, drain-before-close ordering, the tombstone-GC gate, and the four-counter teardown handshake.

### 3.10 Read modes

Each session operates in one of three read modes:

| Mode | Behavior |
|------|----------|
| `ReadMode::Async` | Data delivered via `onData` (default) |
| `ReadMode::Sync` | Data buffered for `receiveSync()` retrieval |
| `ReadMode::Disabled` | Reads suppressed. On TCP the engine removes the session's fd from `EPOLLIN` (no further `recv()`); on UDP (one shared socket) the data is dropped in the dispatch handler. |

```cpp
bool setReadMode(SessionId sid, ReadMode mode);        // false if allowReadModeSwitch is disabled
bool getReadMode(SessionId sid, ReadMode &mode) const; // false if the session is unknown
```

Switching behavior:

- **`Sync` -> `Async`:** buffered data is flushed to the `onData` callback with `syncMutex` released before each invocation (HR-6); the mode flips to `Async` once the buffer drains. A concurrent `receiveSync` on the same session is rejected while the flush is in progress.
- **any -> `Sync`:** a receive buffer is created if one does not already exist.
- **any -> `Disabled`:** `setReadMode` calls `engine->setReadEnabled(sid, false)`. On TCP the engine withholds `EPOLLIN` from the session's epoll interest (via `updateInterest`), so no further `recv()` syscall occurs for the session; during a TLS handshake `EPOLLIN` is forced on regardless, since handshake reads are protocol-level, not application data. On UDP many virtual sessions share one socket, so `setReadEnabled` is a no-op that returns `false` and arriving data is dropped in the dispatch handler.
- **`Disabled` -> any:** `engine->setReadEnabled(sid, true)` restores `EPOLLIN` on TCP.
- **`setReadMode` throws `std::logic_error` on the I/O thread** (a flush invokes `onData`, which could delete the transport and self-deadlock the teardown handshake).
- If `config.allowReadModeSwitch` is `false`, `setReadMode` returns `false`.

### 3.11 Per-connection TLS client identity (`TlsClientOptions`)

The four-argument `connect`/`connectSync` overloads accept a `TlsClientOptions` so a TLS client handshake can present a reference identity via SNI and verify the server certificate against it (RFC 6125 / 9525):

```cpp
struct TlsClientOptions
{
  std::string verifyName;      // reference identity (DNS A-label, e.g. "example.com"), or empty
  unsigned    x509HostFlags{0}; // OpenSSL X509_CHECK_FLAG_* bitmask; 0 = none
};
```

The type is **data-only** by design (no `std::function`, no OpenSSL type), so `transport_types.hpp` stays OpenSSL-include-free and can be included by non-TLS TUs. `verifyName` is the reference identity, **distinct from the connect address**: callers pre-resolve to an IP literal before `connect()`, so the connect address is not the domain. An empty `verifyName` falls back to inspecting the connect address (IP literal => no SNI + iPAddress match; resolved name => SNI + DNS match). An IP literal placed in `verifyName` is routed to the no-SNI / iPAddress branch, never sent as SNI.

For HTTPS, pass the macro-free constant `kHttpsHostFlags` (RFC 9525 §6.3: `NEVER_CHECK_SUBJECT | NO_PARTIAL_WILDCARDS`) as `x509HostFlags` so callers such as `http_client.hpp` never need an `<openssl/*>` include; its value is locked to the real OpenSSL macros by a `static_assert` in `tcp_engine.hpp`. `transport_types.hpp` also defines the SIP-flavored constants `kSipHostFlags` (RFC 5922: `NO_WILDCARDS | NEVER_CHECK_SUBJECT`) and `kSipHostFlagsAllowWildcards` for the SIP layer.

> **Deep dive: [transport_dns_resolution.md](transport_dns_resolution.md)** -- moving named-host `getaddrinfo` off the epoll I/O thread (host resolution, not the DNS wire protocol). The `TransportConfig::resolveTimeout` field (§7.1) bounds that off-thread resolve.

### 3.12 Batching (facade overview)

When `TransportConfig::batching.enabled` is `true`, the engine collects multiple epoll events and processes them as a group (`EventBatchProcessor`) instead of handling one event per `epoll_wait`. The design is two-path: `loopBatched()` when enabled, the original `loopUnbatched()` otherwise, so there is zero overhead when batching is off. Adaptive sizing grows or shrinks the per-`epoll_wait` event budget within `[1, maxBatchSize]` based on fill rate and processing time.

From the facade, batching is purely a `TransportConfig` concern (§7.5) plus one observability surface: `TransportStats::batchingStats` is populated when batching is enabled and `std::nullopt` otherwise.

```cpp
auto stats = transport->getStats();
if (stats.batchingStats)
{
  auto &bs = *stats.batchingStats;
  // bs.totalBatches, bs.totalEvents, throughput metrics, adaptive adjustments
}
```

Batching adds up to `maxBatchDelay` of latency (with a 1 ms floor from `epoll_wait`'s millisecond granularity), so it is a throughput/latency trade-off -- enable it for bulk relays, disable it for SIP signaling and RTP media. The engine internals are owned by the engine layer, not this facade.

### 3.13 Internal state (`Transport::Impl`)

All internal state lives behind a pimpl (`struct Impl`, defined in `transport_impl.hpp`):

| Field group | Members | Guarded by |
|---|---|---|
| Config / engine | `TransportConfig config`, `std::unique_ptr<detail::EngineBase> engine` | -- (config is const after construction; engine is single-owner) |
| Global callbacks | `onAcceptCb`, `onConnectCb`, `onDataCb`, `onCloseCb`, `onErrorCb` | `callbackMutex` |
| Sync ops + teardown | `pendingConnects`, `pendingSends`, `readModes`, `receiveBuffers`, `pendingSyncOps` (concurrent-op cap counter), and the teardown counters `shuttingDown` / `activeReceives` / `activeConnects` / `activeFlushes` / `activeSends` + `teardownCv` | `syncMutex` |
| Observers | `observers` (session -> vector of `{ObserverId, CloseCallback}`), `observerToSession`, `nextObserverId` | `observerMutex` (id counter is atomic) |
| User data | `sessionData` (session -> `{void*, SessionCleanupCallback}`) | `userDataMutex` |

`setupEngineCallbacks()` builds an `EngineBase::Callbacks` whose five lambdas capture the raw `this` (Impl) and route each engine event through the copy-then-invoke dispatch described in §3.6-3.7. The detailed field-by-field semantics of the sync buffers and the teardown handshake are documented in the sync-lifecycle deep dive; this facade guide treats them as an opaque, correctly-synchronized substrate.

---

## 4. Usage Guide

### 4.1 TCP echo server

```cpp
#include <iora/network/transport_impl.hpp>   // include in exactly ONE .cpp file
#include <iostream>
#include <thread>

int main()
{
  auto transport = iora::network::Transport::tcp();

  transport->onAccept([](iora::network::SessionId sid,
                         const iora::network::TransportAddress &peer)
  {
    std::cout << "accepted " << peer.host << ":" << peer.port << "\n";
  });

  transport->onData([transport](iora::network::SessionId sid,
                                iora::core::BufferView data,
                                std::chrono::steady_clock::time_point)
  {
    transport->send(sid, data);   // echo back (safe to call from a callback)
  });

  auto started = transport->start();
  if (!started)
  {
    std::cerr << "start failed: " << started.error().message << "\n";
    return 1;
  }

  auto listening = transport->addListener("0.0.0.0", 8080);
  if (!listening)
  {
    std::cerr << "listen failed: " << listening.error().message << "\n";
    return 1;
  }

  std::this_thread::sleep_for(std::chrono::hours(24));
  transport->stop();
}
```

> The `onData` lambda captures `transport` (a `shared_ptr`) here only because it is the top-level `main` owner and the transport outlives the process; inside a library, capture the raw `Impl`/`this` or a promoted `weak_ptr` to avoid the reference cycle of §3.2.1.

### 4.2 TCP client: connect then send

```cpp
#include <iora/network/transport_impl.hpp>

using namespace iora::network;

void runClient(std::shared_ptr<Transport> transport)
{
  // send() is issued from onConnect: the async connect must complete before a
  // send is valid (CF-H1 rejects a send to a not-yet-open session).
  transport->onConnect([transport](SessionId sid, const TransportAddress &)
  {
    const std::string msg = "hello";
    transport->send(sid, msg.data(), msg.size());
  });

  transport->onData([](SessionId sid, iora::core::BufferView data,
                       std::chrono::steady_clock::time_point)
  {
    std::string response(reinterpret_cast<const char *>(data.data()), data.size());
    // handle response
  });

  transport->start();
  auto result = transport->connect("127.0.0.1", 8080);   // completes asynchronously
  if (!result)
  {
    // connect enqueue failed
  }
}
```

### 4.3 `connectSync` for connect-then-send

```cpp
auto transport = iora::network::Transport::tcp();
transport->start();

auto result = transport->connectSync("10.0.0.1", 5060,
                                     iora::network::TlsMode::None,
                                     std::chrono::milliseconds{5000});
if (result)
{
  iora::network::SessionId sid = result.value();
  const std::string invite = "INVITE sip:user@example.com SIP/2.0\r\n...";
  transport->send(sid, invite.data(), invite.size());   // sid is guaranteed usable
}
else
{
  // result.error().code is Timeout, ShuttingDown, TooManyPendingSyncOps, or a connect failure
}
```

`connectSync` does **not** fire the global `onConnect` -- the result goes straight to the blocking caller. Passing no explicit timeout uses `config.defaultSyncTimeout` via the `kUseConfigSyncTimeout` sentinel.

### 4.4 TLS client with SNI + certificate-identity verification

```cpp
using namespace iora::network;

// Pre-resolve the domain to an IP literal, then verify against the domain name.
TlsClientOptions opts;
opts.verifyName    = "api.example.com";   // reference identity (SNI + cert match)
opts.x509HostFlags = kHttpsHostFlags;     // RFC 9525 host verification

auto result = transport->connectSync(resolvedIpLiteral, 443, TlsMode::Client, opts,
                                     std::chrono::milliseconds{10000});
```

### 4.5 Config presets

```cpp
using namespace iora::network;

auto sipTcp = Transport::tcp(TransportConfig::forSipTcp());   // keepalive, 1h idle, CS3 DSCP
auto sipUdp = Transport::udp(TransportConfig::forSipUdp());   // 32s idle, 10k sessions, CS3
auto bulk   = Transport::tcp(TransportConfig::forHighThroughput());  // batching on

// Customize from a preset:
auto config = TransportConfig::forSipTcp();
config.idleTimeout      = std::chrono::seconds(7200);
config.serverTls.enabled  = true;
config.serverTls.certFile = "/etc/certs/server.pem";
config.serverTls.keyFile  = "/etc/certs/server.key";
auto tls = Transport::tcp(config);
```

### 4.6 Observers for shared-session error propagation

```cpp
auto oid = transport->observe(sid, [txnId](iora::network::SessionId,
                                           const iora::network::TransportErrorInfo &reason)
{
  transactionManager.onTransportFailure(txnId, reason);
});
// On normal completion:
transport->unobserve(oid);
// If the session closes first, the observer fires and is auto-removed.
```

### 4.7 Anti-patterns

- **Do NOT block in a callback.** Callbacks run on the single I/O thread; blocking (disk I/O, a contended mutex, a network round-trip) stalls all I/O for the transport. Copy the data and post the work to a thread pool (e.g. `iora::core::async`).
- **Do NOT forget `transport_impl.hpp` in exactly one TU.** Including only `transport.hpp` yields linker errors for every `Transport` method; including `transport_impl.hpp` in two TUs yields ODR/duplicate-symbol errors.
- **Do NOT call `stop()`, `addListener()`, or any sync op (`connectSync`/`sendSync`/`receiveSync`) or `setReadMode()` from a callback.** Each throws `std::logic_error` on the I/O thread (deadlock or UB). Use `isOnIoThread()` if you need to branch.
- **Do NOT `send()` before the connection is open.** An async `connect()` followed immediately by `send()` will have the `send` rejected (`sessionSendable` / CF-H1) -- wait for `onConnect`, or use `connectSync`.
- **Do NOT assume a `BufferView` outlives the callback.** The engine reuses its read buffer after `onData` returns -- copy anything you retain.
- **Do NOT capture an owning `shared_ptr<Transport>` of the transport itself in a callback** (reference cycle -- §3.2.1). Capture the raw pointer or a promoted `weak_ptr`.
- **Do NOT run two `receiveSync` calls concurrently on one session** -- the second returns `TransportError::Cancelled` (single-waiter contract).

---

## 5. Call Flow / Sequence Reference

### 5.1 `connectSync` (TCP and UDP) -- success path

| Step | Actor | Action |
|---|---|---|
| 1 | Caller | `connectSync(host, port, tls, opts, timeout)`. |
| 2 | Transport | Throws `std::logic_error` if on the I/O thread; resolve the sentinel/default timeout. TCP and UDP now follow the same parking path (no UDP short-circuit). |
| 3 | Transport | **Acquire `syncMutex`** and hold it continuously through entry into `wait_for` (serializes against teardown). |
| 4 | Transport | Entry fence: if `shuttingDown`, release and return `ShuttingDown`; if the concurrent-op cap is reached, return `TooManyPendingSyncOps`. |
| 5 | Transport | `engine->connect(host, port, tls, opts)` -> `sid`; register `pendingConnects[sid] = op`; construct `ParkGuard` (`++activeConnects`). |
| 6 | Transport | `op->cv.wait_for(lk, timeout, pred)` -- atomically **releases `syncMutex`** while parked. |
| 7 | I/O thread | Handshake (or UDP session insert) completes; engine `onConnect` fires; handler **acquires `syncMutex`**, finds `pendingConnects[sid]`, sets `op->result = ok(sid)`, `op->done = true`, erases the entry, **releases `syncMutex`**, then `op->cv.notify_one()`. |
| 8 | Transport | `wait_for` re-acquires `syncMutex`, sees `op->done`, returns `ConnectResult::ok(sid)`. `ParkGuard` dtor decrements `activeConnects` under the lock and wakes the teardown CV. |

### 5.2 `connectSync` -- timeout / cleanup path

| Step | Actor | Action |
|---|---|---|
| 1-6 | as §5.1 | but the handshake does not complete before `timeout`. |
| 7 | Transport | `wait_for` returns with `op->done == false` and `shuttingDown == false`. |
| 8 | Transport | Mark `sid` sync-owned (suppress globals) under the lock, **release `syncMutex`**, call `engine->close(sid)`, **re-acquire `syncMutex`** (`ParkGuard` still in scope keeps `engine` alive across the close). |
| 9 | Transport | Return `TransportError::Timeout`. The `pendingConnects[sid]` entry is **retained** so the eventual `onClose` reaps it and suppresses the spurious global `onClose`. `ParkGuard` dtor decrements `activeConnects` under the lock. |

### 5.3 Session close -> observers -> user-data cleanup

| Step | Actor | Action / lock |
|---|---|---|
| 1 | I/O thread | Engine fires `onClose(sid, reason)`. |
| 2 | Handler | **Acquire `syncMutex`**; if `sid` is a pending `connectSync`, deliver failure to the caller, **release**, `notify_one`, and return (no global onClose/observers/cleanup). |
| 3 | Handler | **Acquire `callbackMutex`**, copy `onCloseCb`, **release**; invoke it (no lock held). |
| 4 | Handler | **Acquire `observerMutex`**, copy the observer vector, erase the observer maps, **release**. |
| 5 | Handler | Invoke each observer from the copy (copy-then-iterate). |
| 6 | Handler | **Acquire `syncMutex`**; mark the receive buffer `closed` + `notify_all` (or leave a tombstone); erase `readModes[sid]`; GC stale tombstones if the map exceeds `syncBufferGcThreshold`; **release**. |
| 7 | Handler | **Acquire `userDataMutex`**, extract + erase the `UserData`, **release**; invoke the cleanup callback last (no lock held). |

### 5.4 `receiveSyncCancellable` -- polling loop

| Step | Actor | Action |
|---|---|---|
| 1 | Caller | `receiveSyncCancellable(sid, buf, len, token, timeout)`. |
| 2 | Default impl | If `token.isCancelled()`, return `Cancelled`. |
| 3 | Default impl | Loop until the deadline: check the token, compute `remaining`, call `receiveSync(sid, buf, len, min(remaining, 100ms))`. |
| 4 | Default impl | On `ok` or any non-`Timeout` error (e.g. `PeerClosed`, `BufferOverflow`, `ShuttingDown`, `TooManyPendingSyncOps`), return it immediately. |
| 5 | Default impl | On `Timeout`, loop again (re-checking the token) until the deadline; then return `Timeout`. |

---

## 6. Thread Safety Model

### 6.1 Transport-level lock inventory

`Transport` uses four independent mutexes. In practice no code path holds more than one at a time.

| Lock | Order | Protects | Acquired by |
|------|-------|----------|-------------|
| `callbackMutex` | 1 | The five global callback slots | callback setters; the dispatch handlers (to copy before invoking) |
| `syncMutex` | 2 | `pendingConnects`, `pendingSends`, `readModes`, `receiveBuffers`, every `SyncReceiveBuffer`/`SyncConnectOp`/`SyncSendOp` field, `pendingSyncOps`, and the teardown counters | `connectSync`, `sendSync`, `receiveSync`, `setReadMode`, `getReadMode`; the `onConnect`/`onData`/`onClose`/send-completion dispatch handlers; the teardown handshake |
| `observerMutex` | 3 | `observers`, `observerToSession` | `observe`, `unobserve`; the `onClose` handler (to copy the observer list) |
| `userDataMutex` | 4 | `sessionData` | `setSessionData`, `getSessionData`; the `onClose` handler (to extract data for cleanup) |

### 6.2 Lock ordering

The declared order is `callbackMutex (1) -> syncMutex (2) -> observerMutex (3) -> userDataMutex (4)`, but it is a **defensive convention, not a live constraint**: no path holds two Transport-level locks simultaneously. Callbacks are copied under `callbackMutex` and the lock is released before `syncMutex` is taken (and vice-versa).

### 6.3 Per-operation synchronization

| Operation | Synchronization | Notes |
|---|---|---|
| `onAccept/onConnect/onData/onClose/onError` (setters) | `callbackMutex` single-shot | Replace the slot; take effect on the next event. |
| `send` / `sendAsync` / `close` / `connect` / `connectViaListener` | none at the Transport layer; enqueue a command on the engine (after the `sessionSendable` check for sends) | The engine serializes the eventfd wakeup-`write` against its teardown `close` under its command mutex. |
| `connectSync` | `syncMutex` held from before `engine->connect` through entry into `wait_for`; CV signalled by the I/O thread | Throws on the I/O thread. See §5.1-5.2. |
| `receiveSync` | one continuous `syncMutex` hold: find-or-create buffer, single-waiter check, park on the buffer CV, drain | Throws on the I/O thread; single-waiter contract (INV-6). Drain is a `memcpy`, so no user callback runs under the lock. |
| `sendSync` | `syncMutex` to register the completion op + cap check; the async send is issued with the lock released; parks on the op CV, signalled by the engine's `SendCompleteCallback` | Blocks until send completion or timeout; counted in `activeSends` for the teardown gate; returns `TooManyPendingSyncOps` at the cap, `ShuttingDown` during teardown. Throws on the I/O thread. |
| `setReadMode` | `syncMutex` for the mode update + `engine->setReadEnabled` toggle; **released before** each `onData` flush invocation (HR-6) | Throws on the I/O thread; a `Sync->Async` flush is counted in `activeFlushes` for the teardown gate. |
| `getReadMode` / `getSessionData` / `setSessionData` | single-shot `syncMutex` / `userDataMutex` | No CV wait. |
| `observe` / `unobserve` | single-shot `observerMutex` | Id counter is a relaxed atomic. |
| `getListenerAddress/getLocalAddress/getRemoteAddress` / `getStats` | engine `shared_lock` (introspection) / engine internal | Near-zero contention; I/O thread takes the write lock only at map mutations. |

### 6.4 Copy-then-invoke / copy-then-iterate (the core invariant)

The single most important rule: **no user-facing lock is held during callback invocation.** Every dispatch handler (§3.6) copies the `std::function` under `callbackMutex`, releases, then invokes; the `onClose` handler copies the observer vector under `observerMutex`, releases, then iterates the copy. This lets a callback safely re-enter the transport and prevents iterator invalidation if an observer calls `unobserve()`. The `sendSync` completion callback likewise updates its op under `syncMutex` and notifies the CV **outside** the lock.

### 6.5 Engine vs Transport lock domains

- **User threads** either enqueue a command to the I/O thread (send/close/connect/addListener) or acquire a Transport lock briefly (observe/setSessionData/setReadMode/getReadMode). Address introspection takes the engine's `shared_lock`.
- **The I/O thread** may hold engine-internal locks while firing an engine callback; the Transport dispatch handler then acquires a Transport lock **briefly** to copy state, **releases** it, and invokes user code with **zero locks held**.

Effective order: engine-internal locks (I/O thread) -> Transport locks (briefly, in the dispatch handlers). This is acyclic because user threads never take the engine's callback lock, and the I/O thread releases every lock before invoking user code.

### 6.6 I/O-thread guards

`connectSync`, `sendSync`, `receiveSync`, `setReadMode`, `stop`, and `addListener` compare `std::this_thread::get_id()` against `engine->getIoThreadId()` and throw `std::logic_error` when they match. The check is on thread identity **alone** (not conjoined with `isRunning()`), so it still fires during `shutdownDrain` when `_running` is already false but an I/O-thread callback is executing. `isOnIoThread()` (§3.2.2) reads a separate race-free atomic and is the safe, non-throwing query.

### 6.7 Teardown safety

The destructor (non-I/O-thread path) calls `performTeardown()`, which sets the `shuttingDown` entry fence, stops the engine, and waits on `teardownCv` until all four external-thread counters (`activeReceives`, `activeConnects`, `activeFlushes`, `activeSends`) reach zero -- so no thread is still touching `_impl` when it is freed. Every parked `connectSync` and `sendSync` waiter is always woken on teardown (neither has data to drain); parked `receiveSync` waiters are drained-then-woken by `engine->stop()`'s `onClose` on the normal path. The I/O-thread self-destruction path defers `Impl` deletion to the detached engine thread's post-loop epilogue. The full four-counter handshake, its invariants, and the drain-before-close ordering are documented in **[transport_sync_lifecycle.md](transport_sync_lifecycle.md)**.

---

## 7. Configuration Reference

All fields are members of `TransportConfig` (`transport_types.hpp`). `std::chrono` types carry their own units. Zero generally means "disabled"/"OS default".

### 7.1 Protocol, Timeouts

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `protocol` | `Protocol` | `TCP` | Selects the engine (`TcpEngine` vs `UdpEngine`). |
| `idleTimeout` | `std::chrono::seconds` | `600` | Close sessions idle for this long. `0` disables. |
| `maxConnAge` | `std::chrono::seconds` | `0` (`seconds::zero()`) | Max connection age before forced close. `0` = unlimited. |
| `connectTimeout` | `std::chrono::milliseconds` | `30000` | TCP outbound connect timeout (TCP only). |
| `handshakeTimeout` | `std::chrono::milliseconds` | `30000` | TLS handshake timeout (TCP+TLS only). |
| `resolveTimeout` | `std::chrono::milliseconds` | `5000` | Off-thread name-resolution timeout for the event-driven `doConnect`. `count() == 0` disables it; **SIP transports MUST NOT disable it** (aggregate-budget violation). See the DNS deep dive. |
| `writeStallTimeout` | `std::chrono::milliseconds` | `0` | Close if the write queue stalls this long. `0` disables. |
| `gcInterval` | `std::chrono::seconds` | `5` | Idle/age garbage-collection sweep interval. |

### 7.2 I/O, Socket

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `epollMaxEvents` | `int` | `256` | Max events per `epoll_wait`. |
| `ioReadChunk` | `std::size_t` | `65536` (64 KB) | Read buffer size. |
| `maxWriteQueue` | `std::size_t` | `1024` | Max pending writes per session; overflow behavior per `closeOnBackpressure`. |
| `closeOnBackpressure` | `bool` | `true` | On write-queue overflow, close the session; if `false`, drop new writes (`send` returns `false`). |
| `useEdgeTriggered` | `bool` | `true` | Use `EPOLLET`. |
| `enableTcpNoDelay` | `bool` | `true` | Set `TCP_NODELAY` (TCP only). |
| `soRcvBuf` | `int` | `0` | `SO_RCVBUF`; `0` = OS default. |
| `soSndBuf` | `int` | `0` | `SO_SNDBUF`; `0` = OS default. |
| `dscpValue` | `std::uint8_t` | `0` | DSCP QoS marking (6-bit, max 63). Applied **at socket creation** (when non-zero) via the shared `applyDscpToFd(fd, dscpValue)` helper: `IP_TOS` on `AF_INET`, and `IPV6_TCLASS` (primary) plus best-effort `IP_TOS` on `AF_INET6` for the mapped-IPv4 egress. There is no per-session runtime setter on the facade. |
| `enableHighResolutionTimers` | `bool` | `true` | Sub-second timer precision. |
| `listenBacklog` | `int` | `256` | `listen()` backlog. |
| `tcpKeepalive.enable` | `bool` | `false` | Enable TCP keepalive probes (TCP only). |
| `tcpKeepalive.idle` | `int` | `60` | Seconds before the first probe. |
| `tcpKeepalive.interval` | `int` | `10` | Seconds between probes. |
| `tcpKeepalive.count` | `int` | `3` | Unanswered probes before close. |
| `maxSessions` | `std::size_t` | `0` | Max concurrent sessions; `0` = unlimited. **Enforced by both engines** (the TCP engine rejects the accepted fd at the cap). It is the only bound on aggregate per-session receive memory, so `0` on a stream transport means the ceiling is the process fd limit. |

### 7.3 Sync operations

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `maxPendingSyncOps` | `std::size_t` | `32` | Max concurrent parked sync ops across all sessions (`connectSync` + `sendSync` + `receiveSync`); `0` = unlimited. An op that would exceed the cap is rejected with `TransportError::TooManyPendingSyncOps` rather than blocking. |
| `maxSyncReceiveBuffer` | `std::size_t` | `1048576` (1 MB) | Max bytes buffered per session in `Sync` mode; an append past this sets the terminal `BufferOverflow` state. |
| `syncBufferGcThreshold` | `std::size_t` | `1024` | Tombstone-GC trigger: when the receive-buffer map exceeds this, `onClose` reclaims closed, drained, unwaited, non-flushing entries. |
| `defaultSyncTimeout` | `std::chrono::milliseconds` | `30000` | Default sync-op timeout used when a caller passes the `kUseConfigSyncTimeout` sentinel (the primary sync ops' default argument). Presets override it (`forSipTcp` 32000 ms, `forSipUdp` 500 ms). A non-positive value is floored to `kFallbackSyncTimeout` (30000 ms) by `resolveSyncTimeout()`. |
| `allowReadModeSwitch` | `bool` | `true` | Allow runtime `Async`/`Sync`/`Disabled` switching; `false` makes `setReadMode` return `false`. |

**Timeout sentinels** (`transport_types.hpp`): `kUseConfigSyncTimeout` is a `-1 ms` sentinel meaning "use `config.defaultSyncTimeout`"; `kFallbackSyncTimeout` is the fixed 30000 ms fallback. The primary sync ops (`connectSync`/`sendSync`/`receiveSync`) default to `kUseConfigSyncTimeout` and resolve it via `Impl::resolveSyncTimeout()`; the `*Cancellable` variants (no config access) default to `kFallbackSyncTimeout`.

### 7.4 TLS, stats

`TransportConfig::serverTls` and `clientTls` are `TlsConfig` (both disabled by default):

| `TlsConfig` field | Type | Default |
|---|---|---|
| `enabled` | `bool` | `false` |
| `defaultMode` | `TlsMode` | `None` |
| `certFile` / `keyFile` / `caFile` / `caPath` / `ciphers` / `alpn` | `std::string` | empty |
| `minVersion` | `int` | `0` (OpenSSL `TLS_method()` default) |
| `verifyPeer` | `bool` | `false` |
| `verifyDepth` | `int` | `4` |

`TransportStats` snapshot fields (all counters start at `0`): `accepted`, `connected`, `closed`, `errors`, `tlsHandshakes`, `tlsFailures`, `bytesIn`, `bytesOut`, `epollWakeups`, `commands`, `gcRuns`, `gcClosedIdle`, `gcClosedAged`, `backpressureCloses` (`std::uint64_t`); `sessionsCurrent`, `sessionsPeak` (`std::size_t`); `batchingStats` (`std::optional<BatchProcessingStats>`).

### 7.5 Batching, rate limiting

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `batching.enabled` | `bool` | `false` | Enable event batching in the I/O loop. |
| `batching.maxBatchSize` | `std::size_t` | `64` | Max events per batch. |
| `batching.maxBatchDelay` | `std::chrono::microseconds` | `100` | Max wait for a full batch (rounded up to a 1 ms floor by `epoll_wait`). |
| `batching.adaptiveThreshold` | `std::chrono::microseconds` | `50` | Processing-time threshold for adaptive sizing. |
| `batching.enableAdaptiveSizing` | `bool` | `true` | Adjust batch size with load. |
| `batching.loadFactor` | `double` | `0.75` | Target utilization for adaptive sizing. |
| `acceptRateLimit` | `double` | `0.0` | Max new connections/sec (global). `0` disables. |
| `perIpAcceptRateLimit` | `double` | `0.0` | Max new connections/sec per source IP. `0` disables. |
| `sendRateLimit` | `double` | `0.0` | Max bytes/sec per session. `0` disables. |

### 7.6 Factory presets

| Preset | Protocol | Key settings |
|--------|----------|-------------|
| `forSipTcp()` | TCP | `idleTimeout=3600s`, `tcpNoDelay=true`, `keepalive.enable=true`, `keepalive.idle=120`, `maxPendingSyncOps=64`, `defaultSyncTimeout=32000ms`, `dscpValue=24` (CS3) |
| `forSipUdp()` | UDP | `idleTimeout=32s`, `maxSessions=10000`, `maxPendingSyncOps=64`, `defaultSyncTimeout=500ms`, `dscpValue=24` (CS3) |
| `forHighThroughput()` | TCP | `batching.enabled=true`, `maxBatchSize=128`, `maxBatchDelay=200us`, `maxWriteQueue=4096`, `soRcvBuf=soSndBuf=262144` |
| `forLowLatency()` | TCP | `batching.enabled=false`, `tcpNoDelay=true`, `useEdgeTriggered=true`, `maxWriteQueue=256` |
| `minimal()` | TCP | All defaults (`TransportConfig{}`). |

---

## 8. API Reference

### 8.1 `ITransport`

```cpp
namespace iora::network
{

class ITransport
{
public:
  virtual ~ITransport() = default;

  // Lifecycle
  virtual StartResult start() = 0;
  virtual void stop() = 0;
  virtual bool isRunning() const = 0;
  virtual TransportErrorInfo lastError() const = 0;

  // Connection management
  virtual ListenResult addListener(const std::string &bindIp, std::uint16_t port,
                                   TlsMode tls = TlsMode::None) = 0;
  virtual ConnectResult connect(const std::string &host, std::uint16_t port,
                                TlsMode tls = TlsMode::None) = 0;
  virtual ConnectResult connect(const std::string &host, std::uint16_t port, TlsMode tls,
                                const TlsClientOptions &opts) = 0;
  virtual ConnectResult connectViaListener(ListenerId lid, const std::string &host,
                                           std::uint16_t port) = 0;
  virtual bool close(SessionId sid) = 0;

  // Async data
  virtual bool send(SessionId sid, iora::core::BufferView data) = 0;
  virtual void sendAsync(SessionId sid, iora::core::BufferView data,
                         SendCompleteCallback cb = nullptr) = 0;
  virtual bool send(SessionId sid, const void *data, std::size_t len);              // default
  virtual void sendAsync(SessionId sid, const void *data, std::size_t len,
                         SendCompleteCallback cb = nullptr);                         // default

  // Sync connect (primary overloads default to the kUseConfigSyncTimeout sentinel)
  virtual ConnectResult connectSync(const std::string &host, std::uint16_t port,
                                    TlsMode tls = TlsMode::None,
                                    std::chrono::milliseconds timeout =
                                      kUseConfigSyncTimeout) = 0;
  virtual ConnectResult connectSync(const std::string &host, std::uint16_t port, TlsMode tls,
                                    const TlsClientOptions &opts,
                                    std::chrono::milliseconds timeout =
                                      kUseConfigSyncTimeout) = 0;
  virtual ConnectResult connectSyncCancellable(const std::string &host, std::uint16_t port,
                                               CancellationToken &token,
                                               TlsMode tls = TlsMode::None,
                                               std::chrono::milliseconds timeout =
                                                 kFallbackSyncTimeout,
                                               const TlsClientOptions &opts = {});   // default

  // Sync data
  virtual SendResult sendSync(SessionId sid, iora::core::BufferView data,
                              std::chrono::milliseconds timeout =
                                kUseConfigSyncTimeout) = 0;
  virtual ReceiveResult receiveSync(SessionId sid, void *buffer, std::size_t &len,
                                    std::chrono::milliseconds timeout =
                                      kUseConfigSyncTimeout) = 0;
  virtual SendResult sendSyncCancellable(SessionId sid, iora::core::BufferView data,
                                         CancellationToken &token,
                                         std::chrono::milliseconds timeout =
                                           kFallbackSyncTimeout);                    // default
  virtual ReceiveResult receiveSyncCancellable(SessionId sid, void *buffer, std::size_t &len,
                                               CancellationToken &token,
                                               std::chrono::milliseconds timeout =
                                                 kFallbackSyncTimeout);              // default

  // Read modes
  virtual bool setReadMode(SessionId sid, ReadMode mode) = 0;
  virtual bool getReadMode(SessionId sid, ReadMode &mode) const = 0;

  // Callbacks
  virtual void onAccept(AcceptCallback cb) = 0;
  virtual void onConnect(ConnectCallback cb) = 0;
  virtual void onData(DataCallback cb) = 0;
  virtual void onClose(CloseCallback cb) = 0;
  virtual void onError(ErrorCallback cb) = 0;

  // Per-session observers
  virtual ObserverId observe(SessionId sid, CloseCallback cb) = 0;
  virtual bool unobserve(ObserverId id) = 0;

  // Session introspection
  virtual TransportAddress getListenerAddress(ListenerId lid) const = 0;
  virtual TransportAddress getLocalAddress(SessionId sid) const = 0;
  virtual TransportAddress getRemoteAddress(SessionId sid) const = 0;
  virtual void setSessionData(SessionId sid, void *data,
                              SessionCleanupCallback cleanup = nullptr) = 0;
  virtual void *getSessionData(SessionId sid) const = 0;

  // Stats
  virtual TransportStats getStats() const = 0;
  virtual Protocol getProtocol() const = 0;
};

} // namespace iora::network
```

### 8.2 `Transport`

```cpp
namespace iora::network
{

class Transport final : public ITransport,
                        public std::enable_shared_from_this<Transport>
{
private:
  struct PrivateTag {};   // passkey: ctors callable only by the factories
public:
  Transport(PrivateTag, TransportConfig config);
  Transport(PrivateTag, std::unique_ptr<detail::EngineBase> engine, TransportConfig config);
  ~Transport();

  Transport(Transport &&) = delete;              // shared-ownership only
  Transport &operator=(Transport &&) = delete;
  Transport(const Transport &) = delete;
  Transport &operator=(const Transport &) = delete;

  // The only public construction surface.
  static std::shared_ptr<Transport> tcp(TransportConfig config = {});
  static std::shared_ptr<Transport> udp(TransportConfig config = {});

  // Transport-specific accessor (NOT on ITransport): race-free I/O-thread query.
  bool isOnIoThread() const noexcept;

  // All ITransport methods overridden. `using ITransport::connect / connectSync /
  // send / sendAsync` keep the base overloads visible (no hiding).

private:
  static std::shared_ptr<Transport> withEngine(std::unique_ptr<detail::EngineBase> engine,
                                               TransportConfig config);   // DI/test seam
  friend struct iora::network::test::TransportEngineInjector;

  struct Impl;
  std::unique_ptr<Impl> _impl;
};

} // namespace iora::network
```

### 8.3 Type aliases, callback typedefs, and constants

```cpp
using SessionId  = std::uint64_t;
using ListenerId = std::uint64_t;
using ObserverId = std::uint64_t;
using ByteBuffer = std::vector<std::uint8_t>;
using MonoClock  = std::chrono::steady_clock;
using MonoTime   = std::chrono::time_point<MonoClock>;

using StartResult   = Result<void, TransportErrorInfo>;
using ListenResult  = Result<ListenerId, TransportErrorInfo>;
using ConnectResult = Result<SessionId, TransportErrorInfo>;
using SendResult    = Result<std::size_t, TransportErrorInfo>;
using ReceiveResult = Result<std::size_t, TransportErrorInfo>;

using AcceptCallback         = std::function<void(SessionId, const TransportAddress &)>;
using ConnectCallback        = std::function<void(SessionId, const TransportAddress &)>;
using DataCallback           = std::function<void(SessionId, iora::core::BufferView,
                                                  std::chrono::steady_clock::time_point)>;
using CloseCallback          = std::function<void(SessionId, const TransportErrorInfo &)>;
using ErrorCallback          = std::function<void(TransportError, const std::string &)>;
using SendCompleteCallback   = std::function<void(SessionId, const SendResult &)>;
using SessionCleanupCallback = std::function<void(void *)>;

// Sync-op timeout sentinels.
static constexpr std::chrono::milliseconds kUseConfigSyncTimeout{-1};      // use config.defaultSyncTimeout
static constexpr std::chrono::milliseconds kFallbackSyncTimeout{30000};    // fixed 30 s fallback

// Host-verification bitmask constants (macro-free; no <openssl/*> needed by consumers).
static constexpr unsigned kHttpsHostFlags = 0x20u | 0x4u;   // RFC 9525: NEVER_CHECK_SUBJECT | NO_PARTIAL_WILDCARDS
static constexpr unsigned kSipHostFlags   = 0x2u | 0x20u;   // RFC 5922: NO_WILDCARDS | NEVER_CHECK_SUBJECT
```

---

## 9. Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Single interface | `ITransport` implemented by `Transport`; engine behind `unique_ptr<EngineBase>` | One class, one interface, one config type. Engine selection is internal. |
| Shared-ownership only (S-3) | `shared_ptr<Transport>` factories; move+copy deleted; `enable_shared_from_this` | Closes the C-1 concurrent-teardown UAF structurally -- a caller co-owns the transport for the call's duration. |
| Passkey ctors | Private `PrivateTag` gate | `make_shared` (single alloc, `enable_shared_from_this`-compatible) without a public constructor. |
| Zero-copy read path | `DataCallback` takes `BufferView` + `receiveTime` | Downstream parsing without a copy; `receiveTime` captured at the `recv()` site (RTP jitter). |
| `Result<T,E>` for errors | All fallible ops return `Result<T, TransportErrorInfo>` | Composable, monadic error handling. |
| Individual callback setters | `onAccept(cb)`, `onConnect(cb)`, ... | Clearer API than one `Callbacks` struct; engines still use one struct internally. |
| `connectSync` wraps async connect (TCP + UDP) | Blocking connect + CV wait; global `onConnect` suppressed; UDP parks like TCP | Simplifies connect-then-send; the result goes to the blocking caller and the returned `sid` is guaranteed usable (no race with the send-time `sessionSendable` check). |
| Blocking `sendSync` | Register a completion op, park on a CV signalled by the engine's `SendCompleteCallback`, gated by `activeSends` | Honors `timeout`; forward-correct for an engine that defers completion. Current engines complete synchronously at enqueue. |
| Send validation (CF-H1) | Engines reject a send to a not-present-or-closed session (`sessionSendable`) | A dropped-but-`true` send masked a dead connection from SIP RFC 3263 failover; connect-then-send must await `onConnect`. |
| Split-header pattern | `transport.hpp` (light) + `transport_impl.hpp` (one TU) | No epoll/OpenSSL leakage into consumers. `transport_types.hpp` is OpenSSL-include-free. |
| Success-only accept/connect callbacks | No error parameter | Failed accepts are engine-internal; failed connects come via `onClose`/`onError`. |
| Single protocol per instance | Each `Transport` handles TCP, UDP, or TLS/TCP | SIP composes two transports; multi-protocol would add complexity with no clear benefit. |
| Presets on `TransportConfig` | `forSipTcp()`, etc. | Transport stays protocol-agnostic; use-case tuning is a config concern; factories never start or bind. |
| Data-only `TlsClientOptions` | `verifyName` + `x509HostFlags`, no OpenSSL type | Keeps `transport_types.hpp` includable by non-TLS TUs; `kHttpsHostFlags`/`kSipHostFlags` let callers avoid `<openssl/*>`. |
| DSCP at construction only, via shared helper | `config.dscpValue` applied at socket creation by `applyDscpToFd`; no per-session setter on the facade | One QoS knob; `IPV6_TCLASS`-primary + best-effort `IP_TOS` covers dual-stack mapped-IPv4 egress. One helper retired the byte-identical per-engine copies. |
| Sync-timeout sentinel | `kUseConfigSyncTimeout` default arg resolved to `config.defaultSyncTimeout` | Lets the SIP presets' tuned timeouts apply by default without the ops hardcoding 30 s and ignoring config. |
| Read gating at the fd level (C5) | `ReadMode::Disabled` calls `engine->setReadEnabled`; TCP removes `EPOLLIN`; UDP no-op | Avoids the wasted `recv()` syscalls a drop-at-callback disable incurred on TCP; UDP's shared socket cannot gate a single session. |
| `getListenerAddress` distinct name | Not a `getLocalAddress` overload | `ListenerId` and `SessionId` are both `uint64_t`; overloads cannot be distinguished by typedef. |
| I/O-thread guard on identity alone | Not conjoined with `isRunning()` | Still fires during `shutdownDrain` (running false, callback executing); `isOnIoThread()` is the non-throwing query. |
| Four-counter teardown handshake | `activeReceives`/`activeConnects`/`activeFlushes`/`activeSends` gate `~Impl` | No parked waiter/flusher/sender is freed out from under it (detailed in the sync-lifecycle deep dive). |

---

## 10. Known Limitations

| Limitation | Description | Status |
|------------|-------------|--------|
| **`sendSync` completion is enqueue-time for the current engines** | `sendSync` blocks until the engine's `SendCompleteCallback` fires, but the current TCP/UDP engines signal completion at the synchronous post-copy acceptance of the bytes (not wire transmission or a TLS flush), so it returns effectively immediately and the `timeout` rarely elapses. The parked-waiter machinery is forward-correct for a future engine that defers completion. | By design (current engines). |
| **`sendSyncCancellable` post-enqueue cancel is advisory** | Because current-engine completion is immediate at enqueue, a `cancel()` observed after the bytes are accepted still returns after they are already queued and will be sent. | Consequence of the current engines' enqueue-time completion above. |
| **`ReadMode::Disabled` on UDP still incurs `recv()`** | UDP multiplexes many virtual sessions over one shared socket, so `setReadEnabled` cannot remove `EPOLLIN` for a single session; disabled UDP sessions still `recv()` and drop the data at the dispatch handler. TCP removes `EPOLLIN` and avoids the syscall. | By design (shared-socket UDP). |
| **`BufferOverflow` is terminal per session** | Once a `Sync`-mode append exceeds `maxSyncReceiveBuffer`, the buffer's overflow flag is set and never cleared (dropped bytes corrupt the stream irrecoverably); a retry re-reports `BufferOverflow`. The caller **must** close the session. | By design (N-2). |
| **`maxSessions == 0` leaves per-session receive memory unbounded on a stream transport** | `maxSessions` is the only bound on aggregate per-session receive memory; `0` (the default) means the effective ceiling is the process fd limit. Set it explicitly on untrusted stream transports. | By design; document + set per deployment. |
| **`IoResult` alias not defined** | `using IoResult = Result<void, TransportErrorInfo>` is deferred because the legacy `IoResult` struct still exists in `transport_types.hpp` (used only by `TcpEngine::lastFatalError()`). | Future: add when the legacy struct is removed. |
| **Batching stats are not thread-safe** | `BatchProcessingStats` fields are plain integers; a `getStats()` read while the I/O thread updates them can tear. Suitable for monitoring only. | Accept: monitoring-only, never used for synchronization. |
| **Batching delay floors at 1 ms** | `epoll_wait` has millisecond granularity, so a sub-millisecond `maxBatchDelay` rounds up to 1 ms. | Accept: `epoll_wait` limitation; `io_uring` would be needed for microsecond precision. |
