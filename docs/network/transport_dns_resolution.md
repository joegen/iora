# Iora Transport DNS Resolution (Off-Thread Host Resolution) -- Architecture & Programmer's Guide

[Back to index](../../README.md)

**Parent guide: [transport.md](transport.md)** (the transport hub). **Related: [transport_sync_lifecycle.md](transport_sync_lifecycle.md)** (synchronous-op teardown and the connect-then-send ordering mechanism).

| | |
|---|---|
| **Version** | 1.2 |
| **Date** | 2026-09-11 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/network/name_resolver.hpp` (the homed `NameResolver` helper). The off-thread machinery is spread across `include/iora/network/detail/engine_base.hpp` (`EnginePostGate` + the `runOnIoThread` seam), `include/iora/network/detail/tcp_engine.hpp`, and `include/iora/network/detail/udp_engine.hpp`; `blockingIoPool()` is declared in `include/iora/core/thread_pool.hpp` and defined in `src/core/iora_core.cpp`; config knobs live in `include/iora/network/transport_types.hpp`. |
| **Namespace** | `iora::network` (helper), `iora::core` (pool), `iora::network::detail` (engines) |
| **Dependencies** | `iora::core::ThreadPool` (`thread_pool.hpp`, `tryEnqueue`), `<netdb.h>` (`::getaddrinfo` / `::freeaddrinfo`), the TCP/UDP transport engines. The SIP-layer budget validation (`iora_sip`) is a downstream consumer, not a dependency of this header. |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-09-06 | Initial implementation (tracker 2026-09-06-4, 31/31). Off-thread, event-driven `::getaddrinfo` for the TCP and UDP transport engines: immortal `blockingIoPool()`, `resolveHostAsync` + `OwnedAddrInfo`, `EnginePostGate` + `EngineBase::runOnIoThread` seam, single-owner `_pendingConnects` one-shot terminal, TCP resolve-timeout via `TimerService`, UDP via the GC-scan deadline. Cross-repo iora_sip budget validation (`validateResolveBudget`) and SIP-transport `onClose` Resolve surfacing. |
| 1.1 | 2026-09-11 | Migrated to `docs/network/`, re-verified against the current worktree source (`name_resolver.hpp`, `detail/engine_base.hpp`, `detail/tcp_engine.hpp`, `detail/udp_engine.hpp`, `transport_types.hpp`). Added the host-resolution-not-DNS clarification and the `NameResolver` vs `DnsClient` boundary. Homed `NameResolver` here (no separate `name_resolver.md`). Corrected two stale claims against the current source: (1) the TCP `resumeConnect` / `ConnectReq` now carry per-connection TLS identity (`verifyName` + `x509HostFlags`) threaded through the resume closure; (2) the former "F1 SNI / RFC 6125 / 9525 cert-identity absent" limitation is now RESOLVED at the TLS setup site (`SSL_set_tlsext_host_name`, `X509_VERIFY_PARAM_set_hostflags` / `SSL_set1_host`, `SSL_get_verify_result`). Reworked to the 12-section guide template. |
| 1.2 | 2026-09-11 | Removed stray leaked authoring tags at EOF. Corrected RFC mislabels: the generic OpenSSL server-identity mechanism (`X509_VERIFY_PARAM_set_hostflags` / `SSL_set1_host` / `X509_VERIFY_PARAM_set1_ip_asc`) is RFC 6125, obsoleted by RFC 9525 -- NOT RFC 5922 (which is the SIP-specific "Domain Certificates in SIP" spec, out of scope for this protocol-generic transport layer). Re-verified all `file:line` citations against the landed worktree source (line numbers had drifted: tcp_engine +~90-190, engine_base/transport_types +~30-40) and re-synced the `NameResolver` API surface, the resume-TLS-identity threading (`verifyName` / `x509HostFlags` through `ConnectReq` / `resumeConnect`), and the CF-H1 connect-then-send ordering (a named-host `send()` must await `onConnect`; `sessionSendable` rejects a not-yet-created session). |

---

## 1. Executive Summary

This guide covers **getaddrinfo-based host resolution** -- turning a `host:port` into a connectable socket address via the operating system's stub resolver -- and how iora moves that blocking call **off** the transport engine's single epoll I/O thread. It is **not** a guide to a DNS-protocol client: the component that speaks the DNS wire protocol (A/AAAA/SRV/NAPTR records, RFC 3263 service discovery) is the separate `DnsClient` (`dns_client.hpp`), documented elsewhere. The distinction is load-bearing and is spelled out verbatim in the boundary subsection below.

### Problem

The transport engines drive all sessions from a **single epoll I/O thread**. Named-host outbound connects resolved DNS **on that thread**, blocking every other session while the resolver ran:

- **TCP** (`tcp_engine.hpp` `doConnect`) resolved a named host via `std::async(std::launch::async)` + `wait_for(2s)` **dispatched from the I/O thread**. Three concrete bugs lived here: the timeout was illusory (`~future` joins the still-running `getaddrinfo` instead of abandoning it), the `addrinfo` chain leaked on the timeout path, and the `[&]`-capturing continuation was a use-after-free across engine teardown/migration. (That inline `std::async` + `wait_for` block has since been removed from `tcp_engine.hpp` `doConnect`.)
- **UDP** (`udp_engine.hpp` `connectDo` and the `connectViaListener` / `viaDo` session-creation site) called `::getaddrinfo` **inline on the I/O thread with no timeout at all**.

Blocking the I/O thread stalls every concurrent session's timers and inbound parsing at once. For SIP this is fatal: a single slow lookup skews engine-wide transaction timers past `64*T1` (Timer B / Timer F = 32 s at the default T1), producing spurious call failures across unrelated dialogs.

### Solution

Move named-host resolution **off** the epoll I/O thread, **event-driven**, **without changing connect behavior**:

- **`iora::network::resolveHostAsync`** (`name_resolver.hpp`) -- the header-only `NameResolver` helper that dispatches `::getaddrinfo` onto a dedicated pool and delivers an RAII `OwnedAddrInfo` chain to a continuation.
- **`iora::core::blockingIoPool()`** -- an immortal, hard-capped (`maxSize = 16`), reject-fast (`tryEnqueue` fails at `maxQueueSize = 128` rather than blocking) `ThreadPool`. A stuck resolver can never starve unrelated work or hang process exit.
- **`EngineBase::runOnIoThread(std::function<void()>) noexcept`** -- a generic, callback-free cross-thread posting seam. The resolver continuation posts a resume closure back onto the I/O thread through it.
- **`EnginePostGate`** -- a `shared_ptr`-owned `{mutex, closed, EngineBase*}` gate, re-created on `start()` and closed in `shutdownDrain()`, that makes the cross-thread post safe across engine teardown and restart.
- **`_pendingConnects[sid]`** -- an I/O-thread-only, single-owner, one-shot terminal record with exactly three eraser-and-fire sites (resume, resolve-timeout, teardown/close).

### `NameResolver` vs `DnsClient` (boundary)

NameResolver (name_resolver.hpp) vs DnsClient (dns_client.hpp). NameResolver is a single-shot host->socket-address helper that wraps the OS stub resolver (::getaddrinfo) and runs it off the I/O thread on blockingIoPool(), handing back an RAII addrinfo chain (OwnedAddrInfo) ready for an immediate connect(). It answers exactly one question -- 'which socket addresses back this host:port right now, per the system resolver?' -- and is an INTERNAL step of Transport's named-host connect path; applications do not call it directly. ('Async' here means off the caller/I/O thread; the resolution itself is a blocking getaddrinfo on a pool thread, not a non-blocking DNS-protocol implementation.) DnsClient is a standalone client that speaks the DNS wire protocol directly for a fixed set of record types -- A, AAAA, CNAME, MX, TXT, PTR, SRV, NAPTR (dns_client.hpp:178) -- plus RFC 3263 service discovery (NAPTR->SRV->A/AAAA, dns_client.hpp:179,289), exposed as synchronous, callback-async, and cancellable-future (AsyncDnsRequest) APIs, and consumed directly by application code (e.g. http_client.hpp). IMPORTANT -- the two consult DIFFERENT resolution stacks and can return different answers: NameResolver/getaddrinfo honors /etc/hosts, NSS ordering, and resolv.conf search/ndots options; DnsClient reads only the nameserver entries from /etc/resolv.conf and queries them directly (no /etc/hosts, no search-list processing), falling back to public resolvers 8.8.8.8/1.1.1.1 if none are configured -- so in split-horizon / internal-DNS deployments (common for SIP/SBC) the two can disagree, and DnsClient can bypass /etc/hosts overrides or leak to public DNS on a misconfigured host. Rule of thumb: connecting a Transport to a hostname -> NameResolver does it for you (internal, getaddrinfo, system resolution semantics); need DNS records or SIP/HTTP SRV service-location as data -> use DnsClient (direct DNS client). The record-type list alone proves they are different tools: MX/TXT/NAPTR/SRV are impossible via getaddrinfo, so DnsClient is not a NameResolver wrapper.

See also: `dns_client.md` (the DNS-protocol client, not yet written).

### Technical Impact

- **Zero I/O-thread blocking on host resolution** -- a slow resolve on one session no longer stalls timers or parsing for any other session.
- **Exactly-once free** -- the resolved chain travels as `std::shared_ptr<OwnedAddrInfo>`; `::freeaddrinfo` runs exactly once when the last handle drops (no leak on the timeout path, no double-free on the connect path).
- **Exactly-once, at-least-once terminal** -- every named-host connect delivers precisely one terminal event (`onConnect` on success; `onClose(Resolve)` / `onClose(ShuttingDown)` on failure), even under timeout-vs-resolve, close-during-resolve, and teardown-with-in-flight-resolve races.
- **Bounded teardown** -- teardown blocks at most for one `noexcept` post, never for `getaddrinfo`.
- **Unchanged connect semantics** -- the literal-IP short-circuit stays synchronous; the resolved chain is iterated exactly as before (single-address, terminal-on-failure). Multi-address failover is a separate, out-of-scope initiative (F2).

---

## 2. System Architecture

### 2.1 Component Relationships

```
iora::core::blockingIoPool()                     [thread_pool.hpp decl / iora_core.cpp def]
`-- immortal ThreadPool(2, 16, 30s, 128)         deliberately leaked; reject-fast

iora::network (header-only)                       [name_resolver.hpp -- "NameResolver"]
|-- OwnedAddrInfo          move-only RAII; ~dtor ::freeaddrinfo iff non-null
|-- ResolveResult          { int gaiCode; shared_ptr<OwnedAddrInfo> addrs; }
|-- RESOLVER_POOL_SATURATED   constexpr int = -1000000  (reject-fast sentinel)
|-- resolveErrorMessage(gaiCode)   "resolver pool saturated" | ::gai_strerror
`-- resolveHostAsync(host, port, hints, onComplete)
        `-- blockingIoPool().tryEnqueue(getaddrinfo task)
              |-- enqueued  -> onComplete on a POOL thread
              `-- rejected  -> onComplete INLINE {RESOLVER_POOL_SATURATED, nullptr}

iora::network::detail::EngineBase                 [engine_base.hpp]
|-- struct EnginePostGate { std::mutex m; bool closed=false; EngineBase* engine; }
|-- std::shared_ptr<EnginePostGate> _postGuard    re-created on start(), closed in drain
`-- virtual bool runOnIoThread(std::function<void()>) noexcept = 0   (PUBLIC seam)

TcpEngine : EngineBase                             [tcp_engine.hpp]
|-- enum Cmd::RunOnIo  + struct Command::fn (std::function<void()>)  -> copyable
|-- struct PendingConnect { uint64_t resolveTimeoutId; }   (TimerService id)
|-- unordered_map<SessionId, PendingConnect> _pendingConnects   (I/O-thread-only)
|-- doConnect -> makeResolveContinuation -> resumeConnect -> connectFromAddrs
|-- handleResolveTimeout (TimerService thread) -> resolveTimeoutOnIo (I/O thread)
`-- shutdownDrain: close gate, drain _pendingConnects; start(): re-create gate

UdpEngine : EngineBase                             [udp_engine.hpp]
|-- enum CmdType::RunOnIo + struct Cmd::fn (std::function<void()>)  -> copyable
|-- struct PendingConnect { MonoTime resolveDeadline; }   (absolute deadline)
|-- unordered_map<SessionId, PendingConnect> _pendingConnects   (I/O-thread-only)
|-- connectDo -> resumeConnect        (connect site)
|-- viaDo     -> resumeVia            (connectViaListener session-creation site)
|-- runGc resolve-deadline scan (collect-then-fire) -> resolveTimeoutOnIo
`-- shutdownDrain / start(): its OWN gate close + re-create (NOT shared with TCP)
```

The `NameResolver` helper is header-only and stateless: it holds no member state and is invoked as free functions in `iora::network`. It is homed in this guide; there is no separate `name_resolver.md`.

### 2.2 Data Flow: Named-Host Connect (Success Path)

```mermaid
sequenceDiagram
    participant App as Caller
    participant IO as Engine I/O thread
    participant Helper as resolveHostAsync
    participant Pool as blockingIoPool thread
    participant Gate as EnginePostGate

    App->>IO: connect("host", port) [enqueues Cmd::Connect]
    IO->>IO: doConnect: not a literal -> arm resolve-timeout
    IO->>IO: _pendingConnects[sid] = { deadline/timerId }
    IO->>Helper: resolveHostAsync(host, port, hints, continuation)
    Helper->>Pool: tryEnqueue(getaddrinfo task)
    Note over IO: doConnect RETURNS (I/O thread free)
    Pool->>Pool: getaddrinfo(host, port) -> addrinfo chain
    Pool->>Pool: continuation: build resume closure (owns sid+addrs)
    Pool->>Gate: lock gate->m; check closed
    alt gate open
        Gate->>IO: runOnIoThread(resume) [Cmd::RunOnIo]
        IO->>IO: resumeConnect: erase _pendingConnects[sid]
        IO->>IO: connectFromAddrs -> socket()/connect() -> onConnect
    else gate closed (torn down)
        Gate->>Gate: drop; addrs freed when closures drop
    end
```

### 2.3 Threading Model

| Thread | Responsibility |
|--------|----------------|
| **Caller thread** | Calls `connect()` / `connectViaListener()`, which only enqueue a command. Never resolves. |
| **Engine I/O thread** (epoll loop) | `doConnect` / `connectDo` / `viaDo` kickoff, `resumeConnect` / `resumeVia`, `resolveTimeoutOnIo`, the `Cmd::Close` handler's pending-drain, `shutdownDrain`, and the UDP `runGc` resolve-deadline scan. Owns `_pendingConnects` (no lock). Never runs `::getaddrinfo`. |
| **`blockingIoPool()` worker** | Runs `::getaddrinfo`, then the resolver continuation: builds the owned resume closure, takes `gate->m`, and posts (or drops+frees). Touches only immortal statics and the gate. Never touches `_sessions` / SSL / `_timerService`. |
| **TCP `TimerService` thread** | `handleResolveTimeout(sid)` fires here and does **only** `runOnIoThread(...)` to marshal `resolveTimeoutOnIo` onto the I/O thread. (UDP has no TimerService.) |

---

## 3. Component Deep Dive

### 3.1 `OwnedAddrInfo` and `ResolveResult`

`OwnedAddrInfo` (`name_resolver.hpp:36`) is the sole `::freeaddrinfo` owner on the resolve path:

- **Move-only RAII.** Copy ctor/assignment are `= delete`; the destructor calls `::freeaddrinfo(_head)` iff `_head != nullptr` (`name_resolver.hpp:44-50`). Move transfers the head and nulls the source.
- **`get()`** borrows the chain head without transferring ownership; **`release()`** relinquishes it; `explicit operator bool()` reports non-null.
- **The connect loop never frees.** `connectFromAddrs` (TCP, `tcp_engine.hpp:1898`) and `viaFromAddrs` (UDP, `udp_engine.hpp:1727`) receive a raw `addrinfo*` whose ownership is **external** -- freeing there would double-free (design principle #6).

`ResolveResult` (`name_resolver.hpp:109`) carries the outcome across threads:

```cpp
struct ResolveResult
{
  int gaiCode{0};                          // 0 = success; EAI_* ; or RESOLVER_POOL_SATURATED
  std::shared_ptr<OwnedAddrInfo> addrs;    // non-null only on success
};
```

`addrs` is a `shared_ptr` specifically so the resolved chain can be **captured by value** into the I/O-thread resume closure and freed **exactly once** when the last handle drops (transiently two handles exist during the copy-enqueue of the `RunOnIo` command; the single-free guarantee is preserved).

### 3.2 `RESOLVER_POOL_SATURATED` and reject-fast

```cpp
constexpr int RESOLVER_POOL_SATURATED = -1000000;   // name_resolver.hpp:101
```

A named, non-`EAI_*` negative constant, deliberately far from glibc's `EAI_*` range (roughly `[-11, -1]`) so it can never collide with a real `::getaddrinfo` error code. When `blockingIoPool().tryEnqueue(...)` returns `false` (queue full -- local backpressure), `resolveHostAsync` invokes `onComplete` **inline on the caller's thread** with `{RESOLVER_POOL_SATURATED, nullptr}` (`name_resolver.hpp:165-168`) -- the resolve never runs.

`resolveErrorMessage(gaiCode)` (`name_resolver.hpp:120`) returns the distinct string `"resolver pool saturated"` for the sentinel (so a local-backpressure event is not logged as a `getaddrinfo` failure) and `::gai_strerror(gaiCode)` otherwise.

**The sentinel is internal-only** (sip-M4, resolved 2026-09-06). `resumeConnect` collapses it to `TransportError::Resolve` at `onClose` exactly like a genuine resolver failure; it never crosses the public transport API. For a single-address, terminal-on-failure connect, a saturated resolve **is** a resolve failure. The only externally visible difference is the distinguishable log message. A distinct `TransportError::ResolverSaturated` carried to the SIP failover boundary is deferred to F2 -- adding a bare enumerator now would be dead code (YAGNI).

### 3.3 `resolveHostAsync` (the `NameResolver` entry point)

```cpp
inline void resolveHostAsync(std::string host, std::string port, ::addrinfo hints,
                             std::function<void(ResolveResult)> onComplete);   // name_resolver.hpp:144
```

The dispatched task captures **only** `host` / `port` / `hints` / `onComplete` **by value** (`name_resolver.hpp:150`) -- no reference, no `this`, no engine pointer -- so it is safe to run after the caller has moved on. `hints` is copied by value; the caller sets only its scalar fields (`ai_family` / `ai_socktype` / `ai_protocol` / `ai_flags`).

The task is intentionally **not** `mutable`: `c_str()` is const and `::getaddrinfo` takes a `const addrinfo*` for hints, so the task is const-callable -- required because `ThreadPool` wraps the task via `std::bind` (whose `operator()` is const).

**Delivery contract:**
- success -> `onComplete({0, chain})` on a **pool thread** (`name_resolver.hpp:159`)
- resolver error -> `onComplete({EAI_*, nullptr})` on a **pool thread** (`name_resolver.hpp:156`)
- pool saturation -> `onComplete({RESOLVER_POOL_SATURATED, nullptr})` **inline on the caller's thread** (`name_resolver.hpp:167`)

Because `tryEnqueue` takes the task **by value**, on rejection the moved-in task is destroyed inside `tryEnqueue`; the reject-fast path fires the **original** `onComplete` parameter (a live copy), never a moved-from function.

### 3.4 `iora::core::blockingIoPool()`

```cpp
// src/core/iora_core.cpp
ThreadPool &blockingIoPool()
{
  static ThreadPool *pool = new ThreadPool(2, 16, std::chrono::seconds(30), 128);
  return *pool;
}
```

The `ThreadPool` arguments are `(initialSize = 2, maxSize = 16, idleTimeout = 30 s, maxQueueSize = 128)`.

- **Immortal / deliberately leaked** (raw `new`, no `delete`, no `atexit` join). This is correct because an **uncancellable** `getaddrinfo` worker may still be parked when process exit runs static destructors -- joining it (the `ThreadPool` destructor) would hang teardown. A late worker at exit only touches immortal statics and its engine's already-closed `EnginePostGate`, then frees its `shared_ptr<OwnedAddrInfo>`. The precedent is the `LoggerData` immortal static in the same file. (See `docs/core/thread_pool.md` for the full pool contract.)
- **Hard-capped and reject-fast.** A stuck resolver (a hung DNS server) must not starve unrelated work: at most 16 workers, and `tryEnqueue` returns `false` at 128 queued tasks rather than blocking. Reject-fast is what makes `RESOLVER_POOL_SATURATED` reachable -- saturation requires `maxSize(16) + maxQueueSize(128) + 1 = 145` concurrently-stuck named resolves.
- **A generic blocking-I/O pool**, not a DNS-specific one; it is reserved for blocking, uncancellable syscalls that must never run on an event-loop thread.

Do **not** revert to `static ThreadPool pool(...)` -- that reopens the exit-hang path.

### 3.5 `EnginePostGate` and `EngineBase::runOnIoThread`

`EnginePostGate` (`engine_base.hpp:41`) is the shutdown/lifetime gate for the cross-thread post:

```cpp
struct EnginePostGate
{
  std::mutex m;
  bool closed{false};
  EngineBase *engine{nullptr};
};
```

The engine owns it as `std::shared_ptr<EnginePostGate> _postGuard` (a `protected` `EngineBase` member, `engine_base.hpp:227`; constructed with `engine == this` in the `EngineBase()` ctor at `engine_base.hpp:203`). Each resolver continuation captures a `shared_ptr` **copy** of the gate. The continuation posts the resume closure **iff** `!closed`, under `gate->m`; otherwise it drops (and the captured `addrs` frees when the closures drop). `closed` and `engine` are always set together, so `!closed` implies `engine` is alive.

`runOnIoThread` is the generic posting seam (`engine_base.hpp:197`):

```cpp
virtual bool runOnIoThread(std::function<void()> fn) noexcept = 0;   // PUBLIC
```

- **PUBLIC** because the resolver continuation reaches it through an `EnginePostGate::engine` (`EngineBase*`), mirroring the public `scheduleSelfDestruct`.
- **ALWAYS posts** -- it never runs `fn` inline, even if called on the I/O thread (documented at the declaration; both callers are off the I/O thread).
- **`noexcept` and callback-free** -- each override wraps `fn` into its `RunOnIo` command variant and enqueues under `_cmdMutex` / `_qmx`; on `_cmdsClosed` / `_qClosed` or any allocation failure it returns `false` and fires **no** user callback (`tcp_engine.hpp:954`, `udp_engine.hpp:804`). A dropped resolve post is backstopped by the resolve-timeout.

Each engine defines a copyable `RunOnIo` command carrying a `std::function<void()> fn` payload -- TCP: `Cmd::RunOnIo` + `Command::fn` (`tcp_engine.hpp:863,887`); UDP: `CmdType::RunOnIo` + `Cmd::fn` (`udp_engine.hpp:665,715`). Both are guarded by a `static_assert` that the command struct remains copy-constructible (`tcp_engine.hpp:939`, `udp_engine.hpp:770`) -- the command deque copies/moves entries.

### 3.6 `_pendingConnects`: the single-owner one-shot terminal

Each engine keeps an **I/O-thread-only** map with **no lock** (every mutation runs on the I/O loop thread):

```cpp
// TCP  (tcp_engine.hpp:844; map at 3370)
struct PendingConnect { std::uint64_t resolveTimeoutId{0}; };  // TimerService id; 0 == none
std::unordered_map<SessionId, PendingConnect> _pendingConnects;

// UDP  (udp_engine.hpp:697; map at 2211)
struct PendingConnect { MonoTime resolveDeadline{}; };         // absolute; default (epoch) == disabled
std::unordered_map<SessionId, PendingConnect> _pendingConnects;
```

A `_pendingConnects[sid]` entry is the **sole owner** of a named-host connect's terminal event. **Exactly one** of three sites erases it and fires the terminal; the others find no entry and no-op:

1. **RESUME** (`resumeConnect` / `resumeVia`) -- connects **only if it erased the entry**.
2. **Resolve-timeout** (`resolveTimeoutOnIo`) -- fires `onClose(Resolve, "resolve timeout")` only if it erased the entry.
3. **Teardown / close** (`shutdownDrain` drain; the `Cmd::Close` command handler) -- fires `onClose(ShuttingDown)` (teardown) or a single `onClose` (close) only if it erased the entry.

This yields exactly-once **and** at-least-once delivery. `PendingConnect` holds **no owned resource and no `connectSync` handle** -- only the timeout handle (TCP) or the absolute deadline (UDP). (`connectSync` is a Transport-layer condition variable; the engine delivers terminals only through `onClose` / `onConnect`.) So a `PendingConnect` left behind at teardown is benign.

### 3.7 TCP kickoff / resume / timeout / close

**Kickoff** (`doConnect`, I/O thread, `tcp_engine.hpp:1730`):
1. Literal IPv4/IPv6 (`inet_pton`) -> build a stack `addrinfo` and `connectFromAddrs` **synchronously** (`tcp_engine.hpp:1733-1763`, unchanged).
2. Named host -> build `hints` (`AF_UNSPEC`, `SOCK_STREAM`, `IPPROTO_TCP`, `ai_flags = AI_ADDRCONFIG`, `tcp_engine.hpp:1783`), arm the resolve-timeout via `_timerService->scheduleAfter(resolveTimeout, handleResolveTimeout)` (only if `resolveTimeout.count() > 0`, `tcp_engine.hpp:1788-1789`), record `_pendingConnects[sid]` (`tcp_engine.hpp:1791`), call `resolveHostAsync(...)` (`tcp_engine.hpp:1793`), and **return** (enqueue-only contract preserved).

`AI_ADDRCONFIG` is set so an IPv4-only host does not receive an AAAA record for a dual-stack FQDN -- otherwise RFC 6724 orders the AAAA first and the single-address, terminal-on-failure connect hits `ENETUNREACH` without ever trying the reachable A record (sip-voip M-1). Loopback is exempt in glibc, so `localhost` resolution is unaffected.

**Continuation** (`makeResolveContinuation`, runs on a pool thread, `tcp_engine.hpp:1802`) captures `this`, a `shared_ptr` gate copy, and owned `{sid, host, port, tls, verifyName, x509HostFlags}`. It builds the `resume` closure **outside** `gate->m`, then under `gate->m`: if `gate->closed` return; else `gate->engine->runOnIoThread(std::move(resume))` (`tcp_engine.hpp:1826`). On `bad_alloc` while building the closure, `r`/`addrs` free on unwind and the resolve-timeout backstops the missing terminal (#16). The per-connection TLS identity (`verifyName`, `x509HostFlags`) is threaded by value through every capture layer so the resumed named-host path reaches the SSL setup site with it (see §3.9).

**Resume** (`resumeConnect`, I/O thread, `tcp_engine.hpp:1833`) finds the entry (no-op if gone), cancels the resolve-timeout, erases the entry (`tcp_engine.hpp:1846`), and either fires `onClose(Resolve)` (`gai != 0 || !addrs || !addrs->get()`) or runs `connectFromAddrs(ConnectReq{sid, host, port, tls, verifyName, x509HostFlags}, addrs->get())` (`tcp_engine.hpp:1861`) -- the existing single-address connect loop verbatim. Note the defensive `gai == 0`-with-null-chain path: it uses the fixed string `"resolve returned no addresses"` rather than `resolveErrorMessage(0)` (which would say `"Success"`, `tcp_engine.hpp:1854`).

**Resolve-timeout** (`handleResolveTimeout`, TimerService thread, `tcp_engine.hpp:1871`) does only `runOnIoThread([this, sid]{ resolveTimeoutOnIo(sid); })`. `resolveTimeoutOnIo` (I/O thread, `tcp_engine.hpp:1879`) erases the entry if present and fires `onClose(Resolve, "resolve timeout")`.

**Close during resolve** (the `Cmd::Close` command handler, I/O thread, `tcp_engine.hpp:1480`) consults `_pendingConnects` **before** the `_sessions` lookup: a pending sid gets its resolve-timeout cancelled, the entry erased, and a single terminal `onClose` fired; the later `resumeConnect` finds nothing and no-ops.

### 3.8 UDP kickoff / resume / timeout / close

The UDP engine has **no TimerService**, so it drives the resolve-timeout off its existing periodic GC (`runGc` on the I/O thread, `udp_engine.hpp:2041`).

- **`connectDo`** (`udp_engine.hpp:1519`) -- literal short-circuit is synchronous (`resolveLiteralSync` uses `AI_NUMERICHOST | AI_NUMERICSERV`, defensive-by-construction, `udp_engine.hpp:1459`). Named host: `hints` from `namedResolveHints()` (`AF_UNSPEC`, `SOCK_DGRAM`, `IPPROTO_UDP`, `AI_ADDRCONFIG`, `udp_engine.hpp:1507`), record `_pendingConnects[sid]` with `resolveDeadline = MonoClock::now() + resolveTimeout` (`udp_engine.hpp:1541`), kick off `resolveHostAsync`, resume via `resumeConnect` (`udp_engine.hpp:1558`) -> `connectFromAddrs` (a single `::connect`; no `EINPROGRESS` / TLS, `udp_engine.hpp:1579`).
- **`viaDo`** (`connectViaListener`, a **session-creation** resolve, **not** a per-datagram send, `udp_engine.hpp:1667`) -- reuses the same `_pendingConnects` one-shot machinery. RESUME (`resumeVia` -> `viaFromAddrs`) **re-looks-up** the listener by `lid` and does the AF-match against the listener's **current** AF (avoiding a kickoff-snapshot TOCTOU on a listener rebind), then creates the peer session on the **listener fd** (source-port preserved, RFC 3581). Every post-resolution terminal is a one-shot eraser-fire: listener-gone / AF-mismatch / AF-unknown / session-cap -> `onClose(Config)`; resolve failure -> `onClose(Resolve)`; success -> `onConnect`. There is **no per-destination coalescing** (`sendDo` has no `getaddrinfo`).
- **Resolve-timeout scan** (`runGc`, I/O thread, `udp_engine.hpp:2041`) uses **collect-then-fire** (mirroring the session GC): first collect every sid whose `resolveDeadline != MonoTime{} && now >= deadline`, **then** call `resolveTimeoutOnIo(sid)` (`udp_engine.hpp:2108`) for each -- never erasing `_pendingConnects` during iteration (#15). Because the deadline is observed at most one `gcInterval` late, the **effective UDP resolve-timeout window is `[resolveTimeout, resolveTimeout + gcInterval]`** -- the budget accounting includes `gcInterval` (see §9).

### 3.9 Per-connection TLS identity carried through the resume (SNI / RFC 6125, 9525)

The named-host connect path threads the caller's per-connection TLS identity options through the off-thread resolve so the resumed connect reaches the TLS setup site with them. The `connect` primitive on `EngineBase` is:

```cpp
// engine_base.hpp:94
virtual ConnectResult connect(const std::string &host, std::uint16_t port,
                              TlsMode tlsMode, const TlsClientOptions &opts) = 0;
// engine_base.hpp:99-101 -- non-pure legacy 3-arg overload delegates with empty opts.
```

`TlsClientOptions` (`transport_types.hpp:219`) carries `verifyName` + `x509HostFlags`. The TCP engine copies them into `ConnectReq` (`tcp_engine.hpp:388`, fields at `833-834`), and the resume closure carries them by value all the way to `connectFromAddrs`. At the TLS setup site (`tcp_engine.hpp:2032-2074`) the reference identity is `verifyName` if set, else the connect address (`refName`, `tcp_engine.hpp:2036`), and it is applied to the SSL object:

- **SNI** -- `SSL_set_tlsext_host_name` (`tcp_engine.hpp:2068`).
- **RFC 6125 / 9525 host verification** -- `X509_VERIFY_PARAM_set_hostflags(vp, x509HostFlags)` + `SSL_set1_host` (`tcp_engine.hpp:2073-2074`); a literal-IP reference identity uses `X509_VERIFY_PARAM_set1_ip_asc` instead (`tcp_engine.hpp:2060`). The handshake result is checked with `SSL_get_verify_result` (`tcp_engine.hpp:2398`). (This is the generic OpenSSL server-identity mechanism specified by RFC 6125 and obsoleted by RFC 9525 -- it is protocol-generic, NOT the SIP-specific RFC 5922 "Domain Certificates in SIP".)

This closes the former "F1: SNI absent" limitation of the 1.0 guide (see Revision History). It is included here only because the off-thread-resolve resume chain is the transport for these fields; the full TLS-identity semantics belong to the transport/TLS guide.

### 3.10 Per-engine lifecycle (start / drain / close)

Both engines wire the gate **independently** -- TCP and UDP have separate `start()`, `shutdownDrain()`, and close implementations. Wiring only TCP would leave UDP's off-thread resolve UAF-unsafe at teardown (the gate's `closed` never set -> the continuation dereferences a freed `EngineBase*`), stale-guard-broken at restart, and orphaning terminals. The base-member location of `_postGuard` makes this easy to miss, so **verify every derived engine wires both hooks**.

**`start()`** re-creates the gate (`_postGuard = std::make_shared<EnginePostGate>(); _postGuard->engine = this;` -- `tcp_engine.hpp:202-203`, `udp_engine.hpp:155-156`) **before** the loop, co-located with the command-queue reopen. A resolver continuation left over from a prior run keeps its **old** (closed) gate and drops; continuations from this run see the fresh (open) gate. Without this, every post-restart named-host resolve would drop against a permanently-closed gate -- a spurious `onClose(Resolve)`.

**`shutdownDrain()`** (at loop exit, before member destruction) does, in order (TCP `tcp_engine.hpp:1218-1321`, UDP `udp_engine.hpp:917-1016`):
1. **(a)** a **standalone** `gate->m` section -- `{ closed = true; engine = nullptr; }` -- **before** the `_cmdMutex` / `_qmx` teardown block, never nested inside it (lock order: `gate->m` strictly **outside** `_cmdMutex` / `_qmx`).
2. **(b)** drain `_pendingConnects` **collect-then-fire**: collect the pending sids, copy `onClose` under `_cbMutex`, then for each sid cancel its resolve-timeout (TCP: `_timerService->cancel`; UDP: just erase), erase, and fire exactly one `onClose(ShuttingDown, "shutdown")` -- outside `gate->m` and outside the command-queue teardown block, erasing **before** firing so a re-entrant callback cannot double-fire.
3. close `_eventFd` and the command queue together under `_cmdMutex` / `_qmx`.

`~EngineBase` is **forbidden** as a close site -- closing must happen in the derived `shutdownDrain`.

---

## 4. Usage Guide

This feature is **transparent** to transport consumers: a named host that previously blocked the I/O thread now resolves off-thread, and the terminal events are unchanged in shape. There is no new public API on `Transport` for resolution -- you observe the feature through the existing callbacks and the `resolveTimeout` config knob. `resolveHostAsync` / `NameResolver` is internal; applications do not call it directly.

### 4.1 Named-host connect (TCP) -- nothing changes at the call site

```cpp
#include <iora/network/transport_impl.hpp>  // in exactly ONE TU
using namespace iora::network;

auto transport = Transport::tcp();

transport->onConnect([&transport](SessionId sid, const TransportAddress &peer)
{
  std::string msg = "hello";
  transport->send(sid, msg.data(), msg.size());
});

transport->onClose([](SessionId sid, const TransportErrorInfo &reason)
{
  // A named-host resolve failure now arrives here as TransportError::Resolve
  // (message "resolve timeout", a getaddrinfo string, or "resolver pool saturated").
  if (reason.code == TransportError::Resolve)
  {
    std::cerr << "resolve failed: " << reason.message << "\n";
  }
});

transport->start();
transport->connect("sip.example.com", 5060);  // resolves OFF the I/O thread
```

**Send only after `onConnect` (CF-H1).** Because a named-host connect now resolves off-thread, the session is **not created synchronously** when `connect()` returns -- it is inserted into `_sessions` only when `resumeConnect` -> `connectFromAddrs` runs on the I/O thread after the resolve completes. A `send()` issued before then is rejected at enqueue time: `sessionSendable(sid)` (`tcp_engine.hpp:739`) returns `false` for an unknown/not-yet-created session and `send()` returns `false` (`tcp_engine.hpp:411`). You must therefore issue the first `send` from inside the `onConnect` callback (as above) rather than immediately after `connect()` returns; FIFO command ordering can no longer be assumed to sequence a Send after the session exists, since the intervening resolve is asynchronous. See [transport_sync_lifecycle.md](transport_sync_lifecycle.md) and [transport.md](transport.md) for the full connect-then-send / synchronous-send mechanism.

### 4.2 Tuning the resolve timeout on the engine config

```cpp
#include <iora/network/transport_impl.hpp>
using namespace iora::network;

TransportConfig cfg = TransportConfig::forSipUdp();
cfg.resolveTimeout = std::chrono::milliseconds(3000);  // off-thread resolution budget
cfg.gcInterval     = std::chrono::seconds(5);          // UDP: resolve-timeout precision

auto transport = Transport::udp(cfg);
transport->start();
transport->connect("peer.example.net", 5060);
```

Setting `cfg.resolveTimeout = std::chrono::milliseconds::zero()` **disables** the engine's resolve-timeout -- permitted for the raw engine, but **rejected for any SIP profile** (see §4.4).

### 4.3 Literal IP -- still synchronous

```cpp
// A literal IPv4/IPv6 address short-circuits the resolver entirely and connects
// synchronously on the I/O thread (inet_pton path). No blockingIoPool() dispatch,
// no resolve-timeout, no _pendingConnects entry.
transport->connect("192.0.2.10", 5060);
transport->connect("2001:db8::1", 5060);
```

### 4.4 SIP transport: configure the per-profile budget (downstream consumer, iora_sip)

The iora_sip transport layer sizes and validates these knobs for SIP; the values below are the iora_sip defaults and are enforced by its startup budget assert (`validateResolveBudget`). This is a downstream consumer of the iora-side feature documented here, not part of `name_resolver.hpp`.

```cpp
#include <iora/sip/transport/SipTransportManager.hpp>
using namespace iora::sip::transport;

SipTransportProfile tls = createTlsProfile("edge-tls", "0.0.0.0", 5061);
tls.resolveTimeout    = std::chrono::milliseconds(3000);  // MUST be > 0 for SIP
tls.connectionTimeout = std::chrono::milliseconds(5000);
tls.handshakeTimeout  = std::chrono::milliseconds(5000);
// Startup asserts resolveTimeout + connectionTimeout + handshakeTimeout < Timer_B/2.
// At the default T1 (Timer B = 32s, ceiling 16s): 3000 + 5000 + 5000 = 13000 ms  OK.
```

### 4.5 Anti-Patterns

- **Do NOT resolve on the I/O thread again.** The whole point is that `doConnect` / `connectDo` / `viaDo` only *arm and kick off*; they must never call `::getaddrinfo` for a named host on the loop thread. The literal-IP short-circuit is the only synchronous resolution.
- **Do NOT free the resolved chain in the connect loop.** `connectFromAddrs` / `viaFromAddrs` receive an externally-owned `addrinfo*`; the `shared_ptr<OwnedAddrInfo>` frees it exactly once. A `::freeaddrinfo` there double-frees.
- **Do NOT wire the gate in only one engine.** `_postGuard` lives on `EngineBase`, but the close/re-create hooks are per-engine. A new `EngineBase` subclass must wire `start()` (re-create) and `shutdownDrain()` (close + drain) itself, or its off-thread resolve is UAF-unsafe at teardown.
- **Do NOT disable `resolveTimeout` for a SIP profile.** `resolveTimeout == 0` is a budget violation, not a zero contribution -- a never-timing-out resolve leaves a named-host connect unbounded by Timer B. `validateResolveBudget` throws at startup.
- **Do NOT expect a distinct saturation code at the public API.** `RESOLVER_POOL_SATURATED` collapses to `TransportError::Resolve`. Distinguish it only by the `"resolver pool saturated"` message string, never by an enum value.
- **Do NOT rely on the UDP resolve-timeout firing exactly at `resolveTimeout`.** It is observed by the GC scan, so it fires within `[resolveTimeout, resolveTimeout + gcInterval]`.
- **Do NOT confuse `NameResolver` with `DnsClient`.** They consult different resolution stacks and can disagree (see the boundary subsection in §1). Use `DnsClient` when you need DNS records or SRV service-location as data.

---

## 5. Call Flow / Sequence Reference

### 5.1 Named-host connect -- success (TCP)

| Step | Thread | Action | State |
|------|--------|--------|-------|
| 1 | Caller | `connect(host, port)` enqueues `Cmd::Connect` | -- |
| 2 | I/O | `doConnect`: not a literal -> build `hints` (`AI_ADDRCONFIG`) | -- |
| 3 | I/O | `_timerService->scheduleAfter(resolveTimeout, handleResolveTimeout)` | `resolveTimeoutId` armed |
| 4 | I/O | `_pendingConnects[sid] = pc` | entry created |
| 5 | I/O | `resolveHostAsync(...)` -> `tryEnqueue` succeeds; `doConnect` returns | I/O thread free |
| 6 | Pool | `::getaddrinfo` -> chain; build resume closure (owns `sid`+`addrs`) | -- |
| 7 | Pool | lock `gate->m`; `closed == false` -> `runOnIoThread(resume)` | `Cmd::RunOnIo` queued |
| 8 | I/O | `resumeConnect`: find entry, `cancel(resolveTimeoutId)`, erase | entry gone (RESUME won) |
| 9 | I/O | `connectFromAddrs` -> `socket()` / `connect()` -> eventually `onConnect(sid, peer)` | session live |

### 5.2 Timeout-then-resolve-completes race (exactly one terminal)

| Step | Thread | Action | State |
|------|--------|--------|-------|
| 1 | TimerService | `handleResolveTimeout(sid)` -> `runOnIoThread(resolveTimeoutOnIo)` | `Cmd::RunOnIo` queued |
| 2 | I/O | `resolveTimeoutOnIo`: find entry, **erase**, `onClose(Resolve, "resolve timeout")` | entry gone (timeout won) |
| 3 | Pool | resolve finishes late -> `runOnIoThread(resume)` | queued |
| 4 | I/O | `resumeConnect`: `_pendingConnects.find(sid) == end()` -> **no-op** | `addrs` frees; no session |

Exactly one terminal (`onClose(Resolve)`), no session created.

### 5.3 Teardown with in-flight resolve

| Step | Thread | Action | State |
|------|--------|--------|-------|
| 1 | I/O | `shutdownDrain` (a): `lock(gate->m)`; `closed = true; engine = nullptr` | gate closed |
| 2 | I/O | `shutdownDrain` (b): collect pending sids; copy `onClose` under `_cbMutex` | -- |
| 3 | I/O | per sid: cancel resolve-timeout, erase, `onClose(ShuttingDown, "shutdown")` | one terminal each |
| 4 | Pool | continuation runs late: `lock(gate->m)`; `closed == true` -> **drop** | `addrs` frees |

Teardown blocks at most for one `noexcept` `runOnIoThread` post, never for `getaddrinfo`. Exactly one `onClose(ShuttingDown)` per pending sid.

### 5.4 Pool saturation (reject-fast)

| Step | Thread | Action | State |
|------|--------|--------|-------|
| 1 | I/O | `doConnect` / `connectDo`: arm timeout, record `_pendingConnects[sid]` | entry created |
| 2 | I/O | `resolveHostAsync` -> `tryEnqueue` returns `false` (145th stuck resolve) | task dropped |
| 3 | I/O | `onComplete` runs **inline** with `{RESOLVER_POOL_SATURATED, nullptr}` | -- |
| 4 | I/O | continuation: `lock(gate->m)`, `closed == false` -> `runOnIoThread(resume)` | queued |
| 5 | I/O | `resumeConnect`: erase entry; `gai != 0` -> `onClose(Resolve, "resolver pool saturated")` | one terminal |

Note: on saturation the continuation runs on the **caller's thread** (the I/O thread here, since `doConnect` runs there), so it posts the resume back through `runOnIoThread` like any other continuation.

---

## 6. Thread Safety Model

| Operation | Thread | Synchronization | Notes |
|-----------|--------|-----------------|-------|
| `resolveHostAsync` dispatch | Caller/I/O | `ThreadPool` internal (`tryEnqueue`) | Task captures only value copies; no `this`/engine (#5) |
| `::getaddrinfo` | Pool | None (self-owning) | Runs **only** on `blockingIoPool()` (#11); no I/O-thread block (#1) |
| Resolver continuation | Pool | `gate->m` (post) | Builds closure **outside** `gate->m`; posts under it iff `!closed` (#8) |
| `runOnIoThread` | Pool / TimerService | `_cmdMutex` / `_qmx` | `noexcept`, callback-free; returns `false` on closed/OOM, no user callback (#10/#14) |
| `_pendingConnects` mutate | I/O only | None (I/O-thread-confined) | `doConnect` / `resume*` / `resolveTimeoutOnIo` / `Cmd::Close` handler / `shutdownDrain` (#7) |
| `resumeConnect` / `resumeVia` | I/O | None | One-shot: connect only if it erased the entry (#7) |
| `resolveTimeoutOnIo` | I/O | Copies `onClose` under `_cbMutex`, invokes outside | Copy-then-invoke (#14) |
| TCP `handleResolveTimeout` | TimerService | Marshals via `runOnIoThread` | Never mutates `_pendingConnects` directly (#8b) |
| UDP resolve-deadline scan | I/O (`runGc`) | None | Collect-then-fire; never erase during iteration (#15) |
| `shutdownDrain` gate close | I/O | `gate->m` standalone, **before** `_cmdMutex` / `_qmx` | Lock order: `gate->m` outside command mutex (#13) |

### 6.1 Invariants (from the architecture doc, verified against source)

- **#1 / #11 / #12** -- the I/O thread never blocks on `::getaddrinfo`; resolution runs only on `blockingIoPool()`; no `std::async` future is joined and no `DnsClient` is used (non-joining everywhere).
- **#4 / #5** -- kickoff holds no engine mutex across the resolve dispatch; resume state is owned (captured by value in the deferred closure), no `[&]` capture.
- **#6** -- `::freeaddrinfo` runs exactly once via `OwnedAddrInfo`'s destructor when the sole `shared_ptr` drops; the `RunOnIo` command stays copyable.
- **#7 / #7b** -- `_pendingConnects[sid]` is the single-owner one-shot terminal with three eraser-fire sites; teardown drains it (collect-then-fire; one `onClose(ShuttingDown)` per sid).
- **#8 / #8b** -- engine-lifetime safety via `EnginePostGate` (post under `gate->m` iff `!closed`; `shutdownDrain` sets `closed=true` + `engine=nullptr`; re-created on `start()` before the loop). TCP resolve-timeout's `this`-lifetime is bounded by `~TimerService` joining the timer thread before `_cmds` / `_cmdMutex` / `_eventFd` are destroyed (they are declared **before** `_timerService`). UDP's resolve-timeout is I/O-thread-confined (GC scan; no TimerService, no cross-thread post) and needs no such bound.
- **#9** -- the continuation runs on the pool thread (except the reject-fast inline path); it only builds the owned closure, takes `gate->m`, and posts/frees. It must not touch `_sessions` / `_fdTags` / SSL / `_timerService` and references only immortal statics.
- **#10 / #13 / #14** -- every foreign-thread post goes through `runOnIoThread` (noexcept, no user callback), never a raw `_cmds` push and never a callback-firing enqueue while `gate->m` is held; `gate->m` is strictly outside `_cmdMutex` / `_qmx`; no user-facing callback runs while `gate->m` is held.
- **#15** -- the UDP resolve-deadline scan uses collect-then-fire, never erase-during-iteration.
- **#16** (OOM residual) -- if **both** the resolver post and the TCP resolve-timeout's own `runOnIoThread` fail on `bad_alloc`, an async connect observer gets no terminal until teardown drains `_pendingConnects` (`connectSync` and the UDP GC scan are unaffected). Documented, not fixed.

### 6.2 SIP-layer callback surfacing (downstream, iora_sip)

The SIP transport `onClose` handlers (UDP/TCP/TLS) classify a `TransportError::Resolve` close as a **connect-setup error**, alongside `Connect` (and `TLSHandshake` for TLS). This lets the reject-fast / resolve-failure message reach the SIP connection-error callback so the consumer fails the transaction fast instead of waiting out Timer B/F. The classification runs under the SIP session mutex, but `onConnectionError` is invoked **outside** the lock (copy-then-invoke). This surfacing is in iora_sip, not in the iora headers this guide homes; it is noted here only to complete the failure story.

---

## 7. Configuration Reference

### 7.1 Engine config -- `iora::network::TransportConfig` (`transport_types.hpp:356`)

| Field | Type | Default | Units | Notes |
|-------|------|---------|-------|-------|
| `resolveTimeout` | `std::chrono::milliseconds` | `5000` | ms | Off-thread name-resolution timeout (`transport_types.hpp:369`). `count() == 0` disables it. SIP transports MUST NOT disable it. |
| `connectTimeout` | `std::chrono::milliseconds` | `30000` | ms | TCP outbound connect timeout (`transport_types.hpp:363`). |
| `handshakeTimeout` | `std::chrono::milliseconds` | `30000` | ms | TLS handshake timeout (`transport_types.hpp:364`). The SIP layer lowers this to a SIP-sized value. |
| `gcInterval` | `std::chrono::seconds` | `5` | s | GC sweep interval (`transport_types.hpp:371`). On **UDP** it also bounds resolve-timeout precision, so it counts toward the UDP connect-setup budget. |

Neither `forSipTcp()` (`transport_types.hpp:452`) nor `forSipUdp()` (`transport_types.hpp:467`) overrides `resolveTimeout` / `handshakeTimeout` on the engine config -- SIP-sizing is applied by the iora_sip layer below.

### 7.2 `blockingIoPool()` (fixed -- not runtime-configurable)

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `initialSize` | `2` | Worker threads spawned at first use. |
| `maxSize` | `16` | Hard cap on worker threads. |
| `idleTimeout` | `30 s` | Idle worker reap interval. |
| `maxQueueSize` | `128` | `tryEnqueue` fails past this -> `RESOLVER_POOL_SATURATED`. |

Saturation threshold: `maxSize(16) + maxQueueSize(128) + 1 = 145` concurrently-stuck named resolves.

### 7.3 SIP profile budget (downstream consumer, iora_sip)

The iora_sip layer copies its per-profile timeouts onto the engine config and calls `validateResolveBudget`, which enforces that the connect-setup latency (which runs **inside** Timer B before the first request reaches the wire) stays under **`Timer_B / 2`**. The sum is **per-protocol** -- each transport contributes only the phases it performs:

| Protocol | Budget terms | Rationale |
|----------|--------------|-----------|
| **UDP** | `resolveTimeout + gcInterval` | The "connect" is an instant kernel route-bind (`SOCK_DGRAM`), no handshake. The resolve-timeout is observed by the I/O-thread GC scan, so its slack is one `gcInterval`. |
| **TCP** (also WS/SCTP) | `resolveTimeout + connectionTimeout` | No TLS handshake; the resolve-timeout is driven by the precise `TimerService` (no `gcInterval` slack). |
| **TLS** (also WSS) | `resolveTimeout + connectionTimeout + handshakeTimeout` | Full TLS handshake latency added. |

A violation throws a `TransportException` at startup. Additionally, `resolveTimeout <= 0` is rejected outright for SIP: a resolve that never times out can block a named-host connect indefinitely, unbounded by Timer B. (These values and the assert live in iora_sip; the iora side only exposes `TransportConfig::resolveTimeout` / `gcInterval`.)

---

## 8. Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Move resolution off the I/O thread** | A blocking `::getaddrinfo` on the single epoll thread stalls every session's timers and parsing at once -- for SIP, engine-wide timer skew past `64*T1` and spurious call failures. |
| **`::getaddrinfo` (`NameResolver`), not `DnsClient`** | Self-owning and abandonable, and it honors system resolution semantics (`/etc/hosts`, NSS, `resolv.conf` search) that a Transport connect must obey. `DnsClient` would add a parity mismatch, a header cycle, and a blocking destructor. Recorded so no future review re-proposes it. |
| **Dedicated immortal `blockingIoPool()`** | Blocking, uncancellable syscalls must never run on an event-loop thread or on a shared/general executor. Immortal because a stuck resolver may be parked at process exit -- joining it would hang teardown (LoggerData precedent). |
| **Reject-fast (`tryEnqueue`, `maxSize=16`, `maxQueueSize=128`)** | A hung DNS server must not spawn unbounded workers or starve unrelated work. Saturation surfaces as `RESOLVER_POOL_SATURATED` -> `TransportError::Resolve`, distinguished only by message. |
| **`shared_ptr<OwnedAddrInfo>` carrier** | Keeps the `RunOnIo` command copyable and guarantees `::freeaddrinfo` runs exactly once when the last handle drops. The connect loop never frees (external ownership). |
| **Generic `runOnIoThread` seam** | A single noexcept, callback-free posting primitive on `EngineBase` (mirroring `scheduleSelfDestruct`), reused by both engines and by both the resolver continuation and the TCP timeout marshal. |
| **`EnginePostGate` re-created on `start()`, closed in `shutdownDrain`** | Makes the cross-thread post safe across teardown (closed -> drop) and restart (stale continuations keep the old closed gate). Teardown blocks at most one noexcept post, never `getaddrinfo`. |
| **`gate->m` strictly outside `_cmdMutex` / `_qmx`; no callback under `gate->m`** | Fixed lock order prevents a lock-inversion; the continuation never fires a user callback while holding the gate (#13/#14). |
| **Single-owner `_pendingConnects` one-shot, three eraser sites** | Exactly-once and at-least-once terminal delivery under timeout-vs-resolve, close-during-resolve, and teardown races. I/O-thread-confined, so no lock. |
| **Per-engine lifecycle wiring** | `_postGuard` lives on the base, but the close/re-create hooks are per-engine. Wiring only TCP would leave UDP UAF-unsafe at teardown, so both engines wire `start()` / `shutdownDrain()` / close independently. |
| **TCP timeout via `TimerService`, UDP via GC scan** | UDP has no `TimerService`; its resolve-timeout is an absolute deadline observed by the existing `runGc` collect-then-fire scan, I/O-thread-confined (no cross-thread post, no `~TimerService` dependency). |
| **`AI_ADDRCONFIG` on named-host hints** | On an IPv4-only host, avoid returning AAAA for a dual-stack FQDN -- otherwise the single-address, terminal-on-failure connect hits `ENETUNREACH` on the AAAA and never tries the reachable A record. |
| **Unchanged single-address connect** | Core scope keeps the existing connect loop verbatim (break on first `EINPROGRESS`, terminal on failure). Multi-address failover is the separate F2 initiative. |
| **Per-connection TLS identity through the resume** | `verifyName` / `x509HostFlags` travel by value through every capture layer so a named-host `sips:` connect reaches the SSL setup site with SNI + RFC 6125 / 9525 host verification (see §3.9). |
| **Per-protocol budget under `Timer_B/2` (iora_sip)** | Connect-setup latency runs inside Timer B before the first request reaches the wire; capping at half leaves round-trip budget. Each protocol counts only the phases it performs. |

---

## 9. Known Limitations

| Item | Impact |
|------|--------|
| **F2 async multi-address failover is out of scope.** This core keeps today's single-address, terminal-on-failure connect: the resolved chain is iterated exactly as before (break on first `EINPROGRESS` for TCP; single `::connect` for UDP), and a connect failure is terminal. Per-address sub-timeouts, per-attempt epoch tokens, and TLS-address failover live in the separate `transport_dns_failover` initiative and its own tracker. | A named host resolving to multiple addresses does not try the second address if the first fails to connect -- same behavior as before this feature. |
| **`NameResolver` and `DnsClient` can disagree.** `NameResolver`/getaddrinfo honors `/etc/hosts`, NSS ordering, and `resolv.conf` search/ndots; `DnsClient` queries `resolv.conf` nameservers directly (no `/etc/hosts`, no search-list) and falls back to public resolvers. In split-horizon / internal-DNS deployments the two can return different answers. | A Transport named-host connect (via `NameResolver`) always uses system resolution semantics; code that separately queried `DnsClient` for the same host may see a different address. This is by design; use the right tool per the §1 boundary. |
| **SIP-sized 3 s `resolveTimeout` is below glibc's ~5 s per-attempt resolver timeout.** A first-packet-loss abandons a lookup that the OS would otherwise retry. | On lossy-DNS deployments, a transient loss can fail a named-host connect that a longer timeout would have completed. Configurable -- raise `resolveTimeout` within the `Timer_B/2` budget for such deployments. |
| **UDP resolve-timeout precision is bounded by `gcInterval`.** The absolute deadline is observed by the periodic `runGc` scan, so it fires within `[resolveTimeout, resolveTimeout + gcInterval]` (default up to 5 s late). | Accounted for in the UDP budget (`resolveTimeout + gcInterval`); TCP has no such slack (precise `TimerService`). |
| **OOM residual (#16).** If **both** the resolver post and the TCP resolve-timeout's own `runOnIoThread` fail on `bad_alloc`, an async connect observer gets no terminal until teardown drains `_pendingConnects`. | Extremely rare (double allocation failure). `connectSync` (a Transport-layer CV) and the UDP GC scan are unaffected. Documented, not fixed. |

> **Resolved since 1.0.** The 1.0 guide listed "F1: SNI and RFC 6125 / 9525 cert-identity absent" and "UDP connection-error surfacing is inert end-to-end" as limitations. SNI / cert-identity is now implemented at the TLS setup site and reached through this resolve path's resume closure (§3.9). The UDP connection-error end-to-end wiring is an iora_sip concern outside this header's scope and is not re-asserted here.

---

## 10. API Reference

### 10.1 `iora::network` -- `NameResolver` (header-only, `name_resolver.hpp`)

```cpp
class OwnedAddrInfo
{
public:
  OwnedAddrInfo() noexcept = default;
  explicit OwnedAddrInfo(::addrinfo *head) noexcept;
  ~OwnedAddrInfo();                                        // ::freeaddrinfo iff non-null
  OwnedAddrInfo(const OwnedAddrInfo &) = delete;
  OwnedAddrInfo &operator=(const OwnedAddrInfo &) = delete;
  OwnedAddrInfo(OwnedAddrInfo &&other) noexcept;
  OwnedAddrInfo &operator=(OwnedAddrInfo &&other) noexcept;
  ::addrinfo *get() const noexcept;                        // borrow, no transfer
  ::addrinfo *release() noexcept;                          // relinquish ownership
  explicit operator bool() const noexcept;                 // true iff non-null
};

struct ResolveResult
{
  int gaiCode{0};
  std::shared_ptr<OwnedAddrInfo> addrs;
};

constexpr int RESOLVER_POOL_SATURATED = -1000000;

inline const char *resolveErrorMessage(int gaiCode) noexcept;

inline void resolveHostAsync(std::string host, std::string port, ::addrinfo hints,
                             std::function<void(ResolveResult)> onComplete);
```

### 10.2 `iora::core` (`thread_pool.hpp` decl; `iora_core.cpp` def)

```cpp
ThreadPool &blockingIoPool();   // immortal ThreadPool(2, 16, 30s, 128)
```

### 10.3 `iora::network::detail::EngineBase` (`engine_base.hpp`)

```cpp
struct EnginePostGate
{
  std::mutex m;
  bool closed{false};
  EngineBase *engine{nullptr};
};

class EngineBase
{
public:
  // ... existing interface ...
  virtual bool runOnIoThread(std::function<void()> fn) noexcept = 0;   // PUBLIC seam
protected:
  EngineBase();                                    // gate with engine == this
  std::shared_ptr<EnginePostGate> _postGuard;      // re-created on start(), closed in drain
};
```

### 10.4 Engine-internal (private) resolution members -- TCP (`tcp_engine.hpp`)

```cpp
struct PendingConnect { std::uint64_t resolveTimeoutId{0}; };
enum class Cmd { Shutdown, AddListener, Connect, Send, Close, RunOnIo };
// struct Command carries: std::function<void()> fn;  static Command runOnIo(fn);

bool runOnIoThread(std::function<void()> fn) noexcept override;
bool doConnect(const ConnectReq &cr);
std::function<void(iora::network::ResolveResult)> makeResolveContinuation(const ConnectReq &cr);
void resumeConnect(SessionId sid, const std::string &host, std::uint16_t port, TlsMode tls,
                   const std::string &verifyName, unsigned x509HostFlags,
                   std::shared_ptr<iora::network::OwnedAddrInfo> addrs, int gai);
void handleResolveTimeout(SessionId sid);       // TimerService thread; marshals only
void resolveTimeoutOnIo(SessionId sid);         // I/O thread
bool connectFromAddrs(const ConnectReq &cr, addrinfo *res);   // never frees res
```

> `ConnectReq` carries `{SessionId sid; std::string host; std::uint16_t port; TlsMode tls; std::string verifyName; unsigned x509HostFlags;}` (`tcp_engine.hpp:823-834`); `verifyName` / `x509HostFlags` come from `TlsClientOptions` on the `connect` primitive (`engine_base.hpp:94`).

### 10.5 Engine-internal (private) resolution members -- UDP (`udp_engine.hpp`)

```cpp
struct PendingConnect { MonoTime resolveDeadline{}; };
enum class CmdType { /* ... */ RunOnIo };
// struct Cmd carries: std::function<void()> fn;

bool runOnIoThread(std::function<void()> fn) noexcept override;
bool connectDo(const ConnectReq &cr);
bool viaDo(const ViaReq &vr);                    // connectViaListener session-creation
std::function<void(iora::network::ResolveResult)>
  makeResolveContinuation(std::function<void(std::shared_ptr<iora::network::OwnedAddrInfo>,
                                             int)> onResolved);
void resumeConnect(SessionId sid, const std::string &host, std::uint16_t port,
                   std::shared_ptr<iora::network::OwnedAddrInfo> addrs, int gai);
void resumeVia(SessionId sid, ListenerId lid,
               std::shared_ptr<iora::network::OwnedAddrInfo> addrs, int gai);
void resolveTimeoutOnIo(SessionId sid);          // I/O thread (from runGc scan)
static addrinfo namedResolveHints();             // AF_UNSPEC, SOCK_DGRAM, AI_ADDRCONFIG
bool resolveLiteralSync(const std::string &host, const std::string &port, SessionId sid,
                        iora::network::OwnedAddrInfo &out);   // literal short-circuit
```

### 10.6 SIP budget validation (downstream, iora_sip -- not in these headers)

```cpp
// iora::sip::transport (SipTransportManager.hpp)
TransportConfig createTransportConfig(const SipTransportProfile &profile);  // calls validate
void validateResolveBudget(const TransportConfig &config) const;            // throws on violation
```
