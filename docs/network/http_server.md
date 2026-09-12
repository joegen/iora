# Iora HTTP Server -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.2 |
| **Date** | 2026-09-13 |
| **Status** | IMPLEMENTED |
| **Headers** | `include/iora/network/http_server.hpp` (HttpServer + routing), `include/iora/network/webhook_server.hpp` (WebhookServer) |
| **Namespace** | `iora::network` |
| **Dependencies** | `iora::network::Transport` (`network/transport_impl.hpp`), `iora::core::ThreadPool` (`core/thread_pool.hpp`), `iora::core::Logger` (`core/logger.hpp`), the HTTP message model `HttpRequest`/`HttpResponse`/`HttpMethod`/`HttpHeaders` (`parsers/http_message.hpp`), and (WebhookServer only) `parsers::Json` (`parsers/json.hpp`). Linux-only via the transport engine (epoll). |

---

## 2. Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.2 | 2026-09-13 | **`quiesceTransport()` drain hardening (iora `2026-09-11-22`).** The pool drain (step 5) no longer caps at 2 s and abandons: it is now **unbounded to `getInFlightCount() == 0`** (the pool's single-critical-section in-flight count, replacing the two-sample `getPendingTaskCount()`/`getActiveThreadCount()` read that admitted the pop->`++_activeThreads` TOCTOU), closing the residual use-after-free where a worker past the 2 s cap dereferenced a destroyed derived member (e.g. `WebhookServer::_jsonConfig`). A `protected virtual drainDeadline()` (default 30 s) backs it with a **fatal-abort circuit breaker** -- past the deadline it writes to stderr and `std::abort()`s (a core dump instead of a silent hang or a UAF; every timed-path diagnostic is a direct stderr write, never the async Logger). Applies uniformly to public `stop()` and every subclass dtor. Doc: `stop()`/`quiesceTransport()`/`quiesceTransportNoexcept()` may abort; `noexcept` stops an exception escaping, not `abort()`; a `stop()`/destroy call from within a handler self-deadlocks. Known-limitation 2 s-drain-cap entry moved to RESOLVED with the generalized LT-8 rule. |
| 1.1 | 2026-09-12 | **Re-sync to landed fixes (iora `e00906e` / `475ffb2` / `c2b332e`).** Request framing hardened: chunked request bodies are now **de-chunked** before delivery (`HttpRequest::fromWireFormat` -> `decodeChunkedRequestBody`), so handlers and `WebhookServer::onJsonPost` see the decoded payload; the framer (`findChunkedRequestEnd`) now reaches the SAME framing verdict as the strict parser (conflicting (differing-value) duplicate `Content-Length`, `CL`+`TE`, non-final chunked coding, and invalid/out-of-range `Content-Length` all poison the connection with 400 + close), parses chunk-size as `1*HEXDIG` with subtraction bounds (no `size_t` wrap), uses the token-aware `detail::isChunkedFinalCoding` for chunked detection, and enforces the 10 MB body cap on the decoded chunked length (413). Connection management: the `Connection` header is parsed as a comma-separated token list (`connectionListHasToken`, RFC 9110 §7.6.1) and repeated `Connection` field-lines combine; RFC 9112 §9.3 version-aware persistence is computed on the per-request **worker-stack local** (HTTP/1.0 defaults to close) -- the shared `SessionInfo.connectionKeepAlive` / `SessionInfo.httpVersion` fields were **removed** (a pipelined-sibling race). Response: repeated `Set-Cookie` via `Response::add_cookie` / `HttpResponse::setCookies` (separate field-lines, RFC 6265 §3, CR/LF/NUL-guarded); a bare query key with no `=` now stores an empty value. Teardown: the subclass-quiesce invariant (`quiesceTransport` / `quiesceTransportNoexcept` + `onUpgradedClose`) is documented. Corrected the fabricated `explicit` on the `HttpServer`/`WebhookServer` constructors and the `WebhookServer` "defaulted destructor" claim; added 413/414/505 to the parse-error status set; documented the `Date` synthesis in `toWireFormat`. Still-open items retagged with tracker refs. |
| 1.0 | 2026-09-11 | **Consolidated guide.** Folds the former `http_server.md` (v3.0, 2026-09-06) and `http_routing.md` (v1.0.0, 2026-05-30) into one document under `docs/network/`, and re-verified every claim against the current headers. Corrected drift: `_transport` is a `std::shared_ptr<Transport>` created by the `Transport::tcp()` factory (S-3), not a `std::unique_ptr`; added the `setIdleTimeout`/`setGcInterval` accessors and the `_idleTimeout` (600 s) / `_gcInterval` (5 s) fields and their `start()`-time transport config; documented the `bool headersOnly` parameter on `sendErrorResponse`; expanded the `getStatusText` table to the real code set; and recorded that several formerly-tracked limitations are now closed in source (unguarded `handleIncomingData` closes, unsupported-method 501). Newly reported code findings: undecoded chunked request bodies, the chunked/`Content-Length` body-cap asymmetry, the dead `MAX_PENDING_REQUESTS` constant and the hard-coded `1024` in the overload log, and the never-populated HTTP/1.0 / keep-alive session fields. |

---

## 3. Executive Summary

### Problem

Iora needs a small, dependency-free HTTP/1.1 server for REST endpoints, webhooks, HTMX
front-ends, and as the base for protocol upgrades (WebSocket, Server-Sent Events). It must parse
and frame requests off a raw byte stream, dispatch by method and path with expressive patterns,
run handlers concurrently across a bounded worker pool, and emit RFC-conformant, keep-alive-safe
responses -- all without leaking the transport/epoll/OpenSSL machinery into consumers, and without
the historical footgun of a single global lock held across every handler invocation.

### Solution

A two-class hierarchy in `iora::network`, layered on the unified `Transport` facade:

- **`HttpServer`** -- the concrete, standalone-usable base. It owns the TCP/TLS `Transport`, a
  `core::ThreadPool`, per-session parse buffers, and the route table. It performs request framing
  (Content-Length and chunked), pattern-based dispatch, response-framing normalization, and
  graceful shutdown, and it exposes virtual seams (`onUpgradeRequest`, `onUpgradedData`,
  `onUpgradedClose`, `onResponseSuppressed`) plus protected transport primitives (`sendRaw`,
  `sendRawForSse`, `closeSession`, `markSessionUpgraded`) and a protected, idempotent
  `quiesceTransport()` teardown helper for subclasses and the SSE machinery.
- **The routing subsystem** (inside `http_server.hpp`) -- compiles each registered path once into a
  `CompiledPattern` (exact, named-segment, or trailing-wildcard), and matches with a deterministic
  precedence (exact > named > wildcard, then registration order) under a single narrow lock pass
  (`classifyRequest`). The matched handler is copied out by value and invoked with **no server lock
  held**, so handlers run concurrently and may safely call back into the transport for their own
  session.
- **`WebhookServer`** -- a thin (~160-line) `HttpServer` subclass. It has **no webhook-specific
  semantics** (no signature verification, no event model): it is simply `HttpServer` with JSON
  request/response wrappers. `onJsonGet`/`onJsonPost` auto-parse the request body into `parsers::Json`
  under a payload-size and parse-limit budget, invoke a `JsonHandler`, and auto-serialize the returned
  JSON. It is named `WebhookServer` for its intended use-case -- a convenience specialization for
  receiving webhook/callback POSTs (JSON request in, JSON response out) -- not for any built-in webhook
  protocol. See [`http_client.md`](http_client.md) for the client-side counterpart.

### Technical Impact

- **Concrete base, no forced derivation.** `HttpServer` has no pure virtuals; plain HTTP needs no
  subclass. WebSocket/SSE subclass the base without touching JSON code.
- **Handler concurrency.** The route-table lock is held only for the match; handlers execute in
  parallel on the worker pool, and a handler may write to its own session (`sendRaw` /
  `sendRawForSse` / `closeSession`) without self-deadlock.
- **Defense-in-depth response framing.** Every terminal response passes a dispatcher normalization
  choke point and the serializer backstop (`HttpResponse::toWireFormat`), so bodyless statuses,
  Content-Length synthesis/overwrite, spurious `Transfer-Encoding`, and CR/LF/NUL header injection
  are all corrected before the bytes reach the wire.
- **Bounded resource use.** Per-session buffer cap (1 MB), header cap (64 KB), body cap (10 MB), and
  a `tryEnqueue` thread-pool with 503 backpressure protect against slow-loris / oversized-request
  DoS.

---

## 4. System Architecture

### 4.1 Component relationships

```
HttpServer  (concrete base -- header-only; iora::network)
|
|-- std::shared_ptr<Transport> _transport      (TCP/TLS engine; created by Transport::tcp(config), S-3)
|     |-- onAccept  -> create SessionInfo, record peer host:port
|     |-- onData    -> handleIncomingData(sid, bytes, len)   [engine I/O thread]
|     |-- onClose   -> erase _sessionInfo[sid] + _upgradedSessions.erase(sid);
|     |                 fire onUpgradedClose(sid, reason) for an upgraded session (no lock held)
|     `-- onError   -> log
|
|-- core::ThreadPool _threadPool               (min 2, max 8 workers, 30 s idle)
|     `-- tryEnqueue(processHttpRequest)        -> 503 on overload (backpressure)
|
|-- Route table   _handlers :
|     std::unordered_map<HttpMethod, std::vector<std::pair<CompiledPattern, Handler>>>
|     |-- CompiledPattern { PatternKind kind; std::string raw; std::vector<Segment> segments;
|     |                     bool hasTrailingWildcard; }        (compiled once at registration)
|     |-- precedence: EXACT > NAMED > WILDCARD, then registration order
|     `-- _defaultHandler : Handler                            (optional 404 hook)
|
|-- Session state _sessionInfo :
|     std::unordered_map<SessionId, SessionInfo>              (guarded by _sessionMutex)
|     `-- SessionInfo { std::string buffer; peerAddress; peerPort;
|                       MAX_BUFFER_SIZE=1MB, MAX_HEADER_SIZE=64KB, MAX_BODY_SIZE=10MB }
|          (NO per-session keep-alive/version field: RFC 9112 §9.3 persistence is a
|           per-request WORKER-STACK local, not shared per-session state)
|
|-- _upgradedSessions : std::unordered_set<SessionId>         (data routed to onUpgradedData)
|
|-- Virtual seams
|     |-- onUpgradeRequest(sid, req, res)   -> protocol upgrade (default false)
|     |-- onUpgradedData(sid, data, len)    -> post-upgrade bytes (default no-op)
|     |-- onUpgradedClose(sid, reason)      -> upgraded-session transport close (default no-op)
|     `-- onResponseSuppressed(sid, req, res) -> SSE takeover (default false)
|
`-- Protected transport primitives + teardown
      quiesceTransport / quiesceTransportNoexcept(who)   (idempotent; subclass dtors call FIRST)
      markSessionUpgraded / sendRaw / sendRawForSse / closeSession
      handleIncomingData / processHttpRequest / sendErrorResponse
      getStatusText [static] / connectionListHasToken [static]
      findChunkedRequestEnd(data, bodyStart, bool& framingError) [const]
      getAllowedMethods [const, under _mutex]
      friend class SseStream;  friend void upgradeToSse(...);   (RD-17 access grant)

WebhookServer : public HttpServer   (webhook_server.hpp)
|-- JsonConfig { std::size_t maxPayloadSize = 10MB; parsers::ParseLimits parseLimits; }
|-- using JsonHandler = std::function<parsers::Json(const parsers::Json&)>;
|-- onJsonGet(path, JsonHandler)   -> wraps onGet:  parse body -> handler -> serialize
|-- onJsonPost(path, JsonHandler)  -> wraps onPost: parse body -> handler -> serialize
|-- ~WebhookServer() override      -> quiesceTransportNoexcept("~WebhookServer") FIRST
`-- private: JsonConfig _jsonConfig
```

The HTTP message model (`HttpRequest`/`HttpResponse`, request-line and header parsing, chunked-final
validation and chunked-body decode, the `statusForbidsBody` / `kBodyFramingHeaders` /
`headerHasInjection` / `isListValuedHeader` helpers, and the `Date` formatter) lives in
`parsers/http_message.hpp` -- see [`../parsers/http_message.md`](../parsers/http_message.md) -- and is
cross-referenced here rather than re-documented; that guide carries the wire-format grammar and RFC 9112
request-smuggling defenses. The transport layer this server consumes is documented in
[`transport.md`](transport.md); the WebSocket and HTTP-client siblings in
[`websocket.md`](websocket.md) and [`http_client.md`](http_client.md).

### 4.2 Request -> match -> handler -> response

```mermaid
sequenceDiagram
  participant Client
  participant Engine as Transport engine (epoll I/O thread)
  participant Server as HttpServer (I/O thread)
  participant Pool as ThreadPool worker
  participant Handler as User handler

  Client->>Engine: TCP bytes
  Engine->>Server: onData(sid, BufferView)
  Server->>Server: handleIncomingData: upgraded? append to buffer; frame (CL / chunked)
  alt buffer/header/body cap exceeded
    Server-->>Client: 431 / 413 (headers-only) + Connection close
  else complete request framed
    Server->>Pool: tryEnqueue(processHttpRequest)
    alt pool overloaded
      Server-->>Client: 503 Service Unavailable
    else enqueued
      Pool->>Server: processHttpRequest: parse (fromWireFormat), split query
      Server->>Server: Upgrade header? -> onUpgradeRequest
      Server->>Server: classifyRequest (acquire _mutex, match, copy out, release)
      Server->>Handler: invokeWithSafetyNet(handler, req, res)   [no lock held]
      Handler-->>Server: fills res (status, headers, body)
      Server->>Server: HEAD strip + framing normalization + injection guard
      Server->>Engine: sendAsync(sid, wire response)
      Engine-->>Client: HTTP/1.1 response
    end
  end
```

### 4.3 Threading model

| Thread | Responsibility |
|---|---|
| Engine I/O thread (one, epoll) | Accepts connections (`onAccept`), reads bytes and runs `onData` -> `handleIncomingData` (upgraded-check, buffer append, framing, size-limit rejection), performs the TLS handshake, runs `onClose` (which fires `onUpgradedClose` for an upgraded session, no lock held) / `onError`, and fires every `sendAsync` completion **synchronously on this thread**. There is no separate acceptor thread. |
| ThreadPool worker (min 2, max 8; 30 s idle reap) | Runs `processHttpRequest`: full HTTP parse, query split, upgrade check, `classifyRequest`, handler invocation, response-framing normalization, and the response send. Handlers run **concurrently** across workers -- the route-table lock is released before invocation. |
| Controlling thread | Constructs the server, registers routes, calls `start()` / `stop()` / `enableTls()` / config setters. |
| TLS | Handled inside the engine on the I/O thread; `enableTls` only validates and stores the cert/key/CA config, which `start()` translates into `TransportConfig::serverTls`. |

### 4.4 Where the transport fits

`HttpServer` is a consumer of the `Transport` facade (see `transport.md`). It always uses TCP
(`Transport::tcp(config)`), enables `TCP_NODELAY` and TCP keepalive, sets a bounded per-session
write queue, and -- when TLS is configured -- sets `serverTls` so the engine performs the server-side
handshake. Inbound bytes arrive as a zero-copy `BufferView` on the I/O thread; the server copies
them into the per-session parse buffer immediately.

---

## 5. Component Deep Dive

### 5.1 HttpServer lifecycle: construct, start, accept, stop

**Construction.** `HttpServer(bindAddress = "0.0.0.0", port = DEFAULT_PORT)` stores the endpoint and
constructs the `ThreadPool(2, 8, 30 s)`. No transport exists yet and nothing binds. The class is
**non-copyable and non-movable** (all four special members are `= delete`) because it owns a
`std::mutex`, an `std::atomic<bool>`, and the transport. `setPort` / `setBindAddress` /
`setIdleTimeout` / `setGcInterval` mutate config under `_mutex` and take effect at the next
`start()`.

**`start()`** (under `_mutex`) builds a `TransportConfig` (protocol TCP, `idleTimeout = _idleTimeout`,
`gcInterval = _gcInterval`, `maxPendingSyncOps = 32`, `defaultSyncTimeout = 30000 ms`,
`enableTcpNoDelay = true`, `tcpKeepalive.enable = true`, `maxWriteQueue = 1024`), copies any stored
`TlsConfig` into `config.serverTls` (with `verifyPeer = requireClientCert`), and creates the engine
via `Transport::tcp(config)`. It wires the four transport callbacks (`onAccept`, `onData`, `onClose`,
`onError`), starts the transport, and adds the listener on `_bindAddress:_port` (with `TlsMode::Server`
when TLS is enabled). Any failure throws `std::runtime_error`.

**Accept.** `onAccept` creates the `SessionInfo` for the new `SessionId` under `_sessionMutex`,
recording the peer host/port and an empty buffer.

**`stop()` / `quiesceTransport()`.** Public `stop()` is a one-line delegate to the protected,
idempotent `quiesceTransport()`, which performs the carefully staged graceful shutdown (SR-22 / LT-12):

1. Snapshot `_transport` under `_mutex`; if it is null (never started, or already quiesced) **early-out**
   -- this is what makes the method idempotent (the null check is keyed on `_transport` alone).
2. Store `_shutdown = true` (lock-free atomic) and sleep 50 ms so in-flight workers observe it.
3. **Holding no `_mutex`**, call `transport->stop()` on the snapshot (no new connections). `_mutex` must
   not be held here: `stop()` joins the I/O thread, whose shutdown-drain fires `onClose` ->
   `onUpgradedClose` (which takes a subclass `_wsMutex`), and a peer thread holding `_wsMutex` and
   waiting on `_mutex` (the documented `_wsMutex -> _mutex` send order) would close a 3-way deadlock.
4. Under `_sessionMutex` only, clear `_sessionInfo`.
5. **Holding no `_mutex`**, drain the thread pool to quiescence, polling
   `_threadPool.getInFlightCount()` (a single-critical-section read of queue depth + workers past the
   pop, under one pool-mutex hold) every 50 ms until it reaches 0. This is the **single-sample**
   predicate -- **not** the old two-sample `getPendingTaskCount() || getActiveThreadCount()` read, which
   admitted the pop->`++_activeThreads` TOCTOU (a worker popped-but-not-yet-counted was invisible to
   both). `_mutex` must not be held here either, because an in-flight worker re-acquires `_mutex` for its
   `sendRaw`/`closeSession`/deferred-close. The drain is **unbounded** (it must not return while a worker
   is still in a handler that may deref a soon-destroyed derived member -- the residual UAF this closes),
   guarded by a **fatal-abort circuit breaker**: past `drainDeadline()` (a `protected virtual`, default
   30 s) it writes a fatal diagnostic to **stderr** and calls `std::abort()` -- a core dump rather than a
   silent hang or a use-after-free (C++ cannot force-cancel a wedged `std::thread`; a never-returning
   handler would already hang the later unconditional `~ThreadPool` join). Every diagnostic on the timed
   drain->abort path is a direct `stderr` write, never the async `Logger` (whose `data.mutex` a wedged
   handler could hold, blocking the drain before the abort); the clock is captured after the last
   pre-loop log. A one-time "handlers are slow" warning is emitted (also via stderr) at `min(2 s,
   deadline/2)`. Sound only while the transport-driven `_threadPool.tryEnqueue` (in `processHttpRequest`)
   is the **sole** enqueuer.
6. Re-acquire `_mutex` and `_transport.reset()`.

**Subclass-quiesce teardown invariant (WS-TS1/WS-TS2).** `~HttpServer` runs only *after* a subclass's
own members are already destroyed, yet the transport I/O thread (`onUpgradedData` / `onUpgradedClose`)
and in-flight pool workers may still touch subclass state. Therefore **every `HttpServer` subclass that
adds state read by a worker or the I/O thread MUST call `quiesceTransport()` first in its own
destructor** -- `WebSocketServer` and `WebhookServer` do (`WebhookServer::~WebhookServer` calls the
noexcept wrapper `quiesceTransportNoexcept("~WebhookServer")` before `_jsonConfig` is destroyed). The
base `~HttpServer` then calls `stop()`, whose `quiesceTransport()` early-outs (nothing left to
quiesce). `quiesceTransportNoexcept(who)` centralizes the swallow-and-log so a throwing quiesce
(logging/engine-stop can allocate) never escapes a noexcept destructor -- but note the wrapper stops an
**exception** escaping, **not** `std::abort()`: a handler wedged past `drainDeadline()` aborts the
process through the wrapper. The unbounded drain (step 5) makes this invariant **absolute** for the
memory-safety guarantee -- `quiesceTransport()` returns only once `getInFlightCount() == 0`, so on return
no worker is still reading a derived member (`getInFlightCount() == 0` provably dominates every handler's
member access: the pool destroys the task functor before the `seq_cst --_busyThreads` the drain's acquire
read pairs with). The residual case is instead the wedged-handler fail-fast: past the deadline the
process aborts rather than destroy members under a live worker. **Do not** call `stop()`/destroy the
server from within one of its own request handlers -- the calling worker counts itself in-flight, so the
drain can never reach 0 and aborts at the deadline (a self-deadlock; accurate diagnostic tracked in
`2026-09-12-10`).

Handlers should poll `getShutdownChecker().isShuttingDown()` (a `ShutdownChecker` holding a
`const std::atomic<bool>&`) in long loops and return early with a 503. The virtual base destructor calls
`stop()` inside a `try/catch(...)` so it never throws during unwinding. Note `_upgradedSessions` is
**not** cleared by `quiesceTransport()` (only `_sessionInfo` is); it is emptied incrementally by
`onClose`.

### 5.2 Request framing (`handleIncomingData`)

`handleIncomingData` runs on the I/O thread and is the framing front door:

1. **Upgraded check** (copy-then-release): if `sid` is in `_upgradedSessions` (read under
   `_sessionMutex`, lock released before the call), the bytes go straight to `onUpgradedData` and
   HTTP parsing is bypassed. Releasing the lock first is essential -- the override typically calls
   `sendRaw` (takes `_mutex`) or touches session state (`_sessionMutex`), so holding `_sessionMutex`
   across the virtual call would risk an ABBA deadlock.
2. **Buffer append with a cap.** New bytes append to `SessionInfo::buffer` under `_sessionMutex`. If
   the append would exceed `MAX_BUFFER_SIZE` (1 MB), the incoming segment is dropped and the request
   is rejected: **431** if the header terminator (`\r\n\r\n`) has not yet been seen (header overflow),
   else **413** (accumulated body overflow). The status is discriminated while the buffer is held,
   checking the accumulated buffer plus the 3+3-byte overlap with the incoming segment so a straddling
   terminator is not missed. `sendErrorResponse` is called **after** the `_sessionMutex` scope
   (documented order `_mutex` -> `_sessionMutex`).
3. **Pipelining loop.** Locate `\r\n\r\n`; if absent, wait for more data. A header block larger than
   `MAX_HEADER_SIZE` (64 KB) -> **431**. Parse the framing-relevant header lines locally and **reach
   the same framing verdict as the strict parser** (`HttpRequest::fromWireFormat`), so the framer and
   parser can never disagree on where a request ends (RFC 9112 §6.3 request smuggling). Concretely the
   framer gathers every `Content-Length` field-line and the *last* `Transfer-Encoding` value, and emits
   **400 + close** (poisoning the connection) for any ambiguous framing: an obs-fold / whitespace-before-colon
   header line, a conflicting (differing-value) duplicate `Content-Length`, `Content-Length` together with
   `Transfer-Encoding`, or a `Transfer-Encoding` whose final coding is not chunked. A single
   `Content-Length` is validated as `1*DIGIT` before it drives the boundary: an invalid or out-of-range
   value is **400 + close** (SRV-L1; no longer a bare close), and a value over `MAX_BODY_SIZE` (10 MB)
   is **413**. Chunked detection uses the token-aware `detail::isChunkedFinalCoding` (so `x-chunked`
   does not false-positive); a chunked request is then framed with `findChunkedRequestEnd`.
4. **Dispatch to the pool.** The complete request slice is removed from the buffer and posted with
   `tryEnqueue(processHttpRequest)`. If the pool rejects it (overloaded) -> **503**; a high-load pool
   logs a warning but still enqueues.

`findChunkedRequestEnd(data, bodyStart, bool& framingError)` walks the chunk-size lines (validated
`1*HEXDIG`, chunk extensions stripped), skips each chunk's data plus its trailing CRLF using
**subtraction bounds** (never `pos + size`, which wraps `size_t` when the size has its MSB set), consumes
the trailer section up to the closing empty line, and returns the offset just past it. A definitively
malformed body (bad chunk-size, a chunk-data run not CRLF-terminated, an obs-folded trailer) sets
`framingError = true` and the caller poisons the connection with **400 + close**; a merely-incomplete
body returns `npos` with `framingError = false` to await more bytes. `findChunkedRequestEnd` determines
only **where the request ends** for pipelining; the chunked body is **decoded** later, by
`HttpRequest::fromWireFormat` -> `decodeChunkedRequestBody`, so the handler sees the decoded payload
(see Section 5.3).

### 5.3 Request processing and response framing (`processHttpRequest`)

Runs on a worker. If `_shutdown` is set, it emits a 503 (`Connection: close`) and closes. Otherwise:

1. **Parse** via `HttpRequest::fromWireFormat` (the parser enforces RFC 9112 request-line strictness,
   single-Host, obs-fold rejection, the Content-Length/Transfer-Encoding smuggling rules, and the
   request-target length limit; a malformed request throws `HttpRequestError` carrying a
   400/413/414/501/505 status -- see Section 7.3). When the final transfer-coding is chunked,
   `fromWireFormat` **de-chunks the body** (`decodeChunkedRequestBody`: strips chunk-size lines, chunk
   extensions, and trailers, and caps the decoded length at 10 MB -> 413), so the handler and
   `WebhookServer::onJsonPost` receive the **decoded** payload, not raw chunk framing (SRV-H1). Convert
   to the server's `Request` (method, path, headers, body), and set `req.sid = sid` once so **every**
   dispatch path carries the real session id.
2. **Connection persistence (RFC 9112 §9.3)** is decided here into a **worker-stack local**:
   `Connection: close` (any token in the comma-list) always closes; otherwise HTTP/1.1+ is persistent
   and HTTP/1.0 is non-persistent unless it carries `Connection: keep-alive`. The value is token-parsed
   via `connectionListHasToken`, not exact-matched. This local is consumed at the send path on the same
   stack; it is **not** written into `SessionInfo` (a shared per-session field would be clobbered by a
   concurrent pipelined sibling running on another worker -- SRV-M3).
3. **Peer address** copied from `SessionInfo` under `_sessionMutex`.
4. **Query split**: everything after `?` is parsed into `req.params` (raw, not percent-decoded, `+` not
   converted to space); `req.path` is the query-stripped path. A bare key with no `=` (`?flag`) stores
   an **empty value** (SRV-L2) so a handler can test flag presence; empty pairs are skipped; duplicate
   keys are last-wins (the map is single-valued).
5. **Upgrade check**: a case-insensitive scan for an `Upgrade` header; if present and
   `onUpgradeRequest` returns `true`, the populated response (typically 101) is sent, any buffered
   post-upgrade bytes are drained into `onUpgradedData`, and normal routing is skipped.
6. **Classify + dispatch** (Section 5.4).
7. **Framing normalization** (see below).
8. **Keep-alive decision + send** (Section 7) -- driven by the step-2 worker-local persistence decision.

**Response-framing normalization** is a single unlocked choke point on the worker's stack-local
`Response`, complemented by the serializer backstop in `HttpResponse::toWireFormat`
(defense-in-depth; the backstop is `const`, lock-free, and cannot be bypassed):

- **Out-of-range / interim status.** A handler status `< 200` or `> 599` is a programming error ->
  rewritten to **500** with all four `kBodyFramingHeaders` erased (an interim 1xx on the normal path
  is illegal; the legitimate 101 upgrade returned earlier).
- **Bodyless statuses (`statusForbidsBody`: 1xx / 204 / 304).** Body and the four body-framing /
  representation headers (`Content-Length`, `Content-Type`, `Transfer-Encoding`, `Trailer`) are
  **erased** (not zeroed); the 304 must-generate set, `Date`, and `Allow` are preserved.
- **205 Reset Content.** Deliberately not in `statusForbidsBody`: body dropped, spurious
  `Transfer-Encoding`/`Trailer`/`Content-Type` stripped, `Content-Length: 0` pinned (RFC 9112 §6.3
  rule 8, so the response is not close-delimited).
- **Non-bodyless framing.** Exactly one framing mechanism: a handler-set `Transfer-Encoding` is
  spurious (the server writes the whole body inline) and is stripped (with `Trailer`); the response
  is framed by `Content-Length`. Absent -> synthesized from `body.size()`; present but disagreeing
  with the body size on a non-HEAD response -> **overwritten** (a wrong value is a keep-alive-desync /
  response-splitting vector). A HEAD reports the would-be-GET `Content-Length` over an empty body.
- **HEAD body-strip** (RFC 9110 §9.3.2). Before the bodyless erase, if the handler set a body but no
  `Content-Length`, the GET-body length is synthesized; then `res.body` is cleared. The strip is
  applied uniformly on every terminal HEAD path.
- **Response-splitting guard** (RFC 9110 §5.5). Any response header whose name or value contains
  CR/LF/NUL (`headerHasInjection`) is **dropped whole**, logged without echoing the offending bytes.
  The same guard is applied to the repeatable `Set-Cookie` lines (they bypass the headers map).
- **Repeated `Set-Cookie` (SRV-M5).** `Response::cookies` (populated via `Response::add_cookie`) is
  moved into `HttpResponse::setCookies` and emitted by `toWireFormat` as **separate** `Set-Cookie`
  field-lines (RFC 6265 §3 -- these MUST NOT be comma-combined), so one response can set several cookies
  (e.g. a session cookie plus a CSRF cookie). `set_header("Set-Cookie", ...)` still goes through the
  single-valued headers map (last-wins) -- use `add_cookie` when more than one is needed.
- **`Date` synthesis.** `HttpResponse::toWireFormat` adds a `Date` header on any 2xx/3xx/4xx response
  when the handler set none (RFC 9110 §6.6.1; `detail::formatHttpDate`). 1xx/5xx are excluded (`Date` is
  MAY there). A bodyless 204/304 still gets a `Date` (it is not a framing header).

### 5.4 The routing subsystem

**Pattern compilation.** `onGet`/`onPost`/`onPut`/`onPatch`/`onDelete` call `registerHandler`, which
compiles the path once (`compilePattern`) under `_mutex` and appends `(CompiledPattern, Handler)` to
the per-method vector. `splitPath` tokenizes on `/`, **preserving leading, trailing, and interior
empty tokens** -- so `/users` (2 tokens) differs from `/users/` (3 tokens), the load-bearing invariant
for exact backward-compat and the wildcard empty-suffix rule.

| Kind | Syntax | Match rule | Capture |
|---|---|---|---|
| `EXACT` | `/users` | segment counts equal, all literals equal | none |
| `NAMED` | `/users/:id` | segment counts equal; `:name` (`[A-Za-z_][A-Za-z0-9_]*`) captures the token | `req.params["id"]` (raw) |
| `WILDCARD` | `/static/*` | request has `>=` the literal-prefix segments; prefix literals equal; suffix joined with `/` | `req.pathRest` (raw; may start with `/`, may be empty) |

`compilePattern` throws `std::invalid_argument` at **registration** (never at request time) for a
non-terminal `*`, a `*` mixed into a segment, or a `:` not followed by a valid identifier. A `:` that
is not the first character of a segment (e.g. `/time/12:30`) is literal.

**Match precedence.** `matchInMethodVector` scans the per-method vector in `{EXACT, NAMED, WILDCARD}`
order, registration order within each class, and stops at the first hit. EXACT re-registration of the
same path **overwrites** the prior handler; NAMED/WILDCARD re-registration **appends** (first
registered wins, so a duplicate is a dead entry).

**The single under-lock pass** (`classifyRequest`) acquires `_mutex` **once**, runs the decision
ladder, copies everything out **by value** into a `DispatchDecision`, and releases:

1. `OPTIONS *` -> `OPTIONS_STAR`.
2. `OPTIONS` on a matching path -> `AUTO_OPTIONS` (compute `Allow` under this lock); else fall through
   to `NO_ROUTE` (copy `_defaultHandler` out in the same lock).
3. `HEAD` on a matching GET route -> `MATCHED_AS_HEAD` (copy the GET handler out).
4. Method match -> `MATCHED` (copy the handler out; capture named params + wildcard suffix).
5. Path matches under another method -> `METHOD_NOT_ALLOWED` (compute `Allow`).
6. Else -> `NO_ROUTE` (copy `_defaultHandler` out if set).

Because `Handler` is a `std::function` copied by value, a concurrent `registerHandler` that
reallocates the vector cannot dangle the in-flight handler. The post-lock switch invokes the handler
inside `invokeWithSafetyNet` with **no lock held**, so handlers run concurrently and may call
`sendRaw`/`sendRawForSse`/`closeSession` on their own session without self-deadlock.

**`invokeWithSafetyNet`** wraps every handler in `try { handler(req, res); } catch (...) {...}`; both
clauses log at ERROR, set a generic **500** body, and **clear `res._suppressSend`** so a handler that
took over the session and then threw still gets a terminal 500 rather than a hung socket. The 405 /
auto-OPTIONS / `OPTIONS *` arms run no handler and are not wrapped.

**Auto behaviors.**

- **Auto HEAD-for-GET** runs the GET handler, then the uniform HEAD strip (Section 5.3). A handler
  that sets `_suppressSend` during a HEAD dispatch is overridden (forced to a bodyless 200 with a
  warning), so a HEAD can never become a half-open socket.
- **Auto-OPTIONS** on a matching path -> **204 No Content** + `Allow` (from `getAllowedMethods`), no
  body, no `Content-Type`.
- **`OPTIONS *`** -> **200** + `Content-Length: 0`, no `Allow`.
- **405** carries the canonical `Allow`. `getAllowedMethods` evaluates the same precedence match per
  method and emits a fixed canonical order (`GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS`), with HEAD
  synthesized whenever GET matches and OPTIONS self-listed. CONNECT/TRACE are never emitted (no
  registrar exposes them in v1).

**SSE / response suppression.** A non-Upgrade GET handler may take over the connection and stream by
writing its preamble via the protected `sendRawForSse`, then either setting `Response::_suppressSend`
or overriding `onResponseSuppressed` to return `true`. After a MATCHED / NO_ROUTE-with-handler
returns normally, the dispatcher sees the suppression and returns **without** sending anything (no
terminal response, no keep-alive/close decision). `sendRawForSse` returns `false` only when the
transport is down/shutting down (a secondary write-failure signal; the primary disconnect signal is
the transport observe callback). The `friend class SseStream` / `friend void upgradeToSse(...)` grant
gives the SSE machinery (defined in a later tier, `sse_stream.hpp`) the same reach a subclass gets,
with no public `transport()` leak.

### 5.5 WebhookServer -- the JSON specialization

`WebhookServer : public HttpServer` adds one private field (`_jsonConfig`) and four public methods.
`onJsonGet(endpoint, JsonHandler)` and `onJsonPost(endpoint, JsonHandler)` are thin wrappers that
register an ordinary `Handler` on the inherited `onGet`/`onPost`:

1. Enforce `req.body.size() <= _jsonConfig.maxPayloadSize` (default `DEFAULT_MAX_JSON_SIZE` = 10 MB).
2. Parse the body with `parsers::Json::parse(body, _jsonConfig.parseLimits)`; a parse failure throws.
   For `onJsonGet`, an empty body yields `parsers::Json::object()` instead of a parse.
3. Invoke the user's `JsonHandler` (`parsers::Json(const parsers::Json&)`).
4. Serialize the returned JSON with `res.set_content(json.dump(), "application/json")`.
5. On **any** `std::exception` (payload too large, parse error, handler throw), set status **500**,
   put `ex.what()` into a `text/plain` body, and log via `Logger::error`.

`setJsonConfig`/`getJsonConfig` set and read the config (no synchronization -- call before `start()`).
The destructor is **not** defaulted: `~WebhookServer()` calls `quiesceTransportNoexcept("~WebhookServer")`
**first**, before its `_jsonConfig` member is destroyed, because `onJsonGet`/`onJsonPost` handlers run on
pool workers and read `_jsonConfig` -- draining the pool only in the base `~HttpServer()` (after
`_jsonConfig` is already gone) would let a mid-handler worker deref a destroyed member (WS-TS2; the
subclass-quiesce invariant of Section 5.1). Because the wrappers
build on the routing subsystem, JSON endpoints may use named segments and wildcards, and plain and
JSON endpoints coexist on one server. Only GET and POST have JSON wrappers; PUT/PATCH/DELETE JSON
endpoints must use the raw `Handler` API.

---

## 6. Usage Guide

All examples are `iora::network`. A TU that includes the HTTP server (which pulls in the transport
implementation and, under TLS, OpenSSL) must be built with the OpenSSL wiring:
`configure_iora_target(<target> ENABLE_OPENSSL)` rather than a bare `iora_lib` link.

### 6.1 Plain HTTP: GET and POST routes

```cpp
#include <iora/network/http_server.hpp>
using namespace iora::network;

HttpServer server("0.0.0.0", 8080);

server.onGet("/health", [](const HttpServer::Request &req, HttpServer::Response &res)
{
  res.set_content("OK", "text/plain");
});

server.onPost("/api/data", [](const HttpServer::Request &req, HttpServer::Response &res)
{
  res.status = 201;
  res.set_content("received " + std::to_string(req.body.size()) + " bytes", "text/plain");
});

server.start();
// ... run ...
server.stop();
```

### 6.2 Path params and a trailing wildcard

```cpp
// Named segment -> req.params.
server.onGet("/users/:id", [](const HttpServer::Request &req, HttpServer::Response &res)
{
  res.set_content("user " + req.params.at("id"), "text/plain");   // raw, NOT percent-decoded
});

// Exact wins over named: /users/me always beats /users/:id.
server.onGet("/users/me", [](const HttpServer::Request &, HttpServer::Response &res)
{
  res.set_content("current user", "text/plain");
});

// Trailing wildcard -> req.pathRest (raw; may begin with '/').
server.onGet("/static/*", [](const HttpServer::Request &req, HttpServer::Response &res)
{
  // Path-traversal hardening is the CONSUMER's job: reject '..' and a leading '/'
  // before any filesystem join.
  res.set_content("would serve: " + req.pathRest, "text/plain");
});

// Custom 404.
server.setDefaultHandler([](const HttpServer::Request &, HttpServer::Response &res)
{
  res.status = 404;
  res.set_content("nothing here", "text/plain");
});
```

### 6.3 JSON endpoints via WebhookServer

```cpp
#include <iora/network/webhook_server.hpp>
using namespace iora::network;
using namespace iora;   // parsers::Json lives in the sibling iora::parsers namespace

WebhookServer server("0.0.0.0", 8080);

WebhookServer::JsonConfig cfg;
cfg.maxPayloadSize = 5 * 1024 * 1024;   // 5 MB
server.setJsonConfig(cfg);              // before start()

server.onJsonPost("/api/submit", [](const parsers::Json &body) -> parsers::Json
{
  auto result = parsers::Json::object();
  result["status"] = "ok";
  result["keys"]   = body.size();
  return result;                        // auto-serialized as application/json
});

// JSON and plain endpoints coexist.
server.onGet("/health", [](const HttpServer::Request &, HttpServer::Response &res)
{
  res.set_content("OK", "text/plain");
});

server.start();
```

### 6.4 TLS listener

```cpp
#include <iora/network/http_server.hpp>
using namespace iora::network;

HttpServer server("0.0.0.0", 443);

HttpServer::TlsConfig tls;
tls.certFile          = "/etc/ssl/server.crt";   // required; PEM, 1..100 KB
tls.keyFile           = "/etc/ssl/server.key";   // required; PEM, 1..100 KB
tls.caFile            = "/etc/ssl/ca.crt";        // required only if requireClientCert
tls.requireClientCert = false;

server.enableTls(tls);   // validates PEM header + file size; THROWS on failure. Call BEFORE start().
server.start();
```

> Build note: the TLS path requires the engine's OpenSSL support -- link the target with
> `configure_iora_target(<target> ENABLE_OPENSSL)`.

### 6.5 A WebSocket-upgrade subclass

```cpp
using namespace iora::network;   // SessionId / TransportErrorInfo are namespace-scope here

class MyWsServer : public iora::network::HttpServer
{
public:
  using HttpServer::HttpServer;   // inherit constructors

protected:
  bool onUpgradeRequest(SessionId sid, const Request &req, Response &res) override
  {
    const auto key = req.get_header_value("Sec-WebSocket-Key");
    if (key.empty())
    {
      return false;   // not a WS upgrade -> fall through to normal routing
    }
    res.status = 101;
    res.set_header("Upgrade", "websocket");
    res.set_header("Connection", "Upgrade");
    // computeAcceptKey(...) is an illustrative stand-in, not a library API: the reader
    // supplies the RFC 6455 Sec-WebSocket-Accept computation (SHA-1 of key + GUID, base64).
    res.set_header("Sec-WebSocket-Accept", computeAcceptKey(key));
    markSessionUpgraded(sid);   // MUST be called here, before returning true
    return true;
  }

  void onUpgradedData(SessionId sid, const std::uint8_t *data, std::size_t len) override
  {
    // Parse WebSocket frames; reply with sendRaw(sid, ...); closeSession(sid) to end.
  }

  void onUpgradedClose(SessionId sid, const TransportErrorInfo &reason) override
  {
    // Transport closed (graceful or abrupt RST/FIN, even with no protocol CLOSE) --
    // prune per-session state and fire the close callback here. Invoked with no
    // internal HttpServer lock held.
  }

  // TEARDOWN INVARIANT (Section 5.1): a subclass that adds state read by a pool
  // worker or the I/O thread MUST quiesce the transport FIRST in its own dtor:
  //   ~MyWsServer() override { quiesceTransportNoexcept("~MyWsServer"); }
  // Omitting this lets a live callback deref a destroyed member (WS-TS1/2). The
  // minimal subclass above adds no such member, so it needs no custom dtor.
};
```

### 6.6 Anti-patterns -- do NOT

- **Do NOT hold `Request`/`Response` references past the handler.** They are worker-stack locals in
  `processHttpRequest` and destroyed when the handler returns.
- **Do NOT assume handlers are serialized.** The `_mutex` narrowing runs handlers concurrently across
  workers; a handler mutating shared state must provide its own synchronization.
- **Do NOT set `Response::_suppressSend` unless you have taken over the session** (written the full
  preamble via `sendRawForSse` and taken over). Suppressing without taking over hangs the connection
  (except on a HEAD dispatch, where suppression is force-cleared).
- **Do NOT set only `res.status` and expect an empty body.** For a non-bodyless status with no
  `set_content`, `Content-Length: 0` is synthesized from the empty body -- but call `set_content` (or
  set the body + `Content-Length`) when you mean to return content.
- **Do NOT call `enableTls` after `start()`.** TLS config is read once at `start()`; there is no
  hot-reload -- certificate rotation requires a restart.
- **Do NOT call `markSessionUpgraded` outside `onUpgradeRequest`** (e.g. from a later timer). Bytes
  arriving before the mark are parsed as HTTP and likely fail.
- **Do NOT call `onUpgradedData` (or any virtual) while holding `_sessionMutex`.** The base already
  releases the lock first (copy-then-release); an override that re-enters `sendRaw`/session state
  under a held `_sessionMutex` risks an ABBA deadlock.
- **Do NOT rely on `onJsonPut`/`onJsonPatch`/`onJsonDelete` -- they do not exist.** Only GET and POST
  have JSON wrappers.
- **Do NOT treat `req.pathRest` or `req.params[...]` as decoded/safe.** Both are raw; decode and
  validate (and traversal-check `pathRest`) in the handler.

---

## 7. Call Flow / Sequence Reference

### 7.1 Success -- GET `/users/42` (named-segment match, keep-alive)

| Step | Actor | Action / lock |
|---|---|---|
| 1 | I/O thread | `onData` -> `handleIncomingData`; not upgraded; append to buffer under `_sessionMutex`; `\r\n\r\n` found; header <= 64 KB; no Content-Length. |
| 2 | I/O thread | Complete request removed from buffer (under `_sessionMutex`); `tryEnqueue(processHttpRequest)`. |
| 3 | Worker | `HttpRequest::fromWireFormat` (de-chunks a chunked body); build `Request`, set `req.sid`. |
| 4 | Worker | Compute the RFC 9112 §9.3 keep-alive decision into a **worker-stack local** (HTTP/1.1, no `Connection: close` token -> persistent); peer address copied under `_sessionMutex`; query split -> `req.path = "/users/42"`; `splitPath` -> `["","users","42"]`. |
| 5 | Worker | No `Upgrade` header. |
| 6 | Worker | `classifyRequest`: **acquire `_mutex`**; GET vector; EXACT none; NAMED `/users/:id` matches -> `MATCHED`, capture `id="42"`, copy handler out; **release `_mutex`**. |
| 7 | Worker | `req.params["id"]="42"`; `invokeWithSafetyNet(handler)` with **no lock held**; handler `set_content(...)`. |
| 8 | Worker | Not suppressed; not HEAD; framing normalization synthesizes/validates `Content-Length`; injection guard. |
| 9 | Worker | Build wire response from the step-4 worker-local keep-alive decision (no `SessionInfo` read); `toWireFormat` adds `Server`/`Connection`/`Date`. |
| 10 | Worker | **Acquire `_mutex`**, `sendAsync` (completion fires synchronously, records outcome via a by-value shared atomic), **release**; connection left open (keep-alive). |

### 7.2 Failure -- no route (404) and wrong method (405)

| Step | Actor | Action |
|---|---|---|
| 1-5 | as 7.1 | up to `classifyRequest`. |
| 6a (404) | Worker | No pattern under any method and no `_defaultHandler` -> `NO_ROUTE`; `res.status = 404`, `set_content("Not Found", ...)`. If `_defaultHandler` is set it runs instead (under the safety net). |
| 6b (405) | Worker | Path matches under another method -> `METHOD_NOT_ALLOWED`; `res.status = 405`, `set_content("Method Not Allowed", ...)`, `Allow` set from `getAllowedMethods`. No handler runs. |
| 7 | Worker | Framing normalization + send as in 7.1. |

### 7.3 Failure -- parse error and handler throw

| Step | Actor | Action |
|---|---|---|
| 1 | Worker | `HttpRequest::fromWireFormat` throws `HttpRequestError` (malformed request line, obs-fold, dup Host, CL/TE smuggling, over-long request-target, unsupported version, or a malformed / oversized chunked body). |
| 2 | Worker | Outer catch: `dynamic_cast<HttpRequestError>` -> use its `status()` -- **400** (malformed / smuggling), **413** (chunked body over 10 MB), **414** (URI too long), **501** (well-formed but unsupported method), or **505** (unsupported HTTP major version); any other exception -> **500**. |
| 3 | Worker | **Acquire `_mutex`**, `sendAsync` the error response (`Connection: close`) with a capture-only completion, **release**; **re-acquire `_mutex`**, guarded `close(sid)`. |
| -- | -- | A handler that throws is caught earlier by `invokeWithSafetyNet` -> 500 body, `_suppressSend` cleared, then the normal framing/send path runs (not this outer catch). |

### 7.4 Size-limit rejection (431 / 413) and overload (503)

| Trigger | Path | Response |
|---|---|---|
| Buffer append exceeds 1 MB, no header terminator yet | `handleIncomingData`, deferred past `_sessionMutex` | **431** headers-only + `Connection: close`, then close. |
| Buffer append exceeds 1 MB, header terminator seen | same | **413** headers-only + `Connection: close`, then close. |
| Header block > 64 KB | `handleIncomingData` (no lock held) | **431** headers-only + close. |
| Declared `Content-Length` > 10 MB | `handleIncomingData` (no lock held) | **413** headers-only + close. |
| `tryEnqueue` rejects (pool overloaded) | `handleIncomingData` | **503** + retry message. |
| `_shutdown` set when the worker runs | `processHttpRequest` | **503** `Connection: close`, then close. |

---

## 8. Thread Safety Model

### 8.1 Lock inventory

| Lock | Guards | Notes |
|---|---|---|
| `_mutex` (`mutable std::mutex`) | `_handlers`, `_defaultHandler`, `_transport`, bind config (`_bindAddress`, `_port`, `_idleTimeout`, `_gcInterval`, `_tlsConfig`, `_listenerId`) | Held only briefly: the `classifyRequest` route-table read, each `sendRaw`/`sendRawForSse`/`closeSession`, the send-enqueue, route registration, config setters, and `stop()`'s transport-stop/reset. |
| `_sessionMutex` (`mutable std::mutex`) | `_sessionInfo`, `_upgradedSessions` | Buffer append/read, peer-info read, keep-alive decision, `markSessionUpgraded`, session/upgraded cleanup. |
| `_shutdown` (`std::atomic<bool>`) | shutdown flag | Plain atomic store at the top of `stop()` (no `_mutex`); read lock-free in the fast path and `ShutdownChecker`. The subsequent `_mutex`-guarded transport reset establishes happens-before for stragglers. |

### 8.2 Lock ordering

```
_wsMutex / _sseMutex  (subclass/friend, OUTER)  ->  _mutex  (HttpServer)  ->  _sessionMutex
```

- The `_wsMutex -> _mutex` edge is real (a `WebSocketServer` may hold its own lock across `sendRaw`,
  which takes `_mutex`).
- `_mutex -> _sessionMutex` is the only place two HttpServer locks co-hold: in `sendErrorResponse`,
  the (hoisted, not in the completion lambda) `_transport->close(sid)` then `_sessionInfo.erase(sid)`
  run under `_sessionMutex` while `_mutex` is still held. There is **no** reverse
  `_sessionMutex -> _mutex` edge.
- `_sseMutex` is prospective (owned by the future `SseStream`); the friend grant only makes the edge
  possible.
- **Invariant:** no code holding `_mutex` calls a subclass/friend method that re-takes a higher lock.
  The dispatch narrowing (copy-then-invoke) guarantees this -- the handler is copied out and invoked
  with no lock held.

### 8.3 Per-operation synchronization

| Operation | Lock | Notes |
|---|---|---|
| `onGet`/`onPost`/`onPut`/`onPatch`/`onDelete`/`setDefaultHandler` | `_mutex` (write) | Compile + append; typically setup-time but safe from any thread. |
| `setPort`/`setBindAddress`/`setIdleTimeout`/`setGcInterval`/`getPort`/`getBindAddress` | `_mutex` | Config access; effective at next `start()`. |
| `enableTls` | `_mutex` | Validates and stores; call before `start()`. |
| `start` | `_mutex` | Creates transport, wires callbacks, adds listener. |
| `stop` / `quiesceTransport` | `_mutex` (narrowed) + `_sessionMutex` | Idempotent (early-out on null `_transport`). Snapshot transport under `_mutex` -> atomic flag -> `transport->stop()` holding **no** `_mutex` (I/O-thread drain fires `onClose`/`onUpgradedClose`, which take `_wsMutex`) -> `_sessionMutex` clear -> pool drain holding **no** `_mutex` -> brief `_mutex` reset. `_upgradedSessions` is not cleared here. |
| `handleIncomingData` (upgraded check / buffer / cleanup) | `_sessionMutex` (brief) | Copy-then-release before the `onUpgradedData` virtual call. |
| `onClose` -> `onUpgradedClose` (upgraded sessions) | `_sessionMutex` (brief) | Prune under `_sessionMutex`, then invoke `onUpgradedClose` with **no** internal lock held so the override may take its own mutex and fire a user callback (copy-then-invoke). |
| `classifyRequest` (route match) | `_mutex` (read, one pass) | Handler/Allow/params copied out by value; lock released **before** invocation. |
| handler body | none | Runs on a worker with no server lock; may call `sendRaw`/`sendRawForSse`/`closeSession`/`markSessionUpgraded`. |
| `sendRaw` / `sendRawForSse` | `_mutex` (brief) | Guarded `_transport && !_shutdown`; completion lambda is capture-only (fires synchronously). |
| `closeSession` | `_mutex` (brief) | Guarded `_transport && !_shutdown`. |
| `sendErrorResponse` | `_mutex` + `_sessionMutex` | The close + session-erase are hoisted OUT of the (log-only) completion lambda, run under `_mutex -> _sessionMutex`. |
| `markSessionUpgraded` | `_sessionMutex` | Insert into the upgraded set. |
| `getShutdownChecker` / `ShutdownChecker::isShuttingDown` | none | Atomic load. |
| `WebhookServer::setJsonConfig`/`getJsonConfig` | none | No synchronization; set before `start()`. |

### 8.4 Route-table mutation vs. serving

The route table (`_handlers`) can be mutated (a late `onGet`) concurrently with serving, but this is
race-free: `classifyRequest` reads under `_mutex`, and `registerHandler` writes under `_mutex`, so the
table is never read and written at the same instant. A registration that reallocates a per-method
vector cannot dangle an in-flight handler because the matched `std::function` is **copied out by
value** before `_mutex` is released. Handler invocation itself holds no lock, so handlers run
concurrently.

### 8.5 Synchronous send completions

The engine's `sendAsync` fires its completion **synchronously on the caller's thread** while `_mutex`
is held, so no completion lambda may re-acquire `_mutex` or capture raw `this`. Each send site's
completion is shaped to that rule, but they differ in how (and whether) they record an outcome:

- **`sendRaw`** and the shutdown / error-catch / `sendErrorResponse` sends use a **capture-only** lambda
  that only keeps the send buffer alive (an owning `shared_ptr<std::string>` captured by value) and, at
  most, logs. Any post-send `close` is deferred until after the enclosing `lock_guard` releases and then
  performed under a fresh guarded `_mutex` -- except `sendErrorResponse`, whose close + `_sessionInfo`
  erase deliberately run inside the already-held `_mutex` (documented `_mutex -> _sessionMutex` order),
  with its completion lambda still log-only.
- **The main terminal-response send** (`processHttpRequest`) needs the outcome to decide whether to
  close, so its lambda captures the buffer **and** a `std::make_shared<std::atomic<SendOutcome>>` **by
  value** (never the stack by reference), storing `Ok`/`Failed` with `memory_order_relaxed`. Because the
  completion is synchronous, the worker reads that atomic right after the lock releases and closes the
  connection on failure or when the request requested `Connection: close`.
- **`sendRawForSse`** records completion into a **stack `bool& delivered`** captured **by reference**,
  set synchronously on the calling thread before the function returns -- it is *not* a by-value shared
  atomic. This is safe precisely because the completion fires synchronously within the same call, so the
  stack local is still alive; the function returns `delivered` (transport-up + enqueued) as the SSE
  primitive's secondary write-failure signal.

---

## 9. Configuration Reference

### 9.1 HttpServer construction and setters

| Parameter | Type | Default | Meaning |
|---|---|---|---|
| `bindAddress` (ctor / `setBindAddress`) | `std::string` | `"0.0.0.0"` | Listener bind IP. |
| `port` (ctor / `setPort`) | `int` | `8080` (`DEFAULT_PORT`) | Listener TCP port. |
| `_idleTimeout` (`setIdleTimeout`) | `std::chrono::seconds` | `600` | Per-connection idle timeout applied at `start()`; the engine GC reaps sessions idle longer than this. |
| `_gcInterval` (`setGcInterval`) | `std::chrono::seconds` | `5` | Transport GC sweep interval applied at `start()`. |
| Thread pool | `core::ThreadPool` | min 2, max 8, 30 s idle | Worker pool for `processHttpRequest` (hard-coded in the constructor). |
| `MAX_PENDING_REQUESTS` | `static constexpr std::size_t` | `1000` | Declared but **not referenced** in the current source (see Known Limitations). |

`start()` builds the `TransportConfig` from the above plus fixed values: `protocol = TCP`,
`maxPendingSyncOps = 32`, `defaultSyncTimeout = 30000 ms`, `enableTcpNoDelay = true`,
`tcpKeepalive.enable = true`, `maxWriteQueue = 1024`. See `transport.md` for the meaning of each.

### 9.2 Per-session size limits (`SessionInfo`, compile-time constants)

| Constant | Value | Effect on overflow |
|---|---|---|
| `MAX_BUFFER_SIZE` | 1 MB (`1024*1024`) | Accumulated per-session parse buffer. Overflow -> **431** (no header terminator yet) or **413** (terminator seen), then close. |
| `MAX_HEADER_SIZE` | 64 KB (`64*1024`) | Header block size. Over -> **431** + `Connection: close`. |
| `MAX_BODY_SIZE` | 10 MB (`10*1024*1024`) | Declared `Content-Length`. Over -> **413** + `Connection: close`. |

### 9.3 TlsConfig

| Field | Type | Default | Meaning |
|---|---|---|---|
| `certFile` | `std::string` | `""` | PEM certificate path (**required**; must exist, begin with `-----BEGIN`, size 1..100 KB). |
| `keyFile` | `std::string` | `""` | PEM private-key path (**required**; same validation). |
| `caFile` | `std::string` | `""` | PEM CA path (**required only if** `requireClientCert`; same validation). |
| `requireClientCert` | `bool` | `false` | Require and verify a client certificate; maps to `serverTls.verifyPeer`. |

`enableTls` throws `std::runtime_error` on any validation failure. There is no hot-reload.

### 9.4 WebhookServer::JsonConfig

| Field | Type | Default | Meaning |
|---|---|---|---|
| `maxPayloadSize` | `std::size_t` | `DEFAULT_MAX_JSON_SIZE` = 10 MB | Max JSON request body; over -> 500 with a size-limit message. |
| `parseLimits` | `parsers::ParseLimits` | default | JSON depth / array-size / etc. limits passed to `Json::parse`. |

---

## 10. API Reference

Concise signatures; behavior is in Sections 5-9.

### 10.1 HttpServer

```cpp
namespace iora::network
{

class HttpServer
{
public:
  static constexpr std::size_t MAX_PENDING_REQUESTS = 1000;
  static constexpr int DEFAULT_PORT = 8080;

  struct TlsConfig
  {
    std::string certFile;
    std::string keyFile;
    std::string caFile;
    bool requireClientCert = false;
  };

  struct Request
  {
    HttpMethod method;
    std::string path;
    HttpHeaders headers;                                     // std::map, case-insensitive
    std::string body;                                        // decoded (chunked bodies de-chunked by fromWireFormat)
    std::unordered_map<std::string, std::string> params;     // query + named captures (raw; bare key -> "")
    std::string remote_addr;
    std::uint16_t remote_port = 0;
    std::string pathRest;                                    // trailing-wildcard suffix (raw)
    SessionId sid{};                                         // connection session id (0 = invalid)
    std::string get_header_value(const std::string &key) const;
    bool has_header(const std::string &key) const;
  };

  struct Response
  {
    int status = 200;
    HttpHeaders headers;
    std::string body;
    std::vector<std::string> cookies;                        // repeated Set-Cookie (RFC 6265 §3)
    bool _suppressSend = false;                              // handler took over the session (SSE)
    void set_content(const std::string &content, const std::string &contentType);
    void set_content(std::string &&content, const std::string &contentType);   // move overload
    void set_header(const std::string &key, const std::string &value);
    void add_cookie(const std::string &setCookieValue);      // one Set-Cookie field-line per call
  };

  using Handler = std::function<void(const Request &, Response &)>;

  class ShutdownChecker
  {
  public:
    explicit ShutdownChecker(const std::atomic<bool> &flag);
    bool isShuttingDown() const;
    void throwIfShuttingDown() const;                        // throws std::runtime_error
  };

  HttpServer(const std::string &bindAddress = "0.0.0.0", int port = DEFAULT_PORT);
  virtual ~HttpServer();

  HttpServer(const HttpServer &) = delete;                   // non-copyable, non-movable
  HttpServer &operator=(const HttpServer &) = delete;
  HttpServer(HttpServer &&) = delete;
  HttpServer &operator=(HttpServer &&) = delete;

  void setPort(int port);
  void setBindAddress(const std::string &bindAddress);
  void setIdleTimeout(std::chrono::seconds timeout);         // default 600 s
  void setGcInterval(std::chrono::seconds interval);         // default 5 s
  int getPort() const;
  std::string getBindAddress() const;
  ShutdownChecker getShutdownChecker() const;
  void enableTls(const TlsConfig &config);                   // throws on invalid cert/key/CA

  void onGet   (const std::string &path, Handler handler);   // throws std::invalid_argument on
  void onPost  (const std::string &path, Handler handler);   //   a malformed pattern
  void onPut   (const std::string &path, Handler handler);
  void onPatch (const std::string &path, Handler handler);
  void onDelete(const std::string &path, Handler handler);
  void setDefaultHandler(Handler handler);                   // 404 customization

  void start();                                              // throws on error
  void stop();

protected:
  void quiesceTransport();                                   // idempotent; subclass dtors call FIRST
  void quiesceTransportNoexcept(const char *who) noexcept;   // swallow+log wrapper for a dtor

  void markSessionUpgraded(SessionId sid);
  virtual void onUpgradedData(SessionId sid, const std::uint8_t *data, std::size_t len);  // no-op
  virtual void onUpgradedClose(SessionId sid, const TransportErrorInfo &reason);          // no-op
  void sendRaw(SessionId sid, const std::uint8_t *data, std::size_t len);
  virtual void closeSession(SessionId sid);
  virtual bool sendRawForSse(SessionId sid, const std::uint8_t *data, std::size_t len);
  virtual bool onResponseSuppressed(SessionId sid, const Request &req, Response &res);    // false
  virtual bool onUpgradeRequest(SessionId sid, const Request &req, Response &res);        // false

  void handleIncomingData(SessionId sid, const std::uint8_t *data, std::size_t len);
  void processHttpRequest(SessionId sid, const std::string &requestData);
  void sendErrorResponse(SessionId sid, int statusCode, const std::string &statusText,
                         const std::string &body = "", bool headersOnly = false);
  static std::string getStatusText(int code);
  static bool connectionListHasToken(const std::string &connectionValue, const char *token);
  std::size_t findChunkedRequestEnd(const std::string &data, std::size_t bodyStart,
                                    bool &framingError) const;
  std::string getAllowedMethods(const std::vector<std::string> &reqToks) const;  // under _mutex

  friend class SseStream;
  friend void upgradeToSse(HttpServer &server, const Request &req, Response &res,
                           std::function<void(std::shared_ptr<SseStream>)> onConnect);
};

} // namespace iora::network
```

### 10.2 WebhookServer

```cpp
namespace iora::network
{

class WebhookServer : public HttpServer
{
public:
  static constexpr std::size_t DEFAULT_MAX_JSON_SIZE = 10 * 1024 * 1024;

  struct JsonConfig
  {
    std::size_t maxPayloadSize = DEFAULT_MAX_JSON_SIZE;
    parsers::ParseLimits parseLimits;
  };

  using JsonHandler = std::function<parsers::Json(const parsers::Json &)>;

  WebhookServer(const std::string &bindAddress = "0.0.0.0", int port = DEFAULT_PORT);
  ~WebhookServer() override;   // calls quiesceTransportNoexcept("~WebhookServer") FIRST (WS-TS2)

  void setJsonConfig(const JsonConfig &config);
  JsonConfig getJsonConfig() const;
  void onJsonGet (const std::string &endpoint, JsonHandler handler);
  void onJsonPost(const std::string &endpoint, JsonHandler handler);
};

} // namespace iora::network
```

### 10.3 Status reason phrases (`getStatusText`)

Carries explicit phrases for 100, 101; 200, 201, 202, 204, 205, 206; 301, 302, 303, 304, 307, 308;
400, 401, 403, 404, 405, 409, 410, 411, 412, 413 ("Content Too Large"), 414, 415, 422
("Unprocessable Content"), 426, 428, 429, 431, 451; 500, 501, 502, 503, 504, 505. Any other valid
code falls back to its RFC 9110 §15 class phrase (`Informational` / `Successful` / `Redirection` /
`Client Error` / `Server Error`) -- never `Unknown` for a valid code.

---

## 11. Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Concrete base, no pure virtuals | `HttpServer` usable standalone | Plain HTTP needs no subclass; WebSocket/SSE subclass without touching JSON. |
| Non-copyable, non-movable | All four special members deleted | Owns a mutex, atomic, and transport; sharing/moving would be unsafe. |
| Shared-ownership transport (S-3) | `std::shared_ptr<Transport>` from `Transport::tcp()` | Matches the transport's structurally-safe teardown; a worker co-owns the transport for its call. |
| Single narrow lock pass (`classifyRequest`) | Match under `_mutex`, copy out by value, invoke unlocked | Handler concurrency; no self-deadlock when a handler writes to its own session; safe against concurrent registration. |
| Ordered per-method `vector<pair<CompiledPattern,Handler>>` | Not a hash map | Registration order is the within-precedence tie-break; route tables are small so O(routes) scan is fine. |
| Compile patterns at registration | Throw `std::invalid_argument` at `onGet`/etc. | A bad pattern is a startup programming error, never a request-time surprise. |
| Precedence EXACT > NAMED > WILDCARD | First hit stops the scan | Deterministic, intuitive dispatch; `/users/me` beats `/users/:id`. |
| Raw captures / `pathRest` | Not percent-decoded | Consistent with the query parser; decode/validate (and traversal-check) is the consumer's job. |
| Auto HEAD/OPTIONS, `OPTIONS *`, canonical `Allow` | Synthesized, never registered | No `onHead`/`onOptions` surface; correct RFC 9110 behavior with keep-alive-safe framing. |
| Two enforcement points for framing | Dispatcher normalization + `toWireFormat` backstop | Defense-in-depth; the backstop is `const`/lock-free and unbypassable across all five builders. |
| Request-level safety net | `invokeWithSafetyNet` -> generic 500, clears `_suppressSend` | A throwing handler never leaves a dangling socket; verbose dev bodies are the Application layer's job. |
| Size caps + `tryEnqueue` 503 backpressure | 1 MB buffer / 64 KB header / 10 MB body; bounded pool | Slow-loris / oversized-request / queue-flood DoS resistance. |
| Copy-then-release before virtuals | `_sessionMutex` released before `onUpgradedData` | Prevents ABBA deadlock when an override re-enters transport/session state. |
| Capture-only send completions + deferred close | Enqueue under `_mutex`, close after release | The engine fires completions synchronously under the held lock; re-locking would recursive-deadlock. |
| `stop()` narrowed off the drain loop | `_mutex` not held across the (unbounded) pool drain | An in-flight worker's deferred close (and the I/O-thread `onUpgradedClose` taking `_wsMutex`) would otherwise deadlock shutdown. |
| Subclass-quiesce teardown (WS-TS1/2) | `quiesceTransport()` first in every subclass dtor | `~HttpServer` drains only after subclass members are gone; quiescing first stops the I/O thread / pool before subclass state is destroyed. |
| Per-request keep-alive, not per-session (SRV-M3) | RFC 9112 §9.3 decided on the worker stack | Pipelined siblings run on different workers; a shared `SessionInfo` field would be clobbered (logical race). HTTP/1.0 correctly defaults to close. |
| `Connection` parsed as a token list (SRV-M2) | `connectionListHasToken` (RFC 9110 §7.6.1) | Honors `close, foo` / `keep-alive, close`; a bare substring test both false-positives and misses members. |
| Repeated `Set-Cookie` as separate lines (SRV-M5) | `cookies` vector -> `setCookies` -> `toWireFormat` | RFC 6265 §3 forbids comma-combining cookies; unblocks session + CSRF cookies in one response. |
| Framer reaches the parser's framing verdict (SRV-M4) | Same CL/TE rules in `handleIncomingData` and `fromWireFormat` | A framer/parser disagreement on the request boundary is the request-smuggling primitive (RFC 9112 §6.3). |
| WebhookServer as a thin subclass | ~160 lines; JSON wrappers over `onGet`/`onPost`; no webhook-specific semantics | JSON logic cleanly separated from transport; plain callers avoid the JSON dependency. |
| `friend` SSE access grant (RD-17) | `SseStream` + `upgradeToSse` | Same reach a subclass gets, with no public `transport()` leak; `sendRawForSse` stays protected. |

---

## 12. Known Limitations

Open items are carried as honest tracked findings with their backlog reference; nothing below is a
defect dressed up as "by design". The genuinely by-design entries are API-shape decisions, not defects.

| Limitation | Description | Severity / Status |
|---|---|---|
| **Query names/values are stored raw (undecoded)** | `req.params[...]`, `req.pathRest`, and the captured named segments are stored verbatim -- no percent-decoding and no `+`->space. A handler needing decoded values must call `parsers::formDecode` / `parsers::urlDecode`. Consistent URI-component decoding across query/route/pathRest is pending. | **Open -- P1**, tracked `2026-09-12-6`. |
| **Duplicate query keys are last-wins** | `req.params` is a single-valued `std::unordered_map`, so `?a=1&a=2` yields `a=="2"`; the API cannot represent a multi-valued query parameter. | Documented API-shape limitation. |
| **Pipelined requests may dispatch past a parse-400 sibling** | Framing (I/O thread) and handler dispatch (pool) are decoupled, so a request already `tryEnqueue`d before a *later* sibling's parse-400+close runs may still be dispatched. The framing-time smuggling checks (SRV-M4) return-without-framing on the poisoned connection, but this general ordering property remains. | **Open -- P2**, tracked `2026-09-12-5`. |
| **Request-parser hardening for bare-CR / NUL / bare-LF / leading empty line** | `fromWireFormat` does not yet fully reject every RFC 9112 §2.2 bare-CR / NUL / bare-LF / leading-empty-line case in the request parser. | **Open -- P2**, tracked `2026-09-12-3`. |
| **`quiesceTransport` drain (formerly a 2 s-cap residual UAF)** | ~~The drain is capped at 2 s and then forces on...~~ **RESOLVED (`2026-09-11-22`).** The drain is now **unbounded to `getInFlightCount() == 0`** with a `drainDeadline()` (30 s) `std::abort()` backstop, so `quiesceTransport()` never returns while a worker is still reading a derived member. **General rule (LT-8):** a base teardown primitive whose worker drain *abandons with work in flight* leaves a residual UAF for any derived member a worker may deref; a derived dtor delegating to it must drain **unbounded** to quiescence via a single-critical-section in-flight count (with a fatal-abort backstop for non-cooperative handlers, since `std::thread` cannot be force-cancelled), OR confine worker access to those members to a shutdown-checked pre-section. | **Resolved -- landed `2026-09-11-22`.** Follow-on: accurate self-call diagnostic `2026-09-12-10` (P2). |
| **Upgrade-vs-transport-close handshake-window race** | A split-brain race exists in the narrow window between accepting a protocol upgrade and the transport-close path, where the two views of the session can disagree. | **Open -- P0**, tracked `2026-09-11-23`. |
| **Framer and parser share logic that is duplicated, not hoisted** | The framing-verdict / chunk-size / trailer-walker logic is implemented in both `handleIncomingData`/`findChunkedRequestEnd` and `fromWireFormat`/`decodeChunkedRequestBody`. They are kept in agreement by construction (SRV-M4), but a shared helper is planned so they cannot drift. This is a refactor, not a behavior gap. | **Open -- P0** (refactor), tracked `2026-09-12-1`. |
| **`MAX_PENDING_REQUESTS` is dead; overload log hard-codes `1024`** | `MAX_PENDING_REQUESTS = 1000` is declared but never referenced; the pool-overload log line prints the literal denominator `1024` (a copy of the transport `maxWriteQueue`), not the `ThreadPool`'s actual pending-task capacity. | **Open -- Low** (cosmetic / observability); no tracker filed. |
| **No `onHead`/`onOptions` registrar** | Auto HEAD-for-GET and auto-OPTIONS are the only mechanisms; the HEAD/OPTIONS pattern vectors are always empty. | By design (v1) -- API shape, not a defect. |
| **Single trailing wildcard only** | Patterns support exact, named-segment, and one trailing `*` -- no mid-path wildcards, multiple wildcards, or regex. Per-method lookup is O(routes). | By design -- API shape. |
| **Re-registering an identical NAMED/WILDCARD pattern appends a dead entry** | Only EXACT re-registration overwrites; a duplicate NAMED/WILDCARD registration leaves an unreachable second entry (first-registered wins, the documented tie-break). | By design -- documented registration contract. |
| **JSON wrappers only for GET and POST** | `WebhookServer` has no `onJsonPut`/`onJsonPatch`/`onJsonDelete`; use the raw `Handler` API for those methods. | By design -- API shape. |
| **`setJsonConfig` is not synchronized** | Call before `start()` or provide external synchronization; `_jsonConfig` has no lock. | By design -- lifecycle contract. |
| **No HTTP/2 or HTTP/3** | Only HTTP/1.0 and HTTP/1.1. Chunked transfer coding is framed and decoded (Section 5.3). | By design -- scope. |
| **`enableTls` validates at call time; no hot-reload** | Certificate rotation requires a server restart. | By design -- scope. |

> **Resolved since the frozen drafts / v1.0.** The following are now fixed in source and are therefore
> **not** listed above: (1) **chunked request bodies are de-chunked** before delivery
> (`fromWireFormat` -> `decodeChunkedRequestBody`; SRV-H1) -- handlers and `onJsonPost` see the decoded
> payload; (2) the **10 MB body cap now covers the decoded chunked length** (413; SRV-M1) -- via
> `HttpServer` the 1 MB `MAX_BUFFER_SIZE` bounds the raw wire first, so there is no longer a
> chunked-vs-`Content-Length` asymmetry; (3) **HTTP/1.0 / keep-alive is version-aware** (SRV-M3) -- the
> dead `SessionInfo.connectionKeepAlive` / `httpVersion` fields were removed and persistence is a
> per-request worker-local (HTTP/1.0 defaults to close); (4) the **`Connection` header is token-parsed**
> (SRV-M2) -- `close, foo` / `keep-alive, close` are honored, and repeated `Connection` field-lines
> combine; (5) **repeated `Set-Cookie`** is supported (SRV-M5); (6) an **invalid / out-of-range request
> `Content-Length` now returns 400** + close (SRV-L1), not a bare close; (7) framer/parser **framing-verdict
> agreement** (conflicting (differing-value) CL, CL+TE, non-final chunked TE -> 400 + close; SRV-M4), token-aware chunked
> detection (SRV-L4TE), and chunk-size subtraction bounds (SRV-H2). Also carried from the v1.0 re-verify:
> the unguarded `handleIncomingData` closes now route through the guarded `sendErrorResponse`; an unknown
> but well-formed method yields **501** and a malformed method token **400**; and `_transport` is a
> `std::shared_ptr<Transport>` from `Transport::tcp()` (S-3), not a `std::unique_ptr`.
</content>
</invoke>
