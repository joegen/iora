# Iora HTTP Client -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Component** | `iora::network::HttpClient`, `iora::network::HttpClientPool` (+ `PooledHttpClient`) |
| **Version** | 2.1 |
| **Date** | 2026-09-12 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/network/http_client.hpp` (client, RFC-9112 framing, exception taxonomy) and `include/iora/network/http_client_pool.hpp` (pool + `PooledHttpClient`) |
| **Namespace** | `iora::network` |
| **Dependencies** | `Transport` (TCP/TLS, via `transport_impl.hpp`), `DnsClient`, `parsers::Json`, `parsers::http_message` (`CaseInsensitiveCompare`, `detail::addOrCombineHeader`, `statusForbidsBody`), `core::Logger`, `core::BufferView`, `core::PooledFuture` / `core::async` / `core::AsyncRejectedError` (`thread_pool.hpp`), `core::BlockingQueue` (pool), `crypto::SecureRng` (multipart boundary) |
| **Related** | `JsonRpcClient` (builds on `postJson`), `WebhookServer` / `HttpServer` (the server side). Sibling guides: [`transport.md`](transport.md) (the TCP/TLS layer this client sits on), [`../parsers/http_message.md`](../parsers/http_message.md) (`CaseInsensitiveCompare` / header-combining helpers used for framing), [`http_server.md`](http_server.md) (the server counterpart). |

---

## 2. Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | (pre-2026-06) | Single cached connection per `host:port`; "one request at a time" contract; idle + failure eviction. |
| 1.1 | 2026-06-15 | Exclusive per-`host:port` **connection lease** (`ConnectionLease`) makes a shared instance safe for concurrent same-host (serialized) and different-host (parallel) requests. Server-sent `Connection: close`, case-insensitive response headers, `thread_local` retry-backoff PRNG, compile-once regexes, `Response::httpVersion`, `Config::leaseAcquireTimeout`. Class made non-movable. |
| 1.2 | 2026-06-15 | **RFC 9112 §6.3/§7.1 response framing**: mode decided once (`NoBody`/`ContentLength`/`Chunked`/`CloseDelimited`), incremental chunked parser, `std::from_chars` numeric guards, receive cap, reject CL+TE / obs-fold / conflicting duplicate CL, multi-1xx skip. New `head()`, `HttpFramingError`. |
| 1.3 | 2026-06-15 | **Idempotent-retry safety (RFC 9110 §9.2.2)**: non-idempotent retry restricted to provably-unsent (`HttpRequestNotSentError`). New static `isIdempotentMethod`. |
| 1.4 | 2026-07-29 | **Cancellation seam** `cancelInFlight() noexcept`; `HttpClientCancelledError`; `_closing` promoted to `std::atomic<bool>`; `cleanup()` = `cancelInFlight()` + teardown tail. |
| 1.5 | 2026-09-03 | Reused-dead-socket pre-write probe; `HttpResponseTimeoutError`; `isRequestProvablyNotSent`; `sendSync` enqueue failure typed not-sent. |
| 1.6 | 2026-09-03 | `HttpConnectTimeoutError` (subclass of `HttpRequestNotSentError`, keyed on `TransportError::Timeout`). |
| 2.0 | 2026-09-11 | **Migrated to `docs/network/` and re-verified against current source.** Documents the additions the prior draft omitted: `Config::totalRequestTimeout` + `HttpExchangeDeadlineError` (whole-exchange slowloris bound), `HttpInvalidUrlError` (userinfo/bad-port rejection, replacing the stale "parseUrl uses `std::stoi`" claim), `HttpInvalidHeaderError` (caller-header validation + framing-controlled-header rejection), `methodAnticipatesContent` (`Content-Length: 0` for empty POST/PUT/PATCH), `formatHostHeaderField` (non-default port in `Host`, replacing the stale "missing port" limitation), the **`virtual` destructor** (factory-owned polymorphic destruction), the async methods now returning **`core::PooledFuture<Response>`** on the shared bounded pool with a **finite-timeout rejection gate** (`rejectUnboundedPooledRequest`), scheme-qualified connection keys (`getHostPort`), and per-connection TLS identity (`verifyName` + `kHttpsHostFlags`). Corrected `followRedirects` default to `false`. Added full `HttpClientPool` / `PooledHttpClient` coverage. |
| 2.1 | 2026-09-12 | **Re-synced to the landed Group-5 fixes (iora 1af4b25).** `HttpClientPool::createClient()` now copies `leaseAcquireTimeout` (plus the previously-copied set) so a pooled client's async API works purely from the pool `Config` (CLI-F1). `PooledHttpClient` now forwards the full surface -- `head`/`postStream`/`getAsync`/`postJsonAsync` added (CLI-F3) -- and its `setTlsConfig` forwarder was removed (CLI-F5); the "footgun" and "does-not-forward" Known-Limitations rows are retired. `Config::enableCompression` is now explicitly RESERVED AND INERT rather than an undocumented dead flag (CLI-F2). `parseUrl` now lowercases the scheme (case-insensitive `HTTP://`/`HTTPS://`, RFC 3986 §3.1, CLI-NEW1) and parses bracketed IPv6-literal authorities (`http://[::1]:8080/`, re-bracketed in `Host`, CLI-NEW2) -- both removed from anti-patterns/limitations. Documented the `_connections` lazy idle sweep (CLI-CACHE) and the `setTlsConfig`-before-DNS-setters ordering constraint. |

---

## 3. Executive Summary

### Problem

`HttpClient` is iora's foundational blocking HTTP/1.1 client -- `JsonRpcClient`, `tmc_edge_proxy`, and `iora_sip` consumers all reach through it. Two classes of hazard drove its evolution, both visible in the source:

- **Shared-instance corruption.** The client caches one persistent connection per `host:port` (`std::unordered_map<std::string, ConnectionEntry> _connections`). Without serialization, two threads issuing concurrent same-host requests would interleave request/response bytes on the one socket and share a single sync-receive buffer, and a failure-path `dropConnection()` on one thread could close a socket another thread was mid-`receiveSync` on.
- **Unsafe or non-terminating exchanges.** A naive HTTP client trusts the peer: it retries non-idempotent POSTs blindly (double-submitting orders), reuses a socket the server idle-closed, frames the body by substring scans (a request-smuggling vector), and lets a slow-trickle or interim-`1xx`-flooding peer reset the per-read timer forever (a client-side slowloris).

### Solution

The two headers provide three cooperating types, all in `iora::network`:

- **`HttpClient`** -- the thread-safe blocking client. Each request acquires an **exclusive per-`host:port` connection lease** (`ConnectionLease`, a move-only RAII guard) that spans the *entire* exchange (connect -> send -> receive -> parse -> eviction). Same-host requests serialize on the lease; different-host requests run in parallel. It frames the response body once per RFC 9112 §6.3 (`determineFraming` + `advanceChunked`), classifies every failure into a typed exception taxonomy so the retry loop only re-sends what RFC 9110 §9.2.2 permits, and bounds the whole exchange with an optional `totalRequestTimeout`.
- **`HttpClientPool`** -- a thread-safe pool of independent `HttpClient` instances over a `core::BlockingQueue`, for real same-host parallelism (each worker gets its own client, hence its own connection cache).
- **`PooledHttpClient`** -- a move-only RAII checkout handle that forwards the blocking operations to a borrowed client and returns it to the pool on scope exit.

### Technical Impact

- **A shared `HttpClient` is safe to call from many threads** (same-host serialized, different-host parallel) -- the lease, not a lock, provides the serialization, and `_mutex` is never held across DNS or transport I/O.
- **Correctness by construction.** The connection key is scheme-qualified (`https://host:port` never reuses an `http://` socket -- no silent TLS downgrade); framing is header-map-driven (no substring smuggling); the retry gate is a typed exception hierarchy shared verbatim with `JsonRpcClient`, so a POST is never double-submitted after the request may have reached the wire.
- **Bounded resource use.** `maxResponseBytes` caps accumulation during receipt; `totalRequestTimeout` bounds total wall-clock to ~1x the deadline against a slowloris; the async path rejects unbounded requests up front so it cannot starve the shared `core::generalAsyncPool`.

---

## 4. System Architecture

### 4.1 Component relationships

```
  HttpClientPool  (thread-safe; owns N independent clients)
    _config : Config              (poolSize, timeouts, tlsConfig, clientFactory, clientConfigurer)
    _queue  : core::BlockingQueue<std::shared_ptr<HttpClient>>   (the free list)
    _closed : std::atomic<bool>
        |  get() / get(timeout) / tryGet()  -> dequeue a client
        v
  PooledHttpClient  (move-only RAII checkout)
    _pool   : HttpClientPool*
    _client : std::shared_ptr<HttpClient>     (borrowed; nulled on return)
        |  forwards get/post/postJson/deleteRequest/postFile/head/postStream/getAsync/postJsonAsync/client()
        |  ~PooledHttpClient -> returnToPool() -> _queue.tryQueue(client)
        v
  HttpClient  (shared instance; thread-safe, same-host serialized)
    performRequest ─► executeRequest ─► acquireLease(scheme://host:port)
                                            | blocks if host leased (bounded by leaseAcquireTimeout)
                                            v
      ConnectionLease (RAII, whole exchange)
        acquireConnection ──(reuse cached | resolveHostAddress + connectSync)──► {SessionId, reused}
        setReadMode(Sync) ─► [pre-write probe if reused] ─► sendSync ─► receiveSync loop ─► frameResponse
        keep-warm (setReadMode Async) | dropConnection
        ~ConnectionLease ─► releaseLease ─► _cv.notify_all
    State (all mutated ONLY under _mutex):
      _connections : scheme://host:port -> ConnectionEntry{ SessionId id; steady_clock lastUsed }
      _leasedHosts : unordered_set<scheme://host:port>     (exactly one lease per key: LEASE-1)
      _cv          : condition_variable      _closing : atomic<bool> (write-once monotonic)
      _transport   : shared_ptr<Transport>   _dnsClient : unique_ptr<DnsClient>   (both lazy)
                         |  (no _mutex held across I/O -- LEASE-7)
                    ┌────▼──────┐                    ┌──────────────┐
                    │ Transport │ (per-session sync  │  DnsClient   │ (ExpiringCache,
                    │  TCP/TLS  │  buffers)           │              │  internally locked)
                    └───────────┘                    └──────────────┘
```

### 4.2 Key-operation sequence: a synchronous `GET`

```mermaid
sequenceDiagram
  participant App as Caller
  participant PR as performRequest
  participant ER as executeRequest
  participant L as acquireLease / ConnectionLease
  participant AC as acquireConnection
  participant T as Transport (TCP/TLS)
  participant FR as frameResponse

  App->>PR: get(url, headers, retries)
  Note over PR: lock _mutex; if _closing throw HttpClientCancelledError; ensureInitialized()
  PR->>ER: executeRequest(method, url, body, headers)
  Note over ER: validate caller headers (name token / value octet / framing-controlled) -> HttpInvalidHeaderError
  ER->>ER: parseUrl(url) -> ParsedUrl (scheme lowercased; HttpInvalidUrlError on userinfo/malformed-IPv6/bad port)
  ER->>L: acquireLease(scheme://host:port)
  Note over L: _cv.wait(pred) bounded by leaseAcquireTimeout; HttpLeaseAcquireTimeoutError on expiry
  L-->>ER: ConnectionLease (held for whole exchange)
  ER->>AC: acquireConnection(parsedUrl)
  alt cached & within connectionIdleTimeout
    AC-->>ER: {id, reused=true}
    ER->>T: receiveSync(id, 1 byte, 0ms)  (pre-write liveness probe)
    Note over ER: Timeout => healthy; any other outcome => dropConnection + throw (not-sent)
  else fresh
    AC->>T: connectSync(resolvedHost, port, tlsMode, tlsOpts, timeout)
    Note over AC: TransportError::Timeout -> HttpConnectTimeoutError
    AC-->>ER: {id, reused=false}
  end
  ER->>T: setReadMode(id, Sync)
  ER->>T: sendSync(id, requestBytes)  (enqueue failure -> HttpRequestNotSentError)
  loop until complete
    ER->>ER: if totalRequestTimeout elapsed -> HttpExchangeDeadlineError
    ER->>T: receiveSync(id, buffer, recvTimeout)
    ER->>FR: frameResponse(...) per RFC 9112 §6.3
    Note over FR: header block once; skip 1xx; NeedMore / Complete / Malformed(->HttpFramingError)
  end
  Note over ER: reusable? setReadMode(Async) : dropConnection(id)
  ER-->>PR: Response
  Note over L: ~ConnectionLease -> releaseLease -> _cv.notify_all
  PR-->>App: Response (or retry per RFC 9110 §9.2.2 gate)
```

### 4.3 Threading model

| Thread | Responsibility |
|---|---|
| Caller / worker thread | Calls the blocking API (`get`/`post`/`postJson`/`head`/`deleteRequest`/`postFile`/`postStream`). Acquires the per-host lease for the whole exchange; holds `_mutex` only for short bookkeeping; is blocked in `connectSync`/`sendSync`/`receiveSync` for the I/O itself. |
| Any thread (concurrent) | May call the same shared `HttpClient` -- different `host:port` targets proceed in parallel; same-target requests serialize on the lease. May call `cancelInFlight()` to unwind in-flight requests. |
| `core::generalAsyncPool` worker | Runs the closure enqueued by `getAsync`/`postJsonAsync` -- i.e. the sync path above -- and completes the returned `PooledFuture<Response>`. Bounded and shared, hence the finite-timeout admission gate. |
| `Transport` engine I/O thread | Performs the actual socket I/O and signals the parked sync ops. Not owned by `HttpClient`. |
| `HttpClientPool` caller threads | Acquire/return clients through the internally-synchronized `core::BlockingQueue`; no `HttpClient` is ever shared between two concurrently-checked-out `PooledHttpClient` handles. |

---

## 5. Component Deep Dive

### 5.1 `HttpClient`

The client owns a `std::mutex _mutex`, a `std::condition_variable _cv`, a lazily-built `std::shared_ptr<Transport> _transport` and `std::unique_ptr<DnsClient> _dnsClient`, the connection cache `_connections`, the lease set `_leasedHosts`, and the `std::atomic<bool> _closing` shutdown latch.

**Lazy initialization.** `ensureInitialized()` (called under `_mutex`) builds the transport on first use, so `setTlsConfig` can run first. It plumbs the *full* `TlsConfig` (CA file, client cert/key, `verifyPeer`) into `TransportConfig::clientTls` -- not just `verifyPeer` -- and starts a `DnsClient`. Because the transport reads `clientTls` exactly once, `setTlsConfig` throws `std::logic_error` if called after initialization rather than silently no-op.

> **Call `setTlsConfig` before any transport-initializing call.** The first request initializes the transport, but so do `setDnsServers`, `addDnsServer`, and `getDnsServers` -- each calls `ensureInitialized()`. Any of them makes a subsequent `setTlsConfig` throw `std::logic_error`. Ordering rule: `setTlsConfig` first, *then* the DNS-server setters/getter, *then* requests.

**Copy/move.** Non-copyable **and** non-movable (all four special members `= delete`). It owns a `std::mutex`/`std::condition_variable` and live lease state; a `std::mutex` member makes a defaulted move implicitly deleted anyway, so the explicit `= delete` documents the intent. Heap-store via `std::shared_ptr<HttpClient>` when movability is needed -- exactly what `HttpClientPool` does.

**Virtual destructor.** `virtual ~HttpClient() { cleanup(); }`. `HttpClientPool::Config::clientFactory` returns `std::unique_ptr<HttpClient>` that a caller may populate with a derived type; destroying that through the base pointer requires a virtual destructor (F-3). Only the destructor is virtualized -- the request methods stay non-virtual, so no hot-path indirect call is added.

**The lease as the concurrency primitive.** `acquireLease(hostPort)` waits on `_cv` with the predicate `_closing || hostPort not in _leasedHosts` (predicate-form wait, spurious-wakeup safe). With `leaseAcquireTimeout > 0` it uses `wait_for` and throws `HttpLeaseAcquireTimeoutError` on expiry; otherwise it waits indefinitely. On wake it re-checks `_closing` (throwing `HttpClientCancelledError` if set), inserts the key, and returns a `ConnectionLease`. `releaseLease` erases the key under `_mutex` then calls `_cv.notify_all()` **after** releasing the lock.

> `notify_all` is load-bearing, not conservative. One `_cv` serves waiters for *every* `host:port`; `notify_one` could wake a waiter whose (different) host is still leased -- it re-parks, while the just-freed host's waiter is never woken (a lost wakeup).

**`ConnectionLease` (RAII guard).** Move-only; its `noexcept` destructor calls `releaseLease` exactly once on every scope exit including exceptions. There is **no hand-placed release anywhere else**. If `dropConnection` also released the lease, a woken waiter could take the freed host's lease and begin its exchange *before* the original guard's destructor ran -- and that destructor would then erase the new holder's lease. Hence `dropConnection` evicts the *connection cache* only and never touches the lease. `release()` is `noexcept` because leaking the lease (permanently deadlocking all future same-host requests) is worse than terminating on the theoretical `std::mutex::lock` corruption throw.

**`acquireConnection` -- lock discipline (LEASE-7).** Called only while holding the host's lease. (1) Under `_mutex`: first, a **lazy idle sweep** (CLI-CACHE) -- only when `_connections.size()` exceeds `kIdleSweepThreshold` (16), it closes and erases any *other* cached entry that is unleased and past `connectionIdleTimeout`, so a long-lived client hitting many distinct hosts does not accumulate dead entries (the common few-hosts case pays nothing, and a currently-leased or the target host is skipped). Then reuse a live cached connection for the target host if within `connectionIdleTimeout`, else close+evict the idle one. (2) **Release `_mutex`**, resolve DNS (`resolveHostAddress`). (3) Still no `_mutex`: `connectSync`. (4) Re-take `_mutex` briefly to publish the new `SessionId`, with a publish-then-recheck of `_closing` (canceller-first closes our own session and throws; publisher-first lets the cancel loop close it -- no interleaving leaves a live session). Returns `AcquiredConnection{ SessionId id; bool reused; }`; `reused` gates the pre-write liveness probe. The loopback connect timeout is clamped to `min(connectTimeout, 200ms)` for `127.0.0.1`/`::1` (and `localhost`, which `resolveHostAddress` maps to `127.0.0.1`), so `connectTimeout` is **not observable against loopback** -- exercise a real connect timeout against a non-routable address such as `192.0.2.1`.

**TLS client identity.** For an `https` target, `acquireConnection` sets `TlsClientOptions::verifyName` to the *original pre-resolution* host (empty for an IP literal, which routes to the iPAddress-match / no-SNI branch) and `x509HostFlags = kHttpsHostFlags` (RFC 9525). The connect authority is the resolved host + numeric port passed straight to `connectSync`, so the scheme prefix in the cache key never leaks onto the wire.

**`executeRequest` -- the exchange.** After caller-header validation and `parseUrl`, it computes the whole-exchange deadline once (if `totalRequestTimeout > 0`), acquires the lease, `acquireConnection`, `setReadMode(Sync)`, runs the pre-write liveness probe on a **reused** socket only, builds the request, `sendSync`s it, then loops `receiveSync` -> `frameResponse` until complete. Every receive-loop exit routes its cancellation check through one `throwIfClosing` lambda (`_closing.load(acquire)`). On completion it decides reuse: `reuseConnections && !responseRequestsClose(resp) && !forceEvict && mode != CloseDelimited` -> keep warm (`setReadMode(Async)`), else `dropConnection`. A `catch (...)` evicts the connection on any throw so no retry reuses a dead socket.

**URL parsing.** `parseUrl` lowercases the captured scheme before matching (RFC 3986 §3.1 makes the scheme case-insensitive), so `HTTP://` / `HTTPS://` parse correctly instead of throwing (CLI-NEW1). A bracketed IPv6-literal authority (`http://[::1]:8080/`) is parsed per RFC 3986 §3.2.2 (`"[" IPv6address "]" [ ":" port ]`): the raw authority is inspected before the regex host class, the bracket contents are validated as a real IPv6 address via `inet_pton(AF_INET6)`, and the host is stored **without** brackets (CLI-NEW2). Userinfo (`user:pass@`), a malformed/empty IPv6 literal, and a bad port are still rejected with `HttpInvalidUrlError`.

**Request line construction.** `formatHostHeaderField` emits `Host` with the port only when it differs from the scheme default (RFC 9110 §4.2.3 normalization), and re-brackets an IPv6-literal host (`Host: [::1]:8080`) since parseUrl stored it unbracketed (RFC 9112 §3.2 / RFC 7230) -- so the IPv6 authority round-trips onto the wire. `User-Agent` is caller-overridable (default emitted only when the caller supplied none). `Connection: keep-alive`/`close` is driven by `reuseConnections`, never a caller header. `Content-Length` is emitted for a non-empty body, and `methodAnticipatesContent(method)` (POST/PUT/PATCH) emits `Content-Length: 0` for an empty body (RFC 9110 §8.6, defect_13).

**Response framing engine (RFC 9112 §6.3/§7.1).**
- `parseHeaderBlock` parses the status line (`HTTP/1.0`/`1.1` only via exact match; status code via `parseFullUInt`/`std::from_chars`) and fields into the `CaseInsensitiveCompare` map. It rejects obs-fold continuations, conflicting duplicate `Content-Length`, and a duplicate `Transfer-Encoding` field-line (defect_18), and combines repeated list-valued fields (`Content-Encoding`/`Accept-Encoding`) into an ordered comma-list via `detail::addOrCombineHeader` (defect_8).
- `determineFraming` applies the §6.3 rule ladder: reject CONNECT (declared non-goal); `NoBody` for HEAD / `statusForbidsBody` (1xx/204/304); reject both CL+TE (rule 3); `Chunked` iff `chunked` is the *final* coding (`transferEncodingFinalIsChunked`) else `CloseDelimited` (rule 4); `ContentLength` validated + capped (rules 5/6); else `CloseDelimited` (rule 8).
- `advanceChunked` is an incremental, index-resuming, binary-safe chunked parser (no O(n^2), no substring false-terminator): hex size via `parseFullUInt`, BWS tolerated only before a chunk-ext `;`, rejects lone-LF / bare-CR / trailing-WS-before-CRLF, consumes the trailer section through the final CRLF, and uses subtraction-based bounds (never `start + n`, which can overflow for a raised cap).
- `frameResponse` ties them together, skipping interim `1xx` responses wholesale and returning `Complete`/`NeedMore`/`Malformed`. Surplus bytes past the framed message, or a close-delimited body, set `forceEvict`.

The raw accumulation buffer is bounded at all times by `effectiveCap = max(maxResponseBytes, jsonConfig.maxPayloadSize)`, enforced during receipt.

**Retry classification (`performRequest`).** The loop catches, in order: `HttpFramingError` (never retry -- includes `HttpInvalidHeaderError` and `HttpExchangeDeadlineError`); `HttpClientCancelledError` (never retry); `HttpInvalidUrlError` (never retry -- a `std::invalid_argument`, must precede the generic catch); then the generic `std::exception` gate `retryEligible = isIdempotentMethod(method) || isRequestProvablyNotSent(e)`. Non-eligible failures throw immediately (logged WARN). Backoff is exponential with a `thread_local std::mt19937` jitter PRNG, shift clamped to `kMaxBackoffShift = 10` and total capped at `kMaxBackoffMs = 1024 * 100 = 102400 ms`.

**Cancellation (`cancelInFlight` / `cleanup`).** `cancelInFlight() noexcept` latches `_closing = true` under `_mutex`, `notify_all`s the lease CV, and closes every cached transport session (waking any thread parked in `receiveSync`), but deliberately does **not** stop the transport/DNS so in-flight threads can unwind through them. It is idempotent and terminal (`_closing` is write-once monotonic -- the client is permanently retired, not paused). `cleanup()` = `cancelInFlight()` + stopping the transport and DNS client; its teardown tail runs outside `_mutex` and carries a no-concurrent-caller precondition. A request parked in DNS/`connectSync`/`sendSync` (no published session) is not accelerated -- it unwinds on its own timeout.

### 5.2 The exception taxonomy

The typed hierarchy is the retry gate. `isRequestProvablyNotSent(e)` is a pointer-form `dynamic_cast` to `HttpRequestNotSentError` -- the single home of the RFC 9110 §9.2.2 not-sent taxonomy, shared verbatim with `JsonRpcClient`.

```
std::runtime_error
├── HttpFramingError                 (deterministic parse/framing violation -- NEVER retried)
│   ├── HttpInvalidHeaderError       (caller-supplied bad/framing-controlled header)
│   └── HttpExchangeDeadlineError    (totalRequestTimeout exceeded -- terminal for the attempt)
├── HttpRequestNotSentError          (provably not sent -- retry-eligible for ANY method)
│   ├── HttpLeaseAcquireTimeoutError (leaseAcquireTimeout expired before any connect)
│   └── HttpConnectTimeoutError      (connectSync TransportError::Timeout -- TCP/TLS handshake)
├── HttpResponseTimeoutError         (response-read timeout -- POSSIBLY sent; retry only if idempotent)
└── HttpClientCancelledError         (client closing -- NEVER retried; send-ambiguous)

std::invalid_argument
└── HttpInvalidUrlError              (malformed URL / userinfo / malformed IPv6 literal / bad port -- NEVER retried)
```

Rationale highlights: `HttpInvalidHeaderError` is a `HttpFramingError` (not a `HttpRequestNotSentError`) so a header-injection caller bug is never re-sent on an idempotent method. `HttpExchangeDeadlineError` is a `HttpFramingError` so the whole-exchange deadline is non-retryable, bounding wall-clock to ~1x. `HttpConnectTimeoutError`/`HttpLeaseAcquireTimeoutError` derive from `HttpRequestNotSentError` so they retry for any method (the 2026-09-03 decision superseded the earlier sibling choice for the lease type), but carry a distinct type for by-type classification. `HttpResponseTimeoutError` is a **direct** `std::runtime_error` sibling -- neither not-sent (a POST must not retry it) nor framing (an idempotent GET should). `HttpInvalidUrlError` stays a `std::invalid_argument` for the `tmc_edge_proxy` cross-repo contract.

### 5.3 `HttpClientPool`

A thread-safe pool of independent clients. Its constructor validates `poolSize > 0` (else `std::invalid_argument`) and pre-populates the `core::BlockingQueue<std::shared_ptr<HttpClient>> _queue` with exactly `poolSize` clients built by `createClient()`. Copy and move are deleted; `~HttpClientPool` calls `close()`.

`createClient()` either invokes `Config::clientFactory` (if set) or builds a default `HttpClient` whose `Config` it fills from the pool `Config`: `requestTimeout`, `connectTimeout` (from `connectionTimeout`), `totalRequestTimeout`, `leaseAcquireTimeout` (CLI-F1), `followRedirects`, `maxRedirects`, `userAgent`, and `reuseConnections` (from `enableKeepAlive`). It then applies `tlsConfig` (via `setTlsConfig`) and the optional `clientConfigurer(HttpClient&)`. Copying `leaseAcquireTimeout` is what makes a pooled client's async API usable: `rejectUnboundedPooledRequest` admits `getAsync`/`postJsonAsync` only when both `totalRequestTimeout > 0` and `leaseAcquireTimeout > 0`, so before this field was copied a pooled client's `leaseAcquireTimeout` stayed `0` and every pooled async call rejected with `core::AsyncRejectedError`.

**Acquisition** is three modes over the queue: `get()` blocks (throws `std::runtime_error` if the pool is closed), `get(std::chrono::milliseconds timeout)` returns `std::optional<PooledHttpClient>` (`std::nullopt` on timeout or closed), and `tryGet()` returns immediately-or-`std::nullopt`. Each wraps the dequeued `shared_ptr<HttpClient>` in a `PooledHttpClient`.

**Return** is `returnClient(std::shared_ptr<HttpClient>)`, called only from `PooledHttpClient::returnToPool()`. It uses `_queue.tryQueue` (non-blocking) so a return can never deadlock; if the queue is closed or full the client is simply destroyed.

**Close** is one-way: `close()` `exchange`s `_closed` to `true` (idempotent) and closes the queue -- outstanding checkouts may still return, but no new acquisition succeeds.

**Statistics** are queue-derived snapshots: `capacity()` (= `poolSize`), `available()` (= `_queue.size()`), `inUse()` (= `capacity() - available()`), `empty()`, `full()`, `utilization()` (0-100), and `config()`. These are approximate under concurrency (each is a separate atomic read).

### 5.4 `PooledHttpClient`

A move-only RAII checkout. Move transfers ownership and nulls the source (`_pool = nullptr`); copy is deleted. Its destructor and move-assignment call `returnToPool()`, which returns the borrowed client to `_pool` and nulls `_client`. Every forwarding method calls `validateClient()` first, throwing `std::runtime_error("PooledHttpClient: Client has been returned to pool")` if the handle was moved-from.

It forwards the **full** blocking and async surface of `HttpClient` (CLI-F3): `get`, `postJson`, `post`, `deleteRequest`, `postFile`, `head`, `postStream`, `getAsync`, and `postJsonAsync`. It exposes `isValid()` and grants raw access via `client()` (both const and non-const) for anything not forwarded directly.

**No `setTlsConfig` forwarder (CLI-F5).** The forwarder was removed. `HttpClient::setTlsConfig` throws `std::logic_error` once the transport is initialized, and a pooled client is reused (its transport comes up on its first request), so a forwarder always threw on any client that had already served a request -- a footgun. TLS for pooled clients is a construction-time concern: set `HttpClientPool::Config::tlsConfig` (applied inside `createClient` before first use) or use a `clientConfigurer`. An advanced caller that truly needs the raw handle can still reach `client().setTlsConfig(...)` -- but only on a client that has not yet served a request.

---

## 6. Usage Guide

All examples are in `iora::network`. Any target that includes these headers pulls in `Transport` (and, for HTTPS, OpenSSL), so wire it with `configure_iora_target(<target> ENABLE_OPENSSL)` in CMake -- **not** a bare `iora_lib` link. Because `http_client.hpp` transitively includes `transport_impl.hpp` (the transport's single-TU definition header), include `http_client.hpp` / `http_client_pool.hpp` in **exactly one translation unit** per binary that also links the transport definitions (see Known Limitations).

### 6.1 Simple GET

```cpp
#include <iora/network/http_client.hpp>   // one TU only (drags in transport_impl.hpp)

int main()
{
  iora::network::HttpClient client;                        // default Config
  auto resp = client.get("http://api.example.com/status");
  if (resp.success())                                      // 2xx
  {
    // resp.statusCode, resp.statusText, resp.httpVersion, resp.headers, resp.body
  }
  return 0;
}
```

### 6.2 POST with a body and custom headers

```cpp
iora::network::HttpClient client;

// String body:
auto r1 = client.post("http://h/echo", "raw-bytes",
                      {{"X-Request-Id", "abc123"}});       // caller headers validated

// JSON body (Content-Type: application/json is library-owned and set for you):
iora::parsers::Json body;
body["name"] = "widget";
auto r2 = client.postJson("http://h/items", body,
                          {{"Authorization", "Bearer TOKEN"}});
```

Do not supply `Host`, `Content-Length`, `Connection`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, or `Expect` in the header map -- each throws `HttpInvalidHeaderError` (they are framing-controlled or owned by the client). `User-Agent` is accepted and overrides the default.

### 6.3 TLS / verification options

```cpp
iora::network::HttpClient client;

iora::network::HttpClient::TlsConfig tls;
tls.verifyPeer     = true;                     // default; verifies the server cert (RFC 9525)
tls.caFile         = "/etc/ssl/my-ca.pem";     // custom trust anchor (optional)
tls.clientCertFile = "/etc/ssl/client.pem";    // mTLS (optional)
tls.clientKeyFile  = "/etc/ssl/client.key";
client.setTlsConfig(tls);                       // MUST precede the first request

auto resp = client.get("https://secure.example.com/data");   // verifyName = host, kHttpsHostFlags
```

`setTlsConfig` throws `std::logic_error` if called after the first request (the transport reads TLS config once). To disable verification for a test endpoint, set `tls.verifyPeer = false` before the first request.

### 6.4 Timeouts and hardening against a slow peer

```cpp
iora::network::HttpClient::Config cfg;
cfg.connectTimeout      = std::chrono::milliseconds(2000);   // default
cfg.requestTimeout      = std::chrono::milliseconds(3000);   // per send/receive iteration
cfg.leaseAcquireTimeout = std::chrono::milliseconds(500);    // 0 = wait forever (default)
cfg.totalRequestTimeout = std::chrono::milliseconds(10000);  // whole-exchange bound; 0 = disabled
cfg.maxResponseBytes    = 32u * 1024 * 1024;                 // raise for large downloads
iora::network::HttpClient client(cfg);

auto resp = client.get("http://slow.example.com/big", {}, /*retries=*/2);
```

### 6.5 Pooled connections for same-host parallelism

```cpp
#include <iora/network/http_client_pool.hpp>

iora::network::HttpClientPool::Config pcfg;
pcfg.poolSize          = 8;
pcfg.requestTimeout    = std::chrono::milliseconds(5000);
pcfg.connectionTimeout = std::chrono::milliseconds(2000);
pcfg.enableKeepAlive   = true;
// TLS for every pooled client:
iora::network::HttpClient::TlsConfig tls; tls.verifyPeer = true;
pcfg.tlsConfig = tls;

iora::network::HttpClientPool pool(pcfg);

// Each worker checks out an independent client (own connection cache => real parallelism):
{
  auto client = pool.get();                    // blocks until one is free
  auto resp = client.get("https://api.example.com/data");
}                                              // client returned to the pool here (RAII)

// Non-blocking / bounded variants:
if (auto c = pool.tryGet())            { c->get("https://api.example.com/x"); }
if (auto c = pool.get(std::chrono::milliseconds(250))) { c->post("https://api.example.com/y", "z"); }
```

### 6.6 Async requests (bounded pool)

```cpp
iora::network::HttpClient::Config cfg;
cfg.totalRequestTimeout = std::chrono::milliseconds(10000);  // BOTH must be finite
cfg.leaseAcquireTimeout = std::chrono::milliseconds(1000);   // or the future carries AsyncRejectedError
iora::network::HttpClient client(cfg);

iora::core::PooledFuture<iora::network::HttpClient::Response> fut =
  client.getAsync("http://api.example.com/status");
auto resp = fut.get();     // joins like std::async; client MUST outlive the future
```

### 6.7 Anti-patterns -- do NOT

- **Do NOT set framing/connection headers.** `Host`, `Content-Length`, `Connection`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Expect` in the header map throw `HttpInvalidHeaderError` (request-smuggling defense).
- **Do NOT put credentials in the URL.** `http://user:pass@host/` throws `HttpInvalidUrlError` (credentials must never reach the request-target, RFC 9112 §3.2). Use an `Authorization` header.

(A bracketed IPv6-literal URL such as `http://[::1]:8080/` and a mixed-case scheme such as `HTTPS://host/` are both supported -- see §5.1. They are no longer errors.)
- **Do NOT call `cleanup()` or destroy an `HttpClient` while requests are in flight on other threads.** Join them first. To unblock from another thread use `cancelInFlight()` -- but it is **terminal** (the client is permanently retired, every later request throws `HttpClientCancelledError`), not a pause.
- **Do NOT rely on `connectTimeout` against loopback** -- it is clamped to `min(connectTimeout, 200ms)` for `127.0.0.1`/`::1`/`localhost`. Target `192.0.2.1` to exercise a real connect timeout.
- **Do NOT expect a shared `HttpClient` to give same-host concurrency** -- same-host requests serialize on the lease. Use `HttpClientPool` for that.
- **Do NOT call `getAsync`/`postJsonAsync` without finite `totalRequestTimeout` AND `leaseAcquireTimeout`** -- the returned future carries `core::AsyncRejectedError` (protects the shared bounded pool).
- **Do NOT try to set TLS on a checked-out pooled client.** `PooledHttpClient` has **no** `setTlsConfig` forwarder (CLI-F5, removed): a pooled client's transport comes up on its first request, after which `setTlsConfig` throws `std::logic_error`. Configure TLS via `HttpClientPool::Config::tlsConfig` (applied at construction) or a `clientConfigurer` instead.
- **Do NOT retry a non-idempotent POST blindly** by catching-and-re-posting -- the built-in gate already retries only what is provably not sent; a manual retry loop reintroduces the double-submit hazard.

---

## 7. Call Flow / Sequence Reference

### 7.1 Success path -- fresh connection, `GET`

| Step | Actor | Action / lock |
|---|---|---|
| 1 | `performRequest` | Lock `_mutex`; if `_closing` throw `HttpClientCancelledError`; `ensureInitialized()`; release. |
| 2 | `executeRequest` | Validate every caller header (token name, value octets, framing-controlled) -> `HttpInvalidHeaderError` on failure. |
| 3 | `executeRequest` | `parseUrl(url)` -> `ParsedUrl` (scheme lowercased for case-insensitive matching; `HttpInvalidUrlError` on userinfo / malformed-IPv6 / bad-port); compute `exchangeDeadline` if `totalRequestTimeout > 0`. |
| 4 | `acquireLease` | Lock `_mutex`; `_cv.wait(pred)`; insert `scheme://host:port` into `_leasedHosts`; return `ConnectionLease`. |
| 5 | `acquireConnection` | Lock `_mutex` (cache miss); **release**; `resolveHostAddress`; `connectSync` (no lock); re-lock to publish `{id, false}` with `_closing` recheck. |
| 6 | `executeRequest` | `setReadMode(id, Sync)`; skip probe (fresh); build request; `sendSync`. |
| 7 | receive loop | Per iteration: deadline check; `receiveSync(id, buffer, recvTimeout)`; `frameResponse` -> `Complete`. |
| 8 | `executeRequest` | Reusable -> `setReadMode(id, Async)` (keep warm); return `Response`. |
| 9 | `~ConnectionLease` | `releaseLease`: erase key under `_mutex`; `_cv.notify_all()` after unlock. |

### 7.2 Reused-connection path -- pre-write liveness probe

| Step | Actor | Action |
|---|---|---|
| 5' | `acquireConnection` | Cache hit within `connectionIdleTimeout` -> return `{id, reused=true}` (no connect). |
| 6' | `executeRequest` | `setReadMode(id, Sync)`; issue `receiveSync(id, 1 byte, 0ms)` **before writing**. |
| 6'a | -- | `Timeout` -> socket healthy, proceed to `sendSync`. |
| 6'b | -- | Any other outcome (PeerClosed / unexpected bytes / overflow / cancel) -> `dropConnection` + throw `std::runtime_error`, re-classified `HttpRequestNotSentError` (or `HttpClientCancelledError` if `_closing`) -> **retried on a fresh socket**. |

Best-effort only: peer close is observed asynchronously, so a missed FIN lets the write proceed and the post-write failure is (correctly) not retried. Safety rests on the type-gate, never the probe.

### 7.3 Failure / timeout / cleanup paths

| Trigger | Where | Exception | Retryable? |
|---|---|---|---|
| Lease wait exceeds `leaseAcquireTimeout` | `acquireLease` | `HttpLeaseAcquireTimeoutError` | Yes -- any method (never touched the wire) |
| `connectSync` returns `TransportError::Timeout` | `acquireConnection` | `HttpConnectTimeoutError` | Yes -- any method |
| Other connect failure (refuse/reset/DNS) | `acquireConnection` -> generic pre-send catch | `HttpRequestNotSentError` | Yes -- any method |
| `sendSync` enqueue failure | `executeRequest` | `HttpRequestNotSentError` | Yes -- any method |
| Per-iteration read timeout (unclamped) | receive loop | `HttpResponseTimeoutError` | Idempotent only |
| `totalRequestTimeout` elapsed | receive loop top | `HttpExchangeDeadlineError` | No |
| Malformed framing / `BufferOverflow` / cap exceeded / unsupported version | `frameResponse` / receive loop | `HttpFramingError` | No |
| Peer close before complete (non-close-delimited) | receive loop | `std::runtime_error` (-> not-sent gate: no) | Idempotent only |
| `cancelInFlight()` on another thread | any abort exit | `HttpClientCancelledError` | No |

### 7.4 Pool acquire / return

| Step | Actor | Action / lock |
|---|---|---|
| 1 | `pool.get()` | If `_closed` -> throw. `_queue.dequeue(client)` (blocks under the queue's own lock). Wrap in `PooledHttpClient(this, client)`. |
| 2 | caller | Issues requests through the borrowed client (which serializes its own same-host work internally). |
| 3 | `~PooledHttpClient` | `returnToPool()` -> `_pool->returnClient(client)` -> `_queue.tryQueue(client)` (non-blocking; dropped if closed/full); `_client = nullptr`. |
| 4 | `pool.close()` | `_closed.exchange(true)`; `_queue.close()` -- parked `get()` callers wake and throw/`nullopt`. |

---

## 8. Thread Safety Model

**Is `HttpClient` itself thread-safe?** Yes. Concurrent requests on one shared instance are safe: same-`host:port` requests are serialized by the connection lease (RFC 7230 §6.3 -- a persistent connection carries one exchange at a time), different-host requests run in parallel. `cancelInFlight()` is safe to call concurrently with in-flight requests.

**Is `HttpClientPool` thread-safe?** Yes -- acquisition/return go through the internally-synchronized `core::BlockingQueue` and the `std::atomic<bool> _closed`. A checked-out client is never shared between two live `PooledHttpClient` handles.

### 8.1 `HttpClient` -- per-operation

| Method | Synchronization | Safe to call from |
|--------|-----------------|-------------------|
| `get`/`head`/`post`/`postJson`/`deleteRequest`/`postFile`/`postStream` | Per-host `ConnectionLease` for the whole exchange; `_mutex` only for short bookkeeping; `_mutex` released across DNS + transport I/O (LEASE-7) | Any thread, concurrently (same-host serialized, different-host parallel) |
| `getAsync`/`postJsonAsync` | Admission gate (`rejectUnboundedPooledRequest`) then `core::async` wrapping the sync path onto `generalAsyncPool` | Any thread; NOT from a `generalAsyncPool` worker (DP-8) |
| `acquireLease`/`releaseLease` (private) | `_mutex` + `_cv`; predicate-form wait; `notify_all` on release | Internal, lease protocol |
| `acquireConnection`/`dropConnection` (private) | `_mutex` for cache bookkeeping; `_transport->close()` is a non-blocking enqueue, safe under `_mutex` | Internal, lease-holder only |
| `cancelInFlight` | `_mutex`; sets `_closing`; `notify_all`; closes cached sessions; does NOT stop transport/DNS | **Any thread, concurrently with in-flight requests** |
| `cleanup` / `~HttpClient` | `cancelInFlight()` then stops transport + DNS (tail outside `_mutex`) | Must NOT race in-flight requests on other threads |
| `setTlsConfig`/`setDnsServers`/`addDnsServer`/`getDnsServers` | `_mutex`; `setTlsConfig` throws if transport already initialized | Best set before concurrent use |

- **Single `_mutex` + single `_cv`:** no lock-ordering hazard.
- **`_closing` is `std::atomic<bool>`, write-once monotonic:** every store is under `_mutex` with `notify_all` under the lock (no lost wakeup); the two lock-free reads (the pre-send generic catch and the `throwIfClosing` lambda) use `load(std::memory_order_acquire)`.
- **No locale races:** response-header case folding uses `CaseInsensitiveCompare::asciiLower` (ASCII-only); all `std::regex` objects are compiled once in a function-local `static` (`compiledRegexes()`), warming the libstdc++ `std::ctype` narrow cache on a single thread.
- **`thread_local` retry PRNG:** de-synchronizes concurrent retry storms and removes a global-PRNG data race.

### 8.2 `HttpClientPool` / `PooledHttpClient`

| Method | Synchronization | Notes |
|--------|-----------------|-------|
| `get()` / `get(timeout)` / `tryGet()` | `core::BlockingQueue` internal lock + `_closed` atomic | Blocking / bounded / non-blocking dequeue |
| `returnClient` (private) | `_queue.tryQueue` (non-blocking) | Called from `PooledHttpClient::returnToPool`; drops the client if closed/full |
| `close` / `isClosed` | `_closed` atomic (`exchange`/`load`) + `_queue.close()` | Idempotent, one-way |
| `capacity`/`available`/`inUse`/`empty`/`full`/`utilization` | queue `size()`/`empty()`/`full()` reads | Approximate under concurrency (separate atomic reads) |
| `PooledHttpClient` forwarders (`get`/`postJson`/`post`/`deleteRequest`/`postFile`/`head`/`postStream`/`getAsync`/`postJsonAsync`) + `client()`/`isValid` | none of its own (delegates to the borrowed `HttpClient`) | Not thread-safe to share one handle across threads; the handle is single-owner |

**Lifetime invariant.** The `HttpClientPool` MUST outlive every `PooledHttpClient` it hands out: `~PooledHttpClient` -> `returnToPool()` dereferences the raw `_pool` back-pointer (AP-19), so destroying the pool while any checkout is still live is undefined behavior.

---

## 9. Configuration Reference

### 9.1 `HttpClient::Config`

| Field | Type | Default | Effect / range |
|-------|------|---------|--------|
| `connectTimeout` | `std::chrono::milliseconds` | `2000` | TCP (and TLS) connect deadline. Clamped to `min(., 200ms)` for loopback (so not observable there). |
| `requestTimeout` | `std::chrono::milliseconds` | `3000` | Per-iteration send/receive sync timeout (re-arms each `receiveSync`). |
| `maxRedirects` | `int` | `5` | **RESERVED AND INERT** -- no redirect logic exists. |
| `followRedirects` | `bool` | `false` | **RESERVED AND INERT** -- defaults `false` so the config advertises no capability it lacks. |
| `userAgent` | `std::string` | `"Iora-HttpClient/1.0"` | Default `User-Agent`; overridden if the caller supplies one. |
| `reuseConnections` | `bool` | `true` | `true` -> `Connection: keep-alive` + warm reuse; `false` -> `Connection: close`, evict after each request. |
| `connectionIdleTimeout` | `std::chrono::seconds` | `300` | Cached connection considered stale after this idle period. |
| `leaseAcquireTimeout` | `std::chrono::milliseconds` | `0` | Max wait for the per-host lease; `0` = wait indefinitely. Non-zero surfaces `HttpLeaseAcquireTimeoutError`. Must be `> 0` for async. |
| `totalRequestTimeout` | `std::chrono::milliseconds` | `0` | Whole-exchange deadline (connect through last byte), computed once. `0` = disabled (opt-in). Expiry -> `HttpExchangeDeadlineError` (non-retryable). Must be `> 0` for async. |
| `maxResponseBytes` | `std::size_t` | `16 * 1024 * 1024` (16 MiB) | Hard cap on total received bytes (headers + body), enforced during receipt. Effective cap = `max(maxResponseBytes, jsonConfig.maxPayloadSize)`. |
| `jsonConfig.maxPayloadSize` | `std::size_t` | `10 * 1024 * 1024` (10 MiB) | Post-receipt JSON size cap (used by `parseJsonOrThrow`); also feeds the effective receive cap. |
| `jsonConfig.parseLimits` | `parsers::ParseLimits` | (parser default) | JSON depth/array-size limits. |

`Config::forLocalhost()` returns a config with `connectTimeout = 100ms`, `requestTimeout = 200ms` (all other fields default).

`TlsConfig`: `caFile` (empty), `clientCertFile` (empty), `clientKeyFile` (empty), `verifyPeer = true`.

### 9.2 `HttpClientPool::Config`

| Field | Type | Default | Effect |
|-------|------|---------|--------|
| `poolSize` | `std::size_t` | `10` | Number of pre-created clients; must be `> 0` (else `std::invalid_argument`). Also `capacity()`. |
| `requestTimeout` | `std::chrono::milliseconds` | `30000` | Copied to each client's `Config::requestTimeout`. |
| `connectionTimeout` | `std::chrono::milliseconds` | `10000` | Copied to each client's `Config::connectTimeout`. |
| `enableKeepAlive` | `bool` | `true` | Copied to each client's `Config::reuseConnections`. |
| `enableCompression` | `bool` | `false` | **RESERVED AND INERT** -- `HttpClient` has no compression path, `createClient()` does not copy it, and `HttpClient::Config` has no matching field. Retained for source/ABI stability; adding compression would need a design pass, not merely honoring this flag (CLI-F2). |
| `totalRequestTimeout` | `std::chrono::milliseconds` | `0` | Copied to each client's `Config::totalRequestTimeout` (opt-in slowloris bound). Set together with `leaseAcquireTimeout` to enable the pooled async API. |
| `leaseAcquireTimeout` | `std::chrono::milliseconds` | `0` | Copied to each client's `Config::leaseAcquireTimeout` (CLI-F1). `0` waits indefinitely for the per-host lease. Must be `> 0` **alongside** `totalRequestTimeout > 0` for a pooled client's `getAsync`/`postJsonAsync` to pass the admission gate. |
| `followRedirects` | `bool` | `false` | **RESERVED AND INERT** -- copied to the client's inert field. |
| `maxRedirects` | `int` | `5` | **RESERVED AND INERT** -- copied to the client's inert field. |
| `userAgent` | `std::string` | `"Iora-HttpClientPool/1.0"` | Copied to each client's `Config::userAgent`. |
| `defaultHeaders` | `std::map<std::string,std::string>` | `{}` | **RESERVED AND INERT** -- not injected into requests. Set headers per request. |
| `clientFactory` | `std::function<std::unique_ptr<HttpClient>()>` | empty | Custom client construction; bypasses the field-copy path above. |
| `clientConfigurer` | `std::function<void(HttpClient&)>` | empty | Post-creation hook (e.g. to set `leaseAcquireTimeout`, DNS servers, or per-client TLS). |
| `tlsConfig` | `std::optional<HttpClient::TlsConfig>` | `std::nullopt` | Applied to every client via `setTlsConfig` at creation. |

> Note: the pool copies the fields above, which now include `leaseAcquireTimeout` (CLI-F1) -- so a pooled client's async API is reachable purely from the pool `Config` by setting both `totalRequestTimeout > 0` and `leaseAcquireTimeout > 0`. The remaining `HttpClient::Config` fields -- `connectionIdleTimeout`, `maxResponseBytes`, and `jsonConfig` -- are **not** configurable through the pool `Config`; use `clientConfigurer` (or `clientFactory`) to set them.

### 9.3 Build wiring

HTTPS requires OpenSSL through the transport. Link consuming targets with `configure_iora_target(<target> ENABLE_OPENSSL)`, not a bare `iora_lib`. `http_client.hpp` includes `transport_impl.hpp`, so include it (or `http_client_pool.hpp`) in exactly one translation unit per binary.

---

## 10. API Reference

### 10.1 Exceptions and free functions

```cpp
namespace iora::network
{
class HttpFramingError          : public std::runtime_error { public: explicit HttpFramingError(const std::string&); };
class HttpInvalidHeaderError    : public HttpFramingError   { public: explicit HttpInvalidHeaderError(const std::string&); };
class HttpInvalidUrlError       : public std::invalid_argument { public: explicit HttpInvalidUrlError(const std::string&); };
class HttpRequestNotSentError   : public std::runtime_error { public: explicit HttpRequestNotSentError(const std::string&); };
class HttpClientCancelledError  : public std::runtime_error { public: using std::runtime_error::runtime_error; };
class HttpLeaseAcquireTimeoutError : public HttpRequestNotSentError { public: explicit HttpLeaseAcquireTimeoutError(const std::string&); };
class HttpResponseTimeoutError  : public std::runtime_error { public: explicit HttpResponseTimeoutError(const std::string&); };
class HttpExchangeDeadlineError : public HttpFramingError   { public: explicit HttpExchangeDeadlineError(const std::string&); };
class HttpConnectTimeoutError   : public HttpRequestNotSentError { public: explicit HttpConnectTimeoutError(const std::string&); };

inline std::string formatHostHeaderField(const std::string& host, std::uint16_t port, bool isHttps);
inline bool isHttpTokenChar(unsigned char c);
inline bool isValidHttpFieldName(const std::string& name);
inline bool isValidHttpFieldValue(const std::string& value);
inline bool ciEqualsAscii(const std::string& a, const std::string& b);
inline bool isFramingControlledHeaderName(const std::string& name);
inline void setLibraryOwnedHeader(std::map<std::string,std::string>& headers,
                                  const std::string& name, const std::string& value);
}
```

### 10.2 `HttpClient`

```cpp
class HttpClient
{
public:
  struct TlsConfig { std::string caFile, clientCertFile, clientKeyFile; bool verifyPeer = true; };

  struct Response
  {
    int statusCode = 0;
    std::string statusText;
    std::string httpVersion;                                                  // "1.1" / "1.0"
    std::map<std::string, std::string, CaseInsensitiveCompare> headers;       // case-insensitive names
    std::string body;
    bool success() const;                                                     // 2xx
  };

  struct JsonConfig { std::size_t maxPayloadSize = 10*1024*1024; parsers::ParseLimits parseLimits; };

  struct Config
  {
    std::chrono::milliseconds connectTimeout;      // 2000
    std::chrono::milliseconds requestTimeout;      // 3000
    int  maxRedirects;                             // 5   (inert)
    bool followRedirects;                          // false (inert)
    std::string userAgent;                         // "Iora-HttpClient/1.0"
    bool reuseConnections;                         // true
    std::chrono::seconds connectionIdleTimeout;    // 300
    std::chrono::milliseconds leaseAcquireTimeout; // 0
    std::chrono::milliseconds totalRequestTimeout; // 0
    std::size_t maxResponseBytes;                  // 16 MiB
    JsonConfig jsonConfig;
    Config();
    static Config forLocalhost();
  };

  explicit HttpClient(const Config& config = Config{});
  virtual ~HttpClient();                                   // virtual: factory may return a derived type
  HttpClient(const HttpClient&)            = delete;
  HttpClient& operator=(const HttpClient&) = delete;
  HttpClient(HttpClient&&)                 = delete;       // non-movable (owns mutex/CV/lease state)
  HttpClient& operator=(HttpClient&&)      = delete;

  void setTlsConfig(const TlsConfig& config);              // throws std::logic_error after init
  void setDnsServers(const std::vector<std::string>& servers);
  void addDnsServer(const std::string& server);
  std::vector<std::string> getDnsServers();

  static bool isIdempotentMethod(const std::string& method);        // GET/HEAD/PUT/DELETE/OPTIONS/TRACE
  static bool methodAnticipatesContent(const std::string& method);  // POST/PUT/PATCH
  static bool isRequestProvablyNotSent(const std::exception& e);    // is-a HttpRequestNotSentError

  Response get(const std::string& url, const std::map<std::string,std::string>& headers = {}, int retries = 0);
  Response head(const std::string& url, const std::map<std::string,std::string>& headers = {}, int retries = 0);
  Response post(const std::string& url, const std::string& body,
                const std::map<std::string,std::string>& headers = {}, int retries = 0);
  Response postJson(const std::string& url, const parsers::Json& body,
                    const std::map<std::string,std::string>& headers = {}, int retries = 0);
  Response deleteRequest(const std::string& url,
                         const std::map<std::string,std::string>& headers = {}, int retries = 0);
  Response postFile(const std::string& url, const std::string& fieldName, const std::string& filePath,
                    const std::map<std::string,std::string>& headers = {}, int retries = 0);
  // NOTE: line-buffered emulation, not incremental streaming -- it buffers the full
  // response, then splits the body into lines and invokes onChunk per line (see Known Limitations).
  void     postStream(const std::string& url, const parsers::Json& body,
                      const std::map<std::string,std::string>& headers,
                      const std::function<void(const std::string&)>& onChunk, int retries = 0);

  core::PooledFuture<Response> getAsync(const std::string& url,
                                        const std::map<std::string,std::string>& headers = {}, int retries = 0);
  core::PooledFuture<Response> postJsonAsync(const std::string& url, const parsers::Json& body,
                                             const std::map<std::string,std::string>& headers = {}, int retries = 0);

  static parsers::Json parseJsonOrThrow(const Response& response);
  static parsers::Json parseJsonOrThrow(const Response& response, const JsonConfig& jsonConfig);

  void cancelInFlight() noexcept;   // unblock in-flight requests from another thread; safe concurrently; terminal
  void cleanup();                   // cancelInFlight() + stop transport/DNS; NOT safe to race in-flight requests
};
```

### 10.3 `PooledHttpClient` and `HttpClientPool`

```cpp
class PooledHttpClient
{
public:
  PooledHttpClient(PooledHttpClient&&) noexcept;
  PooledHttpClient& operator=(PooledHttpClient&&) noexcept;
  PooledHttpClient(const PooledHttpClient&)            = delete;
  PooledHttpClient& operator=(const PooledHttpClient&) = delete;
  ~PooledHttpClient();                                  // returns the client to the pool

  HttpClient::Response get(const std::string& url, const std::map<std::string,std::string>& headers = {}, int maxRetries = 0);
  HttpClient::Response postJson(const std::string& url, const parsers::Json& body,
                                const std::map<std::string,std::string>& headers = {}, int maxRetries = 0);
  HttpClient::Response post(const std::string& url, const std::string& body,
                            const std::map<std::string,std::string>& headers = {}, int maxRetries = 0);
  HttpClient::Response deleteRequest(const std::string& url,
                                     const std::map<std::string,std::string>& headers = {}, int maxRetries = 0);
  HttpClient::Response postFile(const std::string& url, const std::string& fieldName, const std::string& filePath,
                                const std::map<std::string,std::string>& headers = {}, int maxRetries = 0);
  HttpClient::Response head(const std::string& url,
                            const std::map<std::string,std::string>& headers = {}, int maxRetries = 0);
  void                 postStream(const std::string& url, const parsers::Json& body,
                                  const std::map<std::string,std::string>& headers,
                                  const std::function<void(const std::string&)>& onChunk, int maxRetries = 0);
  core::PooledFuture<HttpClient::Response>
                       getAsync(const std::string& url,
                                const std::map<std::string,std::string>& headers = {}, int maxRetries = 0);
  core::PooledFuture<HttpClient::Response>
                       postJsonAsync(const std::string& url, const parsers::Json& body,
                                     const std::map<std::string,std::string>& headers = {}, int maxRetries = 0);

  bool isValid() const;
  HttpClient& client();                    // raw access to anything not forwarded
  const HttpClient& client() const;
  // NOTE: no setTlsConfig forwarder (CLI-F5) -- configure TLS via HttpClientPool::Config::tlsConfig.
};

class HttpClientPool
{
public:
  struct Config
  {
    std::size_t poolSize = 10;
    std::chrono::milliseconds requestTimeout{30000};
    std::chrono::milliseconds connectionTimeout{10000};
    bool enableKeepAlive = true;
    bool enableCompression = false;                  // inert
    std::chrono::milliseconds totalRequestTimeout{0};
    bool followRedirects = false;                    // inert
    int  maxRedirects = 5;                           // inert
    std::string userAgent = "Iora-HttpClientPool/1.0";
    std::map<std::string,std::string> defaultHeaders{};   // inert
    std::function<std::unique_ptr<HttpClient>()> clientFactory;
    std::function<void(HttpClient&)> clientConfigurer;
    std::optional<HttpClient::TlsConfig> tlsConfig;
  };

  explicit HttpClientPool(const Config& config);     // throws std::invalid_argument if poolSize == 0
  ~HttpClientPool();
  HttpClientPool(const HttpClientPool&)            = delete;
  HttpClientPool& operator=(const HttpClientPool&) = delete;
  HttpClientPool(HttpClientPool&&)                 = delete;
  HttpClientPool& operator=(HttpClientPool&&)      = delete;

  PooledHttpClient get();                                            // blocks; throws if closed
  std::optional<PooledHttpClient> get(std::chrono::milliseconds timeout);
  std::optional<PooledHttpClient> tryGet();

  void close();
  bool isClosed() const;

  std::size_t capacity() const;
  std::size_t available() const;
  std::size_t inUse() const;
  bool   empty() const;
  bool   full() const;
  double utilization() const;                        // 0-100
  const Config& config() const;
};
```

---

## 11. Design Decisions

> RFC note: earlier decisions cite RFC 7230/7231; later ones cite RFC 9110/9112, which obsolete them with the same normative content (persistence/`Connection` -> RFC 9110 §7.6.1 + RFC 9112 §9; idempotency -> RFC 9110 §9.2.2). The mixed numbering is historical.

| Decision | Rationale |
|----------|-----------|
| Exclusive per-`host:port` `ConnectionLease` for the whole exchange | Serializes same-host work on one persistent connection (RFC 7230 §6.3) without pipelining; removes byte-interleaving and use-after-evict on a shared instance. |
| Lease released by RAII only; `dropConnection` evicts the cache, never the lease | A second release point would let a woken waiter take the freed lease before the guard's destructor ran, corrupting the new holder. |
| Scheme-qualified connection key (`getHostPort` = `scheme://host:port`) | An `https` request must not reuse a plaintext `http` socket to the same authority (a silent TLS downgrade). Keying on the scheme makes the TLS-mode invariant structural, and re-keys every dependent site at once. |
| `_mutex` never held across DNS or transport I/O (LEASE-7) | The lease, not the mutex, serializes same-host work; holding `_mutex` across I/O would block lease releases and other hosts' bookkeeping. |
| Typed exception taxonomy gating retry (RFC 9110 §9.2.2) | A non-idempotent method that may have reached the wire must not be blindly re-sent (double-submit). Provably-not-sent (`HttpRequestNotSentError`) is safe for any method; framing/deadline/cancel are never retried; response-timeout is idempotent-only. |
| `HttpInvalidUrlError` is a `std::invalid_argument`, not in the framing hierarchy | Preserves the `tmc_edge_proxy` cross-repo contract (malformed URL -> `std::invalid_argument`) while still being non-retryable via a dedicated pre-generic catch. |
| Reject caller `Host`/`Content-Length`/`Connection`/`Transfer-Encoding`/`TE`/`Trailer`/`Upgrade`/`Expect` | Supplying any produces a duplicate/conflicting framing field (CL/CL, TE.CL desync) or a control the client owns -- the request-smuggling primitive. Matched case-insensitively over the case-sensitive caller map. |
| Frame the body once from the parsed header map (never substring scans) | Substring framing false-positives and is a smuggling/desync vector; `determineFraming` + `advanceChunked` implement the RFC 9112 §6.3 rule ladder deterministically. |
| Optional `totalRequestTimeout` as a `HttpFramingError` (non-retryable) | `requestTimeout` re-arms per `receiveSync`, so a trickle/1xx-flood peer resets it forever; only an outer once-computed deadline bounds a client-side slowloris, and it must be terminal to keep wall-clock at ~1x. |
| Best-effort pre-write liveness probe on reused sockets only | A keep-alive socket the peer idle-closed buffers the write and fails on read (possibly-applied); probing before the write turns the common case into provably-not-sent so a POST recovers on a fresh socket -- safety still rests on the type-gate, not the probe. |
| Async methods return `core::PooledFuture<Response>` on the shared bounded pool, gated by a finite-timeout check | Avoids a per-call OS thread; the finite `totalRequestTimeout` + `leaseAcquireTimeout` requirement stops one hung request from occupying a bounded worker forever and starving `generalAsyncPool`. |
| Virtual destructor, non-virtual request methods | `clientFactory` may return a derived type destroyed through the base pointer (needs virtual dtor); keeping request methods non-virtual avoids a hot-path indirect call. |
| High-entropy multipart boundary via `crypto::SecureRng`, verified absent from content | RFC 2046 §5.1.1 makes non-appearance a MUST; a clock-derived boundary was predictable and could collide with binary uploads. |
| Pool of independent clients over `core::BlockingQueue` | Real same-host parallelism needs multiple connections; each client owns its own cache, so the pool provides it without touching the single-connection lease model. |
| `notify_all` (not `notify_one`) on lease release | One `_cv` serves all hosts; `notify_one` could wake a wrong-host waiter and lose the freed host's wakeup. |

---

## 12. Known Limitations

| Limitation | Description | Status |
|------------|-------------|--------|
| **Redirects not followed** | `Config::followRedirects` / `maxRedirects` (client and pool) are reserved and inert -- no `Location`/3xx logic exists. | By design (documented inert). |
| **HTTP/1.x only** | A non-`HTTP/1.0`/`1.1` status line is rejected with `HttpFramingError("unsupported HTTP version")`. | By design (1.x client). |
| **Content codings not decoded** | A chunked-final body is de-chunked, but an inner content-coding (`gzip`, etc.) is returned undecoded -- the client advertises no `Accept-Encoding`/`TE`. | By design. |
| **No `Expect: 100-continue`** | Headers + body are written in one `sendSync`, so there is no "headers sent, body pending" sub-state; `Expect` is rejected as a controlled header. | By design. |
| **`postStream` is not true SSE** | It buffers the full response, throws `std::runtime_error` on a non-2xx status, then line-splits the body and calls `onChunk` per line -- not incremental streaming. | Gap (line-buffered emulation). |
| **`cleanup()`/destruction during in-flight requests is unsupported** | Join request threads first. `cancelInFlight()` unblocks from another thread but is terminal (retires the client), not a pause. A request parked in DNS/`connectSync`/`sendSync` unwinds only on its own timeout. | By design (documented precondition). |
| **No content compression** | `HttpClientPool::Config::enableCompression` is now explicitly RESERVED AND INERT in the source (CLI-F2): `HttpClient` has no gzip/deflate path, `createClient()` does not copy the flag, and `HttpClient::Config` has no matching field. Adding compression is a design pass, not a flag flip. | By design (documented inert). |
| **Pool cannot configure `connectionIdleTimeout`/`maxResponseBytes`/`jsonConfig`** | `createClient()` copies `requestTimeout`, `connectTimeout`, `totalRequestTimeout`, `leaseAcquireTimeout` (CLI-F1), `followRedirects`, `maxRedirects`, `userAgent`, and `reuseConnections`; `connectionIdleTimeout`, `maxResponseBytes`, and `jsonConfig` keep client defaults. Use `clientConfigurer`/`clientFactory` for those. (Async **is** now reachable from the pool `Config` by setting `totalRequestTimeout > 0` and `leaseAcquireTimeout > 0`.) | Gap (workaround via hooks). |
| **`http_client.hpp` is not include-safe in multiple TUs** | It transitively includes `transport_impl.hpp` (single-TU definitions), so including it in two TUs risks ODR/duplicate-symbol errors despite the "header-only" framing. | Constraint (include in one TU). |
| **`connectTimeout` not observable against loopback** | Clamped to `min(connectTimeout, 200ms)` for `127.0.0.1`/`::1`/`localhost`. Use `192.0.2.1` to exercise a real timeout. | By design (defect_9). |
| **Pool must outlive its checkouts** | `~PooledHttpClient` -> `returnToPool()` dereferences a raw `_pool` back-pointer (AP-19); destroying the `HttpClientPool` while any `PooledHttpClient` handle is still live is undefined behavior. Keep the pool alive until every checkout has been returned/destroyed. | Constraint (caller-enforced lifetime). |
