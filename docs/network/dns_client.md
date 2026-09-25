# Iora DnsClient — Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.5 |
| **Date** | 2026-09-25 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/network/dns_client.hpp` |
| **Internal headers** | `include/iora/network/dns/dns_resolver.hpp`, `dns_transport.hpp`, `dns_cache.hpp`, `dns_message.hpp`, `dns_types.hpp`, `dns_utils.hpp` |
| **Namespaces** | `iora::network` (`DnsClient`, `AsyncDnsRequest`, `CancellableFuture<T>`); `iora::network::dns` (all backing types) |
| **Dependencies** | `<algorithm>`, `<atomic>`, `<cctype>`, `<functional>`, `<future>`, `<memory>`, `<sstream>`, `<string>`, `<vector>`; internally `network/transport_impl.hpp` (the UDP/TCP engines), `core/timer.hpp` (`TimerService`), `core/string_utils.hpp`, `util/expiring_cache.hpp` |

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-14 | Initial guide, authored against the hardened implementation. Documents `DnsClient` and its `dns/` backing layer (`DnsResolver`, `DnsTransport`, `DnsCache`, `DnsMessage`) as a standalone, application-facing DNS-protocol client, distinct from the transport-internal `NameResolver`/`getaddrinfo` path. RFC 3263 support is the SIP `S`/`A`-flag server-location subset (no `U`-flag/ENUM, no chained NAPTR), with ascending-`ORDER` NAPTR descent (RFC 3403 §8) and per-service SRV `.` handling (RFC 2782). Negative responses (NXDOMAIN and NODATA) are cached only when an SOA is present (RFC 2308 §5). `cacheTimeout` drives the cache default TTL; `maxUdpSize`/`tcpTimeout` remain declared-but-unused and `maxCacheSize` is not an entry cap (the cache is time-based). |
| 1.1 | 2026-09-24 | DOC-4: rehomed README-unique content (`dns::DnsType` enumerators and typed-accessor coverage, typed record struct fields in §8; `markCompleted()` step in the §5 async-cancellation flow; application-level failover pattern in §4); corrected §3.5 (an RDATA security-check throw fails the whole `DnsMessage::parse`, it is not skipped) and described `validateRdataSecurity`'s actual checks; recorded its false positives on valid AAAA records, UTF-8 or 192–255-byte-string TXT records and `192.[0-63].0.0` A records, and the zero-length TXT/AAAA RDATA null read (process crash) in Known Limitations. |
| 1.2 | 2026-09-24 | DOC-4 doc-review fixes: `DnsTransport::stop()` now documented as collect-under-lock / fire-with-no-lock (deadlock warning and stale citation removed); raw-callback cancel semantics (the callback always fires exactly once, even after `cancel()`) and `CancellableFuture::cancel()` semantics corrected; callback threads now include the caller's thread and the `stop()` caller; NODATA/NXDOMAIN surfacing and the three disjoint exception roots documented, and every §4 example now catches them; §4 snippets made single compilable units and the failover recipe extended to transport errors and server-local rcodes; RFC 3263 direct-SRV ranking, `preferredTransports` reorder-only behavior and the async path's `addressResolutionPolicy` gap documented; lock order and stale `dns_transport.hpp` citations corrected; the invented RFC 3263 quote replaced with RFC 3403 §8; new Known Limitations for the resolver's `DnsResolverException`-only catches, the inert retry path, the `resolveA` immediate-error `std::bad_function_call`, the double-invoked throwing callback, malformed-response no-retry, and the `start()` failure path, each with its tracker status. |
| 1.3 | 2026-09-24 | Synced §3.5 + §10 to the landed fix (iora `fb25b51`, tracker `2026-09-24-10`): `validateRdataSecurity` and its RDATA compression-pointer scan were **removed** — the scan was a false-reject/crash source (compression pointers are legal only in NAME fields, which the loop-protected NAME decoder already handles). This resolves the four Known Limitations removed from §10 (valid AAAA `≥ 0xC0`, UTF-8/long TXT, `192.[0-63].0.0` A records, and the zero-length TXT/AAAA null-read process crash). Documented the new `detail::clampReserveCount` memory-amplification guard on the four `parse` `reserve()` sites. The remaining "one malformed RR fails the whole response" behavior is retracked to `2026-09-24-34` (partial-parse robustness). |
| 1.4 | 2026-09-25 | Synced §3.4/§5/§9/§10 + the summary/config tables to the landed retry fix (tracker `2026-09-24-31`): the per-query timeout timer is now the **sole retry driver** (claims a same-server retransmission under `_queriesMutex`, re-sends with exponential backoff + jitter, fails terminally only after the last attempt); the 10 s cleanup sweep is now a strict orphan-only backstop that never retries. Documented the deliberate retransmission model (constant per-attempt timeout + separate inter-attempt backoff) and flipped the `retryCount`/`initialRetryDelay`/… config rows from "inert" to honored. An unparseable matching-id response is now dropped-and-wait (no longer terminates the query). Kept the **no per-query server failover** limitation. New §10 rows for the TC=1 TCP-fallback-timeout cluster (silent-TCP fails ~10 s late via the sweep; resend-window double-act), tracked `2026-09-25-2`. |
| 1.5 | 2026-09-25 | Synced §5/§10 to the landed exactly-once funnel fix (tracker `2026-09-25-6`): the raw `resolveA(host, callback)` delivery path is now a single-invoke funnel — every branch (cancelled/transport-error/no-records/success) builds a result and converges on one `callback(...)` outside any `try`, so a **throwing user callback is no longer invoked twice** (the §10 double-invoke limitation is now **FIXED**); completion is published by a `noexcept` scope-exit guard that fires after the callback on both normal and exceptional unwind (release/acquire edge for `isCompleted()` preserved). The remaining `resolveA` immediate-error `std::bad_function_call` caveat is retracked to `2026-09-24-32`; the `cancel()` "false if already completed" return-value gap and pending-query teardown are retracked to the Part-A tracker `2026-09-25-9`. |
| 1.6 | 2026-09-25 | Synced §1/§3.3/§9/§10 to the landed SRV-ordering fix (iora `fa31d93`, tracker `2026-09-25-4`, the ordering half of the `2026-09-24-29` split): SRV failover ordering is now **owner-name-delimited and RFC 2782 weighted at the list level**. `sortTargetsByPriority` sorts by `(naptrPreference/transport-rank, transport, priority)` — SRV priority is no longer compared across different SRV RRsets — and then weight-randomizes each equal-priority group of one owner name (repeated running-sum selection-without-replacement, inclusive `[0,sum]`, weight-0 records first with a "very small chance"), seeded by one advancing draw of the resolver's `_rng` under `_rngMutex`. The direct-SRV path now stamps each SRV set's transport-preference rank (its `buildOrderedSrvQueries` index) as `naptrPreference`, so per-set sequencing survives. `ServiceResolutionResult::getPreferredTarget` (all overloads) now returns the already-ordered **head** and no longer re-randomizes; the old `[0,total_weight-1]`+`<` single-pick (which gave weight-0 records zero chance) is removed. **Resolved** the cross-record-set direct-SRV ranking Known Limitation; the SIPS/secure hard-filter half (`preferredTransports` does not filter a SIPS resolution) remains open, now tracked `2026-09-25-12` (slice b2). |

---

## 1. Executive Summary

### Problem

Applications in the Iora ecosystem — a SIP proxy locating an upstream registrar, an HTTP client honoring an SRV-published service, a monitoring task doing reverse lookups — need to query the DNS **as data**: read specific record types (`SRV`, `NAPTR`, `MX`, `TXT`, `PTR`, `A`, `AAAA`, `CNAME`), follow the RFC 3263 service-location chain, and make priority/weight decisions. The host does not want any of that from `getaddrinfo`:

- `getaddrinfo` returns only `A`/`AAAA` addresses. It cannot return `SRV`, `NAPTR`, `MX`, or `TXT`, so it cannot drive SIP/HTTP service location at all.
- Hand-rolling a DNS-wire client per application is where the security bugs live: DNS name compression invites decompression loops, `rdlength` fields invite out-of-bounds reads, and TCP length-prefixing invites unbounded-buffer DoS.
- Retrying, exponential backoff with jitter, UDP-to-TCP fallback on truncation, and TTL-aware caching are cross-cutting concerns no single call site should re-implement.

### Solution

`DnsClient` is a complete DNS-protocol client with RFC 3263 service discovery, layered over four cooperating components:

- **`DnsClient`** (`dns_client.hpp`) — the public façade. Synchronous record accessors (`resolveA`/`resolveSRV`/`resolveNAPTR`/…), a callback-async primary path (`resolveA(host, cb)`), and `CancellableFuture`-based wrappers (`resolveAAsync`, `resolveServiceDomainFuture`).
- **`dns::DnsResolver`** — the RFC 3263 engine: NAPTR→SRV→A/AAAA chaining, RFC 2782 SRV priority/weight selection, and the `AddressResolutionPolicy` (IPv4/IPv6 ordering).
- **`dns::DnsTransport`** — UDP-first with TCP fallback on truncation, exponential-backoff-with-jitter same-server retransmission (the per-query timeout timer is the sole retry driver — §3.4), per-query timeouts, round-robin server selection, and a per-session TCP receive-buffer cap for DoS resistance. It rides two `iora::network::Transport` instances (the UDP and TCP engines).
- **`dns::DnsMessage`** — a hardened DNS wire codec (encode query / parse response) with compression-pointer loop detection, label/name size limits, and per-record bounds validation.
- **`dns::DnsCache`** — a TTL-aware positive/negative cache backed by `util::ExpiringCache` (time-based expiration only).

### Technical Impact

- **Full RFC 3263 SIP server location** (the `S`/`A`-flag subset): `NAPTR`→`SRV`→`A`/`AAAA` with owner-name-delimited ordering — transport tier (NAPTR preference, or direct-SRV transport rank), then SRV priority, then RFC 2782 weighted-random ordering **within each owner name** applied to the whole failover list.
- **Security-hardened parsing**: loop-bounded name decompression (a visited-pointer set caps decompression work), enforced 63-byte label / 253-octet name limits, and a per-session TCP buffer cap that closes abusive sessions.
- **Non-blocking application integration**: a best-effort cancellable async API delivered through `std::future` or a raw callback, with atomic double-delivery guards.
- **TTL-correct caching**: cache lifetime is the minimum record TTL across the response (RFC 1035); NXDOMAIN and NODATA negatives are cached at the SOA `minimum` per RFC 2308, and only when an SOA is present (RFC 2308 §5).

### `NameResolver` vs `DnsClient` (boundary)

NameResolver (name_resolver.hpp) vs DnsClient (dns_client.hpp). NameResolver is a single-shot host->socket-address helper that wraps the OS stub resolver (::getaddrinfo) and runs it off the I/O thread on blockingIoPool(), handing back an RAII addrinfo chain (OwnedAddrInfo) ready for an immediate connect(). It answers exactly one question -- 'which socket addresses back this host:port right now, per the system resolver?' -- and is an INTERNAL step of Transport's named-host connect path; applications do not call it directly. ('Async' here means off the caller/I/O thread; the resolution itself is a blocking getaddrinfo on a pool thread, not a non-blocking DNS-protocol implementation.) DnsClient is a standalone client that speaks the DNS wire protocol directly for a fixed set of record types -- A, AAAA, CNAME, MX, TXT, PTR, SRV, NAPTR (dns_client.hpp:178) -- plus RFC 3263 service discovery (NAPTR->SRV->A/AAAA, dns_client.hpp:179,288), exposed as synchronous, callback-async, and cancellable-future (AsyncDnsRequest) APIs, and consumed directly by application code (e.g. http_client.hpp). IMPORTANT -- the two consult DIFFERENT resolution stacks and can return different answers: NameResolver/getaddrinfo honors /etc/hosts, NSS ordering, and resolv.conf search/ndots options; DnsClient reads only the nameserver entries from /etc/resolv.conf and queries them directly (no /etc/hosts, no search-list processing), falling back to public resolvers 8.8.8.8/1.1.1.1 if none are configured -- so in split-horizon / internal-DNS deployments (common for SIP/SBC) the two can disagree, and DnsClient can bypass /etc/hosts overrides or leak to public DNS on a misconfigured host. Rule of thumb: connecting a Transport to a hostname -> NameResolver does it for you (internal, getaddrinfo, system resolution semantics); need DNS records or SIP/HTTP SRV service-location as data -> use DnsClient (direct DNS client). The record-type list alone proves they are different tools: MX/TXT/NAPTR/SRV are impossible via getaddrinfo, so DnsClient is not a NameResolver wrapper.

---

## 2. System Architecture

### Component Relationships

`DnsClient` owns the four backing components by `shared_ptr` and (re)creates them in `initialize()`:

```
DnsClient  (dns_client.hpp:204)
  _config       : dns::DnsConfig                       // value; the live configuration
  _cache        : shared_ptr<dns::DnsCache>            // null when _config.enableCache == false
  _transport    : shared_ptr<dns::DnsTransport>        // owns the wire layer + timers
  _resolver     : shared_ptr<dns::DnsResolver>         // RFC 3263 engine; holds _transport + _cache

  dns::DnsResolver (dns_resolver.hpp:420)
    _transport  : shared_ptr<dns::DnsTransport>        // shared with DnsClient
    _cache      : shared_ptr<dns::DnsCache>            // shared with DnsClient (may be null)
    _config     : dns::DnsConfig
    _rng        : std::mt19937                          // weighted SRV selection (seedable, _rngMutex)

  dns::DnsTransport (dns_transport.hpp:83)
    _udpTransport : shared_ptr<Transport>              // Transport::udp(config) — created for mode UDP/Both
    _tcpTransport : shared_ptr<Transport>              // Transport::tcp(config) — created for mode TCP/Both
    _pendingQueries : map<QueryKey, shared_ptr<PendingQuery>>   // guarded by _queriesMutex
    _timerService : shared_ptr<core::TimerService>     // "DnsRetryTimer" — retries + timeouts
    _cleanupThread : std::thread                       // 10 s sweep of expired queries

  dns::DnsCache (dns_cache.hpp:70)
    ExpiringCache<DnsCacheKey, CachedDnsResult>        // util/expiring_cache.hpp; time-based TTL

  dns::DnsMessage (dns_message.hpp:53)                 // all-static wire codec; owns no state
```

Ownership is strictly downward: `DnsClient` → `DnsResolver` → `DnsTransport` → the `Transport` engine(s) created for the configured `transportMode` (`Both` creates both). Lifetime across async work differs by layer: `DnsTransport` captures a `weak_ptr` to itself and promotes it per callback (breaking the `Transport`↔`DnsTransport` reference cycle), while `DnsResolver` captures a **shared** `self = shared_from_this()` into its async continuations — a deliberate keep-alive so a fire-and-forget resolution completes even after the caller drops its `shared_ptr`.

### Data Flow: a synchronous `resolveSRV` query

```mermaid
sequenceDiagram
    participant App
    participant Client as DnsClient
    participant Resolver as DnsResolver
    participant Transport as DnsTransport
    participant Cache as DnsCache
    participant Engine as Transport (UDP/TCP)
    participant Server as DNS server

    App->>Client: resolveSRV("_sip._tcp.example.com")
    Client->>Resolver: query(DnsQuestion{SRV})
    Resolver->>Cache: get(question)
    alt cache hit
        Cache-->>Resolver: DnsResult (fromCache)
    else cache miss
        Resolver->>Transport: queryMultiple({question})
        Transport->>Transport: generateUniqueQueryId(); build QueryKey(id,server,port)
        Transport->>Engine: sendUdpQuery (DnsMessage::buildQuery)
        Engine->>Server: UDP query
        Server-->>Engine: UDP response (bytes)
        Engine->>Transport: onData (I/O thread)
        Transport->>Transport: DnsMessage::parse -> processResponse
        alt truncated (TC) and mode == Both
            Transport->>Engine: sendTcpQuery (retry over TCP)
            Engine->>Server: TCP query
            Server-->>Engine: TCP response
        end
        Transport->>Resolver: completeQuery -> promise / callback
        Resolver->>Cache: put(question, result)
    end
    Resolver-->>Client: DnsResult
    Client-->>App: vector<SrvRecord> (or throws; see §3.1 Error surfacing)
```

### Threading Model

| Thread | Responsibility |
|---|---|
| **Caller thread** | Runs the synchronous accessors (`resolveA`/`resolveSRV`/`query`/…); blocks on `std::future::wait_for` inside `DnsTransport::queryMultiple` (`dns_transport.hpp:1020`). Immediate submission errors invoke the async callback here, **before `resolveA` returns**: no transport (`dns_client.hpp:1086-1091`), transport not running (`dns_transport.hpp:1050-1054`), registration refused because a `stop()` raced the submit (`:1091-1095`), or a send/connect failure (`:1113-1123`). A cache hit (positive or negative) in `DnsClient::queryAsync` also calls back here. |
| **Thread calling `stop()`** | `DnsTransport::stop()` fails every still-pending query with `DnsTransportException("Transport stopped")` from the stopping thread (`dns_transport.hpp:917`) — the destructor of `DnsClient`, `updateConfig`/`setDnsServers`/…, or an explicit `stop()`. |
| **Transport engine I/O thread** | Owned by the two `Transport` engines. Delivers normal DNS responses: `onData` → `DnsMessage::parse` → `processResponse` → `completeQuery` → user callback. |
| **`DnsRetryTimer` (TimerService) thread** | Fires the per-query timeout callback, which drives retransmissions (claims the retry and schedules the backoff re-send via `retryQuery`) and, on the last attempt, the terminal timeout completion (§3.4). A timeout's user callback runs here. |
| **Cleanup thread** (`_cleanupThread`) | A 10-second orphan-only backstop (`cleanupExpiredQueries`) that FAILS (never retries) queries left orphaned — expired AND with no live timer (e.g. a reschedule rejected during drain); those completion callbacks run here. |

**Consequence for callers:** an async callback (or the promise behind a `CancellableFuture`) may run on the caller's own thread before the submitting call returns, on the thread that calls `stop()`, or on any of three internal threads — the engine I/O thread, the `DnsRetryTimer` thread, or the cleanup thread. Callbacks must be thread-safe, and **must not take a lock the caller holds across `resolveA`/`queryAsync`** — on the caller-thread path that is a self-deadlock (or undefined behavior for a non-recursive `std::mutex`). The header lists the caller/transport/timer cases on `DnsClient::resolveA(host, cb)` (`dns_client.hpp:450-455`).

---

## 3. Component Deep Dive

### 3.1 `DnsClient` (façade)

`DnsClient` is a thin, ownership-holding façade over the resolver. It is **move-only** (`dns_client.hpp:272-277`: copy deleted, move defaulted) because it owns transport threads.

**Construction and lifecycle.** Both constructors (default, and one taking a `dns::DnsConfig`) call `initialize()`, which: creates `_cache` iff `_config.enableCache` — seeding its default TTL from `_config.cacheTimeout` (else resets it); constructs `_transport` from `_config`; constructs `_resolver` from `(_transport, _cache, _config)`; and starts the transport, wrapping any start failure in `dns::DnsResolverException`. `start()` is a no-op that returns `true` (the transport is already started in the constructor); the destructor calls `stop()`, which stops the transport threads.

**Synchronous accessors.** Each typed accessor issues one `query()` and unpacks the typed record vector, throwing `dns::DnsNoRecordsException` when the corresponding vector is empty (which, because `query()` already throws for an empty answer section, happens only when the answer section is non-empty but holds no record of the asked type — for example a CNAME-only answer). See **Error surfacing** below:

- `resolveA` / `resolveAAAA` → `std::vector<std::string>` of address strings.
- `resolveSRV` → `std::vector<dns::SrvRecord>`; `resolveNAPTR` → `std::vector<dns::NaptrRecord>`.
- `resolveMX` / `resolveTXT` → the typed record vectors; `resolveCNAME` → canonical names; `resolvePTR` → hostnames.
- `resolveHost` (`dns_client.hpp:243`) is the exception: it swallows per-family failures and returns a `HostResult{ipv4, ipv6, success}` where `success` is "at least one family resolved".

**Reverse DNS.** `resolvePTR` builds the query name via `createReverseQuery` (`dns_client.hpp:975`): IPv4 → dotted-octet-reversed `in-addr.arpa`; IPv6 → `createIpv6ReverseQuery` (`:877`) which strips brackets/zone, expands `::` to the full 32-nibble form via `expandIpv6Address` (`:913`), then emits the nibble-reversed `ip6.arpa` name. A malformed address throws `dns::DnsResolverException`.

**Service discovery** delegates straight to the resolver: `resolveServiceDomain` / `resolveServiceDomainAsync` / `resolveCustomServiceDomain[Async]`. The SIP-named `resolveSipDomain[Async]` are thin, `\deprecated` forwarders to the service-domain methods (`dns_client.hpp:695`, `:708`).

**Cancellable async.** The façade adds the future-based ergonomics the resolver lacks:

- `resolveA(host, callback)` → `AsyncDnsRequest` (the primary async path; the sole out-of-line definition, `dns_client.hpp:1097`).
- `resolveAAsync(host)` → `CancellableFuture<std::vector<std::string>>`.
- `resolveServiceDomainFuture(domain, …)` → `CancellableFuture<dns::ServiceResolutionResult>`.

These wrap the resolver's callback API in a `std::promise`, guarding against double-set with a shared `std::atomic<bool>` (`promiseSet`) compare-exchange. `resolveAInternal` (`dns_client.hpp:1008`) adds a second guard, `RequestState::deliveryAttempted`, so exactly one thread enters delivery even if response and timeout race. Within that single delivery, the raw `resolveA(host, callback)` path is now a strict exactly-once **funnel**: every branch (cancelled / transport-error / no-records / success) builds its result and converges on **one** `callback(...)` invocation outside any `try`, so a user callback that **throws** is **no longer** re-invoked — the throw propagates once into the transport's own `catch(...)` (swallowed, not `std::terminate`), and completion is still published via a `noexcept` scope-exit guard that fires on the exceptional unwind. One caveat remains: the immediate-error branch of `resolveA` can throw `std::bad_function_call` without invoking the callback at all (§10, Open — P1, tracked `coding_trackers:tasks/iora/backlog/2026-09-24-32_dnsclient-resolvea-callback-moved-then-invoked_P1.json`).

**Error surfacing.** `DnsResult::isSuccess()` is `rcode == NOERROR && ancount > 0` (`dns_types.hpp:381`), and `DnsResolver::query` throws `DnsResolutionFailedException(qname, rcode)` whenever it is false (`dns_resolver.hpp:613-616`; the same for a negative-cache hit, `:599-602`). So:

| Server answer | Synchronous accessor throws | `getResponseCode()` |
|---|---|---|
| NXDOMAIN | `DnsResolutionFailedException` | `NXDOMAIN` |
| NODATA (NOERROR, empty answer section) | `DnsResolutionFailedException` | `NOERROR` |
| SERVFAIL / REFUSED / NOTIMP / FORMERR / … | `DnsResolutionFailedException` | that rcode |
| NOERROR, answers present but none of the asked type | `DnsNoRecordsException` | `NXDOMAIN` (hard-coded, `dns_resolver.hpp:376-381`) |
| No reply within `timeout`, send/connect failure, transport stopped | `DnsTransportException` / `DnsTimeoutException` | — (not a `DnsResolverException`) |
| Response rejected by the parser | `DnsParseException` | — (not a `DnsResolverException`) |

The raw callback path (`resolveA(host, cb)`, which calls `DnsTransport::queryAsync` directly and bypasses the resolver and cache) differs: any response without A records — NXDOMAIN, NODATA, SERVFAIL — arrives as `DnsNoRecordsException` with `getResponseCode() == NXDOMAIN`, so the real rcode is lost.

### 3.2 `AsyncDnsRequest` and `CancellableFuture<T>`

`AsyncDnsRequest` (`dns_client.hpp:35`) is a cancellation handle over a shared `RequestState` — three `std::atomic<bool>` flags (`cancelled`, `completed`, `deliveryAttempted`) plus the queried `hostname`. `cancel()` does `cancelled.exchange(true, acq_rel)` and returns whether *this* call flipped it — it does not look at `completed`, so the header's "false if already completed" (`dns_client.hpp:46`) is wrong (Open — P1, tracked `coding_trackers:tasks/iora/backlog/2026-09-25-9_dns-async-cancel-teardown-transport-api_P1.json`). Cancellation does **not** suppress the raw callback: nothing removes the pending query, so the callback is **always invoked exactly once** (barring the `std::bad_function_call` path in §10) — with the real result if delivery claimed `deliveryAttempted` before `cancel()`, otherwise with `DnsResolverException("DNS request cancelled")` when the response, timeout, or `stop()` eventually arrives (`dns_client.hpp:1021`,`:1051`). (Proactive teardown of the pending query on `cancel()` — so a cancelled query stops retransmitting — is a separate open item, tracked `coding_trackers:tasks/iora/backlog/2026-09-25-9_dns-async-cancel-teardown-transport-api_P1.json`.) Anything the callback captures must therefore outlive the request (capture a `shared_ptr`/`weak_ptr`, never a stack reference). The header calls this "best-effort" (`:41-43`).

`CancellableFuture<T>` (`dns_client.hpp:104`) pairs a `std::future<T>` with the request handle and the shared promise + `promiseSet` guard. Its `cancel()` (`:118`) cancels the request and, if it wins the `promiseSet` CAS, immediately sets the promise to a `dns::DnsResolverException("DNS request cancelled")` so a thread blocked in `future.get()` wakes without waiting for the network timeout. `cancel()` returning `true` does **not** imply `get()` throws: a delivery that won the `promiseSet` CAS first has already set the value (or the real error), and `get()` returns it.

### 3.3 `dns::DnsResolver` (RFC 3263 engine)

The resolver turns questions into results and orchestrates the service-location chain. It reads exactly one config field itself — `addressResolutionPolicy` — and defers all retry/timeout/server behavior to the transport.

**`query` / `queryAsync`** are the record-level primitives: consult `_cache` (if present), else `_transport->queryMultiple` / `queryAsync`, then apply the cache-write policy via `cacheQueryResult`. That policy caches positive results, and negative results (NXDOMAIN and NODATA — NOERROR with no answers) **only when the response carries an SOA** (RFC 2308 §5: a negative without an SOA has no authoritative TTL to bound it, so it is not cached and is re-queried). `resolveHostname` implements `AddressResolutionPolicy`:

- Query `A` when policy ∈ {IPv4Only, IPv4First, IPv6First}; query `AAAA` when ∈ {IPv6Only, IPv4First, IPv6First}.
- Combine: IPv4Only → A only; IPv6Only → AAAA only; IPv4First → A then AAAA; IPv6First → AAAA then A.
- The legacy `prefer_ipv6 == true` bumps `IPv4First` to `IPv6First` for backward compatibility. Empty result throws `dns::DnsNoRecordsException`.
- Each per-family `query()` is wrapped in `catch (const DnsResolverException &)` only (`dns_resolver.hpp:710`, `:729`, and the outer `:772`). A `DnsTimeoutException`/`DnsTransportException` or `DnsParseException` from either family escapes and **discards the other family's results** — under the default `IPv4First`, an AAAA timeout (or the AAAA parser false positive, §10) throws away already-resolved A addresses. Open — P0, tracked `coding_trackers:tasks/iora/backlog/2026-09-24-29_dns-resolver-catches-only-resolver-exception-and-rfc3263-gaps_P0.json`.

**Service resolution — `resolveServiceDomain`** (`dns_resolver.hpp:457`) drives `performServiceResolution` (`:1166`):

1. **NAPTR query** the domain. If it fails with a `DnsResolverException` (NXDOMAIN, NODATA, an rcode error), fall back to `performDirectSrvResolution(domain, …, nullopt)` and return (`dns_resolver.hpp:1179`). A timeout, transport error, or parse error is **not** caught there: it aborts the whole resolution instead of falling back (§10). If NAPTR succeeds but yields no usable target, the same direct-SRV fallback runs (sync and async behave identically here).
2. `processNaptrRecords` sorts by `order` then `preference` and processes NAPTR records in **ascending `ORDER`**, advancing to the next `ORDER` tier only when the current one yields no usable target and stopping at the first tier that does (RFC 3403 §4.1/§8 DDDS ordering). Within the chosen tier it maps each service string via `parseServiceType`, applies the `preferredTransports` filter, validates the replacement, and splits into `S`-flag SRV targets and `A`-flag direct targets. **`U`-flag (ENUM/regexp, RFC 6116) and empty-flag (chained NAPTR) records are intentionally skipped.**
3. For each `S` target, **SRV query** the replacement and append `ServiceTarget`s carrying the NAPTR preference; SRV queries that fail with a `DnsResolverException` are skipped (`:1206`), but a single SRV timeout/transport/parse failure aborts the whole resolution (§10).
4. For each `A` target, synthesize a `ServiceTarget` directly (no SRV): `port = getDefaultServicePort(service)`, `priority = weight = 0`, `naptrPreference =` the record's NAPTR preference field.
5. `resolveTargetAddresses` resolves every target through `resolveHostname` (so `addressResolutionPolicy` applies) and drops those with no addresses; a target whose lookup throws anything other than `DnsResolverException` aborts the whole resolution (`:1738`). **The async path differs:** `resolveTargetAddressesAsync` (`:1873`) queries A and then AAAA **only if A returned nothing** (`:1912`), ignoring `addressResolutionPolicy` (an `IPv6Only`/`IPv6First` caller still gets IPv4 first, and a dual-stack target gets no IPv6 addresses). The async chain also calls `DnsTransport::queryAsync` directly, so it neither consults nor populates the cache. Open — P0, tracked `coding_trackers:tasks/iora/backlog/2026-09-24-29_dns-resolver-catches-only-resolver-exception-and-rfc3263-gaps_P0.json` (the policy gap).
6. `sortTargetsByPriority` orders the failover list **per SRV owner name**: it stable-sorts by `(naptrPreference, transport, priority)` — so SRV `priority` is never compared across different transports (here `transport`, the `ServiceType`, is a 1:1 proxy for the SRV owner name in the standard SIP mapping, so this is per-RRset per RFC 2782; two NAPTR records sharing preference *and* service but pointing at different SRV owner names — an unusual/misconfigured zone — would group across RRsets, tracked `2026-09-25-14`) — then applies RFC 2782 weighted-random ordering to each equal-`(naptrPreference, transport, priority)` group (repeated running-sum selection-without-replacement, remaining sum recomputed each step, uniform `[0,sum]` inclusive with first cumulative `>=`, weight-0 records placed first and shuffled among themselves for the "very small chance"; all-weights-0 → uniform). The per-call generator is seeded by **one advancing draw** of the resolver's `_rng` under `_rngMutex` (leaf lock), then the ordering runs unlocked (the draw is skipped when fewer than two targets exist).

**`performDirectSrvResolution`** is the no-NAPTR (and no-usable-NAPTR) path: it tries the standard SIP SRV names (`_sips._tcp`, `_sip._tcp`, `_sip._udp`, `_sip._sctp`), reordered by `preferredTransports` (`buildOrderedSrvQueries`, `dns_resolver.hpp:1446-1492`). `preferredTransports` **only reorders the queries, it does not filter**: every one of the four SRV names is still queried and every answer is kept. Each SRV set's position in the `buildOrderedSrvQueries` order is stamped as its targets' `naptrPreference` (the per-set transport rank), so `sortTargetsByPriority` sequences transports **per set** and applies SRV priority (and weight) only **within one owner name** — it no longer compares a `_sip._udp` priority against a `_sips._tcp` priority across RRsets (fixed by tracker `2026-09-25-4`). What remains: because `preferredTransports` does not *filter*, a SIPS resolution (RFC 3263 §4.1: a SIPS URI must use TLS) still yields non-TLS targets, so a SIPS caller must filter the result itself with `getTargetsForTransport(dns::ServiceType::SIPS_TLS)`. Open — P0, tracked `coding_trackers:tasks/iora/backlog/2026-09-25-12_dns-sips-secure-hard-filter-across-paths_P0.json` (slice b2). SRV queries that fail — with `DnsResolverException`, `DnsTransportException`, or `DnsParseException` — are each skipped so one failing SRV set never aborts the others (`dns_resolver.hpp:680-694`, RFC 3263 §4.3 per-record isolation; the async path is likewise non-aborting). The bare-domain A/AAAA fallback, by contrast, still catches only `DnsResolverException` (§10). An SRV RRset whose target is the root `.` (RFC 2782 "service decidedly not available") is skipped and marks that **service** denied. If no targets result, it calls `performFallbackResolution`, which does a plain A/AAAA lookup of the bare domain and builds one target per preferred transport (defaulting to `SIP_UDP`) — **excluding any service a `.` explicitly denied** (per-service suppression, not domain-wide: a `_sips._tcp` `.` does not strand plain SIP reachable via a bare A record).

**RFC 2782 weighted selection.** The weighted-random ordering is applied to the **whole failover list at construction**, inside `sortTargetsByPriority` (above), not deferred to a single-target pick. Consequently `ServiceResolutionResult::getPreferredTarget` — all three overloads (the const overload, `getPreferredTargetWithDefaultRng`, and the caller-RNG template) and the resolver-level `getPreferredTarget(result)` — now simply return the already-ordered **head** (`targets.front()`); they no longer re-randomize (that would double-order the list) and the RNG argument on the template overload is unused. The RNG lives at the list-ordering site: `sortTargetsByPriority` takes one advancing draw of the resolver's seedable `_rng` (`setRngSeed`) under `_rngMutex` (a leaf lock) and orders on a per-call local generator. The previous single-pick cumulative walk over `uniform_int_distribution<uint32_t>(0, total_weight-1)` with a strict `<` — which gave weight-0 records **zero** selection chance — has been removed; the list-level algorithm uses the RFC-correct inclusive `[0,sum]` draw with first cumulative `>=`. A hand-built `ServiceResolutionResult` not produced by the resolver is returned head-first as-is (an unweighted pick), since ordering happens at resolver construction time.

**Async service resolution** (`performServiceResolutionAsync`) mirrors the sync chain but fans SRV queries out in parallel, coordinating completion with a shared `std::atomic<size_t> remainingQueries` (`fetch_sub(acq_rel)`), an `std::atomic<bool> callbackFired`, a `std::mutex resultMutex`, and a shared `deniedServices` vector; the last query to finish triggers async address resolution and fires the callback exactly once.

### 3.4 `dns::DnsTransport` (wire transport)

`DnsTransport` must be owned by a `shared_ptr` — `start()` calls `shared_from_this()`, so a stack instance throws `std::bad_weak_ptr` (`dns_transport.hpp:90-94`). It instantiates the engine(s) the configured `transportMode` needs — `Transport::udp(config)` for `UDP`/`Both`, `Transport::tcp(config)` for `TCP`/`Both` — and wires their `onData`/`onConnect`/`onClose` callbacks, each captured as a `weak_ptr<DnsTransport>` promoted per-use to avoid a reference cycle.

**Query lifecycle.** `queryMultiple` (sync, `:949`) and `queryAsync` (`:1047`) mint a unique 16-bit query ID (`generateUniqueQueryId`, `:2056`), build a `QueryKey{id, server, port}` (`:177`), register a `PendingQuery` under `_queriesMutex`, encode the request with `DnsMessage::buildQuery`, and send over UDP (or TCP per `transportMode`). The sync path then blocks on `future.wait_for(calculateMaxSyncWaitTime())` (`:1020`). `start()` is at `:676`.

**Query-to-response matching** is by `QueryKey` — the `(queryId, server, port)` triple. Because the UDP and TCP engines mint colliding `SessionId`s, the response path maps a session back to its server via `_sessionToServer`, keyed by `(bool isTcp, SessionId)` (`:578`), preventing cross-engine confusion.

**UDP→TCP fallback** is truncation-driven, not size-driven: in `processResponse` (`:1673`) a UDP response with the `TC` flag set, when `transportMode == Both` and the query has not already fallen back, sets `tcpFallback = true` and re-sends over TCP. (`_config.maxUdpSize` is **not** consulted — see Known Limitations.)

**Retry / backoff / jitter.** The **per-query timeout timer is the sole retry driver** (tracker 2026-09-24-31). When the timeout of the current attempt fires, the timeout callback (`scheduleQueryTimeout`) CLAIMS a retransmission under `_queriesMutex` as one critical section — attempt-limit check, `retryCount` increment, `startTime` reset — then `retryQuery` re-sends to the **same** server with the **same query id** after an exponential-backoff idle delay `baseDelay = min(initialRetryDelay * retryMultiplier^n, maxRetryDelay)` (from the pre-increment attempt index `n`, so the first retry uses `initialRetryDelay`), with multiplicative jitter `× U(1 - jitterFactor, 1 + jitterFactor)` re-clamped to `maxRetryDelay` when `jitterFactor > 0`. Only after the last permitted attempt's timeout does the query complete with `dns::DnsTimeoutException`. So a query is sent up to `retryCount + 1` times (measured: `timeout = 250 ms`, `retryCount = 2`, silent server → **3 datagrams** to the same server with growing gaps, then one terminal `DnsTimeoutException`). See §10.

**Retransmission model (deliberate).** This is a **constant per-attempt timeout plus a separate inter-attempt backoff idle gap**: send → wait `timeout` → (on expiry) wait `baseDelay` → resend. `PendingQuery::timeout` is const, so every attempt waits the same `timeout`; the backoff grows the *gap between* attempts, not the per-attempt deadline. This is latency-inflating versus classic RFC 1035 §4.2.1 RTO-doubling (where the per-attempt timeout itself grows), and is a conscious choice: it keeps late-answer correlation simple (the reused query id means a slow answer to attempt *n* still matches) and bounds total wait via `calculateMaxSyncWaitTime()`.

**Timeouts.** Each attempt arms a `TimerService` timeout of `_config.timeout` via `scheduleQueryTimeout`. On expiry the timeout callback either CLAIMS a retransmission (above) or, once the attempt budget is exhausted, fails the query with `DnsTimeoutException` via an atomic `takePending` (exactly-once). The 10-second cleanup sweep (`cleanupExpiredQueries`) is a strict **orphan backstop**: it never retries and fails ONLY a query that is both expired-by-`startTime` **and** has no live timer (`activeTimerId == 0`) — e.g. one whose reschedule was rejected during `stop()`/drain. Because the retry claim resets `startTime`, a healthy mid-backoff query is never expired-by-`startTime`, so the sweep skips it and cannot double-drive or prematurely fail it.

**DoS resistance.** TCP DNS is 2-byte length-prefixed. In `handleTcpData` (`:1539`, under `_tcpBuffersMutex`) the per-session accumulation buffer is capped at `_config.maxTcpBufferSize` (default 65536): exceeding it, or a length prefix that is zero / `> 65535` / `> maxTcpBufferSize`, clears the buffer and **closes the session**. `Transport::close` is enqueue-only, so calling it from inside the I/O-thread `onData` callback is safe.

**Server selection.** `getNextServer` (`:1939`) is round-robin over `_config.servers` via an atomic cursor, chosen per query when the `DnsTransport` caller passes an empty `server` — which `DnsClient`/`DnsResolver` always do (the façade has no per-call server parameter). There is **no per-query failover**: every retransmission re-sends to the **same** server the query started on (required for late-answer correlation, since the query id is reused); only a *new* query advances the cursor. Cross-server per-query failover remains a documented limitation (§10).

### 3.5 `dns::DnsMessage` (wire codec)

`DnsMessage` (`dns_message.hpp:53`) is an all-static, stateless codec.

**Encode.** `buildQuery` (the `recursionDesired` overload at `:339`, reached via the `:326`/`:332` forwarders) writes the 12-byte header (`RD` flag from `recursionDesired`; `opcode`/`rcode` implicitly 0), then the encoded question. `encodeName` (`:288`) enforces the 63-byte label limit and a 253-octet total-name limit — the RFC 1035 §3.1 presentation-format bound, marginally conservative against the 255-octet wire ceiling — throwing `DnsParseException` on violation. `generateQueryId` (`:233`) draws from a `thread_local` `mt19937` in the range 1–65535.

**Decode.** `parse` (`:377`) validates a minimum 12-byte header, decodes flags/counts (`parseHeader`, `:445`), then walks each section calling `parseResourceRecord` and `parseTypedRecord` (`:775`), which dispatches by `DnsType` into the typed vectors (`a_records`, `srv_records`, `naptr_records`, …). A failure inside `parseTypedRecord` (for example an SRV with a short `rdlength`) is logged and that typed record is skipped; the raw record stays in its section vector. A throw from `parseResourceRecord` itself — a bounds violation, or an owner-name compression loop or out-of-range pointer — is **not** caught: it escapes `parse` and the whole response fails, so a single malformed resource record discards an otherwise-usable response (tracked `coding_trackers:tasks/iora/backlog/2026-09-24-34_dns-parse-partial-record-skip-robustness_P1.json`). When `parse` throws, `DnsTransport::processResponse` now **DROPS the datagram and keeps waiting** (drop-and-wait, RFC 1035 §7.3 / RFC 5452 §9.1 Query Matching Rules, tracker 2026-09-24-31, the `catch(std::exception)` `if (!parsed)` branch, `dns_transport.hpp:1799-1818`): a parse-stage failure — whether a malformed question or a malformed resource record — no longer completes the pending query, so a single malformed or spoofed matching-id datagram can no longer kill the query; the per-query timeout/retry machinery stays the sole thing that advances it, and retransmission continues to timeout. The **residual** gap (tracked -34) is only that a partially-malformed response cannot be salvaged: the whole datagram is discarded rather than skipping just the bad RR. (A post-parse processing error on a validly-parsed response is distinct: it still surfaces to the waiter via `completeQuery`.)

**Security.** Every read goes through `checkBounds` (`:279`). Name **decompression is loop-protected**: `decodeNameWithLoopDetection` (`:577`) tracks visited pointer offsets in an `unordered_set<uint16_t>` and throws on a repeated pointer or an out-of-range pointer (`0xC0` mask, `0x3FFF` offset). A compression pointer is followed **only** while decoding a name — in NAME fields, and in name-bearing RDATA (CNAME/NS/PTR/MX/SRV/NAPTR/SOA, via `decodeNameFromRdata` (`:656`)) — both of which route through that same loop-protected decoder; A/AAAA/TXT RDATA is never name-decoded. Each per-type parser validates its minimum `rdlength` (A == 4, AAAA == 16, SRV ≥ 6, NAPTR ≥ 4, MX ≥ 2, SOA ≥ 20) inside the `parseTypedRecord` catch (`:775`), so a single malformed typed record is logged and skipped, never fatal to the whole message.

`parse` does **not** scan RDATA bytes for compression pointers. A/AAAA/TXT RDATA is never compressed — compression pointers are legal only in NAME fields (RFC 1035 §4.1.4) — so a byte with the `0xC0` bits set inside an address or a text string is ordinary data. (An earlier `validateRdataSecurity` heuristic that scanned A/AAAA/TXT RDATA was **removed in v1.3**: it false-rejected valid AAAA addresses, UTF-8 or long TXT strings and 64 legitimate A addresses, and on a zero-length RDATA read past an empty vector and crashed the process — see Revision history.)

Each section's pre-allocation is clamped against the untrusted header count: `parse` reserves `min(count, bytesRemaining / minRecordSize)` slots (`detail::clampReserveCount`; minimum 11 bytes per resource record, 5 per question), so a datagram claiming 65535 records in a few bytes cannot force a large transient allocation.

### 3.6 `dns::DnsCache`

`DnsCache` (`dns_cache.hpp`) wraps a `util::ExpiringCache<DnsCacheKey, CachedDnsResult>` (time-based expiration only — there is no entry-count cap). Its default TTL (for records that carry none) is seeded from `_config.cacheTimeout` and adjustable at runtime via `setCacheTtl`. The cache key (`DnsCacheKey`, `dns_types.hpp`) lowercases the query name for RFC 1035 case-insensitive matching.

**TTL derivation.** Positive entries use `calculateResultTtl` — the **minimum TTL** across every record in all sections (RFC 1035 conservative minimum), falling back to the default TTL only when no record carries one. Negative entries use `calculateNegativeTtl` — the SOA `min(minimum, ttl)` per RFC 2308, then the authority-section SOA TTL, then the default.

**Thread safety.** A `std::shared_mutex _cacheMutex` guards the backing `ExpiringCache` pointer: `get`/`put`/`putNegative`/`remove` take it shared, `clear()` takes it exclusively (it destroys and replaces the instance). A separate `std::mutex _statsMutex` (inner; ordering `_cacheMutex → _statsMutex`) serializes the read-decide-count sequence in `put`/`putNegative` so concurrent same-key writes cannot double-count. Statistics are nine `std::atomic<uint64_t>` counters (`AtomicStats`); `_defaultTtlSeconds` is an `atomic<int64_t>`. `cleanupExpired()` is a no-op returning 0 (ExpiringCache sweeps on its own), and `setCleanupCallback` stores a callback that is never invoked (compatibility no-op).

---

## 4. Usage Guide

All examples assume `#include "iora/network/dns_client.hpp"` and `using namespace iora::network;`.

### Basic record queries (synchronous)

The synchronous calls can throw from three unrelated exception roots (§8): `DnsResolverException` (and its subclasses), `DnsTransportException` (including `DnsTimeoutException`), and `DnsParseException`. Catch all three, or `std::exception` last — catching only `DnsResolverException`, as the header `\throws` comments suggest, lets timeouts and parse failures escape.

```cpp
void basicQueries()
{
  try
  {
    DnsClient client; // default config: system resolv.conf servers, cache on

    std::vector<std::string> ipv4 = client.resolveA("www.example.com");
    for (const auto &addr : ipv4)
    {
      std::cout << "A: " << addr << "\n";
    }

    std::vector<dns::MxRecord> mx = client.resolveMX("example.com");
    for (const auto &rec : mx)
    {
      std::cout << rec.preference << " " << rec.exchange << "\n";
    }
  }
  catch (const dns::DnsNoRecordsException &e)
  {
    std::cerr << "answer had no records of that type: " << e.what() << "\n";
  }
  catch (const dns::DnsResolutionFailedException &e)
  {
    // NXDOMAIN, NODATA (getResponseCode() == NOERROR), SERVFAIL, REFUSED, ...
    std::cerr << "resolution failed (rcode " << static_cast<int>(e.getResponseCode())
              << "): " << e.what() << "\n";
  }
  catch (const dns::DnsResolverException &e)
  {
    std::cerr << "resolver error: " << e.what() << "\n";
  }
  catch (const dns::DnsTransportException &e)
  {
    // DnsTimeoutException, send/connect failure, "Transport stopped"
    std::cerr << "transport error: " << e.what() << "\n";
  }
  catch (const dns::DnsParseException &e)
  {
    std::cerr << "malformed or rejected response: " << e.what() << "\n";
  }
  catch (const std::exception &e)
  {
    std::cerr << "other error: " << e.what() << "\n";
  }
}
```

### RFC 3263 SIP service location

```cpp
void locateSipServer()
{
  try
  {
    DnsClient client;

    // NAPTR -> SRV -> A/AAAA, ordered by NAPTR preference then SRV priority.
    dns::ServiceResolutionResult result =
      client.resolveServiceDomain("example.com",
                                  {dns::ServiceType::SIP_TCP, dns::ServiceType::SIP_UDP});

    for (const auto &target : result.targets)
    {
      std::cout << target.hostname << ":" << target.port
                << " transport=" << target.getTransportString()
                << " prio=" << target.priority << " weight=" << target.weight << "\n";
    }

    // Pick one target using RFC 2782 weighted selection:
    if (result.isSuccess())
    {
      dns::ServiceTarget chosen = result.getPreferredTargetWithDefaultRng();
      std::cout << "chosen: " << chosen.hostname << ":" << chosen.port << "\n";
    }
  }
  catch (const std::exception &e)
  {
    // DnsResolverException, and also DnsTransportException / DnsParseException:
    // a timeout or parse failure at any step aborts the whole chain (see §10).
    std::cerr << "service location failed: " << e.what() << "\n";
  }
}

void locateSipsServer(DnsClient &client)
{
  // preferredTransports only reorders; filter explicitly for a SIPS (TLS-only) target set.
  dns::ServiceResolutionResult result =
    client.resolveServiceDomain("example.com", {dns::ServiceType::SIPS_TLS});
  std::vector<dns::ServiceTarget> tls = result.getTargetsForTransport(dns::ServiceType::SIPS_TLS);
  std::cout << tls.size() << " TLS targets\n";
}
```

### Explicit SRV lookup

```cpp
void listSrv(DnsClient &client)
{
  std::vector<dns::SrvRecord> srv = client.resolveSRV("_sip._tcp.example.com");
  for (const auto &rec : srv)
  {
    std::cout << rec.priority << " " << rec.weight << " "
              << rec.target << ":" << rec.port << "\n";
  }
}
```

### Cancellable async resolution (future)

```cpp
void resolveWithDeadline(DnsClient &client)
{
  CancellableFuture<std::vector<std::string>> f = client.resolveAAsync("slow.example.com");

  if (f.future.wait_for(std::chrono::seconds{1}) != std::future_status::ready)
  {
    // If cancel() wins the promiseSet CAS, get() throws DnsResolverException("DNS request
    // cancelled") at once. If a delivery won first, get() returns that result or error.
    f.cancel();
  }

  try
  {
    std::vector<std::string> addrs = f.future.get();
    std::cout << addrs.size() << " addresses\n";
  }
  catch (const std::exception &e)
  {
    // DnsResolverException (cancelled, no records), DnsTransportException (timeout,
    // send failure, stopped), DnsParseException (rejected response).
    std::cerr << "cancelled or failed: " << e.what() << "\n";
  }
}
```

### Callback async (primary path)

```cpp
struct LookupState
{
  std::mutex mutex;
  std::vector<std::string> addrs;
  std::exception_ptr error;
  bool done = false;
};

std::shared_ptr<LookupState> startLookup(DnsClient &client)
{
  // The callback always runs exactly once — even after cancel() — so everything it
  // touches must outlive it: capture a shared_ptr (or a weak_ptr), never a stack reference.
  auto state = std::make_shared<LookupState>();

  AsyncDnsRequest req = client.resolveA(
    "www.example.com",
    [state](std::vector<std::string> addrs, std::exception_ptr err)
    {
      // Runs on the caller's thread before resolveA returns (immediate errors), an engine
      // I/O thread, the DnsRetryTimer thread, the cleanup thread, or the stop() caller.
      std::lock_guard<std::mutex> lock(state->mutex);
      state->addrs = std::move(addrs);
      state->error = err;
      state->done = true;
    });

  // Does NOT suppress the callback: it still fires once, with
  // DnsResolverException("DNS request cancelled") if this cancel() won.
  req.cancel();
  return state;
}
```

Never hold a lock across `resolveA(host, cb)` that the callback also takes: an immediate error runs the callback on your thread before `resolveA` returns.

### Configuring servers and cache

```cpp
void configuredClient()
{
  dns::DnsConfig cfg;
  cfg.setServers({"8.8.8.8", "1.1.1.1:53", "[2001:4860:4860::8888]:53"});
  cfg.timeout = std::chrono::milliseconds{2000};
  cfg.enableCache = true;

  DnsClient client(cfg);
  client.setCacheTtl(std::chrono::seconds{600});
  dns::DnsCacheStats stats = client.getCacheStats();
  std::cout << "hit ratio: " << stats.getHitRatio() << "\n";
}
```

### Failing over to a second server set

There is no per-query failover (§10): a query is sent only to the server it started on. For hard failover, catch the failures that mean "this server did not give a usable answer" and re-issue the query on a second `DnsClient` configured with different servers:

```cpp
std::vector<std::string> resolveWithFailover(DnsClient &primary, DnsClient &secondary,
                                             const std::string &host)
{
  try
  {
    return primary.resolveA(host);
  }
  catch (const dns::DnsTransportException &)
  {
    // DnsTimeoutException, send/connect failure: the primary server was not reached.
    return secondary.resolveA(host);
  }
  catch (const dns::DnsResolutionFailedException &e)
  {
    const dns::DnsResponseCode rc = e.getResponseCode();
    if (rc == dns::DnsResponseCode::NXDOMAIN || rc == dns::DnsResponseCode::NOERROR)
    {
      throw; // authoritative: the name does not exist (NXDOMAIN) or has no A records (NODATA)
    }
    return secondary.resolveA(host); // SERVFAIL / REFUSED / NOTIMP / FORMERR are server-local
  }
}

dns::DnsConfig makeConfig(const std::string &server)
{
  dns::DnsConfig cfg;
  cfg.setServers({server});
  cfg.timeout = std::chrono::milliseconds{1500}; // bounds how long the primary can stall
  return cfg;
}

struct FailoverResolver
{
  DnsClient primary{makeConfig("10.0.0.53")};
  DnsClient secondary{makeConfig("10.0.1.53")};

  std::vector<std::string> resolve(const std::string &host)
  {
    return resolveWithFailover(primary, secondary, host);
  }
};
```

What to fail over on:

- **`DnsTransportException`** (which includes `DnsTimeoutException`): no reply within `timeout`, or a send/connect failure (`dns_transport.hpp:1232`, `:1271`).
- **`DnsResolutionFailedException` whose `getResponseCode()` is not `NXDOMAIN` or `NOERROR`**: SERVFAIL, REFUSED, NOTIMP and FORMERR describe the server that answered, not the name, so another server may succeed.
- **Not** `NXDOMAIN`, NODATA (`DnsResolutionFailedException` with `NOERROR`) or `DnsNoRecordsException`: these are authoritative answers about the name, and a second server should give the same one.
- `DnsParseException` is not caught above: with the current parser false positives (§10) the secondary rejects the same data.

Cost: failover begins only after the primary has used its whole attempt window — every attempt (`retryCount + 1` sends) plus the inter-attempt backoff delays, bounded by `calculateMaxSyncWaitTime()`. Lower `timeout` (and `retryCount`) on the primary to bound the stall. Two clients also mean two sets of transport threads (engine I/O, timer, cleanup) and two independent caches. `DnsClient` is move-only (copy is deleted, move construction and move assignment are defaulted), so the pair can be held by value in an owning object, as `FailoverResolver` does.

### Anti-Patterns

- **Do NOT assume the async callback runs on an internal thread — or on yours.** It may run on your thread before the call returns (immediate errors), on the thread that calls `stop()`, or on the engine I/O, `DnsRetryTimer`, or cleanup thread. Synchronize everything it touches, and never hold a lock across `resolveA` that the callback takes.
- **Do NOT use `DnsClient` for a plain "connect me to this host".** That is `Transport`'s job via `NameResolver`/`getaddrinfo`, which honors `/etc/hosts`, NSS, and the resolv.conf search list. `DnsClient` queries nameservers directly and can disagree (see the §1 boundary).
- **Do NOT expect `cancel()` to suppress the raw callback.** `AsyncDnsRequest::cancel()` never stops delivery: the callback still runs exactly once, possibly with `DnsResolverException("DNS request cancelled")`, possibly much later (when the response, timeout, or `stop()` arrives). Do not capture stack references or `this` of an object that may be destroyed after cancelling — capture a `shared_ptr`/`weak_ptr`.
- **Do NOT assume `CancellableFuture::cancel() == true` means `get()` throws.** A delivery that already won the `promiseSet` CAS has set the real value or error.
- **Do NOT catch only `DnsResolverException`.** Timeouts and transport failures (`DnsTransportException`, a `std::runtime_error`) and parse failures (`DnsParseException`) are separate roots.
- **Do NOT construct a `dns::DnsTransport` on the stack.** It requires `shared_ptr` ownership (`shared_from_this` in `start()`); a stack/`unique_ptr` instance throws `std::bad_weak_ptr`. Use `DnsClient`, which owns it correctly.
- **Do NOT rely on `maxCacheSize`, `maxUdpSize`, or `tcpTimeout`.** They are declared on `DnsConfig` for compatibility but are not enforced (see Configuration Reference and Known Limitations). (The retry fields — `retryCount`, `initialRetryDelay`, `retryMultiplier`, `maxRetryDelay`, `jitterFactor` — ARE honored: the per-query timeout timer drives same-server retransmission per §3.4.)
- **Do NOT expect a single failing query to try the next server.** Server selection is round-robin per query and a query is sent only to that server. Rotate by issuing independent queries, or fail over explicitly with a second client (§4 "Failing over to a second server set"); `DnsClient` has no per-call server parameter.

---

## 5. Call Flow / Sequence Reference

### Synchronous `resolveA` — success path

| Step | Component | Action |
|---|---|---|
| 1 | `DnsClient::resolveA` | Build `DnsQuestion{host, A, IN}`; call `query()`. |
| 2 | `DnsResolver::query` | Look up `_cache->get()`. On hit, return cached `DnsResult`. |
| 3 | `DnsTransport::queryMultiple` | `generateUniqueQueryId`; register `PendingQuery` under `_queriesMutex`; arm timeout on `_timerService`. |
| 4 | `DnsTransport::sendUdpQuery` | `DnsMessage::buildQuery`; send via the UDP engine. |
| 5 | Caller thread | Block on `future.wait_for(calculateMaxSyncWaitTime())`. |
| 6 | Engine I/O thread | `onData` → `DnsMessage::parse` → `processResponse` → `completeQuery` sets the promise. |
| 7 | `DnsResolver::query` | Populate `_cache->put()`; return `DnsResult`. |
| 8 | `DnsClient::resolveA` | Extract `a_records`; throw `DnsNoRecordsException` if empty (answers present, none of type A), else return addresses. An NXDOMAIN or NODATA reply already threw `DnsResolutionFailedException` at step 7 (§3.1 Error surfacing). |

### Truncation → TCP fallback

| Step | Component | Action |
|---|---|---|
| 1 | Engine I/O thread | UDP `processResponse` observes `result.isTruncated()` (TC flag). |
| 2 | `DnsTransport` | Increment `truncatedResponses`. If `transportMode == Both` and `!tcpFallback` (under `_queriesMutex`): set `tcpFallback = true`. |
| 3 | `DnsTransport::sendTcpQuery` | Re-send the same query over the TCP engine (inner co-hold of `_sessionsMutex`); `return` without completing. |
| 4 | Engine I/O thread | TCP `handleTcpData` accumulates length-prefixed bytes under `_tcpBuffersMutex`; over `maxTcpBufferSize` → clear + `close(session)`. |
| 5 | `DnsTransport` | On a complete TCP message → `processResponse` → `completeQuery`. |

### Async cancellation (future path)

| Step | Component | Action |
|---|---|---|
| 1 | `CancellableFuture::cancel` | `request.cancel()` flips `RequestState::cancelled` (acq_rel exchange). |
| 2 | `CancellableFuture::cancel` | Win the `promiseSet` CAS → set promise to `DnsResolverException("DNS request cancelled")`; a blocked `future.get()` wakes now. If a delivery already won the CAS, the promise keeps that value/error. |
| 3 | `CancellableFuture::cancel` | Because `request.cancel()` succeeded, and a promise is attached, call `request.markCompleted()` (whether or not this call won the `promiseSet` CAS): `isCompleted()` is now `true`, and — when the CAS was won — the future is immediately ready (holding the cancellation exception). |
| 4 | Later, transport thread | The real response (or timeout, or `stop()`) arrives; `resolveAInternal` sees `cancelled` and invokes the wrapper callback with `DnsResolverException("DNS request cancelled")`; the wrapper loses the `promiseSet` CAS and returns without re-setting the promise (no double-set). With a raw `resolveA(host, cb)` callback there is no `promiseSet`: the user callback itself receives that exception here. |

### Retransmission and timeout completion

| Step | Component | Action |
|---|---|---|
| 1 | `DnsRetryTimer` thread | The per-query timeout callback (`scheduleQueryTimeout`) fires `timeout` after the send. Under `_queriesMutex` it checks the attempt budget: if attempts remain it CLAIMS a retransmission (increments `retryCount`, resets `startTime`, sets `retryClaimed`) and releases the lock. |
| 2a | Timeout callback → `retryQuery` (attempts remain) | After releasing the lock, `retryQuery` schedules the backoff re-send; when it fires it re-sends to the SAME server/id, re-arms a fresh `timeout`, and bumps `_stats.retries`. |
| 2b | Timeout callback → `failOne` (budget exhausted) | `takePending` removes the `PendingQuery` under `_queriesMutex` (exactly-once gate), then the callback (guarded) is invoked / the promise is set with `DnsTimeoutException("DNS query timeout after maximum retries")`, and `_stats.timeouts` (only) is bumped. |

---

## 6. Thread Safety Model

`DnsClient` itself carries no lock; it is move-only and expected to be constructed, configured, and destroyed by one owner. Reconfiguration methods (`updateConfig`, `setDnsServers`, `addDnsServer`, `removeDnsServer`) call `initialize()`, which **tears down and rebuilds** the transport/resolver/cache — do this only while the client is quiesced (no outstanding async queries).

| Component / operation | Synchronization | Notes |
|---|---|---|
| `DnsTransport` pending-query map | `_queriesMutex` | Guards `_pendingQueries`. `completeQuery` and the timeout lambda are **copy-then-invoke** (release before callback). |
| `DnsTransport::stop()` | collect under `_queriesMutex`, fire with no lock | Step 6 collects and clears the pending queries under `_queriesMutex` without firing them (`dns_transport.hpp:889-898`); step 7 calls `failCollected(toFail, DnsTransportException("Transport stopped"))` with **no lock held**, before `Stopped` is published (`:913-917`). The worker joins run with no `DnsTransport` lock held; a re-entrant `stop()` from a joined worker (or the teardown driver) is exempted and returns at once (`:824-829`). The callbacks run on the thread calling `stop()`. |
| `DnsTransport` sessions | `_sessionsMutex` | Guards `_serverSessions`, `_sessionToServer`, `_connectedSessions`, `_pendingOnConnect`. |
| `DnsTransport` TCP buffers | `_tcpBuffersMutex` | Guards per-session accumulation; the DoS cap + `close()` run here. |
| `DnsTransport` cleanup thread | `_cleanupMutex` + `_cleanupCv` | 10-second wait loop; `_cleanupRunning` is an atomic. |
| `DnsTransport` lifecycle | `std::atomic<Lifecycle> _state` + `_stateMutex`/`_stateCv` | `_state` (`dns_transport.hpp:548`) replaced the old `_running` flag; transitions are serialized under `_stateMutex`, the query hot paths read `_state` lock-free. |
| `DnsTransport` statistics | `std::atomic` counters | `InternalStatistics` (8 atomics); snapshot via `getStatistics()`. |
| `DnsTransport` lock ordering | Documented, strict | `_stateMutex > _cleanupMutex > _tcpBuffersMutex > _queriesMutex > _sessionsMutex` (`dns_transport.hpp:507-522`). Inner co-holds: `handleTcpData` holds `_tcpBuffersMutex` across `_sessionsMutex`; the UDP-truncation path holds `_queriesMutex` while `sendTcpQuery` takes `_sessionsMutex`. |
| `DnsResolver` async coordination | per-op `std::mutex` + atomics | `resultMutex` + `remainingQueries` (`fetch_sub(acq_rel)`) + `callbackFired` + `deniedServices` are local to each async call, not members. Async continuations capture `self = shared_from_this()` to stay alive across the callback chain. |
| `DnsResolver::_rng` | `_rngMutex` | Guards the weighted-selection generator; `sortTargetsByPriority` takes one advancing draw under it (then orders on a local generator) and `setRngSeed` reseeds under it. A leaf lock — never held across a callback or with a result lock held. |
| `DnsCache` container | `std::shared_mutex _cacheMutex` | Shared for `get`/`put`/`putNegative`/`remove`, exclusive for `clear()` (which replaces the `ExpiringCache`). Guards the pointer; the store is itself internally synchronized. |
| `DnsCache` stats | `_statsMutex` (inner) + `std::atomic` counters | Ordering `_cacheMutex → _statsMutex`; the eviction callback takes neither (atomic `fetch_sub` only). |
| Async callback delivery | `RequestState::deliveryAttempted` + `promiseSet` CAS | One delivery even when response and timeout race across threads. Within that single delivery the raw `resolveA` path is a single-invoke funnel (`dns_client.hpp:1021-1088`): every branch builds a result and converges on one `callback(...)` outside any `try`, so a throwing user callback is invoked **exactly once** (no re-invoking `catch`) — the throw propagates once into the transport's `catch(...)` and completion is published by a `noexcept` scope-exit guard on the unwind. Resolved by tracker `2026-09-25-6`. |

---

## 7. Configuration Reference

All fields are on `dns::DnsConfig` (`dns_types.hpp:543`). Timeouts use `std::chrono` types.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `servers` | `std::vector<DnsServer>` | System `/etc/resolv.conf`, else `{8.8.8.8:53, 1.1.1.1:53}` | Nameservers to query; round-robin per query. |
| `timeout` | `std::chrono::milliseconds` | `5000` | Per-query response timeout (UDP **and** TCP — see below). |
| `tcpTimeout` | `std::chrono::milliseconds` | `10000` | **Declared but unused** by `DnsTransport`; TCP uses `timeout`. |
| `cacheTimeout` | `std::chrono::seconds` | `300` | Default cache TTL for records that carry no TTL (seeds the `DnsCache`; also adjustable at runtime via `setCacheTtl`). |
| `retryCount` | `int` | `3` | Retry attempts per query (`retryCount + 1` total sends). Honored: the per-query timeout timer drives same-server retransmission (§3.4). |
| `initialRetryDelay` | `std::chrono::milliseconds` | `500` | First retry's inter-attempt backoff delay; grows by `retryMultiplier` per attempt. Also lengthens the sync wait bound `calculateMaxSyncWaitTime`. |
| `retryMultiplier` | `double` | `2.0` | Exponential backoff multiplier. |
| `maxRetryDelay` | `std::chrono::milliseconds` | `10000` | Backoff cap. |
| `jitterFactor` | `double` | `0.1` | Multiplicative jitter `× U(1−f, 1+f)` when `> 0`. |
| `enableCache` | `bool` | `true` | Create a `DnsCache`; when false, `_cache` is null. |
| `maxCacheSize` | `std::size_t` | `10000` | **Not an entry cap** — the cache is time-based (`ExpiringCache`), so this is not enforced; entries live for their TTL, not a count. |
| `transportMode` | `DnsTransportMode` | `Both` | `UDP` / `TCP` / `Both` (UDP with TCP fallback on truncation). |
| `recursionDesired` | `bool` | `true` | Sets the `RD` flag in outbound queries. |
| `maxUdpSize` | `std::size_t` | `512` | **Declared but unused** by `DnsTransport`; fallback is TC-flag-driven, not size-driven. |
| `maxTcpBufferSize` | `std::size_t` | `65536` | Per-session TCP receive-buffer cap; exceeding it closes the session (DoS guard). |
| `addressResolutionPolicy` | `AddressResolutionPolicy` | `IPv4First` | `IPv4Only` / `IPv6Only` / `IPv4First` / `IPv6First`; SRV always takes precedence. |

`DnsClient` cache runtime knobs: `setCacheTtl` / `getCacheTtl` (default TTL for records without one), `getCacheStats`, `clearCache`, `removeCacheEntry`, `cleanupCache` (no-op → 0), `setCacheCleanupCallback` (stored, not invoked). Server runtime knobs: `setDnsServers`, `addDnsServer`, `removeDnsServer`, `getDnsServers` — each rebuilds the transport via `initialize()`.

---

## 8. API Reference

`iora::network` — cancellation and futures:

```cpp
class AsyncDnsRequest
{
public:
  AsyncDnsRequest() = default;
  bool cancel();
  bool isCancelled() const;
  bool isCompleted() const;
  std::string getHostname() const;
  void markCompleted();
};

template <typename T> struct CancellableFuture
{
  std::future<T> future;
  AsyncDnsRequest request;
  std::shared_ptr<std::promise<T>> promise;
  std::shared_ptr<std::atomic<bool>> promiseSet;
  bool cancel();
  bool isCancelled() const;
  bool isCompleted() const;
  std::string getHostname() const;
};
```

`iora::network::DnsClient` (public surface):

```cpp
class DnsClient
{
public:
  DnsClient();
  explicit DnsClient(const dns::DnsConfig &config);
  ~DnsClient();

  DnsClient(const DnsClient &) = delete;
  DnsClient &operator=(const DnsClient &) = delete;
  DnsClient(DnsClient &&) = default;
  DnsClient &operator=(DnsClient &&) = default;

  bool start();
  void stop();

  struct HostResult { std::vector<std::string> ipv4; std::vector<std::string> ipv6; bool success = false; };
  HostResult resolveHost(const std::string &hostname);

  // Service discovery (RFC 3263 S/A-flag subset)
  dns::ServiceResolutionResult resolveServiceDomain(
      const std::string &domain,
      const std::vector<dns::ServiceType> &preferredTransports = {});
  dns::ServiceResolutionResult resolveCustomServiceDomain(
      const std::string &domain,
      const std::vector<std::pair<std::string, dns::ServiceType>> &srvQueries,
      const std::vector<dns::ServiceType> &preferredTransports = {});
  void resolveServiceDomainAsync(
      const std::string &domain,
      dns::DnsResolver::ServiceResolutionCallback callback,
      const std::vector<dns::ServiceType> &preferredTransports = {});
  void resolveCustomServiceDomainAsync(
      const std::string &domain,
      const std::vector<std::pair<std::string, dns::ServiceType>> &srvQueries,
      dns::DnsResolver::ServiceResolutionCallback callback,
      const std::vector<dns::ServiceType> &preferredTransports = {});
  CancellableFuture<dns::ServiceResolutionResult> resolveServiceDomainFuture(
      const std::string &domain,
      const std::vector<dns::ServiceType> &preferredTransports = {});

  // Standard queries
  dns::DnsResult query(const dns::DnsQuestion &question);
  void queryAsync(const dns::DnsQuestion &question,
                  std::function<void(const dns::DnsResult &, const std::exception_ptr &)> callback);
  std::vector<std::string> resolveA(const std::string &hostname);
  AsyncDnsRequest resolveA(const std::string &hostname,
                           std::function<void(std::vector<std::string>, std::exception_ptr)> callback);
  CancellableFuture<std::vector<std::string>> resolveAAsync(const std::string &hostname);
  std::vector<std::string> resolveAAAA(const std::string &hostname);
  std::vector<std::string> resolveHostname(const std::string &hostname, bool prefer_ipv6 = false);
  std::vector<dns::SrvRecord> resolveSRV(const std::string &service);
  std::vector<dns::NaptrRecord> resolveNAPTR(const std::string &domain);
  std::vector<std::string> resolveCNAME(const std::string &hostname);
  std::vector<dns::MxRecord> resolveMX(const std::string &domain);
  std::vector<dns::TxtRecord> resolveTXT(const std::string &domain);
  std::vector<std::string> resolvePTR(const std::string &ip);

  // Deprecated SIP-named forwarders
  dns::SipResolutionResult resolveSipDomain(
      const std::string &domain,
      const std::vector<dns::SipServiceType> &preferredTransports = {});
  void resolveSipDomainAsync(
      const std::string &domain,
      std::function<void(const dns::SipResolutionResult &, const std::exception_ptr &)> callback,
      const std::vector<dns::SipServiceType> &preferredTransports = {});

  // Cache + configuration
  dns::DnsCacheStats getCacheStats() const;
  void clearCache();
  void removeCacheEntry(const dns::DnsQuestion &question);
  std::size_t cleanupCache();
  bool isCacheEnabled() const;
  const dns::DnsConfig &getConfig() const;
  void updateConfig(const dns::DnsConfig &config);
  void setDnsServers(const std::vector<std::string> &servers);
  void addDnsServer(const std::string &server);
  void removeDnsServer(const std::string &server);
  std::vector<std::string> getDnsServers() const;
  void setCacheCleanupCallback(std::function<void(const dns::DnsCacheStats &)> callback);
  void setCacheTtl(std::chrono::seconds ttl);
  std::chrono::seconds getCacheTtl() const;
};
```

Record types (`dns_types.hpp:54`):

```cpp
enum class DnsType : std::uint16_t
{
  A = 1, NS = 2, CNAME = 5, SOA = 6, PTR = 12, MX = 15, TXT = 16, AAAA = 28,
  SRV = 33, NAPTR = 35,
  AXFR = 252, MAILB = 253, MAILA = 254, ANY = 255
};
```

| `DnsType` | Typed `DnsClient` accessor | Typed `DnsResult` vector |
|---|---|---|
| `A` | `resolveA` (sync, callback, future) → address strings | `a_records` |
| `AAAA` | `resolveAAAA` → address strings | `aaaa_records` |
| `CNAME` | `resolveCNAME` → name strings | `cname_records` |
| `PTR` | `resolvePTR(ip)` (builds the reverse name) → name strings | `ptr_records` |
| `MX` | `resolveMX` → `MxRecord` | `mx_records` |
| `TXT` | `resolveTXT` → `TxtRecord` | `txt_records` |
| `SRV` | `resolveSRV` → `SrvRecord` | `srv_records` |
| `NAPTR` | `resolveNAPTR` → `NaptrRecord` | `naptr_records` |
| `SOA` | none | `soa_records` (parsed from any section; used for the RFC 2308 negative-cache TTL) |
| `NS` | none | none — use `query(DnsQuestion{name, DnsType::NS, DnsClass::IN})` and read the raw `answers`/`authority`/`additional` records |
| `AXFR`, `ANY`, `MAILA`, `MAILB` | none | Effectively unsupported via `query()`: AXFR needs a multi-message TCP exchange (RFC 5936) that `DnsTransport` does not implement (it completes on the first message); ANY is answered minimally or refused by modern servers (RFC 8482); MAILA/MAILB are obsolete. |

Record structs (`dns_types.hpp:199`–`:357`). Every typed record derives from `DnsResourceRecord`:

```cpp
struct DnsResourceRecord
{
  std::string name; DnsType type; DnsClass cls; std::uint32_t ttl;
  std::uint16_t rdlength; std::vector<std::uint8_t> rdata;   // raw RDATA (empty in typed records)
  std::chrono::steady_clock::time_point getExpirationTime() const;
  bool hasExpired() const;
};
struct ARecord     : DnsResourceRecord { std::string address; };
struct AAAARecord  : DnsResourceRecord { std::string address; };
struct CnameRecord : DnsResourceRecord { std::string cname; };
struct PtrRecord   : DnsResourceRecord { std::string ptrdname; };
struct MxRecord    : DnsResourceRecord { std::uint16_t preference; std::string exchange; };
struct TxtRecord   : DnsResourceRecord { std::vector<std::string> text; };
struct SrvRecord   : DnsResourceRecord { std::uint16_t priority; std::uint16_t weight;
                                         std::uint16_t port; std::string target; };
struct NaptrRecord : DnsResourceRecord { std::uint16_t order; std::uint16_t preference;
                                         std::string flags; std::string service;
                                         std::string regexp; std::string replacement; };
struct SoaRecord   : DnsResourceRecord { std::string mname; std::string rname;
                                         std::uint32_t serial, refresh, retry, expire, minimum; };
```

(Inheritance is `public`; each struct also has a defaulted-argument constructor that sets `type`/`cls = IN`.) The typed records in `a_records`, `srv_records`, … are built through those constructors (`dns_message.hpp:819`, `:836`, `:873`, …), so they carry **no raw RDATA** — `rdata` is empty, `rdlength` is 0 — and `cls` is forced to `IN` whatever the wire class was. Raw RDATA is available only on the generic records in `answers`/`authority`/`additional`.

Other key `iora::network::dns` types (see `dns_types.hpp` / `dns_resolver.hpp`):

```cpp
enum class ServiceType { SIPS_TLS, SIPS_SCTP, SIPS_WSS, SIP_TCP, SIP_UDP,
                         SIP_SCTP, SIP_WS, HTTP_TCP, HTTPS_TCP, Unknown };
using SipServiceType     = ServiceType;        // deprecated
using SipTarget          = ServiceTarget;      // deprecated
using SipResolutionResult = ServiceResolutionResult; // deprecated

struct ServiceTarget
{
  std::string hostname; std::uint16_t port; ServiceType transport;
  std::uint16_t priority; std::uint16_t weight; std::uint16_t naptrPreference{0};
  std::vector<std::string> addresses;
  std::string getTransportString() const;   // "udp"/"tcp"/"tls"/"ws"/"wss"/"sctp"/"unknown"
  bool isSecure() const;
};

struct ServiceResolutionResult
{
  std::vector<ServiceTarget> targets; std::string domain;
  bool fromCache{false}; std::chrono::steady_clock::time_point timestamp;
  bool isSuccess() const;
  std::vector<ServiceTarget> getTargetsForTransport(ServiceType transport) const;
  ServiceTarget getPreferredTarget() const;                  // returns the ordered head (front())
  ServiceTarget getPreferredTargetWithDefaultRng() const;    // ditto (RNG no longer used)
  template <typename RNG> ServiceTarget getPreferredTarget(RNG &rng) const; // ditto; rng unused
};

// Exceptions — three disjoint roots (no common DNS base class):
// dns_resolver.hpp
class DnsResolverException : public std::exception { /* getResponseCode() */ };   // :349
class DnsResolutionFailedException : public DnsResolverException {};              // :367
class DnsNoRecordsException : public DnsResolverException {}; // rcode NXDOMAIN   // :376
// dns_transport.hpp
class DnsTransportException : public std::runtime_error {};                        // :44
class DnsTimeoutException : public DnsTransportException {};                       // :53
class DnsServerException : public DnsTransportException { DnsResponseCode responseCode; }; // :62
// dns_message.hpp
class DnsParseException : public std::runtime_error {};                            // :27
```

`DnsResolverException` derives from `std::exception`; `DnsTransportException`/`DnsTimeoutException` and `DnsParseException` derive from `std::runtime_error`. A `catch (const dns::DnsResolverException &)` therefore does not catch timeouts, transport failures, or parse failures — catch each root, or `std::exception` last. The header `\throws dns::DnsResolverException` comments on the synchronous and service-discovery methods are incomplete for the same reason. Open — P0, tracked `coding_trackers:tasks/iora/backlog/2026-09-24-29_dns-resolver-catches-only-resolver-exception-and-rfc3263-gaps_P0.json`.

---

## 9. Design Decisions

| Decision | Rationale |
|---|---|
| Separate DNS-protocol client from the transport `NameResolver`. | `getaddrinfo` cannot return `SRV`/`NAPTR`/`MX`/`TXT`; SIP/HTTP service location needs a real DNS client that queries nameservers directly. The two are documented as distinct tools with different resolution stacks (§1 boundary). |
| RFC 3263 limited to the `S`/`A`-flag subset. | SIP server location (RFC 3263 §4.1) needs only `S` (→SRV) and `A` (→direct A/AAAA) flags. `U`-flag/ENUM (RFC 6116) and chained NAPTR are out of scope and are explicitly skipped. Scope note: URI-level short-circuits (numeric-IP target, an explicit port, or an explicit transport per RFC 3263 §4.1–4.2) are the SIP-stack caller's responsibility, not `DnsClient`'s. |
| NAPTR processed in ascending `ORDER`, stopping at the first usable tier (RFC 3403 §8). | The DDDS algorithm mandates lowest-`ORDER`-first; descending to a higher `ORDER` only when the current tier yields no usable target avoids silently ignoring a valid fallback tier while still honoring precedence. |
| SRV `.` target suppresses fallback **per service**, not domain-wide (RFC 2782). | A `.` means "this service is decidedly not available at this domain." Suppressing only the denied transport's A/AAAA fallback (not the whole domain) prevents a `_sips._tcp .` from stranding plain SIP reachable via a bare A record. |
| RFC 2782 weighted ordering computed once over the whole failover list, not per pick; `getPreferredTarget` returns the ordered head (tracker `2026-09-25-4`). | Ordering the entire list at resolution time — sequence transports per owner name (`naptrPreference`/transport-rank), then RFC 2782 weighted-random within each equal-priority group — gives correct failover *traversal* order, not just a correct single next-hop. `getPreferredTarget` then returns `front()` and does not re-randomize, so the head and the traversal order agree (no double-ordering) and the per-pick RNG is removed. Weights are summed only within one `(transport, priority)` group; the draw is one advancing pull of `_rng` under the leaf `_rngMutex`, seedable for deterministic tests. |
| Move-only façade owning `shared_ptr` components. | The transport owns threads and timers; copying would double-own them. Move preserves single ownership. Across async work the transport captures a `weak_ptr` (breaking a reference cycle) while the resolver captures a shared `self` (deliberate keep-alive for fire-and-forget resolution). |
| Query matched by `(queryId, server, port)`, session mapped by `(isTcp, SessionId)`. | The UDP and TCP engines mint colliding `SessionId`s; the composite session key prevents cross-engine response misattribution. |
| Truncation (TC flag) drives TCP fallback, not a size check. | The authoritative signal that a UDP answer was cut is the server's TC flag; falling back on a local size guess would be both over- and under-inclusive. |
| Exponential backoff with multiplicative jitter. | Bounded retransmission (`min(base·mult^n, cap)`) with `× U(1−f, 1+f)` jitter avoids synchronized retry storms (thundering herd) against a recovering server. The per-query timeout timer is the sole retry driver (§3.4). |
| Per-query timeout timer is the sole retry driver; the cleanup sweep is an orphan-only backstop. | One driver means exactly-once retry with no CAS: the claim resets `startTime` under `_queriesMutex`, so a sweep serialized after it sees a healthy mid-backoff query as not-expired and skips it. The sweep fails only orphaned entries (expired AND no live timer), which cannot be produced by a healthy retry. |
| Constant per-attempt timeout + separate inter-attempt backoff (not RTO-doubling). | Keeps late-answer correlation trivial (the query id is reused across attempts, so a slow answer to an earlier attempt still matches) at the cost of higher worst-case latency than growing the per-attempt deadline. A conscious §3.4 choice. |
| Per-session TCP buffer cap that closes on breach. | TCP DNS is length-prefixed; without a cap a malicious peer can force unbounded buffering. Closing the session bounds memory and is safe from the I/O thread (`close` is enqueue-only). |
| Best-effort cancellation with a `promiseSet` CAS. | A network request cannot be truly un-sent; the CAS lets `cancel()` win the race to set the promise so a blocked caller wakes immediately, while the later real response harmlessly loses the CAS (no double-set). The raw-callback path has no such suppression: the callback still runs once, with a cancellation exception. |
| TTL = minimum record TTL (RFC 1035); negative TTL from SOA (RFC 2308). | The shortest TTL in a response bounds correctness; SOA `minimum` bounds negative caching. Both are standards-mandated conservative choices. |
| Negatives cached only when an SOA is present (RFC 2308 §5). | NXDOMAIN and NODATA are cached only if the response carries an SOA (the authoritative source of the negative TTL); a no-SOA negative is re-queried rather than cached with a guessed lifetime. |
| Cache is time-based (`ExpiringCache`); no entry-count cap. | A TTL-driven cache needs no LRU/size eviction for correctness; `maxCacheSize` is retained only for API compatibility and is not enforced. |

---

## 10. Known Limitations

| Limitation | Impact |
|---|---|
| **`maxUdpSize` is declared but unused.** | `DnsConfig::maxUdpSize` (default 512) is never consulted by `DnsTransport`; outbound UDP size is not checked and TCP fallback is purely TC-flag-driven. Setting it has no effect. |
| **`tcpTimeout` is declared but unused.** | `DnsConfig::tcpTimeout` (default 10000 ms) is never referenced; TCP queries use `_config.timeout` (5000 ms) like UDP. Do not rely on a distinct TCP timeout. |
| **`maxCacheSize` is not enforced.** | The cache has no entry-count bound; it is expiration-based only. A flood of distinct short-TTL names is bounded only by their TTLs, not by a size cap. |
| **NAPTR tier-descent does not re-descend on SRV-resolution failure.** | `processNaptrRecords` commits to the first `ORDER` tier that produces a selectable `S`/`A` record; if that tier's SRV RRset later resolves to nothing, a usable higher-`ORDER` tier is not retried. This matches RFC 3403 §8 ("If the lookup after a rewrite fails, clients are strongly encouraged to report a failure, rather than backing up to pursue other rewrite paths"), but a peer that publishes fallback tiers expecting SRV-failure re-descent will not get it. |
| **Cache statistics are approximate under concurrent same-key writes.** | The insertion/replacement counters can drift by ±1 when a key expires in the window between a `put`'s existence check and its count update (the eviction callback decrements without `_statsMutex`). Cached data is unaffected; only the monitoring counters are approximate (tracked backlog). |
| **No per-query server failover.** | A query is sent only to the server it started on; only a new query advances the round-robin cursor. A single dead server is not skipped mid-query. For hard failover, catch `DnsTransportException` (including `DnsTimeoutException`) and server-local rcodes, and re-issue on a second `DnsClient` with different servers (§4 "Failing over to a second server set"). |
| **TC=1 TCP-fallback timeout is not identity/state aware (latency, premature failure, and double-act).** | After a TC=1 UDP truncation, the query falls back to TCP and re-arms a timeout. Three known gaps, all needing a timer-identity redesign: (a) if that TCP server is connected but silent, the fallback timeout callback defers rather than failing terminally, so the query fails only via the 10-second orphan-backstop sweep — `~timeout` becomes `~timeout + up to 10 s` (UDP-only queries are unaffected); (b) a stale UDP timeout that fired concurrently with the truncation can zero the live fallback's `activeTimerId`, and because the fallback path never resets `startTime`, the orphan sweep can then **prematurely FAIL a still-in-flight, would-have-succeeded TCP fallback** (worse than added latency); (c) a truncated reply arriving in the retry resend's clear-to-send window can start a TCP fallback while the UDP resend also fires (completion stays exactly-once). Open — P1, tracked `coding_trackers:tasks/iora/backlog/2026-09-25-2_dns-tcp-fallback-timeout-identity-arbitration_P1.json`. |
| **The resolver catches only `DnsResolverException`.** | Every recovery site in `DnsResolver` — `dns_resolver.hpp:710`, `:729`, `:825`, `:1179`, `:1206`, `:1738`, `:1790` — catches `DnsResolverException` only, so `DnsTimeoutException`/`DnsTransportException` and `DnsParseException` escape. A NAPTR timeout aborts RFC 3263 resolution instead of falling back to SRV; a single SRV or target-address failure aborts the whole result; `resolveHostname` under `IPv4First` discards the A results when the AAAA query throws. Combined with the AAAA false positive above, a dual-stack SIP target with an ordinary IPv6 address fails both `resolveHostname` and `resolveServiceDomain`. Open — P0, tracked `coding_trackers:tasks/iora/backlog/2026-09-24-29_dns-resolver-catches-only-resolver-exception-and-rfc3263-gaps_P0.json`. |
| **`preferredTransports` does not filter a SIPS resolution.** | (The cross-record-set direct-SRV *ranking* defect was **fixed** in `2026-09-25-4` — SRV priority/weight are now compared only within one owner name; see §3.3/§3.4.) What remains: `preferredTransports` only reorders the SRV queries, it does not filter, so a SIPS resolution (RFC 3263 §4.1: a SIPS URI must use TLS) still yields non-TLS targets and a SIPS caller must filter with `getTargetsForTransport(ServiceType::SIPS_TLS)` (§3.3). A secure-URI resolution should hard-exclude non-TLS services across all paths (NAPTR/SRV/fallback) and default the A/AAAA fallback to TLS/5061. Open — P0, tracked `coding_trackers:tasks/iora/backlog/2026-09-25-12_dns-sips-secure-hard-filter-across-paths_P0.json` (slice b2). |
| **The async service path ignores `addressResolutionPolicy` and the cache.** | `resolveTargetAddressesAsync` queries AAAA only when A returned nothing (`dns_resolver.hpp:1912`) and calls the transport directly (§3.3 step 5). Open — P0, tracked `coding_trackers:tasks/iora/backlog/2026-09-24-29_dns-resolver-catches-only-resolver-exception-and-rfc3263-gaps_P0.json`. |
| **Partial RFC 5452 response hardening.** | An UNPARSEABLE response whose first two bytes match a pending query ID from the same server/port is now DROPPED (drop-and-wait), so it no longer terminates the query and retransmission continues to timeout (fixed by tracker 2026-09-24-31, RFC 5452 §9.1 Query Matching Rules). Broader hardening — full source/port entropy checks and malformed-record skip robustness — is still tracked `coding_trackers:tasks/iora/backlog/2026-09-24-34_dns-parse-partial-record-skip-robustness_P1.json` / `-29`. |
| **A throwing user callback is invoked twice.** | ~~In `resolveAInternal`, a callback that throws is called again with the thrown exception from `catch (...)`.~~ **FIXED** — `resolveAInternal` is now a single-invoke funnel (all branches build a result and converge on one `callback(...)` outside any `try`; a throwing callback propagates once into the transport's `catch(...)` and completion is published by a `noexcept` scope-exit guard on the unwind). Resolved by tracker `2026-09-25-6` (`dns-async-cancel-teardown-and-double-invoke`). |
| **`resolveA(host, cb)` can throw `std::bad_function_call` instead of calling back.** | On a synchronous throw, the `catch (...)` branch (`dns_client.hpp:1124`) calls `callback`, but it was already moved into `resolveAInternal` (`:1116`), so the call throws `std::bad_function_call` out of `resolveA` and the user callback is never invoked. (The `!_transport` immediate-error branch at `:1105-1111` invokes the callback BEFORE the move and is safe.) Reproduced with a hostname containing a 70-byte label: `DnsMessage::encodeName` throws `DnsParseException` inside `DnsTransport::queryAsync` (before the query is registered), and `resolveA` throws `std::bad_function_call`. Open — P1, tracked `coding_trackers:tasks/iora/backlog/2026-09-24-32_dnsclient-resolvea-callback-moved-then-invoked_P1.json`. |
| **A `start()` failure after publishing can strand running transports.** | `DnsTransport::start()` publishes the transports and `Running` before `startCleanupTimer()`, whose thread creation can throw; the failure path then reports `Stopped` while the started transports stay published, `stop()` returns early, and the next `start()` drops them under `_stateMutex` (`dns_transport.hpp:757-771`). `DnsClient` surfaces it as `DnsResolverException("Failed to start DNS transport: …")` from its constructor or `initialize()`. Open — P1, tracked `coding_trackers:tasks/iora/backlog/2026-09-24-30_dnstransport-start-publishes-before-cleanup-thread-can-throw_P1.json`. |
| **`cleanupCache()` / `setCacheCleanupCallback` are no-ops.** | `cleanupExpired()` always returns 0 (ExpiringCache sweeps itself every ~5 s) and the stored cleanup callback is never invoked. Do not use them for monitoring. |
| **`resolveHost` swallows per-family errors.** | It returns `success = false` only when *both* A and AAAA fail; individual family errors are discarded, so a partial failure is invisible to the caller. Use `resolveA`/`resolveAAAA` when you need per-family error detail. |
| **Async callbacks run on several threads, including the caller's.** | Callbacks fire on the engine I/O thread, the `DnsRetryTimer` thread, or the cleanup thread; on the caller's thread before `resolveA`/`queryAsync` returns for immediate errors (no transport, transport not running, registration refused, send failure) and, for `queryAsync`, cache hits; and on the thread calling `stop()` for queries still pending at shutdown (`dns_transport.hpp:917`). Non-thread-safe callback bodies are a data race, and a lock held across `resolveA` that the callback takes is a self-deadlock. |
| **Cancellation never suppresses the raw callback.** | After `AsyncDnsRequest::cancel()` the callback is still invoked exactly once — with the real result if delivery won, else with `DnsResolverException("DNS request cancelled")` when the response, timeout, or `stop()` arrives (`dns_client.hpp:1021`,`:1051`); nothing removes the pending query. Captured state must outlive it. `CancellableFuture::cancel()` returning `true` does not guarantee `get()` throws. The header's "false if already completed" (`dns_client.hpp:46`) is wrong. Open — P1, tracked `coding_trackers:tasks/iora/backlog/2026-09-25-9_dns-async-cancel-teardown-transport-api_P1.json`. |
| **No DNSSEC, EDNS(0), or `/etc/hosts` / search-list processing.** | `DnsClient` queries configured nameservers directly for a fixed record-type set; it does not validate DNSSEC, negotiate EDNS buffer sizes, or honor `/etc/hosts` or resolv.conf `search`/`ndots`. In split-horizon deployments it can disagree with the system resolver (§1). |
