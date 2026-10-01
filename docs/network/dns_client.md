# Iora DnsClient — Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.11 |
| **Date** | 2026-10-01 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/network/dns_client.hpp` |
| **Internal headers** | `include/iora/network/dns/dns_resolver.hpp`, `dns_transport.hpp`, `dns_cache.hpp`, `dns_message.hpp`, `dns_types.hpp`, `dns_utils.hpp` |
| **Namespaces** | `iora::network` (`DnsClient`, `AsyncDnsRequest`, `CancellableFuture<T>`); `iora::network::dns` (all backing types) |
| **Dependencies** | `<algorithm>`, `<atomic>`, `<cctype>`, `<chrono>`, `<functional>`, `<future>`, `<memory>`, `<optional>`, `<sstream>`, `<string>`, `<vector>`; internally `network/transport_impl.hpp` (the UDP/TCP engines), `core/timer.hpp` (`TimerService`), `core/string_utils.hpp`, `util/expiring_cache.hpp` |

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
| 1.7 | 2026-09-26 | Synced §3.3/§4/§8/§10 to the landed SIPS/secure hard-filter (iora `ff583eb`, tracker `2026-09-25-12`, slice b2 — the filtering half of the `2026-09-24-29` split). Every service-resolution entry point now takes a trailing `bool secure = false`. When `secure` is true (RFC 3263 §4.1, SIP-scoped via `isSecureSipService` = SIPS_TLS/SIPS_SCTP/SIPS_WSS, **excluding** the generic `isSecureService`'s HTTPS_TCP): the direct-SRV default query set is **built by owner-name mapping** (each supported secure transport → its `_sips._<proto>` owner name, default `_sips._tcp`, never `_sips._udp`); a custom SRV set is **filtered** to secure SIP services; `processNaptrRecords` discards every non-SIPS-SIP (and unsupported) service unconditionally on **all** paths (NAPTR, SRV, cache, both async); the A/AAAA fallback **filters-then-defaults to SIPS_TLS/5061**, never a plaintext target; and a `discardInsecure` belt at `sortTargetsByPriority` guards the delivery paths. For **plain** `sip:` (`secure=false`), `preferredTransports` is now the client's **supported set** — an unsupported published transport is **discarded** (not merely reordered) on the default query set and the NAPTR path; an **empty** `preferredTransports` stays permissive. **Resolved** the SIPS/secure hard-filter Known Limitation. The SIP layer (`iora_sip` `SipDnsAdapter`, tracked `iora_sip 2026-09-25-2`) is the hard dependency that drives `secure=true` for a `sips:` URI and owns the explicit-port/transport §4.1/§4.2 short-circuit + the end-to-end contract test. |
| 1.8 | 2026-09-29 | Synced §3.3 step 5 + §10 to the landed async/cached address-resolution-policy fix (iora `bda1c10`, tracker `2026-09-25-5`, slice c of the `2026-09-24-29` split). The async/cached A/AAAA paths (`resolveTargetAddressesAsync`, `performFallbackResolutionAsync`, `processCachedServiceResolution`) now honor `addressResolutionPolicy` **byte-identically to the sync `resolveHostname`** — both families for `IPv4First`/`IPv6First` (policy order; the old "AAAA only if A returned nothing" shortcut is gone, restoring the RFC 3263 §4.2/§4.3 dual-stack failover set), the single family for `IPv4Only`/`IPv6Only` (the other family is not queried). The two families are issued strictly sequentially per target, preserving the fan-out completion-latch invariants; every `queryAsync` issue site (both SRV latches, the target latch, the fallback chain, and the two entry sites) is wrapped so a synchronous throw yields exactly-one decrement/callback and never unwinds into a worker, and `ServiceResolutionCallback` is delivered at most once (a throwing user callback no longer double-delivers). The fallback path emits **no** empty-address target when nothing resolves under the policy (mirrors the sync no-records semantics). **Resolved** the async-policy Known Limitation; the residual (a *fresh* async resolution does not populate the record cache) is reworded as existing behavior, not a defect. `DnsTransport::queryAsync` is now `virtual` (a test seam). |
| 1.9 | 2026-09-30 | Synced §1/§2/§3.1/§3.3/§3.4/§4/§5/§6/§7/§8/§9/§10 to the landed **next-server failover + per-avenue transient/permanent outcome** (iora `c2d0f77`, tracker `2026-09-25-8`, Slice A). The `DnsResolver` now OWNS server selection and fails over across all configured servers on a SERVER-LOCAL condition — an rcode-bearing negative (SERVFAIL/REFUSED/FORMERR/NOTIMP/NODATA-without-SOA) or a delivered/thrown transport fault (timeout, connect/send failure via the new `dns::DnsNetworkException`, per-server query-ID exhaustion, async session close) — retrying the SAME question on the next server (excluding tried) until a success, an AUTHORITATIVE negative (NXDOMAIN / NODATA-with-SOA, which STOPS rotation), or all servers are exhausted (RFC 1035 §7.2). A NAPTR NOTIMP/FORMERR falls straight to direct-SRV WITHOUT rotating (human Q5). Sync (`query()` leaf) and async (`queryAsyncWithFailover`, a per-issue atomic-CAS handshake) share the detection gate. New additive `dns::ResolutionOutcome { Resolved, TransientFailure, PermanentNoService }` on `ServiceResolutionResult` (default `Resolved`; `isSuccess()` unchanged) lets a consumer map a transient outage to 503 vs a permanent no-service to 404; `resolveHostname` now throws the transient-preserving `dns::DnsTransientResolutionException` (distinct from `DnsNoRecordsException`) on all-server exhaustion. **Resolved** the "No per-query server failover" Known Limitation and the resolver-abort-on-transient half of the `2026-09-24-29` limitation. Interim scope: per-avenue (the terminal avenue's outcome); the CROSS-STEP NAPTR→SRV→A/AAAA aggregation is tracked `2026-09-30-1`, the RFC-1035-§7.2 one-transmission-per-round latency/Timer-B budget `2026-09-30-3`, and async fan-out caching + the H1/retransmit exception-type regression test `2026-09-30-2`. |
| 1.10 | 2026-10-01 | Synced §3.1/§3.3/§5/§9/§10 to the landed **RFC-compliance refinements** (iora `510921d`, tracker `2026-09-30-4`, the round-3 follow-ups on Slice A). **H-1** (`isAuthoritativeNegative`): a NODATA (NOERROR + no answers) is authoritative — and so STOPS next-server rotation — when the response carries an **SOA** *or* has **no NS records** (RFC 2308 §2.2 "SOA present … OR absence of NS records"); the pre-fix SOA-*only* gate mis-classified the common dnsmasq/GSLB empty-authority NOERROR (typical for AAAA/SRV/NAPTR) as a retryable outage. SOA-gating stays a **caching**-only concern (RFC 2308 §5). A trustworthiness guard rides with it: an NXDOMAIN or a type-3 (empty-authority) NODATA is authoritative only from a server that **recursed or is authoritative** (`RA || AA`) — a LAME reply (RA=0 ∧ AA=0) rotates (M-2/F-4) — and a **truncated** (TC=1) response is never authoritative (RFC 2181 §9, F-3). **H-2**: the sync wait budget `calculateMaxSyncWaitTime` now honors `retryCount` — `timeout × (retryCount + 1)` plus the inter-attempt backoff sum (was effectively `1×`), so a sync query actually waits for all its retransmissions. **H-3**: an all-SRV-failed NAPTR-`S` avenue now takes the RFC 3263 **§4.2** fallback principle (A/AAAA of the domain at the default port) extended to the NAPTR-chosen transport(s) (was incorrectly cited §4.1 and not performed), sharing ONE empty-avenue policy with the direct-SRV path (`resolveEmptySrvAvenue`) so the two cannot drift. **M-4**: that §4.2 fallback is **suppressed** when any SRV set exhausted its servers server-local (`anySrvTransient`) — a transient is not proof of absence — and the avenue carries `TransientFailure` instead (RFC 2782 "." honored throughout). |
| 1.11 | 2026-10-01 | Added §3.3 **Per-resolution deadline** + §4 usage + §6/§7/§8/§9/§10 to the landed **F-2** per-resolution deadline (iora `0494148`, tracker `2026-09-30-3`), which bounds the serial RFC 3263 NAPTR→SRV→A/AAAA chain under the SIP transaction ceiling (Timer B/F = 64·T1 = 32 s). New additive `DnsConfig::maxResolutionTime` (default `0` = **disabled** = byte-for-byte today's behavior) plus a trailing per-call `std::optional<std::chrono::milliseconds> deadlineOverride` on every public resolution entry; the absolute deadline is computed once at the entry and threaded down as a required by-value parameter. **Sync** is HARD-bounded (a `maxWait` cap on the in-flight `DnsTransport::query` + a pre-issue gate that re-throws without a wire query); **async** is a SOFT gate at the `queryAsyncWithFailover` choke point (stops issuing further servers/families; does not abort the one in-flight attempt — worst case = deadline + one `asyncAttemptBudget()`). On expiry → `DnsDeadlineException` (IS-A `DnsTransientResolutionException`) → `TransientFailure`, sync == async, never `PermanentNoService`; already-resolved targets are kept (partial-Resolved, including the priority-inversion case). New public `asyncAttemptBudget()` / `udpAttemptBudget()` sizing accessors. CARVED OUT: RFC-1035-§7.2 one-transmission-per-round cycling + per-server sub-budgeting → `2026-09-30-5`. |

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
- **`dns::DnsResolver`** — the RFC 3263 engine: NAPTR→SRV→A/AAAA chaining, RFC 2782 SRV priority/weight selection, the `AddressResolutionPolicy` (IPv4/IPv6 ordering), and RFC 1035 §7.2 **next-server failover** with a per-avenue transient/permanent `ResolutionOutcome` (§3.3), and an optional **per-resolution deadline** (§3.3 "Per-resolution deadline") that bounds the whole serial chain under the SIP transaction ceiling. It owns cross-server selection for its own paths; the transport's round-robin `getNextServer` now serves only the raw async A fast-path.
- **`dns::DnsTransport`** — UDP-first with TCP fallback on truncation, exponential-backoff-with-jitter same-server retransmission (the per-query timeout timer is the sole retry driver — §3.4), per-query timeouts, single-target-per-attempt sends (cross-server failover is the resolver's job — §3.3 — while the transport keeps a round-robin `getNextServer` for the one caller that passes no server, the raw async A fast-path), and a per-session TCP receive-buffer cap for DoS resistance. It rides two `iora::network::Transport` instances (the UDP and TCP engines).
- **`dns::DnsMessage`** — a hardened DNS wire codec (encode query / parse response) with compression-pointer loop detection, label/name size limits, and per-record bounds validation.
- **`dns::DnsCache`** — a TTL-aware positive/negative cache backed by `util::ExpiringCache` (time-based expiration only).

### Technical Impact

- **Full RFC 3263 SIP server location** (the `S`/`A`-flag subset): `NAPTR`→`SRV`→`A`/`AAAA` with owner-name-delimited ordering — transport tier (NAPTR preference, or direct-SRV transport rank), then SRV priority, then RFC 2782 weighted-random ordering **within each owner name** applied to the whole failover list.
- **Security-hardened parsing**: loop-bounded name decompression (a visited-pointer set caps decompression work), enforced 63-byte label / 253-octet name limits, and a per-session TCP buffer cap that closes abusive sessions.
- **Non-blocking application integration**: a best-effort cancellable async API delivered through `std::future` or a raw callback, with atomic double-delivery guards.
- **TTL-correct caching**: cache lifetime is the minimum record TTL across the response (RFC 1035); NXDOMAIN and NODATA negatives are cached at the SOA `minimum` per RFC 2308, and only when an SOA is present (RFC 2308 §5).
- **Bounded worst-case latency for SIP**: an opt-in per-resolution deadline (`DnsConfig::maxResolutionTime`, or a per-call override) caps the serial NAPTR→SRV→A/AAAA chain so a blackholed server set cannot push resolution past SIP Timer B/F (64·T1 = 32 s); off by default, so existing behavior is unchanged (§3.3).

### `NameResolver` vs `DnsClient` (boundary)

NameResolver (name_resolver.hpp) vs DnsClient (dns_client.hpp). NameResolver is a single-shot host->socket-address helper that wraps the OS stub resolver (::getaddrinfo) and runs it off the I/O thread on blockingIoPool(), handing back an RAII addrinfo chain (OwnedAddrInfo) ready for an immediate connect(). It answers exactly one question -- 'which socket addresses back this host:port right now, per the system resolver?' -- and is an INTERNAL step of Transport's named-host connect path; applications do not call it directly. ('Async' here means off the caller/I/O thread; the resolution itself is a blocking getaddrinfo on a pool thread, not a non-blocking DNS-protocol implementation.) DnsClient is a standalone client that speaks the DNS wire protocol directly for a fixed set of record types -- A, AAAA, CNAME, MX, TXT, PTR, SRV, NAPTR (dns_client.hpp:181) -- plus RFC 3263 service discovery (NAPTR->SRV->A/AAAA, dns_client.hpp:182,303), exposed as synchronous, callback-async, and cancellable-future (AsyncDnsRequest) APIs, and consumed directly by application code (e.g. http_client.hpp). IMPORTANT -- the two consult DIFFERENT resolution stacks and can return different answers: NameResolver/getaddrinfo honors /etc/hosts, NSS ordering, and resolv.conf search/ndots options; DnsClient reads only the nameserver entries from /etc/resolv.conf and queries them directly (no /etc/hosts, no search-list processing), falling back to public resolvers 8.8.8.8/1.1.1.1 if none are configured -- so in split-horizon / internal-DNS deployments (common for SIP/SBC) the two can disagree, and DnsClient can bypass /etc/hosts overrides or leak to public DNS on a misconfigured host. Rule of thumb: connecting a Transport to a hostname -> NameResolver does it for you (internal, getaddrinfo, system resolution semantics); need DNS records or SIP/HTTP SRV service-location as data -> use DnsClient (direct DNS client). The record-type list alone proves they are different tools: MX/TXT/NAPTR/SRV are impossible via getaddrinfo, so DnsClient is not a NameResolver wrapper.

---

## 2. System Architecture

### Component Relationships

`DnsClient` owns the four backing components by `shared_ptr` and (re)creates them in `initialize()`:

```
DnsClient  (dns_client.hpp:206)
  _config       : dns::DnsConfig                       // value; the live configuration
  _cache        : shared_ptr<dns::DnsCache>            // null when _config.enableCache == false
  _transport    : shared_ptr<dns::DnsTransport>        // owns the wire layer + timers
  _resolver     : shared_ptr<dns::DnsResolver>         // RFC 3263 engine; holds _transport + _cache

  dns::DnsResolver (dns_resolver.hpp:387)
    _transport     : shared_ptr<dns::DnsTransport>     // shared with DnsClient
    _cache         : shared_ptr<dns::DnsCache>         // shared with DnsClient (may be null)
    _config        : const dns::DnsConfig              // immutable after ctor
    _rng           : std::mt19937                       // weighted SRV selection (seedable, _rngMutex)
    _serverRotation: std::atomic<size_t>               // next-server-failover start-server cursor (§3.3)

  dns::DnsTransport (dns_transport.hpp:101)
    _config       : core::AtomicSharedPtr<const DnsConfig>      // atomic-published live config (INV-2)
    _udpTransport : core::AtomicSharedPtr<Transport>   // Transport::udp(config) — created for mode UDP/Both
    _tcpTransport : core::AtomicSharedPtr<Transport>   // Transport::tcp(config) — created for mode TCP/Both
    _pendingQueries : map<QueryKey, shared_ptr<PendingQuery>>   // guarded by _queriesMutex
    _timerService : core::AtomicSharedPtr<core::TimerService>   // "DnsRetryTimer" — retries + timeouts
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
        Resolver->>Resolver: pin getConfig() snapshot; pick rotating start server
        loop next-server failover (each server at most once, §3.3)
            Resolver->>Transport: query(question, server.addr, server.port)
            Transport->>Transport: generateUniqueQueryId(); build QueryKey(id,server,port)
            Transport->>Engine: sendUdpQuery (DnsMessage::buildQuery)
            Engine->>Server: UDP query
            Server-->>Engine: UDP response (bytes)
            Engine->>Transport: onData (I/O thread)
            Transport->>Transport: DnsMessage::parse -> processResponse
            alt truncated (TC) and mode == Both
                Transport->>Engine: sendTcpQuery (retry over TCP, SAME server)
                Engine->>Server: TCP query
                Server-->>Engine: TCP response
            end
            Transport-->>Resolver: DnsResult / DnsNetworkException / DnsTimeoutException
            note over Resolver: server-local (rcode or timeout/network) -> next server;<br/>authoritative negative or success -> stop
        end
        Resolver->>Cache: cacheQueryResult(question, terminal result)
    end
    Resolver-->>Client: DnsResult
    Client-->>App: vector<SrvRecord> (or throws; see §3.1 Error surfacing)
```

### Threading Model

| Thread | Responsibility |
|---|---|
| **Caller thread** | Runs the synchronous accessors (`resolveA`/`resolveSRV`/`query`/…); blocks on `std::future::wait_for` inside `DnsTransport::queryMultiple` (`dns_transport.hpp:1160`). Immediate submission errors invoke the async callback here, **before `resolveA` returns**: no transport (`dns_client.hpp:1165-1170`), transport not running (`dns_transport.hpp:1190-1194`), registration refused because a `stop()` raced the submit (`:1230-1236`), or a send/connect failure (`:1250-1260`). A cache hit (positive or negative) in `DnsClient::queryAsync` also calls back here. |
| **Thread calling `stop()`** | `DnsTransport::stop()` fails every still-pending query with `DnsTransportException("Transport stopped")` from the stopping thread (`dns_transport.hpp:1046-1047`) — the destructor of `DnsClient`, `updateConfig`/`setDnsServers`/…, or an explicit `stop()`. |
| **Transport engine I/O thread** | Owned by the two `Transport` engines. Delivers normal DNS responses: `onData` → `DnsMessage::parse` → `processResponse` → `completeQuery` → user callback. |
| **`DnsRetryTimer` (TimerService) thread** | Fires the per-query timeout callback, which drives retransmissions (claims the retry and schedules the backoff re-send via `retryQuery`) and, on the last attempt, the terminal timeout completion (§3.4). A timeout's user callback runs here. |
| **Cleanup thread** (`_cleanupThread`) | A 10-second orphan-only backstop (`cleanupExpiredQueries`) that FAILS (never retries) queries left orphaned — expired AND with no live timer (e.g. a reschedule rejected during drain); those completion callbacks run here. |

**Consequence for callers:** an async callback (or the promise behind a `CancellableFuture`) may run on the caller's own thread before the submitting call returns, on the thread that calls `stop()`, or on any of three internal threads — the engine I/O thread, the `DnsRetryTimer` thread, or the cleanup thread. Callbacks must be thread-safe, and **must not take a lock the caller holds across `resolveA`/`queryAsync`** — on the caller-thread path that is a self-deadlock (or undefined behavior for a non-recursive `std::mutex`). The header lists the caller/transport/timer cases on `DnsClient::resolveA(host, cb)` (`dns_client.hpp:502-506`).

---

## 3. Component Deep Dive

### 3.1 `DnsClient` (façade)

`DnsClient` is a thin, ownership-holding façade over the resolver. It is **move-only** (`dns_client.hpp:274-279`: copy deleted, move defaulted) because it owns transport threads.

**Construction and lifecycle.** Both constructors (default, and one taking a `dns::DnsConfig`) call `initialize()`, which: creates `_cache` iff `_config.enableCache` — seeding its default TTL from `_config.cacheTimeout` (else resets it); constructs `_transport` from `_config`; constructs `_resolver` from `(_transport, _cache, _config)`; and starts the transport, wrapping any start failure in `dns::DnsResolverException`. `start()` is a no-op that returns `true` (the transport is already started in the constructor); the destructor calls `stop()`, which stops the transport threads.

**Synchronous accessors.** Each typed accessor issues one `query()` and unpacks the typed record vector, throwing `dns::DnsNoRecordsException` when the corresponding vector is empty (which, because `query()` already throws for an empty answer section, happens only when the answer section is non-empty but holds no record of the asked type — for example a CNAME-only answer). See **Error surfacing** below:

- `resolveA` / `resolveAAAA` → `std::vector<std::string>` of address strings.
- `resolveSRV` → `std::vector<dns::SrvRecord>`; `resolveNAPTR` → `std::vector<dns::NaptrRecord>`.
- `resolveMX` / `resolveTXT` → the typed record vectors; `resolveCNAME` → canonical names; `resolvePTR` → hostnames.
- `resolveHost` (`dns_client.hpp:245`) is the exception: it swallows per-family failures and returns a `HostResult{ipv4, ipv6, success}` where `success` is "at least one family resolved".

**Reverse DNS.** `resolvePTR` builds the query name via `createReverseQuery` (`dns_client.hpp:1035`): IPv4 → dotted-octet-reversed `in-addr.arpa`; IPv6 → `createIpv6ReverseQuery` (`:937`) which strips brackets/zone, expands `::` to the full 32-nibble form via `expandIpv6Address` (`:973`), then emits the nibble-reversed `ip6.arpa` name. A malformed address throws `dns::DnsResolverException`.

**Service discovery** delegates straight to the resolver: `resolveServiceDomain` / `resolveServiceDomainAsync` / `resolveCustomServiceDomain[Async]`. The SIP-named `resolveSipDomain[Async]` are thin, `\deprecated` forwarders to the service-domain methods (`dns_client.hpp:760`, `:772`).

**Cancellable async.** The façade adds the future-based ergonomics the resolver lacks:

- `resolveA(host, callback)` → `AsyncDnsRequest` (the primary async path; the sole out-of-line definition, `dns_client.hpp:1157`).
- `resolveAAsync(host)` → `CancellableFuture<std::vector<std::string>>`.
- `resolveServiceDomainFuture(domain, …)` → `CancellableFuture<dns::ServiceResolutionResult>`.

These wrap the resolver's callback API in a `std::promise`, guarding against double-set with a shared `std::atomic<bool>` (`promiseSet`) compare-exchange. `resolveAInternal` (`dns_client.hpp:1068`) adds a second guard, `RequestState::deliveryAttempted`, so exactly one thread enters delivery even if response and timeout race. Within that single delivery, the raw `resolveA(host, callback)` path is now a strict exactly-once **funnel**: every branch (cancelled / transport-error / no-records / success) builds its result and converges on **one** `callback(...)` invocation outside any `try`, so a user callback that **throws** is **no longer** re-invoked — the throw propagates once into the transport's own `catch(...)` (swallowed, not `std::terminate`), and completion is still published via a `noexcept` scope-exit guard that fires on the exceptional unwind. One caveat remains: the immediate-error branch of `resolveA` can throw `std::bad_function_call` without invoking the callback at all (§10, Open — P1, tracked `coding_trackers:tasks/iora/backlog/2026-09-24-32_dnsclient-resolvea-callback-moved-then-invoked_P1.json`).

**Error surfacing.** `DnsResult::isSuccess()` is `rcode == NOERROR && ancount > 0` (`dns_types.hpp:381`). With next-server failover (tracker `2026-09-25-8`, §3.3), `DnsResolver::query` walks all configured servers and its thrown type depends on WHERE the walk ends — an authoritative negative stops it, a server-local condition rotates and, on exhaustion, throws the transient-preserving type. This table is for the **record-level accessors that surface `query()` directly** — `resolveA`/`resolveAAAA`/`resolveSRV`/`resolveNAPTR`/`resolveMX`/`resolveTXT`/`resolveCNAME`/`resolvePTR` (and `query()` itself). The wrapper accessors `resolveHostname` and `resolveServiceDomain` REMAP these (see below the table):

| Server answer (across ALL configured servers) | Record accessor throws | `getResponseCode()` |
|---|---|---|
| An **authoritative** negative from any server — stops rotation — i.e. a recursed/authoritative (`RA` or `AA`) **NXDOMAIN**, or an authoritative **NODATA** (NOERROR + no answers that either carries an **SOA**, *or* — from a recursed/authoritative (`RA`/`AA`) server — has **no NS records**; RFC 2308 §2.2) | `DnsResolutionFailedException` | `NXDOMAIN` / `NOERROR` |
| **Server-local on every server** (exhausted): SERVFAIL / REFUSED / NOTIMP / FORMERR / any other error rcode; a **NODATA referral** (NS present, no SOA); a **LAME** reply (`RA=0 ∧ AA=0`) NXDOMAIN or empty-authority NODATA; a **truncated** (TC=1) response that could not complete over TCP (RFC 2181 §9 — never authoritative); OR a timeout / connect / send fault | `DnsTransientResolutionException` | last server-local rcode (SERVFAIL for a thrown fault) |
| NAPTR query answered NOTIMP/FORMERR (Q5, surfaced by `resolveNAPTR`) | `DnsNaptrUnsupportedException` | that rcode |
| NOERROR, answers present but none of the asked type | `DnsNoRecordsException` | `NXDOMAIN` (hard-coded) |
| Lifecycle fault (transport not running/stopped, no servers configured, UDP/TCP transport unavailable) | `DnsTransportException` (base — not `DnsNetworkException`) | — (not a `DnsResolverException`) |
| A name that cannot be encoded (label > 63 bytes / name too long): `DnsMessage::encodeName` throws before send (record accessors do NOT pre-validate) | `DnsParseException` | — (not a `DnsResolverException`) |

`DnsTransientResolutionException`, `DnsResolutionFailedException`, `DnsNoRecordsException` and `DnsNaptrUnsupportedException` are all `DnsResolverException` subtypes; `DnsNetworkException` (a per-server network fault: connect/send/query-ID-exhaustion/session-close) is a `DnsTransportException` subtype but is consumed by the failover walk and does not normally escape the resolver accessors — it surfaces (as the last server-local hop) folded into the `DnsTransientResolutionException` above.

**Wrapper accessors remap the above** (they do NOT throw the leaf types directly):
- **`resolveHostname`** validates the name first (`validateHostname`: a label > 63 bytes or a name > 255 chars → `DnsResolverException("Invalid hostname")` up front, before any query). It then catches per family and, if the combined result is empty, throws `DnsTransientResolutionException(host)` (rcode hard-coded SERVFAIL) when any family was server-local-exhausted, else `DnsNoRecordsException` (rcode NXDOMAIN) for any other empty result — an authoritative negative, an absorbed terminal lifecycle fault, OR a name in the narrow 254–255-char window (passes `validateHostname`'s ≤255 presentation-char check but `encodeName` rejects a wire-encoded form > 253 octets, so it hits the absorbing per-family catch — the length-mismatch edge tracked `2026-09-30-2`). So `resolveHostname` never surfaces `DnsResolutionFailedException`, a bare `DnsTransportException`, or a `DnsParseException`.
- **`resolveServiceDomain`** returns a `ServiceResolutionResult` and reports failure via `outcome` (Resolved / TransientFailure / PermanentNoService), not by throwing — every NAPTR/SRV/A-AAAA step exception (including lifecycle and parse) is caught and either falls forward or is folded into `outcome`. It throws only the up-front `DnsResolverException("Invalid hostname")` for an invalid domain.

The raw callback fast-path (`resolveA(host, cb)`, which calls `DnsTransport::queryAsync` directly and bypasses the resolver, its cache, AND its failover — §3.3) differs: any response without A records — NXDOMAIN, NODATA, SERVFAIL — arrives as `DnsNoRecordsException` with `getResponseCode() == NXDOMAIN`, so the real rcode is lost and no failover occurs.

### 3.2 `AsyncDnsRequest` and `CancellableFuture<T>`

`AsyncDnsRequest` (`dns_client.hpp:37`) is a cancellation handle over a shared `RequestState` — three `std::atomic<bool>` flags (`cancelled`, `completed`, `deliveryAttempted`) plus the queried `hostname`. `cancel()` does `cancelled.exchange(true, acq_rel)` and returns whether *this* call flipped it — it does not look at `completed`, so the header's "false if already completed" (`dns_client.hpp:48`) is wrong (Open — P1, tracked `coding_trackers:tasks/iora/backlog/2026-09-25-9_dns-async-cancel-teardown-transport-api_P1.json`). Cancellation does **not** suppress the raw callback: nothing removes the pending query, so the callback is **always invoked exactly once** (barring the `std::bad_function_call` path in §10) — with the real result if delivery claimed `deliveryAttempted` before `cancel()`, otherwise with `DnsResolverException("DNS request cancelled")` when the response, timeout, or `stop()` eventually arrives (the single raw-callback funnel `dns_client.hpp:1148`, whose cancelled branch builds the exception at `:1111-1114`). (Proactive teardown of the pending query on `cancel()` — so a cancelled query stops retransmitting — is a separate open item, tracked `coding_trackers:tasks/iora/backlog/2026-09-25-9_dns-async-cancel-teardown-transport-api_P1.json`.) Anything the callback captures must therefore outlive the request (capture a `shared_ptr`/`weak_ptr`, never a stack reference). The header calls this "best-effort" (`:43-45`).

`CancellableFuture<T>` (`dns_client.hpp:106`) pairs a `std::future<T>` with the request handle and the shared promise + `promiseSet` guard. Its `cancel()` (`:120`) cancels the request and, if it wins the `promiseSet` CAS, immediately sets the promise to a `dns::DnsResolverException("DNS request cancelled")` so a thread blocked in `future.get()` wakes without waiting for the network timeout. `cancel()` returning `true` does **not** imply `get()` throws: a delivery that won the `promiseSet` CAS first has already set the value (or the real error), and `get()` returns it.

### 3.3 `dns::DnsResolver` (RFC 3263 engine)

The resolver turns questions into results and orchestrates the service-location chain. It reads `addressResolutionPolicy` and now **owns server selection during a lookup** (next-server failover — see the subsection below), pinning one `getConfig()` snapshot and iterating the configured servers itself; it still defers per-server retry/timeout/backoff to the transport.

**`query` / `queryAsync`** are the record-level primitives: consult `_cache` (if present), else drive **next-server failover** over the pinned server snapshot — the sync `query()` is a bounded loop calling `_transport->query(question, addr, port)` per server; `queryAsync` uses `queryAsyncWithFailover` (see the failover subsection below) — then apply the cache-write policy via `cacheQueryResult` on the terminal result. That policy caches positive results, and negative results (NXDOMAIN and NODATA — NOERROR with no answers) **only when the response carries an SOA** (RFC 2308 §5: a negative without an SOA has no authoritative TTL to bound it, so it is not cached and is re-queried). `resolveHostname` implements `AddressResolutionPolicy`:

- Query `A` when policy ∈ {IPv4Only, IPv4First, IPv6First}; query `AAAA` when ∈ {IPv6Only, IPv4First, IPv6First}.
- Combine: IPv4Only → A only; IPv6Only → AAAA only; IPv4First → A then AAAA; IPv6First → AAAA then A.
- The legacy `prefer_ipv6 == true` bumps `IPv4First` to `IPv6First` for backward compatibility. Empty result throws `dns::DnsNoRecordsException`.
- Each per-family `query()` is wrapped so partial results survive: a `DnsTransientResolutionException` (that family's servers all server-local-exhausted) sets an `anyTransient` flag; an authoritative `DnsResolverException` is skipped; a terminal lifecycle `DnsTransportException` or a `DnsParseException` (unencodable name) is absorbed — none discards the OTHER family's already-resolved addresses (fixed by slice a1 `2026-09-24-29`, landed, + failover `2026-09-25-8`). If the combined result is empty, the terminal throw preserves the transient/permanent distinction: `DnsTransientResolutionException` when any family was transient, else `DnsNoRecordsException`.

**Service resolution — `resolveServiceDomain`** (`dns_resolver.hpp:443`) drives `performServiceResolution` (`:2151`):

1. **NAPTR query** the domain (with next-server failover). **Every** NAPTR-step failure falls forward to the same `performDirectSrvResolutionImpl(domain, …, nullopt, secure, deadline)` — only the reason differs: a `DnsResolverException` (an authoritative NXDOMAIN/NODATA, a `DnsTransientResolutionException` after all servers were server-local, or a `DnsNaptrUnsupportedException` for NOTIMP/FORMERR, Q5), a terminal lifecycle `DnsTransportException`, and an unencodable-name `DnsParseException` are **all** caught at the NAPTR step and fall back to direct-SRV (a per-server timeout/network fault rotates and reaches this catch only as the transient after exhaustion). The only thing that escapes `performServiceResolution` is a `std::bad_alloc`-class throw from `processNaptrRecords` (step 2), which is deliberately not wrapped ("let real bugs propagate"). If NAPTR succeeds but yields no usable target, the same direct-SRV fallback runs (sync and async behave identically here).
2. `processNaptrRecords` sorts by `order` then `preference` and processes NAPTR records in **ascending `ORDER`**, advancing to the next `ORDER` tier only when the current one yields no usable target and stopping at the first tier that does (RFC 3403 §4.1/§8 DDDS ordering). Within the chosen tier it maps each service string via `parseServiceType`, applies the transport discard, validates the replacement, and splits into `S`-flag SRV targets and `A`-flag direct targets. The discard runs on **both** `S`- and `A`-flag records and depends on `secure`: for a **secure** resolution it keeps only `isSecureSipService(service)` **and** (when `preferredTransports` is non-empty) a supported transport — unconditionally, so a non-SIP service (e.g. a `parseServiceType`-recognized `HTTPS+D2T` record — encrypted but not SIP) or an unsupported SIPS transport is dropped (RFC 3263 §4.1); for plain `sip:` it keeps only supported transports when `preferredTransports` is non-empty (empty = permissive). **`U`-flag (ENUM/regexp, RFC 6116) and empty-flag (chained NAPTR) records are intentionally skipped.**
3. For each `S` target, **SRV query** the replacement (with next-server failover) and append `ServiceTarget`s carrying the NAPTR preference; a failing SRV set is skipped so the siblings continue (RFC 3263 §4.3) — a `DnsTransientResolutionException` (all servers server-local) additionally sets `anySrvTransient`, while an authoritative negative, a lifecycle `DnsTransportException`, and an unencodable-name `DnsParseException` are plain skips. A per-server timeout/network fault rotates rather than aborting. If, after the whole `S`/`A` NAPTR tier, **no target at all** was produced (`noTargetsBeforeAddr`), the shared **empty-avenue policy** (`resolveEmptySrvAvenue`, identical to the direct-SRV path so the two cannot drift) decides: if `anySrvTransient`, suppress any fallback and carry `TransientFailure` — a transient is not proof of absence (tracker `2026-09-30-4` M-4); otherwise take the RFC 3263 **§4.2** fallback *principle* (A/AAAA of the **domain** at the default port) extended to the NAPTR-chosen transport(s), honoring any RFC 2782 "." suppression (tracker `2026-09-30-4` H-3 — the pre-fix code wrongly cited §4.1 and performed no NAPTR-S fallback). The §4.2 fallback targets keep NAPTR-preference order and are **not** re-sorted (matching the async path).
4. For each `A` target, synthesize a `ServiceTarget` directly (no SRV): `port = getDefaultServicePort(service)`, `priority = weight = 0`, `naptrPreference =` the record's NAPTR preference field.
5. `resolveTargetAddresses` resolves every target through `resolveHostname` (so `addressResolutionPolicy` applies) and drops those with no addresses; `resolveHostname` absorbs per-family transport/parse errors and keeps partial results, so a failing lookup yields a target with fewer/no addresses (then dropped) rather than aborting the whole resolution. **The async path now honors `addressResolutionPolicy` identically:** `resolveTargetAddressesAsync`, `performFallbackResolutionAsync`, and the cache-hit `processCachedServiceResolution` all issue the policy's families and order the per-target address list byte-identically to `resolveHostname` — **both** families for `IPv4First`/`IPv6First` (in policy order; no longer "AAAA only if A returned nothing"), the single family for `IPv4Only`/`IPv6Only`. The two families are issued **strictly sequentially per target** (the second from inside the first's callback), which preserves the fan-out completion-latch invariants with no new synchronization (tracker `2026-09-25-5`, landed iora `bda1c10`). The fresh async chain still calls `DnsTransport::queryAsync` directly, so a *fresh* async resolution does not populate the record cache (the async service **cache-hit** path — a prior sync resolution having warmed it — does read it via `processCachedServiceResolution`); the fresh-async cache-population behavior is unchanged and out of scope for the policy fix.
6. `sortTargetsByPriority` orders the failover list **per SRV owner name**: it stable-sorts by `(naptrPreference, transport, priority)` — so SRV `priority` is never compared across different transports (here `transport`, the `ServiceType`, is a 1:1 proxy for the SRV owner name in the standard SIP mapping, so this is per-RRset per RFC 2782; two NAPTR records sharing preference *and* service but pointing at different SRV owner names — an unusual/misconfigured zone — would group across RRsets, tracked `2026-09-25-14`) — then applies RFC 2782 weighted-random ordering to each equal-`(naptrPreference, transport, priority)` group (repeated running-sum selection-without-replacement, remaining sum recomputed each step, uniform `[0,sum]` inclusive with first cumulative `>=`, weight-0 records placed first and shuffled among themselves for the "very small chance"; all-weights-0 → uniform). The per-call generator is seeded by **one advancing draw** of the resolver's `_rng` under `_rngMutex` (leaf lock), then the ordering runs unlocked (the draw is skipped when fewer than two targets exist).

**`performDirectSrvResolution`** is the no-NAPTR (and no-usable-NAPTR) path: it builds its SRV query set in `buildOrderedSrvQueries`. **For plain `sip:` (`secure=false`)** the default set is the standard SIP SRV names (`_sips._tcp`, `_sip._tcp`, `_sip._udp`, `_sip._sctp`): a **non-empty** `preferredTransports` is treated as the client's **supported set** and now **filters** the default set — a published transport not in the set is **discarded** (not merely trailing) — then orders it by preference; an **empty** `preferredTransports` stays permissive (all four queried). **For a secure resolution (`secure=true`)** the default set is instead **built by owner-name mapping** — each supported secure SIP transport maps to its `_sips._<proto>` owner name (`SIPS_TLS`→`_sips._tcp`, `SIPS_SCTP`→`_sips._sctp`, `SIPS_WSS`→`_sips._wss`; default `_sips._tcp`; never `_sips._udp`) — note `_sips._wss` is a pragmatic extension, **not** standardized: RFC 7118 defines no SRV owner name for SIP-over-WebSocket, which is discovered via NAPTR (`SIPS`+`D2W`), so a strict RFC 7118 deployment will publish no `_sips._wss` SRV; `_sips._sctp` (SIPS-over-SCTP) is likewise unstandardized (RFC 3263 §4.1 enumerates only SIPS+D2T, i.e. `_sips._tcp`, as the standardized SIPS SRV owner name) — and a caller-supplied **custom** SRV set is filtered to secure SIP services; no plaintext SRV name is ever queried (RFC 3263 §4.1). Each SRV set's position in the `buildOrderedSrvQueries` order is stamped as its targets' `naptrPreference` (the per-set transport rank), so `sortTargetsByPriority` sequences transports **per set** and applies SRV priority (and weight) only **within one owner name** — it no longer compares a `_sip._udp` priority against a `_sips._tcp` priority across RRsets (fixed by tracker `2026-09-25-4`). A **secure** resolution (`secure=true`) that finds no SRV target falls back through `fallbackTransports`, which **filters the transport list to secure SIP services then defaults to `SIPS_TLS`** (TLS, default port 5061 — RFC 3261 §19.1.1) — it never emits a plaintext fallback target (the SIPS service discard is RFC 3263 §4.1; this A/AAAA-at-default-port fallback itself is §4.2); and a `discardInsecure` belt at `sortTargetsByPriority` erases any non-SIPS-SIP target that reaches the delivery paths (defense in depth over the primary query/NAPTR filters). So a `sips:` caller passing `secure=true` gets an already-secure result and no longer needs to post-filter with `getTargetsForTransport` (tracker `2026-09-25-12`, slice b2, landed). SRV queries that fail — with `DnsResolverException`, `DnsTransportException`, or `DnsParseException` — are each skipped so one failing SRV set never aborts the others (`dns_resolver.hpp:1700-1724`, RFC 3263 §4.3 per-record isolation; the async path is likewise non-aborting). The bare-domain A/AAAA fallback (`performFallbackResolution`) resolves via `resolveHostname`, which now absorbs per-family transport/parse errors and preserves the transient/permanent signal into the sync `ServiceResolutionResult::outcome` (a wiped-out fallback yields `TransientFailure` if any family was server-local-exhausted, else `PermanentNoService`), so a fallback timeout no longer aborts abnormally. An SRV RRset whose target is the root `.` (RFC 2782 "service decidedly not available") is skipped and marks that **service** denied. If no targets result, it calls `performFallbackResolution`, which does a plain A/AAAA lookup of the bare domain and builds one target per preferred transport (defaulting to `SIP_UDP`) — **excluding any service a `.` explicitly denied** (per-service suppression, not domain-wide: a `_sips._tcp` `.` does not strand plain SIP reachable via a bare A record).

**RFC 2782 weighted selection.** The weighted-random ordering is applied to the **whole failover list at construction**, inside `sortTargetsByPriority` (above), not deferred to a single-target pick. Consequently `ServiceResolutionResult::getPreferredTarget` — all three overloads (the const overload, `getPreferredTargetWithDefaultRng`, and the caller-RNG template) and the resolver-level `getPreferredTarget(result)` — now simply return the already-ordered **head** (`targets.front()`); they no longer re-randomize (that would double-order the list) and the RNG argument on the template overload is unused. The RNG lives at the list-ordering site: `sortTargetsByPriority` takes one advancing draw of the resolver's seedable `_rng` (`setRngSeed`) under `_rngMutex` (a leaf lock) and orders on a per-call local generator. The previous single-pick cumulative walk over `uniform_int_distribution<uint32_t>(0, total_weight-1)` with a strict `<` — which gave weight-0 records **zero** selection chance — has been removed; the list-level algorithm uses the RFC-correct inclusive `[0,sum]` draw with first cumulative `>=`. A hand-built `ServiceResolutionResult` not produced by the resolver is returned head-first as-is (an unweighted pick), since ordering happens at resolver construction time.

**Async service resolution** (`performServiceResolutionAsync`) mirrors the sync chain but fans SRV queries out in parallel, coordinating completion with a shared `std::atomic<size_t> remainingQueries` (`fetch_sub(acq_rel)`), an `std::atomic<bool> callbackFired`, a `std::mutex resultMutex`, and a shared `deniedServices` vector; the last query to finish triggers async address resolution and fires the callback exactly once.

#### Next-server failover (RFC 1035 §7.2) and the transient/permanent outcome (tracker `2026-09-25-8`)

The resolver OWNS server selection during a lookup and fails over across **all** configured servers, so a single failing server no longer abandons the query (superseding the old per-query-round-robin behavior).

- **Detection gate — by delivery channel then identity.** A completion is classified as either an AUTHORITATIVE negative (STOP rotation) or SERVER-LOCAL (rotate):
  - *Rcode-bearing result* (`isAuthoritativeNegative`, tracker `2026-09-30-4` H-1/M-2/F-3/F-4): authoritative → **stop**; otherwise server-local → **rotate**. A **truncated** (TC=1) response is **never** authoritative (RFC 2181 §9 — its sections may be incomplete), regardless of rcode. An **NXDOMAIN** is authoritative only from a recursed/authoritative server (`RA || AA`); a LAME `RA=0 ∧ AA=0` NXDOMAIN rotates. A **NODATA** (NOERROR + no answers) is authoritative when the response carries an **SOA**, *or* has **no NS records** (a type-3 empty-authority NODATA, from a recursed/authoritative server) — RFC 2308 §2.2 ("SOA present … OR absence of NS records"); a **referral** (NS present, no SOA) rotates, as does a LAME empty-authority reply. SOA-gating is a **caching**-only concern (RFC 2308 §5), NOT the authority test — the pre-fix SOA-*only* gate mis-classified the common dnsmasq/GSLB empty NOERROR as a retryable outage. `SERVFAIL`, `REFUSED`, `FORMERR`, `NOTIMP`, and any other error rcode are server-local → rotate.
  - *Thrown/delivered exception, by TYPE:* `DnsTimeoutException` and the new **`dns::DnsNetworkException`** (a `DnsTransportException` subtype now thrown at the connect/send-failure sites, on per-server query-ID exhaustion, and on the `handleClose` "session closed before connect / with in-flight query" deliveries — which fail whatever query was bound to that session, sync or async) are server-local → rotate; a **lifecycle** `DnsTransportException` ("Transport not running", "Transport stopped", "No questions provided", "No DNS servers configured", "UDP/TCP transport not available") and `std::bad_alloc` are terminal → no rotation. Discriminating by *type* (not a `what()` substring) is why `DnsNetworkException` exists; the initial-send, retransmit-timer, and TCP-fallback completion sites all deliver `std::current_exception()` so the derived type survives to the gate.
  - **NAPTR Q5:** a NAPTR query answered `NOTIMP`/`FORMERR` means "NAPTR unsupported" and falls STRAIGHT to direct-SRV **without** rotating servers (they are likely the same infra); NAPTR still rotates on SERVFAIL/REFUSED/timeout. **Trade-off (human-affirmed):** treating `FORMERR` as "unsupported, don't rotate" is deliberate, but it has a failure mode — if the configured servers genuinely differ in capability, a `FORMERR` from the *first* server short-circuits to direct-SRV instead of trying a NAPTR-capable peer. Concretely, with the default `{8.8.8.8, 1.1.1.1}` a NAPTR-only carrier/ITSP domain becomes unreachable if the first resolver `FORMERR`s the NAPTR query (direct-SRV then finds no `_sip._*` records). Deploy NAPTR-dependent domains behind NAPTR-capable resolvers.
- **Server selection.** One `_transport->getConfig()` snapshot is pinned per failover chain; a resolver-owned `std::atomic` cursor picks the rotating start server; the loop then iterates the remainder in cyclic order, contacting each server at most once (address **and** port passed explicitly; `getNextServer()` is never used). TC=1 truncation remains a **same-server** UDP→TCP fallback, not a failover trigger — though a connect/send failure on that TCP fallback itself completes with `DnsNetworkException` and so does rotate. **Empty server list:** the sync leaf throws the terminal `DnsTransportException("No DNS servers configured")` while the async helper delivers `DnsTransientResolutionException` (→ `TransientFailure`); an empty snapshot is unreachable in practice because `DnsTransport`'s ctor and `DnsTransport::updateConfig` both reject an empty server list (a `DnsConfig` may itself hold an empty `servers` vector, but the transport that pins the snapshot never carries one), so this is a defensive-only asymmetry.
- **Sync vs async.** The sync path is a bounded next-server loop at the `query()` leaf. The async path routes every issue site through `queryAsyncWithFailover`, whose per-issue atomic-CAS handshake (`HANDOFF_PENDING`/`CB_ADVANCE`/`ISSUER_DONE`, acq_rel) resolves "issuer advances vs completion-callback re-enters" at one ordered point — exactly-once terminal delivery, no lost wakeup, no deep recursion (a synchronous completion advances via the loop; a genuine async one re-enters once per hop). The helper never propagates a throw (load-bearing for the no-backstop A/AAAA `finishTarget` latch).
- **Which entry points fail over.** Everything that goes through `DnsResolver`: the sync record accessors and `resolveHostname`, `resolveServiceDomain`/`resolveServiceDomainAsync` (and its `CancellableFuture` wrapper `resolveServiceDomainFuture`, which drives the async service resolution → does fail over), and the resolver's own `query`/`queryAsync`. The **exception** is the `DnsClient` raw async A fast-path — `resolveA(host, callback)` and its `CancellableFuture` wrapper `resolveAAsync` — which calls `DnsTransport::queryAsync` **directly**, bypassing the resolver, so it does **not** fail over (it uses the transport's per-query round-robin, `getNextServer()`). This sync-vs-async asymmetry on the façade's raw A path is out of Slice A's scope (the tracker covers the resolver's issue sites) and is tracked as a follow-on (`coding_trackers:tasks/iora/backlog/2026-09-30-2_dns-servfail-failover-followups_P1.json`). To get failover for a bare A lookup, use the sync `resolveA(host)` or `queryAsync(DnsQuestion{host, DnsType::A})`.
- **Transient vs permanent signal.** `ServiceResolutionResult::outcome` (additive `dns::ResolutionOutcome`, default `Resolved`; `isSuccess()` unchanged) carries `TransientFailure` (all servers exhausted server-local → retryable) vs `PermanentNoService` (authoritative negative). `resolveHostname` signals the same across its throwing return channel: `dns::DnsTransientResolutionException` when any queried family exhausted its servers server-local, else `DnsNoRecordsException` for any other empty result (an authoritative negative, an absorbed terminal lifecycle fault, or an unencodable name); a sibling family's partial success is not overridden by a transient sibling. A terminal transport-lifecycle fault maps to `PermanentNoService` (documented on the enum; teardown-race edge). **SIP response mapping is the adapter's job, not this layer's** (`iora_sip` `SipDnsAdapter`, tracker `2026-09-25-2`), but the correct shape is: `TransientFailure` → **503** (only a 503 triggers RFC 3263 §4.3 upstream failover — not 504); `PermanentNoService` → **404** only when the resolved name equals the Request-URI domain, else 500/502 (and it also covers local teardown / SIPS-empty / unencodable-name, not just an on-wire negative); **never map a DNS failure to a 6xx** (RFC 3261 §16.7 — a 6xx cancels sibling forking branches). A **UAC** maps the failure to a local 503 (RFC 3261 §8.1.3.1); a **proxy** SHOULD NOT forward a blanket 503 upstream for one failed target (RFC 3261 §16.7 — an upstream §4.3 client would blacklist the whole proxy) — generate 500 (§16.7 / §21.5.1) or 504 (§21.5.5) and reserve upstream 503 for a condition affecting every request. **Scope:** this is the **terminal avenue's** per-avenue outcome; combining outcomes ACROSS the NAPTR→SRV→A/AAAA fall-forward chain (deepest-avenue-supersedes) is tracker `2026-09-30-1`.

Consequently a single server's SERVER-LOCAL failure never aborts an avenue: each avenue rotates through the configured servers first, and only an authoritative negative, a success, or full exhaustion ends it (a terminal lifecycle fault also ends it, without rotating).

#### Per-resolution deadline — the SIP Timer B/F bound (tracker `2026-09-30-3`, F-2)

Next-server failover made the serial RFC 3263 chain *correct* but not *bounded*: at defaults one blackholed server costs ≈ 25.85 s (§3.4, after the H-2 budget fix), so a two-server stall, or a long NAPTR→SRV→A→AAAA chain, can exceed the SIP transaction ceiling **Timer B** (INVITE) / **Timer F** (non-INVITE), both `64·T1 = 32 s` (RFC 3261 §17.1.1.2 / §17.1.2.2). The **per-resolution deadline** bounds the whole chain.

- **Opt-in, off by default.** `DnsConfig::maxResolutionTime` (`std::chrono::milliseconds`, default `0`) is **disabled** = byte-for-byte today's behavior. The public resolution entries `query`, `queryAsync`, `resolveHostname`, `resolveServiceDomain[Async]`, `resolveCustomServiceDomain[Async]`, and the typed accessors `resolveSRV`/`resolveNAPTR` also take a trailing `std::optional<std::chrono::milliseconds> deadlineOverride` — `nullopt` uses the config value, a value overrides it, and an explicit `0ms` disables the deadline **for that one call** (the `std::optional` exists precisely because a bare `0` collides with the config's `0 = disabled` sentinel). The `resolveServiceDomainFuture` wrapper and the other typed accessors (`resolveA`/`resolveAAAA`/`resolveCNAME`/`resolveMX`/`resolveTXT`/`resolvePTR`) have **no** per-call override — they honor only the config `maxResolutionTime`.
- **Computed once, threaded as a required parameter.** The public entry calls `computeResolutionDeadline(override)` to turn the budget into an **absolute** `steady_clock::time_point`, which is passed **down** every internal impl as a required, non-defaulted by-value parameter (never a resolver member — a member would let concurrent resolutions on the one long-lived resolver tear a non-atomic `time_point`). The internal impls **use** the given deadline and never recompute it; the public `query`/`resolveHostname` overloads delegate to private `queryImpl`/`resolveHostnameImpl` carrying the absolute deadline.
- **Budget semantics.** `== 0` → disabled (`time_point::max()` sentinel; the gate never fires). `> 0` → `now() + budget`, **saturating** back to disabled if `now() + budget` would overflow the `steady_clock` representation (`now() + ms::max()` is signed-overflow UB). `< 0` → a misconfiguration (most often a consumer computed `D = Timer_B/F − asyncAttemptBudget() − margin` and it underflowed): it **fails CLOSED** to an already-expired deadline, so every non-cached resolution returns `TransientFailure` (retryable) rather than running unbounded — and a one-shot `WARN` fires.
- **Sync = HARD bound.** `queryImpl` serves the cache first (a cache hit is returned even past the deadline), then — before the server loop and before each `_transport->query` issue — if `now() >= deadline` it throws `DnsDeadlineException(qname)` with **no** wire query; the resolver also passes `maxWait = clamp(deadline − now(), ≥ 1ms)` into `DnsTransport::query` so the one in-flight attempt is hard-capped at `min(calculateMaxSyncWaitTime, maxWait)` (the `time_point::max()` guard precedes any `deadline − now()` subtraction — `max() − now()` would overflow). On a genuine single-server **exhaustion** (the loop ends without the deadline firing) the leaf keeps its own `DnsTransientResolutionException(qname, lastServerLocalRcode)` — exhaustion is **not** converted to a deadline exception. Worst-case sync wall-clock ≈ the deadline.
- **Async = SOFT gate (choke point).** `queryAsyncWithFailover` is the single choke point (the only `_transport->queryAsync`). At the loop top, **before** an attempt is armed, two separate branches share the exactly-once `deliver()` funnel: `attempts >= n` delivers the exhaustion `DnsTransientResolutionException(qname, lastServerLocalRcode)`; `now() >= deadline` delivers `DnsDeadlineException(qname)`. The gate stops issuing *further* servers/families but **does not abort the one in-flight transport attempt**, so the async worst case is `deadline + one asyncAttemptBudget()` (the un-abortable overhang). "Cut both A and AAAA" needs no family gate: A/AAAA are issued strictly sequentially, so once the deadline passes, chaining the next family hits the deadline branch → a terminal `DnsDeadlineException` with zero wire queries → that family is marked transient → `finishTarget`. (The branches are kept separate so the OFF path, the per-server rcode fidelity, and sync/async parity are preserved.)
- **Expiry is always transient.** `DnsDeadlineException` **IS-A** `DnsTransientResolutionException`, so it needs no new catch site: every fall-forward `catch (const DnsResolverException&)` unwinds it, every outcome-setting `catch (const DnsTransientResolutionException&)` (ordered before the base handler) maps it to `TransientFailure`, `isTransientError()` is true, and `resolveHostname` folds it into `anyTransient`. A deadline is therefore **never** `PermanentNoService`, and sync == async.
- **Partial success is kept (human decision).** The deadline only STOPS issuing *more* work; it never discards targets already resolved. If a later target/family/avenue is cut while some target already resolved, those targets are returned as `Resolved` — **including the priority-inversion case**: a transiently-cut *higher*-priority target is dropped and a reachable *lower*-priority target is returned (RFC 2782 / RFC 3263 §4.3 "contact the lowest-priority target you can reach"; self-heals on the next resolution). **Sync-vs-async asymmetry:** the async path issues targets concurrently, so a fast backup resolves *live* while the preferred blackholes — async partial-Resolved needs no cache. The sync path resolves targets **serially before sorting**, so the deadline cuts the later target too; sync partial-Resolved is reachable **only** when the surviving lower-priority target is served by the cache-first check (its A/AAAA was pre-cached). A resolution that has resolved **zero** targets at expiry → empty targets + `TransientFailure`.
- **Sizing the deadline.** `DnsClient::asyncAttemptBudget()` (→ `DnsResolver` → `DnsTransport::asyncAttemptBudget(cfg)`) is a conservative **upper bound** on the un-abortable in-flight async issue. It is `udpAttemptBudget(cfg)` **plus** the TC=1→TCP-fallback leg (`timeout + cleanupInterval`, in the default `Both` mode only), where `udpAttemptBudget(cfg)` = `calculateMaxSyncWaitTime(cfg) − kSyncSafetyMargin` is the pure UDP-retransmit cost (one dead server's blackhole cost, used internally for the sub-budget warning). Size `D_safe ≤ Timer_B/F − asyncAttemptBudget() − margin` where the margin is pure slack: DNS resolution **precedes** the client transaction, so the transaction gets its own full Timer B *after* DNS (the two are additive, not shared). **Default-config caveat:** `asyncAttemptBudget()` is dominated by `timeout × (retryCount + 1)` and at the default config already **exceeds** Timer B — the per-server UDP budget alone (`udpAttemptBudget()`) is ≈ 23.85 s and `asyncAttemptBudget()` adds the TCP-fallback leg on top — so **no usable `D` fits at the default config**; a consumer that wants a deadline must first REDUCE `DnsConfig::timeout` / `retryCount`.
- **Known trade-off (failover-defeat below the per-server budget).** A deadline **smaller than one server's `udpAttemptBudget()`** means a single dead server can exhaust the whole deadline before the next server is tried, defeating RFC 1035 §7.2 next-server failover; the resolver `WARN`s once when it detects this. Per-server sub-budgeting (one-transmission-per-server-per-round, RFC 1035 §7.2) that would fix it is carved out to tracker `2026-09-30-5`.
- **Scope.** The URI short-circuits (a numeric-IP target, an explicit port, an explicit transport) bypass the server loop, so the deadline never spuriously fires on them. Aborting the *in-flight* async attempt (a hard async bound) and the §7.2 one-transmission-per-round cycling are out of this slice (→ `2026-09-30-5`); cross-step outcome aggregation and richer "partial" semantics are tracker `2026-09-30-1`.

### 3.4 `dns::DnsTransport` (wire transport)

`DnsTransport` must be owned by a `shared_ptr` — `start()` calls `shared_from_this()`, so a stack instance throws `std::bad_weak_ptr` (`dns_transport.hpp:108-112`). It instantiates the engine(s) the configured `transportMode` needs — `Transport::udp(config)` for `UDP`/`Both`, `Transport::tcp(config)` for `TCP`/`Both` — and wires their `onData`/`onConnect`/`onClose` callbacks, each captured as a `weak_ptr<DnsTransport>` promoted per-use to avoid a reference cycle.

**Query lifecycle.** `queryMultiple` (sync, `:1079`) and `queryAsync` (`:1187`) mint a unique 16-bit query ID (`generateUniqueQueryId`, `:2327`), build a `QueryKey{id, server, port}` (`:239`), register a `PendingQuery` under `_queriesMutex`, encode the request with `DnsMessage::buildQuery`, and send over UDP (or TCP per `transportMode`). The sync path then blocks on `future.wait_for(...)` bounded by `calculateMaxSyncWaitTime()` (capped by the F-2 `maxWait` when a per-resolution deadline is set — §3.3) (`:1160`). `start()` is at `:806`.

**Query-to-response matching** is by `QueryKey` — the `(queryId, server, port)` triple. Because the UDP and TCP engines mint colliding `SessionId`s, the response path maps a session back to its server via `_sessionToServer`, keyed by `(bool isTcp, SessionId)` (`:708`), preventing cross-engine confusion.

**UDP→TCP fallback** is truncation-driven, not size-driven: in `processResponse` (`:1819`) a UDP response with the `TC` flag set, when `transportMode == Both` and the query has not already fallen back, sets `tcpFallback = true` and re-sends over TCP. (`_config.maxUdpSize` is **not** consulted — see Known Limitations.)

**Retry / backoff / jitter.** The **per-query timeout timer is the sole retry driver** (tracker 2026-09-24-31). When the timeout of the current attempt fires, the timeout callback (`scheduleQueryTimeout`) CLAIMS a retransmission under `_queriesMutex` as one critical section — attempt-limit check, `retryCount` increment, `startTime` reset — then `retryQuery` re-sends to the **same** server with the **same query id** after an exponential-backoff idle delay `baseDelay = min(initialRetryDelay * retryMultiplier^n, maxRetryDelay)` (from the pre-increment attempt index `n`, so the first retry uses `initialRetryDelay`), with multiplicative jitter `× U(1 - jitterFactor, 1 + jitterFactor)` re-clamped to `maxRetryDelay` when `jitterFactor > 0`. Only after the last permitted attempt's timeout does the query complete with `dns::DnsTimeoutException`. So a query is sent up to `retryCount + 1` times (measured: `timeout = 250 ms`, `retryCount = 2`, silent server → **3 datagrams** to the same server with growing gaps, then one terminal `DnsTimeoutException`). See §10.

**Retransmission model (deliberate).** This is a **constant per-attempt timeout plus a separate inter-attempt backoff idle gap**: send → wait `timeout` → (on expiry) wait `baseDelay` → resend. `PendingQuery::timeout` is const, so every attempt waits the same `timeout`; the backoff grows the *gap between* attempts, not the per-attempt deadline. This is latency-inflating versus classic RFC 1035 §4.2.1 RTO-doubling (where the per-attempt timeout itself grows), and is a conscious choice: it keeps late-answer correlation simple (the reused query id means a slow answer to attempt *n* still matches) and bounds total wait via `calculateMaxSyncWaitTime()`. As of tracker `2026-09-30-4` (H-2), that per-server sync bound now honors `retryCount` — `timeout × (retryCount + 1)` plus the summed inter-attempt backoff (plus `kSyncSafetyMargin`); the pre-fix formula effectively allowed only `1×` the timeout, so a sync query returned before its own retransmissions could answer. Raising the per-server bound is what makes the F-2 per-resolution deadline (§3.3 "Per-resolution deadline") worth adding: at defaults one blackholed server now costs ≈ 25.85 s, so two can breach SIP Timer B.

**Timeouts.** Each attempt arms a `TimerService` timeout of `_config.timeout` via `scheduleQueryTimeout`. On expiry the timeout callback either CLAIMS a retransmission (above) or, once the attempt budget is exhausted, fails the query with `DnsTimeoutException` via an atomic `takePending` (exactly-once). The 10-second cleanup sweep (`cleanupExpiredQueries`) is a strict **orphan backstop**: it never retries and fails ONLY a query that is both expired-by-`startTime` **and** has no live timer (`activeTimerId == 0`) — e.g. one whose reschedule was rejected during `stop()`/drain. Because the retry claim resets `startTime`, a healthy mid-backoff query is never expired-by-`startTime`, so the sweep skips it and cannot double-drive or prematurely fail it.

**DoS resistance.** TCP DNS is 2-byte length-prefixed. In `handleTcpData` (`:1685`, under `_tcpBuffersMutex`) the per-session accumulation buffer is capped at `_config.maxTcpBufferSize` (default 65536): exceeding it, or a length prefix that is zero / `> 65535` / `> maxTcpBufferSize`, clears the buffer and **closes the session**. `Transport::close` is enqueue-only, so calling it from inside the I/O-thread `onData` callback is safe.

**Server selection.** `getNextServer` (round-robin over `_config.servers` via an atomic cursor) is used only when the `DnsTransport` caller passes an **empty** `server`. Since `2026-09-25-8` the resolver paths pass an **explicit** address+port per attempt (they own next-server failover — §3.3), so `getNextServer` now applies only to the one caller that still passes no server: the `DnsClient` raw async A fast-path (`resolveA(host, cb)` / `resolveAAsync`, via `DnsTransport::queryAsync` with no server arg). Same-server **retransmission** is still the transport's job (every retransmit re-sends to the same server the attempt started on, required for late-answer correlation since the query id is reused). **Cross-server failover is now done by the resolver** (§3.3), not the transport.

### 3.5 `dns::DnsMessage` (wire codec)

`DnsMessage` (`dns_message.hpp:53`) is an all-static, stateless codec.

**Encode.** `buildQuery` (the `recursionDesired` overload at `:356`, reached via the `:343`/`:349` forwarders) writes the 12-byte header (`RD` flag from `recursionDesired`; `opcode`/`rcode` implicitly 0), then the encoded question. `encodeName` (`:305`) enforces the 63-byte label limit (`DNS_MAX_LABEL_SIZE`) and a 253-octet cap on the **wire-encoded** name (`DNS_MAX_NAME_SIZE`, checked against `encoded.size()` — the wire form adds a length octet per label plus the root null), marginally conservative against the 255-octet RFC 1035 §3.1 wire ceiling, throwing `DnsParseException` on violation. `generateQueryId` (`:250`) draws from a `thread_local` `mt19937` in the range 1–65535.

**Decode.** `parse` (`:394`) validates a minimum 12-byte header, decodes flags/counts (`parseHeader`, `:465`), then walks each section calling `parseResourceRecord` and `parseTypedRecord` (`:795`), which dispatches by `DnsType` into the typed vectors (`a_records`, `srv_records`, `naptr_records`, …). A failure inside `parseTypedRecord` (for example an SRV with a short `rdlength`) is logged and that typed record is skipped; the raw record stays in its section vector. A throw from `parseResourceRecord` itself — a bounds violation, or an owner-name compression loop or out-of-range pointer — is **not** caught: it escapes `parse` and the whole response fails, so a single malformed resource record discards an otherwise-usable response (tracked `coding_trackers:tasks/iora/backlog/2026-09-24-34_dns-parse-partial-record-skip-robustness_P1.json`). When `parse` throws, `DnsTransport::processResponse` now **DROPS the datagram and keeps waiting** (drop-and-wait, RFC 1035 §7.3 / RFC 5452 §9.1 Query Matching Rules, tracker 2026-09-24-31, the `catch(std::exception)` `if (!parsed)` branch, `dns_transport.hpp:1912-1930`): a parse-stage failure — whether a malformed question or a malformed resource record — no longer completes the pending query, so a single malformed or spoofed matching-id datagram can no longer kill the query; the per-query timeout/retry machinery stays the sole thing that advances it, and retransmission continues to timeout. The **residual** gap (tracked -34) is only that a partially-malformed response cannot be salvaged: the whole datagram is discarded rather than skipping just the bad RR. (A post-parse processing error on a validly-parsed response is distinct: it still surfaces to the waiter via `completeQuery`.)

**Security.** Every read goes through `checkBounds` (`:296`). Name **decompression is loop-protected**: `decodeNameWithLoopDetection` (`:597`) tracks visited pointer offsets in an `unordered_set<uint16_t>` and throws on a repeated pointer or an out-of-range pointer (`0xC0` mask, `0x3FFF` offset). A compression pointer is followed **only** while decoding a name — in NAME fields, and in name-bearing RDATA (CNAME/NS/PTR/MX/SRV/NAPTR/SOA, via `decodeNameFromRdata` (`:676`)) — both of which route through that same loop-protected decoder; A/AAAA/TXT RDATA is never name-decoded. Each per-type parser validates its minimum `rdlength` (A == 4, AAAA == 16, SRV ≥ 6, NAPTR ≥ 4, MX ≥ 2, SOA ≥ 20) inside the `parseTypedRecord` catch (`:795`), so a single malformed typed record is logged and skipped, never fatal to the whole message.

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

The synchronous calls can throw from three unrelated exception roots (§8): `DnsResolverException` (and its subclasses — now including `DnsTransientResolutionException` when built-in failover exhausts every server on server-local conditions, and `DnsNaptrUnsupportedException`), `DnsTransportException` (now **lifecycle-only** for the resolver accessors — per-server timeouts/network faults are consumed by failover and surface as the transient), and `DnsParseException` (an unencodable name). Catch all three roots, or `std::exception` last.

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
  catch (const dns::DnsTransientResolutionException &e)
  {
    // Every server was server-local (SERVFAIL/REFUSED/NOTIMP/FORMERR/NODATA-without-SOA, timeout,
    // or connect/send fault) — RETRYABLE. Map to a SIP 503-class response. Catch BEFORE the base
    // DnsResolverException / DnsResolutionFailedException clauses (it is a sibling of the latter).
    std::cerr << "transient (retry): " << e.what() << "\n";
  }
  catch (const dns::DnsResolutionFailedException &e)
  {
    // Authoritative negative: NXDOMAIN or NODATA-with-SOA (getResponseCode() == NOERROR).
    std::cerr << "resolution failed (rcode " << static_cast<int>(e.getResponseCode())
              << "): " << e.what() << "\n";
  }
  catch (const dns::DnsResolverException &e)
  {
    // e.g. DnsNaptrUnsupportedException, or an "Invalid hostname" from a wrapper accessor.
    std::cerr << "resolver error: " << e.what() << "\n";
  }
  catch (const dns::DnsTransportException &e)
  {
    // Lifecycle only now (transport not running / stopped / no servers configured). Per-server
    // network faults are consumed by the built-in failover and surface as the transient above.
    std::cerr << "transport error: " << e.what() << "\n";
  }
  catch (const dns::DnsParseException &e)
  {
    // Only an UNENCODABLE query name reaches here (a label > 63 bytes / name too long —
    // DnsMessage::encodeName throws before send). A malformed/spoofed RESPONSE is now
    // dropped-and-wait, so it never surfaces as a DnsParseException (§3.5).
    std::cerr << "unencodable query name: " << e.what() << "\n";
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
  catch (const dns::DnsResolverException &e)
  {
    // resolveServiceDomain reports step failures via result.outcome (Resolved / TransientFailure /
    // PermanentNoService) and next-server failover walks all servers per step, so it does NOT throw
    // for a timeout/SERVFAIL/parse at a step. It throws only DnsResolverException("Invalid hostname")
    // for a malformed domain. (Inspect result.outcome after isSuccess()==false for the 503-vs-404 signal.)
    std::cerr << "invalid service domain: " << e.what() << "\n";
  }
}

void locateSipsServer(DnsClient &client)
{
  // A sips: URI: pass secure=true. The resolver hard-excludes every non-SIPS-SIP service on
  // all paths (RFC 3263 §4.1) and defaults the A/AAAA fallback (§4.2) to TLS/5061 (5061 = the
  // RFC 3261 SIPS default port) — so every target returned is already a secure SIP target.
  dns::ServiceResolutionResult result =
    client.resolveServiceDomain("example.com", {dns::ServiceType::SIPS_TLS}, /*secure=*/true);
  std::cout << result.targets.size() << " secure SIP targets\n";
}
```

### Bounding resolution under SIP Timer B (per-resolution deadline)

```cpp
// A SIP consumer caps the whole NAPTR->SRV->A/AAAA chain so a blackholed server set cannot
// push resolution past Timer B/F (64*T1 = 32s). Size the deadline from asyncAttemptBudget():
// the async overhang is at most (deadline + one asyncAttemptBudget()).
dns::DnsConfig makeBoundedConfig()
{
  dns::DnsConfig cfg;
  cfg.setServers({"10.0.0.53", "10.0.0.54"});
  // The DEFAULT per-server budget alone exceeds Timer B, so a usable deadline REQUIRES
  // reducing timeout/retryCount first (see §3.3 "Per-resolution deadline").
  cfg.timeout = std::chrono::milliseconds{1500};
  cfg.retryCount = 1;
  cfg.maxResolutionTime = std::chrono::milliseconds{8000}; // whole-resolution cap; 0 = disabled (default)
  return cfg;
}

void boundedResolve(DnsClient &client)
{
  // On expiry the result is TransientFailure (retryable), never PermanentNoService; targets
  // already resolved are kept (partial-Resolved). The deadline NEVER throws a new type — a
  // DnsDeadlineException IS-A DnsTransientResolutionException.
  dns::ServiceResolutionResult r = client.resolveServiceDomain("example.com",
                                                               {dns::ServiceType::SIP_TCP});
  if (!r.isSuccess() && r.outcome == dns::ResolutionOutcome::TransientFailure)
  {
    // Deadline hit (or every server exhausted server-local): retryable -> SIP 503 at the adapter.
  }

  // Or override per call without touching the config (0ms disables for THIS call only):
  dns::ServiceResolutionResult quick =
    client.resolveServiceDomain("example.com", {dns::ServiceType::SIP_TCP}, /*secure=*/false,
                                /*deadlineOverride=*/std::chrono::milliseconds{5000});
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
    // send failure, stopped), DnsParseException (unencodable query name).
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

**Within one `DnsClient`, failover across its configured servers is now automatic for the resolver paths** (tracker `2026-09-25-8`, §3.3 "Next-server failover") — the sync `resolveA`/`resolveHostname` accessors, `resolveServiceDomain[Async]`, and `query`/`queryAsync`: a SERVER-LOCAL failure on one server is retried on the next configured server before the call returns, so a single `DnsConfig::setServers({...})` with multiple servers already gives per-query failover. (The raw async `resolveA(host, callback)` fast-path is the exception — it bypasses the resolver and does not fail over; see §3.3.) The recipe below uses the sync `resolveA`, so its primary already walks its own server list; you need the two-client pattern only to fail over across **independently configured** server sets — different `DnsConfig` (distinct caches, timeouts, or `addressResolutionPolicy`), e.g. a primary datacenter resolver and a fallback with a longer timeout. Catch the failures that mean "this server set did not give a usable answer" and re-issue on the second `DnsClient`:

```cpp
std::vector<std::string> resolveWithFailover(DnsClient &primary, DnsClient &secondary,
                                             const std::string &host)
{
  try
  {
    return primary.resolveA(host); // built-in failover exhausts the primary's servers first
  }
  catch (const dns::DnsTransientResolutionException &)
  {
    // EVERY primary server was server-local (SERVFAIL/REFUSED/FORMERR/NOTIMP/NODATA-without-SOA,
    // timeout, or connect/send fault): retryable -> try the independently-configured secondary.
    return secondary.resolveA(host);
  }
  catch (const dns::DnsTransportException &)
  {
    // A lifecycle fault on the primary client (transport not running / stopped / no servers): the
    // primary is unusable -> fall to the secondary. (Per-server network faults do NOT reach here;
    // they are consumed by the built-in failover and surface as the transient above.)
    return secondary.resolveA(host);
  }
  catch (const dns::DnsResolutionFailedException &)
  {
    // Authoritative negative (NXDOMAIN / NODATA-with-SOA): every server would answer the same.
    throw;
  }
}

dns::DnsConfig makeConfig(std::initializer_list<std::string> servers)
{
  dns::DnsConfig cfg;
  cfg.setServers(servers);
  cfg.timeout = std::chrono::milliseconds{1500}; // per-server stall bound (see the cost note below)
  return cfg;
}

struct FailoverResolver
{
  // Each client may itself hold several servers (built-in failover walks them); the two clients
  // fail over across INDEPENDENT configs (distinct caches/timeouts/policy).
  DnsClient primary{makeConfig({"10.0.0.53", "10.0.0.54"})};
  DnsClient secondary{makeConfig({"10.0.1.53"})};

  std::vector<std::string> resolve(const std::string &host)
  {
    return resolveWithFailover(primary, secondary, host);
  }
};
```

What to fail over on (across independent server sets):

- **`DnsTransientResolutionException`**: the primary client exhausted **all** its configured servers on server-local conditions (SERVFAIL/REFUSED/FORMERR/NOTIMP/NODATA-without-SOA, a timeout, or a connect/send fault). `getResponseCode()` carries the last server-local rcode (or SERVFAIL for a thrown fault). Retryable → try the secondary.
- **`DnsTransportException`** (lifecycle only now — transport not running/stopped, no servers configured): the primary client is unusable. Per-server network faults (`DnsNetworkException`, `DnsTimeoutException`) no longer surface here — the built-in failover consumes them and reports the transient above.
- **Not** `DnsResolutionFailedException` (authoritative NXDOMAIN / NODATA-with-SOA), `DnsNoRecordsException`, or `DnsNaptrUnsupportedException`: authoritative or protocol answers that a second server would repeat.
- `DnsParseException` (an unencodable name, e.g. a >63-byte label) is not caught above: the secondary rejects the same input.

Cost: the secondary is tried only after the primary's **built-in** failover has exhausted **all** of the primary's servers, and each of those pays its **whole** attempt window — every attempt (`retryCount + 1` sends) plus inter-attempt backoff, bounded per server by `calculateMaxSyncWaitTime()`. So a primary with N servers can stall up to ≈ N × that window before the secondary is tried. Lower `timeout` (and `retryCount`) to bound it, **or set a per-resolution deadline** (`DnsConfig::maxResolutionTime` / a per-call `deadlineOverride`, §3.3 "Per-resolution deadline") to cap the whole chain under SIP Timer B/F — the recommended bound for a SIP consumer. The complementary one-transmission-per-server-per-round scheme (RFC 1035 §7.2), which would let a small deadline still rotate servers, is tracked `coding_trackers:tasks/iora/backlog/2026-09-30-5_dns-failover-rfc1035-72-per-round-cycling-and-dead-server-memory_P1.json`. Two clients also mean two sets of transport threads (engine I/O, timer, cleanup) and two independent caches. `DnsClient` is move-only (copy is deleted, move construction and move assignment are defaulted), so the pair can be held by value in an owning object, as `FailoverResolver` does.

### Anti-Patterns

- **Do NOT assume the async callback runs on an internal thread — or on yours.** It may run on your thread before the call returns (immediate errors), on the thread that calls `stop()`, or on the engine I/O, `DnsRetryTimer`, or cleanup thread. Synchronize everything it touches, and never hold a lock across `resolveA` that the callback takes.
- **Do NOT use `DnsClient` for a plain "connect me to this host".** That is `Transport`'s job via `NameResolver`/`getaddrinfo`, which honors `/etc/hosts`, NSS, and the resolv.conf search list. `DnsClient` queries nameservers directly and can disagree (see the §1 boundary).
- **Do NOT expect `cancel()` to suppress the raw callback.** `AsyncDnsRequest::cancel()` never stops delivery: the callback still runs exactly once, possibly with `DnsResolverException("DNS request cancelled")`, possibly much later (when the response, timeout, or `stop()` arrives). Do not capture stack references or `this` of an object that may be destroyed after cancelling — capture a `shared_ptr`/`weak_ptr`.
- **Do NOT assume `CancellableFuture::cancel() == true` means `get()` throws.** A delivery that already won the `promiseSet` CAS has set the real value or error.
- **Do NOT catch only `DnsResolverException`.** The three roots are disjoint: a lifecycle transport fault (`DnsTransportException`, a `std::runtime_error`) and an unencodable-name `DnsParseException` are not `DnsResolverException`. (For the resolver accessors a per-server *timeout*/network fault is now absorbed by failover and surfaces as `DnsTransientResolutionException` — a `DnsResolverException` subtype — but the raw async A fast-path still delivers a bare `DnsTimeoutException`, so catch all three roots, or `std::exception` last.)
- **Do NOT construct a `dns::DnsTransport` on the stack.** It requires `shared_ptr` ownership (`shared_from_this` in `start()`); a stack/`unique_ptr` instance throws `std::bad_weak_ptr`. Use `DnsClient`, which owns it correctly.
- **Do NOT rely on `maxCacheSize`, `maxUdpSize`, or `tcpTimeout`.** They are declared on `DnsConfig` for compatibility but are not enforced (see Configuration Reference and Known Limitations). (The retry fields — `retryCount`, `initialRetryDelay`, `retryMultiplier`, `maxRetryDelay`, `jitterFactor` — ARE honored: the per-query timeout timer drives same-server retransmission per §3.4.)
- **A single failing query now DOES try the next configured server** for the resolver paths (tracker `2026-09-25-8`, §3.3 "Next-server failover"): a SERVER-LOCAL failure (SERVFAIL/REFUSED/FORMERR/NOTIMP/NODATA-without-SOA, a timeout, or a connect/send fault) is retried on the next server automatically. It does NOT rotate on an AUTHORITATIVE negative (NXDOMAIN / NODATA-with-SOA). Do NOT hand-roll per-query rotation within one server set for those paths — it is built in. **Exception:** the raw async `resolveA(host, callback)` / `resolveAAsync` fast-path bypasses the resolver and does NOT fail over (use the sync `resolveA` or `queryAsync(DnsQuestion{…A…})`). Use a second `DnsClient` (§4) only to fail over across *independently configured* server sets.

---

## 5. Call Flow / Sequence Reference

### Synchronous `resolveA` — success path

| Step | Component | Action |
|---|---|---|
| 1 | `DnsClient::resolveA` | Build `DnsQuestion{host, A, IN}`; call `query()`. |
| 2 | `DnsResolver::query` | Look up `_cache->get()`. On hit, return cached `DnsResult`. |
| 3 | `DnsResolver::query` | On miss: pin one `getConfig()` snapshot; pick the rotating start server from `_serverRotation`; begin the next-server loop (§3.3). |
| 4 | `DnsTransport::query(question, addr, port)` | Per server: `generateUniqueQueryId`; register `PendingQuery` under `_queriesMutex`; arm timeout on `_timerService`; `sendUdpQuery` (`DnsMessage::buildQuery`) to THIS server. |
| 5 | Caller thread | Block on `future.wait_for(calculateMaxSyncWaitTime())` for this attempt. |
| 6 | Engine I/O thread | `onData` → `DnsMessage::parse` → `processResponse` → `completeQuery` sets the promise. |
| 6b | `DnsResolver::query` | Classify: server-local (server-local rcode, or a caught `DnsTimeoutException`/`DnsNetworkException`) → next server (step 4); authoritative negative or success → stop. On exhaustion → throw `DnsTransientResolutionException`. |
| 7 | `DnsResolver::query` | On a successful terminal result, `cacheQueryResult()`; return `DnsResult`. |
| 8 | `DnsClient::resolveA` | Extract `a_records`; throw `DnsNoRecordsException` if empty (answers present, none of type A), else return addresses. An authoritative NXDOMAIN / NODATA-with-SOA already threw `DnsResolutionFailedException` at step 6b; a NODATA-without-SOA / SERVFAIL / REFUSED / timeout on every server threw `DnsTransientResolutionException` (§3.1 Error surfacing). |

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

**Deadline gate (when `maxResolutionTime` / a `deadlineOverride` is set, §3.3).** On the resolver paths each step re-checks `now() >= deadline` before issuing — sync in `queryImpl` (throws `DnsDeadlineException` with no wire query, and hard-caps the in-flight `DnsTransport::query` via `maxWait`), async at the `queryAsyncWithFailover` loop top (delivers `DnsDeadlineException`, stops issuing). On expiry the chain unwinds with zero further wire queries to a `TransientFailure` terminal; already-resolved targets are kept.

---

## 6. Thread Safety Model

`DnsClient` itself carries no lock; it is move-only and expected to be constructed, configured, and destroyed by one owner. Reconfiguration methods (`updateConfig`, `setDnsServers`, `addDnsServer`, `removeDnsServer`) call `initialize()`, which **tears down and rebuilds** the transport/resolver/cache — do this only while the client is quiesced (no outstanding async queries).

| Component / operation | Synchronization | Notes |
|---|---|---|
| `DnsTransport` pending-query map | `_queriesMutex` | Guards `_pendingQueries`. `completeQuery` and the timeout lambda are **copy-then-invoke** (release before callback). |
| `DnsTransport::stop()` | collect under `_queriesMutex`, fire with no lock | Step 6 collects and clears the pending queries under `_queriesMutex` without firing them (`dns_transport.hpp:1019-1027`); step 7 calls `failCollected(toFail, DnsTransportException("Transport stopped"))` with **no lock held**, before `Stopped` is published (`:1043-1047`). The worker joins run with no `DnsTransport` lock held; a re-entrant `stop()` from a joined worker (or the teardown driver) is exempted and returns at once (`:954-959`). The callbacks run on the thread calling `stop()`. |
| `DnsTransport` sessions | `_sessionsMutex` | Guards `_serverSessions`, `_sessionToServer`, `_connectedSessions`, `_pendingOnConnect`. |
| `DnsTransport` TCP buffers | `_tcpBuffersMutex` | Guards per-session accumulation; the DoS cap + `close()` run here. |
| `DnsTransport` cleanup thread | `_cleanupMutex` + `_cleanupCv` | 10-second wait loop; `_cleanupRunning` is an atomic. |
| `DnsTransport` lifecycle | `std::atomic<Lifecycle> _state` + `_stateMutex`/`_stateCv` | `_state` (`dns_transport.hpp:678`) replaced the old `_running` flag; transitions are serialized under `_stateMutex`, the query hot paths read `_state` lock-free. |
| `DnsTransport` statistics | `std::atomic` counters | `InternalStatistics` (8 atomics); snapshot via `getStatistics()`. |
| `DnsTransport` lock ordering | Documented, strict | `_stateMutex > _cleanupMutex > _tcpBuffersMutex > _queriesMutex > _sessionsMutex` (`dns_transport.hpp:632-665`). Inner co-holds: `handleTcpData` holds `_tcpBuffersMutex` across `_sessionsMutex`; the UDP-truncation path holds `_queriesMutex` while `sendTcpQuery` takes `_sessionsMutex`. |
| `DnsResolver` async coordination | per-op `std::mutex` + atomics | `resultMutex` + `remainingQueries` (`fetch_sub(acq_rel)`) + `callbackFired` + `deniedServices` are local to each async call, not members. Async continuations capture `self = shared_from_this()` to stay alive across the callback chain. |
| `DnsResolver::_serverRotation` | `std::atomic<std::size_t>`, relaxed `fetch_add` | The failover start-server cursor (§3.3). It only spreads load (the loop then walks all servers), publishing no data, so `relaxed` is correct. |
| `DnsResolver` failover chain (`queryAsyncWithFailover`) | per-issue `std::atomic<int>` CAS handshake (acq_rel) | The `HANDOFF_PENDING`/`CB_ADVANCE`/`ISSUER_DONE` gate (one per issue, captured by value into the completion callback) resolves "issuer advances vs callback re-enters" at ONE ordered point — exactly-once advance, no lost wakeup. The acq_rel CAS is the sole handoff edge between the issuer and the completion thread, so it also publishes the non-atomic `FailoverChainState` fields (`snapshot`/`startIndex`/`attempts`/`lastServerLocalRcode`, plus the F-2 read-only, write-once `deadline` set at `makeFailoverChain` time): only one thread owns the chain at a time, and the deadline is construction-published (happens-before every read via the `shared_ptr` capture / register→complete edge), so it needs no atomic. The per-resolution deadline is threaded as a by-value `steady_clock::time_point` parameter (never a resolver member), so concurrent resolutions on the one long-lived resolver cannot tear it. The `handleClose` per-query network-fault deliveries and every completion site's `std::current_exception()` are copy-then-invoke (no lock held). The async A/AAAA per-target transient slots (`vector<char>`, one byte per target index) are written disjointly and read once by the single final `finishTarget` decrement (published by its acq_rel `fetch_sub` release-sequence). |
| `DnsResolver::_rng` | `_rngMutex` | Guards the weighted-selection generator; `sortTargetsByPriority` takes one advancing draw under it (then orders on a local generator) and `setRngSeed` reseeds under it. A leaf lock — never held across a callback or with a result lock held. |
| `DnsCache` container | `std::shared_mutex _cacheMutex` | Shared for `get`/`put`/`putNegative`/`remove`, exclusive for `clear()` (which replaces the `ExpiringCache`). Guards the pointer; the store is itself internally synchronized. |
| `DnsCache` stats | `_statsMutex` (inner) + `std::atomic` counters | Ordering `_cacheMutex → _statsMutex`; the eviction callback takes neither (atomic `fetch_sub` only). |
| Async callback delivery | `RequestState::deliveryAttempted` + `promiseSet` CAS | One delivery even when response and timeout race across threads. Within that single delivery the raw `resolveA` path is a single-invoke funnel (`dns_client.hpp:1076-1149`): every branch builds a result and converges on one `callback(...)` outside any `try`, so a throwing user callback is invoked **exactly once** (no re-invoking `catch`) — the throw propagates once into the transport's `catch(...)` and completion is published by a `noexcept` scope-exit guard on the unwind. Resolved by tracker `2026-09-25-6`. |

---

## 7. Configuration Reference

All fields are on `dns::DnsConfig` (`dns_types.hpp:543`). Timeouts use `std::chrono` types.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `servers` | `std::vector<DnsServer>` | System `/etc/resolv.conf`, else `{8.8.8.8:53, 1.1.1.1:53}` | Nameservers to query. The resolver paths (§3.3) fail over across ALL of them within one lookup, starting from a rotating cursor; a blackholed server costs ≈ its full per-server attempt window before the next is tried, so worst-case lookup latency scales ≈ N × that window — bound the whole chain with `maxResolutionTime` (below). (Per-server one-transmission-per-round cycling is `2026-09-30-5`.) The raw async A fast-path uses plain per-query round-robin (`getNextServer`). |
| `timeout` | `std::chrono::milliseconds` | `5000` | Per-query response timeout (UDP **and** TCP — see below). |
| `tcpTimeout` | `std::chrono::milliseconds` | `10000` | **Declared but unused** by `DnsTransport`; TCP uses `timeout`. |
| `cacheTimeout` | `std::chrono::seconds` | `300` | Default cache TTL for records that carry no TTL (seeds the `DnsCache`; also adjustable at runtime via `setCacheTtl`). |
| `retryCount` | `int` | `3` | Retry attempts per query (`retryCount + 1` total sends). Honored: the per-query timeout timer drives same-server retransmission (§3.4), and the sync wait bound now covers all of them — `calculateMaxSyncWaitTime` ≈ `timeout × (retryCount + 1)` + backoff (tracker `2026-09-30-4` H-2). Clamped to `[0, 100]` for the wait computation. |
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
| `maxResolutionTime` | `std::chrono::milliseconds` | `0` (**disabled**) | Per-resolution deadline bounding the whole RFC 3263 chain under SIP Timer B/F (§3.3 "Per-resolution deadline"). `0` = disabled = today's behavior. `> 0` = cap. `< 0` = fail-closed (every non-cached resolution → `TransientFailure`). A per-call `std::optional<std::chrono::milliseconds> deadlineOverride` on each public entry overrides it (`0ms` disables for that call). Size it from `asyncAttemptBudget()`; the DEFAULT config's per-server budget already exceeds Timer B, so a usable deadline needs a reduced `timeout`/`retryCount`. |

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
  // `secure` (defaulted false) = RFC 3263 §4.1 SIPS SIP-scoped resolution: non-SIPS-SIP
  // services (incl. HTTPS) are discarded and the A/AAAA fallback defaults to TLS/5061. It is
  // NOT generic transport security. The SIP layer drives it true for a `sips:` URI.
  // `deadlineOverride` (F-2, defaulted nullopt) = per-call per-resolution deadline; nullopt uses
  // DnsConfig::maxResolutionTime, a value overrides it, 0ms disables for that call (§3.3).
  dns::ServiceResolutionResult resolveServiceDomain(
      const std::string &domain,
      const std::vector<dns::ServiceType> &preferredTransports = {},
      bool secure = false,
      std::optional<std::chrono::milliseconds> deadlineOverride = std::nullopt);
  dns::ServiceResolutionResult resolveCustomServiceDomain(
      const std::string &domain,
      const std::vector<std::pair<std::string, dns::ServiceType>> &srvQueries,
      const std::vector<dns::ServiceType> &preferredTransports = {},
      bool secure = false,
      std::optional<std::chrono::milliseconds> deadlineOverride = std::nullopt);
  void resolveServiceDomainAsync(
      const std::string &domain,
      dns::DnsResolver::ServiceResolutionCallback callback,
      const std::vector<dns::ServiceType> &preferredTransports = {},
      bool secure = false,
      std::optional<std::chrono::milliseconds> deadlineOverride = std::nullopt);
  void resolveCustomServiceDomainAsync(
      const std::string &domain,
      const std::vector<std::pair<std::string, dns::ServiceType>> &srvQueries,
      dns::DnsResolver::ServiceResolutionCallback callback,
      const std::vector<dns::ServiceType> &preferredTransports = {},
      bool secure = false,
      std::optional<std::chrono::milliseconds> deadlineOverride = std::nullopt);
  // NOTE: the future wrapper has NO per-call deadlineOverride — it honors only DnsConfig::maxResolutionTime.
  CancellableFuture<dns::ServiceResolutionResult> resolveServiceDomainFuture(
      const std::string &domain,
      const std::vector<dns::ServiceType> &preferredTransports = {},
      bool secure = false);

  // Per-resolution-deadline sizing (F-2) and deterministic SRV ordering (test-only).
  std::chrono::milliseconds asyncAttemptBudget() const;  // worst-case un-abortable async overhang
  void setRngSeed(std::uint32_t seed);                   // reproducible RFC 2782 weighted ordering

  // Standard queries. query/queryAsync/resolveHostname/resolveSRV/resolveNAPTR carry the same
  // trailing optional deadlineOverride; the resolveA fast-path and the other typed accessors do not.
  dns::DnsResult query(const dns::DnsQuestion &question,
                       std::optional<std::chrono::milliseconds> deadlineOverride = std::nullopt);
  void queryAsync(const dns::DnsQuestion &question,
                  std::function<void(const dns::DnsResult &, const std::exception_ptr &)> callback,
                  std::optional<std::chrono::milliseconds> deadlineOverride = std::nullopt);
  std::vector<std::string> resolveA(const std::string &hostname);
  AsyncDnsRequest resolveA(const std::string &hostname,
                           std::function<void(std::vector<std::string>, std::exception_ptr)> callback);
  CancellableFuture<std::vector<std::string>> resolveAAsync(const std::string &hostname);
  std::vector<std::string> resolveAAAA(const std::string &hostname);
  std::vector<std::string> resolveHostname(const std::string &hostname, bool prefer_ipv6 = false,
      std::optional<std::chrono::milliseconds> deadlineOverride = std::nullopt);
  std::vector<dns::SrvRecord> resolveSRV(const std::string &service,
      std::optional<std::chrono::milliseconds> deadlineOverride = std::nullopt);
  std::vector<dns::NaptrRecord> resolveNAPTR(const std::string &domain,
      std::optional<std::chrono::milliseconds> deadlineOverride = std::nullopt);
  std::vector<std::string> resolveCNAME(const std::string &hostname);
  std::vector<dns::MxRecord> resolveMX(const std::string &domain);
  std::vector<dns::TxtRecord> resolveTXT(const std::string &domain);
  std::vector<std::string> resolvePTR(const std::string &ip);

  // Deprecated SIP-named forwarders (also carry the trailing `bool secure = false`)
  dns::SipResolutionResult resolveSipDomain(
      const std::string &domain,
      const std::vector<dns::SipServiceType> &preferredTransports = {},
      bool secure = false);
  void resolveSipDomainAsync(
      const std::string &domain,
      std::function<void(const dns::SipResolutionResult &, const std::exception_ptr &)> callback,
      const std::vector<dns::SipServiceType> &preferredTransports = {},
      bool secure = false);

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

Record structs (`dns_types.hpp:199`–`:358`). Every typed record derives from `DnsResourceRecord`:

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

(Inheritance is `public`; each struct also has a defaulted-argument constructor that sets `type`/`cls = IN`.) The typed records in `a_records`, `srv_records`, … are built through those constructors (`dns_message.hpp:863`, `:880`, `:919`, …), so they carry **no raw RDATA** — `rdata` is empty, `rdlength` is 0 — and `cls` is forced to `IN` whatever the wire class was. Raw RDATA is available only on the generic records in `answers`/`authority`/`additional`.

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

// Per-avenue transient/permanent outcome (tracker 2026-09-25-8) — dns_resolver.hpp:
enum class ResolutionOutcome { Resolved, TransientFailure, PermanentNoService };   // :158

struct ServiceResolutionResult                                                     // :169
{
  std::vector<ServiceTarget> targets; std::string domain;
  bool fromCache{false}; std::chrono::steady_clock::time_point timestamp;
  ResolutionOutcome outcome{ResolutionOutcome::Resolved};  // :175 (additive; isSuccess() unchanged)
  explicit ServiceResolutionResult(const std::string &d = "");  // :181 (sets timestamp = now())
  bool isSuccess() const;                                       // !targets.empty()
  std::vector<ServiceTarget> getTargetsForTransport(ServiceType transport) const;
  ServiceTarget getPreferredTarget() const;                  // returns the ordered head (front())
  ServiceTarget getPreferredTargetWithDefaultRng() const;    // ditto (RNG no longer used)
  template <typename RNG> ServiceTarget getPreferredTarget(RNG &rng) const; // ditto; rng unused
};

// Exceptions — three disjoint roots (no common DNS base class):
// dns_resolver.hpp — DnsResolverException family (derive from std::exception)
class DnsResolverException : public std::exception { /* getResponseCode() */ };   // :237
class DnsResolutionFailedException : public DnsResolverException {};              // :255 (authoritative negative)
class DnsNoRecordsException : public DnsResolverException {}; // rcode NXDOMAIN   // :264
class DnsTransientResolutionException : public DnsResolverException {};           // :311 (all servers exhausted, retryable)
class DnsDeadlineException : public DnsTransientResolutionException {};           // :352 (per-resolution deadline, F-2; IS-A transient)
class DnsNaptrUnsupportedException : public DnsResolverException {};              // :370 (NAPTR NOTIMP/FORMERR, Q5)
// dns_transport.hpp — DnsTransportException family (derive from std::runtime_error)
class DnsTransportException : public std::runtime_error {};                        // :45
class DnsTimeoutException : public DnsTransportException {};                       // :54
class DnsServerException : public DnsTransportException { DnsResponseCode responseCode; }; // :63
class DnsNetworkException : public DnsTransportException {};                       // :87 (per-server network fault)
// dns_message.hpp
class DnsParseException : public std::runtime_error {};                            // :43
```

`DnsResolverException` (and its subtypes `DnsResolutionFailedException`, `DnsNoRecordsException`, `DnsTransientResolutionException`, `DnsDeadlineException`, `DnsNaptrUnsupportedException`) derives from `std::exception`; the `DnsTransportException` family (including `DnsTimeoutException` and `DnsNetworkException`) and `DnsParseException` derive from `std::runtime_error`. A `catch (const dns::DnsResolverException &)` therefore does not catch timeouts, transport failures, or parse failures — catch each root, or `std::exception` last. **`DnsDeadlineException` IS-A `DnsTransientResolutionException`** (per-resolution deadline, F-2), so a transient handler catches it automatically and it never needs its own clause. `ResolutionOutcome` is additive on `ServiceResolutionResult` (default `Resolved`, `isSuccess()` unchanged): read it after `isSuccess() == false` to tell a retryable `TransientFailure` from a `PermanentNoService` — the correct SIP mapping (503 vs 404, never 6xx, proxy-vs-UAC) is in §3.3 "Transient vs permanent signal" and is the adapter's job (`iora_sip 2026-09-25-2`). Next-server failover (tracker `2026-09-25-8`) resolved the "resolver catches only `DnsResolverException`" gap for server-local faults (§3.3, §10).

---

## 9. Design Decisions

| Decision | Rationale |
|---|---|
| Separate DNS-protocol client from the transport `NameResolver`. | `getaddrinfo` cannot return `SRV`/`NAPTR`/`MX`/`TXT`; SIP/HTTP service location needs a real DNS client that queries nameservers directly. The two are documented as distinct tools with different resolution stacks (§1 boundary). |
| RFC 3263 limited to the `S`/`A`-flag subset. | SIP server location (RFC 3263 §4.1) needs only `S` (→SRV) and `A` (→direct A/AAAA) flags. `U`-flag/ENUM (RFC 6116) and chained NAPTR are out of scope and are explicitly skipped. Scope note: URI-level short-circuits (numeric-IP target, an explicit port, or an explicit transport per RFC 3263 §4.1–4.2) are the SIP-stack caller's responsibility, not `DnsClient`'s. |
| NAPTR processed in ascending `ORDER`, stopping at the first usable tier (RFC 3403 §8). | The DDDS algorithm mandates lowest-`ORDER`-first; descending to a higher `ORDER` only when the current tier yields no usable target avoids silently ignoring a valid fallback tier while still honoring precedence. |
| SRV `.` target suppresses fallback **per service**, not domain-wide (RFC 2782). | A `.` means "this service is decidedly not available at this domain." Suppressing only the denied transport's A/AAAA fallback (not the whole domain) prevents a `_sips._tcp .` from stranding plain SIP reachable via a bare A record. |
| RFC 2782 weighted ordering computed once over the whole failover list, not per pick; `getPreferredTarget` returns the ordered head (tracker `2026-09-25-4`). | Ordering the entire list at resolution time — sequence transports per owner name (`naptrPreference`/transport-rank), then RFC 2782 weighted-random within each equal-priority group — gives correct failover *traversal* order, not just a correct single next-hop. `getPreferredTarget` then returns `front()` and does not re-randomize, so the head and the traversal order agree (no double-ordering) and the per-pick RNG is removed. Weights are summed only within one `(naptrPreference, transport, priority)` group; the draw is one advancing pull of `_rng` under the leaf `_rngMutex`, seedable for deterministic tests. |
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
| Resolver-owned next-server failover; the transport keeps `getNextServer()` for non-failover callers (tracker `2026-09-25-8`). | RFC 1035 §7.2 requires trying other servers on a server-local failure. Putting selection in the resolver (one pinned `getConfig()` snapshot + a resolver-owned cursor, each server tried at most once, address+port explicit) lets one lookup exclude a failed server and retry the SAME question elsewhere — which the transport's per-distinct-query round-robin cursor cannot express. The detection gate rotates on server-local conditions (rcode or `DnsTimeout`/`DnsNetworkException` by type) and stops on an authoritative negative, so failover never masks a real NXDOMAIN/NODATA. |
| `DnsNetworkException` as a distinct `DnsTransportException` subtype (tracker `2026-09-25-8`). | The failover gate must tell a per-server NETWORK fault (connect/send failure, query-ID exhaustion, async session close → rotate) from a global LIFECYCLE fault (transport stopped → terminal) BY TYPE — a `what()` substring match is unsafe because network messages interpolate the server name. Additive: every existing `catch (const DnsTransportException&)` still catches it. Every completion site delivers `std::current_exception()` (never a re-wrapped base) so the derived type reaches the gate. |
| Additive `ResolutionOutcome` + a distinct transient exception, not a breaking API change (tracker `2026-09-25-8`). | Consumers that only branch on `isSuccess()` are unchanged; a SIP consumer that needs 503-vs-404 opts in by reading `outcome` (or by catching `DnsTransientResolutionException` from `resolveHostname`). A dedicated `DnsNaptrUnsupportedException` (Q5) keeps "NAPTR unsupported → fall to direct-SRV" distinct from a retryable transient so the outcome handlers cannot conflate them. |
| Per-avenue outcome now; cross-step aggregation deferred (trackers `2026-09-30-1`/`-3`/`-2`). | Slice A ships the terminal avenue's own outcome and the failover mechanism; the cross-step deepest-avenue-supersedes combination, the RFC-1035-§7.2 one-transmission-per-round latency budget, and async fan-out caching are separable follow-ons with their own review loops, keeping the P0 failover fix landable without a fixed-point review spiral. |
| Per-resolution deadline: off by default, sync HARD / async SOFT (tracker `2026-09-30-3`, F-2). | Failover made the serial chain correct but unbounded (one blackholed server ≈ 25.85 s after H-2), which can breach SIP Timer B/F (32 s). The deadline bounds the whole chain, but stays `0 = disabled` so no existing caller changes. Sync can be hard-capped (one blocking `wait_for` per attempt → cap it with `maxWait`); the async fan-out cannot abort an in-flight attempt without racing its latches, so it is a SOFT gate at the one choke point (overhang = one `asyncAttemptBudget()`, exposed so a consumer can size `D`). The absolute deadline is computed once at the public entry and threaded as a required by-value parameter so a missed hop fails to compile rather than silently running unbounded. |
| `DnsDeadlineException` IS-A `DnsTransientResolutionException` (F-2). | A deadline is a retryable outage, not a permanent negative, so making it a transient subtype routes it to `TransientFailure` through every existing fall-forward / outcome-setting catch with **no** new catch site, and keeps sync == async. It stays a distinct type (via a protected forwarding ctor carrying its own message) only so logs can tell a deadline from a genuine all-server exhaustion; the exhaustion terminal keeps its own `DnsTransientResolutionException(qname, lastServerLocalRcode)` so rcode fidelity and the OFF path survive. |
| Deadline keeps already-resolved targets (partial-Resolved), including priority inversion (human decision, F-2). | The deadline only STOPS issuing more work; discarding completed targets would waste a usable answer. Returning a reachable lower-priority target when a higher-priority one is transiently cut matches RFC 2782 / RFC 3263 §4.3 ("contact the lowest-priority target you can reach") and self-heals next resolution. The sync-serial vs async-concurrent asymmetry (sync partial-Resolved needs a cache-served backup) is documented in §3.3, not hidden. |

---

## 10. Known Limitations

| Limitation | Impact |
|---|---|
| **`maxUdpSize` is declared but unused.** | `DnsConfig::maxUdpSize` (default 512) is never consulted by `DnsTransport`; outbound UDP size is not checked and TCP fallback is purely TC-flag-driven. Setting it has no effect. |
| **`tcpTimeout` is declared but unused.** | `DnsConfig::tcpTimeout` (default 10000 ms) is never referenced; TCP queries use `_config.timeout` (5000 ms) like UDP. Do not rely on a distinct TCP timeout. |
| **`maxCacheSize` is not enforced.** | The cache has no entry-count bound; it is expiration-based only. A flood of distinct short-TTL names is bounded only by their TTLs, not by a size cap. |
| **NAPTR tier-descent does not re-descend on SRV-resolution failure.** | `processNaptrRecords` commits to the first `ORDER` tier that produces a selectable `S`/`A` record; if that tier's SRV RRset later resolves to nothing, a usable higher-`ORDER` tier is not retried. This matches RFC 3403 §8 ("If the lookup after a rewrite fails, clients are strongly encouraged to report a failure, rather than backing up to pursue other rewrite paths"), but a peer that publishes fallback tiers expecting SRV-failure re-descent will not get it. |
| **Cache statistics are approximate under concurrent same-key writes.** | The insertion/replacement counters can drift by ±1 when a key expires in the window between a `put`'s existence check and its count update (the eviction callback decrements without `_statsMutex`). Cached data is unaffected; only the monitoring counters are approximate (tracked backlog). |
| ~~**No per-query server failover.**~~ **RESOLVED (tracker `2026-09-25-8`, iora `c2d0f77`).** | The resolver now fails over across all configured servers within a single lookup on a SERVER-LOCAL condition (§3.3 "Next-server failover"). The per-resolution **Timer-B deadline** that bounds the whole chain is now **implemented** (tracker `2026-09-30-3`, §3.3 "Per-resolution deadline"). Residual, tracked separately: failover still pays a server's whole retransmit budget before rotating — RFC 1035 §7.2 one-transmission-per-round cycling (which would let a small deadline still rotate) is `2026-09-30-5`; the CROSS-STEP NAPTR→SRV→A/AAAA outcome aggregation is `2026-09-30-1`; async fan-out result caching is `2026-09-30-2`. A second `DnsClient` (§4) is still the way to fail over across *independently configured* server sets (different caches/policies), which built-in failover does not do. |
| **TC=1 TCP-fallback timeout is not identity/state aware (latency, premature failure, and double-act).** | After a TC=1 UDP truncation, the query falls back to TCP and re-arms a timeout. Three known gaps, all needing a timer-identity redesign: (a) if that TCP server is connected but silent, the fallback timeout callback defers rather than failing terminally, so the query fails only via the 10-second orphan-backstop sweep — `~timeout` becomes `~timeout + up to 10 s` (UDP-only queries are unaffected); (b) a stale UDP timeout that fired concurrently with the truncation can zero the live fallback's `activeTimerId`, and because the fallback path never resets `startTime`, the orphan sweep can then **prematurely FAIL a still-in-flight, would-have-succeeded TCP fallback** (worse than added latency); (c) a truncated reply arriving in the retry resend's clear-to-send window can start a TCP fallback while the UDP resend also fires (completion stays exactly-once). Open — P1, tracked `coding_trackers:tasks/iora/backlog/2026-09-25-2_dns-tcp-fallback-timeout-identity-arbitration_P1.json`. |
| ~~**The resolver catches only `DnsResolverException`.**~~ **RESOLVED** (slice a1 `2026-09-24-29`, landed; and next-server failover `2026-09-25-8`, iora `c2d0f77`). | A timeout/network fault on one server no longer aborts an avenue: the `query()` leaf and `queryAsyncWithFailover` classify `DnsTimeoutException`/`DnsNetworkException` as server-local and **rotate to the next server** (§3.3 "Next-server failover"). After all servers are exhausted the sync leaf **throws** `DnsTransientResolutionException` and the async helper **delivers** it via the callback — a `DnsResolverException` subtype, so the NAPTR/SRV step-fallback (`catch (const DnsResolverException&)`) makes a server-local failure fall forward instead of aborting. `resolveHostname` catches `DnsTransientResolutionException` per family and keeps a sibling family's partial results (no more discarding A results on an AAAA fault). Note the `DnsParseException` path IS reachable for an unencodable name (a label > 63 bytes, `DnsMessage::encodeName`) — it is not a server-local fault, does not rotate, and is absorbed as a per-family/step failure (partial results kept). |
| **Fresh async service resolution does not populate the record cache.** | The async/cached A/AAAA paths now **honor `addressResolutionPolicy`** identically to the sync path (both families for the First policies, single family for the Only policies, byte-identical ordering) — **resolved** by tracker `2026-09-25-5` (landed iora `bda1c10`; §3.3 step 5). The residual behavior: a *fresh* async resolution still calls `DnsTransport::queryAsync` directly and so does not write the record cache (the async **cache-hit** service path does read it, and a prior sync resolution warms it). This is existing behavior, not a policy defect; out of scope for `2026-09-25-5`. Async resolver-level result caching (the SRV/NAPTR fan-out completers do not cache like the sync path / the `queryAsync` twin) is tracked as a follow-on, `coding_trackers:tasks/iora/backlog/2026-09-30-2_dns-servfail-failover-followups_P1.json`. |
| **Partial RFC 5452 response hardening.** | An UNPARSEABLE response whose first two bytes match a pending query ID from the same server/port is now DROPPED (drop-and-wait), so it no longer terminates the query and retransmission continues to timeout (fixed by tracker 2026-09-24-31, RFC 5452 §9.1 Query Matching Rules). Broader hardening — full source/port entropy checks and malformed-record skip robustness — is still tracked `coding_trackers:tasks/iora/backlog/2026-09-24-34_dns-parse-partial-record-skip-robustness_P1.json` / `-29`. |
| **A throwing user callback is invoked twice.** | ~~In `resolveAInternal`, a callback that throws is called again with the thrown exception from `catch (...)`.~~ **FIXED** — `resolveAInternal` is now a single-invoke funnel (all branches build a result and converge on one `callback(...)` outside any `try`; a throwing callback propagates once into the transport's `catch(...)` and completion is published by a `noexcept` scope-exit guard on the unwind). Resolved by tracker `2026-09-25-6` (`dns-async-cancel-teardown-and-double-invoke`). |
| **`resolveA(host, cb)` can throw `std::bad_function_call` instead of calling back.** | On a synchronous throw, the `catch (...)` branch (`dns_client.hpp:1181`) calls `callback`, but it was already moved into `resolveAInternal` (`:1176`), so the call throws `std::bad_function_call` out of `resolveA` and the user callback is never invoked. (The `!_transport` immediate-error branch at `:1165-1171` invokes the callback BEFORE the move and is safe.) Reproduced with a hostname containing a 70-byte label: `DnsMessage::encodeName` throws `DnsParseException` inside `DnsTransport::queryAsync` (before the query is registered), and `resolveA` throws `std::bad_function_call`. Open — P1, tracked `coding_trackers:tasks/iora/backlog/2026-09-24-32_dnsclient-resolvea-callback-moved-then-invoked_P1.json`. |
| **A `start()` failure after publishing can strand running transports.** | `DnsTransport::start()` publishes the transports and `Running` before `startCleanupTimer()`, whose thread creation can throw; the failure path then reports `Stopped` while the started transports stay published, `stop()` returns early, and the next `start()` drops them under `_stateMutex` (`dns_transport.hpp:757-771`). `DnsClient` surfaces it as `DnsResolverException("Failed to start DNS transport: …")` from its constructor or `initialize()`. Open — P1, tracked `coding_trackers:tasks/iora/backlog/2026-09-24-30_dnstransport-start-publishes-before-cleanup-thread-can-throw_P1.json`. |
| **`cleanupCache()` / `setCacheCleanupCallback` are no-ops.** | `cleanupExpired()` always returns 0 (ExpiringCache sweeps itself every ~5 s) and the stored cleanup callback is never invoked. Do not use them for monitoring. |
| **`resolveHost` swallows per-family errors.** | It returns `success = false` only when *both* A and AAAA fail; individual family errors are discarded, so a partial failure is invisible to the caller. Use `resolveA`/`resolveAAAA` when you need per-family error detail. |
| **Async callbacks run on several threads, including the caller's.** | Callbacks fire on the engine I/O thread, the `DnsRetryTimer` thread, or the cleanup thread; on the caller's thread before `resolveA`/`queryAsync` returns for immediate errors (no transport, transport not running, registration refused, send failure) and, for `queryAsync`, cache hits; and on the thread calling `stop()` for queries still pending at shutdown (`dns_transport.hpp:1046-1047`). Non-thread-safe callback bodies are a data race, and a lock held across `resolveA` that the callback takes is a self-deadlock. |
| **Cancellation never suppresses the raw callback.** | After `AsyncDnsRequest::cancel()` the callback is still invoked exactly once — with the real result if delivery won, else with `DnsResolverException("DNS request cancelled")` when the response, timeout, or `stop()` arrives (the single raw-callback funnel `dns_client.hpp:1148`); nothing removes the pending query. Captured state must outlive it. `CancellableFuture::cancel()` returning `true` does not guarantee `get()` throws. The header's "false if already completed" (`dns_client.hpp:48`) is wrong. Open — P1, tracked `coding_trackers:tasks/iora/backlog/2026-09-25-9_dns-async-cancel-teardown-transport-api_P1.json`. |
| **The default config cannot meet SIP Timer B, so a deadline needs a tuned config.** | `asyncAttemptBudget()` is dominated by `timeout × (retryCount + 1)` (the per-server UDP budget `udpAttemptBudget()` alone is ≈ 23.85 s at defaults, and `asyncAttemptBudget()` adds the TCP-fallback leg) and already exceeds Timer B/F (32 s), so `D = Timer_B/F − asyncAttemptBudget() − margin` underflows at the default config. A consumer wanting a per-resolution deadline must first REDUCE `DnsConfig::timeout` / `retryCount`; a negative/underflowed budget fails CLOSED (every non-cached resolution → `TransientFailure`) with a one-shot WARN. Not a code defect — a sizing constraint (§3.3 "Per-resolution deadline"). |
| **A deadline below one server's UDP-retransmit budget defeats next-server failover.** | If `maxResolutionTime` (or the override) is smaller than `udpAttemptBudget()` (one dead server's blackhole cost), a single dead server exhausts the whole deadline before the next server is tried, so RFC 1035 §7.2 next-server failover is effectively defeated. The resolver WARNs once on detecting this. The fix — per-server one-transmission-per-round sub-budgeting — is tracked `coding_trackers:tasks/iora/backlog/2026-09-30-5_dns-failover-rfc1035-72-per-round-cycling-and-dead-server-memory_P1.json`. |
| **The async deadline is a SOFT bound (one in-flight attempt is not aborted).** | On the async path the deadline gate stops issuing *further* servers/families at the `queryAsyncWithFailover` choke point but cannot abort the one in-flight `DnsTransport::queryAsync` attempt (that would race the fan-out latches), so the async worst case is `deadline + one asyncAttemptBudget()`, not exactly `deadline`. Size `D` with that overhang in mind. The sync path IS hard-bounded (≈ `deadline`). A hard async bound (aborting the in-flight attempt) is out of scope for this slice. |
| **No DNSSEC, EDNS(0), or `/etc/hosts` / search-list processing.** | `DnsClient` queries configured nameservers directly for a fixed record-type set; it does not validate DNSSEC, negotiate EDNS buffer sizes, or honor `/etc/hosts` or resolv.conf `search`/`ndots`. In split-horizon deployments it can disagree with the system resolver (§1). |
