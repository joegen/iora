# Iora DnsClient — Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-09-14 |
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
- **`dns::DnsTransport`** — UDP-first with TCP fallback on truncation, exponential-backoff-with-jitter retries, per-query timeouts, round-robin server selection, and a per-session TCP receive-buffer cap for DoS resistance. It rides two `iora::network::Transport` instances (the UDP and TCP engines).
- **`dns::DnsMessage`** — a hardened DNS wire codec (encode query / parse response) with compression-pointer loop detection, label/name size limits, and per-record bounds validation.
- **`dns::DnsCache`** — a TTL-aware positive/negative cache backed by `util::ExpiringCache` (time-based expiration only).

### Technical Impact

- **Full RFC 3263 SIP server location** (the `S`/`A`-flag subset): `NAPTR`→`SRV`→`A`/`AAAA` with NAPTR-preference-then-SRV-priority ordering and RFC 2782 weighted selection.
- **Security-hardened parsing**: loop-bounded name decompression (a visited-pointer set caps decompression work), enforced 63-byte label / 253-octet name limits, and a per-session TCP buffer cap that closes abusive sessions.
- **Non-blocking application integration**: a best-effort cancellable async API delivered through `std::future` or a raw callback, with atomic double-delivery guards.
- **TTL-correct caching**: cache lifetime is the minimum record TTL across the response (RFC 1035); NXDOMAIN and NODATA negatives are cached at the SOA `minimum` per RFC 2308, and only when an SOA is present (RFC 2308 §5).

### `NameResolver` vs `DnsClient` (boundary)

NameResolver (name_resolver.hpp) vs DnsClient (dns_client.hpp). NameResolver is a single-shot host->socket-address helper that wraps the OS stub resolver (::getaddrinfo) and runs it off the I/O thread on blockingIoPool(), handing back an RAII addrinfo chain (OwnedAddrInfo) ready for an immediate connect(). It answers exactly one question -- 'which socket addresses back this host:port right now, per the system resolver?' -- and is an INTERNAL step of Transport's named-host connect path; applications do not call it directly. ('Async' here means off the caller/I/O thread; the resolution itself is a blocking getaddrinfo on a pool thread, not a non-blocking DNS-protocol implementation.) DnsClient is a standalone client that speaks the DNS wire protocol directly for a fixed set of record types -- A, AAAA, CNAME, MX, TXT, PTR, SRV, NAPTR (dns_client.hpp:178) -- plus RFC 3263 service discovery (NAPTR->SRV->A/AAAA, dns_client.hpp:179,289), exposed as synchronous, callback-async, and cancellable-future (AsyncDnsRequest) APIs, and consumed directly by application code (e.g. http_client.hpp). IMPORTANT -- the two consult DIFFERENT resolution stacks and can return different answers: NameResolver/getaddrinfo honors /etc/hosts, NSS ordering, and resolv.conf search/ndots options; DnsClient reads only the nameserver entries from /etc/resolv.conf and queries them directly (no /etc/hosts, no search-list processing), falling back to public resolvers 8.8.8.8/1.1.1.1 if none are configured -- so in split-horizon / internal-DNS deployments (common for SIP/SBC) the two can disagree, and DnsClient can bypass /etc/hosts overrides or leak to public DNS on a misconfigured host. Rule of thumb: connecting a Transport to a hostname -> NameResolver does it for you (internal, getaddrinfo, system resolution semantics); need DNS records or SIP/HTTP SRV service-location as data -> use DnsClient (direct DNS client). The record-type list alone proves they are different tools: MX/TXT/NAPTR/SRV are impossible via getaddrinfo, so DnsClient is not a NameResolver wrapper.

---

## 2. System Architecture

### Component Relationships

`DnsClient` owns the four backing components by `shared_ptr` and (re)creates them in `initialize()`:

```
DnsClient  (dns_client.hpp:204)
  config_       : dns::DnsConfig                       // value; the live configuration
  cache_        : shared_ptr<dns::DnsCache>            // null when config_.enableCache == false
  transport_    : shared_ptr<dns::DnsTransport>        // owns the wire layer + timers
  resolver_     : shared_ptr<dns::DnsResolver>         // RFC 3263 engine; holds transport_ + cache_

  dns::DnsResolver (dns_resolver.hpp:420)
    transport_  : shared_ptr<dns::DnsTransport>        // shared with DnsClient
    cache_      : shared_ptr<dns::DnsCache>            // shared with DnsClient (may be null)
    config_     : dns::DnsConfig
    rng_        : std::mt19937                          // weighted SRV selection (seedable, rngMutex_)

  dns::DnsTransport (dns_transport.hpp:79)
    udpTransport_ : shared_ptr<Transport>              // Transport::udp(config) — created for mode UDP/Both
    tcpTransport_ : shared_ptr<Transport>              // Transport::tcp(config) — created for mode TCP/Both
    pendingQueries_ : map<QueryKey, shared_ptr<PendingQuery>>   // guarded by queriesMutex_
    timerService_ : shared_ptr<core::TimerService>     // "DnsRetryTimer" — retries + timeouts
    cleanupThread_ : std::thread                       // 10 s sweep of expired queries

  dns::DnsCache (dns_cache.hpp:70)
    ExpiringCache<DnsCacheKey, CachedDnsResult>        // util/expiring_cache.hpp; time-based TTL

  dns::DnsMessage (dns_message.hpp:37)                 // all-static wire codec; owns no state
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
    Client-->>App: vector<SrvRecord> (or throws DnsNoRecordsException)
```

### Threading Model

| Thread | Responsibility |
|---|---|
| **Caller thread** | Runs the synchronous accessors (`resolveA`/`resolveSRV`/`query`/…); blocks on `std::future::wait_for` inside `DnsTransport::queryMultiple`. Immediate submission errors invoke the async callback here. |
| **Transport engine I/O thread** | Owned by the two `Transport` engines. Delivers normal DNS responses: `onData` → `DnsMessage::parse` → `processResponse` → `completeQuery` → user callback. |
| **`DnsRetryTimer` (TimerService) thread** | Fires per-query timeout completions (`scheduleQueryTimeout`) and retry re-sends (`retryQuery`). A timeout's user callback runs here. |
| **Cleanup thread** (`cleanupThread_`) | A 10-second sweep (`cleanupExpiredQueries`) that retries or times out queries the fast paths missed; those completion callbacks run here. |

**Consequence for callers:** an async callback (or `CancellableFuture` continuation) may run on any of three internal threads — the engine I/O thread, the `DnsRetryTimer` thread, or the cleanup thread — never assume it runs on the caller's thread. Callbacks must be thread-safe. This is documented on `DnsClient::resolveA(host, cb)` (`dns_client.hpp:460-464`).

---

## 3. Component Deep Dive

### 3.1 `DnsClient` (façade)

`DnsClient` is a thin, ownership-holding façade over the resolver. It is **move-only** (`dns_client.hpp:272-277`: copy deleted, move defaulted) because it owns transport threads.

**Construction and lifecycle.** Both constructors (default, and one taking a `dns::DnsConfig`) call `initialize()`, which: creates `cache_` iff `config_.enableCache` — seeding its default TTL from `config_.cacheTimeout` (else resets it); constructs `transport_` from `config_`; constructs `resolver_` from `(transport_, cache_, config_)`; and starts the transport, wrapping any start failure in `dns::DnsResolverException`. `start()` is a no-op that returns `true` (the transport is already started in the constructor); the destructor calls `stop()`, which stops the transport threads.

**Synchronous accessors.** Each typed accessor issues one `query()` and unpacks the typed record vector, throwing `dns::DnsNoRecordsException` when the corresponding vector is empty:

- `resolveA` / `resolveAAAA` → `std::vector<std::string>` of address strings.
- `resolveSRV` → `std::vector<dns::SrvRecord>`; `resolveNAPTR` → `std::vector<dns::NaptrRecord>`.
- `resolveMX` / `resolveTXT` → the typed record vectors; `resolveCNAME` → canonical names; `resolvePTR` → hostnames.
- `resolveHost` (`dns_client.hpp:243`) is the exception: it swallows per-family failures and returns a `HostResult{ipv4, ipv6, success}` where `success` is "at least one family resolved".

**Reverse DNS.** `resolvePTR` builds the query name via `createReverseQuery` (`dns_client.hpp:975`): IPv4 → dotted-octet-reversed `in-addr.arpa`; IPv6 → `createIpv6ReverseQuery` (`:877`) which strips brackets/zone, expands `::` to the full 32-nibble form via `expandIpv6Address` (`:913`), then emits the nibble-reversed `ip6.arpa` name. A malformed address throws `dns::DnsResolverException`.

**Service discovery** delegates straight to the resolver: `resolveServiceDomain` / `resolveServiceDomainAsync` / `resolveCustomServiceDomain[Async]`. The SIP-named `resolveSipDomain[Async]` are thin, `\deprecated` forwarders to the service-domain methods (`dns_client.hpp:701`).

**Cancellable async.** The façade adds the future-based ergonomics the resolver lacks:

- `resolveA(host, callback)` → `AsyncDnsRequest` (the primary async path; the sole out-of-line definition, `dns_client.hpp:1079`).
- `resolveAAsync(host)` → `CancellableFuture<std::vector<std::string>>`.
- `resolveServiceDomainFuture(domain, …)` → `CancellableFuture<dns::ServiceResolutionResult>`.

These wrap the resolver's callback API in a `std::promise`, guarding against double-set with a shared `std::atomic<bool>` (`promiseSet`) compare-exchange. `resolveAInternal` (`dns_client.hpp:1008`) adds a second guard, `RequestState::deliveryAttempted`, so exactly one thread delivers a given result even if response and timeout race.

### 3.2 `AsyncDnsRequest` and `CancellableFuture<T>`

`AsyncDnsRequest` (`dns_client.hpp:35`) is a cancellation handle over a shared `RequestState` — three `std::atomic<bool>` flags (`cancelled`, `completed`, `deliveryAttempted`) plus the queried `hostname`. `cancel()` does `cancelled.exchange(true, acq_rel)` and returns whether *this* call flipped it. Cancellation is **best-effort**: a callback already in flight on a transport thread may still fire (documented at `:54-58`).

`CancellableFuture<T>` (`dns_client.hpp:104`) pairs a `std::future<T>` with the request handle and the shared promise + `promiseSet` guard. Its `cancel()` (`:118`) cancels the request and, if it wins the `promiseSet` CAS, immediately sets the promise to a `dns::DnsResolverException("DNS request cancelled")` so a thread blocked in `future.get()` wakes without waiting for the network timeout.

### 3.3 `dns::DnsResolver` (RFC 3263 engine)

The resolver turns questions into results and orchestrates the service-location chain. It reads exactly one config field itself — `addressResolutionPolicy` — and defers all retry/timeout/server behavior to the transport.

**`query` / `queryAsync`** are the record-level primitives: consult `cache_` (if present), else `transport_->queryMultiple` / `queryAsync`, then apply the cache-write policy via `cacheQueryResult`. That policy caches positive results, and negative results (NXDOMAIN and NODATA — NOERROR with no answers) **only when the response carries an SOA** (RFC 2308 §5: a negative without an SOA has no authoritative TTL to bound it, so it is not cached and is re-queried). `resolveHostname` implements `AddressResolutionPolicy`:

- Query `A` when policy ∈ {IPv4Only, IPv4First, IPv6First}; query `AAAA` when ∈ {IPv6Only, IPv4First, IPv6First}.
- Combine: IPv4Only → A only; IPv6Only → AAAA only; IPv4First → A then AAAA; IPv6First → AAAA then A.
- The legacy `prefer_ipv6 == true` bumps `IPv4First` to `IPv6First` for backward compatibility. Empty result throws `dns::DnsNoRecordsException`.

**Service resolution — `resolveServiceDomain`** (`dns_resolver.hpp:457`) drives `performServiceResolution` (`:1166`):

1. **NAPTR query** the domain. If it fails (no NAPTR), fall back to `performDirectSrvResolution(domain, …, nullopt)` and return. If NAPTR succeeds but yields no usable target, the same direct-SRV fallback runs (sync and async behave identically here).
2. `processNaptrRecords` sorts by `order` then `preference` and processes NAPTR records in **ascending `ORDER`**, advancing to the next `ORDER` tier only when the current one yields no usable target and stopping at the first tier that does (RFC 3403 §4.1/§8 DDDS ordering). Within the chosen tier it maps each service string via `parseServiceType`, applies the `preferredTransports` filter, validates the replacement, and splits into `S`-flag SRV targets and `A`-flag direct targets. **`U`-flag (ENUM/regexp, RFC 6116) and empty-flag (chained NAPTR) records are intentionally skipped.**
3. For each `S` target, **SRV query** the replacement and append `ServiceTarget`s carrying the NAPTR preference; failed SRV queries are skipped.
4. For each `A` target, synthesize a `ServiceTarget` directly (no SRV): `port = getDefaultServicePort(service)`, `priority = weight = 0`, `naptrPreference =` the record's NAPTR preference field.
5. `resolveTargetAddresses` A/AAAA-resolves every target and drops those with no addresses.
6. `sortTargetsByPriority` stable-sorts by NAPTR preference (primary) then SRV priority (secondary).

**`performDirectSrvResolution`** is the no-NAPTR (and no-usable-NAPTR) path: it tries the standard SIP SRV names (`_sips._tcp`, `_sip._tcp`, `_sip._udp`, `_sip._sctp`), reordered by `preferredTransports`. An SRV RRset whose target is the root `.` (RFC 2782 "service decidedly not available") is skipped and marks that **service** denied. If no targets result, it calls `performFallbackResolution`, which does a plain A/AAAA lookup of the bare domain and builds one target per preferred transport (defaulting to `SIP_UDP`) — **excluding any service a `.` explicitly denied** (per-service suppression, not domain-wide: a `_sips._tcp` `.` does not strand plain SIP reachable via a bare A record).

**RFC 2782 weighted selection.** `ServiceResolutionResult::getPreferredTarget` finds the lowest-`naptrPreference` tier, then the lowest `priority` within it, then performs a cumulative-weight walk over `uniform_int_distribution<uint32_t>(0, total_weight-1)`. Three flavors exist: a deterministic-seed const overload, a `thread_local`-RNG production overload `getPreferredTargetWithDefaultRng`, and a caller-RNG template. The resolver-level `getPreferredTarget(result)` uses the resolver's own seedable `rng_` (`setRngSeed`) — guarded by `rngMutex_` — so tests can make selection reproducible without a data race.

**Async service resolution** (`performServiceResolutionAsync`) mirrors the sync chain but fans SRV queries out in parallel, coordinating completion with a shared `std::atomic<size_t> remainingQueries` (`fetch_sub(acq_rel)`), an `std::atomic<bool> callbackFired`, a `std::mutex resultMutex`, and a shared `deniedServices` vector; the last query to finish triggers async address resolution and fires the callback exactly once.

### 3.4 `dns::DnsTransport` (wire transport)

`DnsTransport` must be owned by a `shared_ptr` — `start()` calls `shared_from_this()`, so a stack instance throws `std::bad_weak_ptr` (`dns_transport.hpp:87-90`). It instantiates the engine(s) the configured `transportMode` needs — `Transport::udp(config)` for `UDP`/`Both`, `Transport::tcp(config)` for `TCP`/`Both` — and wires their `onData`/`onConnect`/`onClose` callbacks, each captured as a `weak_ptr<DnsTransport>` promoted per-use to avoid a reference cycle.

**Query lifecycle.** `queryMultiple` (sync, `:578`) and `queryAsync` (`:675`) mint a unique 16-bit query ID (`generateUniqueQueryId`, `:1446`), build a `QueryKey{id, server, port}` (`:167`), register a `PendingQuery` under `queriesMutex_`, encode the request with `DnsMessage::buildQuery`, and send over UDP (or TCP per `transportMode`). The sync path then blocks on `future.wait_for(calculateMaxSyncWaitTime())` (`:645`).

**Query-to-response matching** is by `QueryKey` — the `(queryId, server, port)` triple. Because the UDP and TCP engines mint colliding `SessionId`s, the response path maps a session back to its server via `sessionToServer_`, keyed by `(bool isTcp, SessionId)` (`:373`), preventing cross-engine confusion.

**UDP→TCP fallback** is truncation-driven, not size-driven: in `processResponse` (`:1129`) a UDP response with the `TC` flag set, when `transportMode == Both` and the query has not already fallen back, sets `tcpFallback = true` and re-sends over TCP. (`config_.maxUdpSize` is **not** consulted — see Known Limitations.)

**Retry / backoff / jitter.** `retryQuery` (`:1852`) computes `baseDelay = min(initialRetryDelay * retryMultiplier^retryCount, maxRetryDelay)`, then applies multiplicative jitter `× U(1 - jitterFactor, 1 + jitterFactor)` when `jitterFactor > 0`, and schedules the re-send on `timerService_`. Once `retryCount >= config_.retryCount`, the query completes with `dns::DnsTimeoutException`.

**Timeouts.** Each query arms a `TimerService` timeout of `config_.timeout` via `scheduleQueryTimeout` (`:1696`); the 10-second cleanup sweep (`cleanupExpiredQueries`, `:1774`) is a backstop that retries or times out anything the timer missed.

**DoS resistance.** TCP DNS is 2-byte length-prefixed. In `handleTcpData` (`:1031`, under `tcpBuffersMutex_`) the per-session accumulation buffer is capped at `config_.maxTcpBufferSize` (default 65536): exceeding it, or a length prefix that is zero / `> 65535` / `> maxTcpBufferSize`, clears the buffer and **closes the session**. `Transport::close` is enqueue-only, so calling it from inside the I/O-thread `onData` callback is safe.

**Server selection.** `getNextServer` (`:1339`) is round-robin over `config_.servers` via an atomic cursor, chosen per query only when the caller passes an empty `server`. There is **no per-query failover**: a retry re-sends to the same server; only a *new* query advances the cursor.

### 3.5 `dns::DnsMessage` (wire codec)

`DnsMessage` (`dns_message.hpp:37`) is an all-static, stateless codec.

**Encode.** `buildQuery` (the `recursionDesired` overload at `:328`, reached via the `:315`/`:321` forwarders) writes the 12-byte header (`RD` flag from `recursionDesired`; `opcode`/`rcode` implicitly 0), then the encoded question. `encodeName` (`:277`) enforces the 63-byte label limit and a 253-octet total-name limit — the RFC 1035 §3.1 presentation-format bound, marginally conservative against the 255-octet wire ceiling — throwing `DnsParseException` on violation. `generateQueryId` (`:222`) draws from a `thread_local` `mt19937` in the range 1–65535.

**Decode.** `parse` (`:366`) validates a minimum 12-byte header, decodes flags/counts (`parseHeader`, `:428`), then walks each section calling `parseResourceRecord` and `parseTypedRecord` (`:764`), which dispatches by `DnsType` into the typed vectors (`a_records`, `srv_records`, `naptr_records`, …). Per-record parse failures are logged and skipped, not fatal.

**Security.** Every read goes through `checkBounds` (`:268`). Name **decompression is loop-protected**: `decodeNameWithLoopDetection` (`:566`) tracks visited pointer offsets in an `unordered_set<uint16_t>` and throws on a repeated pointer or an out-of-range pointer (`0xC0` mask, `0x3FFF` offset). Each per-type parser validates its minimum `rdlength` (A == 4, AAAA == 16, SRV ≥ 6, NAPTR ≥ 4, MX ≥ 2, SOA ≥ 20), and `validateRdataSecurity` (`:1072`) runs after each RDATA read.

### 3.6 `dns::DnsCache`

`DnsCache` (`dns_cache.hpp`) wraps a `util::ExpiringCache<DnsCacheKey, CachedDnsResult>` (time-based expiration only — there is no entry-count cap). Its default TTL (for records that carry none) is seeded from `config_.cacheTimeout` and adjustable at runtime via `setCacheTtl`. The cache key (`DnsCacheKey`, `dns_types.hpp`) lowercases the query name for RFC 1035 case-insensitive matching.

**TTL derivation.** Positive entries use `calculateResultTtl` — the **minimum TTL** across every record in all sections (RFC 1035 conservative minimum), falling back to the default TTL only when no record carries one. Negative entries use `calculateNegativeTtl` — the SOA `min(minimum, ttl)` per RFC 2308, then the authority-section SOA TTL, then the default.

**Thread safety.** A `std::shared_mutex cacheMutex_` guards the backing `ExpiringCache` pointer: `get`/`put`/`putNegative`/`remove` take it shared, `clear()` takes it exclusively (it destroys and replaces the instance). A separate `std::mutex statsMutex_` (inner; ordering `cacheMutex_ → statsMutex_`) serializes the read-decide-count sequence in `put`/`putNegative` so concurrent same-key writes cannot double-count. Statistics are nine `std::atomic<uint64_t>` counters (`AtomicStats`); `defaultTtlSeconds_` is an `atomic<int64_t>`. `cleanupExpired()` is a no-op returning 0 (ExpiringCache sweeps on its own), and `setCleanupCallback` stores a callback that is never invoked (compatibility no-op).

---

## 4. Usage Guide

All examples assume `#include "iora/network/dns_client.hpp"` and `using namespace iora::network;`.

### Basic record queries (synchronous)

```cpp
DnsClient client; // default config: system resolv.conf servers, cache on

try
{
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
  std::cerr << "no records: " << e.what() << "\n";
}
catch (const dns::DnsResolverException &e)
{
  std::cerr << "resolve failed: " << e.what() << "\n";
}
```

### RFC 3263 SIP service location

```cpp
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
}
```

### Explicit SRV lookup

```cpp
DnsClient client;
std::vector<dns::SrvRecord> srv = client.resolveSRV("_sip._tcp.example.com");
for (const auto &rec : srv)
{
  std::cout << rec.priority << " " << rec.weight << " "
            << rec.target << ":" << rec.port << "\n";
}
```

### Cancellable async resolution (future)

```cpp
DnsClient client;

CancellableFuture<std::vector<std::string>> f = client.resolveAAsync("slow.example.com");

// ... elsewhere, give up early:
f.cancel(); // wakes a blocked get() with DnsResolverException immediately

try
{
  std::vector<std::string> addrs = f.future.get();
}
catch (const dns::DnsResolverException &e)
{
  std::cerr << "cancelled or failed: " << e.what() << "\n";
}
```

### Callback async (primary path)

```cpp
DnsClient client;

AsyncDnsRequest req = client.resolveA(
  "www.example.com",
  [](std::vector<std::string> addrs, std::exception_ptr err)
  {
    // WARNING: this runs on an internal thread (engine I/O, retry-timer, or cleanup).
    if (err) { /* handle */ return; }
    for (const auto &a : addrs) { /* use a */ }
  });

// best-effort cancel; the callback may still fire if already in flight
req.cancel();
```

### Configuring servers and cache

```cpp
dns::DnsConfig cfg;
cfg.setServers({"8.8.8.8", "1.1.1.1:53", "[2001:4860:4860::8888]:53"});
cfg.timeout = std::chrono::milliseconds{2000};
cfg.retryCount = 2;
cfg.enableCache = true;

DnsClient client(cfg);
client.setCacheTtl(std::chrono::seconds{600});
dns::DnsCacheStats stats = client.getCacheStats();
std::cout << "hit ratio: " << stats.getHitRatio() << "\n";
```

### Anti-Patterns

- **Do NOT assume the async callback runs on your thread.** It runs on the engine I/O thread, the `DnsRetryTimer` thread, or the cleanup thread. Never touch caller-thread-only state without synchronization from inside the callback.
- **Do NOT use `DnsClient` for a plain "connect me to this host".** That is `Transport`'s job via `NameResolver`/`getaddrinfo`, which honors `/etc/hosts`, NSS, and the resolv.conf search list. `DnsClient` queries nameservers directly and can disagree (see the §1 boundary).
- **Do NOT treat `cancel()` as a guarantee.** It is best-effort; a callback already dispatched on a transport thread will still fire. Guard your callback for the "cancelled but delivered" case.
- **Do NOT construct a `dns::DnsTransport` on the stack.** It requires `shared_ptr` ownership (`shared_from_this` in `start()`); a stack/`unique_ptr` instance throws `std::bad_weak_ptr`. Use `DnsClient`, which owns it correctly.
- **Do NOT rely on `maxCacheSize`, `maxUdpSize`, or `tcpTimeout`.** They are declared on `DnsConfig` for compatibility but are not enforced (see Configuration Reference and Known Limitations).
- **Do NOT expect a single failing query to try the next server.** Server selection is round-robin per query; a retry re-sends to the same server. Rotate by issuing independent queries, or pass an explicit `server`.

---

## 5. Call Flow / Sequence Reference

### Synchronous `resolveA` — success path

| Step | Component | Action |
|---|---|---|
| 1 | `DnsClient::resolveA` | Build `DnsQuestion{host, A, IN}`; call `query()`. |
| 2 | `DnsResolver::query` | Look up `cache_->get()`. On hit, return cached `DnsResult`. |
| 3 | `DnsTransport::queryMultiple` | `generateUniqueQueryId`; register `PendingQuery` under `queriesMutex_`; arm timeout on `timerService_`. |
| 4 | `DnsTransport::sendUdpQuery` | `DnsMessage::buildQuery`; send via the UDP engine. |
| 5 | Caller thread | Block on `future.wait_for(calculateMaxSyncWaitTime())`. |
| 6 | Engine I/O thread | `onData` → `DnsMessage::parse` → `processResponse` → `completeQuery` sets the promise. |
| 7 | `DnsResolver::query` | Populate `cache_->put()`; return `DnsResult`. |
| 8 | `DnsClient::resolveA` | Extract `a_records`; throw `DnsNoRecordsException` if empty, else return addresses. |

### Truncation → TCP fallback

| Step | Component | Action |
|---|---|---|
| 1 | Engine I/O thread | UDP `processResponse` observes `result.isTruncated()` (TC flag). |
| 2 | `DnsTransport` | Increment `truncatedResponses`. If `transportMode == Both` and `!tcpFallback` (under `queriesMutex_`): set `tcpFallback = true`. |
| 3 | `DnsTransport::sendTcpQuery` | Re-send the same query over the TCP engine (inner co-hold of `sessionsMutex_`); `return` without completing. |
| 4 | Engine I/O thread | TCP `handleTcpData` accumulates length-prefixed bytes under `tcpBuffersMutex_`; over `maxTcpBufferSize` → clear + `close(session)`. |
| 5 | `DnsTransport` | On a complete TCP message → `processResponse` → `completeQuery`. |

### Async cancellation (future path)

| Step | Component | Action |
|---|---|---|
| 1 | `CancellableFuture::cancel` | `request.cancel()` flips `RequestState::cancelled` (acq_rel exchange). |
| 2 | `CancellableFuture::cancel` | Win the `promiseSet` CAS → set promise to `DnsResolverException("cancelled")`; a blocked `future.get()` wakes now. |
| 3 | Later, transport thread | The real response arrives; the delivery callback loses the `promiseSet` CAS and returns without re-setting the promise (no double-set). |

### Timeout completion (retries exhausted)

| Step | Component | Action |
|---|---|---|
| 1 | `DnsRetryTimer` thread | Per-query timeout lambda fires (`scheduleQueryTimeout`) or `retryQuery` sees `retryCount >= config_.retryCount`. |
| 2 | `DnsTransport::completeQuery` | Remove the `PendingQuery` under `queriesMutex_`, release the lock, then invoke callback / set promise with `DnsTimeoutException`. |

---

## 6. Thread Safety Model

`DnsClient` itself carries no lock; it is move-only and expected to be constructed, configured, and destroyed by one owner. Reconfiguration methods (`updateConfig`, `setDnsServers`, `addDnsServer`, `removeDnsServer`) call `initialize()`, which **tears down and rebuilds** the transport/resolver/cache — do this only while the client is quiesced (no outstanding async queries).

| Component / operation | Synchronization | Notes |
|---|---|---|
| `DnsTransport` pending-query map | `queriesMutex_` | Guards `pendingQueries_`. `completeQuery` and the timeout lambda are **copy-then-invoke** (release before callback). |
| `DnsTransport::stop()` | `queriesMutex_` held during callback | The single callback-under-lock site: `stop()` invokes each pending query's error callback while holding `queriesMutex_` (`dns_transport.hpp:523-527`). A callback that re-enters the transport can deadlock. |
| `DnsTransport` sessions | `sessionsMutex_` | Guards `serverSessions_`, `sessionToServer_`, `connectedSessions_`, `pendingOnConnect_`. |
| `DnsTransport` TCP buffers | `tcpBuffersMutex_` | Guards per-session accumulation; the DoS cap + `close()` run here. |
| `DnsTransport` cleanup thread | `cleanupMutex_` + `cleanupCv_` | 10-second wait loop; `cleanupRunning_`/`running_` are atomics. |
| `DnsTransport` statistics | `std::atomic` counters | `InternalStatistics` (8 atomics); snapshot via `getStatistics()`. |
| `DnsTransport` lock ordering | Documented | `stateMutex_ / cleanupMutex_ > tcpBuffersMutex_ > queriesMutex_ > sessionsMutex_` (`dns_transport.hpp:320-342`). The truncation path holds `queriesMutex_` while `sendTcpQuery` takes `sessionsMutex_` (an intentional inner co-hold). |
| `DnsResolver` async coordination | per-op `std::mutex` + atomics | `resultMutex` + `remainingQueries` (`fetch_sub(acq_rel)`) + `callbackFired` + `deniedServices` are local to each async call, not members. Async continuations capture `self = shared_from_this()` to stay alive across the callback chain. |
| `DnsResolver::rng_` | `rngMutex_` | Guards the weighted-selection generator against concurrent `getPreferredTarget(result)` / `setRngSeed`; a leaf lock. |
| `DnsCache` container | `std::shared_mutex cacheMutex_` | Shared for `get`/`put`/`putNegative`/`remove`, exclusive for `clear()` (which replaces the `ExpiringCache`). Guards the pointer; the store is itself internally synchronized. |
| `DnsCache` stats | `statsMutex_` (inner) + `std::atomic` counters | Ordering `cacheMutex_ → statsMutex_`; the eviction callback takes neither (atomic `fetch_sub` only). |
| Async callback delivery | `RequestState::deliveryAttempted` + `promiseSet` CAS | Exactly-once delivery even when response and timeout race across threads. |

---

## 7. Configuration Reference

All fields are on `dns::DnsConfig` (`dns_types.hpp:542`). Timeouts use `std::chrono` types.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `servers` | `std::vector<DnsServer>` | System `/etc/resolv.conf`, else `{8.8.8.8:53, 1.1.1.1:53}` | Nameservers to query; round-robin per query. |
| `timeout` | `std::chrono::milliseconds` | `5000` | Per-query response timeout (UDP **and** TCP — see below). |
| `tcpTimeout` | `std::chrono::milliseconds` | `10000` | **Declared but unused** by `DnsTransport`; TCP uses `timeout`. |
| `cacheTimeout` | `std::chrono::seconds` | `300` | Default cache TTL for records that carry no TTL (seeds the `DnsCache`; also adjustable at runtime via `setCacheTtl`). |
| `retryCount` | `int` | `3` | Retry attempts per query (4 total attempts). |
| `initialRetryDelay` | `std::chrono::milliseconds` | `500` | First retry delay; grows by `retryMultiplier`. |
| `retryMultiplier` | `double` | `2.0` | Exponential backoff multiplier. |
| `maxRetryDelay` | `std::chrono::milliseconds` | `10000` | Backoff cap. |
| `jitterFactor` | `double` | `0.1` | Multiplicative jitter `× U(1−f, 1+f)` when `> 0`. |
| `enableCache` | `bool` | `true` | Create a `DnsCache`; when false, `cache_` is null. |
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
  std::shared_ptr<std::promise<T>> promise_;
  std::shared_ptr<std::atomic<bool>> promiseSet_;
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

Key `iora::network::dns` types (see `dns_types.hpp` / `dns_resolver.hpp`):

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
  ServiceTarget getPreferredTarget() const;                  // deterministic RNG
  ServiceTarget getPreferredTargetWithDefaultRng() const;    // thread_local RNG
  template <typename RNG> ServiceTarget getPreferredTarget(RNG &rng) const;
};

// Exceptions (dns_resolver.hpp): base + two subclasses
class DnsResolverException : public std::exception { /* getResponseCode() */ };
class DnsResolutionFailedException : public DnsResolverException {};
class DnsNoRecordsException : public DnsResolverException {}; // rcode NXDOMAIN
// dns_transport.hpp: DnsTransportException, DnsServerException (carries a DnsResponseCode),
//                    DnsTimeoutException
// dns_message.hpp:   DnsParseException (std::runtime_error)
```

---

## 9. Design Decisions

| Decision | Rationale |
|---|---|
| Separate DNS-protocol client from the transport `NameResolver`. | `getaddrinfo` cannot return `SRV`/`NAPTR`/`MX`/`TXT`; SIP/HTTP service location needs a real DNS client that queries nameservers directly. The two are documented as distinct tools with different resolution stacks (§1 boundary). |
| RFC 3263 limited to the `S`/`A`-flag subset. | SIP server location (RFC 3263 §4.1) needs only `S` (→SRV) and `A` (→direct A/AAAA) flags. `U`-flag/ENUM (RFC 6116) and chained NAPTR are out of scope and are explicitly skipped. Scope note: URI-level short-circuits (numeric-IP target, an explicit port, or an explicit transport per RFC 3263 §4.1–4.2) are the SIP-stack caller's responsibility, not `DnsClient`'s. |
| NAPTR processed in ascending `ORDER`, stopping at the first usable tier (RFC 3403 §8). | The DDDS algorithm mandates lowest-`ORDER`-first; descending to a higher `ORDER` only when the current tier yields no usable target avoids silently ignoring a valid fallback tier while still honoring precedence. |
| SRV `.` target suppresses fallback **per service**, not domain-wide (RFC 2782). | A `.` means "this service is decidedly not available at this domain." Suppressing only the denied transport's A/AAAA fallback (not the whole domain) prevents a `_sips._tcp .` from stranding plain SIP reachable via a bare A record. |
| Move-only façade owning `shared_ptr` components. | The transport owns threads and timers; copying would double-own them. Move preserves single ownership. Across async work the transport captures a `weak_ptr` (breaking a reference cycle) while the resolver captures a shared `self` (deliberate keep-alive for fire-and-forget resolution). |
| Query matched by `(queryId, server, port)`, session mapped by `(isTcp, SessionId)`. | The UDP and TCP engines mint colliding `SessionId`s; the composite session key prevents cross-engine response misattribution. |
| Truncation (TC flag) drives TCP fallback, not a size check. | The authoritative signal that a UDP answer was cut is the server's TC flag; falling back on a local size guess would be both over- and under-inclusive. |
| Exponential backoff with multiplicative jitter. | Bounded retry (`min(base·mult^n, cap)`) with `× U(1−f, 1+f)` jitter avoids synchronized retry storms (thundering herd) against a recovering server. |
| Per-session TCP buffer cap that closes on breach. | TCP DNS is length-prefixed; without a cap a malicious peer can force unbounded buffering. Closing the session bounds memory and is safe from the I/O thread (`close` is enqueue-only). |
| Best-effort cancellation with a `promiseSet` CAS. | A network request cannot be truly un-sent; the CAS lets `cancel()` win the race to set the promise so a blocked caller wakes immediately, while the later real response harmlessly loses the CAS (no double-set). |
| TTL = minimum record TTL (RFC 1035); negative TTL from SOA (RFC 2308). | The shortest TTL in a response bounds correctness; SOA `minimum` bounds negative caching. Both are standards-mandated conservative choices. |
| Negatives cached only when an SOA is present (RFC 2308 §5). | NXDOMAIN and NODATA are cached only if the response carries an SOA (the authoritative source of the negative TTL); a no-SOA negative is re-queried rather than cached with a guessed lifetime. |
| Cache is time-based (`ExpiringCache`); no entry-count cap. | A TTL-driven cache needs no LRU/size eviction for correctness; `maxCacheSize` is retained only for API compatibility and is not enforced. |

---

## 10. Known Limitations

| Limitation | Impact |
|---|---|
| **`maxUdpSize` is declared but unused.** | `DnsConfig::maxUdpSize` (default 512) is never consulted by `DnsTransport`; outbound UDP size is not checked and TCP fallback is purely TC-flag-driven. Setting it has no effect. |
| **`tcpTimeout` is declared but unused.** | `DnsConfig::tcpTimeout` (default 10000 ms) is never referenced; TCP queries use `config_.timeout` (5000 ms) like UDP. Do not rely on a distinct TCP timeout. |
| **`maxCacheSize` is not enforced.** | The cache has no entry-count bound; it is expiration-based only. A flood of distinct short-TTL names is bounded only by their TTLs, not by a size cap. |
| **NAPTR tier-descent does not re-descend on SRV-resolution failure.** | `processNaptrRecords` commits to the first `ORDER` tier that produces a selectable `S`/`A` record; if that tier's SRV RRset later resolves to nothing, a usable higher-`ORDER` tier is not retried. RFC 3263 §4.1 permits this ("first selectable tier wins"), but a peer that publishes fallback tiers expecting SRV-failure re-descent will not get it. |
| **Cache statistics are approximate under concurrent same-key writes.** | The insertion/replacement counters can drift by ±1 when a key expires in the window between a `put`'s existence check and its count update (the eviction callback decrements without `statsMutex_`). Cached data is unaffected; only the monitoring counters are approximate (tracked backlog). |
| **No per-query server failover.** | A failing query retries against the *same* server; only a new query advances the round-robin cursor. A single dead server is not skipped mid-query. |
| **`stop()` invokes callbacks under `queriesMutex_`.** | `DnsTransport::stop()` is the one callback-under-lock site (`dns_transport.hpp:523-527`); a callback that re-enters the transport during shutdown can deadlock. Keep shutdown-time callbacks non-re-entrant. |
| **`cleanupCache()` / `setCacheCleanupCallback` are no-ops.** | `cleanupExpired()` always returns 0 (ExpiringCache sweeps itself every ~5 s) and the stored cleanup callback is never invoked. Do not use them for monitoring. |
| **`resolveHost` swallows per-family errors.** | It returns `success = false` only when *both* A and AAAA fail; individual family errors are discarded, so a partial failure is invisible to the caller. Use `resolveA`/`resolveAAAA` when you need per-family error detail. |
| **Async callbacks run on internal threads.** | Callbacks fire on the engine I/O thread, the `DnsRetryTimer` thread, or the cleanup thread — never the caller's. Non-thread-safe callback bodies are a data race. |
| **Best-effort cancellation.** | `AsyncDnsRequest::cancel()` / `CancellableFuture::cancel()` cannot prevent an in-flight callback from firing; guard for the cancelled-but-delivered case. |
| **No DNSSEC, EDNS(0), or `/etc/hosts` / search-list processing.** | `DnsClient` queries configured nameservers directly for a fixed record-type set; it does not validate DNSSEC, negotiate EDNS buffer sizes, or honor `/etc/hosts` or resolv.conf `search`/`ndots`. In split-horizon deployments it can disagree with the system resolver (§1). |
