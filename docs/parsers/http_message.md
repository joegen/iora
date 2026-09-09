# Iora HTTP Message Model (parse / serialize / build) — Architecture & Programmer's Guide

[Back to index](../../README.md)

## 1. Metadata

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-09-09 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/parsers/http_message.hpp` |
| **Namespace** | `iora::network` (types), `iora::network::detail` (parse helpers) |
| **Dependencies** | Standard library only: `<algorithm>`, `<cctype>`, `<ctime>`, `<fstream>`, `<map>`, `<random>`, `<set>`, `<sstream>`, `<stdexcept>`, `<string>`, `<unordered_map>`, `<vector>` |

> **Layer note — read this first.** This header lives at `include/iora/parsers/http_message.hpp`, but every public type it declares is in namespace **`iora::network`** (for example `iora::network::HttpRequest`, `iora::network::HttpResponse`, `iora::network::ParsedUrl`), and the header-combining helpers are in **`iora::network::detail`** (`iora::network::detail::addOrCombineHeader`, `iora::network::detail::isListValuedHeader`). The `parsers/` directory is a *physical* location chosen so the message types sit at the foundation layer with no upward `#include` into the transport or application-framework layers; it is **not** a namespace. Do not write `iora::parsers::HttpRequest` — that type does not exist.
>
> This guide is the single source of truth for the message structures. It is cross-linked from the network HTTP guides — the client guide `docs/network/http_client.md` and the server guide `docs/network/http_server.md` (both authored in a later documentation slice) — which describe the transport and dispatch layers that *consume* these types. Where this guide refers to "the transport's own URL parser" or "the server dispatcher", the authoritative behavior of those consumers is documented there.

---

## 2. Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.1 | 2026-09-09 | Re-synced to the hardened header (commit `d915ec1`): bounded `parseChunkedBody` (rejects a non-HEXDIG lead byte and an oversized chunk-size before allocating); `chunked` detected as the FINAL transfer-coding via `detail::isChunkedFinalCoding` (not a substring); `HttpRequest::fromWireFormat` now *rejects* request-smuggling framing (conflicting/invalid `Content-Length`, `Transfer-Encoding`+`Content-Length`, non-final `chunked`, whitespace before a header colon); `MultipartFormData` rejects header-injection in name/filename/contentType and regenerates a colliding boundary; `parseUrl` scheme-lowering uses locale-free `asciiLower`; obs-fold reject framed per RFC 9112 §5.2 (permits reject-or-replace). Retitled to name the parse/serialize/build model; added `Content-Encoding`/`Accept-Encoding` consumer cross-links. |
| 1.0 | 2026-09-09 | Initial guide. Documents `HttpRequest`, `HttpResponse`, `ParsedUrl`, `MultipartFormData`, the RFC 9110 §5.3 field-line combining allow-list, and `normalizeOrigin` origin normalization, as implemented in `include/iora/parsers/http_message.hpp`. |

---

## 3. Executive Summary

### Problem

Iora replaces external HTTP dependencies (`cpr`, `cpp-httplib`) with homegrown, integrated message handling shared between the HTTP client and the HTTP/webhook server. Before this header existed, request/response framing, URL parsing, and duplicate-header handling were each hand-rolled at their point of use, and copies drifted apart. Concretely, the codebase carried:

- **Duplicated body-framing rules.** Multiple hand-rolled copies of "which statuses forbid a body" — one of which omitted the `1xx` range entirely — meant a `100 Continue` or `204 No Content` could be serialized with a stray `Content-Length`, hanging a keep-alive peer.
- **Last-wins-only header maps.** A repeated `X-Forwarded-For` or `Via` field-line silently overwrote the earlier one, discarding proxy hops (an RFC 9110 §5.3 violation) — while a naive "always combine" fix would have corrupted comma-bearing single-value fields such as `Set-Cookie` and `Date`.
- **Lenient URL/version parsing.** `std::stoi`-based version parsing accepted `HTTP/1.1xyz` and misrouted `HTTP/11.0`; ad-hoc origin derivation folded a pathless query into the hostname (`http://h?q=1` → host `h?q=1`), fragmenting one connection pool into one pool per query string.

### Solution

A single header of foundation-layer, dependency-free message primitives in `iora::network`:

- **`HttpRequest` / `HttpResponse`** — value types with `fromWireFormat` parsers and `toWireFormat` serializers. The request parser enforces RFC 9112 request-line, `Host`, and obs-fold rules with status-carrying `HttpRequestError`, and actively **rejects request-smuggling framing** (conflicting/invalid `Content-Length`, `Transfer-Encoding` + `Content-Length`, a non-final `chunked` coding, and whitespace before a header colon) with 400; the response serializer is the unbypassable choke point for bodyless-status framing, `Date` synthesis, and CR/LF/NUL injection suppression.
- **`iora::network::detail::addOrCombineHeader` + `isListValuedHeader`** — RFC 9110 §5.3 duplicate-field-line combining governed by a **safe-by-default allow-list**: only `#list`-grammar fields combine with `", "`; every other field keeps last-wins and can never be corrupted.
- **`ParsedUrl` / `parseUrl` / `normalizeOrigin`** — a lenient structural URL splitter plus a strict, security-relevant origin normalizer that produces a connection-pool key and rejects every form the transport's own URL parser cannot reach.
- **Shared grammar helpers** — `isHttpToken` (RFC 9110 §5.6.2), `isValidFieldValue` (§5.5), `headerHasInjection`, `statusForbidsBody` (RFC 9112 §6.3), and `detail::formatHttpDate` (§5.6.7 IMF-fixdate) — each the single definition consumed by both client and server.

### Technical Impact

- **One definition, no drift.** `statusForbidsBody`, `kBodyFramingHeaders`, `formatHttpDate`, and the `isListValuedHeader` allow-list are each the *single* source consumed by both the client framing path and the server serializer.
- **Locale-independent, injection-safe by construction.** All character classification uses direct ASCII range tests on `unsigned char` (never `std::isalnum`/`std::tolower`), so a non-C locale cannot over-accept non-tchar bytes, and the response serializer drops any field carrying CR/LF/NUL before it reaches the wire.
- **Zero synchronization.** Every function is pure or operates on a caller-owned instance; `formatHttpDate` uses the reentrant `gmtime_r`/`gmtime_s` (never the shared-static `std::gmtime`), so date formatting is safe on concurrent server worker threads with no lock.
- **Correct connection pooling.** `normalizeOrigin` collapses path/query/fragment/host-case/explicit-vs-default-port to one key while keeping `http` and `https` distinct — preventing a silent TLS downgrade from pool reuse.

---

## 4. System Architecture

### Component Relationships

All types are declared in `namespace iora::network`; the parse/format helpers are in the nested `namespace iora::network::detail`. There is no class hierarchy — these are free functions and standalone value types with no shared mutable state.

```
iora::network  (types in include/iora/parsers/http_message.hpp)
│
├── Enumerations / grammar helpers (free functions)
│   ├── enum class HttpMethod            GET..TRACE
│   ├── toString(HttpMethod)             -> "GET".."TRACE"
│   ├── parseMethod(string)              -> HttpMethod  (throws HttpRequestError 400/501)
│   ├── isHttpToken(string)              RFC 9110 §5.6.2  1*tchar
│   ├── isValidFieldValue(string)        RFC 9110 §5.5    field-vchar
│   ├── headerHasInjection(string)       CR / LF / NUL detector
│   └── statusForbidsBody(int)           RFC 9112 §6.3 rule 1  (1xx/204/304)
│
├── struct HttpVersion { int major{1}; int minor{1}; }
│       ├── toString() -> "HTTP/M.N"
│       └── static parse(string)          strict 8-char "HTTP/D.D"
│
├── struct CaseInsensitiveCompare         ASCII-fold ordering comparator
│       └── static asciiLower(unsigned char)
├── using HttpHeaders = std::map<string,string,CaseInsensitiveCompare>
│
├── constexpr kBodyFramingHeaders[]        {Content-Length, Content-Type, Transfer-Encoding, Trailer}
│
├── iora::network::detail
│       ├── formatHttpDate(time_t)         RFC 9110 §5.6.7 IMF-fixdate (reentrant, C-locale)
│       ├── isListValuedHeader(name)       §5.3 combinable allow-list
│       ├── addOrCombineHeader(map,k,v)     §5.3 combine-or-last-wins insert
│       └── isChunkedFinalCoding(te)        RFC 9112 §6.1 chunked-is-FINAL-coding test
│
├── struct ParsedUrl { scheme host port path query fragment }
│       ├── isHttps() / getDefaultPort() / getEffectivePort() / getPathWithQuery()
├── parseUrl(string)      -> ParsedUrl     lenient structural split
├── normalizeOrigin(string) -> string      strict connection-pool ORIGIN key
│
├── class HttpRequest  { method uri version headers body }
│       ├── toWireFormat() / static fromWireFormat(data)
│       └── private: parseRequestLine, parseHeaderLine, MAX_REQUEST_TARGET_SIZE
│
├── class HttpResponse { version statusCode statusText headers body }
│       ├── toWireFormat() [conformance choke point] / static fromWireFormat(data)
│       └── private: parseStatusLine, parseHeaderLine, parseChunkedBody
│
└── class MultipartFormData { struct Part; addField; addFile; getContentType; build }
```

**Ownership.** Every instance is caller-owned by value. `HttpHeaders` is a `std::map` keyed with `CaseInsensitiveCompare`, so header names are stored case-preserving but looked up case-insensitively. The wire bytes produced by `toWireFormat` are a plain `std::string`; the transport layer (documented in `docs/network/http_client.md` / `docs/network/http_server.md`) is responsible for sharing them across threads as an immutable `shared_ptr<string>`.

### Data Flow: parsing a request from the wire

```mermaid
sequenceDiagram
    participant Transport as Transport layer
    participant Req as HttpRequest::fromWireFormat
    participant RL as parseRequestLine
    participant HL as parseHeaderLine
    participant Comb as detail::addOrCombineHeader

    Transport->>Req: fromWireFormat(rawBytes)
    Req->>Req: find "\r\n\r\n" (else throw invalid_argument)
    Req->>Req: split header section / body
    Req->>RL: first line
    RL->>RL: strict single-SP split (method SP target SP version)
    RL->>RL: parseMethod (400 malformed / 501 unsupported)
    RL->>RL: HttpVersion::parse (400 on malformed) then major==1 else 505
    loop each subsequent header line
        Req->>Req: reject obs-fold (leading SP/HTAB -> 400)
        Req->>Req: reject whitespace before ':' (-> 400)
        Req->>Req: count Host; record Content-Length (distinct) + Transfer-Encoding
        Req->>HL: name/value split + OWS trim
        HL->>Comb: addOrCombineHeader(headers, key, value)
        Comb->>Comb: list-valued? combine ", " : last-wins
    end
    Req->>Req: smuggling checks (conflicting/invalid Content-Length; TE+CL; TE not final-chunked -> 400)
    Req->>Req: Host count checks (>1 -> 400; missing on 1.1 -> 400; empty value -> 400)
    Req-->>Transport: HttpRequest (or throws HttpRequestError with status)
```

### Threading Model

| Thread | Responsibility |
|--------|----------------|
| Any caller thread | Constructs, parses (`fromWireFormat`), mutates, and serializes (`toWireFormat`) its own `HttpRequest`/`HttpResponse` instances. No instance is shared. |
| Server worker threads (concurrent) | May call `HttpResponse::toWireFormat` simultaneously on *distinct* instances. Safe because the serializer reads only its own members and uses the reentrant `detail::formatHttpDate`. |

There are no mutexes, atomics, or condition variables in this header. Thread safety derives entirely from the absence of shared mutable state and the use of reentrant time conversion.

---

## 5. Component Deep Dive

### 5.1 RFC 9110 §5.3 duplicate-field-line combining — `addOrCombineHeader` + `isListValuedHeader`

This is the central non-obvious mechanism of the header. RFC 9110 §5.3 says repeated field-lines of a comma-list field are equivalent to one field-line whose value is the values joined, in order, by `", "`. But blindly combining is wrong for fields that carry *intrinsic* commas that are not list separators — `Set-Cookie` (an `Expires=` date contains ", "), `Date`, `Retry-After` (an HTTP-date form), `WWW-Authenticate`. Combining those corrupts them.

The design is therefore a **safe-by-default allow-list**: only fields whose ABNF grammar defines them as a `#list` combine; every other field keeps last-wins and is never corrupted.

**The verified allow-list** (`isListValuedHeader`):

```cpp
inline bool isListValuedHeader(const std::string &name)
{
  static const std::set<std::string, CaseInsensitiveCompare> kListValued = {
    "X-Forwarded-For", "Forwarded", "Via", "Content-Encoding", "Accept-Encoding"};
  return kListValued.count(name) != 0;
}
```

The allow-list is exactly these five field names, matched **case-insensitively** (the set uses `CaseInsensitiveCompare`):

| Field | Why it is combinable |
|-------|----------------------|
| `X-Forwarded-For` | De-facto comma-list of proxy hops. |
| `Forwarded` | RFC 7239 §4 `#list`. |
| `Via` | RFC 9110 §7.6.3 `#list`. |
| `Content-Encoding` | RFC 9110 §8.4 `#list` — a conformant sender MAY split stacked codings across repeated field-lines. |
| `Accept-Encoding` | RFC 9110 §12.5.3 `#list`. |

> **Downstream consumers of the combined value.** Once `addOrCombineHeader` has produced a single `", "`-joined `Content-Encoding` / `Accept-Encoding` string, the coding-negotiation layer splits and interprets it: see **[`docs/parsers/content_coding.md`](content_coding.md)** (parses the combined `Content-Encoding` coding stack for decode) and **[`docs/parsers/accept_encoding.md`](accept_encoding.md)** (parses the combined `Accept-Encoding` q-value list for content negotiation). This guide owns the §5.3 *combining* rule; those guides own the *splitting / negotiation* of the result.

Deliberately **excluded**, and why (from the source comment on `isListValuedHeader`):

- `X-Forwarded-Host` / `X-Forwarded-Proto` are single-valued-per-hop; they do not accumulate, and the protocol-correct handling of a duplicate is *ignore* (last-wins), not comma-join.
- `Set-Cookie`, `Retry-After`, `WWW-Authenticate`, `Date`, `Expires`, `Last-Modified`, `Content-Length`, `Cookie` are not `#list` fields; combining would corrupt them, so they keep last-wins.

The combining logic itself (`addOrCombineHeader`):

```cpp
inline void addOrCombineHeader(HttpHeaders &headers, const std::string &key,
                               const std::string &value)
{
  auto it = headers.find(key);
  if (it == headers.end())
  {
    headers.emplace(key, value);
    return;
  }
  if (isListValuedHeader(key))
  {
    if (value.empty())
    {
      return; // skip empty list element (keep existing combined value)
    }
    if (it->second.empty())
    {
      it->second = value;
    }
    else
    {
      it->second.append(", ").append(value);
    }
  }
  else
  {
    it->second = value; // non-list field: last-wins (prior behavior)
  }
}
```

**Invariants and preconditions:**

- **Precondition:** `value` is already OWS-trimmed by the caller (`parseHeaderLine`), so an all-whitespace value arrives as `""`. RFC 9110 §5.3 permits empty list elements; this implementation **drops** them — an empty element for a list field is a no-op (no stray leading/trailing/double comma).
- **First occurrence always inserts verbatim**, regardless of list-ness. Combining only happens on the *second and later* occurrences of a list-valued field.
- **Combining is unbounded** — any number of repeated lines merge. A per-consumer cap (for example the JSON-RPC decode path caps stacked `Content-Encoding` at ≤ 2) is enforced by that consumer; the server's max-header-bytes limit is the backstop for consumers that impose no cap. See `docs/rpc/jsonrpc.md` §3.5 (rule *a*) for the JSON-RPC consumer's use of this exact helper.
- **Both parse paths call it.** `HttpRequest::parseHeaderLine` and `HttpResponse::parseHeaderLine` are separate copies that each delegate to `detail::addOrCombineHeader`, so the semantics are identical on both directions.

### 5.2 `HttpRequest::fromWireFormat` — request parsing and RFC 9112 enforcement

`HttpRequest::fromWireFormat` splits on the first `"\r\n\r\n"` (throwing `std::invalid_argument` if the header terminator is absent), takes everything after it as the raw `body`, then parses the header section line-by-line. It enforces a set of RFC 9112 / RFC 9110 correctness rules, throwing `HttpRequestError` carrying the status the origin server should return:

| Rule | Source enforcement | Status |
|------|--------------------|--------|
| Request-line = `method SP request-target SP HTTP-version`, exactly one SP between fields | `parseRequestLine` strict SP-index split | 400 |
| No other whitespace/control (`< 0x21`) inside method or version fields | `parseRequestLine` | 400 |
| Request-target ≤ `MAX_REQUEST_TARGET_SIZE` (8192) | `parseRequestLine` | **414** |
| No CTL (`< 0x20`) or DEL (`0x7F`) in request-target; non-ASCII `0x80-0xFF` accepted as opaque | `parseRequestLine` | 400 |
| Method is a well-formed token but unsupported | `parseMethod` | **501** |
| Method token malformed | `parseMethod` | 400 |
| Malformed / missing HTTP-version | `HttpVersion::parse` mapped to 400 | 400 |
| HTTP major version other than 1 (0.9 / 2.0 / 3.0) | `parseRequestLine` | **505** |
| Obsolete line folding (obs-fold: a header line beginning with SP or HTAB) — RFC 9112 §5.2 permits reject-or-replace; iora chooses to reject | `fromWireFormat` header loop | 400 |
| Whitespace between a field-name and its colon (RFC 9112 §5.1) | `fromWireFormat` header loop | 400 |
| Conflicting duplicate `Content-Length` field-lines (two separate, differing values) — RFC 9112 §6.3 rule 5 | `fromWireFormat` | 400 |
| A single invalid (non-`1*DIGIT`) `Content-Length` — non-numeric, signed, empty, or an upstream-combined `"5, 6"` (one field-line, one map entry) | `fromWireFormat` | 400 |
| Both `Transfer-Encoding` and `Content-Length` present (RFC 9112 §6.3 rule 3) | `fromWireFormat` | 400 |
| `Transfer-Encoding` present whose final coding is not `chunked` (RFC 9112 §6.3 rule 4) | `fromWireFormat` via `isChunkedFinalCoding` | 400 |
| More than one `Host` field-line | `fromWireFormat` | 400 |
| Missing `Host` on HTTP/1.1+ (`version.minor >= 1`); HTTP/1.0 exempt | `fromWireFormat` | 400 |
| Empty (OWS-only) `Host` value | `fromWireFormat` | 400 |

**Method case-sensitivity.** `parseMethod` compares registered method names case-*sensitively* (RFC 9110 §9.1 registers uppercase names), so `get` is not `GET`; a well-formed lowercase token throws `501`.

**Strict single-SP request line.** The parser explicitly locates the two spaces (`line.find(' ')`, then `line.find(' ', p1 + 1)`) rather than using `std::istringstream`, which would collapse whitespace runs and silently tolerate smuggling-enabling variants. Empty method (`p1 == 0`), an empty target (`p2 == p1 + 1`), or a missing version field (`p2 + 1 >= line.size()`) all yield 400.

**Note — active request-smuggling rejection (RFC 9112 §6.3 / §5.1).** The parser does **not** merely tolerate framing-ambiguous requests and lean on the server's own body loop — it now actively **rejects** the smuggling vectors before returning a request. During the header loop it accumulates the distinct `Content-Length` values (into a `std::set`) and records whether a `Transfer-Encoding` was seen, then after the loop it throws `HttpRequestError(400)` for: conflicting duplicate `Content-Length` field-lines (two separate, differing values); a single invalid (non-`1*DIGIT`) `Content-Length` — including an upstream-combined `"5, 6"`, which is one field-line and therefore one map entry, rejected as a non-`1*DIGIT` value rather than as a duplicate; `Transfer-Encoding` and `Content-Length` present together; a `Transfer-Encoding` whose final coding is not `chunked` (via `detail::isChunkedFinalCoding`, §5.4); and whitespace between a field-name and its colon. Identical duplicate `Content-Length` values collapse to one and are tolerated. This is in addition to — not a replacement for — the HTTP server framing the request body in its own header loop *before* calling `fromWireFormat`; the parsed map is still never the framing source, but the parser now closes the desync vectors at the source. (See the framing test in `iora_test_http_header_combining.cpp`.)

### 5.3 `HttpResponse::toWireFormat` — the response conformance choke point

`HttpResponse::toWireFormat` is a `const` serializer and the **unbypassable** enforcement point for three response invariants. It mutates nothing — all filtering is applied to the local output stream, so the `const headers` map is untouched and the method is lock-free and safe on any thread.

1. **Bodyless-status framing (RFC 9112 §6.3 rule 1 / RFC 9110 §8.6).** For a status where `statusForbidsBody(statusCode)` is true (`1xx`, `204`, `304`), the body is suppressed and the four body-framing/representation headers in `kBodyFramingHeaders` (`Content-Length`, `Content-Type`, `Transfer-Encoding`, `Trailer`) are omitted from the output — regardless of what the builder set. The suppression set is a `std::set` using `CaseInsensitiveCompare`, so a handler-set `content-length` is matched regardless of case. `Date` is **not** in that set and is preserved.
2. **Date synthesis (RFC 9110 §6.6.1).** If no `Date` header is present (checked case-insensitively) and `statusCode` is in `[200, 500)`, a `Date:` header is appended using `detail::formatHttpDate(std::time(nullptr))`. A bodyless `204`/`304` is in this range and *does* get a `Date` (it is not a framing header). `1xx` and `5xx` are excluded because `Date` is a MAY there.
3. **Injection suppression (RFC 9110 §5.5 / RFC 9112 §2.2).** Any header whose name *or* value contains CR, LF, or NUL (`headerHasInjection`) is dropped in full — an injected value cannot be made safe by truncation. The status line's reason phrase is subject to the same rule: if `statusText` contains an injection byte, an *empty* reason is emitted rather than allowing it to split the response. This closes every start-line and header path to the wire.

> **Warning — do not extend `statusForbidsBody`.** `HEAD` is a *method*, not a status, and is handled separately (a `HEAD` response keeps the `Content-Length` a `GET` would send). `205 Reset Content` is deliberately **not** bodyless-framed: RFC 9112 §6.3 rule 8 makes any other response lacking both `Content-Length` and `Transfer-Encoding` close-delimited, so a `205` must receive `Content-Length: 0`; erasing its framing headers would convert a no-body response into an unframed one that hangs a keep-alive client. This warning is summarized from the source comment on `statusForbidsBody`.

### 5.4 `HttpResponse::fromWireFormat` — response parsing and chunked decoding

`HttpResponse::fromWireFormat` mirrors the request parser: split on `"\r\n\r\n"`, parse the status line, then each header via `parseHeaderLine` (same `addOrCombineHeader` combining). The body is re-assembled by `parseChunkedBody` **only when `chunked` is the final transfer-coding token**, decided by `detail::isChunkedFinalCoding` — *not* a substring match. It splits the (already §5.3-combined) `Transfer-Encoding` value on commas, strips any `;`-parameters and OWS from each token, skips trailing empty list elements (e.g. `"chunked,"`), and compares only the **last** non-empty token, case-insensitively, to `chunked`. So `"x-chunked"`, `"not-chunked"`, and a non-final `"chunked, gzip"` are correctly **not** de-chunked, while a parameterized final coding (`"chunked;x=y"`) still is. The same helper backs the request-side `Transfer-Encoding` framing check in §5.2.

`parseStatusLine` is intentionally lenient — it uses `std::istringstream` to read the version token and integer status code, then takes the remainder (minus a leading space) as `statusText`. This is a *client-side* parse of a trusted upstream response, so it does not apply the strict single-SP discipline of the request line.

`parseChunkedBody` is **bounded against a hostile chunk-size** (it decodes an already-fully-buffered payload). For each chunk-size line it (1) rejects a non-HEXDIG lead byte and stops — so `"-1"`, which `std::stoull(base 16)` would otherwise parse to `SIZE_MAX` and drive a huge allocation, no longer parses; (2) parses the hex size with `std::stoull(line, nullptr, 16)` (which stops at the `;` of any chunk-ext), stopping on a zero-size chunk or an out-of-range/unparseable size; and (3) **rejects a chunk-size greater than the total buffered payload (`chunkedData.size()`) before allocating** — a single chunk can never legitimately exceed the whole input, so this defeats a hostile size like `7fffffffffffffff` that would otherwise exhaust memory. It reads exactly `chunkSize` bytes per chunk and skips the trailing CRLF. It does not parse chunk extensions or a trailer section beyond the terminating chunk (see Known Limitations).

### 5.5 `ParsedUrl` and `parseUrl` — lenient structural URL split

`ParsedUrl` holds `scheme`, `host`, `port` (a `std::uint16_t`, default `0` meaning "use the scheme default"), `path`, `query`, and `fragment`, with convenience accessors:

- `isHttps()` — `scheme == "https"`.
- `getDefaultPort()` — `443` if HTTPS else `80`.
- `getEffectivePort()` — `port == 0 ? getDefaultPort() : port`.
- `getPathWithQuery()` — `path` (or `"/"` if empty), plus `"?" + query` when the query is non-empty.

`parseUrl` is a *lenient* splitter for general use:

- Throws `std::invalid_argument` on an empty URL or a URL missing `"://"`.
- Lowercases the scheme with `CaseInsensitiveCompare::asciiLower` (locale-*independent*; no signed-`char` UB on bytes `>= 0x80`).
- Extracts the fragment (after `#`) first, then path and query.
- Parses `port` via `static_cast<std::uint16_t>(std::stoi(portStr))` — **no range validation**, so `:65536` truncates to `0` and a non-numeric port throws out of `std::stoi`.
- When there is no `/`, the entire remainder (after scheme and fragment removal) is treated as the host — which means a pathless query is folded into the host (`http://h?q=1` → host `h?q=1`).

Because of these leniencies `parseUrl` is **not** suitable as a connection-pool key source; `normalizeOrigin` (§5.6) does a self-contained, strict parse instead. The HTTP transport layer additionally has its *own* private, hardened URL parser (`HttpClient::parseUrl`, documented in `docs/network/http_client.md`) that rejects userinfo, bracketed IPv6, and out-of-range ports; the free `iora::network::parseUrl` documented here is the general-purpose splitter, not that transport parser.

### 5.6 `normalizeOrigin` — strict, security-relevant connection-pool origin key

`normalizeOrigin` produces the canonical origin `scheme://host:effective-port` used as a connection-pool key. It is **security-relevant** on two axes: it must keep `http` and `https` distinct (so a pooled plaintext socket is never reused for a TLS request — a silent downgrade), and it must reject any form the transport's own URL parser would later reject (so a well-keyed pool whose every request fails can never be minted).

It does a **self-contained parse** and deliberately does *not* delegate to `parseUrl` (whose query-folding and lax port cast make it unusable as a key source). Behavior:

**Canonicalization (what collapses to one key):**
- Path, query, fragment, and trailing slash are dropped: `http://h/rpc`, `http://h/`, and `http://h` all normalize to `http://h:80`.
- The effective port is *always* emitted, so an explicit default port collapses with the absent port: `http://h:80/rpc` == `http://h/rpc` == `http://h:80`; `https://h:443/rpc` == `https://h:443`.
- Scheme and host are ASCII-lowercased (locale-*independent*, via `CaseInsensitiveCompare::asciiLower`): `http://EXAMPLE.Test/a` → `http://example.test:80`.
- A single trailing FQDN-root dot is stripped (`host.` and `host` reach the same endpoint): `http://h./rpc` → `http://h:80`.
- A non-default explicit port is preserved: `http://h:8080/rpc` → `http://h:8080`.
- The scheme stays in the key: `http://h:8443/` and `https://h:8443/` are **distinct** origins.

**Rejection (throws `std::invalid_argument`) — every form the transport parser cannot reach:**
- Any ASCII whitespace or control octet anywhere in the URL (`c <= 0x20 || c == 0x7F`), scanned over the *whole* string — including a trailing space in the path region — because the transport regex uses `\s` in its host and path classes and anchors on `$`.
- A scheme that is not the exact lowercase `http` or `https` (the transport matches the scheme case-sensitively): `HTTP://`, `Http://`, `ftp://`, `ws://` all throw.
- Userinfo in the authority (`user@host`, `user:pass@host`).
- A bracketed IPv6 literal (`[::1]`, `[2001:db8::1]`) — the transport's host class cannot express it.
- A port that is empty (`h:`), non-numeric (`h:abc`), zero (`h:0`), or `> 65535` (`h:65536`, `h:99999`). `65535` is the last valid port. Out-of-range values that would overflow `std::stoul` are caught and rethrown as `std::invalid_argument`.
- An empty host, or an empty DNS label — a leading dot (`.h`), a trailing empty label surviving the single-dot strip (`h..`), or an interior double dot (`a..b`). A single trailing root dot (`host.`) is fine.
- A query or fragment with **no path** (`http://h?q=1`, `http://h#frag`, `http://h:8080?q=1`, `http://h#`) — the transport's host regex does not stop at `?`/`#`, so it would fold them into the hostname and DNS-fail every send. A path-bearing query (`http://h/rpc?q=1`) is fine because the `/` stops the host class before the `?`.

**Documented deviations** (from the source comment on `normalizeOrigin`): the trailing-dot strip is a deliberate deviation from WHATWG URL host equality (which keeps `host.` distinct), justified because each request still carries its own `Host` header from its own URL — only the socket/pool is shared. Percent-encoded and IDN hosts are **not** decoded, so two encodings of one host key to two pools — an accepted over-split, never an under-collapse.

### 5.7 Grammar and formatting helpers

- **`isHttpToken(s)`** — true iff `s` is a non-empty RFC 9110 §5.6.2 token (`1*tchar`, where tchar = ALPHA / DIGIT / ``!#$%&'*+-.^_`|~``). Classification is direct ASCII range tests on `unsigned char` — never locale-sensitive `std::isalnum` — so a non-C locale cannot over-accept high bytes.
- **`isValidFieldValue(s)`** — true iff `s`, once surrounding OWS (SP/HTAB only) is stripped, contains only field-vchar / obs-text: it rejects controls other than HTAB (`< 0x20 && != 0x09`, which includes CR and LF — blocking header injection) and DEL (`0x7F`); obs-text `0x80-0xFF` is accepted. An empty or whitespace-only value is valid. OWS trimming is SP/HTAB only and never strips CR/LF (those are structural and must reach the reject test).
- **`headerHasInjection(s)`** — `noexcept`; true iff `s` contains CR, LF, or NUL.
- **`statusForbidsBody(code)`** — `constexpr`, `noexcept`; `code == 204 || code == 304 || (code >= 100 && code < 200)`.
- **`detail::formatHttpDate(t)`** — formats an epoch instant as a fixed 29-char RFC 9110 §5.6.7 IMF-fixdate (`"Sun, 31 May 2026 12:00:00 GMT"`) in UTC with C-locale English day/month abbreviations, using hand-rolled tables and the reentrant `gmTimeReentrant` (`gmtime_r`/`gmtime_s`) — never `std::gmtime` (shared static, not thread-safe) and never `strftime` (locale-dependent). On a conversion failure it returns the epoch (`"Thu, 01 Jan 1970 00:00:00 GMT"`).
- **`CaseInsensitiveCompare`** — the comparator behind `HttpHeaders`; `asciiLower` folds `A-Z` only, leaving bytes `>= 0x80` untouched (locale-independent, avoids UB on negative `char`).

### 5.8 `MultipartFormData`

`MultipartFormData` builds a `multipart/form-data` body. Its constructor generates a random 16-hex-char boundary suffix (`----IoraBoundary` + 16 hex digits from `std::mt19937` seeded by `std::random_device`). `addField(name, value)` adds a text part; `addFile(name, filename, content, contentType = "application/octet-stream")` adds a file part. `getContentType()` returns `"multipart/form-data; boundary=" + boundary` for use as the `Content-Type` header. `build()` serializes all parts with CRLF framing and the closing `--boundary--` delimiter.

**Header-injection rejection (RFC 7578 §4.2 / RFC 9110 §5.6.4).** `name` and `filename` are emitted **inside** a `Content-Disposition` quoted-string, so `rejectQuotedParam` fails fast with `std::invalid_argument` if either contains a double-quote `"` (would close the quoted-string), a backslash `\` (starts a quoted-pair; a trailing `\` escapes the intended closing quote and runs the parser past the part), CR, LF, or NUL. `contentType` is emitted as a **bare** header value, so `rejectBareHeaderParam` rejects only CR, LF, and NUL — a double-quote is legitimate in a media-type parameter (e.g. `charset="utf-8"`) and is therefore **allowed**. `addField`/`addFile` run these checks before storing the part, so an illegal value never reaches `build()`.

**Boundary collision avoidance.** Part content is opaque body data and is never injection-filtered, so a boundary token that happened to appear inside a part's content would forge a part separator. After each `addField`/`addFile`, `ensureBoundaryDistinct` regenerates the boundary (via `makeBoundary`) while it collides with any part's content. Because the boundary — not the content — is what moves, `getBoundary()`, `getContentType()`, and `build()` stay mutually consistent at all times.

---

## 6. Usage Guide

### 6.1 Building and serializing a request

```cpp
#include <iora/parsers/http_message.hpp>

using iora::network::HttpMethod;
using iora::network::HttpRequest;

HttpRequest req(HttpMethod::POST, "/rpc");
req.setHeader("Host", "api.example.test");
req.setJsonBody("{\"method\":\"ping\"}"); // sets Content-Type + Content-Length

std::string wire = req.toWireFormat();
// POST /rpc HTTP/1.1\r\nContent-Length: 17\r\nContent-Type: application/json\r\nHost: api.example.test\r\n\r\n{"method":"ping"}
```

### 6.2 Parsing a request and handling a malformed one by status

```cpp
#include <iora/parsers/http_message.hpp>

using iora::network::HttpRequest;
using iora::network::HttpRequestError;

int handleRawRequest(const std::string &raw)
{
  try
  {
    HttpRequest req = HttpRequest::fromWireFormat(raw);
    // ... dispatch on req.method / req.uri / req.headers ...
    return 200;
  }
  catch (const HttpRequestError &e)
  {
    // e.status() carries the RFC-appropriate status: 400, 414, 501, or 505.
    return e.status();
  }
  catch (const std::invalid_argument &)
  {
    // Missing "\r\n\r\n" header terminator.
    return 400;
  }
}
```

### 6.3 Combining repeated proxy-hop headers (RFC 9110 §5.3)

```cpp
#include <iora/parsers/http_message.hpp>

using iora::network::HttpRequest;

// Two X-Forwarded-For field-lines combine, in order, with ", ".
auto req = HttpRequest::fromWireFormat(
  "GET / HTTP/1.1\r\n"
  "Host: example.test\r\n"
  "X-Forwarded-For: 1.2.3.4\r\n"
  "X-Forwarded-For: 10.0.0.1\r\n"
  "\r\n");

// req.headers.at("X-Forwarded-For") == "1.2.3.4, 10.0.0.1"
// A duplicate Set-Cookie or Content-Length would instead be last-wins.
```

### 6.4 Using the direct combining helper

```cpp
#include <iora/parsers/http_message.hpp>

using iora::network::HttpHeaders;
namespace detail = iora::network::detail;

HttpHeaders h;
detail::addOrCombineHeader(h, "Via", "1.1 proxyA"); // absent -> insert
detail::addOrCombineHeader(h, "Via", "1.1 proxyB"); // list-valued -> combine
// h.at("Via") == "1.1 proxyA, 1.1 proxyB"

detail::addOrCombineHeader(h, "Content-Length", "5");
detail::addOrCombineHeader(h, "Content-Length", "7");
// h.at("Content-Length") == "7"  (non-list -> last-wins)
```

### 6.5 Normalizing an origin for a connection-pool key

```cpp
#include <iora/parsers/http_message.hpp>

using iora::network::normalizeOrigin;

std::string key1 = normalizeOrigin("http://Example.Test/a?x=1"); // "http://example.test:80"
std::string key2 = normalizeOrigin("http://example.test:80/b");  // "http://example.test:80"
// key1 == key2  -> same pool

try
{
  normalizeOrigin("https://user@h/rpc"); // userinfo -> reject
}
catch (const std::invalid_argument &e)
{
  // handle unpoolable URL
}
```

### 6.6 Anti-patterns

- **Do NOT write `iora::parsers::HttpRequest`.** The directory is `parsers/` but the namespace is `iora::network`. There is no `iora::parsers` namespace for these types.
- **Do NOT use `parseUrl` to derive a connection-pool key.** It folds a pathless query into the host and does not range-check the port. Use `normalizeOrigin`, which parses strictly and rejects unpoolable forms.
- **Do NOT extend `statusForbidsBody` with `205` or `HEAD`.** `HEAD` is a method (handled elsewhere) and `205` must carry `Content-Length: 0`; adding either breaks keep-alive framing.
- **Do NOT assume a duplicate `Content-Length` combines.** It is not on the `isListValuedHeader` allow-list. `fromWireFormat` now *rejects* conflicting duplicates and an invalid single value with `HttpRequestError(400)` (RFC 9112 §6.3); only identical duplicates are tolerated (collapsing to one, stored last-wins). It also rejects `Transfer-Encoding` + `Content-Length` together.
- **Do NOT hand `toWireFormat` output a status-injected reason phrase expecting it through.** An injected `statusText` (CR/LF/NUL) is replaced with an empty reason; injected headers are dropped entirely.

---

## 7. Call Flow / Sequence Reference

### 7.1 `HttpRequest::fromWireFormat` — success path

| Step | Action | Source |
|------|--------|--------|
| 1 | Find `"\r\n\r\n"`; if absent, throw `std::invalid_argument`. | `fromWireFormat` |
| 2 | `headerSection` = bytes before; `body` = bytes after the 4-byte terminator. | `fromWireFormat` |
| 3 | Read first line, strip trailing CR, call `parseRequestLine`. | `parseRequestLine` |
| 4 | For each subsequent non-empty line: reject obs-fold if it starts with SP/HTAB (400). | `fromWireFormat` |
| 5 | Reject whitespace before the `:`; OWS-trim the name; count `Host`, and record `Content-Length` (distinct values) and `Transfer-Encoding`. | `fromWireFormat` |
| 6 | `parseHeaderLine` → OWS-trim name & value → `detail::addOrCombineHeader`. | `parseHeaderLine`, `addOrCombineHeader` |
| 7 | After the loop: conflicting/invalid `Content-Length`, `Transfer-Encoding`+`Content-Length`, or `Transfer-Encoding` without a final `chunked` coding → 400. | `fromWireFormat` |
| 8 | `hostCount > 1` → 400. | `fromWireFormat` |
| 9 | `version.minor >= 1 && hostCount == 0` → 400. | `fromWireFormat` |
| 10 | `hostCount >= 1` and stored `Host` value empty → 400. | `fromWireFormat` |
| 11 | Return the populated `HttpRequest`. | `fromWireFormat` |

### 7.2 `parseRequestLine` — failure path (malformed request line)

| Step | Action | Result |
|------|--------|--------|
| 1 | Locate the two SP separators. | If missing/extra/empty field → throw `HttpRequestError(400)`. |
| 2 | Reject whitespace/control (`< 0x21`) inside method or version. | → `HttpRequestError(400)`. |
| 3 | `target.size() > 8192`. | → `HttpRequestError(414)`. |
| 4 | CTL/DEL in target. | → `HttpRequestError(400)`. |
| 5 | `parseMethod(methodStr)`. | Unknown-but-token → `501`; malformed token → `400`. |
| 6 | `HttpVersion::parse(versionStr)`. | Malformed → mapped to `HttpRequestError(400)`. |
| 7 | `version.major != 1`. | → `HttpRequestError(505)`. |

### 7.3 `HttpResponse::toWireFormat` — bodyless-status path

| Step | Action | Source |
|------|--------|--------|
| 1 | Emit status line; drop reason phrase if it contains CR/LF/NUL. | `toWireFormat` |
| 2 | Compute `bodyless = statusForbidsBody(statusCode)` and `hasDate`. | `toWireFormat` |
| 3 | For each header: if `bodyless` and name ∈ `kBodyFramingHeaders` set, skip. | `toWireFormat` |
| 4 | If name or value has injection bytes, skip the whole field. | `toWireFormat` |
| 5 | Else emit `key: value\r\n`. | `toWireFormat` |
| 6 | If `!hasDate && 200 <= statusCode < 500`, append synthesized `Date`. | `toWireFormat` |
| 7 | Emit the header-terminating CRLF; emit `body` only if `!bodyless`. | `toWireFormat` |

---

## 8. Thread Safety Model

No type in this header owns shared mutable state; there are no mutexes, atomics, or condition variables. Safety derives from value semantics and reentrant time conversion.

| Operation | Synchronization | Notes |
|-----------|-----------------|-------|
| `HttpRequest::fromWireFormat` / `toWireFormat` | None | Operates on a caller-owned instance and locals. |
| `HttpResponse::fromWireFormat` | None | Caller-owned instance. |
| `HttpResponse::toWireFormat` (`const`) | None | Reads only its own members; mutates nothing (filters applied to a local stream). Safe to run concurrently on distinct instances. |
| `detail::addOrCombineHeader` | None (caller owns the map) | Not internally synchronized; the caller must not share the target `HttpHeaders` across threads without external locking. |
| `detail::formatHttpDate` | None (reentrant) | Uses `gmtime_r`/`gmtime_s`; safe on concurrent worker threads. `std::gmtime` is deliberately not used. |
| `parseUrl` / `normalizeOrigin` | None | Pure functions of their argument. |
| Grammar helpers (`isHttpToken`, `isValidFieldValue`, `headerHasInjection`, `statusForbidsBody`, `parseMethod`, `toString`) | None | Pure. |
| `MultipartFormData` | None | Per-instance; the constructor's `std::random_device`/`std::mt19937` are instance-local. |

---

## 9. Configuration Reference

This header has no runtime configuration object. The only tunable is a compile-time constant.

| Constant | Value | Units | Where | Meaning |
|----------|-------|-------|-------|---------|
| `HttpRequest::MAX_REQUEST_TARGET_SIZE` | `8192` | bytes | `HttpRequest` private `static constexpr std::size_t` | Maximum request-target length; over-length yields `HttpRequestError(414)`. Kept well below the transport's `SessionInfo::MAX_HEADER_SIZE` (64 KB) so a deterministic 414 fires before the transport's silent header-size close. |

Fixed protocol values embedded in the code (not configurable):

| Item | Value | Source |
|------|-------|--------|
| Default HTTP version | `HttpVersion{1, 1}` | `HttpVersion` member defaults |
| Default response status | `200` / `"OK"` | `HttpResponse` member defaults |
| Default scheme ports | `80` (http) / `443` (https) | `ParsedUrl::getDefaultPort` |
| Bodyless statuses | `1xx`, `204`, `304` | `statusForbidsBody` |
| Body-framing header set | `Content-Length`, `Content-Type`, `Transfer-Encoding`, `Trailer` | `kBodyFramingHeaders` |
| List-valued (combinable) header allow-list | `X-Forwarded-For`, `Forwarded`, `Via`, `Content-Encoding`, `Accept-Encoding` | `isListValuedHeader` |
| `MultipartFormData` boundary prefix | `----IoraBoundary` + 16 random hex | `MultipartFormData::makeBoundary` |
| `addFile` default content type | `application/octet-stream` | `MultipartFormData::addFile` |

---

## 10. API Reference

All symbols are in `namespace iora::network` unless marked `detail`.

```cpp
enum class HttpMethod { GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, CONNECT, TRACE };

std::string toString(HttpMethod method);

class HttpRequestError : public std::runtime_error
{
public:
  HttpRequestError(int status, const std::string &message);
  int status() const noexcept;
};

bool isHttpToken(const std::string &s);
bool isValidFieldValue(const std::string &s);
HttpMethod parseMethod(const std::string &method);

struct HttpVersion
{
  int major{1};
  int minor{1};
  std::string toString() const;
  static HttpVersion parse(const std::string &version); // throws std::invalid_argument
};

struct CaseInsensitiveCompare
{
  static char asciiLower(unsigned char c);
  static bool equals(const std::string &a, const std::string &b); // ASCII case-insensitive equality
  bool operator()(const std::string &a, const std::string &b) const;
};

using HttpHeaders = std::map<std::string, std::string, CaseInsensitiveCompare>;

constexpr bool statusForbidsBody(int code) noexcept;
inline constexpr const char *const kBodyFramingHeaders[] =
  {"Content-Length", "Content-Type", "Transfer-Encoding", "Trailer"};
bool headerHasInjection(const std::string &s) noexcept;

namespace detail
{
  bool gmTimeReentrant(const std::time_t *t, std::tm *out);
  void appendTwoDigits(std::string &s, int v);
  std::string formatHttpDate(std::time_t t);
  bool isListValuedHeader(const std::string &name);
  void addOrCombineHeader(HttpHeaders &headers, const std::string &key,
                          const std::string &value);
  bool isChunkedFinalCoding(const std::string &transferEncoding);
}

struct ParsedUrl
{
  std::string scheme;
  std::string host;
  std::uint16_t port{0};
  std::string path;
  std::string query;
  std::string fragment;
  bool isHttps() const;
  std::uint16_t getDefaultPort() const;
  std::uint16_t getEffectivePort() const;
  std::string getPathWithQuery() const;
};

ParsedUrl parseUrl(const std::string &url);          // throws std::invalid_argument
std::string normalizeOrigin(const std::string &url); // throws std::invalid_argument

class HttpRequest
{
public:
  HttpMethod method{HttpMethod::GET};
  std::string uri;
  HttpVersion version{1, 1};
  HttpHeaders headers;
  std::string body;

  HttpRequest() = default;
  HttpRequest(HttpMethod m, const std::string &u);

  std::string getHeader(const std::string &name) const;
  void setHeader(const std::string &name, const std::string &value);
  bool hasHeader(const std::string &name) const;
  void setJsonBody(const std::string &jsonContent);
  void setFormBody(const std::string &formContent);
  std::string toWireFormat() const;
  static HttpRequest fromWireFormat(const std::string &data); // throws HttpRequestError / std::invalid_argument
};

class HttpResponse
{
public:
  HttpVersion version{1, 1};
  int statusCode{200};
  std::string statusText{"OK"};
  HttpHeaders headers;
  std::string body;

  HttpResponse() = default;
  HttpResponse(int code, const std::string &text = "");

  bool isSuccess() const;
  bool isInformational() const;
  bool isRedirection() const;
  bool isClientError() const;
  bool isServerError() const;
  std::string getHeader(const std::string &name) const;
  void setHeader(const std::string &name, const std::string &value);
  bool hasHeader(const std::string &name) const;
  void setJsonBody(const std::string &jsonContent);
  std::string toWireFormat() const;
  static HttpResponse fromWireFormat(const std::string &data); // throws std::invalid_argument
};

class MultipartFormData
{
public:
  struct Part
  {
    std::string name;
    std::string filename;
    std::string contentType;
    std::string content;
  };
  MultipartFormData();
  void addField(const std::string &name, const std::string &value);
  void addFile(const std::string &name, const std::string &filename,
               const std::string &content,
               const std::string &contentType = "application/octet-stream");
  std::string getBoundary() const;
  std::string getContentType() const;
  std::string build() const;
};
```

---

## 11. Design Decisions

| Decision | Rationale |
|----------|-----------|
| Types in `iora::network`, header in `parsers/` | Foundation placement: the message types must be usable with no upward `#include` into transport/app layers, while remaining conceptually part of the network surface. Directory ≠ namespace. |
| Safe-by-default combining **allow-list** (`isListValuedHeader`) | Combining is correct only for `#list`-grammar fields; a naive always-combine would corrupt `Set-Cookie`, `Date`, `Retry-After`. An allow-list means an unknown or non-list field can never be corrupted — it keeps last-wins. |
| Drop empty list elements when combining | RFC 9110 §5.3 permits empty elements; dropping them avoids stray leading/trailing/double commas. Callers pre-trim OWS so an OWS-only value arrives as `""`. |
| `statusForbidsBody` / `kBodyFramingHeaders` as single definitions | Prior hand-rolled copies drifted (one omitted `1xx`). One source consumed by both client framing and server serializer prevents regressions. |
| `toWireFormat` is the unbypassable conformance choke point | Every server response builder routes through it, so bodyless-framing, `Date` synthesis, and injection suppression are enforced in exactly one place, `const` and lock-free. |
| Locale-independent ASCII classification everywhere | `std::isalnum`/`std::tolower` are locale-sensitive and UB on negative `char`; a non-C locale could over-accept high bytes as tchar or mis-fold header names. Direct range tests on `unsigned char` are correct and deterministic. |
| Reentrant `formatHttpDate` (no `std::gmtime`, no `strftime`) | `std::gmtime` returns a shared static `tm`; Date headers are formatted concurrently on server workers. `strftime` is locale-dependent; the IMF-fixdate must be C-locale English. Hand-rolled tables also avoid `-Wformat-truncation`. |
| `normalizeOrigin` self-contained parse (not `parseUrl`) | `parseUrl` folds a pathless query into the host and does not range-check the port, so it would mint fragmented or dead pools. A dedicated strict parse keeps the pool-key parser and the transport parser in agree-or-both-reject lockstep. |
| `normalizeOrigin` keeps scheme in the key | `http` and `https` to the same authority must never share a pooled socket — that is a silent TLS downgrade. |
| `normalizeOrigin` strips a single trailing root dot | `host.` and `host` reach the same TCP endpoint; each request still carries its own `Host` header, so only the socket is shared. A deliberate deviation from WHATWG host equality, recorded in the source. |
| Strict single-SP request line (not `istringstream`) | Lenient whitespace is a §3 MAY but enables request smuggling across recipients; strict single-SP with 400 on any deviation is the safe choice. |
| Lenient response status-line parse | The response comes from a trusted upstream; strictness there buys nothing and would reject benign variations. |
| Method comparison case-sensitive | RFC 9110 §9.1 registers method names in uppercase; a lowercase token is unsupported (`501`), not silently normalized. |

---

## 12. Known Limitations

| Item | Impact |
|------|--------|
| `parseUrl` does not range-validate the port | `static_cast<std::uint16_t>(std::stoi(portStr))` truncates `:65536` to `0`, and a non-numeric port throws out of `std::stoi`. `parseUrl` is a lenient splitter; use `normalizeOrigin` (or the transport's hardened parser) where validation matters. |
| `parseUrl` folds a pathless query/fragment into the host | `http://h?q=1` yields host `h?q=1`. This is exactly why `normalizeOrigin` does its own parse and rejects such forms for pool keys. |
| `parseChunkedBody` ignores chunk extensions and the trailer section | It reads chunk sizes and data and stops at the zero chunk; chunk extensions (`;name=value`) after the size and any trailer fields after the last chunk are not parsed. Adequate for the responses Iora consumes; not a general-purpose chunked decoder. |
| `parseChunkedBody` stops (rather than throwing) on a malformed chunk size | A non-HEXDIG lead byte, an out-of-range/unparseable size, or a chunk-size larger than the buffered payload stops decoding and returns what was assembled so far. This is a **bounded** stop, not silent over-allocation: an oversized or negative chunk-size (e.g. `"-1"` → would-be `SIZE_MAX`, or `7fffffffffffffff`) is rejected *before* any allocation, so it cannot exhaust memory or let `std::bad_alloc`/`std::length_error` escape `fromWireFormat`. |
| `HttpResponse` framing enforcement lives only in `toWireFormat` | Callers that assemble response bytes without going through `toWireFormat` bypass the bodyless-framing, `Date`, and injection guarantees. All in-tree server builders route through it; out-of-tree callers must too. |
| No `Content-Length`/`Transfer-Encoding`-driven body length parsing in `fromWireFormat` | `fromWireFormat` takes everything after `"\r\n\r\n"` as the body verbatim (except the response chunked case). It assumes the transport has already delimited one complete message; it does not itself frame a stream. |
| Both `fromWireFormat` parsers accept a header framed with a bare LF (no CR) | Line splitting keys on `"\r\n\r\n"` and strips a trailing CR per line, so a header line ending in a lone LF is accepted — permitted by RFC 9112 §2.2 (a recipient MAY recognize a single LF as a line terminator). CRLF-consistency across a proxy chain is assumed to be enforced upstream / at the transport; a lone-LF-vs-CRLF disagreement between recipients is a classic request-smuggling / desync surface. |

---

## Cross-references

- **[`docs/parsers/content_coding.md`](content_coding.md)** — parses/decodes the combined `Content-Encoding` coding stack that `addOrCombineHeader` (§5.1) produces from repeated field-lines.
- **[`docs/parsers/accept_encoding.md`](accept_encoding.md)** — parses/negotiates the combined `Accept-Encoding` q-value list produced by the same §5.3 combining.
- **`docs/rpc/jsonrpc.md` §3.5** — the JSON-RPC content-coding negotiation path consumes `iora::network::detail::addOrCombineHeader` and the `Content-Encoding`/`Accept-Encoding` entries of the `isListValuedHeader` allow-list documented here.
- **`docs/network/http_client.md`** *(later slice)* — the HTTP client transport, its own hardened private URL parser, and connection pooling keyed by `normalizeOrigin`.
- **`docs/network/http_server.md`** *(later slice)* — the HTTP/webhook server dispatch, request body framing, and the response builders that route through `HttpResponse::toWireFormat`.

### Test coverage

| Test file | Covers |
|-----------|--------|
| `tests/parsers/iora_test_http_header_combining.cpp` | RFC 9110 §5.3 combining (both parse paths + direct helpers), `isListValuedHeader` allow/deny set, `isHttpToken`, `isValidFieldValue`, `addOrCombineHeader` branches, `Host`/obs-fold request enforcement, and the full `normalizeOrigin` accept/reject matrix. |
| `tests/network/iora_test_http_client_scheme_cache_key.cpp` | The security consequence of `normalizeOrigin` keeping the scheme in the key (no plaintext-connection reuse for an `https` request). |
| `tests/network/iora_test_http_client_parseurl.cpp` | The transport's own hardened `HttpClient::parseUrl` (distinct from the free `iora::network::parseUrl`); referenced here for the agree-or-both-reject contract. |
