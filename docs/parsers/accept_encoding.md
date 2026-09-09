# Iora Accept-Encoding Acceptability -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-09-09 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/parsers/accept_encoding.hpp` |
| **Namespace** | `iora::parsers` (internal helpers in `iora::parsers::acceptencoding_detail`) |
| **Dependencies** | `<cstddef>`, `<optional>`, `<string_view>` (standard library only -- no `iora/core`, no third-party) |

This guide covers the request-side half of Iora's RFC 9110 content-coding negotiation: the `Accept-Encoding` q-value acceptability decision. Its companion, [`content_coding.md`](content_coding.md), covers the response/`Content-Encoding` coding-list split, gzip classification, and log scrubbing. Both are consumed together by the worked example in [`../rpc/jsonrpc.md` section 3.5 "Content-coding negotiation (RFC 9110)"](../rpc/jsonrpc.md#35-content-coding-negotiation-rfc-9110).

**Document scope.** This guide uses the sanctioned lite variant of the Architecture & Programmer's Guide template (not all 12 sections): `accept_encoding.hpp` is a small set of stateless pure functions over a `std::string_view` -- there is no class, no instance state, no configuration surface, no threading model beyond reentrancy, and no call flow -- so the class-oriented sections (System Architecture, Configuration Reference, Call Flow) do not apply.

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-09 | Initial guide for `accept_encoding.hpp` (`gzipAcceptable`, `parseQValue`). |

---

## Executive Summary

**Problem.** More than one Iora HTTP surface must answer the same question -- "given this `Accept-Encoding` request header, may I gzip the response?" -- and answer it *identically*. The web application framework (static-asset serving) and the JSON-RPC HTTP endpoint each need the RFC 9110 §12.5.3 q-value semantics, not a naive `contains("gzip")`. A `contains` check silently misgets three cases the RFC mandates: `gzip;q=0` (explicitly *un*acceptable), coding precedence, and the `*` wildcard fallback. The decision began life as a private static member of `iora::web::Application`; duplicating or reaching up into the application layer from an endpoint module was the alternative this header replaces (`accept_encoding.hpp:16-27`).

**Solution.**
- `iora::parsers::gzipAcceptable(std::string_view)` -- one boolean, q-value-correct "is gzip acceptable?" decision (`accept_encoding.hpp:183`).
- `iora::parsers::acceptencoding_detail::parseQValue(std::string_view)` -- a locale-independent RFC 9110 §12.4.2 (Quality Values) qvalue parse returning `[0,1]`, `0.0` on any malformed input (`accept_encoding.hpp:89`).
- Deliberately gzip-specific (a boolean, not a generalized `codingAcceptable(ae, coding)`): only gzip is negotiated across Iora, so a generic version would be unused surface (YAGNI) (`accept_encoding.hpp:26-27`).

**Technical impact.** Single-pass, allocation-free scan over the header value using `std::string_view` sub-views throughout -- no `std::string` temporaries, no `std::stod` (which is locale-sensitive and admits scientific/out-of-range forms the grammar forbids). Header-only, standard-library-only, so any module can include it without a link dependency.

---

## Deep Dive & Usage

### What `gzipAcceptable` decides

`gzipAcceptable` returns `true` iff the response may be gzip-encoded for a request that carried the given `Accept-Encoding` value. The full rule set, each verified against source:

| Behavior | RFC 9110 | Source (file:line) |
|---|---|---|
| **Absent** Accept-Encoding: RFC says *any* content-coding is acceptable; `gzipAcceptable` conservatively returns `false` (send identity) | §12.5.3 ("If no Accept-Encoding field is in the request, any content-coding is considered acceptable") | trim-empty guard, `accept_encoding.hpp:186-189` |
| **Empty** Accept-Encoding value: RFC says the client wants *identity only*; `gzipAcceptable` returns `false` | §12.5.3 ("An Accept-Encoding header field with a combined field value that is empty implies that the user agent does not want any content-coding in response") | trim-empty guard, `accept_encoding.hpp:186-189` |
| An explicit `gzip` entry with a **non-zero** q-value is acceptable | §12.5.3 | `accept_encoding.hpp:210-213`, `:219-220` |
| `gzip;q=0` is **not** acceptable (returns `false`) | §12.5.3 (q=0 means "not acceptable") | `parseQValue` returns `0.0`; `eff > 0.0` test at `:219-220` |
| The legacy alias `x-gzip` is treated as `gzip` | §8.4.1 (`x-gzip` is equivalent to `gzip`) | `asciiIEquals(coding, "x-gzip")`, `accept_encoding.hpp:210` |
| `*` is the fallback, used **only** when neither `gzip` nor `x-gzip` is explicitly listed | §12.5.3 (`*` matches codings not otherwise listed) | precedence at `:219` -- `gzipQ` wins over `starQ` |
| An explicit `gzip;q=0` beats a `*` fallback | §12.5.3 (explicit entry has precedence over `*`) | `gzipQ ? *gzipQ : ...`, `:219` |
| Coding tokens are compared **case-insensitively** (ASCII fold) | §8.4.1 | `asciiIEquals` / `asciiLower`, `accept_encoding.hpp:57-83` |
| A **present but malformed / out-of-range** q is conservatively `0.0` (never enables a coding) | §12.4.2 (Quality Values) grammar `qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )` | `parseQValue`, `accept_encoding.hpp:89-136` |
| Absent q parameter on a listed coding defaults to `q=1` | §12.5.3 | `qValueOf` returns `1.0` when no `q`, `accept_encoding.hpp:163` |

RFC 9110 §12.5.3 draws *two distinct* rules for the absent and empty cases -- an **absent** field means any content-coding is acceptable, whereas an **empty** field value means the client wants identity only -- and `gzipAcceptable` collapses both to the same conservative outcome: it returns `false` (send identity). That single answer is permitted under *each* rule: identity is an acceptable choice when any coding is acceptable, and identity is exactly what an empty value demands. The single `trimView(...).empty()` guard (`accept_encoding.hpp:186-189`) covers both because a request with no `Accept-Encoding` field arrives as an empty/absent value at this call site.

Note the `*` wildcard match at `accept_encoding.hpp:214` uses an exact `coding == "*"` comparison (a single-character token), while the gzip/x-gzip match uses the case-insensitive `asciiIEquals`.

### Internal algorithm

`gzipAcceptable` (`accept_encoding.hpp:183-221`) runs one outer scan splitting the header on `','`. For each comma-separated entry it splits the coding token from its parameters on the first `';'`, OWS-trims the coding, and:
- If the coding is `gzip` or `x-gzip` (case-insensitive), it records the entry's q-value in `gzipQ`.
- Else if the coding is exactly `*`, it records the q-value in `starQ`.
- The q-value comes from `qValueOf(params)` (`:142`), which finds the `q=` parameter in the `';'`-list; absent q defaults to `1.0`.

After the scan the effective q is `gzipQ` if a gzip/x-gzip entry appeared, else `starQ` if a `*` appeared, else `0.0`; the function returns `eff > 0.0` (`:219-220`). If both a gzip and an x-gzip entry appear (pathological), the last one wins -- harmless, both mean gzip (`accept_encoding.hpp:208-209`).

`parseQValue` (`:89-136`) is a hand-rolled grammar-faithful parser, chosen over `std::stod` precisely because `std::stod` is locale-sensitive and accepts forms the qvalue grammar forbids. It accepts a leading `0` or `1`, an optional `.` followed by at most three digits, rejects a fourth fractional digit, rejects any non-digit after the leading digit, and rejects `q > 1.0` (e.g. `"1.5"`). Any violation yields `0.0`.

### Usage

The examples compile against the real API. `gzipAcceptable` is the only symbol callers normally need; `parseQValue` and the other helpers live in the `acceptencoding_detail` namespace and are exposed for testing, not for routine use.

**1. Negotiate a response encoding.**

```cpp
#include "iora/parsers/accept_encoding.hpp"

#include <string>
#include <string_view>

std::string chooseResponseEncoding(std::string_view acceptEncoding)
{
  if (iora::parsers::gzipAcceptable(acceptEncoding))
  {
    return "gzip";
  }
  return "identity";
}
```

**2. Feeding the header straight from a request.** The value passed in is the already-combined field value (duplicate `Accept-Encoding` field-lines are comma-combined upstream by [`http_message.md` §5.1](http_message.md) (`detail::addOrCombineHeader`), which owns the RFC 9110 §5.3 combining rule; see also jsonrpc.md §3.5 rule (a)).

```cpp
#include "iora/parsers/accept_encoding.hpp"

// "gzip, identity;q=0" still negotiates gzip: gzip defaults to q=1.
const bool ok = iora::parsers::gzipAcceptable("gzip, identity;q=0"); // true
```

**3. The q=0 and wildcard-precedence cases callers must not "optimize" away.**

```cpp
#include "iora/parsers/accept_encoding.hpp"

using iora::parsers::gzipAcceptable;

const bool a = gzipAcceptable("gzip;q=0");        // false -- explicitly unacceptable
const bool b = gzipAcceptable("gzip;q=0, *");     // false -- explicit gzip beats '*'
const bool c = gzipAcceptable("*");               // true  -- wildcard fallback
const bool d = gzipAcceptable("");                // false -- absent -> identity
```

**Anti-patterns.**
- Do NOT replace `gzipAcceptable` with `acceptEncoding.find("gzip") != npos`. That misses `gzip;q=0` (must be false), the `*` fallback, and case folding, all of which the RFC requires.
- Do NOT "fix" the absent/empty case to always-gzip. RFC 9110 §12.5.3 lets a server send identity when the field is absent; `gzipAcceptable` deliberately returns `false` there (`accept_encoding.hpp:179-182`).
- Do NOT reach for `parseQValue` to parse general floating-point q-like values -- it is a strict qvalue-grammar parser that returns `0.0` for anything outside `[0,1]` or with more than three fractional digits.
- Do NOT pass a single raw field-line when duplicate `Accept-Encoding` headers may arrive -- combine them first (comma-join in arrival order) so the q-value scan sees every entry.
- Do NOT route gzip token-matching in this header through `content_coding.hpp`'s `isGzipContentCoding`: this header intentionally keeps a self-contained match fused into the q-value scan and has no `iora/core` dependency (`content_coding.hpp:59-62`).

---

## Thread Safety Model

**Reentrant, no shared state.** Every function in `accept_encoding.hpp` is a free `inline` function operating solely on its `std::string_view` argument and stack locals; there is no global or static mutable state, no I/O, and no allocation of shared resources. `gzipAcceptable`, `parseQValue`, `qValueOf`, and the character helpers are safe to call concurrently from any number of threads with no synchronization. Passing overlapping or aliasing views to different threads is safe because all access is read-only; the caller retains ownership of the backing buffer and must keep it alive for the duration of the call.

---

## API Reference

All symbols are `inline` free functions. The public entry point is `gzipAcceptable`; the rest live in the nested `acceptencoding_detail` namespace (exposed for unit testing, not routine use).

```cpp
namespace iora
{
namespace parsers
{

/// RFC 9110 §12.5.3 Accept-Encoding acceptability for gzip (q-values).
/// True iff an explicit 'gzip'/'x-gzip' entry -- else '*' -- has a non-zero q.
/// Absent/empty header or q=0 -> false (identity).
inline bool gzipAcceptable(std::string_view acceptEncoding);

namespace acceptencoding_detail
{
inline bool isOws(char c);
inline std::string_view trimView(std::string_view s);
inline char asciiLower(char c);
inline bool asciiIEquals(std::string_view a, std::string_view b);

/// Locale-independent RFC 9110 §12.4.2 qvalue parse. Returns [0,1], or 0.0
/// for any malformed / out-of-range input.
inline double parseQValue(std::string_view v);

/// q-value from a ';'-separated parameter list. Absent q -> 1.0; present but
/// malformed/out-of-range q -> 0.0.
inline double qValueOf(std::string_view params);
} // namespace acceptencoding_detail

} // namespace parsers
} // namespace iora
```

| Function | Signature | Returns |
|---|---|---|
| `gzipAcceptable` | `bool(std::string_view acceptEncoding)` | `true` if gzip may be applied to the response |
| `parseQValue` | `double(std::string_view v)` | q in `[0,1]`, or `0.0` on any malformed / out-of-range input |
| `qValueOf` | `double(std::string_view params)` | q from a `;`-param list; `1.0` if no `q`, `0.0` if malformed |
| `trimView` | `std::string_view(std::string_view s)` | OWS-trimmed sub-view (SP/HTAB only) |
| `asciiIEquals` | `bool(std::string_view a, std::string_view b)` | ASCII case-insensitive equality |
| `asciiLower` | `char(char c)` | ASCII-lowercased character (non-A-Z unchanged) |
| `isOws` | `bool(char c)` | `true` for SP or HTAB |

---

## Design Decisions

| Decision | Rationale |
|---|---|
| Promote to `iora/parsers/` rather than `iora/web/` | Keeps a JSON-RPC endpoint from reaching UP into the application-framework layer for a shared parse decision (`accept_encoding.hpp:22-23`). |
| gzip-specific boolean, not a generic `codingAcceptable(ae, coding)` | Only gzip is negotiated across Iora; a generalization would be unused surface (YAGNI) (`accept_encoding.hpp:26-27`). |
| Hand-rolled `parseQValue`, not `std::stod` | `std::stod` is locale-sensitive and accepts scientific/out-of-range forms the qvalue grammar forbids (`accept_encoding.hpp:85-88`). |
| Present-but-malformed q -> `0.0` (not-acceptable) | Conservative: a garbage q must never *enable* a coding (`accept_encoding.hpp:139-141`). |
| Absent q -> `q=1` | RFC 9110 §12.5.3: a coding listed with no q defaults to q=1 (`accept_encoding.hpp:138-139`, `:163`). |
| `x-gzip` honored symmetrically with the decode side | A third-party client asking with `Accept-Encoding: x-gzip` is served gzip rather than falling through to identity (`accept_encoding.hpp:174-177`). |
| Self-contained token match (own `acceptencoding_detail`), not the shared `parsers::detail` | Avoids collisions with sibling parser helpers and keeps this header free of an `iora/core` dependency; the match is fused into the q-value scan (`accept_encoding.hpp:34-38`, `content_coding.hpp:59-62`). |
| Absent/empty header -> `false` | RFC 9110 §12.5.3 permits identity when the field is absent; callers must not override this (`accept_encoding.hpp:179-182`). |

---

## Known Limitations

- **gzip is the only negotiated coding.** There is no `deflate`, `br`, or generic coding acceptability -- by design (YAGNI, `accept_encoding.hpp:26-27`). A future coding would require extending this header, not a config change.
- **No structured result.** `gzipAcceptable` returns a bare `bool`; it does not expose the winning q-value, whether the match came from `gzip`, `x-gzip`, or `*`, or whether the header was malformed vs. simply absent. Callers needing that detail must scan the header themselves.
- **Caller must pre-combine duplicate field-lines.** `gzipAcceptable` scans one string. If duplicate `Accept-Encoding` field-lines arrive, the caller must comma-combine them (in arrival order) before calling; the header does not itself read the raw message. The JSON-RPC ingress path does this via `iora::network::detail::addOrCombineHeader` (jsonrpc.md §3.5 rule (a)).
- **ASCII-only case folding.** `asciiLower` folds only `A`-`Z`; this is correct for RFC 9110 coding tokens (US-ASCII tokens), but the helper is not a general Unicode case-folder.
- **Dedicated unit-test file.** `gzipAcceptable` and the `acceptencoding_detail` helpers now have a standalone suite in `tests/parsers/iora_test_accept_encoding.cpp`, which asserts the q-value matrix, the absent-vs-empty resolution, `x-gzip`/`*` precedence, and the `parseQValue` grammar boundaries directly. `gzipAcceptable` is additionally exercised through the negotiated-gzip integration matrix in `tests/rpc/iora_test_jsonrpc_gzip_foundation.cpp` (the "promoted gzipAcceptable q-value matrix" and "W-M1 seam" cases).

---

*See also:* [`content_coding.md`](content_coding.md) (the `Content-Encoding` coding-list split, gzip classification, and log scrubbing) and the worked consumer in [`../rpc/jsonrpc.md` section 3.5](../rpc/jsonrpc.md#35-content-coding-negotiation-rfc-9110).
