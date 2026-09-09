# Iora Content-Coding List Primitives -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-09-09 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/parsers/content_coding.hpp` |
| **Namespace** | `iora::parsers` |
| **Dependencies** | `<string>`, `<string_view>`, `<vector>`, `iora/core/string_utils.hpp` (composes `StringUtils::split` / `trim` / `iequals`) |

This guide covers the response-side half of Iora's RFC 9110 content-coding negotiation. The header takes its name from the RFC "content-coding" token (`content_coding.hpp`), and its primitives operate on the value of the `Content-Encoding` header field: splitting a `Content-Encoding` coding list, classifying the gzip content-coding, and scrubbing an untrusted coding value before it can reach a log. Its request-side sibling, [`accept_encoding.md`](accept_encoding.md), covers the `Accept-Encoding` q-value acceptability decision (`gzipAcceptable`). Both are consumed together by the worked example in [`../rpc/jsonrpc.md` section 3.5 "Content-coding negotiation (RFC 9110)"](../rpc/jsonrpc.md#35-content-coding-negotiation-rfc-9110).

**Document scope.** This guide uses the sanctioned lite variant of the Architecture & Programmer's Guide template (not all 12 sections): `content_coding.hpp` is a small set of stateless pure functions -- there is no class, no instance state, no configuration surface, no threading model beyond reentrancy, and no call flow -- so the class-oriented sections (System Architecture, Configuration Reference, Call Flow) do not apply.

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-09 | Initial guide for `content_coding.hpp` (`splitContentCodings`, `isGzipContentCoding`, `sanitizeCodingForLog`). |

---

## Executive Summary

**Problem.** `Content-Encoding` (and, symmetrically, `Accept-Encoding`) is a list-valued field (RFC 9110 §5.3 / §8.4): duplicate field-lines combine with a comma (the combining itself is owned by [`http_message.md` §5.1](http_message.md), `detail::addOrCombineHeader`), and the combined value is an *ordered* comma-list of coding tokens. Both ingress paths of Iora's negotiated-gzip feature -- the server's request decode (`iora::rpc::JsonRpcHttpEndpoint`) and the client's response decode (`iora::rpc::JsonRpcClient`) -- must split that combined value into ordered, OWS-trimmed, non-empty tokens *identically*, must agree on which token means gzip, and must never let a hostile peer's coding value forge a log line (`content_coding.hpp:16-31`, `:72-73`).

**Solution.**
- `iora::parsers::splitContentCodings(std::string_view)` -- splits a combined `Content-Encoding` value into ordered, OWS-trimmed coding tokens, skipping empty/whitespace-only elements (`content_coding.hpp:43`).
- `iora::parsers::isGzipContentCoding(std::string_view)` -- the single home for the `gzip`/`x-gzip` equivalence, compared ASCII case-insensitively (`content_coding.hpp:63`).
- `iora::parsers::sanitizeCodingForLog(std::string_view, std::size_t maxLength = 128)` -- scrubs an untrusted coding value for safe inclusion in a log/exception message (`content_coding.hpp:74`).
- Deliberately Content-Encoding-scoped -- not a generic `splitCommaList(delim)` -- because only content-coding lists need this today (YAGNI) (`content_coding.hpp:29-31`).

**Technical impact.** `splitContentCodings` composes the foundation `iora::core::StringUtils::split` / `trim` primitives (zero-copy `std::string_view` splitting) and materializes owning `std::string` tokens only for the non-empty survivors. `isGzipContentCoding` is allocation-free. `sanitizeCodingForLog` builds one bounded output string, reserving up to `maxLength` bytes up front.

---

## Deep Dive & Usage

### The three functions and the RFC rules they enforce

| Function | Behavior | RFC 9110 | Source (file:line) |
|---|---|---|---|
| `splitContentCodings` | Split a combined value on `','` into ordered tokens, OWS-trim each, **skip** empty/whitespace-only elements. | §5.3 (comma-combining), §8.4 (ordered coding list), §5.6.1 (empty list elements are skipped) | body `content_coding.hpp:43-55`; empty-skip at `:50` |
| `splitContentCodings` | Tokens keep their **original case**; callers compare case-insensitively. | §8.4.1 (codings are case-insensitive) | `content_coding.hpp:41-42` (contract), `:52` (`emplace_back(trimmed)` preserves case) |
| `isGzipContentCoding` | `true` iff the token is `gzip` **or** its legacy alias `x-gzip`, compared ASCII case-insensitively. | §8.4.1 (`x-gzip` == `gzip`; case-insensitive) | `content_coding.hpp:63-67` |
| `sanitizeCodingForLog` | Keep every printable ASCII octet (`32`-`126`) verbatim -- SP included, so an embedded space is preserved as-is; replace each HTAB/CR/LF octet with a single space; drop every other octet (all non-printable-ASCII, including bytes `>= 0x7F`); bound length. | log-integrity defense (no RFC clause -- prevents log-line forgery by a non-conformant peer) | `content_coding.hpp:74-97` |

### `splitContentCodings` -- the ordered, empty-skipping split

`splitContentCodings` (`content_coding.hpp:43-55`) delegates the raw comma-split to `iora::core::StringUtils::split(value, ',')`, then for each resulting view applies `iora::core::StringUtils::trim` (OWS) and pushes an owning `std::string` **only if the trimmed view is non-empty**. This is what makes `"gzip,,"`, `", gzip"`, and `"gzip,   , identity"` all legal: the empty and whitespace-only elements that comma-combining can produce (§5.6.1) are dropped rather than surfaced as empty coding tokens. Order is preserved -- the output vector follows the list order, which matters because codings are applied in list order and decoded outermost-first (jsonrpc.md §3.5 rule (f)).

The returned tokens keep their original case (`content_coding.hpp:52` copies the trimmed view verbatim); the case-insensitive comparison is the caller's job, performed via `isGzipContentCoding` (§8.4.1).

### `isGzipContentCoding` -- the single gzip/x-gzip classifier

`isGzipContentCoding` (`content_coding.hpp:63-67`) returns `iora::core::StringUtils::iequals(tok, "gzip") || iora::core::StringUtils::iequals(tok, "x-gzip")`. It is the one place the `gzip`/`x-gzip` equivalence lives for both decode paths (server request, client response). Note the explicit design constraint (`content_coding.hpp:59-62`): `gzipAcceptable` in [`accept_encoding.hpp`](accept_encoding.md) intentionally keeps its *own* self-contained token match (it does not depend on `iora/core` and fuses the match into its q-value scan); do not reroute that header through this helper.

### `sanitizeCodingForLog` -- log-injection defense

`sanitizeCodingForLog` (`content_coding.hpp:74-97`) scrubs an untrusted `Content-Encoding` value so a hostile or non-conformant peer cannot forge log lines when the value appears in a diagnostic or exception message. It mirrors the DnsResolver precedent (`content_coding.hpp:73`). The algorithm, verified against source:

1. Compute `n = min(value.size(), maxLength)` and reserve `n` bytes (`:77-78`).
2. For the first `n` input octets (`:79`):
   - a printable ASCII octet (`32`-`126`) is kept verbatim (`:82-85`) -- this branch already covers SP (`32`), so an embedded space is preserved as-is rather than folded;
   - a HTAB, CR, or LF octet is replaced by a single space (`:86-89`) -- each such octet becomes one space (this removes the CR/LF that a log-line-forgery attack needs);
   - every other octet is dropped -- all non-printable-ASCII, including bytes `>= 0x7F` (`:90`).
3. If the original `value.size()` exceeds `maxLength`, `"..."` is appended (`:92-95`).

`maxLength` defaults to `128` (`content_coding.hpp:74`) and bounds the number of *input* octets scanned; the output can be shorter than `maxLength` when control octets are dropped, and is at most `maxLength + 3` bytes when truncation appends the ellipsis. There is no header sink here -- the function guards log integrity only (`content_coding.hpp:72-73`).

### Usage

Examples compile against the real API.

**1. Split, then validate every coding (the decode-path pattern).**

```cpp
#include "iora/parsers/content_coding.hpp"

#include <string>
#include <vector>

bool allCodingsAreGzip(const std::string &contentEncoding)
{
  const std::vector<std::string> codings =
    iora::parsers::splitContentCodings(contentEncoding);
  if (codings.empty())
  {
    return false;
  }
  for (const std::string &c : codings)
  {
    if (!iora::parsers::isGzipContentCoding(c))
    {
      return false;
    }
  }
  return true;
}
```

**2. Empty elements from comma-combining are skipped (§5.6.1).**

```cpp
#include "iora/parsers/content_coding.hpp"

// "gzip,," and ", gzip" both yield exactly one token: "gzip".
const auto a = iora::parsers::splitContentCodings("gzip,,");   // {"gzip"}
const auto b = iora::parsers::splitContentCodings(", gzip");   // {"gzip"}
```

**3. Scrub before logging an untrusted coding.**

```cpp
#include "iora/core/logger.hpp"
#include "iora/parsers/content_coding.hpp"

void rejectUnknownCoding(const std::string &rawContentEncoding)
{
  // A peer sending "gzip\r\nInjected-Line: evil" cannot forge a log line:
  // the CR/LF are folded to spaces and any non-printable octet is dropped.
  IORA_LOG_WARN("unsupported content-coding '"
                + iora::parsers::sanitizeCodingForLog(rawContentEncoding) + "'");
}
```

**Anti-patterns.**
- Do NOT compare a coding token with `==` -- codings are case-insensitive (§8.4.1); use `isGzipContentCoding` (or `StringUtils::iequals` for other tokens).
- Do NOT treat an empty result vector as "identity coding present" -- an empty vector means no non-empty coding token was found; the caller decides what that implies (`splitContentCodings` returns `{}` for `""`, `","`, or all-whitespace input).
- Do NOT interpolate a raw `Content-Encoding` value into a log or exception message -- always route it through `sanitizeCodingForLog` first (log-integrity, `content_coding.hpp:72-73`).
- Do NOT assume `sanitizeCodingForLog` collapses *runs* of whitespace -- it replaces each whitespace octet with one space, so `"a\t\tb"` becomes `"a  b"` (two spaces).
- Do NOT expect `splitContentCodings` to lower-case tokens -- it preserves original case by design (`content_coding.hpp:41-42`).
- Do NOT re-implement gzip classification inline; `isGzipContentCoding` is the single home for the `gzip`/`x-gzip` equivalence on the decode side (`content_coding.hpp:57-62`).

---

## Thread Safety Model

**Reentrant, no shared state.** All three functions are free `inline` functions with no global or static mutable state, no I/O, and no shared resources. `splitContentCodings` reads its `std::string_view` argument and returns a fresh `std::vector<std::string>`; `isGzipContentCoding` reads only its `std::string_view` argument; `sanitizeCodingForLog` reads its `std::string_view` argument and returns a fresh `std::string`. Each may be called concurrently from any number of threads with no synchronization. Callers retain ownership of the backing buffers for the `std::string_view` inputs and must keep them alive for the duration of the call. The composed `iora::core::StringUtils` primitives (`split`, `trim`, `iequals`) are themselves stateless static functions.

---

## API Reference

All symbols are `inline` free functions in `iora::parsers`.

```cpp
namespace iora
{
namespace parsers
{

/// Split a combined (RFC 9110 §5.3) Content-Encoding value into ordered,
/// OWS-trimmed coding tokens, skipping empty/whitespace-only elements
/// (§5.6.1). Tokens keep original case (§8.4.1: compare case-insensitively).
inline std::vector<std::string> splitContentCodings(std::string_view value);

/// True iff tok is the gzip content coding or its legacy alias x-gzip
/// (§8.4.1), compared ASCII case-insensitively.
inline bool isGzipContentCoding(std::string_view tok);

/// Scrub an untrusted content-coding value for safe logging: keep printable
/// ASCII verbatim (SP included), replace HTAB/CR/LF with a single space, drop
/// other control octets, and bound the length. Default maxLength = 128.
inline std::string sanitizeCodingForLog(std::string_view value,
                                        std::size_t maxLength = 128);

} // namespace parsers
} // namespace iora
```

| Function | Signature | Returns |
|---|---|---|
| `splitContentCodings` | `std::vector<std::string>(std::string_view value)` | Ordered, OWS-trimmed, non-empty coding tokens (original case) |
| `isGzipContentCoding` | `bool(std::string_view tok)` | `true` for `gzip` or `x-gzip`, case-insensitive |
| `sanitizeCodingForLog` | `std::string(std::string_view value, std::size_t maxLength = 128)` | Scrubbed, length-bounded copy (adds `"..."` if input exceeded `maxLength`) |

---

## Design Decisions

| Decision | Rationale |
|---|---|
| Content-Encoding-scoped, not a generic `splitCommaList(delim)` | Only content-coding lists need this today; a generalization would be unused surface (YAGNI) (`content_coding.hpp:29-31`). |
| Compose `StringUtils::split` / `trim` rather than hand-roll | Reuses the foundation zero-copy primitives; keeps the split identical to the rest of Iora (`content_coding.hpp:42`, `:46-48`). |
| Skip empty/whitespace-only elements | §5.6.1: comma-combining legally produces empty elements (`"gzip,,"`, `", gzip"`); skipping them is the RFC-correct handling (`content_coding.hpp:39-42`, `:50`). |
| Preserve original token case | §8.4.1 says codings are case-insensitive; comparison is the caller's job (via `isGzipContentCoding`), so the split does not destroy the original text (`content_coding.hpp:41-42`). |
| `isGzipContentCoding` is the single `gzip`/`x-gzip` home for the decode paths | One place for the §8.4.1 alias equivalence used by both server request and client response decode (`content_coding.hpp:58-60`). |
| `gzipAcceptable` deliberately does NOT route through `isGzipContentCoding` | `accept_encoding.hpp` has no `iora/core` dependency and fuses its token match into the q-value scan (`content_coding.hpp:59-62`). |
| `sanitizeCodingForLog` folds HTAB/CR/LF to a space (SP kept verbatim as printable) and drops other control octets | Removes the CR/LF a log-line-forgery attack needs while keeping the value human-readable; mirrors the DnsResolver precedent (`content_coding.hpp:72-73`, `:86-90`). |
| Default `maxLength = 128`, with a `"..."` truncation marker | Bounds the logged length against a padding/flood attack while signalling that the value was truncated (`content_coding.hpp:74`, `:92-95`). |

---

## Known Limitations

- **`splitContentCodings` does not validate coding names.** It splits and trims only; it does not reject unknown codings, enforce a maximum list length, or interpret `identity`. The decode paths perform those checks separately (a `<= 2` total-list cap and per-token validation; jsonrpc.md §3.5 rules (h) and the validate-before-decode contract).
- **Only gzip has a named classifier.** `isGzipContentCoding` recognizes `gzip`/`x-gzip`; there is no `deflate`, `br`, or generic coding classifier -- by design (YAGNI, `content_coding.hpp:29-31`). Any other coding token must be classified by the caller.
- **`sanitizeCodingForLog` folds each whitespace octet to its own space.** It does not collapse consecutive whitespace into one space; `maxLength` bounds *input* octets scanned, so the output can be shorter than `maxLength` (control octets dropped) or up to `maxLength + 3` bytes (ellipsis appended). It guards log integrity only -- there is no HTTP header sink involved.
- **Dedicated unit-test file.** These three functions now have a standalone suite in `tests/parsers/iora_test_content_coding.cpp`, asserting each primitive in isolation (the ordered empty-skipping split, `gzip`/`x-gzip` classification, and the log-scrub folding/truncation rules). They are additionally exercised in production through `iora::rpc::JsonRpcHttpEndpoint` (`jsonrpc_http.hpp:218`, `:234`, `:256`) and `iora::rpc::JsonRpcClient` (`jsonrpc_client.hpp:2703`, `:2715`, `:2724`, `:2729`-`:2731`), and the negotiated-gzip behavior is covered by `tests/rpc/iora_test_jsonrpc_gzip_foundation.cpp` and `tests/rpc/iora_test_jsonrpc_gzip_response.cpp`.

---

*See also:* [`accept_encoding.md`](accept_encoding.md) (the request-side `Accept-Encoding` q-value acceptability decision, `gzipAcceptable`) and the worked consumer in [`../rpc/jsonrpc.md` section 3.5](../rpc/jsonrpc.md#35-content-coding-negotiation-rfc-9110).
