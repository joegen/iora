# Iora Base64 / Base64Url Encoding and Decoding -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-09-18 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/util/base64.hpp` |
| **Namespace** | `iora::util` |
| **Dependencies** | `<array>`, `<cstdint>`, `<optional>`, `<string>`, `<string_view>`, `<vector>` (standard library only -- no `iora/core`, no third-party) |

This guide covers `iora::util::Base64Url` (RFC 4648 URL-safe alphabet, encode-only, no padding) and `iora::util::Base64` (RFC 4648 standard alphabet, `=`-padded, encode + strict decode). `Base64` is a load-bearing dependency of two other guides: [`../network/http_basic_auth.md`](../network/http_basic_auth.md) (decodes the RFC 7617 credential token via `Base64::decode`) and [`../network/websocket.md`](../network/websocket.md) (computes `Sec-WebSocket-Accept` and the `Sec-WebSocket-Key` nonce via `Base64::encode`, explicitly *not* `Base64Url` -- see `websocket.md`'s Dependencies row). `Base64Url::encode` is used by `iora::web::Assets::computeEtag` (`assets.hpp:513-519`) to build the filesystem ETag from a truncated SHA-256 digest.

**Document scope.** This guide uses the sanctioned lite variant of the Architecture & Programmer's Guide template (not all 12 sections): `base64.hpp` defines two classes that are pure static-method namespaces over `std::string_view` / byte buffers -- there is no instance state, no configuration surface, no threading model beyond reentrancy, and no multi-step call flow -- so the class-oriented sections (System Architecture, Configuration Reference, Call Flow) do not apply.

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-18 | Initial guide for `base64.hpp` (`Base64Url::encode`, `Base64::encode`, `Base64::decode`, `Base64::decodeToString`). |

---

## Executive Summary

**Problem.** Iora needs two distinct Base64 dialects for two distinct consumers. RFC 6455 WebSocket handshakes and RFC 7617 HTTP Basic auth both require the *standard* `+`/`/`-alphabet, `=`-padded Base64 of RFC 4648 §4 -- and the auth path additionally needs a **strict, non-malleable decode**: a naive decoder that tolerates non-canonical padding bits or embedded garbage turns one credential string into multiple byte-string encodings, which is exactly the kind of ambiguity an auth path must not have. Separately, filesystem-ETag generation (`assets.hpp:513-519`) needs a URL-safe, unpadded token (`=` and `/` are unsafe or meaningless in a header token / filename / URL path segment) but never needs to decode it back.

**Solution.**
- `iora::util::Base64Url::encode(const std::uint8_t*, std::size_t)` / `encode(const std::vector<std::uint8_t>&)` -- RFC 4648 §5 URL-safe alphabet (`-`/`_` in place of `+`/`/`), no padding, encode-only (`base64.hpp:27-87`).
- `iora::util::Base64::encode(...)` -- RFC 4648 §4 standard alphabet with `=` padding (`base64.hpp:122-170`).
- `iora::util::Base64::decode(std::string_view) -> std::optional<std::vector<std::uint8_t>>` -- strict decode; `std::nullopt` on any malformed input (`base64.hpp:194-285`).
- `iora::util::Base64::decodeToString(std::string_view) -> std::optional<std::string>` -- convenience wrapper over `decode()` for the text case (e.g. `user:pass`) (`base64.hpp:296-304`).
- `Base64`'s encoder and decoder share one alphabet definition, `kStdAlphabet`; the decoder's 256-entry reverse-lookup table is generated as that alphabet's inverse (`makeRevTable()`, `base64.hpp:99-118`), so the two directions can never disagree about which character maps to which 6-bit value (`base64.hpp:93-95`).

**Technical impact.** Both encoders are single allocation (`out.reserve(((len + 2) / 3) * 4)`, `base64.hpp:44`, `:130`), single-pass over the input, no intermediate `std::string` copies. `decode()` is binary-safe (indexes its reverse table with `std::uint8_t`, `base64.hpp:224-225` etc.) and never throws on malformed input -- only `std::bad_alloc` can propagate from the output vector (`base64.hpp:189-190`). Both classes are header-only with no `iora/core` dependency, so any translation unit can include `base64.hpp` alone.

---

## Deep Dive & Usage

### `Base64Url::encode` -- URL-safe, unpadded, encode-only

| Behavior | Source (file:line) |
|---|---|
| Alphabet: `A`-`Z a`-`z 0`-`9 - _` (RFC 4648 §5) | `kTable`, `base64.hpp:36-37` |
| Empty input (`len == 0`) returns an empty string | `base64.hpp:38-41` |
| Full 3-byte groups: 4 output characters per group, MSB-first 6-bit slices | main loop, `base64.hpp:46-57` |
| 1 trailing byte: 2 output characters, **no padding emitted** | `base64.hpp:60-67` |
| 2 trailing bytes: 3 output characters, **no padding emitted** | `base64.hpp:68-76` |
| No `decode()` counterpart exists in this class | absent from `base64.hpp:27-87` (class body) |

`encode(const std::vector<std::uint8_t>&)` (`base64.hpp:83-86`) is a thin forwarding overload to the pointer+length form.

### `Base64::encode` -- standard, padded

Identical 3-byte-group loop and 6-bit table indexing to `Base64Url::encode`, but indexing `kStdAlphabet` (`+`/`/`, `base64.hpp:101-102`) and, unlike `Base64Url`, emitting explicit `=` padding on a partial final group:

| Remaining bytes | Output | Source |
|---|---|---|
| 0 (full groups only) | no padding | main loop, `base64.hpp:132-143` |
| 1 | 2 alphabet chars + `==` | `base64.hpp:145-153` |
| 2 | 3 alphabet chars + `=` | `base64.hpp:154-162` |

### `Base64::decode` -- the strict decode contract

`decode` (`base64.hpp:194-285`) is deliberately **strict**: it rejects rather than best-efforts any input that is not canonical RFC 4648 Base64. Every rule below is verified against source:

| Rule | Source (file:line) |
|---|---|
| Empty input (`n == 0`) decodes to a **present, empty** vector (not `nullopt`) | `base64.hpp:197-200` |
| Input length must be a multiple of 4, else `nullopt` | `base64.hpp:201-204` |
| Every byte outside the standard alphabet (`A`-`Z a`-`z 0`-`9 + /`) or the `=` pad -- including embedded whitespace -- causes rejection | `kRevTable` lookup returning `-1`, tested at `base64.hpp:224-229`, `:248-252`, `:272-274` |
| The first two characters of every 4-character quantum must be alphabet bytes, never `=` | `v0 < 0 \|\| v1 < 0` check, `base64.hpp:224-229` |
| `=` padding is valid **only in the final quantum** | `lastQuantum` checks at `base64.hpp:235-238` (`==` case) and `:257-260` (`=` case) |
| `==` in the final quantum decodes to 1 output byte; requires the 3rd char `=` and the 4th char also `=` | `base64.hpp:231-245` |
| A single trailing `=` in the final quantum decodes to 2 output bytes | `base64.hpp:253-269` |
| **Strict pad-bit rejection:** for `==`, the low 4 bits of the 2nd sextet must be zero, else `nullopt`; for a single `=`, the low 2 bits of the 3rd sextet must be zero, else `nullopt` | `(v1 & 0x0F) != 0` at `base64.hpp:240-243`; `(v2 & 0x03) != 0` at `base64.hpp:262-265` |
| A full (unpadded) quantum decodes to 3 output bytes | `base64.hpp:270-281` |
| Malformed input never throws; returns `std::nullopt` | doc comment, `base64.hpp:189-190` |

The strict pad-bit rule is a **canonical-encoding enforcement / malleability defense**: RFC 4648 does not forbid a non-conformant encoder from setting the discarded pad bits to nonzero values, but if a decoder accepted them, two different wire strings could decode to the same bytes -- an ambiguity a decoder on an auth-adjacent path (`Base64::decode` is what `http_auth.hpp:246` calls on the RFC 7617 credential token) must not admit. The doc comment states this explicitly (`base64.hpp:183-187`).

Because the first two quantum characters are checked with a plain `v0 < 0 || v1 < 0` test that has no special case for `=`, degenerate inputs like `====`, `A===`, `=abc`, and `a=bc` are all rejected at that check (`kRevTable['='] == -1`), not at the later padding-specific checks (`base64.hpp:224-229`).

### `decodeToString` -- text convenience, with a caveat

`decodeToString` (`base64.hpp:296-304`) calls `decode()` and, on success, constructs a `std::string` from the byte range (`bytes->begin(), bytes->end()`) rather than treating the buffer as a C string -- so an embedded `NUL` byte is preserved in the resulting string's length, not treated as a terminator (`base64.hpp:303`). It returns `std::nullopt` iff `decode()` does.

The doc comment carries an explicit caveat: **`decodeToString` is not intended for secret material** -- it makes an additional, unscrubbed copy of the decoded bytes. For credentials, prefer `decode()` directly and wipe the returned `std::vector<std::uint8_t>` after use (`base64.hpp:293-295`).

### The string_view lifetime caveat

`decode`'s doc comment is explicit that **the input view is not retained beyond the call**: the caller must ensure the backing storage of the `std::string_view` argument outlives the call -- for example, bind a by-value `std::string` getter's result to a named local variable before deriving a `std::string_view` from it, rather than constructing the view from a temporary (`base64.hpp:191-193`).

### Usage

Examples compile against the real API.

**1. Compute a WebSocket `Sec-WebSocket-Accept`-style digest (standard, padded).**

```cpp
#include "iora/util/base64.hpp"

#include <cstdint>
#include <string>

std::string encodeDigest(const std::uint8_t *digest, std::size_t len)
{
  return iora::util::Base64::encode(digest, len);
}
```

**2. Decode an HTTP Basic auth credential token -- strict, no exceptions.**

```cpp
#include "iora/util/base64.hpp"

#include <optional>
#include <string_view>
#include <vector>

std::optional<std::vector<std::uint8_t>> decodeCredential(std::string_view token)
{
  // nullopt on any malformed token: wrong length, embedded whitespace,
  // non-alphabet byte, misplaced '=', or a nonzero discarded pad bit.
  return iora::util::Base64::decode(token);
}
```

**3. The cases callers must not "optimize" away.**

```cpp
#include "iora/util/base64.hpp"

using iora::util::Base64;

const auto a = Base64::decode("");       // present, empty vector -- not nullopt
const auto b = Base64::decode("TWFu");   // {'M','a','n'}
const auto c = Base64::decode("TWE=");   // {'M','a'}
const auto d = Base64::decode("TQ==");   // {'M'}
const auto e = Base64::decode("A===");   // nullopt -- '=' cannot appear at position 1
const auto f = Base64::decode("Zm 9v");  // nullopt -- embedded whitespace rejected
```

**4. Build a URL-safe token (e.g. an ETag-style digest) with `Base64Url`.**

```cpp
#include "iora/util/base64.hpp"

#include <cstdint>
#include <string>
#include <vector>

std::string urlSafeToken(const std::vector<std::uint8_t> &digestBytes)
{
  // No '=' padding and no '+'/'/' -- safe to embed directly in a URL path
  // segment, filename, or unquoted HTTP token. Encode-only: there is no
  // Base64Url::decode in this header.
  return iora::util::Base64Url::encode(digestBytes);
}
```

**5. `decodeToString` for the common text case.**

```cpp
#include "iora/util/base64.hpp"

#include <optional>
#include <string>
#include <string_view>

std::optional<std::string> decodeUserPass(std::string_view token)
{
  return iora::util::Base64::decodeToString(token); // e.g. "user:pass"
}
```

**Anti-patterns.**
- Do NOT feed a `Base64Url`-encoded string to `Base64::decode` (or vice versa): the two use different alphabets (`-`/`_` vs `+`/`/`) and different padding rules, so cross-decoding either fails outright or silently misdecodes any byte that differs between the two tables.
- Do NOT construct a `std::string_view` from a temporary and pass it to `decode()` -- the view is not retained beyond the call, so the backing storage must outlive it (`base64.hpp:191-193`). Bind a by-value getter result to a named variable first.
- Do NOT use `decodeToString` for secret material (passwords, tokens) without a follow-up wipe -- it makes an additional unscrubbed copy of the decoded bytes (`base64.hpp:293-295`). Prefer `decode()` and scrub the returned vector.
- Do NOT assume `decode()` tolerates surrounding or embedded whitespace -- it does not; the caller must trim before calling (`base64.hpp:178-179`).
- Do NOT treat a `nullopt` from `decode("")`-adjacent inputs as certain -- empty input is a **valid** decode (present empty vector), never `nullopt` (`base64.hpp:197-200`); only non-empty malformed input yields `nullopt`.
- Do NOT expect `Base64Url::encode` to emit padding -- there is no padding character in Base64URL by design here, unlike `Base64::encode`.

---

## Thread Safety Model

**Reentrant, no shared mutable state.** Every method on both classes is a `static` function operating solely on its arguments and stack locals. `Base64Url::kTable`, `Base64::kStdAlphabet`, and the decoder's `kRevTable` (built by `makeRevTable()`, a `constexpr` function) are all `static constexpr` -- their values are fixed at compile time, so there is no runtime initialization race and no mutable global/static state at all. `encode`, `decode`, and `decodeToString` may be called concurrently from any number of threads with no synchronization. All access to the caller-supplied buffers is read-only; the caller retains ownership and must keep the backing storage alive for the duration of each call (see the string_view lifetime caveat above).

---

## API Reference

```cpp
namespace iora
{
namespace util
{

class Base64Url
{
public:
  static std::string encode(const std::uint8_t *data, std::size_t len);
  static std::string encode(const std::vector<std::uint8_t> &bytes);
};

class Base64
{
public:
  static std::string encode(const std::uint8_t *data, std::size_t len);
  static std::string encode(const std::vector<std::uint8_t> &bytes);

  static std::optional<std::vector<std::uint8_t>> decode(std::string_view input);
  static std::optional<std::string> decodeToString(std::string_view input);
};

} // namespace util
} // namespace iora
```

| Method | Signature | Returns |
|---|---|---|
| `Base64Url::encode` | `std::string(const std::uint8_t *data, std::size_t len)` | URL-safe Base64, no padding |
| `Base64Url::encode` | `std::string(const std::vector<std::uint8_t> &bytes)` | Same, from a vector |
| `Base64::encode` | `std::string(const std::uint8_t *data, std::size_t len)` | Standard Base64, `=`-padded |
| `Base64::encode` | `std::string(const std::vector<std::uint8_t> &bytes)` | Same, from a vector |
| `Base64::decode` | `std::optional<std::vector<std::uint8_t>>(std::string_view input)` | Decoded bytes, present-empty for `""`, `nullopt` on any malformed input |
| `Base64::decodeToString` | `std::optional<std::string>(std::string_view input)` | Decoded bytes as text (embedded `NUL` preserved), `nullopt` iff `decode()` is |

---

## Design Decisions

| Decision | Rationale |
|---|---|
| Two separate classes (`Base64Url`, `Base64`), not one configurable encoder | Distinct alphabets, padding contracts, and consumer needs: `Base64Url` serves encode-only URL/filename/SIP-token generation (`base64.hpp:22-26`); `Base64` serves RFC 6455 / RFC 7617 interop, which mandates the standard padded form. |
| `Base64Url` provides `encode()` only, no `decode()` | Its one production caller, `Assets::computeEtag` (`assets.hpp:513-519`), only encodes a digest into an ETag; no consumer in the codebase needs URL-safe decode. |
| `Base64` encode and decode share one alphabet definition (`kStdAlphabet`); the reverse table is its generated inverse | The two directions can never disagree about a character's 6-bit value (`base64.hpp:93-95`, `:99-118`). |
| Strict pad-bit rejection on decode | Canonical-encoding enforcement: prevents multiple wire strings from decoding to the same bytes, closing a malleability vector on the HTTP Basic auth decode path (`base64.hpp:183-187`, `:240-243`, `:262-265`). |
| Reject embedded whitespace and any non-alphabet byte outright (never best-effort skip) | Keeps `decode()` a simple two-outcome contract (well-formed or `nullopt`); the caller is responsible for any pre-trimming (`base64.hpp:178-179`). |
| `decode()` never throws on malformed input | Composability with hot request-handling paths (e.g. auth) without exception-based control flow for routine bad input; only `std::bad_alloc` can propagate (`base64.hpp:189-190`). |
| `decodeToString` documented as unsuitable for secret material | It cannot avoid an additional unscrubbed copy when producing a `std::string`; callers handling credentials are steered to `decode()` plus an explicit wipe (`base64.hpp:293-295`). |

---

## Known Limitations

- **`Base64Url` has no decode counterpart.** Only `encode` is provided (`base64.hpp:27-87`); a caller needing to decode a Base64URL token must implement it separately.
- **`decode()` rejects embedded/surrounding whitespace rather than trimming it.** Callers must trim before calling; there is no lenient mode (`base64.hpp:178-179`).
- **No streaming/incremental API.** Both `encode()` and `decode()` require the complete buffer in memory; there is no chunked accumulator analogous to `Crc32::Incremental` in [`crc32.md`](crc32.md).
- **`decodeToString` is not scrubbed.** It documents the caveat but does not itself wipe the intermediate `decode()` result or the returned string; a caller decoding secret material must scrub explicitly (`base64.hpp:293-295`).
- **Test coverage is decode-focused; `encode()` has no direct known-answer-vector test.** `tests/web/test_base64_decode.cpp` asserts `Base64::decode` against RFC 4648 known-answer vectors (`"TWFu"`, the `"foobar"` progression) and the strict-rejection/padding/pad-bit cases, and exercises `Base64::encode` only indirectly via `decode(encode(x)) == x` round-trips (lengths 0..5) -- there is no test asserting `Base64::encode(bytesOf("Man")) == "TWFu"` or an equivalent direct known-answer check on the encoder. `Base64Url::encode` has no dedicated unit test at all: it is exercised only indirectly through `tests/web/test_assets.cpp`'s ETag test (`"Filesystem ETag is unquoted base64url, stable, content-sensitive"`), which checks output character-set legality, stability, and content-sensitivity, but never asserts a specific input-to-output mapping or the 1-/2-trailing-byte no-padding tail cases against a known-answer vector.

---

*See also:* [`crc32.md`](crc32.md) (the sibling `iora/util/` lite guide) and the consumers [`../network/http_basic_auth.md`](../network/http_basic_auth.md) and [`../network/websocket.md`](../network/websocket.md).
