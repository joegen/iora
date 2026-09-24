# Iora SecureRng -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-09-24 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/crypto/secure_rng.hpp` |
| **Namespace** | `iora::crypto` |
| **Dependencies** | OpenSSL `libcrypto` (`<openssl/rand.h>`, `<openssl/evp.h>`, `<openssl/hmac.h>`, `<openssl/err.h>`); C++17 standard library (`<cstddef>`, `<cstdint>`, `<limits>`, `<stdexcept>`, `<string>`). No `iora/core` dependency. |

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-24 | Initial guide, authored against source. Documents fixes made with it: `fill()` chunks a length above `INT_MAX` instead of narrowing it through the `int` cast, and rejects a null `dst` with `len > 0`; `hmacSha256` rejects a key longer than `INT_MAX`; `sha256`/`sha1`/`hmacSha256` reject a null output buffer; the digest chain short-circuits (Update/Final never run after a failed Init); every OpenSSL call is bracketed by an error-queue mark, so messages carry that call's own error and errors the caller had already queued are left in place; the unused `<array>`/`<vector>` includes were removed (downstream code that relied on them transitively must include them itself; `network/http_client.hpp` now does). New `tests/util/iora_test_secure_rng.cpp` suite. |

---

## 1. Executive Summary

### Problem

Several iora components need either unpredictable bytes or a standard digest, and every one of them is on a security-relevant path: the WebSocket client's `Sec-WebSocket-Key` and per-frame masking key (RFC 6455), the WebSocket server's `Sec-WebSocket-Accept` computation, the HTTP client's multipart boundary, the asset pipeline's content ETag, and (downstream) iora_sip's temporary-GRUU generation. Hand-rolling any of these with `std::rand`, `std::mt19937`, or a copied SHA-1 implementation is a real defect -- a predictable WebSocket mask or boundary defeats the property the spec requires it to have.

### Solution

`iora::crypto::SecureRng` is a stateless, all-`static` facade over OpenSSL `libcrypto`:

- `fill(std::uint8_t *dst, std::size_t len)` / `fill(Container &)` -- cryptographically secure random bytes from `RAND_bytes()` (`secure_rng.hpp:38-68`).
- `sha256(data, out[32])` and `sha1(data, out[20])` -- one-shot digests through the EVP interface (`secure_rng.hpp:75-129`).
- `hmacSha256(key, data, out[32])` -- one-shot HMAC-SHA-256 through OpenSSL's `HMAC()` (`secure_rng.hpp:142-174`).

Every failure throws: `std::runtime_error` for an OpenSSL failure (with the OpenSSL error string where one is available), `std::invalid_argument` for a null output buffer or an empty or over-`INT_MAX` HMAC key.

### Technical impact

Header-only, no instance state, no iora-level locking. Thread safety and entropy quality are exactly OpenSSL's (version details in §6). The EVP/HMAC one-shots allocate their own per-call context. The class name is broader than its contents suggest (it also hosts the digest and HMAC helpers) -- see Design Decisions.

---

## 2. System Architecture

`SecureRng` sits at the bottom of the iora dependency graph: it includes only OpenSSL and the standard library, and its callers are protocol and web components.

```
     iora_sip GruuGenerator, Identifiers, ... (hmacSha256, fill, sha256)   iora_sip Uuid users (via ids::Uuid)
                          |                                   |
  network::WebSocketClient  network::WebSocketServer  network::HttpClient  web::Assets   ids::Uuid
   fill (key, mask)          sha1 (Accept)             fill (boundary)     sha256 (ETag)  fill
   sha1 (verify Accept)
          \                      |                          |                |           /
           +---------------------+------------+-------------+----------------+----------+
                                              |
                                  iora::crypto::SecureRng  (secure_rng.hpp)
                                              |
                        OpenSSL libcrypto: RAND_bytes, EVP_Digest*, HMAC, ERR_*
```

In-tree call sites (verified against source):

| Caller | Call | Purpose |
|---|---|---|
| `network/websocket_client.hpp:669` | `fill(keyBytes, sizeof(keyBytes))` | 16-byte `Sec-WebSocket-Key` nonce (RFC 6455 §4.1) |
| `network/websocket_client.hpp:742` | `sha1(_wsKey + kGuid, sha1Out)` | Verify the server's `Sec-WebSocket-Accept` |
| `network/websocket_client.hpp:1317` | `fill(key, 4)` | Per-frame client masking key (RFC 6455 §5.3) |
| `network/websocket_server.hpp:262` | `sha1(concat, sha1Out)` | Compute `Sec-WebSocket-Accept` |
| `network/http_client.hpp:1065` | `fill(raw, sizeof(raw))` | 18 random bytes, hex-encoded into the multipart boundary |
| `web/assets.hpp:523` | `sha256(bytes, digest)` | Content hash for the static-asset ETag |
| `ids/uuid.hpp` | `fill(b)` / `fill(b.data() + 6, 10)` | Random bits of UUID v4 / v7 (see [`../ids/uuid.md`](../ids/uuid.md)) |

There is no in-tree iora caller of `hmacSha256`; its consumer is iora_sip's `GruuGenerator` (`iora/sip/gruu/GruuGenerator.hpp`). iora_sip also calls `fill` and `sha256` directly (for example in `Identifiers.hpp`, `SipMessage.hpp`, `ViaProcessor.hpp` and `GruuGenerator.hpp`).

---

## 3. Component Deep Dive

### `fill(std::uint8_t *dst, std::size_t len)` (`secure_rng.hpp:38-58`)

`RAND_bytes` takes an `int` length, while `fill` takes `std::size_t`. `fill` therefore loops, drawing at most `std::numeric_limits<int>::max()` bytes per `RAND_bytes` call (the private constant `kMaxIntLen`, `:178`, which `hmacSha256` also uses for its key-length check) and advancing `dst` until `len` is exhausted. A `len` of `0` performs no call at all.

On any `RAND_bytes` return other than `1` it throws `std::runtime_error("SecureRng: RAND_bytes failed: <openssl error>")` (`:50-53`). A null `dst` with `len > 0` is rejected with `std::invalid_argument`; `fill(nullptr, 0)` is a valid no-op. If a large request fails partway through, earlier chunks have already been written; the exception means the buffer as a whole must not be used.

**Fixed in this release.** Previously the whole `len` was passed through `static_cast<int>(len)`. On LP64 a `len` above `INT_MAX` narrowed to a negative or small value: for example `2^32 + 16` became `16`, so `RAND_bytes` filled only the first 16 bytes and returned success, leaving the rest of the buffer untouched without any error. The chunk loop removes that.

### `fill(Container &c)` (`secure_rng.hpp:64-68`)

A template convenience for any class-type container (`std::array<std::uint8_t, N>`, `std::vector<char>`, `std::string`, ...) with `data()`, `size()`, and a one-byte `value_type`. A C array has no `value_type`, so it needs the pointer overload, as in Usage example 2. The `static_assert(sizeof(typename Container::value_type) == 1)` rejects wider element types at compile time; the call then forwards to the pointer overload via `reinterpret_cast<std::uint8_t *>(c.data())`. It fills `size()` bytes, not `capacity()`.

### `sha256` / `sha1` (`secure_rng.hpp:75-129`)

Both first reject a null `out` with `std::invalid_argument`, then set an OpenSSL error-queue mark and run `EVP_MD_CTX_new()` (throw if null), `EVP_DigestInit_ex`, `EVP_DigestUpdate` and `EVP_DigestFinal_ex` as a short-circuiting chain -- Update and Final never run on a context whose Init failed -- then `EVP_MD_CTX_free`, then throw (with the OpenSSL error text) if the chain failed or the produced length is not 32 / 20. The context is freed before the check, so no path leaks it. `out` must point to at least 32 / 20 writable bytes -- the `unsigned char out[32]` parameter is an ordinary pointer after array-to-pointer decay, so only null is rejected; the size is **not** enforced. Input is a `const std::string &`, which is binary-safe (embedded `NUL` bytes are hashed).

SHA-1 is present for the RFC 6455 handshake, where the protocol mandates it; it is not a general-purpose collision-resistant hash (see Known Limitations).

### `hmacSha256` (`secure_rng.hpp:142-174`)

Rejects a null `out`, an empty key, and a key longer than `INT_MAX` bytes (OpenSSL's `HMAC()` takes the key length as `int`), all with `std::invalid_argument` before touching OpenSSL (`:144-156`). The null check matters beyond crash safety: given a null output pointer, OpenSSL's `HMAC()` writes into a shared static buffer (not thread-safe) and still reports success. It then sets an error-queue mark, calls the one-shot `HMAC(EVP_sha256(), key, data, out, &len)` and throws `std::runtime_error` if it returns null or `len != 32`. The empty-key rejection is iora policy: RFC 2104 itself permits an empty key, but for the intended callers (keyed identifiers such as temporary GRUUs) an empty secret is always a configuration mistake. The one-shot `HMAC()` function is not deprecated in OpenSSL 3.x (the deprecated API is `HMAC_CTX_*`).

### `popErrorsToMark()` (private, `secure_rng.hpp:183-195`)

Every OpenSSL call site brackets its call with `ERR_set_mark()` and `ERR_pop_to_mark()`. On failure, `popErrorsToMark()` formats the newest error (`ERR_peek_last_error()` via `ERR_error_string_n`, 256-byte buffer), pops back to the mark, and returns `"no OpenSSL error available"` if nothing was raised since the mark. So every exception message (including the `EVP_MD_CTX_new` failures) carries that call's own error, and OpenSSL errors the calling code had queued before the SecureRng call are left in place for it to read -- SecureRng neither reports them nor clears them.

---

## 4. Usage Guide

**1. Random nonce into a fixed array.**

```cpp
#include <iora/crypto/secure_rng.hpp>

#include <array>
#include <cstdint>

std::array<std::uint8_t, 16> makeNonce()
{
  std::array<std::uint8_t, 16> nonce{};
  iora::crypto::SecureRng::fill(nonce);
  return nonce;
}
```

**2. Random bytes into a raw buffer (e.g. a masking key).**

```cpp
#include <iora/crypto/secure_rng.hpp>

#include <cstdint>

void makeMask(std::uint8_t (&mask)[4])
{
  iora::crypto::SecureRng::fill(mask, sizeof(mask));
}
```

**3. A content ETag (the pattern `web/assets.hpp` uses).**

```cpp
#include <iora/crypto/secure_rng.hpp>
#include <iora/util/base64.hpp>

#include <string>

std::string contentEtag(const std::string &bytes)
{
  unsigned char digest[32];
  iora::crypto::SecureRng::sha256(bytes, digest);
  // 16-byte-truncated SHA-256, Base64Url-encoded, as Assets::computeEtag does.
  return iora::util::Base64Url::encode(digest, 16);
}
```

**4. HMAC-SHA-256 with error handling.**

```cpp
#include <iora/crypto/secure_rng.hpp>

#include <array>
#include <stdexcept>
#include <string>

bool tag(const std::string &secret, const std::string &msg, std::array<unsigned char, 32> &out)
{
  try
  {
    iora::crypto::SecureRng::hmacSha256(secret, msg, out.data());
    return true;
  }
  catch (const std::invalid_argument &)
  {
    return false; // empty (or over-INT_MAX) secret: configuration error
  }
  // std::runtime_error (an OpenSSL failure) propagates to the caller.
}
```

**Anti-patterns.**
- Do NOT pass an output buffer smaller than 32 bytes (`sha256`, `hmacSha256`) or 20 bytes (`sha1`); only null is rejected, and a short buffer is overwritten past its end.
- Do NOT use `sha256` of `secret + message` as a MAC; use `hmacSha256` (a plain hash of a concatenation is open to length extension).
- Do NOT use `sha1` for anything except the RFC 6455 handshake it exists for.
- Do NOT use a partially filled buffer after `fill` throws; treat the whole buffer as invalid.
- Do NOT compare two HMAC outputs with `==` / `memcmp` on an authentication path where timing matters; this header has no constant-time compare (use `CRYPTO_memcmp`).

---

## 5. Call Flow / Sequence Reference

**`fill(dst, len)`** -> null `dst` with `len > 0`? throw `invalid_argument` -> `while (len > 0)`: `chunk = min(len, INT_MAX)` -> mark the error queue -> `RAND_bytes(dst, chunk)` -> on failure `popErrorsToMark()` + throw `runtime_error` -> pop to the mark -> `dst += chunk; len -= chunk`.

**`sha256` / `sha1`** -> null `out`? throw `invalid_argument` -> mark the error queue -> `EVP_MD_CTX_new` (throw on null, with `popErrorsToMark()`) -> `DigestInit_ex` && `DigestUpdate` && `DigestFinal_ex` (short-circuit) -> `EVP_MD_CTX_free` -> throw (with `popErrorsToMark()`) if the chain failed or `len != N` -> pop to the mark.

**`hmacSha256`** -> null `out`, empty key, or `key.size() > INT_MAX`? throw `invalid_argument` -> mark the error queue -> `HMAC(EVP_sha256(), ...)` -> throw `runtime_error` (with `popErrorsToMark()`) if null or `len != 32` -> pop to the mark.

---

## 6. Thread Safety Model

`SecureRng` has no data members and no locks; every function is `static` and reentrant.

| Operation | Synchronization | Notes |
|---|---|---|
| `fill` | none in iora; OpenSSL's RNG is internally synchronized | Safe to call concurrently from any thread. `RAND_bytes` is thread-safe since OpenSSL 1.1.0; 1.1.1 introduced the self-seeding CTR-DRBG (fork-safe reseeding is reliable from 1.1.1d; earlier 1.1.1 releases could repeat output across `fork()`, CVE-2019-1549) with per-thread public/private DRBGs over a locked primary, which 3.x keeps (this build uses 3.5). The build sets no minimum OpenSSL version, but the EVP calls used here need at least 1.1.0. |
| `sha256` / `sha1` | none; a fresh `EVP_MD_CTX` per call | Concurrent calls share no caller-visible state; OpenSSL's default library context (its algorithm-fetch cache) is shared and internally synchronized. |
| `hmacSha256` | none; OpenSSL's one-shot `HMAC()` uses a per-call context | Concurrent calls share no caller-visible state (a null `out`, which would select OpenSSL's shared static buffer, is rejected). |
| error reporting (`popErrorsToMark`) | the calling thread's OpenSSL error queue, bracketed by `ERR_set_mark` / `ERR_pop_to_mark` | The error queue is per thread, so messages never mix across threads, and errors the caller had already queued survive the call. |

The caller must not have another thread writing the `dst`/`out` buffer or mutating the input strings during a call.

---

## 7. Configuration Reference

There is no iora-level configuration. The random source is whatever OpenSSL's default `RAND` provider is (normally the CTR-DRBG seeded from the OS). Replacing the provider or DRBG is done through OpenSSL's own configuration (`openssl.cnf`, `RAND_set_DRBG_type`, or a FIPS provider), not through this class, and must happen before the RNG is first used -- not while other threads may be calling `fill()`.

---

## 8. API Reference

```cpp
namespace iora
{
namespace crypto
{

class SecureRng
{
public:
  static void fill(std::uint8_t *dst, std::size_t len);
  template <typename Container> static void fill(Container &c);

  static void sha256(const std::string &data, unsigned char out[32]);
  static void sha1(const std::string &data, unsigned char out[20]);
  static void hmacSha256(const std::string &key, const std::string &data, unsigned char out[32]);
};

} // namespace crypto
} // namespace iora
```

| Method | Throws | Notes |
|---|---|---|
| `fill(std::uint8_t *dst, std::size_t len)` | `std::invalid_argument` if `dst` is null and `len > 0`; `std::runtime_error` if `RAND_bytes` fails | `len == 0` is a no-op; any `len` is supported (chunked by `INT_MAX`) |
| `fill(Container &c)` | as above | `Container::value_type` must be one byte (`static_assert`); fills `c.size()` bytes |
| `sha256(data, out)` | `std::invalid_argument` if `out` is null; `std::runtime_error` on EVP failure | writes 32 bytes; `out` size not checked |
| `sha1(data, out)` | `std::invalid_argument` if `out` is null; `std::runtime_error` on EVP failure | writes 20 bytes; for RFC 6455 only |
| `hmacSha256(key, data, out)` | `std::invalid_argument` if `out` is null, or `key` is empty or longer than `INT_MAX` bytes; `std::runtime_error` on HMAC failure | writes 32 bytes |

---

## 9. Design Decisions

| Decision | Rationale |
|---|---|
| Delegate to OpenSSL rather than implement primitives | OpenSSL is already a hard iora dependency (TLS); its DRBG (1.1.1d+) is reseeded, fork-safe, and FIPS-capable, which no hand-rolled generator would be. |
| All-`static`, no instance | There is no per-caller state to hold; a static facade keeps call sites one line and removes lifetime questions. |
| Throw on failure, never return a status | A caller that ignored a failed `RAND_bytes` would ship a predictable key or nonce; an exception cannot be ignored silently. |
| Chunk `fill` by `INT_MAX` | `RAND_bytes` takes `int`; chunking keeps the `std::size_t` signature honest for every length instead of narrowing it. |
| Digests and HMAC live in `SecureRng` | Historical grouping of "the OpenSSL crypto helpers" in one header. The name says RNG while the class also hosts SHA-1/SHA-256/HMAC; this was reviewed on 2026-09-24 and kept as-is (documented, not split) because the call sites (8 calls in 5 iora headers, plus iora_sip) are stable and a rename would buy nothing functional. |
| Reject an empty HMAC key | RFC 2104 allows it, but for keyed identifiers an empty secret is always a misconfiguration; failing loudly is safer than producing a keyless tag. |

---

## 10. Known Limitations

- **Output buffer sizes are not type-checked.** `unsigned char out[32]` decays to `unsigned char *`; null is rejected at run time, but a shorter buffer is undefined behavior, not a compile error.
- **Name vs contents.** `SecureRng` also provides hashing and HMAC; there is no separate `Digest`/`Hmac` type (reviewed and accepted 2026-09-24, see Design Decisions).
- **Inputs are `const std::string &` only.** There is no `std::string_view` or pointer+length overload for the digest/HMAC functions, so a caller holding bytes elsewhere must build a `std::string`.
- **One-shot only.** No streaming (init/update/final) digest or HMAC; large inputs must be materialized in memory.
- **No constant-time comparison helper** for verifying HMAC tags.
- **SHA-1 is exposed.** It is required by RFC 6455 but is not collision-resistant; nothing in the API stops it being misused elsewhere.
- **SecureRng's own errors are not left for the caller.** Each call pops back to its mark, so after a `std::runtime_error` the thread's queue holds only what the caller had queued before; the error text exists only in the exception message.
- **Partial writes on failure.** A multi-chunk `fill` that fails after the first chunk leaves the earlier bytes written; the exception is the only signal.
- **Test coverage.** `tests/util/iora_test_secure_rng.cpp` covers zero-length and container `fill`, full-buffer `fill` (distinct draws, filled tail of a 1 MiB buffer), SHA-256 and SHA-1 known-answer vectors (including the RFC 6455 §1.3 Accept example), RFC 4231 HMAC-SHA-256 test cases 1 and 2, empty-key rejection, null-output rejection for all three digest/HMAC functions, null-`dst` rejection in `fill`, a digest over an embedded `NUL`, a container fill through a non-empty `std::string`, and that OpenSSL errors the caller had queued survive every SecureRng call. The `len > INT_MAX` fill regression and the over-`INT_MAX` HMAC key rejection are tagged hidden (`[.large]`) because each allocates about 2 GiB, so they do **not** run under `ctest`; run them explicitly with `iora_test_secure_rng "[.large]"`. The `RAND_bytes`/EVP failure branches are not exercised (they cannot be triggered without fault injection into OpenSSL).

---

*See also:* [`../ids/uuid.md`](../ids/uuid.md) (the UUID generator built on `fill`), [`../network/websocket.md`](../network/websocket.md) (the RFC 6455 handshake and masking consumers).
