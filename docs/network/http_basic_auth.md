# Iora HTTP Basic Authentication -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 2.1 |
| **Date** | 2026-09-12 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/network/http_auth.hpp` |
| **Namespace** | `iora::network` |
| **Public symbol** | `iora::network::requireBasicAuth(realm, verify, inner)` (one free function; the `detail::` helpers are internal) |
| **Dependencies** | `iora::network::HttpServer` (`Handler` typedef, `Request`, `Response`) via `iora/network/http_server.hpp`; `iora::util::Base64::decode` via `iora/util/base64.hpp`; `iora::core` logging (`IORA_LOG_ERROR`) via `iora/core/logger.hpp`. Header-only. |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-05-30 | Initial release: `requireBasicAuth` Handler decorator; best-effort credential scrub (M-1); widened realm reject-set (M-2). Documented jointly with the `util::Base64` decoder. |
| 2.0 | 2026-09-11 | **Migrated to `docs/network/` and re-verified against the current `http_auth.hpp` source.** Scoped the guide to the HTTP Basic auth component (the `util::Base64` decoder is now referenced as a dependency, not deep-dived here). Corrected drift: the realm reject-set is control bytes (`< 0x20`), `0x7F`, `"`, and `\` (obs-text `0x80`-`0xFF` is accepted); the credential-token trim is `SP`/`HTAB` only; the scheme separator is `1*SP` (space only, HTAB rejected); the non-`std::exception` verify throw is also caught and mapped to 500. Added the credential-scrubber inventory and the `bytes`-vector scrub gap (Known Limitations). |
| 2.1 | 2026-09-12 | **Re-synced to the landed Group 6 fixes (iora 1af4b25).** The decoded-credential `bytes` vector is now scrubbed via a `secureZero(std::vector<std::uint8_t>&)` overload -- the bytes-vector gap is **RESOLVED** (AUTH-A1). Reworded the realm HTAB rejection as a deliberate conservative wiring-time strictness choice (HTAB *is* valid `qdtext` per RFC 9110 Section 5.6.4), not an RFC conformance requirement. Reframed the optional `charset` auth-param and charset-agnostic decoding as correct-by-design (RFC 7617), moving them from Known Limitations to Design Decisions. Replaced the `util::Base64`-guide citation with an inline dependency contract; added cross-links to sibling guides. |

---

## 1. Executive Summary

### Problem

iora ships an `HttpServer` but no first-class way to gate a route behind
credentials. A daemon exposing an admin surface (the HTMX admin-UI initiative)
needed the simplest interoperable scheme -- HTTP Basic (RFC 7617) -- without
pulling in an external auth framework, and without every daemon re-implementing
the `Authorization: Basic` decode / `WWW-Authenticate` challenge dance
(and getting the security-sensitive edge cases -- header injection via the
realm, timing leaks, credential lingering in freed heap -- wrong each time).

### Solution

`iora::network::requireBasicAuth(realm, verify, inner)` is a **pure decorator**
over the existing `HttpServer::Handler` typedef:

```cpp
HttpServer::Handler requireBasicAuth(
  std::string realm,
  std::function<bool(const std::string &user, const std::string &pass)> verify,
  HttpServer::Handler inner);
```

It takes a protected handler (`inner`) and returns a new `Handler` that, on
every request:

1. reads the `Authorization` header,
2. matches the case-insensitive `Basic` scheme + `1*SP` separator,
3. Base64-decodes the credential token and splits it on the first `:` into
   user/password,
4. calls the caller-supplied `verify` predicate, and
5. runs `inner` only when `verify` returns `true` -- otherwise it responds
   `401` with a `WWW-Authenticate: Basic realm="<realm>"` challenge.

Because it returns the same `Handler` type it consumes, it introduces **no new
handler type and no change to `HttpServer` dispatch**, so it composes with
`onGet`/`onPost`/`onPut`/..., pattern routes, and the routing safety-net.

### Technical Impact

- **One-line protection of any route.** Wrap an existing handler; the credential
  policy stays entirely in the caller's `verify` callback.
- **iora never stores, hashes, or compares credentials.** That is the `verify`
  callback's responsibility -- including the constant-time comparison that
  prevents timing attacks.
- **Security hardening built in.** The realm is sanitized once at construction
  to block response-header injection and quoted-string breakout; decoded
  credential locals are scrubbed on every exit path (defense-in-depth); the
  decoded credential is never logged.
- **Dependency-free.** No new external dependency -- it reuses the in-tree
  `util::Base64` decoder and `HttpServer` types. Richer auth (sessions, CSRF,
  OIDC, LDAP) is deliberately out of scope and ships separately as
  `iora_web_middleware`.

> **Security note (read before use).** HTTP Basic transmits credentials as
> cleartext-equivalent Base64 on *every* request (RFC 7617 Section 4).
> `requireBasicAuth` MUST be deployed behind TLS only. The `verify` callback
> owns credential comparison and MUST use a constant-time compare (and any
> hashing) to avoid timing attacks.

---

## 2. System Architecture

### 2.1 Component relationships

`requireBasicAuth` is a decorator that sits between `HttpServer` route dispatch
and the protected handler. It owns no state of its own beyond what the returned
closure captures by value.

```
   HttpServer route table (onGet / onPost / pattern routes / default handler)
        |
        |  register the returned Handler on any route
        v
   +-------------------------------------------------------------------+
   |  requireBasicAuth(realm, verify, inner)  -->  returns a Handler   |
   |  (closure captures realm, verify, inner BY VALUE)                 |
   |                                                                   |
   |  Request ---> read "Authorization"                                |
   |          |                                                        |
   |          +-- missing/short / non-Basic scheme / HTAB sep -> 401   |
   |          +-- undecodable token / no ':' in cleartext ----> 401    |
   |          |                                                        |
   |          v                                                        |
   |     util::Base64::decode  --> split on first ':' --> verify(u,p)  |
   |          |                                     |                  |
   |          |                          false -----+---> 401          |
   |          |                          throws ----+---> 500 (+ERROR) |
   |          |                          true                          |
   |          v                                                        |
   |     inner(req, res)  ---- exceptions NOT caught here -------------+--> routing
   +-------------------------------------------------------------------+       safety-net
```

The Base64 decoder lives one layer below in `iora::util::Base64` -- the same
class the WebSocket handshake uses for encoding, so there is a single canonical
Base64 facility (one shared alphabet for encode and decode). **Dependency
contract:** `util::Base64::decode` is the standard padded (RFC 4648) Base64
decoder; it returns `std::nullopt` on any malformed or non-canonical input and a
present (possibly-empty) `std::vector<std::uint8_t>` on success. This document
treats `decode` as a trusted dependency and documents only how `requireBasicAuth`
consumes it; it does not deep-dive the decoder's internals (a dedicated
`util::Base64` guide is TBD).

**Related guides:** [`http_server.md`](http_server.md) -- the `HttpServer` this
decorator wraps (`Handler`/`Request`/`Response` types and route dispatch); and
[`../parsers/http_message.md`](../parsers/http_message.md) -- how a `Request`'s
headers (such as `Authorization`) are parsed and how `get_header_value` returns
them by value.

### 2.2 Request data flow

```mermaid
sequenceDiagram
  participant Client
  participant Server as HttpServer dispatch
  participant Auth as requireBasicAuth closure
  participant B64 as util::Base64::decode
  participant Verify as verify callback
  participant Inner as inner handler

  Client->>Server: GET /admin (Authorization: Basic ...)
  Server->>Auth: closure(req, res)
  Auth->>Auth: read Authorization; match "Basic" + 1*SP
  Auth->>Auth: trim SP/HTAB around token
  Auth->>B64: decode(token)
  alt undecodable
    B64-->>Auth: nullopt
    Auth-->>Client: 401 WWW-Authenticate
  else decoded
    B64-->>Auth: bytes
    Auth->>Auth: split on first ':' -> user, pass
    Auth->>Verify: verify(user, pass)
    alt verify throws
      Verify-->>Auth: exception
      Auth-->>Client: 500 (ERROR log, no credential)
    else verify false
      Verify-->>Auth: false
      Auth-->>Client: 401 WWW-Authenticate
    else verify true
      Verify-->>Auth: true
      Auth->>Inner: inner(req, res)
      Inner-->>Client: 200 (or inner's own status)
    end
  end
  Note over Auth: credential locals scrubbed on scope exit (every path)
```

### 2.3 Threading model

| Element | Threading role |
|---|---|
| `requireBasicAuth(...)` construction | Called once at wiring time (typically the setup thread). Validates the realm and builds an independent closure; touches no shared state. |
| The returned `Handler` | Invoked per request from the `HttpServer` dispatcher thread(s). Captures `realm`/`verify`/`inner` by value and holds no mutable shared state, so it is safe to invoke concurrently. |
| `verify` callback | Runs on the dispatcher thread that invoked the handler. The caller-supplied `verify` MUST itself be thread-safe (it is shared across concurrent requests). |
| Logging (`IORA_LOG_ERROR`) | Only on the verify-throws path; the `iora::core` logger is itself thread-safe. |

There are no mutexes, atomics, or condition variables in this component. See
Section 8 for the per-symbol table.

---

## 3. Component Deep Dive

### 3.1 `requireBasicAuth` -- the decorator

```cpp
inline HttpServer::Handler requireBasicAuth(
  std::string realm,
  std::function<bool(const std::string &user, const std::string &pass)> verify,
  HttpServer::Handler inner);
```

`requireBasicAuth` is a free function in `iora::network`, declared `inline`
(header-only). It has two phases: a **construction-time** realm validation that
runs once when you build the handler, and a **per-request** closure that runs on
every dispatched request.

#### Construction-time realm sanitization

Before the closure is returned, `realm` is scanned byte-by-byte. A realm
containing any of the following throws `std::invalid_argument`:

- any **control byte** `< 0x20` (this includes CR `0x0D` and LF `0x0A`, the
  response-header-injection vector -- `Response::set_header` does no
  sanitization),
- **DEL** `0x7F`,
- a double-quote `"` (would close the quoted-string early), or
- a backslash `\` (quoted-string escape / breakout).

```cpp
for (char c : realm)
{
  const auto uc = static_cast<unsigned char>(c);
  if (uc < 0x20 || uc == 0x7F || c == '"' || c == '\\')
  {
    throw std::invalid_argument(
      "requireBasicAuth: realm must not contain control bytes, DEL, '\"', or "
      "'\\'");
  }
}
```

CR, LF, and the other control bytes below `0x20` (except HTAB) are not valid
quoted-string `qdtext` (RFC 9110 Section 5.6.4) -- and CR/LF are the
response-header-injection vector -- so rejecting them keeps the emitted realm a
clean, well-formed quoted-string. There is also a serializer-level backstop:
`HttpResponse::toWireFormat` runs `headerHasInjection` and drops any field whose
name or value contains CR/LF/NUL (cross-ref [`http_server.md`](http_server.md)
Section 5.3 / HR-18), so a CR/LF realm would cause the challenge header to be
silently dropped rather than injected -- but the fail-loud construction-time
reject is still preferred, because it surfaces the misconfiguration at wiring
time instead of producing a broken 401 on the wire. **HTAB (`0x09`) is a deliberate exception:**
HTAB *is* valid `qdtext` per RFC 9110 Section 5.6.4, but it falls inside the
`< 0x20` guard and is rejected anyway. That is a conservative wiring-time
strictness choice -- a `realm` is developer/config data, where a stray tab is far
more likely a mistake than intent -- **not** an RFC conformance requirement. DEL
(`0x7F`), `"`, and `\` are also genuinely outside `qdtext` (or would break out of
the quoted-string). Bytes `0x80`-`0xFF` (UTF-8 / `obs-text`) **are** valid
`qdtext` and are accepted. Because `realm` is wiring-time developer/config data,
a bad byte is a programming error that fails loudly at construction -- not a
per-request runtime check.

After validation, `realm` (along with `verify` and `inner`) is `std::move`-d
into the returned closure -- captured **by value** so the closure is
self-contained and safe to invoke after `requireBasicAuth` returns.

#### The per-request closure

The returned `Handler` executes the following steps. Each numbered step maps to
the source in `http_auth.hpp`:

1. **Read `Authorization`.** `req.get_header_value("Authorization")` returns a
   `std::string` **by value**; it is bound to a named local `auth` so any
   `std::string_view` derived from it does not dangle. An empty value is treated
   identically to an absent header (both fall through to a `401`).

2. **Declare credential locals up front and arm the scrubber.** `auth`, `token`,
   `cred`, `user`, and `pass` are all declared before any early return, and a
   `detail::CredentialScrubber` is constructed over all five (Section 3.2). This
   guarantees they are wiped on *every* exit path -- early returns and an
   exception propagating out of `inner`.

3. **Match the scheme: case-insensitive `Basic` + `1*SP`.** The scheme token is
   compared against `"Basic"` with an ASCII-only case fold (deliberately not
   `std::tolower`, which is locale-sensitive and UB on a negative `char`). The
   scheme MUST be followed by at least one `SP` (`0x20`); a HTAB `0x09` after the
   scheme is non-conformant and rejected. Requiring the separator also makes the
   scheme token-bounded (`"BasicX"` fails at position 5; a bare `"Basic"` with no
   separator fails). Multiple spaces are consumed. Any mismatch -> 401. **This
   path is intentionally not logged** (it would spam an ERROR on the first,
   credential-free request from every browser).

4. **Trim and extract the token.** The credential token is `SP`/`HTAB`-trimmed
   on both ends -- leniency restricted to `0x20`/`0x09` only; CR/LF and `=`
   padding are never trimmed. This is a separate concern from the `1*SP` scheme
   separator of step 3 (it also absorbs an optional HTAB that a client placed
   between the scheme-space and the token).

5. **Decode.** `util::Base64::decode(token)` (standard alphabet). A `nullopt`
   result (malformed length, non-alphabet byte, bad padding, non-canonical
   pad bits) -> 401 (a malformed credential re-prompts; it is **not** a 400).

6. **Copy out, scrub the vector, then split on the first `:`.** The decoded bytes
   are copied into `cred`, and the decoded `std::vector<std::uint8_t>` is then
   `secureZero`-wiped in place immediately (so no cleartext copy lingers in it --
   see Section 3.2). `cred` is split at the first `:` into `user` and `pass`
   (RFC 7617: the user-id MUST NOT contain `:`; the password MAY). No `:` -> 401.

7. **Call `verify` inside `try/catch`.** `verify(user, pass)` is invoked. A
   throw -- whether `std::exception` or anything else -- is caught and mapped to
   `500`, with an `ERROR` log of the exception message **only** (never the
   credential). `inner` is not run.

8. **Dispatch on the result.** `verify` returns `false` -> 401 re-challenge.
   `verify` returns `true` -> `inner(req, res)` runs. Exceptions from `inner`
   are **not** caught here; they propagate to the `HttpServer` routing
   safety-net (which produces the dev/prod `500` body).

#### `emit401` / `emit500`

Two local lambdas build the non-success responses:

```cpp
const auto emit401 = [&]()
{
  res.status = 401;
  // Built lazily here (only on a challenge), not on the success path.
  res.set_header("WWW-Authenticate", "Basic realm=\"" + realm + "\"");
  res.set_content("Unauthorized", "text/plain");
};
const auto emit500 = [&]()
{
  res.status = 500;
  res.set_content("Internal Server Error", "text/plain");
};
```

- `emit401` sets status `401`, the `WWW-Authenticate: Basic realm="<realm>"`
  header (built lazily -- only on a challenge, never on the success path), and a
  fixed `"Unauthorized"` body via `set_content` (so `Content-Type` and
  `Content-Length` are framed). No `charset` auth-param is emitted (see Known
  Limitations).
- `emit500` sets status `500` with a fixed generic `"Internal Server Error"`
  body. This tier-1 helper deliberately does **not** couple to any
  dev/prod-mode toggle; dev/prod-aware error bodies are the routing safety-net's
  job.

#### Invariants

- The closure is **immutable and self-contained** after construction: it mutates
  no captured state, so concurrent invocations cannot interfere.
- A validated realm is a well-formed quoted-string, so the emitted
  `WWW-Authenticate` value can never be malformed or header-inject.
- Exactly one of `emit401`, `emit500`, or `inner(req, res)` runs per request.
- Every credential-bearing local is scrubbed before the closure returns.

### 3.2 `detail::CredentialScrubber` and `detail::secureZero`

These two internal helpers (in `iora::network::detail`, not part of the public
API) implement the best-effort credential scrub.

`secureZero` overwrites a `std::string`'s buffer through a `volatile` pointer so
the compiler may not elide the writes, then clears the string:

```cpp
inline void secureZero(std::string &s)
{
  if (!s.empty())
  {
    volatile char *p = s.data();
    for (std::size_t i = 0; i < s.size(); ++i)
    {
      p[i] = '\0';
    }
  }
  s.clear();
}
```

A matching overload wipes the decoded-credential **byte vector** the same way,
so the cleartext `user:pass` bytes that `Base64::decode` returns do not linger in
freed heap either:

```cpp
inline void secureZero(std::vector<std::uint8_t> &v)
{
  if (!v.empty())
  {
    volatile std::uint8_t *p = v.data();
    for (std::size_t i = 0; i < v.size(); ++i)
    {
      p[i] = 0;
    }
  }
  v.clear();
}
```

The closure calls this overload on the `Base64::decode` result immediately after
copying it into `cred` (`http_auth.hpp:259`), so the decoded vector is not
left holding cleartext until its own destructor runs.

`CredentialScrubber` is an RAII wrapper that wipes a set of strings on scope
exit -- covering every early return **and** an exception propagating out of the
inner handler:

```cpp
class CredentialScrubber
{
public:
  explicit CredentialScrubber(std::initializer_list<std::string *> fields);
  CredentialScrubber(const CredentialScrubber &) = delete;
  CredentialScrubber &operator=(const CredentialScrubber &) = delete;
  ~CredentialScrubber();   // calls secureZero on each field
private:
  std::vector<std::string *> _fields;
};
```

It is non-copyable and non-assignable (it holds raw pointers to caller-owned
locals). In `requireBasicAuth` it is constructed over `{&auth, &token, &cred,
&user, &pass}`.

**Honest scope of the scrub.** This is defense-in-depth: it reduces the window
in which a cleartext credential lingers in freed heap, a core dump, or swap. It
covers the five request-local strings **and** the intermediate
`std::vector<std::uint8_t>` that `Base64::decode` returns (wiped in place via the
overload above -- closing the earlier bytes-vector gap). It is **not** a
substitute for TLS, and it still cannot cover copies the `verify` callback
retains, nor compiler register/spill slots. iora has no dedicated `SecureString`
type today.

---

## 4. Usage Guide

### 4.1 Protect a route (quick start)

```cpp
#include <iora/network/http_auth.hpp>

using iora::network::HttpServer;        // Request/Response/Handler are nested here
using iora::network::requireBasicAuth;

// `server` is an iora::network::HttpServer you have already constructed/wired,
// listening on a TLS socket.

// The protected handler.
auto adminPage = [](const HttpServer::Request &req, HttpServer::Response &res)
{
  res.set_content("<h1>Admin</h1>", "text/html");
};

server.onGet("/admin", requireBasicAuth(
  "Admin Area",
  [](const std::string &user, const std::string &pass)
  {
    // Illustrative only -- see 4.2 for a correct constant-time check.
    return user == "admin" && pass == "s3cret";
  },
  adminPage));
```

### 4.2 A correct constant-time `verify`

`verify` owns credential comparison. A naive `pass == secret` short-circuits on
the first mismatched byte and is timing-attackable. Compare fixed-length KDF
digests with a branchless accumulator:

```cpp
#include <iora/network/http_auth.hpp>
#include <string>

// Constant-time byte comparison. The XOR-accumulate loop does not early-exit.
// NOTE: the size check is NOT constant-time and leaks the length of the
// right-hand operand -- feed it FIXED-LENGTH inputs (e.g. a KDF digest), never
// a raw variable-length password.
static bool ctEquals(const std::string &a, const std::string &b)
{
  if (a.size() != b.size())
  {
    return false;
  }
  unsigned char diff = 0;
  for (std::size_t i = 0; i < a.size(); ++i)
  {
    diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
  }
  return diff == 0;
}

using iora::network::HttpServer;
using iora::network::requireBasicAuth;

HttpServer::Handler protect(HttpServer::Handler inner,
                            std::string storedUser,
                            std::string storedDigest /* e.g. Argon2id output */)
{
  return requireBasicAuth(
    "Admin Area",
    [storedUser = std::move(storedUser),
     storedDigest = std::move(storedDigest)](const std::string &user,
                                             const std::string &pass)
    {
      // Production: digest = argon2id(pass, salt); compare fixed-length digests.
      const std::string digest = /* argon2id(pass, salt) */ pass;
      return ctEquals(user, storedUser) && ctEquals(digest, storedDigest);
    },
    std::move(inner));
}
```

### 4.3 Handle a bad realm at construction (not per request)

A realm with a forbidden byte throws `std::invalid_argument` from
`requireBasicAuth` itself -- so validate config once at startup, not on every
request:

```cpp
#include <iora/network/http_auth.hpp>
#include <stdexcept>

try
{
  auto guarded = iora::network::requireBasicAuth(realmFromConfig, verify, inner);
  server.onGet("/admin", std::move(guarded));
}
catch (const std::invalid_argument &e)
{
  // Misconfigured realm (CR/LF, control byte, DEL, '"', or '\\'):
  // fail startup, do not swallow this per request.
  throw;
}
```

### 4.4 Decode a Base64 value directly (dependency)

`requireBasicAuth` uses `util::Base64::decode` internally, but you can call it
yourself for any opaque Base64 token. Bind the header value to a named
`std::string` first to avoid a dangling `string_view`:

```cpp
#include <iora/util/base64.hpp>

// get_header_value returns std::string BY VALUE -- bind it before decoding.
std::string b64 = req.get_header_value("X-Token");
if (auto bytes = iora::util::Base64::decode(b64))
{
  // *bytes is std::vector<std::uint8_t> (present, possibly empty)
}
else
{
  // rejected: malformed length, non-alphabet byte, bad padding, or non-canonical
}
```

### 4.5 Anti-patterns -- do NOT

- **Do NOT deploy on a plaintext listener.** Basic credentials are Base64, not
  encrypted; a plaintext listener leaks them on every request. TLS is mandatory.
- **Do NOT use a short-circuiting `verify`.** `user == "admin" && pass == secret`
  is timing-attackable -- use a constant-time compare over fixed-length digests
  (Section 4.2).
- **Do NOT store or compare cleartext passwords in `verify`.** Hash with a
  memory-hard KDF (Argon2id/bcrypt/scrypt) and compare the digests.
- **Do NOT catch a bad-realm exception per request.** A forbidden realm byte
  throws at *construction* (Section 4.3) -- fix the config, do not wrap each
  request in a `try`.
- **Do NOT pass a temporary into `Base64::decode`.**
  `Base64::decode(req.get_header_value("X"))` is a dangling-`string_view` bug
  because the getter returns by value; bind to a named `std::string` first.
  (`requireBasicAuth` already does this internally.)
- **Do NOT expect a `400` for a malformed credential.** A missing, malformed, or
  rejected credential re-challenges with `401`, matching browser re-prompt
  behavior.
- **Do NOT rely on the scrubber for secrecy.** It is best-effort
  defense-in-depth; it cannot wipe copies your `verify` retains. TLS + a KDF are
  the real controls.

---

## 5. Call Flow / Sequence Reference

### 5.1 Success path

| Step | Action |
|---|---|
| 1 | `GET /admin`, `Authorization: Basic YWRtaW46czNjcmV0`. |
| 2 | Read `auth = "Basic YWRtaW46czNjcmV0"`; arm the `CredentialScrubber`. |
| 3 | Case-insensitive `"Basic"` match; `1*SP` separator consumed. |
| 4 | Trim `SP`/`HTAB`; `token = "YWRtaW46czNjcmV0"`. |
| 5 | `Base64::decode(token)` succeeds. |
| 6 | `cred = "admin:s3cret"`; split on first `:` -> `user="admin"`, `pass="s3cret"`. |
| 7 | `verify("admin", "s3cret")` returns `true`. |
| 8 | `inner(req, res)` runs -> `200` (or `inner`'s own status). |
| 9 | On scope exit, `auth`/`token`/`cred`/`user`/`pass` are scrubbed. |

### 5.2 Missing / rejected credential (401)

| Step | Action |
|---|---|
| 1 | `GET /admin` with no `Authorization` (or empty, or non-`Basic`, or undecodable, or no `:`). |
| 2 | The relevant guard fires; `emit401` sets status `401`, header `WWW-Authenticate: Basic realm="Admin Area"`, body `"Unauthorized"` (Content-Length framed). |
| 3 | `inner` is not run; credential locals scrubbed on scope exit. |
| 4 | The browser prompts for credentials and re-requests. |

### 5.3 Verify throws (500) -- failure path

| Step | Action |
|---|---|
| 1 | `verify(user, pass)` throws (e.g. `std::runtime_error("db down")`, or any non-`std::exception`). |
| 2 | The `try/catch` catches it; `emit500` sets status `500`, body `"Internal Server Error"`. |
| 3 | `IORA_LOG_ERROR` logs the exception message **only** -- e.g. `"requireBasicAuth: verify callback threw: db down"` (never the credential); the non-`std::exception` case logs a fixed message. |
| 4 | `inner` is not run; credential locals scrubbed on scope exit. |

### 5.4 Inner throws (propagates)

If `inner(req, res)` throws, the exception is **not** caught by
`requireBasicAuth`; it unwinds through the closure (the `CredentialScrubber`
destructor still runs, scrubbing the locals) and reaches the `HttpServer`
routing safety-net, which frames the final `500` response.

---

## 6. Thread Safety Model

This component is stateless -- there are no mutexes, atomics, or condition
variables. Safety derives entirely from immutability: the returned closure
captures its inputs by value and never mutates them.

| Symbol | Concurrent-call safety | Notes |
|---|---|---|
| `requireBasicAuth(...)` (construction) | Safe | Validates the realm and builds an independent closure; no shared state. Typically called once at wiring time. |
| The returned `Handler` | Safe | Captures `realm`/`verify`/`inner` by value; no mutable shared state. Invoked per request from dispatcher thread(s). |
| `verify` callback | **Caller's responsibility** | Shared across concurrent requests -- the caller-supplied predicate MUST be thread-safe. |
| `detail::secureZero` / `detail::CredentialScrubber` | Safe | Operate only on request-local strings owned by the invoking thread. |

---

## 7. Configuration Reference

`requireBasicAuth` has no global configuration and no config struct. Its three
parameters are the entire configuration surface.

| Parameter | Type | Default | Constraints / effect |
|---|---|---|---|
| `realm` | `std::string` | (required) | Shown in `WWW-Authenticate`. MUST NOT contain any control byte (`< 0x20`, incl. CR/LF), DEL (`0x7F`), `"`, or `\` -- else throws `std::invalid_argument` at construction. Bytes `0x80`-`0xFF` (UTF-8 / obs-text) are accepted. Captured by value. (A serializer-level backstop -- `HttpResponse::toWireFormat` / `headerHasInjection`, HR-18 -- would additionally drop a CR/LF/NUL-bearing challenge header, but the construction-time reject is preferred for failing loud at wiring time.) |
| `verify` | `std::function<bool(const std::string &user, const std::string &pass)>` | (required) | Credential predicate; returns `true` iff valid. Owns all comparison/hashing policy (constant-time compare required). May throw -> `500`. Must be thread-safe. Captured by value. |
| `inner` | `HttpServer::Handler` | (required) | The protected handler, run only when `verify` returns `true`. Its exceptions propagate to the routing safety-net. Captured by value. |

Pinned response defaults (not configurable):

| Response | Status | Body | Extra header |
|---|---|---|---|
| Challenge | `401` | `"Unauthorized"` (`text/plain`) | `WWW-Authenticate: Basic realm="<realm>"` (no `charset` auth-param) |
| Verify threw | `500` | `"Internal Server Error"` (`text/plain`) | -- |

If a `charset` auth-param were ever added, the RFC 7617 form is the
comma-separated `Basic realm="...", charset="UTF-8"`.

---

## 8. API Reference

```cpp
namespace iora
{
namespace network
{

/// Decorate any HttpServer::Handler with HTTP Basic authentication (RFC 7617).
/// Throws std::invalid_argument at construction if `realm` contains a control
/// byte (< 0x20), DEL (0x7F), '"', or '\\'.
inline HttpServer::Handler requireBasicAuth(
  std::string realm,
  std::function<bool(const std::string &user, const std::string &pass)> verify,
  HttpServer::Handler inner);

} // namespace network
} // namespace iora
```

Dependency signature actually consumed (`util::Base64` is the standard padded
RFC 4648 decoder; a dedicated guide is TBD -- see the inline contract in
Section 2.1):

```cpp
namespace iora { namespace util {
  // Returns nullopt on any malformed/rejected input; a present (possibly-empty)
  // vector on success. Standard RFC 4648 alphabet; strict pad-bit rejection.
  static std::optional<std::vector<std::uint8_t>>
    iora::util::Base64::decode(std::string_view input);
} }
```

The `iora::network::detail::secureZero` / `detail::CredentialScrubber` helpers
are internal (namespace `detail`) and are not part of the supported API.

---

## 9. Design Decisions

| Decision | Rationale |
|---|---|
| Pure decorator over `HttpServer::Handler` (no new handler type) | Composes uniformly with `onGet`/`onPost`/pattern routes/default handler and the routing safety-net; nothing in `HttpServer` dispatch changes. |
| Missing / malformed / failed credential -> `401` (not `400`) | Matches real-world browser Basic-auth re-prompt behavior; the structural validity of an `Authorization` header is not an error to surface as `400`. |
| Reject (not strip) control bytes / DEL / `"` / `\` in realm, at construction | Fails loudly on a wiring-time config error; blocks response-header injection (CR/LF) and quoted-string breakout. Most of the reject-set is also invalid `qdtext`; HTAB is the exception -- it is valid `qdtext` but rejected as a deliberate conservative strictness choice (Section 3.1), not for RFC conformance. |
| Accept `0x80`-`0xFF` in realm | UTF-8 / obs-text is valid `qdtext` (RFC 9110 Section 5.6.4); UTF-8 realms are legitimate. |
| No `charset` auth-param emitted in the challenge | RFC 7617 Section 2.1 makes `charset` an OPTIONAL parameter, so omitting it is fully spec-conformant. Clients fall back to their own encoding; it can be added later (Section 7) without changing the challenge's wire form. |
| Decoded credentials passed to `verify` verbatim (no charset validation/normalization) | RFC 7617 is charset-agnostic by design; iora stays encoding-neutral and leaves any UTF-8 validation or normalization policy to the `verify` callback. |
| Scheme separator is `1*SP` (space only); HTAB after the scheme rejected | RFC 7235 Section 2.1 grammar `credentials = auth-scheme [ 1*SP ... ]`; `SP = %x20` is the RFC 5234 App B.1 core rule. Accepting HTAB would over-widen the accept surface. |
| ASCII-only case fold for the scheme (not `std::tolower`) | `std::tolower` is locale-sensitive and UB on a negative `char`; the scheme token is bounded ASCII. |
| Token trim limited to `SP`/`HTAB` (`0x20`/`0x09`); never CR/LF or `=` | Basic credentials are a single unbroken token; strict trimming avoids reinterpreting padding or line-folding bytes as trimmable whitespace. |
| Split on the **first** `:` | RFC 7617: user-id MUST NOT contain `:`, password MAY -- so the first colon is the authoritative separator. |
| iora never stores/hashes/compares credentials -- `verify` owns it | Keeps the core dependency-clean and policy-free; the security-critical constant-time compare belongs to the deployment. |
| Pre-verify rejection paths are intentionally NOT constant-time | The structural validity of an `Authorization` header is not secret; constant-time secrecy is the `verify` callback's job. |
| `verify` throw -> `500` + ERROR log of message only (never credential) | A failing credential store is a server error, not an auth failure; logging the credential would defeat the scheme. Both `std::exception` and non-`std::exception` throws are caught. |
| `inner` exceptions NOT caught here | Single-responsibility: `inner`'s errors belong to the routing safety-net, which owns dev/prod error bodies. |
| Best-effort credential scrub via RAII + volatile write | Defense-in-depth against cleartext lingering in freed heap; honestly scoped (cannot cover copies `verify` retains). |
| `WWW-Authenticate` built lazily in `emit401` | Avoids building the challenge header on the success path. |
| HTTP Basic only; sessions/CSRF/OIDC/LDAP out of scope | Keeps iora core dependency-clean; rich auth ships as `iora_web_middleware`. |

---

## 10. Known Limitations

- **HTTP Basic only.** No sessions, cookies, CSRF, login forms, OIDC, or LDAP --
  those are `iora_web_middleware`.
- **TLS required.** Credentials are Base64, not encrypted; Basic is only safe
  over TLS. Inherent to the scheme (RFC 7617 Section 4).
- **No rate limiting / lockout** on repeated failed verifies -- the `verify`
  callback owns any such policy (see `iora::core::RateLimiterMap`).
- **No credential storage/hashing in iora** -- `verify` owns it entirely,
  including the constant-time comparison.
- **Credential scrub is best-effort (residual copies outside iora's reach).**
  The RAII scrubber wipes `auth`, `token`, `cred`, `user`, and `pass`, and the
  intermediate `std::vector<std::uint8_t>` returned by `Base64::decode` (`bytes`
  in the closure) is now also wiped: a `secureZero(std::vector<std::uint8_t>&)`
  overload zeroes it in place immediately after its contents are copied into
  `cred` (`http_auth.hpp:259`). The earlier gap -- where the decoded vector
  kept a cleartext `user:pass` copy in freed heap -- is **RESOLVED** (Group 6,
  iora `1af4b25`). What remains genuinely outside iora's reach: copies the
  `verify` callback retains, and compiler register/spill slots. iora has no
  dedicated `SecureString` type today.
- **Single `Authorization` header assumed.** `get_header_value("Authorization")`
  reads one value; a request presenting multiple `Authorization` headers is not
  specially handled (RFC 7235 expects one).
- **Standard Base64 alphabet only.** The consumed decoder handles `+`/`/`; a
  Base64URL (`-`/`_`) decoder is not used (HTTP Basic uses standard Base64).
</content>
</invoke>
