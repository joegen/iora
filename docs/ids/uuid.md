# Iora Uuid -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-09-24 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/ids/uuid.hpp` |
| **Namespace** | `iora::ids` |
| **Dependencies** | `iora/crypto/secure_rng.hpp` (random bits); `<array>`, `<chrono>`, `<cstddef>`, `<cstdint>`, `<string>` |

This guide covers `iora::ids::Uuid`. Despite the name it is not a UUID value type: it is a static generator of two functions that return RFC 9562 UUIDs as strings: version 4 (random) and version 7 (Unix-epoch millisecond timestamp plus random). Both return the canonical 36-character lowercase string. Its heaviest consumer is downstream: iora_sip uses `Uuid::v4()` for Call-ID/identifier generation (`iora/sip/Identifiers.hpp:70`), registration Call-IDs, and route IDs.

**Document scope.** This guide uses the sanctioned lite variant of the Architecture & Programmer's Guide template: `uuid.hpp` is one class of two `static` functions plus a private formatter, with no instance state, no configuration, and no call flow beyond "draw bytes, set bits, format", so System Architecture, Call Flow, and Configuration Reference do not apply.

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-24 | Initial guide, authored against source. `toHexString` now indexes with `std::size_t`. Header doc comments corrected in the same change: the standard is RFC 9562 (not "draft RFC"), and v7 ordering is millisecond-granular only. New `tests/util/iora_test_uuid.cpp` suite. |

---

## Executive Summary

**Problem.** Components need globally unique identifiers without coordination -- SIP Call-IDs, route and registration IDs, request correlation IDs. Some want pure unpredictability (v4); others want identifiers that also sort roughly by creation time, which keeps B-tree indexes and logs in insertion order (v7).

**Solution.**
- `Uuid::v4()` -- 16 bytes from `SecureRng::fill`, then the version nibble set to `4` and the variant bits set to `10`; 122 random bits (`uuid.hpp:33-45`).
- `Uuid::v7()` -- the current `system_clock` time in milliseconds since the Unix epoch packed big-endian into the first 48 bits, the remaining 10 bytes from `SecureRng::fill`, then version `7` and variant `10`; 74 random bits (`uuid.hpp:54-81`).
- Both format through a private 256-entry hex-pair table into `xxxxxxxx-xxxx-Vxxx-Nxxx-xxxxxxxxxxxx` (lowercase, hyphens after bytes 4, 6, 8, 10) (`uuid.hpp:87-145`).

**Technical impact.** The random bits come from OpenSSL's CSPRNG (see [`../crypto/secure_rng.md`](../crypto/secure_rng.md)), so v4 values are unguessable, not merely unique. Each call returns a new `std::string` of exactly 36 characters (one allocation for the result; the hex table is `static constexpr`).

---

## Deep Dive & Usage

### Bit layout

| Bits (RFC 9562 §5) | v4 | v7 | Source |
|---|---|---|---|
| 0-47 | random | `unix_ts_ms`, big-endian (`b[0]` = bits 47..40) | v4 `uuid.hpp:36`; v7 `:64-69` |
| 48-51 (`b[6]` high nibble) | `0100` | `0111` | `:39`, `:75` |
| 52-63 | random | random (`rand_a`) | v4 `:36`; v7 `:72` |
| 64-65 (`b[8]` top two bits) | `10` | `10` | `:42`, `:78` |
| 66-127 | random | random (`rand_b`) | `:36`, `:72` |

So the 15th character of the string is always `4` or `7`, and the 20th is always one of `8`, `9`, `a`, `b`.

### v7 ordering

v7 sorts correctly **across** milliseconds: because the timestamp is the most significant 48 bits and the string is fixed-width lowercase hex, comparing two v7 strings lexicographically (`std::string::operator<`) orders them by their millisecond timestamp. **Within** one millisecond the order is random: the header fills `rand_a` with random bits and keeps no counter (RFC 9562 §6.2 describes counter methods that implementations SHOULD use when batch creation or intra-millisecond monotonicity matters; none is used). The timestamp also comes from `system_clock`, so an NTP step backwards produces a v7 that sorts before earlier ones.

### Usage

**1. A random identifier.**

```cpp
#include <iora/ids/uuid.hpp>

#include <string>

std::string newCallId(const std::string &host)
{
  return iora::ids::Uuid::v4() + "@" + host;
}
```

**2. A time-ordered key.**

```cpp
#include <iora/ids/uuid.hpp>

#include <map>
#include <string>

void append(std::map<std::string, std::string> &log, const std::string &entry)
{
  // Keys created in later milliseconds sort after earlier ones.
  log.emplace(iora::ids::Uuid::v7(), entry);
}
```

**3. Recovering the v7 timestamp.**

```cpp
#include <iora/ids/uuid.hpp>

#include <cstdint>
#include <string>

std::uint64_t v7Millis(const std::string &uuid)
{
  // First 48 bits = characters 0-7 and 9-12 of the canonical form.
  return std::stoull(uuid.substr(0, 8) + uuid.substr(9, 4), nullptr, 16);
}
```

**Anti-patterns.**
- Do NOT rely on v7 for strict ordering of events inside one millisecond, or across a clock step; add your own sequence number if you need total order.
- Do NOT use v7 where the creation time must stay private -- it is readable from the identifier.
- Do NOT compare a generated UUID against one from another source (an uppercase or braced form) with plain string equality; the generator always emits lowercase canonical form, so normalize the other side to lowercase canonical first.

---

## Thread Safety Model

Stateless and reentrant. `v4()` and `v7()` hold no locks and share no mutable state; the only shared resources are OpenSSL's internally synchronized RNG (via `SecureRng::fill`) and `system_clock::now()`. Safe to call concurrently from any number of threads.

---

## API Reference

```cpp
namespace iora
{
namespace ids
{

class Uuid
{
public:
  static std::string v4();
  static std::string v7();
};

} // namespace ids
} // namespace iora
```

| Method | Returns | Throws |
|---|---|---|
| `Uuid::v4()` | 36-char lowercase canonical UUID, version 4 | `std::runtime_error` if `SecureRng::fill` fails |
| `Uuid::v7()` | 36-char lowercase canonical UUID, version 7 (48-bit Unix ms prefix) | `std::runtime_error` if `SecureRng::fill` fails |

---

## Design Decisions

| Decision | Rationale |
|---|---|
| Random bits from `SecureRng` (OpenSSL), not `std::mt19937` | Identifiers such as SIP Call-IDs are exposed on the wire; a seeded PRNG would make them predictable. |
| Return `std::string`, no `Uuid` value type | Every in-tree and iora_sip consumer wants the text form immediately (headers, map keys, logs). A parsed value type would be capability nobody uses. |
| Lowercase output | RFC 9562 §4 allows any case (the lowercase-output rule was RFC 4122's, which RFC 9562 obsoletes); iora always emits lowercase so output is stable and string comparison of v7 values matches timestamp order. |
| No v7 monotonic counter | Random `rand_a` is a conforming RFC 9562 layout and keeps the generator stateless and lock-free; strict intra-millisecond order was not a requirement of any consumer. |
| Precomputed 256-entry hex-pair table | Two table lookups per byte and one pre-sized string; no `snprintf`/stream formatting. |

---

## Known Limitations

- **v7 is not monotonic within a millisecond**, and a backwards `system_clock` step breaks ordering (see "v7 ordering").
- **Clock before 1970.** `v7()` casts the millisecond count to `std::uint64_t`; a `system_clock` set before the Unix epoch yields a wrapped, meaningless timestamp prefix.
- **Generation only.** There is no parser, validator, byte-array accessor, or other UUID versions (v1, v3, v5, v6, v8), and no nil/max UUID constants.
- **Test coverage.** `tests/util/iora_test_uuid.cpp` checks the canonical format, version and variant characters of v4 and v7, 1000 distinct v4 values, 1000 distinct back-to-back v7 values (typically many share a millisecond, so the random bits must separate them), that the v7 prefix equals the current Unix-epoch millisecond, and that v7 values created in different milliseconds compare in creation order. The `SecureRng::fill` failure path is not exercised.

---

*See also:* [`../crypto/secure_rng.md`](../crypto/secure_rng.md) (the random source).
