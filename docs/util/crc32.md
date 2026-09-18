# Iora CRC-32 -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-09-18 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/util/crc32.hpp` |
| **Namespace** | `iora::util` |
| **Dependencies** | `<array>`, `<cstddef>`, `<cstdint>`, `<string_view>` (standard library only -- no `iora/core`, no third-party) |

This guide covers `iora::util::Crc32`: the table-driven, reflected CRC-32 (polynomial `0xEDB88320`) used to compute and verify the gzip trailer's checksum field (RFC 1952 §2.3.1). Its production consumer is the gzip codec, [`docs/util/gzip.md`](gzip.md) -- see `iora/util/gzip.hpp`, which calls `Crc32::compute` for the one-shot encoder trailer and header-CRC verification, and holds a `Crc32::Incremental` member in its streaming `Gzip::Encoder` to fold the CRC across chunks without re-scanning already-emitted input.

**Document scope.** This guide uses the sanctioned lite variant of the Architecture & Programmer's Guide template (not all 12 sections): `crc32.hpp` defines one class that is a pure static-method namespace (`compute`) plus a small non-owning accumulator struct (`Incremental`) with no polymorphism, no I/O, and no configuration surface -- there is no instance state beyond the accumulator's single running value, no threading model beyond reentrancy, and no multi-step call flow -- so the class-oriented sections (System Architecture, Configuration Reference, Call Flow) do not apply.

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-18 | Initial guide for `crc32.hpp` (`Crc32::compute`, `Crc32::Incremental`). |

---

## Executive Summary

**Problem.** The gzip container (RFC 1952 §2.3.1) requires a CRC-32 of the *uncompressed* data in its trailer, computed with a specific parameterization (reflected input/output, initial value `0xFFFFFFFF`, final XOR `0xFFFFFFFF`) that is also what zlib and PNG use. A one-shot encoder can compute this over the whole buffer, but a streaming encoder (`Gzip::Encoder`, `gzip.hpp`) must fold the CRC incrementally across chunks as they arrive, without holding the entire input in memory just to checksum it at the end (`crc32.hpp:20-30`).

**Solution.**
- `iora::util::Crc32::compute(std::string_view)` -- one-shot CRC-32 over a byte view (`crc32.hpp:55-58`).
- `iora::util::Crc32::compute(const void*, std::size_t)` -- one-shot CRC-32 over a raw pointer+length range; `data` may be null iff `len == 0` (`crc32.hpp:60-66`).
- `iora::util::Crc32::Incremental` -- a small accumulator: `update(const void*, std::size_t)` / `update(std::string_view)` fold bytes into the running state, and `value()` reads the current CRC-32 at any point without disturbing it, so `update()` can continue afterward (`crc32.hpp:71-102`).
- Deliberately **no `reset()`**: one `Incremental` instance is meant to compute exactly one CRC (one gzip member); a caller needing a second CRC constructs a second `Incremental` (`crc32.hpp:69-70`).

**Technical impact.** The 256-entry lookup table (`makeTable()`, `crc32.hpp:38-51`) is `constexpr`, so it is generated at compile time with no runtime table-init cost and no synchronization concern. `compute` and `update` operate directly on `std::string_view` / raw pointers -- never a `std::vector<std::uint8_t>` -- so the API is binary-safe over embedded `NUL` bytes and requires no copy into an intermediate container (`crc32.hpp:26-29`). `Crc32` is explicitly scoped as a non-cryptographic utility: CRC-32 provides no security property, which is why it lives in `util/` rather than a crypto namespace (`crc32.hpp:26-27`).

---

## Deep Dive & Usage

### Parameterization

| Property | Value | Source (file:line) |
|---|---|---|
| Polynomial | `0xEDB88320` (reflected form) | `makeTable()`, `crc32.hpp:46` |
| Initial value | `0xFFFFFFFF` | `Incremental::_crc` default member initializer, `crc32.hpp:101` |
| Final XOR | `0xFFFFFFFF` | `value()`, `crc32.hpp:98` |
| Input/output reflection | reflected (table-driven right-shift form) | `update()` loop, `crc32.hpp:87` |
| CRC-32 of empty input | `0x00000000` | doc comment `crc32.hpp:24`; verified by construction: `_crc` stays `0xFFFFFFFF` when `update()` folds zero bytes, and `value()` XORs it back to `0` |

This is the same parameterization gzip, zlib, and PNG use (`crc32.hpp:22-24`).

### `compute` -- one-shot

`compute(std::string_view data)` (`crc32.hpp:55-58`) forwards to `compute(data.data(), data.size())`. `compute(const void *data, std::size_t len)` (`crc32.hpp:60-66`) constructs a fresh `Incremental`, folds the whole range through `update()`, and returns `value()`. The doc comment states the null-pointer contract explicitly: `data` may be null **iff** `len` is `0` (`crc32.hpp:60`).

### `Incremental` -- the accumulator

| Behavior | Source (file:line) |
|---|---|
| `update(const void *data, std::size_t len)` folds `len` bytes at `data` into the running CRC via the reflected-polynomial table | `crc32.hpp:74-90` |
| Table lookup indexes with `unsigned char`, not `char` | `static_cast<const unsigned char *>(data)`, `crc32.hpp:83`; doc comment `:81-82` explains a signed `char` would sign-extend bytes `>= 0x80` and corrupt the CRC across the whole high-byte domain |
| `update(std::string_view data)` forwards to the pointer+length overload | `crc32.hpp:93` |
| `value()` is `const` and **non-mutating**: it applies the final XOR to a *copy* of `_crc`, so it can be called mid-stream and `update()` may continue afterward with correct results | `crc32.hpp:95-98` |
| No `reset()` method exists | absent from `crc32.hpp:71-102` (struct body) -- by design, per the doc comment at `:69-70` |
| `_crc` is private, default-initialized to `0xFFFFFFFF` | `crc32.hpp:100-101` |

The lookup table used by `update()` is declared as a `static constexpr std::array<std::uint32_t, 256>` **local to the function body** (`crc32.hpp:80`), built once at compile time by `makeTable()` and shared across every call and every translation unit that includes the header, exactly mirroring the pattern `util/base64.hpp` uses for its own function-local encode table (noted in the doc comment at `crc32.hpp:76-79`).

### Usage

Examples compile against the real API.

**1. One-shot CRC-32 of a complete buffer (gzip trailer field).**

```cpp
#include "iora/util/crc32.hpp"

#include <cstdint>
#include <string_view>

std::uint32_t trailerCrc(std::string_view uncompressed)
{
  return iora::util::Crc32::compute(uncompressed);
}
```

**2. Fold a CRC incrementally across streamed chunks, then read it once at the end.**

```cpp
#include "iora/util/crc32.hpp"

#include <string_view>

std::uint32_t crcOverChunks(std::string_view chunk1, std::string_view chunk2)
{
  iora::util::Crc32::Incremental acc;
  acc.update(chunk1);
  acc.update(chunk2);
  return acc.value();
}
```

**3. Read the running CRC mid-stream without disturbing it (`value()` is non-mutating).**

```cpp
#include "iora/util/crc32.hpp"

#include <cassert>
#include <string_view>

void midStreamCheck()
{
  iora::util::Crc32::Incremental acc;
  acc.update(std::string_view("foo"));
  const std::uint32_t partial = acc.value(); // safe to call here
  acc.update(std::string_view("bar"));
  const std::uint32_t total = acc.value();
  assert(total == iora::util::Crc32::compute(std::string_view("foobar")));
  (void)partial;
}
```

**4. One accumulator per CRC -- no `reset()`, so a second CRC needs a second instance.**

```cpp
#include "iora/util/crc32.hpp"

#include <string_view>

std::uint32_t crcOfSecondMember(std::string_view memberBytes)
{
  // Do NOT reuse a Crc32::Incremental across two independent CRCs -- there is
  // no reset(). Construct a fresh accumulator per gzip member.
  iora::util::Crc32::Incremental fresh;
  fresh.update(memberBytes);
  return fresh.value();
}
```

**Anti-patterns.**
- Do NOT reuse one `Crc32::Incremental` instance across two logically separate CRCs (e.g. two gzip members). There is no `reset()`; construct a new `Incremental` instead (`crc32.hpp:69-70`).
- Do NOT pass a `data == nullptr` to `compute(const void*, std::size_t)` unless `len == 0` -- the documented contract requires `len == 0` whenever `data` is null (`crc32.hpp:60`).
- Do NOT treat `Crc32` as a security primitive (message authentication, tamper detection against an adversary). CRC-32 provides no cryptographic guarantee; it exists to catch accidental corruption, which is exactly what the gzip trailer uses it for (`crc32.hpp:26-27`).
- Do NOT assume `value()` requires a completed stream -- it is safe to call at any point mid-accumulation and does not prevent further `update()` calls (`crc32.hpp:95-98`).
- Do NOT copy input bytes into a `std::vector<std::uint8_t>` before calling -- `compute`/`update` already accept `std::string_view` or a raw pointer+length directly, binary-safe over embedded `NUL`s (`crc32.hpp:26-29`).

---

## Thread Safety Model

**Reentrant, no shared mutable state across calls; `Incremental` is a single-writer accumulator, not a shared object.** `Crc32::compute` is a pure `static` function with no state of its own. The lookup table built by `makeTable()` is `static constexpr`, fixed at compile time -- no runtime initialization race. `Crc32::Incremental` holds one mutable member, `_crc`; concurrent calls to `update()` on the *same* `Incremental` instance from multiple threads are not synchronized by this class and require external locking (or, more simply, one `Incremental` per thread / per stream, which also matches its intended one-CRC-per-instance usage). Distinct `Incremental` instances, and calls to `compute()`, may be used concurrently from any number of threads with no synchronization, subject to the caller keeping each input buffer alive for the duration of its call.

---

## API Reference

```cpp
namespace iora
{
namespace util
{

class Crc32
{
public:
  static std::uint32_t compute(std::string_view data);
  static std::uint32_t compute(const void *data, std::size_t len);

  struct Incremental
  {
    void update(const void *data, std::size_t len);
    void update(std::string_view data);
    std::uint32_t value() const;
  };
};

} // namespace util
} // namespace iora
```

| Method | Signature | Returns |
|---|---|---|
| `Crc32::compute` | `std::uint32_t(std::string_view data)` | CRC-32 of the view |
| `Crc32::compute` | `std::uint32_t(const void *data, std::size_t len)` | CRC-32 of the range; `data` may be null iff `len == 0` |
| `Incremental::update` | `void(const void *data, std::size_t len)` | folds `len` bytes into the running CRC |
| `Incremental::update` | `void(std::string_view data)` | folds a byte view into the running CRC |
| `Incremental::value` | `std::uint32_t() const` | the current CRC-32 (final XOR applied to a copy of the running state); non-mutating |

---

## Design Decisions

| Decision | Rationale |
|---|---|
| Lives in `util/`, not a crypto namespace | CRC-32 provides no security property -- it is a corruption-detection checksum, not a cryptographic primitive (`crc32.hpp:26-27`). |
| Accepts `std::string_view` / raw `const void*` + length, never `std::vector<std::uint8_t>` | Binary-safe over embedded `NUL`s and avoids forcing callers (notably the streaming gzip encoder) to materialize or copy into a vector just to checksum a chunk (`crc32.hpp:27-29`). |
| `Incremental` accumulator with no `reset()` | Enforces one-accumulator-per-CRC (one gzip member) by construction rather than by convention, ruling out an accidental cross-contaminated CRC from a stale accumulator (`crc32.hpp:69-70`). |
| `value()` is non-mutating (applies the final XOR to a copy) | Lets a caller (or a future diagnostic) read the running CRC mid-stream and keep accumulating afterward, rather than making the read destructive (`crc32.hpp:95-98`). |
| Table indexed with `unsigned char`, not `char` | A signed `char` sign-extends bytes `>= 0x80`, which would corrupt the CRC for the entire high-byte domain -- correctness-critical for binary (non-ASCII) payloads (`crc32.hpp:81-83`). |
| Lookup table built as a `static constexpr` local to `update()` | Zero runtime initialization cost (built at compile time) and one shared instance across every translation unit including the header, without a namespace-scope global (`crc32.hpp:76-79`). |

---

## Known Limitations

- **`Incremental` provides no built-in synchronization.** Concurrent `update()` calls on the same instance from multiple threads require external locking; the intended usage is one `Incremental` per in-flight stream (see Thread Safety Model).
- **No `reset()`.** A caller needing to compute many independent CRCs in a loop must construct a new `Incremental` each time rather than reusing one; this is a deliberate design choice, not an oversight, but it does mean the type cannot be pooled/reused across CRCs (`crc32.hpp:69-70`).
- **No incremental variant of the free `compute()` convenience beyond `Incremental` itself.** There is no `compute(view1, view2, ...)` multi-argument overload; multi-chunk one-shot computation requires either concatenating the chunks first or using `Incremental` directly.
- **CRC-32 only.** There is no CRC-32C (Castagnoli) or other polynomial variant in this header; a consumer needing a different CRC parameterization (e.g. for a different container format) would need a separate implementation.
- **Dedicated unit-test file.** `Crc32` has a standalone suite, `tests/util/iora_test_crc32.cpp`, asserting known-answer vectors, that the `const void*`/`len` overload agrees with the `string_view` overload, that an embedded `NUL` is not treated as a terminator, that incremental accumulation in arbitrary (including one-byte and odd-boundary) chunks equals the one-shot result, and that `value()` is non-mutating mid-stream. It is additionally exercised in production through `iora::util::Gzip`'s one-shot `compress`/`decompress` (header-CRC verification and trailer CRC, `gzip.hpp:1017`, `:1080`, `:1276`) and its streaming `Encoder`'s `Crc32::Incremental _crc` member (`gzip.hpp:1206`), covered by `tests/util/iora_test_gzip_decode.cpp`.

---

*See also:* [`base64.md`](base64.md) (the sibling `iora/util/` lite guide) and [`gzip.md`](gzip.md) (the RFC 1952 gzip codec that is `Crc32`'s production consumer).
