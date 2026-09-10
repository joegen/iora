# Iora StringUtils -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 3.0 |
| **Date** | 2026-09-10 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/core/string_utils.hpp` |
| **Namespace** | `iora::core` |
| **Dependencies** | Standard library only -- `<string>`, `<string_view>`, `<vector>`. No intra-Iora headers, no external/third-party dependencies. Header-only. |

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-03-20 | Initial implementation. |
| 1.1 | 2026-03-20 | Added `CaseInsensitiveHash` / `CaseInsensitiveEqual` with `is_transparent`; migration note. |
| 2.0 | 2026-03-20 | Full Architecture & Programmer's Guide rewrite (published as `coding_trackers/docs/iora/string_utils.md`). |
| 3.0 | 2026-09-10 | Migrated to `docs/core/string_utils.md` and **fully re-verified against `include/iora/core/string_utils.hpp` (218 lines) and `tests/core/iora_test_string_utils.cpp`.** **Corrected major drift:** the case-folding path does **not** use `std::tolower` -- it uses hand-rolled, locale-independent ASCII helpers `toLowerChar` / `toUpperChar` (bytes `>= 0x80` pass through verbatim), chosen deliberately so the result is byte-identical across processes and locales. Every prior claim about `std::tolower` UB and `<cctype>` safety has been rewritten to describe the actual implementation. Corrected the `is_transparent` claim: heterogeneous lookup on `std::unordered_map` is a **C++20** feature (P0919) and has **no effect under C++17**, so the markers are currently inert / forward-compatibility only (section 4, section 12). Added the `toUpperChar` helper (absent from the prior draft), the dead-include note, and the migration/storage section was retained as a design-intent record. Reformatted to the 12-section template with contiguous numbered sections. |
| 3.1 | 2026-09-10 | CP-3 doc-review + code-fix sync: the three dead includes (`<algorithm>`, `<cctype>`, `<functional>`) were removed from the header (section 12 candidate-defect now RESOLVED; Dependencies list updated). Added a high-byte (`>= 0x80`) pass-through regression test (`static_cast<char>`-built inputs) exercising the locale-independent fold. |

---

## 1. Executive Summary

### Problem

Every protocol parser in the codebase (SIP, SDP, HTTP, TOML) needs the same handful of primitives: split a field on a delimiter, strip optional whitespace (OWS), and compare tokens case-insensitively. Hand-rolling these per parser produces three recurring defects:

- **Gratuitous allocation on the hot path** -- a `split` that returns `std::vector<std::string>` copies every field of every message; a case-insensitive compare that `toLower`s both operands allocates two strings just to answer a boolean.
- **Locale-dependent case folding** -- routing `tolower` through `std::tolower(int)` makes the fold result depend on the process locale for any byte `>= 0x80`. Two peers (or the same peer under a different `LC_*`) can then disagree on whether two codec names or header values match -- a silent interop hazard for anything that must be byte-identical across sites.
- **The `unsigned char` trap** -- `std::tolower(c)` where `c` is a plain (possibly signed) `char` holding a byte `> 0x7F` is undefined behavior; it is routinely gotten wrong.

The pre-existing `iora::storage::CaseInsensitiveHash` (in `concrete_state_store.hpp`) exhibited the first two problems directly: it allocated a lowercased copy of the whole key on every hash call and lacked any heterogeneous-lookup affordance.

### Solution

A single `struct StringUtils` in `iora::core` -- a namespace-like grouping of `static` methods, no instance state -- providing:

- **Zero-copy `split` / `trim` / `trimLeft` / `trimRight`** that return `std::string_view` sub-views into the caller's buffer; no heap allocation on the parse path (aside from the `split` result vector itself).
- **`iequals`** -- an ASCII, locale-independent case-insensitive compare with an early length-mismatch exit.
- **`toLower` / `toUpper`** -- the only allocating functions; used when an owned, normalized copy is genuinely required.
- **`CaseInsensitiveHash` / `CaseInsensitiveEqual`** -- non-allocating hash/equality traits for a case-insensitive `std::unordered_map`, each carrying an `is_transparent` marker (effective under C++20; see section 4).

### Technical Impact

- **Zero allocation** for `split` views, all three `trim` variants, and `iequals`.
- **Locale-independent, process-deterministic folding.** Case mapping is a hand-rolled ASCII `A`-`Z` / `a`-`z` branch (`toLowerChar` / `toUpperChar`); every byte `>= 0x80` is passed through unchanged and compared verbatim. The answer is identical across processes and locales -- safe for cross-site / cross-process agreement (a codec-name or User-Agent match that must be byte-identical between peers).
- **No `std::tolower` UB exposure.** The helpers never call the `<cctype>` functions; the `unsigned char` cast they do perform is only to make the `A`-`Z` range test well-defined, not to feed a locale function.
- **`CaseInsensitiveHash` folds the lowercase mapping into the hash accumulation loop** (`h = h * 31 + toLowerChar(c)`), so no temporary lowercased string is ever materialized.

---

## 2. System Architecture

### 2.1 Component relationships

```
iora::core  (string_utils.hpp)
|
|-- inline constexpr std::string_view kWhitespace = " \t\r\n"   (trim charset)
|
`-- struct StringUtils                          (all members static; no state, no instances)
    |-- split(input, char)            -> std::vector<std::string_view>   [zero-copy views]
    |-- split(input, string_view)     -> std::vector<std::string_view>   [zero-copy views]
    |-- trim(input)                   -> std::string_view                [zero-copy, noexcept]
    |-- trimLeft(input)               -> std::string_view                [zero-copy, noexcept]
    |-- trimRight(input)              -> std::string_view                [zero-copy, noexcept]
    |-- iequals(a, b)                 -> bool                            [zero-copy, noexcept]
    |-- toLower(input)                -> std::string                     [allocates]
    |-- toUpper(input)                -> std::string                     [allocates]
    |-- struct CaseInsensitiveHash    (nested trait)
    |   |-- using is_transparent = void
    |   `-- operator()(string_view) const noexcept    [h*31 + toLowerChar(c); non-allocating]
    |-- struct CaseInsensitiveEqual   (nested trait)
    |   |-- using is_transparent = void
    |   `-- operator()(a, b) const noexcept           [delegates to iequals]
    |
    |-- (private) toLowerChar(char) noexcept   [ASCII A-Z -> a-z; else pass-through]
    `-- (private) toUpperChar(char) noexcept   [ASCII a-z -> A-Z; else pass-through]

Both nested traits are designed to be plugged into:
  std::unordered_map<std::string, V, StringUtils::CaseInsensitiveHash,
                     StringUtils::CaseInsensitiveEqual>
```

`StringUtils` holds no data members. It is a `struct` used purely to scope a family of generically-named utilities (`split`, `trim`, `iequals`) without leaking those names into `iora::core`, and to host the two nested trait types.

### 2.2 Data flow -- SIP header parse (zero-copy pipeline)

```mermaid
sequenceDiagram
  participant Raw as Raw message buffer (string_view)
  participant Split as StringUtils::split
  participant Trim as StringUtils::trim
  participant Map as unordered_map&lt;string, V, CaseInsensitiveHash, CaseInsensitiveEqual&gt;

  Raw->>Split: split(headerLine, ':')
  Split-->>Raw: {name_view, value_view} (sub-views of Raw)
  Raw->>Trim: trim(value_view)
  Trim-->>Raw: trimmed_view (sub-view of Raw)
  Note over Raw: Raw must outlive every returned view
  Raw->>Map: operator[] / count(name)
  Note over Map: CaseInsensitiveHash + CaseInsensitiveEqual<br/>match name case-insensitively (ASCII, locale-free)
  Map-->>Raw: value
```

### 2.3 Threading model

| Thread | Responsibility |
|---|---|
| **Any thread** | Every function is a pure, stateless operation over its arguments and stack locals. Any number of threads may call any combination concurrently with **no synchronization** -- there is no shared mutable state, no static storage, no I/O. |
| **Caller** | Owns the backing buffer behind every `std::string_view` argument and every returned view, and must keep it alive for the lifetime of those views (section 6). Owns any `unordered_map` built on the traits; `StringUtils` adds no thread-safety to the container itself. |

---

## 3. Component Deep Dive

### 3.1 `split` -- zero-copy tokenization

Two overloads: a single `char` delimiter and a `std::string_view` delimiter. Both scan with `std::string_view::find` and emit `substr` sub-views (pointer + length into the input); the only allocation is the result `std::vector` itself.

```cpp
static std::vector<std::string_view> split(std::string_view input, char delimiter)
{
  std::vector<std::string_view> result;
  if (input.empty())
  {
    return result;
  }
  std::size_t start = 0;
  while (true)
  {
    auto pos = input.find(delimiter, start);
    if (pos == std::string_view::npos)
    {
      result.push_back(input.substr(start));
      break;
    }
    result.push_back(input.substr(start, pos - start));
    start = pos + 1;
  }
  return result;
}
```

**Edge cases** (all confirmed by the test suite):

| Input | Delimiter | Result | Source / test |
|---|---|---|---|
| `""` | `','` | `{}` (empty vector) | empty-input guard; `split(char): empty input` |
| `"hello"` | `','` | `{"hello"}` | no delimiter; `split(char): no delimiter found` |
| `"a,,b"` | `','` | `{"a", "", "b"}` | consecutive delimiters yield empty views; `split(char): consecutive delimiters` |
| `","` | `','` | `{"", ""}` | leading+trailing empty; `split(char): delimiter only` |
| `""` | `"::"` (sv) | `{}` (empty vector) | empty-input guard runs **before** the empty-delimiter guard; `split(string_view): empty input` |
| `"hello"` | `""` (sv) | `{"hello"}` | empty `string_view` delimiter returns input as one element; `split(string_view): empty delimiter returns input` |

The `string_view` overload advances by `delimiter.size()` per match (not `1`), and short-circuits an **empty** delimiter to `{input}` -- but only after the empty-**input** guard, so `split("", "")` is `{}`, not `{""}`.

### 3.2 `trim` / `trimLeft` / `trimRight` -- zero-copy whitespace stripping

The whitespace set is the module constant:

```cpp
inline constexpr std::string_view kWhitespace = " \t\r\n";
```

Space, horizontal tab, carriage return, line feed -- the OWS set shared across the SIP / HTTP / SDP parsers. All three functions locate the non-whitespace bounds with `find_first_not_of` / `find_last_not_of` and return a `substr`; an all-whitespace or empty input returns an **empty** `std::string_view`. All three are `noexcept` (no allocation, no exception source).

```cpp
static std::string_view trim(std::string_view input) noexcept
{
  auto start = input.find_first_not_of(kWhitespace);
  if (start == std::string_view::npos)
  {
    return {};
  }
  auto end = input.find_last_not_of(kWhitespace);
  return input.substr(start, end - start + 1);
}
```

`trimLeft` returns from the first non-whitespace to the end; `trimRight` returns from the start through the last non-whitespace (`input.substr(0, end + 1)`). The returned view carries the same lifetime obligation as `split` (section 6).

### 3.3 `iequals` -- ASCII, locale-independent case-insensitive compare

```cpp
static bool iequals(std::string_view a, std::string_view b) noexcept
{
  if (a.size() != b.size())
  {
    return false;
  }
  for (std::size_t i = 0; i < a.size(); ++i)
  {
    if (toLowerChar(a[i]) != toLowerChar(b[i]))
    {
      return false;
    }
  }
  return true;
}
```

**Early exit.** Unequal lengths return `false` without entering the loop -- the common case when probing one header name against many candidates.

**Byte semantics.** Comparison is per-byte via `toLowerChar`. For the ASCII range `A`-`Z` the byte is folded to lowercase; **every byte `>= 0x80` is compared verbatim** (see section 4 for why this is deliberate, not an oversight). So `iequals("Content-Type", "content-type")` is `true`, while two different byte sequences that a Unicode-aware fold might consider case-variant (e.g. accented display-name characters) are **not** treated as equal.

### 3.4 `toLower` / `toUpper` -- the allocating conversions

These are the only functions that allocate: each builds a new `std::string`, `reserve`s `input.size()` (single allocation, no reallocation), and maps each byte through `toLowerChar` / `toUpperChar` respectively.

```cpp
static std::string toLower(std::string_view input)
{
  std::string result;
  result.reserve(input.size());
  for (char c : input)
  {
    result += toLowerChar(c);
  }
  return result;
}
```

`toUpper` is the mirror image over `toUpperChar`. Use these only when an owned normalized copy is genuinely needed (e.g. a storage key). For a boolean comparison, prefer `iequals` -- it allocates nothing.

### 3.5 The private folding helpers -- `toLowerChar` / `toUpperChar`

This is the heart of the component's correctness contract, and the single largest correction against the prior draft. The folding does **not** call `std::tolower` / `std::toupper`:

```cpp
static char toLowerChar(char c) noexcept
{
  const auto u = static_cast<unsigned char>(c);
  return (u >= 'A' && u <= 'Z') ? static_cast<char>(u + 0x20) : c;
}

static char toUpperChar(char c) noexcept
{
  const auto u = static_cast<unsigned char>(c);
  return (u >= 'a' && u <= 'z') ? static_cast<char>(u - 0x20) : c;
}
```

- **`static_cast<unsigned char>(c)`** makes the range test well-defined on platforms where `char` is signed (a byte `> 0x7F` would otherwise be a negative `int`). The cast feeds a plain range comparison, **not** a `<cctype>` function -- so there is no `std::tolower` undefined-behavior surface at all.
- **ASCII-only, locale-independent.** Only `A`-`Z` (resp. `a`-`z`) are remapped; every other byte -- including all of `0x80`-`0xFF` -- is returned unchanged. The header comment is explicit that this is "deliberately NOT `std::tolower`, which is locale-dependent for bytes `>= 0x80` and would make the 'ASCII only' contract non-deterministic across processes/locales."

### 3.6 `CaseInsensitiveHash` -- non-allocating hash trait

```cpp
struct CaseInsensitiveHash
{
  using is_transparent = void;

  std::size_t operator()(std::string_view key) const noexcept
  {
    std::size_t h = 0;
    for (char c : key)
    {
      h = h * 31 + static_cast<std::size_t>(
        static_cast<unsigned char>(toLowerChar(c)));
    }
    return h;
  }
};
```

- **Non-allocating.** The lowercase mapping is folded into the accumulation loop -- no temporary lowercased `std::string` (the exact defect of the old `storage::CaseInsensitiveHash`, which copied, transformed, then hashed).
- **Algorithm.** `h = h * 31 + toLowerChar(c)` -- the Bernstein-variant (multiplier 31) used by Java's `String.hashCode()`. Adequate bucket distribution for short ASCII tokens (header names); **not** cryptographic.
- **`noexcept`.** The test suite `static_assert`s `noexcept(hash("test"))`.
- **`is_transparent`.** A marker type; see section 4 for its (C++20-gated) effect.

Because the hasher lowercases through `toLowerChar`, `hash("Content-Type") == hash("content-type")` (confirmed by `CaseInsensitiveHash: same hash for different case`).

### 3.7 `CaseInsensitiveEqual` -- equality trait

```cpp
struct CaseInsensitiveEqual
{
  using is_transparent = void;

  bool operator()(std::string_view a, std::string_view b) const noexcept
  {
    return iequals(a, b);
  }
};
```

Delegates to `StringUtils::iequals`, inheriting its ASCII / locale-independent semantics. `noexcept` (`static_assert`ed in the test suite). Paired with `CaseInsensitiveHash`, it makes a `std::unordered_map` key-match header names case-insensitively.

---

## 4. ASCII / Locale-Independence Model

This section records the one cross-cutting correctness property that the whole component rests on, and the one C++ version subtlety that governs a documented feature.

### 4.1 Folding is ASCII-only and locale-independent -- by contract

Every case-sensitive decision in `StringUtils` (`iequals`, `toLower`, `toUpper`, `CaseInsensitiveHash`, `CaseInsensitiveEqual`) runs through `toLowerChar` / `toUpperChar`, which remap **only** the 26 ASCII letters and pass all other bytes through verbatim. The consequences:

| Property | Consequence |
|---|---|
| Bytes `0x00`-`0x7F` outside `A`-`Z`/`a`-`z` | unchanged (digits, punctuation, control bytes). |
| Bytes `0x80`-`0xFF` | unchanged, **compared verbatim** -- no locale, no Unicode fold. |
| Determinism | identical result in every process and under every locale; safe for cross-site / cross-process byte-identical agreement (codec names, header tokens). |
| Correct for | RFC tokens: SIP (RFC 3261), HTTP (RFC 7230/9110), SDP (RFC 4566) header/field names are US-ASCII by spec. |
| **Not** correct for | Unicode case folding -- e.g. accented characters in a SIP `From` display name will not be folded. That is out of scope (would require ICU). |

This is the property that makes `iequals` a safe equality primitive for protocol tokens that must match bit-for-bit between peers. Do not "upgrade" it to `std::tolower`: that reintroduces locale dependence for bytes `>= 0x80` and breaks cross-process agreement.

### 4.2 `is_transparent` is C++20-effective, inert under C++17

Both traits declare `using is_transparent = void;`. For the **ordered** associative containers (`std::map`/`std::set`) a transparent comparator has enabled heterogeneous lookup since C++14. For the **unordered** containers (`std::unordered_map`/`std::unordered_set`) heterogeneous lookup was added only in **C++20** (P0919R3): the container consults `is_transparent` on both the hash and the key-equal traits to let `find` / `count` / `contains` accept a `std::string_view` (or any compatible type) **without** materializing a temporary `key_type`.

Iora builds as C++17. Under C++17 the markers are therefore **inert**: `map.find(std::string_view)` on an `unordered_map<std::string, ...>` still constructs a temporary `std::string` key before hashing. The markers are correct and harmless, and they activate automatically if/when the translation unit is compiled as C++20. The test `Hash traits: is_transparent trait present` only verifies the typedef **exists** (`std::is_same_v<..., void>`); no test exercises an actual heterogeneous lookup (it could not, under C++17). See section 12.

---

## 5. Usage Guide

All examples compile against the real API.

### 5.1 SIP header parse -- zero-copy split + trim

```cpp
#include <iora/core/string_utils.hpp>

#include <string_view>

using namespace iora::core;

void parseViaLine(std::string_view headerLine)
{
  // headerLine points into a message buffer the caller keeps alive.
  auto parts = StringUtils::split(headerLine, ':');   // {"Via", " SIP/2.0/UDP ...;branch=..."}
  if (parts.size() < 2)
  {
    return;
  }

  std::string_view name  = StringUtils::trim(parts[0]);  // "Via"
  std::string_view value = StringUtils::trim(parts[1]);  // "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK"

  auto fields = StringUtils::split(value, ';');          // {"SIP/2.0/UDP 10.0.0.1:5060", "branch=z9hG4bK"}
  // ... all views above alias headerLine; no heap copies of the field data.
}
```

### 5.2 Case-insensitive header map

```cpp
#include <iora/core/string_utils.hpp>

#include <cassert>
#include <string>
#include <unordered_map>

using namespace iora::core;

void headerMapDemo()
{
  std::unordered_map<std::string, std::string,
    StringUtils::CaseInsensitiveHash,
    StringUtils::CaseInsensitiveEqual> headers;

  headers["Content-Type"] = "application/sdp";
  headers["Via"]          = "SIP/2.0/UDP 10.0.0.1:5060";

  // operator[] / count build a std::string key, then hash + compare it
  // case-insensitively -- so differently-cased probes hit the same entry.
  assert(headers["content-type"] == "application/sdp");
  assert(headers.count("VIA") == 1);
}
```

Note: these probes pass a `const char*`/`std::string`, so a `key_type` is constructed regardless. Heterogeneous `find(std::string_view)` without that construction requires a C++20 build (section 4.2).

### 5.3 Case-insensitive token comparison (no allocation)

```cpp
#include <iora/core/string_utils.hpp>

#include <string_view>

using namespace iora::core;

bool isRegister(std::string_view method)
{
  // SIP method names are case-insensitive (RFC 3261). Zero allocation.
  return StringUtils::iequals(method, "REGISTER");
}
```

### 5.4 Owned normalized copy -- `toLower`

```cpp
#include <iora/core/string_utils.hpp>

#include <string>
#include <string_view>

using namespace iora::core;

std::string normalizeSchemeForStorage(std::string_view scheme)
{
  // Only reach for toLower when you need an OWNED lowercase string,
  // e.g. a canonical storage key. For a comparison, use iequals instead.
  return StringUtils::toLower(scheme);  // "SIP" -> "sip"
}
```

### 5.5 Anti-patterns

- **Do NOT store a `split` / `trim` view beyond the source buffer's lifetime.** The views are non-owning pointers into the original data; if the source is freed or reallocated, every view dangles (section 6).
- **Do NOT use `toLower` / `toUpper` merely to compare.** Use `iequals` -- it allocates nothing; `toLower` allocates one string per operand.
- **Do NOT expect `iequals` / the traits to do Unicode case folding.** They are ASCII-only; bytes `>= 0x80` are compared verbatim. Accented display names will not fold.
- **Do NOT assume `find(std::string_view)` on the case-insensitive map skips the temporary `std::string`.** Under C++17 it does not (the `is_transparent` markers are inert); pass the key you already have and rely on the case-insensitive hash/equal, or build as C++20 for true heterogeneous lookup.
- **Do NOT swap `toLowerChar` for `std::tolower`.** That reintroduces locale dependence for bytes `>= 0x80` and breaks the cross-process byte-identical contract (section 4.1).
- **Do NOT rely on `split("", delim)` producing an empty-string element.** Empty input returns an empty vector (`{}`), for both the `char` and `string_view` overloads.

---

## 6. Lifetime and Zero-Copy Contract

The zero-copy design trades an allocation for a lifetime obligation, and that obligation is the single most important thing a caller must get right.

`split`, `trim`, `trimLeft`, and `trimRight` return `std::string_view`s that **point into the `input` argument's buffer** -- they copy no bytes. The header states it plainly: "The source string must outlive returned views." Concretely:

- A view returned from `trim(someTemporaryString)` dangles the moment that temporary is destroyed at the end of the full expression.
- Views from `split` remain valid only while the original buffer is alive **and unmodified**; mutating or reallocating the source (e.g. appending to the `std::string` it came from) invalidates every outstanding view.
- Passing views between threads is safe **only** because all access is read-only; the owning thread must still keep the buffer alive for the whole window during which any thread holds a view.

The `split` result `std::vector<std::string_view>` itself is heap-allocated (the element payloads are not). For an extremely hot path over a known-shape line, a manual `find` / `substr` loop avoids even that vector allocation.

`iequals`, `toLower`, `toUpper`, and the two traits have no lifetime obligation on their outputs: `iequals` returns a `bool`; `toLower`/`toUpper` return owned `std::string`s; the traits return a `std::size_t` / `bool`.

---

## 7. Call Flow / Sequence Reference

### 7.1 `split(input, char)` -- scan

| Step | Action |
|---|---|
| 1 | If `input.empty()`, return `{}` immediately. |
| 2 | `start = 0`. |
| 3 | `pos = input.find(delimiter, start)`. |
| 4 | If `pos == npos`: push `input.substr(start)` (the tail), break. |
| 5 | Else push `input.substr(start, pos - start)`; set `start = pos + 1`; go to 3. |
| 6 | Return the vector of views (each aliases `input`). |

### 7.2 `split(input, string_view)` -- empty-delimiter short-circuit

| Step | Action |
|---|---|
| 1 | If `input.empty()`, return `{}` (runs **before** the delimiter check). |
| 2 | If `delimiter.empty()`, push `input` as the sole element, return. |
| 3 | Otherwise identical to 7.1 but advancing `start = pos + delimiter.size()`. |

### 7.3 `trim` -- success and all-whitespace paths

| Step | Action | Path |
|---|---|---|
| 1 | `start = find_first_not_of(kWhitespace)`. | both |
| 2 | If `start == npos` (all whitespace / empty), return `{}`. | all-whitespace |
| 3 | `end = find_last_not_of(kWhitespace)`. | success |
| 4 | Return `input.substr(start, end - start + 1)`. | success |

### 7.4 `iequals` -- compare

| Step | Action |
|---|---|
| 1 | If `a.size() != b.size()`, return `false` (no loop). |
| 2 | For each index `i`: if `toLowerChar(a[i]) != toLowerChar(b[i])`, return `false`. |
| 3 | Return `true`. |

### 7.5 `CaseInsensitiveHash::operator()` -- accumulate

| Step | Action |
|---|---|
| 1 | `h = 0`. |
| 2 | For each byte `c`: `h = h * 31 + (unsigned)toLowerChar(c)`. |
| 3 | Return `h`. No allocation at any step. |

---

## 8. Thread Safety Model

| Operation | Synchronization | Notes |
|---|---|---|
| `split` (both overloads) | None needed | Pure; reads `input`, returns a fresh vector of views. Not `noexcept` (vector allocation may throw). |
| `trim` / `trimLeft` / `trimRight` | None needed | Pure, read-only, `noexcept`. |
| `iequals` | None needed | Pure, read-only, `noexcept`. |
| `toLower` / `toUpper` | None needed | Pure; returns a new owned `std::string`. Not `noexcept` (allocation). |
| `CaseInsensitiveHash::operator()` | None needed | Stateless functor, `const noexcept`. |
| `CaseInsensitiveEqual::operator()` | None needed | Stateless functor, `const noexcept`; delegates to `iequals`. |
| `toLowerChar` / `toUpperChar` | None needed | Private, pure, `noexcept`. |

**Lock inventory.** None. No mutexes, condition variables, atomics, or static mutable state anywhere in the header. Every function is reentrant and safe to call concurrently from any number of threads without synchronization.

The only shared-state concern is external: a `std::unordered_map` built on the traits is **not** itself made thread-safe by `StringUtils` -- concurrent mutation of the container is the caller's responsibility (use `ConcurrentHashMap` when a thread-safe map is required).

---

## 9. Configuration Reference

`StringUtils` is entirely stateless -- there is no runtime configuration, no environment variable, no tuning parameter, no capacity limit. The only compile-time constant is the trim charset:

| Constant | Type | Value | Meaning |
|---|---|---|---|
| `kWhitespace` | `inline constexpr std::string_view` | `" \t\r\n"` | The whitespace set stripped by `trim` / `trimLeft` / `trimRight` (SP, HTAB, CR, LF). Not itself configurable; changing the trim set means editing this constant. |

The hash multiplier (`31`) and the ASCII fold offset (`0x20`) are hard-coded implementation constants, not configuration.

---

## 10. API Reference

```cpp
namespace iora
{
namespace core
{

inline constexpr std::string_view kWhitespace = " \t\r\n";

struct StringUtils
{
  // Zero-copy split (returns views into `input`).
  static std::vector<std::string_view> split(std::string_view input, char delimiter);
  static std::vector<std::string_view> split(std::string_view input,
                                             std::string_view delimiter);

  // Zero-copy whitespace stripping (views into `input`).
  static std::string_view trim(std::string_view input) noexcept;
  static std::string_view trimLeft(std::string_view input) noexcept;
  static std::string_view trimRight(std::string_view input) noexcept;

  // ASCII, locale-independent case-insensitive comparison.
  static bool iequals(std::string_view a, std::string_view b) noexcept;

  // Allocating ASCII case conversions (bytes >= 0x80 pass through unchanged).
  static std::string toLower(std::string_view input);
  static std::string toUpper(std::string_view input);

  // Hash / equality traits for a case-insensitive unordered_map.
  struct CaseInsensitiveHash
  {
    using is_transparent = void;                                  // effective under C++20
    std::size_t operator()(std::string_view key) const noexcept;
  };

  struct CaseInsensitiveEqual
  {
    using is_transparent = void;                                  // effective under C++20
    bool operator()(std::string_view a, std::string_view b) const noexcept;
  };

private:
  static char toLowerChar(char c) noexcept;   // ASCII A-Z -> a-z; else pass-through
  static char toUpperChar(char c) noexcept;   // ASCII a-z -> A-Z; else pass-through
};

} // namespace core
} // namespace iora
```

---

## 11. Design Decisions

| ID | Decision | Rationale |
|---|---|---|
| D-1 | `struct StringUtils` with only `static` members (not free functions, not a namespace). | Groups generically-named utilities (`split`, `trim`, `iequals`) under one scope without leaking those names into `iora::core`, and hosts the nested `CaseInsensitiveHash` / `CaseInsensitiveEqual` types. No state, no instances. |
| D-2 | Zero-copy `split` / `trim` returning `std::string_view`. | Protocol parsing runs on every message; returning owned strings would allocate per field. The lifetime obligation (section 6) is acceptable because parsers hold the message buffer across the parse. |
| D-3 | Hand-rolled `toLowerChar` / `toUpperChar`, deliberately **not** `std::tolower` / `std::toupper`. | `std::tolower` is locale-dependent for bytes `>= 0x80`, which would make the "ASCII only" contract non-deterministic across processes/locales. The hand-rolled branch is locale-free and yields byte-identical results everywhere -- required for cross-site token agreement. |
| D-4 | Bytes `>= 0x80` pass through verbatim and are compared verbatim. | Keeps folding strictly within US-ASCII (correct for SIP/HTTP/SDP tokens) and avoids pretending to do Unicode case folding, which would need ICU. |
| D-5 | `static_cast<unsigned char>` inside the fold helpers. | Makes the `A`-`Z` / `a`-`z` range test well-defined on signed-`char` platforms -- **without** invoking any `<cctype>` function, so there is no `std::tolower` UB surface. |
| D-6 | `iequals` length-mismatch early exit. | Cheap rejection of the common "wrong candidate" case before any per-byte work. |
| D-7 | Non-allocating `CaseInsensitiveHash` (`h*31 + toLowerChar(c)`). | The old `storage::CaseInsensitiveHash` allocated a lowercased copy per hash call; folding the map into the loop removes that allocation on the hot path. |
| D-8 | `is_transparent` on both traits. | Forward-compatible heterogeneous lookup: a C++20 build lets `find(string_view)` skip the temporary `key_type`. Under C++17 the markers are harmless and inert (section 4.2). |
| D-9 | `noexcept` on `trim` family, `iequals`, and both trait operators; **not** on `split` / `toLower` / `toUpper`. | The former allocate nothing and have no throw source; the latter allocate and can throw `std::bad_alloc`. Matches what the test suite `static_assert`s. |
| D-10 | `kWhitespace` as a single `inline constexpr` constant. | Makes the OWS set visible and consistent across all three trim functions; no magic string buried in each body. |
| D-11 | No `contains` / `startsWith` / `endsWith` / `join` / `splitN`. | C++20 provides `starts_with` / `ends_with` natively; C++17 polyfills would become dead API on upgrade. `splitN` is deliberately omitted (YAGNI) -- callers needing first-delimiter-only split use a manual `find` + `substr`. |

---

## 12. Known Limitations

- **ASCII-only; no Unicode case folding.** `iequals`, `toLower`, `toUpper`, and the traits fold only `A`-`Z`/`a`-`z`; every byte `>= 0x80` is left untouched and compared verbatim. Correct for RFC-defined header/URI tokens; a SIP `From` display name with accented letters will not be case-folded. Using ICU or equivalent is out of scope by design.
- **`is_transparent` is inert under C++17.** Heterogeneous lookup on `std::unordered_map` / `std::unordered_set` is a C++20 feature (P0919R3). Iora builds as C++17, so `find` / `count` / `contains` with a `std::string_view` on a case-insensitive `unordered_map<std::string, ...>` still constructs a temporary `std::string` key; the advertised "no temporary" benefit does not materialize until a C++20 build. The markers are correct and harmless. No test exercises an actual heterogeneous lookup (only the typedef's existence).
- **`split` allocates its result vector.** The element views are zero-copy, but `std::vector<std::string_view>` is heap-allocated; a hot path over a fixed-shape line can avoid even that with a manual `find`/`substr` loop. There is no `splitN` (split with a maximum number of parts), so splitting on only the first delimiter (e.g. `Header: value:with:colons`) requires a manual `find` + `substr`.
- **`toLower` / `toUpper` always allocate.** No in-place variant (`toLowerInPlace(std::string&)`) is provided; a caller that already owns a `std::string` must still allocate a second one.
- **Lifetime obligation on every view.** `split`/`trim`/`trimLeft`/`trimRight` outputs alias the input buffer; outliving or mutating/reallocating the source dangles them (section 6). This is the intrinsic cost of the zero-copy design, not a bug.
- **Hash distribution not benchmarked.** `h = h * 31 + c` is adequate for short ASCII header names but has not been collision-tested for longer keys, and is explicitly non-cryptographic.

### Candidate defects (documentation-only; no code changed)

- **RESOLVED (dead includes removed, 2026-09-10).** `string_utils.hpp:10-12` previously included `<algorithm>`, `<cctype>`, and `<functional>`, none of which the implementation used: no `std::tolower`/`isspace` (`<cctype>`), no `std::transform`/`std::find` etc. (`<algorithm>`), no `std::hash`/`std::function` (`<functional>`). `<cctype>` in particular was a misleading vestige of an earlier `std::tolower`-based fold since replaced by the hand-rolled `toLowerChar`/`toUpperChar` (lines 203-214). All three were removed this session; only the genuinely-used `<string>`, `<string_view>` (line 14 -- always used, kept), and `<vector>` remain. (The earlier citation of a "line 14" dead include was wrong: line 14 is the pervasively-used `<string_view>`.)
- **CANDIDATE DEFECT (low -- latent intent gap on `is_transparent`).** The `is_transparent` markers (`string_utils.hpp:172,190`) encode an intent (heterogeneous lookup) that the C++17 build cannot honor for unordered containers (see the inert-marker limitation above). This is not a correctness bug -- the markers are well-formed and become effective under C++20 -- but the intended performance benefit is silently absent today, and no test would catch its absence. Reasoning: P0919R3 (heterogeneous lookup for unordered containers) is C++20; the project targets C++17 per the workspace build configuration. Flagged for visibility, not fixed.
