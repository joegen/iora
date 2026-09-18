# Iora UTF-8 Encoding \& Hex-Digit Primitives -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-09-18 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/util/unicode.hpp` |
| **Namespace** | `iora::util` |
| **Dependencies** | `<cstdint>`, `<string>` (standard library only -- no `iora/core`, no third-party) |

This guide covers `iora/util/unicode.hpp`, the two smallest primitives Iora's text-format parsers share for turning an escaped numeric character reference into real UTF-8 bytes: `appendUtf8` (the UTF-8 encoder) and `hexDigitValue` (the single-hex-digit decoder). They are the shared building blocks behind JSON `\uXXXX` escape decoding (`include/iora/parsers/json.hpp:1343`, `:1444`) and XML numeric character reference decoding (`&#NNNN;` / `&#xHHHH;`, `include/iora/parsers/xml.hpp:912`, `:942`), and are also used directly by the HTML percent-decoding helper (`include/iora/parsers/html_escape.hpp:72`).

**Document scope.** This guide uses the sanctioned lite variant of the Architecture & Programmer's Guide template (not all 12 sections): `unicode.hpp` is two stateless pure functions -- there is no class, no instance state, no configuration surface, no threading model beyond reentrancy, and no call flow -- so the class-oriented sections (System Architecture, Configuration Reference, Call Flow) do not apply.

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-18 | Initial guide for `unicode.hpp` (`appendUtf8`, `hexDigitValue`). |

---

## Executive Summary

**Problem.** More than one Iora text-format parser needs to turn a numeric escape (JSON's `\uXXXX`, XML's `&#NNNN;` / `&#xHHHH;`, or an HTML percent-decoded hex byte) into UTF-8 bytes appended to an in-progress output string, and each of those escapes is built from one or more ASCII hex digits that must first be decoded to a nibble value. Doing the UTF-8 byte-packing arithmetic and the hex-digit decoding independently in each parser risks each one handling the UTF-16 surrogate range or the `U+10FFFF` ceiling differently (or not at all). `unicode.hpp` gives all of them one shared, tested implementation (`unicode.hpp:17-76`).

**Solution.**
- `iora::util::appendUtf8(std::string &out, std::uint32_t cp) -> bool` -- encodes a Unicode code point as a 1-to-4-byte UTF-8 sequence appended to `out`; rejects the UTF-16 surrogate halves (`U+D800..U+DFFF`) and any value above `U+10FFFF`, returning `false` and leaving `out` unchanged in those cases (`unicode.hpp:23-52`).
- `iora::util::hexDigitValue(char c, std::uint32_t &out) -> bool` -- decodes one ASCII hex digit (`0-9`, `a-f`, `A-F`) into its `0..15` value in `out`, returning `false` (and leaving `out` unchanged) for any other character (`unicode.hpp:57-76`).

**Technical impact.** Both functions are allocation-free beyond `std::string::push_back`'s amortized growth on `out`; there is no heap allocation, no locale dependency, and no exception path -- both report failure via a `bool` return.

---

## Deep Dive & Usage

### Behavior, verified against source

| Function | Behavior | Source (file:line) |
|---|---|---|
| `appendUtf8` | `cp <= 0x7F` -> 1 byte; `cp <= 0x7FF` -> 2 bytes; `cp <= 0xFFFF` -> 3 bytes; else -> 4 bytes. Standard UTF-8 bit-packing (leading-byte marker bits `0xC0`/`0xE0`/`0xF0`, continuation bytes `0x80 | (cp >> shift) & 0x3F`). | branch ladder, `unicode.hpp:29-50` |
| `appendUtf8` | Rejects `0xD800 <= cp <= 0xDFFF` (the UTF-16 surrogate-half range, which is not a valid Unicode scalar value) and any `cp > 0x10FFFF` (above the Unicode range); returns `false` and does not touch `out` in either case. | guard clause, `unicode.hpp:25-28` |
| `appendUtf8` | On acceptance, returns `true` after appending; `out` is only ever appended to (via `push_back`), never cleared or reallocated from scratch. | `unicode.hpp:23-52` |
| `hexDigitValue` | `'0'-'9'` -> `c - '0'`; `'a'-'f'` -> `c - 'a' + 10`; `'A'-'F'` -> `c - 'A' + 10`; any other `char` -> returns `false`, `out` untouched. | `unicode.hpp:59-75` |

Both functions report failure exclusively via their `bool` return value; neither throws, and neither has a "partial success" state -- `out` is either updated exactly as documented, or left completely unchanged.

### `appendUtf8`'s validity guard

The rejection test is a single compound condition (`unicode.hpp:25`): `(cp >= 0xD800u && cp <= 0xDFFFu) || cp > 0x10FFFFu`. This means `appendUtf8` treats a code point as valid Unicode-scalar-value input, matching the definition used by RFC 3629 (UTF-8) and the Unicode standard's exclusion of surrogate code points from UTF-8 encoding -- a caller cannot use `appendUtf8` to smuggle an unpaired UTF-16 surrogate half into a UTF-8 stream. It is the caller's responsibility to have already combined a UTF-16 surrogate pair (as JSON's `\uD800`-`\uDBFF` followed by `\uDC00`-`\uDFFF` escape sequence requires) into one supplementary-plane code point *before* calling `appendUtf8`; the function itself performs no surrogate-pair combination.

`cp == 0` is accepted and encodes as a single NUL byte (`0x00`) appended to `out` -- `std::string` permits embedded NUL bytes, so this is not itself an error, though a caller building a C-string-consuming value from the result must be aware the string may contain an embedded NUL.

### `hexDigitValue`'s decode-then-combine pattern

`hexDigitValue` decodes exactly one hex digit; callers combine several calls to build a multi-digit value (e.g. four calls to decode a `\uXXXX` JSON escape, or one/two calls for an XML `&#xH;`/`&#xHH;` reference). Neither the number of digits nor their combination into a code point is `hexDigitValue`'s concern -- that logic lives in each consumer:
- `include/iora/parsers/json.hpp:1343` decodes the four hex digits of a `\uXXXX` escape.
- `include/iora/parsers/xml.hpp:912` decodes the hex digits of an `&#xHHHH;` numeric character reference.
- `include/iora/parsers/html_escape.hpp:72` decodes the two hex digits of a percent-encoded (`%HH`) byte.

### Usage

The examples compile against the real API.

**1. Encode a Basic Multilingual Plane code point.**

```cpp
#include "iora/util/unicode.hpp"

#include <string>

std::string encodeCodePoint(std::uint32_t cp)
{
  std::string out;
  if (!iora::util::appendUtf8(out, cp))
  {
    return {};
  }
  return out;
}
```

**2. Combine a UTF-16 surrogate pair into a supplementary-plane code point before encoding it.**

```cpp
#include "iora/util/unicode.hpp"

#include <cstdint>
#include <string>

bool appendSurrogatePair(std::string &out, std::uint32_t high, std::uint32_t low)
{
  // Caller must combine the pair first: appendUtf8 rejects lone surrogates.
  const std::uint32_t cp =
    0x10000u + ((high - 0xD800u) << 10) + (low - 0xDC00u);
  return iora::util::appendUtf8(out, cp);
}
```

**3. Decode two hex digits into a byte value (the percent-decoding pattern).**

```cpp
#include "iora/util/unicode.hpp"

#include <cstdint>

bool decodeHexByte(char hi, char lo, std::uint8_t &byteOut)
{
  std::uint32_t hiVal = 0;
  std::uint32_t loVal = 0;
  if (!iora::util::hexDigitValue(hi, hiVal) || !iora::util::hexDigitValue(lo, loVal))
  {
    return false;
  }
  byteOut = static_cast<std::uint8_t>((hiVal << 4) | loVal);
  return true;
}
```

**4. Rejected inputs -- what callers must not "optimize" away.**

```cpp
#include "iora/util/unicode.hpp"

#include <string>

void rejectedCases()
{
  std::string out;
  const bool a = iora::util::appendUtf8(out, 0xD800u);   // false -- lone high surrogate
  const bool b = iora::util::appendUtf8(out, 0x110000u); // false -- above U+10FFFF
  std::uint32_t v = 0;
  const bool c = iora::util::hexDigitValue('g', v);       // false -- not a hex digit
  // out is untouched by all three; a, b, c are all false.
}
```

**Anti-patterns.**
- Do NOT pass a raw UTF-16 code unit from a `\uXXXX` JSON escape to `appendUtf8` without first checking for and combining a surrogate pair -- a lone surrogate half is rejected (`unicode.hpp:25`), and silently skipping the character (rather than erroring) hides a malformed escape sequence from the caller.
- Do NOT assume `appendUtf8` clears or resets `out` on failure -- it never touches `out` at all when it returns `false`; it also never clears prior content on success, since it appends.
- Do NOT call `hexDigitValue` expecting it to decode more than one character -- it decodes exactly one ASCII hex digit per call; multi-digit combination is the caller's responsibility.
- Do NOT treat `hexDigitValue`'s `false` return as "digit value 0" -- `out` is left unchanged on failure, so a caller that ignores the return value and reads `out` anyway will silently reuse a stale or default-initialized value.
- Do NOT reimplement UTF-8 byte-packing or surrogate-range rejection inline in a new parser -- `appendUtf8` is the single shared home for this logic across Iora's JSON, XML, and HTML-escape parsers.

---

## Thread Safety Model

**Reentrant, no shared state.** Both functions are free `inline` functions operating only on their arguments (`out` by reference, plus value parameters) and stack locals; there is no global or static mutable state, no I/O, and no shared resource. `appendUtf8` and `hexDigitValue` are safe to call concurrently from any number of threads, provided each call's `out` / `out` reference argument is not itself shared (unsynchronized) with another thread's concurrent read or write of the same object -- the functions perform no synchronization of their own on the referenced output parameters.

---

## API Reference

Both symbols are `inline` free functions in `iora::util`.

```cpp
namespace iora
{
namespace util
{

/// Append a Unicode code point to out encoded as UTF-8.
/// Encodes cp as a 1- to 4-byte UTF-8 sequence. Rejects the UTF-16 surrogate
/// halves (U+D800..U+DFFF) and any value above U+10FFFF, returning false and
/// leaving out unchanged in those cases.
inline bool appendUtf8(std::string &out, std::uint32_t cp);

/// Decode a single ASCII hex digit into its 0..15 value.
/// Returns false if c is not one of [0-9A-Fa-f], leaving out unchanged.
inline bool hexDigitValue(char c, std::uint32_t &out);

} // namespace util
} // namespace iora
```

| Function | Signature | Returns |
|---|---|---|
| `appendUtf8` | `bool(std::string &out, std::uint32_t cp)` | `true` if `cp` was valid and appended; `false` if `cp` is a surrogate half or `> U+10FFFF` (`out` unchanged) |
| `hexDigitValue` | `bool(char c, std::uint32_t &out)` | `true` and `out` set to `0..15` if `c` is a hex digit; `false` (`out` unchanged) otherwise |

---

## Design Decisions

| Decision | Rationale |
|---|---|
| One shared `appendUtf8`, not a per-parser encoder | JSON `\uXXXX`, XML numeric character references, and any future escape-decoding parser must agree on UTF-8 byte-packing and surrogate rejection; a single implementation removes the risk of divergence (`json.hpp:1444`, `xml.hpp:942`). |
| Reject surrogate halves and `> U+10FFFF` inside the encoder itself | Keeps the validity check co-located with the encoding it protects, so no caller can bypass it by calling `appendUtf8` directly (`unicode.hpp:25-28`). |
| `bool` return + unchanged-output-on-failure, not an exception | Matches the allocation-free, exception-free style of the surrounding parser headers, and lets a caller in a tight decode loop check the result inline without a `try`/`catch` (`unicode.hpp:23`, `:57`). |
| `hexDigitValue` decodes exactly one digit, no width/combination logic | Keeps the primitive minimal; each consumer (JSON 4-digit `\uXXXX`, XML variable-width `&#xH...H;`, HTML fixed 2-digit `%HH`) has different digit-count and combination rules, so baking one into the shared primitive would not fit all three (`json.hpp:1343`, `xml.hpp:912`, `html_escape.hpp:72`). |

---

## Known Limitations

- **No surrogate-pair combination helper.** `appendUtf8` rejects lone surrogate halves but provides no shared function to combine a valid high/low pair into a supplementary-plane code point; each consumer (currently `json.hpp`) implements that arithmetic itself. A second, independent implementation of the surrogate-pair-combination formula would not be caught by anything in this header.
- **No decode direction (UTF-8 to code point).** `unicode.hpp` only encodes (`appendUtf8`); there is no companion UTF-8-decoding function in this header for a caller that needs to walk existing UTF-8 bytes back into code points.
- **`hexDigitValue` is ASCII-only by design.** It recognizes only `0-9`, `a-f`, `A-F`; there is no wide-character or locale-aware variant, which is correct for the ASCII-only hex-digit grammars of JSON/XML/HTML escapes but would not generalize to other input.
- **No dedicated unit-test file.** There is no standalone `tests/util/iora_test_unicode.cpp` (or similarly named) exercising `appendUtf8` / `hexDigitValue` directly in isolation; they are currently exercised only indirectly through their consumers' own test suites (e.g. `tests/parsers/iora_test_xml_parser.cpp` for the XML numeric-character-reference path), with no test asserting `unicode.hpp`'s boundary behavior (surrogate rejection, `U+10FFFF` ceiling, non-hex-digit rejection) against the primitives directly.
