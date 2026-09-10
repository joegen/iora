# Iora errnoMessage -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-09-10 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/core/errno_utils.hpp` |
| **Namespace** | `iora::core` |
| **Dependencies** | `<cstring>`, `<string>` (standard library only -- no `iora/core` siblings, no third-party) |

This guide covers a single thread-safe helper: `iora::core::errnoMessage(int)`, which converts an `errno` value to its human-readable message string by wrapping `::strerror_r` correctly for both its GNU and XSI/POSIX variants. The function exists so that Iora code that wants the text of a failed syscall never reaches for the MT-Unsafe `std::strerror` / `strerror`.

**Document scope.** This guide uses the sanctioned lite variant of the Architecture & Programmer's Guide template (not all 12 sections): `errno_utils.hpp` is one stateless, reentrant free function with no class, no instance state, no configuration surface, no threading model beyond reentrancy, and no call flow -- so the class-oriented sections (System Architecture, Component Deep Dive, Call Flow, Configuration Reference) do not apply.

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-10 | Initial guide for `errno_utils.hpp` (`errnoMessage`). |

---

## Executive Summary

**Problem.** Code that reports a failed POSIX call wants the system's error text, but the obvious routes are unsafe. `std::strerror(errno)` and C `strerror(errno)` are documented **MT-Unsafe**: they return a pointer into a process-global static buffer, so two threads formatting two different errors at once race -- one can observe the other's message, or a half-overwritten buffer (`errno_utils.hpp:21-23`). The thread-safe replacement, `::strerror_r`, is itself a trap, because it comes in **two incompatible shapes** selected by feature-test macros, and using one shape's calling convention against the other silently misreads the result -- in the GNU case, reading the `buf` argument instead of the return value can run `strlen` off the end of an unterminated buffer and corrupt the heap (`errno_utils.hpp:24-28`).

**Solution.**
- `iora::core::errnoMessage(int errnoVal)` -- one `inline std::string` that returns the message for `errnoVal`, safely callable from any thread (`errno_utils.hpp:33`).
- It selects the correct `::strerror_r` convention at compile time, gated on `_GNU_SOURCE` (not merely `__GLIBC__`) and excluding Apple, so the helper is correct whether or not the GNU extension is in effect (`errno_utils.hpp:31-32`, `:36`).
- On the XSI path it never reads a possibly-unterminated buffer on failure: a non-zero return falls back to a deterministic `"Unknown error N"` string (`errno_utils.hpp:46-48`).

**Technical impact.** Header-only, standard-library-only, zero shared state -- any module can include it with no link dependency and call it concurrently without synchronization. A fixed 256-byte stack buffer means no heap allocation beyond the returned `std::string`.

---

## Deep Dive & Usage

### Why bare `strerror` / `std::strerror` is unsafe

`strerror(int)` and `std::strerror(int)` return a `char*` that points into a **single process-global static buffer** owned by the C library. The text is valid only until the next call. Two threads that each call `strerror` for a different `errno` race on that one buffer: the second call can overwrite the first thread's message before it has copied it, and an implementation that formats an "Unknown error N" string into the shared buffer can even be observed mid-write. There is no lock a caller can take to make this safe -- the buffer is not exposed. This is why POSIX marks `strerror` MT-Unsafe and provides `strerror_r` (the `_r` = reentrant) as the thread-safe alternative (`errno_utils.hpp:21-23`).

### The `strerror_r` GNU-vs-XSI mechanism

`::strerror_r` has two mutually incompatible signatures, and which one the compiler sees is decided by feature-test macros when `<string.h>` / `<cstring>` is included:

| Variant | When active | Signature | Where the message is |
|---|---|---|---|
| **GNU** | glibc **with** `_GNU_SOURCE` defined | `char *strerror_r(int, char *buf, size_t)` | the **return value** (may be a static string, may be `buf`) |
| **XSI / POSIX** | macOS, or glibc **without** `_GNU_SOURCE` | `int strerror_r(int, char *buf, size_t)` | always written into **`buf`**; return is `0` on success |

`errnoMessage` branches on exactly this distinction (`errno_utils.hpp:36`):

```cpp
char buf[256] = {0};
#if defined(__GLIBC__) && defined(_GNU_SOURCE) && !defined(__APPLE__)
  // GNU variant: char* return is the message (may be static, may be buf).
  return std::string(::strerror_r(errnoVal, buf, sizeof(buf)));
#else
  // XSI variant: int return, message written into buf.
  const int rc = ::strerror_r(errnoVal, buf, sizeof(buf));
  if (rc == 0)
  {
    return std::string(buf);
  }
  return "Unknown error " + std::to_string(errnoVal);
#endif
```

The two correctness points the code encodes:

1. **GNU path -- take the return value, never `buf`.** The GNU `strerror_r` may leave `buf` entirely untouched and return a pointer to a static string instead. An untouched buffer is not guaranteed NUL-terminated, so `std::string(buf)` would run `strlen` past the end and corrupt the heap. Constructing the `std::string` from the **return value** is the only correct read (`errno_utils.hpp:24-28`, `:38`).

2. **XSI path -- do not trust `buf` on failure.** The XSI variant returns `0` on success (message in `buf`) and a non-zero error code (e.g. `EINVAL` for an unknown errno, `ERANGE` if the buffer were too small) otherwise. On a non-zero return the helper deliberately ignores `buf` -- which may hold a truncated, possibly-unterminated message -- and returns a deterministic synthesized string instead (`errno_utils.hpp:40-48`).

The gate is on `_GNU_SOURCE`, **not** merely `__GLIBC__`, because glibc supplies the XSI signature when `_GNU_SOURCE` is absent even though `__GLIBC__` is still defined; gating on the library alone would pick the wrong convention (`errno_utils.hpp:31-32`). `__APPLE__` is excluded so macOS (always XSI) takes the XSI branch (`errno_utils.hpp:36`).

### Usage

The example compiles against the real API. `errnoMessage` is the only symbol.

**Report a failed syscall with its error text.**

```cpp
#include "iora/core/errno_utils.hpp"

#include <cerrno>
#include <fcntl.h>
#include <string>

std::string openForRead(const char *path)
{
  const int fd = ::open(path, O_RDONLY);
  if (fd < 0)
  {
    // Capture errno immediately -- any later call may clobber it.
    const int err = errno;
    return "open failed: " + iora::core::errnoMessage(err);
  }
  ::close(fd);
  return "ok";
}
```

**Anti-patterns.**
- Do NOT use `std::strerror(errno)` or `strerror(errno)` in multi-threaded code -- they share a process-global static buffer and race; that is exactly what `errnoMessage` replaces (`errno_utils.hpp:21-23`).
- Do NOT read the `buf` argument of a GNU `strerror_r` directly -- it may be untouched and unterminated; always take the `char*` return value (`errno_utils.hpp:24-28`).
- Do NOT pass a live `errno` expression that another call might clobber between evaluations -- snapshot it into a local `int` at the failure site, then pass that to `errnoMessage`.
- Do NOT assume `errnoMessage` reflects the *current* `errno`; it translates the integer you pass in, nothing more.

---

## Thread Safety Model

**Reentrant, no shared state.** `errnoMessage` takes its input by value (`int errnoVal`), writes only into a function-local `char buf[256]` stack array, and returns a freshly constructed `std::string`. It holds no mutex and touches no global or static mutable state. It may be called concurrently from any number of threads with no synchronization.

The entire reason the function exists is thread safety: it wraps `::strerror_r` (the reentrant POSIX call) precisely so callers never touch the MT-Unsafe `std::strerror` / `strerror`, which return a pointer into a single process-global buffer that concurrent callers race on. The GNU-vs-XSI branch is resolved at compile time (`_GNU_SOURCE` gating), so there is no runtime dispatch and no per-call state to protect.

---

## API Reference

A single `inline` free function in `iora::core`.

```cpp
namespace iora
{
namespace core
{

/// Convert an errno value to its message string, thread-safely.
/// Wraps ::strerror_r for both the GNU and XSI/POSIX variants (gated on
/// _GNU_SOURCE). On the XSI path, a non-zero return yields a deterministic
/// "Unknown error N" rather than reading a possibly-unterminated buffer.
inline std::string errnoMessage(int errnoVal);

} // namespace core
} // namespace iora
```

| Function | Signature | Returns |
|---|---|---|
| `errnoMessage` | `std::string(int errnoVal)` | The system message for `errnoVal`; on the XSI path, `"Unknown error N"` when `strerror_r` reports failure |

---

## Design Decisions

| Decision | Rationale |
|---|---|
| Wrap `::strerror_r`, never `std::strerror` | `std::strerror` / `strerror` are MT-Unsafe (shared process-global buffer); `strerror_r` is the reentrant POSIX replacement (`errno_utils.hpp:21-23`). |
| Gate on `_GNU_SOURCE`, not `__GLIBC__` | glibc supplies the XSI signature when `_GNU_SOURCE` is absent even though `__GLIBC__` is still defined; gating on the library alone picks the wrong calling convention (`errno_utils.hpp:31-32`). |
| Exclude `__APPLE__` from the GNU branch | macOS always provides the XSI variant; the `!defined(__APPLE__)` guard routes it correctly (`errno_utils.hpp:36`). |
| GNU path returns `std::string(returnValue)`, not `std::string(buf)` | GNU `strerror_r` may leave `buf` untouched and unterminated and return a static string; reading `buf` could run `strlen` off the end and corrupt the heap (`errno_utils.hpp:24-28`, `:38`). |
| XSI path falls back to a synthesized string on non-zero return | On failure `buf` may hold a truncated, possibly-unterminated message; a deterministic `"Unknown error N"` avoids reading it (`errno_utils.hpp:46-48`). |
| Fixed 256-byte stack buffer | Ample for any system error message; avoids heap allocation and keeps the function allocation-free apart from the returned `std::string`. |
| Header-only `inline`, standard-library-only | Any module can include it with no link dependency and no `iora/core` sibling dependency (`errno_utils.hpp:13-14`). |

---

## Known Limitations

- **Input is the errno integer, not the live `errno`.** `errnoMessage` translates the value you pass; it does not read `errno` itself. Callers must snapshot `errno` at the failure site before any intervening call can clobber it.
- **XSI-path unknown-errno text differs from libc.** On the XSI branch an unknown errno makes `strerror_r` return a non-zero code, so the helper returns its own `"Unknown error N"` string rather than whatever text the C library would have written into `buf` (e.g. a localized "Unknown error nnn"). The GNU branch returns the library's own string for the same input. The distinction is cosmetic but means the exact text for an invalid errno is platform-dependent (`errno_utils.hpp:46-48`).
- **XSI path discards any truncated message on `ERANGE`.** If `strerror_r` ever returned `ERANGE` (buffer too small), the helper returns `"Unknown error N"` and drops the partial text in `buf`. With a 256-byte buffer this is not reachable for real system messages, but the behavior is to discard rather than surface a truncated string (`errno_utils.hpp:46-47`).
- **No dedicated unit-test file.** There is no `tests/core/iora_test_errno_utils.cpp`; the helper is currently exercised only indirectly wherever callers format errno-based diagnostics. A standalone suite asserting both branch outcomes (a known errno such as `EACCES`, and an out-of-range errno driving the XSI fallback) would lock the behavior down.
- **CANDIDATE DEFECT -- latent ODR hazard from a macro-dependent `inline` body (`errno_utils.hpp:33-50`).** `errnoMessage` is an `inline` function in a header, but its compiled body depends on `_GNU_SOURCE` (and `__GLIBC__` / `__APPLE__`) **at each translation unit's point of inclusion**. If one TU includes this header with `_GNU_SOURCE` defined (GNU branch: `return std::string(::strerror_r(...))`) and another TU includes it without (XSI branch: the `int`-return path), the two TUs emit **different definitions of the same `inline` function** -- an ODR violation whose result is unspecified (the linker keeps one arbitrary definition). Reasoning: `_GNU_SOURCE` also changes the declared signature of `::strerror_r`, so the mismatch is not merely cosmetic -- the surviving definition may call the wrong convention for the other TU's expectations. In practice `_GNU_SOURCE` is defined uniformly across a build (glibc's own headers often define it transitively), which is why this is latent rather than active; but the header does not itself `#define _GNU_SOURCE`, so it relies on every includer agreeing. A robust fix (not applied here -- code is not edited in this doc task) would move the body into a single `.cpp` with one fixed convention, or assert a consistent feature-test state. **Tracked as backlog `2026-09-10-26`** (iora), disposition: fix via its own targeted review loop.
