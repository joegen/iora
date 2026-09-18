# Iora Filesystem Helpers -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.1 |
| **Date** | 2026-09-18 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/util/filesystem.hpp` |
| **Namespace** | `iora::util` |
| **Dependencies** | `<cstddef>` (`std::size_t` for `readlinkGrow`'s buffer sizing), `<filesystem>`, `<string>`, `<system_error>` (`std::error_code` for the non-throwing `remove`/`is_regular_file` overloads), `<unistd.h>` (POSIX `::readlink` -- Linux-specific), `<vector>` (standard library only -- no `iora/core`, no third-party) |

This guide covers `iora/util/filesystem.hpp`, a small set of free functions used to locate the running executable's own directory and to clean up test-generated files. The dominant real-world caller is Iora's own test suite: plugin-loading tests resolve `.so` paths next to the test binary via `getExecutableDir()` (`tests/service/iora_test_plugin.cpp:26`, `tests/simple_chained_test.cpp:11-13`, and a dozen others), and logger/service tests scrub generated log and state files between cases via `removeFilesMatchingPrefix` / `removeFilesContainingAny` (`tests/core/iora_test_logger.cpp`, `tests/service/iora_test_iora_service.cpp`). A dedicated test file, `tests/util/iora_test_filesystem.cpp`, exercises all five public functions directly, plus the internal `filesystem_detail::readlinkGrow` grow-and-retry path.

**Document scope.** This guide uses the sanctioned lite variant of the Architecture & Programmer's Guide template (not all 12 sections): `filesystem.hpp` is a small set of stateless, non-member functions over `std::string` and `std::filesystem::path` -- there is no class, no instance state, no configuration surface, no threading model beyond reentrancy, and no call flow -- so the class-oriented sections (System Architecture, Configuration Reference, Call Flow) do not apply.

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.1 | 2026-09-18 | Re-synced against fixed `filesystem.hpp`: `removeFilesMatchingPrefix` is now an anchored filename-prefix match (was unanchored substring on the full path); both removal helpers now match on filename only, collect-then-delete, skip non-regular files, and use the non-throwing `remove` overload via the new `filesystem_detail` helpers; `getExecutablePath` is now truncation-safe via `readlinkGrow`. Removed the now-fixed limitations; added a note on the new dedicated test file. |
| 1.0 | 2026-09-18 | Initial guide for `filesystem.hpp` (`getExecutablePath`, `getExecutableDir`, `resolveRelativePath`, `removeFilesMatchingPrefix`, `removeFilesContainingAny`). |

---

## Executive Summary

**Problem.** A plugin-loading test or a service that ships a `.so` alongside its own binary needs to find "the directory I was launched from" without the caller hardcoding a build-tree-relative path. Separately, a fixture-based test suite that writes log/state files into its working directory needs a way to sweep those files out between test cases without every test file hand-rolling its own `std::filesystem::directory_iterator` loop. `filesystem.hpp` centralizes both needs as five small free functions built on two shared `filesystem_detail` helpers (`filesystem.hpp:21-154`).

**Solution.**
- `iora::util::getExecutablePath()` -- resolves the absolute path of the running executable via the Linux `/proc/self/exe` symlink, delegating to the truncation-safe `filesystem_detail::readlinkGrow` (`filesystem.hpp:102-105`; helper at `:32-53`).
- `iora::util::getExecutableDir()` -- the parent directory of `getExecutablePath()` (`filesystem.hpp:108-116`).
- `iora::util::resolveRelativePath(base_absolute_path, relative_path)` -- joins and normalizes a relative path against an absolute base using `std::filesystem::weakly_canonical` (`filesystem.hpp:119-126`).
- `iora::util::removeFilesMatchingPrefix(prefix)` -- removes regular files in the current working directory whose FILENAME begins with `prefix` (anchored prefix match) (`filesystem.hpp:130-135`).
- `iora::util::removeFilesContainingAny(fragments)` -- removes regular files in the current working directory whose FILENAME contains any of `fragments` as a substring (`filesystem.hpp:139-154`).

**Technical impact.** Header-only, standard-library-plus-POSIX, no allocation beyond the strings/paths the standard library itself allocates. `getExecutablePath` is the only Linux-specific function in the header (it reads `/proc/self/exe`); the remaining four are portable `std::filesystem` code. The two removal functions share collect-then-delete scaffolding (`filesystem_detail::collectMatchingCwdFiles` and `filesystem_detail::removeRegularFilesQuiet`, `filesystem.hpp:63-97`): neither ever mutates the directory while `directory_iterator` is walking it, neither deletes a matched non-regular-file entry, and neither can throw past a concurrently-vanished or permission-denied entry.

---

## Deep Dive & Usage

### Behavior, verified against source

| Function | Behavior | Source (file:line) |
|---|---|---|
| `getExecutablePath` | Delegates to `filesystem_detail::readlinkGrow("/proc/self/exe")`: reads the symlink into a growable buffer (starting at 4096 bytes), doubling and retrying whenever the returned length equals the current buffer size (a possible truncation), up to a 1 MiB ceiling; returns `{}` on `::readlink` failure or past the ceiling. | `filesystem.hpp:102-105`; `readlinkGrow` at `:32-53` |
| `getExecutableDir` | Calls `getExecutablePath()`; if non-empty, returns `std::filesystem::path(exePath).parent_path().string()`; otherwise returns `{}`. | `filesystem.hpp:108-116` |
| `resolveRelativePath` | Returns `std::filesystem::weakly_canonical(std::filesystem::path(base_absolute_path) / relative_path).string()` -- joins with `operator/`, then lexically/existence-aware normalizes (`weakly_canonical` does not require the full result to exist). | `filesystem.hpp:119-126` |
| `removeFilesMatchingPrefix` | Collects current-working-directory entries (via `filesystem_detail::collectMatchingCwdFiles`, which walks `directory_iterator(".")` -- top level only, no recursion) whose **filename** begins with `prefix` (`name.rfind(prefix, 0) == 0` -- an anchored prefix test, not substring containment), then deletes the collected regular files after the scan completes (via `filesystem_detail::removeRegularFilesQuiet`). | `filesystem.hpp:130-135`; helpers at `:63-73`, `:78-97` |
| `removeFilesContainingAny` | Same collect-then-delete scaffolding; an entry matches if its **filename** contains any of `fragments` as a substring (`std::string::find`). | `filesystem.hpp:139-154`; helpers at `:63-73`, `:78-97` |

### The `/proc/self/exe` dependency

`getExecutablePath` (and therefore `getExecutableDir`) is Linux-specific: it depends on the Linux-only `/proc/self/exe` symlink exposed by procfs (`filesystem.hpp:13` includes `<unistd.h>` for `::readlink`; the path string `"/proc/self/exe"` is hardcoded at the `getExecutablePath` call site, `:104`). This works under any Linux kernel with `/proc` mounted (the normal case, including inside containers), but the function has no fallback for a system where `/proc` is unavailable, and no `#ifdef` guard for a non-Linux build -- on such a platform `::readlink("/proc/self/exe", ...)` simply fails at runtime and the function returns `{}` (it does not fail to compile, since `::readlink` itself is POSIX and exists on other POSIX systems too, but the specific path only resolves on Linux).

`readlinkGrow` (`filesystem.hpp:32-53`) is truncation-safe. `::readlink` does not report truncation via a distinguishing return value and never NUL-terminates its result, so a returned length equal to the current buffer size is treated as "possibly truncated": the buffer is doubled and the read retried, up to a 1 MiB ceiling (`buf.size() >= std::size_t{1} << 20`, `:47`), past which the function gives up and returns `{}` rather than looping unbounded. A length strictly less than the buffer size is trusted as complete and returned as `std::string(buf.data(), len)` (`:42-45`). `readlinkGrow` takes the target path as a parameter rather than hardcoding `/proc/self/exe` itself, so the growth path is independently unit-testable against an arbitrary long-target symlink (`tests/util/iora_test_filesystem.cpp` exercises this directly with a 5000-byte symlink target).

### `resolveRelativePath` and absolute `relative_path` inputs

`resolveRelativePath` joins with `std::filesystem::path::operator/`. Per `std::filesystem::path` composition rules, if `relative_path` is itself an absolute path, `operator/` **discards `base_absolute_path` entirely** and the result is `relative_path` alone -- this was confirmed by compiling a standalone test: `std::filesystem::path("/base/dir") / "/abs/other"` yields `/abs/other`, not `/base/dir/abs/other`. The function name and its one caller-facing parameter name (`relative_path`) suggest the input is always relative; nothing in `resolveRelativePath` validates that assumption or rejects an absolute `relative_path`.

### `removeFilesMatchingPrefix` / `removeFilesContainingAny` scope

Both functions:
- Operate **only** on the process's current working directory (the literal string `"."` passed to `directory_iterator` inside `filesystem_detail::collectMatchingCwdFiles`, `filesystem.hpp:87`) -- not a caller-supplied directory, and not recursively into subdirectories.
- Match against the entry's **filename only** (`it->path().filename().string()`, `filesystem.hpp:91`), not the full path string. `removeFilesMatchingPrefix` uses an anchored prefix test (`name.rfind(prefix, 0) == 0`, `filesystem.hpp:134`): the fragment must be a leading prefix of the filename, so `removeFilesMatchingPrefix("log")` does **not** delete `mydeploylog.txt` (`"log"` is a substring but not a leading prefix). `removeFilesContainingAny` uses unanchored substring containment (`std::string::find`, `filesystem.hpp:147`) against the filename, by design -- its name says "containing".
- Collect all matches first, then delete after the directory scan completes (`filesystem_detail::collectMatchingCwdFiles` returns a `std::vector<std::filesystem::path>` that `filesystem_detail::removeRegularFilesQuiet` iterates in a separate pass, `filesystem.hpp:63-73`, `:78-97`) -- neither function ever deletes an entry while `directory_iterator` is still walking the directory.
- Skip any matched entry that is not a regular file: `removeRegularFilesQuiet` guards each removal with `std::filesystem::is_regular_file(p, ec)` (`filesystem.hpp:68`), so a matched directory is left untouched rather than passed to `std::filesystem::remove`, which would throw `std::filesystem::filesystem_error` on a non-empty directory.
- Use the `error_code` (non-throwing) overload of `std::filesystem::remove` (`filesystem.hpp:70`), so a concurrently-vanished or permission-denied entry is silently skipped rather than propagating an exception to the caller.

### Usage

The examples compile against the real API.

**1. Locate a plugin shipped next to the executable (the dominant real usage).**

```cpp
#include "iora/util/filesystem.hpp"

#include <string>

std::string pluginPath(const std::string &name)
{
  return iora::util::getExecutableDir() + "/plugins/" + name;
}
```

**2. Resolve a config path relative to a known absolute base.**

```cpp
#include "iora/util/filesystem.hpp"

#include <string>

std::string configFile(const std::string &installRoot)
{
  // installRoot must be absolute; "config/app.toml" is joined and normalized.
  return iora::util::resolveRelativePath(installRoot, "config/app.toml");
}
```

**3. Sweep test-generated log files between Catch2 test cases.**

```cpp
#include "iora/util/filesystem.hpp"

void cleanupTestLogs()
{
  // Removes every top-level regular file in the CWD whose name STARTS WITH
  // "testlog." (anchored prefix match).
  iora::util::removeFilesMatchingPrefix("testlog.");
}
```

**4. Remove several distinct generated artifacts by fragment.**

```cpp
#include "iora/util/filesystem.hpp"
#include <vector>
#include <string>

void cleanupServiceArtifacts()
{
  iora::util::removeFilesContainingAny(
    std::vector<std::string>{"ioraservice_basic_log", "ioraservice_basic_state.json"});
}
```

**Anti-patterns.**
- Do NOT expect `removeFilesMatchingPrefix` to match a fragment appearing anywhere in a filename -- it is an anchored prefix test (`name.rfind(prefix, 0) == 0`, `filesystem.hpp:134`); use `removeFilesContainingAny` when substring matching is what you want.
- Do NOT expect either removal function to affect anything outside the current working directory, or anything in a subdirectory of it -- both use a single, non-recursive `directory_iterator(".")` pass (`filesystem.hpp:87`).
- Do NOT rely on `getExecutablePath()` / `getExecutableDir()` on a non-Linux target -- they read the Linux-only `/proc/self/exe` symlink and simply return `{}` when it cannot be resolved.
- Do NOT pass an absolute path as `resolveRelativePath`'s `relative_path` argument expecting it to be joined under `base_absolute_path` -- `std::filesystem::path::operator/` discards the base entirely in that case.

---

## Thread Safety Model

**Reentrant, no shared state -- with one caveat.** Every function in `filesystem.hpp` is a free `inline` function with no global or static mutable state. `getExecutablePath`, `getExecutableDir`, and `resolveRelativePath` are pure reads (of `/proc/self/exe` or of their arguments) and are safe to call concurrently from any number of threads. `removeFilesMatchingPrefix` and `removeFilesContainingAny` read and mutate the filesystem state of the process-wide current working directory (`"."`); calling either concurrently with another thread that changes the current working directory (`chdir`) is still a race at the filesystem level -- the collect pass and the delete pass may run against a working directory another thread renames or replaces from underneath. Two concurrent calls to the removal functions themselves are less hazardous than a naive implementation: each uses the non-throwing `error_code` overload of `std::filesystem::remove` inside `filesystem_detail::removeRegularFilesQuiet` (`filesystem.hpp:70`), so a file already removed by one call before the other reaches it is silently skipped rather than throwing -- but the two directory scans can still race to observe an inconsistent listing. Iora's own test suite avoids this by never running these two functions concurrently against a shared CWD.

---

## API Reference

All symbols are `inline` free functions in `iora::util`.

```cpp
namespace iora
{
namespace util
{

/// Get the path to the currently running executable.
/// Reads /proc/self/exe (Linux-specific) via a truncation-safe grow-and-retry
/// readlink. Returns "" on failure.
inline std::string getExecutablePath();

/// Get the directory of the currently running executable.
/// Returns "" if getExecutablePath() failed.
inline std::string getExecutableDir();

/// Resolve a relative path against an absolute base path.
/// Joins with operator/ then normalizes via weakly_canonical.
inline std::string resolveRelativePath(const std::string &base_absolute_path,
                                        const std::string &relative_path);

/// Remove regular files in the current directory whose FILENAME begins with
/// the given prefix (anchored prefix match, not substring containment).
inline void removeFilesMatchingPrefix(const std::string &prefix);

/// Remove regular files in the current directory whose FILENAME contains
/// any of the given fragments (substring match).
inline void removeFilesContainingAny(const std::vector<std::string> &fragments);

} // namespace util
} // namespace iora
```

| Function | Signature | Returns |
|---|---|---|
| `getExecutablePath` | `std::string()` | Absolute executable path, or `""` on failure |
| `getExecutableDir` | `std::string()` | Parent directory of the executable path, or `""` |
| `resolveRelativePath` | `std::string(const std::string &base_absolute_path, const std::string &relative_path)` | Joined and normalized path string |
| `removeFilesMatchingPrefix` | `void(const std::string &prefix)` | none (removes matching regular files in `"."`) |
| `removeFilesContainingAny` | `void(const std::vector<std::string> &fragments)` | none (removes matching regular files in `"."`) |

---

## Design Decisions

| Decision | Rationale |
|---|---|
| `/proc/self/exe` via `::readlink` (through `readlinkGrow`), not `argv[0]` | `argv[0]` can be a relative path, a bare name found via `PATH`, or forged by the caller; `/proc/self/exe` is the kernel's own resolved, absolute path to the running binary (`filesystem.hpp:104`; `::readlink` call inside `readlinkGrow` at `:37`). |
| `getExecutableDir` composed from `getExecutablePath`, not its own `readlink` call | Avoids duplicating the procfs read; failure propagates uniformly as `""` (`filesystem.hpp:108-116`). |
| `weakly_canonical`, not `canonical` | `resolveRelativePath` must not require the full joined path to exist on disk (e.g. resolving a config path before the file is written); `weakly_canonical` normalizes the non-existent tail lexically instead of throwing (`filesystem.hpp:123-125`). |
| Anchored `rfind(prefix, 0) == 0` for prefix matching; unanchored `find` substring for fragment matching | Distinguishes the two removal semantics precisely: `removeFilesMatchingPrefix` needs an anchored leading-prefix test to match its name; `removeFilesContainingAny` is deliberately substring-based, matching its name (`filesystem.hpp:134`, `:147`). No glob engine is pulled in. |
| Collect-then-delete via shared `filesystem_detail::collectMatchingCwdFiles` / `removeRegularFilesQuiet` helpers | Deleting while `directory_iterator` is still walking the directory has unspecified effect on not-yet-visited entries; collecting the full match list first, then deleting, avoids that hazard and lets both removal functions share one predicate-parameterized scan (`filesystem.hpp:63-73`, `:78-97`). |
| Skip non-regular-file matches; use the `error_code` overload of `std::filesystem::remove` | These helpers exist to clean up test log/state *files*; a matched directory is left alone rather than risking `std::filesystem::remove` throwing on a non-empty directory, and the `error_code` overload means a concurrently-vanished or permission-denied entry is skipped instead of throwing (`filesystem.hpp:68`, `:70`). |
| `readlinkGrow` grows and retries instead of a single fixed-size buffer | `::readlink` does not report truncation and never NUL-terminates; treating a full buffer as "possibly truncated" and doubling it (up to a 1 MiB ceiling) avoids silently returning a truncated executable path (`filesystem.hpp:32-53`). |
| CWD-only, non-recursive iteration | Matches the test-fixture use case (logs/state files written directly into the test binary's working directory); no caller in the codebase passes a different directory (`filesystem.hpp:87`). |

---

## Known Limitations

- **CWD-only, non-recursive.** Both removal functions operate solely on the top level of the current working directory (`filesystem_detail::collectMatchingCwdFiles`'s `directory_iterator(".")`); they cannot target a different directory or descend into subdirectories (`filesystem.hpp:87`).
- **Linux-only.** `getExecutablePath` / `getExecutableDir` depend on `/proc/self/exe`; there is no portable fallback (e.g. `dladdr`, `_NSGetExecutablePath`, `GetModuleFileName`) for non-Linux targets (`filesystem.hpp:13`, `:104`).
- **`resolveRelativePath` does not validate its `relative_path` argument is actually relative.** An absolute `relative_path` silently discards `base_absolute_path` per `std::filesystem::path::operator/` semantics (verified above); the function performs no check or documentation of this at the call site.
- **`resolveRelativePath` and direct calls to `getExecutablePath` have no production callers.** `tests/util/iora_test_filesystem.cpp` now exercises both directly, but in the wider codebase `getExecutablePath` is used only through `getExecutableDir`, and no caller invokes `resolveRelativePath`.
