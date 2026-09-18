// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once
#include <cstddef>
#include <filesystem>
#include <string>
#include <system_error>
#include <unistd.h> // for readlink
#include <vector>

namespace iora
{
namespace util
{

namespace filesystem_detail
{
/// \brief readlink() with buffer-growth on truncation. readlink() does not report
/// truncation and never NUL-terminates: a return equal to the buffer size means
/// the target is at least that long and may be truncated, so grow and retry.
/// Returns "" on error or past an implausible ceiling (bounds the loop).
/// \p path is parameterized so the function is unit-testable against an arbitrary
/// symlink; \p initialSize defaults to 4096 in production (larger than any real
/// /proc/self/exe path, so the grow loop is defensive there) and can be set small
/// by a test to exercise the grow path deterministically (a symlink target cannot
/// exceed PATH_MAX, so the default-size grow branch is not reachable via a symlink).
inline std::string readlinkGrow(const char *path, std::size_t initialSize = 4096)
{
  std::vector<char> buf(initialSize == 0 ? std::size_t{1} : initialSize);
  for (;;)
  {
    ssize_t len = ::readlink(path, buf.data(), buf.size());
    if (len < 0)
    {
      return {}; // readlink failed
    }
    if (static_cast<std::size_t>(len) < buf.size())
    {
      // Not truncated. readlink does not NUL-terminate, so bound by len.
      return std::string(buf.data(), static_cast<std::size_t>(len));
    }
    if (buf.size() >= (std::size_t{1} << 20))
    {
      return {}; // implausibly long; do not loop unbounded
    }
    buf.resize(buf.size() * 2);
  }
}

/// \brief Best-effort delete of the collected regular files. Collect-then-delete
/// (never delete while iterating the directory — modifying a directory during
/// std::filesystem::directory_iterator traversal has unspecified effect on
/// not-yet-visited entries). Only regular files are removed; a matched directory
/// or special file is skipped (these helpers clean up test log/state FILES, and
/// std::filesystem::remove throws on a non-empty directory). Each removal uses
/// the error_code overload so a concurrently-vanished or permission-denied entry
/// does not propagate an exception to the caller.
inline void removeRegularFilesQuiet(const std::vector<std::filesystem::path> &victims)
{
  for (const auto &p : victims)
  {
    std::error_code ec;
    if (std::filesystem::is_regular_file(p, ec))
    {
      std::filesystem::remove(p, ec); // error_code overload: never throws
    }
  }
}

/// \brief Collect the paths of current-directory entries whose FILENAME satisfies
/// \p pred. Shared walk/collect scaffolding for the removeFiles* helpers, whose
/// match predicates (prefix vs. substring) legitimately differ.
template <typename Predicate>
inline std::vector<std::filesystem::path> collectMatchingCwdFiles(Predicate pred)
{
  std::vector<std::filesystem::path> victims;
  // error_code overloads throughout: a CWD removed/renamed mid-scan, or a
  // per-entry read/permission error while advancing, ends the scan quietly
  // rather than throwing std::filesystem::filesystem_error out of the caller
  // (these are best-effort cleanup helpers, matching removeRegularFilesQuiet).
  std::error_code ec;
  std::filesystem::directory_iterator it(".", ec);
  const std::filesystem::directory_iterator end;
  for (; !ec && it != end; it.increment(ec))
  {
    if (pred(it->path().filename().string()))
    {
      victims.push_back(it->path());
    }
  }
  return victims;
}
} // namespace filesystem_detail

/// \brief Get the path to the currently running executable (Linux; reads
/// /proc/self/exe). Returns "" on failure. Truncation-safe (see readlinkGrow).
inline std::string getExecutablePath()
{
  return filesystem_detail::readlinkGrow("/proc/self/exe");
}

/// \brief Get the directory of the currently running executable
inline std::string getExecutableDir()
{
  std::string exePath = getExecutablePath();
  if (!exePath.empty())
  {
    return std::filesystem::path(exePath).parent_path().string();
  }
  return {};
}

/// \brief Resolve a relative path against an absolute base path
inline std::string resolveRelativePath(const std::string &base_absolute_path,
                                       const std::string &relative_path)
{
  // Use std::filesystem to join and normalize the path
  return std::filesystem::weakly_canonical(std::filesystem::path(base_absolute_path) /
                                           relative_path)
    .string();
}

/// \brief Remove regular files in the current directory whose FILENAME begins
/// with the given prefix (anchored prefix match, not substring containment).
inline void removeFilesMatchingPrefix(const std::string &prefix)
{
  filesystem_detail::removeRegularFilesQuiet(
    filesystem_detail::collectMatchingCwdFiles(
      [&](const std::string &name) { return name.rfind(prefix, 0) == 0; }));
}

/// \brief Remove regular files in the current directory whose FILENAME contains
/// any of the given fragments (substring match).
inline void removeFilesContainingAny(const std::vector<std::string> &fragments)
{
  filesystem_detail::removeRegularFilesQuiet(
    filesystem_detail::collectMatchingCwdFiles(
      [&](const std::string &name)
      {
        for (const auto &fragment : fragments)
        {
          if (name.find(fragment) != std::string::npos)
          {
            return true;
          }
        }
        return false;
      }));
}

} // namespace util
} // namespace iora
