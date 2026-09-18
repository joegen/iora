// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <filesystem>
#include <fstream>
#include <string>

#include <iora/util/filesystem.hpp>

namespace fs = std::filesystem;

namespace
{
// A distinctive per-file token so this test never collides with other tests'
// CWD artifacts (removeFiles* operate on the current working directory).
constexpr const char *kTok = "iora_fs_test_9f3c_";

void touch(const std::string &name)
{
  std::ofstream(name) << "x";
}

bool exists(const std::string &name)
{
  std::error_code ec;
  return fs::exists(name, ec);
}

// Remove every CWD entry carrying our token, so a failed assertion cannot leave
// artifacts behind for the next run.
void scrub()
{
  iora::util::removeFilesContainingAny({kTok});
}
} // namespace

TEST_CASE("removeFilesMatchingPrefix is an anchored prefix match, not substring",
          "[filesystem]")
{
  scrub();
  const std::string pfx = std::string(kTok) + "pfx_";
  const std::string a = pfx + "a.log";
  const std::string b = pfx + "b.log";
  const std::string notPrefixed = std::string(kTok) + "other_pfx_c.log"; // CONTAINS "pfx_" but does not START with it
  touch(a);
  touch(b);
  touch(notPrefixed);

  iora::util::removeFilesMatchingPrefix(pfx);

  REQUIRE_FALSE(exists(a));
  REQUIRE_FALSE(exists(b));
  REQUIRE(exists(notPrefixed)); // substring match would have wrongly deleted this

  scrub();
  REQUIRE_FALSE(exists(notPrefixed));
}

TEST_CASE("removeFilesContainingAny deletes any fragment match, spares others",
          "[filesystem]")
{
  scrub();
  const std::string alpha = std::string(kTok) + "svc_alpha_log.txt";
  const std::string beta = std::string(kTok) + "svc_beta_state.json";
  const std::string keep = std::string(kTok) + "keepme.dat";
  touch(alpha);
  touch(beta);
  touch(keep);

  iora::util::removeFilesContainingAny({"alpha_log", "beta_state"});

  REQUIRE_FALSE(exists(alpha));
  REQUIRE_FALSE(exists(beta));
  REQUIRE(exists(keep));

  scrub();
}

TEST_CASE("removeFiles* skip a matched directory and do not throw", "[filesystem]")
{
  scrub();
  const std::string dir = std::string(kTok) + "dir_target";
  std::error_code ec;
  fs::create_directory(dir, ec);
  REQUIRE_FALSE(ec);
  touch(dir + "/inside.txt"); // make it non-empty (remove() would throw on it)

  // The name matches the prefix, but it is a directory: the helper must skip it
  // (regular-file guard) rather than let std::filesystem::remove throw.
  REQUIRE_NOTHROW(iora::util::removeFilesMatchingPrefix(std::string(kTok) + "dir_"));
  REQUIRE(fs::exists(dir, ec)); // directory untouched

  fs::remove_all(dir, ec);
  scrub();
}

TEST_CASE("readlinkGrow grows the buffer to return a target longer than the "
          "initial size",
          "[filesystem]")
{
  // A symlink target cannot exceed PATH_MAX, so the production 4096-byte initial
  // buffer's grow branch is not reachable via a real symlink. Drive the grow loop
  // deterministically instead with a small initialSize and a target longer than
  // it (but well within PATH_MAX): 300 bytes with initialSize=8 forces several
  // doublings (8 -> 16 -> ... -> 512) before the full target fits.
  const std::string target(300, 'x');
  const std::string link = std::string(kTok) + "grow_link";
  std::error_code ec;
  fs::remove(link, ec);
  fs::create_symlink(target, link, ec);
  REQUIRE_FALSE(ec); // symlink target < PATH_MAX -> creation succeeds

  REQUIRE(iora::util::filesystem_detail::readlinkGrow(link.c_str(), 8) == target);
  // The default-size path returns the same target without needing to grow.
  REQUIRE(iora::util::filesystem_detail::readlinkGrow(link.c_str()) == target);

  fs::remove(link, ec);
}

TEST_CASE("getExecutablePath / getExecutableDir resolve the running binary",
          "[filesystem]")
{
  const std::string path = iora::util::getExecutablePath();
  REQUIRE_FALSE(path.empty());
  std::error_code ec;
  REQUIRE(fs::exists(path, ec));

  const std::string dir = iora::util::getExecutableDir();
  REQUIRE_FALSE(dir.empty());
  REQUIRE(fs::path(path).parent_path().string() == dir);
}
