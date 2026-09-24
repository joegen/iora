// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <chrono>
#include <cstdint>
#include <regex>
#include <set>
#include <string>
#include <thread>

#include <iora/ids/uuid.hpp>

using iora::ids::Uuid;

namespace
{
const std::regex kUuidRe("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");

std::uint64_t v7Millis(const std::string &u)
{
  // First 48 bits: chars 0-7 and 9-12 of the canonical form.
  return std::stoull(u.substr(0, 8) + u.substr(9, 4), nullptr, 16);
}

std::int64_t nowMillis()
{
  return std::chrono::duration_cast<std::chrono::milliseconds>(
           std::chrono::system_clock::now().time_since_epoch())
    .count();
}
} // namespace

TEST_CASE("Uuid::v4 format, version and variant", "[uuid]")
{
  for (int i = 0; i < 100; ++i)
  {
    const std::string u = Uuid::v4();
    REQUIRE(std::regex_match(u, kUuidRe));
    REQUIRE(u[14] == '4');
    REQUIRE(std::string("89ab").find(u[19]) != std::string::npos);
  }
}

TEST_CASE("Uuid::v4 values are distinct", "[uuid]")
{
  std::set<std::string> seen;
  for (int i = 0; i < 1000; ++i)
  {
    seen.insert(Uuid::v4());
  }
  REQUIRE(seen.size() == 1000);
}

TEST_CASE("Uuid::v7 format, version and variant", "[uuid]")
{
  for (int i = 0; i < 100; ++i)
  {
    const std::string u = Uuid::v7();
    REQUIRE(std::regex_match(u, kUuidRe));
    REQUIRE(u[14] == '7');
    REQUIRE(std::string("89ab").find(u[19]) != std::string::npos);
  }
}

TEST_CASE("Uuid::v7 values generated back to back are distinct", "[uuid]")
{
  // Most of these share a millisecond, so only the random bits keep them apart.
  std::set<std::string> seen;
  for (int i = 0; i < 1000; ++i)
  {
    seen.insert(Uuid::v7());
  }
  REQUIRE(seen.size() == 1000);
}

// system_clock can step backwards (NTP); a sample window that saw a step is
// retried rather than asserted on, and a step that keeps recurring fails.
constexpr int kClockStepRetries = 5;

TEST_CASE("Uuid::v7 carries the Unix-epoch millisecond timestamp", "[uuid]")
{
  for (int attempt = 0; attempt < kClockStepRetries; ++attempt)
  {
    const auto before = nowMillis();
    const std::string u = Uuid::v7();
    const auto after = nowMillis();
    if (after < before)
    {
      continue; // clock stepped back mid-sample
    }
    const std::uint64_t ms = v7Millis(u);
    REQUIRE(ms >= static_cast<std::uint64_t>(before));
    REQUIRE(ms <= static_cast<std::uint64_t>(after));
    return;
  }
  FAIL("system_clock stepped backwards on every attempt");
}

TEST_CASE("Uuid::v7 sorts by creation time across milliseconds", "[uuid]")
{
  for (int attempt = 0; attempt < kClockStepRetries; ++attempt)
  {
    const auto beforeA = nowMillis();
    const std::string a = Uuid::v7();
    std::this_thread::sleep_for(std::chrono::milliseconds(3));
    const auto beforeB = nowMillis();
    const std::string b = Uuid::v7();
    if (beforeB <= beforeA)
    {
      continue; // clock stepped back (or did not advance) between the two samples
    }
    REQUIRE(v7Millis(a) < v7Millis(b));
    REQUIRE(a < b);
    return;
  }
  FAIL("system_clock stepped backwards on every attempt");
}
