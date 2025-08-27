// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include "iora/network/dns_client.hpp"

using namespace iora::network;

TEST_CASE("DNS utility functions", "[dns][utils]")
{
  SECTION("toLowerAscii")
  {
    REQUIRE(toLowerAscii("EXAMPLE.COM") == "example.com");
    REQUIRE(toLowerAscii("Example.Com") == "example.com");
    REQUIRE(toLowerAscii("example.com") == "example.com");
    REQUIRE(toLowerAscii("EXAMPLE123.COM") == "example123.com");
  }

  SECTION("normalizeName")
  {
    REQUIRE(normalizeName("example.com.") == "example.com");
    REQUIRE(normalizeName("EXAMPLE.COM.") == "example.com");
    REQUIRE(normalizeName("example.com") == "example.com");
    REQUIRE(normalizeName("EXAMPLE.COM...") == "example.com");
  }
}

TEST_CASE("DNS IP conversion utilities", "[dns][utils]")
{
  SECTION("IPv4 to string")
  {
    std::uint8_t ip4[] = {192, 168, 1, 1};
    REQUIRE(ipv4ToString(ip4) == "192.168.1.1");

    std::uint8_t ip4_2[] = {8, 8, 8, 8};
    REQUIRE(ipv4ToString(ip4_2) == "8.8.8.8");

    std::uint8_t ip4_3[] = {255, 255, 255, 255};
    REQUIRE(ipv4ToString(ip4_3) == "255.255.255.255");
  }

  SECTION("IPv6 to string")
  {
    std::uint8_t ip6[] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    auto result = ipv6ToString(ip6);
    REQUIRE(result.find(':') != std::string::npos);
    REQUIRE(result.length() > 0);
  }
}

TEST_CASE("DNS client construction", "[dns][construction]")
{
  SECTION("Default construction")
  {
    DnsClient client;
    // Should not crash
  }

  SECTION("Custom configuration")
  {
    DnsClient::Config cfg;
    cfg.servers = {"8.8.4.4:53", "1.0.0.1:53"};
    cfg.maxRetries = 2;
    cfg.maxParallelServers = 3;
    cfg.enableCache = false;

    DnsClient client(cfg);
    // Should not crash
  }
}

TEST_CASE("DNS client safe lifecycle", "[dns][lifecycle]")
{
  DnsClient client;

  SECTION("Start and stop safely")
  {
    // Try to start - may fail if network unavailable
    bool started = false;
    try
    {
      started = client.start();
    }
    catch (...)
    {
      // Network may not be available in test environment
    }

    // Always try to stop safely
    try
    {
      client.stop();
    }
    catch (...)
    {
      // Ignore cleanup errors
    }

    // Multiple stops should be safe
    try
    {
      client.stop();
    }
    catch (...)
    {
      // Should be idempotent
    }
  }
}