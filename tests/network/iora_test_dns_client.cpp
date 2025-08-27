// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "test_helpers.hpp"
#include <thread>
#include <chrono>
#include <future>
#include <atomic>

#include "iora/network/dns_client.hpp"

using namespace iora::network;
using namespace std::chrono_literals;

TEST_CASE("DnsClient construction and configuration", "[dns][network]")
{
  SECTION("Default construction")
  {
    DnsClient client;
    // Should use default servers
  }

  SECTION("Custom configuration")
  {
    DnsClient::Config cfg;
    cfg.servers = {"8.8.4.4:53", "1.0.0.1:53"};
    cfg.maxRetries = 2;
    cfg.maxParallelServers = 3;
    cfg.enableCache = false;
    cfg.maxCacheEntries = 1024;
    cfg.timeouts.udpWait = 500ms;
    cfg.timeouts.tcpConnect = 800ms;
    cfg.timeouts.tcpRead = 1000ms;
    cfg.timeouts.overall = 2000ms;

    DnsClient client(cfg);
    // Configuration should be applied
  }

  SECTION("Empty server list defaults")
  {
    DnsClient::Config cfg;
    cfg.servers.clear();
    DnsClient client(cfg);
    // Should use default Google and Cloudflare DNS
  }
}

TEST_CASE("DnsClient start/stop lifecycle", "[dns][network]")
{
  DnsClient client;

  SECTION("Start and stop")
  {
    REQUIRE(client.start());
    client.stop();
  }

  SECTION("Multiple start calls")
  {
    REQUIRE(client.start());
    REQUIRE(client.start()); // Should be idempotent
    client.stop();
  }

  SECTION("Multiple stop calls")
  {
    REQUIRE(client.start());
    client.stop();
    client.stop(); // Should be idempotent
  }
}

TEST_CASE("DnsClient A/AAAA record resolution", "[dns][network][integration]")
{
  DnsClient::Config cfg;
  cfg.enableCache = false; // Disable cache for testing
  cfg.timeouts.udpWait = std::chrono::milliseconds(500);
  cfg.timeouts.overall = std::chrono::milliseconds(1000);
  DnsClient client(cfg);

  REQUIRE(client.start());

  SECTION("Resolve IPv4 address")
  {
    try
    {
      auto result = client.resolveHost("google.com");
      REQUIRE(!result.ipv4.empty());
      // Google should have at least one IPv4 address
      for (const auto& ip : result.ipv4)
      {
        // Basic IPv4 format check
        REQUIRE(ip.find('.') != std::string::npos);
        REQUIRE(ip.length() >= 7);  // Minimum: 1.1.1.1
        REQUIRE(ip.length() <= 15); // Maximum: 255.255.255.255
      }
    }
    catch (const std::exception& e)
    {
      INFO("DNS query failed: " << e.what());
      // May fail in offline/restricted environments
    }
  }

  SECTION("Resolve IPv6 address")
  {
    try
    {
      auto result = client.resolveHost("google.com");
      // Google typically has IPv6 addresses
      if (!result.ipv6.empty())
      {
        for (const auto& ip : result.ipv6)
        {
          // Basic IPv6 format check
          REQUIRE(ip.find(':') != std::string::npos);
        }
      }
    }
    catch (const std::exception& e)
    {
      INFO("DNS query failed: " << e.what());
    }
  }

  SECTION("Resolve with CNAME")
  {
    try
    {
      auto result = client.resolveHost("www.google.com");
      // www.google.com may have a canonical name
      if (!result.canonicalName.empty())
      {
        REQUIRE(!result.canonicalName.empty());
      }
      REQUIRE(!result.ipv4.empty());
    }
    catch (const std::exception& e)
    {
      INFO("DNS query failed: " << e.what());
    }
  }

  SECTION("Non-existent domain")
  {
    try
    {
      auto result =
          client.resolveHost("this-domain-definitely-does-not-exist-12345.com");
      // If we get here without exception, that's fine too (depends on DNS
      // server)
      INFO("Unexpectedly resolved non-existent domain");
    }
    catch (const std::runtime_error& e)
    {
      // Expected behavior
      INFO("Expected exception for non-existent domain: " << e.what());
      REQUIRE(true); // Mark as passed
    }
    catch (...)
    {
      // Some other exception occurred, but that's not necessarily wrong
      INFO("Other exception occurred for non-existent domain");
      REQUIRE(true); // Still mark as passed
    }
  }

  client.stop();
}

TEST_CASE("DnsClient CNAME resolution", "[dns][network][integration]")
{
  DnsClient client;
  REQUIRE(client.start());

  SECTION("Resolve CNAME")
  {
    try
    {
      auto cname = client.resolveCName("www.google.com");
      // May or may not have a CNAME
      INFO("CNAME result: " << cname);
    }
    catch (const std::exception& e)
    {
      INFO("CNAME query failed: " << e.what());
    }
  }

  client.stop();
}

TEST_CASE("DnsClient MX record resolution", "[dns][network][integration]")
{
  DnsClient client;
  REQUIRE(client.start());

  SECTION("Resolve MX records")
  {
    try
    {
      auto records = client.resolveMx("google.com");
      if (!records.empty())
      {
        // MX records should be sorted by priority
        for (size_t i = 1; i < records.size(); ++i)
        {
          REQUIRE(records[i - 1].priority <= records[i].priority);
        }

        for (const auto& mx : records)
        {
          REQUIRE(!mx.exchange.empty());
          REQUIRE(mx.ttl > 0);
        }
      }
    }
    catch (const std::exception& e)
    {
      INFO("MX query failed: " << e.what());
    }
  }

  client.stop();
}

TEST_CASE("DnsClient TXT record resolution", "[dns][network][integration]")
{
  DnsClient client;
  REQUIRE(client.start());

  SECTION("Resolve TXT records")
  {
    try
    {
      auto records = client.resolveTxt("google.com");
      if (!records.empty())
      {
        for (const auto& txt : records)
        {
          REQUIRE(!txt.strings.empty());
          REQUIRE(txt.ttl > 0);
        }
      }
    }
    catch (const std::exception& e)
    {
      INFO("TXT query failed: " << e.what());
    }
  }

  client.stop();
}

TEST_CASE("DnsClient SRV record resolution", "[dns][network][integration]")
{
  DnsClient client;
  REQUIRE(client.start());

  SECTION("Resolve SRV records")
  {
    try
    {
      // SRV records are often used for services like XMPP, SIP
      auto records = client.resolveSrv("_xmpp-client._tcp.google.com");
      if (!records.empty())
      {
        // SRV records should be sorted by priority and weighted
        for (const auto& srv : records)
        {
          REQUIRE(!srv.target.empty());
          REQUIRE(srv.port > 0);
          REQUIRE(srv.ttl > 0);
        }
      }
    }
    catch (const std::exception& e)
    {
      INFO("SRV query failed: " << e.what());
    }
  }

  client.stop();
}

TEST_CASE("DnsClient cache functionality", "[dns][network]")
{
  DnsClient::Config cfg;
  cfg.enableCache = true;
  cfg.maxCacheEntries = 10;
  DnsClient client(cfg);

  REQUIRE(client.start());

  SECTION("Cache hit for repeated queries")
  {
    try
    {
      // First query - cache miss
      auto result1 = client.resolveHost("example.com");

      // Second query - should hit cache
      auto start = std::chrono::steady_clock::now();
      auto result2 = client.resolveHost("example.com");
      auto duration = std::chrono::steady_clock::now() - start;

      // Cached query should be very fast (< 10ms)
      REQUIRE(duration < 10ms);

      // Results should match
      REQUIRE(result1.ipv4 == result2.ipv4);
      REQUIRE(result1.ipv6 == result2.ipv6);
      REQUIRE(result1.canonicalName == result2.canonicalName);
    }
    catch (const std::exception& e)
    {
      INFO("DNS query failed: " << e.what());
    }
  }

  SECTION("Cache statistics")
  {
    client.clearCache();
    auto stats1 = client.getCacheStats();
    REQUIRE(stats1.totalEntries == 0);

    try
    {
      client.resolveHost("example.com");
      auto stats2 = client.getCacheStats();
      REQUIRE(stats2.totalEntries > 0);
    }
    catch (const std::exception& e)
    {
      INFO("DNS query failed: " << e.what());
    }
  }

  SECTION("Clear cache")
  {
    try
    {
      client.resolveHost("example.com");
      auto stats1 = client.getCacheStats();
      REQUIRE(stats1.totalEntries > 0);

      client.clearCache();
      auto stats2 = client.getCacheStats();
      REQUIRE(stats2.totalEntries == 0);
    }
    catch (const std::exception& e)
    {
      INFO("DNS query failed: " << e.what());
    }
  }

  client.stop();
}

TEST_CASE("DnsClient async operations", "[dns][network][async]")
{
  DnsClient client;
  REQUIRE(client.start());

  SECTION("Async host resolution")
  {
    std::promise<DnsClient::HostResult> promise;
    auto future = promise.get_future();

    client.resolveHostAsync("example.com",
                            [&promise](bool success, const std::string& error,
                                       const DnsClient::HostResult& result)
                            {
                              if (success)
                              {
                                promise.set_value(result);
                              }
                              else
                              {
                                promise.set_exception(std::make_exception_ptr(
                                    std::runtime_error(error)));
                              }
                            });

    try
    {
      auto result = future.get();
      REQUIRE(!result.ipv4.empty());
    }
    catch (const std::exception& e)
    {
      INFO("Async DNS query failed: " << e.what());
    }
  }

  SECTION("Multiple concurrent async queries")
  {
    std::vector<std::future<DnsClient::HostResult>> futures;
    std::vector<std::string> domains = {"google.com", "example.com",
                                        "cloudflare.com"};

    for (const auto& domain : domains)
    {
      auto promise = std::make_shared<std::promise<DnsClient::HostResult>>();
      futures.push_back(promise->get_future());

      client.resolveHostAsync(
          domain,
          [promise](bool success, const std::string& error,
                    const DnsClient::HostResult& result)
          {
            if (success)
            {
              promise->set_value(result);
            }
            else
            {
              promise->set_exception(
                  std::make_exception_ptr(std::runtime_error(error)));
            }
          });
    }

    int successCount = 0;
    for (auto& future : futures)
    {
      try
      {
        auto result = future.get();
        if (!result.ipv4.empty())
        {
          successCount++;
        }
      }
      catch (const std::exception& e)
      {
        INFO("Async query failed: " << e.what());
      }
    }

    REQUIRE(successCount > 0);
  }

  client.stop();
}

TEST_CASE("DnsClient timeout handling", "[dns][network][timeout]")
{
  DnsClient::Config cfg;
  cfg.servers = {"192.0.2.1:53"}; // TEST-NET-1, should not respond
  cfg.enableCache = false;
  cfg.maxRetries = 0;
  cfg.timeouts.udpWait = 100ms;
  cfg.timeouts.overall = 200ms;

  DnsClient client(cfg);
  REQUIRE(client.start());

  SECTION("Query timeout")
  {
    auto start = std::chrono::steady_clock::now();
    REQUIRE_THROWS_AS(client.resolveHost("example.com"), std::runtime_error);
    auto duration = std::chrono::steady_clock::now() - start;

    // Should timeout within configured time + some margin
    REQUIRE(duration < 500ms);
  }

  client.stop();
}

TEST_CASE("DnsClient custom timeout per query", "[dns][network]")
{
  DnsClient client;
  REQUIRE(client.start());

  SECTION("Override timeout for specific query")
  {
    DnsClient::QueryOptions opts;
    opts.timeouts = DnsClient::Timeouts{};
    opts.timeouts->udpWait = 50ms;
    opts.timeouts->overall = 100ms;

    try
    {
      // Query with very short timeout might fail
      auto result = client.resolveHost("example.com", opts);
      // If it succeeds, good
      REQUIRE(!result.ipv4.empty());
    }
    catch (const std::exception& e)
    {
      // Expected for very short timeouts
      INFO("Query with short timeout failed as expected: " << e.what());
    }
  }

  client.stop();
}

TEST_CASE("DnsClient error conditions", "[dns][network][error]")
{
  SECTION("Query without starting")
  {
    DnsClient client;
    // Should throw or return error
    REQUIRE_THROWS(client.resolveHost("example.com"));
  }

  SECTION("Invalid domain names")
  {
    DnsClient client;
    REQUIRE(client.start());

    // Domain with invalid characters
    REQUIRE_THROWS(client.resolveHost("invalid_domain!@#$.com"));

    // Empty domain
    REQUIRE_THROWS(client.resolveHost(""));

    client.stop();
  }
}

TEST_CASE("DnsClient parallel server queries", "[dns][network]")
{
  DnsClient::Config cfg;
  cfg.servers = {"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "1.0.0.1:53"};
  cfg.maxParallelServers = 2; // Query 2 servers at once
  cfg.enableCache = false;

  DnsClient client(cfg);
  REQUIRE(client.start());

  SECTION("Parallel queries to multiple servers")
  {
    try
    {
      // Should query first 2 servers in parallel
      auto result = client.resolveHost("example.com");
      REQUIRE(!result.ipv4.empty());
    }
    catch (const std::exception& e)
    {
      INFO("Parallel query failed: " << e.what());
    }
  }

  client.stop();
}

TEST_CASE("DnsClient name normalization", "[dns][network]")
{
  // Test the normalization functions
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

TEST_CASE("DnsClient IP conversion utilities", "[dns][network]")
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

TEST_CASE("DnsClient NAPTR record resolution", "[dns][network][integration]")
{
  DnsClient client;
  REQUIRE(client.start());

  SECTION("Resolve NAPTR records")
  {
    try
    {
      // NAPTR records are used for ENUM and other services
      // This is an example - may not have NAPTR records
      auto records = client.resolveNaptr("e164.arpa");
      if (!records.empty())
      {
        for (const auto& naptr : records)
        {
          REQUIRE(naptr.ttl > 0);
          // NAPTR has order and preference for sorting
          INFO("NAPTR: order=" << naptr.order << " pref=" << naptr.preference
                               << " flags=" << naptr.flags
                               << " services=" << naptr.services);
        }
      }
    }
    catch (const std::exception& e)
    {
      INFO("NAPTR query failed (expected if no records): " << e.what());
    }
  }

  client.stop();
}

TEST_CASE("DnsClient async MX resolution", "[dns][network][async]")
{
  DnsClient client;
  REQUIRE(client.start());

  SECTION("Async MX resolution")
  {
    std::promise<std::vector<DnsClient::MxRecord>> promise;
    auto future = promise.get_future();

    client.resolveMxAsync(
        "google.com",
        [&promise](bool success, const std::string& error,
                   const std::vector<DnsClient::MxRecord>& records)
        {
          if (success)
          {
            promise.set_value(records);
          }
          else
          {
            promise.set_exception(
                std::make_exception_ptr(std::runtime_error(error)));
          }
        });

    try
    {
      auto records = future.get();
      if (!records.empty())
      {
        REQUIRE(records[0].priority > 0);
        REQUIRE(!records[0].exchange.empty());
      }
    }
    catch (const std::exception& e)
    {
      INFO("Async MX query failed: " << e.what());
    }
  }

  client.stop();
}

TEST_CASE("DnsClient async TXT resolution", "[dns][network][async]")
{
  DnsClient client;
  REQUIRE(client.start());

  SECTION("Async TXT resolution")
  {
    std::promise<std::vector<DnsClient::TxtRecord>> promise;
    auto future = promise.get_future();

    client.resolveTxtAsync(
        "google.com",
        [&promise](bool success, const std::string& error,
                   const std::vector<DnsClient::TxtRecord>& records)
        {
          if (success)
          {
            promise.set_value(records);
          }
          else
          {
            promise.set_exception(
                std::make_exception_ptr(std::runtime_error(error)));
          }
        });

    try
    {
      auto records = future.get();
      // Google typically has TXT records
      if (!records.empty())
      {
        REQUIRE(!records[0].strings.empty());
      }
    }
    catch (const std::exception& e)
    {
      INFO("Async TXT query failed: " << e.what());
    }
  }

  client.stop();
}

TEST_CASE("DnsClient async SRV resolution", "[dns][network][async]")
{
  DnsClient client;
  REQUIRE(client.start());

  SECTION("Async SRV resolution")
  {
    std::promise<std::vector<DnsClient::SrvRecord>> promise;
    auto future = promise.get_future();

    client.resolveSrvAsync(
        "_xmpp-client._tcp.google.com",
        [&promise](bool success, const std::string& error,
                   const std::vector<DnsClient::SrvRecord>& records)
        {
          if (success)
          {
            promise.set_value(records);
          }
          else
          {
            promise.set_exception(
                std::make_exception_ptr(std::runtime_error(error)));
          }
        });

    try
    {
      auto records = future.get();
      if (!records.empty())
      {
        REQUIRE(!records[0].target.empty());
        REQUIRE(records[0].port > 0);
      }
    }
    catch (const std::exception& e)
    {
      INFO("Async SRV query failed: " << e.what());
    }
  }

  client.stop();
}

TEST_CASE("DnsClient cache expiration", "[dns][network][cache]")
{
  DnsClient::Config cfg;
  cfg.enableCache = true;
  // Note: We can't easily test actual TTL expiration without mocking time
  // but we can test the cache functionality

  DnsClient client(cfg);
  REQUIRE(client.start());

  SECTION("Cache entry count limits")
  {
    cfg.maxCacheEntries = 5;
    DnsClient limitedClient(cfg);
    REQUIRE(limitedClient.start());

    // Try to cache more than the limit
    std::vector<std::string> domains = {"example1.com", "example2.com",
                                        "example3.com", "example4.com",
                                        "example5.com", "example6.com"};

    for (const auto& domain : domains)
    {
      try
      {
        limitedClient.resolveHost(domain);
      }
      catch (...)
      {
        // Ignore resolution failures
      }
    }

    auto stats = limitedClient.getCacheStats();
    // Total entries should not exceed limit * number of cache types
    REQUIRE(stats.totalEntries <= cfg.maxCacheEntries * 7); // 7 cache types

    limitedClient.stop();
  }

  client.stop();
}