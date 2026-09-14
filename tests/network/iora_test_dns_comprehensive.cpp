// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_dns_comprehensive.cpp
/// \brief Comprehensive DNS client testing with wire-level validation
///
/// This test suite provides thorough coverage of the DNS client implementation
/// including wire-format message handling, network behavior simulation,
/// compression edge cases, and all RFC compliance aspects.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "MockDnsServer.hpp"
#include "iora/network/dns/dns_cache.hpp"
#include "iora/network/dns/dns_resolver.hpp"
#include "iora/network/dns/dns_transport.hpp"
#include "iora/network/dns/dns_types.hpp"
#include "iora/network/dns_client.hpp"

#include <algorithm>
#include <chrono>
#include <future>
#include <random>
#include <thread>
#include <utility>
#include <vector>

using namespace iora::network::dns;
using iora::network::DnsClient;

namespace
{

/// \brief Test configuration constants
constexpr std::uint16_t TEST_UDP_PORT = 15353; // Non-standard port for testing
constexpr std::uint16_t TEST_TCP_PORT = 15353;
constexpr std::chrono::milliseconds ASYNC_TIMEOUT{2000};
constexpr std::chrono::milliseconds SERVER_STARTUP_DELAY{200};

/// \brief Test fixture for DNS client testing
class DnsTestFixture
{
public:
  DnsTestFixture()
  {
    // Configure mock server for comprehensive testing
    MockDnsServer::Config serverConfig;
    serverConfig.udpPort = TEST_UDP_PORT;
    serverConfig.tcpPort = TEST_TCP_PORT;
    serverConfig.enableLogging = true;
    serverConfig.maxUdpSize = 512;        // Standard DNS UDP size limit
    serverConfig.maxTcpFragmentSize = 64; // Small fragments for testing

    mockServer_ = std::make_unique<MockDnsServer>(serverConfig);

    // Configure DNS client to use test server
    DnsConfig clientConfig;
    std::vector<std::string> testServers = {"127.0.0.1:" + std::to_string(TEST_UDP_PORT)};
    clientConfig.setServers(testServers);
    clientConfig.timeout = std::chrono::milliseconds(1000);
    clientConfig.retryCount = 2;
    clientConfig.transportMode = DnsTransportMode::Both; // Test UDP->TCP fallback
    clientConfig.enableCache = true;
    clientConfig.maxCacheSize = 1000;

    dnsClient_ = std::make_unique<DnsClient>(clientConfig);
  }

  ~DnsTestFixture()
  {
    // Destroy client first to stop any ongoing operations
    dnsClient_.reset();

    if (mockServer_)
    {
      mockServer_->stop();
    }
  }

  void startServer()
  {
    // Stop server if already running (for section isolation)
    if (mockServer_)
    {
      mockServer_->stop();
      std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Allow cleanup
    }
    REQUIRE(mockServer_->start());
    std::this_thread::sleep_for(SERVER_STARTUP_DELAY);
  }

  MockDnsServer &server() { return *mockServer_; }
  DnsClient &client() { return *dnsClient_; }

private:
  std::unique_ptr<MockDnsServer> mockServer_;
  std::unique_ptr<DnsClient> dnsClient_;
};

} // anonymous namespace

// =============================================================================
// BASIC FUNCTIONALITY TESTS
// =============================================================================

TEST_CASE_METHOD(DnsTestFixture, "DNS Client Basic A Record Resolution", "[dns][basic]")
{
  startServer();

  // Setup basic A record
  server().addRecord({"test.example.com", "A", "192.168.1.100", 3600});
  // Add AAAA record to prevent fallback queries from hanging
  server().addRecord({"test.example.com", "AAAA", "2001:db8::1", 3600});

  // Direct test without SECTION
  auto results = client().resolveA("test.example.com");

  REQUIRE(results.size() == 1);
  CHECK(results[0] == "192.168.1.100");
}

TEST_CASE_METHOD(DnsTestFixture, "DNS Client Additional A Record Tests", "[dns][basic]")
{
  startServer();

  SECTION("Different hostname test")
  {
    // Test with different hostname to verify multiple queries work
    server().addRecord({"test2.example.com", "A", "192.168.1.101", 3600});

    auto results = client().resolveA("test2.example.com");
    REQUIRE(results.size() == 1);
    CHECK(results[0] == "192.168.1.101");
  }

  SECTION("Multiple A records for same domain")
  {
    server().addRecord({"multi.example.com", "A", "192.168.1.10", 3600});
    server().addRecord({"multi.example.com", "A", "192.168.1.11", 3600});
    server().addRecord({"multi.example.com", "A", "192.168.1.12", 3600});

    auto results = client().resolveA("multi.example.com");

    REQUIRE(results.size() == 3);
    CHECK(std::find(results.begin(), results.end(), "192.168.1.10") != results.end());
    CHECK(std::find(results.begin(), results.end(), "192.168.1.11") != results.end());
    CHECK(std::find(results.begin(), results.end(), "192.168.1.12") != results.end());
  }
}

TEST_CASE_METHOD(DnsTestFixture, "DNS Client AAAA Record Resolution", "[dns][basic][ipv6]")
{
  startServer();

  server().addRecord({"ipv6.example.com", "AAAA", "2001:db8::1", 3600});
  server().addRecord({"ipv6.example.com", "AAAA", "2001:db8::2", 3600});

  auto results = client().resolveAAAA("ipv6.example.com");

  REQUIRE(results.size() == 2);
  CHECK(std::find(results.begin(), results.end(), "2001:db8::1") != results.end());
  CHECK(std::find(results.begin(), results.end(), "2001:db8::2") != results.end());
}

// =============================================================================
// SERVICE DISCOVERY TESTS (RFC 3263)
// =============================================================================

TEST_CASE_METHOD(DnsTestFixture, "DNS Service Discovery SRV Records",
                 "[dns][srv][service-discovery]")
{
  startServer();

  SECTION("Basic SRV record resolution")
  {
    server().addRecord({"_sip._udp.example.com", "SRV", "sip1.example.com", 3600, 10, 5, 5060});
    server().addRecord({"_sip._udp.example.com", "SRV", "sip2.example.com", 3600, 20, 10, 5061});
    server().addRecord({"sip1.example.com", "A", "192.168.1.10", 3600});
    server().addRecord({"sip2.example.com", "A", "192.168.1.11", 3600});

    auto result = client().resolveServiceDomain("example.com");

    REQUIRE_FALSE(result.targets.empty());

    // Should have resolved SRV records and their A records
    bool foundSip1 = false, foundSip2 = false;
    for (const auto &target : result.targets)
    {
      if (target.hostname == "sip1.example.com" && target.port == 5060)
      {
        foundSip1 = true;
        CHECK(target.priority == 10);
        CHECK(target.weight == 5);
      }
      if (target.hostname == "sip2.example.com" && target.port == 5061)
      {
        foundSip2 = true;
        CHECK(target.priority == 20);
        CHECK(target.weight == 10);
      }
    }

    CHECK(foundSip1);
    CHECK(foundSip2);
  }

  // Weighted SRV selection test temporarily disabled
  // due to MockDnsServer implementation requirements
}

// =============================================================================
// WIRE-FORMAT AND NETWORK BEHAVIOR TESTS
// =============================================================================

TEST_CASE_METHOD(DnsTestFixture, "DNS Parser Compression Pointer Security",
                 "[dns][parser][security]")
{
  SECTION("Compression pointer loop detection")
  {
    // Create malicious DNS message with pointer loop
    // Message format: Header(12) + Question(varies) + Answer with pointer loop

    std::vector<std::uint8_t> maliciousMessage = {
      // DNS Header (12 bytes)
      0x12, 0x34, // Query ID
      0x81, 0x80, // Flags: QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
      0x00, 0x01, // QDCOUNT=1
      0x00, 0x01, // ANCOUNT=1
      0x00, 0x00, // NSCOUNT=0
      0x00, 0x00, // ARCOUNT=0

      // Question section: "test.com" A IN
      0x04, 't', 'e', 's', 't', // label "test"
      0x03, 'c', 'o', 'm',      // label "com"
      0x00,                     // null terminator
      0x00, 0x01,               // QTYPE=A
      0x00, 0x01,               // QCLASS=IN

      // Answer section with compression pointer loop
      0xc0, 0x0c,             // NAME: pointer to offset 12 (question name)
      0x00, 0x01,             // TYPE=A
      0x00, 0x01,             // CLASS=IN
      0x00, 0x00, 0x0e, 0x10, // TTL=3600
      0x00, 0x04,             // RDLENGTH=4

      // RDATA with pointer loop: points back to itself
      0xc0, 0x20, // Pointer to offset 32 (points to this very pointer!)
      0x00, 0x00  // Padding to make RDLENGTH=4
    };

    // Test that DnsMessage throws on pointer loop
    REQUIRE_THROWS_AS(DnsMessage::parse(maliciousMessage), DnsParseException);
  }

  SECTION("Compression pointer beyond bounds")
  {
    std::vector<std::uint8_t> maliciousMessage = {
      // DNS Header
      0x12, 0x34, // Query ID
      0x81, 0x80, // Flags
      0x00, 0x01, // QDCOUNT=1
      0x00, 0x01, // ANCOUNT=1
      0x00, 0x00, // NSCOUNT=0
      0x00, 0x00, // ARCOUNT=0

      // Question section
      0x04, 't', 'e', 's', 't', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, // TYPE=A
      0x00, 0x01,                                                      // CLASS=IN

      // Answer section
      0xc0, 0x0c,             // NAME: pointer to question
      0x00, 0x01,             // TYPE=A
      0x00, 0x01,             // CLASS=IN
      0x00, 0x00, 0x0e, 0x10, // TTL
      0x00, 0x02,             // RDLENGTH=2

      // RDATA with pointer beyond message bounds
      0xc0, 0xFF // Pointer to offset 255 (beyond message!)
    };

    REQUIRE_THROWS_AS(DnsMessage::parse(maliciousMessage), DnsParseException);
  }

  SECTION("Compression pointer to non-label position")
  {
    std::vector<std::uint8_t> maliciousMessage = {
      // DNS Header
      0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,

      // Question section
      0x04, 't', 'e', 's', 't', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,

      // Answer section
      0xc0, 0x0c,             // NAME: pointer to question
      0x00, 0x01,             // TYPE=A
      0x00, 0x01,             // CLASS=IN
      0x00, 0x00, 0x0e, 0x10, // TTL
      0x00, 0x02,             // RDLENGTH=2

      // RDATA with pointer to middle of TYPE field (invalid position)
      0xc0, 0x1a // Pointer to offset 26 (middle of question TYPE)
    };

    REQUIRE_THROWS_AS(DnsMessage::parse(maliciousMessage), DnsParseException);
  }
}

TEST_CASE_METHOD(DnsTestFixture, "DNS UDP Truncation and TCP Fallback",
                 "[dns][transport][truncation]")
{
  startServer();

  SECTION("TC bit triggers TCP fallback")
  {
    // NOTE: This test requires wire-mode MockDnsServer capabilities
    // Current MockDnsServer works at record level, not wire level
    // TODO: Implement wire-mode mock to send raw DNS bytes with TC bit

    INFO("Test requires wire-mode MockDnsServer implementation");
    INFO("Required capabilities:");
    INFO("1. Send UDP response with TC (truncation) bit set");
    INFO("2. Send full TCP response when client retries over TCP");
    INFO("3. Verify transport layer handles UDP→TCP fallback correctly");

    // Placeholder test structure for when wire-mode mock is available:
    /*
    // Setup large response that would require TCP
    server().addLargeRecord("large.example.com", "TXT", largeTextRecord);

    // Configure UDP to return truncated response (TC=1)
    MockDnsServer::WireConfig udpConfig;
    udpConfig.setTruncationFlag = true;
    udpConfig.protocol = ProtocolType::UDP;
    server().configureWireResponse("large.example.com", udpConfig);

    // Configure TCP to return full response
    MockDnsServer::WireConfig tcpConfig;
    tcpConfig.setTruncationFlag = false;
    tcpConfig.protocol = ProtocolType::TCP;
    server().configureWireResponse("large.example.com", tcpConfig);

    // Query should automatically fallback to TCP and succeed
    auto result = client().resolveTXT("large.example.com");
    CHECK_FALSE(result.empty());

    // Verify both UDP and TCP were used
    auto stats = server().getStats();
    CHECK(stats.udpQueries > 0);  // Initial UDP attempt
    CHECK(stats.tcpQueries > 0);  // TCP fallback
    */

    WARN("UDP Truncation → TCP fallback test requires wire-mode MockDnsServer");
  }
}

TEST_CASE_METHOD(DnsTestFixture, "DNS TCP Fragmentation Reassembly",
                 "[dns][transport][tcp][fragmentation]")
{
  startServer();

  SECTION("TCP response fragmentation handling")
  {
    // NOTE: This test requires wire-mode MockDnsServer with TCP fragmentation
    INFO("Test requires wire-mode MockDnsServer with TCP fragmentation support");
    INFO("Required capabilities:");
    INFO("1. Fragment TCP responses across multiple send() calls");
    INFO("2. Test 2-byte length prefix fragmentation");
    INFO("3. Test DNS message payload fragmentation");
    INFO("4. Verify transport correctly reassembles fragmented TCP responses");

    WARN("TCP fragmentation test requires enhanced MockDnsServer");
  }
}

// =============================================================================
// CACHING TESTS (RFC 2308)
// =============================================================================

TEST_CASE_METHOD(DnsTestFixture, "DNS Caching and TTL Handling", "[dns][cache][ttl]")
{
  startServer();

  SECTION("Positive cache hit")
  {
    server().addRecord({"cached.example.com", "A", "192.168.1.50", 300}); // 5 min TTL

    // First query - cache miss
    auto results1 = client().resolveA("cached.example.com");
    REQUIRE(results1.size() == 1);

    auto stats1 = server().getStats();
    auto udpQueries1 = stats1.udpQueries;

    // Second query - should be cache hit (no network query)
    auto results2 = client().resolveA("cached.example.com");
    REQUIRE(results2.size() == 1);
    CHECK(results1[0] == results2[0]);

    auto stats2 = server().getStats();
    CHECK(stats2.udpQueries == udpQueries1); // No additional network queries
  }

  SECTION("Negative caching with SOA minimum (RFC 2308)")
  {
    // Setup SOA record for negative caching
    // SOA format: MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM
    std::string soaData = "ns1.example.com. admin.example.com. 2023010101 3600 1800 604800 300";
    server().addRecord({"example.com", "SOA", soaData, 3600});

    // NOTE: This test requires MockDnsServer NXDOMAIN support
    // MockDnsServer::QueryConfig nxConfig;
    // nxConfig.shouldReturnNXDOMAIN = true;
    // nxConfig.includeSOAInAuthority = true;
    // server().configureQuery("nonexistent.example.com", nxConfig);

    // First query - should get NXDOMAIN and cache the negative result
    REQUIRE_THROWS_AS(client().resolveA("nonexistent.example.com"), DnsResolverException);

    auto stats1 = server().getStats();
    auto udpQueries1 = stats1.udpQueries;

    // Second query - should hit negative cache (no network query)
    REQUIRE_THROWS_AS(client().resolveA("nonexistent.example.com"), DnsResolverException);

    auto stats2 = server().getStats();
    CHECK(stats2.udpQueries == udpQueries1); // No additional queries due to negative cache

    // Verify a negative entry was inserted and subsequently hit from cache.
    if (client().isCacheEnabled())
    {
      auto cacheStats = client().getCacheStats();
      CHECK(cacheStats.negative_insertions >= 1);
      CHECK(cacheStats.negative_hits >= 1);
    }
  }
}

// =============================================================================
// ERROR HANDLING AND EDGE CASES
// =============================================================================

TEST_CASE_METHOD(DnsTestFixture, "DNS Error Handling", "[dns][error-handling]")
{
  startServer();

  SECTION("Timeout handling")
  {
    MockDnsServer::QueryConfig timeoutConfig;
    timeoutConfig.shouldTimeout = true;
    timeoutConfig.delay = std::chrono::milliseconds(5000);
    server().configureQuery("timeout.example.com", timeoutConfig);

    REQUIRE_THROWS_AS(client().resolveA("timeout.example.com"), DnsTimeoutException);
  }

  SECTION("Very short timeout handling (50ms)")
  {
    // Create a client with very short timeout to test transport layer timeout precision
    DnsConfig shortTimeoutConfig;
    std::vector<std::string> shortTimeoutServers = {"127.0.0.1:" + std::to_string(TEST_UDP_PORT)};
    shortTimeoutConfig.setServers(shortTimeoutServers);
    shortTimeoutConfig.timeout = std::chrono::milliseconds(50); // Very short timeout
    shortTimeoutConfig.retryCount = 0; // No retries to ensure we test raw timeout
    shortTimeoutConfig.transportMode = DnsTransportMode::UDP;
    shortTimeoutConfig.enableCache = false; // Disable cache to ensure network query

    DnsClient shortTimeoutClient(shortTimeoutConfig);

    // Configure mock server to delay response longer than timeout
    MockDnsServer::QueryConfig delayConfig;
    delayConfig.delay = std::chrono::milliseconds(200); // 200ms delay > 50ms timeout
    server().configureQuery("shorttimeout.example.com", delayConfig);

    // Measure actual timeout duration
    auto startTime = std::chrono::steady_clock::now();

    // Should timeout quickly (around 50ms, not wait for 200ms delay)
    try
    {
      shortTimeoutClient.resolveA("shorttimeout.example.com");
      FAIL("Expected DNS resolution to throw exception");
    }
    catch (const DnsTimeoutException &e)
    {
      INFO("Got expected DnsTimeoutException: " << e.what());
    }
    catch (const std::exception &e)
    {
      INFO("Got unexpected exception type: " << e.what());
      INFO("This indicates the DNS timeout is NOT working correctly!");
      FAIL("Expected DnsTimeoutException but got different exception type");
    }

    auto endTime = std::chrono::steady_clock::now();
    auto actualDuration =
      std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    // Verify timeout happened quickly (allow some tolerance for system scheduling)
    CHECK(actualDuration.count() < 150); // Should be much less than 200ms server delay
    CHECK(actualDuration.count() > 30);  // But at least close to 50ms timeout

    INFO("Configured timeout: 50ms, Server delay: 200ms, Actual duration: "
         << actualDuration.count() << "ms");
  }

  SECTION("NXDOMAIN handling")
  {
    // Query for non-configured domain
    REQUIRE_THROWS_AS(client().resolveA("nonexistent.example.com"), DnsResolverException);
  }

  SECTION("Server failure simulation")
  {
    MockDnsServer::QueryConfig failConfig;
    failConfig.shouldFail = true;
    failConfig.errorMessage = "Server failure";
    server().configureQuery("serverfail.example.com", failConfig);

    REQUIRE_THROWS_AS(client().resolveA("serverfail.example.com"), DnsResolverException);
  }
}

// =============================================================================
// IPv6 REVERSE DNS TESTS
// =============================================================================

TEST_CASE_METHOD(DnsTestFixture, "IPv6 Reverse DNS (ip6.arpa)", "[dns][ipv6][reverse]")
{
  startServer();

  SECTION("IPv6 address to reverse DNS format")
  {
    // Test the IPv6 reverse DNS implementation
    std::string ipv6 = "2001:db8::1";
    std::string expected =
      "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";

    // Create temporary DnsClient to access createReverseQuery
    DnsClient tempClient;
    // Note: createReverseQuery is private, so this would need to be made public or tested via PTR
    // queries

    // For now, test via PTR query if implemented
    server().addRecord({expected, "PTR", "test.example.com", 3600});

    // This would test the full reverse lookup chain
    // auto result = client().resolvePTR(ipv6);
    // CHECK(result == "test.example.com");
  }
}

// =============================================================================
// ASYNC API AND CANCELLATION TESTS
// =============================================================================

TEST_CASE_METHOD(DnsTestFixture, "DNS Future Cancellation Readiness", "[dns][async][cancellation]")
{
  startServer();

  SECTION("resolveAAsync cancellation prevents future hang")
  {
    server().addRecord({"slow.example.com", "A", "192.168.1.100", 3600});

    // Configure server to delay response
    MockDnsServer::QueryConfig slowConfig;
    slowConfig.delay = std::chrono::milliseconds(5000); // 5 second delay
    server().configureQuery("slow.example.com", slowConfig);

    // Start async resolution
    auto cancellableFuture = client().resolveAAsync("slow.example.com");

    // Immediately cancel the request
    bool cancelResult = cancellableFuture.cancel();
    CHECK(cancelResult == true); // Should successfully cancel

    // Future must become ready with cancellation exception (no hang)
    auto status = cancellableFuture.future.wait_for(std::chrono::milliseconds(1000));
    REQUIRE(status == std::future_status::ready);

    // Future should contain cancellation exception
    REQUIRE_THROWS_AS(cancellableFuture.future.get(), DnsResolverException);

    // Verify cancellation state
    CHECK(cancellableFuture.isCancelled());
    CHECK(cancellableFuture.isCompleted());
  }

  SECTION("resolveServiceDomainFuture cancellation prevents hang")
  {
    server().addRecord(
      {"slow-service.example.com", "SRV", "target.example.com", 3600, 10, 5, 5060});

    // Configure delay for ALL possible service discovery queries to ensure cancellation wins
    MockDnsServer::QueryConfig slowConfig;
    slowConfig.delay =
      std::chrono::milliseconds(5000); // Longer delay to ensure cancellation happens first

    // Service discovery may query NAPTR, SRV, and potentially other records
    server().configureQuery("slow-service.example.com", slowConfig);
    server().configureQuery("_sip._tcp.slow-service.example.com", slowConfig);
    server().configureQuery("_sips._tcp.slow-service.example.com", slowConfig);
    server().configureQuery("_sip._udp.slow-service.example.com", slowConfig);
    server().configureQuery("target.example.com", slowConfig);

    // Start async service resolution
    auto cancellableFuture = client().resolveServiceDomainFuture("slow-service.example.com");

    // Cancel immediately
    CHECK(cancellableFuture.cancel());

    // Must not hang
    auto status = cancellableFuture.future.wait_for(std::chrono::milliseconds(1000));
    REQUIRE(status == std::future_status::ready);

    // Should throw cancellation exception
    REQUIRE_THROWS_AS(cancellableFuture.future.get(), DnsResolverException);
  }

  SECTION("Best-effort cancellation semantics")
  {
    server().addRecord({"race.example.com", "A", "192.168.1.200", 3600});

    // Start resolution (might complete before cancel)
    auto cancellableFuture = client().resolveAAsync("race.example.com");

    // Try to cancel (may or may not succeed due to timing)
    bool cancelled = cancellableFuture.cancel();

    // Future must become ready regardless
    auto status = cancellableFuture.future.wait_for(std::chrono::milliseconds(2000));
    REQUIRE(status == std::future_status::ready);

    if (cancelled)
    {
      // If successfully cancelled, should throw
      REQUIRE_THROWS_AS(cancellableFuture.future.get(), DnsResolverException);
    }
    else
    {
      // If not cancelled, should return result
      auto result = cancellableFuture.future.get();
      CHECK_FALSE(result.empty());
    }
  }
}

// =============================================================================
// PERFORMANCE AND CONCURRENT ACCESS TESTS
// =============================================================================

TEST_CASE_METHOD(DnsTestFixture, "DNS Concurrent Query Performance",
                 "[dns][performance][concurrency]")
{
  startServer();

  server().setupCommonSipRecords();

  SECTION("Sequential queries performance")
  {
    const int numQueries = 10; // Reduced for synchronous testing

    auto startTime = std::chrono::steady_clock::now();

    // Run sequential queries
    int successCount = 0;
    for (int i = 0; i < numQueries; ++i)
    {
      try
      {
        auto result = client().resolveA("example.com");
        if (!result.empty())
        {
          successCount++;
        }
      }
      catch (const std::exception &)
      {
        // Some queries might fail - that's ok for this test
      }
    }

    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    // Should complete reasonably quickly with good success rate
    CHECK(duration < std::chrono::milliseconds(10000)); // More time for sequential
    CHECK(successCount > numQueries / 2);               // At least 50% success rate

    INFO("Sequential queries: " << numQueries);
    INFO("Successful: " << successCount);
    INFO("Duration: " << duration.count() << "ms");
  }
}

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

TEST_CASE_METHOD(DnsTestFixture, "DNS Full Service Discovery Chain",
                 "[dns][integration][service-discovery]")
{
  startServer();

  SECTION("Complete NAPTR -> SRV -> A resolution chain")
  {
    // Setup complete service discovery chain with a real NAPTR record (S flag ->
    // SRV -> A), exercising processNaptrRecords rather than the direct-SRV fallback.
    // Use a NON-default SRV name so this test genuinely exercises the NAPTR 'S'
    // path: if it were broken, the direct-SRV fallback (which queries the default
    // _sip._udp/_tcp/... names) could not reach this SRV, and there is no bare-domain
    // A record for it to fall back to either.
    MockDnsServer::DnsRecord naptr;
    naptr.name = "service.example.com";
    naptr.type = "NAPTR";
    naptr.ttl = 3600;
    naptr.naptrOrder = 100;
    naptr.naptrPreference = 10;
    naptr.naptrFlags = "s";
    naptr.naptrService = "SIP+D2U";
    naptr.naptrReplacement = "_sipchain._udp.service.example.com";
    server().addRecord(naptr);
    server().addRecord(
      {"_sipchain._udp.service.example.com", "SRV", "sip.service.example.com", 3600, 10, 5, 5060});
    server().addRecord({"sip.service.example.com", "A", "192.168.1.100", 3600});

    auto result = client().resolveServiceDomain("service.example.com");

    REQUIRE_FALSE(result.targets.empty());
    CHECK(result.targets[0].hostname == "sip.service.example.com");
    CHECK(result.targets[0].port == 5060);
    CHECK(result.targets[0].transport == ServiceType::SIP_UDP);

    // Test preferred target selection
    auto preferred = result.getPreferredTarget();
    CHECK(preferred.hostname == "sip.service.example.com");
  }
}

// =============================================================================
// REGRESSION TESTS FOR THE 2026-09-14 DNS RESILIENCY/CORRECTNESS FIXES
// =============================================================================

TEST_CASE("DNS cacheTimeout drives the default cache TTL", "[dns][cache][config]")
{
  // Regression: DnsConfig::cacheTimeout was previously never applied — the cache
  // was built via the size_t DnsCache ctor, which hardcodes a 300s TTL. It must
  // now seed the cache default TTL. (No network: only the cache is exercised.)
  DnsConfig cfg;
  cfg.enableCache = true;
  cfg.cacheTimeout = std::chrono::seconds(123);
  DnsClient client(cfg);

  REQUIRE(client.isCacheEnabled());
  CHECK(client.getCacheTtl() == std::chrono::seconds(123));
}

TEST_CASE_METHOD(DnsTestFixture,
                 "DNS SRV target '.' suppresses A/AAAA fallback (RFC 2782)",
                 "[dns][service-discovery][rfc2782]")
{
  startServer();

  SECTION("A single SRV '.' target means service unavailable — no A/AAAA fallback")
  {
    // _sip._udp.denied.example.com publishes one SRV with target "." — RFC 2782
    // "the service is decidedly not available at this domain". An A record for
    // the bare domain also exists; the resolver must NOT fall back to it.
    server().addRecord({"_sip._udp.denied.example.com", "SRV", ".", 3600, 0, 0, 5060});
    server().addRecord({"denied.example.com", "A", "192.168.1.77", 3600});

    auto result = client().resolveServiceDomain("denied.example.com", {ServiceType::SIP_UDP});

    // The "." target is skipped and the A/AAAA fallback is suppressed: no target.
    CHECK(result.targets.empty());
    CHECK_FALSE(result.isSuccess());
  }
}

TEST_CASE_METHOD(DnsTestFixture, "DNS NODATA (NOERROR/0-answers) is negative-cached (RFC 2308)",
                 "[dns][cache][rfc2308][nodata]")
{
  startServer();

  SECTION("A NODATA response is cached and re-thrown without a second network query")
  {
    // NOERROR with no answers + an SOA in authority = RFC 2308 NODATA.
    MockDnsServer::QueryConfig nodata;
    nodata.shouldReturnNodata = true;
    server().configureQuery("nodata.example.com", nodata);

    // First query: NODATA -> negatively cached (SOA present) + throws.
    REQUIRE_THROWS_AS(client().resolveA("nodata.example.com"), DnsResolverException);
    auto udpAfterFirst = server().getStats().udpQueries;

    // Second query: served from the negative cache, no additional network query.
    REQUIRE_THROWS_AS(client().resolveA("nodata.example.com"), DnsResolverException);
    CHECK(server().getStats().udpQueries == udpAfterFirst);

    if (client().isCacheEnabled())
    {
      auto stats = client().getCacheStats();
      CHECK(stats.negative_insertions >= 1);
      CHECK(stats.negative_hits >= 1);
    }
  }
}

TEST_CASE_METHOD(DnsTestFixture,
                 "DNS NAPTR ascending-ORDER descent skips an unusable lower tier (RFC 3403)",
                 "[dns][service-discovery][rfc3403][naptr]")
{
  startServer();

  SECTION("Lowest ORDER is all-unsupported; the next ORDER's usable target is used")
  {
    // ORDER 10: an unsupported service (skipped). ORDER 20: a usable SIP+D2U 's'
    // record pointing at a NON-default SRV name, so only real ascending-order NAPTR
    // processing (not the direct-SRV fallback, which queries default names) reaches it.
    MockDnsServer::DnsRecord low;
    low.name = "multi.example.com";
    low.type = "NAPTR";
    low.naptrOrder = 10;
    low.naptrPreference = 10;
    low.naptrFlags = "s";
    low.naptrService = "FOO+BAR"; // unsupported -> Unknown -> skipped
    low.naptrReplacement = "_foo._udp.multi.example.com";
    server().addRecord(low);

    MockDnsServer::DnsRecord high;
    high.name = "multi.example.com";
    high.type = "NAPTR";
    high.naptrOrder = 20;
    high.naptrPreference = 10;
    high.naptrFlags = "s";
    high.naptrService = "SIP+D2U";
    high.naptrReplacement = "_sipcustom._udp.multi.example.com"; // non-default SRV name
    server().addRecord(high);

    server().addRecord(
      {"_sipcustom._udp.multi.example.com", "SRV", "sipcustom.multi.example.com", 3600, 5, 0, 5060});
    server().addRecord({"sipcustom.multi.example.com", "A", "192.168.1.99", 3600});
    // Deliberately NO A record for multi.example.com: the direct-SRV fallback would
    // find nothing, so a pass proves the ORDER-20 tier was actually processed.

    auto result = client().resolveServiceDomain("multi.example.com");

    REQUIRE_FALSE(result.targets.empty());
    CHECK(result.targets[0].hostname == "sipcustom.multi.example.com");
    CHECK(result.targets[0].transport == ServiceType::SIP_UDP);
  }
}

TEST_CASE_METHOD(DnsTestFixture,
                 "DNS sync service resolution falls back to direct SRV when NAPTR is unusable",
                 "[dns][service-discovery][rfc3263]")
{
  startServer();

  SECTION("NAPTR present but all-unusable -> sync direct-SRV fallback (parity with async)")
  {
    MockDnsServer::DnsRecord naptr;
    naptr.name = "unusable.example.com";
    naptr.type = "NAPTR";
    naptr.naptrOrder = 10;
    naptr.naptrPreference = 10;
    naptr.naptrFlags = "s";
    naptr.naptrService = "FOO+BAR"; // unsupported -> no usable target
    naptr.naptrReplacement = "_foo._udp.unusable.example.com";
    server().addRecord(naptr);

    server().addRecord(
      {"_sip._udp.unusable.example.com", "SRV", "sip.unusable.example.com", 3600, 10, 0, 5060});
    server().addRecord({"sip.unusable.example.com", "A", "192.168.1.55", 3600});

    auto result = client().resolveServiceDomain("unusable.example.com");

    REQUIRE_FALSE(result.targets.empty());
    CHECK(result.targets[0].hostname == "sip.unusable.example.com");
  }
}

TEST_CASE_METHOD(DnsTestFixture, "DNS async SRV '.' suppresses the A/AAAA fallback (RFC 2782)",
                 "[dns][service-discovery][rfc2782][async]")
{
  startServer();

  SECTION("Async path honors the '.' abort like the sync path")
  {
    server().addRecord({"_sip._udp.adenied.example.com", "SRV", ".", 3600, 0, 0, 5060});
    server().addRecord({"adenied.example.com", "A", "192.168.1.66", 3600});

    std::promise<ServiceResolutionResult> prom;
    auto fut = prom.get_future();
    client().resolveServiceDomainAsync(
      "adenied.example.com",
      [&prom](const ServiceResolutionResult &r, const std::exception_ptr &)
      { prom.set_value(r); },
      {ServiceType::SIP_UDP});

    REQUIRE(fut.wait_for(std::chrono::seconds(3)) == std::future_status::ready);
    auto result = fut.get();
    CHECK(result.targets.empty());
  }
}

TEST_CASE_METHOD(DnsTestFixture,
                 "DNS SRV '.' suppression is per-service, not domain-wide (RFC 2782)",
                 "[dns][service-discovery][rfc2782]")
{
  startServer();

  SECTION("SIPS disabled via '.' must not strand plain SIP reachable via a bare A record")
  {
    // _sips._tcp declares SIPS unavailable ("."); no other SRV exists; the domain
    // has a bare A record. Plain SIP (UDP) must still resolve via A/AAAA fallback.
    server().addRecord({"_sips._tcp.persvc.example.com", "SRV", ".", 3600, 0, 0, 5060});
    server().addRecord({"persvc.example.com", "A", "192.168.1.88", 3600});

    auto result = client().resolveServiceDomain(
      "persvc.example.com", {ServiceType::SIP_UDP, ServiceType::SIPS_TLS});

    REQUIRE_FALSE(result.targets.empty());
    // Only the non-denied transport (UDP) is present; SIPS is suppressed.
    for (const auto &t : result.targets)
    {
      CHECK(t.transport != ServiceType::SIPS_TLS);
    }
    bool hasUdp = false;
    for (const auto &t : result.targets)
    {
      if (t.transport == ServiceType::SIP_UDP)
      {
        hasUdp = true;
        CHECK(std::find(t.addresses.begin(), t.addresses.end(), "192.168.1.88") !=
              t.addresses.end());
      }
    }
    CHECK(hasUdp);
  }
}

TEST_CASE_METHOD(DnsTestFixture,
                 "DNS resolveCustomServiceDomainAsync with an empty SRV set still fires the callback",
                 "[dns][service-discovery][async]")
{
  startServer();

  SECTION("Empty srvQueries must not lose the completion (no caller hang)")
  {
    server().addRecord({"h1.example.com", "A", "192.168.1.11", 3600});

    std::promise<bool> prom;
    auto fut = prom.get_future();
    std::vector<std::pair<std::string, ServiceType>> emptyQueries;
    client().resolveCustomServiceDomainAsync(
      "h1.example.com", emptyQueries,
      [&prom](const ServiceResolutionResult &, const std::exception_ptr &)
      { prom.set_value(true); });

    // Without the zero-work guard the callback never fires and this times out.
    REQUIRE(fut.wait_for(std::chrono::seconds(3)) == std::future_status::ready);
    CHECK(fut.get());
  }
}

TEST_CASE_METHOD(DnsTestFixture,
                 "DNS NODATA without an SOA is NOT negative-cached (RFC 2308 section 5)",
                 "[dns][cache][rfc2308][nodata]")
{
  startServer();

  SECTION("A no-SOA negative re-queries the network (negative-control for the SOA gate)")
  {
    MockDnsServer::QueryConfig nodataNoSoa;
    nodataNoSoa.shouldReturnNodataNoSoa = true;
    server().configureQuery("nosoa.example.com", nodataNoSoa);

    REQUIRE_THROWS_AS(client().resolveA("nosoa.example.com"), DnsResolverException);
    auto udpAfterFirst = server().getStats().udpQueries;

    // Second query MUST re-hit the network: a negative without an SOA is not cached.
    REQUIRE_THROWS_AS(client().resolveA("nosoa.example.com"), DnsResolverException);
    CHECK(server().getStats().udpQueries > udpAfterFirst);

    if (client().isCacheEnabled())
    {
      CHECK(client().getCacheStats().negative_insertions == 0);
    }
  }
}

TEST_CASE_METHOD(DnsTestFixture,
                 "DNS async SRV '.' suppression is per-service, not domain-wide (RFC 2782)",
                 "[dns][service-discovery][rfc2782][async]")
{
  startServer();

  SECTION("Async: SIPS denied via '.' still leaves plain SIP reachable via bare A")
  {
    server().addRecord({"_sips._tcp.apersvc.example.com", "SRV", ".", 3600, 0, 0, 5060});
    server().addRecord({"apersvc.example.com", "A", "192.168.1.90", 3600});

    std::promise<ServiceResolutionResult> prom;
    auto fut = prom.get_future();
    client().resolveServiceDomainAsync(
      "apersvc.example.com",
      [&prom](const ServiceResolutionResult &r, const std::exception_ptr &) { prom.set_value(r); },
      {ServiceType::SIP_UDP, ServiceType::SIPS_TLS});

    REQUIRE(fut.wait_for(std::chrono::seconds(3)) == std::future_status::ready);
    auto result = fut.get();
    REQUIRE_FALSE(result.targets.empty());
    for (const auto &t : result.targets)
    {
      CHECK(t.transport != ServiceType::SIPS_TLS);
    }
  }
}