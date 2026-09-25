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

/// \brief Run resolveServiceDomainAsync and block for the result (test helper).
/// \param secure RFC 3263 §4.1 SIPS SIP-scoped secure resolution (defaulted false).
inline ServiceResolutionResult
resolveServiceBlocking(DnsClient &c, const std::string &domain,
                       const std::vector<ServiceType> &preferred = {}, bool secure = false)
{
  // Hold the promise in a shared_ptr captured BY VALUE: if the 5s wait times out and this
  // function throws, the in-flight async op is not cancelled and may still fire the callback —
  // a stack promise captured by reference would be a use-after-scope. (shared_ptr keeps the
  // promise alive until the last of {this scope, the callback} releases it.)
  auto prom = std::make_shared<std::promise<ServiceResolutionResult>>();
  auto fut = prom->get_future();
  c.resolveServiceDomainAsync(
    domain, [prom](const ServiceResolutionResult &r, const std::exception_ptr &)
    { prom->set_value(r); },
    preferred, secure);
  if (fut.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
  {
    throw std::runtime_error("async service resolve timed out: " + domain);
  }
  return fut.get();
}

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
// CATCH-SCOPE / PARTIAL-RESULTS REGRESSION TESTS (tracker 2026-09-24-29, slice a1)
// The sync DnsResolver catch sites were broadened from DnsResolverException-only
// to also catch DnsTransportException (incl. DnsTimeoutException) and
// DnsParseException, so a timeout/transport/parse error on one query no longer
// aborts the whole RFC 3263 resolution or discards already-collected results.
//
// Coverage notes (tracker step-0 residuals R2-M3 + steps-4-8 review):
//  * The timeout injections below throw DnsTimeoutException, which derives from
//    DnsTransportException, so they exercise the newly-added DnsTransportException
//    catch clauses in resolveHostname (A/AAAA), performServiceResolution (NAPTR),
//    and the direct-SRV / NAPTR-derived-SRV loops. All DnsTransportException
//    subtypes share the identical catch body, so the DnsTimeoutException subclass
//    suffices to prove a NON-timeout transport error also falls back rather than
//    aborting (review L-a / tracker test #5).
//  * The added DnsParseException catch clauses are DEFENSIVE and currently
//    UNREACHABLE: the transport drops-and-waits on a malformed datagram
//    (dns_transport.hpp:1804-1823, the -31 fix) so a parse failure surfaces as a
//    timeout, not a DnsParseException. They are kept per the human's
//    enumerate-the-three-types decision; there is intentionally no test for them
//    (review M-a / R2-M3). The -31 drop-and-wait behavior itself is regression-
//    guarded by -31's own suite and the parser tests in this file (review L-b).
//  * Tracker test #6 (-10 validateRdataSecurity false-positive AAAA drop must not
//    abort the sibling A) is UNCONSTRUCTABLE here: validateRdataSecurity has been
//    fully removed from the DNS tree. The general sibling-isolation mechanism is
//    covered by the dual-stack and SRV-sibling tests below (review M-b).
//  * Assertions match on exception TYPE / behavior, never on exact timeout
//    wording, which differs between the sync and async paths (review R2-L3).
// =============================================================================

namespace
{
/// \brief A DnsClient with a short timeout and no retries, pointed at the
/// fixture's mock server, so timeout-injection tests finish quickly.
/// Shared by the catch-scope regression tests and the "Very short timeout"
/// error-handling section (review L-g).
std::unique_ptr<DnsClient>
makeFastTimeoutClient(std::chrono::milliseconds timeout = std::chrono::milliseconds(150))
{
  DnsConfig cfg;
  cfg.setServers({"127.0.0.1:" + std::to_string(TEST_UDP_PORT)});
  cfg.timeout = timeout;
  cfg.retryCount = 0;
  cfg.transportMode = DnsTransportMode::UDP;
  cfg.enableCache = false;
  return std::make_unique<DnsClient>(cfg);
}
} // namespace

TEST_CASE_METHOD(DnsTestFixture,
                 "DNS resolveHostname keeps A results when AAAA times out",
                 "[dns][resolver][catch-scope][regression][ipv6]")
{
  startServer();
  server().addRecord({"dual.example.com", "A", "192.0.2.10", 3600});
  // AAAA query for the SAME name times out (per-type injection).
  MockDnsServer::QueryConfig aaaaTimeout;
  aaaaTimeout.shouldTimeout = true;
  server().configureQuery("dual.example.com", "AAAA", aaaaTimeout);

  auto fast = makeFastTimeoutClient();
  // IPv4First (default): before the fix the AAAA DnsTimeoutException escaped
  // resolveHostname and discarded the already-collected A result -> this threw.
  // After the fix the A result is retained and returned.
  std::vector<std::string> addrs;
  REQUIRE_NOTHROW(addrs = fast->resolveHostname("dual.example.com"));
  REQUIRE(addrs.size() == 1);
  CHECK(addrs[0] == "192.0.2.10");
}

TEST_CASE_METHOD(DnsTestFixture,
                 "DNS NAPTR timeout falls back to direct SRV instead of aborting",
                 "[dns][resolver][catch-scope][regression][rfc3263]")
{
  startServer();
  // NAPTR for the domain times out; the direct-SRV records still resolve.
  MockDnsServer::QueryConfig naptrTimeout;
  naptrTimeout.shouldTimeout = true;
  server().configureQuery("srvfallback.example.com", "NAPTR", naptrTimeout);
  server().addRecord(
    {"_sip._udp.srvfallback.example.com", "SRV", "sip1.srvfallback.example.com", 3600, 10, 5, 5060});
  server().addRecord({"sip1.srvfallback.example.com", "A", "192.0.2.20", 3600});

  auto fast = makeFastTimeoutClient();
  // Before the fix the NAPTR DnsTimeoutException escaped the NAPTR catch and
  // aborted resolution. After the fix it falls back to direct SRV (RFC 3263 4.1).
  auto result = fast->resolveServiceDomain("srvfallback.example.com");
  REQUIRE(result.isSuccess());
  REQUIRE_FALSE(result.targets.empty());
  bool found = false;
  for (const auto &t : result.targets)
  {
    if (t.hostname == "sip1.srvfallback.example.com")
    {
      found = true;
    }
  }
  CHECK(found);
}

TEST_CASE_METHOD(DnsTestFixture,
                 "DNS one SRV set timing out does not abort sibling SRV sets",
                 "[dns][resolver][catch-scope][regression][rfc3263]")
{
  startServer();
  // No NAPTR configured -> direct-SRV path queries _sips._tcp/_sip._tcp/_sip._udp.
  // Make the _sip._tcp SRV query time out; _sip._udp must still yield a target.
  MockDnsServer::QueryConfig srvTimeout;
  srvTimeout.shouldTimeout = true;
  server().configureQuery("_sip._tcp.sibling.example.com", "SRV", srvTimeout);
  server().addRecord(
    {"_sip._udp.sibling.example.com", "SRV", "u.sibling.example.com", 3600, 10, 5, 5060});
  server().addRecord({"u.sibling.example.com", "A", "192.0.2.30", 3600});

  auto fast = makeFastTimeoutClient();
  auto result = fast->resolveServiceDomain("sibling.example.com");
  REQUIRE(result.isSuccess());
  bool foundUdp = false;
  for (const auto &t : result.targets)
  {
    if (t.hostname == "u.sibling.example.com")
    {
      foundUdp = true;
    }
  }
  CHECK(foundUdp);
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

  SECTION("Weighted SRV selection distributes across an equal-priority group (RFC 2782)")
  {
    // Re-enabled (2026-09-25-4): MockDnsServer surfaces SRV weight (see the basic-SRV
    // section above), so the prior "MockDnsServer requirements" blocker is stale. One owner
    // name, one priority, two weighted targets (90/10). With a fixed seed the sequence is
    // deterministic; the head target's frequency tracks the weight split.
    server().addRecord({"_sip._udp.wsel.example.com", "SRV", "w90.example.com", 3600, 10, 90, 5060});
    server().addRecord({"_sip._udp.wsel.example.com", "SRV", "w10.example.com", 3600, 10, 10, 5060});
    server().addRecord({"w90.example.com", "A", "192.168.1.90", 3600});
    server().addRecord({"w10.example.com", "A", "192.168.1.10", 3600});

    client().setRngSeed(12345);
    int w90First = 0, w10First = 0;
    const int N = 400;
    for (int i = 0; i < N; ++i)
    {
      auto r = client().resolveServiceDomain("wsel.example.com", {ServiceType::SIP_UDP});
      REQUIRE_FALSE(r.targets.empty());
      if (r.targets.front().hostname == "w90.example.com")
      {
        ++w90First;
      }
      else if (r.targets.front().hostname == "w10.example.com")
      {
        ++w10First;
      }
    }
    CHECK(w90First + w10First == N);
    // Weight-90 dominates; weight-10 still wins sometimes (proves the RNG advances — a frozen
    // master would make one of these exactly 0). Generous tolerance for 400 samples.
    CHECK(w90First > w10First);
    CHECK(w90First > static_cast<int>(N * 0.75));
    CHECK(w10First > 0);
  }
}

TEST_CASE_METHOD(DnsTestFixture, "DNS SRV RFC 2782 per-owner-name ordering + weighting",
                 "[dns][srv][service-discovery][rfc2782][ordering]")
{
  startServer();

  SECTION("Cross-set priority: transports sequenced per set, priority never cross-compared")
  {
    // Direct-SRV (no NAPTR). TCP set has a WORSE (higher) SRV priority than the UDP set, but
    // TCP is the preferred transport (rank 0). The old (naptrPreference=0, priority) sort would
    // cross-compare priority and put UDP (prio 5) first; the fix sequences by transport rank, so
    // TCP (prio 10) leads. Priority is compared only WITHIN a set.
    server().addRecord({"_sip._tcp.xset.example.com", "SRV", "tcp.example.com", 3600, 10, 0, 5060});
    server().addRecord({"_sip._udp.xset.example.com", "SRV", "udp.example.com", 3600, 5, 0, 5060});
    server().addRecord({"tcp.example.com", "A", "192.168.1.10", 3600});
    server().addRecord({"udp.example.com", "A", "192.168.1.20", 3600});

    const std::vector<ServiceType> pref{ServiceType::SIP_TCP, ServiceType::SIP_UDP};

    auto check = [](const ServiceResolutionResult &r)
    {
      REQUIRE(r.targets.size() >= 2);
      // TCP (rank 0) must lead despite its worse SRV priority — no cross-set priority compare.
      CHECK(r.targets.front().transport == ServiceType::SIP_TCP);
      CHECK(r.targets.front().hostname == "tcp.example.com");
      // All TCP targets precede all UDP targets (owner-name-delimited sequencing).
      bool seenUdp = false;
      for (const auto &t : r.targets)
      {
        if (t.transport == ServiceType::SIP_UDP)
        {
          seenUdp = true;
        }
        else if (t.transport == ServiceType::SIP_TCP)
        {
          CHECK_FALSE(seenUdp); // no TCP after a UDP — not interleaved
        }
      }
    };

    check(client().resolveServiceDomain("xset.example.com", pref));    // sync
    check(resolveServiceBlocking(client(), "xset.example.com", pref)); // async
    // Re-resolved: this domain has NO NAPTR, so the NAPTR cache hit is negative and
    // processCachedServiceResolution can't produce targets — the call falls through to a fresh
    // direct-SRV resolution (SRV/A answers served from the DNS-answer cache), through the SAME
    // performDirectSrvResolution sort site as the sync run. Genuine processCachedServiceResolution
    // sort-site coverage comes from the NAPTR-backed tests below (iso / naptr-weight-iso).
    check(client().resolveServiceDomain("xset.example.com", pref));
  }

  SECTION("Owner-name PRIORITY isolation on the NAPTR equal-preference path (H1)")
  {
    // Two S-flag NAPTR services in ONE order tier with EQUAL preference (20). Their SRV sets
    // have DIFFERING priority (tcp 10, udp 5). The old outer key (naptrPreference, priority)
    // shares naptrPreference=20 and would interleave the two RRSets by raw priority (udp prio 5
    // first). The fix adds `transport` to the outer key, so the sets are never interleaved.
    auto naptr = [this](const std::string &svc, const std::string &repl)
    {
      MockDnsServer::DnsRecord n;
      n.name = "iso.example.com";
      n.type = "NAPTR";
      n.ttl = 3600;
      n.naptrOrder = 100;
      n.naptrPreference = 20;
      n.naptrFlags = "s";
      n.naptrService = svc;
      n.naptrReplacement = repl;
      server().addRecord(n);
    };
    naptr("SIP+D2T", "_sip._tcp.iso.example.com");
    naptr("SIP+D2U", "_sip._udp.iso.example.com");
    server().addRecord({"_sip._tcp.iso.example.com", "SRV", "t.example.com", 3600, 10, 0, 5060});
    server().addRecord({"_sip._udp.iso.example.com", "SRV", "u.example.com", 3600, 5, 0, 5060});
    server().addRecord({"t.example.com", "A", "192.168.1.10", 3600});
    server().addRecord({"u.example.com", "A", "192.168.1.20", 3600});

    auto check = [](const ServiceResolutionResult &r)
    {
      REQUIRE(r.targets.size() >= 2);
      // Not interleaved by raw priority: one transport's whole RRSet, then the other's.
      bool seenUdp = false;
      for (const auto &t : r.targets)
      {
        if (t.transport == ServiceType::SIP_UDP)
        {
          seenUdp = true;
        }
        else if (t.transport == ServiceType::SIP_TCP)
        {
          CHECK_FALSE(seenUdp);
        }
      }
      // TCP (enum-order first among equal tier) leads despite its higher priority number.
      CHECK(r.targets.front().transport == ServiceType::SIP_TCP);
    };

    check(client().resolveServiceDomain("iso.example.com"));       // sync
    check(resolveServiceBlocking(client(), "iso.example.com"));    // async
    check(client().resolveServiceDomain("iso.example.com"));       // cache-hit
  }

  SECTION("Within-owner-name multi-priority: priority dominates, no cross-priority weight pool")
  {
    // One owner name (_sip._udp), two priority tiers. prio 5 group {p5a w10, p5b w90};
    // prio 20 group {p20a w10, p20b w90}. Every prio-5 target must precede every prio-20
    // target; within prio 5 the head distribution tracks 10/90 with NO contribution from the
    // prio-20 weights (weights summed per (transport, priority) group only).
    server().addRecord({"_sip._udp.mp.example.com", "SRV", "p5a.example.com", 3600, 5, 10, 5060});
    server().addRecord({"_sip._udp.mp.example.com", "SRV", "p5b.example.com", 3600, 5, 90, 5060});
    server().addRecord({"_sip._udp.mp.example.com", "SRV", "p20a.example.com", 3600, 20, 10, 5060});
    server().addRecord({"_sip._udp.mp.example.com", "SRV", "p20b.example.com", 3600, 20, 90, 5060});
    for (const char *h : {"p5a", "p5b", "p20a", "p20b"})
    {
      server().addRecord({std::string(h) + ".example.com", "A", "192.168.1.1", 3600});
    }

    client().setRngSeed(999);
    int p5bFirst = 0, p5aFirst = 0;
    const int N = 400;
    for (int i = 0; i < N; ++i)
    {
      auto r = client().resolveServiceDomain("mp.example.com", {ServiceType::SIP_UDP});
      REQUIRE(r.targets.size() == 4);
      // Priority dominance: first two are the prio-5 group, last two the prio-20 group.
      CHECK(r.targets[0].priority == 5);
      CHECK(r.targets[1].priority == 5);
      CHECK(r.targets[2].priority == 20);
      CHECK(r.targets[3].priority == 20);
      if (r.targets.front().hostname == "p5b.example.com")
      {
        ++p5bFirst;
      }
      else if (r.targets.front().hostname == "p5a.example.com")
      {
        ++p5aFirst;
      }
    }
    CHECK(p5aFirst + p5bFirst == N);
    // 90/10 split within prio-5, unaffected by the identical prio-20 weights.
    CHECK(p5bFirst > p5aFirst);
    CHECK(p5bFirst > static_cast<int>(N * 0.75));
    CHECK(p5aFirst > 0);
  }

  SECTION("Weight-0 minimal chance: rare with a large positive sum {0,50,50}")
  {
    // One group {w0, w50, w50}. The weight-0 record wins the head only on draw==0 (~1/101);
    // the positive-weight records dominate.
    server().addRecord({"_sip._udp.w0.example.com", "SRV", "z.example.com", 3600, 10, 0, 5060});
    server().addRecord({"_sip._udp.w0.example.com", "SRV", "a.example.com", 3600, 10, 50, 5060});
    server().addRecord({"_sip._udp.w0.example.com", "SRV", "b.example.com", 3600, 10, 50, 5060});
    server().addRecord({"z.example.com", "A", "192.168.1.1", 3600});
    server().addRecord({"a.example.com", "A", "192.168.1.2", 3600});
    server().addRecord({"b.example.com", "A", "192.168.1.3", 3600});

    client().setRngSeed(7);
    int zeroFirst = 0;
    const int N = 400;
    for (int i = 0; i < N; ++i)
    {
      auto r = client().resolveServiceDomain("w0.example.com", {ServiceType::SIP_UDP});
      REQUIRE(r.targets.size() == 3);
      if (r.targets.front().hostname == "z.example.com")
      {
        ++zeroFirst;
      }
    }
    CHECK(zeroFirst < static_cast<int>(N * 0.15)); // rare, as the RFC "very small chance" intends
  }

  SECTION("RFC 2782 range fidelity: weight-0 IS selectable via the inclusive [0,sum] '>=' path")
  {
    // NON-VACUOUS discriminator for the [0,sum-1]+'<' zero-chance regression. Small-sum group
    // {w0, w1}: inclusive [0,1] draw -> P(weight-0 head) = 1/2, so over N seeded resolutions the
    // weight-0 record reaches the head MANY times. The old exclusive-range bug (dist(0,0)+'<')
    // gives the weight-0 record EXACTLY ZERO chance -> zeroFirst == 0, which this CHECK catches.
    server().addRecord({"_sip._udp.rf.example.com", "SRV", "z.example.com", 3600, 10, 0, 5060});
    server().addRecord({"_sip._udp.rf.example.com", "SRV", "o.example.com", 3600, 10, 1, 5060});
    server().addRecord({"z.example.com", "A", "192.168.1.1", 3600});
    server().addRecord({"o.example.com", "A", "192.168.1.2", 3600});

    client().setRngSeed(4242);
    int zeroFirst = 0, oneFirst = 0;
    const int N = 200;
    for (int i = 0; i < N; ++i)
    {
      auto r = client().resolveServiceDomain("rf.example.com", {ServiceType::SIP_UDP});
      REQUIRE(r.targets.size() == 2);
      if (r.targets.front().hostname == "z.example.com")
      {
        ++zeroFirst;
      }
      else if (r.targets.front().hostname == "o.example.com")
      {
        ++oneFirst;
      }
    }
    CHECK(zeroFirst + oneFirst == N);
    CHECK(zeroFirst > 0); // the guard: bug -> 0; correct inclusive-range -> ~N/2
    CHECK(oneFirst > 0);
  }

  SECTION("Multiple weight-0 records randomize among themselves {0,0,50,50}")
  {
    // Both weight-0 records must be able to reach the head across reseeds (guards the
    // std::shuffle of the weight-0 prefix — not only the first-arranged zero).
    server().addRecord({"_sip._udp.mz.example.com", "SRV", "z1.example.com", 3600, 10, 0, 5060});
    server().addRecord({"_sip._udp.mz.example.com", "SRV", "z2.example.com", 3600, 10, 0, 5060});
    server().addRecord({"_sip._udp.mz.example.com", "SRV", "p1.example.com", 3600, 10, 50, 5060});
    server().addRecord({"_sip._udp.mz.example.com", "SRV", "p2.example.com", 3600, 10, 50, 5060});
    for (const char *h : {"z1", "z2", "p1", "p2"})
    {
      server().addRecord({std::string(h) + ".example.com", "A", "192.168.1.1", 3600});
    }

    client().setRngSeed(31);
    // Across resolutions, look at the RELATIVE order of the two zeros among themselves (both are
    // at the tail after the positive records, but their internal order must vary with shuffle).
    int z1BeforeZ2 = 0, z2BeforeZ1 = 0;
    const int N = 200;
    for (int i = 0; i < N; ++i)
    {
      auto r = client().resolveServiceDomain("mz.example.com", {ServiceType::SIP_UDP});
      REQUIRE(r.targets.size() == 4);
      std::size_t iz1 = 5, iz2 = 5;
      for (std::size_t k = 0; k < r.targets.size(); ++k)
      {
        if (r.targets[k].hostname == "z1.example.com")
        {
          iz1 = k;
        }
        else if (r.targets[k].hostname == "z2.example.com")
        {
          iz2 = k;
        }
      }
      REQUIRE((iz1 != 5 && iz2 != 5));
      if (iz1 < iz2)
      {
        ++z1BeforeZ2;
      }
      else
      {
        ++z2BeforeZ1;
      }
    }
    // Shuffle among the zeros -> both orderings occur (a dropped shuffle would pin one order).
    CHECK(z1BeforeZ2 > 0);
    CHECK(z2BeforeZ1 > 0);
  }

  SECTION("All-weights-0 group orders uniformly (non-degenerate permutation)")
  {
    // remaining==0 branch: order is the shuffled arrangement -> the head varies across reseeds.
    server().addRecord({"_sip._udp.az.example.com", "SRV", "x.example.com", 3600, 10, 0, 5060});
    server().addRecord({"_sip._udp.az.example.com", "SRV", "y.example.com", 3600, 10, 0, 5060});
    server().addRecord({"_sip._udp.az.example.com", "SRV", "w.example.com", 3600, 10, 0, 5060});
    for (const char *h : {"x", "y", "w"})
    {
      server().addRecord({std::string(h) + ".example.com", "A", "192.168.1.1", 3600});
    }

    client().setRngSeed(88);
    int distinctHeads = 0;
    bool seenX = false, seenY = false, seenW = false;
    const int N = 200;
    for (int i = 0; i < N; ++i)
    {
      auto r = client().resolveServiceDomain("az.example.com", {ServiceType::SIP_UDP});
      REQUIRE(r.targets.size() == 3);
      const auto &h = r.targets.front().hostname;
      if (h == "x.example.com" && !seenX) { seenX = true; ++distinctHeads; }
      if (h == "y.example.com" && !seenY) { seenY = true; ++distinctHeads; }
      if (h == "w.example.com" && !seenW) { seenW = true; ++distinctHeads; }
    }
    CHECK(distinctHeads >= 2); // not pinned to one order
  }

  SECTION("Weighted distribution holds through the async + NAPTR cache-hit sort sites")
  {
    // The async (resolveTargetAddressesAsync) and NAPTR cache-hit (processCachedServiceResolution)
    // sort sites are distinct from the sync direct-SRV site; assert the 90/10 weighting there too.
    auto naptr = [this](const std::string &svc, const std::string &repl)
    {
      MockDnsServer::DnsRecord n;
      n.name = "wdist.example.com";
      n.type = "NAPTR";
      n.ttl = 3600;
      n.naptrOrder = 100;
      n.naptrPreference = 10;
      n.naptrFlags = "s";
      n.naptrService = svc;
      n.naptrReplacement = repl;
      server().addRecord(n);
    };
    naptr("SIP+D2U", "_sip._udp.wdist.example.com");
    server().addRecord({"_sip._udp.wdist.example.com", "SRV", "w90.example.com", 3600, 10, 90, 5060});
    server().addRecord({"_sip._udp.wdist.example.com", "SRV", "w10.example.com", 3600, 10, 10, 5060});
    server().addRecord({"w90.example.com", "A", "192.168.1.90", 3600});
    server().addRecord({"w10.example.com", "A", "192.168.1.10", 3600});

    // Warm the NAPTR cache with one sync resolve, then measure the async and cache-hit paths.
    (void)client().resolveServiceDomain("wdist.example.com");

    auto measure = [this](std::function<ServiceResolutionResult()> resolve)
    {
      client().setRngSeed(555);
      int w90First = 0, w10First = 0;
      const int N = 300;
      for (int i = 0; i < N; ++i)
      {
        auto r = resolve();
        REQUIRE_FALSE(r.targets.empty());
        if (r.targets.front().hostname == "w90.example.com")
        {
          ++w90First;
        }
        else if (r.targets.front().hostname == "w10.example.com")
        {
          ++w10First;
        }
      }
      CHECK(w90First + w10First == N);
      CHECK(w90First > w10First);
      CHECK(w10First > 0); // proves the RNG advances on this path too
    };

    measure([this] { return resolveServiceBlocking(client(), "wdist.example.com"); }); // async
    measure([this] { return client().resolveServiceDomain("wdist.example.com"); });    // cache-hit
  }

  SECTION("Owner-name WEIGHT isolation on the NAPTR path: weights not pooled across RRSets")
  {
    // Two equal-preference NAPTR services, EQUAL SRV priority, DIFFERING weights per set. Weights
    // must be summed only within one owner name (transport), never pooled across the two RRSets.
    // Each transport's targets stay grouped; the weighted sub-order is per-set.
    auto naptr = [this](const std::string &svc, const std::string &repl)
    {
      MockDnsServer::DnsRecord n;
      n.name = "wiso.example.com";
      n.type = "NAPTR";
      n.ttl = 3600;
      n.naptrOrder = 100;
      n.naptrPreference = 20;
      n.naptrFlags = "s";
      n.naptrService = svc;
      n.naptrReplacement = repl;
      server().addRecord(n);
    };
    naptr("SIP+D2T", "_sip._tcp.wiso.example.com");
    naptr("SIP+D2U", "_sip._udp.wiso.example.com");
    server().addRecord({"_sip._tcp.wiso.example.com", "SRV", "t90.example.com", 3600, 10, 90, 5060});
    server().addRecord({"_sip._tcp.wiso.example.com", "SRV", "t10.example.com", 3600, 10, 10, 5060});
    server().addRecord({"_sip._udp.wiso.example.com", "SRV", "u90.example.com", 3600, 10, 90, 5060});
    server().addRecord({"_sip._udp.wiso.example.com", "SRV", "u10.example.com", 3600, 10, 10, 5060});
    for (const char *h : {"t90", "t10", "u90", "u10"})
    {
      server().addRecord({std::string(h) + ".example.com", "A", "192.168.1.1", 3600});
    }

    auto check = [](const ServiceResolutionResult &r)
    {
      REQUIRE(r.targets.size() == 4);
      // Grouped by transport (owner name): the first two are one transport, the last two the
      // other — never interleaved. This is what prevents cross-RRSet weight pooling.
      CHECK(r.targets[0].transport == r.targets[1].transport);
      CHECK(r.targets[2].transport == r.targets[3].transport);
      CHECK(r.targets[0].transport != r.targets[2].transport);
    };

    client().setRngSeed(17);
    // Also confirm the per-set weighted sub-order favors the weight-90 host within each transport,
    // independently, over many resolutions (no pooling would let a set's own 90 dominate its set).
    int tcp90First = 0, udp90First = 0;
    const int N = 200;
    for (int i = 0; i < N; ++i)
    {
      auto r = client().resolveServiceDomain("wiso.example.com");
      check(r);
      // find first target of each transport
      for (const auto &t : r.targets)
      {
        if (t.transport == ServiceType::SIP_TCP)
        {
          if (t.hostname == "t90.example.com") { ++tcp90First; }
          break;
        }
      }
      for (const auto &t : r.targets)
      {
        if (t.transport == ServiceType::SIP_UDP)
        {
          if (t.hostname == "u90.example.com") { ++udp90First; }
          break;
        }
      }
    }
    CHECK(tcp90First > static_cast<int>(N * 0.6)); // 90/10 within the TCP set
    CHECK(udp90First > static_cast<int>(N * 0.6)); // 90/10 within the UDP set, independently

    // sync + async + cache-hit ordering/grouping all hold.
    check(client().resolveServiceDomain("wiso.example.com"));
    check(resolveServiceBlocking(client(), "wiso.example.com"));
    check(client().resolveServiceDomain("wiso.example.com"));
  }

  SECTION("getPreferredTarget returns the ordered head and does not re-randomize")
  {
    server().addRecord({"_sip._udp.pt.example.com", "SRV", "h.example.com", 3600, 10, 50, 5060});
    server().addRecord({"h.example.com", "A", "192.168.1.9", 3600});

    client().setRngSeed(3);
    auto r = client().resolveServiceDomain("pt.example.com", {ServiceType::SIP_UDP});
    REQUIRE_FALSE(r.targets.empty());
    auto p1 = r.getPreferredTarget();
    auto p2 = r.getPreferredTarget();
    CHECK(p1.hostname == r.targets.front().hostname);
    CHECK(p1.hostname == p2.hostname); // stable, no re-draw
  }
}

// =============================================================================
// WIRE-FORMAT AND NETWORK BEHAVIOR TESTS
// =============================================================================

// Helpers for hand-assembled, socket-free wire-format parse KATs (DnsMessage::parse is static).
namespace
{
/// 12-byte DNS header with the given question/answer/authority/additional counts.
inline std::vector<std::uint8_t> dnsHeader(std::uint16_t qd, std::uint16_t an, std::uint16_t ns,
                                           std::uint16_t ar)
{
  return {0x12, 0x34, 0x81, 0x80,
          static_cast<std::uint8_t>(qd >> 8), static_cast<std::uint8_t>(qd & 0xFF),
          static_cast<std::uint8_t>(an >> 8), static_cast<std::uint8_t>(an & 0xFF),
          static_cast<std::uint8_t>(ns >> 8), static_cast<std::uint8_t>(ns & 0xFF),
          static_cast<std::uint8_t>(ar >> 8), static_cast<std::uint8_t>(ar & 0xFF)};
}
/// Question "test.com" A IN: occupies offsets 12..25 (name at offset 12); records begin at 26.
inline void appendTestComQuestion(std::vector<std::uint8_t> &m)
{
  const std::uint8_t q[] = {0x04, 't', 'e', 's', 't', 0x03, 'c', 'o', 'm', 0x00,
                            0x00, 0x01, 0x00, 0x01};
  m.insert(m.end(), std::begin(q), std::end(q));
}
inline void append(std::vector<std::uint8_t> &m, std::initializer_list<std::uint8_t> b)
{
  m.insert(m.end(), b.begin(), b.end());
}
} // namespace

// =============================================================================
// RFC 3263 §4.1 SIPS / secure hard-filter tests (tracker 2026-09-25-12, slice b2)
// =============================================================================

namespace
{
/// \brief True if any target uses a non-SIPS-SIP (plaintext or non-SIP) transport.
inline bool hasInsecureTarget(const ServiceResolutionResult &r)
{
  for (const auto &t : r.targets)
  {
    if (t.transport != ServiceType::SIPS_TLS && t.transport != ServiceType::SIPS_SCTP &&
        t.transport != ServiceType::SIPS_WSS)
    {
      return true;
    }
  }
  return false;
}

/// \brief Assert every target is a SIPS_TLS/5061 target and none is plaintext.
inline void checkAllTls5061(const ServiceResolutionResult &r)
{
  REQUIRE_FALSE(r.targets.empty());
  CHECK_FALSE(hasInsecureTarget(r));
  for (const auto &t : r.targets)
  {
    CHECK(t.transport == ServiceType::SIPS_TLS);
    CHECK(t.port == 5061);
  }
}

/// \brief Build a NAPTR record for the mock server (flags default to 'S').
inline MockDnsServer::DnsRecord naptr(const std::string &name, std::uint16_t order,
                                      std::uint16_t pref, const std::string &service,
                                      const std::string &replacement,
                                      const std::string &flags = "S")
{
  MockDnsServer::DnsRecord rec;
  rec.name = name;
  rec.type = "NAPTR";
  rec.naptrOrder = order;
  rec.naptrPreference = pref;
  rec.naptrFlags = flags;
  rec.naptrService = service;
  rec.naptrReplacement = replacement;
  return rec;
}
} // namespace

TEST_CASE_METHOD(DnsTestFixture, "DNS SIPS secure hard-filter (RFC 3263 4.1)",
                 "[dns][srv][sips][secure][rfc3263]")
{
  startServer();

  SECTION("Direct-SRV mixed preferredTransports: only _sips._tcp, zero plaintext (H-A)")
  {
    server().addRecord({"_sips._tcp.mix.example.com", "SRV", "tls.example.com", 3600, 10, 0, 5061});
    server().addRecord({"_sip._udp.mix.example.com", "SRV", "udp.example.com", 3600, 10, 0, 5060});
    server().addRecord({"_sip._tcp.mix.example.com", "SRV", "tcp.example.com", 3600, 10, 0, 5060});
    server().addRecord({"tls.example.com", "A", "192.168.2.1", 3600});
    server().addRecord({"udp.example.com", "A", "192.168.2.2", 3600});
    server().addRecord({"tcp.example.com", "A", "192.168.2.3", 3600});

    const std::vector<ServiceType> pref{ServiceType::SIP_UDP, ServiceType::SIP_TCP,
                                        ServiceType::SIPS_TLS};
    checkAllTls5061(client().resolveServiceDomain("mix.example.com", pref, /*secure=*/true)); // sync
    checkAllTls5061(resolveServiceBlocking(client(), "mix.example.com", pref, /*secure=*/true));
  }

  SECTION("NAPTR HTTPS+D2T is discarded for a sips: resolution (H-fold-1, 4.1)")
  {
    server().addRecord(
      naptr("svc.example.com", 10, 10, "SIPS+D2T", "_sips._tcp.svc.example.com"));
    server().addRecord(
      naptr("svc.example.com", 10, 20, "HTTPS+D2T", "_https._tcp.svc.example.com"));
    server().addRecord({"_sips._tcp.svc.example.com", "SRV", "tls.example.com", 3600, 10, 0, 5061});
    server().addRecord({"_https._tcp.svc.example.com", "SRV", "web.example.com", 3600, 10, 0, 443});
    server().addRecord({"tls.example.com", "A", "192.168.2.10", 3600});
    server().addRecord({"web.example.com", "A", "192.168.2.11", 3600});

    auto r = client().resolveServiceDomain("svc.example.com", {}, /*secure=*/true);
    REQUIRE_FALSE(r.targets.empty());
    CHECK_FALSE(hasInsecureTarget(r));
    for (const auto &t : r.targets)
    {
      CHECK(t.transport == ServiceType::SIPS_TLS);
      CHECK(t.hostname != "web.example.com");
    }
  }

  SECTION("NAPTR SIPS+D2S discarded when client supports only SIPS_TLS (M-fold-1, 4.1 support)")
  {
    server().addRecord(
      naptr("sctp.example.com", 10, 10, "SIPS+D2S", "_sips._sctp.sctp.example.com"));
    server().addRecord(
      naptr("sctp.example.com", 10, 20, "SIPS+D2T", "_sips._tcp.sctp.example.com"));
    server().addRecord(
      {"_sips._sctp.sctp.example.com", "SRV", "sctp1.example.com", 3600, 10, 0, 5061});
    server().addRecord({"_sips._tcp.sctp.example.com", "SRV", "tls1.example.com", 3600, 10, 0, 5061});
    server().addRecord({"sctp1.example.com", "A", "192.168.2.20", 3600});
    server().addRecord({"tls1.example.com", "A", "192.168.2.21", 3600});

    auto r = client().resolveServiceDomain("sctp.example.com", {ServiceType::SIPS_TLS}, true);
    REQUIRE_FALSE(r.targets.empty());
    for (const auto &t : r.targets)
    {
      CHECK(t.transport == ServiceType::SIPS_TLS);
      CHECK(t.transport != ServiceType::SIPS_SCTP);
    }
  }

  SECTION("Secure fallback: no SRV -> TLS/5061 A-fallback, never plaintext (4.1)")
  {
    server().addRecord({"fallback.example.com", "A", "192.168.2.30", 3600});
    checkAllTls5061(client().resolveServiceDomain("fallback.example.com", {}, true));
  }

  SECTION("Secure fallback on the ASYNC path -> TLS/5061, zero plaintext (L-1)")
  {
    server().addRecord({"afallback.example.com", "A", "192.168.2.31", 3600});
    checkAllTls5061(resolveServiceBlocking(client(), "afallback.example.com", {}, /*secure=*/true));
  }

  SECTION("Owner-name mapping: SIPS_SCTP preference queries _sips._sctp (M-b)")
  {
    server().addRecord(
      {"_sips._sctp.osctp.example.com", "SRV", "sctpx.example.com", 3600, 10, 0, 5061});
    server().addRecord({"sctpx.example.com", "A", "192.168.2.40", 3600});
    auto r = client().resolveServiceDomain("osctp.example.com", {ServiceType::SIPS_SCTP}, true);
    REQUIRE_FALSE(r.targets.empty());
    bool found = false;
    for (const auto &t : r.targets)
    {
      CHECK(t.transport == ServiceType::SIPS_SCTP);
      if (t.hostname == "sctpx.example.com")
      {
        found = true;
      }
    }
    CHECK(found);
  }

  SECTION("Empty preferredTransports + secure on direct-SRV queries only _sips._tcp (L3)")
  {
    server().addRecord({"_sips._tcp.eps.example.com", "SRV", "epstls.example.com", 3600, 10, 0, 5061});
    server().addRecord({"_sip._udp.eps.example.com", "SRV", "epsudp.example.com", 3600, 10, 0, 5060});
    server().addRecord({"epstls.example.com", "A", "192.168.2.50", 3600});
    server().addRecord({"epsudp.example.com", "A", "192.168.2.51", 3600});
    auto r = client().resolveServiceDomain("eps.example.com", {}, true);
    REQUIRE_FALSE(r.targets.empty());
    CHECK_FALSE(hasInsecureTarget(r));
    for (const auto &t : r.targets)
    {
      CHECK(t.transport == ServiceType::SIPS_TLS);
    }
  }

  SECTION("Async custom-SRV + secure filters plaintext custom queries (cpp17 HIGH-1)")
  {
    server().addRecord(
      {"_sips._tcp.cust.example.com", "SRV", "custtls.example.com", 3600, 10, 0, 5061});
    server().addRecord({"_sip._udp.cust.example.com", "SRV", "custudp.example.com", 3600, 10, 0, 5060});
    server().addRecord({"custtls.example.com", "A", "192.168.2.60", 3600});
    server().addRecord({"custudp.example.com", "A", "192.168.2.61", 3600});

    std::vector<std::pair<std::string, ServiceType>> custom{
      {"_sips._tcp.cust.example.com", ServiceType::SIPS_TLS},
      {"_sip._udp.cust.example.com", ServiceType::SIP_UDP}};

    auto prom = std::make_shared<std::promise<ServiceResolutionResult>>();
    auto fut = prom->get_future();
    client().resolveCustomServiceDomainAsync(
      "cust.example.com", custom,
      [prom](const ServiceResolutionResult &r, const std::exception_ptr &) { prom->set_value(r); },
      {}, /*secure=*/true);
    REQUIRE(fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    auto r = fut.get();
    REQUIRE_FALSE(r.targets.empty());
    CHECK_FALSE(hasInsecureTarget(r));
    for (const auto &t : r.targets)
    {
      CHECK(t.transport == ServiceType::SIPS_TLS);
    }
  }

  SECTION("Plain sip: supported-set discards an unsupported published transport (M-a)")
  {
    server().addRecord({"_sip._tcp.plain.example.com", "SRV", "ptcp.example.com", 3600, 10, 0, 5060});
    server().addRecord({"_sip._udp.plain.example.com", "SRV", "pudp.example.com", 3600, 10, 0, 5060});
    server().addRecord({"ptcp.example.com", "A", "192.168.2.70", 3600});
    server().addRecord({"pudp.example.com", "A", "192.168.2.71", 3600});
    // Client supports only UDP -> the published TCP target must be DISCARDED, not trailing.
    auto r = client().resolveServiceDomain("plain.example.com", {ServiceType::SIP_UDP});
    REQUIRE_FALSE(r.targets.empty());
    for (const auto &t : r.targets)
    {
      CHECK(t.transport == ServiceType::SIP_UDP);
    }
  }

  SECTION("SIPS+D2U NAPTR yields no SIPS-over-UDP target (SIPS+D2U SHOULD NOT exist, 4.1)")
  {
    server().addRecord(
      naptr("d2u.example.com", 10, 10, "SIPS+D2U", "_sips._udp.d2u.example.com"));
    server().addRecord({"_sips._udp.d2u.example.com", "SRV", "x.example.com", 3600, 10, 0, 5061});
    server().addRecord({"x.example.com", "A", "192.168.2.80", 3600});
    // Give the domain a bare A record so the secure fallback yields a NON-EMPTY TLS/5061
    // set — the loop below is then a real (non-vacuous) check that the _sips._udp SRV host
    // was never followed.
    server().addRecord({"d2u.example.com", "A", "192.168.2.81", 3600});
    // SIPS+D2U parses to Unknown -> discarded; the _sips._udp SRV is never queried; the
    // resolution falls back to a TLS/5061 target on d2u.example.com's A record.
    auto r = client().resolveServiceDomain("d2u.example.com", {}, true);
    checkAllTls5061(r);
    for (const auto &t : r.targets)
    {
      CHECK(t.hostname != "x.example.com");
    }
  }

  SECTION("Cache-hit secure resolution still filters plaintext (M1, steady-state 4.1)")
  {
    server().addRecord(
      naptr("cache.example.com", 10, 10, "SIPS+D2T", "_sips._tcp.cache.example.com"));
    server().addRecord(naptr("cache.example.com", 10, 20, "SIP+D2U", "_sip._udp.cache.example.com"));
    server().addRecord({"_sips._tcp.cache.example.com", "SRV", "ctls.example.com", 3600, 10, 0, 5061});
    server().addRecord({"_sip._udp.cache.example.com", "SRV", "cudp.example.com", 3600, 10, 0, 5060});
    server().addRecord({"ctls.example.com", "A", "192.168.2.90", 3600});
    server().addRecord({"cudp.example.com", "A", "192.168.2.91", 3600});

    // First resolution populates the NAPTR/SRV/A caches.
    auto first = client().resolveServiceDomain("cache.example.com", {}, /*secure=*/true);
    REQUIRE_FALSE(first.targets.empty());
    CHECK_FALSE(hasInsecureTarget(first));
    // Second resolution takes the NAPTR cache hit -> processCachedServiceResolution(secure);
    // the SIPS filter must still hold on the steady-state path.
    auto second = client().resolveServiceDomain("cache.example.com", {}, /*secure=*/true);
    REQUIRE_FALSE(second.targets.empty());
    CHECK(second.fromCache);
    CHECK_FALSE(hasInsecureTarget(second));
    // Async cache path too.
    auto asyncR = resolveServiceBlocking(client(), "cache.example.com", {}, /*secure=*/true);
    REQUIRE_FALSE(asyncR.targets.empty());
    CHECK_FALSE(hasInsecureTarget(asyncR));
  }

  SECTION("Secure SRV '.' denial yields no target and no plaintext (M2, RFC 2782 + 4.1)")
  {
    // _sips._tcp explicitly denied ("."); no other secure service. The secure fallback must be
    // suppressed for the denied service -> no target, and never a plaintext leak from the A record.
    server().addRecord({"_sips._tcp.deny.example.com", "SRV", ".", 3600, 0, 0, 5060});
    server().addRecord({"deny.example.com", "A", "192.168.2.100", 3600});
    auto r = client().resolveServiceDomain("deny.example.com", {}, /*secure=*/true);
    CHECK(r.targets.empty());
    CHECK_FALSE(hasInsecureTarget(r));
  }

  SECTION("Secure discard applies to an 'A'-flag NAPTR target too (M3, 4.1)")
  {
    // Mixed NAPTR: an 'S'-flag SIPS service + an 'A'-flag plaintext service. Under secure the
    // plaintext direct-A target must be discarded, not just the SRV one.
    server().addRecord(
      naptr("aflag.example.com", 10, 10, "SIPS+D2T", "_sips._tcp.aflag.example.com"));
    server().addRecord(
      naptr("aflag.example.com", 10, 20, "SIP+D2U", "sipudp.aflag.example.com", /*flags=*/"A"));
    server().addRecord({"_sips._tcp.aflag.example.com", "SRV", "atls.example.com", 3600, 10, 0, 5061});
    server().addRecord({"atls.example.com", "A", "192.168.2.110", 3600});
    server().addRecord({"sipudp.aflag.example.com", "A", "192.168.2.111", 3600});
    auto r = client().resolveServiceDomain("aflag.example.com", {}, /*secure=*/true);
    REQUIRE_FALSE(r.targets.empty());
    CHECK_FALSE(hasInsecureTarget(r));
    for (const auto &t : r.targets)
    {
      CHECK(t.hostname != "sipudp.aflag.example.com");
    }
  }

  SECTION("resolveServiceDomainFuture under secure filters plaintext (M4)")
  {
    server().addRecord({"_sips._tcp.fut.example.com", "SRV", "futtls.example.com", 3600, 10, 0, 5061});
    server().addRecord({"_sip._udp.fut.example.com", "SRV", "futudp.example.com", 3600, 10, 0, 5060});
    server().addRecord({"futtls.example.com", "A", "192.168.2.120", 3600});
    server().addRecord({"futudp.example.com", "A", "192.168.2.121", 3600});
    auto cf = client().resolveServiceDomainFuture(
      "fut.example.com", {ServiceType::SIP_UDP, ServiceType::SIPS_TLS}, /*secure=*/true);
    REQUIRE(cf.future.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    auto r = cf.future.get();
    REQUIRE_FALSE(r.targets.empty());
    CHECK_FALSE(hasInsecureTarget(r));
  }

  SECTION("Owner-name mapping: SIPS_WSS preference queries _sips._wss (M5, M-b)")
  {
    server().addRecord({"_sips._wss.owss.example.com", "SRV", "wssx.example.com", 3600, 10, 0, 443});
    server().addRecord({"wssx.example.com", "A", "192.168.2.130", 3600});
    auto r = client().resolveServiceDomain("owss.example.com", {ServiceType::SIPS_WSS}, true);
    REQUIRE_FALSE(r.targets.empty());
    bool found = false;
    for (const auto &t : r.targets)
    {
      CHECK(t.transport == ServiceType::SIPS_WSS);
      if (t.hostname == "wssx.example.com")
      {
        found = true;
      }
    }
    CHECK(found);
  }

  SECTION("Plain sip: NAPTR path discards an unsupported published transport (M6, M-a parity)")
  {
    // NAPTR publishes SIP+D2U and SIP+D2S; client supports only UDP -> the SCTP service must be
    // discarded on the NAPTR path (parity with the direct-SRV supported-set discard).
    server().addRecord(naptr("pnaptr.example.com", 10, 10, "SIP+D2U", "_sip._udp.pnaptr.example.com"));
    server().addRecord(naptr("pnaptr.example.com", 10, 20, "SIP+D2S", "_sip._sctp.pnaptr.example.com"));
    server().addRecord({"_sip._udp.pnaptr.example.com", "SRV", "nudp.example.com", 3600, 10, 0, 5060});
    server().addRecord({"_sip._sctp.pnaptr.example.com", "SRV", "nsctp.example.com", 3600, 10, 0, 5060});
    server().addRecord({"nudp.example.com", "A", "192.168.2.140", 3600});
    server().addRecord({"nsctp.example.com", "A", "192.168.2.141", 3600});
    auto r = client().resolveServiceDomain("pnaptr.example.com", {ServiceType::SIP_UDP});
    REQUIRE_FALSE(r.targets.empty());
    for (const auto &t : r.targets)
    {
      CHECK(t.transport == ServiceType::SIP_UDP);
    }
  }
}

// Post-fix behavior of removing validateRdataSecurity (the bogus 0xC0 RDATA byte-scan +
// A-record 192.[0-63].0.0 heuristic). RDATA is never compression-decoded, so a 0xC0 byte in
// A/AAAA/TXT RDATA is ordinary data and must not fail the record, let alone the whole message.
TEST_CASE("DNS Parser removes the bogus RDATA compression scan (post-fix)",
          "[dns][parser][security]")
{
  SECTION("size-4 A record whose RDATA leads with 0xC0 parses as an address")
  {
    // Pre-fix: validateRdataSecurity rejected c0 20 00 00 as a 'malicious compression pointer'.
    auto m = dnsHeader(1, 1, 0, 0);
    appendTestComQuestion(m);
    append(m, {0xc0, 0x0c,             // NAME -> question name (offset 12)
               0x00, 0x01,             // TYPE=A
               0x00, 0x01,             // CLASS=IN
               0x00, 0x00, 0x0e, 0x10, // TTL
               0x00, 0x04,             // RDLENGTH=4
               0xc0, 0x20, 0x00, 0x00}); // RDATA = 192.32.0.0
    DnsResult r;
    REQUIRE_NOTHROW(r = DnsMessage::parse(m));
    REQUIRE(r.answers.size() == 1);
    REQUIRE(r.answers[0].type == DnsType::A);
    REQUIRE(r.a_records.size() == 1);
    REQUIRE(r.a_records[0].address == "192.32.0.0");
  }

  SECTION("wrong-length A record is dropped per-record; the message still parses")
  {
    // Pre-fix: the wrong-length-with-0xC0 branch threw out of the WHOLE message.
    auto m = dnsHeader(1, 1, 0, 0);
    appendTestComQuestion(m);
    append(m, {0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
               0x00, 0x02,   // RDLENGTH=2 (invalid for an A record)
               0xc0, 0xff}); // 2-byte RDATA
    DnsResult r;
    REQUIRE_NOTHROW(r = DnsMessage::parse(m));
    REQUIRE(r.a_records.empty());   // parseARecord threw inside the per-record catch -> dropped
    REQUIRE(r.answers.size() == 1); // the raw RR is still present
    REQUIRE(r.answers[0].rdlength == 2);
  }

  SECTION("size-4 A record 192.0.0.0 (the recorded reproducer) parses")
  {
    // 192.0.0.0 == c0 00 00 00 sits in the deleted A heuristic's 192.[0-63].0.0 range.
    auto m = dnsHeader(1, 1, 0, 0);
    appendTestComQuestion(m);
    append(m, {0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
               0x00, 0x04,               // RDLENGTH=4
               0xc0, 0x00, 0x00, 0x00}); // RDATA = 192.0.0.0
    DnsResult r;
    REQUIRE_NOTHROW(r = DnsMessage::parse(m));
    REQUIRE(r.a_records.size() == 1);
    REQUIRE(r.a_records[0].address == "192.0.0.0");
  }
}

// The real compression-pointer defense lives in the NAME decoder, not the deleted RDATA scan.
// These drive decodeName through actual NAME fields (the old A-RDATA 'security' tests never did).
TEST_CASE("DNS Parser NAME-field compression safety", "[dns][parser][security]")
{
  SECTION("self-referential compression-pointer loop is rejected")
  {
    auto m = dnsHeader(1, 1, 0, 0);
    appendTestComQuestion(m);
    append(m, {0xc0, 0x1a}); // answer NAME at offset 26 -> pointer to offset 26 (itself) => loop
    REQUIRE_THROWS_AS(DnsMessage::parse(m), DnsParseException);
  }

  SECTION("out-of-bounds compression pointer is rejected")
  {
    auto m = dnsHeader(1, 1, 0, 0);
    appendTestComQuestion(m);
    append(m, {0xc0, 0xff}); // answer NAME -> pointer to offset 255 (beyond the message)
    REQUIRE_THROWS_AS(DnsMessage::parse(m), DnsParseException);
  }

  SECTION("valid compression pointer in CNAME RDATA resolves")
  {
    auto m = dnsHeader(1, 1, 0, 0);
    appendTestComQuestion(m);
    append(m, {0xc0, 0x0c,             // NAME -> "test.com"
               0x00, 0x05,             // TYPE=CNAME
               0x00, 0x01,             // CLASS=IN
               0x00, 0x00, 0x0e, 0x10, // TTL
               0x00, 0x02,             // RDLENGTH=2
               0xc0, 0x0c});           // RDATA: compressed name -> "test.com"
    DnsResult r;
    REQUIRE_NOTHROW(r = DnsMessage::parse(m));
    REQUIRE(r.cname_records.size() == 1);
    REQUIRE(r.cname_records[0].cname == "test.com");
  }

  SECTION("SOA with compressed MNAME and RNAME resolves both names")
  {
    auto m = dnsHeader(1, 0, 1, 0); // one authority record
    appendTestComQuestion(m);
    append(m, {0xc0, 0x0c,             // NAME -> "test.com"
               0x00, 0x06,             // TYPE=SOA
               0x00, 0x01,             // CLASS=IN
               0x00, 0x00, 0x0e, 0x10, // TTL
               0x00, 0x18,             // RDLENGTH=24 (2 + 2 + 20)
               0xc0, 0x0c,             // MNAME -> "test.com"
               0xc0, 0x0c,             // RNAME -> "test.com"
               0x00, 0x00, 0x00, 0x01, // SERIAL
               0x00, 0x00, 0x0e, 0x10, // REFRESH
               0x00, 0x00, 0x07, 0x08, // RETRY
               0x00, 0x00, 0x1c, 0x20, // EXPIRE
               0x00, 0x00, 0x00, 0x3c}); // MINIMUM
    DnsResult r;
    REQUIRE_NOTHROW(r = DnsMessage::parse(m));
    REQUIRE(r.soa_records.size() == 1);
    REQUIRE(r.soa_records[0].mname == "test.com");
    REQUIRE(r.soa_records[0].rname == "test.com");
  }
}

// RDATA bytes with the 0xC0 mask set are legitimate data; the deleted scan false-rejected them.
TEST_CASE("DNS Parser accepts RDATA bytes with the 0xC0 mask (false-reject regression)",
          "[dns][parser][security]")
{
  SECTION("AAAA with high-order octets (fe80::, fc00::, 2607:f8b0::) is accepted")
  {
    auto m = dnsHeader(1, 3, 0, 0);
    appendTestComQuestion(m);
    auto aaaa = [&m](std::initializer_list<std::uint8_t> addr) {
      append(m, {0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x10});
      append(m, addr);
    };
    aaaa({0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}); // fe80::1 (0xfe >= 0xC0)
    aaaa({0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}); // fc00::1 (0xfc >= 0xC0)
    aaaa({0x26, 0x07, 0xf8, 0xb0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}); // 2607:f8b0::1
    DnsResult r;
    REQUIRE_NOTHROW(r = DnsMessage::parse(m));
    REQUIRE(r.aaaa_records.size() == 3);
  }

  SECTION("TXT with a >=192-byte character-string and high bytes is accepted")
  {
    auto m = dnsHeader(1, 1, 0, 0);
    appendTestComQuestion(m);
    const std::size_t txtLen = 200; // length octet 0xC8 has the 0xC0 bits set (pre-fix tripped it)
    const std::uint16_t rdlen = static_cast<std::uint16_t>(1 + txtLen);
    append(m, {0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
               static_cast<std::uint8_t>(rdlen >> 8), static_cast<std::uint8_t>(rdlen & 0xFF)});
    m.push_back(static_cast<std::uint8_t>(txtLen)); // character-string length octet
    m.insert(m.end(), txtLen, 0xC2);                // 200 content bytes, each >= 0xC0
    DnsResult r;
    REQUIRE_NOTHROW(r = DnsMessage::parse(m));
    REQUIRE(r.txt_records.size() == 1);
    REQUIRE(r.txt_records[0].text.size() == 1);
    REQUIRE(r.txt_records[0].text[0].size() == txtLen);
  }

  SECTION("multi-string TXT RDATA parses every character-string")
  {
    auto m = dnsHeader(1, 1, 0, 0);
    appendTestComQuestion(m);
    std::vector<std::uint8_t> rdata;
    auto addStr = [&rdata](std::size_t n, std::uint8_t fill) {
      rdata.push_back(static_cast<std::uint8_t>(n));
      rdata.insert(rdata.end(), n, fill);
    };
    addStr(255, 0x41); // "A" x255
    addStr(255, 0x42); // "B" x255
    addStr(3, 0x43);   // "CCC"
    const std::uint16_t rdlen = static_cast<std::uint16_t>(rdata.size()); // 516
    append(m, {0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
               static_cast<std::uint8_t>(rdlen >> 8), static_cast<std::uint8_t>(rdlen & 0xFF)});
    m.insert(m.end(), rdata.begin(), rdata.end());
    DnsResult r;
    REQUIRE_NOTHROW(r = DnsMessage::parse(m));
    REQUIRE(r.txt_records.size() == 1);
    REQUIRE(r.txt_records[0].text.size() == 3);
    REQUIRE(r.txt_records[0].text[0].size() == 255);
    REQUIRE(r.txt_records[0].text[1].size() == 255);
    REQUIRE(r.txt_records[0].text[2].size() == 3);
  }

  SECTION("truncated trailing TXT character-string is dropped without error")
  {
    // Exercises parseTxtRecord's overflow-safe `len > size() - offset` break branch.
    auto m = dnsHeader(1, 1, 0, 0);
    appendTestComQuestion(m);
    // One complete 3-byte string, then a length octet (5) claiming more than the 2 bytes left.
    const std::uint8_t rdata[] = {0x03, 'a', 'b', 'c', 0x05, 'x', 'y'};
    const std::uint16_t rdlen = static_cast<std::uint16_t>(sizeof(rdata)); // 7
    append(m, {0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
               static_cast<std::uint8_t>(rdlen >> 8), static_cast<std::uint8_t>(rdlen & 0xFF)});
    m.insert(m.end(), std::begin(rdata), std::end(rdata));
    DnsResult r;
    REQUIRE_NOTHROW(r = DnsMessage::parse(m));
    REQUIRE(r.txt_records.size() == 1);
    REQUIRE(r.txt_records[0].text.size() == 1); // the truncated trailer is dropped, not an error
    REQUIRE(r.txt_records[0].text[0] == "abc");
  }

  SECTION("valid UTF-8 TXT content round-trips byte-exact")
  {
    auto m = dnsHeader(1, 1, 0, 0);
    appendTestComQuestion(m);
    const std::uint8_t utf8[] = {0x63, 0x61, 0x66, 0xC3, 0xA9}; // "café" (0xC3 lead byte >= 0xC0)
    const std::uint8_t clen = static_cast<std::uint8_t>(sizeof(utf8)); // 5
    const std::uint16_t rdlen = static_cast<std::uint16_t>(1 + clen);
    append(m, {0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
               static_cast<std::uint8_t>(rdlen >> 8), static_cast<std::uint8_t>(rdlen & 0xFF)});
    m.push_back(clen);
    m.insert(m.end(), std::begin(utf8), std::end(utf8));
    DnsResult r;
    REQUIRE_NOTHROW(r = DnsMessage::parse(m));
    REQUIRE(r.txt_records.size() == 1);
    REQUIRE(r.txt_records[0].text.size() == 1);
    REQUIRE(r.txt_records[0].text[0] == std::string("caf\xC3\xA9"));
  }
}

// Malformed RDATA must not crash (the original zero-length SEGV) or force a large allocation.
TEST_CASE("DNS Parser malformed-RDATA robustness", "[dns][parser][security]")
{
  SECTION("zero-length TXT and AAAA RDATA do not crash")
  {
    // Pre-fix: `for (i=0; i < rdata.size()-1; ++i)` underflowed to SIZE_MAX -> OOB read -> SEGV.
    auto m = dnsHeader(1, 2, 0, 0);
    appendTestComQuestion(m);
    append(m, {0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00}); // TXT r=0
    append(m, {0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00}); // AAAA r=0
    DnsResult r;
    REQUIRE_NOTHROW(r = DnsMessage::parse(m));
    REQUIRE(r.answers.size() == 2);
    REQUIRE(r.aaaa_records.empty());    // zero-length AAAA rejected per-record
    REQUIRE(r.txt_records.size() == 1); // zero-length TXT accepted as empty
    REQUIRE(r.txt_records[0].text.empty());
  }

  SECTION("zero-length A RDATA is rejected per-record; the message still parses")
  {
    auto m = dnsHeader(1, 1, 0, 0);
    appendTestComQuestion(m);
    append(m, {0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00}); // A rdlen=0
    DnsResult r;
    REQUIRE_NOTHROW(r = DnsMessage::parse(m));
    REQUIRE(r.a_records.empty());   // size != 4 threw inside the per-record catch -> dropped
    REQUIRE(r.answers.size() == 1); // the raw RR is still present
  }

  SECTION("rdlength exceeding the remaining bytes is rejected cleanly")
  {
    auto m = dnsHeader(1, 1, 0, 0);
    appendTestComQuestion(m);
    append(m, {0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
               0x00, 0x40}); // RDLENGTH=64 with no RDATA following
    REQUIRE_THROWS_AS(DnsMessage::parse(m), DnsParseException);
  }

  SECTION("oversized section counts do not force a large allocation")
  {
    // A header claiming 0xFFFF records per section with no record bytes: clampReserveCount caps
    // each reserve() to (bytesRemaining / MIN_RR_SIZE) == 0, so parse returns promptly (throwing
    // on the first absent record) instead of reserving tens of MB. The clamp arithmetic itself is
    // verified directly by the "DNS clampReserveCount ..." unit test below; here we drive each of
    // the four clamp CALL SITES (questions / answers / authority / additional).
    REQUIRE_THROWS_AS(DnsMessage::parse(dnsHeader(0xFFFF, 0, 0, 0)), DnsParseException); // questions
    REQUIRE_THROWS_AS(DnsMessage::parse(dnsHeader(0, 0xFFFF, 0, 0)), DnsParseException); // answers
    REQUIRE_THROWS_AS(DnsMessage::parse(dnsHeader(0, 0, 0xFFFF, 0)), DnsParseException); // authority
    REQUIRE_THROWS_AS(DnsMessage::parse(dnsHeader(0, 0, 0, 0xFFFF)), DnsParseException); // additional
  }
}

// White-box unit test for the memory-amplification guard: this discriminates the clamp
// (min(count, bytes/minSize)) that the parse()-level KATs above cannot observe, because a lying
// header count always throws before parse() returns a result whose capacity could be inspected.
TEST_CASE("DNS clampReserveCount bounds untrusted counts", "[dns][parser][security]")
{
  using iora::network::dns::detail::clampReserveCount;
  // A lying count with no (or too few) backing bytes clamps to 0.
  REQUIRE(clampReserveCount(0xFFFF, 0, 11) == 0);
  REQUIRE(clampReserveCount(0xFFFF, 10, 11) == 0);
  REQUIRE(clampReserveCount(0xFFFF, 0, 5) == 0);
  // A count the remaining bytes can hold passes through unchanged.
  REQUIRE(clampReserveCount(3, 33, 11) == 3);  // 33/11 == 3, count is the bound
  REQUIRE(clampReserveCount(3, 100, 11) == 3); // count still the smaller bound
  REQUIRE(clampReserveCount(10, 33, 11) == 3); // bytes are the smaller bound -> clamped down
  REQUIRE(clampReserveCount(2, 10, 5) == 2);   // question floor (min size 5)
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
    // Create a client with very short timeout to test transport layer timeout
    // precision (shared short-timeout builder — review L-g).
    auto shortTimeoutClientPtr = makeFastTimeoutClient(std::chrono::milliseconds(50));
    DnsClient &shortTimeoutClient = *shortTimeoutClientPtr;

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

    auto prom = std::make_shared<std::promise<ServiceResolutionResult>>();
    auto fut = prom->get_future();
    client().resolveServiceDomainAsync(
      "adenied.example.com",
      [prom](const ServiceResolutionResult &r, const std::exception_ptr &)
      { prom->set_value(r); },
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

    auto prom = std::make_shared<std::promise<bool>>();
    auto fut = prom->get_future();
    std::vector<std::pair<std::string, ServiceType>> emptyQueries;
    client().resolveCustomServiceDomainAsync(
      "h1.example.com", emptyQueries,
      [prom](const ServiceResolutionResult &, const std::exception_ptr &)
      { prom->set_value(true); });

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

    auto prom = std::make_shared<std::promise<ServiceResolutionResult>>();
    auto fut = prom->get_future();
    client().resolveServiceDomainAsync(
      "apersvc.example.com",
      [prom](const ServiceResolutionResult &r, const std::exception_ptr &) { prom->set_value(r); },
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