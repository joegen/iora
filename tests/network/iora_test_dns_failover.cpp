// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_dns_failover.cpp
/// \brief DnsResolver next-server failover (RFC 1035 §7.2) + PER-AVENUE
///        transient/permanent ResolutionOutcome (tracker 2026-09-25-8, Slice A).
///
/// A recursive-resolver server-local failure -- an rcode-bearing negative
/// (SERVFAIL/REFUSED/FORMERR/NOTIMP/NODATA-without-SOA) OR a thrown transport
/// fault (timeout, connect/send failure) -- must fail over to the next configured
/// server (excluding tried), sync + async + A/AAAA, terminating on the first
/// authoritative response. An authoritative negative (NXDOMAIN / NODATA-with-SOA)
/// must NOT rotate. A single resolution avenue publishes a per-avenue
/// ResolutionOutcome { Resolved, TransientFailure, PermanentNoService }.
///
/// Two test styles (mirroring iora_test_dns_address_policy.cpp):
///  * WIRE (two MockDnsServer instances, real UDP): rcode/timeout failover across
///    real servers; per-server getStatistics().udpQueries proves which server was
///    hit and that a failed server is not re-queried.
///  * THROWING/FAULTY-DOUBLE (a DnsResolver built with an injectable DnsTransport
///    subclass that records/branches on the server arg): the connect/send-failure
///    (DnsNetworkException) + synchronous-issue-throw + lifecycle-terminal paths the
///    wire mock cannot reach, asserting exactly-once completion (no hang, no double).

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "MockDnsServer.hpp"
#include "iora/network/dns/dns_cache.hpp"
#include "iora/network/dns/dns_resolver.hpp"
#include "iora/network/dns/dns_transport.hpp"
#include "iora/network/dns/dns_types.hpp"

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace iora::network::dns;

namespace
{
// Distinct port block from the other DNS suites (comprehensive=15353, address_policy=15453).
constexpr std::uint16_t PORT_A = 15553;
constexpr std::uint16_t PORT_B = 15554;
constexpr std::uint16_t PORT_C = 15555;
constexpr std::uint16_t PORT_DEAD = 15559; // nothing binds here (connect-refused / timeout)

constexpr std::chrono::milliseconds STARTUP_DELAY{150};
constexpr std::chrono::milliseconds SHORT_TIMEOUT{400};

/// \brief One MockDnsServer instance on a dedicated port, started for its lifetime.
/// getStats().udpQueries proves per-server which server a lookup actually hit — the
/// observable that a failed server is not re-queried (tracker 2026-09-25-8).
struct MockNode
{
  std::unique_ptr<MockDnsServer> server;
  std::uint16_t port;

  explicit MockNode(std::uint16_t p, bool enableLogging = false) : port(p)
  {
    MockDnsServer::Config c;
    c.udpPort = p;
    c.tcpPort = p;
    c.enableLogging = enableLogging; // needed for getQueryLog()-based per-type counting
    server = std::make_unique<MockDnsServer>(c);
    REQUIRE(server->start());
    std::this_thread::sleep_for(STARTUP_DELAY);
  }

  MockDnsServer *operator->() { return server.get(); }
  std::uint64_t udpQueries() const { return server->getStats().udpQueries; }
  std::uint64_t tcpQueries() const { return server->getStats().tcpQueries; }

  /// Count queries of a DNS qtype this node received (from the enabled query log).
  /// A=1, AAAA=28, SRV=33, NAPTR=35.
  std::size_t countType(int qtype) const
  {
    const std::string needle = "type=" + std::to_string(qtype) + " ";
    std::size_t n = 0;
    for (const auto &line : server->getQueryLog())
    {
      if (line.find("DNS query:") != std::string::npos &&
          line.find(needle) != std::string::npos)
      {
        ++n;
      }
    }
    return n;
  }
};

// A NAPTR 'S'-flag record for `domain` pointing at `replacement` (an SRV owner name).
MockDnsServer::DnsRecord naptrS(const std::string &domain, const std::string &replacement)
{
  MockDnsServer::DnsRecord rec;
  rec.name = domain;
  rec.type = "NAPTR";
  rec.ttl = 3600;
  rec.naptrOrder = 10;
  rec.naptrPreference = 10;
  rec.naptrFlags = "S";
  rec.naptrService = "SIP+D2U";
  rec.naptrReplacement = replacement;
  return rec;
}

/// \brief Build a real DnsResolver over a started DnsTransport pointed at the given ports,
/// IN ORDER. A fresh resolver's _serverRotation starts at 0, so the first query() starts at
/// ports[0] — deterministic "primary = ports[0]" for the failover assertions.
std::shared_ptr<DnsResolver> makeResolver(const std::vector<std::uint16_t> &ports,
                                          std::chrono::milliseconds timeout = SHORT_TIMEOUT,
                                          int retryCount = 0,
                                          DnsTransportMode mode = DnsTransportMode::UDP,
                                          std::shared_ptr<DnsCache> cache = nullptr)
{
  DnsConfig cfg;
  std::vector<std::string> servers;
  for (auto p : ports)
  {
    servers.push_back("127.0.0.1:" + std::to_string(p));
  }
  cfg.setServers(servers);
  cfg.timeout = timeout;
  cfg.retryCount = retryCount;
  cfg.transportMode = mode;
  cfg.enableCache = (cache != nullptr);
  auto transport = std::make_shared<DnsTransport>(cfg);
  transport->start();
  return std::make_shared<DnsResolver>(transport, cache, cfg);
}

MockDnsServer::QueryConfig servfail()
{
  MockDnsServer::QueryConfig q;
  q.shouldFail = true;
  return q;
}
MockDnsServer::QueryConfig refused()
{
  MockDnsServer::QueryConfig q;
  q.shouldRefuse = true;
  return q;
}
MockDnsServer::QueryConfig notimp()
{
  MockDnsServer::QueryConfig q;
  q.shouldReturnNotimp = true;
  return q;
}
MockDnsServer::QueryConfig formerr()
{
  MockDnsServer::QueryConfig q;
  q.shouldReturnFormerr = true;
  return q;
}
MockDnsServer::QueryConfig nodataWithSoa()
{
  MockDnsServer::QueryConfig q;
  q.shouldReturnNodata = true;
  return q;
}
MockDnsServer::QueryConfig nodataNoSoa()
{
  MockDnsServer::QueryConfig q;
  q.shouldReturnNodataNoSoa = true;
  return q;
}
MockDnsServer::QueryConfig timeoutCfg()
{
  MockDnsServer::QueryConfig q;
  q.shouldTimeout = true;
  return q;
}

DnsQuestion aQ(const std::string &name) { return DnsQuestion(name, DnsType::A, DnsClass::IN); }

} // namespace

// =============================================================================
// PHASE 1 — SYNC next-server failover at the query() leaf
// =============================================================================

TEST_CASE("SYNC SERVFAIL on A -> failover to B; A not re-hit", "[dns][failover][sync]")
{
  MockNode a(PORT_A), b(PORT_B);
  a->configureQuery("host.example.com", servfail());
  b->addRecord({"host.example.com", "A", "192.0.2.10", 3600});

  auto r = makeResolver({PORT_A, PORT_B});
  DnsResult result = r->query(aQ("host.example.com"));

  REQUIRE(result.isSuccess());
  REQUIRE(result.a_records.size() == 1);
  REQUIRE(result.a_records[0].address == "192.0.2.10");
  // A hit exactly once (the SERVFAIL), never re-queried; B hit once (the success).
  REQUIRE(a.udpQueries() == 1);
  REQUIRE(b.udpQueries() == 1);
}

TEST_CASE("SYNC REFUSED triggers failover; NXDOMAIN and NODATA+SOA do NOT",
          "[dns][failover][sync][gate]")
{
  SECTION("REFUSED -> failover to B")
  {
    MockNode a(PORT_A), b(PORT_B);
    a->configureQuery("host.example.com", refused());
    b->addRecord({"host.example.com", "A", "192.0.2.11", 3600});
    auto r = makeResolver({PORT_A, PORT_B});
    DnsResult result = r->query(aQ("host.example.com"));
    REQUIRE(result.isSuccess());
    REQUIRE(a.udpQueries() == 1);
    REQUIRE(b.udpQueries() == 1);
  }

  SECTION("NXDOMAIN is authoritative -> NO failover, B untouched")
  {
    MockNode a(PORT_A), b(PORT_B);
    // A has no record for the name -> authoritative NXDOMAIN from A.
    b->addRecord({"host.example.com", "A", "192.0.2.12", 3600});
    auto r = makeResolver({PORT_A, PORT_B});
    REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsResolutionFailedException);
    REQUIRE(a.udpQueries() == 1);
    REQUIRE(b.udpQueries() == 0); // authoritative negative stops rotation
  }

  SECTION("NODATA-with-SOA is authoritative -> NO failover, B untouched")
  {
    MockNode a(PORT_A), b(PORT_B);
    a->configureQuery("host.example.com", nodataWithSoa());
    b->addRecord({"host.example.com", "A", "192.0.2.13", 3600});
    auto r = makeResolver({PORT_A, PORT_B});
    REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsResolutionFailedException);
    REQUIRE(a.udpQueries() == 1);
    REQUIRE(b.udpQueries() == 0);
  }
}

TEST_CASE("SYNC FORMERR/NOTIMP/NODATA-without-SOA failover; NODATA-with-SOA does not",
          "[dns][failover][sync][gate]")
{
  SECTION("FORMERR on an A query -> failover")
  {
    MockNode a(PORT_A), b(PORT_B);
    a->configureQuery("host.example.com", formerr());
    b->addRecord({"host.example.com", "A", "192.0.2.14", 3600});
    auto r = makeResolver({PORT_A, PORT_B});
    REQUIRE(r->query(aQ("host.example.com")).isSuccess());
    REQUIRE(b.udpQueries() == 1);
  }

  SECTION("NOTIMP on an A query -> failover (A-record NOTIMP is NOT the NAPTR Q5 case)")
  {
    MockNode a(PORT_A), b(PORT_B);
    a->configureQuery("host.example.com", notimp());
    b->addRecord({"host.example.com", "A", "192.0.2.15", 3600});
    auto r = makeResolver({PORT_A, PORT_B});
    REQUIRE(r->query(aQ("host.example.com")).isSuccess());
    REQUIRE(a.udpQueries() == 1);
    REQUIRE(b.udpQueries() == 1);
  }

  SECTION("NODATA-without-SOA -> failover (not authoritative, RFC 2308 §5)")
  {
    MockNode a(PORT_A), b(PORT_B);
    a->configureQuery("host.example.com", nodataNoSoa());
    b->addRecord({"host.example.com", "A", "192.0.2.16", 3600});
    auto r = makeResolver({PORT_A, PORT_B});
    REQUIRE(r->query(aQ("host.example.com")).isSuccess());
    REQUIRE(b.udpQueries() == 1);
  }
}

TEST_CASE("SYNC TIMEOUT on primary (exception channel) -> failover to B; bounded",
          "[dns][failover][sync][timeout]")
{
  MockNode a(PORT_A), b(PORT_B);
  a->configureQuery("host.example.com", timeoutCfg());
  b->addRecord({"host.example.com", "A", "192.0.2.17", 3600});
  auto r = makeResolver({PORT_A, PORT_B}, SHORT_TIMEOUT, /*retryCount=*/0);

  auto start = std::chrono::steady_clock::now();
  DnsResult result = r->query(aQ("host.example.com"));
  auto elapsed = std::chrono::steady_clock::now() - start;

  REQUIRE(result.isSuccess());
  REQUIRE(b.udpQueries() == 1);
  // Bounded: one timeout window on A + one success on B, well under 3x the timeout.
  REQUIRE(elapsed < SHORT_TIMEOUT * 3);
}

TEST_CASE("SYNC all-server SERVFAIL -> DnsTransientResolutionException, N attempts, terminal once",
          "[dns][failover][sync][transient]")
{
  MockNode a(PORT_A), b(PORT_B), c(PORT_C);
  a->configureQuery("host.example.com", servfail());
  b->configureQuery("host.example.com", servfail());
  c->configureQuery("host.example.com", servfail());
  auto r = makeResolver({PORT_A, PORT_B, PORT_C});

  REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsTransientResolutionException);
  // Each of the N servers contacted exactly once (bounded by server count, tried excluded).
  REQUIRE(a.udpQueries() == 1);
  REQUIRE(b.udpQueries() == 1);
  REQUIRE(c.udpQueries() == 1);
}

TEST_CASE("SYNC N=1 single-server failover no-op", "[dns][failover][sync]")
{
  SECTION("single-server SERVFAIL -> transient")
  {
    MockNode a(PORT_A);
    a->configureQuery("host.example.com", servfail());
    auto r = makeResolver({PORT_A});
    REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsTransientResolutionException);
    REQUIRE(a.udpQueries() == 1);
  }
  SECTION("single-server success")
  {
    MockNode a(PORT_A);
    a->addRecord({"host.example.com", "A", "192.0.2.18", 3600});
    auto r = makeResolver({PORT_A});
    REQUIRE(r->query(aQ("host.example.com")).isSuccess());
  }
}

TEST_CASE("SYNC SERVFAIL -> NXDOMAIN-on-B stops rotation at B's authoritative negative",
          "[dns][failover][sync][gate]")
{
  MockNode a(PORT_A), b(PORT_B), c(PORT_C);
  a->configureQuery("host.example.com", servfail());
  // B has no record -> authoritative NXDOMAIN. C would succeed but must never be reached.
  c->addRecord({"host.example.com", "A", "192.0.2.19", 3600});
  auto r = makeResolver({PORT_A, PORT_B, PORT_C});

  REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsResolutionFailedException);
  REQUIRE(a.udpQueries() == 1);
  REQUIRE(b.udpQueries() == 1);
  REQUIRE(c.udpQueries() == 0); // stopped at B's authoritative NXDOMAIN
}

TEST_CASE("SYNC 3-server partial set: A SERVFAIL, B SERVFAIL, C NOERROR -> success on C",
          "[dns][failover][sync]")
{
  MockNode a(PORT_A), b(PORT_B), c(PORT_C);
  a->configureQuery("host.example.com", servfail());
  b->configureQuery("host.example.com", servfail());
  c->addRecord({"host.example.com", "A", "192.0.2.20", 3600});
  auto r = makeResolver({PORT_A, PORT_B, PORT_C});

  DnsResult result = r->query(aQ("host.example.com"));
  REQUIRE(result.isSuccess());
  REQUIRE(result.a_records[0].address == "192.0.2.20");
  REQUIRE(a.udpQueries() == 1);
  REQUIRE(b.udpQueries() == 1);
  REQUIRE(c.udpQueries() == 1);
}

TEST_CASE("SYNC TC=1 truncation from A -> SAME server A over TCP, B NOT contacted",
          "[dns][failover][sync][truncation]")
{
  MockNode a(PORT_A), b(PORT_B);
  // A returns a truncated UDP response, then answers the TCP retry (same server).
  MockDnsServer::QueryConfig trunc;
  trunc.shouldTruncate = true;
  a->configureQuery("host.example.com", trunc);
  a->addRecord({"host.example.com", "A", "192.0.2.21", 3600});
  b->addRecord({"host.example.com", "A", "192.0.2.99", 3600});
  auto r = makeResolver({PORT_A, PORT_B}, SHORT_TIMEOUT, /*retryCount=*/1,
                        DnsTransportMode::Both);

  DnsResult result = r->query(aQ("host.example.com"));
  REQUIRE(result.isSuccess());
  // Truncation is a same-server UDP->TCP fallback, NOT a failover trigger: B is never used.
  REQUIRE(b.udpQueries() == 0);
  REQUIRE(b.tcpQueries() == 0);
}

// =============================================================================
// PHASE 1 — resolveHostname transient-preserving failure channel
// =============================================================================

TEST_CASE("resolveHostname all-server SERVFAIL -> transient throw, not DnsNoRecordsException",
          "[dns][failover][sync][resolvehostname]")
{
  MockNode a(PORT_A), b(PORT_B);
  // Both families server-local on both servers.
  a->configureQuery("host.example.com", "A", servfail());
  a->configureQuery("host.example.com", "AAAA", servfail());
  b->configureQuery("host.example.com", "A", servfail());
  b->configureQuery("host.example.com", "AAAA", servfail());
  auto r = makeResolver({PORT_A, PORT_B});

  REQUIRE_THROWS_AS(r->resolveHostname("host.example.com"), DnsTransientResolutionException);
}

TEST_CASE("resolveHostname all-server NODATA-without-SOA -> transient throw",
          "[dns][failover][sync][resolvehostname]")
{
  MockNode a(PORT_A), b(PORT_B);
  a->configureQuery("host.example.com", "A", nodataNoSoa());
  a->configureQuery("host.example.com", "AAAA", nodataNoSoa());
  b->configureQuery("host.example.com", "A", nodataNoSoa());
  b->configureQuery("host.example.com", "AAAA", nodataNoSoa());
  auto r = makeResolver({PORT_A, PORT_B});

  REQUIRE_THROWS_AS(r->resolveHostname("host.example.com"), DnsTransientResolutionException);
}

TEST_CASE("resolveHostname A transient but AAAA success -> returns AAAA, no throw",
          "[dns][failover][sync][resolvehostname]")
{
  MockNode a(PORT_A), b(PORT_B);
  // A-family server-local on both servers; AAAA succeeds on the primary.
  a->configureQuery("host.example.com", "A", servfail());
  b->configureQuery("host.example.com", "A", servfail());
  a->addRecord({"host.example.com", "AAAA", "2001:db8::1", 3600});
  b->addRecord({"host.example.com", "AAAA", "2001:db8::1", 3600});
  auto r = makeResolver({PORT_A, PORT_B});

  std::vector<std::string> addrs;
  REQUIRE_NOTHROW(addrs = r->resolveHostname("host.example.com"));
  REQUIRE_FALSE(addrs.empty());
  REQUIRE(addrs[0] == "2001:db8::1"); // a transient sibling does not override a partial success
}

TEST_CASE("resolveHostname all-authoritative-negative -> DnsNoRecordsException (permanent)",
          "[dns][failover][sync][resolvehostname]")
{
  MockNode a(PORT_A), b(PORT_B);
  // No records anywhere -> both families NXDOMAIN (authoritative). Each family's query()
  // stops at its FIRST server's authoritative negative (no rotation), so neither family is
  // failed over — but the resolver's rotation cursor advances per query() call, so the two
  // families start on different servers. The invariant under test is the terminal exception
  // TYPE (permanent, not transient), not which server each family happened to hit.
  auto r = makeResolver({PORT_A, PORT_B});
  REQUIRE_THROWS_AS(r->resolveHostname("nope.example.com"), DnsNoRecordsException);
  // No rotation on an authoritative negative: at most one query per family per server.
  REQUIRE(a.udpQueries() <= 1);
  REQUIRE(b.udpQueries() <= 1);
}

// =============================================================================
// PHASE 1 — NAPTR-specific failover semantics (RFC 3263 + human Q5)
// =============================================================================

TEST_CASE("SYNC NAPTR SERVFAIL -> next-server retry of the SAME NAPTR before direct-SRV",
          "[dns][failover][sync][naptr]")
{
  MockNode a(PORT_A, /*log=*/true), b(PORT_B, /*log=*/true);
  const std::string domain = "example.net";
  const std::string srvName = "_sip._udp." + domain;

  // A: NAPTR SERVFAILs. B: has the NAPTR record. Both carry the SRV+A chain.
  a->configureQuery(domain, "NAPTR", servfail());
  b->addRecord(naptrS(domain, srvName));
  for (auto *n : {&a, &b})
  {
    (*n)->addRecord({srvName, "SRV", "sip1." + domain, 3600, 10, 0, 5060});
    (*n)->addRecord({"sip1." + domain, "A", "192.0.2.30", 3600});
    (*n)->addRecord({"sip1." + domain, "AAAA", "2001:db8::30", 3600});
  }

  auto r = makeResolver({PORT_A, PORT_B});
  ServiceResolutionResult res = r->resolveServiceDomain(domain, {ServiceType::SIP_UDP});

  REQUIRE(res.isSuccess());
  // The SAME NAPTR query was retried on B (not skipped straight to direct-SRV): B saw a NAPTR.
  REQUIRE(a.countType(35) == 1);
  REQUIRE(b.countType(35) >= 1);
}

TEST_CASE("SYNC NAPTR NOTIMP/FORMERR -> straight to direct-SRV WITHOUT exhausting (Q5)",
          "[dns][failover][sync][naptr][q5]")
{
  auto runQ5 = [](MockDnsServer::QueryConfig naptrCfg)
  {
    MockNode a(PORT_A, /*log=*/true), b(PORT_B, /*log=*/true);
    const std::string domain = "example.net";
    const std::string srvName = "_sip._udp." + domain;

    // A answers the NAPTR with NOTIMP/FORMERR. NO NAPTR record on B: if the resolver
    // (wrongly) rotated the NAPTR to B, B would receive a NAPTR query — the Q5 violation.
    a->configureQuery(domain, "NAPTR", naptrCfg);
    for (auto *n : {&a, &b})
    {
      (*n)->addRecord({srvName, "SRV", "sip1." + domain, 3600, 10, 0, 5060});
      (*n)->addRecord({"sip1." + domain, "A", "192.0.2.31", 3600});
      (*n)->addRecord({"sip1." + domain, "AAAA", "2001:db8::31", 3600});
    }

    auto r = makeResolver({PORT_A, PORT_B});
    ServiceResolutionResult res = r->resolveServiceDomain(domain, {ServiceType::SIP_UDP});

    REQUIRE(res.isSuccess());                 // fell forward to direct-SRV
    REQUIRE(a.countType(35) == 1);            // exactly ONE NAPTR query
    REQUIRE(b.countType(35) == 0);            // Q5: NOT rotated across servers
  };

  SECTION("NOTIMP") { runQ5(notimp()); }
  SECTION("FORMERR") { runQ5(formerr()); }
}

// =============================================================================
// PHASE 1 — non-failover TERMINAL faults + connect-refused (DnsNetworkException)
// =============================================================================

TEST_CASE("SYNC lifecycle 'Transport stopped' -> TERMINAL, no rotation, not transient",
          "[dns][failover][sync][terminal]")
{
  MockNode a(PORT_A), b(PORT_B);
  a->addRecord({"host.example.com", "A", "192.0.2.40", 3600});
  b->addRecord({"host.example.com", "A", "192.0.2.41", 3600});

  DnsConfig cfg;
  cfg.setServers({"127.0.0.1:" + std::to_string(PORT_A), "127.0.0.1:" + std::to_string(PORT_B)});
  cfg.timeout = SHORT_TIMEOUT;
  cfg.retryCount = 0;
  cfg.transportMode = DnsTransportMode::UDP;
  auto transport = std::make_shared<DnsTransport>(cfg);
  transport->start();
  auto r = std::make_shared<DnsResolver>(transport, nullptr, cfg);

  transport->stop(); // lifecycle fault: every server query throws "Transport not running"

  bool sawTransient = false;
  bool sawTransport = false;
  try
  {
    r->query(aQ("host.example.com"));
  }
  catch (const DnsTransientResolutionException &)
  {
    sawTransient = true; // MUST NOT happen: a lifecycle fault is not a transient failover
  }
  catch (const DnsTransportException &)
  {
    sawTransport = true; // terminal, propagated as-is, no rotation
  }
  REQUIRE(sawTransport);
  REQUIRE_FALSE(sawTransient);
  // No server was contacted (transport is stopped).
  REQUIRE(a.udpQueries() == 0);
  REQUIRE(b.udpQueries() == 0);
}

TEST_CASE("SYNC connect-refused on primary (TCP) -> failover to B",
          "[dns][failover][sync][network]")
{
  MockNode b(PORT_B); // real server on TCP (tcpPort == udpPort in MockNode)
  b->addRecord({"host.example.com", "A", "192.0.2.50", 3600});

  // Primary points at a dead port over TCP: connect is refused before any DNS exchange.
  auto r = makeResolver({PORT_DEAD, PORT_B}, SHORT_TIMEOUT, /*retryCount=*/0,
                        DnsTransportMode::TCP);
  DnsResult result = r->query(aQ("host.example.com"));

  REQUIRE(result.isSuccess());
  REQUIRE(result.a_records[0].address == "192.0.2.50");
  REQUIRE(b.tcpQueries() == 1);
}

TEST_CASE("Transport-level: refused TCP connect throws DnsNetworkException (type discriminates)",
          "[dns][failover][transport][network]")
{
  DnsConfig cfg;
  cfg.setServers({"127.0.0.1:" + std::to_string(PORT_DEAD)});
  cfg.timeout = SHORT_TIMEOUT;
  cfg.retryCount = 0;
  cfg.transportMode = DnsTransportMode::TCP;
  auto transport = std::make_shared<DnsTransport>(cfg);
  transport->start();

  // A refused connect must surface as DnsNetworkException (a DnsTransportException subtype),
  // so the resolver gate rotates on it BY TYPE rather than by a what()-substring match.
  bool threw = false;
  bool wasNetwork = false;
  try
  {
    transport->query(aQ("host.example.com"), "127.0.0.1", PORT_DEAD);
  }
  catch (const DnsNetworkException &)
  {
    threw = true;
    wasNetwork = true;
  }
  catch (const DnsTransportException &)
  {
    threw = true; // e.g. a timeout path on hosts where a dead-port TCP connect is not refused
  }
  transport->stop();
  REQUIRE(threw);
  // On loopback a dead-port TCP connect is refused deterministically -> DnsNetworkException.
  REQUIRE(wasNetwork);
}


// =============================================================================
// PHASE 2/3 — ASYNC next-server failover (queryAsyncWithFailover helper)
// =============================================================================

namespace
{
constexpr std::chrono::seconds ASYNC_WAIT{5};

/// \brief A DnsTransport double whose async queryAsync branches on the SERVER argument, so a
/// deterministic per-server rcode / success / injected-throw sequence drives the resolver's
/// async failover helper without real sockets. queryAsync is the only virtual seam.
class FailoverDouble : public DnsTransport
{
public:
  explicit FailoverDouble(const DnsConfig &cfg) : DnsTransport(cfg) {}

  // Per-server-address behavior. Absent server -> SERVFAIL (server-local).
  std::unordered_map<std::string, DnsResponseCode> rcodeByServer;
  std::unordered_map<std::string, std::vector<std::string>> aByServer; // success addresses (A)
  std::atomic<int> issueCount{0};
  std::atomic<int> callbackCount{0};
  int throwOnIssue{-1}; // 1-based Nth issue throws synchronously; -1 = off
  bool asyncDispatch{true};

  void queryAsync(const DnsQuestion &q, QueryCallback cb, const std::string &server,
                  std::uint16_t) override
  {
    const int n = ++issueCount;
    if (n == throwOnIssue)
    {
      throw std::runtime_error("injected synchronous issue throw @call " + std::to_string(n));
    }

    DnsResult r;
    DnsResponseCode rc = DnsResponseCode::SERVFAIL;
    auto it = rcodeByServer.find(server);
    if (it != rcodeByServer.end())
    {
      rc = it->second;
    }
    r.header.rcode = rc;
    if (rc == DnsResponseCode::NOERROR)
    {
      auto ait = aByServer.find(server);
      if (ait != aByServer.end())
      {
        for (const auto &a : ait->second)
        {
          r.a_records.push_back(ARecord(q.qname, a, 3600));
        }
      }
      r.header.ancount = static_cast<std::uint16_t>(r.a_records.size());
    }
    else
    {
      r.header.ancount = 0;
    }

    auto deliver = [this, cb, r]()
    {
      ++callbackCount;
      try
      {
        cb(r, nullptr);
      }
      catch (...)
      {
      }
    };
    if (asyncDispatch)
    {
      std::thread(deliver).detach();
    }
    else
    {
      deliver();
    }
  }
};

struct AsyncOutcome
{
  DnsResult result;
  std::exception_ptr error;
  int callbacks{0};
  bool completed{false};
};

// Drive the resolver's public async queryAsync twin and block (bounded) for the first callback.
AsyncOutcome driveQueryAsync(const std::shared_ptr<DnsResolver> &r, const DnsQuestion &q)
{
  auto count = std::make_shared<std::atomic<int>>(0);
  auto once = std::make_shared<std::atomic<bool>>(false);
  auto prom = std::make_shared<std::promise<std::pair<DnsResult, std::exception_ptr>>>();
  auto fut = prom->get_future();
  r->queryAsync(q, [count, once, prom](const DnsResult &res, const std::exception_ptr &e)
                {
                  count->fetch_add(1);
                  if (!once->exchange(true))
                  {
                    prom->set_value({res, e});
                  }
                });
  AsyncOutcome out;
  out.completed = fut.wait_for(ASYNC_WAIT) == std::future_status::ready;
  if (out.completed)
  {
    auto p = fut.get();
    out.result = p.first;
    out.error = p.second;
    std::this_thread::sleep_for(std::chrono::milliseconds(60)); // catch any spurious extra callback
  }
  out.callbacks = count->load();
  return out;
}

std::shared_ptr<FailoverDouble> makeDouble(const std::vector<std::string> &servers)
{
  DnsConfig cfg;
  cfg.setServers(servers);
  cfg.timeout = std::chrono::milliseconds(400);
  cfg.retryCount = 0;
  return std::make_shared<FailoverDouble>(cfg);
}

std::shared_ptr<DnsResolver> resolverOver(const std::shared_ptr<FailoverDouble> &t)
{
  DnsConfig cfg;
  cfg.setServers({"1.1.1.1:53", "2.2.2.2:53"}); // resolver _config server list is unused for the
                                                 // snapshot (that comes from the transport)
  return std::make_shared<DnsResolver>(t, nullptr, cfg);
}

} // namespace

TEST_CASE("ASYNC SERVFAIL on A -> failover to B; exactly one callback", "[dns][failover][async]")
{
  auto t = makeDouble({"10.0.0.1:53", "10.0.0.2:53"});
  t->rcodeByServer["10.0.0.1"] = DnsResponseCode::SERVFAIL;
  t->rcodeByServer["10.0.0.2"] = DnsResponseCode::NOERROR;
  t->aByServer["10.0.0.2"] = {"192.0.2.60"};
  auto r = resolverOver(t);

  auto out = driveQueryAsync(r, aQ("host.example.com"));
  REQUIRE(out.completed);
  REQUIRE(out.callbacks == 1);
  REQUIRE_FALSE(out.error);
  REQUIRE(out.result.isSuccess());
  REQUIRE(out.result.a_records[0].address == "192.0.2.60");
}

TEST_CASE("ASYNC all-server SERVFAIL -> transient, exactly one callback", "[dns][failover][async]")
{
  auto t = makeDouble({"10.0.0.1:53", "10.0.0.2:53"});
  t->rcodeByServer["10.0.0.1"] = DnsResponseCode::SERVFAIL;
  t->rcodeByServer["10.0.0.2"] = DnsResponseCode::SERVFAIL;
  auto r = resolverOver(t);

  auto out = driveQueryAsync(r, aQ("host.example.com"));
  REQUIRE(out.completed);
  REQUIRE(out.callbacks == 1);
  REQUIRE(out.error);
  bool transient = false;
  try
  {
    std::rethrow_exception(out.error);
  }
  catch (const DnsTransientResolutionException &)
  {
    transient = true;
  }
  catch (...)
  {
  }
  REQUIRE(transient);
  REQUIRE(t->issueCount.load() == 2); // each server tried exactly once
}

TEST_CASE("ASYNC 3-server round-robin wrap never re-hits an excluded server",
          "[dns][failover][async]")
{
  auto t = makeDouble({"10.0.0.1:53", "10.0.0.2:53", "10.0.0.3:53"});
  t->rcodeByServer["10.0.0.1"] = DnsResponseCode::SERVFAIL;
  t->rcodeByServer["10.0.0.2"] = DnsResponseCode::SERVFAIL;
  t->rcodeByServer["10.0.0.3"] = DnsResponseCode::NOERROR;
  t->aByServer["10.0.0.3"] = {"192.0.2.61"};
  auto r = resolverOver(t);

  auto out = driveQueryAsync(r, aQ("host.example.com"));
  REQUIRE(out.completed);
  REQUIRE(out.callbacks == 1);
  REQUIRE(out.result.isSuccess());
  REQUIRE(t->issueCount.load() == 3); // exactly N issues, no re-hit
}

TEST_CASE("ASYNC re-issue in flight never double-fires the terminal (exactly once)",
          "[dns][failover][async][exactly-once]")
{
  // asyncDispatch=true: each completion is on a worker thread, so the SERVFAIL->re-issue
  // transition is a genuine cross-thread hand-off; the callback must still fire exactly once.
  auto t = makeDouble({"10.0.0.1:53", "10.0.0.2:53"});
  t->asyncDispatch = true;
  t->rcodeByServer["10.0.0.1"] = DnsResponseCode::SERVFAIL;
  t->rcodeByServer["10.0.0.2"] = DnsResponseCode::NOERROR;
  t->aByServer["10.0.0.2"] = {"192.0.2.62"};
  auto r = resolverOver(t);

  auto out = driveQueryAsync(r, aQ("host.example.com"));
  REQUIRE(out.completed);
  REQUIRE(out.callbacks == 1);
  REQUIRE(out.result.isSuccess());
}

TEST_CASE("ASYNC synchronous FIRST-issue throw -> exactly one terminal callback, no hang",
          "[dns][failover][async][throw]")
{
  // The helper must NEVER propagate a synchronous issue-throw: it converts it to exactly one
  // terminal wrappedCallback. A double-fire OR a lost callback makes this bounded wait fail.
  auto t = makeDouble({"10.0.0.1:53", "10.0.0.2:53"});
  t->asyncDispatch = false; // inline completion path (re-entrant)
  t->throwOnIssue = 1;      // the very first issue throws synchronously
  t->rcodeByServer["10.0.0.2"] = DnsResponseCode::NOERROR;
  t->aByServer["10.0.0.2"] = {"192.0.2.63"};
  auto r = resolverOver(t);

  auto out = driveQueryAsync(r, aQ("host.example.com"));
  REQUIRE(out.completed);      // no hang
  REQUIRE(out.callbacks == 1); // exactly one terminal
  REQUIRE(out.error);          // a non-network injected throw is delivered terminal
}

TEST_CASE("ASYNC concurrent failovers on different owner names do not corrupt each other",
          "[dns][failover][async][concurrent]")
{
  auto t = makeDouble({"10.0.0.1:53", "10.0.0.2:53"});
  t->rcodeByServer["10.0.0.1"] = DnsResponseCode::SERVFAIL; // primary always fails -> both rotate
  t->rcodeByServer["10.0.0.2"] = DnsResponseCode::NOERROR;
  t->aByServer["10.0.0.2"] = {"192.0.2.64"};
  auto r = resolverOver(t);

  constexpr int N = 8;
  std::vector<std::future<AsyncOutcome>> futs;
  for (int i = 0; i < N; ++i)
  {
    futs.push_back(std::async(std::launch::async, [&r, i]()
                              { return driveQueryAsync(r, aQ("host" + std::to_string(i) + ".example.com")); }));
  }
  for (auto &f : futs)
  {
    AsyncOutcome out = f.get();
    REQUIRE(out.completed);
    REQUIRE(out.callbacks == 1);
    REQUIRE(out.result.isSuccess());
  }
}

TEST_CASE("ASYNC all-server exhaustion -> resolveServiceDomainAsync outcome=TransientFailure",
          "[dns][failover][async][outcome]")
{
  // Every avenue (NAPTR -> direct-SRV -> A/AAAA fallback) exhausts BOTH servers on server-local
  // SERVFAIL, so each helper funnels a terminal transient. The delivered ServiceResolutionResult
  // must carry the terminal avenue's per-avenue outcome = TransientFailure (retryable), never a
  // silent empty / PermanentNoService. (The empty-server-snapshot n==0 branch in the helper is a
  // defensive subset of this exhaustion path; a genuinely empty snapshot is unreachable through
  // DnsConfig, whose ctor and updateConfig both reject an empty server list.)
  auto t = makeDouble({"10.0.0.1:53", "10.0.0.2:53"}); // both default to SERVFAIL for every name
  auto r = resolverOver(t);

  auto prom = std::make_shared<std::promise<ServiceResolutionResult>>();
  auto fut = prom->get_future();
  auto once = std::make_shared<std::atomic<bool>>(false);
  r->resolveServiceDomainAsync(
    "example.com",
    [prom, once](const ServiceResolutionResult &res, const std::exception_ptr &)
    {
      if (!once->exchange(true))
      {
        prom->set_value(res);
      }
    },
    {ServiceType::SIP_UDP});
  REQUIRE(fut.wait_for(ASYNC_WAIT) == std::future_status::ready);
  ServiceResolutionResult res = fut.get();
  REQUIRE_FALSE(res.isSuccess());
  REQUIRE(res.outcome == ResolutionOutcome::TransientFailure);
}

TEST_CASE("ASYNC end-to-end: two real MockDnsServer, SERVFAIL on A -> resolveServiceDomainAsync via B",
          "[dns][failover][async][wire]")
{
  MockNode a(PORT_A), b(PORT_B);
  const std::string domain = "example.net";
  const std::string srvName = "_sip._udp." + domain;
  // A SERVFAILs the NAPTR and SRV; B answers the full direct-SRV chain.
  a->configureQuery(domain, "NAPTR", servfail());
  a->configureQuery(srvName, "SRV", servfail());
  b->addRecord({srvName, "SRV", "sip1." + domain, 3600, 10, 0, 5060});
  for (auto *n : {&a, &b})
  {
    (*n)->addRecord({"sip1." + domain, "A", "192.0.2.70", 3600});
    (*n)->addRecord({"sip1." + domain, "AAAA", "2001:db8::70", 3600});
  }
  auto r = makeResolver({PORT_A, PORT_B});

  auto prom = std::make_shared<std::promise<ServiceResolutionResult>>();
  auto fut = prom->get_future();
  auto once = std::make_shared<std::atomic<bool>>(false);
  r->resolveServiceDomainAsync(
    domain,
    [prom, once](const ServiceResolutionResult &res, const std::exception_ptr &)
    {
      if (!once->exchange(true))
      {
        prom->set_value(res);
      }
    },
    {ServiceType::SIP_UDP});
  REQUIRE(fut.wait_for(ASYNC_WAIT) == std::future_status::ready);
  ServiceResolutionResult res = fut.get();
  REQUIRE(res.isSuccess()); // failover to B produced the target chain
}
