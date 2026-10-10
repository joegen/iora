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
/// (SERVFAIL/REFUSED/FORMERR/NOTIMP / a referral (NS, no SOA) / a truncated (TC=1) or lame
/// (RA=0,AA=0) empty answer) OR a thrown transport fault (timeout, connect/send failure) -- must
/// fail over to the next configured server (excluding tried), sync + async + A/AAAA, terminating on
/// the first authoritative response. An authoritative negative (NXDOMAIN / authoritative NODATA --
/// SOA present or type-3 empty-authority, RFC 2308 §2.2.1) must NOT rotate. A single resolution
/// avenue publishes a per-avenue ResolutionOutcome { Resolved, TransientFailure, PermanentNoService }.
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
#include "iora_test_net_utils.hpp"
#include "dns_transport_test_access.hpp" // white-box seam: calcMaxSyncWait (H-2 budget test)
#include "iora/network/dns/dns_cache.hpp"
#include "iora/network/dns/dns_resolver.hpp"
#include "iora/network/dns/dns_transport.hpp"
#include "iora/network/dns/dns_types.hpp"

#include <algorithm>
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
constexpr std::chrono::milliseconds STARTUP_DELAY{150};
constexpr std::chrono::milliseconds SHORT_TIMEOUT{400};

/// \brief One MockDnsServer instance on a dedicated port, started for its lifetime.
/// getStats().udpQueries proves per-server which server a lookup actually hit — the
/// observable that a failed server is not re-queried (tracker 2026-09-25-8).
struct MockNode
{
  std::unique_ptr<MockDnsServer> server;
  std::uint16_t port;

  explicit MockNode(bool enableLogging = false) : port(testnet::getFreePortUdpTcp())
  {
    MockDnsServer::Config c;
    c.udpPort = port;
    c.tcpPort = port;
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
// A NAPTR 'S'-flag record with an explicit service field (e.g. "SIP+D2U", "SIPS+D2T") pointing at
// an SRV owner name.
MockDnsServer::DnsRecord naptrSvc(const std::string &domain, const std::string &service,
                                  const std::string &replacement, std::uint16_t order = 10,
                                  std::uint16_t pref = 10)
{
  MockDnsServer::DnsRecord rec;
  rec.name = domain;
  rec.type = "NAPTR";
  rec.ttl = 3600;
  rec.naptrOrder = order;
  rec.naptrPreference = pref;
  rec.naptrFlags = "S";
  rec.naptrService = service;
  rec.naptrReplacement = replacement;
  return rec;
}

MockDnsServer::DnsRecord naptrS(const std::string &domain, const std::string &replacement)
{
  return naptrSvc(domain, "SIP+D2U", replacement);
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
// NOERROR/0-answers with an NS record in authority and NO SOA = a REFERRAL (RFC 2308 §2.2.1):
// server-local -> the failover rotates (distinct from a type-3 NODATA, which is authoritative).
MockDnsServer::QueryConfig referral()
{
  MockDnsServer::QueryConfig q;
  q.shouldReturnReferral = true;
  return q;
}
// NOERROR/0-answers/TC=1 (truncated) — never authoritative, never cached (RFC 2181 §9 / F-3).
MockDnsServer::QueryConfig truncatedEmpty()
{
  MockDnsServer::QueryConfig q;
  q.shouldReturnTruncatedEmpty = true;
  return q;
}
// NOERROR/0-answers, no SOA/NS, RA=0 AND AA=0 = a LAME / non-recursive reply -> rotate (F-4).
MockDnsServer::QueryConfig lameEmpty()
{
  MockDnsServer::QueryConfig q;
  q.shouldReturnLameEmpty = true;
  return q;
}
// NOERROR answer = one CNAME to `target`, no RR of the queried type. withSoa=true adds an
// authoritative SOA (CNAME-chain NODATA, RFC 2308 §2.2); withSoa=false leaves empty authority so
// the target is "not resolved" and the resolver must rotate (M-1).
MockDnsServer::QueryConfig cnameOnly(const std::string &target, bool withSoa = true)
{
  MockDnsServer::QueryConfig q;
  q.cnameOnlyTarget = target;
  q.cnameOnlyIncludeSoa = withSoa;
  return q;
}
// NOERROR answer = CNAME(qname->target) AND A(target->addr) — a chased CNAME, a real success (F-7 control).
MockDnsServer::QueryConfig cnameThenA(const std::string &target, const std::string &addr)
{
  MockDnsServer::QueryConfig q;
  q.cnameThenATarget = target;
  q.cnameThenAAddr = addr;
  return q;
}
// NOERROR/0-answers with NS AND SOA in authority = RFC 2308 §2.2.1 type-1 NODATA -> authoritative.
MockDnsServer::QueryConfig nodataNsAndSoa()
{
  MockDnsServer::QueryConfig q;
  q.shouldReturnNodataNsAndSoa = true;
  return q;
}
// NXDOMAIN with RA=0 AND AA=0 = a lame / non-recursive negative -> the resolver must rotate (M-2).
MockDnsServer::QueryConfig lameNxdomain()
{
  MockDnsServer::QueryConfig q;
  q.shouldReturnLameNxdomain = true;
  return q;
}
// CNAME-only + SOA but TRUNCATED (TC=1): must rotate, never be treated as authoritative (M-A).
MockDnsServer::QueryConfig cnameOnlyTruncated(const std::string &target)
{
  MockDnsServer::QueryConfig q;
  q.cnameOnlyTarget = target;
  q.cnameOnlyIncludeSoa = true;
  q.cnameOnlyTruncated = true;
  return q;
}
// NOERROR/0-answers with the SOA in the ADDITIONAL section only (RFC 2308 §3 violation): must NOT
// be authoritative nor negatively cached (L-1).
MockDnsServer::QueryConfig nodataSoaInAdditional()
{
  MockDnsServer::QueryConfig q;
  q.shouldReturnNodataSoaInAdditional = true;
  return q;
}

DnsQuestion aQ(const std::string &name) { return DnsQuestion(name, DnsType::A, DnsClass::IN); }
DnsQuestion anyQ(const std::string &name) { return DnsQuestion(name, DnsType::ANY, DnsClass::IN); }

} // namespace

// =============================================================================
// PHASE 1 — SYNC next-server failover at the query() leaf
// =============================================================================

TEST_CASE("SYNC SERVFAIL on A -> failover to B; A not re-hit", "[dns][failover][sync]")
{
  MockNode a, b;
  a->configureQuery("host.example.com", servfail());
  b->addRecord({"host.example.com", "A", "192.0.2.10", 3600});

  auto r = makeResolver({a.port, b.port});
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
    MockNode a, b;
    a->configureQuery("host.example.com", refused());
    b->addRecord({"host.example.com", "A", "192.0.2.11", 3600});
    auto r = makeResolver({a.port, b.port});
    DnsResult result = r->query(aQ("host.example.com"));
    REQUIRE(result.isSuccess());
    REQUIRE(a.udpQueries() == 1);
    REQUIRE(b.udpQueries() == 1);
  }

  SECTION("NXDOMAIN is authoritative -> NO failover, B untouched")
  {
    MockNode a, b;
    // A has no record for the name -> authoritative NXDOMAIN from A.
    b->addRecord({"host.example.com", "A", "192.0.2.12", 3600});
    auto r = makeResolver({a.port, b.port});
    REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsResolutionFailedException);
    REQUIRE(a.udpQueries() == 1);
    REQUIRE(b.udpQueries() == 0); // authoritative negative stops rotation
  }

  SECTION("NODATA-with-SOA is authoritative -> NO failover, B untouched")
  {
    MockNode a, b;
    a->configureQuery("host.example.com", nodataWithSoa());
    b->addRecord({"host.example.com", "A", "192.0.2.13", 3600});
    auto r = makeResolver({a.port, b.port});
    REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsResolutionFailedException);
    REQUIRE(a.udpQueries() == 1);
    REQUIRE(b.udpQueries() == 0);
  }
}

TEST_CASE("SYNC FORMERR/NOTIMP/referral failover; type-3 NODATA and NODATA-with-SOA do not",
          "[dns][failover][sync][gate]")
{
  SECTION("FORMERR on an A query -> failover")
  {
    MockNode a, b;
    a->configureQuery("host.example.com", formerr());
    b->addRecord({"host.example.com", "A", "192.0.2.14", 3600});
    auto r = makeResolver({a.port, b.port});
    REQUIRE(r->query(aQ("host.example.com")).isSuccess());
    REQUIRE(b.udpQueries() == 1);
  }

  SECTION("NOTIMP on an A query -> failover (A-record NOTIMP is NOT the NAPTR Q5 case)")
  {
    MockNode a, b;
    a->configureQuery("host.example.com", notimp());
    b->addRecord({"host.example.com", "A", "192.0.2.15", 3600});
    auto r = makeResolver({a.port, b.port});
    REQUIRE(r->query(aQ("host.example.com")).isSuccess());
    REQUIRE(a.udpQueries() == 1);
    REQUIRE(b.udpQueries() == 1);
  }

  // H-1 (tracker 2026-09-30-4): a REFERRAL (NOERROR/empty with NS in authority, no SOA) is
  // server-local per RFC 2308 §2.2.1 -> the failover rotates to the next server.
  SECTION("referral (NS-only authority, no SOA) -> failover (RFC 2308 §2.2.1)")
  {
    MockNode a, b;
    a->configureQuery("host.example.com", referral());
    b->addRecord({"host.example.com", "A", "192.0.2.16", 3600});
    auto r = makeResolver({a.port, b.port});
    REQUIRE(r->query(aQ("host.example.com")).isSuccess());
    REQUIRE(a.udpQueries() == 1); // A returned the referral ...
    REQUIRE(b.udpQueries() == 1); // ... and the query failed over to B
  }

  // H-1 (tracker 2026-09-30-4): a type-3 NODATA (NOERROR/empty, NO SOA and NO NS) IS authoritative
  // per RFC 2308 §2.2.1 -> NO rotation; the query stops at A's authoritative negative. (This
  // corrects the pre-fix behavior that mis-classified it as a retryable server-local outage.)
  SECTION("type-3 NODATA (empty authority, no SOA/no NS) is authoritative -> NO failover")
  {
    MockNode a, b;
    a->configureQuery("host.example.com", nodataNoSoa());
    b->addRecord({"host.example.com", "A", "192.0.2.17", 3600});
    auto r = makeResolver({a.port, b.port});
    REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsResolutionFailedException);
    REQUIRE(a.udpQueries() == 1); // authoritative negative stops rotation at A ...
    REQUIRE(b.udpQueries() == 0); // ... B is never contacted
  }

  // Unchanged control: NODATA-with-SOA is authoritative -> NO failover.
  SECTION("NODATA-with-SOA is authoritative -> NO failover")
  {
    MockNode a, b;
    a->configureQuery("host.example.com", nodataWithSoa());
    b->addRecord({"host.example.com", "A", "192.0.2.18", 3600});
    auto r = makeResolver({a.port, b.port});
    REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsResolutionFailedException);
    REQUIRE(a.udpQueries() == 1);
    REQUIRE(b.udpQueries() == 0);
  }
}

TEST_CASE("SYNC TIMEOUT on primary (exception channel) -> failover to B; bounded",
          "[dns][failover][sync][timeout]")
{
  MockNode a, b;
  a->configureQuery("host.example.com", timeoutCfg());
  b->addRecord({"host.example.com", "A", "192.0.2.17", 3600});
  auto r = makeResolver({a.port, b.port}, SHORT_TIMEOUT, /*retryCount=*/0);

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
  MockNode a, b, c;
  a->configureQuery("host.example.com", servfail());
  b->configureQuery("host.example.com", servfail());
  c->configureQuery("host.example.com", servfail());
  auto r = makeResolver({a.port, b.port, c.port});

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
    MockNode a;
    a->configureQuery("host.example.com", servfail());
    auto r = makeResolver({a.port});
    REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsTransientResolutionException);
    REQUIRE(a.udpQueries() == 1);
  }
  SECTION("single-server success")
  {
    MockNode a;
    a->addRecord({"host.example.com", "A", "192.0.2.18", 3600});
    auto r = makeResolver({a.port});
    REQUIRE(r->query(aQ("host.example.com")).isSuccess());
  }
}

TEST_CASE("SYNC SERVFAIL -> NXDOMAIN-on-B stops rotation at B's authoritative negative",
          "[dns][failover][sync][gate]")
{
  MockNode a, b, c;
  a->configureQuery("host.example.com", servfail());
  // B has no record -> authoritative NXDOMAIN. C would succeed but must never be reached.
  c->addRecord({"host.example.com", "A", "192.0.2.19", 3600});
  auto r = makeResolver({a.port, b.port, c.port});

  REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsResolutionFailedException);
  REQUIRE(a.udpQueries() == 1);
  REQUIRE(b.udpQueries() == 1);
  REQUIRE(c.udpQueries() == 0); // stopped at B's authoritative NXDOMAIN
}

TEST_CASE("SYNC 3-server partial set: A SERVFAIL, B SERVFAIL, C NOERROR -> success on C",
          "[dns][failover][sync]")
{
  MockNode a, b, c;
  a->configureQuery("host.example.com", servfail());
  b->configureQuery("host.example.com", servfail());
  c->addRecord({"host.example.com", "A", "192.0.2.20", 3600});
  auto r = makeResolver({a.port, b.port, c.port});

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
  MockNode a, b;
  // A returns a truncated UDP response, then answers the TCP retry (same server).
  MockDnsServer::QueryConfig trunc;
  trunc.shouldTruncate = true;
  a->configureQuery("host.example.com", trunc);
  a->addRecord({"host.example.com", "A", "192.0.2.21", 3600});
  b->addRecord({"host.example.com", "A", "192.0.2.99", 3600});
  auto r = makeResolver({a.port, b.port}, SHORT_TIMEOUT, /*retryCount=*/1,
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
  MockNode a, b;
  // Both families server-local on both servers.
  a->configureQuery("host.example.com", "A", servfail());
  a->configureQuery("host.example.com", "AAAA", servfail());
  b->configureQuery("host.example.com", "A", servfail());
  b->configureQuery("host.example.com", "AAAA", servfail());
  auto r = makeResolver({a.port, b.port});

  REQUIRE_THROWS_AS(r->resolveHostname("host.example.com"), DnsTransientResolutionException);
}

// H-1 (tracker 2026-09-30-4): a type-3 NODATA (NOERROR/empty, no SOA/no NS) is AUTHORITATIVE
// (RFC 2308 §2.2.1) -> resolveHostname reports a permanent no-records, NOT a transient outage.
// (Pre-fix this mis-classified the common dnsmasq/GSLB no-SOA empty answer as retryable.)
TEST_CASE("resolveHostname all-server type-3 NODATA -> DnsNoRecordsException (authoritative)",
          "[dns][failover][sync][resolvehostname]")
{
  MockNode a, b;
  a->configureQuery("host.example.com", "A", nodataNoSoa());
  a->configureQuery("host.example.com", "AAAA", nodataNoSoa());
  b->configureQuery("host.example.com", "A", nodataNoSoa());
  b->configureQuery("host.example.com", "AAAA", nodataNoSoa());
  auto r = makeResolver({a.port, b.port});

  REQUIRE_THROWS_AS(r->resolveHostname("host.example.com"), DnsNoRecordsException);
}

// H-1 (tracker 2026-09-30-4): a REFERRAL (NS in authority, no SOA) IS server-local -> both
// families rotate across all servers and, all exhausted, resolveHostname throws the TRANSIENT
// signal (retryable). This is the branch the pre-fix code took for EVERY no-SOA negative.
TEST_CASE("resolveHostname all-server referral -> transient throw (RFC 2308 §2.2.1)",
          "[dns][failover][sync][resolvehostname]")
{
  MockNode a, b;
  a->configureQuery("host.example.com", "A", referral());
  a->configureQuery("host.example.com", "AAAA", referral());
  b->configureQuery("host.example.com", "A", referral());
  b->configureQuery("host.example.com", "AAAA", referral());
  auto r = makeResolver({a.port, b.port});

  REQUIRE_THROWS_AS(r->resolveHostname("host.example.com"), DnsTransientResolutionException);
}

TEST_CASE("resolveHostname A transient but AAAA success -> returns AAAA, no throw",
          "[dns][failover][sync][resolvehostname]")
{
  MockNode a, b;
  // A-family server-local on both servers; AAAA succeeds on the primary.
  a->configureQuery("host.example.com", "A", servfail());
  b->configureQuery("host.example.com", "A", servfail());
  a->addRecord({"host.example.com", "AAAA", "2001:db8::1", 3600});
  b->addRecord({"host.example.com", "AAAA", "2001:db8::1", 3600});
  auto r = makeResolver({a.port, b.port});

  std::vector<std::string> addrs;
  REQUIRE_NOTHROW(addrs = r->resolveHostname("host.example.com"));
  REQUIRE_FALSE(addrs.empty());
  REQUIRE(addrs[0] == "2001:db8::1"); // a transient sibling does not override a partial success
}

TEST_CASE("resolveHostname all-authoritative-negative -> DnsNoRecordsException (permanent)",
          "[dns][failover][sync][resolvehostname]")
{
  MockNode a, b;
  // No records anywhere -> both families NXDOMAIN (authoritative). Each family's query()
  // stops at its FIRST server's authoritative negative (no rotation), so neither family is
  // failed over — but the resolver's rotation cursor advances per query() call, so the two
  // families start on different servers. The invariant under test is the terminal exception
  // TYPE (permanent, not transient), not which server each family happened to hit.
  auto r = makeResolver({a.port, b.port});
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
  MockNode a(/*log=*/true), b(/*log=*/true);
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

  auto r = makeResolver({a.port, b.port});
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
    MockNode a(/*log=*/true), b(/*log=*/true);
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

    auto r = makeResolver({a.port, b.port});
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
  MockNode a, b;
  a->addRecord({"host.example.com", "A", "192.0.2.40", 3600});
  b->addRecord({"host.example.com", "A", "192.0.2.41", 3600});

  DnsConfig cfg;
  cfg.setServers({"127.0.0.1:" + std::to_string(a.port), "127.0.0.1:" + std::to_string(b.port)});
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
  testnet::RefusingEndpoint dead;
  MockNode b; // real server on TCP (tcpPort == udpPort in MockNode)
  b->addRecord({"host.example.com", "A", "192.0.2.50", 3600});

  // Primary points at a dead port over TCP: connect is refused before any DNS exchange.
  auto r = makeResolver({dead.port(), b.port}, SHORT_TIMEOUT, /*retryCount=*/0,
                        DnsTransportMode::TCP);
  DnsResult result = r->query(aQ("host.example.com"));

  REQUIRE(result.isSuccess());
  REQUIRE(result.a_records[0].address == "192.0.2.50");
  REQUIRE(b.tcpQueries() == 1);
}

TEST_CASE("Transport-level: refused TCP connect throws DnsNetworkException (type discriminates)",
          "[dns][failover][transport][network]")
{
  testnet::RefusingEndpoint dead;
  DnsConfig cfg;
  cfg.setServers({"127.0.0.1:" + std::to_string(dead.port())});
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
    transport->query(aQ("host.example.com"), "127.0.0.1", dead.port());
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

  // Per-server-address behavior. Absent server -> SERVFAIL (server-local, rcode channel).
  std::unordered_map<std::string, DnsResponseCode> rcodeByServer;
  std::unordered_map<std::string, std::vector<std::string>> aByServer; // success addresses (A)
  // ERROR-channel injection: deliver an exception via the callback's `error` arg (models the
  // transport's failCallback/handleClose delivery), keyed by server. 't'=DnsTimeoutException,
  // 'n'=DnsNetworkException, 'l'=lifecycle DnsTransportException.
  std::unordered_map<std::string, char> errorByServer;
  std::atomic<int> issueCount{0};
  std::atomic<int> callbackCount{0};
  int throwOnIssue{-1};        // 1-based Nth issue THROWS std::runtime_error synchronously; -1=off
  int throwNetworkOnIssue{-1}; // 1-based Nth issue THROWS DnsNetworkException synchronously; -1=off
  bool asyncDispatch{true};

  void queryAsync(const DnsQuestion &q, QueryCallback cb, const std::string &server,
                  std::uint16_t) override
  {
    const int n = ++issueCount;
    if (n == throwOnIssue)
    {
      throw std::runtime_error("injected synchronous issue throw @call " + std::to_string(n));
    }
    if (n == throwNetworkOnIssue)
    {
      // Synchronous per-server network throw (e.g. query-ID exhaustion) escaping queryAsync.
      throw DnsNetworkException("injected synchronous network throw @call " + std::to_string(n));
    }

    // Error-channel delivery for this server?
    std::exception_ptr deliverErr;
    auto eit = errorByServer.find(server);
    if (eit != errorByServer.end())
    {
      switch (eit->second)
      {
      case 't':
        deliverErr = std::make_exception_ptr(DnsTimeoutException("injected async timeout"));
        break;
      case 'n':
        deliverErr = std::make_exception_ptr(DnsNetworkException("injected async network fault"));
        break;
      case 'l':
      default:
        deliverErr = std::make_exception_ptr(DnsTransportException("Transport stopped"));
        break;
      }
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

    auto deliver = [this, cb, r, deliverErr]()
    {
      ++callbackCount;
      try
      {
        cb(r, deliverErr);
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
  MockNode a, b;
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
  auto r = makeResolver({a.port, b.port});

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

// =============================================================================
// STEPS 4-8 ROUND-1 FIXES — added test coverage
// =============================================================================

// --- M1: async ERROR-channel failover (timeout / DnsNetworkException) + synchronous network throw ---

TEST_CASE("ASYNC timeout via error channel on A -> failover to B", "[dns][failover][async][errchan]")
{
  auto t = makeDouble({"10.0.0.1:53", "10.0.0.2:53"});
  t->errorByServer["10.0.0.1"] = 't'; // DnsTimeoutException via the callback error arg
  t->rcodeByServer["10.0.0.2"] = DnsResponseCode::NOERROR;
  t->aByServer["10.0.0.2"] = {"192.0.2.80"};
  auto r = resolverOver(t);

  auto out = driveQueryAsync(r, aQ("host.example.com"));
  REQUIRE(out.completed);
  REQUIRE(out.callbacks == 1);
  REQUIRE(out.result.isSuccess());
  REQUIRE(out.result.a_records[0].address == "192.0.2.80");
}

TEST_CASE("ASYNC DnsNetworkException via error channel on A -> failover to B",
          "[dns][failover][async][errchan]")
{
  auto t = makeDouble({"10.0.0.1:53", "10.0.0.2:53"});
  t->errorByServer["10.0.0.1"] = 'n'; // DnsNetworkException via the callback error arg
  t->rcodeByServer["10.0.0.2"] = DnsResponseCode::NOERROR;
  t->aByServer["10.0.0.2"] = {"192.0.2.81"};
  auto r = resolverOver(t);

  auto out = driveQueryAsync(r, aQ("host.example.com"));
  REQUIRE(out.completed);
  REQUIRE(out.callbacks == 1);
  REQUIRE(out.result.isSuccess());
  REQUIRE(out.result.a_records[0].address == "192.0.2.81");
}

TEST_CASE("ASYNC lifecycle error via error channel on A -> TERMINAL, no failover",
          "[dns][failover][async][errchan][terminal]")
{
  auto t = makeDouble({"10.0.0.1:53", "10.0.0.2:53"});
  t->errorByServer["10.0.0.1"] = 'l'; // lifecycle DnsTransportException -> terminal
  t->rcodeByServer["10.0.0.2"] = DnsResponseCode::NOERROR;
  t->aByServer["10.0.0.2"] = {"192.0.2.82"};
  auto r = resolverOver(t);

  auto out = driveQueryAsync(r, aQ("host.example.com"));
  REQUIRE(out.completed);
  REQUIRE(out.callbacks == 1);
  REQUIRE(out.error);              // delivered terminal, not failed over
  REQUIRE(t->issueCount.load() == 1); // B never contacted
}

TEST_CASE("ASYNC synchronous DnsNetworkException throw on first issue -> failover to B",
          "[dns][failover][async][throw]")
{
  // Exercises the helper's catch(DnsNetworkException) -> continue advance (e.g. query-ID
  // exhaustion escaping queryAsync). Mutation intent: the pre-H1 behavior (slicing) or a missing
  // network-catch would make this terminal (no failover) and the address assert fail.
  auto t = makeDouble({"10.0.0.1:53", "10.0.0.2:53"});
  t->throwNetworkOnIssue = 1; // first issue throws DnsNetworkException synchronously
  t->rcodeByServer["10.0.0.2"] = DnsResponseCode::NOERROR;
  t->aByServer["10.0.0.2"] = {"192.0.2.83"};
  auto r = resolverOver(t);

  auto out = driveQueryAsync(r, aQ("host.example.com"));
  REQUIRE(out.completed);
  REQUIRE(out.callbacks == 1);
  REQUIRE(out.result.isSuccess());
  REQUIRE(out.result.a_records[0].address == "192.0.2.83");
}

// --- helper: drive resolveServiceDomainAsync and block for the result ---

namespace
{
ServiceResolutionResult driveServiceAsync(const std::shared_ptr<DnsResolver> &r,
                                          const std::string &domain,
                                          const std::vector<ServiceType> &preferred = {},
                                          bool secure = false)
{
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
    preferred, secure);
  if (fut.wait_for(ASYNC_WAIT) != std::future_status::ready)
  {
    throw std::runtime_error("async service resolve timed out: " + domain);
  }
  return fut.get();
}
} // namespace

// --- M2c: async A/AAAA fan-out failover (issueTargetFamily via the helper) ---

TEST_CASE("ASYNC A/AAAA fan-out failover: target host A SERVFAIL on one server, resolved via other",
          "[dns][failover][async][wire][aaaa]")
{
  MockNode a, b;
  const std::string domain = "example.net";
  const std::string srvName = "_sip._udp." + domain;
  for (auto *n : {&a, &b})
  {
    (*n)->addRecord(naptrS(domain, srvName));
    (*n)->addRecord({srvName, "SRV", "sip1." + domain, 3600, 10, 0, 5060});
  }
  // The target host's A SERVFAILs on A but is present on B -> the A/AAAA fan-out must fail over.
  a->configureQuery("sip1." + domain, "A", servfail());
  b->addRecord({"sip1." + domain, "A", "192.0.2.90", 3600});
  auto r = makeResolver({a.port, b.port});

  ServiceResolutionResult res = driveServiceAsync(r, domain, {ServiceType::SIP_UDP});
  REQUIRE(res.isSuccess());
  const auto *tg = &res.targets.front();
  REQUIRE(tg->hostname == "sip1." + domain);
  REQUIRE_FALSE(tg->addresses.empty()); // failover recovered the address
}

// --- H3: async SRV-success but ALL target A/AAAA transient -> outcome=TransientFailure ---

TEST_CASE("ASYNC SRV target with all-server-transient A/AAAA -> outcome=TransientFailure",
          "[dns][failover][async][outcome][aaaa]")
{
  MockNode a, b;
  const std::string domain = "example.net";
  const std::string srvName = "_sip._udp." + domain;
  for (auto *n : {&a, &b})
  {
    (*n)->addRecord(naptrS(domain, srvName));
    (*n)->addRecord({srvName, "SRV", "sip1." + domain, 3600, 10, 0, 5060});
    // The one target host's A AND AAAA SERVFAIL on BOTH servers -> the target is wiped out, and
    // the terminal A/AAAA avenue must classify the empty result as transient (retryable).
    (*n)->configureQuery("sip1." + domain, "A", servfail());
    (*n)->configureQuery("sip1." + domain, "AAAA", servfail());
  }
  auto r = makeResolver({a.port, b.port});

  ServiceResolutionResult res = driveServiceAsync(r, domain, {ServiceType::SIP_UDP});
  REQUIRE_FALSE(res.isSuccess());
  REQUIRE(res.outcome == ResolutionOutcome::TransientFailure);
}

// --- M2b: SIPS/secure-path failover preserves the b2 secure filter (no plaintext leak) ---

TEST_CASE("ASYNC secure resolution failover preserves the SIPS filter (no plaintext target)",
          "[dns][failover][async][secure]")
{
  MockNode a, b;
  const std::string domain = "secure.example.net";
  const std::string sipsSrv = "_sips._tcp." + domain;
  // A SERVFAILs the NAPTR and the SIPS SRV; B answers the secure chain.
  a->configureQuery(domain, "NAPTR", servfail());
  a->configureQuery(sipsSrv, "SRV", servfail());
  b->addRecord({sipsSrv, "SRV", "sips1." + domain, 3600, 10, 0, 5061});
  for (auto *n : {&a, &b})
  {
    (*n)->addRecord({"sips1." + domain, "A", "192.0.2.91", 3600});
  }
  auto r = makeResolver({a.port, b.port});

  ServiceResolutionResult res = driveServiceAsync(r, domain, {ServiceType::SIPS_TLS}, /*secure=*/true);
  REQUIRE(res.isSuccess()); // non-vacuous: failover to B produced the secure direct-SRV target
  // Every produced target must be a secure SIP service after failover (RFC 3263 §4.1); a plaintext
  // target would be a b2-filter regression across the failover boundary.
  for (const auto &tgt : res.targets)
  {
    REQUIRE(isSecureSipService(tgt.transport));
  }
}

// --- M3: NOTIMP-on-SRV failover (sync direct-SRV path) ---

TEST_CASE("SYNC NOTIMP on a direct-SRV query -> failover to B", "[dns][failover][sync][gate]")
{
  MockNode a, b;
  const std::string domain = "example.net";
  const std::string srvName = "_sip._udp." + domain;
  // No NAPTR anywhere -> direct-SRV. The SRV query gets NOTIMP on A (server-local for a NON-NAPTR
  // query -> rotate), succeeds on B.
  a->configureQuery(srvName, "SRV", notimp());
  b->addRecord({srvName, "SRV", "sip1." + domain, 3600, 10, 0, 5060});
  for (auto *n : {&a, &b})
  {
    (*n)->addRecord({"sip1." + domain, "A", "192.0.2.92", 3600});
  }
  auto r = makeResolver({a.port, b.port});

  ServiceResolutionResult res = r->resolveServiceDomain(domain, {ServiceType::SIP_UDP});
  REQUIRE(res.isSuccess());
}

// --- M3: N=1 single-server TIMEOUT -> transient ---

TEST_CASE("SYNC N=1 single-server timeout -> DnsTransientResolutionException",
          "[dns][failover][sync][timeout]")
{
  MockNode a;
  a->configureQuery("host.example.com", timeoutCfg());
  auto r = makeResolver({a.port}, SHORT_TIMEOUT, /*retryCount=*/0);
  REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsTransientResolutionException);
}

// --- M3: resolveHostname all-server TIMEOUT variant -> transient ---

TEST_CASE("resolveHostname all-server timeout -> transient throw", "[dns][failover][sync][resolvehostname]")
{
  MockNode a, b;
  a->configureQuery("host.example.com", "A", timeoutCfg());
  a->configureQuery("host.example.com", "AAAA", timeoutCfg());
  b->configureQuery("host.example.com", "A", timeoutCfg());
  b->configureQuery("host.example.com", "AAAA", timeoutCfg());
  auto r = makeResolver({a.port, b.port}, SHORT_TIMEOUT, /*retryCount=*/0);
  REQUIRE_THROWS_AS(r->resolveHostname("host.example.com"), DnsTransientResolutionException);
}

// --- H4: SYNC resolveServiceDomain per-avenue outcome ---

TEST_CASE("SYNC resolveServiceDomain all-server-transient -> outcome=TransientFailure",
          "[dns][failover][sync][outcome]")
{
  MockNode a, b;
  const std::string domain = "example.net";
  const std::string srvName = "_sip._udp." + domain;
  for (auto *n : {&a, &b})
  {
    (*n)->addRecord(naptrS(domain, srvName));
    (*n)->addRecord({srvName, "SRV", "sip1." + domain, 3600, 10, 0, 5060});
    (*n)->configureQuery("sip1." + domain, "A", servfail());
    (*n)->configureQuery("sip1." + domain, "AAAA", servfail());
  }
  auto r = makeResolver({a.port, b.port});
  ServiceResolutionResult res = r->resolveServiceDomain(domain, {ServiceType::SIP_UDP});
  REQUIRE_FALSE(res.isSuccess());
  REQUIRE(res.outcome == ResolutionOutcome::TransientFailure);
}

TEST_CASE("SYNC resolveServiceDomain success -> outcome=Resolved", "[dns][failover][sync][outcome]")
{
  MockNode a, b;
  const std::string domain = "example.net";
  const std::string srvName = "_sip._udp." + domain;
  for (auto *n : {&a, &b})
  {
    (*n)->addRecord(naptrS(domain, srvName));
    (*n)->addRecord({srvName, "SRV", "sip1." + domain, 3600, 10, 0, 5060});
    (*n)->addRecord({"sip1." + domain, "A", "192.0.2.93", 3600});
  }
  auto r = makeResolver({a.port, b.port});
  ServiceResolutionResult res = r->resolveServiceDomain(domain, {ServiceType::SIP_UDP});
  REQUIRE(res.isSuccess());
  REQUIRE(res.outcome == ResolutionOutcome::Resolved);
}

// =============================================================================
// STEPS 4-8 ROUND-2 FIXES — added test coverage
// =============================================================================

// --- M-2: CAS handshake arms exercised DETERMINISTICALLY (not race-won) ---

TEST_CASE("ASYNC inline SERVFAIL->success exercises the sync-completion CAS arm (state 1)",
          "[dns][failover][async][cas]")
{
  // asyncDispatch=false -> the completion fires INLINE inside queryAsync on the issuer thread, so
  // the callback's CAS(0->1) wins and the issuer epilogue observes HANDOFF_CB_ADVANCE and advances
  // via the loop (the state-1 path a real synchronous send-failure takes). Deterministic.
  auto t = makeDouble({"10.0.0.1:53", "10.0.0.2:53"});
  t->asyncDispatch = false;
  t->rcodeByServer["10.0.0.1"] = DnsResponseCode::SERVFAIL;
  t->rcodeByServer["10.0.0.2"] = DnsResponseCode::NOERROR;
  t->aByServer["10.0.0.2"] = {"192.0.2.100"};
  auto r = resolverOver(t);

  auto out = driveQueryAsync(r, aQ("host.example.com"));
  REQUIRE(out.completed);
  REQUIRE(out.callbacks == 1);
  REQUIRE(out.result.isSuccess());
  REQUIRE(t->issueCount.load() == 2); // A (SERVFAIL) then B (success), iterative, no recursion
}

TEST_CASE("ASYNC inline N=3 all-SERVFAIL -> one transient terminal, exactly N issues",
          "[dns][failover][async][cas]")
{
  auto t = makeDouble({"10.0.0.1:53", "10.0.0.2:53", "10.0.0.3:53"});
  t->asyncDispatch = false; // all inline
  auto r = resolverOver(t);
  auto out = driveQueryAsync(r, aQ("host.example.com"));
  REQUIRE(out.completed);
  REQUIRE(out.callbacks == 1);
  REQUIRE(out.error);
  REQUIRE(t->issueCount.load() == 3);
}

TEST_CASE("ASYNC synchronous throw on the SECOND issue -> exactly one terminal, no hang",
          "[dns][failover][async][cas][throw]")
{
  // First issue (A) inline-SERVFAILs and advances; the second issue throws synchronously -> the
  // helper's catch(...) delivers exactly one terminal. Mutation intent: a double-fire or a lost
  // terminal makes callbacks != 1 or the wait time out.
  auto t = makeDouble({"10.0.0.1:53", "10.0.0.2:53"});
  t->asyncDispatch = false;
  t->rcodeByServer["10.0.0.1"] = DnsResponseCode::SERVFAIL;
  t->throwOnIssue = 2;
  auto r = resolverOver(t);
  auto out = driveQueryAsync(r, aQ("host.example.com"));
  REQUIRE(out.completed);
  REQUIRE(out.callbacks == 1);
  REQUIRE(out.error);
}

TEST_CASE("ASYNC throwing user callback on the ISSUER-thread deliver does not double-fire (M-1)",
          "[dns][failover][async][exactly-once]")
{
  // The throw must reach the HELPER's own issuer-thread `deliver` guard, not the double's inline
  // callback wrap (MEDIUM-2 fix: the prior single-NOERROR-server version was vacuous — the double's
  // try/catch swallowed the throw before the helper saw it). Here BOTH servers SERVFAIL with inline
  // dispatch, so the terminal transient is delivered from the issuer-thread exhaustion path
  // (helper `deliver`). If the helper did NOT guard it, the throw would escape to the twin's site
  // catch(...) and re-deliver -> count == 2. Mutation intent: remove the deliver guard -> this fails.
  auto t = makeDouble({"10.0.0.1:53", "10.0.0.2:53"});
  t->asyncDispatch = false; // all inline -> exhaustion delivered on the issuer thread
  auto r = resolverOver(t);

  auto count = std::make_shared<std::atomic<int>>(0);
  r->queryAsync(aQ("host.example.com"),
                [count](const DnsResult &, const std::exception_ptr &)
                {
                  count->fetch_add(1);
                  throw std::runtime_error("user callback throws");
                });
  std::this_thread::sleep_for(std::chrono::milliseconds(80));
  REQUIRE(count->load() == 1); // exactly once despite the throw (no twin re-fire)
}

// --- M-3: real-transport async connect-refused (H1 / handleClose DnsNetworkException path) ---

TEST_CASE("ASYNC connect-refused on primary (TCP, real transport) -> failover to B",
          "[dns][failover][async][wire][network]")
{
  testnet::RefusingEndpoint dead;
  MockNode b;
  b->addRecord({"host.example.com", "A", "192.0.2.102", 3600});
  auto r = makeResolver({dead.port(), b.port}, SHORT_TIMEOUT, /*retryCount=*/0, DnsTransportMode::TCP);
  auto out = driveQueryAsync(r, aQ("host.example.com"));
  REQUIRE(out.completed);
  REQUIRE(out.callbacks == 1);
  REQUIRE(out.result.isSuccess()); // handleClose DnsNetworkException -> failover through the real transport
  REQUIRE(b.tcpQueries() == 1);
}

// --- HIGH-A: NAPTR-S (SRV terminal, no A/AAAA fallback) per-avenue outcome ---

TEST_CASE("SYNC NAPTR-S all-SRV-transient -> outcome=TransientFailure (SRV is terminal)",
          "[dns][failover][sync][outcome][naptr]")
{
  MockNode a, b;
  const std::string domain = "example.net";
  const std::string srvName = "_sip._udp." + domain;
  for (auto *n : {&a, &b})
  {
    (*n)->addRecord(naptrS(domain, srvName));
    (*n)->configureQuery(srvName, "SRV", servfail()); // SRV exhausts server-local on both servers
  }
  auto r = makeResolver({a.port, b.port});
  ServiceResolutionResult res = r->resolveServiceDomain(domain, {ServiceType::SIP_UDP});
  REQUIRE_FALSE(res.isSuccess());
  REQUIRE(res.outcome == ResolutionOutcome::TransientFailure);
}

TEST_CASE("ASYNC NAPTR-S all-SRV-transient -> outcome=TransientFailure",
          "[dns][failover][async][outcome][naptr]")
{
  MockNode a, b;
  const std::string domain = "example.net";
  const std::string srvName = "_sip._udp." + domain;
  for (auto *n : {&a, &b})
  {
    (*n)->addRecord(naptrS(domain, srvName));
    (*n)->configureQuery(srvName, "SRV", servfail());
  }
  auto r = makeResolver({a.port, b.port});
  ServiceResolutionResult res = driveServiceAsync(r, domain, {ServiceType::SIP_UDP});
  REQUIRE_FALSE(res.isSuccess());
  REQUIRE(res.outcome == ResolutionOutcome::TransientFailure);
}

// --- M-4: PermanentNoService negative controls (authoritative negative, not transient) ---

TEST_CASE("SYNC target host all-NXDOMAIN -> outcome=PermanentNoService", "[dns][failover][sync][outcome]")
{
  MockNode a, b;
  const std::string domain = "example.net";
  const std::string srvName = "_sip._udp." + domain;
  for (auto *n : {&a, &b})
  {
    (*n)->addRecord(naptrS(domain, srvName));
    (*n)->addRecord({srvName, "SRV", "sip1." + domain, 3600, 10, 0, 5060});
    // sip1 has NO A/AAAA record anywhere -> authoritative NXDOMAIN -> permanent, not transient.
  }
  auto r = makeResolver({a.port, b.port});
  ServiceResolutionResult res = r->resolveServiceDomain(domain, {ServiceType::SIP_UDP});
  REQUIRE_FALSE(res.isSuccess());
  REQUIRE(res.outcome == ResolutionOutcome::PermanentNoService);
}

TEST_CASE("ASYNC target host all-NXDOMAIN -> outcome=PermanentNoService", "[dns][failover][async][outcome]")
{
  MockNode a, b;
  const std::string domain = "example.net";
  const std::string srvName = "_sip._udp." + domain;
  for (auto *n : {&a, &b})
  {
    (*n)->addRecord(naptrS(domain, srvName));
    (*n)->addRecord({srvName, "SRV", "sip1." + domain, 3600, 10, 0, 5060});
  }
  auto r = makeResolver({a.port, b.port});
  ServiceResolutionResult res = driveServiceAsync(r, domain, {ServiceType::SIP_UDP});
  REQUIRE_FALSE(res.isSuccess());
  REQUIRE(res.outcome == ResolutionOutcome::PermanentNoService);
}

// --- M-2: async Q5 (NAPTR NOTIMP delivered terminal, no rotation, direct-SRV) ---

TEST_CASE("ASYNC NAPTR NOTIMP -> straight to direct-SRV, B not asked for NAPTR (Q5)",
          "[dns][failover][async][naptr][q5]")
{
  MockNode a(/*log=*/true), b(/*log=*/true);
  const std::string domain = "example.net";
  const std::string srvName = "_sip._udp." + domain;
  a->configureQuery(domain, "NAPTR", notimp());
  for (auto *n : {&a, &b})
  {
    (*n)->addRecord({srvName, "SRV", "sip1." + domain, 3600, 10, 0, 5060});
    (*n)->addRecord({"sip1." + domain, "A", "192.0.2.103", 3600});
    (*n)->addRecord({"sip1." + domain, "AAAA", "2001:db8::103", 3600});
  }
  auto r = makeResolver({a.port, b.port});
  ServiceResolutionResult res = driveServiceAsync(r, domain, {ServiceType::SIP_UDP});
  REQUIRE(res.isSuccess());
  REQUIRE(a.countType(35) == 1); // exactly ONE NAPTR query
  REQUIRE(b.countType(35) == 0); // Q5: NOT rotated across servers
}

// --- L-6: strengthened SIPS/secure failover (non-vacuous: isSuccess + plaintext bait) ---

TEST_CASE("SIPS/secure failover exercises the NAPTR §4.1 filter: plaintext NAPTR discarded (LOW-4)",
          "[dns][failover][async][secure][naptr]")
{
  MockNode a(/*log=*/true), b(/*log=*/true);
  const std::string domain = "secure.example.net";
  const std::string sipsSrv = "_sips._tcp." + domain;
  const std::string sipTcpSrv = "_sip._tcp." + domain;
  // A SERVFAILs the NAPTR -> the NAPTR query fails over to B. B publishes BOTH a SIPS+D2T NAPTR
  // (secure) and a SIP+D2T NAPTR (plaintext bait). The secure resolution's RFC 3263 §4.1
  // service-field filter must discard the plaintext NAPTR outright, so the plaintext SRV/target is
  // never even queried. A filter regression across the failover boundary would surface plain1.
  a->configureQuery(domain, "NAPTR", servfail());
  for (auto *n : {&a, &b})
  {
    (*n)->addRecord(naptrSvc(domain, "SIPS+D2T", sipsSrv, /*order=*/10));
    (*n)->addRecord(naptrSvc(domain, "SIP+D2T", sipTcpSrv, /*order=*/20)); // plaintext bait
    (*n)->addRecord({sipsSrv, "SRV", "sips1." + domain, 3600, 10, 0, 5061});
    (*n)->addRecord({sipTcpSrv, "SRV", "plain1." + domain, 3600, 10, 0, 5060});
    (*n)->addRecord({"sips1." + domain, "A", "192.0.2.104", 3600});
    (*n)->addRecord({"plain1." + domain, "A", "192.0.2.105", 3600});
  }
  auto r = makeResolver({a.port, b.port});
  ServiceResolutionResult res = driveServiceAsync(r, domain, {ServiceType::SIPS_TLS}, /*secure=*/true);

  REQUIRE(res.isSuccess());        // non-vacuous: the secure chain resolved
  REQUIRE(a.countType(35) == 1);   // NAPTR failed over: A asked once (SERVFAIL) ...
  REQUIRE(b.countType(35) >= 1);   // ... then B answered the NAPTR (proves failover happened)
  for (const auto &tgt : res.targets)
  {
    REQUIRE(isSecureSipService(tgt.transport)); // no plaintext target leaked across failover
    REQUIRE(tgt.hostname != "plain1." + domain);
  }
}

// =============================================================================
// STEPS 4-8 ROUND-3 FIXES — added test coverage
// =============================================================================

namespace
{
// Two NAPTR-S records (two SRV owner names) so a NAPTR-S fan-out has SIBLING SRV sets. They share
// the SAME NAPTR order (both selected in one tier) with distinct preference, so BOTH SRV owner
// names are queried in the fan-out (a lower-order + higher-order pair would select only the lower).
void addTwoNaptrSets(MockNode &n, const std::string &domain, const std::string &udpSrv,
                     const std::string &tcpSrv)
{
  n->addRecord(naptrSvc(domain, "SIP+D2U", udpSrv, /*order=*/10, /*pref=*/10));
  n->addRecord(naptrSvc(domain, "SIP+D2T", tcpSrv, /*order=*/10, /*pref=*/20));
}
} // namespace

// --- MEDIUM-3: NAPTR-S partial success is not overwritten by a transient sibling ---

TEST_CASE("NAPTR-S partial success (one SRV set transient, other resolves) -> Resolved (sync+async)",
          "[dns][failover][outcome][naptr]")
{
  const std::string domain = "example.net";
  const std::string udpSrv = "_sip._udp." + domain;
  const std::string tcpSrv = "_sip._tcp." + domain;
  const std::vector<ServiceType> pref{ServiceType::SIP_UDP, ServiceType::SIP_TCP};

  auto configure = [&](MockNode &a, MockNode &b)
  {
    for (auto *n : {&a, &b})
    {
      addTwoNaptrSets(*n, domain, udpSrv, tcpSrv);
      (*n)->configureQuery(udpSrv, "SRV", servfail());                          // set 1 transient
      (*n)->addRecord({tcpSrv, "SRV", "sip2." + domain, 3600, 10, 0, 5060});    // set 2 resolves
      (*n)->addRecord({"sip2." + domain, "A", "192.0.2.110", 3600});
    }
  };

  SECTION("sync")
  {
    MockNode a, b;
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = r->resolveServiceDomain(domain, pref);
    REQUIRE(res.isSuccess());
    REQUIRE(res.outcome == ResolutionOutcome::Resolved);
  }
  SECTION("async")
  {
    MockNode a, b;
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = driveServiceAsync(r, domain, pref);
    REQUIRE(res.isSuccess());
    REQUIRE(res.outcome == ResolutionOutcome::Resolved);
  }
}

TEST_CASE("NAPTR-S all-SRV-authoritative-negative -> PermanentNoService (sync+async)",
          "[dns][failover][outcome][naptr]")
{
  const std::string domain = "example.net";
  const std::string udpSrv = "_sip._udp." + domain;
  const std::string tcpSrv = "_sip._tcp." + domain;
  const std::vector<ServiceType> pref{ServiceType::SIP_UDP, ServiceType::SIP_TCP};

  // Both SRV owner names have NO SRV record -> authoritative NXDOMAIN (not transient).
  auto configure = [&](MockNode &a, MockNode &b)
  {
    for (auto *n : {&a, &b})
    {
      addTwoNaptrSets(*n, domain, udpSrv, tcpSrv);
    }
  };

  SECTION("sync")
  {
    MockNode a, b;
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = r->resolveServiceDomain(domain, pref);
    REQUIRE_FALSE(res.isSuccess());
    REQUIRE(res.outcome == ResolutionOutcome::PermanentNoService);
  }
  SECTION("async")
  {
    MockNode a, b;
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = driveServiceAsync(r, domain, pref);
    REQUIRE_FALSE(res.isSuccess());
    REQUIRE(res.outcome == ResolutionOutcome::PermanentNoService);
  }
}

// --- MEDIUM-1: sync and async agree on the mixed NAPTR-S case (SRV target wiped by A/AAAA) ---

TEST_CASE("NAPTR-S mixed (transient SRV sibling + resolved-then-NXDOMAIN target): sync == async",
          "[dns][failover][outcome][naptr][parity]")
{
  const std::string domain = "example.net";
  const std::string udpSrv = "_sip._udp." + domain;
  const std::string tcpSrv = "_sip._tcp." + domain;
  const std::vector<ServiceType> pref{ServiceType::SIP_UDP, ServiceType::SIP_TCP};

  // set 1 (_sip._udp) SERVFAILs on all servers (transient). set 2 (_sip._tcp) resolves to sip2, but
  // sip2 has NO A/AAAA anywhere (authoritative NXDOMAIN) -> sip2 wiped. SRV DID produce a target, so
  // the terminal avenue is the A/AAAA resolution (authoritative) -> PermanentNoService. Combining the
  // transient SRV sibling with the permanent A/AAAA branch is CROSS-STEP (tracker 2026-09-30-1); Slice
  // A must give the SAME answer sync and async (the round-2 fold made them disagree — MEDIUM-1).
  auto configure = [&](MockNode &a, MockNode &b)
  {
    for (auto *n : {&a, &b})
    {
      addTwoNaptrSets(*n, domain, udpSrv, tcpSrv);
      (*n)->configureQuery(udpSrv, "SRV", servfail());
      (*n)->addRecord({tcpSrv, "SRV", "sip2." + domain, 3600, 10, 0, 5060});
      // sip2: no A/AAAA -> NXDOMAIN
    }
  };

  ResolutionOutcome syncOutcome, asyncOutcome;
  {
    MockNode a, b;
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    syncOutcome = r->resolveServiceDomain(domain, pref).outcome;
  }
  {
    MockNode a, b;
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    asyncOutcome = driveServiceAsync(r, domain, pref).outcome;
  }
  REQUIRE(syncOutcome == asyncOutcome);                         // parity is the invariant under test
  REQUIRE(syncOutcome == ResolutionOutcome::PermanentNoService); // Slice-A terminal-avenue answer
}

// =============================================================================
// ROUND-4 FIXES — tracker 2026-09-30-4 (doc-review round-3 RFC-compliance HIGHs + M-4)
// =============================================================================

// --- H-2: the sync-wait budget covers (retryCount+1) full timeout windows ---

TEST_CASE("H-2: sync-wait budget honors retryCount ((retryCount+1) full timeouts)",
          "[dns][failover][sync][budget]")
{
  // calculateMaxSyncWaitTime must allot a full `timeout` to EACH of the retryCount+1 attempts so
  // the sync retransmit schedule is not truncated (RFC-honored retryCount). Pre-fix it started the
  // budget at ONE timeout, so queryMultiple's wait_for abandoned the query after ~2 sends. This is
  // the deterministic budget assertion (the seam calcMaxSyncWait exists for exactly this — C-L2);
  // mutation: revert totalWait to `cfg->timeout` -> the budget drops below (retryCount+1)*timeout.
  using Access = iora::network::dns::DnsTransportTestAccess;
  DnsConfig cfg;
  cfg.setServers({"127.0.0.1:5399"});
  cfg.timeout = std::chrono::milliseconds(5000);
  cfg.retryCount = 3;
  auto t = std::make_shared<DnsTransport>(cfg);
  // The budget must cover a full `timeout` per attempt AND the inter-attempt backoff (so the last
  // send is not cut off). Pre-H-2 budget = 1*timeout + backoff + 2s = 10.85s < 20s = 4*timeout.
  REQUIRE(Access::calcMaxSyncWait(*t) >= cfg.timeout * (cfg.retryCount + 1));

  // M-2: a misconfigured negative retryCount must NOT collapse the budget below one timeout. Use a
  // timeout strictly larger than the 2s margin so the pre-fix formula (timeout*0 + 2000 = 2000)
  // lands BELOW the threshold (5000) — otherwise the assertion is vacuous (round-2 MED-1).
  DnsConfig cfgNeg;
  cfgNeg.setServers({"127.0.0.1:5399"});
  cfgNeg.timeout = std::chrono::milliseconds(5000);
  cfgNeg.retryCount = -1;
  auto tNeg = std::make_shared<DnsTransport>(cfgNeg);
  // clamp to 0 retries -> exactly one full timeout window + the 2s margin (no backoff at 0 retries).
  REQUIRE(Access::calcMaxSyncWait(*tNeg) >= cfgNeg.timeout);
  REQUIRE(Access::calcMaxSyncWait(*tNeg) == cfgNeg.timeout + std::chrono::milliseconds(2000));
}

TEST_CASE("H-2: sync path issues retryCount+1 sends to a blackhole server before throwing",
          "[dns][failover][sync][retry]")
{
  // End-to-end proof (not just the formula): a silent server must receive initial + retryCount
  // retransmits before the sync wait gives up. timeout dominates the backoff so pre-H-2's
  // 1*timeout+backoff+2s budget cuts the schedule off before the 4th send (~3 sends), while the
  // H-2 4*timeout budget admits all 4. Mutation: revert H-2 -> udpQueries() drops below 4.
  MockNode a;
  a->configureQuery("blackhole.example.com", timeoutCfg()); // never responds
  DnsConfig cfg;
  cfg.setServers({"127.0.0.1:" + std::to_string(a.port)});
  cfg.timeout = std::chrono::milliseconds(1200);
  cfg.retryCount = 3;
  cfg.initialRetryDelay = std::chrono::milliseconds(50);
  cfg.retryMultiplier = 1.0; // constant small backoff so `timeout` dominates the budget
  cfg.jitterFactor = 0.0;
  cfg.transportMode = DnsTransportMode::UDP;
  auto transport = std::make_shared<DnsTransport>(cfg);
  transport->start();
  auto r = std::make_shared<DnsResolver>(transport, nullptr, cfg);
  REQUIRE_THROWS_AS(r->query(aQ("blackhole.example.com")), DnsTransientResolutionException);
  REQUIRE(a.udpQueries() == 4); // initial + 3 retries; pre-H-2 the budget truncated this to < 4
}

// --- H-3: NAPTR-S all-SRV-authoritative-negative -> RFC 3263 §4.2 A/AAAA fallback of the domain ---

TEST_CASE("H-3: NAPTR-S all-SRV-NXDOMAIN -> §4.2 A/AAAA fallback on the NAPTR transport (sync+async)",
          "[dns][failover][outcome][naptr][fallback]")
{
  const std::string domain = "fallback.example.net";
  const std::string srvName = "_sip._udp." + domain;

  // NAPTR-S points at an SRV owner name that has NO SRV record (authoritative NXDOMAIN), and the
  // domain apex publishes an A record. RFC 3263 §4.2: fall back to an A/AAAA lookup of the domain
  // on the NAPTR-chosen transport (SIP_UDP) at the default port. Pre-fix: empty result / no target.
  auto configure = [&](MockNode &a, MockNode &b)
  {
    for (auto *n : {&a, &b})
    {
      (*n)->addRecord(naptrS(domain, srvName)); // SIP+D2U -> SIP_UDP
      // srvName: no SRV record anywhere -> authoritative NXDOMAIN
      (*n)->addRecord({domain, "A", "192.0.2.200", 3600}); // apex A for the §4.2 fallback
    }
  };

  SECTION("sync")
  {
    MockNode a, b;
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = r->resolveServiceDomain(domain, {ServiceType::SIP_UDP});
    REQUIRE(res.isSuccess());
    REQUIRE(res.outcome == ResolutionOutcome::Resolved);
    REQUIRE(res.targets.size() == 1);
    REQUIRE(res.targets[0].hostname == domain);              // A/AAAA of the DOMAIN, not an SRV host
    REQUIRE(res.targets[0].transport == ServiceType::SIP_UDP); // the NAPTR-chosen transport
    REQUIRE(res.targets[0].port == 5060);                    // default SIP_UDP port
  }
  SECTION("async")
  {
    MockNode a, b;
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = driveServiceAsync(r, domain, {ServiceType::SIP_UDP});
    REQUIRE(res.isSuccess());
    REQUIRE(res.outcome == ResolutionOutcome::Resolved);
    REQUIRE(res.targets.size() == 1);
    REQUIRE(res.targets[0].hostname == domain);
    REQUIRE(res.targets[0].transport == ServiceType::SIP_UDP);
    REQUIRE(res.targets[0].port == 5060);
  }
}

TEST_CASE("H-3: NAPTR-S SRV '.' suppresses the §4.2 fallback for that service (RFC 2782) (sync+async)",
          "[dns][failover][outcome][naptr][fallback][rfc2782]")
{
  const std::string domain = "denied.example.net";
  const std::string srvName = "_sip._udp." + domain;

  // The SRV set returns an RFC 2782 "." (service decidedly unavailable). The §4.2 A/AAAA fallback
  // MUST be suppressed for that service even though the apex publishes an A record -> the sole
  // service is denied -> PermanentNoService, and the apex A is a bait that must NOT be used.
  auto configure = [&](MockNode &a, MockNode &b)
  {
    for (auto *n : {&a, &b})
    {
      (*n)->addRecord(naptrS(domain, srvName));                     // SIP+D2U -> SIP_UDP
      (*n)->addRecord({srvName, "SRV", ".", 3600, 0, 0, 0});        // RFC 2782 "." abort
      (*n)->addRecord({domain, "A", "192.0.2.201", 3600});         // bait: must NOT be used
    }
  };

  SECTION("sync")
  {
    MockNode a, b;
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = r->resolveServiceDomain(domain, {ServiceType::SIP_UDP});
    REQUIRE_FALSE(res.isSuccess());
    REQUIRE(res.outcome == ResolutionOutcome::PermanentNoService);
  }
  SECTION("async")
  {
    MockNode a, b;
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = driveServiceAsync(r, domain, {ServiceType::SIP_UDP});
    REQUIRE_FALSE(res.isSuccess());
    REQUIRE(res.outcome == ResolutionOutcome::PermanentNoService);
  }
}

// --- M-4: direct-SRV all-server-transient must NOT fall back to the domain apex ---

TEST_CASE("M-4: direct-SRV all-server-SERVFAIL -> TransientFailure, NO apex A/AAAA fallback (sync+async)",
          "[dns][failover][outcome][fallback][m4]")
{
  const std::string domain = "m4direct.example.net";
  const std::string srvName = "_sip._udp." + domain;

  // No NAPTR (the apex has only an A record) -> direct-SRV path. Every SRV query SERVFAILs on all
  // servers (transient). A transient SRV outage is NOT proof of absence, so the bare-domain A/AAAA
  // fallback MUST be suppressed and the outcome carried as TransientFailure. The apex A is a bait:
  // if the fallback wrongly fired it would resolve and report Resolved (the pre-fix masking bug).
  // Mutation: drop the anySrvTransient gate -> outcome becomes Resolved with an apex target and
  // countType(1) (A queries) becomes >= 1.
  auto configure = [&](MockNode &a, MockNode &b)
  {
    for (auto *n : {&a, &b})
    {
      (*n)->configureQuery(srvName, "SRV", servfail());     // SRV transient on both servers
      (*n)->addRecord({domain, "A", "192.0.2.202", 3600});  // apex bait: must NOT be queried
    }
  };

  SECTION("sync")
  {
    MockNode a(/*log=*/true), b(/*log=*/true);
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = r->resolveServiceDomain(domain, {ServiceType::SIP_UDP});
    REQUIRE_FALSE(res.isSuccess());
    REQUIRE(res.outcome == ResolutionOutcome::TransientFailure);
    REQUIRE(a.countType(1) == 0); // no apex A query -> the fallback was suppressed
    REQUIRE(b.countType(1) == 0);
  }
  SECTION("async")
  {
    MockNode a(/*log=*/true), b(/*log=*/true);
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = driveServiceAsync(r, domain, {ServiceType::SIP_UDP});
    REQUIRE_FALSE(res.isSuccess());
    REQUIRE(res.outcome == ResolutionOutcome::TransientFailure);
    REQUIRE(a.countType(1) == 0);
    REQUIRE(b.countType(1) == 0);
  }
}

// =============================================================================
// ROUND-4 FIXES (2) — tracker 2026-09-30-4 steps-4-8 round-1 findings
//   F-3 TC=1, F-4 lame, F-5/H-A ordering, F-7 CNAME-only, plus strengthened M-4/H-3 coverage.
// =============================================================================

// --- F-3: a truncated (TC=1) empty NOERROR is never authoritative (RFC 2181 §9) -> failover ---

TEST_CASE("F-3: truncated (TC=1) empty NOERROR is NOT authoritative -> failover (RFC 2181 §9)",
          "[dns][failover][sync][gate]")
{
  MockNode a, b;
  a->configureQuery("host.example.com", truncatedEmpty()); // A: NOERROR/0/TC=1
  b->addRecord({"host.example.com", "A", "192.0.2.30", 3600});
  auto r = makeResolver({a.port, b.port});
  // Pre-fix: TC=1 empty was classified as an authoritative type-3 NODATA -> query() would STOP at A
  // and throw. Post-fix: server-local -> rotate to B and resolve.
  REQUIRE(r->query(aQ("host.example.com")).isSuccess());
  REQUIRE(b.udpQueries() >= 1); // the query failed over to B
}

// --- F-4: a lame (RA=0, AA=0) empty NOERROR is not trustworthy absence -> failover ---

TEST_CASE("F-4: lame (RA=0/AA=0) empty NOERROR is server-local -> failover; RA=1 type-3 still stops",
          "[dns][failover][sync][gate]")
{
  SECTION("lame empty (RA=0) rotates")
  {
    MockNode a, b;
    a->configureQuery("host.example.com", lameEmpty());
    b->addRecord({"host.example.com", "A", "192.0.2.31", 3600});
    auto r = makeResolver({a.port, b.port});
    REQUIRE(r->query(aQ("host.example.com")).isSuccess());
    REQUIRE(b.udpQueries() >= 1);
  }
  SECTION("type-3 NODATA (RA=1, empty authority) is authoritative -> NO failover (control)")
  {
    MockNode a, b;
    a->configureQuery("host.example.com", nodataNoSoa()); // RA=1, no SOA/NS
    b->addRecord({"host.example.com", "A", "192.0.2.32", 3600});
    auto r = makeResolver({a.port, b.port});
    REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsResolutionFailedException);
    REQUIRE(b.udpQueries() == 0);
  }
}

// --- F-3/F-4/H-1 async: referral rotates and type-3 NODATA stops, through classifyAsyncCompletion ---

TEST_CASE("H-1 async: referral rotates, type-3 NODATA is terminal (classifyAsyncCompletion)",
          "[dns][failover][async][gate]")
{
  SECTION("referral -> failover to B (async)")
  {
    MockNode a, b;
    a->configureQuery("host.example.com", referral());
    b->addRecord({"host.example.com", "A", "192.0.2.33", 3600});
    auto r = makeResolver({a.port, b.port});
    auto out = driveQueryAsync(r, aQ("host.example.com"));
    REQUIRE(out.completed);
    REQUIRE(out.callbacks == 1);
    REQUIRE(out.result.isSuccess());
    REQUIRE(b.udpQueries() >= 1);
  }
  SECTION("type-3 NODATA -> terminal, NO rotation (async)")
  {
    MockNode a, b;
    a->configureQuery("host.example.com", nodataNoSoa());
    b->addRecord({"host.example.com", "A", "192.0.2.34", 3600});
    auto r = makeResolver({a.port, b.port});
    auto out = driveQueryAsync(r, aQ("host.example.com"));
    REQUIRE(out.completed);
    REQUIRE(out.callbacks == 1);
    REQUIRE_FALSE(out.result.isSuccess()); // authoritative empty delivered as terminal
    REQUIRE(b.udpQueries() == 0);
  }
}

// --- F-7: a CNAME-only NOERROR (no RR of the queried type) is a NODATA, not a success ---

TEST_CASE("F-7: CNAME-only NOERROR is classified as NODATA, not returned as success (RFC 2308 §2.2)",
          "[dns][failover][sync][cname]")
{
  MockNode a;
  // alias -> CNAME real.example.com, but NO A for alias in this answer + an authoritative SOA.
  a->configureQuery("alias.example.com", "A", cnameOnly("real.example.com"));
  auto r = makeResolver({a.port});
  // Pre-fix: isSuccess() (ANCOUNT>0 for the CNAME) returned it as a success. Post-fix: recognized
  // as an authoritative NODATA and thrown, so it is not returned/cached as a positive result.
  REQUIRE_THROWS_AS(r->query(aQ("alias.example.com")), DnsResolutionFailedException);
}

// --- F-5 / H-A: the §4.2 NAPTR-S fallback keeps NAPTR preference order; sync == async ---

TEST_CASE("F-5: NAPTR-S §4.2 fallback keeps NAPTR preference order (UDP<TCP), sync == async",
          "[dns][failover][outcome][naptr][fallback][order]")
{
  const std::string domain = "order.example.net";
  const std::string udpSrv = "_sip._udp." + domain;
  const std::string tcpSrv = "_sip._tcp." + domain;
  const std::vector<ServiceType> pref{ServiceType::SIP_UDP, ServiceType::SIP_TCP};

  // Two NAPTR-S: SIP+D2U pref 10 (UDP), SIP+D2T pref 20 (TCP). Both SRV owner names NXDOMAIN
  // (authoritative). Apex has an A -> §4.2 fallback builds a target per NAPTR transport. The order
  // must follow NAPTR preference (UDP before TCP), NOT the ServiceType enum value (which would put
  // SIP_TCP before SIP_UDP), and sync must equal async.
  auto configure = [&](MockNode &a, MockNode &b)
  {
    for (auto *n : {&a, &b})
    {
      addTwoNaptrSets(*n, domain, udpSrv, tcpSrv);
      (*n)->addRecord({domain, "A", "192.0.2.210", 3600});
    }
  };

  SECTION("sync")
  {
    MockNode a, b;
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = r->resolveServiceDomain(domain, pref);
    REQUIRE(res.isSuccess());
    REQUIRE(res.targets.size() == 2);
    REQUIRE(res.targets[0].transport == ServiceType::SIP_UDP);
    REQUIRE(res.targets[1].transport == ServiceType::SIP_TCP);
  }
  SECTION("async")
  {
    MockNode a, b;
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = driveServiceAsync(r, domain, pref);
    REQUIRE(res.isSuccess());
    REQUIRE(res.targets.size() == 2);
    REQUIRE(res.targets[0].transport == ServiceType::SIP_UDP); // parity with sync
    REQUIRE(res.targets[1].transport == ServiceType::SIP_TCP);
  }
}

// --- H-3 secure: SIPS NAPTR-S -> SRV NXDOMAIN -> §4.2 fallback yields SIPS/5061, no plaintext ---

TEST_CASE("H-3 secure: NAPTR-S SIPS all-SRV-NXDOMAIN -> §4.2 fallback SIPS/5061, no plaintext",
          "[dns][failover][outcome][naptr][fallback][secure]")
{
  const std::string domain = "securefb.example.net";
  const std::string sipsSrv = "_sips._tcp." + domain;

  auto configure = [&](MockNode &a, MockNode &b)
  {
    for (auto *n : {&a, &b})
    {
      (*n)->addRecord(naptrSvc(domain, "SIPS+D2T", sipsSrv, /*order=*/10)); // SIPS -> SIPS_TLS
      // sipsSrv: no SRV record anywhere -> authoritative NXDOMAIN
      (*n)->addRecord({domain, "A", "192.0.2.211", 3600}); // apex A for the §4.2 fallback
    }
  };

  SECTION("sync")
  {
    MockNode a, b;
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = r->resolveServiceDomain(domain, {ServiceType::SIPS_TLS}, true);
    REQUIRE(res.isSuccess());
    REQUIRE(res.targets.size() == 1);
    REQUIRE(res.targets[0].transport == ServiceType::SIPS_TLS);
    REQUIRE(res.targets[0].port == 5061);
    for (const auto &t : res.targets)
    {
      REQUIRE(isSecureSipService(t.transport)); // no plaintext leaked through the fallback
    }
  }
  SECTION("async")
  {
    MockNode a, b;
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = driveServiceAsync(r, domain, {ServiceType::SIPS_TLS}, true);
    REQUIRE(res.isSuccess());
    REQUIRE(res.targets.size() == 1);
    REQUIRE(res.targets[0].transport == ServiceType::SIPS_TLS);
    REQUIRE(res.targets[0].port == 5061);
  }
}

// --- H-3 per-service '.' : one service denied via RFC 2782 '.', the other authoritative-absent ---

TEST_CASE("H-3: per-service '.' suppression under NAPTR-S multi-service (only TCP falls back)",
          "[dns][failover][outcome][naptr][fallback][rfc2782]")
{
  const std::string domain = "persvc.example.net";
  const std::string udpSrv = "_sip._udp." + domain;
  const std::string tcpSrv = "_sip._tcp." + domain;
  const std::vector<ServiceType> pref{ServiceType::SIP_UDP, ServiceType::SIP_TCP};

  // UDP SRV returns RFC 2782 '.' (service decidedly unavailable -> suppressed from fallback);
  // TCP SRV is NXDOMAIN (authoritative absence -> eligible for the §4.2 fallback). Apex A present.
  // The fallback must yield exactly ONE target, on TCP (UDP suppressed, not domain-wide).
  auto configure = [&](MockNode &a, MockNode &b)
  {
    for (auto *n : {&a, &b})
    {
      addTwoNaptrSets(*n, domain, udpSrv, tcpSrv);
      (*n)->addRecord({udpSrv, "SRV", ".", 3600, 0, 0, 0}); // '.' -> UDP decidedly unavailable
      // tcpSrv: no SRV -> NXDOMAIN
      (*n)->addRecord({domain, "A", "192.0.2.212", 3600});
    }
  };

  SECTION("sync")
  {
    MockNode a, b;
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = r->resolveServiceDomain(domain, pref);
    REQUIRE(res.isSuccess());
    REQUIRE(res.targets.size() == 1);
    REQUIRE(res.targets[0].transport == ServiceType::SIP_TCP); // UDP '.'-suppressed
  }
  SECTION("async")
  {
    MockNode a, b;
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = driveServiceAsync(r, domain, pref);
    REQUIRE(res.isSuccess());
    REQUIRE(res.targets.size() == 1);
    REQUIRE(res.targets[0].transport == ServiceType::SIP_TCP);
  }
}

// --- M-4 strengthened: NAPTR-S all-SRV-transient must NOT touch the apex bait (sync+async) ---

TEST_CASE("M-4: NAPTR-S all-SRV-SERVFAIL -> TransientFailure, apex A NOT queried (sync+async)",
          "[dns][failover][outcome][naptr][m4]")
{
  const std::string domain = "m4naptr.example.net";
  const std::string srvName = "_sip._udp." + domain;

  auto configure = [&](MockNode &a, MockNode &b)
  {
    for (auto *n : {&a, &b})
    {
      (*n)->addRecord(naptrS(domain, srvName));       // SIP+D2U -> SIP_UDP
      (*n)->configureQuery(srvName, "SRV", servfail()); // all-server transient
      (*n)->addRecord({domain, "A", "192.0.2.213", 3600}); // apex bait: must NOT be queried
    }
  };

  SECTION("sync")
  {
    MockNode a(/*log=*/true), b(/*log=*/true);
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = r->resolveServiceDomain(domain, {ServiceType::SIP_UDP});
    REQUIRE_FALSE(res.isSuccess());
    REQUIRE(res.outcome == ResolutionOutcome::TransientFailure);
    REQUIRE(a.countType(1) == 0); // no apex A query -> §4.2 fallback suppressed on transient
    REQUIRE(b.countType(1) == 0);
  }
  SECTION("async")
  {
    MockNode a(/*log=*/true), b(/*log=*/true);
    configure(a, b);
    auto r = makeResolver({a.port, b.port});
    ServiceResolutionResult res = driveServiceAsync(r, domain, {ServiceType::SIP_UDP});
    REQUIRE_FALSE(res.isSuccess());
    REQUIRE(res.outcome == ResolutionOutcome::TransientFailure);
    REQUIRE(a.countType(1) == 0);
    REQUIRE(b.countType(1) == 0);
  }
}

// --- H-1 not-cached: an authoritative type-3 NODATA (no SOA) is not negatively cached ---

TEST_CASE("H-1: type-3 NODATA (no SOA) authoritative but NOT negatively cached (RFC 2308 §5)",
          "[dns][failover][sync][cache]")
{
  MockNode a;
  a->configureQuery("host.example.com", "A", nodataNoSoa()); // RA=1, no SOA -> authoritative, no TTL
  auto cache = std::make_shared<DnsCache>();
  auto r = makeResolver({a.port}, SHORT_TIMEOUT, /*retryCount=*/0, DnsTransportMode::UDP, cache);
  REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsResolutionFailedException);
  REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsResolutionFailedException);
  REQUIRE(a.udpQueries() == 2); // NOT cached (no SOA) -> the second query re-hits the network
}

// --- F-1: authority/additional glue must NEVER be returned as the queried host's address ---

TEST_CASE("F-1: additional-section glue is not returned as the host address (RFC 2181 §5.4.1)",
          "[dns][failover][sync][glue]")
{
  MockNode a;
  // Answer A(host -> 192.0.2.1), authority NS, additional glue A(ns1.host -> 192.0.2.53).
  MockDnsServer::QueryConfig withGlue;
  withGlue.answerAddrWithGlue = "192.0.2.1";
  withGlue.glueOwner = "ns1.host.example.com";
  withGlue.glueAddr = "192.0.2.53";
  a->configureQuery("host.example.com", "A", withGlue);
  auto r = makeResolver({a.port});
  auto addrs = r->resolveHostname("host.example.com");
  // Pre-fix: the parser merged the additional-section glue into a_records, so 192.0.2.53 leaked in.
  REQUIRE(addrs.size() == 1);
  REQUIRE(addrs[0] == "192.0.2.1");
  REQUIRE(std::find(addrs.begin(), addrs.end(), "192.0.2.53") == addrs.end());
}

// =============================================================================
// ROUND-4 FIXES (3) — tracker 2026-09-30-4 steps-4-8 round-2 findings
//   H-1 (F-7 cache+async completeness), M-1 (CNAME-only needs SOA), M-2 (lame NXDOMAIN),
//   plus the missing async / control coverage (MED-2 / M-4 / LOW-8).
// =============================================================================

// --- H-1: F-7 is complete — CNAME-only NODATA is negative on the cache and async paths too ---

TEST_CASE("H-1: CNAME-only NODATA is not cached positive; sync twice both throw (F-7 cache)",
          "[dns][failover][sync][cname][cache]")
{
  MockNode a;
  a->configureQuery("alias.example.com", "A", cnameOnly("real.example.com")); // CNAME + SOA
  auto cache = std::make_shared<DnsCache>();
  auto r = makeResolver({a.port}, SHORT_TIMEOUT, /*retryCount=*/0, DnsTransportMode::UDP, cache);
  REQUIRE_THROWS_AS(r->query(aQ("alias.example.com")), DnsResolutionFailedException);
  // It must be cached NEGATIVELY (SOA-min TTL), never positively with the CNAME TTL. Mutation: revert
  // cacheQueryResult to `isSuccess()` -> a positive insertion (insertions>=1, negative_insertions==0).
  REQUIRE(cache->getStats().negative_insertions >= 1);
  REQUIRE(cache->getStats().insertions == 0);
  // Pre-fix: the first call cached it POSITIVE, so the second returned success from cache.
  REQUIRE_THROWS_AS(r->query(aQ("alias.example.com")), DnsResolutionFailedException);
  REQUIRE(a.udpQueries() == 1); // second call served from the NEGATIVE cache entry, no re-query
}

TEST_CASE("H-1: queryAsync delivers CNAME-only NODATA as an ERROR, matching sync (F-7 async)",
          "[dns][failover][async][cname]")
{
  MockNode a;
  a->configureQuery("alias.example.com", "A", cnameOnly("real.example.com"));
  auto r = makeResolver({a.port});
  auto out = driveQueryAsync(r, aQ("alias.example.com"));
  REQUIRE(out.completed);
  REQUIRE(out.callbacks == 1);
  REQUIRE(out.error); // pre-fix: delivered success(nullptr) -> async disagreed with sync
}

// --- H-1 / F-7 control: a genuinely-chased CNAME -> A answer is STILL a success ---

TEST_CASE("F-7 control: CNAME chased to an A in the same answer resolves (not a NODATA)",
          "[dns][failover][sync][cname]")
{
  MockNode a;
  a->configureQuery("alias.example.com", "A", cnameThenA("real.example.com", "192.0.2.77"));
  auto r = makeResolver({a.port});
  auto addrs = r->resolveHostname("alias.example.com");
  REQUIRE(addrs.size() == 1);
  REQUIRE(addrs[0] == "192.0.2.77"); // the chased target A is a real positive answer
}

// --- M-1: a CNAME-only reply with EMPTY authority (no SOA) is not proof of absence -> rotate ---

TEST_CASE("M-1: CNAME-only without SOA (empty authority) rotates; with SOA is authoritative",
          "[dns][failover][sync][cname][gate]")
{
  SECTION("no SOA -> server-local -> failover to B")
  {
    MockNode a, b;
    a->configureQuery("alias.example.com", "A", cnameOnly("real.example.com", /*withSoa=*/false));
    b->addRecord({"alias.example.com", "A", "192.0.2.78", 3600});
    auto r = makeResolver({a.port, b.port});
    REQUIRE(r->query(aQ("alias.example.com")).isSuccess());
    REQUIRE(b.udpQueries() >= 1); // rotated: an unresolved CNAME target is not authoritative absence
  }
  SECTION("with SOA -> authoritative -> NO failover (control)")
  {
    MockNode a, b;
    a->configureQuery("alias.example.com", "A", cnameOnly("real.example.com", /*withSoa=*/true));
    b->addRecord({"alias.example.com", "A", "192.0.2.79", 3600});
    auto r = makeResolver({a.port, b.port});
    REQUIRE_THROWS_AS(r->query(aQ("alias.example.com")), DnsResolutionFailedException);
    REQUIRE(b.udpQueries() == 0);
  }
}

// --- M-2: a lame (RA=0/AA=0) NXDOMAIN is not trustworthy -> rotate; a recursive NXDOMAIN stops ---

TEST_CASE("M-2: lame NXDOMAIN (RA=0/AA=0) rotates; RA=1 NXDOMAIN stops (control)",
          "[dns][failover][sync][gate]")
{
  SECTION("lame NXDOMAIN rotates to B")
  {
    MockNode a, b;
    a->configureQuery("host.example.com", lameNxdomain());
    b->addRecord({"host.example.com", "A", "192.0.2.80", 3600});
    auto r = makeResolver({a.port, b.port});
    REQUIRE(r->query(aQ("host.example.com")).isSuccess());
    REQUIRE(b.udpQueries() >= 1);
  }
  SECTION("recursive NXDOMAIN (RA=1) stops at A -> B untouched (control)")
  {
    MockNode a, b;
    // A has no record for host.example.com -> the mock's default NXDOMAIN has RA=1 -> authoritative.
    b->addRecord({"host.example.com", "A", "192.0.2.81", 3600}); // present but must NOT be reached
    auto r = makeResolver({a.port, b.port});
    REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsResolutionFailedException);
    REQUIRE(b.udpQueries() == 0); // authoritative NXDOMAIN stopped rotation at A
  }
}

// --- MED-2: async twins for the F-3 (TC=1) and F-4 (lame NODATA) gate changes ---

TEST_CASE("MED-2 async: TC=1-empty and lame-empty rotate through classifyAsyncCompletion",
          "[dns][failover][async][gate]")
{
  SECTION("TC=1 empty rotates (async)")
  {
    MockNode a, b;
    a->configureQuery("host.example.com", truncatedEmpty());
    b->addRecord({"host.example.com", "A", "192.0.2.82", 3600});
    auto r = makeResolver({a.port, b.port});
    auto out = driveQueryAsync(r, aQ("host.example.com"));
    REQUIRE(out.completed);
    REQUIRE(out.callbacks == 1);
    REQUIRE(out.result.isSuccess());
    REQUIRE(b.udpQueries() >= 1);
  }
  SECTION("lame empty rotates (async)")
  {
    MockNode a, b;
    a->configureQuery("host.example.com", lameEmpty());
    b->addRecord({"host.example.com", "A", "192.0.2.83", 3600});
    auto r = makeResolver({a.port, b.port});
    auto out = driveQueryAsync(r, aQ("host.example.com"));
    REQUIRE(out.completed);
    REQUIRE(out.callbacks == 1);
    REQUIRE(out.result.isSuccess());
    REQUIRE(b.udpQueries() >= 1);
  }
}

// --- M-4 control: RFC 2308 §2.2.1 type-1 NODATA (NS + SOA) is authoritative -> NO failover ---

TEST_CASE("type-1 NODATA (NS + SOA in authority) is authoritative -> NO failover (RFC 2308 §2.2.1)",
          "[dns][failover][sync][gate]")
{
  MockNode a, b;
  a->configureQuery("host.example.com", "A", nodataNsAndSoa()); // SOA present -> authoritative
  b->addRecord({"host.example.com", "A", "192.0.2.84", 3600});
  auto r = makeResolver({a.port, b.port});
  REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsResolutionFailedException);
  REQUIRE(b.udpQueries() == 0); // SOA is the deciding marker even with NS present
}

// --- LOW-8: the F-5 order test must distinguish NAPTR preference from caller preference ---

TEST_CASE("LOW-8: §4.2 fallback follows NAPTR preference even when caller order is reversed",
          "[dns][failover][outcome][naptr][fallback][order]")
{
  const std::string domain = "revorder.example.net";
  const std::string udpSrv = "_sip._udp." + domain;
  const std::string tcpSrv = "_sip._tcp." + domain;
  // Caller lists TCP first, but NAPTR ranks UDP (pref 10) above TCP (pref 20). The fallback order
  // must follow NAPTR preference (UDP first), NOT the caller's preferredTransports order.
  const std::vector<ServiceType> reversedPref{ServiceType::SIP_TCP, ServiceType::SIP_UDP};
  MockNode a, b;
  for (auto *n : {&a, &b})
  {
    addTwoNaptrSets(*n, domain, udpSrv, tcpSrv);
    (*n)->addRecord({domain, "A", "192.0.2.214", 3600});
  }
  auto r = makeResolver({a.port, b.port});
  ServiceResolutionResult res = r->resolveServiceDomain(domain, reversedPref);
  REQUIRE(res.isSuccess());
  REQUIRE(res.targets.size() == 2);
  REQUIRE(res.targets[0].transport == ServiceType::SIP_UDP); // NAPTR pref, not caller order
  REQUIRE(res.targets[1].transport == ServiceType::SIP_TCP);
}

// =============================================================================
// ROUND-4 FIXES — tracker 2026-09-30-4 steps-4-8 round-3 findings
//   M-A (TC bypass in CNAME branch), M-C (meta-qtype), L-1 (additional-SOA), M-D (untested paths).
// =============================================================================

// --- M-A: a TRUNCATED CNAME-only+SOA response must rotate, not be classified authoritative ---

TEST_CASE("M-A: truncated (TC=1) CNAME-only+SOA is server-local -> failover (RFC 2181 §9)",
          "[dns][failover][sync][cname][gate]")
{
  MockNode a, b;
  a->configureQuery("alias.example.com", "A", cnameOnlyTruncated("real.example.com")); // CNAME+SOA+TC
  b->addRecord({"alias.example.com", "A", "192.0.2.90", 3600});
  auto r = makeResolver({a.port, b.port});
  // Pre-fix: the CNAME-only branch returned Authoritative before the TC guard -> stopped at A/threw.
  REQUIRE(r->query(aQ("alias.example.com")).isSuccess());
  REQUIRE(b.udpQueries() >= 1); // TC-truncated -> rotated to B
}

// --- M-C: an ANY query answered with only a CNAME is a positive answer, not a NODATA ---

TEST_CASE("M-C: ANY query on a CNAME-only answer resolves (meta-qtype not NODATA, RFC 1034 §3.6.2)",
          "[dns][failover][sync][cname][gate]")
{
  MockNode a;
  // Name-level config (no type) so it also answers the ANY (type 255) query.
  a->configureQuery("alias.example.com", cnameOnly("real.example.com"));
  auto r = makeResolver({a.port});
  // Pre-fix: none_of(answers, type==ANY) was always true -> misclassified as NODATA and thrown.
  DnsResult res = r->query(anyQ("alias.example.com"));
  REQUIRE(res.isSuccess());              // the CNAME IS the valid answer to an ANY query on an alias
  REQUIRE_FALSE(res.cname_records.empty());
}

// --- L-1: an SOA in the ADDITIONAL section (not authority) must not be used for negative caching ---

TEST_CASE("L-1: an ADDITIONAL-section SOA is not used for negative caching (RFC 2308 §3)",
          "[dns][failover][sync][gate][cache]")
{
  MockNode a;
  a->configureQuery("host.example.com", "A", nodataSoaInAdditional()); // SOA in ADDITIONAL only, RA=1
  auto cache = std::make_shared<DnsCache>();
  auto r = makeResolver({a.port}, SHORT_TIMEOUT, /*retryCount=*/0, DnsTransportMode::UDP, cache);
  // The reply is an authoritative type-3 NODATA (empty AUTHORITY, RA=1) -> it throws. The L-1 point
  // is CACHING: the SOA sits in ADDITIONAL, not AUTHORITY, so there is no RFC 2308 §5 TTL and it must
  // NOT be negatively cached. Mutation: promote the additional SOA -> negative_insertions >= 1.
  REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsResolutionFailedException);
  REQUIRE(cache->getStats().negative_insertions == 0);
}

// --- M-D: the async cache-hit read path must also reject a negatively-cached CNAME-only NODATA ---

TEST_CASE("M-D: queryAsync served from a negative cache entry delivers an error (async cache read)",
          "[dns][failover][async][cname][cache]")
{
  MockNode a;
  a->configureQuery("alias.example.com", "A", cnameOnly("real.example.com"));
  auto cache = std::make_shared<DnsCache>();
  auto r = makeResolver({a.port}, SHORT_TIMEOUT, /*retryCount=*/0, DnsTransportMode::UDP, cache);
  auto first = driveQueryAsync(r, aQ("alias.example.com"));
  REQUIRE(first.completed);
  REQUIRE(first.error); // first fresh async resolution -> error (negative), cached negatively
  auto second = driveQueryAsync(r, aQ("alias.example.com"));
  REQUIRE(second.completed);
  REQUIRE(second.callbacks == 1);
  REQUIRE(second.error);                    // served from the NEGATIVE cache entry as an error ...
  REQUIRE(a.udpQueries() == 1);             // ... with no second network query
  REQUIRE(cache->getStats().negative_hits >= 1);
}

// --- LOW-7: async twins for the M-1 (CNAME-only-no-SOA) and M-2 (lame NXDOMAIN) rotations ---

TEST_CASE("LOW-7 async: CNAME-only-no-SOA and lame-NXDOMAIN rotate through the async gate",
          "[dns][failover][async][gate][cname]")
{
  SECTION("CNAME-only without SOA rotates (async, M-1)")
  {
    MockNode a, b;
    a->configureQuery("alias.example.com", "A", cnameOnly("real.example.com", /*withSoa=*/false));
    b->addRecord({"alias.example.com", "A", "192.0.2.92", 3600});
    auto r = makeResolver({a.port, b.port});
    auto out = driveQueryAsync(r, aQ("alias.example.com"));
    REQUIRE(out.completed);
    REQUIRE(out.callbacks == 1);
    REQUIRE(out.result.isSuccess());
    REQUIRE(b.udpQueries() >= 1);
  }
  SECTION("lame NXDOMAIN rotates (async, M-2)")
  {
    MockNode a, b;
    a->configureQuery("host.example.com", lameNxdomain());
    b->addRecord({"host.example.com", "A", "192.0.2.93", 3600});
    auto r = makeResolver({a.port, b.port});
    auto out = driveQueryAsync(r, aQ("host.example.com"));
    REQUIRE(out.completed);
    REQUIRE(out.callbacks == 1);
    REQUIRE(out.result.isSuccess());
    REQUIRE(b.udpQueries() >= 1);
  }
}
