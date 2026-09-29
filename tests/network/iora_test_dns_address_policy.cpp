// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_dns_address_policy.cpp
/// \brief Async/cached DNS A/AAAA addressResolutionPolicy honoring + TS-C1
///        latch-loss-on-synchronous-throw robustness (tracker 2026-09-25-5).
///
/// Two test styles:
///  * WIRE (MockDnsServer, real UDP): policy honoring across the three async/cached
///    sites -- ordering (primary observable), no-leak / skip-not-discard, First!=Only,
///    error/timeout latch. Result set is compared to the sync resolveHostname oracle.
///  * THROWING-DOUBLE (a DnsResolver built with an injectable faulty DnsTransport):
///    the TS-C1 synchronous-issue-throw paths the wire mock cannot reach -- every
///    fan-out/chain site + the entry sites -- asserting completion (no hang) and
///    exactly-one callback. The mutation intent: a lost-decrement / lost-callback
///    implementation makes these bounded waits time out (FAIL).

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "MockDnsServer.hpp"
#include "iora/network/dns/dns_cache.hpp"
#include "iora/network/dns/dns_resolver.hpp"
#include "iora/network/dns/dns_transport.hpp"
#include "iora/network/dns/dns_types.hpp"
#include "iora/network/dns_client.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace iora::network::dns;
using iora::network::DnsClient;

namespace
{
constexpr std::uint16_t TEST_UDP_PORT = 15453; // distinct from other DNS suites
constexpr std::chrono::seconds BOUNDED_WAIT{5};

bool isIPv6(const std::string &a) { return a.find(':') != std::string::npos; }
bool isIPv4(const std::string &a) { return !isIPv6(a); }

// ---------------------------------------------------------------------------
// WIRE fixture: a policy-configurable DnsClient pointed at a per-test MockDnsServer.
// ---------------------------------------------------------------------------
class PolicyWireFixture
{
public:
  PolicyWireFixture()
  {
    MockDnsServer::Config cfg;
    cfg.udpPort = TEST_UDP_PORT;
    cfg.tcpPort = TEST_UDP_PORT;
    cfg.enableLogging = false;
    server_ = std::make_unique<MockDnsServer>(cfg);
  }

  ~PolicyWireFixture()
  {
    if (server_)
    {
      server_->stop();
    }
  }

  void startServer()
  {
    REQUIRE(server_->start());
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  MockDnsServer &server() { return *server_; }

  // A short-timeout, no-retry, no-cache client honoring `policy`.
  std::unique_ptr<DnsClient> makeClient(AddressResolutionPolicy policy, bool cache = false,
                                        std::chrono::milliseconds timeout = std::chrono::milliseconds(400))
  {
    DnsConfig cfg;
    cfg.setServers({"127.0.0.1:" + std::to_string(TEST_UDP_PORT)});
    cfg.timeout = timeout;
    cfg.retryCount = 0;
    cfg.transportMode = DnsTransportMode::UDP;
    cfg.enableCache = cache;
    cfg.addressResolutionPolicy = policy;
    return std::make_unique<DnsClient>(cfg);
  }

private:
  std::unique_ptr<MockDnsServer> server_;
};

// Run resolveServiceDomainAsync on a DnsClient and block (bounded). FAIL on timeout.
ServiceResolutionResult resolveService(DnsClient &c, const std::string &domain,
                                       const std::vector<ServiceType> &preferred = {})
{
  auto prom = std::make_shared<std::promise<ServiceResolutionResult>>();
  auto fut = prom->get_future();
  c.resolveServiceDomainAsync(
    domain, [prom](const ServiceResolutionResult &r, const std::exception_ptr &) { prom->set_value(r); },
    preferred);
  REQUIRE(fut.wait_for(BOUNDED_WAIT) == std::future_status::ready);
  return fut.get();
}

// Find the resolved target for a hostname (targets keep per-target ordered addresses).
const ServiceTarget *findTarget(const ServiceResolutionResult &r, const std::string &host)
{
  for (const auto &t : r.targets)
  {
    if (t.hostname == host)
    {
      return &t;
    }
  }
  return nullptr;
}

// ---------------------------------------------------------------------------
// THROWING DOUBLE: a DnsTransport whose queryAsync answers inline with synthetic
// records and can inject a SYNCHRONOUS throw (the TS-C1 fault the mock cannot make).
// ---------------------------------------------------------------------------
class FaultyDnsTransport : public DnsTransport
{
public:
  FaultyDnsTransport() : DnsTransport(DnsConfig{}) {}

  // Fault injection (either mechanism):
  std::atomic<int> callCount{0};
  int throwOnCall{-1};        // 1-based Nth queryAsync issue throws synchronously; -1 = off
  std::string throwName;      // throw when the question name matches; "" = off
  DnsType throwType{DnsType::A};
  bool throwTypeSet{false};

  // Deliver an async ERROR (exception via the callback, NOT a throw) for a matching query
  // -- models the transport's failCallback/failOne inline-error path.
  std::string errorName;
  DnsType errorType{DnsType::A};
  bool errorTypeSet{false};

  // Synthetic answers:
  std::unordered_map<std::string, std::vector<std::string>> srvTargets;  // srvName -> target hosts
  std::unordered_map<std::string, std::vector<NaptrRecord>> naptr;       // domain -> NAPTR records
  std::unordered_map<std::string, std::vector<std::string>> aAddrs;      // host -> IPv4s
  std::unordered_map<std::string, std::vector<std::string>> aaaaAddrs;   // host -> IPv6s

  // Dispatch mode: true (default) delivers the callback on a WORKER thread like a real
  // transport -- so a synchronous throw at an in-callback (2nd-family / chained) issue
  // occurs on a worker thread with only issueTargetFamily's own try around it (the real
  // TS-C1 hazard; a missing wrap -> unhandled exception on that thread / lost decrement,
  // not merely an inline unwind to an outer try). false delivers inline (re-entrancy).
  bool asyncDispatch{true};

  // queryAsync override: MUST NOT restate the base default arguments (they bind
  // statically to the base declaration); must be owned via shared_ptr (base dtor
  // is non-virtual). See tracker 2026-09-25-5 seam notes.
  void queryAsync(const DnsQuestion &q, QueryCallback cb, const std::string &,
                  std::uint16_t) override
  {
    const int n = ++callCount;
    if (throwOnCall == n)
    {
      throw std::runtime_error("injected synchronous throw @call " + std::to_string(n));
    }
    if (!throwName.empty() && q.qname == throwName && (!throwTypeSet || q.qtype == throwType))
    {
      throw std::runtime_error("injected synchronous throw @" + q.qname);
    }

    std::exception_ptr deliverErr;
    if (!errorName.empty() && q.qname == errorName && (!errorTypeSet || q.qtype == errorType))
    {
      deliverErr = std::make_exception_ptr(std::runtime_error("injected async error @" + q.qname));
    }

    DnsResult r;
    switch (q.qtype)
    {
    case DnsType::A:
    {
      auto it = aAddrs.find(q.qname);
      if (it != aAddrs.end())
      {
        for (const auto &a : it->second)
        {
          r.a_records.push_back(ARecord(q.qname, a, 3600));
        }
      }
      break;
    }
    case DnsType::AAAA:
    {
      auto it = aaaaAddrs.find(q.qname);
      if (it != aaaaAddrs.end())
      {
        for (const auto &a : it->second)
        {
          r.aaaa_records.push_back(AAAARecord(q.qname, a, 3600));
        }
      }
      break;
    }
    case DnsType::SRV:
    {
      auto it = srvTargets.find(q.qname);
      if (it != srvTargets.end())
      {
        std::uint16_t prio = 10;
        for (const auto &host : it->second)
        {
          r.srv_records.push_back(SrvRecord(q.qname, prio++, 0, 5060, host, 3600));
        }
      }
      break;
    }
    case DnsType::NAPTR:
    {
      auto it = naptr.find(q.qname);
      if (it != naptr.end())
      {
        r.naptr_records = it->second;
      }
      break; // no NAPTR entry -> empty answer (drives the direct-SRV path)
    }
    default:
      break;
    }

    // Like the real transport, swallow a throwing user callback at the leaf (the real
    // DnsTransport wraps every callback in catch(...)); this keeps a throwing-callback
    // test from terminating and faithfully models the "callbacks may throw" condition.
    if (asyncDispatch)
    {
      std::thread([cb, r, deliverErr]() { try { cb(r, deliverErr); } catch (...) {} }).detach();
    }
    else
    {
      try { cb(r, deliverErr); } catch (...) {} // inline (re-entrant) completion
    }
  }
};

// Build a DnsResolver directly over a faulty transport (no cache).
std::shared_ptr<DnsResolver> makeFaultyResolver(std::shared_ptr<FaultyDnsTransport> t,
                                                AddressResolutionPolicy policy)
{
  DnsConfig cfg;
  cfg.setServers({"127.0.0.1:1"});
  cfg.addressResolutionPolicy = policy;
  return std::make_shared<DnsResolver>(t, nullptr, cfg);
}

// Drive resolveServiceDomainAsync on a DnsResolver, count callback invocations,
// and block (bounded). Returns {result, callbackCount, completedInTime}.
struct ServiceOutcome
{
  ServiceResolutionResult result;
  int callbacks{0};
  bool completed{false};
};

ServiceOutcome driveService(const std::shared_ptr<DnsResolver> &r, const std::string &domain,
                            const std::vector<ServiceType> &preferred = {})
{
  auto count = std::make_shared<std::atomic<int>>(0);
  auto prom = std::make_shared<std::promise<ServiceResolutionResult>>();
  auto fut = prom->get_future();
  auto once = std::make_shared<std::atomic<bool>>(false);
  r->resolveServiceDomainAsync(
    domain,
    [count, prom, once](const ServiceResolutionResult &res, const std::exception_ptr &)
    {
      count->fetch_add(1);
      if (!once->exchange(true))
      {
        prom->set_value(res);
      }
    },
    preferred);
  ServiceOutcome out;
  out.completed = fut.wait_for(BOUNDED_WAIT) == std::future_status::ready;
  if (out.completed)
  {
    out.result = fut.get();
    // Allow a moment for any (erroneous) extra callback to land before counting.
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  out.callbacks = count->load();
  return out;
}

} // namespace

// =============================================================================
// WIRE TESTS -- site 1 (SRV -> target host with A+AAAA)
// =============================================================================

TEST_CASE_METHOD(PolicyWireFixture, "async site1 honors policy: ordering + membership",
                 "[dns][policy][site1][ordering]")
{
  startServer();
  server().addRecord({"_sip._udp.svc1.test", "SRV", "h1.svc1.test", 3600, 10, 0, 5060});
  server().addRecord({"h1.svc1.test", "A", "192.0.2.11", 3600});
  server().addRecord({"h1.svc1.test", "AAAA", "2001:db8::11", 3600});
  const std::vector<ServiceType> udp{ServiceType::SIP_UDP};

  SECTION("IPv4First: both families, IPv4 first")
  {
    auto c = makeClient(AddressResolutionPolicy::IPv4First);
    auto r = resolveService(*c, "svc1.test", udp);
    const auto *t = findTarget(r, "h1.svc1.test");
    REQUIRE(t != nullptr);
    REQUIRE(t->addresses.size() == 2);
    CHECK(isIPv4(t->addresses[0]));
    CHECK(isIPv6(t->addresses[1]));
  }
  SECTION("IPv6First: both families, IPv6 first")
  {
    auto c = makeClient(AddressResolutionPolicy::IPv6First);
    auto r = resolveService(*c, "svc1.test", udp);
    const auto *t = findTarget(r, "h1.svc1.test");
    REQUIRE(t != nullptr);
    REQUIRE(t->addresses.size() == 2);
    CHECK(isIPv6(t->addresses[0]));
    CHECK(isIPv4(t->addresses[1]));
  }
  SECTION("IPv4Only: only IPv4, no IPv6 leak")
  {
    auto c = makeClient(AddressResolutionPolicy::IPv4Only);
    auto r = resolveService(*c, "svc1.test", udp);
    const auto *t = findTarget(r, "h1.svc1.test");
    REQUIRE(t != nullptr);
    REQUIRE(t->addresses.size() == 1);
    CHECK(isIPv4(t->addresses[0]));
  }
  SECTION("IPv6Only: only IPv6, no IPv4 leak")
  {
    auto c = makeClient(AddressResolutionPolicy::IPv6Only);
    auto r = resolveService(*c, "svc1.test", udp);
    const auto *t = findTarget(r, "h1.svc1.test");
    REQUIRE(t != nullptr);
    REQUIRE(t->addresses.size() == 1);
    CHECK(isIPv6(t->addresses[0]));
  }
}

TEST_CASE_METHOD(PolicyWireFixture, "async site1 skip-not-discard: skipped family is not queried",
                 "[dns][policy][site1][noleak]")
{
  startServer();
  server().addRecord({"_sip._udp.skip.test", "SRV", "h.skip.test", 3600, 10, 0, 5060});
  server().addRecord({"h.skip.test", "A", "192.0.2.20", 3600});
  server().addRecord({"h.skip.test", "AAAA", "2001:db8::20", 3600});
  const std::vector<ServiceType> udp{ServiceType::SIP_UDP};

  // IPv6Only must NOT issue an A query: make A time out. If the impl queried A it
  // would stall on the (400ms) timeout; a proper skip completes fast with just AAAA.
  MockDnsServer::QueryConfig aTimeout;
  aTimeout.shouldTimeout = true;
  server().configureQuery("h.skip.test", "A", aTimeout);

  auto c = makeClient(AddressResolutionPolicy::IPv6Only);
  auto start = std::chrono::steady_clock::now();
  auto r = resolveService(*c, "skip.test", udp);
  auto elapsed = std::chrono::steady_clock::now() - start;

  const auto *t = findTarget(r, "h.skip.test");
  REQUIRE(t != nullptr);
  REQUIRE(t->addresses.size() == 1);
  CHECK(isIPv6(t->addresses[0]));
  // Well under the A-query timeout -> A was never issued (skip, not query-then-discard).
  CHECK(elapsed < std::chrono::milliseconds(300));
}

TEST_CASE_METHOD(PolicyWireFixture, "async site1 First!=Only for single-family targets",
                 "[dns][policy][site1][firstvsonly]")
{
  startServer();
  // Host has ONLY AAAA.
  server().addRecord({"_sip._udp.aonly.test", "SRV", "h6.aonly.test", 3600, 10, 0, 5060});
  server().addRecord({"h6.aonly.test", "AAAA", "2001:db8::66", 3600});
  const std::vector<ServiceType> udp{ServiceType::SIP_UDP};

  SECTION("IPv4First with only-AAAA target: returns AAAA (target survives)")
  {
    auto c = makeClient(AddressResolutionPolicy::IPv4First);
    auto r = resolveService(*c, "aonly.test", udp);
    const auto *t = findTarget(r, "h6.aonly.test");
    REQUIRE(t != nullptr);
    REQUIRE(t->addresses.size() == 1);
    CHECK(isIPv6(t->addresses[0]));
  }
  SECTION("IPv4Only with only-AAAA target: dropped (empty -> erased)")
  {
    auto c = makeClient(AddressResolutionPolicy::IPv4Only);
    auto r = resolveService(*c, "aonly.test", udp);
    CHECK(findTarget(r, "h6.aonly.test") == nullptr);
  }
}

TEST_CASE_METHOD(PolicyWireFixture, "async site1 error-path latch: A times out, AAAA succeeds",
                 "[dns][policy][site1][latch]")
{
  startServer();
  server().addRecord({"_sip._udp.err.test", "SRV", "h.err.test", 3600, 10, 0, 5060});
  server().addRecord({"h.err.test", "AAAA", "2001:db8::77", 3600});
  MockDnsServer::QueryConfig aTimeout;
  aTimeout.shouldTimeout = true;
  server().configureQuery("h.err.test", "A", aTimeout);
  const std::vector<ServiceType> udp{ServiceType::SIP_UDP};

  // IPv4First: A times out but the latch must still decrement exactly once and the
  // AAAA result be retained (RFC 3263 dual-stack partial results). No hang.
  auto c = makeClient(AddressResolutionPolicy::IPv4First);
  auto r = resolveService(*c, "err.test", udp);
  const auto *t = findTarget(r, "h.err.test");
  REQUIRE(t != nullptr);
  REQUIRE(t->addresses.size() == 1);
  CHECK(isIPv6(t->addresses[0]));
}

// =============================================================================
// WIRE TESTS -- site 2 (no SRV / no NAPTR -> direct A/AAAA fallback on the domain)
// =============================================================================

TEST_CASE_METHOD(PolicyWireFixture, "async site2 fallback honors policy",
                 "[dns][policy][site2]")
{
  startServer();
  // No SRV / NAPTR: the domain itself carries A + AAAA -> fallback path.
  server().addRecord({"fb.test", "A", "192.0.2.30", 3600});
  server().addRecord({"fb.test", "AAAA", "2001:db8::30", 3600});
  const std::vector<ServiceType> udp{ServiceType::SIP_UDP};

  SECTION("IPv4First: IPv4 then IPv6")
  {
    auto c = makeClient(AddressResolutionPolicy::IPv4First);
    auto r = resolveService(*c, "fb.test", udp);
    const auto *t = findTarget(r, "fb.test");
    REQUIRE(t != nullptr);
    REQUIRE(t->addresses.size() == 2);
    CHECK(isIPv4(t->addresses[0]));
    CHECK(isIPv6(t->addresses[1]));
  }
  SECTION("IPv6First: IPv6 then IPv4")
  {
    auto c = makeClient(AddressResolutionPolicy::IPv6First);
    auto r = resolveService(*c, "fb.test", udp);
    const auto *t = findTarget(r, "fb.test");
    REQUIRE(t != nullptr);
    REQUIRE(t->addresses.size() == 2);
    CHECK(isIPv6(t->addresses[0]));
    CHECK(isIPv4(t->addresses[1]));
  }
  SECTION("IPv6Only: only IPv6")
  {
    auto c = makeClient(AddressResolutionPolicy::IPv6Only);
    auto r = resolveService(*c, "fb.test", udp);
    const auto *t = findTarget(r, "fb.test");
    REQUIRE(t != nullptr);
    REQUIRE(t->addresses.size() == 1);
    CHECK(isIPv6(t->addresses[0]));
  }
}

// =============================================================================
// WIRE TESTS -- async result set matches the sync resolveHostname oracle
// =============================================================================

TEST_CASE_METHOD(PolicyWireFixture, "async per-target addresses match sync resolveHostname",
                 "[dns][policy][oracle]")
{
  startServer();
  server().addRecord({"_sip._udp.orc.test", "SRV", "h.orc.test", 3600, 10, 0, 5060});
  server().addRecord({"h.orc.test", "A", "192.0.2.40", 3600});
  server().addRecord({"h.orc.test", "A", "192.0.2.41", 3600});
  server().addRecord({"h.orc.test", "AAAA", "2001:db8::40", 3600});
  const std::vector<ServiceType> udp{ServiceType::SIP_UDP};

  for (auto policy : {AddressResolutionPolicy::IPv4First, AddressResolutionPolicy::IPv6First,
                      AddressResolutionPolicy::IPv4Only, AddressResolutionPolicy::IPv6Only})
  {
    auto c = makeClient(policy);
    auto sync = c->resolveHostname("h.orc.test");            // reference oracle
    auto r = resolveService(*c, "orc.test", udp);            // site-1 async path
    const auto *t = findTarget(r, "h.orc.test");
    if (sync.empty())
    {
      CHECK(t == nullptr); // e.g. IPv4Only with only... (here both exist, so non-empty)
    }
    else
    {
      REQUIRE(t != nullptr);
      CHECK(t->addresses == sync); // identical family-selection + ordering
    }
  }
}

// =============================================================================
// THROWING-DOUBLE TESTS -- TS-C1 synchronous-issue-throw at every site (no hang)
// =============================================================================

TEST_CASE("TS-C1 site1 2nd-family synchronous throw completes, target keeps 1st family",
          "[dns][tsc1][site1]")
{
  auto t = std::make_shared<FaultyDnsTransport>();
  t->srvTargets["_sip._udp.d.test"] = {"h.d.test"};
  t->aAddrs["h.d.test"] = {"192.0.2.50"};
  t->aaaaAddrs["h.d.test"] = {"2001:db8::50"};
  // IPv4First: the 2nd family issued per target is AAAA -> make the AAAA issue throw.
  t->throwName = "h.d.test";
  t->throwType = DnsType::AAAA;
  t->throwTypeSet = true;

  auto r = makeFaultyResolver(t, AddressResolutionPolicy::IPv4First);
  auto out = driveService(r, "d.test", {ServiceType::SIP_UDP});

  REQUIRE(out.completed);      // no hang despite the synchronous AAAA-issue throw
  CHECK(out.callbacks == 1);   // exactly one user callback
  const auto *tg = findTarget(out.result, "h.d.test");
  REQUIRE(tg != nullptr);
  REQUIRE(tg->addresses.size() == 1);
  CHECK(isIPv4(tg->addresses[0]));
}

TEST_CASE("TS-C1 SRV latch #2 (direct-SRV) synchronous throw on one query completes",
          "[dns][tsc1][srv2]")
{
  auto t = std::make_shared<FaultyDnsTransport>();
  // Two SRV sets; make the FIRST SRV issue throw, the second resolve normally.
  t->srvTargets["_sip._tcp.m.test"] = {"ht.m.test"};
  t->aAddrs["ht.m.test"] = {"192.0.2.60"};
  t->aaaaAddrs["ht.m.test"] = {"2001:db8::60"};
  t->throwOnCall = 1; // the first SRV issue in performDirectSrvResolutionAsync throws

  auto r = makeFaultyResolver(t, AddressResolutionPolicy::IPv4First);
  // Drive the direct-SRV path over both UDP + TCP so >1 SRV query is issued.
  auto count = std::make_shared<std::atomic<int>>(0);
  auto prom = std::make_shared<std::promise<ServiceResolutionResult>>();
  auto fut = prom->get_future();
  auto once = std::make_shared<std::atomic<bool>>(false);
  r->performDirectSrvResolutionAsync(
    "m.test",
    [count, prom, once](const ServiceResolutionResult &res, const std::exception_ptr &)
    {
      count->fetch_add(1);
      if (!once->exchange(true))
      {
        prom->set_value(res);
      }
    },
    {ServiceType::SIP_UDP, ServiceType::SIP_TCP});

  REQUIRE(fut.wait_for(BOUNDED_WAIT) == std::future_status::ready); // no hang
  auto res = fut.get();
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  CHECK(count->load() == 1); // exactly one callback
}

TEST_CASE("TS-C1 entry-site (initial NAPTR) synchronous throw delivers via callback",
          "[dns][tsc1][entry]")
{
  auto t = std::make_shared<FaultyDnsTransport>();
  t->throwName = "e.test"; // the initial NAPTR query for the domain throws
  t->throwType = DnsType::NAPTR;
  t->throwTypeSet = true;

  auto r = makeFaultyResolver(t, AddressResolutionPolicy::IPv4First);
  auto out = driveService(r, "e.test", {ServiceType::SIP_UDP});

  REQUIRE(out.completed);    // callback fired (via error), not a synchronous throw to caller
  CHECK(out.callbacks == 1);
}

TEST_CASE("TS-C1 queryAsync wrapper entry synchronous throw delivers via callback",
          "[dns][tsc1][entry][wrapper]")
{
  auto t = std::make_shared<FaultyDnsTransport>();
  t->throwOnCall = 1; // the wrapper's single issue throws synchronously

  auto r = makeFaultyResolver(t, AddressResolutionPolicy::IPv4First);
  DnsQuestion q("x.test", DnsType::A, DnsClass::IN);
  auto count = std::make_shared<std::atomic<int>>(0);
  auto prom = std::make_shared<std::promise<void>>();
  auto fut = prom->get_future();
  auto once = std::make_shared<std::atomic<bool>>(false);
  bool sawError = false;
  r->queryAsync(q, [&](const DnsResult &, const std::exception_ptr &ex)
                {
                  count->fetch_add(1);
                  if (ex) { sawError = true; }
                  if (!once->exchange(true)) { prom->set_value(); }
                });
  REQUIRE(fut.wait_for(BOUNDED_WAIT) == std::future_status::ready);
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  CHECK(count->load() == 1);
  CHECK(sawError);
}

TEST_CASE("TS-C1 exactly-once completion on the normal (no-fault) fan-out path",
          "[dns][tsc1][exactlyonce]")
{
  for (auto policy : {AddressResolutionPolicy::IPv4First, AddressResolutionPolicy::IPv6First,
                      AddressResolutionPolicy::IPv4Only, AddressResolutionPolicy::IPv6Only})
  {
    auto t = std::make_shared<FaultyDnsTransport>();
    t->srvTargets["_sip._udp.ok.test"] = {"h.ok.test"};
    t->aAddrs["h.ok.test"] = {"192.0.2.70"};
    t->aaaaAddrs["h.ok.test"] = {"2001:db8::70"};
    auto r = makeFaultyResolver(t, policy);
    auto out = driveService(r, "ok.test", {ServiceType::SIP_UDP});
    REQUIRE(out.completed);
    CHECK(out.callbacks == 1);
  }
}

TEST_CASE("TS-C1 inline (re-entrant) completion fires the callback exactly once",
          "[dns][tsc1][inline]")
{
  auto t = std::make_shared<FaultyDnsTransport>();
  t->asyncDispatch = false; // deliver callbacks inline (re-entrantly on the issuing thread)
  t->srvTargets["_sip._udp.inl.test"] = {"h.inl.test"};
  t->aAddrs["h.inl.test"] = {"192.0.2.80"};
  t->aaaaAddrs["h.inl.test"] = {"2001:db8::80"};
  auto r = makeFaultyResolver(t, AddressResolutionPolicy::IPv4First);
  auto out = driveService(r, "inl.test", {ServiceType::SIP_UDP});
  REQUIRE(out.completed);
  CHECK(out.callbacks == 1);
  const auto *tg = findTarget(out.result, "h.inl.test");
  REQUIRE(tg != nullptr);
  REQUIRE(tg->addresses.size() == 2);
  CHECK(isIPv4(tg->addresses[0]));
  CHECK(isIPv6(tg->addresses[1]));
}

// =============================================================================
// THROWING-DOUBLE TESTS -- multi-target fan-out, SRV latch #1 (NAPTR), NAPTR 'A'-flag
// =============================================================================

TEST_CASE("TS-C1 multi-target: outer/last issue throw on one target, siblings resolve",
          "[dns][tsc1][multitarget]")
{
  // Two SRV targets under one name -> site-1 fan-out over 2 targets.
  auto mk = []()
  {
    auto t = std::make_shared<FaultyDnsTransport>();
    t->srvTargets["_sip._udp.mt.test"] = {"h1.mt.test", "h2.mt.test"};
    t->aAddrs["h1.mt.test"] = {"192.0.2.101"};
    t->aaaaAddrs["h1.mt.test"] = {"2001:db8::101"};
    t->aAddrs["h2.mt.test"] = {"192.0.2.102"};
    t->aaaaAddrs["h2.mt.test"] = {"2001:db8::102"};
    return t;
  };

  SECTION("throw on the FIRST-issued target's outer A: it drops, sibling resolves")
  {
    auto t = mk();
    t->throwName = "h1.mt.test";
    t->throwType = DnsType::A;
    t->throwTypeSet = true;
    auto r = makeFaultyResolver(t, AddressResolutionPolicy::IPv4First);
    auto out = driveService(r, "mt.test", {ServiceType::SIP_UDP});
    REQUIRE(out.completed);
    CHECK(out.callbacks == 1);
    CHECK(findTarget(out.result, "h1.mt.test") == nullptr);   // dropped (no addresses)
    REQUIRE(findTarget(out.result, "h2.mt.test") != nullptr); // sibling resolved
  }
  SECTION("throw on the LAST-issued target's outer A: completer still fires")
  {
    auto t = mk();
    t->throwName = "h2.mt.test";
    t->throwType = DnsType::A;
    t->throwTypeSet = true;
    auto r = makeFaultyResolver(t, AddressResolutionPolicy::IPv4First);
    auto out = driveService(r, "mt.test", {ServiceType::SIP_UDP});
    REQUIRE(out.completed); // no hang when the throw is on the last target
    CHECK(out.callbacks == 1);
    REQUIRE(findTarget(out.result, "h1.mt.test") != nullptr);
    CHECK(findTarget(out.result, "h2.mt.test") == nullptr);
  }
}

TEST_CASE("multi-target heterogeneous (A-only / AAAA-only / both / neither) honors policy",
          "[dns][policy][multitarget][heterogeneous]")
{
  // "both" has A+AAAA, "aonly" only A, "a6only" only AAAA, "none" nothing.
  auto mk = []()
  {
    auto t = std::make_shared<FaultyDnsTransport>();
    t->srvTargets["_sip._udp.het.test"] = {"both.het", "aonly.het", "a6only.het", "none.het"};
    t->aAddrs["both.het"] = {"192.0.2.1"};
    t->aaaaAddrs["both.het"] = {"2001:db8::1"};
    t->aAddrs["aonly.het"] = {"192.0.2.2"};
    t->aaaaAddrs["a6only.het"] = {"2001:db8::3"};
    return t;
  };

  auto run = [&](AddressResolutionPolicy policy)
  {
    auto r = makeFaultyResolver(mk(), policy);
    auto out = driveService(r, "het.test", {ServiceType::SIP_UDP});
    REQUIRE(out.completed);
    CHECK(out.callbacks == 1);
    CHECK(findTarget(out.result, "none.het") == nullptr); // no records -> always erased
    return out.result;
  };

  SECTION("IPv4First: both=[A,AAAA]; aonly=[A]; a6only kept=[AAAA]")
  {
    auto res = run(AddressResolutionPolicy::IPv4First);
    const auto *both = findTarget(res, "both.het");
    REQUIRE((both && both->addresses.size() == 2));
    CHECK(isIPv4(both->addresses[0]));
    CHECK(isIPv6(both->addresses[1]));
    const auto *a4 = findTarget(res, "aonly.het");
    CHECK((a4 && a4->addresses.size() == 1 && isIPv4(a4->addresses[0])));
    const auto *a6 = findTarget(res, "a6only.het"); // First keeps only-AAAA
    CHECK((a6 && a6->addresses.size() == 1 && isIPv6(a6->addresses[0])));
  }
  SECTION("IPv6First: both=[AAAA,A]; aonly kept=[A]; a6only=[AAAA]")
  {
    auto res = run(AddressResolutionPolicy::IPv6First);
    const auto *both = findTarget(res, "both.het");
    REQUIRE((both && both->addresses.size() == 2));
    CHECK(isIPv6(both->addresses[0]));
    CHECK(isIPv4(both->addresses[1]));
    const auto *a4 = findTarget(res, "aonly.het"); // First keeps only-A
    CHECK((a4 && a4->addresses.size() == 1 && isIPv4(a4->addresses[0])));
    const auto *a6 = findTarget(res, "a6only.het");
    CHECK((a6 && a6->addresses.size() == 1 && isIPv6(a6->addresses[0])));
  }
  SECTION("IPv4Only: both=[A]; aonly=[A]; a6only DROPPED")
  {
    auto res = run(AddressResolutionPolicy::IPv4Only);
    const auto *both = findTarget(res, "both.het");
    CHECK((both && both->addresses.size() == 1 && isIPv4(both->addresses[0])));
    CHECK(findTarget(res, "aonly.het") != nullptr);
    CHECK(findTarget(res, "a6only.het") == nullptr); // Only drops the other family
  }
  SECTION("IPv6Only: both=[AAAA]; a6only=[AAAA]; aonly DROPPED")
  {
    auto res = run(AddressResolutionPolicy::IPv6Only);
    const auto *both = findTarget(res, "both.het");
    CHECK((both && both->addresses.size() == 1 && isIPv6(both->addresses[0])));
    CHECK(findTarget(res, "a6only.het") != nullptr);
    CHECK(findTarget(res, "aonly.het") == nullptr);
  }
}

TEST_CASE("TS-C1 SRV latch #1 (NAPTR-derived) synchronous throw on one SRV set completes",
          "[dns][tsc1][srv1][naptr]")
{
  auto t = std::make_shared<FaultyDnsTransport>();
  // NAPTR yields two SRV sets in one order tier.
  t->naptr["nap.test"] = {
    NaptrRecord("nap.test", 10, 10, "S", "SIP+D2U", "", "_sip._udp.nap.test", 3600),
    NaptrRecord("nap.test", 10, 20, "S", "SIP+D2T", "", "_sip._tcp.nap.test", 3600)};
  t->srvTargets["_sip._udp.nap.test"] = {"hu.nap.test"};
  t->srvTargets["_sip._tcp.nap.test"] = {"ht.nap.test"};
  t->aAddrs["hu.nap.test"] = {"192.0.2.111"};
  t->aaaaAddrs["hu.nap.test"] = {"2001:db8::111"};
  t->aAddrs["ht.nap.test"] = {"192.0.2.112"};
  // Throw on the _sip._tcp SRV issue in the NAPTR-derived SRV latch.
  t->throwName = "_sip._tcp.nap.test";
  t->throwType = DnsType::SRV;
  t->throwTypeSet = true;

  auto r = makeFaultyResolver(t, AddressResolutionPolicy::IPv4First);
  auto out = driveService(r, "nap.test", {ServiceType::SIP_UDP, ServiceType::SIP_TCP});
  REQUIRE(out.completed);    // no hang: the surviving SRV set drives completion
  CHECK(out.callbacks == 1);
  CHECK(findTarget(out.result, "hu.nap.test") != nullptr);
}

TEST_CASE("NAPTR 'A'-flag direct-target honors policy", "[dns][policy][naptr][aflag]")
{
  auto t = std::make_shared<FaultyDnsTransport>();
  t->naptr["af.test"] = {NaptrRecord("af.test", 10, 10, "A", "SIP+D2U", "", "ha.af.test", 3600)};
  t->aAddrs["ha.af.test"] = {"192.0.2.121"};
  t->aaaaAddrs["ha.af.test"] = {"2001:db8::121"};

  SECTION("IPv6First: AAAA before A on the direct-A target")
  {
    auto r = makeFaultyResolver(t, AddressResolutionPolicy::IPv6First);
    auto out = driveService(r, "af.test", {ServiceType::SIP_UDP});
    REQUIRE(out.completed);
    const auto *tg = findTarget(out.result, "ha.af.test");
    REQUIRE(tg != nullptr);
    REQUIRE(tg->addresses.size() == 2);
    CHECK(isIPv6(tg->addresses[0]));
    CHECK(isIPv4(tg->addresses[1]));
  }
}

TEST_CASE("TS-C1 site-2 fallback outer issue synchronous throw delivers via callback",
          "[dns][tsc1][site2]")
{
  auto t = std::make_shared<FaultyDnsTransport>();
  // No SRV/NAPTR -> direct SRV empty -> fallback on the domain; throw the fallback A issue.
  t->throwName = "s2.test";
  t->throwType = DnsType::A;
  t->throwTypeSet = true;
  auto r = makeFaultyResolver(t, AddressResolutionPolicy::IPv4First);
  auto out = driveService(r, "s2.test", {ServiceType::SIP_UDP});
  REQUIRE(out.completed);    // no hang / no unwind to caller
  CHECK(out.callbacks == 1);
}

TEST_CASE("throwing user callback is delivered AT MOST ONCE (no double delivery)",
          "[dns][tsc1][doublefire]")
{
  // Path A (steps-4-8 thread-safety H-1): performServiceResolutionAsync's runCompleter
  // calls resolveTargetAddressesAsync UNCONDITIONALLY; with an empty SRV result the
  // empty-target branch fires callback(*result, nullptr) DIRECTLY (not via the transport's
  // wrapped leaf), so a throwing callback would propagate into runCompleter's own catch and
  // be re-delivered as an error. This callback is resolver-invoked, so the transport's
  // leaf catch(...) does NOT shield it -- the single-fire gate must.
  auto t = std::make_shared<FaultyDnsTransport>();
  // NAPTR yields one SRV set, but the SRV returns NO records -> result->targets empty.
  t->naptr["pa.test"] = {
    NaptrRecord("pa.test", 10, 10, "S", "SIP+D2U", "", "_sip._udp.pa.test", 3600)};
  // (deliberately no srvTargets["_sip._udp.pa.test"] -> empty SRV answer)
  auto r = makeFaultyResolver(t, AddressResolutionPolicy::IPv4First);
  auto count = std::make_shared<std::atomic<int>>(0);
  auto prom = std::make_shared<std::promise<void>>();
  auto fut = prom->get_future();
  auto signaled = std::make_shared<std::atomic<bool>>(false);
  r->resolveServiceDomainAsync(
    "pa.test",
    [count, prom, signaled](const ServiceResolutionResult &, const std::exception_ptr &)
    {
      count->fetch_add(1);
      if (!signaled->exchange(true))
      {
        prom->set_value(); // signal first delivery BEFORE throwing
      }
      throw std::runtime_error("user callback throws"); // must not cause a second delivery
    },
    {ServiceType::SIP_UDP});
  REQUIRE(fut.wait_for(BOUNDED_WAIT) == std::future_status::ready); // first delivery happened
  // A broken gate re-delivers on the same worker stack, well within this drain window.
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  CHECK(count->load() == 1); // single-fire gate: exactly one delivery despite the throw
}

// =============================================================================
// WIRE TESTS -- site 3 (cache), H-1 regression (non-resolving fallback), secure x policy
// =============================================================================

TEST_CASE_METHOD(PolicyWireFixture, "site3 cache-hit path honors policy",
                 "[dns][policy][site3][cache]")
{
  startServer();
  MockDnsServer::DnsRecord naptrRec;
  naptrRec.name = "cache.test";
  naptrRec.type = "NAPTR";
  naptrRec.ttl = 3600;
  naptrRec.naptrOrder = 10;
  naptrRec.naptrPreference = 10;
  naptrRec.naptrFlags = "S";
  naptrRec.naptrService = "SIP+D2U";
  naptrRec.naptrReplacement = "_sip._udp.cache.test";
  server().addRecord(naptrRec);
  server().addRecord({"_sip._udp.cache.test", "SRV", "hc.cache.test", 3600, 10, 0, 5060});
  server().addRecord({"hc.cache.test", "A", "192.0.2.131", 3600});
  server().addRecord({"hc.cache.test", "AAAA", "2001:db8::131", 3600});
  const std::vector<ServiceType> udp{ServiceType::SIP_UDP};

  SECTION("IPv6First from cache: IPv6 before IPv4")
  {
    auto c = makeClient(AddressResolutionPolicy::IPv6First, /*cache=*/true);
    c->resolveServiceDomain("cache.test", udp); // sync warm (caches NAPTR+SRV+A+AAAA)
    auto r = resolveService(*c, "cache.test", udp); // async -> cache-hit -> site 3
    REQUIRE(r.fromCache);
    const auto *t = findTarget(r, "hc.cache.test");
    REQUIRE(t != nullptr);
    REQUIRE(t->addresses.size() == 2);
    CHECK(isIPv6(t->addresses[0]));
    CHECK(isIPv4(t->addresses[1]));
  }
  SECTION("IPv6Only from cache: only IPv6")
  {
    auto c = makeClient(AddressResolutionPolicy::IPv6Only, /*cache=*/true);
    c->resolveServiceDomain("cache.test", udp);
    auto r = resolveService(*c, "cache.test", udp);
    REQUIRE(r.fromCache);
    const auto *t = findTarget(r, "hc.cache.test");
    REQUIRE(t != nullptr);
    REQUIRE(t->addresses.size() == 1);
    CHECK(isIPv6(t->addresses[0]));
  }
}

TEST_CASE_METHOD(PolicyWireFixture, "site2 fallback non-resolving under policy emits NO target (H-1)",
                 "[dns][policy][site2][h1]")
{
  startServer();
  server().addRecord({"nr6.test", "AAAA", "2001:db8::140", 3600}); // only AAAA
  server().addRecord({"nr4.test", "A", "192.0.2.140", 3600});      // only A
  // nr0.test: no A/AAAA at all
  const std::vector<ServiceType> udp{ServiceType::SIP_UDP};

  // Every case must mirror sync resolveHostname (throws NoRecords -> no target); never an
  // empty-address target that would make isSuccess() falsely true.
  auto expectEmpty = [&](DnsClient &c, const std::string &domain)
  {
    auto r = resolveService(c, domain, udp);
    CHECK(r.targets.empty());
    CHECK_FALSE(r.isSuccess());
  };

  SECTION("IPv4Only + only-AAAA domain -> no target")
  {
    auto c = makeClient(AddressResolutionPolicy::IPv4Only);
    expectEmpty(*c, "nr6.test");
  }
  SECTION("IPv6Only + only-A domain -> no target (symmetric)")
  {
    auto c = makeClient(AddressResolutionPolicy::IPv6Only);
    expectEmpty(*c, "nr4.test");
  }
  SECTION("IPv4First + fully non-resolving domain -> no target (both families queried, empty)")
  {
    auto c = makeClient(AddressResolutionPolicy::IPv4First);
    expectEmpty(*c, "nr0.test");
  }
}

TEST_CASE_METHOD(PolicyWireFixture, "secure (SIPS) resolution is orthogonal to address policy",
                 "[dns][policy][secure]")
{
  startServer();
  server().addRecord({"_sips._tcp.sec.test", "SRV", "hs.sec.test", 3600, 10, 0, 5061});
  server().addRecord({"hs.sec.test", "A", "192.0.2.151", 3600});
  server().addRecord({"hs.sec.test", "AAAA", "2001:db8::151", 3600});

  auto c = makeClient(AddressResolutionPolicy::IPv6Only);
  auto prom = std::make_shared<std::promise<ServiceResolutionResult>>();
  auto fut = prom->get_future();
  c->resolveServiceDomainAsync(
    "sec.test",
    [prom](const ServiceResolutionResult &r, const std::exception_ptr &) { prom->set_value(r); },
    {ServiceType::SIPS_TLS}, /*secure=*/true);
  REQUIRE(fut.wait_for(BOUNDED_WAIT) == std::future_status::ready);
  auto r = fut.get();
  const auto *t = findTarget(r, "hs.sec.test");
  REQUIRE(t != nullptr);
  REQUIRE(t->addresses.size() == 1); // IPv6Only honored on the TLS target
  CHECK(isIPv6(t->addresses[0]));
}

// =============================================================================
// M2 -- full policy matrix vs the sync resolveHostname oracle, site 2 and site 3
// =============================================================================

TEST_CASE_METHOD(PolicyWireFixture, "site2 fallback matches sync oracle across all 4 policies",
                 "[dns][policy][site2][oracle]")
{
  startServer();
  server().addRecord({"s2o.test", "A", "192.0.2.160", 3600});
  server().addRecord({"s2o.test", "A", "192.0.2.161", 3600});
  server().addRecord({"s2o.test", "AAAA", "2001:db8::160", 3600});
  const std::vector<ServiceType> udp{ServiceType::SIP_UDP};

  for (auto policy : {AddressResolutionPolicy::IPv4First, AddressResolutionPolicy::IPv6First,
                      AddressResolutionPolicy::IPv4Only, AddressResolutionPolicy::IPv6Only})
  {
    auto c = makeClient(policy);
    auto sync = c->resolveHostname("s2o.test"); // oracle
    auto r = resolveService(*c, "s2o.test", udp);
    const auto *t = findTarget(r, "s2o.test");
    REQUIRE(t != nullptr);
    CHECK(t->addresses == sync); // identical family-selection + ordering to sync
  }
}

TEST_CASE_METHOD(PolicyWireFixture, "site3 cache matches sync oracle across all 4 policies",
                 "[dns][policy][site3][oracle]")
{
  startServer();
  MockDnsServer::DnsRecord naptrRec;
  naptrRec.name = "c3o.test";
  naptrRec.type = "NAPTR";
  naptrRec.ttl = 3600;
  naptrRec.naptrOrder = 10;
  naptrRec.naptrPreference = 10;
  naptrRec.naptrFlags = "S";
  naptrRec.naptrService = "SIP+D2U";
  naptrRec.naptrReplacement = "_sip._udp.c3o.test";
  server().addRecord(naptrRec);
  server().addRecord({"_sip._udp.c3o.test", "SRV", "hc3.c3o.test", 3600, 10, 0, 5060});
  server().addRecord({"hc3.c3o.test", "A", "192.0.2.170", 3600});
  server().addRecord({"hc3.c3o.test", "AAAA", "2001:db8::170", 3600});
  const std::vector<ServiceType> udp{ServiceType::SIP_UDP};

  for (auto policy : {AddressResolutionPolicy::IPv4First, AddressResolutionPolicy::IPv6First,
                      AddressResolutionPolicy::IPv4Only, AddressResolutionPolicy::IPv6Only})
  {
    auto c = makeClient(policy, /*cache=*/true);
    auto sync = c->resolveHostname("hc3.c3o.test"); // oracle
    c->resolveServiceDomain("c3o.test", udp);       // sync warm -> caches NAPTR+SRV+A+AAAA
    auto r = resolveService(*c, "c3o.test", udp);   // async -> cache-hit -> site 3
    REQUIRE(r.fromCache);
    const auto *t = findTarget(r, "hc3.c3o.test");
    REQUIRE(t != nullptr);
    CHECK(t->addresses == sync);
  }
}

// =============================================================================
// M-A -- secure (SIPS) A/AAAA FALLBACK path (RFC 3263 4.1 never-plaintext) x policy
// =============================================================================

TEST_CASE_METHOD(PolicyWireFixture, "secure fallback yields a TLS target and honors policy (never plaintext)",
                 "[dns][policy][secure][site2]")
{
  startServer();
  // No SRV/NAPTR -> secure resolution falls back to A/AAAA on the domain, which per
  // RFC 3263 4.1 must produce a SIPS/TLS target (never a plaintext transport).
  server().addRecord({"secfb.test", "A", "192.0.2.180", 3600});
  server().addRecord({"secfb.test", "AAAA", "2001:db8::180", 3600});

  auto secureResolve = [&](DnsClient &c, const std::string &domain)
  {
    auto prom = std::make_shared<std::promise<ServiceResolutionResult>>();
    auto fut = prom->get_future();
    c.resolveServiceDomainAsync(
      domain, [prom](const ServiceResolutionResult &r, const std::exception_ptr &) { prom->set_value(r); },
      {ServiceType::SIPS_TLS}, /*secure=*/true);
    REQUIRE(fut.wait_for(BOUNDED_WAIT) == std::future_status::ready);
    return fut.get();
  };

  SECTION("IPv6Only secure fallback -> AAAA on a SIPS/TLS target")
  {
    auto c = makeClient(AddressResolutionPolicy::IPv6Only);
    auto r = secureResolve(*c, "secfb.test");
    const auto *t = findTarget(r, "secfb.test");
    REQUIRE(t != nullptr);
    CHECK(t->transport == ServiceType::SIPS_TLS); // never a plaintext transport
    REQUIRE(t->addresses.size() == 1);
    CHECK(isIPv6(t->addresses[0]));
  }
  SECTION("secure fallback non-resolving under policy -> no target")
  {
    server().addRecord({"secfb4.test", "A", "192.0.2.181", 3600}); // only A
    auto c = makeClient(AddressResolutionPolicy::IPv6Only);
    auto r = secureResolve(*c, "secfb4.test"); // IPv6Only + only-A -> nothing resolves
    CHECK(r.targets.empty());
    CHECK_FALSE(r.isSuccess());
  }
}

// =============================================================================
// M3 -- concurrent multi-target stress (fan-out latch under contention)
// =============================================================================

TEST_CASE("concurrent multi-target resolutions all complete correctly (stress)",
          "[dns][tsc1][stress]")
{
  auto t = std::make_shared<FaultyDnsTransport>();
  t->srvTargets["_sip._udp.st.test"] = {"h1.st.test", "h2.st.test", "h3.st.test"};
  for (const char *h : {"h1.st.test", "h2.st.test", "h3.st.test"})
  {
    t->aAddrs[h] = {std::string("192.0.2.") + std::to_string(1 + (h[1] - '0'))};
    t->aaaaAddrs[h] = {std::string("2001:db8::") + std::to_string(1 + (h[1] - '0'))};
  }
  auto r = makeFaultyResolver(t, AddressResolutionPolicy::IPv4First);

  constexpr int N = 60;
  std::vector<std::future<ServiceResolutionResult>> futs;
  std::vector<std::shared_ptr<std::promise<ServiceResolutionResult>>> proms;
  for (int i = 0; i < N; ++i)
  {
    auto prom = std::make_shared<std::promise<ServiceResolutionResult>>();
    auto once = std::make_shared<std::atomic<bool>>(false);
    proms.push_back(prom);
    futs.push_back(prom->get_future());
    r->resolveServiceDomainAsync(
      "st.test",
      [prom, once](const ServiceResolutionResult &res, const std::exception_ptr &)
      { if (!once->exchange(true)) { prom->set_value(res); } },
      {ServiceType::SIP_UDP});
  }
  for (auto &f : futs)
  {
    REQUIRE(f.wait_for(BOUNDED_WAIT) == std::future_status::ready); // no hang under contention
    auto res = f.get();
    CHECK(res.targets.size() == 3); // all three targets resolved (no early/lost completion)
    for (const auto &tg : res.targets)
    {
      REQUIRE(tg.addresses.size() == 2);
      CHECK(isIPv4(tg.addresses[0])); // IPv4First order preserved under concurrency
      CHECK(isIPv6(tg.addresses[1]));
    }
  }
}

// =============================================================================
// L2 -- inline synchronous ERROR (failCallback-style) at the 2nd family
// =============================================================================

TEST_CASE("inline synchronous error at site-1 2nd family: exactly-once, chain continues",
          "[dns][tsc1][inline][error]")
{
  auto t = std::make_shared<FaultyDnsTransport>();
  t->asyncDispatch = false; // inline (re-entrant) delivery, like failCallback
  t->srvTargets["_sip._udp.ie.test"] = {"h.ie.test"};
  t->aAddrs["h.ie.test"] = {"192.0.2.190"};
  t->aaaaAddrs["h.ie.test"] = {"2001:db8::190"};
  // IPv4First: A first (ok), then AAAA -> deliver an inline ERROR for AAAA.
  t->errorName = "h.ie.test";
  t->errorType = DnsType::AAAA;
  t->errorTypeSet = true;

  auto r = makeFaultyResolver(t, AddressResolutionPolicy::IPv4First);
  auto out = driveService(r, "ie.test", {ServiceType::SIP_UDP});
  REQUIRE(out.completed);      // exactly-one decrement despite the inline error
  CHECK(out.callbacks == 1);
  const auto *tg = findTarget(out.result, "h.ie.test");
  REQUIRE(tg != nullptr);      // A retained (dual-stack partial result, RFC 3263 4.3)
  REQUIRE(tg->addresses.size() == 1);
  CHECK(isIPv4(tg->addresses[0]));
}
