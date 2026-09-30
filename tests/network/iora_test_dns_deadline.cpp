// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_dns_deadline.cpp
/// \brief DnsResolver per-resolution DEADLINE bounding the RFC 3263
///        NAPTR->SRV->A/AAAA chain under the SIP transaction ceiling
///        (Timer B/F = 64*T1 = 32s). Tracker 2026-09-30-3 (F-2), co-land with
///        the Slice-A failover mechanism (tracker 2026-09-25-8).
///
/// The deadline is an ADDITIVE, OFF-BY-DEFAULT cap (DnsConfig.maxResolutionTime{0}
/// = disabled = byte-for-byte today's behavior) plus an optional per-call override.
/// SYNC is HARD-bounded (an absolute steady_clock deadline threaded as a required
/// param through every internal impl + a maxWait hard-cap on DnsTransport::query);
/// ASYNC is SOFT-bounded via a single two-branch choke-point gate at
/// queryAsyncWithFailover (it stops issuing further servers/families past the
/// deadline but does not abort the one in-flight transport query).
///
/// On expiry the outcome is ALWAYS ResolutionOutcome::TransientFailure, NEVER
/// PermanentNoService, sync == async (a new DnsDeadlineException IS-A
/// DnsTransientResolutionException).
///
/// Test styles mirror iora_test_dns_failover.cpp:
///  * WIRE (MockDnsServer, incl. a shouldTimeout / non-responding node): real
///    wall-clock bounding and per-server udpQueries counting.
///  * WHITE-BOX (dns_transport_test_access.hpp): asyncAttemptBudget() value vs the
///    sync budget.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "MockDnsServer.hpp"
#include "dns_transport_test_access.hpp" // white-box seam: calcMaxSyncWait
#include "iora/network/dns_client.hpp"   // DnsClient forwarding smoke (M-C)
#include "iora/network/dns/dns_cache.hpp"
#include "iora/network/dns/dns_resolver.hpp"
#include "iora/network/dns/dns_transport.hpp"
#include "iora/network/dns/dns_types.hpp"

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

using namespace iora::network::dns;
using namespace std::chrono_literals;

namespace
{
// Distinct port block from the other DNS suites (comprehensive=15353, address_policy=15453,
// failover=15553). Deadline suite = PORT_A (15653) + small offsets, spanning ~15653..16003.
constexpr std::uint16_t PORT_A = 15653;
constexpr std::uint16_t PORT_B = 15654;

constexpr std::chrono::milliseconds STARTUP_DELAY{150};
constexpr std::chrono::seconds ASYNC_WAIT{6};

/// \brief One MockDnsServer instance on a dedicated port, started for its lifetime.
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

  /// Count queries of a DNS qtype this node received (from the enabled query log).
  /// A=1, AAAA=28, SRV=33, NAPTR=35.
  std::size_t countType(int qtype) const
  {
    const std::string needle = "type=" + std::to_string(qtype) + " ";
    std::size_t n = 0;
    for (const auto &line : server->getQueryLog())
    {
      if (line.find("DNS query:") != std::string::npos && line.find(needle) != std::string::npos)
      {
        ++n;
      }
    }
    return n;
  }
};

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
// A response (NXDOMAIN when no record is configured for the name) delivered after `d` — the mock
// sleeps before building the reply. Lets a query stay in flight PAST the deadline yet still return
// an AUTHORITATIVE negative (not a timeout-transient).
MockDnsServer::QueryConfig delayCfg(std::chrono::milliseconds d)
{
  MockDnsServer::QueryConfig q;
  q.delay = d;
  return q;
}
// A server that receives the query but NEVER responds -> the client waits its
// full (possibly maxWait-capped) budget. This is the deterministic "blackhole"
// for the deadline wall-clock / hard-cap tests.
MockDnsServer::QueryConfig timeoutCfg()
{
  MockDnsServer::QueryConfig q;
  q.shouldTimeout = true;
  return q;
}

DnsQuestion aQ(const std::string &name) { return DnsQuestion(name, DnsType::A, DnsClass::IN); }

/// \brief Build a real DnsResolver over a started DnsTransport, IN server order, with a
/// configurable per-resolution deadline (maxResolutionTime). A fresh resolver's
/// _serverRotation starts at 0, so the first query() starts at ports[0].
std::shared_ptr<DnsResolver> makeResolver(const std::vector<std::uint16_t> &ports,
                                          std::chrono::milliseconds timeout,
                                          int retryCount,
                                          std::chrono::milliseconds maxResolutionTime,
                                          std::shared_ptr<DnsCache> cache = nullptr,
                                          DnsTransportMode mode = DnsTransportMode::UDP)
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
  cfg.maxResolutionTime = maxResolutionTime;
  cfg.enableCache = (cache != nullptr);
  auto transport = std::make_shared<DnsTransport>(cfg);
  transport->start();
  return std::make_shared<DnsResolver>(transport, cache, cfg);
}

std::chrono::milliseconds elapsedMs(std::chrono::steady_clock::time_point t0)
{
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
}

// RAII capture of WARNING log lines: installs an external handler on construction and clears it on
// destruction, so a failing REQUIRE (which throws) never leaks the handler into later tests (cpp17
// round-3 L-2). The vector is mutex-guarded — a DNS I/O thread may log concurrently with the test
// thread's read, and this target runs under TSan.
struct LogCapture
{
  std::mutex mu;
  std::vector<std::string> warnings;
  LogCapture()
  {
    iora::core::Logger::setExternalHandler(
      [this](iora::core::Logger::Level level, const std::string &msg, const std::string &)
      {
        if (level == iora::core::Logger::Level::Warning)
        {
          std::lock_guard<std::mutex> lk(mu);
          warnings.push_back(msg);
        }
      });
  }
  ~LogCapture() { iora::core::Logger::clearExternalHandler(); }
  LogCapture(const LogCapture &) = delete;
  LogCapture &operator=(const LogCapture &) = delete;
  bool contains(const std::string &needle)
  {
    std::lock_guard<std::mutex> lk(mu);
    for (const auto &l : warnings)
    {
      if (l.find(needle) != std::string::npos)
      {
        return true;
      }
    }
    return false;
  }
};
} // namespace

// =============================================================================
// Config field default (backward-compat surface)
// =============================================================================

TEST_CASE("DnsConfig::maxResolutionTime defaults to 0 (disabled)", "[dns][deadline][config]")
{
  DnsConfig cfg;
  REQUIRE(cfg.maxResolutionTime == std::chrono::milliseconds::zero());
}

// =============================================================================
// SYNC — hard cap + deadline gate
// =============================================================================

TEST_CASE("SYNC hard-cap bounds the in-flight wait far below the full budget",
          "[dns][deadline][sync][hardcap]")
{
  // One non-responding server, a LARGE config budget (timeout 5s => full budget >> 5s), and a
  // SMALL deadline. Without the cap query() would wait the full budget; the maxWait hard-cap must
  // bound the single in-flight wait to ~the deadline. (retryCount 0 so exactly one send.)
  MockNode a(PORT_A);
  a->configureQuery("host.example.com", timeoutCfg());
  auto r = makeResolver({PORT_A}, /*timeout*/ 5000ms, /*retry*/ 0, /*maxResolutionTime*/ 400ms);

  auto t0 = std::chrono::steady_clock::now();
  REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsTransientResolutionException);
  auto took = elapsedMs(t0);

  // Bounded by ~deadline (400ms) + slop, and nowhere near the full ~7s budget.
  REQUIRE(took < 1500ms);
  REQUIRE(a.udpQueries() == 1); // exactly one send, capped
}

TEST_CASE("SYNC query() deadline -> transient terminal, wall-clock bounded by ~deadline",
          "[dns][deadline][sync][gate]")
{
  // Two blackholed servers, a large config timeout (so the deadline maxWait-cap governs, not the
  // per-query timer) and a small deadline. The chain must terminate transiently at ~the deadline and
  // never spend the full ~7s budget. We assert the BASE transient type here (both the exhaustion
  // DnsTransientResolutionException and the deadline-branch DnsDeadlineException are IS-A it, and
  // either is a correct terminal); the concrete DnsDeadlineException sub-type firing is asserted
  // deterministically in the IS-A test above (the ceil'd maxWait makes the gate fire on rotation).
  MockNode a(PORT_A), b(PORT_B);
  a->configureQuery("host.example.com", timeoutCfg());
  b->configureQuery("host.example.com", timeoutCfg());
  auto r = makeResolver({PORT_A, PORT_B}, /*timeout*/ 5000ms, /*retry*/ 0, /*maxResolutionTime*/ 300ms);

  auto t0 = std::chrono::steady_clock::now();
  REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsTransientResolutionException);
  auto took = elapsedMs(t0);

  // Bounded by ~the deadline (the last in-flight wait is capped to the remaining budget), never
  // the ~7s two-server full budget.
  REQUIRE(took < 1500ms);
}

TEST_CASE("SYNC DnsDeadlineException is delivered and IS-A DnsTransientResolutionException",
          "[dns][deadline][sync][type]")
{
  // Compile-time IS-A guarantee (the whole outcome-routing rests on it).
  static_assert(std::is_base_of<DnsTransientResolutionException, DnsDeadlineException>::value,
                "DnsDeadlineException must derive from DnsTransientResolutionException");

  // Two blackholed servers. With remainingSyncWait rounding UP (ceil), server A's capped wait ends
  // at-or-after the deadline, so the rotation to server B DETERMINISTICALLY hits the deadline
  // branch -> a concrete DnsDeadlineException (not merely the base exhaustion transient). Verify
  // both the concrete type AND that it unwinds through the transient BASE handler + carries its
  // distinct message.
  MockNode a(PORT_A + 100), b(PORT_A + 101);
  a->configureQuery("h2.example.com", timeoutCfg());
  b->configureQuery("h2.example.com", timeoutCfg());
  auto r = makeResolver({static_cast<std::uint16_t>(PORT_A + 100),
                         static_cast<std::uint16_t>(PORT_A + 101)},
                        5000ms, 0, 250ms);

  // Concrete type (REQUIRE_THROWS_AS) + distinct message (REQUIRE_THROWS_WITH — fails if no throw,
  // unlike a bare try/catch whose assertion would silently not run; cpp17 L-6). The IS-A / base-
  // handler routing is guaranteed at COMPILE time by the static_assert above, so no runtime re-check
  // (and no third query() call) is needed (simpl M-2d).
  REQUIRE_THROWS_AS(r->query(aQ("h2.example.com")), DnsDeadlineException);
  REQUIRE_THROWS_WITH(r->query(aQ("h2.example.com")), Catch::Contains("deadline exceeded"));
}

TEST_CASE("SYNC deadline OFF (0) -> full failover; exhaustion terminal is "
          "DnsTransientResolutionException (backward-compat)",
          "[dns][deadline][sync][off]")
{
  // Two servers, immediate responses (no waiting): A SERVFAIL, B REFUSED. With the deadline
  // disabled the loop visits BOTH and the terminal is the plain transient exhaustion type, NOT
  // DnsDeadlineException, and it carries the LAST server's rcode (REFUSED) faithfully (L-5).
  MockNode a(PORT_A), b(PORT_B);
  a->configureQuery("host.example.com", servfail());
  b->configureQuery("host.example.com", refused());
  auto r = makeResolver({PORT_A, PORT_B}, 400ms, 0, /*maxResolutionTime*/ 0ms);

  bool threwDeadline = false;
  bool threwTransient = false;
  DnsResponseCode terminalRcode = DnsResponseCode::NOERROR;
  try
  {
    r->query(aQ("host.example.com"));
  }
  catch (const DnsDeadlineException &)
  {
    threwDeadline = true;
  }
  catch (const DnsTransientResolutionException &e)
  {
    threwTransient = true;
    terminalRcode = e.getResponseCode();
  }
  REQUIRE_FALSE(threwDeadline);
  REQUIRE(threwTransient);
  REQUIRE(terminalRcode == DnsResponseCode::REFUSED); // faithful last-server rcode (not the default)
  REQUIRE(a.udpQueries() == 1);
  REQUIRE(b.udpQueries() == 1); // full failover: both servers visited
}

TEST_CASE("SYNC resolveServiceDomain deadline -> TransientFailure, whole chain bounded by ~deadline",
          "[dns][deadline][sync][outcome][gate]")
{
  // A single blackholed server + a small deadline. The NAPTR wait is maxWait-capped to the
  // deadline; every SUBSEQUENT RFC 3263 step (direct-SRV, A/AAAA) then enters queryImpl with the
  // deadline expired (or all-but-expired) and is gated/capped, so the WHOLE multi-step chain
  // terminates at ~the deadline instead of ~5s (the un-capped NAPTR budget alone). The delivered
  // result is TransientFailure, never PermanentNoService. (An exact wire-query COUNT is a boundary
  // tie — the maxWait cap makes elapsed converge to the deadline — so the deterministic properties
  // asserted here are the OUTCOME and the whole-chain WALL-CLOCK bound.)
  MockNode a(PORT_A);
  a->configureQuery("example.com", "NAPTR", timeoutCfg());
  auto r = makeResolver({PORT_A}, /*timeout*/ 5000ms, /*retry*/ 0, /*maxResolutionTime*/ 300ms);

  auto t0 = std::chrono::steady_clock::now();
  ServiceResolutionResult res = r->resolveServiceDomain("example.com", {ServiceType::SIP_UDP});
  auto took = elapsedMs(t0);

  REQUIRE_FALSE(res.isSuccess());
  REQUIRE(res.outcome == ResolutionOutcome::TransientFailure);
  // Whole NAPTR->SRV->A/AAAA chain bounded near the deadline; a single un-capped NAPTR wait alone
  // would be ~5s.
  REQUIRE(took < 2000ms);
}

// =============================================================================
// SYNC — per-call override semantics
// =============================================================================

TEST_CASE("SYNC per-call override: enables when config is off, and overrides config",
          "[dns][deadline][sync][override]")
{
  SECTION("override enables the deadline when config is disabled (0)")
  {
    MockNode a(PORT_A);
    a->configureQuery("host.example.com", timeoutCfg());
    auto r = makeResolver({PORT_A}, 5000ms, 0, /*config*/ 0ms);

    auto t0 = std::chrono::steady_clock::now();
    REQUIRE_THROWS_AS(r->query(aQ("host.example.com"), /*override*/ 350ms),
                      DnsTransientResolutionException);
    REQUIRE(elapsedMs(t0) < 1500ms); // override bounded the wait
  }

  SECTION("override beats a large config deadline")
  {
    MockNode a(PORT_A + 1);
    a->configureQuery("host.example.com", timeoutCfg());
    auto r = makeResolver({static_cast<std::uint16_t>(PORT_A + 1)}, 5000ms, 0, /*config*/ 5000ms);

    auto t0 = std::chrono::steady_clock::now();
    REQUIRE_THROWS_AS(r->query(aQ("host.example.com"), /*override*/ 350ms),
                      DnsTransientResolutionException);
    REQUIRE(elapsedMs(t0) < 1500ms); // 350ms override wins over the 5s config
  }

  SECTION("override == 0ms disables the deadline for this call (distinct from config)")
  {
    MockNode a(PORT_A + 2);
    a->configureQuery("host.example.com", timeoutCfg());
    // Config would bound to 250ms. With retries the un-bounded query lives across ~4 retransmits
    // (>> 250ms) before giving up; the per-call override 0ms DISABLES the deadline for this call,
    // so the full retry budget is spent -> wall-clock well above the 250ms config value. (With
    // the config deadline active it would instead cap at ~250ms.)
    auto r = makeResolver({static_cast<std::uint16_t>(PORT_A + 2)}, /*timeout*/ 250ms, /*retry*/ 4,
                          /*config*/ 250ms);

    auto t0 = std::chrono::steady_clock::now();
    REQUIRE_THROWS_AS(r->query(aQ("host.example.com"), /*override*/ std::chrono::milliseconds{0}),
                      DnsTransientResolutionException);
    REQUIRE(elapsedMs(t0) > 700ms); // NOT bounded to 250ms -> the override disabled the deadline
  }
}

// =============================================================================
// ASYNC — soft gate
// =============================================================================

// --- async drivers that COUNT every delivery (for exactly-once checks) ---
namespace
{
struct AsyncQueryOutcome
{
  bool completed{false};
  std::exception_ptr error;
  DnsResult result;
  int deliveries{0};
};

// Drive queryAsync. queryAsync does NOT wrap the callback in makeSingleFire, so `deliveries` is a
// GENUINE RAW count — an internal double-fire IS observable here (the real exactly-once guard).
AsyncQueryOutcome driveQueryAsync(const std::shared_ptr<DnsResolver> &r, const DnsQuestion &q)
{
  auto prom = std::make_shared<std::promise<void>>();
  auto fut = prom->get_future();
  auto out = std::make_shared<AsyncQueryOutcome>();
  auto once = std::make_shared<std::atomic<bool>>(false);
  r->queryAsync(q,
                [prom, out, once](const DnsResult &res, const std::exception_ptr &ex)
                {
                  out->deliveries++; // counts real deliveries; first one settles the promise
                  if (!once->exchange(true))
                  {
                    out->result = res;
                    out->error = ex;
                    prom->set_value();
                  }
                });
  out->completed = fut.wait_for(ASYNC_WAIT) == std::future_status::ready;
  std::this_thread::sleep_for(std::chrono::milliseconds(100)); // settle a spurious 2nd delivery
  return *out;
}

struct AsyncSvcOutcome
{
  bool completed{false};
  ServiceResolutionResult result{""};
  int deliveries{0};
};
// Drive resolveServiceDomainAsync. NOTE (thread-safety M-1): resolveServiceDomainAsync wraps the
// user callback in makeSingleFire, so `deliveries` here is USER-FACING at-most-once, NOT a raw
// internal-double-fire detector (makeSingleFire would mask an internal double-callback). The
// internal fan-out finishTarget exactly-once is guarded by the Slice-A tests + TSan; the RAW gate
// exactly-once is guarded by the queryAsync-based [gate]/[overhang] tests above.
AsyncSvcOutcome driveSvcAsyncCounted(const std::shared_ptr<DnsResolver> &r, const std::string &domain,
                                     const std::vector<ServiceType> &transports)
{
  auto prom = std::make_shared<std::promise<void>>();
  auto fut = prom->get_future();
  auto out = std::make_shared<AsyncSvcOutcome>();
  auto once = std::make_shared<std::atomic<bool>>(false);
  r->resolveServiceDomainAsync(
    domain,
    [prom, out, once](const ServiceResolutionResult &res, const std::exception_ptr &)
    {
      out->deliveries++;
      if (!once->exchange(true))
      {
        out->result = res;
        prom->set_value();
      }
    },
    transports);
  out->completed = fut.wait_for(ASYNC_WAIT) == std::future_status::ready;
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  return *out;
}

bool isDeadlineErr(const std::exception_ptr &ex)
{
  if (!ex)
  {
    return false;
  }
  try
  {
    std::rethrow_exception(ex);
  }
  catch (const DnsDeadlineException &)
  {
    return true;
  }
  catch (...)
  {
  }
  return false;
}
} // namespace

TEST_CASE("ASYNC mid-NAPTR-expiry fall-forward: TransientFailure, delivered once, ZERO wire after "
          "expiry",
          "[dns][deadline][async][outcome]")
{
  // A generic NAPTR-publishing carrier/ITSP domain (NOT Teams — SRV-based, no NAPTR). One
  // non-responding server; the in-flight NAPTR runs to its natural (config) timeout (the async
  // bound is soft), then every later step (direct-SRV, A/AAAA) is deadline-gated -> TransientFailure,
  // delivered exactly once, and NO wire query is issued after expiry (only the one NAPTR hit).
  MockNode a(PORT_A);
  a->configureQuery("carrier.example.com", "NAPTR", timeoutCfg());
  auto r = makeResolver({PORT_A}, /*timeout*/ 200ms, /*retry*/ 0, /*maxResolutionTime*/ 60ms);

  auto t0 = std::chrono::steady_clock::now();
  auto out = driveSvcAsyncCounted(r, "carrier.example.com", {ServiceType::SIP_UDP});
  auto took = elapsedMs(t0);

  REQUIRE(out.completed);
  REQUIRE(out.deliveries == 1);
  REQUIRE_FALSE(out.result.isSuccess());
  REQUIRE(out.result.outcome == ResolutionOutcome::TransientFailure);
  REQUIRE(a.udpQueries() == 1);        // only the NAPTR; direct-SRV + A/AAAA gated, zero wire
  REQUIRE(took < 3000ms);              // soft bound ~ deadline + one in-flight attempt
}

// =============================================================================
// UNIT — asyncAttemptBudget() value + resolver delegation
// =============================================================================

TEST_CASE("asyncAttemptBudget(): UDP mode == syncBudget - margin; Both mode adds the TCP-fallback leg",
          "[dns][deadline][unit][budget]")
{
  using Access = iora::network::dns::DnsTransportTestAccess;

  SECTION("UDP mode: exactly the sync budget minus the sync-only safety margin")
  {
    DnsConfig cfg;
    cfg.setServers({"127.0.0.1:5353"});
    cfg.timeout = 5000ms;
    cfg.retryCount = 2; // within [0,100] clamp
    cfg.transportMode = DnsTransportMode::UDP; // no TCP fallback leg
    auto t = std::make_shared<DnsTransport>(cfg);
    t->start();

    auto sync = Access::calcMaxSyncWait(*t); // calculateMaxSyncWaitTime uses the same clamp
    auto async = t->asyncAttemptBudget(cfg);
    REQUIRE(async == sync - 2000ms);
    REQUIRE(async > 0ms);
    // Dominated by timeout*(retryCount+1): a usable async deadline generally needs a reduced budget.
    REQUIRE(async >= cfg.timeout * (cfg.retryCount + 1));
  }

  SECTION("Both mode: TC=1 -> TCP fallback leg is EXACTLY timeout + _cleanupInterval")
  {
    DnsConfig cfg;
    cfg.setServers({"127.0.0.1:5353"});
    cfg.timeout = 5000ms;
    cfg.retryCount = 2;
    cfg.transportMode = DnsTransportMode::Both;
    auto t = std::make_shared<DnsTransport>(cfg);
    // Pin the cleanup interval BEFORE start() (test-access requires un-started) so the exact leg
    // size is known. The leg is timeout + cleanupInterval (the TCP fallback arms a FRESH timeout
    // timer from t_TC, cpp17 round-3 H-1); a mutation dropping the `timeout` term FAILS here.
    constexpr auto kCleanup = std::chrono::milliseconds{7000};
    iora::network::dns::DnsTransportTestAccess::setCleanupInterval(*t, kCleanup);
    t->start();

    auto udpEquivalent = t->udpAttemptBudget(cfg); // == calcMaxSyncWait - kSyncSafetyMargin
    REQUIRE(udpEquivalent == Access::calcMaxSyncWait(*t) - 2000ms);
    auto both = t->asyncAttemptBudget(cfg);
    REQUIRE(both == udpEquivalent + cfg.timeout + kCleanup);
  }

  SECTION("TCP-only mode: no UDP->TCP fallback leg (== UDP-retransmit portion)")
  {
    DnsConfig cfg;
    cfg.setServers({"127.0.0.1:5353"});
    cfg.timeout = 5000ms;
    cfg.retryCount = 1;
    cfg.transportMode = DnsTransportMode::TCP;
    auto t = std::make_shared<DnsTransport>(cfg);
    t->start();
    // TCP mode issues TCP from the start with its own timer (already in the budget) — no extra leg.
    REQUIRE(t->asyncAttemptBudget(cfg) == Access::calcMaxSyncWait(*t) - 2000ms);
  }
}

TEST_CASE("DnsResolver::asyncAttemptBudget() delegates to the transport on the live config",
          "[dns][deadline][unit][budget]")
{
  DnsConfig cfg;
  cfg.setServers({"127.0.0.1:5353"});
  cfg.timeout = 3000ms;
  cfg.retryCount = 1;
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();
  auto r = std::make_shared<DnsResolver>(t, nullptr, cfg);

  REQUIRE(r->asyncAttemptBudget() == t->asyncAttemptBudget(cfg));
  REQUIRE(r->asyncAttemptBudget() > 0ms);
}

TEST_CASE("computeResolutionDeadline saturates a huge budget to 'disabled' (no overflow)",
          "[dns][deadline][unit][overflow]")
{
  // A caller passing milliseconds::max() (meaning "effectively unbounded") must NOT overflow
  // now()+budget into a PAST deadline (which would make every resolution instantly expire). It is
  // treated as disabled, so a plain SERVFAIL exhausts normally (transient, not a deadline).
  MockNode a(PORT_A), b(PORT_B);
  a->configureQuery("host.example.com", servfail());
  b->configureQuery("host.example.com", servfail());
  auto r = makeResolver({PORT_A, PORT_B}, 300ms, 0, /*config*/ 0ms);

  bool threwDeadline = false;
  try
  {
    r->query(aQ("host.example.com"), /*override*/ std::chrono::milliseconds::max());
  }
  catch (const DnsDeadlineException &)
  {
    threwDeadline = true;
  }
  catch (const DnsTransientResolutionException &)
  {
  }
  REQUIRE_FALSE(threwDeadline);       // NOT instantly expired
  REQUIRE(a.udpQueries() == 1);       // full failover happened (deadline effectively disabled)
  REQUIRE(b.udpQueries() == 1);
}

TEST_CASE("A NEGATIVE deadline FAILS CLOSED to TransientFailure (HIGH-A), never unbounded",
          "[dns][deadline][unit][failclosed]")
{
  // HIGH-A: a negative budget (e.g. a consumer's Timer_B - asyncAttemptBudget() - margin
  // underflowing negative) must NOT silently disable the deadline. It fails CLOSED to an
  // already-expired deadline: TransientFailure, with ZERO wire queries (the first gate fires before
  // any issue). Distinct from an explicit 0 (disabled, full failover — the overflow test above
  // shows the disabled path). A blackholed server would take ~2s+ if the deadline were disabled;
  // here it returns immediately.
  MockNode a(PORT_A), b(PORT_B);
  a->configureQuery("host.example.com", timeoutCfg()); // would blackhole if the deadline were off
  a->configureQuery("host.example.com", "NAPTR", timeoutCfg());
  b->configureQuery("host.example.com", timeoutCfg());

  SECTION("sync query() via a per-call negative override -> DnsDeadlineException, zero wire")
  {
    auto r = makeResolver({PORT_A, PORT_B}, 5000ms, 0, /*config*/ 0ms);
    auto t0 = std::chrono::steady_clock::now();
    // Concrete DnsDeadlineException (deterministic — the first gate fires on the already-expired now()).
    REQUIRE_THROWS_AS(r->query(aQ("host.example.com"), /*override*/ std::chrono::milliseconds{-1}),
                      DnsDeadlineException);
    REQUIRE(elapsedMs(t0) < 500ms); // failed closed immediately, not the ~10s two-server soak
    REQUIRE(a.udpQueries() == 0);   // ZERO wire queries — gated before the first issue
    REQUIRE(b.udpQueries() == 0);
  }

  SECTION("negative CONFIG maxResolutionTime (not just an override) also fails closed")
  {
    auto r = makeResolver({PORT_A, PORT_B}, 5000ms, 0, /*config*/ std::chrono::milliseconds{-5});
    auto t0 = std::chrono::steady_clock::now();
    REQUIRE_THROWS_AS(r->query(aQ("host.example.com")), DnsDeadlineException);
    REQUIRE(elapsedMs(t0) < 500ms);
    REQUIRE(a.udpQueries() == 0);
  }

  SECTION("sync resolveServiceDomain negative -> outcome TransientFailure, zero wire")
  {
    auto r = makeResolver({PORT_A, PORT_B}, 5000ms, 0, /*config*/ std::chrono::milliseconds{-1});
    auto t0 = std::chrono::steady_clock::now();
    auto res = r->resolveServiceDomain("host.example.com", {ServiceType::SIP_UDP});
    REQUIRE(res.outcome == ResolutionOutcome::TransientFailure);
    REQUIRE(elapsedMs(t0) < 500ms);
    REQUIRE(a.udpQueries() == 0); // §4.2 apex fallback also suppressed (transient) -> zero wire
  }

  SECTION("async queryAsync negative (config) -> DnsDeadlineException, delivered once, zero wire")
  {
    auto r = makeResolver({PORT_A, PORT_B}, 5000ms, 0, /*config*/ std::chrono::milliseconds{-1});
    auto t0 = std::chrono::steady_clock::now();
    auto out = driveQueryAsync(r, aQ("host.example.com"));
    REQUIRE(out.completed);
    REQUIRE(out.deliveries == 1);
    REQUIRE(isDeadlineErr(out.error)); // the async deadline gate fires immediately
    REQUIRE(elapsedMs(t0) < 1000ms);
    REQUIRE(a.udpQueries() == 0);
  }
}

// =============================================================================
// SYNC — zero-extra-queries after expiry + per-avenue / §4.2 wall-clock bounds
// =============================================================================

namespace
{
// Pre-populate a cache with a POSITIVE A answer for `host` -> `addr`, so queryImpl's cache-first
// check (which precedes the deadline gate) serves it even past the deadline.
void putCachedA(const std::shared_ptr<DnsCache> &cache, const std::string &host,
                const std::string &addr)
{
  DnsResult res;
  res.header.rcode = DnsResponseCode::NOERROR;
  res.header.ancount = 1;
  res.a_records.emplace_back(host, addr, 3600);
  cache->put(DnsQuestion(host, DnsType::A, DnsClass::IN), res);
}
} // namespace

TEST_CASE("SYNC deadline unwinds with ZERO extra wire queries after NAPTR expiry",
          "[dns][deadline][sync][gate][zeroextra]")
{
  // NAPTR blackholes and its maxWait-capped wait consumes the whole deadline; the direct-SRV step
  // then enters queryImpl with the deadline already expired and (thanks to remainingSyncWait rounding
  // UP) re-throws DnsDeadlineException BEFORE issuing -> marks anySrvTransient, which SUPPRESSES the
  // RFC 3263 §4.2 apex A/AAAA fallback entirely (a transient is not proof of absence). Net: the
  // server sees EXACTLY the one NAPTR query.
  MockNode a(PORT_A);
  a->configureQuery("z.example.com", "NAPTR", timeoutCfg());
  auto r = makeResolver({PORT_A}, /*timeout*/ 5000ms, /*retry*/ 0, /*maxResolutionTime*/ 300ms);

  ServiceResolutionResult res = r->resolveServiceDomain("z.example.com", {ServiceType::SIP_UDP});
  REQUIRE(res.outcome == ResolutionOutcome::TransientFailure);
  REQUIRE(a.udpQueries() == 1); // only NAPTR; direct-SRV gated, §4.2 apex suppressed -> zero wire
}

TEST_CASE("SYNC per-avenue wall-clock bounds: each avenue's timeout is capped by the deadline",
          "[dns][deadline][sync][peravenue]")
{
  constexpr std::chrono::milliseconds D{400};
  const auto bound = 2000ms; // « the 5s config timeout the blackhole would otherwise consume

  SECTION("NAPTR avenue timeout")
  {
    MockNode a(PORT_A);
    a->configureQuery("pa.example.com", "NAPTR", timeoutCfg());
    auto r = makeResolver({PORT_A}, 5000ms, 0, D);
    auto t0 = std::chrono::steady_clock::now();
    auto res = r->resolveServiceDomain("pa.example.com", {ServiceType::SIP_UDP});
    REQUIRE(elapsedMs(t0) < bound);
    REQUIRE(res.outcome == ResolutionOutcome::TransientFailure);
  }

  SECTION("direct-SRV avenue timeout (NAPTR authoritative-absent, SRV blackholes)")
  {
    MockNode a(PORT_B);
    // NAPTR unconfigured -> NXDOMAIN (authoritative) -> fall to direct SRV, which blackholes.
    a->configureQuery("_sip._udp.pb.example.com", "SRV", timeoutCfg());
    auto r = makeResolver({PORT_B}, 5000ms, 0, D);
    auto t0 = std::chrono::steady_clock::now();
    auto res = r->resolveServiceDomain("pb.example.com", {ServiceType::SIP_UDP});
    REQUIRE(elapsedMs(t0) < bound);
    REQUIRE(res.outcome == ResolutionOutcome::TransientFailure);
  }

  SECTION("A/AAAA avenue timeout (SRV resolves a target whose A blackholes)")
  {
    MockNode a(static_cast<std::uint16_t>(PORT_A + 200));
    const std::string domain = "pc.example.com";
    a->addRecord({"_sip._udp." + domain, "SRV", "t." + domain, 3600, 10, 0, 5060});
    a->configureQuery("t." + domain, "A", timeoutCfg());
    a->configureQuery("t." + domain, "AAAA", timeoutCfg());
    auto r = makeResolver({static_cast<std::uint16_t>(PORT_A + 200)}, 5000ms, 0, D);
    auto t0 = std::chrono::steady_clock::now();
    auto res = r->resolveServiceDomain(domain, {ServiceType::SIP_UDP});
    REQUIRE(elapsedMs(t0) < bound);
    REQUIRE(res.outcome == ResolutionOutcome::TransientFailure);
  }

  SECTION("§4.2 apex fallback avenue timeout (NAPTR/SRV absent, apex A/AAAA blackhole)")
  {
    MockNode a(static_cast<std::uint16_t>(PORT_A + 201));
    const std::string domain = "pd.example.com";
    // NAPTR + SRV unconfigured -> authoritative NXDOMAIN -> RFC 3263 §4.2 apex A/AAAA fallback.
    a->configureQuery(domain, "A", timeoutCfg());
    a->configureQuery(domain, "AAAA", timeoutCfg());
    auto r = makeResolver({static_cast<std::uint16_t>(PORT_A + 201)}, 5000ms, 0, D);
    auto t0 = std::chrono::steady_clock::now();
    auto res = r->resolveServiceDomain(domain, {ServiceType::SIP_UDP});
    REQUIRE(elapsedMs(t0) < bound);
    REQUIRE(res.outcome == ResolutionOutcome::TransientFailure);
  }
}

TEST_CASE("SYNC partial-Resolved: preferred target blackholed, cached backup returned "
          "(RFC 2782 / §4.3)",
          "[dns][deadline][sync][partial][adversarial]")
{
  // Human M-1 = ACCEPT partial-Resolved. Two SRV targets: priority-10 PREFERRED (A blackholed) and
  // priority-20 backup (A pre-cached). The preferred is resolved first, consumes the deadline; the
  // backup is then served from cache (queryImpl cache-first precedes the gate). Result: Resolved
  // with ONLY the reachable backup; the preferred is dropped (priority inversion, self-heals next
  // resolution). NOTE: this validates the partial-Resolved OUTCOME; it does NOT prove the priority
  // pre-sort (preferred is inserted first here, so wire order already equals priority order) — the
  // next test proves the sort by inserting the backup first.
  const std::string domain = "prio.example.com";
  const std::string preferred = "primary." + domain;
  const std::string backup = "backup." + domain;

  MockNode a(static_cast<std::uint16_t>(PORT_A + 210));
  // NAPTR unconfigured -> NXDOMAIN -> direct SRV. Two SRV targets at different priorities.
  a->addRecord({"_sip._udp." + domain, "SRV", preferred, 3600, /*prio*/ 10, /*weight*/ 0, 5060});
  a->addRecord({"_sip._udp." + domain, "SRV", backup, 3600, /*prio*/ 20, /*weight*/ 0, 5060});
  a->configureQuery(preferred, "A", timeoutCfg());    // preferred blackholes
  a->configureQuery(preferred, "AAAA", timeoutCfg());

  auto cache = std::make_shared<DnsCache>();
  putCachedA(cache, backup, "192.0.2.80"); // backup served from cache, past the deadline

  auto r = makeResolver({static_cast<std::uint16_t>(PORT_A + 210)}, 5000ms, 0,
                        /*maxResolutionTime*/ 500ms, cache);

  ServiceResolutionResult res = r->resolveServiceDomain(domain, {ServiceType::SIP_UDP});
  REQUIRE(res.isSuccess());
  REQUIRE(res.outcome == ResolutionOutcome::Resolved);
  REQUIRE(res.targets.size() == 1);
  REQUIRE(res.getPreferredTarget().hostname == backup); // preferred dropped, reachable backup wins
}

TEST_CASE("SYNC priority pre-sort defeats a wire-order inversion (HIGH-3): backup FIRST on the wire "
          "+ blackholed, preferred SECOND + live -> preferred wins",
          "[dns][deadline][sync][partial][inversion]")
{
  // The mutation guard for the H-3 stable_sort (sip-voip HIGH-B / cpp17 M-1): MockDnsServer returns
  // SRV RRs in INSERTION order, so inserting the LOWER-priority (20) backup FIRST and the healthy
  // priority-10 preferred SECOND makes wire order the OPPOSITE of priority order. WITHOUT the
  // pre-sort the deadline would resolve the backup first, let it consume the budget, and CUT the
  // preferred -> wrong result. WITH the pre-sort the preferred is resolved first (healthy, fast) and
  // wins; the backup then blackholes harmlessly. Deleting the stable_sort makes this test FAIL.
  const std::string domain = "inv.example.com";
  const std::string preferred = "primary." + domain; // priority 10, healthy
  const std::string backup = "backup." + domain;      // priority 20, blackholed

  MockNode a(static_cast<std::uint16_t>(PORT_A + 240));
  // Insert the BACKUP (prio 20) FIRST, the PREFERRED (prio 10) SECOND (wire order = anti-priority).
  a->addRecord({"_sip._udp." + domain, "SRV", backup, 3600, /*prio*/ 20, /*weight*/ 0, 5060});
  a->addRecord({"_sip._udp." + domain, "SRV", preferred, 3600, /*prio*/ 10, /*weight*/ 0, 5060});
  a->configureQuery(backup, "A", timeoutCfg()); // backup blackholes (would consume D if resolved first)
  a->configureQuery(backup, "AAAA", timeoutCfg());
  a->addRecord({preferred, "A", "192.0.2.81", 3600}); // preferred resolves live

  auto r = makeResolver({static_cast<std::uint16_t>(PORT_A + 240)}, /*timeout*/ 5000ms, /*retry*/ 0,
                        /*maxResolutionTime*/ 500ms);

  ServiceResolutionResult res = r->resolveServiceDomain(domain, {ServiceType::SIP_UDP});
  REQUIRE(res.isSuccess());
  REQUIRE(res.outcome == ResolutionOutcome::Resolved);
  REQUIRE(res.getPreferredTarget().hostname == preferred); // the pre-sort resolved the preferred first
}

// =============================================================================
// H-B: deadline vs RFC 1035 §7.2 next-server failover (warn+doc; per-server sub-budget -> 2026-09-30-5)
// =============================================================================

TEST_CASE("SYNC deadline LARGE enough for two servers still fails over (primary dead, secondary OK)",
          "[dns][deadline][sync][failover]")
{
  // With a deadline comfortably above two servers' per-server budgets, next-server failover still
  // works: primary blackholed, secondary healthy -> Resolved via the secondary. (The DEFEAT case —
  // a deadline BELOW one server's budget — is a documented limitation warned about at config time;
  // the per-server sub-budget that would fix small-D failover is tracked on 2026-09-30-5.)
  MockNode a(static_cast<std::uint16_t>(PORT_A + 220)),
    b(static_cast<std::uint16_t>(PORT_A + 221));
  a->configureQuery("hb.example.com", timeoutCfg()); // primary blackholes (short per-server timeout)
  b->addRecord({"hb.example.com", "A", "192.0.2.90", 3600});
  // Short per-server timeout (300ms) so one blackholed server fits well inside a 3s deadline, then
  // failover to the healthy secondary happens WITHIN the deadline.
  auto r = makeResolver({static_cast<std::uint16_t>(PORT_A + 220),
                         static_cast<std::uint16_t>(PORT_A + 221)},
                        /*timeout*/ 300ms, /*retry*/ 0, /*maxResolutionTime*/ 3000ms);

  DnsResult res = r->query(aQ("hb.example.com"));
  REQUIRE(res.isSuccess());
  REQUIRE(res.a_records.size() == 1);
  REQUIRE(b.udpQueries() >= 1); // the secondary was reached within the deadline
}

TEST_CASE("SYNC multi-step RFC 3263 chain fails over across two servers within a large deadline",
          "[dns][deadline][sync][failover][chain]")
{
  // MEDIUM-1: failover must work across the multi-step NAPTR->SRV->A chain, not just a single
  // query(). The primary blackholes every name; the secondary answers the full direct-SRV chain.
  // D (4s) >> the per-step primary timeouts, so the resolution succeeds via the secondary.
  // NOTE (sip-voip LOW-3): the resolver's _serverRotation cursor advances per query, so which STEP
  // starts at the dead primary alternates. This run's NAPTR (rotation 0) and A (rotation 2) start at
  // the primary and fail over; SRV (rotation 1) starts at the healthy secondary. We assert the
  // primary WAS contacted on the NAPTR and A steps (so those steps genuinely failed over) rather
  // than claiming "every step" — the cross-step deadline bound holds regardless of which step rotates.
  const std::string domain = "chain.example.com";
  const std::string srvName = "_sip._udp." + domain;
  const std::string target = "sip1." + domain;
  MockNode a(static_cast<std::uint16_t>(PORT_A + 250), /*enableLogging*/ true),
    b(static_cast<std::uint16_t>(PORT_A + 251));
  a->configureQuery(domain, "NAPTR", timeoutCfg()); // primary blackholes each name
  a->configureQuery(srvName, "SRV", timeoutCfg());
  a->configureQuery(target, "A", timeoutCfg());
  a->configureQuery(target, "AAAA", timeoutCfg());
  // secondary: no NAPTR (NXDOMAIN -> direct SRV), a real SRV + A.
  b->addRecord({srvName, "SRV", target, 3600, 10, 0, 5060});
  b->addRecord({target, "A", "192.0.2.95", 3600});
  auto r = makeResolver({static_cast<std::uint16_t>(PORT_A + 250),
                         static_cast<std::uint16_t>(PORT_A + 251)},
                        /*timeout*/ 300ms, /*retry*/ 0, /*maxResolutionTime*/ 4000ms);

  ServiceResolutionResult res = r->resolveServiceDomain(domain, {ServiceType::SIP_UDP});
  REQUIRE(res.isSuccess());
  REQUIRE(res.outcome == ResolutionOutcome::Resolved);
  REQUIRE(res.getPreferredTarget().hostname == target); // resolved via the healthy secondary
  REQUIRE(a.countType(35) >= 1); // NAPTR (qtype 35) hit the dead primary -> failed over
  REQUIRE(a.countType(1) >= 1);  // A (qtype 1) hit the dead primary -> failed over
}

TEST_CASE("The sub-budget failover WARNING is emitted below the UDP-retransmit budget, not above it",
          "[dns][deadline][sync][warn]")
{
  // MEDIUM-1: the warning must fire against the per-server UDP-retransmit budget (a blackhole never
  // sends TC=1), NOT asyncAttemptBudget() which includes the TCP-fallback leg. Uses BOTH mode so the
  // two DIFFER: with timeout 5000/retry 0 the UDP budget is 5000ms, while asyncAttemptBudget(Both) is
  // 5000 + timeout + cleanupInterval (~20s). A deadline of 6000ms is ABOVE the UDP budget (failover
  // NOT defeated -> must NOT warn) but BELOW asyncAttemptBudget — so a reverted fix (comparing
  // asyncAttemptBudget) WOULD warn here, and this section catches it. Separate resolvers because the
  // warning is latched once per resolver.
  const std::string host = "warnok.example.com";

  SECTION("above the UDP budget (Both mode): NO failover warning")
  {
    LogCapture cap;
    MockNode a(static_cast<std::uint16_t>(PORT_A + 260));
    a->addRecord({host, "A", "192.0.2.96", 3600});
    auto r = makeResolver({static_cast<std::uint16_t>(PORT_A + 260)}, /*timeout*/ 5000ms,
                          /*retry*/ 0, /*maxResolutionTime*/ 6000ms, /*cache*/ nullptr,
                          DnsTransportMode::Both);
    (void)r->query(aQ(host));
    REQUIRE_FALSE(cap.contains("failover (RFC 1035"));
  }

  SECTION("below the UDP budget (Both mode): failover warning IS emitted")
  {
    LogCapture cap;
    MockNode a(static_cast<std::uint16_t>(PORT_A + 261));
    a->addRecord({host, "A", "192.0.2.96", 3600});
    auto r = makeResolver({static_cast<std::uint16_t>(PORT_A + 261)}, /*timeout*/ 5000ms,
                          /*retry*/ 0, /*maxResolutionTime*/ 500ms, /*cache*/ nullptr,
                          DnsTransportMode::Both);
    (void)r->query(aQ(host));
    REQUIRE(cap.contains("failover (RFC 1035"));
  }
}

// =============================================================================
// DnsClient forwarding smoke (M-C): the SIP-facing wrapper can size + pass a deadline
// =============================================================================

TEST_CASE("DnsClient forwards asyncAttemptBudget() and the per-call deadline override",
          "[dns][deadline][dnsclient]")
{
  DnsConfig cfg;
  cfg.setServers({"127.0.0.1:" + std::to_string(static_cast<int>(PORT_A + 230))});
  cfg.timeout = 5000ms;
  cfg.retryCount = 0;
  auto client = std::make_shared<iora::network::DnsClient>(cfg);

  // The consumer can read the sizing budget through the wrapper (M-C reachability).
  REQUIRE(client->asyncAttemptBudget() > 0ms);

  // Each forwarder that takes an override threads it through (a defaulted passthrough that was
  // dropped would compile clean but NOT bound the blackholed query — the fail-open the required-param
  // design guards against, cpp17 L-7). Assert a small override bounds each against a blackholed server.
  MockNode a(static_cast<std::uint16_t>(PORT_A + 230));
  a->configureQuery("dc.example.com", timeoutCfg());          // query()
  a->configureQuery("dc.example.com", "NAPTR", timeoutCfg()); // resolveServiceDomain / resolveNAPTR
  a->configureQuery("_sip._udp.dc.example.com", "SRV", timeoutCfg()); // resolveSRV
  const auto bound = 1500ms;

  auto t0 = std::chrono::steady_clock::now();
  REQUIRE_THROWS_AS(client->query(aQ("dc.example.com"), /*override*/ 350ms),
                    DnsTransientResolutionException);
  REQUIRE(elapsedMs(t0) < bound);

  // resolveServiceDomain: the whole chain bounded near the override (never the ~7s per-server budget).
  t0 = std::chrono::steady_clock::now();
  auto res = client->resolveServiceDomain("dc.example.com", {ServiceType::SIP_UDP}, /*secure*/ false,
                                          /*override*/ 350ms);
  REQUIRE(res.outcome == ResolutionOutcome::TransientFailure);
  REQUIRE(elapsedMs(t0) < 2500ms);

  // resolveHostname / resolveSRV / resolveNAPTR: each blackholed call bounded by its override.
  t0 = std::chrono::steady_clock::now();
  REQUIRE_THROWS(client->resolveHostname("dc.example.com", false, /*override*/ 350ms));
  REQUIRE(elapsedMs(t0) < bound);

  t0 = std::chrono::steady_clock::now();
  REQUIRE_THROWS(client->resolveSRV("_sip._udp.dc.example.com", /*override*/ 350ms));
  REQUIRE(elapsedMs(t0) < bound);

  t0 = std::chrono::steady_clock::now();
  REQUIRE_THROWS(client->resolveNAPTR("dc.example.com", /*override*/ 350ms));
  REQUIRE(elapsedMs(t0) < bound);

  // ASYNC forwarder (the SIP adapter's actual entry point is resolveServiceDomainAsync): a dropped
  // override passthrough would compile clean and fail OPEN (cpp17 M-5 / sip-voip LOW-6). A fresh
  // SHORT-timeout client makes the difference observable: with the override threaded, the multi-step
  // NAPTR->SRV->A/AAAA chain is deadline-gated after the first in-flight attempt (~one timeout);
  // dropped, the config deadline (0=off) lets every step run a full timeout (~4x), blowing the bound.
  {
    DnsConfig acfg;
    acfg.setServers({"127.0.0.1:" + std::to_string(static_cast<int>(PORT_A + 231))});
    acfg.timeout = 300ms;
    acfg.retryCount = 0;
    auto aclient = std::make_shared<iora::network::DnsClient>(acfg);
    MockNode an(static_cast<std::uint16_t>(PORT_A + 231));
    an->configureQuery("dcasync.example.com", "NAPTR", timeoutCfg());
    an->configureQuery("_sip._udp.dcasync.example.com", "SRV", timeoutCfg());

    auto prom = std::make_shared<std::promise<ServiceResolutionResult>>();
    auto fut = prom->get_future();
    auto once = std::make_shared<std::atomic<bool>>(false);
    t0 = std::chrono::steady_clock::now();
    aclient->resolveServiceDomainAsync(
      "dcasync.example.com",
      [prom, once](const ServiceResolutionResult &res, const std::exception_ptr &)
      {
        if (!once->exchange(true))
        {
          prom->set_value(res);
        }
      },
      {ServiceType::SIP_UDP}, /*secure*/ false, /*override*/ 100ms);
    REQUIRE(fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    REQUIRE(fut.get().outcome == ResolutionOutcome::TransientFailure);
    // Threaded: ~one in-flight (300ms) + gated rest. Dropped (no deadline): ~4x300ms. < 800ms
    // distinguishes them.
    REQUIRE(elapsedMs(t0) < 800ms);
  }
}

// =============================================================================
// ASYNC — soft choke-point gate (multi-server), family-cut, priority-cut, overhang, no-latch
// (drivers that count deliveries are defined in the top namespace)
// =============================================================================

TEST_CASE("ASYNC deadline choke-point gate stops rotating past D on a MULTI-server set",
          "[dns][deadline][async][gate]")
{
  // 3 blackholed servers, in-flight cfg.timeout 150ms, deadline 50ms. The first server's one
  // in-flight query runs to its natural (soft) timeout ~150ms; by the loop-top re-entry the deadline
  // has passed, so the gate delivers a terminal DnsDeadlineException and servers 2 & 3 are NEVER
  // issued (the gate stops rotating). Exactly one delivery.
  MockNode a(static_cast<std::uint16_t>(PORT_A + 300)),
    b(static_cast<std::uint16_t>(PORT_A + 301)), c(static_cast<std::uint16_t>(PORT_A + 302));
  for (auto *n : {&a, &b, &c})
  {
    (*n)->configureQuery("g.example.com", timeoutCfg());
  }
  auto r = makeResolver({static_cast<std::uint16_t>(PORT_A + 300),
                         static_cast<std::uint16_t>(PORT_A + 301),
                         static_cast<std::uint16_t>(PORT_A + 302)},
                        /*timeout*/ 150ms, /*retry*/ 0, /*maxResolutionTime*/ 50ms);

  auto out = driveQueryAsync(r, aQ("g.example.com"));
  REQUIRE(out.completed);
  REQUIRE(out.deliveries == 1);            // exactly once (not masked by a once-guard)
  REQUIRE(isDeadlineErr(out.error));       // terminal DnsDeadlineException
  REQUIRE(a.udpQueries() >= 1);            // only the first server was contacted
  REQUIRE(b.udpQueries() == 0);            // rotation stopped at the deadline
  REQUIRE(c.udpQueries() == 0);
}

TEST_CASE("ASYNC deadline OFF (0): exhaustion terminal is transient with the last server's rcode, "
          "delivered exactly once",
          "[dns][deadline][async][off]")
{
  MockNode a(PORT_A), b(PORT_B);
  a->configureQuery("host.example.com", servfail());
  b->configureQuery("host.example.com", refused());
  auto r = makeResolver({PORT_A, PORT_B}, 400ms, 0, /*maxResolutionTime*/ 0ms);

  auto out = driveQueryAsync(r, aQ("host.example.com"));
  REQUIRE(out.completed);
  REQUIRE(out.deliveries == 1);
  REQUIRE(out.error != nullptr);
  REQUIRE_FALSE(isDeadlineErr(out.error)); // NOT a deadline; a plain exhaustion transient
  bool isTransient = false;
  DnsResponseCode rcode = DnsResponseCode::NOERROR;
  try
  {
    std::rethrow_exception(out.error);
  }
  catch (const DnsTransientResolutionException &e)
  {
    isTransient = true;
    rcode = e.getResponseCode();
  }
  catch (...)
  {
  }
  REQUIRE(isTransient);
  REQUIRE(rcode == DnsResponseCode::REFUSED); // last server's rcode, faithfully
  REQUIRE(a.udpQueries() == 1);
  REQUIRE(b.udpQueries() == 1);
}

TEST_CASE("ASYNC 'cut A and AAAA': after the deadline, the AAAA family issues ZERO wire queries",
          "[dns][deadline][async][family]")
{
  // SRV yields one target whose A blackholes (in-flight ~1000ms). The deadline (400ms) expires
  // during A's in-flight; when A's family exhausts and chains AAAA, the AAAA family hits the deadline
  // gate and issues NO wire query. Outcome TransientFailure (the cut family marks the target
  // transient). Wide margin (timeout 1000ms, D 400ms, pre-cut NAPTR/SRV hops « D) so the test is
  // robust under TSan's slowdown (cpp17 M-4).
  MockNode a(static_cast<std::uint16_t>(PORT_A + 310), /*enableLogging*/ true);
  const std::string domain = "fam.example.com";
  a->addRecord({"_sip._udp." + domain, "SRV", "t." + domain, 3600, 10, 0, 5060});
  a->configureQuery("t." + domain, "A", timeoutCfg()); // A blackholes
  // AAAA intentionally left unconfigured; if it were ever issued it would be a fast NXDOMAIN — the
  // assertion is that it is NEVER issued at all (cut by the deadline).
  auto r = makeResolver({static_cast<std::uint16_t>(PORT_A + 310)}, /*timeout*/ 1000ms, /*retry*/ 0,
                        /*maxResolutionTime*/ 400ms);

  auto out = driveSvcAsyncCounted(r, domain, {ServiceType::SIP_UDP});
  REQUIRE(out.completed);
  REQUIRE(out.deliveries == 1);
  REQUIRE(out.result.outcome == ResolutionOutcome::TransientFailure);
  REQUIRE(a.countType(1) >= 1);   // at least one A query (the blackholed one)
  REQUIRE(a.countType(28) == 0);  // AAAA (qtype 28) NEVER sent — cut by the deadline
}

TEST_CASE("ASYNC A-AUTHORITATIVE-NEGATIVE then DEADLINE cuts AAAA -> TransientFailure NOT Permanent",
          "[dns][deadline][async][permanentguard]")
{
  // Round-1 HIGH-1 mutation guard (cpp17 M-2 / sip-voip): the A family returns an AUTHORITATIVE
  // negative (NXDOMAIN) AFTER the deadline (so A is NOT transient), then the deadline GATE cuts the
  // AAAA family (zero wire). The target must be marked transient BY THE CUT -> TransientFailure. If
  // the gate-cut failed to mark the target transient, the target would be A-NXDOMAIN (not transient)
  // + AAAA-cut (not marked) = PermanentNoService, and this test would FAIL. The delayed A (delay >
  // D) keeps it in flight past the deadline yet still authoritative-negative (not a timeout).
  MockNode a(static_cast<std::uint16_t>(PORT_A + 320), /*enableLogging*/ true);
  const std::string domain = "pg.example.com";
  a->addRecord({"_sip._udp." + domain, "SRV", "t." + domain, 3600, 10, 0, 5060});
  // t.<domain> A: NXDOMAIN after 600ms (no record + delay); AAAA unconfigured (will be gate-cut).
  a->configureQuery("t." + domain, "A", delayCfg(600ms));
  auto r = makeResolver({static_cast<std::uint16_t>(PORT_A + 320)}, /*timeout*/ 2000ms, /*retry*/ 0,
                        /*maxResolutionTime*/ 250ms); // D < the 600ms A delay -> AAAA is gate-cut

  auto out = driveSvcAsyncCounted(r, domain, {ServiceType::SIP_UDP});
  REQUIRE(out.completed);
  REQUIRE(out.deliveries == 1);
  REQUIRE_FALSE(out.result.isSuccess());
  REQUIRE(out.result.outcome == ResolutionOutcome::TransientFailure); // NOT PermanentNoService
  REQUIRE(a.countType(28) == 0); // AAAA gate-cut: zero wire queries
}

TEST_CASE("ASYNC ADVERSARIAL priority-cut: preferred blackholed, live backup returned (concurrent)",
          "[dns][deadline][async][partial][adversarial]")
{
  // Async issues targets CONCURRENTLY, so a live lower-priority backup resolves while the preferred
  // blackholes — partial-Resolved needs NO cache here. Preferred (priority 10) A blackholes; backup
  // (priority 20) A resolves live. Result: Resolved with ONLY the backup; getPreferredTarget()==backup.
  MockNode a(static_cast<std::uint16_t>(PORT_A + 330));
  const std::string domain = "aprio.example.com";
  const std::string preferred = "primary." + domain;
  const std::string backup = "backup." + domain;
  a->addRecord({"_sip._udp." + domain, "SRV", preferred, 3600, /*prio*/ 10, 0, 5060});
  a->addRecord({"_sip._udp." + domain, "SRV", backup, 3600, /*prio*/ 20, 0, 5060});
  a->configureQuery(preferred, "A", timeoutCfg());   // preferred blackholes
  a->configureQuery(preferred, "AAAA", timeoutCfg());
  a->addRecord({backup, "A", "192.0.2.85", 3600});   // backup resolves live
  // Wide margin (timeout 1000ms, D 400ms) so the pre-cut NAPTR/SRV + the live backup resolve well
  // inside D even under TSan (cpp17 M-4).
  auto r = makeResolver({static_cast<std::uint16_t>(PORT_A + 330)}, /*timeout*/ 1000ms, /*retry*/ 0,
                        /*maxResolutionTime*/ 400ms);

  auto out = driveSvcAsyncCounted(r, domain, {ServiceType::SIP_UDP});
  REQUIRE(out.completed);
  REQUIRE(out.deliveries == 1);
  REQUIRE(out.result.isSuccess());
  REQUIRE(out.result.outcome == ResolutionOutcome::Resolved);
  REQUIRE(out.result.getPreferredTarget().hostname == backup); // reachable backup wins
}

TEST_CASE("ASYNC overhang bound: worst case ~ deadline + ONE in-flight attempt (no extra rotation)",
          "[dns][deadline][async][overhang]")
{
  // TWO blackholed servers (so servers REMAIN when the deadline trips — with a single server the
  // exhaustion branch, checked first, fires before the deadline branch). In-flight cfg.timeout
  // 150ms, deadline 50ms. The soft bound = deadline + <= ONE in-flight attempt: the first server's
  // query runs to ~150ms, then the gate cuts the SECOND server (never issued). The resolution must
  // NOT run two full attempts.
  MockNode a(static_cast<std::uint16_t>(PORT_A + 340)),
    b(static_cast<std::uint16_t>(PORT_A + 341));
  a->configureQuery("oh.example.com", timeoutCfg());
  b->configureQuery("oh.example.com", timeoutCfg());
  auto r = makeResolver({static_cast<std::uint16_t>(PORT_A + 340),
                         static_cast<std::uint16_t>(PORT_A + 341)},
                        /*timeout*/ 150ms, /*retry*/ 0, /*maxResolutionTime*/ 50ms);

  auto t0 = std::chrono::steady_clock::now();
  auto out = driveQueryAsync(r, aQ("oh.example.com"));
  auto took = elapsedMs(t0);
  REQUIRE(out.completed);
  REQUIRE(out.deliveries == 1);
  REQUIRE(isDeadlineErr(out.error)); // deadline cut the 2nd server (servers remained)
  REQUIRE(b.udpQueries() == 0);      // the second server was NOT issued (overhang = one attempt)
  // deadline(50) + one attempt(~150) + settle(100) « two full attempts (~300+).
  REQUIRE(took < 1200ms);
}

TEST_CASE("ASYNC no-latch-corruption: concurrent multi-target with a deadline-cut family "
          "(TSan-primary; exactly-once + surviving target under a normal build)",
          "[dns][deadline][async][tsan][nolatch]")
{
  // PRIMARY discriminator is ThreadSanitizer: the live target's addresses are appended on the UDP
  // I/O thread while the blackholed target's terminal (timer thread) runs the LAST finishTarget
  // decrement -> erase+sort, reading the I/O thread's writes across the remainingTargets acq_rel
  // handoff. This target is registered in IORA_SANITIZED_TEST_TARGETS; downgrade that handoff to
  // relaxed and TSan reports here. Under a NON-TSan build we still assert the observable invariants:
  // exactly-one USER delivery, and the live target survives while the blackholed one is dropped.
  // (The RAW internal exactly-once is guarded by the queryAsync [gate]/[overhang] tests; here
  // deliveries is behind makeSingleFire — thread-safety M-1.) The MockNode is hoisted (its records
  // don't mutate per query, L-7); only the resolver is fresh per iteration (fresh rotation). Wide
  // margin (timeout 600ms, D 300ms) keeps the pre-cut NAPTR/SRV + live-A inside D under TSan (M-4).
  MockNode a(static_cast<std::uint16_t>(PORT_A + 350));
  const std::string domain = "nl.example.com";
  const std::string dead = "dead." + domain;
  const std::string live = "live." + domain;
  a->addRecord({"_sip._udp." + domain, "SRV", dead, 3600, 10, 0, 5060});
  a->addRecord({"_sip._udp." + domain, "SRV", live, 3600, 10, 0, 5060});
  a->configureQuery(dead, "A", timeoutCfg());
  a->configureQuery(dead, "AAAA", timeoutCfg());
  a->addRecord({live, "A", "192.0.2.86", 3600});

  for (int iter = 0; iter < 10; ++iter)
  {
    auto r = makeResolver({static_cast<std::uint16_t>(PORT_A + 350)}, /*timeout*/ 600ms, /*retry*/ 0,
                          /*maxResolutionTime*/ 300ms);

    auto out = driveSvcAsyncCounted(r, domain, {ServiceType::SIP_UDP});
    REQUIRE(out.completed);
    REQUIRE(out.deliveries == 1); // exactly-once user delivery despite the concurrent cut vs append
    REQUIRE(out.result.isSuccess());
    REQUIRE(out.result.getPreferredTarget().hostname == live); // the live target survived the erase
  }
}
