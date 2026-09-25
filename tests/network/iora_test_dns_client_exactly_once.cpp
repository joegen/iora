// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_dns_client_exactly_once.cpp
/// \brief Exactly-once delivery regression tests for DnsClient::resolveA(hostname, callback).
///
/// Tracker: tasks/iora/ongoing/2026-09-25-6 (Part B, double-invoke funnel).
/// Validates that the raw-callback async resolveA delivers the user callback
/// EXACTLY ONCE on every funnel branch (success / empty-result / transport-error
/// / cancelled), even when the user callback THROWS, and that isCompleted() is
/// published after delivery on both normal and exceptional paths.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "MockDnsServer.hpp"
#include "iora/network/dns/dns_resolver.hpp"
#include "iora/network/dns/dns_types.hpp"
#include "iora/network/dns_client.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using iora::network::AsyncDnsRequest;
using iora::network::DnsClient;
using namespace iora::network::dns;

namespace
{
// Distinct fixed ports from iora_test_dns_comprehensive (15353/15354): same-repo
// ctest runs -j1 so serial reuse would be safe, but distinct ports avoid any
// accidental overlap. Do NOT convert to a dynamic probe (fixed is the DNS-suite
// convention here).
constexpr std::uint16_t EO_UDP_PORT = 15373;
constexpr std::uint16_t EO_TCP_PORT = 15374;
constexpr std::chrono::milliseconds EO_STARTUP_DELAY{200};
constexpr std::chrono::milliseconds EO_WAIT_BUDGET{3000};

/// \brief Latch signalled by a callback so the test never sleeps to synchronise.
class Latch
{
public:
  void signal()
  {
    {
      std::lock_guard<std::mutex> lk(_m);
      _fired = true;
    }
    _cv.notify_all();
  }

  bool waitFor(std::chrono::milliseconds budget)
  {
    std::unique_lock<std::mutex> lk(_m);
    return _cv.wait_for(lk, budget, [this] { return _fired; });
  }

private:
  std::mutex _m;
  std::condition_variable _cv;
  bool _fired{false};
};

/// \brief Fixture: a DnsClient pointed at a local MockDnsServer.
class ExactlyOnceFixture
{
public:
  ExactlyOnceFixture()
  {
    MockDnsServer::Config serverConfig;
    serverConfig.udpPort = EO_UDP_PORT;
    serverConfig.tcpPort = EO_TCP_PORT;
    serverConfig.enableLogging = false;
    mockServer_ = std::make_unique<MockDnsServer>(serverConfig);

    DnsConfig clientConfig;
    clientConfig.setServers({"127.0.0.1:" + std::to_string(EO_UDP_PORT)});
    clientConfig.timeout = std::chrono::milliseconds(800);
    clientConfig.retryCount = 0; // bound timeout-branch tests to ~one timeout interval
    clientConfig.transportMode = DnsTransportMode::UDP;
    clientConfig.enableCache = false;
    dnsClient_ = std::make_unique<DnsClient>(clientConfig);
  }

  ~ExactlyOnceFixture()
  {
    dnsClient_.reset();
    if (mockServer_)
    {
      mockServer_->stop();
    }
  }

  void startServer()
  {
    REQUIRE(mockServer_->start());
    std::this_thread::sleep_for(EO_STARTUP_DELAY);
  }

  MockDnsServer &server() { return *mockServer_; }
  DnsClient &client() { return *dnsClient_; }

private:
  std::unique_ptr<MockDnsServer> mockServer_;
  std::unique_ptr<DnsClient> dnsClient_;
};

/// \brief Captures what the user callback saw, so the test can assert on it
/// AFTER the callback ran on the transport I/O thread (no test-side sleeps).
struct Capture
{
  std::atomic<int> invocations{0};
  std::atomic<bool> hadError{false};
  std::atomic<std::size_t> addrCount{0};
  std::mutex m;
  std::string errMsg;

  void record(const std::vector<std::string> &addrs, std::exception_ptr err)
  {
    invocations.fetch_add(1, std::memory_order_acq_rel);
    addrCount.store(addrs.size(), std::memory_order_release);
    if (err)
    {
      hadError.store(true, std::memory_order_release);
      try
      {
        std::rethrow_exception(err);
      }
      catch (const std::exception &e)
      {
        std::lock_guard<std::mutex> lk(m);
        errMsg = e.what();
      }
    }
  }
};

/// \brief Bounded wait for delivery to be published (guard fired). Waits for a
/// real completion signal; it does NOT loosen any timeout to hide a race. A poll
/// (not a latch) is used deliberately: completion is published in the guard
/// destructor AFTER the callback returns/throws, so there is no in-callback point
/// at which a latch could be signalled to mark completion; the bounded poll
/// returns immediately once true and only exhausts its budget on a genuine failure.
bool waitCompleted(const AsyncDnsRequest &req, std::chrono::milliseconds budget)
{
  const auto deadline = std::chrono::steady_clock::now() + budget;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (req.isCompleted())
    {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  return req.isCompleted();
}

} // namespace

// A throwing user callback must be invoked EXACTLY ONCE on every funnel branch,
// and completion must be published on the exceptional unwind (guard). Pre-fix,
// the re-invoking catch(...) fired the callback twice AND skipped the completed
// store on the throwing path.
TEST_CASE_METHOD(ExactlyOnceFixture, "throwing user callback invoked exactly once per branch",
                 "[dns][async][exactly-once]")
{
  startServer();

  SECTION("success branch")
  {
    server().addRecord({"eo-success.example.com", "A", "192.0.2.10", 3600});
    Capture cap;
    Latch delivered;
    auto req = client().resolveA("eo-success.example.com",
                                 [&](std::vector<std::string> a, std::exception_ptr e)
                                 {
                                   cap.record(a, e);
                                   delivered.signal();
                                   throw std::runtime_error("user callback throws");
                                 });
    REQUIRE(delivered.waitFor(EO_WAIT_BUDGET));
    REQUIRE(waitCompleted(req, EO_WAIT_BUDGET));
    CHECK(cap.invocations.load() == 1);
    CHECK_FALSE(cap.hadError.load());
  }

  SECTION("empty-result branch (NODATA -> DnsNoRecordsException)")
  {
    MockDnsServer::QueryConfig nodata;
    nodata.shouldReturnNodata = true;
    server().configureQuery("eo-empty.example.com", "A", nodata);
    Capture cap;
    Latch delivered;
    auto req = client().resolveA("eo-empty.example.com",
                                 [&](std::vector<std::string> a, std::exception_ptr e)
                                 {
                                   cap.record(a, e);
                                   delivered.signal();
                                   throw std::runtime_error("user callback throws");
                                 });
    REQUIRE(delivered.waitFor(EO_WAIT_BUDGET));
    REQUIRE(waitCompleted(req, EO_WAIT_BUDGET));
    CHECK(cap.invocations.load() == 1);
    CHECK(cap.hadError.load());
    CHECK(cap.addrCount.load() == 0); // M2 contract: empty vector alongside error
    {
      // Branch attribution: this MUST be the empty/no-records branch.
      std::lock_guard<std::mutex> lk(cap.m);
      CHECK(cap.errMsg.find("No A records found") != std::string::npos);
    }
  }

  SECTION("transport-error branch (timeout -> non-null error)")
  {
    // A genuine transport error exercises the funnel's `else if (error)` branch.
    // NOTE: a SERVFAIL rcode is delivered by this raw async path as an EMPTY result
    // -> DnsNoRecordsException (rcode loss, separately tracked in 2026-09-24-32), so
    // a timeout (not SERVFAIL) is used here to get a non-null error parameter.
    MockDnsServer::QueryConfig timeout;
    timeout.shouldTimeout = true;
    server().configureQuery("eo-timeout.example.com", "A", timeout);
    Capture cap;
    Latch delivered;
    auto req = client().resolveA("eo-timeout.example.com",
                                 [&](std::vector<std::string> a, std::exception_ptr e)
                                 {
                                   cap.record(a, e);
                                   delivered.signal();
                                   throw std::runtime_error("user callback throws");
                                 });
    REQUIRE(delivered.waitFor(EO_WAIT_BUDGET));
    REQUIRE(waitCompleted(req, EO_WAIT_BUDGET));
    CHECK(cap.invocations.load() == 1);
    CHECK(cap.hadError.load());
    CHECK(cap.addrCount.load() == 0); // M2 contract
    {
      // Branch attribution (L1): the transport-error branch, NOT the no-records one.
      std::lock_guard<std::mutex> lk(cap.m);
      CHECK(cap.errMsg.find("No A records found") == std::string::npos);
    }
  }

  SECTION("cancelled branch (cancel observed before delivery, callback throws)")
  {
    // Delay the response so cancel() is observed at the in-lambda cancelled-check.
    // The 300ms server delay vs a synchronous cancel() gives a wide (margin-based,
    // not hook-forced) ordering guarantee that the cancelled branch is taken; a
    // deterministic hook would require Part A (2026-09-25-9) test support.
    server().addRecord({"eo-cancel.example.com", "A", "192.0.2.20", 3600});
    MockDnsServer::QueryConfig slow;
    slow.delay = std::chrono::milliseconds(300);
    server().configureQuery("eo-cancel.example.com", "A", slow);
    Capture cap;
    Latch delivered;
    auto req = client().resolveA("eo-cancel.example.com",
                                 [&](std::vector<std::string> a, std::exception_ptr e)
                                 {
                                   cap.record(a, e);
                                   delivered.signal();
                                   throw std::runtime_error("user callback throws");
                                 });
    CHECK(req.cancel()); // best-effort deliver; teardown is Part A (2026-09-25-9)
    REQUIRE(delivered.waitFor(EO_WAIT_BUDGET));
    REQUIRE(waitCompleted(req, EO_WAIT_BUDGET));
    CHECK(cap.invocations.load() == 1);
    CHECK(cap.hadError.load());
    CHECK(cap.addrCount.load() == 0);
    {
      std::lock_guard<std::mutex> lk(cap.m);
      CHECK(cap.errMsg.find("cancelled") != std::string::npos);
    }
  }
}

// Non-throwing baseline: each branch delivers exactly once, and every non-success
// branch delivers an EMPTY address vector alongside a non-null error (M2 contract).
TEST_CASE_METHOD(ExactlyOnceFixture, "non-throwing single delivery and empty-on-error contract",
                 "[dns][async][exactly-once]")
{
  startServer();

  SECTION("success delivers addresses with no error")
  {
    server().addRecord({"eo-ok.example.com", "A", "192.0.2.30", 3600});
    Capture cap;
    Latch delivered;
    auto req = client().resolveA("eo-ok.example.com",
                                 [&](std::vector<std::string> a, std::exception_ptr e)
                                 {
                                   cap.record(a, e);
                                   delivered.signal();
                                 });
    REQUIRE(delivered.waitFor(EO_WAIT_BUDGET));
    REQUIRE(waitCompleted(req, EO_WAIT_BUDGET));
    CHECK(cap.invocations.load() == 1);
    CHECK_FALSE(cap.hadError.load());
    CHECK(cap.addrCount.load() >= 1);
  }

  SECTION("transport-error (timeout) delivers empty vector with non-null error")
  {
    // Genuine transport error -> funnel `else if (error)` branch (see the throwing
    // case for why timeout, not SERVFAIL, is used to get a non-null error param).
    MockDnsServer::QueryConfig timeout;
    timeout.shouldTimeout = true;
    server().configureQuery("eo-timeout2.example.com", "A", timeout);
    Capture cap;
    Latch delivered;
    auto req = client().resolveA("eo-timeout2.example.com",
                                 [&](std::vector<std::string> a, std::exception_ptr e)
                                 {
                                   cap.record(a, e);
                                   delivered.signal();
                                 });
    REQUIRE(delivered.waitFor(EO_WAIT_BUDGET));
    REQUIRE(waitCompleted(req, EO_WAIT_BUDGET));
    CHECK(cap.invocations.load() == 1);
    CHECK(cap.hadError.load());
    CHECK(cap.addrCount.load() == 0);
    {
      // Branch attribution (L1): transport-error branch, NOT the no-records branch.
      std::lock_guard<std::mutex> lk(cap.m);
      CHECK(cap.errMsg.find("No A records found") == std::string::npos);
    }
  }

  SECTION("empty-result (NODATA) delivers empty vector with DnsNoRecordsException")
  {
    MockDnsServer::QueryConfig nodata;
    nodata.shouldReturnNodata = true;
    server().configureQuery("eo-empty2.example.com", "A", nodata);
    Capture cap;
    Latch delivered;
    auto req = client().resolveA("eo-empty2.example.com",
                                 [&](std::vector<std::string> a, std::exception_ptr e)
                                 {
                                   cap.record(a, e);
                                   delivered.signal();
                                 });
    REQUIRE(delivered.waitFor(EO_WAIT_BUDGET));
    REQUIRE(waitCompleted(req, EO_WAIT_BUDGET));
    CHECK(cap.invocations.load() == 1);
    CHECK(cap.hadError.load());
    CHECK(cap.addrCount.load() == 0);
    {
      std::lock_guard<std::mutex> lk(cap.m);
      CHECK(cap.errMsg.find("No A records found") != std::string::npos);
    }
  }

  SECTION("cancelled delivers empty vector with cancellation error")
  {
    server().addRecord({"eo-cancel2.example.com", "A", "192.0.2.60", 3600});
    MockDnsServer::QueryConfig slow;
    slow.delay = std::chrono::milliseconds(300);
    server().configureQuery("eo-cancel2.example.com", "A", slow);
    Capture cap;
    Latch delivered;
    auto req = client().resolveA("eo-cancel2.example.com",
                                 [&](std::vector<std::string> a, std::exception_ptr e)
                                 {
                                   cap.record(a, e);
                                   delivered.signal();
                                 });
    CHECK(req.cancel());
    REQUIRE(delivered.waitFor(EO_WAIT_BUDGET));
    REQUIRE(waitCompleted(req, EO_WAIT_BUDGET));
    CHECK(cap.invocations.load() == 1);
    CHECK(cap.hadError.load());
    CHECK(cap.addrCount.load() == 0);
    {
      std::lock_guard<std::mutex> lk(cap.m);
      CHECK(cap.errMsg.find("cancelled") != std::string::npos);
    }
  }
}

// cancel() racing the in-lambda cancelled-check: exactly one invocation on EITHER
// outcome. This exercises the 'cancelled' acquire-load, NOT the deliveryAttempted
// CAS (genuine CAS contention needs Part A's teardown second-delivery path).
TEST_CASE_METHOD(ExactlyOnceFixture, "cancel-vs-cancelled-check interleaving is exactly-once",
                 "[dns][async][exactly-once]")
{
  startServer();
  server().addRecord({"eo-race.example.com", "A", "192.0.2.40", 3600});
  MockDnsServer::QueryConfig slow;
  slow.delay = std::chrono::milliseconds(50);
  server().configureQuery("eo-race.example.com", "A", slow);

  for (int i = 0; i < 25; ++i)
  {
    Capture cap;
    Latch delivered;
    auto req = client().resolveA("eo-race.example.com",
                                 [&](std::vector<std::string> a, std::exception_ptr e)
                                 {
                                   cap.record(a, e);
                                   delivered.signal();
                                 });
    // Deterministic jitter across [0,63]ms straddles the ~50ms delivery, so some
    // iterations cancel BEFORE delivery (cancelled branch) and some AFTER (no-op
    // cancel, real result). Exactly-once must hold on either outcome (L2). This
    // widens the interleaving; it does NOT inflate any timeout to hide a race.
    const auto jitter = std::chrono::milliseconds((i * 7) % 70);
    if (jitter.count() > 0)
    {
      std::this_thread::sleep_for(jitter);
    }
    req.cancel();
    REQUIRE(delivered.waitFor(EO_WAIT_BUDGET));
    REQUIRE(waitCompleted(req, EO_WAIT_BUDGET));
    CHECK(cap.invocations.load() == 1); // exactly-once on both outcomes
  }
}

// The future wrapper routes through resolveAInternal but is promiseSet-CAS
// guarded; verify the funnel change did not perturb its single-delivery contract.
TEST_CASE_METHOD(ExactlyOnceFixture, "resolveAAsync future delivers exactly one result",
                 "[dns][async][exactly-once]")
{
  startServer();

  SECTION("success future yields addresses once")
  {
    server().addRecord({"eo-fut.example.com", "A", "192.0.2.50", 3600});
    auto cf = client().resolveAAsync("eo-fut.example.com");
    REQUIRE(cf.future.wait_for(EO_WAIT_BUDGET) == std::future_status::ready);
    auto addrs = cf.future.get();
    CHECK(addrs.size() >= 1);
  }

  SECTION("SERVFAIL future yields exception once")
  {
    MockDnsServer::QueryConfig fail;
    fail.shouldFail = true;
    server().configureQuery("eo-fut-fail.example.com", "A", fail);
    auto cf = client().resolveAAsync("eo-fut-fail.example.com");
    REQUIRE(cf.future.wait_for(EO_WAIT_BUDGET) == std::future_status::ready);
    CHECK_THROWS(cf.future.get());
  }

  // Tracker test #5 names BOTH future wrappers. resolveServiceDomainFuture routes
  // through resolveServiceDomainAsync (a separate promiseSet-guarded lambda, NOT
  // the changed resolveAInternal), so this is a regression guard that the funnel
  // change did not perturb the service-domain future's single-delivery contract.
  SECTION("resolveServiceDomainFuture yields a result once")
  {
    server().addRecord({"_sip._udp.eo-svc.example.com", "SRV", "sip1.eo-svc.example.com", 3600, 10, 5,
                        5060});
    server().addRecord({"sip1.eo-svc.example.com", "A", "192.0.2.70", 3600});
    auto cf = client().resolveServiceDomainFuture("eo-svc.example.com");
    REQUIRE(cf.future.wait_for(EO_WAIT_BUDGET) == std::future_status::ready);
    auto result = cf.future.get(); // single delivery; a double-set would have thrown
    CHECK_FALSE(result.targets.empty());
  }
}
