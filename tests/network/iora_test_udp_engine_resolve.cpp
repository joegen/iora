// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_udp_engine_resolve.cpp
/// \brief ISOLATED, LAST-ORDERED event-driven resolve integration tests for the
///        UDP engine — connect-site, via-listener terminal matrix, and lifecycle
///        parity (architecture/iora/transport_dns_resolve.json
///        testStrategy.udp_c5; tracker 2026-09-06-4 task-6.3).
///
/// Like the TCP resolve tests, the timeout/teardown/close/reject-fast cases stall
/// the process-wide blockingIoPool() (via PoolStall) so a named-host getaddrinfo
/// can be held deterministically. The via-listener terminal matrix is forced with
/// production affordances: a bogus listener id (listener-gone), an IPv6-only name
/// against an IPv4 listener (AF-mismatch), and maxSessions=1 (session-cap). These
/// seize the global pool / exercise last-ordered paths, so they live in their own
/// binary ordered LAST in NETWORK_TESTS.
///
/// The happy-path event-driven connect / via / restart cases live in
/// iora_test_udp_engine.cpp (no stall needed) and are not duplicated here.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/network/detail/udp_engine.hpp"
#include "iora_test_net_utils.hpp"
#include "resolve_stall_harness.hpp"

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

using namespace std::chrono_literals;
using UdpEngine = iora::network::UdpEngine;
using TransportConfig = iora::network::TransportConfig;
using TransportAddress = iora::network::TransportAddress;
using TransportErrorInfo = iora::network::TransportErrorInfo;
using TransportError = iora::network::TransportError;
using TlsMode = iora::network::TlsMode;
using SessionId = iora::network::SessionId;
using ListenerId = iora::network::ListenerId;

namespace
{
/// \brief UDP engine + callback capture with a configurable resolveTimeout /
///        gcInterval / maxSessions.
struct ResolveFixture
{
  TransportConfig cfg{};
  std::unique_ptr<UdpEngine> tx;

  std::mutex m;
  std::atomic<int> connectCount{0};
  std::atomic<int> closeCount{0};
  std::vector<SessionId> closedSids;
  TransportError lastCloseCode{TransportError::Unknown};
  std::string lastCloseMsg;

  explicit ResolveFixture(std::chrono::milliseconds resolveTimeout,
                          std::chrono::seconds gcInterval = std::chrono::seconds(5),
                          std::size_t maxSessions = 0)
  {
    cfg.resolveTimeout = resolveTimeout;
    cfg.gcInterval = gcInterval;
    cfg.maxSessions = maxSessions;
    tx = std::make_unique<UdpEngine>(cfg);

    iora::network::detail::EngineBase::Callbacks cbs{};
    cbs.onConnect = [&](SessionId, const TransportAddress &) { connectCount++; };
    cbs.onClose = [&](SessionId sid, const TransportErrorInfo &err)
    {
      std::lock_guard<std::mutex> lock(m);
      closedSids.push_back(sid);
      lastCloseCode = err.code;
      lastCloseMsg = err.message;
      closeCount++;
    };
    tx->setCallbacks(std::move(cbs));
  }

  bool waitFor(std::function<bool()> cond, std::chrono::milliseconds timeout = 2000ms)
  {
    return resolvetest::waitFor(cond, timeout);
  }
};

/// \brief True iff \p name resolves (via the production hints: AF_UNSPEC UDP +
/// AI_ADDRCONFIG) to an IPv6-only address chain — the precondition for the
/// AF-mismatch case against an IPv4 listener. Guards against hosts whose
/// /etc/hosts lacks the ip6-localhost alias (ts-aside test-determinism).
bool ipv6OnlyNameAvailable(const char *name)
{
  ::addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = AI_ADDRCONFIG;
  ::addrinfo *res = nullptr;
  if (::getaddrinfo(name, "5060", &hints, &res) != 0 || res == nullptr)
  {
    return false;
  }
  bool hasV4 = false, hasV6 = false;
  for (::addrinfo *ai = res; ai != nullptr; ai = ai->ai_next)
  {
    if (ai->ai_family == AF_INET)
    {
      hasV4 = true;
    }
    else if (ai->ai_family == AF_INET6)
    {
      hasV6 = true;
    }
  }
  ::freeaddrinfo(res);
  return hasV6 && !hasV4;
}
} // namespace

// ── connect-site: resolve-timeout / teardown / close ────────────────────────

TEST_CASE("UDP resolve timeout fires onClose(Resolve) via the GC scan; late worker no-ops",
          "[udp][resolve][isolated]")
{
  // Short resolveTimeout + small gcInterval: the resolve deadline scan (runGc)
  // fires exactly one onClose(Resolve) within [resolveTimeout, +gcInterval] while
  // the getaddrinfo sits un-run in the stalled pool.
  ResolveFixture f{150ms, std::chrono::seconds(1)};
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cr = f.tx->connect("localhost", port, TlsMode::None);
  REQUIRE(cr.isOk());

  REQUIRE(f.waitFor([&] { return f.closeCount >= 1; }, 2500ms));
  {
    std::lock_guard<std::mutex> lock(f.m);
    CHECK(f.closeCount == 1);
    CHECK(f.lastCloseCode == TransportError::Resolve);
    CHECK(f.lastCloseMsg.find("resolve timeout") != std::string::npos);
  }

  stall.release();
  std::this_thread::sleep_for(200ms);
  CHECK(f.closeCount == 1); // late worker no-oped

  f.tx->stop();
}

TEST_CASE("UDP teardown with an in-flight resolve fires one onClose(ShuttingDown)",
          "[udp][resolve][isolated]")
{
  ResolveFixture f{30000ms};
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cr = f.tx->connect("localhost", port, TlsMode::None);
  REQUIRE(cr.isOk());

  auto t0 = std::chrono::steady_clock::now();
  f.tx->stop();
  auto elapsed = std::chrono::steady_clock::now() - t0;

  {
    std::lock_guard<std::mutex> lock(f.m);
    CHECK(f.closeCount == 1);
    CHECK(f.lastCloseCode == TransportError::ShuttingDown);
  }
  CHECK(elapsed < 3000ms);

  stall.release();
  std::this_thread::sleep_for(150ms);
  CHECK(f.closeCount == 1);
}

TEST_CASE("UDP close during resolve fires one terminal; later resume no-ops",
          "[udp][resolve][isolated]")
{
  ResolveFixture f{30000ms};
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cr = f.tx->connect("localhost", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId sid = cr.value();

  f.tx->close(sid);
  REQUIRE(f.waitFor([&] { return f.closeCount >= 1; }));
  {
    std::lock_guard<std::mutex> lock(f.m);
    CHECK(f.closeCount == 1);
    CHECK(f.closedSids.size() == 1);
    CHECK(f.closedSids.front() == sid);
  }

  stall.release();
  std::this_thread::sleep_for(200ms);
  CHECK(f.closeCount == 1);

  f.tx->stop();
}

// ── via-listener terminal matrix ────────────────────────────────────────────

TEST_CASE("UDP named-host via-listener success preserves the listener source port (RFC 3581)",
          "[udp][via][resolve][isolated]")
{
  ResolveFixture f{5000ms};
  REQUIRE(f.tx->start().isOk());
  auto port1 = testnet::getFreePortUDP(); // listener port
  auto port2 = testnet::getFreePortUDP(); // external peer port

  auto lr = f.tx->addListener("127.0.0.1", port1, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  // A plain UDP peer socket to observe the source port of the via session.
  int peer = ::socket(AF_INET, SOCK_DGRAM, 0);
  REQUIRE(peer >= 0);
  sockaddr_in pa{};
  pa.sin_family = AF_INET;
  pa.sin_port = htons(port2);
  ::inet_pton(AF_INET, "127.0.0.1", &pa.sin_addr);
  REQUIRE(::bind(peer, reinterpret_cast<sockaddr *>(&pa), sizeof(pa)) == 0);

  auto cs = f.tx->connectViaListener(lid, "localhost", port2);
  REQUIRE(cs.isOk());
  REQUIRE(f.waitFor([&] { return f.connectCount >= 1; }, 3000ms));
  CHECK(f.closeCount == 0);

  const char *msg = "via";
  REQUIRE(f.tx->send(cs.value(), msg, std::strlen(msg)));

  // The peer must receive the datagram sourced from the LISTENER port.
  char buf[16];
  sockaddr_in src{};
  socklen_t sl = sizeof(src);
  timeval tv{2, 0};
  ::setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  ssize_t n = ::recvfrom(peer, buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&src), &sl);
  REQUIRE(n == 3);
  CHECK(ntohs(src.sin_port) == port1); // source-port preserved (RFC 3581)

  ::close(peer);
  f.tx->stop();
}

TEST_CASE("UDP named-host via-listener with a bogus listener id fires onClose(Config: listener not found)",
          "[udp][via][resolve][isolated]")
{
  ResolveFixture f{5000ms};
  REQUIRE(f.tx->start().isOk());

  // No listener with this id: resolve succeeds, resume re-looks-up and fails.
  const ListenerId bogus = 999999;
  auto cs = f.tx->connectViaListener(bogus, "localhost", testnet::getFreePortUDP());
  REQUIRE(cs.isOk()); // sid allocated; the terminal is delivered on resume

  REQUIRE(f.waitFor([&] { return f.closeCount >= 1; }, 3000ms));
  {
    std::lock_guard<std::mutex> lock(f.m);
    CHECK(f.closeCount == 1);
    CHECK(f.lastCloseCode == TransportError::Config);
    CHECK(f.lastCloseMsg.find("listener not found") != std::string::npos);
  }
  CHECK(f.connectCount == 0);

  f.tx->stop();
}

TEST_CASE("UDP named-host via-listener AF mismatch fires onClose(Config)",
          "[udp][via][resolve][isolated]")
{
  if (!ipv6OnlyNameAvailable("ip6-localhost"))
  {
    WARN("ip6-localhost is not IPv6-only-resolvable on this host; skipping AF-mismatch case");
    SUCCEED();
    return;
  }
  ResolveFixture f{5000ms};
  REQUIRE(f.tx->start().isOk());
  auto port1 = testnet::getFreePortUDP();

  // IPv4 listener; resolve an IPv6-only name (ip6-localhost -> ::1 via /etc/hosts).
  auto lr = f.tx->addListener("127.0.0.1", port1, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  auto cs = f.tx->connectViaListener(lid, "ip6-localhost", testnet::getFreePortUDP());
  REQUIRE(cs.isOk());

  REQUIRE(f.waitFor([&] { return f.closeCount >= 1; }, 3000ms));
  {
    std::lock_guard<std::mutex> lock(f.m);
    CHECK(f.closeCount == 1);
    CHECK(f.lastCloseCode == TransportError::Config);
    CHECK(f.lastCloseMsg.find("AF mismatch") != std::string::npos);
  }
  CHECK(f.connectCount == 0);

  f.tx->stop();
}

TEST_CASE("UDP named-host via-listener session cap fires onClose(Config: session cap reached)",
          "[udp][via][resolve][isolated]")
{
  ResolveFixture f{5000ms, std::chrono::seconds(5), /*maxSessions=*/1};
  REQUIRE(f.tx->start().isOk());
  auto port1 = testnet::getFreePortUDP();
  auto port2 = testnet::getFreePortUDP();

  auto lr = f.tx->addListener("127.0.0.1", port1, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  // Fill the single session slot with a literal via session (synchronous).
  auto first = f.tx->connectViaListener(lid, "127.0.0.1", port2);
  REQUIRE(first.isOk());
  REQUIRE(f.waitFor([&] { return f.connectCount >= 1; }));

  // A named-host via session now exceeds the cap at resume.
  auto second = f.tx->connectViaListener(lid, "localhost", port2);
  REQUIRE(second.isOk());

  REQUIRE(f.waitFor([&] { return f.closeCount >= 1; }, 3000ms));
  {
    std::lock_guard<std::mutex> lock(f.m);
    CHECK(f.closeCount == 1);
    CHECK(f.lastCloseCode == TransportError::Config);
    CHECK(f.lastCloseMsg.find("session cap reached") != std::string::npos);
  }

  f.tx->stop();
}

TEST_CASE("UDP named-host via-listener reject-fast fires onClose(Resolve: resolver pool saturated)",
          "[udp][via][resolve][isolated]")
{
  ResolveFixture f{5000ms};
  REQUIRE(f.tx->start().isOk());
  auto port1 = testnet::getFreePortUDP();

  auto lr = f.tx->addListener("127.0.0.1", port1, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  resolvetest::PoolStall stall;
  stall.saturate(); // queue full -> the via resolve reject-fasts

  auto cs = f.tx->connectViaListener(lid, "localhost", testnet::getFreePortUDP());
  REQUIRE(cs.isOk());

  REQUIRE(f.waitFor([&] { return f.closeCount >= 1; }, 3000ms));
  {
    std::lock_guard<std::mutex> lock(f.m);
    CHECK(f.closeCount == 1);
    CHECK(f.lastCloseCode == TransportError::Resolve);
    CHECK(f.lastCloseMsg == "resolver pool saturated");
  }
  CHECK(f.connectCount == 0);

  stall.release();
  f.tx->stop();
}

TEST_CASE("UDP named-host via-listener teardown-in-flight fires one onClose(ShuttingDown)",
          "[udp][via][resolve][isolated]")
{
  ResolveFixture f{30000ms};
  REQUIRE(f.tx->start().isOk());
  auto port1 = testnet::getFreePortUDP();

  auto lr = f.tx->addListener("127.0.0.1", port1, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cs = f.tx->connectViaListener(lid, "localhost", testnet::getFreePortUDP());
  REQUIRE(cs.isOk());

  f.tx->stop();
  {
    std::lock_guard<std::mutex> lock(f.m);
    CHECK(f.closeCount == 1);
    CHECK(f.lastCloseCode == TransportError::ShuttingDown);
  }

  stall.release();
  std::this_thread::sleep_for(150ms);
  CHECK(f.closeCount == 1);
}

TEST_CASE("UDP named-host via-listener resolve timeout fires onClose(Resolve) via the GC scan",
          "[udp][via][resolve][isolated]")
{
  // The via-listener resolve-timeout completes the terminal matrix (cpp17-L2):
  // a named-host ViaReq whose resolve is parked past a short resolveTimeout gets
  // exactly one onClose(Resolve) from the GC-scan deadline; the late resumeVia
  // no-ops.
  ResolveFixture f{150ms, std::chrono::seconds(1)};
  REQUIRE(f.tx->start().isOk());
  auto port1 = testnet::getFreePortUDP();

  auto lr = f.tx->addListener("127.0.0.1", port1, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cs = f.tx->connectViaListener(lid, "localhost", testnet::getFreePortUDP());
  REQUIRE(cs.isOk());

  REQUIRE(f.waitFor([&] { return f.closeCount >= 1; }, 2500ms));
  {
    std::lock_guard<std::mutex> lock(f.m);
    CHECK(f.closeCount == 1);
    CHECK(f.lastCloseCode == TransportError::Resolve);
    CHECK(f.lastCloseMsg.find("resolve timeout") != std::string::npos);
  }

  stall.release();
  std::this_thread::sleep_for(200ms);
  CHECK(f.closeCount == 1); // late resumeVia no-ops
  CHECK(f.connectCount == 0);

  f.tx->stop();
}
