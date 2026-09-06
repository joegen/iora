// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_tcp_engine_resolve.cpp
/// \brief ISOLATED, LAST-ORDERED event-driven resolve integration tests for the
///        TCP engine (architecture/iora/transport_dns_resolve.json
///        testStrategy.c2_integration; tracker 2026-09-06-4 task-6.2).
///
/// These cases stall the process-wide blockingIoPool() (via PoolStall) so a
/// named-host getaddrinfo can be held un-run past a short resolveTimeout, or
/// held pending across a close/teardown — deterministically, with no DNS or
/// resolver-config dependency. Because they seize the global pool they live in
/// their own binary, ordered LAST in NETWORK_TESTS.
///
/// The happy-path event-driven connect and the restart case live in
/// iora_test_tcp_engine.cpp (they need no stall) and are not duplicated here.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/network/detail/tcp_engine.hpp"
#include "iora_test_net_utils.hpp"
#include "resolve_stall_harness.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

using namespace std::chrono_literals;
using TcpEngine = iora::network::TcpEngine;
using TransportConfig = iora::network::TransportConfig;
using TransportAddress = iora::network::TransportAddress;
using TransportErrorInfo = iora::network::TransportErrorInfo;
using TransportError = iora::network::TransportError;
using TlsMode = iora::network::TlsMode;
using SessionId = iora::network::SessionId;

namespace
{
/// \brief TCP engine + callback capture with a configurable resolveTimeout.
struct ResolveFixture
{
  TransportConfig cfg{};
  std::unique_ptr<TcpEngine> tx;

  std::mutex m;
  std::atomic<size_t> connectCount{0};
  std::atomic<size_t> closeCount{0};
  std::vector<SessionId> closedSids;
  std::map<SessionId, TransportError> closeCodeBySid;
  TransportError lastCloseCode{TransportError::Unknown};
  std::string lastCloseMsg;

  explicit ResolveFixture(std::chrono::milliseconds resolveTimeout, bool enableClientTls = false,
                          std::chrono::milliseconds handshakeTimeout = std::chrono::milliseconds(30000))
  {
    cfg.resolveTimeout = resolveTimeout;
    cfg.handshakeTimeout = handshakeTimeout;
    if (enableClientTls)
    {
      // Cert-free client context: enough to create _sslCli so the TLS branch in
      // connectFromAddrs runs (verifyPeer defaults off; no cert/key needed).
      cfg.clientTls.enabled = true;
      cfg.clientTls.defaultMode = TlsMode::Client;
    }
    tx = std::make_unique<TcpEngine>(cfg);

    iora::network::detail::EngineBase::Callbacks cbs{};
    cbs.onConnect = [&](SessionId, const TransportAddress &) { connectCount++; };
    cbs.onClose = [&](SessionId sid, const TransportErrorInfo &err)
    {
      std::lock_guard<std::mutex> lock(m);
      closedSids.push_back(sid);
      closeCodeBySid[sid] = err.code;
      lastCloseCode = err.code;
      lastCloseMsg = err.message;
      closeCount++;
    };
    tx->setCallbacks(cbs);
  }

  bool waitFor(std::function<bool()> cond, std::chrono::milliseconds timeout = 2000ms)
  {
    return resolvetest::waitFor(cond, timeout);
  }
};
} // namespace

TEST_CASE("TCP slow resolve does not stall a concurrent literal connect",
          "[tcp][resolve][isolated]")
{
  // A named-host resolve parked in the stalled pool must not block the epoll I/O
  // thread: a concurrent literal-IP connect (synchronous path, no pool) still
  // completes. resolveTimeout is long so the parked resolve stays pending.
  ResolveFixture f{30000ms};
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortTCP();
  REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  // Named-host connect: its getaddrinfo sits un-run behind the blocked workers.
  auto named = f.tx->connect("localhost", port, TlsMode::None);
  REQUIRE(named.isOk());

  // Literal connect: must complete even while the resolve is parked.
  auto literal = f.tx->connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(literal.isOk());
  REQUIRE(f.waitFor([&] { return f.connectCount >= 1; }));

  stall.release();
  f.tx->stop();
}

TEST_CASE("TCP resolve timeout fires onClose(Resolve); late worker no-ops",
          "[tcp][resolve][isolated]")
{
  // Short resolveTimeout + a resolve held un-run in the stalled pool => the
  // resolve-timeout must fire exactly one onClose(Resolve). Releasing the pool
  // afterwards lets the late getaddrinfo worker run; its resumeConnect must
  // no-op (pending entry already erased) — still exactly one terminal.
  ResolveFixture f{150ms};
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortTCP();
  REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cr = f.tx->connect("localhost", port, TlsMode::None);
  REQUIRE(cr.isOk());

  REQUIRE(f.waitFor([&] { return f.closeCount >= 1; }));
  {
    std::lock_guard<std::mutex> lock(f.m);
    CHECK(f.closeCount == 1);
    CHECK(f.lastCloseCode == TransportError::Resolve);
    CHECK(f.lastCloseMsg.find("resolve timeout") != std::string::npos);
  }

  // Release the parked worker; its completion must not produce a second terminal
  // AND must not create a session (the late resumeConnect no-ops on the erased
  // pending entry) — exactly one terminal, no session (cpp17-L1).
  stall.release();
  std::this_thread::sleep_for(200ms);
  CHECK(f.closeCount == 1);
  CHECK(f.connectCount == 0);

  f.tx->stop();
}

TEST_CASE("TCP teardown with an in-flight resolve fires one onClose(ShuttingDown)",
          "[tcp][resolve][isolated]")
{
  ResolveFixture f{30000ms};
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortTCP();
  REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cr = f.tx->connect("localhost", port, TlsMode::None);
  REQUIRE(cr.isOk());

  // Tear down while the resolve is parked: shutdownDrain must fire exactly one
  // onClose(ShuttingDown) for the pending sid, with bounded latency (it does not
  // wait on the uncancellable pool task).
  auto t0 = std::chrono::steady_clock::now();
  f.tx->stop();
  auto elapsed = std::chrono::steady_clock::now() - t0;

  {
    std::lock_guard<std::mutex> lock(f.m);
    CHECK(f.closeCount == 1);
    CHECK(f.lastCloseCode == TransportError::ShuttingDown);
  }
  CHECK(elapsed < 3000ms); // not blocked on the parked resolve

  // Release after stop: the late worker's continuation drops against the closed
  // gate; no second terminal.
  stall.release();
  std::this_thread::sleep_for(150ms);
  CHECK(f.closeCount == 1);
}

TEST_CASE("TCP close during resolve fires one terminal; later resume no-ops",
          "[tcp][resolve][isolated]")
{
  ResolveFixture f{30000ms};
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortTCP();
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
    CHECK(f.lastCloseCode != TransportError::Resolve); // an explicit close, not a resolve failure
  }

  stall.release();
  std::this_thread::sleep_for(200ms);
  CHECK(f.closeCount == 1); // the late resume no-oped

  f.tx->stop();
}

TEST_CASE("TCP literal single-address connect failure is terminal (unchanged)",
          "[tcp][resolve][isolated]")
{
  // The literal path stays synchronous and a single-address connect failure is
  // terminal exactly as before the off-thread-resolve refactor.
  ResolveFixture f{5000ms};
  REQUIRE(f.tx->start().isOk());

  testnet::RefusingEndpoint refuser;
  auto cr = f.tx->connect("127.0.0.1", refuser.port(), TlsMode::None);
  REQUIRE(cr.isOk());

  REQUIRE(f.waitFor([&] { return f.closeCount >= 1; }));
  CHECK(f.connectCount == 0);
  CHECK(f.closeCount == 1);

  f.tx->stop();
}

TEST_CASE("TCP named-host connect failure is terminal (single-address)",
          "[tcp][resolve][isolated]")
{
  // Resolve succeeds (localhost) then the single resolved address is refused:
  // terminal, matching today's single-address behavior (no retry/failover here).
  ResolveFixture f{5000ms};
  REQUIRE(f.tx->start().isOk());

  testnet::RefusingEndpoint refuser;
  auto cr = f.tx->connect("localhost", refuser.port(), TlsMode::None);
  REQUIRE(cr.isOk());

  REQUIRE(f.waitFor([&] { return f.closeCount >= 1; }, 3000ms));
  CHECK(f.connectCount == 0);
  CHECK(f.closeCount == 1);
  {
    std::lock_guard<std::mutex> lock(f.m);
    CHECK(f.lastCloseCode != TransportError::Resolve); // resolve succeeded; the connect failed
  }

  f.tx->stop();
}

TEST_CASE("TCP named-host TLS connect reaches SSL setup with the host (F1-no-regression)",
          "[tcp][resolve][tls][isolated]")
{
  // Guards that the phase-2 off-thread-resolve refactor kept cr.host flowing into
  // the TLS branch of connectFromAddrs: a named-host TLS connect must RESOLVE and
  // then reach SSL setup on the resolved path. Handshaking against a plain-TCP
  // listener fails at the TLS layer (not at resolve), proving SSL setup ran.
  // Short handshakeTimeout so the TLS handshake against a silent plain-TCP peer
  // fails fast (it never receives a ServerHello) instead of waiting out the
  // default 30s — the terminal is a TLS-layer failure, not a resolve failure.
  ResolveFixture f{5000ms, /*enableClientTls=*/true, /*handshakeTimeout=*/500ms};
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortTCP();
  REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk()); // plain server

  auto cr = f.tx->connect("localhost", port, TlsMode::Client);
  REQUIRE(cr.isOk());
  SessionId clientSid = cr.value();

  // The client session's terminal must arrive (the accepted server session may
  // also close — assert on the CLIENT sid specifically). The predicate takes f.m
  // because closeCodeBySid (a std::map) is written by onClose on the I/O thread
  // under f.m — an unlocked container read here would be a data race (ts-HIGH).
  REQUIRE(f.waitFor(
    [&]
    {
      std::lock_guard<std::mutex> lk(f.m);
      return f.closeCodeBySid.count(clientSid) > 0;
    },
    3000ms));
  {
    std::lock_guard<std::mutex> lock(f.m);
    // The client terminal is a TLS-layer failure, NOT a resolve failure — the
    // resolved path reached SSL setup with the host in scope.
    CHECK(f.closeCodeBySid[clientSid] != TransportError::Resolve);
    CHECK(f.closeCodeBySid[clientSid] != TransportError::None);
  }
  CHECK(f.connectCount == 0); // handshake never completed against a non-TLS peer

  f.tx->stop();
}
