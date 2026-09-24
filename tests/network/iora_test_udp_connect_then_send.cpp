// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_udp_connect_then_send.cpp
/// \brief UdpEngine connect-then-send parity (tracker 2026-09-24-2 A3 / AX9.1):
///        connect()/connectViaListener() + immediate send delivers with no await,
///        NotConnected on unknown/closed/cap-rejected sids, connecting-registry
///        hygiene across both entry points, named-host/Via pending buffering, and
///        the resolve-completion duplicate burst.
///
/// The named-host/Via registry-hygiene cases stall the process-wide
/// blockingIoPool() (PoolStall), so this binary is ISOLATED and LAST-ORDERED in
/// NETWORK_TESTS, like iora_test_tcp_connect_then_send.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/network/detail/tcp_engine.hpp"
#include "iora/network/detail/udp_engine.hpp"
#include "iora_test_net_utils.hpp"
#include "resolve_stall_harness.hpp"
#include "udp_engine_test_access.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using UdpEngine = iora::network::UdpEngine;
using TcpEngine = iora::network::TcpEngine;
using TransportConfig = iora::network::TransportConfig;
using TransportAddress = iora::network::TransportAddress;
using TransportErrorInfo = iora::network::TransportErrorInfo;
using TransportError = iora::network::TransportError;
using SendResult = iora::network::SendResult;
using TlsMode = iora::network::TlsMode;
using SessionId = iora::network::SessionId;
using ListenerId = iora::network::ListenerId;
using UTA = iora::network::UdpEngineTestAccess;

namespace
{
/// \brief UDP engine + callback capture geared to connect-then-send: the server
/// side accumulates every received datagram IN ARRIVAL ORDER so a test can assert
/// the exact byte stream a client sent (each send is one datagram; loopback
/// preserves order for small datagrams).
struct CtsFixture
{
  TransportConfig cfg{};
  std::unique_ptr<UdpEngine> tx;

  std::mutex m;
  std::atomic<int> connectCount{0};
  std::atomic<int> closeCount{0};
  std::atomic<int> errorCount{0};
  std::string serverBytes; // concatenation of every datagram received by a peer session
  std::vector<SessionId> closedSids;
  TransportError lastCloseCode{TransportError::None};
  TransportError lastErrorCode{TransportError::None};

  explicit CtsFixture(TransportConfig c = TransportConfig{}) : cfg(std::move(c))
  {
    tx = std::make_unique<UdpEngine>(cfg);
    iora::network::detail::EngineBase::Callbacks cbs{};
    cbs.onConnect = [&](SessionId, const TransportAddress &) { connectCount++; };
    cbs.onData = [&](SessionId, iora::core::BufferView bv, std::chrono::steady_clock::time_point)
    {
      std::lock_guard<std::mutex> lock(m);
      serverBytes.append(reinterpret_cast<const char *>(bv.data()), bv.size());
    };
    cbs.onClose = [&](SessionId sid, const TransportErrorInfo &info)
    {
      std::lock_guard<std::mutex> lock(m);
      closedSids.push_back(sid);
      lastCloseCode = info.code;
      closeCount++;
    };
    cbs.onError = [&](TransportError code, const std::string &)
    {
      std::lock_guard<std::mutex> lock(m);
      lastErrorCode = code;
      errorCount++;
    };
    tx->setCallbacks(std::move(cbs));
  }

  ~CtsFixture() noexcept
  {
    try
    {
      tx->stop();
    }
    catch (...)
    {
    }
  }

  // simp-M5: reuse the shared deadline-based poll helper (not an iteration-count loop,
  // which inflates its wall-clock budget under scheduler contention).
  bool waitFor(const std::function<bool()> &cond, int ms = 2000)
  {
    return resolvetest::waitFor(cond, std::chrono::milliseconds(ms));
  }

  std::string bytes()
  {
    std::lock_guard<std::mutex> lock(m);
    return serverBytes;
  }
};

/// Capture the (synchronous) sendAsync completion code.
TransportError sendAsyncCode(UdpEngine &e, SessionId sid, const char *p, std::size_t n)
{
  TransportError code = TransportError::None;
  bool fired = false;
  e.sendAsync(sid, p, n,
              [&](SessionId, const SendResult &r)
              {
                fired = true;
                code = r.isOk() ? TransportError::None : r.error().code;
              });
  REQUIRE(fired); // completion is synchronous on the caller thread (EngineBase contract)
  return code;
}
} // namespace

// ─────────────────────────── AX9.1: connect-then-send ──────────────────────────

TEST_CASE("UDP literal connect + immediate send delivers in order", "[udp][connect-then-send]")
{
  CtsFixture f;
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  auto cr = f.tx->connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId sid = cr.value();

  // Send IMMEDIATELY — no wait for onConnect. The sid is sendable via _connecting.
  REQUIRE(f.tx->send(sid, "A|", 2));
  REQUIRE(TransportError::None == sendAsyncCode(*f.tx, sid, "B|", 2));
  REQUIRE(f.tx->send(sid, "C|", 2));

  REQUIRE(f.waitFor([&] { return f.bytes() == "A|B|C|"; }));
  CHECK(f.connectCount == 1);
  CHECK(UTA::connectingCount(*f.tx) == 0);
}

TEST_CASE("UDP connectViaListener + immediate send delivers", "[udp][connect-then-send][via]")
{
  CtsFixture f;
  REQUIRE(f.tx->start().isOk());
  auto lport = testnet::getFreePortUDP();
  auto lr = f.tx->addListener("127.0.0.1", lport, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();
  // A second listener is the delivery target (via a peer session on the FIRST fd).
  auto dport = testnet::getFreePortUDP();
  REQUIRE(f.tx->addListener("127.0.0.1", dport, TlsMode::None).isOk());

  auto cr = f.tx->connectViaListener(lid, "127.0.0.1", dport);
  REQUIRE(cr.isOk());
  SessionId sid = cr.value();

  REQUIRE(f.tx->send(sid, "X|", 2));
  REQUIRE(f.tx->send(sid, "Y|", 2));

  REQUIRE(f.waitFor([&] { return f.bytes() == "X|Y|"; }));
  CHECK(UTA::connectingCount(*f.tx) == 0);
}

TEST_CASE("UDP connect + immediate send issued FROM the I/O thread delivers",
          "[udp][connect-then-send][iothread]")
{
  CtsFixture f;
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  // Issue connect()+send() from inside a RunOnIo closure (I/O thread). runOnIoThread
  // is public on EngineBase (the UdpEngine override sits in a private section), so
  // reach it through the base interface.
  auto *base = static_cast<iora::network::detail::EngineBase *>(f.tx.get());
  REQUIRE(base->runOnIoThread(
    [&]()
    {
      auto cr = f.tx->connect("127.0.0.1", port, TlsMode::None);
      if (cr.isOk())
      {
        f.tx->send(cr.value(), "Z|", 2);
      }
    }));

  REQUIRE(f.waitFor([&] { return f.bytes() == "Z|"; }));
  CHECK(UTA::connectingCount(*f.tx) == 0);
}

TEST_CASE("UDP send to unknown / closed / cap-rejected sid returns NotConnected",
          "[udp][connect-then-send][notconnected]")
{
  SECTION("unknown UDP sid")
  {
    CtsFixture f;
    REQUIRE(f.tx->start().isOk());
    REQUIRE(TransportError::NotConnected == sendAsyncCode(*f.tx, 999999, "x", 1));
    CHECK_FALSE(f.tx->send(999999, "x", 1));
    // L1: a 0-length send to an unknown sid also reports NotConnected (not a spurious Ok).
    REQUIRE(TransportError::NotConnected == sendAsyncCode(*f.tx, 999999, "", 0));
  }

  SECTION("closed UDP sid")
  {
    CtsFixture f;
    REQUIRE(f.tx->start().isOk());
    auto port = testnet::getFreePortUDP();
    REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());
    auto cr = f.tx->connect("127.0.0.1", port, TlsMode::None);
    REQUIRE(cr.isOk());
    SessionId sid = cr.value();
    REQUIRE(f.waitFor([&] { return f.connectCount == 1; }));
    REQUIRE(f.tx->close(sid));
    REQUIRE(f.waitFor([&] { return f.closeCount == 1; }));
    CHECK(TransportError::NotConnected == sendAsyncCode(*f.tx, sid, "x", 1));
  }

  SECTION("cap-rejected sid")
  {
    TransportConfig cfg;
    cfg.maxSessions = 1;
    CtsFixture f{cfg};
    REQUIRE(f.tx->start().isOk());
    auto port = testnet::getFreePortUDP();
    REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

    auto first = f.tx->connect("127.0.0.1", port, TlsMode::None);
    REQUIRE(first.isOk());
    REQUIRE(f.waitFor([&] { return f.connectCount == 1; }));

    auto second = f.tx->connect("127.0.0.1", port, TlsMode::None);
    REQUIRE(second.isOk()); // ok(sid): enqueued; the cap rejection is async
    SessionId sid2 = second.value();
    REQUIRE(f.waitFor([&] { return f.closeCount == 1; }));
    {
      std::lock_guard<std::mutex> lock(f.m);
      CHECK(f.lastCloseCode == TransportError::ResourceLimit);
    }
    // After the cap rejection cleared _connecting, a send is NotConnected.
    CHECK(TransportError::NotConnected == sendAsyncCode(*f.tx, sid2, "x", 1));
    CHECK(UTA::connectingCount(*f.tx) == 0);
  }
}

TEST_CASE("TCP send to an unknown sid returns NotConnected", "[udp][connect-then-send][notconnected][tcp]")
{
  // A3.3 applies to BOTH engines: an unknown TCP sid reports the structured code.
  TransportConfig cfg;
  TcpEngine e{cfg};
  REQUIRE(e.start().isOk());
  TransportError code = TransportError::None;
  bool fired = false;
  e.sendAsync(424242, "x", 1,
              [&](SessionId, const SendResult &r)
              {
                fired = true;
                code = r.isOk() ? TransportError::None : r.error().code;
              });
  REQUIRE(fired);
  CHECK(code == TransportError::NotConnected);
  e.stop();
}

// ─────────────── AX9.1: named-host pending buffering + overflow ─────────────────

TEST_CASE("UDP named-host pending buffering: sends during the resolve window flush in order",
          "[udp][connect-then-send][resolve][isolated]")
{
  CtsFixture f{[] { TransportConfig c; c.resolveTimeout = 30000ms; return c; }()};
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cr = f.tx->connect("localhost", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId sid = cr.value();

  // The sid is sendable via _connecting while resolution is stalled — datagrams
  // buffer in the PendingConnect entry.
  REQUIRE(f.tx->send(sid, "A|", 2));
  REQUIRE(f.tx->send(sid, "B|", 2));
  REQUIRE(f.tx->send(sid, "C|", 2));
  CHECK(f.bytes().empty()); // nothing delivered yet — no session

  stall.release(); // resolution completes -> insert -> replay buffered in order
  REQUIRE(f.waitFor([&] { return f.bytes() == "A|B|C|"; }));
  CHECK(UTA::connectingCount(*f.tx) == 0);
}

TEST_CASE("UDP pending-buffer overflow drops OLDEST but keeps >=1 (floor-at-1)",
          "[udp][connect-then-send][resolve][isolated]")
{
  // maxWriteQueue == 1: while(size > 1 && size > 1) pop_front -> retains the LAST copy.
  CtsFixture f{[]
               {
                 TransportConfig c;
                 c.resolveTimeout = 30000ms;
                 c.maxWriteQueue = 1;
                 return c;
               }()};
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cr = f.tx->connect("localhost", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId sid = cr.value();

  REQUIRE(f.tx->send(sid, "A|", 2));
  REQUIRE(f.tx->send(sid, "B|", 2));
  REQUIRE(f.tx->send(sid, "C|", 2));
  REQUIRE(f.tx->send(sid, "D|", 2));

  stall.release();
  // Only the last datagram survives the drop-oldest floor-at-1 policy.
  REQUIRE(f.waitFor([&] { return f.bytes() == "D|"; }));
  CHECK(f.bytes().find("A|") == std::string::npos);
}

TEST_CASE("UDP multi-transaction burst to one next-hop preserves >=1 deliverable",
          "[udp][connect-then-send][resolve][isolated]")
{
  // >=2 distinct requests to one next-hop share ONE PendingConnect during the
  // resolve window; the buffer preserves at least the most recent (recoverable via
  // retransmission). With maxWriteQueue large enough, all survive in order.
  CtsFixture f{[]
               {
                 TransportConfig c;
                 c.resolveTimeout = 30000ms;
                 c.maxWriteQueue = 16;
                 return c;
               }()};
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cr = f.tx->connect("localhost", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId sid = cr.value();

  REQUIRE(f.tx->send(sid, "REQ1|", 5));
  REQUIRE(f.tx->send(sid, "REQ2|", 5));

  stall.release();
  REQUIRE(f.waitFor([&] { return f.bytes() == "REQ1|REQ2|"; }));
}

// ─────────────────────────── AX9.1: registry hygiene ───────────────────────────

TEST_CASE("UDP connecting registry is empty after a named-host resolve failure",
          "[udp][connect-then-send][registry][resolve]")
{
  // emitResolveFailure fires BOTH channels (onClose(Resolve) + onError) and clears
  // the registry (covers the code-identical resolveLiteralSync both-channels path,
  // which a valid inet_pton literal cannot exercise organically).
  CtsFixture f;
  REQUIRE(f.tx->start().isOk());

  auto cr = f.tx->connect("nonexistent.invalid.example.", 5060, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId sid = cr.value();

  REQUIRE(f.waitFor([&] { return f.closeCount == 1; }, 4000));
  {
    std::lock_guard<std::mutex> lock(f.m);
    CHECK(f.closeCount == 1);          // exactly ONE terminal
    CHECK(f.errorCount >= 1);          // the separate onError diagnostic channel
    CHECK(f.lastCloseCode == TransportError::Resolve);
    CHECK(f.closedSids.size() == 1);
    CHECK(f.closedSids.front() == sid);
  }
  CHECK(UTA::connectingCount(*f.tx) == 0);
}

TEST_CASE("UDP connecting registry is empty after stop() and after restart",
          "[udp][connect-then-send][registry][lifecycle]")
{
  CtsFixture f;
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  auto cr = f.tx->connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(f.waitFor([&] { return f.connectCount == 1; }));

  f.tx->stop();
  CHECK(UTA::connectingCount(*f.tx) == 0);

  // Restart and connect-then-send again against a fresh registry.
  REQUIRE(f.tx->start().isOk());
  auto port2 = testnet::getFreePortUDP();
  REQUIRE(f.tx->addListener("127.0.0.1", port2, TlsMode::None).isOk());
  auto cr2 = f.tx->connect("127.0.0.1", port2, TlsMode::None);
  REQUIRE(cr2.isOk());
  REQUIRE(f.tx->send(cr2.value(), "R|", 2));
  REQUIRE(f.waitFor([&] { return f.bytes() == "R|"; }));
  CHECK(UTA::connectingCount(*f.tx) == 0);
}

TEST_CASE("UDP stop() with an in-flight connecting sid fires exactly one onClose(ShuttingDown)",
          "[udp][connect-then-send][registry][resolve][isolated]")
{
  CtsFixture f{[] { TransportConfig c; c.resolveTimeout = 30000ms; return c; }()};
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cr = f.tx->connect("localhost", port, TlsMode::None);
  REQUIRE(cr.isOk());
  // Queue sends onto the connecting sid too — they must not resurrect anything.
  f.tx->send(cr.value(), "A|", 2);

  f.tx->stop();
  {
    std::lock_guard<std::mutex> lock(f.m);
    CHECK(f.closeCount == 1);
    CHECK(f.lastCloseCode == TransportError::ShuttingDown);
  }
  CHECK(UTA::connectingCount(*f.tx) == 0);

  stall.release();
  std::this_thread::sleep_for(150ms);
  CHECK(f.closeCount == 1); // late worker no-oped
}

TEST_CASE("UDP multi-transaction overflow evicts the oldest distinct request; newest survives",
          "[udp][connect-then-send][resolve][isolated]")
{
  // sip NEW-2 / R1 sip-M1: >=2 DISTINCT requests to one next-hop share ONE
  // PendingConnect during the resolve window; maxWriteQueue=1 evicts REQ1's only copy
  // (drop-oldest) and keeps the newest deliverable. This is recoverable LATENCY (the
  // client transaction re-emits REQ1 after establishment), not loss — the iora-side
  // proof that >=1 survives; the SIP-level absorption proof is a Slice B obligation.
  CtsFixture f{[]
               {
                 TransportConfig c;
                 c.resolveTimeout = 30000ms;
                 c.maxWriteQueue = 1;
                 return c;
               }()};
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cr = f.tx->connect("localhost", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId sid = cr.value();

  REQUIRE(f.tx->send(sid, "REQ1|", 5));
  REQUIRE(f.tx->send(sid, "REQ2|", 5));

  stall.release();
  REQUIRE(f.waitFor([&] { return f.bytes() == "REQ2|"; }));
  CHECK(f.bytes().find("REQ1|") == std::string::npos); // oldest distinct request evicted
}

TEST_CASE("UDP connecting registry is empty after a resolve timeout",
          "[udp][connect-then-send][registry][resolve][isolated]")
{
  // R1 cpp17-M2: the resolveDeadline scan (runGc) fires ONE onClose(Resolve) and
  // clears the registry while the getaddrinfo sits un-run in the stalled pool.
  CtsFixture f{[]
               {
                 TransportConfig c;
                 c.resolveTimeout = 150ms;
                 c.gcInterval = std::chrono::seconds(1);
                 return c;
               }()};
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cr = f.tx->connect("localhost", port, TlsMode::None);
  REQUIRE(cr.isOk());

  REQUIRE(f.waitFor([&] { return f.closeCount == 1; }, 3000));
  {
    std::lock_guard<std::mutex> lk(f.m);
    CHECK(f.lastCloseCode == TransportError::Resolve);
  }
  CHECK(UTA::connectingCount(*f.tx) == 0);

  stall.release();
  std::this_thread::sleep_for(150ms);
  CHECK(f.closeCount == 1); // late worker no-oped
}

TEST_CASE("UDP app close during the resolve window fires one terminal; registry empty",
          "[udp][connect-then-send][registry][resolve][isolated]")
{
  // R1 cpp17-M2: close(sid) during resolve routes through the process() Close ->
  // preInsertTerminal path (distinct from the shutdown pending-drain).
  CtsFixture f{[] { TransportConfig c; c.resolveTimeout = 30000ms; return c; }()};
  REQUIRE(f.tx->start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cr = f.tx->connect("localhost", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId sid = cr.value();

  f.tx->close(sid);
  REQUIRE(f.waitFor([&] { return f.closeCount == 1; }));
  {
    std::lock_guard<std::mutex> lk(f.m);
    CHECK(f.closedSids.size() == 1);
    CHECK(f.closedSids.front() == sid);
  }
  CHECK(UTA::connectingCount(*f.tx) == 0);

  stall.release();
  std::this_thread::sleep_for(150ms);
  CHECK(f.closeCount == 1); // late resume no-oped
}

TEST_CASE("UDP shutdownDrain invokes a residual RunOnIo posted from a drain onClose (H1)",
          "[udp][connect-then-send][drain][h1]")
{
  // R1 H1 regression pin (deterministic): during stop()'s session drain the engine
  // fires onClose; posting a RunOnIo from there lands it in the queue AFTER
  // shutdownDrain's process() but BEFORE _qClosed, i.e. as a RESIDUAL command. The
  // drain MUST invoke residual RunOnIo closures — before the fix they were dropped
  // (residualRan stays 0), stranding e.g. a Transport::observe() owned terminal.
  TransportConfig cfg;
  UdpEngine tx{cfg};
  std::atomic<int> connectCount{0};
  std::atomic<int> residualRan{0};
  auto *base = static_cast<iora::network::detail::EngineBase *>(&tx);
  iora::network::detail::EngineBase::Callbacks cbs{};
  cbs.onConnect = [&](SessionId, const TransportAddress &) { connectCount++; };
  cbs.onClose = [&](SessionId, const TransportErrorInfo &)
  { base->runOnIoThread([&]() { residualRan++; }); };
  tx.setCallbacks(std::move(cbs));

  REQUIRE(tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(tx.addListener("127.0.0.1", port, TlsMode::None).isOk());
  auto cr = tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(resolvetest::waitFor([&] { return connectCount.load() == 1; }, 2000ms));

  tx.stop(); // session drain -> onClose -> residual RunOnIo -> H1 invokes it
  CHECK(residualRan.load() == 1);
}

// ─────────────────────── AX9.1b: connect-path exception guard ───────────────────

TEST_CASE("UDP injected enqueue failure: connect() rolls the registry back, no onConnect",
          "[udp][connect-then-send][guard]")
{
  CtsFixture f;
  REQUIRE(f.tx->start().isOk());
  UTA::injectEnqueueFailure(*f.tx, true);

  auto cr = f.tx->connect("127.0.0.1", 9, TlsMode::None);
  CHECK(cr.isErr());
  CHECK(cr.error().code == TransportError::ShuttingDown);
  CHECK(UTA::connectingCount(*f.tx) == 0); // rolled back
  std::this_thread::sleep_for(50ms);
  CHECK(f.connectCount == 0);

  auto vr = f.tx->connectViaListener(1, "127.0.0.1", 9);
  CHECK(vr.isErr());
  CHECK(UTA::connectingCount(*f.tx) == 0);

  UTA::injectEnqueueFailure(*f.tx, false);
}

TEST_CASE("UDP connect-path exception guard: one terminal, no registry leak, loop survives",
          "[udp][connect-then-send][guard][isolated]")
{
  struct Point
  {
    const char *name;
    UTA::ConnectThrowPoint pt;
    bool via;
    bool named;
  };
  const Point points[] = {
    {"before-insert literal", UTA::ConnectThrowPoint::BEFORE_INSERT_LITERAL, false, false},
    {"resume-path before-insert", UTA::ConnectThrowPoint::BEFORE_INSERT_RESUME, false, true},
    {"Via kickoff after pending insert", UTA::ConnectThrowPoint::VIA_KICKOFF_AFTER_PENDING_INSERT,
     true, true},
  };

  for (const auto &p : points)
  {
    SECTION(p.name)
    {
      CtsFixture f{[] { TransportConfig c; c.resolveTimeout = 30000ms; return c; }()};
      REQUIRE(f.tx->start().isOk());
      auto port = testnet::getFreePortUDP();
      auto lr = f.tx->addListener("127.0.0.1", port, TlsMode::None);
      REQUIRE(lr.isOk());
      ListenerId lid = lr.value();

      std::unique_ptr<resolvetest::PoolStall> stall;
      if (p.named)
      {
        stall = std::make_unique<resolvetest::PoolStall>();
        stall->occupyWorkers();
      }
      UTA::injectConnectThrow(*f.tx, p.pt);

      const char *host = p.named ? "localhost" : "127.0.0.1";
      auto cr = p.via ? f.tx->connectViaListener(lid, host, port)
                      : f.tx->connect(host, port, TlsMode::None);
      REQUIRE(cr.isOk());

      if (p.named)
      {
        stall->release();
      }
      // Exactly one onClose terminal, registry clean, and the engine still works.
      REQUIRE(f.waitFor([&] { return f.closeCount >= 1; }, 4000));
      CHECK(f.closeCount == 1);
      CHECK(UTA::connectingCount(*f.tx) == 0);

      // Loop survives: a fresh literal connect-then-send still delivers.
      auto ok = f.tx->connect("127.0.0.1", port, TlsMode::None);
      REQUIRE(ok.isOk());
      REQUIRE(f.tx->send(ok.value(), "S|", 2));
      REQUIRE(f.waitFor([&] { return f.bytes() == "S|"; }));
    }
  }
}

TEST_CASE("UDP a throwing onConnect / onData on a LIVE session does not end the I/O loop",
          "[udp][connect-then-send][guard]")
{
  // R3 (cpp17 M): the round-2 callback-guarding fix routes onConnect/onData through
  // invokeUserCallback (swallow+log). A throwing onConnect (now swallowed, not a
  // withConnectGuard teardown) leaves the session up; a throwing onData on the epoll
  // read path (which has NO outer try) no longer std::terminates the process. Against
  // the pre-guard code the first throw kills the I/O thread and the second datagram is
  // never delivered -> this test fails (mutation-valid).
  TransportConfig cfg;
  UdpEngine tx{cfg};
  std::atomic<int> connectCount{0};
  std::atomic<int> dataCount{0};
  std::string serverBytes;
  std::mutex m;
  iora::network::detail::EngineBase::Callbacks cbs{};
  cbs.onConnect = [&](SessionId, const TransportAddress &)
  {
    if (connectCount.fetch_add(1) == 0)
    {
      throw std::runtime_error("onConnect throws once");
    }
  };
  cbs.onData = [&](SessionId, iora::core::BufferView bv, std::chrono::steady_clock::time_point)
  {
    int n = dataCount.fetch_add(1);
    {
      std::lock_guard<std::mutex> lk(m);
      serverBytes.append(reinterpret_cast<const char *>(bv.data()), bv.size());
    }
    if (n == 0)
    {
      throw std::runtime_error("onData throws once"); // swallowed by invokeUserCallback
    }
  };
  tx.setCallbacks(std::move(cbs));
  REQUIRE(tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  auto cr = tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId sid = cr.value();
  // onConnect threw once (swallowed) -> the session is still up, so send() succeeds.
  REQUIRE(tx.send(sid, "A|", 2)); // first datagram: server onData throws once (swallowed)
  REQUIRE(resolvetest::waitFor([&] { return dataCount.load() >= 1; }, 2000ms));
  REQUIRE(tx.send(sid, "B|", 2)); // second datagram: the loop is alive -> delivers
  REQUIRE(resolvetest::waitFor([&] { return dataCount.load() >= 2; }, 2000ms));
  {
    std::lock_guard<std::mutex> lk(m);
    CHECK(serverBytes == "A|B|");
  }
  CHECK(tx.isRunning()); // the I/O loop survived both throws
  tx.stop();
}

// ───────────────────────────── AX9.3: mutation guard ───────────────────────────
// Each AX9.1 case above fails against the pre-A-ext code: without _connecting a
// connect()'d sid is not sendable (send returns false), without the single-decision
// send an unknown sid reports Socket not NotConnected, without pending buffering the
// resolve-window datagrams are dropped, and without preInsertTerminal the registry
// leaks. Recorded in the tracker AX9.3 mutation matrix rather than duplicated here.
