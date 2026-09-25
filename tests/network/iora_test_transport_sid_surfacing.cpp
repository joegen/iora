// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_transport_sid_surfacing.cpp
/// \brief Transport send-seam SID surfacing + engine allocate-then-connect split
///        (tracker 2026-09-25-18). Proves the register-before-connect primitives
///        allocateSid() + connectWith() on TcpEngine, UdpEngine and network::Transport:
///          - DP-SS1: allocateSid() mints WITHOUT publishing (nothing in _connecting).
///          - DP-SS1/DP-SS2: a send() before connectWith() is REJECTED, never dropped.
///          - DP-SS2/DP-SS3: connectWith() enqueues; a connect FAILURE is delivered to
///            the sid whose onClose was registered BEFORE connectWith() (deterministic
///            dead-port refusal + an I/O-thread-occupied ordering case).
///          - DP-SS4: on enqueue-fail / closed queue, connectWith() returns err, rolls
///            _connecting back, and fires NO onClose (err XOR onClose for a registered sid).
///          - DP-SS6: connectWith() is single-shot per sid.
///          - DP-SS7: the sid-agnostic connect() and UDP connectViaListener() paths are
///            unchanged (regression).
///          - DP-SS5: network::Transport delegates allocateSid()/connectWith() to the engine.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/network/transport.hpp"
#include "iora/network/transport_impl.hpp"
#include "iora/network/detail/udp_engine.hpp"

#include "tcp_connect_test_fixtures.hpp"
#include "udp_engine_test_access.hpp"

#include <atomic>
#include <chrono>
#include <map>
#include <mutex>

using namespace tcptest;
using namespace std::chrono_literals;

using UdpEngine = iora::network::UdpEngine;
using UTA = iora::network::UdpEngineTestAccess;
using iora::core::BufferView;

namespace
{
BufferView bv(const char *s, std::size_t n)
{
  return BufferView{reinterpret_cast<const std::uint8_t *>(s), n};
}

/// Minimal UDP probe: a started UdpEngine with per-sid onClose capture.
struct UdpProbe
{
  std::mutex m;
  std::map<SessionId, int> closes;
  std::map<SessionId, TransportErrorInfo> closeInfo;
  std::unique_ptr<UdpEngine> eng;

  UdpProbe()
  {
    TransportConfig cfg{};
    eng = std::make_unique<UdpEngine>(cfg);
    iora::network::detail::EngineBase::Callbacks cbs{};
    cbs.onClose = [this](SessionId sid, const TransportErrorInfo &e)
    {
      std::lock_guard<std::mutex> lk(m);
      closes[sid]++;
      closeInfo[sid] = e;
    };
    eng->setCallbacks(cbs);
    REQUIRE(eng->start().isOk());
  }
  ~UdpProbe()
  {
    if (eng)
    {
      eng->stop();
    }
  }
  int closesFor(SessionId sid)
  {
    std::lock_guard<std::mutex> lk(m);
    auto it = closes.find(sid);
    return it == closes.end() ? 0 : it->second;
  }
};
} // namespace

// ───────────── DP-SS1/DP-SS2: mint publishes nothing; send before connectWith rejected ─────────────

TEST_CASE("TCP allocateSid mints without publishing; send before connectWith is rejected",
          "[sid-surfacing][tcp][ss1][ss2]")
{
  Client client(false);
  REQUIRE(client.tx->start().isOk());

  SessionId sid = client.tx->allocateSid();
  REQUIRE(sid != 0);
  // DP-SS1: nothing engine-discoverable published — sid is in neither registry.
  REQUIRE(TA::connectingCount(*client.tx) == 0);
  REQUIRE_FALSE(TA::hasSession(*client.tx, sid));

  // DP-SS2: a send/sendAsync before connectWith() is REJECTED (not silently dropped),
  // because sessionSendable() finds the sid in neither _sessions nor _connecting.
  REQUIRE_FALSE(client.tx->send(sid, "x", 1));
  bool asyncOk = true;
  client.tx->sendAsync(sid, "y", 1, [&](SessionId, const SendResult &r) { asyncOk = r.isOk(); });
  REQUIRE_FALSE(asyncOk);
}

// ───────────── DP-SS2/DP-SS3: connect failure delivered to the pre-registered sid ─────────────

TEST_CASE("TCP connectWith to a dead port delivers the connect terminal to the registered sid",
          "[sid-surfacing][tcp][ss2][ss3]")
{
  Client client(false);
  REQUIRE(client.tx->start().isOk());

  // Deterministic refusal: a free port with nothing listening → ECONNREFUSED.
  const std::uint16_t deadPort = testnet::getFreePortTCP();
  SessionId sid = client.tx->allocateSid();
  // client.onClose was installed at construction — i.e. registered BEFORE connectWith().
  auto cr = client.tx->connectWith(sid, "127.0.0.1", deadPort, TlsMode::None, {});
  REQUIRE(cr.isOk());
  REQUIRE(cr.value() == sid); // the caller's registered sid is the one that connects

  REQUIRE(waitFor([&] { return client.closesFor(sid) >= 1; }));
  REQUIRE(client.closeInfo(sid).code == TransportError::Connect);
  REQUIRE(TA::connectingCount(*client.tx) == 0); // reclaimed on terminal
}

TEST_CASE("TCP connectWith issued FROM the I/O thread: mint publishes nothing, connectWith registers "
          "before the connect Cmd can run (deterministic ordering)",
          "[sid-surfacing][tcp][ss1][ss2][ss8][iothread]")
{
  Client client(false);
  REQUIRE(client.tx->start().isOk());
  const std::uint16_t deadPort = testnet::getFreePortTCP();

  std::size_t connectingAfterAllocate = 99;
  std::size_t connectingAfterConnectWith = 99;
  bool connectWithOk = false;
  SessionId sid = 0;
  // Occupying the I/O thread guarantees the enqueued Connect Cmd cannot run until this
  // returns — so the observed states are ordered: allocateSid (nothing), connectWith
  // (registered in _connecting), THEN the connect attempt/failure afterwards.
  REQUIRE(runOnIo(*client.tx,
                  [&]
                  {
                    sid = client.tx->allocateSid();
                    connectingAfterAllocate = TA::connectingCount(*client.tx); // DP-SS1 -> 0
                    auto cr = client.tx->connectWith(sid, "127.0.0.1", deadPort, TlsMode::None, {});
                    connectWithOk = cr.isOk();
                    connectingAfterConnectWith = TA::connectingCount(*client.tx); // DP-SS2 -> 1
                  }));
  REQUIRE(connectingAfterAllocate == 0);
  REQUIRE(connectWithOk);
  REQUIRE(connectingAfterConnectWith == 1);
  // The connect Cmd runs only after the I/O-thread task returns; the terminal is then
  // delivered to the sid that was registered before connectWith() enqueued it.
  REQUIRE(waitFor([&] { return client.closesFor(sid) >= 1; }));
  REQUIRE(client.closeInfo(sid).code == TransportError::Connect);
}

TEST_CASE("TCP connectWith to a NAMED host (resumeConnect async path) delivers the terminal to the "
          "pre-registered sid",
          "[sid-surfacing][tcp][ss2][ss3][ss8][resolve]")
{
  // DP-SS8 / Phase 3.1 requires the named-host async-resolve path, distinct from the
  // literal-IP synchronous path: doConnect posts the resolve to the blockingIoPool, the
  // continuation posts runOnIoThread back, and the terminal fires from the I/O thread via
  // the gate->m -> _cmdMutex edge. "localhost" resolves locally (no network DNS) and the
  // dead port makes the post-resolve connect fail deterministically (ECONNREFUSED).
  Client client(false);
  REQUIRE(client.tx->start().isOk());
  const std::uint16_t deadPort = testnet::getFreePortTCP();

  SessionId sid = client.tx->allocateSid(); // onClose already registered (before connectWith)
  auto cr = client.tx->connectWith(sid, "localhost", deadPort, TlsMode::None, {});
  REQUIRE(cr.isOk());
  REQUIRE(cr.value() == sid);

  REQUIRE(waitFor([&] { return client.closesFor(sid) >= 1; }));
  REQUIRE(client.closeInfo(sid).code == TransportError::Connect);
  REQUIRE(TA::connectingCount(*client.tx) == 0);
}

// ───────────── DP-SS4: err XOR onClose (enqueue-fail rolls _connecting back, no terminal) ─────────────

TEST_CASE("TCP connectWith on a failed enqueue returns err, rolls _connecting back, fires NO onClose",
          "[sid-surfacing][tcp][ss4]")
{
  Client client(false);
  REQUIRE(client.tx->start().isOk());
  TA::injectEnqueueFailure(*client.tx, true);

  const std::uint16_t deadPort = testnet::getFreePortTCP();
  SessionId sid = client.tx->allocateSid();
  auto cr = client.tx->connectWith(sid, "127.0.0.1", deadPort, TlsMode::None, {});
  REQUIRE_FALSE(cr.isOk());                         // err returned to the caller
  REQUIRE(TA::connectingCount(*client.tx) == 0);    // DP-SS4: reservation rolled back
  // No Connect Cmd was queued, so no terminal can fire for this sid (err XOR onClose).
  std::this_thread::sleep_for(150ms);
  REQUIRE(client.closesFor(sid) == 0);
}

TEST_CASE("TCP connectWith on a stopped (closed-queue) engine returns ShuttingDown, no onClose",
          "[sid-surfacing][tcp][ss4]")
{
  Client client(false);
  REQUIRE(client.tx->start().isOk());
  client.tx->stop(); // closes the command queue (DD-5)

  SessionId sid = client.tx->allocateSid();
  auto cr = client.tx->connectWith(sid, "127.0.0.1", 9, TlsMode::None, {});
  REQUIRE_FALSE(cr.isOk());
  REQUIRE(cr.error().code == TransportError::ShuttingDown);
  REQUIRE(TA::connectingCount(*client.tx) == 0);
  REQUIRE(client.closesFor(sid) == 0);
}

// ───────────── DP-SS6: single-shot flush ─────────────

TEST_CASE("TCP connectWith is single-shot: a second flush for the same sid is rejected",
          "[sid-surfacing][tcp][ss6]")
{
  SinkServer server(false, "", "");
  Client client(false);
  REQUIRE(client.tx->start().isOk());

  SessionId sid = client.tx->allocateSid();
  auto cr1 = client.tx->connectWith(sid, "127.0.0.1", server.port, TlsMode::None, {});
  REQUIRE(cr1.isOk());
  // sid is now in _connecting (or _sessions once established) — a second connectWith
  // must be rejected so it cannot double-enqueue a Connect (DP-SS6).
  auto cr2 = client.tx->connectWith(sid, "127.0.0.1", server.port, TlsMode::None, {});
  REQUIRE_FALSE(cr2.isOk());
}

// ───────────── DP-SS7: the unsplit paths are unchanged (regression) ─────────────

TEST_CASE("TCP sid-agnostic connect()+send() still delivers (DP-SS7 regression)",
          "[sid-surfacing][tcp][ss7][regression]")
{
  SinkServer server(false, "", "");
  Client client(false);
  REQUIRE(client.tx->start().isOk());

  auto cr = client.tx->connect("127.0.0.1", server.port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId sid = cr.value();
  REQUIRE(client.tx->send(sid, "A|", 2)); // immediately sendable, as before
  REQUIRE(waitFor([&] { return server.data() == "A|"; }));
  REQUIRE(client.closeCount == 0);
}

// ───────────── DP-SS1/DP-SS2/DP-SS6 on UDP + connectViaListener regression ─────────────

TEST_CASE("UDP allocateSid/connectWith: mint publishes nothing, send rejected, single-shot",
          "[sid-surfacing][udp][ss1][ss2][ss6]")
{
  UdpProbe probe;
  const std::uint16_t peerPort = testnet::getFreePortUDP();

  SessionId sid = probe.eng->allocateSid();
  REQUIRE(sid != 0);
  REQUIRE(UTA::connectingCount(*probe.eng) == 0);   // DP-SS1
  REQUIRE_FALSE(UTA::hasSession(*probe.eng, sid));
  REQUIRE_FALSE(probe.eng->send(sid, "x", 1));       // DP-SS2: rejected, not dropped

  auto cr = probe.eng->connectWith(sid, "127.0.0.1", peerPort, TlsMode::None, {});
  REQUIRE(cr.isOk());
  REQUIRE(cr.value() == sid);

  auto cr2 = probe.eng->connectWith(sid, "127.0.0.1", peerPort, TlsMode::None, {}); // DP-SS6
  REQUIRE_FALSE(cr2.isOk());
}

TEST_CASE("UDP connectWith on a failed enqueue returns err, rolls _connecting back, no onClose",
          "[sid-surfacing][udp][ss4]")
{
  UdpProbe probe;
  UTA::injectEnqueueFailure(*probe.eng, true);

  const std::uint16_t peerPort = testnet::getFreePortUDP();
  SessionId sid = probe.eng->allocateSid();
  auto cr = probe.eng->connectWith(sid, "127.0.0.1", peerPort, TlsMode::None, {});
  REQUIRE_FALSE(cr.isOk());                          // err returned
  REQUIRE(UTA::connectingCount(*probe.eng) == 0);    // DP-SS4: reservation rolled back
  std::this_thread::sleep_for(150ms);
  REQUIRE(probe.closesFor(sid) == 0);                // no Connect Cmd queued -> no terminal
}

TEST_CASE("UDP connectWith rejects TLS (parity with connect())", "[sid-surfacing][udp][ss5]")
{
  UdpProbe probe;
  SessionId sid = probe.eng->allocateSid();
  auto cr = probe.eng->connectWith(sid, "127.0.0.1", 5060, TlsMode::Client, {});
  REQUIRE_FALSE(cr.isOk());
  REQUIRE(cr.error().code == TransportError::Config);
}

TEST_CASE("UDP connectViaListener still works unchanged (DP-SS7 regression)",
          "[sid-surfacing][udp][ss7][regression]")
{
  UdpProbe probe;
  const std::uint16_t listenPort = testnet::getFreePortUDP();
  auto lr = probe.eng->addListener("127.0.0.1", listenPort, TlsMode::None);
  REQUIRE(lr.isOk());
  const std::uint16_t peerPort = testnet::getFreePortUDP();
  auto cr = probe.eng->connectViaListener(lr.value(), "127.0.0.1", peerPort);
  REQUIRE(cr.isOk());
  REQUIRE(cr.value() != 0);
}

// ───────────── DP-SS5: network::Transport delegates to the engine ─────────────

TEST_CASE("network::Transport delegates allocateSid()/connectWith() to the TCP engine",
          "[sid-surfacing][transport][ss5]")
{
  TransportConfig cfg{};
  auto tx = iora::network::Transport::tcp(cfg);
  REQUIRE(tx->start().isOk());

  std::mutex m;
  std::map<SessionId, TransportErrorInfo> closeInfo;
  std::atomic<int> closeCount{0};
  tx->onClose(
    [&](SessionId sid, const TransportErrorInfo &e)
    {
      std::lock_guard<std::mutex> lk(m);
      closeInfo[sid] = e;
      closeCount++;
    });

  SessionId sid = tx->allocateSid();
  REQUIRE(sid != 0);
  REQUIRE_FALSE(tx->send(sid, bv("x", 1))); // send before connectWith rejected

  const std::uint16_t deadPort = testnet::getFreePortTCP();
  auto cr = tx->connectWith(sid, "127.0.0.1", deadPort, TlsMode::None, {});
  REQUIRE(cr.isOk());
  REQUIRE(cr.value() == sid);
  REQUIRE(waitFor([&] { return closeCount.load() >= 1; }));
  {
    std::lock_guard<std::mutex> lk(m);
    REQUIRE(closeInfo[sid].code == TransportError::Connect);
  }
  tx->stop();
}
