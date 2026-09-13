// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_dns_transport_sid_keying.cpp
/// \brief Regression tests for the cross-engine bare-SessionId keying collision in
///        DnsTransport (tracker 2026-09-11-5).
///
/// The UDP and TCP transport engines mint SessionIds from independent counters that
/// both start at 1, so the first UDP session and the first TCP session both get
/// sid == 1. Before the fix, sessionToServer_ was keyed by a bare SessionId and
/// handleClose erased serverSessions_/tcpBuffers_ ignoring the protocol, so a
/// colliding UDP/TCP sid pair aliased each other's server mapping (wrong-server
/// attribution) and one protocol's close tore down the other's still-live state.
///
/// These tests are WHITE-BOX and deterministic (no real sockets, no timing): they
/// drive the private I/O-thread handlers directly and inspect the private per-session
/// maps via the DnsTransportSidKeyingTestAccess friend seam, so the exact collision
/// is reproduced without flakiness. They cover the tracker test_plan assertions:
///   (A) routing / no-misattribution across a colliding (UDP sid=1, TCP sid=1) pair;
///   (B) teardown isolation -- a TCP close must not tear down the UDP sibling;
///   (C) tcpBuffers_ cross-erase -- a UDP close must not erase the TCP sibling's
///       partially-reassembled buffer, while a TCP close still erases its own.
/// Non-vacuity (RED-against-unfixed) is demonstrated separately by targeted mutation
/// of each fixed site (see the tracker); the assertions below pin the fixed behavior.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/core/buffer_view.hpp"
#include "iora/network/dns/dns_message.hpp"
#include "iora/network/dns/dns_transport.hpp"
#include "iora/network/dns/dns_types.hpp"
#include "iora/network/transport_types.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace iora
{
namespace network
{
namespace dns
{

/// \brief Friend test seam granting deterministic access to DnsTransport internals.
///
/// USAGE CONTRACT: these accessors are for an UN-STARTED DnsTransport instance only
/// (no start() called, so no I/O thread is running). The feed*/close drivers invoke
/// the private I/O-thread handlers directly; running them concurrently with a live
/// I/O thread would produce nondeterministic interleavings against the same guarded
/// maps (each map op is locked, but a manually-invoked handler is not atomic w.r.t.
/// a concurrent real handler). The driver accessors assert(!isRunning()) to enforce
/// this. The reproduction here targets a key-aliasing LOGICAL race, not a data race,
/// so single-threaded white-box driving is the correct, deterministic verification.
struct DnsTransportSidKeyingTestAccess
{
  using T = DnsTransport;

  static void putSession(T &t, bool isTcp, SessionId sid, const std::string &server,
                         std::uint16_t port)
  {
    std::lock_guard<std::mutex> l(t.sessionsMutex_);
    t.sessionToServer_[std::make_pair(isTcp, sid)] = {server, port};
    t.serverSessions_[T::serverKey(server, port, isTcp)] = sid;
  }

  static bool hasSession(T &t, bool isTcp, SessionId sid)
  {
    std::lock_guard<std::mutex> l(t.sessionsMutex_);
    return t.sessionToServer_.count(std::make_pair(isTcp, sid)) != 0;
  }

  static bool hasServerSession(T &t, const std::string &server, std::uint16_t port, bool isTcp)
  {
    std::lock_guard<std::mutex> l(t.sessionsMutex_);
    return t.serverSessions_.count(T::serverKey(server, port, isTcp)) != 0;
  }

  static void putTcpBuffer(T &t, SessionId sid, const std::vector<std::uint8_t> &bytes)
  {
    std::lock_guard<std::mutex> l(t.tcpBuffersMutex_);
    auto &buf = t.tcpBuffers_[sid];
    buf.insert(buf.end(), bytes.begin(), bytes.end());
  }

  static bool hasTcpBuffer(T &t, SessionId sid)
  {
    std::lock_guard<std::mutex> l(t.tcpBuffersMutex_);
    return t.tcpBuffers_.count(sid) != 0;
  }

  static std::size_t tcpBufferSize(T &t, SessionId sid)
  {
    std::lock_guard<std::mutex> l(t.tcpBuffersMutex_);
    auto it = t.tcpBuffers_.find(sid);
    return it == t.tcpBuffers_.end() ? 0 : it->second.size();
  }

  static void registerPending(T &t, std::uint16_t id, const std::string &server,
                              std::uint16_t port)
  {
    auto q = std::make_shared<T::PendingQuery>(id, std::chrono::milliseconds(5000), server, port,
                                               std::vector<std::uint8_t>{});
    std::lock_guard<std::mutex> l(t.queriesMutex_);
    t.pendingQueries_.emplace(T::QueryKey(id, server, port), q);
  }

  static bool hasPending(T &t, std::uint16_t id, const std::string &server, std::uint16_t port)
  {
    std::lock_guard<std::mutex> l(t.queriesMutex_);
    return t.pendingQueries_.count(T::QueryKey(id, server, port)) != 0;
  }

  static void feedUdp(T &t, SessionId sid, const std::vector<std::uint8_t> &bytes)
  {
    assert(!t.isRunning()); // un-started instances only (see USAGE CONTRACT above)
    t.handleUdpData(sid, iora::core::BufferView(bytes.data(), bytes.size()),
                    std::chrono::steady_clock::now());
  }

  static void feedTcp(T &t, SessionId sid, const std::vector<std::uint8_t> &bytes)
  {
    assert(!t.isRunning());
    t.handleTcpData(sid, iora::core::BufferView(bytes.data(), bytes.size()),
                    std::chrono::steady_clock::now());
  }

  static void close(T &t, SessionId sid, bool isTcp)
  {
    assert(!t.isRunning());
    t.handleClose(sid, TransportErrorInfo{}, isTcp);
  }
};

} // namespace dns
} // namespace network
} // namespace iora

using namespace iora::network::dns;
using Access = iora::network::dns::DnsTransportSidKeyingTestAccess;

namespace
{
constexpr const char *SERVER_A = "127.0.0.1";
constexpr std::uint16_t PORT_A = 5301;
constexpr const char *SERVER_B = "127.0.0.1";
constexpr std::uint16_t PORT_B = 5302;
constexpr std::uint16_t ID_A = 0x1111;
constexpr std::uint16_t ID_B = 0x2222;

/// \brief Build a parseable DNS wire buffer carrying a chosen header id. processResponse
///        keys completion on (header.id, sourceServer, sourcePort), so this stands in
///        for a response for the routing assertions.
std::vector<std::uint8_t> wireWithId(std::uint16_t id)
{
  return DnsMessage::buildQuery(DnsQuestion("example.test", DnsType::A, DnsClass::IN), id);
}

/// \brief Prefix a message with the 2-byte length used by TCP DNS framing.
std::vector<std::uint8_t> framed(const std::vector<std::uint8_t> &msg)
{
  std::vector<std::uint8_t> out;
  out.push_back(static_cast<std::uint8_t>((msg.size() >> 8) & 0xFF));
  out.push_back(static_cast<std::uint8_t>(msg.size() & 0xFF));
  out.insert(out.end(), msg.begin(), msg.end());
  return out;
}

std::shared_ptr<DnsTransport> makeTransport()
{
  DnsConfig cfg; // default transportMode == Both; not start()ed (white-box).
  return std::make_shared<DnsTransport>(cfg);
}
} // namespace

// (A) Routing / no-misattribution: with the colliding pair UDP sid=1 -> serverA and
// TCP sid=1 -> serverB both live, a response on one protocol must complete ONLY the
// query for the correct server, never the sibling on the other protocol.
TEST_CASE("dns sid-keying: colliding sessions route to the correct server", "[dns][sid-keying]")
{
  auto t = makeTransport();
  Access::putSession(*t, /*isTcp=*/false, 1, SERVER_A, PORT_A);
  Access::putSession(*t, /*isTcp=*/true, 1, SERVER_B, PORT_B);
  Access::registerPending(*t, ID_A, SERVER_A, PORT_A);
  Access::registerPending(*t, ID_B, SERVER_B, PORT_B);

  SECTION("UDP response on sid=1 completes the serverA query, not the serverB sibling")
  {
    Access::feedUdp(*t, 1, wireWithId(ID_A));
    CHECK_FALSE(Access::hasPending(*t, ID_A, SERVER_A, PORT_A)); // completed via serverA
    CHECK(Access::hasPending(*t, ID_B, SERVER_B, PORT_B));       // untouched
  }

  SECTION("TCP response on sid=1 completes the serverB query, not the serverA sibling")
  {
    Access::feedTcp(*t, 1, framed(wireWithId(ID_B)));
    CHECK_FALSE(Access::hasPending(*t, ID_B, SERVER_B, PORT_B)); // completed via serverB
    CHECK(Access::hasPending(*t, ID_A, SERVER_A, PORT_A));       // untouched
  }
}

// (B) Teardown isolation: closing the TCP session (sid=1) must not tear down the
// colliding, still-live UDP session (sid=1).
TEST_CASE("dns sid-keying: TCP close preserves the colliding UDP sibling", "[dns][sid-keying]")
{
  auto t = makeTransport();
  Access::putSession(*t, /*isTcp=*/false, 1, SERVER_A, PORT_A);
  Access::putSession(*t, /*isTcp=*/true, 1, SERVER_B, PORT_B);

  Access::close(*t, 1, /*isTcp=*/true);

  // TCP side removed...
  CHECK_FALSE(Access::hasSession(*t, /*isTcp=*/true, 1));
  CHECK_FALSE(Access::hasServerSession(*t, SERVER_B, PORT_B, /*isTcp=*/true));
  // ...UDP sibling survives.
  CHECK(Access::hasSession(*t, /*isTcp=*/false, 1));
  CHECK(Access::hasServerSession(*t, SERVER_A, PORT_A, /*isTcp=*/false));
}

// (C) tcpBuffers_ cross-erase: a UDP close of the colliding sid must not erase the
// live TCP session's partially-reassembled buffer; a TCP close still erases its own.
TEST_CASE("dns sid-keying: UDP close preserves the colliding TCP reassembly buffer",
          "[dns][sid-keying]")
{
  auto t = makeTransport();
  Access::putSession(*t, /*isTcp=*/false, 1, SERVER_A, PORT_A);
  Access::putSession(*t, /*isTcp=*/true, 1, SERVER_B, PORT_B);
  // A partial (incomplete) length-prefixed TCP message buffered on TCP sid=1.
  Access::putTcpBuffer(*t, 1, std::vector<std::uint8_t>{0x00, 0x20, 0xDE, 0xAD});
  const std::size_t bufBefore = Access::tcpBufferSize(*t, 1);
  REQUIRE(bufBefore == 4);

  SECTION("UDP close of colliding sid=1 leaves the TCP buffer and TCP mapping intact")
  {
    Access::close(*t, 1, /*isTcp=*/false);
    CHECK(Access::hasTcpBuffer(*t, 1));
    CHECK(Access::tcpBufferSize(*t, 1) == bufBefore);
    CHECK(Access::hasSession(*t, /*isTcp=*/true, 1)); // TCP mapping survives a UDP close
    CHECK_FALSE(Access::hasSession(*t, /*isTcp=*/false, 1)); // UDP mapping removed
  }

  SECTION("TCP close of sid=1 erases its own reassembly buffer")
  {
    Access::close(*t, 1, /*isTcp=*/true);
    CHECK_FALSE(Access::hasTcpBuffer(*t, 1));
  }
}
