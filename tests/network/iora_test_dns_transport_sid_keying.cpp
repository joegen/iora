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
/// sid == 1. Before the fix, _sessionToServer was keyed by a bare SessionId and
/// handleClose erased _serverSessions/_tcpBuffers ignoring the protocol, so a
/// colliding UDP/TCP sid pair aliased each other's server mapping (wrong-server
/// attribution) and one protocol's close tore down the other's still-live state.
///
/// These tests are WHITE-BOX and deterministic (no real sockets, no timing): they
/// drive the private I/O-thread handlers directly and inspect the private per-session
/// maps via the DnsTransportTestAccess friend seam, so the exact collision
/// is reproduced without flakiness. They cover the tracker test_plan assertions:
///   (A) routing / no-misattribution across a colliding (UDP sid=1, TCP sid=1) pair;
///   (B) teardown isolation -- a TCP close must not tear down the UDP sibling;
///   (C) _tcpBuffers cross-erase -- a UDP close must not erase the TCP sibling's
///       partially-reassembled buffer, while a TCP close still erases its own.
/// Non-vacuity (RED-against-unfixed) is demonstrated separately by targeted mutation
/// of each fixed site (see the tracker); the assertions below pin the fixed behavior.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "dns_transport_test_access.hpp" // shared white-box seam (SM-M1)

#include "iora/network/dns/dns_message.hpp"
#include "iora/network/dns/dns_types.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>


using namespace iora::network::dns;
using Access = iora::network::dns::DnsTransportTestAccess;

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

// (C) _tcpBuffers cross-erase: a UDP close of the colliding sid must not erase the
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
