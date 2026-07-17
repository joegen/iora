// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// Tests for iora::network::sockaddr_utils — the shared sockaddr_storage <->
/// TransportAddress conversion. addressFromSockaddr replaced byte-identical
/// private copies in tcp_engine.hpp and udp_engine.hpp, plus a third copy in
/// iora_media's RTP transport binding; toSockaddr is the shared implementation
/// of the opposite direction, whose in-library consumption is not yet finished
/// (see the header).
///
/// These live here, with the API, rather than in the consumer that prompted the
/// lift: it is public foundation API, its byte order is easy to get subtly wrong
/// in a way that only shows up as traffic going to the wrong host, and the
/// isValid()==false leg is a real branch that callers depend on.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/network/sockaddr_utils.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>

using iora::network::addressFromSockaddr;
using iora::network::toSockaddr;
using iora::network::TransportAddress;

TEST_CASE("toSockaddr builds an IPv4 sockaddr with correct NETWORK byte order",
          "[network][sockaddr]")
{
  sockaddr_storage ss{};
  socklen_t sl = 0;
  REQUIRE(toSockaddr(TransportAddress{"192.0.2.133", 5060}, ss, sl));

  REQUIRE(sl == sizeof(sockaddr_in));
  const auto *sa4 = reinterpret_cast<const sockaddr_in *>(&ss);
  CHECK(sa4->sin_family == AF_INET);
  CHECK(sa4->sin_port == htons(5060));

  // The load-bearing assertion. IpAddress::ipv4() is HOST order, so the
  // implementation must htonl() it; a missing or doubled swap yields a valid-
  // looking sockaddr pointing at an entirely different host (2.133.0.192 here),
  // which no type system catches and which only shows up as traffic vanishing.
  in_addr expected{};
  REQUIRE(::inet_pton(AF_INET, "192.0.2.133", &expected) == 1);
  CHECK(sa4->sin_addr.s_addr == expected.s_addr);
}

TEST_CASE("toSockaddr builds an IPv6 sockaddr with the address bytes intact",
          "[network][sockaddr]")
{
  sockaddr_storage ss{};
  socklen_t sl = 0;
  REQUIRE(toSockaddr(TransportAddress{"2001:db8::a:1", 5061}, ss, sl));

  REQUIRE(sl == sizeof(sockaddr_in6));
  const auto *sa6 = reinterpret_cast<const sockaddr_in6 *>(&ss);
  CHECK(sa6->sin6_family == AF_INET6);
  CHECK(sa6->sin6_port == htons(5061));

  in6_addr expected{};
  REQUIRE(::inet_pton(AF_INET6, "2001:db8::a:1", &expected) == 1);
  CHECK(std::memcmp(&sa6->sin6_addr, &expected, sizeof(expected)) == 0);
}

TEST_CASE("toSockaddr FAILS on anything that is not an IP literal",
          "[network][sockaddr]")
{
  // The documented failure leg callers branch on (iora_media's RTP send() early-
  // returns on it, treating an unresolved destination as a drop). It is the ONLY
  // way a caller learns the conversion did not happen, so it must actually fire.
  //
  // POISON `ss` FIRST. Value-initializing it (`sockaddr_storage ss{}`) makes the
  // zeroed-out assertion below VACUOUS: the buffer is already all-zero, so the
  // check passes even with toSockaddr's std::memset deleted. Poisoning is what
  // makes it test the guarantee rather than the initializer — and the guarantee is
  // load-bearing, because a caller that ignores the return value must not be left
  // holding a PREVIOUS destination and silently send media to it.
  sockaddr_storage ss;
  std::memset(&ss, 0xAB, sizeof(ss));
  socklen_t sl = 0xFFFF;

  SECTION("a hostname is NOT resolved — this function never does DNS")
  {
    CHECK_FALSE(toSockaddr(TransportAddress{"example.com", 5060}, ss, sl));
  }
  SECTION("an empty host")
  {
    CHECK_FALSE(toSockaddr(TransportAddress{"", 5060}, ss, sl));
  }
  SECTION("a malformed literal")
  {
    CHECK_FALSE(toSockaddr(TransportAddress{"192.0.2.999", 5060}, ss, sl));
  }

  // On failure `out` is zeroed rather than left with the poison, and outLen is
  // reset — so a caller that ignored the return value cannot reuse stale bytes.
  CHECK(sl == 0);
  sockaddr_storage zero{};
  CHECK(std::memcmp(&ss, &zero, sizeof(zero)) == 0);
}

TEST_CASE("addressFromSockaddr renders IPv4 and IPv6 back", "[network][sockaddr]")
{
  SECTION("IPv4")
  {
    sockaddr_storage ss{};
    auto *sa4 = reinterpret_cast<sockaddr_in *>(&ss);
    sa4->sin_family = AF_INET;
    sa4->sin_port = htons(1234);
    REQUIRE(::inet_pton(AF_INET, "198.51.100.7", &sa4->sin_addr) == 1);

    const auto addr = addressFromSockaddr(ss);
    CHECK(addr.host == "198.51.100.7");
    CHECK(addr.port == 1234);
  }

  SECTION("IPv6")
  {
    sockaddr_storage ss{};
    auto *sa6 = reinterpret_cast<sockaddr_in6 *>(&ss);
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons(4321);
    REQUIRE(::inet_pton(AF_INET6, "2001:db8::1", &sa6->sin6_addr) == 1);

    const auto addr = addressFromSockaddr(ss);
    CHECK(addr.host == "2001:db8::1");
    CHECK(addr.port == 4321);
  }

  SECTION("an unsupported family yields a default-constructed address")
  {
    sockaddr_storage ss{};
    ss.ss_family = AF_UNIX;
    const auto addr = addressFromSockaddr(ss);
    CHECK(addr.host.empty());
    CHECK(addr.port == 0);
  }
}

TEST_CASE("toSockaddr and addressFromSockaddr ROUND-TRIP", "[network][sockaddr]")
{
  // The two halves are used as a pair on the media path (build a destination,
  // then read back a peer's source), so they must agree with each other — a
  // matched pair of byte-order bugs would pass each test above in isolation.
  const auto cases = {
    TransportAddress{"127.0.0.1", 5060},   TransportAddress{"192.0.2.133", 1},
    TransportAddress{"255.255.255.255", 65535},
    TransportAddress{"::1", 5061},         TransportAddress{"2001:db8::a:1", 40000},
  };
  for (const auto &in : cases)
  {
    sockaddr_storage ss{};
    socklen_t sl = 0;
    REQUIRE(toSockaddr(in, ss, sl));
    const auto out = addressFromSockaddr(ss);
    CHECK(out.host == in.host);
    CHECK(out.port == in.port);
  }
}
