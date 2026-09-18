// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// Tests for iora::network::ip_utils — the IPv4/IPv6 parsers, the unified
/// IpAddress value type, CidrNetwork, and the shared_mutex-guarded
/// TrustedNetworkList. Emphasis on the security-relevant parsing choices
/// (leading-zero rejection, colon-boundary rejection, prefix strictness) and
/// the canonical single-host matching in TrustedNetworkList.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/network/ip_utils.hpp"

using namespace iora::network;

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

TEST_CASE("IPv4::parse accepts well-formed addresses", "[ip_utils][ipv4]")
{
  std::uint32_t v = 0;
  REQUIRE(IPv4::parse("192.168.1.1", v));
  REQUIRE(v == 0xC0A80101u); // host order
  REQUIRE(IPv4::toString(v) == "192.168.1.1");

  REQUIRE(IPv4::parse("0.0.0.0", v));
  REQUIRE(v == 0u);
  REQUIRE(IPv4::parse("255.255.255.255", v));
  REQUIRE(v == 0xFFFFFFFFu);
}

TEST_CASE("IPv4::parse rejects malformed and ambiguous input", "[ip_utils][ipv4][security]")
{
  std::uint32_t v = 0;
  REQUIRE_FALSE(IPv4::parse("", v));
  REQUIRE_FALSE(IPv4::parse("1.2.3", v));       // too few octets
  REQUIRE_FALSE(IPv4::parse("1.2.3.4.5", v));   // too many octets
  REQUIRE_FALSE(IPv4::parse("1.2.3.4x", v));    // trailing char
  REQUIRE_FALSE(IPv4::parse("256.0.0.1", v));   // out of range
  REQUIRE_FALSE(IPv4::parse("1.2.3.999", v));   // out of range
  // Leading-zero rejection (anti-octal): only lone "0" is allowed
  REQUIRE_FALSE(IPv4::parse("010.0.0.1", v));
  REQUIRE_FALSE(IPv4::parse("192.168.001.1", v));
  REQUIRE_FALSE(IPv4::parse("00.0.0.0", v));
  REQUIRE(IPv4::parse("0.0.0.0", v)); // lone zero still fine
}

TEST_CASE("IPv4 classification and CIDR containment", "[ip_utils][ipv4]")
{
  std::uint32_t v = 0;
  REQUIRE(IPv4::parse("10.1.2.3", v));
  REQUIRE(IPv4::isPrivate(v));
  REQUIRE(IPv4::parse("172.16.0.1", v));
  REQUIRE(IPv4::isPrivate(v));
  REQUIRE(IPv4::parse("192.168.5.5", v));
  REQUIRE(IPv4::isPrivate(v));
  REQUIRE(IPv4::parse("8.8.8.8", v));
  REQUIRE_FALSE(IPv4::isPrivate(v));
  REQUIRE(IPv4::parse("127.0.0.1", v));
  REQUIRE(IPv4::isLoopback(v));

  REQUIRE(IPv4::inNetwork("192.168.1.42", "192.168.1.0", 24));
  REQUIRE_FALSE(IPv4::inNetwork("192.168.2.42", "192.168.1.0", 24));
  REQUIRE(IPv4::prefixToNetmask(24) == 0xFFFFFF00u);
  REQUIRE(IPv4::prefixToNetmask(0) == 0u);
  REQUIRE(IPv4::prefixToNetmask(32) == 0xFFFFFFFFu);
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

TEST_CASE("IPv6::parse accepts valid forms", "[ip_utils][ipv6]")
{
  IPv6::Address a{};
  REQUIRE(IPv6::parse("::", a));
  REQUIRE(IPv6::parse("::1", a));
  REQUIRE(IPv6::isLoopback(a));
  REQUIRE(IPv6::parse("2001:db8::1", a));
  REQUIRE(IPv6::parse("2001:0db8:0000:0000:0000:0000:0000:0001", a));
  REQUIRE(IPv6::parse("fe80::1", a));
  REQUIRE(IPv6::isLinkLocal(a));
  REQUIRE(IPv6::parse("fc00::1", a));
  REQUIRE(IPv6::isUniqueLocal(a));
  REQUIRE(IPv6::parse("2001:db8::", a)); // trailing "::" is valid compression
}

TEST_CASE("IPv6::parse rejects stray non-doubled colons (boundary fix)",
          "[ip_utils][ipv6][security]")
{
  IPv6::Address a{};
  // A single leading/trailing/mid colon is NOT the "::" compression and must
  // be rejected as malformed rather than silently skipped.
  REQUIRE_FALSE(IPv6::parse(":1:2:3:4:5:6:7:8", a)); // stray leading colon
  REQUIRE_FALSE(IPv6::parse("1:2:3:4:5:6:7:8:", a)); // stray trailing colon
  REQUIRE_FALSE(IPv6::parse("1::2:", a));            // stray trailing after "::"
  REQUIRE_FALSE(IPv6::parse(":", a));                // lone colon
  // Existing strictness still holds:
  REQUIRE_FALSE(IPv6::parse("1::2::3", a));          // multiple "::"
  REQUIRE_FALSE(IPv6::parse("12345::1", a));         // over-long group
  REQUIRE_FALSE(IPv6::parse("1:2:3:4:5:6:7:8:9", a));// too many groups
  REQUIRE_FALSE(IPv6::parse("gggg::1", a));          // non-hex
}

TEST_CASE("IPv6::parse documents its embedded-IPv4 / zone-id scope",
          "[ip_utils][ipv6]")
{
  // Embedded IPv4 is accepted ONLY in the ::ffff: mapped form (see the accepting
  // test above). These out-of-scope forms are intentionally rejected:
  IPv6::Address a{};
  REQUIRE_FALSE(IPv6::parse("64:ff9b::192.0.2.1", a)); // NAT64, non-mapped embedded v4
  REQUIRE_FALSE(IPv6::parse("::1.2.3.4", a));          // deprecated IPv4-compatible
  REQUIRE_FALSE(IPv6::parse("0:0:0:0:0:ffff:1.2.3.4", a)); // expanded mapped form
  REQUIRE_FALSE(IPv6::parse("fe80::1%eth0", a));       // zone/scope id not parsed
}

TEST_CASE("IPv6::parse handles IPv4-mapped in the ::ffff: form", "[ip_utils][ipv6]")
{
  IPv6::Address a{};
  REQUIRE(IPv6::parse("::ffff:192.168.1.1", a));
  REQUIRE(IPv6::isIPv4Mapped(a));
  REQUIRE(a[10] == 0xff);
  REQUIRE(a[11] == 0xff);
  REQUIRE(a[12] == 192);
  REQUIRE(a[15] == 1);
}

TEST_CASE("IPv6::toString RFC 5952 compression", "[ip_utils][ipv6]")
{
  IPv6::Address a{};
  REQUIRE(IPv6::parse("2001:db8:0:0:0:0:0:1", a));
  REQUIRE(IPv6::toString(a) == "2001:db8::1");
  REQUIRE(IPv6::parse("::", a));
  REQUIRE(IPv6::toString(a) == "::");
  REQUIRE(IPv6::parse("::1", a));
  REQUIRE(IPv6::toString(a) == "::1");
  // First-longest-run wins on a tie: 1:0:0:1:0:0:0:1 -> the SECOND run (len 3).
  REQUIRE(IPv6::parse("1:0:0:1:0:0:0:1", a));
  REQUIRE(IPv6::toString(a) == "1:0:0:1::1");
}

TEST_CASE("IPv6 CIDR containment", "[ip_utils][ipv6]")
{
  REQUIRE(IPv6::inNetwork("2001:db8::5", "2001:db8::", 32));
  REQUIRE_FALSE(IPv6::inNetwork("2001:db9::5", "2001:db8::", 32));
  REQUIRE(IPv6::inNetwork("2001:db8::1", "2001:db8::", 128) == false);
}

// ---------------------------------------------------------------------------
// IpAddress
// ---------------------------------------------------------------------------

TEST_CASE("IpAddress auto-detects family", "[ip_utils][ipaddress]")
{
  IpAddress v4("192.168.1.1");
  REQUIRE(v4.isValid());
  REQUIRE(v4.family() == AddressFamily::IPv4);
  REQUIRE(v4.toString() == "192.168.1.1");

  IpAddress v6("2001:db8::1");
  REQUIRE(v6.isValid());
  REQUIRE(v6.family() == AddressFamily::IPv6);
  REQUIRE(v6.toString() == "2001:db8::1");

  IpAddress bad("not.an.ip");
  REQUIRE_FALSE(bad.isValid());
  REQUIRE(bad.toString().empty());
}

TEST_CASE("IpAddress::inNetwork rejects family mismatch", "[ip_utils][ipaddress]")
{
  IpAddress ip("10.0.0.5");
  IpAddress net4("10.0.0.0");
  IpAddress net6("2001:db8::");
  REQUIRE(ip.inNetwork(net4, 8));
  REQUIRE_FALSE(ip.inNetwork(net6, 8)); // v4 vs v6 -> false
}

TEST_CASE("free helpers isIPv6Address / isValidIpAddress", "[ip_utils]")
{
  REQUIRE(isIPv6Address("::1"));
  REQUIRE_FALSE(isIPv6Address("1.2.3.4"));
  REQUIRE(isValidIpAddress("1.2.3.4"));
  REQUIRE(isValidIpAddress("2001:db8::1"));
  REQUIRE_FALSE(isValidIpAddress("999.1.1.1"));
}

// ---------------------------------------------------------------------------
// CidrNetwork
// ---------------------------------------------------------------------------

TEST_CASE("CidrNetwork::parse accepts valid CIDR and single hosts", "[ip_utils][cidr]")
{
  CidrNetwork n;
  REQUIRE(n.parse("192.168.1.0/24"));
  REQUIRE(n.isValid());
  REQUIRE(n.prefixLength == 24);
  REQUIRE_FALSE(n.isSingleHost());
  REQUIRE(n.contains("192.168.1.42"));
  REQUIRE_FALSE(n.contains("192.168.2.42"));

  CidrNetwork host;
  REQUIRE(host.parse("10.0.0.1")); // no slash -> /32
  REQUIRE(host.prefixLength == 32);
  REQUIRE(host.isSingleHost());

  CidrNetwork v6;
  REQUIRE(v6.parse("2001:db8::/32"));
  REQUIRE(v6.isIPv6());
  REQUIRE(v6.contains("2001:db8::dead"));
  REQUIRE_FALSE(v6.contains("192.168.1.1")); // family mismatch
}

TEST_CASE("CidrNetwork::parse rejects trailing garbage after the prefix (fix)",
          "[ip_utils][cidr][security]")
{
  CidrNetwork n;
  REQUIRE_FALSE(n.parse("10.0.0.0/24garbage"));
  REQUIRE_FALSE(n.parse("10.0.0.0/"));         // empty prefix
  REQUIRE_FALSE(n.parse("10.0.0.0/ 24"));      // leading space
  REQUIRE_FALSE(n.parse("10.0.0.0/+24"));      // sign
  REQUIRE_FALSE(n.parse("10.0.0.0/33"));       // prefix > 32 for IPv4
  REQUIRE_FALSE(n.parse("2001:db8::/129"));    // prefix > 128 for IPv6
  REQUIRE_FALSE(n.parse("10.0.0.0/99999999999999999999")); // out of range
}

// ---------------------------------------------------------------------------
// TrustedNetworkList
// ---------------------------------------------------------------------------

TEST_CASE("TrustedNetworkList single-host IPv4 fast path", "[ip_utils][trusted]")
{
  TrustedNetworkList list;
  REQUIRE_FALSE(list.addCidr("192.168.1.50/32").empty());
  REQUIRE(list.contains("192.168.1.50"));
  REQUIRE_FALSE(list.contains("192.168.1.51"));
  REQUIRE(list.size() == 1);
}

TEST_CASE("TrustedNetworkList matches single IPv6 host across spellings (fix)",
          "[ip_utils][trusted][security]")
{
  TrustedNetworkList list;
  REQUIRE_FALSE(list.addCidr("::1/128").empty());
  // Same address, different textual spelling, must still match.
  REQUIRE(list.contains("::1"));
  REQUIRE(list.contains("0:0:0:0:0:0:0:1"));

  TrustedNetworkList list2;
  REQUIRE_FALSE(list2.addCidr("2001:DB8::1/128").empty()); // uppercase
  REQUIRE(list2.contains("2001:db8::1")); // canonical lowercase query
  REQUIRE_FALSE(list2.contains("2001:db8::2"));
}

TEST_CASE("TrustedNetworkList rejects canonical duplicates (fix)", "[ip_utils][trusted]")
{
  TrustedNetworkList list;
  REQUIRE_FALSE(list.addCidr("::1/128").empty());
  // Different spelling of the same /128 must be rejected as a duplicate.
  REQUIRE(list.addCidr("0:0:0:0:0:0:0:1/128").empty());
  REQUIRE(list.size() == 1);
}

TEST_CASE("TrustedNetworkList CIDR-range matching and lifecycle", "[ip_utils][trusted]")
{
  TrustedNetworkList list;
  std::string id4 = list.addCidr("10.0.0.0/8", "corp");
  std::string id6 = list.addCidr("2001:db8::/32", "v6");
  REQUIRE_FALSE(id4.empty());
  REQUIRE_FALSE(id6.empty());

  REQUIRE(list.contains("10.9.9.9"));
  REQUIRE(list.contains("2001:db8::dead"));
  REQUIRE_FALSE(list.contains("11.0.0.1"));

  // Disable removes from the lookup index but keeps the entry.
  REQUIRE(list.setEnabled(id6, false));
  REQUIRE_FALSE(list.contains("2001:db8::dead"));
  REQUIRE(list.size() == 2);
  REQUIRE(list.setEnabled(id6, true));
  REQUIRE(list.contains("2001:db8::dead"));

  // getById / getAll
  REQUIRE(list.getById(id4).has_value());
  REQUIRE(list.getById("does-not-exist").has_value() == false);
  REQUIRE(list.getAll().size() == 2);

  // Remove by id and by cidr
  REQUIRE(list.removeById(id4));
  REQUIRE_FALSE(list.contains("10.9.9.9"));
  REQUIRE(list.removeByCidr("2001:db8::/32"));
  REQUIRE(list.size() == 0);

  list.addCidr("192.168.0.0/16");
  list.clear();
  REQUIRE(list.size() == 0);
  REQUIRE_FALSE(list.contains("192.168.1.1"));
}
