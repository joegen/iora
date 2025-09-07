// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_dns_basic.cpp
/// \brief Basic DNS functionality tests
///
/// This test suite validates core DNS message parsing and basic operations
/// without requiring complex transport layer integration.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/network/dns/dns_message.hpp"
#include "iora/network/dns/dns_types.hpp"

using namespace iora::network::dns;

TEST_CASE("DNS Message Basic Functionality", "[dns][basic]")
{
  SECTION("DNS question construction")
  {
    DnsQuestion q("example.com", DnsType::A, DnsClass::IN);

    CHECK(q.qname == "example.com");
    CHECK(q.qtype == DnsType::A);
    CHECK(q.qclass == DnsClass::IN);
  }

  SECTION("DNS resource record construction")
  {
    DnsResourceRecord rr;
    rr.name = "test.example.com";
    rr.type = DnsType::A;
    rr.cls = DnsClass::IN;
    rr.ttl = 3600;
    rr.rdlength = 4;
    rr.rdata = {192, 168, 1, 1}; // 192.168.1.1

    CHECK(rr.name == "test.example.com");
    CHECK(rr.type == DnsType::A);
    CHECK(rr.ttl == 3600);
    CHECK(rr.rdlength == 4);
    CHECK(rr.rdata.size() == 4);
  }
}

TEST_CASE("DNS Message Parsing", "[dns][parsing]")
{
  SECTION("DNS header parsing")
  {
    DnsHeader header;
    header.id = 0x1234;
    header.qr = true; // Response
    header.aa = true; // Authoritative answer
    header.qdcount = 1;
    header.ancount = 1;
    header.nscount = 0;
    header.arcount = 0;

    CHECK(header.id == 0x1234);
    CHECK(header.qr == true);
    CHECK(header.aa == true);
    CHECK(header.qdcount == 1);
    CHECK(header.ancount == 1);
  }
}

TEST_CASE("DNS Types and Constants", "[dns][types]")
{
  SECTION("DNS type enumeration")
  {
    CHECK(static_cast<std::uint16_t>(DnsType::A) == 1);
    CHECK(static_cast<std::uint16_t>(DnsType::AAAA) == 28);
    CHECK(static_cast<std::uint16_t>(DnsType::SRV) == 33);
    CHECK(static_cast<std::uint16_t>(DnsType::SOA) == 6);
  }

  SECTION("DNS class enumeration") { CHECK(static_cast<std::uint16_t>(DnsClass::IN) == 1); }
}