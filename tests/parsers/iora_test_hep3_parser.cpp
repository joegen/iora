// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include "iora/parsers/hep3.hpp"
#include <catch2/catch.hpp>
#include <cstdint>
#include <string>
#include <vector>

using namespace iora::parsers;
using iora::core::BufferView;

// NOTE ON LIFETIMES: parseHep3 returns a Hep3Message whose `payload` and
// `correlationId` are NON-OWNING views into the caller's buffer (documented
// contract). Every test therefore binds the finalized packet to a NAMED vector
// that outlives the parse Result before reading any view — never parse a
// temporary and then read payload/correlationId (that would be a use-after-free
// in the test, not a parser defect).

namespace
{

void putU16BE(std::vector<std::uint8_t>& b, std::uint16_t v)
{
  b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
  b.push_back(static_cast<std::uint8_t>(v & 0xff));
}

void putU32BE(std::vector<std::uint8_t>& b, std::uint32_t v)
{
  b.push_back(static_cast<std::uint8_t>((v >> 24) & 0xff));
  b.push_back(static_cast<std::uint8_t>((v >> 16) & 0xff));
  b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
  b.push_back(static_cast<std::uint8_t>(v & 0xff));
}

/// \brief Append a chunk (vendorId + typeId + length + payload). `len` defaults
/// to the correct value (payload + 6); pass an override to forge a lying chunk.
void addChunk(std::vector<std::uint8_t>& b, std::uint16_t vendor, std::uint16_t type,
              const std::vector<std::uint8_t>& payload, int lenOverride = -1)
{
  putU16BE(b, vendor);
  putU16BE(b, type);
  const std::uint16_t len =
    lenOverride >= 0 ? static_cast<std::uint16_t>(lenOverride)
                     : static_cast<std::uint16_t>(payload.size() + 6);
  putU16BE(b, len);
  b.insert(b.end(), payload.begin(), payload.end());
}

std::vector<std::uint8_t> u8(std::uint8_t v) { return {v}; }
std::vector<std::uint8_t> u16(std::uint16_t v)
{
  std::vector<std::uint8_t> b;
  putU16BE(b, v);
  return b;
}
std::vector<std::uint8_t> u32(std::uint32_t v)
{
  std::vector<std::uint8_t> b;
  putU32BE(b, v);
  return b;
}
std::vector<std::uint8_t> bytes(std::initializer_list<std::uint8_t> l)
{
  return std::vector<std::uint8_t>(l);
}
std::vector<std::uint8_t> str(const std::string& s)
{
  return std::vector<std::uint8_t>(s.begin(), s.end());
}

/// \brief Finalize: prepend the "HEP3" header + patch the total-length field.
std::vector<std::uint8_t> finalize(std::vector<std::uint8_t> chunks)
{
  std::vector<std::uint8_t> out = {'H', 'E', 'P', '3'};
  const std::uint16_t total = static_cast<std::uint16_t>(chunks.size() + 6);
  putU16BE(out, total);
  out.insert(out.end(), chunks.begin(), chunks.end());
  return out;
}

BufferView view(const std::vector<std::uint8_t>& b)
{
  return BufferView(b.data(), b.size());
}

std::string payloadStr(const Hep3Message& m)
{
  if (m.payload.data() == nullptr || m.payload.size() == 0)
  {
    return std::string();
  }
  return std::string(reinterpret_cast<const char*>(m.payload.data()), m.payload.size());
}

} // namespace

TEST_CASE("HEP3: scaffold compiles and empty input is Incomplete", "[hep3]")
{
  auto r = parseHep3(BufferView());
  REQUIRE(r.isErr());
  REQUIRE(r.error().code == Hep3ErrorCode::Incomplete);
}

TEST_CASE("HEP3: golden IPv4 SIP packet decodes all chunks", "[hep3]")
{
  std::vector<std::uint8_t> c;
  addChunk(c, 0, 0x0001, u8(2));                       // family AF_INET (hint only)
  addChunk(c, 0, 0x0002, u8(17));                      // proto UDP
  addChunk(c, 0, 0x0003, bytes({192, 168, 1, 10}));    // v4 src
  addChunk(c, 0, 0x0004, bytes({192, 168, 1, 20}));    // v4 dst
  addChunk(c, 0, 0x0007, u16(5060));                   // src port
  addChunk(c, 0, 0x0008, u16(5061));                   // dst port
  addChunk(c, 0, 0x0009, u32(1600000000));             // ts sec
  addChunk(c, 0, 0x000a, u32(123456));                 // ts usec
  addChunk(c, 0, 0x000b, u8(0x01));                    // proto-type SIP
  addChunk(c, 0, 0x000c, u32(42));                     // capture agent id
  addChunk(c, 0, 0x0011, str("call-abc@1.2.3.4"));     // correlation id
  addChunk(c, 0, 0x000f, str("INVITE sip:x SIP/2.0")); // payload
  auto pkt = finalize(c);

  auto r = parseHep3(view(pkt));
  REQUIRE(r.isOk());
  const Hep3Message& m = r.value();
  REQUIRE(m.family == Hep3IpFamily::IPv4);
  REQUIRE(m.protocol == 17);
  REQUIRE(m.srcAddr.has_value());
  REQUIRE(m.srcAddr->family == Hep3IpFamily::IPv4);
  REQUIRE(m.srcAddr->bytes[0] == 192);
  REQUIRE(m.srcAddr->bytes[3] == 10);
  REQUIRE(m.dstAddr->bytes[3] == 20);
  REQUIRE(m.srcPort == 5060);
  REQUIRE(m.dstPort == 5061);
  REQUIRE(m.timestampMicros == static_cast<std::uint64_t>(1600000000) * 1000000 + 123456);
  REQUIRE(m.protoTypeRaw == 0x01);
  REQUIRE(m.protoType == Hep3ProtoType::SIP);
  REQUIRE(m.captureAgentId == 42u);
  REQUIRE(m.correlationId.has_value());
  REQUIRE(std::string(reinterpret_cast<const char*>(m.correlationId->data()),
                      m.correlationId->size()) == "call-abc@1.2.3.4");
  REQUIRE(m.payloadStatus == Hep3PayloadStatus::Uncompressed);
  REQUIRE(payloadStr(m) == "INVITE sip:x SIP/2.0");
  REQUIRE(m.messageLength == pkt.size());
}

TEST_CASE("HEP3: IPv6 addresses decode (BSD/macOS family byte 30)", "[hep3]")
{
  std::vector<std::uint8_t> src(16, 0), dst(16, 0);
  src[0] = 0x20; src[1] = 0x01; src[15] = 0x01;
  dst[0] = 0x20; dst[1] = 0x01; dst[15] = 0x02;
  std::vector<std::uint8_t> c;
  addChunk(c, 0, 0x0001, u8(30)); // AF_INET6 on macOS/Darwin — hint only
  addChunk(c, 0, 0x0005, src);
  addChunk(c, 0, 0x0006, dst);
  addChunk(c, 0, 0x000b, u8(0x01));
  auto pkt = finalize(c);
  auto r = parseHep3(view(pkt));
  REQUIRE(r.isOk());
  REQUIRE(r.value().family == Hep3IpFamily::IPv6);
  REQUIRE(r.value().srcAddr->bytes[15] == 0x01);
  REQUIRE(r.value().dstAddr->bytes[15] == 0x02);
}

TEST_CASE("HEP3: proto-type classification + RTCP-as-JSON passthrough", "[hep3]")
{
  auto classify = [](std::uint8_t raw)
  {
    std::vector<std::uint8_t> c;
    addChunk(c, 0, 0x000b, u8(raw));
    auto pkt = finalize(c);
    return parseHep3(view(pkt)).value().protoType;
  };
  REQUIRE(classify(0x01) == Hep3ProtoType::SIP);
  REQUIRE(classify(0x03) == Hep3ProtoType::SDP);
  REQUIRE(classify(0x04) == Hep3ProtoType::RTP);
  REQUIRE(classify(0x05) == Hep3ProtoType::RTCP);
  REQUIRE(classify(0x63) == Hep3ProtoType::OTHER);

  {
    std::vector<std::uint8_t> c;
    addChunk(c, 0, 0x000b, u8(0x63));
    auto pkt = finalize(c);
    REQUIRE(parseHep3(view(pkt)).value().protoTypeRaw == 0x63); // raw byte authoritative
  }

  // RTCP (0x05) carrying a JSON body: raw byte preserved, payload handed through
  // UNTOUCHED for the consumer to content-sniff (parser does not assume binary).
  std::vector<std::uint8_t> c;
  addChunk(c, 0, 0x000b, u8(0x05));
  addChunk(c, 0, 0x000f, str("{\"mos\":4.2}"));
  auto pkt = finalize(c);
  auto r = parseHep3(view(pkt));
  REQUIRE(r.value().protoType == Hep3ProtoType::RTCP);
  REQUIRE(r.value().protoTypeRaw == 0x05);
  REQUIRE(payloadStr(r.value()) == "{\"mos\":4.2}");
}

TEST_CASE("HEP3: auth-key chunk 0x000e is never exposed", "[hep3]")
{
  std::vector<std::uint8_t> c;
  addChunk(c, 0, 0x000e, str("s3cr3t-password")); // auth key
  addChunk(c, 0, 0x000b, u8(0x01));
  addChunk(c, 0, 0x000f, str("body"));
  auto pkt = finalize(c);
  auto r = parseHep3(view(pkt));
  REQUIRE(r.isOk());
  // No struct field carries the auth-key; the message exposes only the payload.
  REQUIRE(payloadStr(r.value()) == "body");
  REQUIRE(r.value().payloadStatus == Hep3PayloadStatus::Uncompressed);
}

TEST_CASE("HEP3: compressed payload is CompressedUnsupported, uncompressed preferred",
          "[hep3]")
{
  SECTION("compressed only -> CompressedUnsupported")
  {
    std::vector<std::uint8_t> c;
    addChunk(c, 0, 0x0010, str("\x78\x9c compressed-bytes"));
    auto pkt = finalize(c);
    auto r = parseHep3(view(pkt));
    REQUIRE(r.isOk());
    REQUIRE(r.value().payloadStatus == Hep3PayloadStatus::CompressedUnsupported);
    REQUIRE(r.value().payload.size() > 0);
  }
  SECTION("both present -> uncompressed wins")
  {
    std::vector<std::uint8_t> c;
    addChunk(c, 0, 0x0010, str("compressed"));
    addChunk(c, 0, 0x000f, str("plain"));
    auto pkt = finalize(c);
    auto r = parseHep3(view(pkt));
    REQUIRE(r.value().payloadStatus == Hep3PayloadStatus::Uncompressed);
    REQUIRE(payloadStr(r.value()) == "plain");
  }
  SECTION("neither present -> None")
  {
    std::vector<std::uint8_t> c;
    addChunk(c, 0, 0x000b, u8(0x01)); // no payload chunk at all
    auto pkt = finalize(c);
    auto r = parseHep3(view(pkt));
    REQUIRE(r.value().payloadStatus == Hep3PayloadStatus::None);
  }
}

TEST_CASE("HEP3: vendor chunks are skipped even when typeId collides", "[hep3]")
{
  std::vector<std::uint8_t> c;
  // Vendor 0x0002 (Kamailio) with a type-id colliding with generic src-port
  // (0x0007) must NOT be decoded as a port.
  addChunk(c, 0x0002, 0x0007, u16(9999));
  addChunk(c, 0x0002, 0x000b, u8(0x02)); // vendor "proto-type" collision, ignored
  addChunk(c, 0, 0x0007, u16(5060));      // the real generic src-port
  addChunk(c, 0, 0x000b, u8(0x01));
  auto pkt = finalize(c);
  auto r = parseHep3(view(pkt));
  REQUIRE(r.isOk());
  REQUIRE(r.value().srcPort == 5060);            // vendor 9999 ignored
  REQUIRE(r.value().protoType == Hep3ProtoType::SIP);
}

TEST_CASE("HEP3: TCP framing — concatenated messages and short buffer", "[hep3]")
{
  std::vector<std::uint8_t> c1;
  addChunk(c1, 0, 0x000b, u8(0x01));
  addChunk(c1, 0, 0x000f, str("first"));
  auto m1 = finalize(c1);

  std::vector<std::uint8_t> c2;
  addChunk(c2, 0, 0x000f, str("second"));
  auto m2 = finalize(c2);

  // Two messages back-to-back on a stream.
  std::vector<std::uint8_t> stream = m1;
  stream.insert(stream.end(), m2.begin(), m2.end());

  auto r1 = parseHep3(view(stream));
  REQUIRE(r1.isOk());
  REQUIRE(r1.value().messageLength == m1.size()); // bytesConsumed == first total
  REQUIRE(payloadStr(r1.value()) == "first");

  // Advance and parse the second.
  BufferView rest(stream.data() + m1.size(), stream.size() - m1.size());
  auto r2 = parseHep3(rest);
  REQUIRE(r2.isOk());
  REQUIRE(payloadStr(r2.value()) == "second");

  // A short buffer (fewer bytes than the declared total) is Incomplete + total.
  BufferView shortBuf(m1.data(), m1.size() - 3);
  auto rs = parseHep3(shortBuf);
  REQUIRE(rs.isErr());
  REQUIRE(rs.error().code == Hep3ErrorCode::Incomplete);
  REQUIRE(rs.error().declaredTotal == m1.size());
}

TEST_CASE("HEP3: structural violations are Malformed", "[hep3]")
{
  SECTION("wrong magic")
  {
    // bytes(), not str() — str() would strlen-truncate at the embedded NUL.
    auto b = bytes({'X', 'E', 'P', '3', 0x00, 0x08, 'z', 'z'});
    auto r = parseHep3(view(b));
    REQUIRE(r.error().code == Hep3ErrorCode::Malformed);
    REQUIRE_FALSE(r.error().declaredTotal.has_value());
  }
  SECTION("HEP1/HEP2-style datagram (no HEP3 magic)")
  {
    auto b = bytes({0x02, 0x10, 0x02, 0x00, 0x11, 0x22});
    REQUIRE(parseHep3(view(b)).error().code == Hep3ErrorCode::Malformed);
  }
  SECTION("total < 6")
  {
    std::vector<std::uint8_t> b = {'H', 'E', 'P', '3'};
    putU16BE(b, 3); // total = 3
    auto r = parseHep3(view(b));
    REQUIRE(r.error().code == Hep3ErrorCode::Malformed);
    REQUIRE_FALSE(r.error().declaredTotal.has_value());
  }
  SECTION("chunk length < 6 (underflow guard) -> Malformed with total")
  {
    std::vector<std::uint8_t> c;
    addChunk(c, 0, 0x000b, u8(0x01), /*lenOverride*/ 3); // lying chunk
    auto pkt = finalize(c);
    auto r = parseHep3(view(pkt));
    REQUIRE(r.error().code == Hep3ErrorCode::Malformed);
    REQUIRE(r.error().declaredTotal == pkt.size());
  }
  SECTION("chunk overruns the message window -> Malformed with total")
  {
    std::vector<std::uint8_t> c;
    addChunk(c, 0, 0x000f, str("hi"), /*lenOverride*/ 200); // claims 200 bytes
    auto pkt = finalize(c);
    auto r = parseHep3(view(pkt));
    REQUIRE(r.error().code == Hep3ErrorCode::Malformed);
    REQUIRE(r.error().declaredTotal == pkt.size());
  }
  SECTION("1-3 byte consistent prefix is Incomplete, not Malformed")
  {
    auto b = str("HE");
    auto r = parseHep3(view(b));
    REQUIRE(r.error().code == Hep3ErrorCode::Incomplete);
  }
}

TEST_CASE("HEP3: known-chunk tolerance — bad length/value leaves field absent", "[hep3]")
{
  SECTION("wrong-length port and family -> fields absent, unit still Ok")
  {
    std::vector<std::uint8_t> c;
    addChunk(c, 0, 0x0007, bytes({1, 2, 3})); // src port wrong length (3, not 2)
    addChunk(c, 0, 0x0003, bytes({1, 2, 3}));  // v4 addr wrong length (3, not 4)
    addChunk(c, 0, 0x000f, str("ok"));
    auto pkt = finalize(c);
    auto r = parseHep3(view(pkt));
    REQUIRE(r.isOk());
    REQUIRE_FALSE(r.value().srcPort.has_value());
    REQUIRE_FALSE(r.value().srcAddr.has_value());
    REQUIRE(r.value().family == Hep3IpFamily::Unknown); // no family evidence
    REQUIRE(payloadStr(r.value()) == "ok");
  }
  SECTION("usec out of range -> seconds kept, usec contributes 0")
  {
    std::vector<std::uint8_t> c;
    addChunk(c, 0, 0x0009, u32(1000));
    addChunk(c, 0, 0x000a, u32(2000000)); // >= 1e6, out of range
    auto pkt = finalize(c);
    auto r = parseHep3(view(pkt));
    REQUIRE(r.value().timestampMicros == static_cast<std::uint64_t>(1000) * 1000000);
  }
  SECTION("absent address chunk -> address unset, not zeroed")
  {
    std::vector<std::uint8_t> c;
    addChunk(c, 0, 0x000b, u8(0x01));
    auto pkt = finalize(c);
    auto r = parseHep3(view(pkt));
    REQUIRE_FALSE(r.value().srcAddr.has_value());
    REQUIRE_FALSE(r.value().dstAddr.has_value());
  }
}

TEST_CASE("HEP3: cross-family precedence and duplicate first-wins", "[hep3]")
{
  SECTION("v4 then v6 -> first (v4) wins the family")
  {
    std::vector<std::uint8_t> v6(16, 0);
    std::vector<std::uint8_t> c;
    addChunk(c, 0, 0x0003, bytes({10, 0, 0, 1})); // v4 src first
    addChunk(c, 0, 0x0005, v6);                    // v6 src later -> ignored
    auto pkt = finalize(c);
    auto r = parseHep3(view(pkt));
    REQUIRE(r.value().family == Hep3IpFamily::IPv4);
    REQUIRE(r.value().srcAddr->family == Hep3IpFamily::IPv4);
  }
  SECTION("duplicate src port -> first wins")
  {
    std::vector<std::uint8_t> c;
    addChunk(c, 0, 0x0007, u16(1111));
    addChunk(c, 0, 0x0007, u16(2222));
    auto pkt = finalize(c);
    auto r = parseHep3(view(pkt));
    REQUIRE(r.value().srcPort == 1111);
  }
}

TEST_CASE("HEP3: defined-but-undecoded chunks are skipped (forward-compat)", "[hep3]")
{
  std::vector<std::uint8_t> c;
  addChunk(c, 0, 0x000d, u16(30));           // keep-alive timer
  addChunk(c, 0, 0x0012, u8(7));             // VLAN id
  addChunk(c, 0, 0x0013, str("group-a"));    // group id
  addChunk(c, 0, 0x00ff, str("future"));     // unknown generic
  addChunk(c, 0, 0x000b, u8(0x01));
  addChunk(c, 0, 0x000f, str("payload"));
  auto pkt = finalize(c);
  auto r = parseHep3(view(pkt));
  REQUIRE(r.isOk());
  REQUIRE(payloadStr(r.value()) == "payload");
  REQUIRE(r.value().protoType == Hep3ProtoType::SIP);
}

TEST_CASE("HEP3: sub-6-byte trailing remainder stops the walk cleanly", "[hep3]")
{
  std::vector<std::uint8_t> c;
  addChunk(c, 0, 0x000f, str("body"));
  c.push_back(0x00); // 3 stray bytes < a chunk header, inside the total window
  c.push_back(0x00);
  c.push_back(0x00);
  auto pkt = finalize(c);
  auto r = parseHep3(view(pkt));
  REQUIRE(r.isOk());
  REQUIRE(payloadStr(r.value()) == "body");
}

TEST_CASE("HEP3: duplicate proto-type -> first wins", "[hep3]")
{
  std::vector<std::uint8_t> c;
  addChunk(c, 0, 0x000b, u8(0x01)); // SIP first
  addChunk(c, 0, 0x000b, u8(0x05)); // RTCP later -> ignored (first-wins)
  auto pkt = finalize(c);
  auto r = parseHep3(view(pkt));
  REQUIRE(r.value().protoTypeRaw == 0x01);
  REQUIRE(r.value().protoType == Hep3ProtoType::SIP);
}

TEST_CASE("HEP3: family byte resolves family when no address chunk present", "[hep3]")
{
  SECTION("AF_INET (2) with ports only")
  {
    std::vector<std::uint8_t> c;
    addChunk(c, 0, 0x0001, u8(2));
    addChunk(c, 0, 0x0007, u16(5060));
    auto pkt = finalize(c);
    auto r = parseHep3(view(pkt));
    REQUIRE(r.value().family == Hep3IpFamily::IPv4);
    REQUIRE_FALSE(r.value().srcAddr.has_value());
  }
  SECTION("AF_INET6 macOS variant (30) with no addresses")
  {
    std::vector<std::uint8_t> c;
    addChunk(c, 0, 0x0001, u8(30));
    auto pkt = finalize(c);
    REQUIRE(parseHep3(view(pkt)).value().family == Hep3IpFamily::IPv6);
  }
  SECTION("address chunk overrides a conflicting family byte")
  {
    std::vector<std::uint8_t> c;
    addChunk(c, 0, 0x0001, u8(30));               // hint says v6
    addChunk(c, 0, 0x0003, bytes({10, 0, 0, 1})); // but a v4 address is present
    auto pkt = finalize(c);
    REQUIRE(parseHep3(view(pkt)).value().family == Hep3IpFamily::IPv4);
  }
}

TEST_CASE("HEP3: valid minimal message (total==6, zero chunks)", "[hep3]")
{
  auto pkt = finalize({});
  REQUIRE(pkt.size() == 6);
  auto r = parseHep3(view(pkt));
  REQUIRE(r.isOk());
  REQUIRE(r.value().messageLength == 6);
  REQUIRE(r.value().payloadStatus == Hep3PayloadStatus::None);
  REQUIRE(r.value().family == Hep3IpFamily::Unknown);
  REQUIRE_FALSE(r.value().srcAddr.has_value());
  REQUIRE_FALSE(r.value().protocol.has_value());
}

TEST_CASE("HEP3: short-prefix lengths classify per the content-only rule", "[hep3]")
{
  // n==1 contradicting the magic -> Malformed.
  REQUIRE(parseHep3(view(bytes({'X'}))).error().code == Hep3ErrorCode::Malformed);
  // n==1 / n==3 consistent prefix -> Incomplete.
  REQUIRE(parseHep3(view(bytes({'H'}))).error().code == Hep3ErrorCode::Incomplete);
  REQUIRE(parseHep3(view(bytes({'H', 'E', 'P'}))).error().code == Hep3ErrorCode::Incomplete);
  // n==4 full magic, total not yet readable -> Incomplete, no declaredTotal.
  {
    auto r = parseHep3(view(bytes({'H', 'E', 'P', '3'})));
    REQUIRE(r.error().code == Hep3ErrorCode::Incomplete);
    REQUIRE_FALSE(r.error().declaredTotal.has_value());
  }
  // n==5, one total byte present -> still Incomplete.
  REQUIRE(parseHep3(view(bytes({'H', 'E', 'P', '3', 0x00}))).error().code ==
          Hep3ErrorCode::Incomplete);
}

TEST_CASE("HEP3: many small chunks -> walk terminates, envelope decoded", "[hep3]")
{
  std::vector<std::uint8_t> c;
  for (int i = 0; i < 2000; ++i)
  {
    addChunk(c, 0, 0x00fe, {}); // 6-byte empty unknown generic chunk
  }
  addChunk(c, 0, 0x000b, u8(0x01));
  auto pkt = finalize(c);
  auto r = parseHep3(view(pkt));
  REQUIRE(r.isOk());
  REQUIRE(r.value().protoType == Hep3ProtoType::SIP);
}

TEST_CASE("HEP3: capture-agent-id and correlation-id absent are unset", "[hep3]")
{
  std::vector<std::uint8_t> c;
  addChunk(c, 0, 0x000b, u8(0x01));
  addChunk(c, 0, 0x000f, str("no-ids"));
  auto pkt = finalize(c);
  auto r = parseHep3(view(pkt));
  REQUIRE_FALSE(r.value().captureAgentId.has_value());
  REQUIRE_FALSE(r.value().correlationId.has_value());
}

TEST_CASE("HEP3: empty payload chunk -> status set, size 0", "[hep3]")
{
  std::vector<std::uint8_t> c;
  addChunk(c, 0, 0x000f, {}); // 0x0f with zero-length payload
  auto pkt = finalize(c);
  auto r = parseHep3(view(pkt));
  REQUIRE(r.isOk());
  REQUIRE(r.value().payloadStatus == Hep3PayloadStatus::Uncompressed);
  REQUIRE(r.value().payload.size() == 0);
}

TEST_CASE("HEP3: literal 'EEP3' magic is rejected", "[hep3]")
{
  auto b = bytes({'E', 'E', 'P', '3', 0x00, 0x06});
  REQUIRE(parseHep3(view(b)).error().code == Hep3ErrorCode::Malformed);
}

TEST_CASE("HEP3: spec-modeled real-agent layouts", "[hep3]")
{
  // MODELED on documented agent behavior (NOT live captures). Tracked for
  // replacement with genuine tcpdump captures: tasks/iora/backlog/2026-09-20-3.
  SECTION("heplify-style SIP: family+proto first, payload last")
  {
    std::vector<std::uint8_t> c;
    addChunk(c, 0, 0x0001, u8(2));                  // heplify emits family
    addChunk(c, 0, 0x0002, u8(17));                 // and proto
    addChunk(c, 0, 0x0003, bytes({10, 0, 0, 1}));
    addChunk(c, 0, 0x0004, bytes({10, 0, 0, 2}));
    addChunk(c, 0, 0x0007, u16(5060));
    addChunk(c, 0, 0x0008, u16(5060));
    addChunk(c, 0, 0x0009, u32(1700000000));
    addChunk(c, 0, 0x000a, u32(500));
    addChunk(c, 0, 0x000b, u8(0x01));               // SIP
    addChunk(c, 0, 0x000c, u32(2001));              // node id
    addChunk(c, 0, 0x0011, str("cid-1"));           // correlation id
    addChunk(c, 0, 0x000f, str("REGISTER sip:x SIP/2.0\r\n\r\n")); // payload last
    auto pkt = finalize(c);
    auto r = parseHep3(view(pkt));
    REQUIRE(r.isOk());
    REQUIRE(r.value().protoType == Hep3ProtoType::SIP);
    REQUIRE(r.value().family == Hep3IpFamily::IPv4);
    REQUIRE(r.value().captureAgentId == 2001u);
    REQUIRE(r.value().srcPort == 5060);
    REQUIRE(payloadStr(r.value()).rfind("REGISTER", 0) == 0);
  }
  SECTION("rtpengine-style RTCP-as-JSON with an interleaved vendor chunk")
  {
    std::vector<std::uint8_t> c;
    addChunk(c, 0, 0x0001, u8(2));
    addChunk(c, 0, 0x0002, u8(17));
    addChunk(c, 0x0007, 0x0001, u32(9)); // vendor chunk (vendor 0x0007) -> skipped
    addChunk(c, 0, 0x0003, bytes({10, 0, 0, 5}));
    addChunk(c, 0, 0x0007, u16(30000));
    addChunk(c, 0, 0x000b, u8(0x05)); // RTCP
    addChunk(c, 0, 0x000f, str("{\"ssrc\":123,\"mos\":4.1}"));
    auto pkt = finalize(c);
    auto r = parseHep3(view(pkt));
    REQUIRE(r.isOk());
    REQUIRE(r.value().protoType == Hep3ProtoType::RTCP);
    REQUIRE(r.value().protoTypeRaw == 0x05);
    REQUIRE(r.value().srcPort == 30000); // vendor chunk did not corrupt the port
    REQUIRE(payloadStr(r.value()) == "{\"ssrc\":123,\"mos\":4.1}");
  }
}

