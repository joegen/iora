// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>

#include "iora/core/buffer_view.hpp"
#include "iora/core/result.hpp"

/// \file hep3.hpp
/// \brief Zero-dependency HEP3 (sipcapture/EEP) capture-transport envelope parser.
///
/// HEP3 is the de-facto (NON-RFC) sipcapture protocol used by capture agents
/// (HOMER/heplify, captagent, kamailio, FreeSWITCH, rtpengine, ...) to ship
/// already-framed application units (SIP messages, RTCP reports, SBC quality
/// metrics) to a collector over UDP/TCP/SCTP. Wire format (HEP3 rev12):
///
///   general header : "HEP3" magic (0x48455033) + u16 TOTAL length (network byte
///                    order; counts the whole message INCLUDING the 6-byte header).
///   then a sequence of TLV chunks, each:
///     u16 vendorId + u16 typeId + u16 length   (all network byte order)
///   where `length` is the TOTAL chunk length INCLUDING its own 6-byte header,
///   so the chunk payload length is `length - 6` and `length < 6` is malformed.
///   Generic chunks carry vendorId == 0x0000; any non-zero vendorId is a
///   VENDOR chunk whose typeId lives in the vendor's own namespace and MUST be
///   skipped (its typeId may collide with a generic typeId).
///
/// This parser EXTRACTS the envelope (addresses, ports, protocol, timestamp,
/// capture-agent id, correlation id) and CLASSIFIES the captured payload by the
/// proto-type discriminator (chunk 0x000b). It does NOT parse the payload:
/// a SIP payload is handed to the SIP parser by the consumer; an RTCP payload
/// to the RTCP parser; the JSON-vs-binary distinction (a common RTCP-over-HEP
/// case) is a consumer content-sniff, not a proto-type value. The captured
/// payload is exposed as a non-owning BufferView into the caller's buffer.
///
/// The parser is TRANSPORT-AGNOSTIC and NON-THROWING: it decides status from
/// buffer contents alone and returns a Result. A HEP-over-TCP consumer uses the
/// returned message length (bytesConsumed) to re-frame a stream of concatenated
/// messages, and maps `Incomplete` to "await more bytes" (TCP) or "drop" (UDP).

namespace iora
{
namespace parsers
{

/// \brief Classified captured-payload protocol (chunk 0x000b), best-effort.
/// The raw byte is authoritative (see Hep3Message::protoTypeRaw); this enum is a
/// convenience. Values per HEP3 rev12: SIP=1, SDP=3, RTP=4, RTCP=5.
enum class Hep3ProtoType : std::uint8_t
{
  SIP,
  SDP,
  RTP,
  RTCP,
  OTHER
};

/// \brief Availability of the captured payload on a successfully-parsed message.
/// A compressed or absent payload is a valid Ok(Hep3Message) — the ENVELOPE
/// (addresses, correlation id, capture-agent id) still survives so downstream
/// correlation/binding works; it is never a parse error.
enum class Hep3PayloadStatus : std::uint8_t
{
  None,                 ///< No payload chunk (neither 0x000f nor 0x0010) present.
  Uncompressed,         ///< 0x000f present; `payload` is the captured bytes.
  CompressedUnsupported ///< 0x0010 present; `payload` is the RAW compressed bytes
                        ///< (zlib). In-parser inflation is out of scope (zero-dep);
                        ///< decompression is a consumer concern.
};

/// \brief Resolved IP family, determined authoritatively by which address chunk
/// is present (NOT by the OS-dependent numeric family byte in chunk 0x0001).
enum class Hep3IpFamily : std::uint8_t
{
  Unknown,
  IPv4,
  IPv6
};

/// \brief A captured IP address. `family` selects how many bytes of `bytes` are
/// significant: IPv4 uses bytes[0..3], IPv6 uses bytes[0..15].
struct Hep3Address
{
  Hep3IpFamily family = Hep3IpFamily::Unknown;
  std::array<std::uint8_t, 16> bytes{};
};

/// \brief A successfully-parsed HEP3 message envelope. All decoded metadata
/// fields are optional and left UNSET (not silently zeroed) when their chunk is
/// absent or malformed, so a consumer can tell "0" from "not present".
struct Hep3Message
{
  Hep3IpFamily family = Hep3IpFamily::Unknown;    ///< First address chunk's family.
  std::optional<std::uint8_t> protocol;           ///< 0x0002 (IPPROTO_UDP/TCP).
  std::optional<Hep3Address> srcAddr;             ///< 0x0003 (v4) / 0x0005 (v6).
  std::optional<Hep3Address> dstAddr;             ///< 0x0004 (v4) / 0x0006 (v6).
  std::optional<std::uint16_t> srcPort;           ///< 0x0007.
  std::optional<std::uint16_t> dstPort;           ///< 0x0008.
  std::optional<std::uint64_t> timestampMicros;   ///< 0x0009 sec*1e6 + 0x000a usec.
  std::uint8_t protoTypeRaw = 0;                   ///< 0x000b raw value (authoritative).
  Hep3ProtoType protoType = Hep3ProtoType::OTHER;  ///< Convenience classification.
  Hep3PayloadStatus payloadStatus = Hep3PayloadStatus::None;
  iora::core::BufferView payload;                  ///< 0x000f/0x0010 payload (non-owning).
  std::optional<iora::core::BufferView> correlationId; ///< 0x0011 (agent-populated).
  std::optional<std::uint32_t> captureAgentId;    ///< 0x000c NodeID.
  std::uint16_t messageLength = 0;                 ///< Total length == bytesConsumed.
};

/// \brief Parse outcome discriminator.
enum class Hep3ErrorCode : std::uint8_t
{
  Incomplete, ///< Not (yet) a full message: consistent-but-short input. A TCP
              ///< consumer awaits more bytes; a UDP consumer drops.
  Malformed   ///< Structurally invalid: contradicts the magic, total < 6, or an
              ///< inner chunk lies about its length. Never a partial-read.
};

/// \brief Parse error. `declaredTotal` carries the message's declared total
/// length when it was readable (>= 6 bytes present): for `Incomplete` it lets a
/// TCP consumer size its next read; for a `Malformed` message with otherwise
/// valid outer framing (a lying inner chunk) it lets the consumer skip that many
/// bytes and resync. It is absent for a magic-contradiction or total-<6 error.
struct Hep3ParseError
{
  Hep3ErrorCode code = Hep3ErrorCode::Malformed;
  std::optional<std::uint16_t> declaredTotal;
};

using Hep3Result = iora::core::Result<Hep3Message, Hep3ParseError>;

namespace detail
{

/// \brief The 6-byte generic/vendor chunk header.
inline constexpr std::size_t HEP3_CHUNK_HEADER = 6;
/// \brief The general header: 4-byte magic + 2-byte total length.
inline constexpr std::size_t HEP3_GENERAL_HEADER = 6;
inline constexpr std::uint16_t HEP3_VENDOR_GENERIC = 0x0000;

// Generic chunk type ids (vendorId == 0x0000).
inline constexpr std::uint16_t CHUNK_IP_FAMILY = 0x0001;
inline constexpr std::uint16_t CHUNK_PROTOCOL = 0x0002;
inline constexpr std::uint16_t CHUNK_IPV4_SRC = 0x0003;
inline constexpr std::uint16_t CHUNK_IPV4_DST = 0x0004;
inline constexpr std::uint16_t CHUNK_IPV6_SRC = 0x0005;
inline constexpr std::uint16_t CHUNK_IPV6_DST = 0x0006;
inline constexpr std::uint16_t CHUNK_SRC_PORT = 0x0007;
inline constexpr std::uint16_t CHUNK_DST_PORT = 0x0008;
inline constexpr std::uint16_t CHUNK_TS_SEC = 0x0009;
inline constexpr std::uint16_t CHUNK_TS_USEC = 0x000a;
inline constexpr std::uint16_t CHUNK_PROTO_TYPE = 0x000b;
inline constexpr std::uint16_t CHUNK_CAPTURE_AGENT = 0x000c;
inline constexpr std::uint16_t CHUNK_AUTH_KEY = 0x000e; // SECRET — never decoded/exposed.
inline constexpr std::uint16_t CHUNK_PAYLOAD = 0x000f;
inline constexpr std::uint16_t CHUNK_PAYLOAD_COMPRESSED = 0x0010;
inline constexpr std::uint16_t CHUNK_CORRELATION_ID = 0x0011;

inline constexpr std::uint32_t USEC_PER_SEC = 1000000u;

inline Hep3ProtoType classifyProtoType(std::uint8_t raw) noexcept
{
  switch (raw)
  {
    case 0x01:
      return Hep3ProtoType::SIP;
    case 0x03:
      return Hep3ProtoType::SDP;
    case 0x04:
      return Hep3ProtoType::RTP;
    case 0x05:
      return Hep3ProtoType::RTCP;
    default:
      return Hep3ProtoType::OTHER;
  }
}

inline Hep3Result makeErr(Hep3ErrorCode code,
                          std::optional<std::uint16_t> declaredTotal) noexcept
{
  return Hep3Result::err(Hep3ParseError{code, declaredTotal});
}

} // namespace detail

/// \brief Parse a single HEP3 message from `buf`.
///
/// Status is decided from `buf` contents alone (the parser cannot know its
/// transport):
///   - bytes contradict the "HEP3" magic prefix        -> Malformed (no total)
///   - a consistent magic prefix but fewer than 6 bytes -> Incomplete (no total)
///   - magic OK but declared total < 6                  -> Malformed (no total)
///   - magic OK but buffer shorter than total           -> Incomplete (total set)
///   - magic OK and buffer >= total                     -> walk chunks, then Ok
///     (or Malformed with total set if an inner chunk lies about its length).
///
/// On success, `bytesConsumed`/messageLength equals the declared total; a
/// consumer re-framing a TCP stream advances by that many bytes.
inline Hep3Result parseHep3(iora::core::BufferView buf) noexcept
{
  using namespace iora::parsers::detail;

  static constexpr std::uint8_t MAGIC[4] = {'H', 'E', 'P', '3'};

  // ── General header: magic + total, content-only status ───────────────────
  const std::size_t n = buf.size();
  const std::size_t cmp = n < 4 ? n : 4;
  // Compare the available prefix (min(n,4) bytes) against the "HEP3" magic. Both
  // views have length cmp, so a short-but-consistent prefix is NOT a mismatch —
  // it falls through to the n<6 Incomplete check below. An empty buffer compares
  // equal (both empty) and is likewise treated as Incomplete.
  if (buf.subview(0, cmp) != iora::core::BufferView(MAGIC, cmp))
  {
    return makeErr(Hep3ErrorCode::Malformed, std::nullopt);
  }
  if (n < HEP3_GENERAL_HEADER)
  {
    // Consistent prefix of "HEP3" but the total-length field is not yet readable.
    return makeErr(Hep3ErrorCode::Incomplete, std::nullopt);
  }

  const std::uint16_t total = buf.readU16BEChecked(4).value(); // safe: n >= 6 checked above
  if (total < HEP3_GENERAL_HEADER)
  {
    return makeErr(Hep3ErrorCode::Malformed, std::nullopt);
  }
  if (n < total)
  {
    // Complete magic + total, but the message body has not fully arrived.
    return makeErr(Hep3ErrorCode::Incomplete, total);
  }

  // ── Chunk walk, bounded to the [6, total) message window ─────────────────
  // (NOT buffer end: a TCP buffer may hold the next message's bytes after total.)
  Hep3Message msg;
  msg.messageLength = total;

  std::optional<std::uint32_t> tsSec;
  std::optional<std::uint32_t> tsUsec;
  std::optional<Hep3IpFamily> familyHint; // from the 0x0001 byte; only a fallback
  bool sawProtoType = false;              // enforce first-wins on proto-type (0x000b)

  std::size_t off = HEP3_GENERAL_HEADER;
  while (off < total)
  {
    if (total - off < HEP3_CHUNK_HEADER)
    {
      // 0 < remainder < 6: cannot form a chunk header. Stop and accept what we
      // decoded (only structural violations are Malformed).
      break;
    }

    // safe: total-off >= HEP3_CHUNK_HEADER (checked above) and n >= total, so
    // off+6 <= total <= n — all three 2-byte reads are in bounds.
    const std::uint16_t vendorId = buf.readU16BEChecked(off).value();
    const std::uint16_t typeId = buf.readU16BEChecked(off + 2).value();
    const std::uint16_t clen = buf.readU16BEChecked(off + 4).value();

    if (clen < HEP3_CHUNK_HEADER)
    {
      // A chunk cannot be smaller than its own header — a lying chunk.
      return makeErr(Hep3ErrorCode::Malformed, total);
    }
    if (off + clen > total)
    {
      // Chunk overruns the message window.
      return makeErr(Hep3ErrorCode::Malformed, total);
    }

    const std::size_t payOff = off + HEP3_CHUNK_HEADER;
    const std::size_t payLen = static_cast<std::size_t>(clen) - HEP3_CHUNK_HEADER;
    const iora::core::BufferView chunk = buf.subview(payOff, payLen);

    // Generic chunks only decode when vendorId == 0x0000; any vendor chunk is
    // skipped by length (its typeId lives in the vendor's own namespace and may
    // collide with a generic typeId).
    if (vendorId == HEP3_VENDOR_GENERIC)
    {
      switch (typeId)
      {
        case CHUNK_PROTOCOL:
          if (!msg.protocol && payLen == 1)
          {
            msg.protocol = chunk.readU8Checked(0);
          }
          break;

        case CHUNK_IPV4_SRC:
        case CHUNK_IPV4_DST:
        case CHUNK_IPV6_SRC:
        case CHUNK_IPV6_DST:
        {
          const bool isV6 =
            (typeId == CHUNK_IPV6_SRC || typeId == CHUNK_IPV6_DST);
          const bool isSrc =
            (typeId == CHUNK_IPV4_SRC || typeId == CHUNK_IPV6_SRC);
          const std::size_t addrLen = isV6 ? 16u : 4u;
          const Hep3IpFamily fam =
            isV6 ? Hep3IpFamily::IPv6 : Hep3IpFamily::IPv4;

          // Wrong length -> field absent, no family evidence (tolerance).
          if (payLen != addrLen)
          {
            break;
          }
          // Cross-family precedence: the first well-formed address chunk sets
          // the family; a later conflicting-family address chunk is ignored.
          if (msg.family != Hep3IpFamily::Unknown && msg.family != fam)
          {
            break;
          }
          std::optional<Hep3Address>& slot = isSrc ? msg.srcAddr : msg.dstAddr;
          if (slot)
          {
            break; // first-wins for duplicates
          }
          Hep3Address addr;
          addr.family = fam;
          // safe: payLen == addrLen == chunk.size() (verified above), addrLen <= 16.
          std::copy(chunk.begin(), chunk.end(), addr.bytes.begin());
          slot = addr;
          if (msg.family == Hep3IpFamily::Unknown)
          {
            msg.family = fam;
          }
          break;
        }

        case CHUNK_SRC_PORT:
          if (!msg.srcPort && payLen == 2)
          {
            msg.srcPort = chunk.readU16BEChecked(0);
          }
          break;

        case CHUNK_DST_PORT:
          if (!msg.dstPort && payLen == 2)
          {
            msg.dstPort = chunk.readU16BEChecked(0);
          }
          break;

        case CHUNK_TS_SEC:
          if (!tsSec && payLen == 4)
          {
            tsSec = chunk.readU32BEChecked(0);
          }
          break;

        case CHUNK_TS_USEC:
          if (!tsUsec && payLen == 4)
          {
            tsUsec = chunk.readU32BEChecked(0);
          }
          break;

        case CHUNK_PROTO_TYPE:
          if (!sawProtoType && payLen == 1)
          {
            // safe: payLen == 1 guarantees the single byte is present.
            msg.protoTypeRaw = chunk.readU8Checked(0).value();
            msg.protoType = classifyProtoType(msg.protoTypeRaw);
            sawProtoType = true; // first-wins for a duplicate 0x000b
          }
          break;

        case CHUNK_CAPTURE_AGENT:
          if (!msg.captureAgentId && payLen == 4)
          {
            msg.captureAgentId = chunk.readU32BEChecked(0);
          }
          break;

        case CHUNK_PAYLOAD:
          // Uncompressed payload wins over any compressed payload and over a
          // duplicate; only the first uncompressed chunk is taken.
          if (msg.payloadStatus != Hep3PayloadStatus::Uncompressed)
          {
            msg.payload = chunk;
            msg.payloadStatus = Hep3PayloadStatus::Uncompressed;
          }
          break;

        case CHUNK_PAYLOAD_COMPRESSED:
          // Recognized but not inflated; only sets the payload if no payload
          // (uncompressed or compressed) has been seen yet.
          if (msg.payloadStatus == Hep3PayloadStatus::None)
          {
            msg.payload = chunk;
            msg.payloadStatus = Hep3PayloadStatus::CompressedUnsupported;
          }
          break;

        case CHUNK_CORRELATION_ID:
          if (!msg.correlationId)
          {
            msg.correlationId = chunk;
          }
          break;

        case CHUNK_IP_FAMILY:
          // Only a HINT: address-chunk presence is authoritative. Tolerate the
          // OS-dependent family constants (AF_INET=2; AF_INET6 = 10 Linux /
          // 23 Windows / 28 FreeBSD / 30 macOS). Applied as a fallback after the
          // walk, only when no address chunk resolved the family.
          if (!familyHint && payLen == 1)
          {
            const std::uint8_t fam = chunk.readU8Checked(0).value(); // safe: payLen==1
            if (fam == 2)
            {
              familyHint = Hep3IpFamily::IPv4;
            }
            else if (fam == 10 || fam == 23 || fam == 28 || fam == 30)
            {
              familyHint = Hep3IpFamily::IPv6;
            }
          }
          break;

        case CHUNK_AUTH_KEY:
        default:
          // 0x000e auth-key is a secret and is never decoded or exposed.
          // Everything else (0x000d/0x0012/0x0013/unknown) is skipped by length
          // for forward-compatibility.
          break;
      }
    }

    off += clen;
  }

  // Address-chunk presence is authoritative for the family; fall back to the
  // 0x0001 family-byte hint only when no address chunk resolved it (e.g. a
  // metrics/QoS unit carrying ports but no address chunks).
  if (msg.family == Hep3IpFamily::Unknown && familyHint)
  {
    msg.family = *familyHint;
  }

  // Timestamp: seconds are required; an out-of-range or absent microseconds
  // field contributes 0 rather than discarding the timestamp.
  if (tsSec)
  {
    const std::uint32_t usec =
      (tsUsec && *tsUsec < USEC_PER_SEC) ? *tsUsec : 0u;
    msg.timestampMicros =
      static_cast<std::uint64_t>(*tsSec) * USEC_PER_SEC + usec;
  }

  return Hep3Result::ok(std::move(msg));
}

/// \brief Convenience overload taking a raw pointer + size.
inline Hep3Result parseHep3(const std::uint8_t* data, std::size_t size) noexcept
{
  return parseHep3(iora::core::BufferView(data, size));
}

} // namespace parsers
} // namespace iora
