// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include "iora/core/buffer_view.hpp"

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace iora {
namespace network {

/// \brief WebSocket frame opcodes (RFC 6455 Section 5.2).
enum class WsOpcode : std::uint8_t
{
  CONTINUATION = 0x0,
  TEXT = 0x1,
  BINARY = 0x2,
  CLOSE = 0x8,
  PING = 0x9,
  PONG = 0xA
};

/// \brief Returns true for Close, Ping, Pong.
inline bool isControlFrame(WsOpcode op)
{
  return op == WsOpcode::CLOSE || op == WsOpcode::PING || op == WsOpcode::PONG;
}

/// \brief Distinguishes an incomplete buffer from a protocol error when parse()
/// returns std::nullopt.
struct WsParseError
{
  bool isError = false;        // false => "incomplete, need more bytes"; true => protocol error, close
  std::uint16_t closeCode = 0; // 1002 protocol error, 1009 message too big
};

/// \brief Parsed WebSocket frame.
struct WebSocketFrame
{
  bool fin = true;
  WsOpcode opcode = WsOpcode::TEXT;
  bool masked = false;
  std::uint8_t maskKey[4] = {0, 0, 0, 0};
  std::vector<std::uint8_t> payload;

  /// \brief Default cap on a single frame's declared payload length (64 MiB).
  static constexpr std::size_t kDefaultMaxFrameSize = 64u * 1024u * 1024u;

  /// \brief Parse a frame from raw bytes (tri-state).
  ///
  /// Sets \p consumed and, when \p outError is non-null, \p *outError on every
  /// path:
  ///   - Ok: returns the frame; consumed = bytes used; outError->isError = false.
  ///   - Incomplete (need more bytes): returns nullopt; consumed = 0;
  ///     outError->isError = false.
  ///   - ProtocolError: returns nullopt; consumed = 0; outError->{isError = true,
  ///     closeCode = ...} (1002 protocol error, 1009 message too big).
  static std::optional<WebSocketFrame> parse(core::BufferView data,
                                             std::size_t& consumed,
                                             std::size_t maxFrameSize = kDefaultMaxFrameSize,
                                             WsParseError* outError = nullptr)
  {
    consumed = 0;
    if (outError != nullptr)
    {
      outError->isError = false;
      outError->closeCode = 0;
    }

    auto protocolError = [&](std::uint16_t code) -> std::optional<WebSocketFrame>
    {
      consumed = 0;
      if (outError != nullptr)
      {
        outError->isError = true;
        outError->closeCode = code;
      }
      return std::nullopt;
    };

    // 1. Need at least the 2-byte fixed header.
    if (data.size() < 2)
    {
      return std::nullopt; // incomplete
    }

    WebSocketFrame frame;
    std::size_t pos = 0;

    // Byte 0: FIN, RSV, opcode
    std::uint8_t byte0 = data[pos++];
    frame.fin = (byte0 & 0x80) != 0;
    std::uint8_t rsv = (byte0 >> 4) & 0x07;
    frame.opcode = static_cast<WsOpcode>(byte0 & 0x0F);

    // 2. RSV bits set without a negotiated extension — protocol error (RFC 6455 §5.2).
    if (rsv != 0)
    {
      return protocolError(1002);
    }

    // 2b. Reject any opcode that is not one of the six defined ones (RFC 6455
    //     §5.2). Centralizes reserved-opcode rejection for BOTH server and client
    //     so neither dispatcher can silently accept an undefined opcode.
    switch (frame.opcode)
    {
    case WsOpcode::CONTINUATION:
    case WsOpcode::TEXT:
    case WsOpcode::BINARY:
    case WsOpcode::CLOSE:
    case WsOpcode::PING:
    case WsOpcode::PONG:
      break;
    default:
      return protocolError(1002);
    }

    // Byte 1: MASK, payload length
    std::uint8_t byte1 = data[pos++];
    frame.masked = (byte1 & 0x80) != 0;
    std::uint64_t payloadLen = byte1 & 0x7F;

    // 3. RFC 6455 §5.5: control frames MUST have payload <= 125 and FIN=1.
    if (isControlFrame(frame.opcode))
    {
      if (payloadLen > 125 || !frame.fin)
      {
        return protocolError(1002);
      }
    }

    // 4. 126-form: 16-bit extended length.
    if (payloadLen == 126)
    {
      if (data.size() < pos + 2)
      {
        return std::nullopt; // incomplete
      }
      payloadLen = data.readU16BE(pos);
      pos += 2;
      // RFC 6455 §5.2: the minimal number of bytes MUST be used to encode the
      // length — a 16-bit form carrying a value <= 125 is a non-minimal
      // encoding and is a protocol error.
      if (payloadLen <= 125)
      {
        return protocolError(1002);
      }
    }
    // 5. 127-form: 64-bit extended length.
    else if (payloadLen == 127)
    {
      if (data.size() < pos + 8)
      {
        return std::nullopt; // incomplete
      }
      payloadLen = data.readU64BE(pos);
      pos += 8;
      // RFC 6455 §5.2: the most significant bit of a 64-bit length MUST be 0.
      if ((payloadLen & 0x8000000000000000ULL) != 0)
      {
        return protocolError(1002);
      }
      // RFC 6455 §5.2: minimal-length encoding — a 64-bit form carrying a value
      // that fits the 16-bit form (<= 0xFFFF) is a non-minimal encoding and is
      // a protocol error.
      if (payloadLen <= 0xFFFFULL)
      {
        return protocolError(1002);
      }
    }

    // 6. Reject an over-large declared length BEFORE any allocation.
    if (payloadLen > maxFrameSize)
    {
      return protocolError(1009);
    }

    // 7. Mask key (4 bytes if masked)
    if (frame.masked)
    {
      if (data.size() < pos + 4)
      {
        return std::nullopt; // incomplete
      }
      frame.maskKey[0] = data[pos++];
      frame.maskKey[1] = data[pos++];
      frame.maskKey[2] = data[pos++];
      frame.maskKey[3] = data[pos++];
    }

    // 8. Payload present? Use subtraction (pos <= data.size() is guaranteed by
    //    the earlier checks) so the bound cannot wrap.
    if (payloadLen > data.size() - pos)
    {
      return std::nullopt; // incomplete
    }

    // 9. Copy + unmask.
    frame.payload.resize(static_cast<std::size_t>(payloadLen));
    if (payloadLen > 0)
    {
      std::memcpy(frame.payload.data(), data.data() + pos, static_cast<std::size_t>(payloadLen));

      // Unmask if needed
      if (frame.masked)
      {
        for (std::size_t i = 0; i < frame.payload.size(); ++i)
        {
          frame.payload[i] ^= frame.maskKey[i % 4];
        }
      }
    }

    pos += static_cast<std::size_t>(payloadLen);
    consumed = pos;
    return frame;
  }

  /// \brief Serialize this frame to wire format.
  /// If \p applyMask is true, masks the payload with the caller-set stored
  /// maskKey (no randomness is generated here — the caller populates maskKey).
  std::vector<std::uint8_t> serialize(bool applyMask = false) const
  {
    std::vector<std::uint8_t> out;
    out.reserve(2 + 8 + 4 + payload.size()); // worst case header size

    // Byte 0: FIN + opcode
    std::uint8_t byte0 = static_cast<std::uint8_t>(opcode);
    if (fin) byte0 |= 0x80;
    out.push_back(byte0);

    // Byte 1: MASK + length
    std::uint8_t byte1 = applyMask ? 0x80 : 0x00;
    if (payload.size() <= 125)
    {
      byte1 |= static_cast<std::uint8_t>(payload.size());
      out.push_back(byte1);
    }
    else if (payload.size() <= 0xFFFF)
    {
      byte1 |= 126;
      out.push_back(byte1);
      out.push_back(static_cast<std::uint8_t>(payload.size() >> 8));
      out.push_back(static_cast<std::uint8_t>(payload.size()));
    }
    else
    {
      byte1 |= 127;
      out.push_back(byte1);
      for (int i = 7; i >= 0; --i)
      {
        out.push_back(static_cast<std::uint8_t>(payload.size() >> (i * 8)));
      }
    }

    // Mask key + masked payload (or plain payload)
    if (applyMask)
    {
      // Masks with the caller-set stored maskKey — no randomness is generated
      // here. The caller MUST populate maskKey (e.g. via SecureRng for
      // client-to-server frames) before calling serialize(true) for RFC 6455
      // compliance.
      out.push_back(maskKey[0]);
      out.push_back(maskKey[1]);
      out.push_back(maskKey[2]);
      out.push_back(maskKey[3]);
      for (std::size_t i = 0; i < payload.size(); ++i)
      {
        out.push_back(payload[i] ^ maskKey[i % 4]);
      }
    }
    else
    {
      out.insert(out.end(), payload.begin(), payload.end());
    }

    return out;
  }

  /// \brief Extract close code and reason from a Close frame payload.
  /// Returns (code, reason). If payload is too short, returns (1005, "").
  std::pair<std::uint16_t, std::string> closePayload() const
  {
    if (payload.size() < 2)
    {
      return {1005, ""}; // No status code received
    }
    std::uint16_t code = (static_cast<std::uint16_t>(payload[0]) << 8)
                       | static_cast<std::uint16_t>(payload[1]);
    std::string reason;
    if (payload.size() > 2)
    {
      reason.assign(payload.begin() + 2, payload.end());
    }
    return {code, reason};
  }

  /// \brief True iff this frame carries a 2-byte close status code.
  bool hasCloseCode() const { return payload.size() >= 2; }

  /// \brief Result of validating an inbound CLOSE frame's payload.
  struct CloseValidation
  {
    bool ok;                 // true => conforming CLOSE
    std::uint16_t failCode;  // when !ok: the code to close with (1002 / 1007)
  };

  /// \brief Validate an inbound CLOSE frame per RFC 6455 §5.5.1 / §7.4. A
  /// non-CLOSE frame and a no-code CLOSE (empty payload) are conforming. A 1-byte
  /// payload is a malformed length (1002). With a code present, an invalid/reserved
  /// code fails 1002 and a non-UTF-8 reason fails 1007.
  CloseValidation validateClose() const
  {
    if (opcode != WsOpcode::CLOSE)
    {
      return {true, 0};
    }
    if (payload.size() == 0)
    {
      return {true, 0}; // no code — valid
    }
    if (payload.size() == 1)
    {
      return {false, 1002}; // malformed length
    }
    std::uint16_t code = closePayload().first;
    if (!isValidCloseCode(code))
    {
      return {false, 1002};
    }
    if (!isValidUtf8(payload.data() + 2, payload.size() - 2))
    {
      return {false, 1007};
    }
    return {true, 0};
  }

  /// \brief Create a Close frame with status code and reason.
  static WebSocketFrame makeClose(std::uint16_t code,
                                  const std::string& reason = "")
  {
    WebSocketFrame frame;
    frame.fin = true;
    frame.opcode = WsOpcode::CLOSE;
    frame.payload.push_back(static_cast<std::uint8_t>(code >> 8));
    frame.payload.push_back(static_cast<std::uint8_t>(code));
    frame.payload.insert(frame.payload.end(), reason.begin(), reason.end());
    return frame;
  }

  /// \brief Create a Close frame with NO status code (empty payload). This is
  /// the correct on-the-wire echo when the peer sent a Close with no code — it
  /// must never put 1005 (or 1006/1015) on the wire.
  static WebSocketFrame makeCloseNoCode()
  {
    WebSocketFrame frame;
    frame.fin = true;
    frame.opcode = WsOpcode::CLOSE;
    return frame;
  }

  /// \brief True iff \p c is a valid close code to send on the wire (RFC 6455
  /// §7.4): 1000-1003, 1007-1011, or 3000-4999. False for reserved/invalid
  /// codes (1004, 1005, 1006, 1012-1015, <1000, 1016-2999).
  static bool isValidCloseCode(std::uint16_t c)
  {
    if (c >= 3000 && c <= 4999)
    {
      return true;
    }
    if (c >= 1000 && c <= 1003)
    {
      return true;
    }
    if (c >= 1007 && c <= 1011)
    {
      return true;
    }
    return false;
  }

  /// \brief Build the correct on-the-wire CLOSE echo for a received CLOSE frame
  /// (RFC 6455 §5.5.1). Dedupes the server/client echo policy: a peer CLOSE with
  /// no status code echoes an empty CLOSE (never 1005/1006/1015); a valid received
  /// code echoes a normal-closure ack (1000); a reserved/invalid received code
  /// echoes a protocol error (1002).
  static WebSocketFrame makeCloseEcho(const WebSocketFrame& received)
  {
    if (!received.hasCloseCode())
    {
      return makeCloseNoCode();
    }
    return makeClose(isValidCloseCode(received.closePayload().first) ? 1000 : 1002);
  }

  /// \brief Create a Ping frame.
  static WebSocketFrame makePing(const std::vector<std::uint8_t>& payload = {})
  {
    WebSocketFrame frame;
    frame.fin = true;
    frame.opcode = WsOpcode::PING;
    frame.payload = payload;
    return frame;
  }

  /// \brief Create a Pong frame matching a Ping's payload.
  static WebSocketFrame makePong(const std::vector<std::uint8_t>& payload = {})
  {
    WebSocketFrame frame;
    frame.fin = true;
    frame.opcode = WsOpcode::PONG;
    frame.payload = payload;
    return frame;
  }

  /// \brief Create a Text frame.
  static WebSocketFrame makeText(const std::string& text, bool fin = true)
  {
    WebSocketFrame frame;
    frame.fin = fin;
    frame.opcode = WsOpcode::TEXT;
    frame.payload.assign(text.begin(), text.end());
    return frame;
  }

  /// \brief Create a Binary frame.
  static WebSocketFrame makeBinary(const std::vector<std::uint8_t>& data,
                                   bool fin = true)
  {
    WebSocketFrame frame;
    frame.fin = fin;
    frame.opcode = WsOpcode::BINARY;
    frame.payload = data;
    return frame;
  }

  /// \brief Create a Continuation frame.
  static WebSocketFrame makeContinuation(const std::vector<std::uint8_t>& data,
                                         bool fin = true)
  {
    WebSocketFrame frame;
    frame.fin = fin;
    frame.opcode = WsOpcode::CONTINUATION;
    frame.payload = data;
    return frame;
  }

  /// \brief Validate UTF-8 encoding of an arbitrary byte range.
  /// Returns true if valid UTF-8 (or empty). This is the single implementation;
  /// the vector overload and the member overload delegate to it, avoiding a
  /// throwaway temp-frame copy at call sites that only have raw bytes.
  static bool isValidUtf8(const std::uint8_t* data, std::size_t len)
  {
    std::size_t i = 0;
    while (i < len)
    {
      std::uint8_t c = data[i];
      std::size_t seqLen = 0;

      if (c <= 0x7F)
      {
        seqLen = 1;
      }
      else if ((c & 0xE0) == 0xC0)
      {
        seqLen = 2;
      }
      else if ((c & 0xF0) == 0xE0)
      {
        seqLen = 3;
      }
      else if ((c & 0xF8) == 0xF0)
      {
        seqLen = 4;
      }
      else
      {
        return false; // invalid leading byte
      }

      if (i + seqLen > len)
      {
        return false; // truncated
      }

      // Validate continuation bytes
      for (std::size_t j = 1; j < seqLen; ++j)
      {
        if ((data[i + j] & 0xC0) != 0x80)
        {
          return false;
        }
      }

      // Overlong encoding checks
      if (seqLen == 2 && c < 0xC2)
      {
        return false; // overlong 2-byte
      }
      if (seqLen == 3 && c == 0xE0 && data[i + 1] < 0xA0)
      {
        return false; // overlong 3-byte (< U+0800)
      }
      if (seqLen == 4 && c == 0xF0 && data[i + 1] < 0x90)
      {
        return false; // overlong 4-byte (< U+10000)
      }

      // Reject UTF-16 surrogates (U+D800..U+DFFF) encoded as 3-byte sequences
      if (seqLen == 3 && c == 0xED && data[i + 1] >= 0xA0)
      {
        return false;
      }

      // Reject code points above U+10FFFF
      if (seqLen == 4 && (c > 0xF4 || (c == 0xF4 && data[i + 1] > 0x8F)))
      {
        return false;
      }

      i += seqLen;
    }
    return true;
  }

  /// \brief Validate UTF-8 encoding of a byte vector. Delegates to the pointer
  /// overload.
  static bool isValidUtf8(const std::vector<std::uint8_t>& v)
  {
    return isValidUtf8(v.data(), v.size());
  }

  /// \brief Validate UTF-8 encoding of this frame's payload. Delegates to the
  /// pointer overload over \c payload.
  bool isValidUtf8() const
  {
    return isValidUtf8(payload.data(), payload.size());
  }
};

} // namespace network
} // namespace iora
