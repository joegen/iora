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

/// \brief Parsed WebSocket frame.
struct WebSocketFrame
{
  bool fin = true;
  WsOpcode opcode = WsOpcode::TEXT;
  bool masked = false;
  std::uint8_t maskKey[4] = {0, 0, 0, 0};
  std::vector<std::uint8_t> payload;

  /// \brief Parse a frame from raw bytes.
  /// Returns nullopt if the buffer is incomplete. Sets consumed to bytes used.
  static std::optional<WebSocketFrame> parse(core::BufferView data,
                                             std::size_t& consumed)
  {
    consumed = 0;
    if (data.size() < 2)
    {
      return std::nullopt;
    }

    WebSocketFrame frame;
    std::size_t pos = 0;

    // Byte 0: FIN, RSV, opcode
    std::uint8_t byte0 = data[pos++];
    frame.fin = (byte0 & 0x80) != 0;
    std::uint8_t rsv = (byte0 >> 4) & 0x07;
    if (rsv != 0)
    {
      // RSV bits set without extension — protocol error
      // Return a frame with opcode that signals error to caller
      frame.opcode = static_cast<WsOpcode>(byte0 & 0x0F);
      frame.payload.clear();
      consumed = data.size(); // consume all to prevent re-parse
      return frame; // caller checks RSV via the raw byte if needed
    }
    frame.opcode = static_cast<WsOpcode>(byte0 & 0x0F);

    // Byte 1: MASK, payload length
    std::uint8_t byte1 = data[pos++];
    frame.masked = (byte1 & 0x80) != 0;
    std::uint64_t payloadLen = byte1 & 0x7F;

    // RFC 6455 Section 5.5: control frames MUST have payload <= 125 and FIN=1
    if (isControlFrame(frame.opcode))
    {
      if (payloadLen > 125 || !frame.fin)
      {
        return std::nullopt; // protocol error — caller should close with 1002
      }
    }

    if (payloadLen == 126)
    {
      if (data.size() < pos + 2) return std::nullopt;
      payloadLen = data.readU16BE(pos);
      pos += 2;
    }
    else if (payloadLen == 127)
    {
      if (data.size() < pos + 8) return std::nullopt;
      payloadLen = data.readU64BE(pos);
      pos += 8;
    }

    // Mask key (4 bytes if masked)
    if (frame.masked)
    {
      if (data.size() < pos + 4) return std::nullopt;
      frame.maskKey[0] = data[pos++];
      frame.maskKey[1] = data[pos++];
      frame.maskKey[2] = data[pos++];
      frame.maskKey[3] = data[pos++];
    }

    // Payload
    if (data.size() < pos + payloadLen)
    {
      return std::nullopt; // incomplete
    }

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
  /// If mask is true, applies a random mask key.
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
      // Use stored mask key. Caller must set a non-zero mask key
      // before calling serialize(true) for RFC 6455 compliance.
      // For client-to-server frames, use SecureRng to generate random keys.
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

  /// \brief Validate UTF-8 encoding of the payload.
  /// Returns true if valid UTF-8 (or empty).
  bool isValidUtf8() const
  {
    std::size_t i = 0;
    while (i < payload.size())
    {
      std::uint8_t c = payload[i];
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

      if (i + seqLen > payload.size())
      {
        return false; // truncated
      }

      // Validate continuation bytes
      for (std::size_t j = 1; j < seqLen; ++j)
      {
        if ((payload[i + j] & 0xC0) != 0x80)
        {
          return false;
        }
      }

      // Overlong encoding checks
      if (seqLen == 2 && c < 0xC2)
      {
        return false; // overlong 2-byte
      }
      if (seqLen == 3 && c == 0xE0 && payload[i + 1] < 0xA0)
      {
        return false; // overlong 3-byte (< U+0800)
      }
      if (seqLen == 4 && c == 0xF0 && payload[i + 1] < 0x90)
      {
        return false; // overlong 4-byte (< U+10000)
      }

      // Reject UTF-16 surrogates (U+D800..U+DFFF) encoded as 3-byte sequences
      if (seqLen == 3 && c == 0xED && payload[i + 1] >= 0xA0)
      {
        return false;
      }

      // Reject code points above U+10FFFF
      if (seqLen == 4 && (c > 0xF4 || (c == 0xF4 && payload[i + 1] > 0x8F)))
      {
        return false;
      }

      i += seqLen;
    }
    return true;
  }
};

} // namespace network
} // namespace iora
