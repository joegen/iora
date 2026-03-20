// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for WebSocket frame parser/serializer

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/network/websocket_frame.hpp>
#include <iora/crypto/secure_rng.hpp>
#include <iora/util/base64.hpp>

using namespace iora::network;
using namespace iora::core;

// ══════════════════════════════════════════════════════════════════════════════
// Parse / Serialize Roundtrip
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Frame: text frame roundtrip", "[ws][frame]")
{
  auto frame = WebSocketFrame::makeText("Hello");
  auto wire = frame.serialize();

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  auto parsed = WebSocketFrame::parse(view, consumed);

  REQUIRE(parsed.has_value());
  REQUIRE(consumed == wire.size());
  REQUIRE(parsed->fin);
  REQUIRE(parsed->opcode == WsOpcode::TEXT);
  REQUIRE_FALSE(parsed->masked);
  std::string text(parsed->payload.begin(), parsed->payload.end());
  REQUIRE(text == "Hello");
}

TEST_CASE("WS Frame: binary frame roundtrip", "[ws][frame]")
{
  std::vector<std::uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
  auto frame = WebSocketFrame::makeBinary(data);
  auto wire = frame.serialize();

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  auto parsed = WebSocketFrame::parse(view, consumed);

  REQUIRE(parsed.has_value());
  REQUIRE(parsed->opcode == WsOpcode::BINARY);
  REQUIRE(parsed->payload == data);
}

TEST_CASE("WS Frame: close frame roundtrip", "[ws][frame]")
{
  auto frame = WebSocketFrame::makeClose(1000, "normal");
  auto wire = frame.serialize();

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  auto parsed = WebSocketFrame::parse(view, consumed);

  REQUIRE(parsed.has_value());
  REQUIRE(parsed->opcode == WsOpcode::CLOSE);
  auto [code, reason] = parsed->closePayload();
  REQUIRE(code == 1000);
  REQUIRE(reason == "normal");
}

TEST_CASE("WS Frame: ping/pong roundtrip", "[ws][frame]")
{
  auto ping = WebSocketFrame::makePing({0x01, 0x02});
  auto pongWire = WebSocketFrame::makePong(ping.payload).serialize();

  BufferView view(pongWire.data(), pongWire.size());
  std::size_t consumed = 0;
  auto parsed = WebSocketFrame::parse(view, consumed);

  REQUIRE(parsed.has_value());
  REQUIRE(parsed->opcode == WsOpcode::PONG);
  REQUIRE(parsed->payload == std::vector<std::uint8_t>{0x01, 0x02});
}

// ══════════════════════════════════════════════════════════════════════════════
// Length Encodings
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Frame: 7-bit length (0-125)", "[ws][frame][length]")
{
  std::string text(100, 'A');
  auto frame = WebSocketFrame::makeText(text);
  auto wire = frame.serialize();

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  auto parsed = WebSocketFrame::parse(view, consumed);

  REQUIRE(parsed.has_value());
  REQUIRE(parsed->payload.size() == 100);
}

TEST_CASE("WS Frame: 16-bit length (126-65535)", "[ws][frame][length]")
{
  std::string text(300, 'B');
  auto frame = WebSocketFrame::makeText(text);
  auto wire = frame.serialize();

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  auto parsed = WebSocketFrame::parse(view, consumed);

  REQUIRE(parsed.has_value());
  REQUIRE(parsed->payload.size() == 300);
}

TEST_CASE("WS Frame: 64-bit length (>65535)", "[ws][frame][length]")
{
  std::vector<std::uint8_t> data(70000, 0xCC);
  auto frame = WebSocketFrame::makeBinary(data);
  auto wire = frame.serialize();

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  auto parsed = WebSocketFrame::parse(view, consumed);

  REQUIRE(parsed.has_value());
  REQUIRE(parsed->payload.size() == 70000);
}

// ══════════════════════════════════════════════════════════════════════════════
// Masking
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Frame: masked frame encode/decode", "[ws][frame][mask]")
{
  auto frame = WebSocketFrame::makeText("Hello");
  frame.maskKey[0] = 0x37;
  frame.maskKey[1] = 0xFA;
  frame.maskKey[2] = 0x21;
  frame.maskKey[3] = 0x3D;
  auto wire = frame.serialize(true); // apply mask

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  auto parsed = WebSocketFrame::parse(view, consumed);

  REQUIRE(parsed.has_value());
  REQUIRE(parsed->masked);
  // parse() unmasks automatically
  std::string text(parsed->payload.begin(), parsed->payload.end());
  REQUIRE(text == "Hello");
}

// ══════════════════════════════════════════════════════════════════════════════
// Incomplete Frame
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Frame: incomplete frame returns nullopt", "[ws][frame]")
{
  auto frame = WebSocketFrame::makeText("Hello World");
  auto wire = frame.serialize();

  // Truncate to 3 bytes (header only, no payload)
  BufferView view(wire.data(), 3);
  std::size_t consumed = 0;
  auto parsed = WebSocketFrame::parse(view, consumed);

  REQUIRE_FALSE(parsed.has_value());
  REQUIRE(consumed == 0);
}

TEST_CASE("WS Frame: empty buffer returns nullopt", "[ws][frame]")
{
  BufferView view;
  std::size_t consumed = 0;
  REQUIRE_FALSE(WebSocketFrame::parse(view, consumed).has_value());
}

// ══════════════════════════════════════════════════════════════════════════════
// Close Frame Payload
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Frame: close with no payload", "[ws][frame]")
{
  WebSocketFrame frame;
  frame.fin = true;
  frame.opcode = WsOpcode::CLOSE;
  // empty payload
  auto [code, reason] = frame.closePayload();
  REQUIRE(code == 1005);
  REQUIRE(reason.empty());
}

// ══════════════════════════════════════════════════════════════════════════════
// Fragmentation
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Frame: fragmented message parse", "[ws][frame][fragment]")
{
  // Fragment 1: Text with FIN=0
  auto frag1 = WebSocketFrame::makeText("Hel", false);
  // Fragment 2: Continuation with FIN=0
  auto frag2 = WebSocketFrame::makeContinuation({'l', 'o'}, false);
  // Fragment 3: Continuation with FIN=1
  auto frag3 = WebSocketFrame::makeContinuation({' ', 'W', 'S'}, true);

  auto w1 = frag1.serialize();
  auto w2 = frag2.serialize();
  auto w3 = frag3.serialize();

  // Parse each
  std::size_t consumed;
  auto p1 = WebSocketFrame::parse(BufferView(w1.data(), w1.size()), consumed);
  REQUIRE(p1.has_value());
  REQUIRE_FALSE(p1->fin);
  REQUIRE(p1->opcode == WsOpcode::TEXT);

  auto p2 = WebSocketFrame::parse(BufferView(w2.data(), w2.size()), consumed);
  REQUIRE(p2.has_value());
  REQUIRE_FALSE(p2->fin);
  REQUIRE(p2->opcode == WsOpcode::CONTINUATION);

  auto p3 = WebSocketFrame::parse(BufferView(w3.data(), w3.size()), consumed);
  REQUIRE(p3.has_value());
  REQUIRE(p3->fin);
  REQUIRE(p3->opcode == WsOpcode::CONTINUATION);
}

TEST_CASE("WS Frame: control frame interleaved with fragments", "[ws][frame][fragment]")
{
  auto frag1 = WebSocketFrame::makeText("Hel", false);
  auto ping = WebSocketFrame::makePing();
  auto frag2 = WebSocketFrame::makeContinuation({'l', 'o'}, true);

  auto w1 = frag1.serialize();
  auto wp = ping.serialize();
  auto w2 = frag2.serialize();

  // Concatenate all into one buffer
  std::vector<std::uint8_t> buf;
  buf.insert(buf.end(), w1.begin(), w1.end());
  buf.insert(buf.end(), wp.begin(), wp.end());
  buf.insert(buf.end(), w2.begin(), w2.end());

  BufferView view(buf.data(), buf.size());
  std::size_t consumed;
  std::size_t offset = 0;

  auto p1 = WebSocketFrame::parse(BufferView(view.data() + offset, view.size() - offset), consumed);
  REQUIRE(p1.has_value());
  REQUIRE(p1->opcode == WsOpcode::TEXT);
  offset += consumed;

  auto pp = WebSocketFrame::parse(BufferView(view.data() + offset, view.size() - offset), consumed);
  REQUIRE(pp.has_value());
  REQUIRE(pp->opcode == WsOpcode::PING);
  offset += consumed;

  auto p2 = WebSocketFrame::parse(BufferView(view.data() + offset, view.size() - offset), consumed);
  REQUIRE(p2.has_value());
  REQUIRE(p2->opcode == WsOpcode::CONTINUATION);
  REQUIRE(p2->fin);
}

// ══════════════════════════════════════════════════════════════════════════════
// UTF-8 Validation
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Frame: valid UTF-8 passes", "[ws][frame][utf8]")
{
  auto frame = WebSocketFrame::makeText("Hello 世界");
  REQUIRE(frame.isValidUtf8());
}

TEST_CASE("WS Frame: invalid UTF-8 rejects", "[ws][frame][utf8]")
{
  WebSocketFrame frame;
  frame.opcode = WsOpcode::TEXT;
  frame.payload = {0xFF, 0xFE}; // invalid UTF-8
  REQUIRE_FALSE(frame.isValidUtf8());
}

TEST_CASE("WS Frame: surrogate halves rejected", "[ws][frame][utf8]")
{
  WebSocketFrame frame;
  frame.opcode = WsOpcode::TEXT;
  // U+D800 encoded as UTF-8: ED A0 80
  frame.payload = {0xED, 0xA0, 0x80};
  REQUIRE_FALSE(frame.isValidUtf8());
}

TEST_CASE("WS Frame: overlong 3-byte sequence rejected", "[ws][frame][utf8]")
{
  WebSocketFrame frame;
  frame.opcode = WsOpcode::TEXT;
  // Overlong encoding of U+0000: E0 80 80
  frame.payload = {0xE0, 0x80, 0x80};
  REQUIRE_FALSE(frame.isValidUtf8());
}

TEST_CASE("WS Frame: overlong 4-byte sequence rejected", "[ws][frame][utf8]")
{
  WebSocketFrame frame;
  frame.opcode = WsOpcode::TEXT;
  // Overlong encoding of U+0000: F0 80 80 80
  frame.payload = {0xF0, 0x80, 0x80, 0x80};
  REQUIRE_FALSE(frame.isValidUtf8());
}

TEST_CASE("WS Frame: empty payload is valid UTF-8", "[ws][frame][utf8]")
{
  auto frame = WebSocketFrame::makeText("");
  REQUIRE(frame.isValidUtf8());
}

// ══════════════════════════════════════════════════════════════════════════════
// Zero-Length Payload
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Frame: zero-length ping roundtrip", "[ws][frame]")
{
  auto frame = WebSocketFrame::makePing();
  auto wire = frame.serialize();

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  auto parsed = WebSocketFrame::parse(view, consumed);

  REQUIRE(parsed.has_value());
  REQUIRE(parsed->opcode == WsOpcode::PING);
  REQUIRE(parsed->payload.empty());
}

TEST_CASE("WS Frame: zero-length close roundtrip", "[ws][frame]")
{
  WebSocketFrame frame;
  frame.fin = true;
  frame.opcode = WsOpcode::CLOSE;
  auto wire = frame.serialize();

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  auto parsed = WebSocketFrame::parse(view, consumed);

  REQUIRE(parsed.has_value());
  REQUIRE(parsed->opcode == WsOpcode::CLOSE);
  REQUIRE(parsed->payload.empty());
}

// ══════════════════════════════════════════════════════════════════════════════
// isControlFrame
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Frame: isControlFrame", "[ws][frame]")
{
  REQUIRE(isControlFrame(WsOpcode::CLOSE));
  REQUIRE(isControlFrame(WsOpcode::PING));
  REQUIRE(isControlFrame(WsOpcode::PONG));
  REQUIRE_FALSE(isControlFrame(WsOpcode::TEXT));
  REQUIRE_FALSE(isControlFrame(WsOpcode::BINARY));
  REQUIRE_FALSE(isControlFrame(WsOpcode::CONTINUATION));
}

// ══════════════════════════════════════════════════════════════════════════════
// SHA-1 + Base64 for WebSocket Handshake
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("SHA-1: known test vector", "[ws][crypto]")
{
  unsigned char out[20];
  iora::crypto::SecureRng::sha1("", out);
  // SHA-1 of empty string = da39a3ee5e6b4b0d3255bfef95601890afd80709
  REQUIRE(out[0] == 0xda);
  REQUIRE(out[1] == 0x39);
  REQUIRE(out[19] == 0x09);
}

TEST_CASE("Base64: standard encoding with padding", "[ws][crypto]")
{
  // "Hello" -> "SGVsbG8="
  std::string input = "Hello";
  auto encoded = iora::util::Base64::encode(
    reinterpret_cast<const std::uint8_t*>(input.data()), input.size());
  REQUIRE(encoded == "SGVsbG8=");
}

TEST_CASE("Base64: RFC 6455 handshake example", "[ws][crypto]")
{
  // From RFC 6455 Section 4.2.2:
  // Key: "dGhlIHNhbXBsZSBub25jZQ=="
  // GUID: "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  // SHA-1(key + GUID) -> Base64 = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
  std::string key = "dGhlIHNhbXBsZSBub25jZQ==";
  std::string guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  std::string concat = key + guid;

  unsigned char sha1Out[20];
  iora::crypto::SecureRng::sha1(concat, sha1Out);

  auto accept = iora::util::Base64::encode(sha1Out, 20);
  REQUIRE(accept == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}
