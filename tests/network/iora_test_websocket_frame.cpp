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
// Tri-state parse() protocol errors + maxFrameSize
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Frame: 64-bit length with MSB set is protocol error 1002", "[ws][frame][parse]")
{
  // FIN + BINARY, unmasked, 127-form length with the MSB of the 64-bit length set.
  std::vector<std::uint8_t> wire = {
    0x82,                                           // FIN + BINARY
    0x7F,                                           // len = 127 (64-bit follows)
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01  // MSB set (invalid per RFC 6455 §5.2)
  };

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  WsParseError err;
  auto parsed = WebSocketFrame::parse(view, consumed, WebSocketFrame::kDefaultMaxFrameSize, &err);

  REQUIRE_FALSE(parsed.has_value());
  REQUIRE(consumed == 0);
  REQUIRE(err.isError);
  REQUIRE(err.closeCode == 1002);
}

TEST_CASE("WS Frame: non-minimal 16-bit length (value <= 125) is protocol error 1002",
          "[ws][frame][parse]")
{
  // FIN + BINARY, 126-form carrying 5 — a value that fits the 7-bit form, so the
  // 16-bit encoding is non-minimal (RFC 6455 §5.2 minimal-length-encoding MUST).
  std::vector<std::uint8_t> wire = {
    0x82,       // FIN + BINARY
    0x7E,       // len = 126 (16-bit follows)
    0x00, 0x05  // 5 (should have used the 7-bit form)
  };

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  WsParseError err;
  auto parsed = WebSocketFrame::parse(view, consumed, WebSocketFrame::kDefaultMaxFrameSize, &err);

  REQUIRE_FALSE(parsed.has_value());
  REQUIRE(consumed == 0);
  REQUIRE(err.isError);
  REQUIRE(err.closeCode == 1002);
}

TEST_CASE("WS Frame: non-minimal 64-bit length (value <= 0xFFFF) is protocol error 1002",
          "[ws][frame][parse]")
{
  // FIN + BINARY, 127-form carrying 256 — a value that fits the 16-bit form, so the
  // 64-bit encoding is non-minimal (RFC 6455 §5.2 minimal-length-encoding MUST).
  std::vector<std::uint8_t> wire = {
    0x82,                                           // FIN + BINARY
    0x7F,                                           // len = 127 (64-bit follows)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00  // 256 (should have used the 16-bit form)
  };

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  WsParseError err;
  auto parsed = WebSocketFrame::parse(view, consumed, WebSocketFrame::kDefaultMaxFrameSize, &err);

  REQUIRE_FALSE(parsed.has_value());
  REQUIRE(consumed == 0);
  REQUIRE(err.isError);
  REQUIRE(err.closeCode == 1002);
}

TEST_CASE("WS Frame: 16-bit length carrying exactly 125 is protocol error 1002 (reject boundary)",
          "[ws][frame][parse][length]")
{
  // The exact non-minimal reject boundary for the 16-bit form: 125 still fits the
  // 7-bit form, so a 126-form carrying 125 MUST be rejected. Pins the `<= 125`
  // predicate against a `< 125` off-by-one.
  std::vector<std::uint8_t> wire = {
    0x82,       // FIN + BINARY
    0x7E,       // len = 126 (16-bit follows)
    0x00, 0x7D  // 125 (largest value that still fits the 7-bit form)
  };

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  WsParseError err;
  auto parsed = WebSocketFrame::parse(view, consumed, WebSocketFrame::kDefaultMaxFrameSize, &err);

  REQUIRE_FALSE(parsed.has_value());
  REQUIRE(consumed == 0);
  REQUIRE(err.isError);
  REQUIRE(err.closeCode == 1002);
}

TEST_CASE("WS Frame: 64-bit length carrying exactly 0xFFFF is protocol error 1002 (reject boundary)",
          "[ws][frame][parse][length]")
{
  // The exact non-minimal reject boundary for the 64-bit form: 0xFFFF still fits the
  // 16-bit form, so a 127-form carrying 65535 MUST be rejected. Pins the `<= 0xFFFF`
  // predicate against a `< 0xFFFF` off-by-one.
  std::vector<std::uint8_t> wire = {
    0x82,                                           // FIN + BINARY
    0x7F,                                           // len = 127 (64-bit follows)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF  // 65535 (largest value that fits the 16-bit form)
  };

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  WsParseError err;
  auto parsed = WebSocketFrame::parse(view, consumed, WebSocketFrame::kDefaultMaxFrameSize, &err);

  REQUIRE_FALSE(parsed.has_value());
  REQUIRE(consumed == 0);
  REQUIRE(err.isError);
  REQUIRE(err.closeCode == 1002);
}

TEST_CASE("WS Frame: minimal 16-bit length (126, value 126) parses",
          "[ws][frame][parse][length]")
{
  // The smallest value that legitimately requires the 16-bit form: 126.
  std::vector<std::uint8_t> payload(126, 0x61); // 126 'a' bytes
  std::vector<std::uint8_t> wire = {0x82, 0x7E, 0x00, 0x7E};
  wire.insert(wire.end(), payload.begin(), payload.end());

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  WsParseError err;
  auto parsed = WebSocketFrame::parse(view, consumed, WebSocketFrame::kDefaultMaxFrameSize, &err);

  REQUIRE(parsed.has_value());
  REQUIRE_FALSE(err.isError);
  REQUIRE(parsed->payload.size() == 126);
}

TEST_CASE("WS Frame: minimal 64-bit length (127, value 65536) parses",
          "[ws][frame][parse][length]")
{
  // The smallest value that legitimately requires the 64-bit form: 65536.
  std::vector<std::uint8_t> payload(65536, 0x62); // 65536 'b' bytes
  std::vector<std::uint8_t> wire = {
    0x82, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
  wire.insert(wire.end(), payload.begin(), payload.end());

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  WsParseError err;
  auto parsed = WebSocketFrame::parse(view, consumed, WebSocketFrame::kDefaultMaxFrameSize, &err);

  REQUIRE(parsed.has_value());
  REQUIRE_FALSE(err.isError);
  REQUIRE(parsed->payload.size() == 65536);
}

TEST_CASE("WS Frame: maximal 16-bit length (126, value 65535) parses (accept boundary)",
          "[ws][frame][parse][length]")
{
  // The largest value the 16-bit form may legitimately carry: 65535. Guards against
  // a spurious upper-bound reject on the 126-form.
  std::vector<std::uint8_t> payload(65535, 0x63); // 65535 'c' bytes
  std::vector<std::uint8_t> wire = {0x82, 0x7E, 0xFF, 0xFF};
  wire.insert(wire.end(), payload.begin(), payload.end());

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  WsParseError err;
  auto parsed = WebSocketFrame::parse(view, consumed, WebSocketFrame::kDefaultMaxFrameSize, &err);

  REQUIRE(parsed.has_value());
  REQUIRE_FALSE(err.isError);
  REQUIRE(parsed->payload.size() == 65535);
}

TEST_CASE("WS Frame: declared length over maxFrameSize is 1009 regardless of payload presence",
          "[ws][frame][parse]")
{
  // 126-form declaring 2000 bytes, but only the header is present. The size check
  // precedes the payload-present check, so this is 1009 (message too big), not
  // "incomplete".
  std::vector<std::uint8_t> wire = {
    0x82,        // FIN + BINARY
    0x7E,        // len = 126 (16-bit follows)
    0x07, 0xD0   // 2000
  };

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  WsParseError err;
  auto parsed = WebSocketFrame::parse(view, consumed, /*maxFrameSize=*/1024, &err);

  REQUIRE_FALSE(parsed.has_value());
  REQUIRE(consumed == 0);
  REQUIRE(err.isError);
  REQUIRE(err.closeCode == 1009);
}

TEST_CASE("WS Frame: RSV bit set is protocol error 1002", "[ws][frame][parse]")
{
  // byte0 = FIN + RSV1 + TEXT: 0x80 | 0x40 | 0x01 = 0xC1.
  std::vector<std::uint8_t> wire = {0xC1, 0x00};

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  WsParseError err;
  auto parsed = WebSocketFrame::parse(view, consumed, WebSocketFrame::kDefaultMaxFrameSize, &err);

  REQUIRE_FALSE(parsed.has_value());
  REQUIRE(consumed == 0);
  REQUIRE(err.isError);
  REQUIRE(err.closeCode == 1002);
}

TEST_CASE("WS Frame: control frame with 126-length field is protocol error 1002",
          "[ws][frame][parse]")
{
  // PING (0x9) with FIN, 7-bit length field = 126 (a control frame may not use an
  // extended length). This is a protocol error, distinguishable from incomplete.
  std::vector<std::uint8_t> wire = {0x89, 0x7E};

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  WsParseError err;
  auto parsed = WebSocketFrame::parse(view, consumed, WebSocketFrame::kDefaultMaxFrameSize, &err);

  REQUIRE_FALSE(parsed.has_value());
  REQUIRE(consumed == 0);
  REQUIRE(err.isError);
  REQUIRE(err.closeCode == 1002);
}

TEST_CASE("WS Frame: hasCloseCode / isValidCloseCode / makeCloseNoCode", "[ws][frame][close]")
{
  WebSocketFrame empty;
  empty.opcode = WsOpcode::CLOSE;
  REQUIRE_FALSE(empty.hasCloseCode());

  auto withCode = WebSocketFrame::makeClose(1000);
  REQUIRE(withCode.hasCloseCode());

  REQUIRE(WebSocketFrame::isValidCloseCode(1000));
  REQUIRE_FALSE(WebSocketFrame::isValidCloseCode(1005));
  REQUIRE_FALSE(WebSocketFrame::isValidCloseCode(1006));
  REQUIRE(WebSocketFrame::isValidCloseCode(3000));
  REQUIRE_FALSE(WebSocketFrame::isValidCloseCode(1015));

  auto noCode = WebSocketFrame::makeCloseNoCode();
  REQUIRE(noCode.opcode == WsOpcode::CLOSE);
  REQUIRE(noCode.payload.empty());
  REQUIRE_FALSE(noCode.hasCloseCode());
}

TEST_CASE("WS Frame: reserved data opcode 0x3 is protocol error 1002", "[ws][frame][parse]")
{
  // FIN + reserved data opcode 0x3, unmasked, zero-length. parse() must reject it
  // (RFC 6455 §5.2) — not silently accept an undefined opcode.
  std::vector<std::uint8_t> wire = {0x83, 0x00};

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  WsParseError err;
  auto parsed = WebSocketFrame::parse(view, consumed, WebSocketFrame::kDefaultMaxFrameSize, &err);

  REQUIRE_FALSE(parsed.has_value());
  REQUIRE(consumed == 0);
  REQUIRE(err.isError);
  REQUIRE(err.closeCode == 1002);
}

TEST_CASE("WS Frame: reserved control opcode 0xB is protocol error 1002", "[ws][frame][parse]")
{
  // FIN + reserved control opcode 0xB, unmasked, zero-length.
  std::vector<std::uint8_t> wire = {0x8B, 0x00};

  BufferView view(wire.data(), wire.size());
  std::size_t consumed = 0;
  WsParseError err;
  auto parsed = WebSocketFrame::parse(view, consumed, WebSocketFrame::kDefaultMaxFrameSize, &err);

  REQUIRE_FALSE(parsed.has_value());
  REQUIRE(consumed == 0);
  REQUIRE(err.isError);
  REQUIRE(err.closeCode == 1002);
}

// ══════════════════════════════════════════════════════════════════════════════
// validateClose (RFC 6455 §5.5.1 / §7.4)
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Frame: validateClose accepts no-code and code+reason", "[ws][frame][close]")
{
  WebSocketFrame noCode;
  noCode.opcode = WsOpcode::CLOSE; // empty payload
  auto v0 = noCode.validateClose();
  REQUIRE(v0.ok);
  REQUIRE(v0.failCode == 0);

  auto withReason = WebSocketFrame::makeClose(1000, "bye");
  auto v1 = withReason.validateClose();
  REQUIRE(v1.ok);
  REQUIRE(v1.failCode == 0);
}

TEST_CASE("WS Frame: validateClose rejects 1-byte payload with 1002", "[ws][frame][close]")
{
  WebSocketFrame f;
  f.opcode = WsOpcode::CLOSE;
  f.payload = {0x03}; // malformed length (only 1 byte)
  auto v = f.validateClose();
  REQUIRE_FALSE(v.ok);
  REQUIRE(v.failCode == 1002);
}

TEST_CASE("WS Frame: validateClose rejects invalid code with 1002", "[ws][frame][close]")
{
  // 1005 is a reserved code that MUST NOT appear on the wire.
  WebSocketFrame f;
  f.opcode = WsOpcode::CLOSE;
  f.payload = {0x03, 0xED}; // 0x03ED == 1005
  auto v = f.validateClose();
  REQUIRE_FALSE(v.ok);
  REQUIRE(v.failCode == 1002);
}

TEST_CASE("WS Frame: validateClose rejects invalid-UTF-8 reason with 1007", "[ws][frame][close]")
{
  WebSocketFrame f;
  f.opcode = WsOpcode::CLOSE;
  // code 1000 (0x03E8) followed by an invalid UTF-8 reason (0xFF 0xFE).
  f.payload = {0x03, 0xE8, 0xFF, 0xFE};
  auto v = f.validateClose();
  REQUIRE_FALSE(v.ok);
  REQUIRE(v.failCode == 1007);
}

TEST_CASE("WS Frame: validateClose passes valid code + valid reason", "[ws][frame][close]")
{
  auto f = WebSocketFrame::makeClose(1001, "going away");
  auto v = f.validateClose();
  REQUIRE(v.ok);
  REQUIRE(v.failCode == 0);
}

// ══════════════════════════════════════════════════════════════════════════════
// makeCloseEcho
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Frame: makeCloseEcho maps received close to the correct echo",
          "[ws][frame][close]")
{
  // No code -> empty CLOSE (never 1005/1006/1015).
  WebSocketFrame noCode;
  noCode.opcode = WsOpcode::CLOSE;
  auto echo0 = WebSocketFrame::makeCloseEcho(noCode);
  REQUIRE(echo0.opcode == WsOpcode::CLOSE);
  REQUIRE(echo0.payload.empty());
  REQUIRE_FALSE(echo0.hasCloseCode());

  // Valid received code -> normal-closure ack (1000).
  auto valid = WebSocketFrame::makeClose(1000, "bye");
  auto echo1 = WebSocketFrame::makeCloseEcho(valid);
  REQUIRE(echo1.closePayload().first == 1000);

  // Invalid/reserved received code -> protocol error (1002).
  auto invalid = WebSocketFrame::makeClose(1005);
  auto echo2 = WebSocketFrame::makeCloseEcho(invalid);
  REQUIRE(echo2.closePayload().first == 1002);
}

// ══════════════════════════════════════════════════════════════════════════════
// isValidCloseCode boundaries
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Frame: isValidCloseCode boundary values", "[ws][frame][close]")
{
  REQUIRE_FALSE(WebSocketFrame::isValidCloseCode(999));
  REQUIRE_FALSE(WebSocketFrame::isValidCloseCode(1004));
  REQUIRE_FALSE(WebSocketFrame::isValidCloseCode(1005));
  REQUIRE_FALSE(WebSocketFrame::isValidCloseCode(1006));
  REQUIRE_FALSE(WebSocketFrame::isValidCloseCode(1012));
  REQUIRE_FALSE(WebSocketFrame::isValidCloseCode(1013));
  REQUIRE_FALSE(WebSocketFrame::isValidCloseCode(1014));
  REQUIRE_FALSE(WebSocketFrame::isValidCloseCode(1015));
  REQUIRE_FALSE(WebSocketFrame::isValidCloseCode(1016));
  REQUIRE_FALSE(WebSocketFrame::isValidCloseCode(2999));
  REQUIRE(WebSocketFrame::isValidCloseCode(3000));
  REQUIRE(WebSocketFrame::isValidCloseCode(4999));
  REQUIRE_FALSE(WebSocketFrame::isValidCloseCode(5000));
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
