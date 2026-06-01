// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Unit tests for iora::network::SseStream + upgradeToSse + SseManager
// (network/sse_stream.hpp).
// Tracker: 2026-05-29-7 (htmx-support phase 6); architecture: sse_and_channels.json.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <atomic>
#include <clocale>
#include <ctime>
#include <memory>
#include <string>

#include <iora/network/sse_stream.hpp>
#include <iora/web/channel.hpp>

using iora::network::SseStream;

namespace
{

// Test double: records the bytes SseStream hands to sendRawForSse and the
// closeSession calls, and can simulate a write failure. sendRawForSse /
// closeSession are virtual on HttpServer for exactly this purpose.
class RecordingSseServer : public iora::network::HttpServer
{
public:
  using HttpServer::HttpServer;

  std::string captured;
  std::vector<iora::network::SessionId> closeCalls;
  bool failWrites = false;

  bool sendRawForSse(iora::network::SessionId, const std::uint8_t *data,
                     std::size_t len) override
  {
    if (failWrites)
    {
      return false;
    }
    captured.append(reinterpret_cast<const char *>(data), len);
    return true;
  }

  void closeSession(iora::network::SessionId sid) override
  {
    closeCalls.push_back(sid);
  }
};

} // namespace

// ── Static wire-format formatters (pure, no transport) ───────────────────────

TEST_CASE("sse formatEvent wire format", "[sse][wire]")
{
  REQUIRE(SseStream::formatEvent("update", "<tr>x</tr>") ==
          "event: update\ndata: <tr>x</tr>\n\n");
  // Empty event name omits the event: line.
  REQUIRE(SseStream::formatEvent("", "hi") == "data: hi\n\n");
  // Multi-line: one data: line per logical line.
  REQUIRE(SseStream::formatEvent("m", "a\nb") == "event: m\ndata: a\ndata: b\n\n");
}

TEST_CASE("sse formatEvent RD-8 line-ending normalization", "[sse][wire][rd8]")
{
  // Split on \r\n, \r, AND \n; no stray \r in any data: line.
  REQUIRE(SseStream::formatEvent("m", "a\r\nb\rc") ==
          "event: m\ndata: a\ndata: b\ndata: c\n\n");
}

TEST_CASE("sse formatEvent leading-space round-trip (web-H1)", "[sse][wire][h1]")
{
  // 'data:' + ONE separator space + the payload's own leading space preserved.
  REQUIRE(SseStream::formatEvent("m", " <td>x") == "event: m\ndata:  <td>x\n\n");
}

TEST_CASE("sse formatEvent empty data emits one data line (web-L1)", "[sse][wire][l1]")
{
  REQUIRE(SseStream::formatEvent("m", "") == "event: m\ndata: \n\n");
}

TEST_CASE("sse formatEvent UTF-8 passthrough (L-4)", "[sse][wire][utf8]")
{
  const std::string utf8 = "<td>caf\xC3\xA9</td>"; // café
  const std::string out = SseStream::formatEvent("m", utf8);
  REQUIRE(out == "event: m\ndata: " + utf8 + "\n\n");
  REQUIRE(out.find("\xC3\xA9") != std::string::npos); // multi-byte bytes intact
}

TEST_CASE("sse formatComment / formatRetry", "[sse][wire]")
{
  REQUIRE(SseStream::formatComment("keepalive") == ": keepalive\n\n");
  REQUIRE(SseStream::formatRetry(5000) == "retry: 5000\n\n");
}

TEST_CASE("sse field-injection hardening: CR/LF stripped from event name + comment (web-W1)",
          "[sse][wire][security]")
{
  // A '\n'/'\r' in the event name must NOT terminate the event: field early or
  // inject a forged data:/event:/retry: field.
  REQUIRE(SseStream::formatEvent("up\ndate", "x") == "event: update\ndata: x\n\n");
  REQUIRE(SseStream::formatEvent("a\r\nb", "x") == "event: ab\ndata: x\n\n");
  REQUIRE(SseStream::formatEvent("e\rvil\ndata: forged", "x") ==
          "event: evildata: forged\ndata: x\n\n");
  // Same for comment text.
  REQUIRE(SseStream::formatComment("ev\nil") == ": evil\n\n");
  REQUIRE(SseStream::formatComment("a\r\nb") == ": ab\n\n");
}

// ── writeEvent / writeComment / writeRetry over the recording server ─────────

TEST_CASE("sse writeEvent enqueues exact bytes", "[sse][write]")
{
  RecordingSseServer srv;
  SseStream stream(srv, 1);
  stream.writeEvent("update", "<tr>x</tr>");
  REQUIRE(srv.captured == "event: update\ndata: <tr>x</tr>\n\n");
  stream.writeComment("keepalive");
  REQUIRE(srv.captured == "event: update\ndata: <tr>x</tr>\n\n: keepalive\n\n");
  stream.writeRetry(4000);
  REQUIRE(srv.captured ==
          "event: update\ndata: <tr>x</tr>\n\n: keepalive\n\nretry: 4000\n\n");
}

TEST_CASE("sse write-after-close is a no-op and isOpen stays false", "[sse][close]")
{
  RecordingSseServer srv;
  SseStream stream(srv, 1);
  REQUIRE(stream.isOpen());
  stream.close();
  REQUIRE_FALSE(stream.isOpen());
  srv.captured.clear();
  stream.writeEvent("e", "after");
  stream.writeComment("after");
  stream.writeRetry(1000);
  REQUIRE(srv.captured.empty()); // all writers are no-ops after close
  REQUIRE_FALSE(stream.isOpen());
}

TEST_CASE("sse write failure marks closed", "[sse][close][failure]")
{
  RecordingSseServer srv;
  srv.failWrites = true;
  SseStream stream(srv, 1);
  REQUIRE(stream.isOpen());
  stream.writeEvent("e", "x"); // sendRawForSse returns false
  REQUIRE_FALSE(stream.isOpen());
}

// ── Close-latch: RD-19 two paths + RD-22 immediate-fire + fire-once ──────────

TEST_CASE("sse close() is idempotent and fires onClose exactly once", "[sse][close][rd19]")
{
  RecordingSseServer srv;
  SseStream stream(srv, 7);
  int fires = 0;
  stream.onClose([&fires]() { ++fires; });
  stream.close();
  stream.close(); // idempotent
  REQUIRE(fires == 1);
  // closeSession fires EXACTLY once across the double close (M-6: the second
  // close lost the latch and must NOT re-close the session).
  REQUIRE(std::count(srv.closeCalls.begin(), srv.closeCalls.end(),
                     iora::network::SessionId{7}) == 1);
}

TEST_CASE("sse RD-19: explicit close() calls closeSession; markClosed() does not",
          "[sse][close][rd19]")
{
  RecordingSseServer srv;
  // Explicit close path.
  {
    SseStream a(srv, 11);
    int fires = 0;
    a.onClose([&fires]() { ++fires; });
    a.close();
    REQUIRE(fires == 1);
  }
  // Observer-driven path.
  {
    SseStream b(srv, 22);
    int fires = 0;
    b.onClose([&fires]() { ++fires; });
    b.markClosed();
    REQUIRE(fires == 1);
  }
  // closeSession recorded for the explicit close (11) but NOT the observer (22).
  REQUIRE(std::count(srv.closeCalls.begin(), srv.closeCalls.end(),
                     iora::network::SessionId{11}) == 1);
  REQUIRE(std::count(srv.closeCalls.begin(), srv.closeCalls.end(),
                     iora::network::SessionId{22}) == 0);
}

TEST_CASE("sse onClose convergence across explicit + observer fires once",
          "[sse][close][rd19]")
{
  RecordingSseServer srv;
  SseStream stream(srv, 3);
  int fires = 0;
  stream.onClose([&fires]() { ++fires; });
  stream.markClosed(); // observer first (engine already closing)
  stream.close();      // explicit second — latch already fired
  REQUIRE(fires == 1);
  // M-6 / RD-19: the observer won the latch, so the engine is already closing
  // this session — the losing explicit close() must NOT call closeSession.
  REQUIRE(std::count(srv.closeCalls.begin(), srv.closeCalls.end(),
                     iora::network::SessionId{3}) == 0);
}

TEST_CASE("sse RD-22: onClose after already-closed fires immediately, never twice",
          "[sse][close][rd22]")
{
  RecordingSseServer srv;
  SseStream stream(srv, 5);
  stream.close();
  int fires = 0;
  stream.onClose([&fires]() { ++fires; }); // registered AFTER close
  REQUIRE(fires == 1);                      // fired immediately/synchronously
  // A second registration after the latch fired also fires immediately.
  int fires2 = 0;
  stream.onClose([&fires2]() { ++fires2; });
  REQUIRE(fires2 == 1);
}

TEST_CASE("sse onClose callback runs OUTSIDE the close-latch (re-entrant, cpp17-M3)",
          "[sse][close][reentrant]")
{
  RecordingSseServer srv;
  auto stream = std::make_shared<SseStream>(srv, 9);
  iora::web::SseChannel channel("reentrant");
  channel.subscribe(stream);
  std::atomic<bool> ok{false};
  // A callback that re-enters the stream (isOpen + onClose) AND a channel method
  // (subscriberCount / removeClosed) must NOT deadlock, proving it fires outside
  // _closeMutex and outside any channel lock (copy-then-invoke, cpp17-M3).
  stream->onClose(
    [&]()
    {
      (void)stream->isOpen();
      (void)channel.subscriberCount();
      channel.removeClosed();
      stream->onClose([&ok]() { ok.store(true); }); // already-closed -> immediate
    });
  stream->close();
  REQUIRE(ok.load()); // inner onClose fired immediately without deadlock
}

// ── IMF-fixdate Date helper (thread-H4 reentrant gmtime) ─────────────────────

TEST_CASE("sse formatHttpDate exact IMF-fixdate for known epochs", "[sse][date][web-h2]")
{
  using iora::network::detail::formatHttpDate;
  REQUIRE(formatHttpDate(0) == "Thu, 01 Jan 1970 00:00:00 GMT");
  // 1700000000 = 2023-11-14T22:13:20Z
  REQUIRE(formatHttpDate(1700000000) == "Tue, 14 Nov 2023 22:13:20 GMT");
}

TEST_CASE("sse formatHttpDate is fixed-length and locale-independent", "[sse][date][web-h2]")
{
  using iora::network::detail::formatHttpDate;
  // Try to install a non-C locale; the hand-rolled English tables must win.
  std::setlocale(LC_TIME, "de_DE.UTF-8"); // may fail (no-op) — that is fine
  const std::string d = formatHttpDate(0);
  REQUIRE(d.size() == 29);
  REQUIRE(d.substr(d.size() - 4) == " GMT");
  REQUIRE(d == "Thu, 01 Jan 1970 00:00:00 GMT"); // English regardless of locale
  std::setlocale(LC_TIME, "C");
}
