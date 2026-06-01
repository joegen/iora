// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Unit tests for iora::web::SseChannel + WsChannel (web/channel.hpp).
// Tracker: 2026-05-29-7 (htmx-support phase 6); architecture: sse_and_channels.json.
//
// SseChannel is driven via a RecordingSseServer (captures the SSE bytes). WsChannel
// is driven via a TestWsServer double that simulates session liveness and captures
// sendText calls (isSessionActive + sendText are virtual on WebSocketServer). The
// REAL send-boundary closeSent drop guarantee is covered in test_application_integration.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <iora/web/channel.hpp>

using iora::network::SessionId;
using iora::network::SseStream;
using iora::web::SseChannel;
using iora::web::WsChannel;

namespace
{

class RecordingSseServer : public iora::network::HttpServer
{
public:
  using HttpServer::HttpServer;
  std::unordered_map<SessionId, std::string> captured;
  bool sendRawForSse(SessionId sid, const std::uint8_t *data, std::size_t len) override
  {
    captured[sid].append(reinterpret_cast<const char *>(data), len);
    return true;
  }
  void closeSession(SessionId) override {}
};

// Drives WsChannel: a controllable liveness map + captured sends. No real socket.
class TestWsServer : public iora::network::WebSocketServer
{
public:
  using WebSocketServer::WebSocketServer;
  std::unordered_set<SessionId> active;
  std::vector<std::pair<SessionId, std::string>> sent;

  bool isSessionActive(SessionId sid) const override
  {
    return active.count(sid) != 0;
  }
  void sendText(SessionId sid, const std::string &text) override
  {
    sent.emplace_back(sid, text);
  }
};

std::shared_ptr<SseStream> makeStream(RecordingSseServer &srv, SessionId sid)
{
  return std::make_shared<SseStream>(srv, sid);
}

} // namespace

// ── SseChannel ───────────────────────────────────────────────────────────────

TEST_CASE("SseChannel fan-out to all subscribers", "[channels][sse]")
{
  RecordingSseServer srv;
  SseChannel ch("updates");
  auto a = makeStream(srv, 1);
  auto b = makeStream(srv, 2);
  auto c = makeStream(srv, 3);
  ch.subscribe(a);
  ch.subscribe(b);
  ch.subscribe(c);
  REQUIRE(ch.subscriberCount() == 3);

  ch.publish("e", "frag");
  const std::string expected = "event: e\ndata: frag\n\n";
  REQUIRE(srv.captured[1] == expected);
  REQUIRE(srv.captured[2] == expected);
  REQUIRE(srv.captured[3] == expected);
}

TEST_CASE("SseChannel prunes closed streams on publish", "[channels][sse][prune]")
{
  RecordingSseServer srv;
  SseChannel ch("updates");
  auto a = makeStream(srv, 1);
  auto b = makeStream(srv, 2);
  auto c = makeStream(srv, 3);
  ch.subscribe(a);
  ch.subscribe(b);
  ch.subscribe(c);

  b->close(); // mark one closed
  ch.publish("e", "frag");

  const std::string expected = "event: e\ndata: frag\n\n";
  REQUIRE(srv.captured[1] == expected);
  REQUIRE(srv.captured.count(2) == 0); // closed stream got nothing
  REQUIRE(srv.captured[3] == expected);
  REQUIRE(ch.subscriberCount() == 2); // pruned
}

TEST_CASE("SseChannel zero-subscriber publish is a no-op", "[channels][sse][zero]")
{
  RecordingSseServer srv;
  SseChannel ch("empty");
  REQUIRE_NOTHROW(ch.publish("e", "frag"));
  REQUIRE(ch.subscriberCount() == 0);
  REQUIRE(srv.captured.empty());
}

TEST_CASE("SseChannel subscribe-before and publish-before both deliver",
          "[channels][sse][ordering]")
{
  RecordingSseServer srv;
  SseChannel ch("updates");

  // publish before any subscriber: no-op.
  ch.publish("e", "early");
  REQUIRE(srv.captured.empty());

  // subscribe then publish: delivered.
  auto a = makeStream(srv, 1);
  ch.subscribe(a);
  ch.publish("e", "late");
  REQUIRE(srv.captured[1] == "event: e\ndata: late\n\n");
}

// ── WsChannel ────────────────────────────────────────────────────────────────

TEST_CASE("WsChannel fan-out via sendText for active sessions", "[channels][ws]")
{
  TestWsServer srv;
  WsChannel ch("ws");
  srv.active = {10, 20, 30};
  ch.subscribe(srv, 10);
  ch.subscribe(srv, 20);
  ch.subscribe(srv, 30);
  REQUIRE(ch.subscriberCount() == 3);

  ch.publish("<li>x</li>");
  REQUIRE(srv.sent.size() == 3);
  for (auto &p : srv.sent)
  {
    REQUIRE(p.second == "<li>x</li>");
  }
}

TEST_CASE("WsChannel skips and prunes inactive sessions", "[channels][ws][prune]")
{
  TestWsServer srv;
  WsChannel ch("ws");
  srv.active = {10, 30}; // 20 is inactive
  ch.subscribe(srv, 10);
  ch.subscribe(srv, 20);
  ch.subscribe(srv, 30);

  ch.publish("<li>x</li>");
  // only the two active sessions got sendText
  REQUIRE(srv.sent.size() == 2);
  bool sent20 = false;
  for (auto &p : srv.sent)
  {
    if (p.first == 20)
    {
      sent20 = true;
    }
  }
  REQUIRE_FALSE(sent20);
  REQUIRE(ch.subscriberCount() == 2); // inactive 20 pruned
}

TEST_CASE("WsChannel data-after-close skip (closeSent simulated)", "[channels][ws][web-m7]")
{
  TestWsServer srv;
  WsChannel ch("ws");
  srv.active = {10};
  ch.subscribe(srv, 10);

  // Mark the session mid-close (modelled as no longer active).
  srv.active.clear();
  ch.publish("<li>x</li>");
  REQUIRE(srv.sent.empty()); // no sendText to a closing session
  REQUIRE(ch.subscriberCount() == 0);
}

TEST_CASE("WsChannel subscribe with a different server is ignored (L-1)",
          "[channels][ws][l1]")
{
  TestWsServer a;
  TestWsServer b;
  WsChannel ch("ws");
  a.active = {1};
  b.active = {2};
  ch.subscribe(a, 1);
  ch.subscribe(b, 2); // different server -> ignored
  REQUIRE(ch.subscriberCount() == 1);

  ch.publish("frag");
  REQUIRE(a.sent.size() == 1);
  REQUIRE(b.sent.empty());
}

// NOTE (cpp17-L4 / tracker task-6.5.2): the architecture testStrategy lists a
// "lazy-creation cross-doc" case — two concurrent sseChannel(name) calls return
// the SAME instance. That asserts application_wiring.json's findOrInsert channel
// REGISTRY, which does not exist in phase 6 (this doc owns only the channel
// objects, not the registry). The case is DEFERRED to the phase-8 application
// tracker and intentionally NOT implemented here (no fake registry is stubbed);
// it is not counted in phase-6 coverage.
