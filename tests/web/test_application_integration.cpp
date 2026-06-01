// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Real-socket integration tests for iora SSE — the C-1 (no-deadlock) regression
// guard. Tracker: 2026-05-29-7 (htmx-support phase 6); architecture: sse_and_channels.json.
//
// Exercises upgradeToSse end-to-end over a real HttpServer + TCP socket: the
// subscribe-then-publish no-deadlock guard, preamble correctness on the wire,
// disconnect cleanup, CRLF normalization, single-space round-trip, heartbeat,
// M-3 idle survival/reap, graceful-shutdown socket close, Last-Event-ID accept,
// and auto-HEAD. ctest runs -j1 (web tests share ports).

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <iora/network/sse_stream.hpp>
#include <iora/network/websocket_client.hpp>
#include <iora/network/websocket_server.hpp>
#include <iora/web/channel.hpp>

using iora::network::HttpServer;
using iora::network::SessionId;
using iora::network::SseManager;
using iora::network::SseStream;
using iora::web::SseChannel;
using Request = HttpServer::Request;
using Response = HttpServer::Response;

namespace
{

std::atomic<int> g_nextPort{19200};
int nextPort() { return g_nextPort.fetch_add(1); }

template <typename Pred>
bool waitFor(Pred pred, int timeoutMs = 5000)
{
  auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
  while (!pred())
  {
    if (std::chrono::steady_clock::now() > deadline)
    {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return true;
}

// Minimal raw client that keeps the socket open and accumulates bytes (SSE has
// no Content-Length and never closes on its own).
class SseConn
{
public:
  bool open(int port)
  {
    _fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (_fd < 0)
    {
      return false;
    }
    timeval tv{};
    tv.tv_sec = 1;
    ::setsockopt(_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<std::uint16_t>(port));
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    return ::connect(_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0;
  }

  ~SseConn() { closeNow(); }

  void closeNow()
  {
    if (_fd >= 0)
    {
      ::close(_fd);
      _fd = -1;
    }
  }

  void sendGet(const std::string &target, const std::string &extraHeaders = "")
  {
    std::string req = "GET " + target + " HTTP/1.1\r\nHost: 127.0.0.1\r\n";
    req += extraHeaders;
    req += "\r\n";
    ::send(_fd, req.data(), req.size(), 0);
  }

  void sendRawRequest(const std::string &raw) { ::send(_fd, raw.data(), raw.size(), 0); }

  // Read once (1s socket timeout); returns "" on timeout or EOF.
  std::string readSome()
  {
    char tmp[8192];
    ssize_t n = ::recv(_fd, tmp, sizeof(tmp), 0);
    if (n <= 0)
    {
      return "";
    }
    return std::string(tmp, static_cast<std::size_t>(n));
  }

  // Accumulate until `needle` appears or the deadline elapses.
  std::string readUntil(const std::string &needle, int maxMs = 3000)
  {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(maxMs);
    while (_acc.find(needle) == std::string::npos &&
           std::chrono::steady_clock::now() < deadline)
    {
      _acc += readSome();
    }
    return _acc;
  }

  const std::string &accumulated() const { return _acc; }

private:
  int _fd = -1;
  std::string _acc;
};

// Owns a server + channel + manager + timer with an /sse route wired to
// upgradeToSse. Construction order (srv, timer, manager) makes the manager die
// first; the destructor drains explicitly. heartbeatMs <= 0 disables the
// heartbeat (onConnect does not register with the manager).
struct SseFixture
{
  HttpServer srv;
  iora::core::TimerService timer;
  SseManager manager;
  SseChannel channel;
  std::atomic<int> onCloseCount{0};
  int port;

  explicit SseFixture(int heartbeatMs = 200, std::chrono::seconds idle = std::chrono::seconds(600),
                      std::chrono::seconds gc = std::chrono::seconds(5))
      : manager(srv, timer,
                std::chrono::milliseconds(heartbeatMs > 0 ? heartbeatMs : 15000)),
        channel("updates"), port(nextPort())
  {
    timer.start();
    srv.setPort(port);
    srv.setIdleTimeout(idle);
    srv.setGcInterval(gc);
    const bool useHeartbeat = heartbeatMs > 0;
    srv.onGet("/sse",
              [this, useHeartbeat](const Request &req, Response &res)
              {
                iora::network::upgradeToSse(
                  srv, req, res,
                  [this, useHeartbeat](std::shared_ptr<SseStream> stream)
                  {
                    if (useHeartbeat)
                    {
                      manager.add(stream);
                    }
                    channel.subscribe(stream);
                    stream->onClose([this]() { onCloseCount.fetch_add(1); });
                  });
              });
    srv.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
  }

  ~SseFixture()
  {
    manager.shutdown();
    timer.stop();
    srv.stop();
  }
};

} // namespace

TEST_CASE("integration: subscribe-then-publish over a real socket (C-1 no-deadlock)",
          "[sse][integration][c1]")
{
  SseFixture fx;
  SseConn c;
  REQUIRE(c.open(fx.port));
  c.sendGet("/sse", "Accept: text/event-stream\r\n");
  c.readUntil("\r\n\r\n"); // preamble head
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(fx.channel.subscriberCount() == 1);

  fx.channel.publish("update", "<tr>x</tr>");
  const std::string got = c.readUntil("event: update\ndata: <tr>x</tr>\n\n");
  REQUIRE(got.find("event: update\ndata: <tr>x</tr>\n\n") != std::string::npos);

  // cpp17-L2: a healthy stream stays OPEN across repeated real-path writes — the
  // real sendRawForSse returns true (delivered, synchronous completion), so the
  // stream is NOT spuriously pruned. Publish several more and confirm the
  // subscriber survives (subscriberCount stays 1).
  for (int i = 0; i < 5; ++i)
  {
    fx.channel.publish("update", "<tr>y</tr>");
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  REQUIRE(fx.channel.subscriberCount() == 1);
}

TEST_CASE("integration: preamble correctness over the wire", "[sse][integration][preamble]")
{
  SseFixture fx;
  SseConn c;
  REQUIRE(c.open(fx.port));
  c.sendGet("/sse");
  // Read until the retry line's blank terminator so the FULL preamble (head +
  // retry body line) is present before the structural assertions run (web-W2: the
  // head's '\r\n\r\n' contains no '\n\n', so the first '\n\n' is the retry line's).
  const std::string got = c.readUntil("\n\n");
  const std::size_t hdrEnd = got.find("\r\n\r\n");
  REQUIRE(hdrEnd != std::string::npos);
  const std::string head = got.substr(0, hdrEnd);

  REQUIRE(got.rfind("HTTP/1.1 200 OK\r\n", 0) == 0);
  REQUIRE(head.find("Content-Type: text/event-stream; charset=utf-8") != std::string::npos);
  REQUIRE(head.find("Cache-Control: no-cache, no-transform") != std::string::npos);
  REQUIRE(head.find("X-Accel-Buffering: no") != std::string::npos);
  // NO Connection header, NO Content-Length, NO chunked framing.
  REQUIRE(head.find("Connection:") == std::string::npos);
  REQUIRE(head.find("Content-Length") == std::string::npos);
  REQUIRE(head.find("Transfer-Encoding") == std::string::npos);
  // Date is a structurally-valid IMF-fixdate: "Ddd, DD Mmm YYYY HH:MM:SS GMT"
  // (web-L2 — validate the structure + English names on the WIRE, not just length).
  const std::size_t dpos = head.find("Date: ");
  REQUIRE(dpos != std::string::npos);
  const std::size_t deol = head.find("\r\n", dpos);
  const std::string dateVal = head.substr(dpos + 6, deol - (dpos + 6));
  REQUIRE(dateVal.size() == 29);
  REQUIRE(dateVal.substr(25) == " GMT");
  REQUIRE(dateVal[3] == ',');
  REQUIRE(dateVal[4] == ' ');
  REQUIRE(dateVal[7] == ' ');
  REQUIRE(dateVal[11] == ' ');
  REQUIRE(dateVal[16] == ' ');
  REQUIRE(dateVal[19] == ':');
  REQUIRE(dateVal[22] == ':');
  const std::string days = "Mon Tue Wed Thu Fri Sat Sun";
  const std::string months = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec";
  REQUIRE(days.find(dateVal.substr(0, 3)) != std::string::npos);   // English day
  REQUIRE(months.find(dateVal.substr(8, 3)) != std::string::npos); // English month
  // The initial 'retry:' is the FIRST SSE BODY line — AFTER the header terminator.
  const std::size_t retryPos = got.find("retry:");
  REQUIRE(retryPos != std::string::npos);
  REQUIRE(retryPos > hdrEnd);
  // The SSE BODY uses LF endings, not CRLF (web-L3): the body begins exactly at
  // the header terminator with 'retry: ', and the retry line through its blank
  // terminator contains no '\r'.
  REQUIRE(got.compare(hdrEnd + 4, 7, "retry: ") == 0);
  const std::size_t retryEnd = got.find("\n\n", retryPos);
  REQUIRE(retryEnd != std::string::npos);
  REQUIRE(got.find('\r', hdrEnd + 4) > retryEnd); // no CR in the retry body line
}

TEST_CASE("integration: disconnect cleanup fires onClose once and prunes",
          "[sse][integration][disconnect]")
{
  SseFixture fx(/*heartbeatMs=*/0); // no heartbeat: isolate disconnect handling
  {
    SseConn c;
    REQUIRE(c.open(fx.port));
    c.sendGet("/sse");
    c.readUntil("\r\n\r\n");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    REQUIRE(fx.channel.subscriberCount() == 1);
    c.closeNow(); // client drops the connection
  }
  // observe callback fires markClosed -> onClose once.
  bool closed = false;
  for (int i = 0; i < 50 && !closed; ++i)
  {
    closed = fx.onCloseCount.load() == 1;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  REQUIRE(fx.onCloseCount.load() == 1);
  fx.channel.publish("e", "x"); // prune closed
  REQUIRE(fx.channel.subscriberCount() == 0);
}

TEST_CASE("integration: CRLF normalization over the wire (RD-8)", "[sse][integration][rd8]")
{
  SseFixture fx;
  SseConn c;
  REQUIRE(c.open(fx.port));
  c.sendGet("/sse");
  c.readUntil("\r\n\r\n");
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  fx.channel.publish("m", "a\r\nb\rc");
  const std::string got = c.readUntil("data: c\n");
  REQUIRE(got.find("event: m\ndata: a\ndata: b\ndata: c\n\n") != std::string::npos);
  // No stray '\r' in the data lines.
  const std::size_t mpos = got.find("event: m\n");
  REQUIRE(mpos != std::string::npos);
  REQUIRE(got.find('\r', mpos) == std::string::npos);
}

TEST_CASE("integration: single-space round-trip over the wire (web-M2)",
          "[sse][integration][h1]")
{
  SseFixture fx;
  SseConn c;
  REQUIRE(c.open(fx.port));
  c.sendGet("/sse");
  c.readUntil("\r\n\r\n");
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  fx.channel.publish("m", " <td>x"); // payload starts with a space
  const std::string got = c.readUntil("data:  <td>x\n");
  // colon + producer space + the payload's own leading space.
  REQUIRE(got.find("data:  <td>x\n") != std::string::npos);
}

TEST_CASE("integration: heartbeat keepalive over the wire", "[sse][integration][heartbeat]")
{
  SseFixture fx(/*heartbeatMs=*/150);
  SseConn c;
  REQUIRE(c.open(fx.port));
  c.sendGet("/sse");
  const std::string got = c.readUntil(": keepalive\n\n", 3000);
  REQUIRE(got.find(": keepalive\n\n") != std::string::npos);
}

TEST_CASE("integration: M-3 heartbeat keeps the session alive vs idle reap",
          "[sse][integration][m3]")
{
  // Keep-alive: short idle, fast heartbeat -> NOT reaped (onClose stays 0).
  {
    SseFixture fx(/*heartbeatMs=*/200, /*idle=*/std::chrono::seconds(1),
                  /*gc=*/std::chrono::seconds(1));
    SseConn c;
    REQUIRE(c.open(fx.port));
    c.sendGet("/sse");
    c.readUntil("\r\n\r\n");
    std::this_thread::sleep_for(std::chrono::milliseconds(3500)); // > 3 GC ticks
    REQUIRE(fx.onCloseCount.load() == 0); // heartbeat refreshed lastActivity
  }
  // Reap: short idle, NO heartbeat -> engine GC reaps (onClose -> 1).
  {
    SseFixture fx(/*heartbeatMs=*/0, /*idle=*/std::chrono::seconds(1),
                  /*gc=*/std::chrono::seconds(1));
    SseConn c;
    REQUIRE(c.open(fx.port));
    c.sendGet("/sse");
    c.readUntil("\r\n\r\n");
    bool reaped = false;
    for (int i = 0; i < 60 && !reaped; ++i)
    {
      reaped = fx.onCloseCount.load() == 1;
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    REQUIRE(reaped); // ReadMode::Disabled does NOT exempt idle reaping
  }
}

TEST_CASE("integration: graceful shutdown writes ':shutting down' then closes the socket",
          "[sse][integration][shutdown]")
{
  auto fx = std::make_unique<SseFixture>(/*heartbeatMs=*/150);
  SseConn c;
  REQUIRE(c.open(fx->port));
  c.sendGet("/sse");
  c.readUntil(": keepalive\n\n", 2000); // ensure at least one keepalive flowed

  fx->manager.shutdown(); // writes ':shutting down' + close()
  const std::string got = c.readUntil(": shutting down\n\n", 2000);
  const std::size_t sd = got.rfind(": shutting down\n\n");
  REQUIRE(sd != std::string::npos);
  // No ':keepalive' after the ':shutting down' marker (draining flag, thread-H3).
  REQUIRE(got.find(": keepalive\n\n", sd) == std::string::npos);
  // Socket then closes (subsequent reads hit EOF/timeout, no more data).
  fx.reset();
}

TEST_CASE("integration: Last-Event-ID is accepted (not 4xx)", "[sse][integration][web-m3]")
{
  SseFixture fx;
  SseConn c;
  REQUIRE(c.open(fx.port));
  c.sendGet("/sse", "Last-Event-ID: 42\r\nAccept: text/event-stream\r\n");
  const std::string got = c.readUntil("\r\n\r\n");
  REQUIRE(got.rfind("HTTP/1.1 200 OK\r\n", 0) == 0); // upgraded normally
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(fx.channel.subscriberCount() == 1);
}

TEST_CASE("integration: auto-HEAD to a GET SSE route yields a normal bodyless response",
          "[sse][integration][rd21]")
{
  SseFixture fx;
  SseConn c;
  REQUIRE(c.open(fx.port));
  // HEAD to the GET SSE route: upgradeToSse is a no-op for non-GET, so the
  // dispatcher synthesizes a normal bodyless HEAD response (not an SSE upgrade).
  c.sendRawRequest("HEAD /sse HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
  const std::string got = c.readUntil("\r\n\r\n", 2000);
  REQUIRE(got.rfind("HTTP/1.1 200 OK\r\n", 0) == 0);
  REQUIRE(got.find("text/event-stream") == std::string::npos); // no SSE preamble
  REQUIRE(fx.channel.subscriberCount() == 0);                  // no upgrade happened
}

// ── web-M7 / RFC 6455 §5.5.1: the REAL WebSocketServer send-boundary closeSent
//    recheck, exercised against a live WS connection (not a double). ───────────

TEST_CASE("integration: WebSocketServer drops sendText after sendClose (web-M7)",
          "[ws][integration][web-m7]")
{
  const int port = nextPort();
  iora::network::WebSocketServer server("127.0.0.1", port);
  std::atomic<SessionId> sid{0};
  server.setOnConnect([&](SessionId s, const std::string &) { sid.store(s); });
  server.start();
  std::this_thread::sleep_for(std::chrono::milliseconds(150));

  iora::network::WebSocketClient client;
  std::mutex mtx;
  std::vector<std::string> received;
  std::atomic<bool> sawBinaryAfterClose{false};
  client.setOnTextMessage(
    [&](const std::string &m)
    {
      std::lock_guard<std::mutex> lk(mtx);
      received.push_back(m);
    });
  client.setOnBinaryMessage(
    [&](const std::vector<std::uint8_t> &) { sawBinaryAfterClose.store(true); });
  REQUIRE(client.connect("127.0.0.1", port));
  REQUIRE(waitFor([&]() { return sid.load() != 0; }));
  const SessionId s = sid.load();

  // A normal text frame is delivered while the session is active.
  REQUIRE(server.isSessionActive(s));
  server.sendText(s, "before");
  REQUIRE(waitFor(
    [&]()
    {
      std::lock_guard<std::mutex> lk(mtx);
      return !received.empty();
    }));

  // Send the CLOSE frame: closeSent is now set under _wsMutex.
  server.sendClose(s, 1000, "bye");
  REQUIRE_FALSE(server.isSessionActive(s)); // closing session is not active

  // The authoritative recheck inside sendText/sendBinary MUST drop these data
  // frames — a DATA frame can never follow a CLOSE frame (RFC 6455 §5.5.1).
  server.sendText(s, "after-close");
  server.sendBinary(s, {0x01, 0x02});
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  {
    std::lock_guard<std::mutex> lk(mtx);
    bool sawAfter = false;
    for (const auto &m : received)
    {
      if (m == "after-close")
      {
        sawAfter = true;
      }
    }
    REQUIRE_FALSE(sawAfter); // text dropped at the send boundary
  }
  REQUIRE_FALSE(sawBinaryAfterClose.load()); // binary also dropped (web-W3)

  // sendText to an UNKNOWN sid is a safe no-op (absent from _sessions).
  server.sendText(999999u, "nobody");

  client.disconnect();
  server.stop();
}

TEST_CASE("integration: WsChannel publish skips a closed real WS session (web-M7)",
          "[ws][integration][web-m7]")
{
  const int port = nextPort();
  iora::network::WebSocketServer server("127.0.0.1", port);
  std::atomic<SessionId> sid{0};
  server.setOnConnect([&](SessionId s, const std::string &) { sid.store(s); });
  server.start();
  std::this_thread::sleep_for(std::chrono::milliseconds(150));

  iora::network::WebSocketClient client;
  std::mutex mtx;
  std::vector<std::string> received;
  client.setOnTextMessage(
    [&](const std::string &m)
    {
      std::lock_guard<std::mutex> lk(mtx);
      received.push_back(m);
    });
  REQUIRE(client.connect("127.0.0.1", port));
  REQUIRE(waitFor([&]() { return sid.load() != 0; }));
  const SessionId s = sid.load();

  iora::web::WsChannel channel("ws");
  channel.subscribe(server, s);

  // Active session: publish delivers.
  channel.publish("live");
  REQUIRE(waitFor(
    [&]()
    {
      std::lock_guard<std::mutex> lk(mtx);
      return !received.empty();
    }));

  // Close the session, then publish: WsChannel skips (isSessionActive false) and
  // the send-boundary recheck would drop it anyway — no 'gone' delivered, and the
  // subscriber is pruned.
  server.sendClose(s, 1000, "bye");
  REQUIRE_FALSE(server.isSessionActive(s));
  channel.publish("gone");
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  {
    std::lock_guard<std::mutex> lk(mtx);
    bool sawGone = false;
    for (const auto &m : received)
    {
      if (m == "gone")
      {
        sawGone = true;
      }
    }
    REQUIRE_FALSE(sawGone);
  }
  REQUIRE(channel.subscriberCount() == 0); // pruned

  client.disconnect();
  server.stop();
}
