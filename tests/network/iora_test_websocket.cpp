// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Integration tests: WebSocketClient ↔ WebSocketServer over real TCP

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/network/websocket_server.hpp>
#include <iora/network/websocket_client.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace iora::network;
using namespace std::chrono_literals;

// Use random port base to avoid TIME_WAIT conflicts between test runs
static std::uint16_t nextPort()
{
  static std::atomic<std::uint16_t> base{static_cast<std::uint16_t>(
    9200 + (std::chrono::steady_clock::now().time_since_epoch().count() % 1000))};
  return base.fetch_add(1);
}

// Helper: wait for a condition with timeout
template<typename Pred>
bool waitFor(Pred pred, std::chrono::milliseconds timeout = 5000ms)
{
  auto deadline = std::chrono::steady_clock::now() + timeout;
  while (!pred())
  {
    if (std::chrono::steady_clock::now() > deadline) return false;
    std::this_thread::sleep_for(10ms);
  }
  return true;
}

// ══════════════════════════════════════════════════════════════════════════════
// Upgrade Handshake
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Integration: client connects and upgrades", "[ws][integration]")
{
  auto port = nextPort();
  WebSocketServer server("127.0.0.1", port);
  std::atomic<bool> serverGotConnect{false};

  server.setOnConnect([&](SessionId, const std::string&)
  {
    serverGotConnect.store(true);
  });

  server.start();
  std::this_thread::sleep_for(100ms);

  auto client = WebSocketClient::create();
  std::atomic<bool> clientConnected{false};

  client->setOnConnect([&](const std::string&)
  {
    clientConnected.store(true);
  });

  REQUIRE(client->connect("127.0.0.1", port));
  REQUIRE(client->getState() == WebSocketState::CONNECTED);
  REQUIRE(waitFor([&]() { return serverGotConnect.load(); }));

  client->disconnect();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// Text Echo
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Integration: text echo", "[ws][integration]")
{
  auto port = nextPort();
  WebSocketServer server("127.0.0.1", port);

  // Server echoes text messages back
  server.setOnTextMessage([&](SessionId sid, const std::string& msg)
  {
    server.sendText(sid, msg);
  });

  server.start();
  std::this_thread::sleep_for(100ms);

  auto client = WebSocketClient::create();
  std::string received;
  std::mutex mtx;
  std::condition_variable cv;

  client->setOnTextMessage([&](const std::string& msg)
  {
    std::lock_guard lock(mtx);
    received = msg;
    cv.notify_one();
  });

  REQUIRE(client->connect("127.0.0.1", port));

  client->sendText("Hello WebSocket!");

  {
    std::unique_lock lock(mtx);
    REQUIRE(cv.wait_for(lock, 5s, [&]() { return !received.empty(); }));
  }
  REQUIRE(received == "Hello WebSocket!");

  client->disconnect();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// Binary Echo
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Integration: binary echo", "[ws][integration]")
{
  auto port = nextPort();
  WebSocketServer server("127.0.0.1", port);

  server.setOnBinaryMessage([&](SessionId sid, const std::vector<std::uint8_t>& data)
  {
    server.sendBinary(sid, data);
  });

  server.start();
  std::this_thread::sleep_for(100ms);

  auto client = WebSocketClient::create();
  std::vector<std::uint8_t> received;
  std::mutex mtx;
  std::condition_variable cv;

  client->setOnBinaryMessage([&](const std::vector<std::uint8_t>& data)
  {
    std::lock_guard lock(mtx);
    received = data;
    cv.notify_one();
  });

  REQUIRE(client->connect("127.0.0.1", port));

  std::vector<std::uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
  client->sendBinary(payload);

  {
    std::unique_lock lock(mtx);
    REQUIRE(cv.wait_for(lock, 5s, [&]() { return !received.empty(); }));
  }
  REQUIRE(received == payload);

  client->disconnect();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// Close Handshake
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Integration: close handshake", "[ws][integration]")
{
  auto port = nextPort();
  WebSocketServer server("127.0.0.1", port);
  std::atomic<bool> serverGotClose{false};
  std::atomic<uint16_t> closeCode{0};

  server.setOnClose([&](SessionId, std::uint16_t code, const std::string&)
  {
    closeCode.store(code);
    serverGotClose.store(true);
  });

  server.start();
  std::this_thread::sleep_for(100ms);

  auto client = WebSocketClient::create();
  std::atomic<bool> clientGotClose{false};

  client->setOnClose([&](std::uint16_t, const std::string&)
  {
    clientGotClose.store(true);
  });

  REQUIRE(client->connect("127.0.0.1", port));

  client->disconnect(1000, "normal close");
  REQUIRE(waitFor([&]() { return serverGotClose.load(); }, 3000ms));
  REQUIRE(closeCode.load() == 1000);

  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// Close fires _onClose exactly once
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Integration: server _onClose fires exactly once on client close",
          "[ws][integration][close]")
{
  auto port = nextPort();
  WebSocketServer server("127.0.0.1", port);
  std::atomic<int> serverCloseCount{0};
  std::atomic<std::uint16_t> serverCloseCode{0};

  server.setOnClose([&](SessionId, std::uint16_t code, const std::string&)
  {
    serverCloseCode.store(code);
    serverCloseCount.fetch_add(1);
  });

  server.start();
  std::this_thread::sleep_for(100ms);

  auto client = WebSocketClient::create();
  REQUIRE(client->connect("127.0.0.1", port));

  client->disconnect(1000, "normal close");

  // The inbound CLOSE fires _onClose once; the session is then erased + torn down,
  // so no path can re-fire it.
  REQUIRE(waitFor([&]() { return serverCloseCount.load() >= 1; }, 3000ms));
  REQUIRE(serverCloseCode.load() == 1000);

  // Settle: confirm it stays exactly one (no double-callback after teardown).
  std::this_thread::sleep_for(250ms);
  REQUIRE(serverCloseCount.load() == 1);

  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// Abrupt client disconnect (TCP FIN/RST, NO WS CLOSE frame): server fires
// _onClose(1006) exactly once and prunes the session (backlog 2026-09-11-16).
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Integration: abrupt client disconnect fires server _onClose(1006) once and prunes session",
          "[ws][integration][close][abrupt]")
{
  auto port = nextPort();
  WebSocketServer server("127.0.0.1", port);
  std::atomic<int> serverCloseCount{0};
  std::atomic<std::uint16_t> serverCloseCode{0};
  std::atomic<SessionId> serverSid{0};
  std::atomic<bool> gotSid{false};

  server.setOnConnect([&](SessionId sid, const std::string&)
  {
    serverSid.store(sid);
    gotSid.store(true);
  });
  server.setOnClose([&](SessionId, std::uint16_t code, const std::string&)
  {
    serverCloseCode.store(code);
    serverCloseCount.fetch_add(1);
  });

  server.start();
  std::this_thread::sleep_for(100ms);

  auto client = WebSocketClient::create();
  REQUIRE(client->connect("127.0.0.1", port));
  REQUIRE(waitFor([&]() { return gotSid.load(); }, 3000ms));
  SessionId sid = serverSid.load();

  // Abrupt disconnect: drop the client WITHOUT calling disconnect() — ~WebSocketClient
  // tears the socket down (gracefulClose=false), so the server sees a TCP FIN/RST with
  // NO WebSocket CLOSE frame. The transport-close hook (onUpgradedClose) is then the
  // only path that reaches the server, and the reason is PeerClosed -> code 1006.
  client.reset();

  REQUIRE(waitFor([&]() { return serverCloseCount.load() >= 1; }, 3000ms));
  REQUIRE(serverCloseCode.load() == 1006);

  // Settle: exactly one callback, and the session is pruned.
  std::this_thread::sleep_for(250ms);
  REQUIRE(serverCloseCount.load() == 1);
  REQUIRE_FALSE(server.isSessionActive(sid));

  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// Server shutdown with a still-open session: the transport shutdown-drain reaches
// onUpgradedClose with a server-initiated reason, so the app callback reports
// RFC 6455 §7.4.1 code 1001 (going away), NOT 1006.
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Integration: server shutdown fires _onClose(1001 going away) for an open session",
          "[ws][integration][close][shutdown]")
{
  auto port = nextPort();
  WebSocketServer server("127.0.0.1", port);
  std::atomic<int> serverCloseCount{0};
  std::atomic<std::uint16_t> serverCloseCode{0};
  std::atomic<bool> gotSid{false};

  server.setOnConnect([&](SessionId, const std::string&) { gotSid.store(true); });
  server.setOnClose([&](SessionId, std::uint16_t code, const std::string&)
  {
    serverCloseCode.store(code);
    serverCloseCount.fetch_add(1);
  });

  server.start();
  std::this_thread::sleep_for(100ms);

  auto client = WebSocketClient::create();
  REQUIRE(client->connect("127.0.0.1", port));
  REQUIRE(waitFor([&]() { return gotSid.load(); }, 3000ms));

  // Stop the server while the session is still open and no CLOSE frame was exchanged.
  // The engine shutdown-drain fires the transport onClose(ShuttingDown) for the live
  // session -> onUpgradedClose -> _onClose(1001).
  server.stop();

  REQUIRE(waitFor([&]() { return serverCloseCount.load() >= 1; }, 3000ms));
  REQUIRE(serverCloseCode.load() == 1001);

  // Settle: exactly one callback for this session (at-most-once across shutdown).
  std::this_thread::sleep_for(250ms);
  REQUIRE(serverCloseCount.load() == 1);

  client.reset();
}

// ══════════════════════════════════════════════════════════════════════════════
// Oversized frame -> server 1009 close + session teardown
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Integration: oversized frame closes 1009 and tears the session down",
          "[ws][integration][toolarge]")
{
  auto port = nextPort();
  WebSocketServer server("127.0.0.1", port);
  server.setMaxFrameSize(1024); // small cap so a modest frame trips it

  std::atomic<bool> gotSid{false};
  std::atomic<SessionId> serverSid{0};
  server.setOnConnect([&](SessionId sid, const std::string&)
  {
    serverSid.store(sid);
    gotSid.store(true);
  });

  server.start();
  std::this_thread::sleep_for(100ms);

  auto client = WebSocketClient::create();
  std::atomic<int> clientCloseCount{0};
  std::atomic<std::uint16_t> clientCloseCode{0};
  client->setOnClose([&](std::uint16_t code, const std::string&)
  {
    clientCloseCode.store(code);
    clientCloseCount.fetch_add(1);
  });

  REQUIRE(client->connect("127.0.0.1", port));
  REQUIRE(waitFor([&]() { return gotSid.load(); }));

  // A single 4096-byte text frame exceeds the server's 1024-byte cap. The server
  // rejects it (1009) and tears the session down through eraseAndCloseSession.
  client->sendText(std::string(4096, 'x'));

  // Client observes the CLOSE echo (1009).
  REQUIRE(waitFor([&]() { return clientCloseCount.load() >= 1; }, 3000ms));
  REQUIRE(clientCloseCode.load() == 1009);

  // Server dropped the session (no unbounded buffer left behind).
  REQUIRE(waitFor([&]() { return !server.isSessionActive(serverSid.load()); }, 3000ms));

  // A subsequent send is a harmless no-op — the session is gone and the client is
  // CLOSED, so nothing accumulates and _onClose does not re-fire.
  client->sendText("after-close");
  std::this_thread::sleep_for(150ms);
  REQUIRE(clientCloseCount.load() == 1);
  REQUIRE_FALSE(server.isSessionActive(serverSid.load()));

  client->disconnect();
  server.stop();
}

// The server sendText path (makeText) does NOT validate UTF-8 — it copies the bytes
// verbatim — so it can emit an invalid-UTF-8 TEXT frame on the wire. The client MUST
// reject the completed TEXT (RFC 6455 §8.1: text payloads are UTF-8), close 1007, and
// NOT deliver it via onTextMessage (WS-L4 / C1).
TEST_CASE("WS Integration: client rejects invalid-UTF-8 TEXT with 1007 and no delivery",
          "[ws][integration][utf8]")
{
  auto port = nextPort();
  WebSocketServer server("127.0.0.1", port);

  std::atomic<bool> gotSid{false};
  std::atomic<SessionId> serverSid{0};
  server.setOnConnect([&](SessionId sid, const std::string&)
  {
    serverSid.store(sid);
    gotSid.store(true);
  });
  // The client tears the connection down itself on the bad frame, so its terminal
  // status surfaces on the WIRE as the CLOSE(1007) it sends — which the server
  // observes here. (closeWithError fires the client's _onError, not _onClose.)
  std::atomic<int> serverCloseCount{0};
  std::atomic<std::uint16_t> serverCloseCode{0};
  server.setOnClose([&](SessionId, std::uint16_t code, const std::string&)
  {
    serverCloseCode.store(code);
    serverCloseCount.fetch_add(1);
  });

  server.start();
  std::this_thread::sleep_for(100ms);

  auto client = WebSocketClient::create();
  std::atomic<int> clientTextCount{0};
  std::atomic<int> clientErrorCount{0};
  client->setOnTextMessage([&](const std::string&)
  {
    clientTextCount.fetch_add(1);
  });
  client->setOnError([&](const std::string&)
  {
    clientErrorCount.fetch_add(1);
  });

  REQUIRE(client->connect("127.0.0.1", port));
  REQUIRE(waitFor([&]() { return gotSid.load(); }));

  // Invalid UTF-8: a lone 0xFF 0xFE pair is not a valid encoding.
  std::string invalid;
  invalid.push_back(static_cast<char>(0xFF));
  invalid.push_back(static_cast<char>(0xFE));
  server.sendText(serverSid.load(), invalid);

  // The client rejects the frame with a 1007 CLOSE (seen on the wire by the server)
  // and transitions to CLOSED, without ever delivering the payload.
  REQUIRE(waitFor([&]() { return serverCloseCount.load() >= 1; }, 3000ms));
  REQUIRE(serverCloseCode.load() == 1007);
  REQUIRE(waitFor([&]()
                  { return client->getState() == WebSocketState::CLOSED; }, 3000ms));
  std::this_thread::sleep_for(150ms);
  REQUIRE(clientTextCount.load() == 0);
  REQUIRE(clientErrorCount.load() >= 1);

  client->disconnect();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// Subprotocol Negotiation
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Integration: subprotocol negotiation", "[ws][integration]")
{
  auto port = nextPort();
  WebSocketServer server("127.0.0.1", port);

  server.setSubprotocolCallback([](const std::vector<std::string>& requested)
    -> std::string
  {
    for (const auto& p : requested)
    {
      if (p == "sip") return "sip";
    }
    return "";
  });

  std::string serverProtocol;
  server.setOnConnect([&](SessionId, const std::string& proto)
  {
    serverProtocol = proto;
  });

  server.start();
  std::this_thread::sleep_for(100ms);

  auto client = WebSocketClient::create();
  std::string clientProtocol;

  client->setOnConnect([&](const std::string& proto)
  {
    clientProtocol = proto;
  });

  WebSocketClient::Options opts;
  opts.subprotocols = {"sip", "xmpp"};
  REQUIRE(client->connect("127.0.0.1", port, "/", opts));
  REQUIRE(waitFor([&]() { return !clientProtocol.empty(); }));
  REQUIRE(clientProtocol == "sip");
  REQUIRE(serverProtocol == "sip");

  client->disconnect();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// Multiple Concurrent Sessions
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WS Integration: multiple concurrent clients", "[ws][integration]")
{
  auto port = nextPort();
  WebSocketServer server("127.0.0.1", port);
  std::atomic<int> messageCount{0};

  server.setOnTextMessage([&](SessionId sid, const std::string& msg)
  {
    server.sendText(sid, "echo:" + msg);
    messageCount.fetch_add(1);
  });

  server.start();
  std::this_thread::sleep_for(100ms);

  constexpr int numClients = 3;
  std::vector<std::shared_ptr<WebSocketClient>> clients;
  std::atomic<int> responses{0};

  for (int i = 0; i < numClients; ++i)
  {
    auto c = WebSocketClient::create();
    c->setOnTextMessage([&](const std::string&)
    {
      responses.fetch_add(1);
    });
    REQUIRE(c->connect("127.0.0.1", port));
    clients.push_back(std::move(c));
  }

  // Each client sends a message
  for (int i = 0; i < numClients; ++i)
  {
    clients[i]->sendText("msg" + std::to_string(i));
  }

  REQUIRE(waitFor([&]() { return responses.load() >= numClients; }));

  for (auto& c : clients)
  {
    c->disconnect();
  }
  server.stop();
}
