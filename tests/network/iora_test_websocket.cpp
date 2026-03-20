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

  WebSocketClient client;
  std::atomic<bool> clientConnected{false};

  client.setOnConnect([&](const std::string&)
  {
    clientConnected.store(true);
  });

  REQUIRE(client.connect("127.0.0.1", port));
  REQUIRE(client.getState() == WebSocketState::CONNECTED);
  REQUIRE(waitFor([&]() { return serverGotConnect.load(); }));

  client.disconnect();
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

  WebSocketClient client;
  std::string received;
  std::mutex mtx;
  std::condition_variable cv;

  client.setOnTextMessage([&](const std::string& msg)
  {
    std::lock_guard lock(mtx);
    received = msg;
    cv.notify_one();
  });

  REQUIRE(client.connect("127.0.0.1", port));

  client.sendText("Hello WebSocket!");

  {
    std::unique_lock lock(mtx);
    REQUIRE(cv.wait_for(lock, 5s, [&]() { return !received.empty(); }));
  }
  REQUIRE(received == "Hello WebSocket!");

  client.disconnect();
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

  WebSocketClient client;
  std::vector<std::uint8_t> received;
  std::mutex mtx;
  std::condition_variable cv;

  client.setOnBinaryMessage([&](const std::vector<std::uint8_t>& data)
  {
    std::lock_guard lock(mtx);
    received = data;
    cv.notify_one();
  });

  REQUIRE(client.connect("127.0.0.1", port));

  std::vector<std::uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
  client.sendBinary(payload);

  {
    std::unique_lock lock(mtx);
    REQUIRE(cv.wait_for(lock, 5s, [&]() { return !received.empty(); }));
  }
  REQUIRE(received == payload);

  client.disconnect();
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

  WebSocketClient client;
  std::atomic<bool> clientGotClose{false};

  client.setOnClose([&](std::uint16_t, const std::string&)
  {
    clientGotClose.store(true);
  });

  REQUIRE(client.connect("127.0.0.1", port));

  client.disconnect(1000, "normal close");
  REQUIRE(waitFor([&]() { return serverGotClose.load(); }, 3000ms));
  REQUIRE(closeCode.load() == 1000);

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

  WebSocketClient client;
  std::string clientProtocol;

  client.setOnConnect([&](const std::string& proto)
  {
    clientProtocol = proto;
  });

  WebSocketClient::Options opts;
  opts.subprotocols = {"sip", "xmpp"};
  REQUIRE(client.connect("127.0.0.1", port, "/", opts));
  REQUIRE(waitFor([&]() { return !clientProtocol.empty(); }));
  REQUIRE(clientProtocol == "sip");
  REQUIRE(serverProtocol == "sip");

  client.disconnect();
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
  std::vector<std::unique_ptr<WebSocketClient>> clients;
  std::atomic<int> responses{0};

  for (int i = 0; i < numClients; ++i)
  {
    auto c = std::make_unique<WebSocketClient>();
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
