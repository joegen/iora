#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "iora/network/detail/tcp_engine.hpp"
#include "iora/network/detail/udp_engine.hpp"
#include "iora_test_net_utils.hpp"
#include "test_helpers.hpp"

using namespace std::chrono_literals;
using TcpEngine = iora::network::TcpEngine;
using UdpEngine = iora::network::UdpEngine;
using TransportConfig = iora::network::TransportConfig;
using TransportAddress = iora::network::TransportAddress;
using TransportErrorInfo = iora::network::TransportErrorInfo;
using TransportError = iora::network::TransportError;
using TlsMode = iora::network::TlsMode;
using SessionId = iora::network::SessionId;
using ListenerId = iora::network::ListenerId;

namespace
{

bool waitFor(std::function<bool()> cond, int ms = 1000)
{
  for (int i = 0; i < ms / 5 && !cond(); ++i)
    std::this_thread::sleep_for(5ms);
  return cond();
}

// ═══════════════════════════════════════════════════════════════════════
// TCP Engine Introspection
// ═══════════════════════════════════════════════════════════════════════

struct TcpIntrospectFixture
{
  TransportConfig cfg{};
  TcpEngine tx{cfg};

  std::atomic<int> acceptCount{0};
  std::atomic<int> connectCount{0};
  std::atomic<int> closeCount{0};
  SessionId serverSid{0};
  SessionId clientSid{0};
  ListenerId listenerId{0};
  std::mutex mu;

  TcpIntrospectFixture()
  {
    iora::network::detail::EngineBase::Callbacks cbs{};
    cbs.onAccept = [&](SessionId sid, const TransportAddress &)
    {
      std::lock_guard<std::mutex> lk(mu);
      serverSid = sid;
      acceptCount++;
    };
    cbs.onConnect = [&](SessionId sid, const TransportAddress &)
    {
      std::lock_guard<std::mutex> lk(mu);
      clientSid = sid;
      connectCount++;
    };
    cbs.onData = [&](SessionId, iora::core::BufferView, std::chrono::steady_clock::time_point) {};
    cbs.onClose = [&](SessionId, const TransportErrorInfo &) { closeCount++; };
    cbs.onError = [&](TransportError, const std::string &) {};
    tx.setCallbacks(cbs);
  }
};

// ─── TCP Listener Address ────────────────────────────────────────────

TEST_CASE("TCP getListenerAddress returns bound address", "[tcp][introspection]")
{
  TcpIntrospectFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();

  auto lr = f.tx.addListener("127.0.0.1", port, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  auto addr = f.tx.getListenerAddress(lid);
  REQUIRE(addr.host == "127.0.0.1");
  REQUIRE(addr.port == port);

  f.tx.stop();
}

TEST_CASE("TCP getListenerAddress returns empty for invalid lid", "[tcp][introspection]")
{
  TcpIntrospectFixture f;
  REQUIRE(f.tx.start().isOk());

  auto addr = f.tx.getListenerAddress(9999);
  REQUIRE(addr.host.empty());
  REQUIRE(addr.port == 0);

  f.tx.stop();
}

// ─── TCP Local/Remote Address ────────────────────────────────────────

TEST_CASE("TCP getLocalAddress and getRemoteAddress after connect", "[tcp][introspection]")
{
  TcpIntrospectFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();

  auto lr = f.tx.addListener("127.0.0.1", port, TlsMode::None);
  REQUIRE(lr.isOk());

  auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());

  REQUIRE(waitFor([&] { return f.acceptCount > 0 && f.connectCount > 0; }));

  // Client session: local address should be 127.0.0.1 with some ephemeral port
  auto clientLocal = f.tx.getLocalAddress(f.clientSid);
  REQUIRE(clientLocal.host == "127.0.0.1");
  REQUIRE(clientLocal.port > 0);

  // Client session: remote address should be 127.0.0.1:port (the listener)
  auto clientRemote = f.tx.getRemoteAddress(f.clientSid);
  REQUIRE(clientRemote.host == "127.0.0.1");
  REQUIRE(clientRemote.port == port);

  // Server session: local address should be 127.0.0.1:port (the listener)
  auto serverLocal = f.tx.getLocalAddress(f.serverSid);
  REQUIRE(serverLocal.host == "127.0.0.1");
  REQUIRE(serverLocal.port == port);

  // Server session: remote address should be 127.0.0.1 with ephemeral port matching client's local
  auto serverRemote = f.tx.getRemoteAddress(f.serverSid);
  REQUIRE(serverRemote.host == "127.0.0.1");
  REQUIRE(serverRemote.port == clientLocal.port);

  f.tx.stop();
}

TEST_CASE("TCP getLocalAddress returns empty for invalid sid", "[tcp][introspection]")
{
  TcpIntrospectFixture f;
  REQUIRE(f.tx.start().isOk());

  auto addr = f.tx.getLocalAddress(9999);
  REQUIRE(addr.host.empty());
  REQUIRE(addr.port == 0);

  f.tx.stop();
}

TEST_CASE("TCP getRemoteAddress returns empty after session close", "[tcp][introspection]")
{
  TcpIntrospectFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();

  f.tx.addListener("127.0.0.1", port, TlsMode::None);
  auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId cid = cr.value();
  REQUIRE(waitFor([&] { return f.acceptCount > 0 && f.connectCount > 0; }));

  // Close and wait
  f.tx.close(cid);
  REQUIRE(waitFor([&] { return f.closeCount > 0; }));

  // After close, address should be empty
  auto addr = f.tx.getRemoteAddress(cid);
  REQUIRE(addr.host.empty());

  f.tx.stop();
}

// ─── TCP setDscp ─────────────────────────────────────────────────────

TEST_CASE("TCP setDscp succeeds on connected session", "[tcp][introspection]")
{
  TcpIntrospectFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();

  f.tx.addListener("127.0.0.1", port, TlsMode::None);
  auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return f.acceptCount > 0 && f.connectCount > 0; }));

  // Set DSCP on client session (CS3 = 24)
  REQUIRE(f.tx.setDscp(f.clientSid, 24));

  // Set DSCP on server session
  REQUIRE(f.tx.setDscp(f.serverSid, 24));

  f.tx.stop();
}

TEST_CASE("TCP setDscp returns false for invalid sid", "[tcp][introspection]")
{
  TcpIntrospectFixture f;
  REQUIRE(f.tx.start().isOk());
  REQUIRE_FALSE(f.tx.setDscp(9999, 24));
  f.tx.stop();
}

// ═══════════════════════════════════════════════════════════════════════
// UDP Engine Introspection
// ═══════════════════════════════════════════════════════════════════════

struct UdpIntrospectFixture
{
  TransportConfig cfg{};
  UdpEngine tx{cfg};

  std::atomic<int> acceptCount{0};
  std::atomic<int> connectCount{0};
  std::atomic<int> closeCount{0};
  std::atomic<int> dataCount{0};
  SessionId serverSid{0};
  SessionId clientSid{0};
  std::mutex mu;

  UdpIntrospectFixture()
  {
    iora::network::detail::EngineBase::Callbacks cbs{};
    cbs.onAccept = [&](SessionId sid, const TransportAddress &)
    {
      std::lock_guard<std::mutex> lk(mu);
      serverSid = sid;
      acceptCount++;
    };
    cbs.onConnect = [&](SessionId sid, const TransportAddress &)
    {
      std::lock_guard<std::mutex> lk(mu);
      clientSid = sid;
      connectCount++;
    };
    cbs.onData = [&](SessionId, iora::core::BufferView, std::chrono::steady_clock::time_point)
    { dataCount++; };
    cbs.onClose = [&](SessionId, const TransportErrorInfo &) { closeCount++; };
    cbs.onError = [&](TransportError, const std::string &) {};
    tx.setCallbacks(std::move(cbs));
  }
};

// ─── UDP Listener Address ────────────────────────────────────────────

TEST_CASE("UDP getListenerAddress returns bound address", "[udp][introspection]")
{
  UdpIntrospectFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();

  auto lr = f.tx.addListener("127.0.0.1", port, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  auto addr = f.tx.getListenerAddress(lid);
  REQUIRE(addr.host == "127.0.0.1");
  REQUIRE(addr.port == port);

  f.tx.stop();
}

TEST_CASE("UDP getListenerAddress returns empty for invalid lid", "[udp][introspection]")
{
  UdpIntrospectFixture f;
  REQUIRE(f.tx.start().isOk());

  auto addr = f.tx.getListenerAddress(9999);
  REQUIRE(addr.host.empty());
  REQUIRE(addr.port == 0);

  f.tx.stop();
}

// ─── UDP Local/Remote Address ────────────────────────────────────────

TEST_CASE("UDP getLocalAddress and getRemoteAddress after connect/data", "[udp][introspection]")
{
  UdpIntrospectFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();

  auto lr = f.tx.addListener("127.0.0.1", port, TlsMode::None);
  REQUIRE(lr.isOk());

  auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return f.connectCount > 0; }));

  // Send data to trigger server-side session creation
  const char *msg = "introspect";
  f.tx.send(f.clientSid, msg, std::strlen(msg));
  REQUIRE(waitFor([&] { return f.acceptCount > 0; }));

  // Client session (ClientConnected): local address should have some ephemeral port
  auto clientLocal = f.tx.getLocalAddress(f.clientSid);
  REQUIRE(clientLocal.host == "127.0.0.1");
  REQUIRE(clientLocal.port > 0);

  // Client session: remote address should be the listener
  auto clientRemote = f.tx.getRemoteAddress(f.clientSid);
  REQUIRE(clientRemote.host == "127.0.0.1");
  REQUIRE(clientRemote.port == port);

  // Server session (ServerPeer): local address should be the listener address
  auto serverLocal = f.tx.getLocalAddress(f.serverSid);
  REQUIRE(serverLocal.host == "127.0.0.1");
  REQUIRE(serverLocal.port == port);

  // Server session: remote address should be the client
  auto serverRemote = f.tx.getRemoteAddress(f.serverSid);
  REQUIRE(serverRemote.host == "127.0.0.1");
  REQUIRE(serverRemote.port == clientLocal.port);

  f.tx.stop();
}

TEST_CASE("UDP getLocalAddress returns empty for invalid sid", "[udp][introspection]")
{
  UdpIntrospectFixture f;
  REQUIRE(f.tx.start().isOk());

  auto addr = f.tx.getLocalAddress(9999);
  REQUIRE(addr.host.empty());
  REQUIRE(addr.port == 0);

  f.tx.stop();
}

// ─── UDP setDscp ─────────────────────────────────────────────────────

TEST_CASE("UDP setDscp succeeds on connected session", "[udp][introspection]")
{
  UdpIntrospectFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();

  f.tx.addListener("127.0.0.1", port, TlsMode::None);
  auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return f.connectCount > 0; }));

  // Set DSCP on client session
  REQUIRE(f.tx.setDscp(f.clientSid, 24));

  f.tx.stop();
}

TEST_CASE("UDP setDscp returns false for invalid sid", "[udp][introspection]")
{
  UdpIntrospectFixture f;
  REQUIRE(f.tx.start().isOk());
  REQUIRE_FALSE(f.tx.setDscp(9999, 24));
  f.tx.stop();
}

// ═══════════════════════════════════════════════════════════════════════
// Batching Integration Tests
// ═══════════════════════════════════════════════════════════════════════

TEST_CASE("TCP batching enabled - data exchange and stats", "[tcp][batching]")
{
  TransportConfig cfg{};
  cfg.batching.enabled = true;
  cfg.batching.maxBatchSize = 32;
  cfg.batching.maxBatchDelay = std::chrono::microseconds(500);
  TcpEngine tx{cfg};

  std::atomic<int> acceptCount{0}, connectCount{0}, dataCount{0};
  SessionId serverSid{0}, clientSid{0};
  std::mutex mu;

  iora::network::detail::EngineBase::Callbacks cbs{};
  cbs.onAccept = [&](SessionId sid, const TransportAddress &)
  {
    std::lock_guard<std::mutex> lk(mu);
    serverSid = sid;
    acceptCount++;
  };
  cbs.onConnect = [&](SessionId sid, const TransportAddress &)
  {
    std::lock_guard<std::mutex> lk(mu);
    clientSid = sid;
    connectCount++;
  };
  cbs.onData = [&](SessionId sid, iora::core::BufferView data, std::chrono::steady_clock::time_point)
  {
    dataCount++;
    // Echo from server
    {
      std::lock_guard<std::mutex> lk(mu);
      if (sid == serverSid)
        tx.send(sid, data.data(), data.size());
    }
  };
  cbs.onClose = [](SessionId, const TransportErrorInfo &) {};
  cbs.onError = [](TransportError, const std::string &) {};
  tx.setCallbacks(cbs);

  REQUIRE(tx.start().isOk());
  auto port = testnet::getFreePortTCP();
  tx.addListener("127.0.0.1", port, TlsMode::None);
  auto cr = tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return acceptCount > 0 && connectCount > 0; }));

  const char *msg = "batch test";
  tx.send(clientSid, msg, std::strlen(msg));
  REQUIRE(waitFor([&] { return dataCount >= 2; }));

  auto stats = tx.getStats();
  REQUIRE(stats.batchingStats.has_value());
  REQUIRE(stats.batchingStats->totalEvents > 0);

  tx.stop();
}

TEST_CASE("TCP batching disabled - no batching stats", "[tcp][batching]")
{
  TransportConfig cfg{};
  cfg.batching.enabled = false;
  TcpEngine tx{cfg};

  iora::network::detail::EngineBase::Callbacks cbs{};
  cbs.onAccept = [](SessionId, const TransportAddress &) {};
  cbs.onConnect = [](SessionId, const TransportAddress &) {};
  cbs.onData = [](SessionId, iora::core::BufferView, std::chrono::steady_clock::time_point) {};
  cbs.onClose = [](SessionId, const TransportErrorInfo &) {};
  cbs.onError = [](TransportError, const std::string &) {};
  tx.setCallbacks(cbs);

  REQUIRE(tx.start().isOk());

  auto stats = tx.getStats();
  REQUIRE_FALSE(stats.batchingStats.has_value());

  tx.stop();
}

TEST_CASE("UDP batching enabled - data exchange and stats", "[udp][batching]")
{
  TransportConfig cfg{};
  cfg.batching.enabled = true;
  cfg.batching.maxBatchSize = 32;
  cfg.batching.maxBatchDelay = std::chrono::microseconds(500);
  UdpEngine tx{cfg};

  std::atomic<int> acceptCount{0}, connectCount{0}, dataCount{0};
  SessionId serverSid{0}, clientSid{0};
  std::mutex mu;

  iora::network::detail::EngineBase::Callbacks cbs{};
  cbs.onAccept = [&](SessionId sid, const TransportAddress &)
  {
    std::lock_guard<std::mutex> lk(mu);
    serverSid = sid;
    acceptCount++;
  };
  cbs.onConnect = [&](SessionId sid, const TransportAddress &)
  {
    std::lock_guard<std::mutex> lk(mu);
    clientSid = sid;
    connectCount++;
  };
  cbs.onData = [&](SessionId sid, iora::core::BufferView data, std::chrono::steady_clock::time_point)
  {
    dataCount++;
    // Echo from server
    {
      std::lock_guard<std::mutex> lk(mu);
      if (sid == serverSid)
        tx.send(sid, data.data(), data.size());
    }
  };
  cbs.onClose = [](SessionId, const TransportErrorInfo &) {};
  cbs.onError = [](TransportError, const std::string &) {};
  tx.setCallbacks(cbs);

  REQUIRE(tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  tx.addListener("127.0.0.1", port, TlsMode::None);
  auto cr = tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return connectCount > 0; }));

  const char *msg = "udp batch";
  tx.send(clientSid, msg, std::strlen(msg));
  REQUIRE(waitFor([&] { return dataCount >= 2; }));

  auto stats = tx.getStats();
  REQUIRE(stats.batchingStats.has_value());
  REQUIRE(stats.batchingStats->totalEvents > 0);

  tx.stop();
}

TEST_CASE("UDP batching disabled - no batching stats", "[udp][batching]")
{
  TransportConfig cfg{};
  cfg.batching.enabled = false;
  UdpEngine tx{cfg};

  iora::network::detail::EngineBase::Callbacks cbs{};
  cbs.onAccept = [](SessionId, const TransportAddress &) {};
  cbs.onConnect = [](SessionId, const TransportAddress &) {};
  cbs.onData = [](SessionId, iora::core::BufferView, std::chrono::steady_clock::time_point) {};
  cbs.onClose = [](SessionId, const TransportErrorInfo &) {};
  cbs.onError = [](TransportError, const std::string &) {};
  tx.setCallbacks(cbs);

  REQUIRE(tx.start().isOk());

  auto stats = tx.getStats();
  REQUIRE_FALSE(stats.batchingStats.has_value());

  tx.stop();
}

} // namespace
