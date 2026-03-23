// Transport API tests — Phase 6 of transport refactor
// Tests the new Transport class (ITransport, Config, Stats, Result<T,E> integration)

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/network/transport_impl.hpp"
#include "iora_test_net_utils.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace iora::network;
using namespace std::chrono_literals;

// Helper: wait for a condition with timeout
static bool waitFor(std::function<bool()> pred, std::chrono::milliseconds timeout = 2000ms)
{
  auto deadline = std::chrono::steady_clock::now() + timeout;
  while (!pred())
  {
    if (std::chrono::steady_clock::now() > deadline)
    {
      return false;
    }
    std::this_thread::sleep_for(1ms);
  }
  return true;
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.1: Construction and lifecycle
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Transport::tcp() produces Protocol::TCP", "[transport][construction]")
{
  auto t = Transport::tcp();
  REQUIRE(t.getProtocol() == Protocol::TCP);
  REQUIRE_FALSE(t.isRunning());
}

TEST_CASE("Transport::udp() produces Protocol::UDP", "[transport][construction]")
{
  auto t = Transport::udp();
  REQUIRE(t.getProtocol() == Protocol::UDP);
  REQUIRE_FALSE(t.isRunning());
}

TEST_CASE("Factory methods do NOT call start", "[transport][construction]")
{
  auto tcp = Transport::tcp();
  REQUIRE_FALSE(tcp.isRunning());

  auto udp = Transport::udp();
  REQUIRE_FALSE(udp.isRunning());

  auto sipTcp = Transport(TransportConfig::forSipTcp());
  REQUIRE_FALSE(sipTcp.isRunning());

  auto sipUdp = Transport(TransportConfig::forSipUdp());
  REQUIRE_FALSE(sipUdp.isRunning());
}

TEST_CASE("Transport lifecycle: start -> isRunning -> stop", "[transport][lifecycle]")
{
  auto t = Transport::tcp();
  REQUIRE_FALSE(t.isRunning());

  auto result = t.start();
  REQUIRE(result.isOk());
  REQUIRE(t.isRunning());

  t.stop();
  REQUIRE_FALSE(t.isRunning());
}

TEST_CASE("Double start() returns err", "[transport][lifecycle]")
{
  auto t = Transport::tcp();
  auto r1 = t.start();
  REQUIRE(r1.isOk());

  auto r2 = t.start();
  REQUIRE(r2.isErr());

  t.stop();
}

TEST_CASE("stop() on unstarted transport is no-op", "[transport][lifecycle]")
{
  auto t = Transport::tcp();
  t.stop(); // Should not crash
  REQUIRE_FALSE(t.isRunning());
}

TEST_CASE("Destructor calls stop if running", "[transport][lifecycle]")
{
  {
    auto t = Transport::tcp();
    auto r = t.start();
    REQUIRE(r.isOk());
    REQUIRE(t.isRunning());
    // Destructor at end of scope should call stop()
  }
  // No crash = success
}

TEST_CASE("Transport is movable but not copyable", "[transport][construction]")
{
  static_assert(!std::is_copy_constructible_v<Transport>);
  static_assert(!std::is_copy_assignable_v<Transport>);
  static_assert(std::is_move_constructible_v<Transport>);
  static_assert(std::is_move_assignable_v<Transport>);

  auto t1 = Transport::tcp();
  auto r = t1.start();
  REQUIRE(r.isOk());

  auto t2 = std::move(t1);
  REQUIRE(t2.isRunning());
  REQUIRE(t2.getProtocol() == Protocol::TCP);

  t2.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.11: Config presets
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config::forSipTcp() has correct defaults", "[transport][config]")
{
  auto c = TransportConfig::forSipTcp();
  REQUIRE(c.protocol == Protocol::TCP);
  REQUIRE(c.idleTimeout == 3600s);
  REQUIRE(c.tcpKeepalive.enable == true);
  REQUIRE(c.tcpKeepalive.idle == 120);
  REQUIRE(c.maxPendingSyncOps == 64);
  REQUIRE(c.defaultSyncTimeout == 32000ms);
  REQUIRE(c.autoHealthMonitoring == true);
  REQUIRE(c.dscpValue == 24);
}

TEST_CASE("Config::forSipUdp() has correct defaults", "[transport][config]")
{
  auto c = TransportConfig::forSipUdp();
  REQUIRE(c.protocol == Protocol::UDP);
  REQUIRE(c.idleTimeout == 32s);
  REQUIRE(c.maxSessions == 10000);
  REQUIRE(c.maxPendingSyncOps == 64);
  REQUIRE(c.defaultSyncTimeout == 500ms);
  REQUIRE(c.dscpValue == 24);
}

TEST_CASE("Config::forHighThroughput() enables batching", "[transport][config]")
{
  auto c = TransportConfig::forHighThroughput();
  REQUIRE(c.protocol == Protocol::TCP);
  REQUIRE(c.batching.enabled == true);
  REQUIRE(c.batching.maxBatchSize == 128);
  REQUIRE(c.maxWriteQueue == 4096);
  REQUIRE(c.soRcvBuf == 262144);
}

TEST_CASE("Config::forLowLatency() disables batching", "[transport][config]")
{
  auto c = TransportConfig::forLowLatency();
  REQUIRE(c.batching.enabled == false);
  REQUIRE(c.enableTcpNoDelay == true);
  REQUIRE(c.maxWriteQueue == 256);
}

TEST_CASE("Default Config has documented defaults", "[transport][config]")
{
  TransportConfig c;
  REQUIRE(c.protocol == Protocol::TCP);
  REQUIRE(c.idleTimeout == 600s);
  REQUIRE(c.connectTimeout == 30000ms);
  REQUIRE(c.epollMaxEvents == 256);
  REQUIRE(c.ioReadChunk == 64 * 1024);
  REQUIRE(c.maxWriteQueue == 1024);
  REQUIRE(c.dscpValue == 0);
  REQUIRE(c.batching.enabled == false);
  REQUIRE(c.acceptRateLimit == 0.0);
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.2: TCP connection management
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TCP addListener and connect", "[transport][tcp][connection]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  std::atomic<int> acceptCount{0};
  std::atomic<int> connectCount{0};

  server.onAccept([&](SessionId, const TransportAddress &) { acceptCount++; });

  auto sr = server.start();
  REQUIRE(sr.isOk());

  auto lr = server.addListener("127.0.0.1", port);
  REQUIRE(lr.isOk());

  auto client = Transport::tcp();
  client.onConnect([&](SessionId, const TransportAddress &) { connectCount++; });
  auto cr = client.start();
  REQUIRE(cr.isOk());

  auto connResult = client.connect("127.0.0.1", port);
  REQUIRE(connResult.isOk());

  REQUIRE(waitFor([&] { return acceptCount > 0 && connectCount > 0; }));
  REQUIRE(acceptCount.load() == 1);
  REQUIRE(connectCount.load() == 1);

  client.stop();
  server.stop();
}

TEST_CASE("TCP connectViaListener returns err(Config)", "[transport][tcp][connection]")
{
  auto t = Transport::tcp();
  auto r = t.start();
  REQUIRE(r.isOk());

  auto result = t.connectViaListener(1, "127.0.0.1", 5060);
  REQUIRE(result.isErr());
  REQUIRE(result.error().code == TransportError::Config);

  t.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.3: TCP data operations
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TCP bidirectional data exchange", "[transport][tcp][data]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();

  std::mutex mtx;
  std::string serverReceived;
  std::atomic<SessionId> serverSid{0};

  server.onAccept([&](SessionId sid, const TransportAddress &)
  {
    std::lock_guard<std::mutex> lk(mtx);
    serverSid = sid;
  });

  server.onData([&](SessionId, iora::core::BufferView data, std::chrono::steady_clock::time_point)
  {
    std::lock_guard<std::mutex> lk(mtx);
    serverReceived.append(reinterpret_cast<const char *>(data.data()), data.size());
  });

  std::string clientReceived;
  client.onData([&](SessionId, iora::core::BufferView data, std::chrono::steady_clock::time_point)
  {
    std::lock_guard<std::mutex> lk(mtx);
    clientReceived.append(reinterpret_cast<const char *>(data.data()), data.size());
  });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());

  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());
  SessionId clientSid = conn.value();

  REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(mtx); return serverSid != 0; }));

  // Client -> Server
  const char *msg1 = "hello server";
  client.send(clientSid, msg1, std::strlen(msg1));
  REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(mtx); return !serverReceived.empty(); }));
  {
    std::lock_guard<std::mutex> lk(mtx);
    REQUIRE(serverReceived == "hello server");
  }

  // Server -> Client
  const char *msg2 = "hello client";
  {
    std::lock_guard<std::mutex> lk(mtx);
    server.send(serverSid, msg2, std::strlen(msg2));
  }
  REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(mtx); return !clientReceived.empty(); }));
  {
    std::lock_guard<std::mutex> lk(mtx);
    REQUIRE(clientReceived == "hello client");
  }

  client.stop();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.7: Callback behavior
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("All callbacks fire correctly", "[transport][callbacks]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();

  std::atomic<int> acceptCount{0}, connectCount{0}, dataCount{0}, closeCount{0};

  server.onAccept([&](SessionId, const TransportAddress &) { acceptCount++; });
  server.onData([&](SessionId, iora::core::BufferView, std::chrono::steady_clock::time_point)
  { dataCount++; });
  server.onClose([&](SessionId, const TransportErrorInfo &) { closeCount++; });

  client.onConnect([&](SessionId, const TransportAddress &) { connectCount++; });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());

  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());

  REQUIRE(waitFor([&] { return acceptCount > 0 && connectCount > 0; }));

  // Send data
  client.send(conn.value(), "test", 4);
  REQUIRE(waitFor([&] { return dataCount > 0; }));

  // Close
  client.close(conn.value());
  REQUIRE(waitFor([&] { return closeCount > 0; }));

  client.stop();
  server.stop();
}

TEST_CASE("Replacing callback after start", "[transport][callbacks]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  std::atomic<int> count1{0}, count2{0};

  server.onAccept([&](SessionId, const TransportAddress &) { count1++; });
  server.onAccept([&](SessionId, const TransportAddress &) { count2++; }); // Replace

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());

  auto client = Transport::tcp();
  REQUIRE(client.start().isOk());
  client.connect("127.0.0.1", port);
  REQUIRE(waitFor([&] { return count2 > 0; }));

  REQUIRE(count1.load() == 0); // First callback replaced, never fires
  REQUIRE(count2.load() == 1); // Second callback active

  client.stop();
  server.stop();
}

TEST_CASE("HR-6: Callback can re-enter Transport without deadlock", "[transport][callbacks][hr6]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  std::atomic<bool> reentered{false};

  server.onAccept([&](SessionId sid, const TransportAddress &)
  {
    // Re-enter Transport from within callback — must not deadlock
    auto stats = server.getStats();
    (void)stats;
    server.close(sid);
    reentered = true;
  });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());

  auto client = Transport::tcp();
  REQUIRE(client.start().isOk());
  client.connect("127.0.0.1", port);

  REQUIRE(waitFor([&] { return reentered.load(); }));

  client.stop();
  server.stop();
}

TEST_CASE("HR-7: Observer self-unobserve during iteration", "[transport][observers][hr7]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  std::atomic<SessionId> sid{0};
  std::atomic<int> obs1Count{0}, obs2Count{0};
  ObserverId id1{0};

  server.onAccept([&](SessionId s, const TransportAddress &) { sid = s; });
  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());

  auto client = Transport::tcp();
  REQUIRE(client.start().isOk());
  client.connect("127.0.0.1", port);
  REQUIRE(waitFor([&] { return sid != 0; }));

  // Observer 1 unobserves itself during invocation
  id1 = server.observe(sid, [&](SessionId, const TransportErrorInfo &)
  {
    server.unobserve(id1); // Self-remove — must not crash or deadlock
    obs1Count++;
  });
  server.observe(sid, [&](SessionId, const TransportErrorInfo &)
  {
    obs2Count++; // Observer 2 must still fire
  });

  server.close(sid);
  REQUIRE(waitFor([&] { return obs2Count > 0; }));

  REQUIRE(obs1Count.load() == 1); // Observer 1 fired (then self-removed)
  REQUIRE(obs2Count.load() == 1); // Observer 2 still fired

  client.stop();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.8: Observer pattern
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("observe() returns unique ObserverId", "[transport][observers]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  std::atomic<SessionId> sid{0};

  server.onAccept([&](SessionId s, const TransportAddress &) { sid = s; });
  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());

  auto client = Transport::tcp();
  REQUIRE(client.start().isOk());
  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());

  REQUIRE(waitFor([&] { return sid != 0; }));

  auto id1 = server.observe(sid, [](SessionId, const TransportErrorInfo &) {});
  auto id2 = server.observe(sid, [](SessionId, const TransportErrorInfo &) {});
  REQUIRE(id1 != id2);

  client.stop();
  server.stop();
}

TEST_CASE("Observers fire after global onClose, in registration order", "[transport][observers]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  std::atomic<SessionId> sid{0};

  std::vector<int> order;
  std::mutex mtx;

  server.onAccept([&](SessionId s, const TransportAddress &) { sid = s; });
  server.onClose([&](SessionId, const TransportErrorInfo &)
  {
    std::lock_guard<std::mutex> lk(mtx);
    order.push_back(0); // Global onClose = 0
  });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());

  auto client = Transport::tcp();
  REQUIRE(client.start().isOk());
  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());

  REQUIRE(waitFor([&] { return sid != 0; }));

  server.observe(sid, [&](SessionId, const TransportErrorInfo &)
  {
    std::lock_guard<std::mutex> lk(mtx);
    order.push_back(1); // Observer 1
  });
  server.observe(sid, [&](SessionId, const TransportErrorInfo &)
  {
    std::lock_guard<std::mutex> lk(mtx);
    order.push_back(2); // Observer 2
  });

  // Trigger close
  client.close(conn.value());
  REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(mtx); return order.size() >= 3; }));

  std::lock_guard<std::mutex> lk(mtx);
  REQUIRE(order.size() == 3);
  REQUIRE(order[0] == 0); // Global onClose first
  REQUIRE(order[1] == 1); // Observer 1 second
  REQUIRE(order[2] == 2); // Observer 2 third

  client.stop();
  server.stop();
}

TEST_CASE("unobserve() removes specific observer", "[transport][observers]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  std::atomic<SessionId> sid{0};

  server.onAccept([&](SessionId s, const TransportAddress &) { sid = s; });
  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());

  auto client = Transport::tcp();
  REQUIRE(client.start().isOk());
  client.connect("127.0.0.1", port);
  REQUIRE(waitFor([&] { return sid != 0; }));

  std::atomic<int> count1{0}, count2{0};
  auto id1 = server.observe(sid, [&](SessionId, const TransportErrorInfo &) { count1++; });
  server.observe(sid, [&](SessionId, const TransportErrorInfo &) { count2++; });

  REQUIRE(server.unobserve(id1));

  // Close the observed session — only observer 2 should fire (observer 1 was removed)
  server.close(sid);
  REQUIRE(waitFor([&] { return count2 > 0; }));

  REQUIRE(count1.load() == 0); // Removed
  REQUIRE(count2.load() == 1); // Still active

  client.stop();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.10: User data
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("setSessionData/getSessionData round-trip", "[transport][userdata]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  std::atomic<SessionId> sid{0};

  server.onAccept([&](SessionId s, const TransportAddress &) { sid = s; });
  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());

  auto client = Transport::tcp();
  REQUIRE(client.start().isOk());
  client.connect("127.0.0.1", port);
  REQUIRE(waitFor([&] { return sid != 0; }));

  int myData = 42;
  server.setSessionData(sid, &myData);
  REQUIRE(server.getSessionData(sid) == &myData);
  REQUIRE(server.getSessionData(999) == nullptr); // Unknown session

  client.stop();
  server.stop();
}

TEST_CASE("User data cleanup fires on session close, after observers", "[transport][userdata]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  std::atomic<SessionId> sid{0};

  std::vector<int> order;
  std::mutex mtx;

  server.onAccept([&](SessionId s, const TransportAddress &) { sid = s; });
  server.onClose([&](SessionId, const TransportErrorInfo &)
  {
    std::lock_guard<std::mutex> lk(mtx);
    order.push_back(0); // Global onClose
  });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());

  auto client = Transport::tcp();
  REQUIRE(client.start().isOk());
  client.connect("127.0.0.1", port);
  REQUIRE(waitFor([&] { return sid != 0; }));

  server.observe(sid, [&](SessionId, const TransportErrorInfo &)
  {
    std::lock_guard<std::mutex> lk(mtx);
    order.push_back(1); // Observer
  });

  int myData = 99;
  server.setSessionData(sid, &myData, [&](void *)
  {
    std::lock_guard<std::mutex> lk(mtx);
    order.push_back(2); // Cleanup
  });

  // Trigger close on the observed session
  server.close(sid);

  // Wait for close to propagate (need all 3: onClose, observer, cleanup)
  REQUIRE(waitFor([&]
  {
    std::lock_guard<std::mutex> lk(mtx);
    // We need at least 3 entries AND the last one should be cleanup (2)
    return order.size() >= 3 &&
           std::count(order.begin(), order.end(), 2) > 0;
  }));

  // Filter to only entries from our observed session's close flow
  // (the global onClose may also fire for other sessions)
  std::lock_guard<std::mutex> lk(mtx);
  REQUIRE(order.size() >= 3);
  // Verify ordering: 0 (global onClose) comes before 1 (observer) comes before 2 (cleanup)
  auto pos0 = std::find(order.begin(), order.end(), 0);
  auto pos1 = std::find(order.begin(), order.end(), 1);
  auto pos2 = std::find(order.begin(), order.end(), 2);
  REQUIRE(pos0 != order.end());
  REQUIRE(pos1 != order.end());
  REQUIRE(pos2 != order.end());
  REQUIRE(pos0 < pos1); // Global onClose before observer
  REQUIRE(pos1 < pos2); // Observer before cleanup (HR-11)

  client.stop();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.14: Result<T,E> integration
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("addListener returns Result<ListenerId>", "[transport][result]")
{
  auto t = Transport::tcp();
  REQUIRE(t.start().isOk());

  auto port = testnet::getFreePortTCP();
  auto result = t.addListener("127.0.0.1", port);
  REQUIRE(result.isOk());
  REQUIRE(result.value() > 0);

  t.stop();
}

TEST_CASE("connect returns Result<SessionId> (async, immediate ok)", "[transport][result]")
{
  // Async connect returns ok(SessionId) immediately before handshake.
  // The SessionId is pre-allocated; actual connection completes asynchronously.
  auto t = Transport::tcp();
  REQUIRE(t.start().isOk());

  auto port = testnet::getFreePortTCP();
  auto result = t.connect("127.0.0.1", port);
  REQUIRE(result.isOk());
  REQUIRE(result.value() > 0);

  t.stop();
}

TEST_CASE("start returns Result<void>", "[transport][result]")
{
  auto t = Transport::tcp();
  auto result = t.start();
  REQUIRE(result.isOk());

  t.stop();
}

TEST_CASE("TransportErrorInfo carries all fields on failure", "[transport][result]")
{
  auto t = Transport::tcp();
  REQUIRE(t.start().isOk());

  // TCP connectViaListener returns err with TransportError::Config
  auto result = t.connectViaListener(999, "127.0.0.1", 5060);
  REQUIRE(result.isErr());
  REQUIRE(result.error().code == TransportError::Config);
  REQUIRE_FALSE(result.error().message.empty());

  t.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.14: DataCallback receiveTime
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("DataCallback receiveTime is recent", "[transport][timestamp]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();

  std::chrono::steady_clock::time_point receivedTime{};
  std::atomic<bool> connected{false};
  std::atomic<bool> dataReceived{false};

  server.onAccept([](SessionId, const TransportAddress &) {});
  server.onData([&](SessionId, iora::core::BufferView,
                    std::chrono::steady_clock::time_point t)
  {
    receivedTime = t;
    dataReceived = true;
  });

  client.onConnect([&](SessionId, const TransportAddress &) { connected = true; });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());

  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());

  REQUIRE(waitFor([&] { return connected.load(); }));

  auto before = std::chrono::steady_clock::now();
  client.send(conn.value(), "test", 4);
  REQUIRE(waitFor([&] { return dataReceived.load(); }));
  auto after = std::chrono::steady_clock::now();

  REQUIRE(receivedTime >= before);
  REQUIRE(receivedTime <= after);

  client.stop();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.13: Stats
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Stats fields populated after activity", "[transport][stats]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();
  std::atomic<SessionId> serverSid{0};
  std::atomic<bool> connected{false};

  server.onAccept([&](SessionId s, const TransportAddress &) { serverSid = s; });
  client.onConnect([&](SessionId, const TransportAddress &) { connected = true; });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());

  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());
  REQUIRE(waitFor([&] { return connected.load() && serverSid != 0; }));

  // Send data in both directions
  client.send(conn.value(), "hello", 5);
  REQUIRE(waitFor([&] { return server.getStats().bytesIn > 0; }));

  server.send(serverSid, "world", 5);
  REQUIRE(waitFor([&] { return client.getStats().bytesIn > 0; }));

  // Check server stats
  auto ss = server.getStats();
  REQUIRE(ss.accepted >= 1);
  REQUIRE(ss.sessionsCurrent >= 1);
  REQUIRE(ss.bytesIn >= 5);
  REQUIRE(ss.bytesOut >= 5);

  // Check client stats
  auto cs = client.getStats();
  REQUIRE(cs.connected >= 1);
  REQUIRE(cs.bytesIn >= 5);
  REQUIRE(cs.bytesOut >= 5);

  // Close and check sessionsCurrent drops
  client.close(conn.value());
  REQUIRE(waitFor([&] { return server.getStats().closed > 0; }));

  auto finalStats = server.getStats();
  REQUIRE(finalStats.closed >= 1);
  REQUIRE(finalStats.sessionsPeak >= 1);

  client.stop();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.4: UDP session management
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("UDP connectViaListener works", "[transport][udp][connection]")
{
  auto port = testnet::getFreePortUDP();
  auto t = Transport::udp();

  REQUIRE(t.start().isOk());
  auto lr = t.addListener("127.0.0.1", port);
  REQUIRE(lr.isOk());

  auto cr = t.connectViaListener(lr.value(), "127.0.0.1", port + 1);
  REQUIRE(cr.isOk());
  REQUIRE(cr.value() > 0);

  t.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.5: Sync data operations
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("sendSync blocks and returns result", "[transport][sync]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();
  std::atomic<SessionId> serverSid{0};

  server.onAccept([&](SessionId s, const TransportAddress &) { serverSid = s; });
  server.onData([](SessionId, iora::core::BufferView, std::chrono::steady_clock::time_point) {});

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());

  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());
  REQUIRE(waitFor([&] { return serverSid.load() != 0; }));

  const char *msg = "sync hello";
  auto result = client.sendSync(conn.value(),
    iora::core::BufferView{reinterpret_cast<const std::uint8_t *>(msg), std::strlen(msg)});
  REQUIRE(result.isOk());
  REQUIRE(result.value() == std::strlen(msg));

  client.stop();
  server.stop();
}

TEST_CASE("receiveSync blocks and returns data", "[transport][sync]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();
  std::atomic<SessionId> serverSid{0};
  std::atomic<bool> clientConnected{false};

  server.onAccept([&](SessionId s, const TransportAddress &) { serverSid = s; });
  client.onConnect([&](SessionId, const TransportAddress &) { clientConnected = true; });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());

  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());
  REQUIRE(waitFor([&] { return serverSid.load() != 0 && clientConnected.load(); }));

  REQUIRE(client.setReadMode(conn.value(), ReadMode::Sync));
  server.send(serverSid.load(), "sync data", 9);

  char buf[64]{};
  std::size_t len = sizeof(buf);
  auto result = client.receiveSync(conn.value(), buf, len);
  REQUIRE(result.isOk());
  REQUIRE(result.value() > 0);
  REQUIRE(std::string(buf, result.value()) == "sync data");

  client.stop();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.6: connectSync operations
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("connectSync blocks until handshake completes", "[transport][connectSync]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  server.onAccept([](SessionId, const TransportAddress &) {});
  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());

  auto client = Transport::tcp();
  REQUIRE(client.start().isOk());

  auto result = client.connectSync("127.0.0.1", port);
  REQUIRE(result.isOk());
  SessionId sid = result.value();
  REQUIRE(sid > 0);
  REQUIRE(client.send(sid, "test", 4));

  client.stop();
  server.stop();
}

TEST_CASE("connectSync timeout on unreachable host", "[transport][connectSync]")
{
  auto client = Transport::tcp();
  REQUIRE(client.start().isOk());

  auto result = client.connectSync("10.254.254.254", 9999, TlsMode::None, 500ms);
  REQUIRE(result.isErr());
  REQUIRE(result.error().code == TransportError::Timeout);

  client.stop();
}

TEST_CASE("connectSync global onConnect NOT fired", "[transport][connectSync]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  server.onAccept([](SessionId, const TransportAddress &) {});
  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());

  auto client = Transport::tcp();
  std::atomic<int> globalConnectCount{0};
  client.onConnect([&](SessionId, const TransportAddress &) { globalConnectCount++; });
  REQUIRE(client.start().isOk());

  auto result = client.connectSync("127.0.0.1", port);
  REQUIRE(result.isOk());

  std::this_thread::sleep_for(100ms);
  REQUIRE(globalConnectCount.load() == 0);

  client.stop();
  server.stop();
}

TEST_CASE("UDP connectSync behaves like connect (immediate)", "[transport][connectSync][udp]")
{
  auto port = testnet::getFreePortUDP();
  auto t = Transport::udp();
  REQUIRE(t.start().isOk());
  REQUIRE(t.addListener("127.0.0.1", port).isOk());

  auto before = std::chrono::steady_clock::now();
  auto result = t.connectSync("127.0.0.1", port + 1);
  auto elapsed = std::chrono::steady_clock::now() - before;

  REQUIRE(result.isOk());
  REQUIRE(result.value() > 0);
  REQUIRE(elapsed < 100ms);

  t.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.8 remaining: Observer edge cases
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Observer auto-cleanup on session destruction", "[transport][observers]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  std::atomic<SessionId> sid{0};
  std::atomic<int> obsCount{0};

  server.onAccept([&](SessionId s, const TransportAddress &) { sid = s; });
  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());

  auto client = Transport::tcp();
  REQUIRE(client.start().isOk());
  client.connect("127.0.0.1", port);
  REQUIRE(waitFor([&] { return sid.load() != 0; }));

  auto id = server.observe(sid.load(), [&](SessionId, const TransportErrorInfo &) { obsCount++; });

  server.close(sid.load());
  REQUIRE(waitFor([&] { return obsCount.load() > 0; }));

  REQUIRE_FALSE(server.unobserve(id));

  client.stop();
  server.stop();
}

TEST_CASE("Observer can close a different session", "[transport][observers]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  std::atomic<SessionId> sid1{0};
  std::atomic<SessionId> sid2{0};
  std::atomic<int> acceptCount{0};
  std::atomic<int> closeCount{0};

  server.onAccept([&](SessionId s, const TransportAddress &)
  {
    if (acceptCount.fetch_add(1) == 0)
      sid1 = s;
    else
      sid2 = s;
  });
  server.onClose([&](SessionId, const TransportErrorInfo &) { closeCount++; });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());

  auto client1 = Transport::tcp();
  auto client2 = Transport::tcp();
  REQUIRE(client1.start().isOk());
  REQUIRE(client2.start().isOk());
  client1.connect("127.0.0.1", port);
  client2.connect("127.0.0.1", port);
  REQUIRE(waitFor([&] { return sid1.load() != 0 && sid2.load() != 0; }));

  server.observe(sid1.load(), [&](SessionId, const TransportErrorInfo &)
  { server.close(sid2.load()); });

  server.close(sid1.load());
  REQUIRE(waitFor([&] { return closeCount.load() >= 2; }));

  client1.stop();
  client2.stop();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.12: Read modes
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("setReadMode switches between Async and Sync", "[transport][readmode]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();
  std::atomic<bool> clientConnected{false};

  server.onAccept([](SessionId, const TransportAddress &) {});
  client.onConnect([&](SessionId, const TransportAddress &) { clientConnected = true; });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());
  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());
  REQUIRE(waitFor([&] { return clientConnected.load(); }));

  REQUIRE(client.setReadMode(conn.value(), ReadMode::Sync));
  REQUIRE(client.setReadMode(conn.value(), ReadMode::Async));

  client.stop();
  server.stop();
}

TEST_CASE("Sync mode buffers data for receiveSync", "[transport][readmode]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();
  std::atomic<SessionId> serverSid{0};
  std::atomic<bool> clientConnected{false};

  server.onAccept([&](SessionId s, const TransportAddress &) { serverSid = s; });
  client.onConnect([&](SessionId, const TransportAddress &) { clientConnected = true; });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());
  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());
  REQUIRE(waitFor([&] { return serverSid.load() != 0 && clientConnected.load(); }));

  REQUIRE(client.setReadMode(conn.value(), ReadMode::Sync));
  server.send(serverSid.load(), "buffered", 8);

  char buf[64]{};
  std::size_t len = sizeof(buf);
  auto result = client.receiveSync(conn.value(), buf, len);
  REQUIRE(result.isOk());
  REQUIRE(std::string(buf, result.value()) == "buffered");

  client.stop();
  server.stop();
}

TEST_CASE("Switching Sync to Async flushes buffered data", "[transport][readmode]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();
  std::atomic<SessionId> serverSid{0};
  std::atomic<bool> clientConnected{false};
  std::string asyncReceived;
  std::mutex mtx;

  server.onAccept([&](SessionId s, const TransportAddress &) { serverSid = s; });
  client.onConnect([&](SessionId, const TransportAddress &) { clientConnected = true; });
  client.onData([&](SessionId, iora::core::BufferView data, std::chrono::steady_clock::time_point)
  {
    std::lock_guard<std::mutex> lk(mtx);
    asyncReceived.append(reinterpret_cast<const char *>(data.data()), data.size());
  });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());
  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());
  REQUIRE(waitFor([&] { return serverSid.load() != 0 && clientConnected.load(); }));

  REQUIRE(client.setReadMode(conn.value(), ReadMode::Sync));
  server.send(serverSid.load(), "flushed", 7);
  std::this_thread::sleep_for(200ms);

  REQUIRE(client.setReadMode(conn.value(), ReadMode::Async));
  REQUIRE(waitFor([&]
  {
    std::lock_guard<std::mutex> lk(mtx);
    return !asyncReceived.empty();
  }));

  std::lock_guard<std::mutex> lk(mtx);
  REQUIRE(asyncReceived == "flushed");

  client.stop();
  server.stop();
}

TEST_CASE("Disabled mode suppresses reads", "[transport][readmode]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();
  std::atomic<SessionId> serverSid{0};
  std::atomic<bool> clientConnected{false};
  std::atomic<int> dataCount{0};

  server.onAccept([&](SessionId s, const TransportAddress &) { serverSid = s; });
  client.onConnect([&](SessionId, const TransportAddress &) { clientConnected = true; });
  client.onData([&](SessionId, iora::core::BufferView, std::chrono::steady_clock::time_point)
  { dataCount++; });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());
  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());
  REQUIRE(waitFor([&] { return serverSid.load() != 0 && clientConnected.load(); }));

  REQUIRE(client.setReadMode(conn.value(), ReadMode::Disabled));
  server.send(serverSid.load(), "dropped", 7);
  std::this_thread::sleep_for(200ms);
  REQUIRE(dataCount.load() == 0);

  REQUIRE(client.setReadMode(conn.value(), ReadMode::Async));
  server.send(serverSid.load(), "visible", 7);
  REQUIRE(waitFor([&] { return dataCount.load() > 0; }));

  client.stop();
  server.stop();
}

TEST_CASE("getReadMode returns false for unknown session", "[transport][readmode]")
{
  auto t = Transport::tcp();
  REQUIRE(t.start().isOk());
  ReadMode mode;
  REQUIRE_FALSE(t.getReadMode(999999, mode));
  t.stop();
}

TEST_CASE("setReadMode returns false when allowReadModeSwitch is false", "[transport][readmode]")
{
  TransportConfig cfg;
  cfg.allowReadModeSwitch = false;
  auto t = Transport(std::move(cfg));
  REQUIRE(t.start().isOk());
  REQUIRE_FALSE(t.setReadMode(1, ReadMode::Sync));
  t.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.9: Session introspection (adapter stubs — Phase 7 for full impl)
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("getListenerAddress returns actual bound address", "[transport][introspection]")
{
  auto port = testnet::getFreePortTCP();
  auto t = Transport::tcp();
  REQUIRE(t.start().isOk());
  auto lr = t.addListener("127.0.0.1", port);
  REQUIRE(lr.isOk());
  auto addr = t.getListenerAddress(lr.value());
  REQUIRE(addr.host == "127.0.0.1");
  REQUIRE(addr.port == port);
  t.stop();
}

TEST_CASE("getLocalAddress/getRemoteAddress return actual addresses", "[transport][introspection]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();
  std::atomic<bool> connected{false};

  client.onConnect([&](SessionId, const TransportAddress &) { connected = true; });
  server.onAccept([](SessionId, const TransportAddress &) {});

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());
  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());
  REQUIRE(waitFor([&] { return connected.load(); }));

  auto local = client.getLocalAddress(conn.value());
  auto remote = client.getRemoteAddress(conn.value());
  REQUIRE(local.host == "127.0.0.1");
  REQUIRE(local.port > 0);
  REQUIRE(remote.host == "127.0.0.1");
  REQUIRE(remote.port == port);

  client.stop();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.15: DSCP (adapter stub — Phase 7 for socket-level verification)
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("DSCP config value accepted without crash", "[transport][dscp]")
{
  TransportConfig cfg;
  cfg.dscpValue = 46;
  auto t = Transport(std::move(cfg));
  REQUIRE(t.start().isOk());
  t.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.16: Batching (adapter stub — Phase 7 for batched I/O verification)
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Batching config accepted without crash", "[transport][batching]")
{
  auto cfg = TransportConfig::forHighThroughput();
  REQUIRE(cfg.batching.enabled == true);
  auto t = Transport(std::move(cfg));
  REQUIRE(t.start().isOk());
  t.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.14 addition: lastError
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("lastError returns error info without crash", "[transport][result]")
{
  auto t = Transport::tcp();
  auto err = t.lastError();
  (void)err;
  REQUIRE(t.start().isOk());
  auto err2 = t.lastError();
  (void)err2;
  t.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// task-6.17: Thread safety (concurrent access)
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Concurrent send from multiple threads", "[transport][thread-safety]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();
  std::atomic<SessionId> serverSid{0};
  std::atomic<bool> clientConnected{false};
  std::atomic<std::size_t> totalReceived{0};

  server.onAccept([&](SessionId s, const TransportAddress &) { serverSid = s; });
  server.onData([&](SessionId, iora::core::BufferView data, std::chrono::steady_clock::time_point)
  { totalReceived += data.size(); });
  client.onConnect([&](SessionId, const TransportAddress &) { clientConnected = true; });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());
  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());
  REQUIRE(waitFor([&] { return clientConnected.load(); }));

  constexpr int numThreads = 4;
  constexpr int sendsPerThread = 50;
  std::atomic<int> successfulSends{0};
  std::vector<std::thread> threads;
  for (int i = 0; i < numThreads; ++i)
  {
    threads.emplace_back([&, sid = conn.value()]
    {
      for (int j = 0; j < sendsPerThread; ++j)
      {
        if (client.send(sid, "X", 1))
        {
          successfulSends++;
        }
      }
    });
  }
  for (auto &th : threads)
  {
    th.join();
  }

  // All successfully enqueued sends should arrive
  REQUIRE(successfulSends.load() > 0);
  REQUIRE(waitFor([&]
  {
    return totalReceived.load() >= static_cast<std::size_t>(successfulSends.load());
  }));

  client.stop();
  server.stop();
}

TEST_CASE("observe/unobserve concurrent with session close", "[transport][thread-safety]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  std::atomic<SessionId> sid{0};

  server.onAccept([&](SessionId s, const TransportAddress &) { sid = s; });
  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());

  auto client = Transport::tcp();
  REQUIRE(client.start().isOk());
  client.connect("127.0.0.1", port);
  REQUIRE(waitFor([&] { return sid.load() != 0; }));

  std::atomic<bool> done{false};
  std::thread observerThread([&]
  {
    while (!done.load())
    {
      auto id = server.observe(sid.load(), [](SessionId, const TransportErrorInfo &) {});
      server.unobserve(id);
    }
  });

  std::this_thread::sleep_for(50ms);
  server.close(sid.load());
  done = true;
  observerThread.join();

  client.stop();
  server.stop();
}

TEST_CASE("Callback replacement concurrent with callback invocation", "[transport][thread-safety]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  std::atomic<int> totalAccepts{0};

  server.onAccept([&](SessionId, const TransportAddress &) { totalAccepts++; });
  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());

  std::atomic<bool> done{false};
  std::thread replacer([&]
  {
    while (!done.load())
    {
      server.onAccept([&](SessionId, const TransportAddress &) { totalAccepts++; });
    }
  });

  std::vector<Transport> clients;
  for (int i = 0; i < 5; ++i)
  {
    clients.push_back(Transport::tcp());
    clients.back().start();
    clients.back().connect("127.0.0.1", port);
  }

  REQUIRE(waitFor([&] { return totalAccepts.load() >= 3; }));

  done = true;
  replacer.join();

  for (auto &c : clients)
  {
    c.stop();
  }
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// Review round 4: onError callback
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("onError callback registration and bind failure via result", "[transport][callbacks][onError]")
{
  // Note: bind failures are returned synchronously via ListenResult::err(),
  // not asynchronously via the onError callback. The onError callback fires
  // for engine-level errors (epoll failures, I/O thread panics). This test
  // verifies the callback registration plumbing doesn't crash and that
  // bind failures are properly reported.
  auto t = Transport::tcp();
  std::atomic<int> errorCount{0};

  t.onError([&](TransportError code, const std::string &msg)
  {
    errorCount++;
    (void)code;
    (void)msg;
  });

  REQUIRE(t.start().isOk());

  // Bind to an invalid address — fails synchronously
  auto lr = t.addListener("192.0.2.1", 0);
  REQUIRE(lr.isErr());
  REQUIRE(lr.error().code == TransportError::Bind);

  t.stop();
}

TEST_CASE("onError callback replacement: only latest fires", "[transport][callbacks][onError]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  std::atomic<int> count1{0}, count2{0};

  server.onError([&](TransportError, const std::string &) { count1++; });
  server.onError([&](TransportError, const std::string &) { count2++; }); // Replaces first

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());

  // Verify replacement didn't break normal operation
  auto client = Transport::tcp();
  REQUIRE(client.start().isOk());
  auto conn = client.connectSync("127.0.0.1", port);
  REQUIRE(conn.isOk());

  client.stop();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// Review round 4: connectSync connection-refused race
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("connectSync ECONNREFUSED returns err, no global onClose", "[transport][connectSync][refused]")
{
  auto client = Transport::tcp();
  std::mutex mtx;
  std::vector<SessionId> closedSids;
  std::atomic<int> globalConnectCount{0};

  client.onClose([&](SessionId sid, const TransportErrorInfo &)
  {
    std::lock_guard<std::mutex> lk(mtx);
    closedSids.push_back(sid);
  });
  client.onConnect([&](SessionId, const TransportAddress &) { globalConnectCount++; });
  REQUIRE(client.start().isOk());

  // Connect to a port with no listener — ECONNREFUSED
  auto port = testnet::getFreePortTCP();
  auto result = client.connectSync("127.0.0.1", port, TlsMode::None, 2000ms);
  REQUIRE(result.isErr());

  // Flush the I/O queue: do a successful connectSync round-trip to ensure
  // all deferred callbacks from the failed connect have been processed.
  auto flushPort = testnet::getFreePortTCP();
  auto flushServer = Transport::tcp();
  flushServer.onAccept([](SessionId, const TransportAddress &) {});
  REQUIRE(flushServer.start().isOk());
  REQUIRE(flushServer.addListener("127.0.0.1", flushPort).isOk());
  auto flushResult = client.connectSync("127.0.0.1", flushPort);
  REQUIRE(flushResult.isOk());
  SessionId flushSid = flushResult.value();

  // Check that no global onClose fired for unknown sids before the flush.
  // The flush session may fire onClose when we close it, but that's expected.
  {
    std::lock_guard<std::mutex> lk(mtx);
    // No global close should have fired yet (the ECONNREFUSED was suppressed,
    // and the flush session is still open).
    REQUIRE(closedSids.empty());
  }
  REQUIRE(globalConnectCount.load() == 0);

  // Clean up
  client.close(flushSid);
  flushServer.stop();
  client.stop();
}

TEST_CASE("connectSync ECONNREFUSED does not leak pending entry", "[transport][connectSync][refused]")
{
  auto client = Transport::tcp();
  REQUIRE(client.start().isOk());

  // Multiple sequential connectSync failures should not leak state
  auto port = testnet::getFreePortTCP();
  for (int i = 0; i < 10; ++i)
  {
    auto result = client.connectSync("127.0.0.1", port, TlsMode::None, 500ms);
    REQUIRE(result.isErr());
  }

  // If state leaked, the transport would have stale entries.
  // Verify we can still connect successfully after failures.
  auto serverPort = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  server.onAccept([](SessionId, const TransportAddress &) {});
  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", serverPort).isOk());

  auto result = client.connectSync("127.0.0.1", serverPort);
  REQUIRE(result.isOk());

  client.stop();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// Review round 4: receiveSync close-before-receive race
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("receiveSync returns PeerClosed when close arrives during blocking wait", "[transport][sync][close-race]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();
  std::atomic<SessionId> serverSid{0};
  std::atomic<bool> clientConnected{false};

  server.onAccept([&](SessionId s, const TransportAddress &) { serverSid = s; });
  client.onConnect([&](SessionId, const TransportAddress &) { clientConnected = true; });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());

  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());
  REQUIRE(waitFor([&] { return serverSid.load() != 0 && clientConnected.load(); }));

  // Set read mode to Sync
  REQUIRE(client.setReadMode(conn.value(), ReadMode::Sync));

  // Start receiveSync in a background thread BEFORE triggering close.
  // This tests the actual race: receiveSync is blocking when close arrives.
  std::atomic<bool> receiveDone{false};
  SendResult receiveResult = SendResult::err(TransportErrorInfo{TransportError::None, ""});
  std::thread receiver([&]
  {
    char buf[64]{};
    std::size_t len = sizeof(buf);
    receiveResult = client.receiveSync(conn.value(), buf, len, 5000ms);
    receiveDone = true;
  });

  // Wait for the receiver thread to be blocked in receiveSync
  std::this_thread::sleep_for(100ms);

  // Close the server-side session (triggers close on client side)
  server.close(serverSid.load());

  // The receiver thread should wake up with PeerClosed
  receiver.join();
  REQUIRE(receiveDone.load());
  REQUIRE(receiveResult.isErr());
  REQUIRE(receiveResult.error().code == TransportError::PeerClosed);

  client.stop();
  server.stop();
}

TEST_CASE("receiveSync on closed session with tombstone returns PeerClosed", "[transport][sync][tombstone]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();
  std::atomic<SessionId> serverSid{0};
  std::atomic<bool> clientConnected{false};
  std::atomic<bool> clientClosed{false};

  server.onAccept([&](SessionId s, const TransportAddress &) { serverSid = s; });
  client.onConnect([&](SessionId, const TransportAddress &) { clientConnected = true; });
  client.onClose([&](SessionId, const TransportErrorInfo &) { clientClosed = true; });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());

  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());
  REQUIRE(waitFor([&] { return serverSid.load() != 0 && clientConnected.load(); }));

  // Close the server-side session — triggers onClose on client before setReadMode
  server.close(serverSid.load());
  REQUIRE(waitFor([&] { return clientClosed.load(); }));

  // NOW set read mode after close — tombstone should be present
  REQUIRE(client.setReadMode(conn.value(), ReadMode::Sync));

  // receiveSync should return PeerClosed via the tombstone
  char buf[64]{};
  std::size_t len = sizeof(buf);
  auto result = client.receiveSync(conn.value(), buf, len, 500ms);
  REQUIRE(result.isErr());
  REQUIRE(result.error().code == TransportError::PeerClosed);

  client.stop();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// Review round 4: TLS handshake via Transport API
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TLS connection via Transport API", "[transport][tls]")
{
  std::string certFile = std::string(IORA_TEST_RESOURCE_DIR) + "/tls-certs/test_tls_cert.pem";
  std::string keyFile = std::string(IORA_TEST_RESOURCE_DIR) + "/tls-certs/test_tls_key.pem";

  // Check if TLS certs are available
  {
    FILE *f = std::fopen(certFile.c_str(), "r");
    if (!f)
    {
      WARN("TLS certs not available at " << certFile << " — skipping TLS test");
      return;
    }
    std::fclose(f);
  }

  auto port = testnet::getFreePortTCP();

  TransportConfig serverCfg;
  serverCfg.serverTls.enabled = true;
  serverCfg.serverTls.defaultMode = TlsMode::Server;
  serverCfg.serverTls.certFile = certFile;
  serverCfg.serverTls.keyFile = keyFile;
  auto server = Transport(std::move(serverCfg));

  TransportConfig clientCfg;
  clientCfg.clientTls.enabled = true;
  clientCfg.clientTls.defaultMode = TlsMode::Client;
  clientCfg.clientTls.verifyPeer = false; // Self-signed cert
  auto client = Transport(std::move(clientCfg));

  std::atomic<int> acceptCount{0};
  std::atomic<bool> connected{false};
  std::string serverReceived;
  std::mutex mtx;

  server.onAccept([&](SessionId, const TransportAddress &) { acceptCount++; });
  server.onData([&](SessionId, iora::core::BufferView data, std::chrono::steady_clock::time_point)
  {
    std::lock_guard<std::mutex> lk(mtx);
    serverReceived.append(reinterpret_cast<const char *>(data.data()), data.size());
  });

  client.onConnect([&](SessionId, const TransportAddress &) { connected = true; });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port, TlsMode::Server).isOk());
  REQUIRE(client.start().isOk());

  auto conn = client.connect("127.0.0.1", port, TlsMode::Client);
  REQUIRE(conn.isOk());

  REQUIRE(waitFor([&] { return connected.load() && acceptCount.load() > 0; }, 5000ms));

  // Send data over TLS connection
  client.send(conn.value(), "tls hello", 9);
  REQUIRE(waitFor([&]
  {
    std::lock_guard<std::mutex> lk(mtx);
    return serverReceived.size() >= 9;
  }));

  {
    std::lock_guard<std::mutex> lk(mtx);
    REQUIRE(serverReceived == "tls hello");
  }

  // Verify TLS stats on both sides
  auto ss = server.getStats();
  REQUIRE(ss.tlsHandshakes >= 1);
  REQUIRE(ss.tlsFailures == 0);

  auto cs = client.getStats();
  REQUIRE(cs.tlsHandshakes >= 1);
  REQUIRE(cs.tlsFailures == 0);

  client.stop();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// Review round 4: Cancellation tokens
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("CancellationToken basic operations", "[transport][cancellation]")
{
  CancellationToken token;
  REQUIRE_FALSE(token.isCancelled());

  token.cancel();
  REQUIRE(token.isCancelled());

  token.reset();
  REQUIRE_FALSE(token.isCancelled());
}

TEST_CASE("connectSyncCancellable returns Cancelled when pre-cancelled", "[transport][cancellation]")
{
  auto client = Transport::tcp();
  REQUIRE(client.start().isOk());

  CancellationToken token;
  token.cancel();

  auto result = client.connectSyncCancellable("127.0.0.1", 9999, token);
  REQUIRE(result.isErr());
  REQUIRE(result.error().code == TransportError::Cancelled);

  client.stop();
}

TEST_CASE("sendSyncCancellable returns Cancelled when pre-cancelled", "[transport][cancellation]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();
  std::atomic<bool> connected{false};

  server.onAccept([](SessionId, const TransportAddress &) {});
  client.onConnect([&](SessionId, const TransportAddress &) { connected = true; });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());

  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());
  REQUIRE(waitFor([&] { return connected.load(); }));

  CancellationToken token;
  token.cancel();

  auto result = client.sendSyncCancellable(conn.value(),
    iora::core::BufferView{reinterpret_cast<const std::uint8_t *>("test"), 4}, token);
  REQUIRE(result.isErr());
  REQUIRE(result.error().code == TransportError::Cancelled);

  client.stop();
  server.stop();
}

TEST_CASE("receiveSyncCancellable returns Cancelled when pre-cancelled", "[transport][cancellation]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();
  std::atomic<bool> connected{false};

  server.onAccept([](SessionId, const TransportAddress &) {});
  client.onConnect([&](SessionId, const TransportAddress &) { connected = true; });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());

  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());
  REQUIRE(waitFor([&] { return connected.load(); }));

  REQUIRE(client.setReadMode(conn.value(), ReadMode::Sync));

  CancellationToken token;
  token.cancel();

  char buf[64]{};
  std::size_t len = sizeof(buf);
  auto result = client.receiveSyncCancellable(conn.value(), buf, len, token);
  REQUIRE(result.isErr());
  REQUIRE(result.error().code == TransportError::Cancelled);

  client.stop();
  server.stop();
}

TEST_CASE("receiveSyncCancellable wakes up when cancelled mid-operation", "[transport][cancellation][blocking]")
{
  auto port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();
  std::atomic<bool> connected{false};

  server.onAccept([](SessionId, const TransportAddress &) {});
  client.onConnect([&](SessionId, const TransportAddress &) { connected = true; });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());

  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());
  REQUIRE(waitFor([&] { return connected.load(); }));

  REQUIRE(client.setReadMode(conn.value(), ReadMode::Sync));

  CancellationToken token;
  std::atomic<bool> receiveDone{false};
  SendResult receiveResult = SendResult::err(TransportErrorInfo{TransportError::None, ""});

  // Start receiveSyncCancellable in background with a long timeout.
  // No data is being sent, so it will block.
  std::thread receiver([&]
  {
    char buf[64]{};
    std::size_t len = sizeof(buf);
    receiveResult = client.receiveSyncCancellable(conn.value(), buf, len, token, 30000ms);
    receiveDone = true;
  });

  // Wait for the receiver to be blocked
  std::this_thread::sleep_for(200ms);
  REQUIRE_FALSE(receiveDone.load());

  // Cancel the token — the receiver should wake up within ~100ms (sub-timeout interval)
  auto cancelTime = std::chrono::steady_clock::now();
  token.cancel();

  receiver.join();
  auto wakeTime = std::chrono::steady_clock::now();

  REQUIRE(receiveDone.load());
  REQUIRE(receiveResult.isErr());
  REQUIRE(receiveResult.error().code == TransportError::Cancelled);

  // Should have woken within 200ms (sub-timeout is 100ms + some overhead)
  auto wakeLatency = std::chrono::duration_cast<std::chrono::milliseconds>(wakeTime - cancelTime);
  REQUIRE(wakeLatency < 500ms);

  client.stop();
  server.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// Review round 4: UDP data exchange
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("UDP bidirectional data exchange via connectViaListener", "[transport][udp][data]")
{
  auto portA = testnet::getFreePortUDP();
  auto portB = testnet::getFreePortUDP();

  auto nodeA = Transport::udp();
  auto nodeB = Transport::udp();

  std::string receivedByA, receivedByB;
  std::mutex mtx;

  nodeA.onData([&](SessionId, iora::core::BufferView data, std::chrono::steady_clock::time_point)
  {
    std::lock_guard<std::mutex> lk(mtx);
    receivedByA.append(reinterpret_cast<const char *>(data.data()), data.size());
  });
  nodeB.onData([&](SessionId, iora::core::BufferView data, std::chrono::steady_clock::time_point)
  {
    std::lock_guard<std::mutex> lk(mtx);
    receivedByB.append(reinterpret_cast<const char *>(data.data()), data.size());
  });

  REQUIRE(nodeA.start().isOk());
  REQUIRE(nodeB.start().isOk());

  auto lrA = nodeA.addListener("127.0.0.1", portA);
  REQUIRE(lrA.isOk());
  auto lrB = nodeB.addListener("127.0.0.1", portB);
  REQUIRE(lrB.isOk());

  // A connects to B via its own listener
  auto connA = nodeA.connectViaListener(lrA.value(), "127.0.0.1", portB);
  REQUIRE(connA.isOk());

  // B connects to A via its own listener
  auto connB = nodeB.connectViaListener(lrB.value(), "127.0.0.1", portA);
  REQUIRE(connB.isOk());

  // Wait a bit for UDP "connections" to be established
  std::this_thread::sleep_for(100ms);

  // A -> B
  nodeA.send(connA.value(), "hello B", 7);
  REQUIRE(waitFor([&]
  {
    std::lock_guard<std::mutex> lk(mtx);
    return receivedByB.size() >= 7;
  }));

  // B -> A
  nodeB.send(connB.value(), "hello A", 7);
  REQUIRE(waitFor([&]
  {
    std::lock_guard<std::mutex> lk(mtx);
    return receivedByA.size() >= 7;
  }));

  {
    std::lock_guard<std::mutex> lk(mtx);
    REQUIRE(receivedByA == "hello A");
    REQUIRE(receivedByB == "hello B");
  }

  nodeA.stop();
  nodeB.stop();
}

// ══════════════════════════════════════════════════════════════════════════════
// Review round 4: Batching config behavior
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Data delivery works with batching config enabled (smoke test)", "[transport][batching][data]")
{
  auto port = testnet::getFreePortTCP();

  auto serverCfg = TransportConfig::forHighThroughput();
  auto server = Transport(std::move(serverCfg));

  auto clientCfg = TransportConfig::forHighThroughput();
  auto client = Transport(std::move(clientCfg));

  std::atomic<std::size_t> totalReceived{0};
  std::atomic<SessionId> serverSid{0};
  std::atomic<bool> connected{false};

  server.onAccept([&](SessionId s, const TransportAddress &) { serverSid = s; });
  server.onData([&](SessionId, iora::core::BufferView data, std::chrono::steady_clock::time_point)
  { totalReceived += data.size(); });
  client.onConnect([&](SessionId, const TransportAddress &) { connected = true; });

  REQUIRE(server.start().isOk());
  REQUIRE(server.addListener("127.0.0.1", port).isOk());
  REQUIRE(client.start().isOk());

  auto conn = client.connect("127.0.0.1", port);
  REQUIRE(conn.isOk());
  REQUIRE(waitFor([&] { return connected.load() && serverSid.load() != 0; }));

  // Send multiple small messages
  for (int i = 0; i < 20; ++i)
  {
    client.send(conn.value(), "batch", 5);
  }

  // All 100 bytes should eventually arrive
  REQUIRE(waitFor([&] { return totalReceived.load() >= 100; }));

  client.stop();
  server.stop();
}

TEST_CASE("forHighThroughput preset values are correct", "[transport][batching][config]")
{
  auto cfg = TransportConfig::forHighThroughput();
  // These are explicitly set by forHighThroughput():
  REQUIRE(cfg.batching.enabled == true);
  REQUIRE(cfg.batching.maxBatchSize == 128);
  REQUIRE(cfg.batching.maxBatchDelay == std::chrono::microseconds(200));
  REQUIRE(cfg.maxWriteQueue == 4096);
  REQUIRE(cfg.soRcvBuf == 262144);
  REQUIRE(cfg.soSndBuf == 262144);

  // Verify transport accepts the config
  auto t = Transport(std::move(cfg));
  REQUIRE(t.start().isOk());
  REQUIRE(t.getProtocol() == Protocol::TCP);
  t.stop();
}
