// Transport API tests — Phase 6 of transport refactor
// Tests the new Transport class (ITransport, Config, Stats, Result<T,E> integration)

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/network/transport_impl.hpp"
#include "iora_test_net_utils.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
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
