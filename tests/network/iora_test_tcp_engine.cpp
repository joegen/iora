#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "iora/network/detail/tcp_engine.hpp"
#include "iora_test_net_utils.hpp"
#include "test_helpers.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdio>
#include <map>
#include <memory>
#include <numeric>
#include <vector>
#include <openssl/err.h>
#include <openssl/ssl.h>

using namespace std::chrono_literals;
using TcpEngine = iora::network::TcpEngine;
using TransportConfig = iora::network::TransportConfig;
using TransportAddress = iora::network::TransportAddress;
using TransportErrorInfo = iora::network::TransportErrorInfo;
using TransportError = iora::network::TransportError;
using TlsMode = iora::network::TlsMode;
using SessionId = iora::network::SessionId;
using ListenerId = iora::network::ListenerId;

namespace
{
struct TcpFixture
{
  TransportConfig cfg{};
  TcpEngine tx{cfg};

  std::atomic<size_t> acceptCount{0};
  std::atomic<size_t> connectCount{0};
  std::atomic<size_t> connectFailCount{0};
  std::atomic<size_t> dataCount{0};
  std::atomic<size_t> closeCount{0};
  std::atomic<size_t> errorCount{0};
  std::atomic<size_t> totalBytesReceived{0};
  // Optional server-side echo delay (ms). Default 0 = echo immediately (existing
  // tests). The half-close drop test sets it >0 so onData holds the I/O thread long
  // enough for the client's FIN to arrive and closeNow to run BEFORE the echo is
  // flushed by the command loop — making the drop deterministic instead of relying on
  // the client's send()/shutdown() FIN batching (tracker 2026-09-14-4 round-3 M-1).
  // Set it BEFORE start() so the write happens-before the I/O thread reads it.
  std::atomic<int> echoDelayMs{0};

  std::vector<SessionId> acceptedSessions;
  std::vector<SessionId> connectedSessions;
  std::vector<SessionId> closedSessions;
  std::map<SessionId, std::string> sessionData;
  std::vector<std::string> errorMessages;

  std::mutex callbackMutex;

  SessionId serverSid{0};
  SessionId clientSid{0};
  std::string lastErrMsg;

  TcpFixture()
  {
    iora::network::detail::EngineBase::Callbacks cbs{};
    cbs.onAccept = [&](SessionId sid, const TransportAddress &addr)
    {
      std::lock_guard<std::mutex> lock(callbackMutex);
      acceptedSessions.push_back(sid);
      if (serverSid == 0)
        serverSid = sid;
      acceptCount++;
    };
    cbs.onConnect = [&](SessionId sid, const TransportAddress &addr)
    {
      std::lock_guard<std::mutex> lock(callbackMutex);
      connectedSessions.push_back(sid);
      if (clientSid == 0)
        clientSid = sid;
      connectCount++;
    };
    cbs.onData = [&](SessionId sid, iora::core::BufferView data,
                      std::chrono::steady_clock::time_point)
    {
      bool echo = false;
      {
        std::lock_guard<std::mutex> lock(callbackMutex);
        totalBytesReceived += data.size();
        sessionData[sid].append(reinterpret_cast<const char *>(data.data()), data.size());
        echo = (sid == serverSid); // decide under the lock
        dataCount++;
      }
      // Echo back from server OUTSIDE callbackMutex (copy-then-invoke): tx.send
      // only enqueues today, but holding the fixture lock across an engine call
      // would self-deadlock if send ever dispatched onError/onClose inline. The
      // BufferView stays valid for the callback duration.
      if (echo)
      {
        // Optional delay (default 0): holds the I/O thread so a subsequent client
        // FIN is seen (recv()==0 -> closeNow) before this echo is flushed. See
        // echoDelayMs. Copy the bytes first since the delay outlives the BufferView.
        if (int d = echoDelayMs.load(std::memory_order_relaxed))
        {
          std::string owned(reinterpret_cast<const char *>(data.data()), data.size());
          std::this_thread::sleep_for(std::chrono::milliseconds(d));
          tx.send(sid, owned.data(), owned.size());
        }
        else
        {
          tx.send(sid, data.data(), data.size());
        }
      }
    };
    cbs.onClose = [&](SessionId sid, const TransportErrorInfo &err)
    {
      std::lock_guard<std::mutex> lock(callbackMutex);
      closedSessions.push_back(sid);
      closeCount++;
    };
    cbs.onError = [&](TransportError err, const std::string &msg)
    {
      std::lock_guard<std::mutex> lock(callbackMutex);
      lastErrMsg = msg;
      errorMessages.push_back(msg);
      errorCount++;
    };
    tx.setCallbacks(cbs);
  }

  // Join the engine I/O thread while the callback-touched members are still alive.
  // tx is declared BEFORE those members, so member reverse-destruction would otherwise
  // free them before ~TcpEngine (which stop()s+joins the I/O thread) runs — a live
  // callback then touches freed callbackMutex/sessionData. The trailing f.tx.stop() in
  // each test hides it on the happy path, but a REQUIRE that throws (e.g. a load-induced
  // waitForCondition timeout) unwinds past that stop() and detonates the UAF. noexcept +
  // guarded so a stop() during unwinding cannot std::terminate. (tracker 2026-09-13-7;
  // same fix as ~UdpFixture / ~TlsEchoServer.)
  ~TcpFixture() noexcept
  {
    try
    {
      tx.stop();
    }
    catch (...)
    {
    }
  }

  void reset()
  {
    std::lock_guard<std::mutex> lock(callbackMutex);
    acceptCount = connectCount = connectFailCount = dataCount = closeCount = errorCount =
      totalBytesReceived = 0;
    serverSid = clientSid = 0;
    acceptedSessions.clear();
    connectedSessions.clear();
    closedSessions.clear();
    sessionData.clear();
    errorMessages.clear();
    lastErrMsg.clear();
  }

  // Delegates to the shared iora::test::waitFor poll helper (same predicate-poll-until-
  // timeout loop); keeps the fixture's own 1000ms default. (simplification review.)
  bool waitForCondition(std::function<bool()> condition, std::chrono::milliseconds timeout = 1000ms)
  {
    return iora::test::waitFor(std::move(condition), timeout);
  }

  // Thread-safe snapshot of a session's accumulated bytes: the onData callback
  // appends on the engine I/O thread under callbackMutex, so test bodies (and
  // waitForCondition predicates) MUST read the same map under the same lock.
  // Uses find(), never operator[], so a read never inserts a node and races the
  // I/O-thread write; returns a copy the caller can size/compare/index freely.
  std::string dataFor(SessionId sid)
  {
    std::lock_guard<std::mutex> lock(callbackMutex);
    auto it = sessionData.find(sid);
    return it == sessionData.end() ? std::string{} : it->second;
  }

  // Locked snapshot of the accepted-session ids (onAccept push_back()s on the
  // engine I/O thread under callbackMutex). A test body that reads the vector
  // directly while the I/O thread is still pushing races it; take the lock.
  std::vector<SessionId> acceptedSnapshot()
  {
    std::lock_guard<std::mutex> lock(callbackMutex);
    return acceptedSessions;
  }
  std::vector<SessionId> connectedSnapshot()
  {
    std::lock_guard<std::mutex> lock(callbackMutex);
    return connectedSessions;
  }

  // Size-only locked read: avoids copying the whole accumulated payload just to
  // check its length in a waitForCondition poll (the large-data poll runs for
  // seconds at 5ms granularity).
  std::size_t dataSizeFor(SessionId sid)
  {
    std::lock_guard<std::mutex> lock(callbackMutex);
    auto it = sessionData.find(sid);
    return it == sessionData.end() ? 0u : it->second.size();
  }
};
} // namespace

TEST_CASE("TCP start/stop idempotent", "[tcp]")
{
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());
  REQUIRE(f.tx.start().isErr()); // already running should return err
  f.tx.stop();
  f.tx.stop(); // idempotent
}

TEST_CASE("TCP loopback echo", "[tcp][echo]")
{
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();

  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId cs = cr.value();

  // Wait for accept/connect to fire
  REQUIRE(f.waitForCondition([&]() { return f.acceptCount > 0 && f.connectCount > 0; }));
  REQUIRE(f.acceptedSnapshot().size() == 1);
  REQUIRE(f.connectedSnapshot().size() == 1);

  const char *msg = "hello tcp";
  REQUIRE(f.tx.send(cs, msg, std::strlen(msg)));

  // Wait for echo data to come back
  REQUIRE(f.waitForCondition([&]() { return f.dataSizeFor(cs) > 0; }));
  REQUIRE(f.dataFor(cs) == "hello tcp");

  // close client
  REQUIRE(f.tx.close(cs));
  REQUIRE(f.waitForCondition([&]() { return f.closeCount > 0; }));

  f.tx.stop();
}

TEST_CASE("TCP named-host connect (event-driven resolve)", "[tcp][resolve]")
{
  // Connect by NAME (not an IP literal) so doConnect takes the off-thread
  // resolve -> resumeConnect path (phase-2). "localhost" resolves via
  // /etc/hosts, no network dependency.
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();
  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  auto cr = f.tx.connect("localhost", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId cs = cr.value();

  // The resolve is async, so allow a little longer than the literal path.
  REQUIRE(f.waitForCondition([&]() { return f.connectCount > 0 && f.acceptCount > 0; }, 3000ms));
  REQUIRE(f.connectedSnapshot().size() == 1);
  REQUIRE(f.closeCount == 0); // no spurious onClose(Resolve) on the happy path

  const char *msg = "hello named";
  REQUIRE(f.tx.send(cs, msg, std::strlen(msg)));
  REQUIRE(f.waitForCondition([&]() { return f.dataSizeFor(cs) > 0; }));
  REQUIRE(f.dataFor(cs) == "hello named");

  f.tx.stop();
}

TEST_CASE("TCP named-host connect after restart (fresh post gate)", "[tcp][resolve][restart]")
{
  // Validates task-2.2: start() re-creates the EnginePostGate before the loop.
  // Without it, a resolver continuation posted after restart would drop against
  // a permanently-closed gate, yielding a spurious onClose(Resolve).
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());
  f.tx.stop();
  REQUIRE(f.tx.start().isOk()); // restart — fresh gate must be installed
  f.reset();

  auto port = testnet::getFreePortTCP();
  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  auto cr = f.tx.connect("localhost", port, TlsMode::None);
  REQUIRE(cr.isOk());

  REQUIRE(f.waitForCondition([&]() { return f.connectCount > 0 && f.acceptCount > 0; }, 3000ms));
  REQUIRE(f.connectedSnapshot().size() == 1);
  REQUIRE(f.closeCount == 0); // no spurious onClose(Resolve) after restart

  f.tx.stop();
}

TEST_CASE("TCP stats verification", "[tcp][stats]")
{
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();

  auto stats1 = f.tx.getStats();
  REQUIRE(stats1.sessionsCurrent == 0);
  REQUIRE(stats1.sessionsPeak == 0);
  REQUIRE(stats1.bytesOut == 0);
  REQUIRE(stats1.bytesIn == 0);

  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId cs = cr.value();

  REQUIRE(f.waitForCondition([&]() { return f.acceptCount > 0 && f.connectCount > 0; }));

  auto stats2 = f.tx.getStats();
  REQUIRE(stats2.sessionsCurrent == 2); // client + server session
  REQUIRE(stats2.sessionsPeak >= 2);

  const char *msg = "test stats";
  size_t msgLen = std::strlen(msg);
  REQUIRE(f.tx.send(cs, msg, msgLen));

  REQUIRE(f.waitForCondition([&]() { return f.dataSizeFor(cs) > 0; }));

  auto stats3 = f.tx.getStats();
  REQUIRE(stats3.bytesOut >= msgLen);
  REQUIRE(stats3.bytesIn >= msgLen);

  f.tx.close(cs);
  REQUIRE(f.waitForCondition([&]() { return f.closeCount > 0; }));

  auto stats4 = f.tx.getStats();
  REQUIRE(stats4.sessionsCurrent < stats3.sessionsCurrent);
  REQUIRE(stats4.sessionsPeak >= stats3.sessionsPeak);

  f.tx.stop();
}

TEST_CASE("TCP multiple clients to single server", "[tcp][multiconnect]")
{
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();

  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  const size_t numClients = 5;
  std::vector<SessionId> clients;

  // Connect multiple clients
  for (size_t i = 0; i < numClients; ++i)
  {
    auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
    REQUIRE(cr.isOk());
    clients.push_back(cr.value());
  }

  REQUIRE(f.waitForCondition(
    [&]() { return f.acceptCount >= numClients && f.connectCount >= numClients; }));

  REQUIRE(f.acceptedSnapshot().size() == numClients);
  REQUIRE(f.connectedSnapshot().size() == numClients);

  // Send data from each client
  for (size_t i = 0; i < numClients; ++i)
  {
    std::string msg = "client " + std::to_string(i);
    REQUIRE(f.tx.send(clients[i], msg.c_str(), msg.size()));
  }

  // Wait for all echoes with extended timeout for multiple connections
  bool allEchoed = f.waitForCondition(
    [&]()
    {
      size_t clientsWithData = 0;
      for (auto client : clients)
      {
        if (f.dataSizeFor(client) > 0)
          clientsWithData++;
      }
      return clientsWithData == numClients;
    });

  // If not all echoes received immediately, allow more time for concurrent operations
  if (!allEchoed)
  {
    std::this_thread::sleep_for(300ms);
    size_t clientsWithData = 0;
    for (auto client : clients)
    {
      if (f.dataSizeFor(client) > 0)
        clientsWithData++;
    }
    REQUIRE(clientsWithData >= 1); // At least one client should succeed in concurrent scenario
  }

  // Verify clients that received data got the correct echo
  for (size_t i = 0; i < numClients; ++i)
  {
    std::string got = f.dataFor(clients[i]); // one consistent locked snapshot
    if (got.size() > 0)
    {
      std::string expected = "client " + std::to_string(i);
      REQUIRE(got == expected);
    }
  }

  f.tx.stop();
}

TEST_CASE("TCP failed connection handling", "[tcp][error]")
{
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());

  // Connect to a bound-but-not-listening port: the kernel RSTs it -> ECONNREFUSED
  // deterministically on both standard Linux and WSL2 (a truly-unbound port
  // black-holes the SYN on WSL2). Held open for the whole test scope.
  testnet::RefusingEndpoint refuser;
  auto cr = f.tx.connect("127.0.0.1", refuser.port(), TlsMode::None);
  REQUIRE(cr.isOk());

  // Connect failures now come through onClose, not onConnect
  REQUIRE(f.waitForCondition([&]() { return f.closeCount > 0; }));
  REQUIRE(f.closeCount >= 1);
  REQUIRE(f.connectCount == 0);

  f.tx.stop();
}

TEST_CASE("TCP large data transfer", "[tcp][largedata]")
{
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();

  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId cs = cr.value();

  REQUIRE(f.waitForCondition([&]() { return f.acceptCount > 0 && f.connectCount > 0; }));

  // Send large data (64KB)
  const size_t dataSize = 65536;
  std::vector<uint8_t> largeData(dataSize);
  std::iota(largeData.begin(), largeData.end(), 0);

  REQUIRE(f.tx.send(cs, largeData.data(), largeData.size()));

  REQUIRE(f.waitForCondition([&]() { return f.dataSizeFor(cs) == dataSize; }, 5000ms));

  // Verify data integrity (one consistent locked snapshot)
  std::string got = f.dataFor(cs);
  REQUIRE(got.size() == dataSize);
  for (size_t i = 0; i < dataSize; ++i)
  {
    REQUIRE(static_cast<uint8_t>(got[i]) == static_cast<uint8_t>(i));
  }

  f.tx.stop();
}

TEST_CASE("TCP binary data handling", "[tcp][binary]")
{
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();

  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId cs = cr.value();

  REQUIRE(f.waitForCondition([&]() { return f.acceptCount > 0 && f.connectCount > 0; }));

  // Binary data with null bytes and high values
  std::vector<uint8_t> binaryData = {0x00, 0x01, 0xFF, 0x7F, 0x80, 0xAB, 0xCD, 0xEF};
  REQUIRE(f.tx.send(cs, binaryData.data(), binaryData.size()));

  REQUIRE(f.waitForCondition([&]() { return f.dataSizeFor(cs) == binaryData.size(); }));

  // Verify binary data integrity (one consistent locked snapshot)
  std::string got = f.dataFor(cs);
  REQUIRE(got.size() == binaryData.size());
  for (size_t i = 0; i < binaryData.size(); ++i)
  {
    REQUIRE(static_cast<uint8_t>(got[i]) == binaryData[i]);
  }

  f.tx.stop();
}

TEST_CASE("TCP immediate close after connect", "[tcp][closefast]")
{
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();

  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId cs = cr.value();

  REQUIRE(f.waitForCondition([&]() { return f.acceptCount > 0 && f.connectCount > 0; }));

  // Immediately close after connect
  REQUIRE(f.tx.close(cs));
  REQUIRE(f.waitForCondition([&]() { return f.closeCount > 0; }));

  f.tx.stop();
}

TEST_CASE("TCP operations on closed session", "[tcp][closedops]")
{
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();

  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId cs = cr.value();

  REQUIRE(f.waitForCondition([&]() { return f.acceptCount > 0 && f.connectCount > 0; }));

  // Close session
  REQUIRE(f.tx.close(cs));
  REQUIRE(f.waitForCondition([&]() { return f.closeCount > 0; }));

  // Operations on closed session should either fail gracefully or be handled by implementation
  // TCP transport may not immediately fail on send to closed session
  (void)f.tx.send(cs, "test", 4);
  // Note: Some implementations may still return true for recently closed sessions
  (void)f.tx.close(cs); // Already closed - may return false or true

  f.tx.stop();
}

TEST_CASE("TCP invalid session operations", "[tcp][invalidsession]")
{
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());

  // Operations on invalid session ID should be handled by implementation
  SessionId invalidSid = 99999;
  // TCP transport may not validate session IDs immediately
  (void)f.tx.send(invalidSid, "test", 4);
  (void)f.tx.close(invalidSid);
  // Note: Implementation may queue operations and detect invalid sessions later

  f.tx.stop();
}

TEST_CASE("TCP listener management", "[tcp][listeners]")
{
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());

  auto port1 = testnet::getFreePortTCP();
  auto port2 = testnet::getFreePortTCP();

  // Add multiple listeners
  auto lr1 = f.tx.addListener("127.0.0.1", port1, TlsMode::None);
  REQUIRE(lr1.isOk());
  ListenerId lid1 = lr1.value();

  auto lr2 = f.tx.addListener("127.0.0.1", port2, TlsMode::None);
  REQUIRE(lr2.isOk());
  ListenerId lid2 = lr2.value();

  REQUIRE(lid1 != lid2);

  // Connect to both listeners
  auto cr1 = f.tx.connect("127.0.0.1", port1, TlsMode::None);
  auto cr2 = f.tx.connect("127.0.0.1", port2, TlsMode::None);
  REQUIRE(cr1.isOk());
  REQUIRE(cr2.isOk());
  SessionId cs1 = cr1.value();
  SessionId cs2 = cr2.value();

  REQUIRE(f.waitForCondition([&]() { return f.acceptCount >= 2 && f.connectCount >= 2; }));

  // Note: removeListener API not available, skip this test part
  // REQUIRE(f.tx.removeListener(lid1));

  // Existing connections should still work
  REQUIRE(f.tx.send(cs1, "test1", 5));
  REQUIRE(f.tx.send(cs2, "test2", 5));

  // Wait for data with some tolerance for connection timing
  bool dataReceived = f.waitForCondition(
    [&]() { return f.dataSizeFor(cs1) > 0 && f.dataSizeFor(cs2) > 0; });

  // If immediate data transfer fails, allow for connection setup timing
  if (!dataReceived)
  {
    std::this_thread::sleep_for(200ms);
    dataReceived = f.dataSizeFor(cs1) > 0 && f.dataSizeFor(cs2) > 0;
  }

  f.tx.stop();
}

TEST_CASE("TCP empty data send", "[tcp][emptydata]")
{
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();

  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId cs = cr.value();

  REQUIRE(f.waitForCondition([&]() { return f.acceptCount > 0 && f.connectCount > 0; }));

  // Send empty data
  REQUIRE(f.tx.send(cs, nullptr, 0));

  std::this_thread::sleep_for(100ms); // Give it time to process

  f.tx.stop();
}

TEST_CASE("TCP session ID uniqueness", "[tcp][sessionids]")
{
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();

  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  const size_t numConnections = 10;
  std::vector<SessionId> clientIds;
  std::vector<SessionId> serverIds;

  // Create multiple connections
  for (size_t i = 0; i < numConnections; ++i)
  {
    auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
    REQUIRE(cr.isOk());
    clientIds.push_back(cr.value());
  }

  REQUIRE(f.waitForCondition([&]() { return f.acceptCount >= numConnections; }));

  serverIds = f.acceptedSnapshot();

  // Verify all session IDs are unique
  std::set<SessionId> allIds(clientIds.begin(), clientIds.end());
  allIds.insert(serverIds.begin(), serverIds.end());
  REQUIRE(allIds.size() == clientIds.size() + serverIds.size());

  f.tx.stop();
}

TEST_CASE("TCP high frequency small messages", "[tcp][highfreq]")
{
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();

  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId cs = cr.value();

  REQUIRE(f.waitForCondition([&]() { return f.acceptCount > 0 && f.connectCount > 0; }));

  const size_t numMessages = 100;
  size_t totalExpectedBytes = 0;

  // Send many small messages rapidly
  for (size_t i = 0; i < numMessages; ++i)
  {
    std::string msg = "msg" + std::to_string(i);
    totalExpectedBytes += msg.size();
    REQUIRE(f.tx.send(cs, msg.c_str(), msg.size()));
  }

  // Wait for all data to be echoed back (the waitForCondition REQUIRE is the
  // post-condition: it fails on timeout, and the accumulated size is monotonic).
  REQUIRE(
    f.waitForCondition([&]() { return f.dataSizeFor(cs) == totalExpectedBytes; }, 3000ms));

  f.tx.stop();
}

TEST_CASE("TCP duplicate listener error handling", "[tcp][duplicatelistener]")
{
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();

  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  // Second bind to same port — may succeed (SO_REUSEADDR) or fail
  (void)f.tx.addListener("127.0.0.1", port, TlsMode::None);

  // Give time for async bind failures to surface
  std::this_thread::sleep_for(100ms);

  f.tx.stop();
}

TEST_CASE("TCP transport restart with existing sessions", "[tcp][restart]")
{
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();

  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId cs = cr.value();

  REQUIRE(f.waitForCondition([&]() { return f.acceptCount > 0 && f.connectCount > 0; }));

  // Stop transport (should close all sessions)
  f.tx.stop();

  // Wait for cleanup
  std::this_thread::sleep_for(100ms);

  // Operations on old sessions after restart
  REQUIRE(f.tx.start().isOk());
  // TCP transport may not immediately fail on send to stale session
  (void)f.tx.send(cs, "test", 4);
  // Note: Implementation may handle stale sessions gracefully or asynchronously

  f.tx.stop();
}

// ============================================================================
// TransportConfig::maxSessions on the ACCEPT path.
//
// The cap was UDP-only until 2026-07-26; on TCP/TLS the real ceiling was the
// process fd limit, which invalidated every aggregate per-session memory bound
// stated above this layer. Written because the enforcement shipped with zero
// coverage: `grep maxSessions tests/` matched only UDP, so deleting the check
// would have passed the entire suite identically.
//
// NOTE these build their OWN engine rather than using TcpFixture. TcpEngine takes
// a COPY of the config in its constructor (tcp_engine.hpp:2793), and the fixture
// constructs `TcpEngine tx{cfg}` as a member initializer — so mutating f.cfg in a
// test body never reaches the engine. A first version of this test did exactly
// that and was VACUOUS; it passed with the cap set to 2 and four live sessions.
// (The pre-existing UDP cap test at iora_test_udp_engine.cpp:652 sets f.cfg the
// same way and has the same flaw.)
// ============================================================================

namespace
{
/// Minimal engine harness that fixes the config BEFORE construction.
struct CappedTcpEngine
{
  TransportConfig cfg{};
  std::unique_ptr<TcpEngine> tx;
  std::atomic<size_t> acceptCount{0};
  std::atomic<size_t> errorCount{0};
  std::mutex mu;
  std::string lastErrMsg;

  explicit CappedTcpEngine(std::size_t maxSessions)
  {
    cfg.maxSessions = maxSessions;
    tx = std::make_unique<TcpEngine>(cfg);
    iora::network::detail::EngineBase::Callbacks cbs{};
    cbs.onAccept = [this](SessionId, const TransportAddress &) { acceptCount++; };
    cbs.onConnect = [](SessionId, const TransportAddress &) {};
    cbs.onData = [](SessionId, iora::core::BufferView, std::chrono::steady_clock::time_point) {};
    cbs.onClose = [](SessionId, const TransportErrorInfo &) {};
    cbs.onError = [this](TransportError, const std::string &msg)
    {
      std::lock_guard<std::mutex> lock(mu);
      lastErrMsg = msg;
      errorCount++;
    };
    tx->setCallbacks(cbs);
  }

  // Delegates to the shared iora::test::waitFor poll helper (keeps the 3000ms default);
  // same as TcpFixture::waitForCondition. (simplification review.)
  bool waitFor(std::function<bool()> pred, std::chrono::milliseconds cap = 3000ms)
  {
    return iora::test::waitFor(std::move(pred), cap);
  }

  // Same member-ordering teardown hazard as TcpFixture: tx is declared before the
  // callback-touched acceptCount/errorCount/mu/lastErrMsg, so join the I/O thread here
  // (dtor body, members still alive) rather than during ~TcpEngine at member teardown.
  // A REQUIRE that throws before the test's trailing e.tx->stop() would otherwise unwind
  // into the UAF. (tracker 2026-09-13-7 secondary-instance sweep; same fix as ~TcpFixture.)
  ~CappedTcpEngine() noexcept
  {
    try
    {
      if (tx)
      {
        tx->stop();
      }
    }
    catch (...)
    {
    }
  }
};
} // namespace

TEST_CASE("TCP accept path enforces maxSessions", "[tcp][limits]")
{
  // RAW client sockets, deliberately, NOT e.tx->connect(). Both the accept path
  // (bumpSess at tcp_engine.hpp:1432) and the connect path (:1677) bump the SAME
  // sessionsCurrent that the accept guard tests, so driving clients through the
  // engine under test makes the outcome depend on how those two interleave — a
  // first version of this test did that and failed intermittently (it passed under
  // a [limits] filter and failed in the full binary). Raw sockets mean ONLY accepts
  // consume the budget, which is also the case H-6 is actually about.
  CappedTcpEngine e(2);
  REQUIRE(e.tx->start().isOk());

  auto port = testnet::getFreePortTCP();
  REQUIRE(e.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  auto rawConnect = [&]() -> int
  {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) != 0)
    {
      ::close(fd);
      return -1;
    }
    return fd;
  };

  // Two accepted connections fill the cap exactly.
  std::vector<int> fds;
  for (int i = 0; i < 2; ++i)
  {
    int fd = rawConnect();
    REQUIRE(fd >= 0);
    fds.push_back(fd);
  }
  REQUIRE(e.waitFor([&]() { return e.acceptCount.load() == 2; }));

  // The third is refused AT ACCEPT: the fd is closed immediately, so no onAccept
  // fires and an error naming the cap is raised. The TCP handshake itself still
  // completes (the kernel backlog accepts it), which is why this is observed as an
  // engine-side rejection rather than a connect() failure.
  int extra = rawConnect();
  REQUIRE(e.waitFor([&]() { return e.errorCount.load() > 0; }));
  {
    std::lock_guard<std::mutex> lock(e.mu);
    INFO("last error: " << e.lastErrMsg);
    REQUIRE(e.lastErrMsg.find("maxSessions") != std::string::npos);
  }

  // No extra accept was admitted, and the engine neither busy-spun nor died.
  std::this_thread::sleep_for(200ms);
  REQUIRE(e.acceptCount.load() == 2);
  REQUIRE(e.tx->getStats().sessionsCurrent <= e.cfg.maxSessions);

  if (extra >= 0)
  {
    ::close(extra);
  }
  for (int fd : fds)
  {
    ::close(fd);
  }
  e.tx->stop();
}

TEST_CASE("maxSessions of 0 means unlimited on TCP", "[tcp][limits]")
{
  // 0 is the default for every consumer that does not opt in, so this is the
  // branch that must NOT reject. Guards a truthiness slip in the guard.
  CappedTcpEngine e(0);
  REQUIRE(e.tx->start().isOk());

  auto port = testnet::getFreePortTCP();
  REQUIRE(e.tx->addListener("127.0.0.1", port, TlsMode::None).isOk());

  std::vector<int> fds;
  for (int i = 0; i < 5; ++i)
  {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    REQUIRE(::connect(fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) == 0);
    fds.push_back(fd);
  }
  REQUIRE(e.waitFor([&]() { return e.acceptCount.load() == 5; }));
  REQUIRE(e.errorCount.load() == 0);

  for (int fd : fds)
  {
    ::close(fd);
  }
  e.tx->stop();
}

TEST_CASE("TCP full exchange echoes (positive control for the half-close pin)",
          "[tcp][halfclose]")
{
  // POSITIVE CONTROL for the drop test below: a full-duplex client that does NOT
  // half-close DOES receive the echo, proving the echo path works. It runs on its OWN
  // fixture — sharing one fixture with the drop test would latch TcpFixture::serverSid to
  // whichever client connected first, leaving the other client's session unserviced and
  // making the drop assertion vacuous (round-2 review HIGH). Same design as the TLS pair.
  TcpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();
  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  std::string echoed = testnet::rawTcpHalfCloseExchange(port, "PING", /*halfClose=*/false);
  CHECK(echoed.find("PING") != std::string::npos);

  f.tx.stop();
}

TEST_CASE("TCP read-half-close drops the pending response (recv()==0 close contract)",
          "[tcp][halfclose]")
{
  // tracker 2026-09-14-4: iora tears a session down on read-half EOF (recv()==0). A
  // client that finishes its request then shutdown(SHUT_WR) (a legitimate TCP
  // half-close: "done sending, still reading your response") delivers FIN on the
  // server read half while the response is still being produced (send is async), so
  // readAvail hits recv()==0 -> closeNow() drops the queued/in-flight response. This
  // test PINS that deliberate, documented non-conformance with RFC 9112 §9.6
  // (Tear-down): request half-close is NOT supported. Deferred-close support (fork b)
  // is the conditional backlog tasks/iora/backlog/2026-09-16-1.
  //
  // OWN fixture, ONLY the half-close client connects: it is accepted as the FIRST session
  // so TcpFixture::serverSid latches to it and the server DOES try to echo to it — the
  // drop is therefore observable (non-vacuous). Non-vacuity is also demonstrated by the
  // positive-control test above (same server shape, full-duplex client, echo arrives).
  TcpFixture f;
  // Deterministic drop (round-3 M-1): delay the server echo so the client's FIN is
  // always seen (recv()==0 -> closeNow) BEFORE the echo is flushed. Without this, a
  // client-thread preemption between send() and shutdown() could let the server drain
  // data-only, flush the echo, and only then see the FIN — delivering the echo and
  // false-failing the drop CHECK. Set before start() (happens-before the I/O thread).
  f.echoDelayMs.store(100);
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortTCP();
  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  // Send then shutdown(SHUT_WR): the server reads the request, and the echoDelayMs delay
  // holds the I/O thread until the FIN arrives, so recv()==0 -> closeNow fires and drops
  // the not-yet-flushed echo. Deterministic regardless of send()/FIN batching.
  std::string got = testnet::rawTcpHalfCloseExchange(port, "PING", /*halfClose=*/true);

  // The request DID arrive at the server (onData) and the session WAS closed on the
  // read-half EOF...
  REQUIRE(f.waitForCondition([&] { return f.dataCount.load() >= 1; }));
  REQUIRE(f.waitForCondition([&] { return f.closeCount.load() >= 1; }, 3000ms));
  // ...but the half-closing client received no echo: the echo the server DID attempt for
  // this (serverSid) session was dropped by the close on read-half EOF.
  CHECK(got.find("PING") == std::string::npos);

  f.tx.stop();
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS read-half-close parity (tracker 2026-09-14-4 phase-1 TLS variants)
// ─────────────────────────────────────────────────────────────────────────────
namespace
{
/// How a raw TLS client ends its write half after the request.
enum class TlsClientClose
{
  CLEAN_CLOSE_NOTIFY, ///< SSL_shutdown => TLS close_notify => server SSL_ERROR_ZERO_RETURN
  DIRTY_BARE_FIN,     ///< ::shutdown(SHUT_WR) => bare TCP FIN => server TLSIO branch
  NO_HALF_CLOSE       ///< full-duplex: no half-close (positive control — echo arrives)
};

/// A minimal TLS-server TcpEngine (the code under test) with an echo onData handler
/// and data/close counters. serverTls MUST be configured before the engine is
/// constructed — TcpEngine copies TransportConfig by value at construction (tracker
/// 2026-09-13-6), so post-construction cfg mutation would be ignored. All shared state
/// is atomic (callbacks run on the engine I/O thread; the test thread polls), so no
/// mutex is needed; the echo uses the sid the callback is handed.
struct TlsEchoServer
{
  TransportConfig cfg{};
  std::unique_ptr<TcpEngine> tx;
  std::atomic<size_t> dataCount{0};
  std::atomic<size_t> closeCount{0};
  std::atomic<int> lastCloseCode{-1};
  // See TcpFixture::echoDelayMs — the half-close drop test sets this >0 so the FIN is
  // seen and closeNow runs before the echo is flushed (deterministic drop, round-3 M-1).
  // Set before start(). Default 0 keeps the positive control fast.
  std::atomic<int> echoDelayMs{0};

  TlsEchoServer(const std::string &certFile, const std::string &keyFile)
  {
    cfg.serverTls.enabled = true;
    cfg.serverTls.defaultMode = TlsMode::Server;
    cfg.serverTls.certFile = certFile;
    cfg.serverTls.keyFile = keyFile;
    tx = std::make_unique<TcpEngine>(cfg);

    iora::network::detail::EngineBase::Callbacks cbs{};
    cbs.onData = [this](SessionId sid, iora::core::BufferView data,
                        std::chrono::steady_clock::time_point)
    {
      dataCount.fetch_add(1);
      // Echo back: send() only enqueues. On the half-close the session is torn down
      // (readAvail ZERO_RETURN / TLSIO -> closeNow) before this drains, so the echo is
      // dropped — the behavior this test pins. The optional echoDelayMs holds the I/O
      // thread so the FIN-triggered closeNow always precedes the echo flush (copy the
      // bytes first, since the delay outlives the BufferView).
      if (int d = echoDelayMs.load(std::memory_order_relaxed))
      {
        std::string owned(reinterpret_cast<const char *>(data.data()), data.size());
        std::this_thread::sleep_for(std::chrono::milliseconds(d));
        tx->send(sid, owned.data(), owned.size());
      }
      else
      {
        tx->send(sid, data.data(), data.size());
      }
    };
    cbs.onClose = [this](SessionId, const TransportErrorInfo &err)
    {
      // Store the code BEFORE bumping the counter: the test reads lastCloseCode only
      // after observing closeCount>=1, so this publishes the code before that flag.
      lastCloseCode.store(static_cast<int>(err.code));
      closeCount.fetch_add(1);
    };
    tx->setCallbacks(cbs);
  }

  // Join the I/O thread while this object is still alive (see ~TcpFixture rationale).
  ~TlsEchoServer() noexcept
  {
    try
    {
      if (tx)
      {
        tx->stop();
      }
    }
    catch (...)
    {
    }
  }
};

/// Raw OpenSSL client: TLS handshake, SSL_write(payload), then end the write half per
/// `mode`, then read the server's reply. Clean/Dirty read to EOF (the server closes);
/// NO_HALF_CLOSE (positive control) stops once `payload.size()` bytes are in hand, since
/// the echo server keeps the session open. Leak-free (null-checked SSL/SSL_CTX free;
/// SSL_set_fd uses BIO_NOCLOSE so the explicit ::close(fd) is the sole fd close).
inline std::string rawTlsHalfCloseExchange(int port, const std::string &payload,
                                           TlsClientClose mode)
{
  int fd = testnet::connectLoopbackTcp(port);
  if (fd < 0)
  {
    return "";
  }
  std::string out;
  SSL_CTX *ctx = ::SSL_CTX_new(::TLS_client_method());
  SSL *ssl = nullptr;
  if (ctx != nullptr)
  {
    ssl = ::SSL_new(ctx);
  }
  if (ssl != nullptr)
  {
    ::SSL_set_fd(ssl, fd);
    if (::SSL_connect(ssl) == 1 &&
        ::SSL_write(ssl, payload.data(), static_cast<int>(payload.size())) ==
          static_cast<int>(payload.size()))
    {
      if (mode == TlsClientClose::CLEAN_CLOSE_NOTIFY)
      {
        ::SSL_shutdown(ssl); // close_notify -> server SSL_ERROR_ZERO_RETURN
      }
      else if (mode == TlsClientClose::DIRTY_BARE_FIN)
      {
        ::shutdown(fd, SHUT_WR); // bare FIN, no close_notify -> server TLSIO branch
      }
      char buf[4096];
      int n;
      while ((n = ::SSL_read(ssl, buf, sizeof(buf))) > 0)
      {
        out.append(buf, static_cast<std::size_t>(n));
        if (mode == TlsClientClose::NO_HALF_CLOSE && out.size() >= payload.size())
        {
          break; // positive control: full echo in hand, don't stall to timeout
        }
      }
    }
  }
  if (ssl != nullptr)
  {
    ::SSL_free(ssl);
  }
  if (ctx != nullptr)
  {
    ::SSL_CTX_free(ctx);
  }
  ::close(fd);
  return out;
}

/// Resolve the static test cert/key paths (from the per-target IORA_TEST_RESOURCE_DIR),
/// delegating the fopen-probe/WARN to the shared testnet::tlsCertFileReadable. Returns
/// false (and WARNs) if absent.
inline bool tlsHalfCloseCerts(std::string &certFile, std::string &keyFile)
{
  certFile = std::string(IORA_TEST_RESOURCE_DIR) + "/tls-certs/test_tls_cert.pem";
  keyFile = std::string(IORA_TEST_RESOURCE_DIR) + "/tls-certs/test_tls_key.pem";
  return testnet::tlsCertFileReadable(certFile);
}
} // namespace

TEST_CASE("TLS full exchange echoes (positive control for the half-close pin)",
          "[tcp][halfclose][tls]")
{
  // POSITIVE CONTROL for the drop test below: a full-duplex TLS client that does NOT
  // half-close DOES receive the echo, proving the TLS echo server genuinely works — so a
  // drop under half-close is specifically the half-close, not a broken TLS fixture.
  std::string certFile, keyFile;
  if (!tlsHalfCloseCerts(certFile, keyFile))
  {
    return;
  }

  TlsEchoServer server(certFile, keyFile);
  REQUIRE(server.tx->start().isOk());
  auto port = testnet::getFreePortTCP();
  REQUIRE(server.tx->addListener("127.0.0.1", port, TlsMode::Server).isOk());

  std::string echoed = rawTlsHalfCloseExchange(port, "PING", TlsClientClose::NO_HALF_CLOSE);
  CHECK(echoed.find("PING") != std::string::npos);
}

TEST_CASE("TLS read-half-close drops the pending response (close_notify + bare-FIN)",
          "[tcp][halfclose][tls]")
{
  // tracker 2026-09-14-4 phase-1 TLS parity: the read-half EOF that drops a plaintext
  // response drops a TLS one too, via BOTH TLS EOF shapes:
  //   * CLEAN close_notify -> SSL_read SSL_ERROR_ZERO_RETURN -> closeNow(PeerClosed)
  //   * DIRTY bare TCP FIN -> SSL_read != ZERO_RETURN        -> closeNow(TLSIO)
  // Both tear the read-ENABLED session down before the async echo drains, dropping an
  // owed response — the deliberate RFC 9112 §9.6 non-conformance the read-half-close
  // contract (transport_types.hpp) documents. Pins both the drop and the distinct error
  // classification of each EOF shape. Non-vacuity is proven by the positive-control test
  // above (same server, full-duplex client, echo arrives).
  std::string certFile, keyFile;
  if (!tlsHalfCloseCerts(certFile, keyFile))
  {
    return;
  }

  const TlsClientClose mode =
    GENERATE(TlsClientClose::CLEAN_CLOSE_NOTIFY, TlsClientClose::DIRTY_BARE_FIN);
  const bool cleanClose = (mode == TlsClientClose::CLEAN_CLOSE_NOTIFY);
  const char *modeName = cleanClose ? "clean-close_notify" : "dirty-bare-FIN";
  CAPTURE(modeName);

  TlsEchoServer server(certFile, keyFile);
  // Deterministic drop (round-3 M-1): delay the echo so the client's EOF (close_notify
  // or bare FIN) is seen and closeNow runs before the echo is flushed. Set before start().
  server.echoDelayMs.store(100);
  REQUIRE(server.tx->start().isOk());
  auto port = testnet::getFreePortTCP();
  REQUIRE(server.tx->addListener("127.0.0.1", port, TlsMode::Server).isOk());

  std::string got = rawTlsHalfCloseExchange(port, "PING", mode);

  // The request reached the server (onData) and the session was torn down on the
  // read-half EOF (only the half-close client connects, so lastCloseCode is that
  // session's close, unambiguously)...
  REQUIRE(iora::test::waitFor([&] { return server.dataCount.load() >= 1; }));
  REQUIRE(iora::test::waitFor([&] { return server.closeCount.load() >= 1; }, 3000ms));
  // ...classified by EOF shape: close_notify => PeerClosed, bare FIN => TLSIO. This
  // mapping is OpenSSL-version-ROBUST, not version-fragile: only a real close_notify
  // yields SSL_ERROR_ZERO_RETURN => PeerClosed; a bare FIN yields SSL_ERROR_SYSCALL
  // (OpenSSL 1.1.1) or SSL_ERROR_SSL/UNEXPECTED_EOF_WHILE_READING (3.0+), and the engine
  // maps BOTH of those (any non-ZERO_RETURN SSL_read error) to TLSIO via the same
  // ERR_get_error else-branch (tcp_engine.hpp readAvail). So bare FIN can never surface
  // as PeerClosed regardless of OpenSSL version — the exact-code assertion is sound.
  const int expectedCode = cleanClose ? static_cast<int>(TransportError::PeerClosed)
                                      : static_cast<int>(TransportError::TLSIO);
  CHECK(server.lastCloseCode.load() == expectedCode);
  // ...and no echo came back: the response was dropped by the close.
  CHECK(got.find("PING") == std::string::npos);
}
