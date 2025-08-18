// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <atomic>
#include <chrono>
#include <future>
#include <thread>
#include <vector>

#include "../include/iora/network/hybrid_transport.hpp"
#include "../include/iora/network/shared_transport.hpp"
#include "../include/iora/network/shared_transport_udp.hpp"

using namespace iora::network;
using namespace std::chrono_literals;

// Mock transport for testing
class MockTransport : public ITransport
{
public:
  MockTransport() = default;

  void setCallbacks(const UnifiedCallbacks& cbs) override { callbacks = cbs; }

  bool start() override
  {
    running = true;
    return true;
  }

  void stop() override { running = false; }

  ListenerId addListener(const std::string&, std::uint16_t, TlsMode) override
  {
    return ++nextListenerId;
  }

  SessionId connect(const std::string&, std::uint16_t, TlsMode) override
  {
    SessionId sid = ++nextSessionId;
    // Simulate async connect success
    if (callbacks.onConnect)
    {
      std::thread(
          [this, sid]
          {
            std::this_thread::sleep_for(10ms);
            callbacks.onConnect(sid, IoResult::success());
          })
          .detach();
    }
    return sid;
  }

  SessionId connectViaListener(ListenerId, const std::string&,
                               std::uint16_t) override
  {
    return ++nextSessionId;
  }

  bool send(SessionId sid, const void* data, std::size_t n) override
  {
    std::lock_guard<std::mutex> lock(sendMutex);
    lastSendData.assign(static_cast<const std::uint8_t*>(data),
                        static_cast<const std::uint8_t*>(data) + n);
    lastSendSession = sid;
    sendCount++;

    // Simulate echo for testing
    if (autoEcho && callbacks.onData)
    {
      std::thread(
          [this, sid, n]
          {
            std::this_thread::sleep_for(5ms);
            callbacks.onData(sid, lastSendData.data(), n, IoResult::success());
          })
          .detach();
    }

    return !failSends;
  }

  bool close(SessionId sid) override
  {
    if (callbacks.onClosed)
    {
      callbacks.onClosed(sid, IoResult::success());
    }
    return true;
  }

  void reconfigure(const UnifiedConfig&) override {}

  UnifiedStats stats() const override
  {
    UnifiedStats s;
    s.bytesIn = 1000;
    s.bytesOut = 2000;
    s.sessionsCurrent = 5;
    return s;
  }

  Capability caps() const override { return Capability::IsConnectionOriented; }

  // Test helpers
  void simulateIncomingData(SessionId sid,
                            const std::vector<std::uint8_t>& data)
  {
    if (callbacks.onData)
    {
      callbacks.onData(sid, data.data(), data.size(), IoResult::success());
    }
  }

  void simulateError(SessionId sid, TransportError err, const std::string& msg)
  {
    if (callbacks.onData)
    {
      callbacks.onData(sid, nullptr, 0, IoResult::failure(err, msg));
    }
  }

  void simulateClose(SessionId sid)
  {
    if (callbacks.onClosed)
    {
      callbacks.onClosed(sid, IoResult::success());
    }
  }

  UnifiedCallbacks callbacks;
  std::atomic<bool> running{false};
  std::atomic<bool> failSends{false};
  std::atomic<bool> autoEcho{false};
  std::atomic<SessionId> nextSessionId{0};
  std::atomic<ListenerId> nextListenerId{0};
  std::atomic<int> sendCount{0};
  SessionId lastSendSession{0};
  std::vector<std::uint8_t> lastSendData;
  std::mutex sendMutex;
};

TEST_CASE("HybridTransport basic operations", "[hybrid][transport]")
{
  auto mockTransport = std::make_unique<MockTransport>();
  auto* mock = mockTransport.get();

  HybridTransport hybrid(std::move(mockTransport));

  SECTION("Start and stop")
  {
    REQUIRE(hybrid.start());
    REQUIRE(mock->running);

    hybrid.stop();
    REQUIRE_FALSE(mock->running);
  }

  SECTION("Connection management")
  {
    REQUIRE(hybrid.start());

    SessionId sid = hybrid.connect("localhost", 8080);
    REQUIRE(sid > 0);

    std::this_thread::sleep_for(20ms); // Wait for async connect

    REQUIRE(hybrid.close(sid));

    hybrid.stop();
  }
}

TEST_CASE("HybridTransport exclusive read modes",
          "[hybrid][transport][read-modes]")
{
  auto mockTransport = std::make_unique<MockTransport>();
  auto* mock = mockTransport.get();

  HybridTransport hybrid(std::move(mockTransport));
  REQUIRE(hybrid.start());

  SessionId sid = hybrid.connect("localhost", 8080);
  REQUIRE(sid > 0);

  SECTION("Default read mode is Async")
  {
    REQUIRE(hybrid.getReadMode(sid) == ReadMode::Async);
  }

  SECTION("Switch to Sync mode")
  {
    REQUIRE(hybrid.setReadMode(sid, ReadMode::Sync));
    REQUIRE(hybrid.getReadMode(sid) == ReadMode::Sync);
  }

  SECTION("Switch to Disabled mode")
  {
    REQUIRE(hybrid.setReadMode(sid, ReadMode::Disabled));
    REQUIRE(hybrid.getReadMode(sid) == ReadMode::Disabled);
  }

  SECTION("Cannot set async callback in Sync mode")
  {
    REQUIRE(hybrid.setReadMode(sid, ReadMode::Sync));

    auto callback = [](SessionId, const std::uint8_t*, std::size_t,
                       const IoResult&) {};
    REQUIRE_FALSE(hybrid.setDataCallback(sid, callback));
  }

  SECTION("Can set async callback in Async mode")
  {
    REQUIRE(hybrid.setReadMode(sid, ReadMode::Async));

    std::atomic<bool> callbackCalled{false};
    auto callback = [&](SessionId, const std::uint8_t*, std::size_t,
                        const IoResult&) { callbackCalled = true; };

    REQUIRE(hybrid.setDataCallback(sid, callback));

    // Simulate incoming data
    mock->simulateIncomingData(sid, {1, 2, 3, 4});
    std::this_thread::sleep_for(10ms);

    REQUIRE(callbackCalled);
  }

  hybrid.stop();
}

TEST_CASE("HybridTransport synchronous operations", "[hybrid][transport][sync]")
{
  auto mockTransport = std::make_unique<MockTransport>();
  auto* mock = mockTransport.get();

  HybridTransport hybrid(std::move(mockTransport));
  REQUIRE(hybrid.start());

  SessionId sid = hybrid.connect("localhost", 8080);
  std::this_thread::sleep_for(20ms); // Wait for connect

  SECTION("Synchronous send")
  {
    std::vector<std::uint8_t> data = {1, 2, 3, 4, 5};
    auto result = hybrid.sendSync(sid, data.data(), data.size(), 100ms);

    REQUIRE(result.ok);
    REQUIRE(result.bytesTransferred == data.size());
    REQUIRE(mock->lastSendData == data);
    REQUIRE(mock->lastSendSession == sid);
  }

  SECTION("Synchronous send with timeout")
  {
    mock->failSends = true;
    std::vector<std::uint8_t> data = {1, 2, 3};

    auto result = hybrid.sendSync(sid, data.data(), data.size(), 50ms);

    REQUIRE_FALSE(result.ok);
  }

  SECTION("Synchronous receive in Sync mode")
  {
    REQUIRE(hybrid.setReadMode(sid, ReadMode::Sync));

    // Simulate incoming data
    std::thread(
        [mock, sid]
        {
          std::this_thread::sleep_for(10ms);
          mock->simulateIncomingData(sid, {9, 8, 7, 6, 5});
        })
        .detach();

    std::uint8_t buffer[10];
    std::size_t len = sizeof(buffer);
    auto result = hybrid.receiveSync(sid, buffer, len, 100ms);

    REQUIRE(result.ok);
    REQUIRE(len == 5);
    REQUIRE(buffer[0] == 9);
    REQUIRE(buffer[4] == 5);
  }

  SECTION("Synchronous receive timeout")
  {
    REQUIRE(hybrid.setReadMode(sid, ReadMode::Sync));

    std::uint8_t buffer[10];
    std::size_t len = sizeof(buffer);
    auto result = hybrid.receiveSync(sid, buffer, len, 50ms);

    REQUIRE_FALSE(result.ok);
    REQUIRE(result.error == TransportError::Timeout);
  }

  SECTION("Cannot receive sync in Async mode")
  {
    REQUIRE(hybrid.getReadMode(sid) == ReadMode::Async);

    std::uint8_t buffer[10];
    std::size_t len = sizeof(buffer);
    auto result = hybrid.receiveSync(sid, buffer, len, 50ms);

    REQUIRE_FALSE(result.ok);
    REQUIRE(result.error == TransportError::Config);
  }

  hybrid.stop();
}

TEST_CASE("HybridTransport cancellation", "[hybrid][transport][cancel]")
{
  auto mockTransport = std::make_unique<MockTransport>();
  auto* mock = mockTransport.get();

  HybridTransport hybrid(std::move(mockTransport));
  REQUIRE(hybrid.start());

  SessionId sid = hybrid.connect("localhost", 8080);
  std::this_thread::sleep_for(20ms);

  SECTION("Cancel synchronous send")
  {
    CancellationToken token;
    std::vector<std::uint8_t> data(1000, 0x42);

    // Start send in another thread
    auto future = std::async(std::launch::async,
                             [&]
                             {
                               return hybrid.sendSyncCancellable(
                                   sid, data.data(), data.size(), token, 5s);
                             });

    // Cancel after short delay
    std::this_thread::sleep_for(10ms);
    token.cancel();

    auto result = future.get();
    REQUIRE_FALSE(result.ok);
    REQUIRE(result.error == TransportError::Cancelled);
  }

  SECTION("Cancel synchronous receive")
  {
    REQUIRE(hybrid.setReadMode(sid, ReadMode::Sync));

    CancellationToken token;
    std::uint8_t buffer[100];
    std::size_t len = sizeof(buffer);

    // Start receive in another thread
    auto future = std::async(
        std::launch::async, [&]
        { return hybrid.receiveSyncCancellable(sid, buffer, len, token, 5s); });

    // Cancel after short delay
    std::this_thread::sleep_for(10ms);
    token.cancel();

    auto result = future.get();
    REQUIRE_FALSE(result.ok);
    REQUIRE(result.error == TransportError::Cancelled);
  }

  SECTION("Cancel all pending operations")
  {
    std::atomic<int> cancelledOps{0};
    std::vector<std::future<SyncResult>> futures;

    // Queue multiple operations
    for (int i = 0; i < 5; ++i)
    {
      futures.push_back(std::async(
          std::launch::async,
          [&, i]
          {
            std::vector<std::uint8_t> data(10, i);
            auto result = hybrid.sendSync(sid, data.data(), data.size(), 5s);
            if (!result.ok && result.error == TransportError::Cancelled)
            {
              cancelledOps++;
            }
            return result;
          }));
    }

    // Cancel all
    std::this_thread::sleep_for(10ms);
    hybrid.cancelPendingOperations(sid);

    // Wait for all operations
    for (auto& f : futures)
    {
      f.wait();
    }

    REQUIRE(cancelledOps > 0);
  }

  hybrid.stop();
}

TEST_CASE("HybridTransport mixed sync/async operations",
          "[hybrid][transport][mixed]")
{
  auto mockTransport = std::make_unique<MockTransport>();
  auto* mock = mockTransport.get();
  mock->autoEcho = true; // Enable echo for testing

  HybridTransport hybrid(std::move(mockTransport));
  REQUIRE(hybrid.start());

  SessionId sid = hybrid.connect("localhost", 8080);
  std::this_thread::sleep_for(20ms);

  SECTION("Async receive with sync send")
  {
    // Set up async receive
    std::atomic<int> receivedCount{0};
    std::vector<std::uint8_t> lastReceived;
    std::mutex receiveMutex;

    auto callback = [&](SessionId, const std::uint8_t* data, std::size_t len,
                        const IoResult& result)
    {
      if (result.ok && len > 0)
      {
        std::lock_guard<std::mutex> lock(receiveMutex);
        lastReceived.assign(data, data + len);
        receivedCount++;
      }
    };

    REQUIRE(hybrid.setDataCallback(sid, callback));

    // Send data synchronously
    std::vector<std::uint8_t> sendData = {0xAA, 0xBB, 0xCC};
    auto result = hybrid.sendSync(sid, sendData.data(), sendData.size(), 100ms);
    REQUIRE(result.ok);

    // Wait for echo
    std::this_thread::sleep_for(20ms);

    // Check received data
    REQUIRE(receivedCount == 1);
    {
      std::lock_guard<std::mutex> lock(receiveMutex);
      REQUIRE(lastReceived == sendData);
    }
  }

  SECTION("Multiple threads sending synchronously")
  {
    std::atomic<int> successCount{0};
    std::vector<std::thread> threads;

    // Launch multiple sender threads
    for (int i = 0; i < 10; ++i)
    {
      threads.emplace_back(
          [&, i]
          {
            std::vector<std::uint8_t> data(5, i);
            auto result = hybrid.sendSync(sid, data.data(), data.size(), 1s);
            if (result.ok)
            {
              successCount++;
            }
          });
    }

    // Wait for all threads
    for (auto& t : threads)
    {
      t.join();
    }

    REQUIRE(successCount == 10);
    REQUIRE(mock->sendCount == 10);
  }

  SECTION("Switch between read modes")
  {
    // Start with async
    std::atomic<bool> asyncReceived{false};
    auto asyncCallback = [&](SessionId, const std::uint8_t*, std::size_t,
                             const IoResult&) { asyncReceived = true; };

    REQUIRE(hybrid.setDataCallback(sid, asyncCallback));
    mock->simulateIncomingData(sid, {1, 2, 3});
    std::this_thread::sleep_for(10ms);
    REQUIRE(asyncReceived);

    // Switch to sync
    REQUIRE(hybrid.setReadMode(sid, ReadMode::Sync));

    // Send data that will be buffered for sync read
    mock->simulateIncomingData(sid, {4, 5, 6});

    std::uint8_t buffer[10];
    std::size_t len = sizeof(buffer);
    auto result = hybrid.receiveSync(sid, buffer, len, 100ms);

    REQUIRE(result.ok);
    REQUIRE(len == 3);
    REQUIRE(buffer[0] == 4);

    // Switch back to async
    REQUIRE(hybrid.setReadMode(sid, ReadMode::Async));
    REQUIRE(hybrid.setDataCallback(sid, asyncCallback));

    asyncReceived = false;
    mock->simulateIncomingData(sid, {7, 8, 9});
    std::this_thread::sleep_for(10ms);
    REQUIRE(asyncReceived);
  }

  hybrid.stop();
}

TEST_CASE("HybridTransport connection health monitoring",
          "[hybrid][transport][health]")
{
  HybridTransport::Config config;
  config.autoHealthMonitoring = true;

  auto mockTransport = std::make_unique<MockTransport>();
  auto* mock = mockTransport.get();

  HybridTransport hybrid(std::move(mockTransport), config);
  REQUIRE(hybrid.start());

  SessionId sid = hybrid.connect("localhost", 8080);
  std::this_thread::sleep_for(20ms);

  SECTION("Health metrics updated on successful operations")
  {
    std::vector<std::uint8_t> data = {1, 2, 3, 4, 5};

    auto result = hybrid.sendSync(sid, data.data(), data.size(), 100ms);
    REQUIRE(result.ok);

    auto health = hybrid.getConnectionHealth(sid);
    REQUIRE(health.isHealthy);
    REQUIRE(health.bytesOut >= data.size());
    REQUIRE(health.successCount > 0);
    REQUIRE(health.errorCount == 0);
  }

  SECTION("Health metrics updated on failures")
  {
    mock->failSends = true;
    std::vector<std::uint8_t> data = {1, 2, 3};

    auto result = hybrid.sendSync(sid, data.data(), data.size(), 50ms);
    REQUIRE_FALSE(result.ok);

    auto health = hybrid.getConnectionHealth(sid);
    REQUIRE_FALSE(health.isHealthy);
    REQUIRE(health.errorCount > 0);
  }

  SECTION("Health tracks pending operations")
  {
    std::vector<std::future<SyncResult>> futures;

    // Queue multiple operations
    for (int i = 0; i < 3; ++i)
    {
      futures.push_back(std::async(std::launch::async,
                                   [&]
                                   {
                                     std::vector<std::uint8_t> data(10, 0);
                                     return hybrid.sendSync(sid, data.data(),
                                                            data.size(), 5s);
                                   }));
    }

    std::this_thread::sleep_for(10ms);

    auto health = hybrid.getConnectionHealth(sid);
    REQUIRE(health.pendingOperations > 0);

    // Cancel and wait
    hybrid.cancelPendingOperations(sid);
    for (auto& f : futures)
    {
      f.wait();
    }

    health = hybrid.getConnectionHealth(sid);
    REQUIRE(health.pendingOperations == 0);
  }

  hybrid.stop();
}

TEST_CASE("HybridTransport thread safety", "[hybrid][transport][thread-safety]")
{
  auto mockTransport = std::make_unique<MockTransport>();
  auto* mock = mockTransport.get();
  mock->autoEcho = true;

  HybridTransport hybrid(std::move(mockTransport));
  REQUIRE(hybrid.start());

  SessionId sid = hybrid.connect("localhost", 8080);
  std::this_thread::sleep_for(20ms);

  SECTION("Concurrent sync sends from multiple threads")
  {
    const int numThreads = 20;
    const int sendsPerThread = 10;
    std::atomic<int> successCount{0};
    std::atomic<int> failCount{0};

    std::vector<std::thread> threads;
    for (int t = 0; t < numThreads; ++t)
    {
      threads.emplace_back(
          [&, t]
          {
            for (int i = 0; i < sendsPerThread; ++i)
            {
              std::vector<std::uint8_t> data(10, t * 10 + i);
              auto result = hybrid.sendSync(sid, data.data(), data.size(), 1s);
              if (result.ok)
              {
                successCount++;
              }
              else
              {
                failCount++;
              }
            }
          });
    }

    for (auto& t : threads)
    {
      t.join();
    }

    REQUIRE(successCount == numThreads * sendsPerThread);
    REQUIRE(failCount == 0);
    REQUIRE(mock->sendCount == numThreads * sendsPerThread);
  }

  SECTION("Concurrent read mode changes and operations")
  {
    std::atomic<bool> running{true};
    std::atomic<int> modeChanges{0};
    std::atomic<int> sends{0};
    std::atomic<int> receives{0};

    // Thread changing read modes
    std::thread modeChanger(
        [&]
        {
          while (running)
          {
            hybrid.setReadMode(sid, ReadMode::Async);
            std::this_thread::sleep_for(1ms);
            hybrid.setReadMode(sid, ReadMode::Sync);
            std::this_thread::sleep_for(1ms);
            hybrid.setReadMode(sid, ReadMode::Disabled);
            std::this_thread::sleep_for(1ms);
            modeChanges++;
          }
        });

    // Thread sending data
    std::thread sender(
        [&]
        {
          while (running)
          {
            std::vector<std::uint8_t> data = {1, 2, 3};
            hybrid.sendAsync(sid, data.data(), data.size());
            sends++;
            std::this_thread::sleep_for(2ms);
          }
        });

    // Thread attempting sync receives
    std::thread receiver(
        [&]
        {
          while (running)
          {
            if (hybrid.getReadMode(sid) == ReadMode::Sync)
            {
              std::uint8_t buffer[10];
              std::size_t len = sizeof(buffer);
              hybrid.receiveSync(sid, buffer, len, 5ms);
              receives++;
            }
            std::this_thread::sleep_for(3ms);
          }
        });

    // Let threads run
    std::this_thread::sleep_for(100ms);
    running = false;

    modeChanger.join();
    sender.join();
    receiver.join();

    // Just verify no crashes and some operations completed
    REQUIRE(modeChanges > 0);
    REQUIRE(sends > 0);
  }

  hybrid.stop();
}

TEST_CASE("HybridTransport SIP-like usage pattern", "[hybrid][transport][sip]")
{
  auto mockTransport = std::make_unique<MockTransport>();
  auto* mock = mockTransport.get();

  HybridTransport hybrid(std::move(mockTransport));
  REQUIRE(hybrid.start());

  // Simulate SIP connection setup
  SessionId sid = hybrid.connect("sip.example.com", 5060);
  std::this_thread::sleep_for(20ms);

  // SIP typically uses async receive for incoming messages
  std::queue<std::vector<std::uint8_t>> receivedMessages;
  std::mutex receiveMutex;
  std::condition_variable receiveCv;

  auto sipReceiveCallback = [&](SessionId, const std::uint8_t* data,
                                std::size_t len, const IoResult& result)
  {
    if (result.ok && len > 0)
    {
      std::lock_guard<std::mutex> lock(receiveMutex);
      receivedMessages.emplace(data, data + len);
      receiveCv.notify_one();
    }
  };

  REQUIRE(hybrid.setDataCallback(sid, sipReceiveCallback));

  SECTION("SIP INVITE transaction with sync send and async receive")
  {
    // SIP sends INVITE synchronously for immediate error handling
    std::string invite = "INVITE sip:user@example.com SIP/2.0\r\n";
    auto sendResult = hybrid.sendSync(sid, invite.data(), invite.size(), 500ms);
    REQUIRE(sendResult.ok);

    // Simulate receiving 100 Trying
    std::string trying = "SIP/2.0 100 Trying\r\n";
    mock->simulateIncomingData(
        sid, std::vector<std::uint8_t>(trying.begin(), trying.end()));

    // Wait for async receive
    {
      std::unique_lock<std::mutex> lock(receiveMutex);
      REQUIRE(receiveCv.wait_for(lock, 100ms,
                                 [&] { return !receivedMessages.empty(); }));

      auto received = receivedMessages.front();
      receivedMessages.pop();
      std::string receivedStr(received.begin(), received.end());
      REQUIRE(receivedStr == trying);
    }

    // Send ACK synchronously
    std::string ack = "ACK sip:user@example.com SIP/2.0\r\n";
    sendResult = hybrid.sendSync(sid, ack.data(), ack.size(), 500ms);
    REQUIRE(sendResult.ok);
  }

  SECTION("Multiple SIP transactions on same connection")
  {
    // Simulate multiple concurrent SIP transactions
    std::vector<std::thread> transactions;
    std::atomic<int> successfulTransactions{0};

    for (int t = 0; t < 5; ++t)
    {
      transactions.emplace_back(
          [&, t]
          {
            // Each transaction sends a request synchronously
            std::string request = "OPTIONS sip:user" + std::to_string(t) +
                                  "@example.com SIP/2.0\r\n";
            auto result =
                hybrid.sendSync(sid, request.data(), request.size(), 1s);

            if (result.ok)
            {
              successfulTransactions++;
            }
          });
    }

    // Simulate receiving responses asynchronously
    for (int t = 0; t < 5; ++t)
    {
      std::string response =
          "SIP/2.0 200 OK\r\nCall-ID: " + std::to_string(t) + "\r\n";
      mock->simulateIncomingData(
          sid, std::vector<std::uint8_t>(response.begin(), response.end()));
    }

    // Wait for all transactions
    for (auto& t : transactions)
    {
      t.join();
    }

    REQUIRE(successfulTransactions == 5);

    // Verify all responses received
    std::this_thread::sleep_for(50ms);
    {
      std::lock_guard<std::mutex> lock(receiveMutex);
      REQUIRE(receivedMessages.size() == 5);
    }
  }

  SECTION("Connection reuse after error with health check")
  {
    // Send initial request
    std::string register1 = "REGISTER sip:example.com SIP/2.0\r\n";
    auto result =
        hybrid.sendSync(sid, register1.data(), register1.size(), 500ms);
    REQUIRE(result.ok);

    // Simulate network error
    mock->simulateError(sid, TransportError::Socket, "Network unreachable");

    // Check health
    auto health = hybrid.getConnectionHealth(sid);
    REQUIRE(health.errorCount > 0);

    // Application decides to retry based on health
    if (health.errorCount < 3) // Retry threshold
    {
      // Send another request on same connection
      std::string register2 = "REGISTER sip:example.com SIP/2.0\r\n";
      result = hybrid.sendSync(sid, register2.data(), register2.size(), 500ms);

      // Connection is still usable
      REQUIRE(mock->sendCount >= 2);
    }
  }

  hybrid.stop();
}