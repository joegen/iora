/// \file iora_test_tcp_rapid_send.cpp
/// \brief Tests for TCP rapid send behavior to reproduce data loss issue
///
/// This test was created to reproduce an issue where TCP sends report success
/// (::send() returns correct byte count) but data doesn't arrive at the peer
/// when multiple messages are sent in rapid succession (< 20 microseconds apart).
///
/// The SIP proxy architecture:
///   1. I/O thread receives data from UAS via SyncAsyncTransport
///   2. SyncAsyncTransport's onData callback fires (still in I/O thread context)
///   3. Data is enqueued to TransactionShard's per-worker BlockingQueue
///   4. TransactionShard worker thread dequeues and processes the event
///   5. Worker thread calls proxy callbacks which call sendSync() to relay to UAC
///
/// The rapid send scenario:
///   - UAS sends 180 Ringing followed by 200 OK within ~17 microseconds
///   - TransactionShard worker thread A processes 180 Ringing → calls sendSync() to UAC
///   - TransactionShard worker thread A (or B) processes 200 OK → calls sendSync() to UAC
///   - Both sendSync() calls queue commands to I/O thread which processes them sequentially
///   - BUT: 200 OK data is lost despite sendSync() and ::send() reporting success
///
/// Related investigation tracker:
///   /workspace/karoo_sbc/libs/iora/agent_tasks/2025-12-11_tcp_rapid_send_investigation.json

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "iora/network/shared_transport.hpp"
#include "iora/network/sync_async_transport.hpp"
#include "iora_test_net_utils.hpp"
#include "test_helpers.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using SharedTransport = iora::network::SharedTransport;
using SyncAsyncTransport = iora::network::SyncAsyncTransport;
using TransportError = iora::network::TransportError;
using TlsMode = iora::network::TlsMode;
using IoResult = iora::network::IoResult;
using SessionId = iora::network::SessionId;
using ListenerId = iora::network::ListenerId;

namespace
{

/// \brief Encode a message with length prefix for framing
std::vector<uint8_t> encodeMessage(const std::string &msg)
{
  std::vector<uint8_t> frame(4 + msg.size());
  uint32_t len = static_cast<uint32_t>(msg.size());
  frame[0] = (len >> 24) & 0xFF;
  frame[1] = (len >> 16) & 0xFF;
  frame[2] = (len >> 8) & 0xFF;
  frame[3] = len & 0xFF;
  std::memcpy(frame.data() + 4, msg.data(), msg.size());
  return frame;
}

/// \brief Test fixture that mimics the actual SIP proxy threading model
///
/// The real SIP proxy has:
/// - I/O thread: handles epoll, network I/O
/// - TransactionShard worker threads: process SIP messages, call sendSync()
///
/// This fixture simulates:
/// - A "server" that accepts connections
/// - "Worker threads" that process incoming triggers and call send() rapidly
/// - A "client" that tracks received messages
struct ProxyThreadedFixture
{
  SharedTransport::Config cfg{};
  SharedTransport::TlsConfig srvTls{};
  SharedTransport::TlsConfig cliTls{};
  SharedTransport tx{cfg, srvTls, cliTls};

  // Connection tracking
  SessionId serverSid{0};  // Server's view of client connection
  SessionId clientSid{0};  // Client side connection (for sends from client to server)

  std::mutex mtx;
  std::condition_variable cv;

  // Message tracking
  std::atomic<size_t> serverMessagesReceived{0};
  std::atomic<size_t> clientMessagesReceived{0};
  std::vector<std::string> serverReceivedMessages;
  std::vector<std::string> clientReceivedMessages;

  // Receive buffers for length-prefixed message parsing
  std::map<SessionId, std::vector<uint8_t>> receiveBuffers;

  // Worker thread simulation
  struct WorkItem
  {
    std::string message;
    SessionId targetSid;
  };
  std::queue<WorkItem> workQueue;
  std::mutex workMutex;
  std::condition_variable workCv;
  std::atomic<bool> workersRunning{false};
  std::vector<std::thread> workerThreads;

  // Tracking for rapid sends
  std::atomic<int> sendSuccessCount{0};
  std::atomic<int> sendFailCount{0};

  ProxyThreadedFixture()
  {
    SharedTransport::Callbacks cbs{};

    cbs.onAccept = [&](SessionId sid, const std::string &, const IoResult &res)
    {
      std::lock_guard<std::mutex> lock(mtx);
      if (res.ok)
      {
        serverSid = sid;
      }
      cv.notify_all();
    };

    cbs.onConnect = [&](SessionId sid, const IoResult &res)
    {
      std::lock_guard<std::mutex> lock(mtx);
      if (res.ok)
      {
        clientSid = sid;
      }
      cv.notify_all();
    };

    cbs.onData = [&](SessionId sid, const std::uint8_t *data, std::size_t n, const IoResult &res)
    {
      if (!res.ok || n == 0) return;

      std::unique_lock<std::mutex> lock(mtx);

      // Accumulate data and parse length-prefixed messages
      auto &buf = receiveBuffers[sid];
      buf.insert(buf.end(), data, data + n);

      while (buf.size() >= 4)
      {
        uint32_t msgLen = (static_cast<uint32_t>(buf[0]) << 24) |
                          (static_cast<uint32_t>(buf[1]) << 16) |
                          (static_cast<uint32_t>(buf[2]) << 8) |
                          (static_cast<uint32_t>(buf[3]));

        if (buf.size() < 4 + msgLen) break;

        std::string msg(buf.begin() + 4, buf.begin() + 4 + msgLen);
        buf.erase(buf.begin(), buf.begin() + 4 + msgLen);

        // Track which side received it
        if (sid == serverSid)
        {
          serverReceivedMessages.push_back(msg);
          serverMessagesReceived++;
        }
        else
        {
          clientReceivedMessages.push_back(msg);
          clientMessagesReceived++;
        }
      }

      lock.unlock();
      cv.notify_all();
    };

    cbs.onClosed = [&](SessionId, const IoResult &)
    {
    };

    cbs.onError = [&](TransportError, const std::string &)
    {
    };

    tx.setCallbacks(cbs);
  }

  ~ProxyThreadedFixture()
  {
    stopWorkers();
  }

  /// \brief Start worker threads that process work items and call send()
  void startWorkers(size_t numWorkers)
  {
    workersRunning = true;
    for (size_t i = 0; i < numWorkers; i++)
    {
      workerThreads.emplace_back([this, i]() { workerLoop(i); });
    }
  }

  void stopWorkers()
  {
    workersRunning = false;
    workCv.notify_all();
    for (auto &t : workerThreads)
    {
      if (t.joinable())
      {
        t.join();
      }
    }
    workerThreads.clear();
  }

  void workerLoop(size_t workerId)
  {
    while (workersRunning)
    {
      WorkItem item;
      {
        std::unique_lock<std::mutex> lock(workMutex);
        workCv.wait_for(lock, 10ms, [&] { return !workQueue.empty() || !workersRunning; });

        if (!workersRunning && workQueue.empty())
        {
          break;
        }

        if (workQueue.empty())
        {
          continue;
        }

        item = std::move(workQueue.front());
        workQueue.pop();
      }

      // Worker sends the message (this is what happens in TransactionShard worker)
      auto frame = encodeMessage(item.message);

      bool sent = tx.send(item.targetSid, frame.data(), frame.size());

      if (sent)
      {
        sendSuccessCount++;
      }
      else
      {
        sendFailCount++;
      }
    }
  }

  /// \brief Queue work items for worker threads to process
  void queueWork(const std::string &message, SessionId targetSid)
  {
    std::lock_guard<std::mutex> lock(workMutex);
    workQueue.push({message, targetSid});
    workCv.notify_one();
  }

  /// \brief Queue multiple work items at once (to simulate burst)
  void queueWorkBurst(const std::vector<std::string> &messages, SessionId targetSid)
  {
    std::lock_guard<std::mutex> lock(workMutex);
    for (const auto &msg : messages)
    {
      workQueue.push({msg, targetSid});
    }
    workCv.notify_all();
  }

  bool waitFor(std::function<bool()> condition, std::chrono::milliseconds timeout = 5000ms)
  {
    std::unique_lock<std::mutex> lock(mtx);
    return cv.wait_for(lock, timeout, condition);
  }

  size_t getClientReceivedCount()
  {
    return clientMessagesReceived.load();
  }

  std::vector<std::string> getClientMessages()
  {
    std::lock_guard<std::mutex> lock(mtx);
    return clientReceivedMessages;
  }
};

} // namespace

// ============================================================================
// THREADED-1: Single worker sends multiple messages rapidly
// ============================================================================

TEST_CASE("THREADED-1: Single worker rapid sends", "[tcp][rapid][threaded][critical]")
{
  ProxyThreadedFixture f;
  REQUIRE(f.tx.start());

  auto port = testnet::getFreePortTCP();
  REQUIRE(port > 0);

  // Start server
  f.tx.addListener("127.0.0.1", port, TlsMode::None);

  // Connect client
  SessionId cid = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cid != 0);

  // Wait for connection
  REQUIRE(f.waitFor([&] { return f.serverSid != 0; }));
  std::this_thread::sleep_for(50ms);

  INFO("Connection established: client=" << cid << ", server=" << f.serverSid);

  // Start single worker thread
  f.startWorkers(1);

  // Queue 5 messages to be sent rapidly by the worker
  // This mimics: worker processes 180 Ringing, then 200 OK, etc.
  std::vector<std::string> messages = {"MSG-1", "MSG-2", "MSG-3", "MSG-4", "MSG-5"};
  f.queueWorkBurst(messages, cid);

  // Wait for all messages to be sent and received
  bool received = f.waitFor([&] { return f.serverMessagesReceived >= messages.size(); }, 5000ms);

  INFO("Server received " << f.serverMessagesReceived.load() << " of " << messages.size() << " messages");
  INFO("Send success: " << f.sendSuccessCount.load() << ", fail: " << f.sendFailCount.load());

  f.stopWorkers();

  REQUIRE(received);
  REQUIRE(f.serverMessagesReceived.load() == messages.size());

  f.tx.stop();
}

// ============================================================================
// THREADED-2: Two workers send concurrently (like TransactionShard workers)
// ============================================================================

TEST_CASE("THREADED-2: Two workers concurrent rapid sends", "[tcp][rapid][threaded]")
{
  ProxyThreadedFixture f;
  REQUIRE(f.tx.start());

  auto port = testnet::getFreePortTCP();
  f.tx.addListener("127.0.0.1", port, TlsMode::None);

  SessionId cid = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(f.waitFor([&] { return f.serverSid != 0; }));
  std::this_thread::sleep_for(50ms);

  // Start 2 worker threads (like TransactionShard with threadPoolSize=2)
  f.startWorkers(2);

  // Queue multiple messages that will be processed by both workers
  const int numMessages = 10;
  for (int i = 0; i < numMessages; i++)
  {
    f.queueWork("CONCURRENT-" + std::to_string(i), cid);
  }

  bool received = f.waitFor([&] { return f.serverMessagesReceived >= numMessages; }, 5000ms);

  INFO("Server received " << f.serverMessagesReceived.load() << " of " << numMessages << " messages");

  f.stopWorkers();

  REQUIRE(received);
  REQUIRE(f.serverMessagesReceived.load() == numMessages);

  f.tx.stop();
}

// ============================================================================
// THREADED-3: Burst of messages queued at once (simulates rapid UAS responses)
// ============================================================================

TEST_CASE("THREADED-3: Burst queue with single worker", "[tcp][rapid][threaded][critical]")
{
  ProxyThreadedFixture f;
  REQUIRE(f.tx.start());

  auto port = testnet::getFreePortTCP();
  f.tx.addListener("127.0.0.1", port, TlsMode::None);

  SessionId cid = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(f.waitFor([&] { return f.serverSid != 0; }));
  std::this_thread::sleep_for(50ms);

  // Single worker - guarantees messages processed sequentially
  f.startWorkers(1);

  // Simulate the exact SIP scenario: 180 Ringing followed by 200 OK
  // In real case, both arrive within ~17 microseconds
  std::vector<std::string> sipResponses = {
    "SIP/2.0 180 Ringing",
    "SIP/2.0 200 OK"
  };
  f.queueWorkBurst(sipResponses, cid);

  bool received = f.waitFor([&] { return f.serverMessagesReceived >= 2; }, 5000ms);

  INFO("Server received " << f.serverMessagesReceived.load() << " of 2 messages");
  {
    std::lock_guard<std::mutex> lock(f.mtx);
    for (size_t i = 0; i < f.serverReceivedMessages.size(); i++)
    {
      INFO("  [" << i << "] " << f.serverReceivedMessages[i]);
    }
  }

  f.stopWorkers();

  REQUIRE(received);
  REQUIRE(f.serverMessagesReceived.load() == 2);

  // Verify message order preserved
  {
    std::lock_guard<std::mutex> lock(f.mtx);
    REQUIRE(f.serverReceivedMessages[0] == "SIP/2.0 180 Ringing");
    REQUIRE(f.serverReceivedMessages[1] == "SIP/2.0 200 OK");
  }

  f.tx.stop();
}

// ============================================================================
// THREADED-4: Server sends TO client (reverse direction - like proxy to UAC)
// ============================================================================

TEST_CASE("THREADED-4: Server-to-client rapid sends (proxy to UAC pattern)", "[tcp][rapid][threaded][critical]")
{
  ProxyThreadedFixture f;
  REQUIRE(f.tx.start());

  auto port = testnet::getFreePortTCP();
  f.tx.addListener("127.0.0.1", port, TlsMode::None);

  // Client connects
  (void)f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(f.waitFor([&] { return f.serverSid != 0; }));
  std::this_thread::sleep_for(50ms);

  INFO("Server session ID: " << f.serverSid << " (will send to client)");

  // Start worker that will send FROM SERVER TO CLIENT
  // This is the actual proxy pattern: proxy sends responses to UAC
  f.startWorkers(1);

  // Queue messages to be sent from server to client
  std::vector<std::string> responses = {"180 Ringing", "200 OK"};
  for (const auto &resp : responses)
  {
    f.queueWork(resp, f.serverSid);  // Note: using serverSid, not clientLocalSid
  }

  // Wait for client to receive both
  bool received = f.waitFor([&] { return f.clientMessagesReceived >= 2; }, 5000ms);

  INFO("Client received " << f.clientMessagesReceived.load() << " of 2 messages");
  INFO("Send success: " << f.sendSuccessCount.load() << ", fail: " << f.sendFailCount.load());
  {
    std::lock_guard<std::mutex> lock(f.mtx);
    for (size_t i = 0; i < f.clientReceivedMessages.size(); i++)
    {
      INFO("  [" << i << "] " << f.clientReceivedMessages[i]);
    }
  }

  f.stopWorkers();

  REQUIRE(received);
  REQUIRE(f.clientMessagesReceived.load() == 2);

  f.tx.stop();
}

// ============================================================================
// THREADED-5: High volume stress test
// ============================================================================

TEST_CASE("THREADED-5: High volume threaded sends", "[tcp][rapid][threaded][stress]")
{
  ProxyThreadedFixture f;
  REQUIRE(f.tx.start());

  auto port = testnet::getFreePortTCP();
  f.tx.addListener("127.0.0.1", port, TlsMode::None);

  SessionId cid = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(f.waitFor([&] { return f.serverSid != 0; }));
  std::this_thread::sleep_for(50ms);

  // Use multiple workers to maximize concurrency
  f.startWorkers(4);

  // Send 100 messages
  const int numMessages = 100;
  for (int i = 0; i < numMessages; i++)
  {
    f.queueWork("STRESS-" + std::to_string(i), cid);
  }

  // Longer timeout for stress test
  bool received = f.waitFor([&] { return f.serverMessagesReceived >= numMessages; }, 10000ms);

  INFO("Server received " << f.serverMessagesReceived.load() << " of " << numMessages << " messages");
  INFO("Send success: " << f.sendSuccessCount.load() << ", fail: " << f.sendFailCount.load());

  f.stopWorkers();

  REQUIRE(received);
  REQUIRE(f.serverMessagesReceived.load() == numMessages);

  f.tx.stop();
}

// ============================================================================
// BASELINE: Direct send from main thread (should always work)
// ============================================================================

TEST_CASE("BASELINE: Direct sequential sends from main thread", "[tcp][baseline]")
{
  ProxyThreadedFixture f;
  REQUIRE(f.tx.start());

  auto port = testnet::getFreePortTCP();
  f.tx.addListener("127.0.0.1", port, TlsMode::None);

  SessionId cid = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(f.waitFor([&] { return f.serverSid != 0; }));
  std::this_thread::sleep_for(50ms);

  // Direct sends from main thread (no workers)
  for (int i = 0; i < 5; i++)
  {
    auto frame = encodeMessage("BASELINE-" + std::to_string(i));
    REQUIRE(f.tx.send(cid, frame.data(), frame.size()));
  }

  bool received = f.waitFor([&] { return f.serverMessagesReceived >= 5; }, 5000ms);

  INFO("Server received " << f.serverMessagesReceived.load() << " of 5 messages");

  REQUIRE(received);
  REQUIRE(f.serverMessagesReceived.load() == 5);

  f.tx.stop();
}
