#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "iora/network/detail/udp_engine.hpp"
#include "udp_engine_test_access.hpp"
#include "iora_test_net_utils.hpp"
#include "test_helpers.hpp"

#include <cstdio>
#include <thread>

using namespace std::chrono_literals;
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
struct UdpFixture
{
  // `cfg` is a CONSTRUCTION-TIME SNAPSHOT: UdpEngine copies it BY VALUE at
  // construction (UdpEngine's `_config(config)` member init), so mutate cfg ONLY before
  // it reaches the engine. Build a TransportConfig, set fields, and pass it via
  // `UdpFixture f{cfg}`. A post-construction `f.cfg.X = ...` write is a SILENT
  // NO-OP — it never reaches the already-copied _config (this is the very defect
  // tracker 2026-09-13-6 fixed). Declaration order (cfg before tx) guarantees the
  // `tx{cfg}` member initializer copies a fully-initialized cfg.
  TransportConfig cfg{};
  UdpEngine tx{cfg};

  std::atomic<bool> accepted{false};
  std::atomic<bool> connected{false};
  std::atomic<bool> clientGotEcho{false};
  std::atomic<bool> anyClosed{false};
  std::atomic<bool> errored{false};
  // A server-side echo send that FAILED, recorded off the test thread: onData
  // runs on the engine I/O thread where Catch2 macros are UB (issue #99), so it
  // records here and the MAIN thread asserts REQUIRE_FALSE(f.sendFailed).
  std::atomic<bool> sendFailed{false};
  std::atomic<int> acceptCount{0};
  std::atomic<int> connectCount{0};
  std::atomic<int> dataCount{0};
  std::atomic<int> closeCount{0};

  // I/O-THREAD-ONLY: serverSid/clientSid/connectedSessions/acceptedSessions/
  // lastErrMsg are written in the callbacks on the single engine I/O thread and
  // read ONLY from those callbacks (same thread) — they are NOT synchronized for
  // a main-thread read. If a future test needs one from the test thread, guard it
  // with a mutex + a locked snapshot accessor (as TcpFixture does), or gate it
  // behind an atomic set AFTER the write. (lastData is the exception: it is
  // published to the main thread via the clientGotEcho release/acquire edge.
  // PRECONDITION: each echo test sends exactly ONE datagram per client, so
  // lastData has a single I/O-thread writer per publish. A test that echoes
  // twice — or resets clientGotEcho and re-waits with a prior echo in flight —
  // would race the write; guard lastData with dataMutex if that ever changes.)
  SessionId serverSid{0};
  SessionId clientSid{0};
  std::string lastErrMsg;
  std::string lastData;
  std::vector<SessionId> connectedSessions;
  std::vector<SessionId> acceptedSessions;
  std::mutex dataMutex;
  std::vector<std::string> receivedData;

  // Per-onData (sid,payload) record (tracker 2026-10-02-3, Phase 0): lets a test assert
  // WHICH session a datagram was dispatched to — the behavioural discriminator for the
  // cross-listener / per-listener-key fix. Written under dataMutex on the I/O thread
  // (same publication rule as receivedData), read via sidForPayload() on the test thread.
  std::vector<std::pair<SessionId, std::string>> dataBySid;
  // Gate the server-side echo (default on). A self-origination test (datagrams whose
  // source IS one of our own listeners) would otherwise cascade echoes across listeners;
  // such a test sets this false and asserts on acceptCount + the dispatched sid instead.
  std::atomic<bool> echoEnabled{true};

  // Optional hook invoked FIRST in onData on the engine I/O thread (tracker 2026-10-04-2 (g)):
  // lets a test read getLocalAddress(sid) at request receipt — the DP4 consumer pattern — from the
  // I/O thread (re-entering _sessionRwMutex shared inside a user callback, which must not deadlock;
  // the engine fires onData AFTER releasing the lock). A test setting this MUST declare the state it
  // captures BEFORE the fixture so the I/O thread is joined (in ~UdpFixture) before that state dies.
  std::function<void(SessionId)> onDataHook;

  // The sid the FIRST onData carrying \p payload was dispatched to, or 0 if none yet.
  SessionId sidForPayload(const std::string &payload)
  {
    std::lock_guard<std::mutex> g(dataMutex);
    for (const auto &kv : dataBySid)
    {
      if (kv.second == payload)
      {
        return kv.first;
      }
    }
    return 0;
  }

  // Close-terminal capture (tracker 2026-09-14-1, cpp17-M3). onClose runs on the
  // engine I/O thread; the test thread reads these via lastClose(). Guarded by the
  // existing dataMutex (one mutex per fixture, matching TcpFixture/ResolveFixture)
  // + a locked snapshot accessor, per this fixture's own I/O-thread-only publication
  // rule above. Written BEFORE closeCount++ so a test that waits on closeCount then
  // calls lastClose() observes the matching terminal.
  TransportError lastCloseError{TransportError::None};
  std::string lastCloseMsg;
  std::pair<TransportError, std::string> lastClose()
  {
    std::lock_guard<std::mutex> g(dataMutex);
    return {lastCloseError, lastCloseMsg};
  }

  // Option (b) (tracker 2026-09-13-6): take the TransportConfig by value (defaulted,
  // so `UdpFixture f;` still works) and move it into `cfg` in the mem-init list
  // BEFORE the `tx{cfg}` member initializer runs (member init follows declaration
  // order: cfg then tx), so the engine is constructed with the test's config — not
  // the default. `tx` stays a plain UdpEngine member, so the ~UdpFixture stop()+join
  // teardown invariant is preserved verbatim (dtor body joins the I/O thread before
  // any member destructs).
  explicit UdpFixture(TransportConfig c = TransportConfig{}) : cfg(std::move(c))
  {
    iora::network::detail::EngineBase::Callbacks cbs{};
    cbs.onAccept = [&](SessionId sid, const TransportAddress &)
    {
      serverSid = sid;
      accepted = true;
      acceptCount++;
      acceptedSessions.push_back(sid);
    };
    cbs.onConnect = [&](SessionId sid, const TransportAddress &)
    {
      clientSid = sid;
      connected = true;
      connectCount++;
      connectedSessions.push_back(sid);
    };
    cbs.onData = [&](SessionId sid, iora::core::BufferView bv,
                     std::chrono::steady_clock::time_point)
    {
      if (onDataHook)
      {
        onDataHook(sid);
      }
      dataCount++;
      auto *data = bv.data();
      auto n = bv.size();
      // Echo on server; detect on client. This runs on the engine I/O thread —
      // no Catch2 macro here (issue #99): record a failed send for the main
      // thread to assert.
      if (echoEnabled.load() &&
          std::find(acceptedSessions.begin(), acceptedSessions.end(), sid) !=
            acceptedSessions.end())
      {
        if (!tx.send(sid, data, n))
        {
          sendFailed.store(true);
        }
      }
      if (sid == clientSid)
      {
        // Write lastData BEFORE publishing clientGotEcho, so a main-thread
        // waitFor(clientGotEcho) that then reads lastData has a correct
        // happens-before edge (the flag must gate the data it advertises).
        lastData = std::string(reinterpret_cast<const char *>(data), n);
        clientGotEcho = true;
      }
      {
        std::lock_guard<std::mutex> lock(dataMutex);
        std::string payload(reinterpret_cast<const char *>(data), n);
        receivedData.push_back(payload);
        dataBySid.emplace_back(sid, std::move(payload));
      }
    };
    cbs.onClose = [&](SessionId, const TransportErrorInfo &info)
    {
      {
        std::lock_guard<std::mutex> g(dataMutex);
        lastCloseError = info.code;
        lastCloseMsg = info.message;
      }
      anyClosed = true;
      closeCount++;
    };
    cbs.onError = [&](TransportError, const std::string &msg)
    {
      lastErrMsg = msg;
      errored = true;
    };
    tx.setCallbacks(std::move(cbs));
  }

  // Stop (and join) the engine's I/O thread BEFORE any data member the callbacks
  // touch (connectedSessions/receivedData/atomics) is destroyed. Member reverse-
  // destruction would otherwise free those members first (tx is declared early,
  // so ~UdpEngine's stop()+join runs last) — a live I/O thread firing onConnect/
  // onData into a freed member is heap corruption. This matters whenever a test's
  // trailing f.tx.stop() is skipped or omitted (a REQUIRE throwing and unwinding,
  // or a section that never calls stop()). The join is guaranteed here: this
  // fixture never calls scheduleSelfDestruct, so _running is still true and
  // stop()'s CAS cannot short-circuit past the join. Wrapped like ~UdpEngine —
  // a throwing stop()/join() in an (implicitly noexcept) dtor would std::terminate
  // and mask the original assertion failure.
  ~UdpFixture() noexcept
  {
    try
    {
      tx.stop();
    }
    catch (...)
    {
    }
  }

  bool waitFor(const std::atomic<bool> &flag, int ms = 1000)
  {
    return pollUntil([&] { return flag.load(); }, ms);
  }

  bool waitForCount(const std::atomic<int> &counter, int expected, int ms = 1000)
  {
    return pollUntil([&] { return counter.load() >= expected; }, ms);
  }

  // Bounded poll of a getStats()-derived predicate — the observable analogue of
  // waitForCount for the GC/age/backpressure tests. Prefer this over a fixed sleep +
  // hard equality: the number of GC cycles completed within a wall-clock window is
  // nondeterministic under load, so a fixed-sleep `== N` can flake. Main-thread-safe
  // here: getStats() reads the atomic stats (udp_engine.hpp:354-372). (It also reads
  // the non-atomic _batchProcessor pointer at :373-376, but batching is never enabled
  // in these tests, so that is a stable-null read; if a future test enables batching
  // while polling getStats(), re-verify EventBatchProcessor::getStats() thread-safety.)
  template <typename Pred> bool waitForStats(Pred pred, int ms = 5000)
  {
    return pollUntil([&] { return pred(tx.getStats()); }, ms);
  }

  // Generic bounded poll of an arbitrary predicate (not a stats predicate) — e.g. waiting
  // for a RecordingPeer to receive N datagrams (simpl L-7).
  template <typename Pred> bool waitUntil(Pred pred, int ms = 2000)
  {
    return pollUntil(pred, ms);
  }

private:
  // Single bounded-poll primitive shared by the three wait helpers above (5ms tick).
  template <typename Pred> bool pollUntil(Pred pred, int ms)
  {
    for (int i = 0; i < ms / 5 && !pred(); ++i)
    {
      std::this_thread::sleep_for(5ms);
    }
    return pred();
  }
};
} // namespace

TEST_CASE("UDP start/stop idempotent", "[udp]")
{
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  REQUIRE(f.tx.start().isErr());
  f.tx.stop();
  f.tx.stop();
}

TEST_CASE("UDP loopback echo", "[udp][echo]")
{
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();

  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId cs = cr.value();

  // In UDP, connected should be immediate, but accepted only happens after first data
  REQUIRE(f.waitFor(f.connected));

  const char *msg = "hello udp";
  REQUIRE(f.tx.send(cs, msg, std::strlen(msg)));

  // Now wait for both acceptance (from first data) and echo response
  REQUIRE(f.waitFor(f.accepted));
  REQUIRE(f.waitFor(f.clientGotEcho));
  REQUIRE_FALSE(f.sendFailed); // server-side echo send succeeded (recorded off-thread)
  REQUIRE(f.lastData == msg);

  // UDP "close" is semantic in your API; ensure it returns true and does not crash.
  REQUIRE(f.tx.close(cs));
  REQUIRE(f.waitFor(f.anyClosed));

  f.tx.stop();
}

TEST_CASE("UDP named-host connect (event-driven resolve)", "[udp][resolve]")
{
  // Connect by NAME so connectDo takes the off-thread resolve -> resumeConnect
  // path (phase-4). "localhost" resolves via getaddrinfo, which returns ::1 first on
  // a host with a global IPv6 address (glibc does not count the loopback address as a
  // configured address for AI_ADDRCONFIG); bind
  // BOTH loopback families so the connected UDP echo arrives (tracker 2026-09-25-15).
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::addLoopbackListeners(f.tx, SOCK_DGRAM, TlsMode::None);

  auto cr = f.tx.connect("localhost", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId cs = cr.value();

  REQUIRE(f.waitFor(f.connected, 3000));
  REQUIRE(f.closeCount == 0); // no spurious onClose(Resolve)

  const char *msg = "udp named";
  REQUIRE(f.tx.send(cs, msg, std::strlen(msg)));
  REQUIRE(f.waitFor(f.clientGotEcho, 2000));
  REQUIRE_FALSE(f.sendFailed); // server-side echo send succeeded (recorded off-thread)
  REQUIRE(f.lastData == "udp named");

  f.tx.stop();
}

TEST_CASE("addLoopbackListeners binds BOTH loopback families for UDP (dual-bind regression guard)",
          "[udp][resolve][dualbind]")
{
  // M2: the UDP dual-bind hardening is PERMANENT (a connected UDP socket to a dead ::1
  // cannot fail over — the datagram is silently lost). Prove the listener actually
  // RECEIVES a datagram on 127.0.0.1 AND ::1. A ::1-capable host always gets a ::1
  // listener (the helper FAILs rather than degrade), so v6Bound reflects the host.
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  bool v6Bound = false;
  auto port = testnet::addLoopbackListeners(f.tx, SOCK_DGRAM, TlsMode::None, &v6Bound);

  auto rawSendTo = [&](int family, const char *text)
  {
    testnet::ScopedFd s{::socket(family, SOCK_DGRAM, 0)};
    REQUIRE(s.get() >= 0);
    auto len = static_cast<ssize_t>(std::strlen(text));
    if (family == AF_INET)
    {
      sockaddr_in a{};
      a.sin_family = AF_INET;
      a.sin_port = htons(port);
      a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      CHECK(::sendto(s.get(), text, std::strlen(text), 0, reinterpret_cast<sockaddr *>(&a),
                     sizeof(a)) == len);
    }
    else
    {
      sockaddr_in6 a{};
      a.sin6_family = AF_INET6;
      a.sin6_port = htons(port);
      a.sin6_addr = in6addr_loopback;
      CHECK(::sendto(s.get(), text, std::strlen(text), 0, reinterpret_cast<sockaddr *>(&a),
                     sizeof(a)) == len);
    }
  };

  auto received = [&](const char *text)
  {
    std::lock_guard<std::mutex> g(f.dataMutex);
    return std::find(f.receivedData.begin(), f.receivedData.end(), text) !=
           f.receivedData.end();
  };

  rawSendTo(AF_INET, "v4-dgram");
  if (v6Bound)
  {
    rawSendTo(AF_INET6, "v6-dgram");
  }

  // Wait on the asserted PROPERTY (receivedData contents), not on dataCount — the fixture
  // bumps dataCount before pushing to receivedData, so a dataCount wait could read the
  // vector before the push.
  REQUIRE(iora::test::waitFor(
    [&] { return received("v4-dgram") && (!v6Bound || received("v6-dgram")); }, 3000ms));

  f.tx.stop();
}

TEST_CASE("UDP named-host connectViaListener (event-driven, listener re-lookup)", "[udp][via][resolve]")
{
  // Named-host via-listener: resolve off-thread, re-look-up the listener at
  // resume, create the session on the listener fd (phase-4 task-4.3).
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port1 = testnet::getFreePortUDP();
  auto port2 = testnet::getFreePortUDP();

  auto lr = f.tx.addListener("127.0.0.1", port1, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  auto cs = f.tx.connectViaListener(lid, "localhost", port2);
  REQUIRE(cs.isOk());

  REQUIRE(f.waitFor(f.connected, 3000));
  REQUIRE(f.closeCount == 0); // resolved + session created on the listener fd

  f.tx.stop();
}

TEST_CASE("UDP named-host connect after restart (fresh post gate)", "[udp][resolve][restart]")
{
  // Validates task-4.4: UDP start() re-creates the EnginePostGate before the
  // loop, so a post-restart resolver continuation does not drop.
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  f.tx.stop();
  REQUIRE(f.tx.start().isOk()); // restart — fresh gate must be installed

  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  auto cr = f.tx.connect("localhost", port, TlsMode::None);
  REQUIRE(cr.isOk());

  REQUIRE(f.waitFor(f.connected, 3000));
  REQUIRE(f.closeCount == 0); // no spurious onClose(Resolve) after restart

  f.tx.stop();
}

TEST_CASE("UDP rejects TLS mode", "[udp][config]")
{
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();

  // Should return err for TLS attempt
  auto lr = f.tx.addListener("127.0.0.1", port, TlsMode::Server);
  REQUIRE(lr.isErr());

  f.tx.stop();
}

TEST_CASE("UDP duplicate listener error", "[udp][error]")
{
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();

  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  // Second bind to same port — may succeed or fail
  (void)f.tx.addListener("127.0.0.1", port, TlsMode::None);

  // Give time for async bind error
  std::this_thread::sleep_for(100ms);

  f.tx.stop();
}

TEST_CASE("UDP stats verification", "[udp][stats]")
{
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();

  auto stats1 = f.tx.getStats();
  REQUIRE(stats1.connected == 0);
  REQUIRE(stats1.accepted == 0);
  REQUIRE(stats1.bytesIn == 0);
  REQUIRE(stats1.bytesOut == 0);
  REQUIRE(stats1.sessionsCurrent == 0);

  (void)f.tx.addListener("127.0.0.1", port, TlsMode::None);
  SessionId cs = f.tx.connect("127.0.0.1", port, TlsMode::None).value();

  REQUIRE(f.waitFor(f.connected));

  const char *msg = "test message";
  size_t msgLen = std::strlen(msg);
  REQUIRE(f.tx.send(cs, msg, msgLen));

  REQUIRE(f.waitFor(f.accepted));
  REQUIRE(f.waitFor(f.clientGotEcho));
  REQUIRE_FALSE(f.sendFailed); // server-side echo send succeeded (recorded off-thread)

  auto stats2 = f.tx.getStats();
  REQUIRE(stats2.connected == 1);
  REQUIRE(stats2.accepted == 1);
  REQUIRE(stats2.bytesIn >= msgLen);    // At least the original message
  REQUIRE(stats2.bytesOut >= msgLen);   // At least the echo
  REQUIRE(stats2.sessionsCurrent == 2); // Client and server peer
  REQUIRE(stats2.sessionsPeak >= 2);

  f.tx.close(cs);
  REQUIRE(f.waitFor(f.anyClosed));

  auto stats3 = f.tx.getStats();
  REQUIRE(stats3.closed >= 1);
  REQUIRE(stats3.sessionsCurrent == 1); // Server peer still exists

  f.tx.stop();
}

TEST_CASE("UDP multiple simultaneous connections", "[udp][multi]")
{
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();

  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  // Create multiple clients
  const int numClients = 5;
  std::vector<SessionId> clients;

  for (int i = 0; i < numClients; ++i)
  {
    auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
    REQUIRE(cr.isOk());
    clients.push_back(cr.value());
  }

  // Wait for all connections
  REQUIRE(f.waitForCount(f.connectCount, numClients, 2000));

  // Send from each client
  for (int i = 0; i < numClients; ++i)
  {
    std::string msg = "client" + std::to_string(i);
    REQUIRE(f.tx.send(clients[i], msg.data(), msg.size()));
  }

  // Wait for all accepts and data
  REQUIRE(f.waitForCount(f.acceptCount, numClients, 2000));
  REQUIRE(f.waitForCount(f.dataCount, numClients * 2, 2000)); // Original + echo

  auto stats = f.tx.getStats();
  REQUIRE(stats.accepted == numClients);
  REQUIRE(stats.connected == numClients);
  REQUIRE(stats.sessionsCurrent == numClients * 2); // Clients + server peers

  REQUIRE_FALSE(f.sendFailed); // server-side echo send succeeded (recorded off-thread)
  f.tx.stop();
}

TEST_CASE("UDP connectViaListener", "[udp][via]")
{
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port1 = testnet::getFreePortUDP();
  auto port2 = testnet::getFreePortUDP();

  auto lr = f.tx.addListener("127.0.0.1", port1, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  // Set up a second UDP server to connect to. Declare tx2 AFTER the locals its
  // onData captures by-ref, so tx2 (destroyed first, reverse declaration order)
  // joins its I/O thread before those locals die — same teardown-UAF guard as
  // ~UdpFixture, needed because the trailing tx2.stop() is skipped if a REQUIRE
  // throws.
  TransportConfig cfg2{};
  std::atomic<bool> server2Received{false};
  UdpEngine tx2{cfg2};
  iora::network::detail::EngineBase::Callbacks cbs2{};
  cbs2.onData = [&](SessionId, iora::core::BufferView bv,
                    std::chrono::steady_clock::time_point)
  {
    std::string msg(reinterpret_cast<const char *>(bv.data()), bv.size());
    if (msg == "via_test")
    {
      server2Received = true;
    }
  };
  tx2.setCallbacks(std::move(cbs2));

  REQUIRE(tx2.start().isOk());
  REQUIRE(tx2.addListener("127.0.0.1", port2, TlsMode::None).isOk());

  // Connect via the first listener to the second server
  SessionId cs = f.tx.connectViaListener(lid, "127.0.0.1", port2).value();

  REQUIRE(f.waitFor(f.connected));

  const char *msg = "via_test";
  REQUIRE(f.tx.send(cs, msg, std::strlen(msg)));

  // Wait for server2 to receive
  for (int i = 0; i < 200 && !server2Received.load(); ++i)
  {
    std::this_thread::sleep_for(5ms);
  }
  REQUIRE(server2Received.load());

  REQUIRE_FALSE(f.sendFailed); // server-side echo send succeeded (recorded off-thread)
  f.tx.stop();
  tx2.stop();
}

TEST_CASE("UDP basic operation after start", "[udp][config]")
{
  // NOTE: this test previously set gcInterval=1s and maxWriteQueue=10, but neither
  // is exercised here (idleTimeout stays the 600s default so nothing goes idle in
  // the window; a single small echo never approaches the write queue). Once config
  // actually reaches the engine those knobs would be inert decoration implying a
  // check this test does not perform, so they are dropped — this is a plain
  // post-start echo test (tracker 2026-09-13-6, cpp17-F5).
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());

  auto port = testnet::getFreePortUDP();
  (void)f.tx.addListener("127.0.0.1", port, TlsMode::None);
  SessionId cs = f.tx.connect("127.0.0.1", port, TlsMode::None).value();

  REQUIRE(f.waitFor(f.connected));

  // Verify connection works
  const char *msg = "basic_op";
  REQUIRE(f.tx.send(cs, msg, std::strlen(msg)));

  REQUIRE(f.waitFor(f.accepted));
  REQUIRE(f.waitFor(f.clientGotEcho));
  REQUIRE_FALSE(f.sendFailed); // server-side echo send succeeded (recorded off-thread)
  REQUIRE(f.lastData == msg);

  f.tx.stop();
}

TEST_CASE("UDP error conditions", "[udp][error]")
{
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());

  SECTION("send to non-existent session")
  {
    SessionId fakeSid = 9999;
    const char *msg = "test";
    // CF-H1: send() to an unknown/closed session now returns FALSE (it must not
    // mask a dead session — SIP RFC 3263 failover depends on the false).
    REQUIRE_FALSE(f.tx.send(fakeSid, msg, std::strlen(msg)));
  }

  SECTION("close non-existent session")
  {
    SessionId fakeSid = 9999;
    REQUIRE(f.tx.close(fakeSid)); // Returns true but does nothing
  }

  SECTION("invalid address format")
  {
    SessionId cs = f.tx.connect("not.an.ip.address", 1234, TlsMode::None).value();
    REQUIRE(cs != 0); // ID allocated

    // Wait for connect error callback
    std::this_thread::sleep_for(100ms);

    // Connection should have failed
    REQUIRE_FALSE(f.connected.load());
  }

  SECTION("connect via non-existent listener")
  {
    ListenerId fakeLid = 9999;
    (void)f.tx.connectViaListener(fakeLid, "127.0.0.1", 1234); // ID allocated

    // Wait a bit
    std::this_thread::sleep_for(100ms);

    // Connection should have failed
    REQUIRE_FALSE(f.connected.load());
  }

  f.tx.stop();
}

TEST_CASE("UDP garbage collection", "[udp][gc]")
{
  // Config now reaches the engine (tracker 2026-09-13-6): idleTimeout=1s so idle
  // sessions are GC-closed. maxConnAge=0 disables age-close (== default) — this
  // test isolates the idle path.
  TransportConfig cfg;
  cfg.idleTimeout = std::chrono::seconds(1);
  cfg.gcInterval = std::chrono::seconds(1);
  cfg.maxConnAge = std::chrono::seconds(0);
  UdpFixture f{cfg};

  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();

  (void)f.tx.addListener("127.0.0.1", port, TlsMode::None);
  SessionId cs = f.tx.connect("127.0.0.1", port, TlsMode::None).value();

  REQUIRE(f.waitFor(f.connected));

  const char *msg = "test";
  REQUIRE(f.tx.send(cs, msg, std::strlen(msg)));
  REQUIRE(f.waitFor(f.accepted));

  // Both sessions established. Bound-poll rather than a hard == read so the check is
  // robust if it ever races the 1s GC timer under extreme load (cpp17-L3).
  REQUIRE(f.waitForStats([](const auto &s) { return s.sessionsCurrent == 2; }, 2000));

  // Both sessions go idle (no further traffic) and are idle-GC'd. Bounded-poll the
  // atomic sessionsCurrent to 0 rather than a fixed sleep + hard == (the number of
  // GC cycles within a wall-clock window is nondeterministic; cpp17-L2 / ts M-1).
  REQUIRE(f.waitForStats([](const auto &s) { return s.sessionsCurrent == 0; }, 6000));
  auto stats2 = f.tx.getStats();
  REQUIRE(stats2.gcRuns >= 1);
  REQUIRE(stats2.gcClosedIdle >= 1);

  REQUIRE_FALSE(f.sendFailed); // server-side echo send succeeded (recorded off-thread)
  f.tx.stop();
}

TEST_CASE("UDP max connection age", "[udp][gc][age]")
{
  // Config now reaches the engine (tracker 2026-09-13-6): maxConnAge=1s ages
  // sessions out REGARDLESS of activity. idleTimeout=0 disables idle-close (==
  // default) so this test isolates the age path.
  TransportConfig cfg;
  cfg.idleTimeout = std::chrono::seconds(0);
  cfg.maxConnAge = std::chrono::seconds(1);
  cfg.gcInterval = std::chrono::seconds(1);
  UdpFixture f{cfg};

  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();

  (void)f.tx.addListener("127.0.0.1", port, TlsMode::None);
  SessionId cs = f.tx.connect("127.0.0.1", port, TlsMode::None).value();

  REQUIRE(f.waitFor(f.connected));

  const char *msg = "test";
  REQUIRE(f.tx.send(cs, msg, std::strlen(msg)));
  REQUIRE(f.waitFor(f.accepted));

  // Both sessions established. Bound-poll rather than a hard == read so the check is
  // robust if it ever races the 1s GC timer under extreme load (cpp17-L3).
  REQUIRE(f.waitForStats([](const auto &s) { return s.sessionsCurrent == 2; }, 2000));

  // The previous keep-alive send loop (send every 500ms "to prevent idle timeout")
  // is removed: idleTimeout is disabled here so it guarded nothing, and once
  // maxConnAge actually applies GC ages the session out mid-loop (age-close ignores
  // activity), after which send() returns false for the GC-closed sid (CF-H1) — the
  // loop's REQUIRE(send) would fail. Age-out IS the point of the test (tracker
  // 2026-09-13-6, cpp17-F1). Bounded-poll for the age-close instead of a fixed sleep.
  REQUIRE(f.waitForStats([](const auto &s) { return s.sessionsCurrent < 2; }, 6000));
  auto stats2 = f.tx.getStats();
  REQUIRE(stats2.gcClosedAged >= 1);

  REQUIRE_FALSE(f.sendFailed); // server-side echo send succeeded (recorded off-thread)
  f.tx.stop();
}

// A small payload recorder: a separate UDP engine whose onData appends every datagram it
// receives, so drop-oldest ORDER can be verified after the drain.
namespace
{
struct RecordingPeer
{
  TransportConfig cfg{};
  UdpEngine tx{cfg};
  std::mutex mu;
  std::vector<std::string> got;
  RecordingPeer()
  {
    iora::network::detail::EngineBase::Callbacks cbs{};
    cbs.onData = [this](SessionId, iora::core::BufferView bv,
                        std::chrono::steady_clock::time_point)
    {
      std::lock_guard<std::mutex> g(mu);
      got.emplace_back(reinterpret_cast<const char *>(bv.data()), bv.size());
    };
    tx.setCallbacks(std::move(cbs));
  }
  ~RecordingPeer() noexcept
  {
    try
    {
      tx.stop();
    }
    catch (...)
    {
    }
  }
  std::vector<std::string> snapshot()
  {
    std::lock_guard<std::mutex> g(mu);
    return got;
  }
};

// Distinct 4-char tag per datagram ("D000".."D999"), so order/content is checkable.
// (No `inline`: internal linkage already applies in this anonymous namespace — simpl L-8.)
std::string bpTag(int i)
{
  char b[8];
  std::snprintf(b, sizeof(b), "D%03d", i);
  return std::string(b);
}

// --- Shared setup helpers (simpl L-5/L-6); REQUIREs inside free helpers throw correctly. ---

// Start f.tx + a RecordingPeer, connect a client session from f to the peer; return the sid.
SessionId connectToPeer(UdpFixture &f, RecordingPeer &peer)
{
  REQUIRE(f.tx.start().isOk());
  REQUIRE(peer.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(peer.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());
  auto cr = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  SessionId cs = cr.value();
  REQUIRE(f.waitFor(f.connected));
  return cs;
}

struct ListenerRig
{
  ListenerId lid;
  std::uint16_t port;
};
// Start f.tx and add a listener on a free port; return {lid, port}.
ListenerRig startWithListener(UdpFixture &f)
{
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  auto lr = f.tx.addListener("127.0.0.1", port, TlsMode::None);
  REQUIRE(lr.isOk());
  return {lr.value(), port};
}

// Two via-sessions from f's listener to one peer port; return {ss1, ss2} (both are twins in the
// one (listener,peer) index list in insertion order; ss1 is the front / dispatch target).
std::pair<SessionId, SessionId> twinVias(UdpFixture &f, ListenerId lid, std::uint16_t peerPort)
{
  auto r1 = f.tx.connectViaListener(lid, "127.0.0.1", peerPort);
  auto r2 = f.tx.connectViaListener(lid, "127.0.0.1", peerPort);
  REQUIRE(r1.isOk());
  REQUIRE(r2.isOk());
  return {r1.value(), r2.value()};
}

// Send one datagram from a raw loopback-v4 fd to 127.0.0.1:port (tracker 2026-10-02-3 L-5 DRY).
void sendLoopbackV4(int fd, std::uint16_t port, const std::string &msg)
{
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  REQUIRE(::sendto(fd, msg.data(), msg.size(), 0, reinterpret_cast<sockaddr *>(&a), sizeof(a)) ==
          static_cast<ssize_t>(msg.size()));
}

// Send one datagram from a raw v4 fd to a SPECIFIC dest IP:port (tracker 2026-10-03-1). On a
// WILDCARD (0.0.0.0) iora listener this exercises the per-datagram local-dest capture: a peer
// bound to 127.0.0.1 sending to 127.0.0.2 must be answered FROM 127.0.0.2 (RFC 3581 §4).
void sendV4ToDest(int fd, const char *destIp, std::uint16_t port, const std::string &msg)
{
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  REQUIRE(::inet_pton(AF_INET, destIp, &a.sin_addr) == 1);
  REQUIRE(::sendto(fd, msg.data(), msg.size(), 0, reinterpret_cast<sockaddr *>(&a), sizeof(a)) ==
          static_cast<ssize_t>(msg.size()));
}

// Read one datagram's (source-IP-string, payload) off a raw v4 fd; {"",""} on timeout/error. The
// RFC 3581 §4 address-half discriminator: a wildcard-bind reply's SOURCE IP must equal the dest
// IP the request was sent to, not the kernel route-preferred source. The fd should carry an
// SO_RCVTIMEO so a missing reply (the pre-fix pinhole-drop case) returns promptly.
std::pair<std::string, std::string> recvV4Src(int fd)
{
  char buf[256];
  sockaddr_in src{};
  socklen_t sl = sizeof(src);
  ssize_t r = ::recvfrom(fd, buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&src), &sl);
  if (r <= 0)
  {
    return {"", ""};
  }
  char ip[INET_ADDRSTRLEN]{};
  ::inet_ntop(AF_INET, &src.sin_addr, ip, sizeof(ip));
  return {std::string(ip), std::string(buf, static_cast<std::size_t>(r))};
}

// A raw v4 UDP socket bound to a SPECIFIC loopback source IP (e.g. 127.0.0.1) on an ephemeral
// port, with a short SO_RCVTIMEO. Lets a test drive "request arrives on local X from source Y"
// and read the reply source. Returns the fd (RAII) and fills `port`.
testnet::ScopedFd bindV4Source(const char *srcIp, std::uint16_t &port, int rcvTimeoutMs = 1500)
{
  testnet::ScopedFd fd{::socket(AF_INET, SOCK_DGRAM, 0)};
  REQUIRE(fd.get() >= 0);
  int reuse = 1;
  ::setsockopt(fd.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = 0;
  REQUIRE(::inet_pton(AF_INET, srcIp, &a.sin_addr) == 1);
  REQUIRE(::bind(fd.get(), reinterpret_cast<sockaddr *>(&a), sizeof(a)) == 0);
  socklen_t sl = sizeof(a);
  REQUIRE(::getsockname(fd.get(), reinterpret_cast<sockaddr *>(&a), &sl) == 0);
  port = ntohs(a.sin_port);
  timeval tv{rcvTimeoutMs / 1000, (rcvTimeoutMs % 1000) * 1000};
  ::setsockopt(fd.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  return fd;
}

// v6 twins of sendV4ToDest / bindV4Source for the native-IPv6 getLocalAddress presentation test
// (tracker 2026-10-04-2 test (b)): a bare v6 literal must come back WITHOUT brackets.
void sendV6ToDest(int fd, const char *destIp, std::uint16_t port, const std::string &msg)
{
  sockaddr_in6 a{};
  a.sin6_family = AF_INET6;
  a.sin6_port = htons(port);
  REQUIRE(::inet_pton(AF_INET6, destIp, &a.sin6_addr) == 1);
  REQUIRE(::sendto(fd, msg.data(), msg.size(), 0, reinterpret_cast<sockaddr *>(&a), sizeof(a)) ==
          static_cast<ssize_t>(msg.size()));
}

testnet::ScopedFd bindV6Source(const char *srcIp, std::uint16_t &port, int rcvTimeoutMs = 1500)
{
  testnet::ScopedFd fd{::socket(AF_INET6, SOCK_DGRAM, 0)};
  REQUIRE(fd.get() >= 0);
  int reuse = 1;
  ::setsockopt(fd.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
  sockaddr_in6 a{};
  a.sin6_family = AF_INET6;
  a.sin6_port = 0;
  REQUIRE(::inet_pton(AF_INET6, srcIp, &a.sin6_addr) == 1);
  REQUIRE(::bind(fd.get(), reinterpret_cast<sockaddr *>(&a), sizeof(a)) == 0);
  socklen_t sl = sizeof(a);
  REQUIRE(::getsockname(fd.get(), reinterpret_cast<sockaddr *>(&a), &sl) == 0);
  port = ntohs(a.sin6_port);
  timeval tv{rcvTimeoutMs / 1000, (rcvTimeoutMs % 1000) * 1000};
  ::setsockopt(fd.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  return fd;
}

// True if the kernel allows a non-local source address (net.ipv4.ip_nonlocal_bind=1 — common on
// keepalived/VRRP HA hosts). DD7's close-on-source-not-local then does NOT fire (sendmsg succeeds
// from the departed address), so the T8 source-not-local tests must skip there (sip LOW-1).
bool nonLocalBindAllowed()
{
  int v = 0;
  if (FILE *fp = std::fopen("/proc/sys/net/ipv4/ip_nonlocal_bind", "r"))
  {
    if (std::fscanf(fp, "%d", &v) != 1)
    {
      v = 0;
    }
    std::fclose(fp);
  }
  return v != 0;
}

struct ServerPeerRig
{
  ListenerId lid;
  SessionId ss;
};
// Stand up f.tx as server with a listener; an external client `cli` pokes it so it accepts a
// ServerPeer; return {lid, ss}. `cli` must outlive use of the rig (it owns the poke socket).
ServerPeerRig makeServerPeer(UdpFixture &f, UdpEngine &cli)
{
  auto rig = startWithListener(f);
  iora::network::detail::EngineBase::Callbacks ccbs{}; // client discards
  cli.setCallbacks(std::move(ccbs));
  REQUIRE(cli.start().isOk());
  auto ccr = cli.connect("127.0.0.1", rig.port, TlsMode::None);
  REQUIRE(ccr.isOk());
  SessionId ccs = ccr.value();
  const char *poke = "hi";
  (void)cli.send(ccs, poke, 2); // buffered through _connecting if needed (A3.1b)
  REQUIRE(f.waitFor(f.accepted));
  return {rig.lid, f.serverSid}; // serverSid published via the `accepted` atomic (one accept)
}
} // namespace

// Backpressure is driven DETERMINISTICALLY and host-independently by the per-session
// forced-EAGAIN seam (tracker 2026-09-25-16). Native-Linux loopback UDP never EAGAINs
// (loopback_xmit skb_orphan()s the skb, releasing SO_SNDBUF accounting in-syscall), so the
// old soSndBuf+volume approach was structurally unreachable here. The seam holds a chosen
// session's datagrams at EVERY send site (sendDo client/listener + the EPOLLOUT drain), so
// the write queue grows past maxWriteQueue -> backpressureCloses++; closeOnBackpressure
// decides close (true) vs drop-oldest (false). backpressureCloses counts OVERFLOW EVENTS in
// BOTH modes (not closes); the config-discriminating observable is the ACTION.
TEST_CASE("UDP backpressure handling (client path)", "[udp][backpressure]")
{
  using iora::network::UdpEngineTestAccess;
  constexpr std::size_t kMaxQ = 5;
  const int kSends = static_cast<int>(kMaxQ) + 3; // overflow by 3

  SECTION("closeOnBackpressure=true closes the session with WriteBackpressure")
  {
    TransportConfig cfg;
    cfg.maxWriteQueue = kMaxQ;
    cfg.closeOnBackpressure = true;
    UdpFixture f{cfg};
    RecordingPeer peer;
    SessionId cs = connectToPeer(f, peer);

    UdpEngineTestAccess::armForceEagain(f.tx, cs); // hold this session's sends
    for (int i = 0; i < kSends; ++i)
    {
      auto t = bpTag(i);
      bool ok = f.tx.send(cs, t.data(), t.size());
      if (i == 0)
      {
        REQUIRE(ok); // first send is definitely accepted (session open)
      }
      // later sends race the ASYNC overflow close (processed on the I/O thread), so their
      // true/false result is not deterministic from the test thread -> not asserted.
    }

    REQUIRE(f.waitForStats([](const auto &s) { return s.backpressureCloses >= 1; }, 2000));
    REQUIRE(f.waitFor(f.anyClosed)); // close action fired
    REQUIRE(f.lastClose().first == TransportError::WriteBackpressure); // intended reason
    f.tx.stop();
  }

  SECTION("closeOnBackpressure=false keeps the session, drops oldest, newest kept in order")
  {
    TransportConfig cfg;
    cfg.maxWriteQueue = kMaxQ;
    cfg.closeOnBackpressure = false;
    UdpFixture f{cfg};
    RecordingPeer peer;
    SessionId cs = connectToPeer(f, peer);

    UdpEngineTestAccess::armForceEagain(f.tx, cs);
    for (int i = 0; i < kSends; ++i)
    {
      auto t = bpTag(i);
      REQUIRE(f.tx.send(cs, t.data(), t.size())); // survives -> all accepted
    }

    REQUIRE(f.waitForStats([](const auto &s) { return s.backpressureCloses >= 1; }, 2000));
    // Queue bounded to maxWriteQueue (drop-oldest), via an I/O-thread snapshot.
    REQUIRE(UdpEngineTestAccess::sessionQueueSize(f.tx, cs) == kMaxQ);
    // I/O barrier, then the CONFIG-DISCRIMINATING assertion: the session SURVIVED
    // (reverting closeOnBackpressure to the default true closes it -> this fails).
    UdpEngineTestAccess::ioBarrier(f.tx);
    REQUIRE_FALSE(f.anyClosed);

    // Release the hold; the kept datagrams drain to the peer on the next EPOLLOUT.
    UdpEngineTestAccess::disarmForceEagain(f.tx);
    UdpEngineTestAccess::ioBarrier(f.tx); // formal ordering edge for the drain reads (L-3)
    REQUIRE(f.waitUntil([&] { return peer.snapshot().size() >= kMaxQ; }, 2000));
    auto got = peer.snapshot();
    REQUIRE(got.size() == kMaxQ);
    for (std::size_t i = 0; i < kMaxQ; ++i)
    {
      // newest kMaxQ, in order: tags [kSends-kMaxQ .. kSends)
      REQUIRE(got[i] == bpTag(static_cast<int>(kSends - kMaxQ + i)));
    }
    f.tx.stop();
  }
}

// ServerPeer (listener) send path: datagrams live in the SHARED listener write queue, so a
// backpressure close MUST purge only the closed session's datagrams (by sid, not peer
// address) and never leave them to be sent post-close (tracker 2026-09-25-16 H-2/M-2).
TEST_CASE("UDP backpressure handling (ServerPeer listener path)", "[udp][backpressure]")
{
  using iora::network::UdpEngineTestAccess;
  constexpr std::size_t kMaxQ = 5;
  const int kSends = static_cast<int>(kMaxQ) + 3;

  SECTION("close mode purges the closed session's datagrams from the shared queue")
  {
    TransportConfig cfg;
    cfg.maxWriteQueue = kMaxQ;
    cfg.closeOnBackpressure = true;
    UdpFixture f{cfg};
    TransportConfig ccfg{};
    UdpEngine cli{ccfg};
    auto rig = makeServerPeer(f, cli);
    ListenerId lid = rig.lid;
    SessionId ss = rig.ss;

    UdpEngineTestAccess::armForceEagain(f.tx, ss);
    for (int i = 0; i < kSends; ++i)
    {
      auto t = bpTag(i);
      (void)f.tx.send(ss, t.data(), t.size());
    }

    REQUIRE(f.waitForStats([](const auto &s) { return s.backpressureCloses >= 1; }, 2000));
    REQUIRE(f.waitFor(f.anyClosed));
    REQUIRE(f.lastClose().first == TransportError::WriteBackpressure);
    // Purge-by-sid: the closed session has NOTHING left in the shared queue, and (since it
    // was the only sender) the whole shared queue is empty -> bounded.
    REQUIRE(UdpEngineTestAccess::listenerQueuedForSid(f.tx, lid, ss) == 0);
    REQUIRE(UdpEngineTestAccess::listenerQueueSize(f.tx, lid) == 0);
    cli.stop();
    f.tx.stop();
  }

  SECTION("drop-oldest mode keeps the session and bounds the shared queue")
  {
    TransportConfig cfg;
    cfg.maxWriteQueue = kMaxQ;
    cfg.closeOnBackpressure = false;
    UdpFixture f{cfg};
    TransportConfig ccfg{};
    UdpEngine cli{ccfg};
    auto rig = makeServerPeer(f, cli);
    ListenerId lid = rig.lid;
    SessionId ss = rig.ss;

    UdpEngineTestAccess::armForceEagain(f.tx, ss);
    for (int i = 0; i < kSends; ++i)
    {
      auto t = bpTag(i);
      REQUIRE(f.tx.send(ss, t.data(), t.size()));
    }

    REQUIRE(f.waitForStats([](const auto &s) { return s.backpressureCloses >= 1; }, 2000));
    REQUIRE(UdpEngineTestAccess::listenerQueuedForSid(f.tx, lid, ss) == kMaxQ);
    REQUIRE(UdpEngineTestAccess::listenerQueueSize(f.tx, lid) == kMaxQ); // bounded (F-5)
    UdpEngineTestAccess::ioBarrier(f.tx);
    REQUIRE_FALSE(f.anyClosed);
    UdpEngineTestAccess::disarmForceEagain(f.tx); // end the armed EPOLLOUT spin (L-7)
    cli.stop();
    f.tx.stop();
  }
}

// H-2 (tracker 2026-09-25-16): the purge is keyed by owning SID, not peer address, so
// closing one of two sibling sessions to the SAME peer must not drop the sibling's queued
// datagrams. Two via-sessions to one peer address share pkey but have distinct sids.
TEST_CASE("UDP listener backpressure purge spares a sibling session to the same peer",
          "[udp][backpressure][sibling]")
{
  using iora::network::UdpEngineTestAccess;
  constexpr std::size_t kMaxQ = 5;

  TransportConfig cfg;
  cfg.maxWriteQueue = kMaxQ;
  cfg.closeOnBackpressure = true;
  UdpFixture f{cfg};
  ListenerId lid = startWithListener(f).lid;
  auto peerPort = testnet::getFreePortUDP(); // black-hole peer (nothing drains — see below)
  auto twins = twinVias(f, lid, peerPort);
  SessionId ss1 = twins.first;
  SessionId ss2 = twins.second;

  // Arm ss2 so ITS datagram sits at the FRONT of the shared queue and the seam holds the
  // whole queue at the drain (flushListener stops at the held front) — this removes any
  // EPOLLOUT drain race. ss1's datagrams queue behind (M-5). Then close ss1 EXPLICITLY:
  // closeNow purges ss1 by sid on EVERY close path (M-2), and ss2's datagram must survive.
  UdpEngineTestAccess::armForceEagain(f.tx, ss2);
  auto front = bpTag(200);
  REQUIRE(f.tx.send(ss2, front.data(), front.size())); // -> queued (ss2, front, held)
  for (int i = 0; i < 2; ++i)
  {
    auto t = bpTag(i);
    REQUIRE(f.tx.send(ss1, t.data(), t.size())); // -> queued behind (ss1)
  }
  // Snapshot BEFORE the close: both sets present in the shared queue.
  REQUIRE(UdpEngineTestAccess::listenerQueuedForSid(f.tx, lid, ss1) == 2);
  REQUIRE(UdpEngineTestAccess::listenerQueuedForSid(f.tx, lid, ss2) == 1);

  REQUIRE(f.tx.close(ss1)); // explicit close -> purge ss1 by sid
  UdpEngineTestAccess::ioBarrier(f.tx);
  REQUIRE_FALSE(UdpEngineTestAccess::hasSession(f.tx, ss1));
  REQUIRE(UdpEngineTestAccess::hasSession(f.tx, ss2));
  REQUIRE(UdpEngineTestAccess::listenerQueuedForSid(f.tx, lid, ss1) == 0); // purged
  REQUIRE(UdpEngineTestAccess::listenerQueuedForSid(f.tx, lid, ss2) == 1); // sibling intact
  UdpEngineTestAccess::disarmForceEagain(f.tx);
  f.tx.stop();
}

// H-3 (tracker 2026-09-25-16): closing a via-TWIN (second session to an already-indexed
// peer) must not evict the live sibling's _peerIndex entry (ownership-guarded erase).
TEST_CASE("UDP closing a peer twin preserves the sibling's peer-index entry",
          "[udp][backpressure][peerindex]")
{
  using iora::network::UdpEngineTestAccess;
  UdpFixture f{};
  ListenerId lid = startWithListener(f).lid;
  auto peerPort = testnet::getFreePortUDP();
  auto twins = twinVias(f, lid, peerPort); // both twins in one (lid,peer) list; ss1 at front
  SessionId ss1 = twins.first;
  SessionId ss2 = twins.second;

  // Task 1.5 (tracker 2026-10-02-3): assert the exact index state via peerIndexLookup (the
  // per-listener key shape), not just any-bucket membership. Both twins present in insertion
  // order; ss1 is the front / dispatch target.
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "127.0.0.1", peerPort) ==
          std::vector<SessionId>{ss1, ss2});
  REQUIRE(f.tx.close(ss2)); // close the (non-front) twin
  UdpEngineTestAccess::ioBarrier(f.tx);
  REQUIRE_FALSE(UdpEngineTestAccess::hasSession(f.tx, ss2));
  // ss1 survives at the front; ss2 removed (H-3: closing a twin does not evict the sibling).
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "127.0.0.1", peerPort) ==
          std::vector<SessionId>{ss1});
  f.tx.stop();
}

// === tracker 2026-10-02-3: _peerIndex cross-listener misrouting ===
// Red-before-green discriminators. Each test leads with BLACK-BOX observables (acceptCount, the
// dispatched sid via sidForPayload(), and the on-wire source port) that FAIL on the pre-fix
// engine; the structural peerIndexLookup() assertions (the post-fix per-listener key shape) are
// added AFTER those, per Phase 1.5, and only pin the green (REQUIRE stops at the first failure,
// so they never run pre-fix). helpers: sendLoopbackV4 (raw-fd send), twinVias (two via twins).

TEST_CASE("UDP _peerIndex one peer source to two listeners dispatches per-listener (a)",
          "[udp][peerindex][multi-listener]")
{
  using iora::network::UdpEngineTestAccess;
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto portA = testnet::getFreePortUDP();
  auto portB = testnet::getFreePortUDP();
  auto lrA = f.tx.addListener("127.0.0.1", portA, TlsMode::None);
  auto lrB = f.tx.addListener("127.0.0.1", portB, TlsMode::None);
  REQUIRE(lrA.isOk());
  REQUIRE(lrB.isOk());
  ListenerId lidA = lrA.value();
  ListenerId lidB = lrB.value();

  // ONE raw peer socket => one source ip:port reaching BOTH our listeners.
  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = testnet::bindLoopbackV4Ephemeral(SOCK_DGRAM, pPort);
  timeval tv{2, 0};
  ::setsockopt(peer.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  sendLoopbackV4(peer.get(), portA, "toA");
  sendLoopbackV4(peer.get(), portB, "toB");

  // Fixed: two distinct sessions accepted (one per listener). Pre-fix: the second datagram
  // collides on the address-only key and is dispatched to the first session -> only ONE
  // accept ever fires -> this wait times out (RED).
  REQUIRE(f.waitForCount(f.acceptCount, 2));

  // The server echoes each datagram back from the listener it was dispatched on. Read the
  // source port off the wire. Pre-fix both echoes leave from portA; fixed, "toB" from portB.
  std::uint16_t fromToA = 0, fromToB = 0;
  for (int i = 0; i < 6 && (fromToA == 0 || fromToB == 0); ++i)
  {
    char buf[64];
    sockaddr_in src{};
    socklen_t sl = sizeof(src);
    ssize_t r = ::recvfrom(peer.get(), buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&src),
                           &sl);
    if (r <= 0)
    {
      break;
    }
    std::string p(buf, static_cast<std::size_t>(r));
    if (p == "toA")
    {
      fromToA = ntohs(src.sin_port);
    }
    else if (p == "toB")
    {
      fromToB = ntohs(src.sin_port);
    }
  }
  REQUIRE(fromToA == portA);
  REQUIRE(fromToB == portB); // RED pre-fix (the "toB" echo leaves from portA)

  // Two distinct sessions, one per listener (the B-arrival is not the A-session).
  SessionId sA = f.sidForPayload("toA");
  SessionId sB = f.sidForPayload("toB");
  REQUIRE(sA != 0);
  REQUIRE(sB != 0);
  REQUIRE(sA != sB);
  // Structural (post-fix shape): each listener owns its own single-session (listener,peer) list.
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lidA, "127.0.0.1", pPort) ==
          std::vector<SessionId>{sA});
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lidB, "127.0.0.1", pPort) ==
          std::vector<SessionId>{sB});
  f.tx.stop();
}

TEST_CASE("UDP _peerIndex via on a second listener to an already-indexed peer dispatches per-listener (b)",
          "[udp][peerindex][via][multi-listener]")
{
  using iora::network::UdpEngineTestAccess;
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto portA = testnet::getFreePortUDP();
  auto portB = testnet::getFreePortUDP();
  auto lrA = f.tx.addListener("127.0.0.1", portA, TlsMode::None);
  auto lrB = f.tx.addListener("127.0.0.1", portB, TlsMode::None);
  REQUIRE(lrA.isOk());
  REQUIRE(lrB.isOk());
  ListenerId lidA = lrA.value();
  ListenerId lidB = lrB.value();

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = testnet::bindLoopbackV4Ephemeral(SOCK_DGRAM, pPort);
  timeval tv{2, 0};
  ::setsockopt(peer.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  // Two vias to the SAME peer, one per listener. Pre-fix viaB is NOT indexed (the global
  // peerExists check), so a datagram from the peer to listener B is dispatched to viaA.
  auto rA = f.tx.connectViaListener(lidA, "127.0.0.1", pPort);
  auto rB = f.tx.connectViaListener(lidB, "127.0.0.1", pPort);
  REQUIRE(rA.isOk());
  REQUIRE(rB.isOk());
  SessionId viaA = rA.value();
  SessionId viaB = rB.value();
  REQUIRE(f.waitForCount(f.connectCount, 2));

  // Outbound half (sip-voip L-2): each via's request must EGRESS its own listener's port, so a
  // real peer replying per Via sent-by/rport (RFC 3581 §4 / RFC 3261 §18.2.2) reaches the right
  // session. Observe the source port on the wire from the raw peer.
  REQUIRE(f.tx.send(viaB, "reqB", 4));
  REQUIRE(f.tx.send(viaA, "reqA", 4));
  std::uint16_t fromReqA = 0, fromReqB = 0;
  for (int i = 0; i < 6 && (fromReqA == 0 || fromReqB == 0); ++i)
  {
    char buf[64];
    sockaddr_in src{};
    socklen_t sl = sizeof(src);
    ssize_t r = ::recvfrom(peer.get(), buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&src),
                           &sl);
    if (r <= 0)
    {
      break;
    }
    std::string p(buf, static_cast<std::size_t>(r));
    if (p == "reqA")
    {
      fromReqA = ntohs(src.sin_port);
    }
    else if (p == "reqB")
    {
      fromReqB = ntohs(src.sin_port);
    }
  }
  REQUIRE(fromReqA == portA);
  REQUIRE(fromReqB == portB);

  // Inbound half: the peer's datagram to listener B dispatches to viaB (not viaA).
  sendLoopbackV4(peer.get(), portB, "fromP");
  REQUIRE(f.waitForCount(f.dataCount, 1));
  UdpEngineTestAccess::ioBarrier(f.tx);
  REQUIRE(f.acceptCount.load() == 0);          // an index entry exists -> no spurious accept
  REQUIRE(f.sidForPayload("fromP") == viaB);   // RED pre-fix (dispatched to viaA)
  // Structural (post-fix shape): each listener owns its OWN (listener,peer) twin list.
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lidA, "127.0.0.1", pPort) ==
          std::vector<SessionId>{viaA});
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lidB, "127.0.0.1", pPort) ==
          std::vector<SessionId>{viaB});
  f.tx.stop();
}

TEST_CASE("UDP _peerIndex closing the indexed original re-points to a surviving twin (c, F-6)",
          "[udp][peerindex][via]")
{
  using iora::network::UdpEngineTestAccess;
  UdpFixture f;
  auto rig = startWithListener(f);
  ListenerId lid = rig.lid;
  std::uint16_t ourPort = rig.port;

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = testnet::bindLoopbackV4Ephemeral(SOCK_DGRAM, pPort);

  // Two twins (same listener, same peer). ss1 is inserted first => front / indexed original.
  auto twins = twinVias(f, lid, pPort);
  SessionId ss1 = twins.first;
  SessionId ss2 = twins.second;
  REQUIRE(f.waitForCount(f.connectCount, 2));

  REQUIRE(f.tx.close(ss1)); // close the indexed original
  UdpEngineTestAccess::ioBarrier(f.tx);
  REQUIRE_FALSE(UdpEngineTestAccess::hasSession(f.tx, ss1));

  // Inject an inbound datagram from the peer's source port to our listener.
  sendLoopbackV4(peer.get(), ourPort, "reinject");

  REQUIRE(f.waitForCount(f.dataCount, 1));
  UdpEngineTestAccess::ioBarrier(f.tx);
  // Fixed: promoted to ss2, no new accept. Pre-fix: the entry was erased -> a spurious accept
  // + a new sid (RED on both assertions).
  REQUIRE(f.acceptCount.load() == 0);
  REQUIRE(f.sidForPayload("reinject") == ss2);
  // Structural (post-fix shape): ss1 removed, ss2 promoted to the front / sole twin.
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "127.0.0.1", pPort) ==
          std::vector<SessionId>{ss2});
  f.tx.stop();
}

TEST_CASE("UDP _peerIndex closing the last twin removes the entry; next inbound is a fresh accept (e)",
          "[udp][peerindex][via]")
{
  using iora::network::UdpEngineTestAccess;
  UdpFixture f;
  auto rig = startWithListener(f);
  ListenerId lid = rig.lid;
  std::uint16_t ourPort = rig.port;

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = testnet::bindLoopbackV4Ephemeral(SOCK_DGRAM, pPort);

  auto twins = twinVias(f, lid, pPort);
  SessionId ss1 = twins.first;
  SessionId ss2 = twins.second;
  REQUIRE(f.waitForCount(f.connectCount, 2));
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "127.0.0.1", pPort) ==
          std::vector<SessionId>{ss1, ss2});

  // Close BOTH twins -> the (listener,peer) entry is erased (closeNow erase-on-empty branch).
  REQUIRE(f.tx.close(ss1));
  REQUIRE(f.tx.close(ss2));
  UdpEngineTestAccess::ioBarrier(f.tx);
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "127.0.0.1", pPort).empty());

  // The next inbound datagram from that peer must now be a FRESH accept with a new sid.
  sendLoopbackV4(peer.get(), ourPort, "revive");
  REQUIRE(f.waitForCount(f.acceptCount, 1));
  UdpEngineTestAccess::ioBarrier(f.tx);
  SessionId revived = f.sidForPayload("revive");
  REQUIRE(revived != 0);
  REQUIRE(revived != ss1);
  REQUIRE(revived != ss2);
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "127.0.0.1", pPort) ==
          std::vector<SessionId>{revived});
  f.tx.stop();
}

TEST_CASE("UDP _peerIndex self-origination to another listener is not misrouted (d, self-loop collision)",
          "[udp][peerindex][multi-listener][loopback]")
{
  using iora::network::UdpEngineTestAccess;
  UdpFixture f;
  // Self-origination datagrams carry our OWN listener as their source; with echo on they would
  // cascade across listeners. Assert on acceptCount + the dispatched sid instead.
  f.echoEnabled.store(false);
  REQUIRE(f.tx.start().isOk());
  auto portA = testnet::getFreePortUDP();
  auto portB = testnet::getFreePortUDP();
  auto lrA = f.tx.addListener("127.0.0.1", portA, TlsMode::None);
  auto lrB = f.tx.addListener("127.0.0.1", portB, TlsMode::None);
  REQUIRE(lrA.isOk());
  REQUIRE(lrB.isOk());
  ListenerId lidA = lrA.value();
  ListenerId lidB = lrB.value();

  // 1) Self-loop via on A: send to listener A's own address. selfVia is itself indexed under
  // (A, 127.0.0.1:portA); the looped-back datagram arrives on A from that same source, so it is
  // dispatched to selfVia itself — NO new accept (the existing "self-loopback via" test relies
  // on the same behaviour). So inboundOnA == selfVia and acceptsAfterSelf == 0.
  SessionId selfVia = f.tx.connectViaListener(lidA, "127.0.0.1", portA).value();
  REQUIRE(f.waitForCount(f.connectCount, 1));
  REQUIRE(f.tx.send(selfVia, "self", 4));
  REQUIRE(f.waitForCount(f.dataCount, 1));
  UdpEngineTestAccess::ioBarrier(f.tx);
  SessionId inboundOnA = f.sidForPayload("self");
  REQUIRE(inboundOnA == selfVia);                    // self-loop dispatches to the via itself
  const int acceptsAfterSelf = f.acceptCount.load();
  REQUIRE(acceptsAfterSelf == 0);                    // no ServerPeer accepted for a self-loop

  // 2) Via A -> B: egresses listener A's fd (source 127.0.0.1:portA) to listener B, so the
  // datagram arrives on B with the SAME source (127.0.0.1:portA) as the self-loop on A.
  SessionId viaAtoB = f.tx.connectViaListener(lidA, "127.0.0.1", portB).value();
  REQUIRE(f.waitForCount(f.connectCount, 2));
  REQUIRE(f.tx.send(viaAtoB, "toB2", 4));
  REQUIRE(f.waitForCount(f.dataCount, 2));
  UdpEngineTestAccess::ioBarrier(f.tx);

  // Fixed: key (B, 127.0.0.1:portA) misses -> a NEW ServerPeer accepted on B; "toB2" goes to
  // it, distinct from the A-side self-loop session. Pre-fix: the address-only key collides with
  // selfVia's entry -> "toB2" misrouted to selfVia, no new accept (RED on both).
  REQUIRE(f.acceptCount.load() == acceptsAfterSelf + 1);
  SessionId sidToB2 = f.sidForPayload("toB2");
  REQUIRE(sidToB2 != inboundOnA);
  // Structural (post-fix shape): listener B owns a fresh (B, 127.0.0.1:portA) entry distinct
  // from A's self-loop entry.
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lidA, "127.0.0.1", portA) ==
          std::vector<SessionId>{selfVia});
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lidB, "127.0.0.1", portA) ==
          std::vector<SessionId>{sidToB2});
  f.tx.stop();
}

// ── RFC 3581 §4 ADDRESS-HALF: wildcard-bind reply source selection (tracker 2026-10-03-1) ──
// On a 0.0.0.0/:: bind a reply must egress FROM the local address the request arrived on, not the
// kernel route-preferred source. The root-free rig: all 127/8 is local on Linux, so a peer bound
// to 127.0.0.1 can send to 127.0.0.2 on our wildcard listener; pre-fix the echo leaves from
// 127.0.0.1 (the route src to the peer), fixed it leaves from 127.0.0.2. Phase-0 tests use
// BLACK-BOX assertions (on-wire source IP, acceptCount, dispatched sid) ONLY — the structural
// peerIndexLookup(local) assertions are added in Phase 1 (they need the post-fix key shape).

TEST_CASE("UDP wildcard reply egresses the request local dest IP, direct path (T1, RFC 3581 §4)",
          "[udp][wildcard][srcip]")
{
  using iora::network::UdpEngineTestAccess;
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx.addListener("0.0.0.0", port, TlsMode::None).isOk());

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort);
  // Request arrives on local 127.0.0.2; the fixture echoes it (direct sendDo reply path).
  sendV4ToDest(peer.get(), "127.0.0.2", port, "d-direct");

  REQUIRE(f.waitFor(f.accepted));
  auto reply = recvV4Src(peer.get());
  REQUIRE(reply.second == "d-direct");
  REQUIRE(reply.first == "127.0.0.2"); // RED pre-fix: kernel picks 127.0.0.1

  // Retransmission (RFC 3261 §17.1.2.2): the same request to the same local hits the EXACT key — no
  // second accept, reply still from 127.0.0.2.
  sendV4ToDest(peer.get(), "127.0.0.2", port, "d-direct");
  REQUIRE(f.waitForCount(f.dataCount, 2));
  UdpEngineTestAccess::ioBarrier(f.tx);
  REQUIRE(f.acceptCount.load() == 1);
  auto reply2 = recvV4Src(peer.get());
  REQUIRE(reply2.second == "d-direct");
  REQUIRE(reply2.first == "127.0.0.2");
  f.tx.stop();
}

TEST_CASE("UDP wildcard reply egresses the request local dest IP, queued-flush path (T2)",
          "[udp][wildcard][srcip]")
{
  using iora::network::UdpEngineTestAccess;
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  auto lr = f.tx.addListener("0.0.0.0", port, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort);
  // 1) First datagram → accept (and a direct echo we ignore); capture the ServerPeer sid.
  sendV4ToDest(peer.get(), "127.0.0.2", port, "accept");
  REQUIRE(f.waitFor(f.accepted));
  SessionId ss = f.serverSid; // published via `accepted` (one accept)
  REQUIRE(ss != 0);
  (void)recvV4Src(peer.get()); // drain the direct echo

  // 2) Arm the per-session EAGAIN seam so the next echo QUEUES on the shared listener wq, then send
  //    a second datagram. GATE the disarm on the echo actually being QUEUED (M1): the fixture bumps
  //    dataCount BEFORE its echo send() enqueues the command, so waiting on dataCount alone can let
  //    the disarm win and the echo take the DIRECT path (which also pins the source, masking the
  //    flush path). Waiting on listenerQueuedForSid==1 guarantees flushListener is exercised.
  UdpEngineTestAccess::armForceEagain(f.tx, ss);
  sendV4ToDest(peer.get(), "127.0.0.2", port, "d-flush");
  REQUIRE(f.waitUntil(
    [&] { return UdpEngineTestAccess::listenerQueuedForSid(f.tx, lid, ss) == 1; }));
  UdpEngineTestAccess::disarmForceEagain(f.tx);

  auto reply = recvV4Src(peer.get());
  REQUIRE(reply.second == "d-flush");
  REQUIRE(reply.first == "127.0.0.2"); // RED pre-fix: the flushed echo leaves from 127.0.0.1
  f.tx.stop();
}

TEST_CASE("UDP wildcard reply reaches a CONNECTED peer (T-CONN, symmetric-NAT/pinhole repro)",
          "[udp][wildcard][srcip]")
{
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx.addListener("0.0.0.0", port, TlsMode::None).isOk());

  // Peer bound to 127.0.0.1, connect()ed to 127.0.0.2:port. The kernel then DROPS any reply whose
  // source != 127.0.0.2 — exactly a strict pinhole / symmetric NAT. Pre-fix the echo leaves from
  // 127.0.0.1 and is dropped (no reply); fixed it leaves from 127.0.0.2 and arrives.
  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort);
  sockaddr_in dst{};
  dst.sin_family = AF_INET;
  dst.sin_port = htons(port);
  REQUIRE(::inet_pton(AF_INET, "127.0.0.2", &dst.sin_addr) == 1);
  REQUIRE(::connect(peer.get(), reinterpret_cast<sockaddr *>(&dst), sizeof(dst)) == 0);
  const char *m = "d-conn";
  REQUIRE(::send(peer.get(), m, 6, 0) == 6);

  REQUIRE(f.waitFor(f.accepted));
  auto reply = recvV4Src(peer.get());
  REQUIRE(reply.second == "d-conn"); // RED pre-fix: the 127.0.0.1-sourced echo is dropped (timeout)
  f.tx.stop();
}

TEST_CASE("UDP dual-stack :: wildcard reply egresses the v4 request local dest IP (T3)",
          "[udp][wildcard][srcip][dualstack]")
{
  using iora::network::UdpEngineTestAccess;
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  auto lr = f.tx.addListener("::", port, TlsMode::None); // V6ONLY=0 dual-stack
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort); // v4 peer → v4-mapped arrival
  sendV4ToDest(peer.get(), "127.0.0.2", port, "d-ds");

  REQUIRE(f.waitFor(f.accepted));
  auto reply = recvV4Src(peer.get());
  REQUIRE(reply.second == "d-ds");
  REQUIRE(reply.first == "127.0.0.2"); // RED pre-fix (v4-mapped reply from the kernel source)
  // Structural (M6): the key uses the CANONICAL v4-mapped form ::ffff:a.b.c.d for both the peer and
  // the captured local (DD4; this exact spelling is what sibling 2026-10-03-2 must match).
  UdpEngineTestAccess::ioBarrier(f.tx);
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "::ffff:127.0.0.1", pPort,
                                               "::ffff:127.0.0.2") ==
          std::vector<SessionId>{f.serverSid});
  f.tx.stop();
}

TEST_CASE("UDP wildcard splits one peer source across local dest IPs (T4, key extension)",
          "[udp][wildcard][srcip][peerindex]")
{
  using iora::network::UdpEngineTestAccess;
  UdpFixture f;
  f.echoEnabled.store(false); // reply manually so we control ordering (M3)
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  auto lr = f.tx.addListener("0.0.0.0", port, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  // ONE peer source (127.0.0.1:pPort) reaching TWO local dest IPs on ONE wildcard listener.
  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort);
  sendV4ToDest(peer.get(), "127.0.0.2", port, "to2");
  sendV4ToDest(peer.get(), "127.0.0.3", port, "to3");

  // Fixed: two distinct sessions (keys differ by local). Pre-fix: the address-only key collapses
  // both to one session → only ONE accept (this wait times out → RED).
  REQUIRE(f.waitForCount(f.acceptCount, 2));
  REQUIRE(f.waitForCount(f.dataCount, 2));
  UdpEngineTestAccess::ioBarrier(f.tx);
  SessionId s2 = f.sidForPayload("to2");
  SessionId s3 = f.sidForPayload("to3");
  REQUIRE(s2 != 0);
  REQUIRE(s3 != 0);
  REQUIRE(s2 != s3);
  // Structural (M6): the two sessions live under DISTINCT local-aware keys.
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "127.0.0.1", pPort, "127.0.0.2") ==
          std::vector<SessionId>{s2});
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "127.0.0.1", pPort, "127.0.0.3") ==
          std::vector<SessionId>{s3});

  // Reply in REVERSE arrival order (M3): each reply MUST leave from its own session's local, ruling
  // out a last-writer source bleed between the two co-resident sessions.
  REQUIRE(f.tx.send(s3, "r3", 2));
  REQUIRE(f.tx.send(s2, "r2", 2));
  std::string from2, from3;
  for (int i = 0; i < 4 && (from2.empty() || from3.empty()); ++i)
  {
    auto r = recvV4Src(peer.get());
    if (r.second == "r2")
    {
      from2 = r.first;
    }
    else if (r.second == "r3")
    {
      from3 = r.first;
    }
  }
  REQUIRE(from2 == "127.0.0.2");
  REQUIRE(from3 == "127.0.0.3");
  f.tx.stop();
}

TEST_CASE("UDP wildcard via to a peer dispatches that peer's inbound without a spurious accept "
          "(T5 guard)",
          "[udp][wildcard][srcip][via]")
{
  using iora::network::UdpEngineTestAccess;
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  auto lr = f.tx.addListener("0.0.0.0", port, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort);
  auto rv = f.tx.connectViaListener(lid, "127.0.0.1", pPort);
  REQUIRE(rv.isOk());
  SessionId via = rv.value();
  REQUIRE(f.waitForCount(f.connectCount, 1));

  // The peer sends to local 127.0.0.2. The via already targets 127.0.0.1:pPort, so inbound from
  // that peer must dispatch to the via (adopted on a wildcard bind), NOT a fresh accept. Black-box
  // (passes pre- and post-fix — a regression guard for the adopt path).
  sendV4ToDest(peer.get(), "127.0.0.2", port, "p-in");
  REQUIRE(f.waitForCount(f.dataCount, 1));
  UdpEngineTestAccess::ioBarrier(f.tx);
  REQUIRE(f.acceptCount.load() == 0);
  REQUIRE(f.sidForPayload("p-in") == via);

  // M2: after adopt, a send ON the adopted via MUST egress from the captured local (127.0.0.2) — the
  // core DD5 benefit. MUTATION-CHECK: deleting `sessions[i]->localSrc = local` in adoptWildcardVia
  // makes this assert fail (source reverts to the kernel's 127.0.0.1) — verified manually.
  REQUIRE(f.tx.send(via, "va", 2));
  auto adoptedReply = recvV4Src(peer.get());
  REQUIRE(adoptedReply.second == "va");
  REQUIRE(adoptedReply.first == "127.0.0.2");

  // LOW-2 / 0.6: a SECOND via created AFTER the adopt stays in the sentinel bucket (unadopted) and
  // sends from the kernel source — not adopted onto the existing local-aware key.
  auto rv2 = f.tx.connectViaListener(lid, "127.0.0.1", pPort);
  REQUIRE(rv2.isOk());
  SessionId via2 = rv2.value();
  REQUIRE(f.waitForCount(f.connectCount, 2));
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "127.0.0.1", pPort,
                                               UdpEngineTestAccess::VIA_LOCAL_SENTINEL) ==
          std::vector<SessionId>{via2});
  REQUIRE(f.tx.send(via2, "v2", 2));
  auto via2Reply = recvV4Src(peer.get());
  REQUIRE(via2Reply.second == "v2");
  REQUIRE(via2Reply.first == "127.0.0.1"); // unadopted → kernel source
  f.tx.stop();
}

TEST_CASE("UDP wildcard: inbound-created session is not displaced by a later via (T-not-adopted guard)",
          "[udp][wildcard][srcip][via]")
{
  using iora::network::UdpEngineTestAccess;
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  auto lr = f.tx.addListener("0.0.0.0", port, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort);
  // 1) Inbound FIRST creates the (listener,local,peer) session.
  sendV4ToDest(peer.get(), "127.0.0.2", port, "in1");
  REQUIRE(f.waitFor(f.accepted));
  SessionId inbound = f.serverSid;
  (void)recvV4Src(peer.get());

  // 2) A later via to the same peer must NOT be adopted (an exact inbound key already exists).
  auto rv = f.tx.connectViaListener(lid, "127.0.0.1", pPort);
  REQUIRE(rv.isOk());
  SessionId via = rv.value();
  REQUIRE(f.waitForCount(f.connectCount, 1));

  // 3) Next inbound from the peer still dispatches to the inbound session, no new accept.
  sendV4ToDest(peer.get(), "127.0.0.2", port, "in2");
  REQUIRE(f.waitForCount(f.dataCount, 2)); // in1 + in2 (echoes aside)
  UdpEngineTestAccess::ioBarrier(f.tx);
  REQUIRE(f.acceptCount.load() == 1);
  REQUIRE(f.sidForPayload("in2") == inbound);
  // Structural (M6): the inbound session owns the local-aware key; the via stays UNADOPTED in the
  // sentinel bucket (its exact-key lookup never matched the inbound's).
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "127.0.0.1", pPort, "127.0.0.2") ==
          std::vector<SessionId>{inbound});
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "127.0.0.1", pPort,
                                               UdpEngineTestAccess::VIA_LOCAL_SENTINEL) ==
          std::vector<SessionId>{via});
  f.tx.stop();
}

TEST_CASE("UDP specific-bind reply source unchanged (T7 regression guard)", "[udp][wildcard][srcip]")
{
  using iora::network::UdpEngineTestAccess;
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  auto lr = f.tx.addListener("127.0.0.1", port, TlsMode::None); // SPECIFIC bind: no pktinfo
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort);
  sendV4ToDest(peer.get(), "127.0.0.1", port, "spec");

  REQUIRE(f.waitFor(f.accepted));
  auto reply = recvV4Src(peer.get());
  REQUIRE(reply.second == "spec");
  REQUIRE(reply.first == "127.0.0.1"); // passes pre- and post-fix (byte-identical specific path)
  // Structural (M6): a specific bind keys WITHOUT a local segment (nullptr) — byte-identical to the
  // pre-task lid|host:port shape, so existing index tests are unaffected.
  UdpEngineTestAccess::ioBarrier(f.tx);
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "127.0.0.1", pPort, nullptr) ==
          std::vector<SessionId>{f.serverSid});
  f.tx.stop();
}

TEST_CASE("UDP wildcard via adopts on first inbound, then re-accepts after close (T6, no black-hole)",
          "[udp][wildcard][srcip][via]")
{
  using iora::network::UdpEngineTestAccess;
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  auto lr = f.tx.addListener("0.0.0.0", port, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort);
  // TWO vias to the same peer on the wildcard listener (M5): both start in the sentinel bucket and
  // must adopt TOGETHER onto the local-aware key, each twin's pkey rewritten.
  auto twins = twinVias(f, lid, pPort);
  SessionId via1 = twins.first;
  SessionId via2 = twins.second;
  REQUIRE(f.waitForCount(f.connectCount, 2));
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "127.0.0.1", pPort,
                                               UdpEngineTestAccess::VIA_LOCAL_SENTINEL) ==
          std::vector<SessionId>{via1, via2});

  // First inbound to local 127.0.0.2 ADOPTS the WHOLE twin list onto (lid, 127.0.0.2, peer) — no new
  // accept; dispatch goes to the front (via1).
  sendV4ToDest(peer.get(), "127.0.0.2", port, "adopt");
  REQUIRE(f.waitForCount(f.dataCount, 1));
  UdpEngineTestAccess::ioBarrier(f.tx);
  REQUIRE(f.acceptCount.load() == 0);
  REQUIRE(f.sidForPayload("adopt") == via1);
  // Structural: the whole twin list moved from the sentinel key to the local-aware key (every twin's
  // pkey rewritten). MUTATION-CHECK: skipping `s->pkey.swap` in adoptWildcardVia makes the close
  // below a no-op (dead sid at front, no re-accept) — verified manually.
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "127.0.0.1", pPort,
                                               UdpEngineTestAccess::VIA_LOCAL_SENTINEL)
            .empty());
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "127.0.0.1", pPort, "127.0.0.2") ==
          std::vector<SessionId>{via1, via2});

  // Close the FRONT twin: via2 is promoted (pkey was rewritten for it too), no spurious accept.
  REQUIRE(f.tx.close(via1));
  UdpEngineTestAccess::ioBarrier(f.tx);
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "127.0.0.1", pPort, "127.0.0.2") ==
          std::vector<SessionId>{via2});
  sendV4ToDest(peer.get(), "127.0.0.2", port, "to-v2");
  REQUIRE(f.waitForCount(f.dataCount, 2));
  UdpEngineTestAccess::ioBarrier(f.tx);
  REQUIRE(f.acceptCount.load() == 0);
  REQUIRE(f.sidForPayload("to-v2") == via2);

  // Close the LAST twin: the entry is erased; the next inbound is a FRESH accept (no black hole).
  REQUIRE(f.tx.close(via2));
  UdpEngineTestAccess::ioBarrier(f.tx);
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "127.0.0.1", pPort, "127.0.0.2").empty());
  sendV4ToDest(peer.get(), "127.0.0.2", port, "revive");
  REQUIRE(f.waitForCount(f.acceptCount, 1));
  UdpEngineTestAccess::ioBarrier(f.tx);
  SessionId revived = f.sidForPayload("revive");
  REQUIRE(revived != 0);
  REQUIRE(revived != via1);
  REQUIRE(revived != via2);
  f.tx.stop();
}

TEST_CASE("UDP wildcard: a pinned source no longer local closes the session, direct path (T8a)",
          "[udp][wildcard][srcip]")
{
  using iora::network::UdpEngineTestAccess;
  if (nonLocalBindAllowed())
  {
    WARN("ip_nonlocal_bind=1: a non-local source is accepted so DD7 cannot fire; skipping T8a");
    return;
  }
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx.addListener("0.0.0.0", port, TlsMode::None).isOk());

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort);
  sendV4ToDest(peer.get(), "127.0.0.2", port, "accept");
  REQUIRE(f.waitFor(f.accepted));
  SessionId ss = f.serverSid;
  REQUIRE(ss != 0);
  (void)recvV4Src(peer.get());

  // Point the captured local at a NON-LOCAL address (TEST-NET-1): the next echo's sendmsg fails
  // (EINVAL/EADDRNOTAVAIL) and DD7 closes the session on the DIRECT send path.
  REQUIRE(UdpEngineTestAccess::setLocalSrcV4(f.tx, ss, "192.0.2.1"));
  sendV4ToDest(peer.get(), "127.0.0.2", port, "boom");
  REQUIRE(f.waitForCount(f.closeCount, 1));
  REQUIRE(f.lastClose().first == TransportError::Socket);
  f.tx.stop();
}

TEST_CASE("UDP wildcard: a pinned source no longer local closes the session, flush path (T8b)",
          "[udp][wildcard][srcip]")
{
  using iora::network::UdpEngineTestAccess;
  if (nonLocalBindAllowed())
  {
    WARN("ip_nonlocal_bind=1: a non-local source is accepted so DD7 cannot fire; skipping T8b");
    return;
  }
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  auto lr = f.tx.addListener("0.0.0.0", port, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort);
  sendV4ToDest(peer.get(), "127.0.0.2", port, "accept");
  REQUIRE(f.waitFor(f.accepted));
  SessionId ss = f.serverSid;
  REQUIRE(ss != 0);
  (void)recvV4Src(peer.get());

  // Non-local local + the EAGAIN seam so the echo QUEUES with the bad source snapshotted into the
  // OutDg; GATE the disarm on the echo being QUEUED (M1), then disarm → flushListener's sendmsg
  // fails → DD7 closes the session on the FLUSH path.
  REQUIRE(UdpEngineTestAccess::setLocalSrcV4(f.tx, ss, "192.0.2.1"));
  UdpEngineTestAccess::armForceEagain(f.tx, ss);
  sendV4ToDest(peer.get(), "127.0.0.2", port, "qboom");
  REQUIRE(f.waitUntil(
    [&] { return UdpEngineTestAccess::listenerQueuedForSid(f.tx, lid, ss) == 1; }));
  UdpEngineTestAccess::disarmForceEagain(f.tx);
  REQUIRE(f.waitForCount(f.closeCount, 1));
  REQUIRE(f.lastClose().first == TransportError::Socket);
  // After the DD7 close the session's datagrams are purged (none left queued).
  UdpEngineTestAccess::ioBarrier(f.tx);
  REQUIRE(UdpEngineTestAccess::listenerQueuedForSid(f.tx, lid, ss) == 0);
  f.tx.stop();
}

TEST_CASE("UDP wildcard idle-reap reopens a response on the kernel source (T9 characterization)",
          "[udp][wildcard][srcip][gc]")
{
  // CHARACTERIZES known_limitations[1] (NOT a red test): a reply reopened via connectViaListener
  // AFTER the receiving ServerPeer was idle-reaped leaves from the KERNEL source, not the request's
  // local. followups_to_file[1]+[2] flip this (they let the reopen pin the captured local).
  TransportConfig cfg;
  cfg.idleTimeout = std::chrono::seconds(1);
  cfg.gcInterval = std::chrono::seconds(1);
  UdpFixture f{cfg};
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  auto lr = f.tx.addListener("0.0.0.0", port, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort, 3000);
  // While the session is live, the reply IS pinned to 127.0.0.2 (the fix works pre-reap).
  sendV4ToDest(peer.get(), "127.0.0.2", port, "live");
  REQUIRE(f.waitFor(f.accepted));
  auto live = recvV4Src(peer.get());
  REQUIRE(live.second == "live");
  REQUIRE(live.first == "127.0.0.2");

  // Let the ServerPeer be idle-reaped.
  REQUIRE(f.waitForCount(f.closeCount, 1, 6000));

  // Reopen for the "final response" via connectViaListener: unadopted → kernel source (127.0.0.1).
  auto rv = f.tx.connectViaListener(lid, "127.0.0.1", pPort);
  REQUIRE(rv.isOk());
  SessionId via = rv.value();
  REQUIRE(f.waitForCount(f.connectCount, 1));
  REQUIRE(f.tx.send(via, "final", 5));
  auto reopened = recvV4Src(peer.get());
  REQUIRE(reopened.second == "final");
  REQUIRE(reopened.first == "127.0.0.1"); // documented limitation (followup flips to 127.0.0.2)
  f.tx.stop();
}

// ── getLocalAddress captured-local presentation (tracker 2026-10-04-2) ──────────────────────────
// getLocalAddress(sid) must report the per-session CAPTURED local (2026-10-03-1), UNMAPPED, on a
// wildcard bind — not the wildcard getsockname result.

TEST_CASE("UDP getLocalAddress reports each ServerPeer's captured local on a wildcard bind (GLA1, "
          "multi-local discriminating)",
          "[udp][wildcard][srcip][getlocal]")
{
  using iora::network::UdpEngineTestAccess;
  // Run on BOTH a v4 wildcard (0.0.0.0) and a dual-stack wildcard (::): the dual-stack path is the
  // one whose captured local is v4-mapped and must be unmapped bare (sip L-3).
  const char *bind = GENERATE("0.0.0.0", "::");
  UdpFixture f;
  f.echoEnabled.store(false);
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  auto lr = f.tx.addListener(bind, port, TlsMode::None);
  REQUIRE(lr.isOk());

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort);
  sendV4ToDest(peer.get(), "127.0.0.2", port, "g2");
  sendV4ToDest(peer.get(), "127.0.0.3", port, "g3");
  REQUIRE(f.waitForCount(f.acceptCount, 2));
  REQUIRE(f.waitForCount(f.dataCount, 2));
  UdpEngineTestAccess::ioBarrier(f.tx);
  SessionId s2 = f.sidForPayload("g2");
  SessionId s3 = f.sidForPayload("g3");
  REQUIRE(s2 != 0);
  REQUIRE(s3 != 0);

  // Each session reports its OWN captured local (not the wildcard, not the other session's local),
  // with the bound listener port, UNMAPPED (bare v4 even on the dual-stack bind). A single-local
  // case could not catch first/last-wins.
  auto a2 = f.tx.getLocalAddress(s2);
  auto a3 = f.tx.getLocalAddress(s3);
  REQUIRE(a2.host == "127.0.0.2");
  REQUIRE(a2.port == port);
  REQUIRE(a3.host == "127.0.0.3");
  REQUIRE(a3.port == port);
  f.tx.stop();
}

TEST_CASE("UDP getLocalAddress presents a dual-stack v4-mapped captured local as BARE IPv4 (GLA2, "
          "+ key-form round-trip)",
          "[udp][wildcard][srcip][getlocal][dualstack]")
{
  using iora::network::UdpEngineTestAccess;
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  auto lr = f.tx.addListener("::", port, TlsMode::None); // V6ONLY=0 dual-stack
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort); // v4 arrival → v4-mapped capture
  sendV4ToDest(peer.get(), "127.0.0.2", port, "gm");
  REQUIRE(f.waitFor(f.accepted));
  UdpEngineTestAccess::ioBarrier(f.tx);

  // Outward presentation is BARE IPv4 — never ::ffff:127.0.0.2, never the wildcard ::.
  auto a = f.tx.getLocalAddress(f.serverSid);
  REQUIRE(a.host == "127.0.0.2");
  REQUIRE(a.port == port);

  // Round-trip (H-1): the INTERNAL key form stays v4-mapped. RE-MAP the getter's unmapped output
  // (a.host, proven bare v4 above) back to the v4-mapped spelling and require it equals the captured
  // localSrc's canonical key form byte-for-byte — this exercises the re-map rather than asserting a
  // constant. The peer-index key uses that same mapped form.
  REQUIRE(UdpEngineTestAccess::localSrcText(f.tx, f.serverSid) == "::ffff:" + a.host);
  REQUIRE(UdpEngineTestAccess::peerIndexLookup(f.tx, lid, "::ffff:127.0.0.1", pPort,
                                               "::ffff:127.0.0.2") ==
          std::vector<SessionId>{f.serverSid});
  f.tx.stop();
}

TEST_CASE("UDP getLocalAddress presents a native IPv6 captured local bare, no brackets (GLA3)",
          "[udp][wildcard][srcip][getlocal][dualstack]")
{
  using iora::network::UdpEngineTestAccess;
  // Skip (not fail) on a host/container with IPv6 loopback disabled (disable_ipv6=1): a ::1 bind is
  // unavailable there though AF_INET6 :: sockets still work (cpp17 L-6 / sip L-5).
  {
    testnet::ScopedFd probe{::socket(AF_INET6, SOCK_DGRAM, 0)};
    sockaddr_in6 a{};
    a.sin6_family = AF_INET6;
    REQUIRE(::inet_pton(AF_INET6, "::1", &a.sin6_addr) == 1);
    if (probe.get() < 0 || ::bind(probe.get(), reinterpret_cast<sockaddr *>(&a), sizeof(a)) != 0)
    {
      WARN("IPv6 loopback (::1) unavailable on this host — skipping native-v6 getLocalAddress test");
      return;
    }
  }
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  auto lr = f.tx.addListener("::", port, TlsMode::None);
  REQUIRE(lr.isOk());

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV6Source("::1", pPort);
  sendV6ToDest(peer.get(), "::1", port, "g6");
  REQUIRE(f.waitFor(f.accepted));
  UdpEngineTestAccess::ioBarrier(f.tx);

  auto a = f.tx.getLocalAddress(f.serverSid);
  REQUIRE(a.host == "::1"); // bare, NO brackets (bracketing is the SIP serializer's job)
  REQUIRE(a.port == port);
  f.tx.stop();
}

TEST_CASE("UDP getLocalAddress/getListenerAddress unmap a v4-mapped specific bind; wildcard falls "
          "back (GLA4)",
          "[udp][wildcard][srcip][getlocal]")
{
  using iora::network::UdpEngineTestAccess;
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());

  // A MAPPED specific bind (loopback-resolvable): getListenerAddress presents it bare.
  auto port = testnet::getFreePortUDP();
  auto lr = f.tx.addListener("::ffff:127.0.0.1", port, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();
  REQUIRE(f.tx.getListenerAddress(lid).host == "127.0.0.1");

  // A specific bind leaves localSrc AF_UNSPEC (no capture), so getLocalAddress falls back to the
  // (unmapped) getsockname result — bare 127.0.0.1, with the bound port.
  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort);
  sendV4ToDest(peer.get(), "127.0.0.1", port, "gsp");
  REQUIRE(f.waitFor(f.accepted));
  UdpEngineTestAccess::ioBarrier(f.tx);
  auto a = f.tx.getLocalAddress(f.serverSid);
  REQUIRE(a.host == "127.0.0.1");
  REQUIRE(a.port == port);
  f.tx.stop();

  // ::ffff:0.0.0.0 is treated as a wildcard bind (engine) → getListenerAddress returns bare 0.0.0.0.
  // (An unadopted-via getLocalAddress on this mapped-wildcard would also return 0.0.0.0, but creating
  // that via needs connectViaListener-to-v4 on a dual-stack socket — the UNFIXED 2026-10-03-2 path;
  // the unadopted-via → wildcard fallback itself is covered by GLA5 on 0.0.0.0.)
  UdpFixture f2;
  REQUIRE(f2.tx.start().isOk());
  auto port2 = testnet::getFreePortUDP();
  auto lr2 = f2.tx.addListener("::ffff:0.0.0.0", port2, TlsMode::None);
  REQUIRE(lr2.isOk());
  REQUIRE(f2.tx.getListenerAddress(lr2.value()).host == "0.0.0.0");
  f2.tx.stop();
}

TEST_CASE("UDP getLocalAddress: unadopted via → wildcard, then captured local after adopt; unknown "
          "sid → empty (GLA5)",
          "[udp][wildcard][srcip][getlocal][via]")
{
  using iora::network::UdpEngineTestAccess;
  // 0.0.0.0 only: the via-adopt path uses connectViaListener to a v4 peer, and originating to a v4
  // peer on a dual-stack :: listener is the separate UNFIXED limitation iora 2026-10-03-2
  // (viaFromAddrs rejects the AF mismatch). The dual-stack CAPTURE-presents-bare half is covered by
  // GLA2 (inbound v4-mapped); the dual-stack via-adopt presentation becomes testable once
  // 2026-10-03-2 lands.
  const char *bind = "0.0.0.0";
  const std::string wildcardHost = "0.0.0.0";
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  auto lr = f.tx.addListener(bind, port, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort);
  auto rv = f.tx.connectViaListener(lid, "127.0.0.1", pPort);
  REQUIRE(rv.isOk());
  SessionId via = rv.value();
  REQUIRE(f.waitForCount(f.connectCount, 1));
  UdpEngineTestAccess::ioBarrier(f.tx);

  // Unadopted via: localSrc AF_UNSPEC → fallback to the wildcard (DP5: no pinned local). The
  // WILDCARD round-trip (sip M-B): a wildcard getter result re-maps to NO seed — localSrcText is
  // empty because localSrc stays AF_UNSPEC.
  REQUIRE(f.tx.getLocalAddress(via).host == wildcardHost);
  REQUIRE(UdpEngineTestAccess::localSrcText(f.tx, via).empty());

  // First unicast inbound adopts the via onto the (listener,local,peer) key → captured local,
  // presented bare even on the dual-stack bind.
  sendV4ToDest(peer.get(), "127.0.0.2", port, "adopt");
  REQUIRE(f.waitForCount(f.dataCount, 1));
  UdpEngineTestAccess::ioBarrier(f.tx);
  REQUIRE(f.sidForPayload("adopt") == via);
  auto a = f.tx.getLocalAddress(via);
  REQUIRE(a.host == "127.0.0.2");
  REQUIRE(a.port == port);

  // An unknown/reaped sid returns {} (empty host) — DP4 reaped-sid behavior.
  REQUIRE(f.tx.getLocalAddress(999999).host.empty());
  f.tx.stop();
}

TEST_CASE("UDP getLocalAddress is race-free vs adopt-time localSrc publication (GLA6, TSan)",
          "[udp][wildcard][srcip][getlocal][tsan]")
{
  using iora::network::UdpEngineTestAccess;
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  auto lr = f.tx.addListener("0.0.0.0", port, TlsMode::None);
  REQUIRE(lr.isOk());
  ListenerId lid = lr.value();

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort);
  auto rv = f.tx.connectViaListener(lid, "127.0.0.1", pPort);
  REQUIRE(rv.isOk());
  SessionId via = rv.value();
  REQUIRE(f.waitForCount(f.connectCount, 1));

  // A caller thread spins getLocalAddress(via) (bounded deadline + yield — never raise the deadline
  // to mask a failure; the yield avoids the reader-preferring shared_mutex starving the adopt
  // unique_lock) while the I/O thread adopts the via on the first inbound. MUTATION CHECK: removing
  // the unique_lock in adoptWildcardVia makes this a localSrc read/write data race TSan reports.
  std::atomic<bool> sawCaptured{false};
  std::atomic<bool> stop{false};
  std::thread reader(
    [&]()
    {
      auto deadline = std::chrono::steady_clock::now() + 3s;
      while (!stop.load(std::memory_order_relaxed) &&
             std::chrono::steady_clock::now() < deadline)
      {
        if (f.tx.getLocalAddress(via).host == "127.0.0.2")
        {
          sawCaptured.store(true, std::memory_order_relaxed);
          break;
        }
        std::this_thread::yield();
      }
    });

  sendV4ToDest(peer.get(), "127.0.0.2", port, "radopt");
  // Join on EVERY path BEFORE any REQUIRE that can throw: a throwing REQUIRE while `reader` is still
  // joinable would run ~thread() on a joinable thread → std::terminate, aborting the whole binary and
  // losing every other case's result. Capture the wait result, stop + join, THEN assert.
  const bool gotData = f.waitForCount(f.dataCount, 1);
  stop.store(true);
  reader.join();
  REQUIRE(gotData);
  REQUIRE(sawCaptured.load());
  f.tx.stop();
}

TEST_CASE("UDP getLocalAddress: value read in onData survives an idle reap; reaped sid → {} (GLA7, "
          "DP4)",
          "[udp][wildcard][srcip][getlocal][gc]")
{
  using iora::network::UdpEngineTestAccess;
  // Capture state declared BEFORE the fixture so the I/O thread (joined in ~UdpFixture) stops before
  // this state dies, even on a throwing-REQUIRE unwind path.
  std::mutex m;
  std::string capturedHost;
  std::uint16_t capturedPort = 0;
  std::atomic<bool> captured{false};

  TransportConfig cfg;
  cfg.idleTimeout = std::chrono::seconds(1);
  cfg.gcInterval = std::chrono::seconds(1);
  UdpFixture f{cfg};
  auto port = testnet::getFreePortUDP();
  // onDataHook runs on the I/O thread at request receipt: read getLocalAddress(sid) (shared_lock, no
  // deadlock — the engine fired onData after releasing _sessionRwMutex) and store a VALUE copy. DP4:
  // consumers capture HERE, not at response time.
  f.onDataHook = [&](SessionId sid)
  {
    auto a = f.tx.getLocalAddress(sid);
    std::lock_guard<std::mutex> g(m);
    capturedHost = a.host;
    capturedPort = a.port;
    captured.store(true);
  };
  REQUIRE(f.tx.start().isOk());
  auto lr = f.tx.addListener("0.0.0.0", port, TlsMode::None);
  REQUIRE(lr.isOk());

  std::uint16_t pPort = 0;
  testnet::ScopedFd peer = bindV4Source("127.0.0.1", pPort, 3000);
  sendV4ToDest(peer.get(), "127.0.0.2", port, "live");
  REQUIRE(f.waitFor(f.accepted));
  (void)recvV4Src(peer.get()); // drain the echo
  UdpEngineTestAccess::ioBarrier(f.tx);
  SessionId ss = f.serverSid;
  REQUIRE(captured.load());

  // The value read in onData is the captured local, bare and with the bound port.
  {
    std::lock_guard<std::mutex> g(m);
    REQUIRE(capturedHost == "127.0.0.2");
    REQUIRE(capturedPort == port);
  }

  // After the ServerPeer is idle-reaped, the reaped sid returns {} (DP4) — but the value captured in
  // onData still pins 127.0.0.2 (it is an independent copy, not a reference into the session).
  REQUIRE(f.waitForCount(f.closeCount, 1, 6000));
  UdpEngineTestAccess::ioBarrier(f.tx);
  REQUIRE(f.tx.getLocalAddress(ss).host.empty());
  {
    std::lock_guard<std::mutex> g(m);
    REQUIRE(capturedHost == "127.0.0.2");
  }
  f.tx.stop();
}

TEST_CASE("UDP classifyLocalSrc verdict table (synthesized cmsgs)", "[udp][wildcard][srcip][unit]")
{
  using iora::network::UdpEngineTestAccess;
  using Verdict = UdpEngineTestAccess::LocalSrcVerdict;

  // Owns a cmsg control buffer and exposes an msghdr for the pure classifier (M-5: multicast/
  // broadcast/link-local/v4-mapped cannot be driven over loopback root-free, so test the pure fn).
  struct CmsgRig
  {
    alignas(cmsghdr) std::uint8_t buf[512]{};
    msghdr msg{};
    CmsgRig()
    {
      msg.msg_control = buf;
      msg.msg_controllen = 0;
      msg.msg_flags = 0;
    }
    void addV4(const char *dst, const char *specDst)
    {
      auto *c = reinterpret_cast<cmsghdr *>(buf + msg.msg_controllen);
      c->cmsg_level = IPPROTO_IP;
      c->cmsg_type = IP_PKTINFO;
      c->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
      in_pktinfo pi{};
      REQUIRE(::inet_pton(AF_INET, dst, &pi.ipi_addr) == 1);
      REQUIRE(::inet_pton(AF_INET, specDst, &pi.ipi_spec_dst) == 1);
      std::memcpy(CMSG_DATA(c), &pi, sizeof(pi));
      msg.msg_controllen += CMSG_SPACE(sizeof(in_pktinfo));
    }
    void addV6(const char *addr)
    {
      auto *c = reinterpret_cast<cmsghdr *>(buf + msg.msg_controllen);
      c->cmsg_level = IPPROTO_IPV6;
      c->cmsg_type = IPV6_PKTINFO;
      c->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
      in6_pktinfo pi{};
      REQUIRE(::inet_pton(AF_INET6, addr, &pi.ipi6_addr) == 1);
      std::memcpy(CMSG_DATA(c), &pi, sizeof(pi));
      msg.msg_controllen += CMSG_SPACE(sizeof(in6_pktinfo));
    }
  };

  SECTION("v4 unicast → PINNED ipi_spec_dst")
  {
    CmsgRig r;
    r.addV4("127.0.0.2", "127.0.0.2");
    auto res = UdpEngineTestAccess::classifyLocalSrc(AF_INET, r.msg);
    REQUIRE(res.verdict == Verdict::PINNED);
    REQUIRE(res.src.family == AF_INET);
    in_addr want{};
    ::inet_pton(AF_INET, "127.0.0.2", &want);
    REQUIRE(res.src.addr.v4.s_addr == want.s_addr);
  }
  SECTION("v4 limited broadcast → UNPINNED_NON_UNICAST")
  {
    CmsgRig r;
    r.addV4("255.255.255.255", "127.0.0.2");
    REQUIRE(UdpEngineTestAccess::classifyLocalSrc(AF_INET, r.msg).verdict ==
            Verdict::UNPINNED_NON_UNICAST);
  }
  SECTION("v4 subnet-directed broadcast (ipi_addr != ipi_spec_dst) → UNPINNED_NON_UNICAST")
  {
    CmsgRig r;
    r.addV4("10.0.0.255", "10.0.0.7");
    REQUIRE(UdpEngineTestAccess::classifyLocalSrc(AF_INET, r.msg).verdict ==
            Verdict::UNPINNED_NON_UNICAST);
  }
  SECTION("v4 multicast → UNPINNED_NON_UNICAST")
  {
    CmsgRig r;
    r.addV4("224.0.1.75", "224.0.1.75");
    // test_matrix (j): an UNPINNED verdict also carries src.family == AF_UNSPEC — that is exactly
    // what routes getLocalAddress to the wildcard fallback (DP5) for a non-unicast arrival.
    auto res = UdpEngineTestAccess::classifyLocalSrc(AF_INET, r.msg);
    REQUIRE(res.verdict == Verdict::UNPINNED_NON_UNICAST);
    REQUIRE(res.src.family == AF_UNSPEC);
  }
  SECTION("v4 socket, no cmsg → DROP")
  {
    CmsgRig r;
    REQUIRE(UdpEngineTestAccess::classifyLocalSrc(AF_INET, r.msg).verdict == Verdict::DROP);
  }
  SECTION("MSG_CTRUNC → DROP")
  {
    CmsgRig r;
    r.addV4("127.0.0.2", "127.0.0.2");
    r.msg.msg_flags |= MSG_CTRUNC;
    REQUIRE(UdpEngineTestAccess::classifyLocalSrc(AF_INET, r.msg).verdict == Verdict::DROP);
  }
  SECTION("v4-mapped on v6 socket via IP_PKTINFO → PINNED v4-mapped (exact bytes)")
  {
    CmsgRig r;
    r.addV4("127.0.0.2", "127.0.0.2");
    auto res = UdpEngineTestAccess::classifyLocalSrc(AF_INET6, r.msg);
    REQUIRE(res.verdict == Verdict::PINNED);
    REQUIRE(res.src.family == AF_INET6);
    REQUIRE(IN6_IS_ADDR_V4MAPPED(&res.src.addr.v6));
    in6_addr want{};
    REQUIRE(::inet_pton(AF_INET6, "::ffff:127.0.0.2", &want) == 1);
    REQUIRE(std::memcmp(&res.src.addr.v6, &want, sizeof(want)) == 0);
  }
  SECTION("v6 socket, BOTH IP_PKTINFO + IPV6_PKTINFO present (real dual-stack v4 arrival) → "
          "PINNED from ipi_spec_dst, not the mapped ipi6_addr")
  {
    // The kernel delivers BOTH cmsgs for a v4 arrival on a dual-stack socket. The classifier must
    // take the IP_PKTINFO ipi_spec_dst, regardless of cmsg order.
    CmsgRig r;
    r.addV4("127.0.0.2", "127.0.0.2");
    r.addV6("::ffff:10.9.9.9"); // a (wrong) mapped header-dest that must be ignored
    auto res = UdpEngineTestAccess::classifyLocalSrc(AF_INET6, r.msg);
    REQUIRE(res.verdict == Verdict::PINNED);
    in6_addr want{};
    REQUIRE(::inet_pton(AF_INET6, "::ffff:127.0.0.2", &want) == 1);
    REQUIRE(std::memcmp(&res.src.addr.v6, &want, sizeof(want)) == 0);
  }
  SECTION("v6 socket, directed-broadcast IP_PKTINFO + mapped IPV6_PKTINFO → UNPINNED, no fallback")
  {
    CmsgRig r;
    r.addV4("10.0.0.255", "10.0.0.7"); // ipi_addr != ipi_spec_dst → non-unicast
    r.addV6("::ffff:10.0.0.255");
    REQUIRE(UdpEngineTestAccess::classifyLocalSrc(AF_INET6, r.msg).verdict ==
            Verdict::UNPINNED_NON_UNICAST);
  }
  SECTION("v4-mapped on v6 socket with ONLY IPV6_PKTINFO → DROP (no ipi6_addr fallback, LOW-2)")
  {
    CmsgRig r;
    r.addV6("::ffff:127.0.0.2");
    REQUIRE(UdpEngineTestAccess::classifyLocalSrc(AF_INET6, r.msg).verdict == Verdict::DROP);
  }
  SECTION("v6 socket, no cmsg → DROP")
  {
    CmsgRig r;
    REQUIRE(UdpEngineTestAccess::classifyLocalSrc(AF_INET6, r.msg).verdict == Verdict::DROP);
  }
  SECTION("native v6 unicast → PINNED ipi6_addr (exact bytes)")
  {
    CmsgRig r;
    r.addV6("2001:db8::1");
    auto res = UdpEngineTestAccess::classifyLocalSrc(AF_INET6, r.msg);
    REQUIRE(res.verdict == Verdict::PINNED);
    REQUIRE(res.src.family == AF_INET6);
    in6_addr want{};
    REQUIRE(::inet_pton(AF_INET6, "2001:db8::1", &want) == 1);
    REQUIRE(std::memcmp(&res.src.addr.v6, &want, sizeof(want)) == 0);
  }
  SECTION("v6 multicast → UNPINNED_NON_UNICAST")
  {
    CmsgRig r;
    r.addV6("ff02::1");
    // test_matrix (j): UNPINNED ⇒ src.family AF_UNSPEC ⇒ getLocalAddress wildcard fallback (DP5).
    auto res = UdpEngineTestAccess::classifyLocalSrc(AF_INET6, r.msg);
    REQUIRE(res.verdict == Verdict::UNPINNED_NON_UNICAST);
    REQUIRE(res.src.family == AF_UNSPEC);
  }
  // MUTATION-CHECK (1.12): swapping the v4-mapped PINNED branch to use ipi6_addr instead of
  // ipi_spec_dst makes the "BOTH present" and "directed-broadcast" sections fail — verified manually.
}

// L-8 (tracker 2026-09-25-16): the GC write-stall safety net must reclaim a wedged
// ServerPeer whose datagrams are stuck in the SHARED listener queue (it has no s->wq).
TEST_CASE("UDP GC write-stall reclaims a stalled ServerPeer", "[udp][backpressure][gc]")
{
  using iora::network::UdpEngineTestAccess;
  TransportConfig cfg;
  cfg.maxWriteQueue = 100;                          // don't close via backpressure
  cfg.closeOnBackpressure = false;
  cfg.writeStallTimeout = std::chrono::seconds(1);  // reclaim a stuck writer
  cfg.gcInterval = std::chrono::seconds(1);
  cfg.idleTimeout = std::chrono::seconds(0);        // isolate the write-stall path
  UdpFixture f{cfg};
  ListenerId lid = startWithListener(f).lid;
  auto peerPort = testnet::getFreePortUDP();
  auto r1 = f.tx.connectViaListener(lid, "127.0.0.1", peerPort);
  REQUIRE(r1.isOk());
  SessionId ss = r1.value();

  UdpEngineTestAccess::armForceEagain(f.tx, ss); // wedge: datagrams stick in lst->wq
  for (int i = 0; i < 3; ++i)
  {
    auto t = bpTag(i);
    REQUIRE(f.tx.send(ss, t.data(), t.size()));
  }
  REQUIRE(UdpEngineTestAccess::listenerQueuedForSid(f.tx, lid, ss) >= 1);
  // The write-stall GC should close the wedged ServerPeer within a couple of gc cycles.
  REQUIRE(f.waitFor(f.anyClosed, 6000));
  REQUIRE(f.lastClose().first == TransportError::GCClosed); // intended reason (F-10)
  REQUIRE_FALSE(UdpEngineTestAccess::hasSession(f.tx, ss));
  UdpEngineTestAccess::disarmForceEagain(f.tx);
  f.tx.stop();
}

// M-1 (tracker 2026-09-25-16, steps-4-8 round 2): the L-8 redesign must reclaim ONLY the
// owner of the front datagram, never a healthy peer queued behind it. Two via sessions share
// the listener queue: ss1 is wedged at the front (seam), ss2 is queued behind (M-5). The GC
// must close ss1 only; ss2 survives and, once ss1 is purged, drains. The OLD per-peer scan
// would close BOTH, so this test discriminates the redesign.
TEST_CASE("UDP GC write-stall reclaims only the front owner, not a peer behind it",
          "[udp][backpressure][gc]")
{
  using iora::network::UdpEngineTestAccess;
  TransportConfig cfg;
  cfg.maxWriteQueue = 100; // don't close via backpressure
  cfg.closeOnBackpressure = false;
  cfg.writeStallTimeout = std::chrono::seconds(1);
  cfg.gcInterval = std::chrono::seconds(1);
  cfg.idleTimeout = std::chrono::seconds(0);
  UdpFixture f{cfg};
  ListenerId lid = startWithListener(f).lid;
  RecordingPeer peer;
  REQUIRE(peer.tx.start().isOk());
  auto peerPort = testnet::getFreePortUDP();
  REQUIRE(peer.tx.addListener("127.0.0.1", peerPort, TlsMode::None).isOk());
  auto twins = twinVias(f, lid, peerPort);
  SessionId ss1 = twins.first;
  SessionId ss2 = twins.second;

  UdpEngineTestAccess::armForceEagain(f.tx, ss1); // ss1 wedged at the front
  auto s1 = bpTag(1);
  REQUIRE(f.tx.send(ss1, s1.data(), s1.size())); // front, held
  auto s2 = bpTag(2);
  REQUIRE(f.tx.send(ss2, s2.data(), s2.size())); // queued behind (M-5), NOT armed
  REQUIRE(UdpEngineTestAccess::listenerQueuedForSid(f.tx, lid, ss2) == 1);

  // GC reclaims the FRONT owner (ss1) only. The old per-peer scan would close ss2 too.
  REQUIRE(f.waitFor(f.anyClosed, 6000));
  REQUIRE(f.lastClose().first == TransportError::GCClosed);
  REQUIRE_FALSE(UdpEngineTestAccess::hasSession(f.tx, ss1));
  // ss2 survives and its datagram drains (ss1 purged -> ss2 at front, unheld).
  REQUIRE(f.waitUntil([&] { return !peer.snapshot().empty(); }, 3000));
  REQUIRE(UdpEngineTestAccess::hasSession(f.tx, ss2));
  auto got = peer.snapshot();
  REQUIRE(std::find(got.begin(), got.end(), s2) != got.end()); // ss2 delivered
  REQUIRE(std::find(got.begin(), got.end(), s1) == got.end()); // ss1 never sent (purged)
  UdpEngineTestAccess::disarmForceEagain(f.tx);
  f.tx.stop();
}

// F-2 (tracker 2026-09-25-16): the client-path M-5 "queue behind a non-empty queue" rule is
// discriminating. Arm the seam and queue A,B; then disarm and send C in ONE I/O-thread step
// (no EPOLLOUT drain between), so C must land behind A,B. Without M-5, C's direct ::send
// overtakes the still-queued A,B and the peer sees C,A,B.
TEST_CASE("UDP client send preserves FIFO past a non-empty queue (M-5)",
          "[udp][backpressure][ordering]")
{
  using iora::network::UdpEngineTestAccess;
  TransportConfig cfg;
  cfg.maxWriteQueue = 100; // no overflow; this is an ordering test
  cfg.closeOnBackpressure = false;
  UdpFixture f{cfg};
  RecordingPeer peer;
  SessionId cs = connectToPeer(f, peer);

  UdpEngineTestAccess::armForceEagain(f.tx, cs);
  auto a = bpTag(1);
  auto b = bpTag(2);
  REQUIRE(f.tx.send(cs, a.data(), a.size())); // queued (held), front
  REQUIRE(f.tx.send(cs, b.data(), b.size())); // queued behind
  REQUIRE(UdpEngineTestAccess::sessionQueueSize(f.tx, cs) == 2);

  auto c = bpTag(3);
  UdpEngineTestAccess::disarmThenSend(f.tx, cs, c); // disarm + send C atomically on the I/O thread

  REQUIRE(f.waitUntil([&] { return peer.snapshot().size() >= 3; }, 2000));
  auto got = peer.snapshot();
  REQUIRE(got.size() == 3);
  REQUIRE(got[0] == a);
  REQUIRE(got[1] == b);
  REQUIRE(got[2] == c);
  f.tx.stop();
}

// F-3 (tracker 2026-09-25-16): the OVERFLOW-close variant of the sibling case. Overflow and
// close ss1 via backpressure; its sibling ss2 (same peer address) must survive AND remain
// deliverable (routability), verified by positive delivery to a RecordingPeer (no drain race:
// ss1's held front blocks the queue until the close purges ss1, after which ss2 drains).
TEST_CASE("UDP listener backpressure overflow close spares and still delivers a sibling",
          "[udp][backpressure][sibling]")
{
  using iora::network::UdpEngineTestAccess;
  constexpr std::size_t kMaxQ = 5;
  TransportConfig cfg;
  cfg.maxWriteQueue = kMaxQ;
  cfg.closeOnBackpressure = true;
  UdpFixture f{cfg};
  ListenerId lid = startWithListener(f).lid;
  RecordingPeer peer; // real receiver so ss2 delivery is observable
  REQUIRE(peer.tx.start().isOk());
  auto peerPort = testnet::getFreePortUDP();
  REQUIRE(peer.tx.addListener("127.0.0.1", peerPort, TlsMode::None).isOk());
  auto twins = twinVias(f, lid, peerPort);
  SessionId ss1 = twins.first;
  SessionId ss2 = twins.second;

  UdpEngineTestAccess::armForceEagain(f.tx, ss1); // ss1 held at the front -> no drain race
  auto s1front = bpTag(10);
  REQUIRE(f.tx.send(ss1, s1front.data(), s1front.size())); // queued (ss1, front, held)
  auto s2tag = bpTag(20);
  REQUIRE(f.tx.send(ss2, s2tag.data(), s2tag.size())); // queued behind (ss2)
  for (int i = 0; i < static_cast<int>(kMaxQ); ++i)
  {
    auto t = bpTag(11 + i);
    (void)f.tx.send(ss1, t.data(), t.size()); // pushes the shared queue over -> close ss1
  }

  REQUIRE(f.waitForStats([](const auto &s) { return s.backpressureCloses >= 1; }, 2000));
  REQUIRE(f.waitFor(f.anyClosed));
  REQUIRE(f.lastClose().first == TransportError::WriteBackpressure);
  REQUIRE_FALSE(UdpEngineTestAccess::hasSession(f.tx, ss1)); // ss1 closed
  REQUIRE(UdpEngineTestAccess::hasSession(f.tx, ss2));       // ss2 survives
  // ss2's datagram, queued behind ss1's purged front, now drains and reaches the peer;
  // none of ss1's datagrams were ever sent (held then purged on close).
  REQUIRE(f.waitUntil([&] { return !peer.snapshot().empty(); }, 2000));
  auto got = peer.snapshot();
  REQUIRE(std::find(got.begin(), got.end(), s2tag) != got.end()); // ss2 delivered (routable)
  REQUIRE(std::find(got.begin(), got.end(), s1front) == got.end()); // ss1 never sent
  f.tx.stop();
}

TEST_CASE("UDP IPv6 support", "[udp][ipv6]")
{
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());

  auto port = testnet::getFreePortUDP();

  // Try IPv6 loopback
  auto lr6 = f.tx.addListener("::1", port, TlsMode::None);

  if (lr6.isOk()) // Only if IPv6 is available
  {
    auto cr6 = f.tx.connect("::1", port, TlsMode::None);
    REQUIRE(cr6.isOk());
    SessionId cs = cr6.value();

    REQUIRE(f.waitFor(f.connected));

    const char *msg = "ipv6_test";
    REQUIRE(f.tx.send(cs, msg, std::strlen(msg)));

    REQUIRE(f.waitFor(f.accepted));
    REQUIRE(f.waitFor(f.clientGotEcho));
    REQUIRE_FALSE(f.sendFailed); // server-side echo send succeeded (recorded off-thread)
    REQUIRE(f.lastData == msg);
  }

  f.tx.stop();
}

TEST_CASE("UDP large data transfer", "[udp][large]")
{
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();

  (void)f.tx.addListener("127.0.0.1", port, TlsMode::None);
  SessionId cs = f.tx.connect("127.0.0.1", port, TlsMode::None).value();

  REQUIRE(f.waitFor(f.connected));

  // Send a message near UDP MTU limit (typically ~1500 bytes for Ethernet)
  std::string largeMsg(1400, 'A');
  largeMsg[0] = 'S';
  largeMsg[largeMsg.size() - 1] = 'E';

  REQUIRE(f.tx.send(cs, largeMsg.data(), largeMsg.size()));

  REQUIRE(f.waitFor(f.accepted));
  REQUIRE(f.waitFor(f.clientGotEcho));
  REQUIRE_FALSE(f.sendFailed); // server-side echo send succeeded (recorded off-thread)
  REQUIRE(f.lastData == largeMsg);

  // Verify integrity
  REQUIRE(f.lastData.size() == largeMsg.size());
  REQUIRE(f.lastData[0] == 'S');
  REQUIRE(f.lastData[f.lastData.size() - 1] == 'E');

  f.tx.stop();
}

TEST_CASE("UDP multiple listeners", "[udp][multi-listener]")
{
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());

  auto port1 = testnet::getFreePortUDP();
  auto port2 = testnet::getFreePortUDP();
  auto port3 = testnet::getFreePortUDP();

  auto lr1 = f.tx.addListener("127.0.0.1", port1, TlsMode::None);
  auto lr2 = f.tx.addListener("127.0.0.1", port2, TlsMode::None);
  auto lr3 = f.tx.addListener("127.0.0.1", port3, TlsMode::None);
  REQUIRE(lr1.isOk());
  REQUIRE(lr2.isOk());
  REQUIRE(lr3.isOk());
  REQUIRE(lr1.value() != lr2.value());
  REQUIRE(lr2.value() != lr3.value());

  // Connect to each listener
  auto cr1 = f.tx.connect("127.0.0.1", port1, TlsMode::None);
  auto cr2 = f.tx.connect("127.0.0.1", port2, TlsMode::None);
  auto cr3 = f.tx.connect("127.0.0.1", port3, TlsMode::None);
  REQUIRE(cr1.isOk());
  REQUIRE(cr2.isOk());
  REQUIRE(cr3.isOk());
  SessionId cs1 = cr1.value();
  SessionId cs2 = cr2.value();
  SessionId cs3 = cr3.value();

  REQUIRE(f.waitForCount(f.connectCount, 3));

  // Send to each
  REQUIRE(f.tx.send(cs1, "msg1", 4));
  REQUIRE(f.tx.send(cs2, "msg2", 4));
  REQUIRE(f.tx.send(cs3, "msg3", 4));

  REQUIRE(f.waitForCount(f.acceptCount, 3));

  auto stats = f.tx.getStats();
  REQUIRE(stats.accepted == 3);
  REQUIRE(stats.connected == 3);

  // The echo send runs later in onData than the counter waited on above, so give
  // the I/O thread time to execute it before reading sendFailed.
  std::this_thread::sleep_for(100ms);
  REQUIRE_FALSE(f.sendFailed); // server-side echo send succeeded (recorded off-thread)
  f.tx.stop();
}

TEST_CASE("UDP edge vs level triggered", "[udp][epoll]")
{
  SECTION("edge triggered (default)")
  {
    // useEdgeTriggered=true == default: this section is a smoke check that
    // duplicates the default-config echo tests. epoll trigger mode has no getStats
    // observable, so it is asserted only via functional echo (tracker 2026-09-13-6,
    // cpp17-F4).
    TransportConfig cfg;
    cfg.useEdgeTriggered = true;
    UdpFixture f{cfg};
    REQUIRE(f.tx.start().isOk());

    auto port = testnet::getFreePortUDP();
    (void)f.tx.addListener("127.0.0.1", port, TlsMode::None);
    SessionId cs = f.tx.connect("127.0.0.1", port, TlsMode::None).value();

    REQUIRE(f.waitFor(f.connected));

    const char *msg = "edge_test";
    REQUIRE(f.tx.send(cs, msg, std::strlen(msg)));
    REQUIRE(f.waitFor(f.clientGotEcho));
    REQUIRE_FALSE(f.sendFailed); // server-side echo send succeeded (recorded off-thread)
    REQUIRE(f.lastData == msg);

    f.tx.stop();
  }

  SECTION("level triggered")
  {
    // Config now reaches the engine (tracker 2026-09-13-6): this genuinely exercises
    // the LEVEL-triggered epoll path (previously it ran the default edge path, so
    // the level path was never tested). No stat observable for epoll mode — asserted
    // via functional echo only (cpp17-F4).
    TransportConfig cfg;
    cfg.useEdgeTriggered = false;
    UdpFixture f{cfg};
    REQUIRE(f.tx.start().isOk());

    auto port = testnet::getFreePortUDP();
    (void)f.tx.addListener("127.0.0.1", port, TlsMode::None);
    SessionId cs = f.tx.connect("127.0.0.1", port, TlsMode::None).value();

    REQUIRE(f.waitFor(f.connected));

    const char *msg = "level_test";
    REQUIRE(f.tx.send(cs, msg, std::strlen(msg)));
    REQUIRE(f.waitFor(f.clientGotEcho));
    REQUIRE_FALSE(f.sendFailed); // server-side echo send succeeded (recorded off-thread)
    REQUIRE(f.lastData == msg);

    f.tx.stop();
  }
}

TEST_CASE("UDP connect() session cap rejection", "[udp][limits]")
{
  // tracker 2026-09-14-1: the plain client connect() path now enforces maxSessions.
  // Previously only inbound server-peer creation and connectViaListener were capped;
  // plain connect() bumped the session count with no check (the production asymmetry).
  TransportConfig cfg;
  cfg.maxSessions = 2;
  UdpFixture f{cfg};
  REQUIRE(f.tx.start().isOk());

  auto port = testnet::getFreePortUDP();
  (void)f.tx.addListener("127.0.0.1", port, TlsMode::None);

  // Fill to the cap with 2 client connects (no sends -> no server peers created).
  for (int i = 0; i < 2; ++i)
  {
    REQUIRE(f.tx.connect("127.0.0.1", port, TlsMode::None).isOk());
  }
  REQUIRE(f.waitForCount(f.connectCount, 2));
  REQUIRE(f.tx.getStats().sessionsCurrent == 2); // at cap

  // A 3rd connect() is admission-rejected. connect() returns ok(sid) SYNCHRONOUSLY
  // (the sid is allocated + the request enqueued before the async cap check runs on
  // the I/O thread), so the rejection is observed via onClose, NOT the ConnectResult.
  auto third = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(third.isOk()); // sid allocated synchronously; admission decided async

  // The async cap check (connectFromAddrs guard) fires onClose(ResourceLimit).
  REQUIRE(f.waitForCount(f.closeCount, 1));
  auto lastClose = f.lastClose();
  CHECK(lastClose.first == TransportError::ResourceLimit);
  CHECK(lastClose.second.find("session cap reached") != std::string::npos);

  // No 3rd session materialized: onConnect never fired for it and the aggregate stays
  // at the cap. CONFIG-DISCRIMINATING mutation-check: reverting the connectFromAddrs
  // guard makes the 3rd connect succeed (connectCount -> 3, sessionsCurrent -> 3), so
  // both assertions below fail on revert -> they genuinely exercise the cap.
  CHECK_FALSE(f.waitForCount(f.connectCount, 3, 500));
  CHECK(f.tx.getStats().sessionsCurrent == 2);

  f.tx.stop();
}

TEST_CASE("UDP inbound server-peer drop at session cap", "[udp][limits]")
{
  // Retains coverage of the inbound listener-read server-peer cap drop
  // (udp_engine.hpp ~:1334 `continue`), which the old 'UDP session limits' test
  // exercised via a 3rd client's datagram — no longer possible now that a 3rd
  // connect() is rejected. tracker 2026-09-14-1 cpp17-R2 N1.
  TransportConfig cfg;
  cfg.maxSessions = 3;
  UdpFixture f{cfg};
  REQUIRE(f.tx.start().isOk());

  auto port = testnet::getFreePortUDP();
  (void)f.tx.addListener("127.0.0.1", port, TlsMode::None);

  // Client 1 connects and sends -> the server creates exactly 1 server peer.
  auto c1 = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(c1.isOk());
  REQUIRE(f.waitForCount(f.connectCount, 1));
  REQUIRE(f.tx.send(c1.value(), "one", 3));
  REQUIRE(f.waitForCount(f.acceptCount, 1));     // 1 server peer created
  REQUIRE(f.tx.getStats().sessionsCurrent == 2); // 1 client + 1 server peer

  // Client 2 connects (sessionsCurrent -> 3, at cap), then sends. Its inbound
  // datagram is from a NEW peer address, so the server tries to create a 2nd server
  // peer -> at cap (3 >= 3) it hits the :1334 drop (`continue`): NO 2nd onAccept.
  auto c2 = f.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(c2.isOk());
  REQUIRE(f.waitForCount(f.connectCount, 2));
  REQUIRE(f.tx.getStats().sessionsCurrent == 3); // at cap
  REQUIRE(f.tx.send(c2.value(), "two", 3));

  // CONFIG-DISCRIMINATING: the 2nd server peer is dropped by the cap. Under reverted
  // (default maxSessions=0) config the datagram WOULD create a 2nd server peer
  // (acceptCount -> 2, sessionsCurrent -> 4), so this pair fails-on-revert.
  CHECK_FALSE(f.waitForCount(f.acceptCount, 2, 500)); // no 2nd server peer
  CHECK(f.tx.getStats().sessionsCurrent == 3);        // cap held

  f.tx.stop();
}

TEST_CASE("UDP socket buffer configuration", "[udp][socket]")
{
  // Config now reaches the engine (tracker 2026-09-13-6): soRcvBuf/soSndBuf are
  // applied via setsockopt (udp_engine.hpp:1256-1259,1587-1590), exercising the
  // soRcvBuf/soSndBuf>0 branches that were dead before (default 0). NOTE: the buffer
  // sizes have NO test observable — getStats reports no socket-buffer field and this
  // test has no fd handle to getsockopt — so the effect is UNVERIFIED here; the test
  // asserts only that the socket functions correctly with non-default buffers
  // (cpp17-F3; human disposition 2026-09-14: scope honestly, no backlog).
  TransportConfig cfg;
  cfg.soRcvBuf = 256 * 1024;
  cfg.soSndBuf = 256 * 1024;
  UdpFixture f{cfg};
  REQUIRE(f.tx.start().isOk());

  auto port = testnet::getFreePortUDP();
  (void)f.tx.addListener("127.0.0.1", port, TlsMode::None);
  SessionId cs = f.tx.connect("127.0.0.1", port, TlsMode::None).value();

  REQUIRE(f.waitFor(f.connected));

  // Verify it works with configured buffers
  const char *msg = "buffer_test";
  REQUIRE(f.tx.send(cs, msg, std::strlen(msg)));
  REQUIRE(f.waitFor(f.clientGotEcho));
  REQUIRE_FALSE(f.sendFailed); // server-side echo send succeeded (recorded off-thread)
  REQUIRE(f.lastData == msg);

  f.tx.stop();
}

TEST_CASE("UDP self-loopback via listener", "[udp][loopback][via]")
{
  // This tests the critical scenario where an application sends data
  // to itself via the listener (e.g., SIP proxy routing to itself).
  // The packet is sent from listener:port TO listener:port.
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();

  auto lrSelf = f.tx.addListener("127.0.0.1", port, TlsMode::None);
  REQUIRE(lrSelf.isOk());
  ListenerId lid = lrSelf.value();

  // Connect via the listener TO THE SAME listener address (self-loopback)
  SessionId cs = f.tx.connectViaListener(lid, "127.0.0.1", port).value();
  REQUIRE(f.waitFor(f.connected));

  // Send to self
  const char *msg = "self_loopback_test";
  REQUIRE(f.tx.send(cs, msg, std::strlen(msg)));

  // Data should arrive on the listener
  REQUIRE(f.waitForCount(f.dataCount, 1, 2000));

  // Verify we received the data
  {
    std::lock_guard<std::mutex> lock(f.dataMutex);
    REQUIRE(f.receivedData.size() >= 1);
    REQUIRE(f.receivedData[0] == msg);
  }

  // The echo send runs later in onData than the dataCount wait above, so give the
  // I/O thread time to execute it before reading sendFailed.
  std::this_thread::sleep_for(100ms);
  REQUIRE_FALSE(f.sendFailed); // server-side echo send succeeded (recorded off-thread)
  f.tx.stop();
}

TEST_CASE("UDP multiple sessions to same peer", "[udp][loopback][multi]")
{
  // Test that multiple SessionIds can connect to the same peer.
  // This is important for protocols that use multiple logical connections
  // to the same remote address (e.g., SIP dialogs).
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port1 = testnet::getFreePortUDP();
  auto port2 = testnet::getFreePortUDP();

  // Set up a server. Declare tx2 AFTER the locals its onData captures, so tx2 is
  // destroyed (and its I/O thread joined) before they die — teardown-UAF guard,
  // as in ~UdpFixture (the trailing tx2.stop() is skipped if a REQUIRE throws).
  TransportConfig cfg2{};
  std::atomic<int> server2DataCount{0};
  std::mutex server2Mutex;
  std::vector<std::string> server2Data;
  UdpEngine tx2{cfg2};
  iora::network::detail::EngineBase::Callbacks cbs2{};
  cbs2.onData = [&](SessionId, iora::core::BufferView bv,
                    std::chrono::steady_clock::time_point)
  {
    std::lock_guard<std::mutex> lock(server2Mutex);
    server2Data.push_back(std::string(reinterpret_cast<const char *>(bv.data()), bv.size()));
    server2DataCount++;
  };
  tx2.setCallbacks(std::move(cbs2));

  REQUIRE(tx2.start().isOk());
  REQUIRE(tx2.addListener("127.0.0.1", port2, TlsMode::None).isOk());

  // Create a listener to connect via
  auto lrMulti = f.tx.addListener("127.0.0.1", port1, TlsMode::None);
  REQUIRE(lrMulti.isOk());
  ListenerId lid1 = lrMulti.value();

  // Connect via the first listener to the server - multiple times
  SessionId cs1 = f.tx.connectViaListener(lid1, "127.0.0.1", port2).value();
  REQUIRE(f.waitFor(f.connected));

  // Reset and connect again (same peer, different SessionId)
  f.connected = false;
  SessionId cs2 = f.tx.connectViaListener(lid1, "127.0.0.1", port2).value();
  REQUIRE(cs2 != cs1); // Different SessionId
  REQUIRE(f.waitFor(f.connected));

  f.connected = false;
  SessionId cs3 = f.tx.connectViaListener(lid1, "127.0.0.1", port2).value();
  REQUIRE(cs3 != cs1);
  REQUIRE(cs3 != cs2);
  REQUIRE(f.waitFor(f.connected));

  // Send from each session
  REQUIRE(f.tx.send(cs1, "msg1", 4));
  REQUIRE(f.tx.send(cs2, "msg2", 4));
  REQUIRE(f.tx.send(cs3, "msg3", 4));

  // Wait for server to receive all 3 messages
  for (int i = 0; i < 200 && server2DataCount.load() < 3; ++i)
  {
    std::this_thread::sleep_for(5ms);
  }
  REQUIRE(server2DataCount.load() == 3);

  // Verify all messages received
  {
    std::lock_guard<std::mutex> lock(server2Mutex);
    std::sort(server2Data.begin(), server2Data.end());
    REQUIRE(server2Data.size() == 3);
    REQUIRE(server2Data[0] == "msg1");
    REQUIRE(server2Data[1] == "msg2");
    REQUIRE(server2Data[2] == "msg3");
  }

  REQUIRE_FALSE(f.sendFailed); // server-side echo send succeeded (recorded off-thread)
  f.tx.stop();
  tx2.stop();
}