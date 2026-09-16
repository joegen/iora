#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "iora/network/detail/udp_engine.hpp"
#include "iora_test_net_utils.hpp"
#include "test_helpers.hpp"

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
  // construction (udp_engine.hpp:58 `_config(config)`), so mutate cfg ONLY before
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
      dataCount++;
      auto *data = bv.data();
      auto n = bv.size();
      // Echo on server; detect on client. This runs on the engine I/O thread —
      // no Catch2 macro here (issue #99): record a failed send for the main
      // thread to assert.
      if (std::find(acceptedSessions.begin(), acceptedSessions.end(), sid) !=
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
        receivedData.push_back(std::string(reinterpret_cast<const char *>(data), n));
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
  // path (phase-4). "localhost" resolves via /etc/hosts, no network dependency.
  UdpFixture f;
  REQUIRE(f.tx.start().isOk());
  auto port = testnet::getFreePortUDP();
  REQUIRE(f.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

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

TEST_CASE("UDP backpressure handling", "[udp][backpressure]")
{
  // Config now reaches the engine (tracker 2026-09-13-6). Drive deterministic
  // backpressure: a non-echoing peer + a shrunk client soSndBuf (4096, host-
  // independent EAGAIN) + a large-volume burst forces the client ::send to EAGAIN,
  // growing the write queue past maxWriteQueue -> backpressureCloses++ (udp_engine
  // .hpp:1930-1935). closeOnBackpressure then decides the ACTION: close the session
  // (true, :1935) or drop the oldest queued datagram and keep it open (false, :1940).
  //
  // NOTE on non-vacuity: backpressureCloses>=1 is VOLUME-driven — it fires under any
  // config given this burst — so it verifies only that the mechanism ran, NOT that
  // config reached the engine. The config-DISCRIMINATING observable is the ACTION
  // (anyClosed): the closeOnBackpressure=false section below asserts the session
  // SURVIVES, which fails if the value is reverted to the default (true). soSndBuf
  // and maxWriteQueue are determinism aids, not discriminators (loopback backpressure
  // is inherently volume-driven; cpp17-F6/L1).

  // Shared driver: stand up a non-echoing server, connect the fixture's client to it,
  // burst datagrams, and confirm the backpressure mechanism fired. tx2's callbacks
  // capture nothing, so its teardown (stop()+join here) is order-independent.
  auto drive = [](UdpFixture &f)
  {
    REQUIRE(f.tx.start().isOk());
    TransportConfig cfg2{};
    UdpEngine tx2{cfg2};
    iora::network::detail::EngineBase::Callbacks cbs2{};
    cbs2.onData = [](SessionId, iora::core::BufferView,
                     std::chrono::steady_clock::time_point) { /* receive, don't echo */ };
    tx2.setCallbacks(std::move(cbs2));
    REQUIRE(tx2.start().isOk());
    auto port2 = testnet::getFreePortUDP();
    (void)tx2.addListener("127.0.0.1", port2, TlsMode::None);

    SessionId cs = f.tx.connect("127.0.0.1", port2, TlsMode::None).value();
    REQUIRE(f.waitFor(f.connected));

    std::string bigMsg(4000, 'X');
    for (int i = 0; i < 2000; ++i)
    {
      f.tx.send(cs, bigMsg.data(), bigMsg.size());
    }
    REQUIRE(f.waitForStats([](const auto &s) { return s.backpressureCloses >= 1; }, 3000));
    tx2.stop(); // join tx2's I/O thread before it leaves scope
  };

  SECTION("closeOnBackpressure=true closes the session")
  {
    // Covers the close action (udp_engine.hpp:1935). NOT config-discriminating on its
    // own (true == default), but exercises the close path under real backpressure.
    TransportConfig cfg;
    cfg.maxWriteQueue = 5;
    cfg.closeOnBackpressure = true;
    cfg.soSndBuf = 4096;
    UdpFixture f{cfg};
    drive(f);
    REQUIRE(f.waitFor(f.anyClosed)); // backpressure closed the session
    f.tx.stop();
  }

  SECTION("closeOnBackpressure=false keeps the session (drop-oldest)")
  {
    // NON-default value -> drop-oldest path (udp_engine.hpp:1940); the session must
    // SURVIVE backpressure. This is the CONFIG-DISCRIMINATING assertion: reverting
    // closeOnBackpressure to the default (true) closes the session -> REQUIRE_FALSE
    // below fails. Also covers the previously-untested drop-oldest branch (cpp17-L4).
    TransportConfig cfg;
    cfg.maxWriteQueue = 5;
    cfg.closeOnBackpressure = false;
    cfg.soSndBuf = 4096;
    UdpFixture f{cfg};
    drive(f);
    std::this_thread::sleep_for(100ms); // allow any (erroneous) close to surface
    REQUIRE_FALSE(f.anyClosed);         // drop-oldest kept the session open
    f.tx.stop();
  }
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