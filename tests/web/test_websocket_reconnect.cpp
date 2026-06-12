// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Real-socket integration tests for the WebSocketClient reconnect worker — the
// S-3 phase-2 F-1 / H-1 regression guard. Tracker:
// 2026-06-11-4 (transport-shared-ownership phase 2); architecture:
// transport_shared_ownership.json, component "WebSocketClient reconnect worker
// (F-1 fix)".
//
// Exercises the single CV-driven reconnect worker end-to-end over a live
// WebSocketServer + WebSocketClient:
//   (a) F-1 deadlock — a reconnect in-flight (blocked in Transport::stop()) while
//       a fresh transport-level disconnect fires on that transport's I/O thread
//       and the I/O thread join()s the reconnect thread (pre-fix: deadlock).
//   (b) disconnect()-from-onClose — the client's WS-close callback calls
//       client.disconnect(); the teardown guard must keep it off the I/O-thread
//       worker-join (pre-fix: relocated deadlock / stop()-on-I/O-thread throw).
//   (c) reconnect-success — a transport-level drop is followed by an automatic
//       reconnect to the same live server within a bound.
//   (d) concurrent-send-during-reconnect — sendText() racing repeated
//       disconnect/reconnect under ASan + watchdog (member-sync H-1-NEW / M-5).
//   (e) connect-after-disconnect-from-callback lifecycle — connect (autoReconnect)
//       -> disconnect()-from-onClose (skips the join) -> connect() again on the
//       main thread; auto-reconnect must still function (reap-then-respawn).
//
// NOTE (supersedes the "no Catch2" note in tests/transport/transport_teardown_harness.cpp:6-9):
// per the architecture testStrategy these reconnect/teardown scenarios ARE covered
// by Catch2 web tests with bounded watchdogs, not only the standalone harness.
//
// Every scenario that could deadlock runs inside completesWithin(): the body runs
// on a worker thread that is DETACHED (intentionally leaked) on timeout, so a
// genuine deadlock reports a clean test failure instead of wedging the binary. The
// body is self-contained (owns its server + client; captures only heap/shared
// state) so a leaked-on-timeout body never dangles into the test's stack.
//
// ASan substitutes for TSan here (TSan is unavailable — the ASLR personality is
// blocked in this environment). ASan + the stress loops + the watchdog are a
// best-effort data-race probe; they do NOT PROVE race-freedom. Correctness rests
// on the _transportMutex copy-then-invoke discipline and the control-block (A')
// safety gate (block-only predicate, clientAlive-first) applied exactly.
//
// ctest runs -j1 (web tests bind fixed loopback ports).

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <iora/network/websocket_client.hpp>
#include <iora/network/websocket_server.hpp>

using iora::network::SessionId;
using iora::network::WebSocketClient;
using iora::network::WebSocketServer;
using iora::network::WebSocketState;

namespace
{

std::atomic<int> g_nextPort{19400};
int nextPort() { return g_nextPort.fetch_add(1); }

template <typename Pred> bool waitFor(Pred pred, int timeoutMs = 5000)
{
  auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
  while (!pred())
  {
    if (std::chrono::steady_clock::now() > deadline)
    {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return true;
}

// Runs `fn` and returns true iff it completed within timeoutMs. On timeout the
// worker thread is DETACHED — a genuine deadlock then surfaces as a clean test
// failure (this returns false) rather than wedging the whole binary. `fn` MUST be
// self-contained: on the timeout path it keeps running after this returns, so it
// may capture only by value / heap / shared state, never the caller's stack.
bool completesWithin(std::function<void()> fn, int timeoutMs)
{
  auto done = std::make_shared<std::atomic<bool>>(false);
  std::thread t(
    [fn, done]()
    {
      // A throw counts as "did not hang": the watchdog detects hangs, not
      // exceptions. (An uncaught throw on a library I/O thread is a separate,
      // process-level failure the binary will surface on its own.)
      try
      {
        fn();
      }
      catch (...)
      {
      }
      done->store(true);
    });
  bool ok = waitFor([&]() { return done->load(); }, timeoutMs);
  if (ok)
  {
    t.join();
  }
  else
  {
    t.detach(); // intentional leak: the body is wedged; let the binary report.
  }
  return ok;
}

// Exposes the protected TCP-level closeSession() so a test can drop a session at
// the transport layer (FIN) — distinct from a graceful WS CLOSE frame.
class TestWsServer : public WebSocketServer
{
public:
  using WebSocketServer::WebSocketServer;
  void dropSession(SessionId s) { closeSession(s); }
};

// Spins up a live loopback WebSocketServer and tracks connect/close counts.
struct WsTestServer
{
  TestWsServer server;
  int port;
  std::atomic<SessionId> lastSid{0};
  std::atomic<int> connectCount{0};

  explicit WsTestServer(int p) : server("127.0.0.1", p), port(p)
  {
    server.setOnConnect(
      [this](SessionId s, const std::string &)
      {
        lastSid.store(s);
        connectCount.fetch_add(1);
      });
    server.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
  }

  ~WsTestServer() { server.stop(); }

  // TCP-level drop of a session (FIN) — the client sees a transport-level
  // disconnect (NOT a graceful WS CLOSE), driving handleDisconnect ->
  // reconnect.
  void dropLast()
  {
    SessionId s = lastSid.load();
    if (s != 0)
    {
      server.dropSession(s);
    }
  }
};

WebSocketClient::Options autoReconnectOptions(int initialDelayMs = 20, int maxDelayMs = 200)
{
  WebSocketClient::Options o;
  o.autoReconnect = true;
  o.initialReconnectDelay = std::chrono::milliseconds(initialDelayMs);
  o.maxReconnectDelay = std::chrono::milliseconds(maxDelayMs);
  return o;
}

} // namespace

// ── (c) reconnect-success — the clean, deterministic baseline ────────────────
// A transport-level drop is followed by an automatic reconnect to the same live
// server. This is the positive control: it MUST pass post-fix and demonstrates
// the auto-reconnect machinery works end-to-end.
TEST_CASE("ws-reconnect: transport drop triggers a successful auto-reconnect (c)",
          "[ws][reconnect][integration][c]")
{
  const int port = nextPort();
  bool finished = completesWithin(
    [port]()
    {
      WsTestServer srv(port);
      auto client = std::make_shared<WebSocketClient>();
      REQUIRE(client->connect("127.0.0.1", port, "/", autoReconnectOptions()));
      REQUIRE(waitFor([&]() { return srv.connectCount.load() >= 1; }));

      // Force a transport-level drop; the client must auto-reconnect.
      srv.dropLast();
      REQUIRE(waitFor([&]() { return srv.connectCount.load() >= 2; }, 8000));
      REQUIRE(waitFor(
        [&]() { return client->getState() == WebSocketState::CONNECTED; }, 8000));

      client->disconnect();
    },
    20000);
  REQUIRE(finished);
}

// ── (b) disconnect()-from-onClose — teardown-guard path ──────────────────────
// The client's WS-close callback calls client.disconnect() while running on the
// I/O thread. The teardown guard must keep the worker-join off the I/O thread
// (pre-fix: relocated F-1 deadlock or a stop()-on-I/O-thread throw). The watchdog
// asserts the operation completes (no hang).
TEST_CASE("ws-reconnect: disconnect() invoked from the onClose callback does not hang (b)",
          "[ws][reconnect][integration][b][negative-baseline]")
{
  const int port = nextPort();
  bool finished = completesWithin(
    [port]()
    {
      WsTestServer srv(port);
      auto client = std::make_shared<WebSocketClient>();
      auto closed = std::make_shared<std::atomic<bool>>(false);

      // onClose runs on the client I/O thread (WS CLOSE-frame path). Calling
      // disconnect() from here is the H-1 teardown scenario.
      client->setOnClose(
        [client, closed](std::uint16_t, const std::string &)
        {
          client->disconnect();
          closed->store(true);
        });

      // No auto-reconnect here: isolate the teardown-from-callback path.
      REQUIRE(client->connect("127.0.0.1", port));
      REQUIRE(waitFor([&]() { return srv.lastSid.load() != 0; }));

      // Server initiates a graceful WS close -> client receives CLOSE frame ->
      // handleFrame -> _onClose -> disconnect() on the I/O thread.
      srv.server.sendClose(srv.lastSid.load(), 1000, "bye");

      REQUIRE(waitFor([&]() { return closed->load(); }, 8000));
    },
    20000);
  REQUIRE(finished);
}

// ── (a) F-1 deadlock — reconnect-in-flight vs I/O-thread join ────────────────
// Pre-fix: scheduleReconnect() (on the I/O thread) join()s a prior reconnect
// thread that is blocked in Transport::stop(); the stop() needs the same I/O
// thread to drain -> deadlock. We stress rapid drops with a near-zero reconnect
// delay to land a reconnect mid-stop() exactly when a fresh disconnect fires.
// The watchdog asserts no deadlock across the whole cycle + teardown.
TEST_CASE("ws-reconnect: rapid drop/reconnect cycling never deadlocks (a F-1)",
          "[ws][reconnect][integration][a][f1][negative-baseline]")
{
  const int port = nextPort();
  bool finished = completesWithin(
    [port]()
    {
      WsTestServer srv(port);
      auto client = std::make_shared<WebSocketClient>();
      // Near-zero reconnect delay maximizes the chance a reconnect is mid-stop()
      // when the next drop's handleDisconnect fires on that transport's I/O
      // thread (the F-1 window).
      REQUIRE(client->connect("127.0.0.1", port, "/", autoReconnectOptions(1, 10)));
      REQUIRE(waitFor([&]() { return srv.connectCount.load() >= 1; }));

      // Hammer the connection: each accepted session is dropped immediately, so
      // the client is perpetually reconnecting while the I/O thread keeps firing
      // disconnects.
      for (int i = 0; i < 40; ++i)
      {
        srv.dropLast();
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
      }

      // Let it settle into a stable CONNECTED state, then tear down. The teardown
      // (~client) joins the worker — it must not deadlock either.
      waitFor([&]() { return client->getState() == WebSocketState::CONNECTED; }, 5000);
      client->disconnect();
    },
    25000);
  REQUIRE(finished);
}

// ── (d) concurrent-send-during-reconnect — member-sync stress ────────────────
// Thread A loops sendText() while thread B forces repeated drops/reconnects. Run
// under ASan + watchdog: no crash / UAF, and no send to a stale (transport,
// sessionId) pair. The assertion is "no hang, no crash"; ASan is the UAF probe.
TEST_CASE("ws-reconnect: concurrent send during repeated reconnect is race-clean (d M-5)",
          "[ws][reconnect][integration][d][stress]")
{
  const int port = nextPort();
  bool finished = completesWithin(
    [port]()
    {
      WsTestServer srv(port);
      auto client = std::make_shared<WebSocketClient>();
      REQUIRE(client->connect("127.0.0.1", port, "/", autoReconnectOptions(1, 10)));
      REQUIRE(waitFor([&]() { return srv.connectCount.load() >= 1; }));

      auto stop = std::make_shared<std::atomic<bool>>(false);

      std::thread sender(
        [client, stop]()
        {
          while (!stop->load())
          {
            client->sendText("ping"); // no-op unless CONNECTED; reads the pair
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
          }
        });

      std::thread dropper(
        [&srv, stop]()
        {
          for (int i = 0; i < 60 && !stop->load(); ++i)
          {
            srv.dropLast();
            std::this_thread::sleep_for(std::chrono::milliseconds(3));
          }
        });

      dropper.join();
      stop->store(true);
      sender.join();

      client->disconnect();
    },
    25000);
  REQUIRE(finished);
}

// ── (e) connect-after-disconnect-from-callback lifecycle ─────────────────────
// connect (autoReconnect) -> disconnect()-from-onClose (skips the join) ->
// connect() again on the main thread. Auto-reconnect must still function after
// the second connect (the reap-then-respawn path), proving the worker was not
// stranded by the I/O-thread-skip in the first disconnect().
TEST_CASE("ws-reconnect: connect again after disconnect-from-callback still auto-reconnects (e)",
          "[ws][reconnect][integration][e][lifecycle]")
{
  const int port = nextPort();
  bool finished = completesWithin(
    [port]()
    {
      WsTestServer srv(port);
      auto client = std::make_shared<WebSocketClient>();
      auto firstClosed = std::make_shared<std::atomic<bool>>(false);

      client->setOnClose(
        [client, firstClosed](std::uint16_t, const std::string &)
        {
          // Only the first (server-initiated) close drives the teardown-from-
          // callback path; later closes are normal.
          if (!firstClosed->exchange(true))
          {
            client->disconnect();
          }
        });

      REQUIRE(client->connect("127.0.0.1", port, "/", autoReconnectOptions()));
      REQUIRE(waitFor([&]() { return srv.lastSid.load() != 0; }));

      // Graceful close -> onClose -> disconnect() on the I/O thread (skips join).
      srv.server.sendClose(srv.lastSid.load(), 1000, "bye");
      REQUIRE(waitFor([&]() { return firstClosed->load(); }, 8000));

      // Second connect on the main thread must reap the old worker and respawn.
      const int beforeSecond = srv.connectCount.load();
      REQUIRE(client->connect("127.0.0.1", port, "/", autoReconnectOptions()));
      REQUIRE(waitFor([&]() { return srv.connectCount.load() > beforeSecond; }, 8000));

      // Auto-reconnect must still function after the second connect.
      const int beforeDrop = srv.connectCount.load();
      srv.dropLast();
      REQUIRE(waitFor([&]() { return srv.connectCount.load() > beforeDrop; }, 8000));
      REQUIRE(waitFor(
        [&]() { return client->getState() == WebSocketState::CONNECTED; }, 8000));

      client->disconnect();
    },
    30000);
  REQUIRE(finished);
}
