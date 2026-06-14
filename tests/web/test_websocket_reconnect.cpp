// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Real-socket integration tests for the WebSocketClient reconnect worker — the
// S-3 phase-2 F-1 / H-1 regression guard. Tracker:
// 2026-06-11-4 (transport-shared-ownership phase 2); architecture:
// transport_shared_ownership.json, component "WebSocketClient reconnect worker
// (F-1 fix) — OPTION C (shared_ptr-managed client)".
//
// OPTION C model (the contract these tests exercise):
//   * WebSocketClient is shared_ptr-managed: enable_shared_from_this + a private
//     ctor + a static create() -> shared_ptr; copy AND move are deleted. A client
//     exists only inside a shared_ptr — hence WebSocketClient::create(), never a
//     stack value / make_unique / make_shared with a public ctor.
//   * Every transport callback (onData/onClose/onError) and the single long-lived
//     CV-driven reconnect worker capture std::weak_ptr<WebSocketClient> and
//     promote `self = weak.lock(); if (!self) return;` BEFORE touching any member
//     (weak_from_this only; shared_from_this is forbidden — UB at refcount 0).
//   * The worker holds its promoted `self` across the WHOLE attempt (and the I/O
//     callback across the whole frame), so the client cannot be destroyed
//     mid-use — destroy-from-own-callback is deferred until the frame unwinds.
//   * _transportMutex guards the {_transport,_sessionId,_rc,_reconnectWorker}
//     member group (copy-then-invoke; orthogonal to esft lifetime). Teardown
//     routes through a noexcept teardownTransport() that gates stop() OFF the I/O
//     thread (the last-Transport-ref drop terminates the loop via ~Transport).
//   * USER-CALLBACK CONTRACT (HR-11): user callbacks MUST weak-capture the client,
//     never an owning shared_ptr — a self-owning cycle leaks the client + worker.
//     Every onClose/onConnect below weak-captures and promotes per call.
//
// Exercises the worker end-to-end over a live WebSocketServer + WebSocketClient:
//   (a) F-1 deadlock — a reconnect in-flight (blocked in Transport::stop()) while
//       a fresh transport-level disconnect fires on that transport's I/O thread
//       (pre-fix: deadlock / rapid-cycle SIGABRT on a joinable std::thread).
//   (b) disconnect()-from-onClose — the client's WS-close callback (weak-captured)
//       calls disconnect() on the I/O thread; teardown must keep the worker-join
//       off the I/O thread and stop() off the I/O thread (pre-fix: relocated
//       deadlock / stop()-on-I/O-thread throw).
//   (c) reconnect-success — a transport-level drop is followed by an automatic
//       reconnect to the same live server within a bound (positive control).
//   (d) concurrent-send-during-reconnect — sendText() racing repeated
//       disconnect/reconnect under ASan + watchdog (member-sync AP-16).
//   (e) connect-after-disconnect-from-callback lifecycle — connect (autoReconnect)
//       -> disconnect()-from-onClose (skips the join) -> connect() again on the
//       main thread; auto-reconnect must still function (reap-then-respawn).
//   (f) destroy-from-own-callback (I/O thread) — a weak-captured onClose drops the
//       last external shared_ptr<WebSocketClient> while a close is in flight;
//       ~client must be deferred to after the I/O callback unwinds (no UAF, no
//       hang). The promoted self in the transport callback pins the client.
//   (f2) destroy-from-own-callback (worker thread) — a weak-captured onConnect,
//       fired by the WORKER during an auto-reconnect attempt, drops the last
//       external ref; the worker's loop-frame self pins the client through the
//       end of the attempt, so ~client runs on the worker only after the attempt
//       fully returns (no UAF, no hang).
//
// NEGATIVE BASELINE (established step-1 against PRE-FIX code): scenario (a) rapid
// drop/reconnect cycling SIGABRTed ("terminate called without an active
// exception" — the std::thread was joinable at destruction); scenario (b)
// disconnect()-from-onClose THREW at _transport->stop() on the I/O thread
// (Transport::stop() self-joins/throws, transport_impl.hpp:677-682). Option C
// closes both: a single guarded worker + universal-reaper noexcept dtor (a), and
// stop() gated off the I/O thread (b).
//
// Every scenario that could deadlock runs inside completesWithin(): the body runs
// on a worker thread that is DETACHED (intentionally leaked) on timeout, so a
// genuine deadlock reports a clean test failure instead of wedging the binary. The
// body is self-contained (owns its server + client; captures only heap/shared
// state) so a leaked-on-timeout body never dangles into the test's stack.
//
// ASan substitutes for TSan here (TSan is unavailable — the ASLR personality is
// blocked in this environment). ASan + the stress loops + the watchdog are a
// best-effort data-race / UAF probe; they do NOT PROVE race-freedom. Correctness
// rests on the _transportMutex copy-then-invoke discipline + the per-callback
// weak.lock() gate + the onIo-gated teardown applied exactly.
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
#include <type_traits>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iora/network/websocket_client.hpp>
#include <iora/network/websocket_server.hpp>

using iora::network::SessionId;
using iora::network::WebSocketClient;
using iora::network::WebSocketServer;
using iora::network::WebSocketState;

// esft enforcement (task-4.3 / arch testStrategy): a WebSocketClient cannot be
// default-, copy-, or move-constructed — only WebSocketClient::create() yields
// one. NOTE: these traits reflect BOTH the explicit =delete of copy/move AND the
// non-movable members (std::thread/mutex/condition_variable); the AUTHORITATIVE
// enforcement of "only create() constructs" is the PRIVATE constructor, which
// makes every value / make_unique / make_shared instantiation a hard compile
// break (proven by the migrated call sites in task-4.1), not these traits alone.
static_assert(!std::is_default_constructible<WebSocketClient>::value,
              "WebSocketClient must not be default-constructible (use create())");
static_assert(!std::is_copy_constructible<WebSocketClient>::value,
              "WebSocketClient must not be copy-constructible");
static_assert(!std::is_move_constructible<WebSocketClient>::value,
              "WebSocketClient must not be move-constructible");

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

// A raw TCP listener that ACCEPTS connections and holds them open WITHOUT ever
// responding (a "half-open" server). Pointing the reconnect worker at it makes
// each reconnect's TCP connect succeed but the WS upgrade never complete, so the
// worker parks in reconnectAttempt's handshake-settle wait (kHandshakeSettleTimeout
// ~10s) — the exact state H-3 is about.
struct HalfOpenListener
{
  int listenFd{-1};
  int port;
  std::thread acceptThread;
  std::atomic<bool> stop{false};
  std::atomic<int> accepted{0};
  std::mutex heldMutex;
  std::vector<int> heldFds;

  explicit HalfOpenListener(int p) : port(p)
  {
    listenFd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(listenFd >= 0); // runs on the test body thread (not the accept thread)
    int one = 1;
    ::setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ::inet_addr("127.0.0.1");
    addr.sin_port = htons(static_cast<std::uint16_t>(port));
    REQUIRE(::bind(listenFd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
    REQUIRE(::listen(listenFd, 16) == 0);
    acceptThread = std::thread(
      [this]()
      {
        while (!stop.load())
        {
          int fd = ::accept(listenFd, nullptr, nullptr);
          if (fd < 0)
          {
            if (stop.load()) break;
            // Avoid a tight busy-spin on a persistent accept() error.
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
          }
          {
            std::lock_guard<std::mutex> lk(heldMutex);
            heldFds.push_back(fd);
          }
          accepted.fetch_add(1);
          // Hold the connection open, never respond (no 101).
        }
      });
  }

  ~HalfOpenListener()
  {
    stop.store(true);
    if (listenFd >= 0)
    {
      ::shutdown(listenFd, SHUT_RDWR); // unblock accept()
      ::close(listenFd);
    }
    if (acceptThread.joinable()) acceptThread.join();
    std::lock_guard<std::mutex> lk(heldMutex);
    for (int fd : heldFds) ::close(fd);
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
      auto client = WebSocketClient::create();
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
      auto client = WebSocketClient::create();
      auto closed = std::make_shared<std::atomic<bool>>(false);

      // onClose runs on the client I/O thread (WS CLOSE-frame path). Calling
      // disconnect() from here is the H-1 teardown scenario. Weak-capture the
      // client (HR-11: never an owning shared_ptr in a stored user callback) and
      // promote per call.
      std::weak_ptr<WebSocketClient> weak = client;
      client->setOnClose(
        [weak, closed](std::uint16_t, const std::string &)
        {
          if (auto self = weak.lock())
          {
            self->disconnect();
          }
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
      auto client = WebSocketClient::create();
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
      auto client = WebSocketClient::create();
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
      auto client = WebSocketClient::create();
      auto firstClosed = std::make_shared<std::atomic<bool>>(false);

      // Weak-capture the client (HR-11) and promote per call.
      std::weak_ptr<WebSocketClient> weak = client;
      client->setOnClose(
        [weak, firstClosed](std::uint16_t, const std::string &)
        {
          // Only the first (server-initiated) close drives the teardown-from-
          // callback path; later closes are normal.
          if (!firstClosed->exchange(true))
          {
            if (auto self = weak.lock())
            {
              self->disconnect();
            }
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

// ── (f) destroy-from-own-callback (I/O thread) ───────────────────────────────
// A weak-captured onClose drops the LAST external shared_ptr<WebSocketClient>
// from inside the I/O-thread close callback while a close is in flight. Under
// Option C the transport callback's promoted self pins the client across the
// whole frame, so the last-ref drop merely decrements — ~WebSocketClient is
// deferred until the I/O callback unwinds, then runs on the I/O thread (the
// dtor's onIo branch: reap-skip + stop()-skip + ~Transport deferred-self-
// destruct). Assert: no hang (watchdog), no UAF (ASan), and the client really
// is destroyed afterward (no self-owning-cycle leak).
//
// The only strong ref after our local is released lives in a heap slot captured
// by the onClose lambda — a deliberate (client -> _onClose -> slot -> client)
// cycle that is broken inside the callback by slot->reset(). This is a TEST
// device to force the last-ref drop on the I/O thread; production callbacks must
// weak-capture and never form such a cycle (HR-11).
TEST_CASE("ws-reconnect: dropping the last client ref from onClose (I/O thread) is UAF-free (f)",
          "[ws][reconnect][integration][f][destroy-from-callback]")
{
  const int port = nextPort();
  auto weakProbe = std::make_shared<std::weak_ptr<WebSocketClient>>();
  bool finished = completesWithin(
    [port, weakProbe]()
    {
      WsTestServer srv(port);
      auto client = WebSocketClient::create();
      *weakProbe = client;
      auto destroyed = std::make_shared<std::atomic<bool>>(false);
      // Heap slot holding the only strong ref once our local is released.
      auto slot = std::make_shared<std::shared_ptr<WebSocketClient>>(client);
      std::weak_ptr<WebSocketClient> weak = client;

      client->setOnClose(
        [weak, slot, destroyed](std::uint16_t, const std::string &)
        {
          if (auto self = weak.lock())
          {
            // Drop the last external strong ref from inside the I/O-thread
            // callback. `self` (this frame) + the promoted self in the transport
            // callback still pin the client, so ~WebSocketClient is deferred
            // until the callback unwinds — then runs on the I/O thread.
            slot->reset();
          }
          destroyed->store(true);
        });

      // No auto-reconnect: isolate the destroy-from-I/O-callback path.
      REQUIRE(client->connect("127.0.0.1", port));
      REQUIRE(waitFor([&]() { return srv.lastSid.load() != 0; }));

      client.reset(); // `slot` now holds the only strong ref to the client

      // Graceful close -> onClose on the I/O thread -> drops the last ref.
      srv.server.sendClose(srv.lastSid.load(), 1000, "bye");
      REQUIRE(waitFor([&]() { return destroyed->load(); }, 8000));
    },
    20000);
  REQUIRE(finished);
  // The client must actually have been destroyed (no leaked self-owning cycle).
  REQUIRE(waitFor([&]() { return weakProbe->expired(); }, 5000));
}

// ── (f2) destroy-from-own-callback (WORKER thread) ───────────────────────────
// Drops the LAST external shared_ptr<WebSocketClient> from a callback that
// genuinely fires ON THE WORKER THREAD, exercising the dtor's onWorker branch
// (invariant 13). The right hook is onStateChange's CONNECTING transition: it
// fires on the connect() thread for the INITIAL connect, but on the reconnect
// WORKER thread for each auto-reconnect attempt (doConnect -> setState(CONNECTING)
// runs inside reconnectAttempt on the worker). (onConnect, by contrast, fires in
// handleData on the I/O thread — using it would merely duplicate scenario (f).)
//
// The worker holds its promoted self in the LOOP frame (never moved into
// reconnectAttempt), so dropping the external ref mid-attempt merely decrements;
// ~WebSocketClient runs on the worker only after the attempt returns and self
// drops at end-of-iteration — where reapWorker takes the onWorker DETACH path
// (never self-join). We prove the drop ran on the worker (a thread distinct from
// the connect()/body thread) via a captured std::thread::id. The server is kept
// alive until the client is actually destroyed so the reconnect handshake can
// complete deterministically. Same heap-slot test device as (f).
TEST_CASE("ws-reconnect: dropping the last client ref from a worker callback (onStateChange) is UAF-free (f2)",
          "[ws][reconnect][integration][f2][destroy-from-callback]")
{
  const int port = nextPort();
  auto weakProbe = std::make_shared<std::weak_ptr<WebSocketClient>>();
  auto bodyThreadId = std::make_shared<std::atomic<std::thread::id>>();
  auto destroyThreadId = std::make_shared<std::atomic<std::thread::id>>();
  auto ioThreadId = std::make_shared<std::atomic<std::thread::id>>();
  bool finished = completesWithin(
    [port, weakProbe, bodyThreadId, destroyThreadId, ioThreadId]()
    {
      bodyThreadId->store(std::this_thread::get_id());
      WsTestServer srv(port);
      auto client = WebSocketClient::create();
      *weakProbe = client;
      auto destroyed = std::make_shared<std::atomic<bool>>(false);
      auto slot = std::make_shared<std::shared_ptr<WebSocketClient>>(client);
      auto connecting = std::make_shared<std::atomic<int>>(0);
      std::weak_ptr<WebSocketClient> weak = client;

      // onConnect fires inside handleData on the I/O thread — capture that id so
      // we can prove the destroy did NOT run on the I/O thread.
      client->setOnConnect(
        [ioThreadId](const std::string &)
        { ioThreadId->store(std::this_thread::get_id()); });

      client->setOnStateChange(
        [weak, slot, destroyed, connecting, destroyThreadId](WebSocketState st)
        {
          if (st != WebSocketState::CONNECTING) return;
          // 0 == initial connect (connect() thread); 1 == the first auto-reconnect
          // attempt's CONNECTING, which runs on the WORKER thread.
          if (connecting->fetch_add(1) == 1)
          {
            destroyThreadId->store(std::this_thread::get_id());
            if (auto self = weak.lock())
            {
              // Drop the last external ref ON THE WORKER, mid-attempt. The
              // worker's loop-frame self still pins the client, so ~client is
              // deferred to end-of-iteration — then runs on the worker.
              slot->reset();
            }
            destroyed->store(true);
          }
        });

      REQUIRE(client->connect("127.0.0.1", port, "/", autoReconnectOptions()));
      REQUIRE(waitFor([&]() { return connecting->load() >= 1; })); // initial CONNECTING
      client.reset(); // `slot` now holds the only strong ref

      // Force a transport drop -> worker reconnects -> CONNECTING (#2) on the
      // worker drops the last ref mid-attempt.
      srv.dropLast();
      REQUIRE(waitFor([&]() { return destroyed->load(); }, 10000));
      // Keep the server alive until ~client actually runs on the worker (the
      // reconnect succeeds, then the worker's self drops) — so the handshake is
      // not racing srv teardown.
      REQUIRE(waitFor([&]() { return weak.expired(); }, 10000));
    },
    25000);
  REQUIRE(finished);
  REQUIRE(waitFor([&]() { return weakProbe->expired(); }, 5000));
  // Prove the destroy ran on the reconnect WORKER thread — a thread distinct from
  // BOTH the connect()/body thread AND the transport I/O thread (the worker
  // setState(CONNECTING) precedes the new transport's I/O thread even starting).
  REQUIRE(destroyThreadId->load() != std::thread::id{});
  REQUIRE(destroyThreadId->load() != bodyThreadId->load());
  REQUIRE(ioThreadId->load() != std::thread::id{}); // onConnect did fire (I/O thread seen)
  REQUIRE(destroyThreadId->load() != ioThreadId->load());
}

// ── (g) no self-owning-cycle leak (HR-11 / R-8) ──────────────────────────────
// The ONE non-structural Option C residual: a user callback that captures an
// OWNING shared_ptr<WebSocketClient> forms a self-owning cycle that leaks the
// client + its worker thread. This test installs ONLY weak-capturing callbacks,
// holds the sole shared_ptr, drops it, and asserts the client is actually
// destroyed (weak_ptr expires) and the worker exits within a bound — i.e. no
// cycle. autoReconnect=true so a worker thread exists and ~WebSocketClient must
// reap it: if ~client never ran (a cycle) the weak_ptr would not expire; if the
// worker did not exit, ~client's reap would block and the watchdog would fire.
TEST_CASE("ws-reconnect: weak-only callbacks leave no self-owning cycle (g leak)",
          "[ws][reconnect][integration][g][leak]")
{
  const int port = nextPort();
  auto weakProbe = std::make_shared<std::weak_ptr<WebSocketClient>>();
  bool finished = completesWithin(
    [port, weakProbe]()
    {
      WsTestServer srv(port);
      auto client = WebSocketClient::create();
      *weakProbe = client;
      std::weak_ptr<WebSocketClient> weak = client;

      // Weak-only user callbacks (HR-11): none captures an owning shared_ptr.
      client->setOnConnect([weak](const std::string &) { (void)weak; });
      client->setOnClose([weak](std::uint16_t, const std::string &) { (void)weak; });

      REQUIRE(client->connect("127.0.0.1", port, "/", autoReconnectOptions()));
      REQUIRE(waitFor(
        [&]() { return client->getState() == WebSocketState::CONNECTED; }));

      client.reset(); // drop the SOLE strong ref
    },
    20000);
  REQUIRE(finished);
  // No leaked cycle: ~WebSocketClient ran (refcount hit 0) and the worker exited.
  REQUIRE(waitFor([&]() { return weakProbe->expired(); }, 5000));
}

// ── (h) teardown interrupts a long backoff sleep promptly ────────────────────
// The reconnect worker's backoff between attempts is an INTERRUPTIBLE wait on
// the control-block CV (predicate !shouldRun), not a plain sleep_for. With a very
// large backoff delay, a transport drop parks the worker in that backoff; a
// subsequent disconnect() must wake it (shouldRun=false + notify) and return
// promptly — far under the backoff delay. If the backoff were a non-interruptible
// sleep, disconnect()'s reapWorker join would block for the full delay and the
// watchdog would fire. This guards the interruptible-backoff invariant against
// regression (it is otherwise asserted only by construction).
TEST_CASE("ws-reconnect: disconnect() interrupts a long backoff sleep promptly (h)",
          "[ws][reconnect][integration][h][backoff]")
{
  const int port = nextPort();
  bool finished = completesWithin(
    [port]()
    {
      WsTestServer srv(port);
      auto client = WebSocketClient::create();
      // Very large backoff: a non-interruptible sleep would block teardown ~30s.
      WebSocketClient::Options o;
      o.autoReconnect = true;
      o.initialReconnectDelay = std::chrono::milliseconds(30000);
      o.maxReconnectDelay = std::chrono::milliseconds(30000);
      REQUIRE(client->connect("127.0.0.1", port, "/", o));
      REQUIRE(waitFor(
        [&]() { return client->getState() == WebSocketState::CONNECTED; }));

      // Drop -> worker wakes (requested) and parks in the 30s backoff sleep
      // before its first reconnect attempt.
      srv.dropLast();
      std::this_thread::sleep_for(std::chrono::milliseconds(300));

      // disconnect() must wake the backoff-parked worker and return promptly,
      // NOT block for the 30s backoff.
      auto t0 = std::chrono::steady_clock::now();
      client->disconnect();
      auto elapsed = std::chrono::steady_clock::now() - t0;
      REQUIRE(elapsed < std::chrono::seconds(5));
    },
    20000);
  REQUIRE(finished);
}

// ── (h2) disconnect() interrupts a parked HANDSHAKE-SETTLE wait promptly (H-3) ─
// Distinct from (h), which covers the rc->cv BACKOFF wait. Here the worker is
// parked in reconnectAttempt's _connectCv handshake-settle wait against a
// half-open server (TCP accepts, no 101). reapWorker signals rc->shouldRun on
// rc->cv — but the worker is on _connectCv, so without the H-3 fix the
// reap-join would block for the full kHandshakeSettleTimeout (~10s). The fix
// adds !shouldRun to the settle-wait predicate and notify_all's _connectCv from
// reapWorker / connect()'s reap, so disconnect() returns promptly. Pre-fix
// baseline: ~10s stall; post-fix: well under it.
TEST_CASE("ws-reconnect: disconnect() interrupts a parked handshake-settle wait promptly (h2 H-3)",
          "[ws][reconnect][integration][h2][negative-baseline]")
{
  const int port = nextPort();
  bool finished = completesWithin(
    [port]()
    {
      auto client = WebSocketClient::create();
      {
        WsTestServer srv(port);
        REQUIRE(client->connect("127.0.0.1", port, "/", autoReconnectOptions(5, 50)));
        REQUIRE(waitFor(
          [&]() { return client->getState() == WebSocketState::CONNECTED; }));
        // srv destructs here: the server stops, frees the port, and drops the
        // client's connection — the worker begins auto-reconnecting.
      }

      // Half-open listener on the SAME port: the worker's reconnect attempts now
      // TCP-connect successfully but never receive a 101, parking the worker in
      // the handshake-settle wait.
      HalfOpenListener half(port);
      REQUIRE(waitFor([&]() { return half.accepted.load() >= 1; }, 10000));
      // Let the worker enter the settle-wait after its TCP connect + upgrade send.
      std::this_thread::sleep_for(std::chrono::milliseconds(300));

      auto t0 = std::chrono::steady_clock::now();
      client->disconnect();
      auto elapsed = std::chrono::steady_clock::now() - t0;
      REQUIRE(elapsed < std::chrono::seconds(5));
    },
    25000);
  REQUIRE(finished);
}

// ── (h3) disconnect() racing the worker's ENTRY into the settle-wait (H-3-R2) ─
// h2 sleeps 300ms before disconnect, so the worker is already blocked — it does
// NOT exercise the lost-wakeup WINDOW (the gap between the worker's predicate
// re-check and its kernel block inside wait_for). h3 disconnects with a tiny,
// varied delay right after the worker TCP-connects to the half-open listener, to
// probabilistically land in that window across cycles. With the H-3-R2 fix (the
// _connectCv notify is serialized by an empty _connectMutex critical section)
// every disconnect is prompt; a lost wakeup would stall one iteration for ~the
// handshake-settle timeout and trip the per-call bound (or the watchdog). This is
// a best-effort probabilistic guard, not a deterministic window hit.
TEST_CASE("ws-reconnect: disconnect() racing settle-wait entry stays prompt across cycles (h3 H-3-R2)",
          "[ws][reconnect][integration][h3]")
{
  bool finished = completesWithin(
    []()
    {
      for (int i = 0; i < 8; ++i)
      {
        const int port = nextPort();
        auto client = WebSocketClient::create();
        {
          WsTestServer srv(port);
          REQUIRE(client->connect("127.0.0.1", port, "/", autoReconnectOptions(1, 5)));
          REQUIRE(waitFor(
            [&]() { return client->getState() == WebSocketState::CONNECTED; }));
        } // srv stops -> drops the client -> the worker begins reconnecting
        HalfOpenListener half(port);
        // Worker has TCP-connected to the half-open listener (now at/near the
        // settle-wait entry); disconnect with a tiny varied delay to race it.
        // A missed accept is acceptable (best-effort window setup): the disconnect
        // is still prompt via the rc->cv-covered backoff/top wait, so this cycle
        // just contributes less window coverage — explicitly discard the result.
        (void)waitFor([&]() { return half.accepted.load() >= 1; }, 8000);
        std::this_thread::sleep_for(std::chrono::milliseconds(i % 4)); // 0..3ms
        auto t0 = std::chrono::steady_clock::now();
        client->disconnect();
        REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(5));
      }
    },
    60000);
  REQUIRE(finished);
}
