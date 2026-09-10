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
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
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

// ── Cross-thread assertion channel (Catch2 issue #99) ────────────────────────
// Catch2's assertion macros (REQUIRE/CHECK/INFO/WARN/FAIL) touch unsynchronized
// global RunContext state and are single-thread-only: only the thread that
// entered the TEST_CASE may use them. Every scenario body below runs on a
// completesWithin() WORKER thread (DETACHED on timeout), so NO Catch2 macro may
// execute inside a body. Instead the body records pass/fail into this heap-owned
// result and the MAIN test thread asserts on it after the worker joins/times out.
//
// Synchronization: on the success path completesWithin() join()s the worker — the
// join is the happens-before edge for the main thread's reads. On the TIMEOUT
// path the worker is DETACHED and keeps running with NO join edge, so every
// access to the non-atomic `_message` (the worker's write AND the main thread's
// read) MUST hold `_m`; the mutex is mandatory, not defensive. The result is
// heap-owned via shared_ptr and captured BY VALUE into the worker lambda, so a
// leaked-on-timeout body never dangles into freed state.
struct BodyResult
{
  mutable std::mutex _m;
  bool _failed{false};  // guarded by _m
  std::string _message; // guarded by _m; first recorded failure only

  void record(const std::string &msg)
  {
    std::lock_guard<std::mutex> lk(_m);
    if (!_failed) // keep the FIRST failure; the body aborts after the first anyway
    {
      _message = msg;
      _failed = true;
    }
  }
  // Single locked snapshot so the diagnostic message and the asserted flag come
  // from the SAME critical section — a still-running detached body (timeout path)
  // cannot slip a failure in between two separate locked reads.
  std::pair<bool, std::string> snapshot() const
  {
    std::lock_guard<std::mutex> lk(_m);
    return {_failed, _message};
  }
};

// Thrown by bodyRequire() to abort a scenario body early — mirrors REQUIRE's
// abort-on-failure. A PLAIN sentinel (NOT derived from std::exception) so
// completesWithin()'s catch clauses distinguish a recorded assertion failure from
// an unexpected exception. It never reaches Catch2 on the worker thread.
struct BodyAbort
{
};

// Worker-thread assertion: on failure record the message and abort the body.
// Use in place of REQUIRE(cond) inside a completesWithin() body.
inline void bodyRequire(BodyResult &r, bool cond, const std::string &msg)
{
  if (!cond)
  {
    r.record(msg);
    throw BodyAbort{};
  }
}

// Outcome of completesWithin: whether the body finished within the watchdog, plus
// the shared result channel (co-owned with the — possibly detached — worker).
struct BodyOutcome
{
  bool completed{false};
  std::shared_ptr<BodyResult> result;
};

// Runs `fn(result)` on a worker thread and reports whether it finished within
// timeoutMs. On timeout the worker is DETACHED — a genuine deadlock then surfaces
// as completed==false (a clean main-thread failure) rather than wedging the whole
// binary. `fn` MUST be self-contained: on the timeout path it keeps running after
// this returns, so it may capture only by value / heap / shared state, never the
// caller's stack.
BodyOutcome completesWithin(std::function<void(BodyResult &)> fn, int timeoutMs)
{
  auto done = std::make_shared<std::atomic<bool>>(false);
  auto result = std::make_shared<BodyResult>();
  std::thread t(
    [fn, done, result]() // shared_ptrs BY VALUE: outlive a detached body
    {
      try
      {
        fn(*result);
      }
      catch (const BodyAbort &)
      {
        // A bodyRequire() failure — already recorded; nothing more to do.
      }
      catch (const std::exception &e)
      {
        result->record(std::string("unexpected exception: ") + e.what());
      }
      catch (...)
      {
        result->record("unexpected non-standard exception");
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
  return BodyOutcome{ok, result};
}

// MAIN-thread assertion over a completesWithin() outcome. The two REQUIREs
// guarantee every scenario has >=2 main-thread assertions (no Catch2 "no
// assertions in test case" warning). firstMessage() reads under the mutex, so it
// is safe even against a still-running detached body on the timeout path.
void requireOutcome(const BodyOutcome &o)
{
  const auto snap = o.result->snapshot(); // {failed, first message} in one lock
  INFO("first recorded body failure: " << snap.second);
  REQUIRE(o.completed);      // false == watchdog timeout (hang/deadlock)
  REQUIRE_FALSE(snap.first); // a body-recorded assertion failure
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
    // This ctor runs on the completesWithin() worker/body thread (h2/h3
    // construct it inside the body), so it must NOT use Catch2 macros. Socket
    // setup failures throw std::runtime_error, which completesWithin() records
    // as a body failure via its std::exception catch. The ctor throw skips
    // ~HalfOpenListener, so close listenFd here before throwing.
    auto fail = [this](const char *what)
    {
      if (listenFd >= 0)
      {
        ::close(listenFd);
        listenFd = -1;
      }
      throw std::runtime_error(std::string("HalfOpenListener: ") + what);
    };
    listenFd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listenFd < 0)
    {
      fail("socket() failed");
    }
    int one = 1;
    ::setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ::inet_addr("127.0.0.1");
    addr.sin_port = htons(static_cast<std::uint16_t>(port));
    if (::bind(listenFd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0)
    {
      fail("bind() failed");
    }
    if (::listen(listenFd, 16) != 0)
    {
      fail("listen() failed");
    }
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
  BodyOutcome outcome = completesWithin(
    [port](BodyResult &r)
    {
      WsTestServer srv(port);
      auto client = WebSocketClient::create();
      bodyRequire(r, client->connect("127.0.0.1", port, "/", autoReconnectOptions()),
                  "(c) initial connect failed");
      bodyRequire(r, waitFor([&]() { return srv.connectCount.load() >= 1; }),
                  "(c) server never saw the first connect");

      // Force a transport-level drop; the client must auto-reconnect.
      srv.dropLast();
      bodyRequire(r, waitFor([&]() { return srv.connectCount.load() >= 2; }, 8000),
                  "(c) auto-reconnect: server never saw the second connect");
      bodyRequire(r,
                  waitFor([&]() { return client->getState() == WebSocketState::CONNECTED; },
                          8000),
                  "(c) client did not return to CONNECTED after reconnect");

      client->disconnect();
    },
    20000);
  requireOutcome(outcome);
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
  BodyOutcome outcome = completesWithin(
    [port](BodyResult &r)
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
      bodyRequire(r, client->connect("127.0.0.1", port), "(b) connect failed");
      bodyRequire(r, waitFor([&]() { return srv.lastSid.load() != 0; }),
                  "(b) server never saw the session");

      // Server initiates a graceful WS close -> client receives CLOSE frame ->
      // handleFrame -> _onClose -> disconnect() on the I/O thread.
      srv.server.sendClose(srv.lastSid.load(), 1000, "bye");

      bodyRequire(r, waitFor([&]() { return closed->load(); }, 8000),
                  "(b) onClose (disconnect-from-callback) never completed");
    },
    20000);
  requireOutcome(outcome);
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
  BodyOutcome outcome = completesWithin(
    [port](BodyResult &r)
    {
      WsTestServer srv(port);
      auto client = WebSocketClient::create();
      // Near-zero reconnect delay maximizes the chance a reconnect is mid-stop()
      // when the next drop's handleDisconnect fires on that transport's I/O
      // thread (the F-1 window).
      bodyRequire(r, client->connect("127.0.0.1", port, "/", autoReconnectOptions(1, 10)),
                  "(a) initial connect failed");
      bodyRequire(r, waitFor([&]() { return srv.connectCount.load() >= 1; }),
                  "(a) server never saw the first connect");

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
  requireOutcome(outcome);
}

// ── (d) concurrent-send-during-reconnect — member-sync stress ────────────────
// Thread A loops sendText() while thread B forces repeated drops/reconnects. Run
// under ASan + watchdog: no crash / UAF, and no send to a stale (transport,
// sessionId) pair. The assertion is "no hang, no crash"; ASan is the UAF probe.
TEST_CASE("ws-reconnect: concurrent send during repeated reconnect is race-clean (d M-5)",
          "[ws][reconnect][integration][d][stress]")
{
  const int port = nextPort();
  BodyOutcome outcome = completesWithin(
    [port](BodyResult &r)
    {
      WsTestServer srv(port);
      auto client = WebSocketClient::create();
      // Both asserts run BEFORE the sender/dropper threads are spawned: a
      // bodyRequire() throw (BodyAbort) must never unwind past a joinable
      // std::thread (that would std::terminate).
      bodyRequire(r, client->connect("127.0.0.1", port, "/", autoReconnectOptions(1, 10)),
                  "(d) initial connect failed");
      bodyRequire(r, waitFor([&]() { return srv.connectCount.load() >= 1; }),
                  "(d) server never saw the first connect");

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
  requireOutcome(outcome);
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
  BodyOutcome outcome = completesWithin(
    [port](BodyResult &r)
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

      bodyRequire(r, client->connect("127.0.0.1", port, "/", autoReconnectOptions()),
                  "(e) first connect failed");
      bodyRequire(r, waitFor([&]() { return srv.lastSid.load() != 0; }),
                  "(e) server never saw the first session");

      // Graceful close -> onClose -> disconnect() on the I/O thread (skips join).
      srv.server.sendClose(srv.lastSid.load(), 1000, "bye");
      bodyRequire(r, waitFor([&]() { return firstClosed->load(); }, 8000),
                  "(e) first close (disconnect-from-callback) never completed");

      // Second connect on the main thread must reap the old worker and respawn.
      const int beforeSecond = srv.connectCount.load();
      bodyRequire(r, client->connect("127.0.0.1", port, "/", autoReconnectOptions()),
                  "(e) second connect failed");
      bodyRequire(r, waitFor([&]() { return srv.connectCount.load() > beforeSecond; }, 8000),
                  "(e) server never saw the reconnect after the second connect");

      // Auto-reconnect must still function after the second connect.
      const int beforeDrop = srv.connectCount.load();
      srv.dropLast();
      bodyRequire(r, waitFor([&]() { return srv.connectCount.load() > beforeDrop; }, 8000),
                  "(e) auto-reconnect after second connect never re-established");
      bodyRequire(r,
                  waitFor([&]() { return client->getState() == WebSocketState::CONNECTED; },
                          8000),
                  "(e) client did not return to CONNECTED after the post-reconnect drop");

      client->disconnect();
    },
    30000);
  requireOutcome(outcome);
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
  BodyOutcome outcome = completesWithin(
    [port, weakProbe](BodyResult &r)
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
      bodyRequire(r, client->connect("127.0.0.1", port), "(f) connect failed");
      bodyRequire(r, waitFor([&]() { return srv.lastSid.load() != 0; }),
                  "(f) server never saw the session");

      client.reset(); // `slot` now holds the only strong ref to the client

      // Graceful close -> onClose on the I/O thread -> drops the last ref.
      srv.server.sendClose(srv.lastSid.load(), 1000, "bye");
      bodyRequire(r, waitFor([&]() { return destroyed->load(); }, 8000),
                  "(f) onClose (last-ref-drop on the I/O thread) never completed");
    },
    20000);
  requireOutcome(outcome);
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
  // Brace-init the contained id to the "no thread" sentinel explicitly (the
  // trailing REQUIREs compare against std::thread::id{}); pre-C++20
  // std::atomic<T> has a non-initializing default ctor.
  auto bodyThreadId = std::make_shared<std::atomic<std::thread::id>>(std::thread::id{});
  auto destroyThreadId = std::make_shared<std::atomic<std::thread::id>>(std::thread::id{});
  auto ioThreadId = std::make_shared<std::atomic<std::thread::id>>(std::thread::id{});
  BodyOutcome outcome = completesWithin(
    [port, weakProbe, bodyThreadId, destroyThreadId, ioThreadId](BodyResult &r)
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

      bodyRequire(r, client->connect("127.0.0.1", port, "/", autoReconnectOptions()),
                  "(f2) connect failed");
      bodyRequire(r, waitFor([&]() { return connecting->load() >= 1; }),
                  "(f2) initial CONNECTING transition never observed");
      client.reset(); // `slot` now holds the only strong ref

      // Force a transport drop -> worker reconnects -> CONNECTING (#2) on the
      // worker drops the last ref mid-attempt.
      srv.dropLast();
      bodyRequire(r, waitFor([&]() { return destroyed->load(); }, 10000),
                  "(f2) worker-thread last-ref-drop (2nd CONNECTING) never ran");
      // Keep the server alive until ~client actually runs on the worker (the
      // reconnect succeeds, then the worker's self drops) — so the handshake is
      // not racing srv teardown.
      bodyRequire(r, waitFor([&]() { return weak.expired(); }, 10000),
                  "(f2) client was not destroyed on the worker within the bound");
    },
    25000);
  requireOutcome(outcome);
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
  BodyOutcome outcome = completesWithin(
    [port, weakProbe](BodyResult &r)
    {
      WsTestServer srv(port);
      auto client = WebSocketClient::create();
      *weakProbe = client;
      std::weak_ptr<WebSocketClient> weak = client;

      // Weak-only user callbacks (HR-11): none captures an owning shared_ptr.
      client->setOnConnect([weak](const std::string &) { (void)weak; });
      client->setOnClose([weak](std::uint16_t, const std::string &) { (void)weak; });

      bodyRequire(r, client->connect("127.0.0.1", port, "/", autoReconnectOptions()),
                  "(g) connect failed");
      bodyRequire(r,
                  waitFor([&]() { return client->getState() == WebSocketState::CONNECTED; }),
                  "(g) client never reached CONNECTED");

      client.reset(); // drop the SOLE strong ref
    },
    20000);
  requireOutcome(outcome);
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
  BodyOutcome outcome = completesWithin(
    [port](BodyResult &r)
    {
      WsTestServer srv(port);
      auto client = WebSocketClient::create();
      // Very large backoff: a non-interruptible sleep would block teardown ~30s.
      WebSocketClient::Options o;
      o.autoReconnect = true;
      o.initialReconnectDelay = std::chrono::milliseconds(30000);
      o.maxReconnectDelay = std::chrono::milliseconds(30000);
      bodyRequire(r, client->connect("127.0.0.1", port, "/", o), "(h) connect failed");
      bodyRequire(r,
                  waitFor([&]() { return client->getState() == WebSocketState::CONNECTED; }),
                  "(h) client never reached CONNECTED");

      // Drop -> worker wakes (requested) and parks in the 30s backoff sleep
      // before its first reconnect attempt.
      srv.dropLast();
      std::this_thread::sleep_for(std::chrono::milliseconds(300));

      // disconnect() must wake the backoff-parked worker and return promptly,
      // NOT block for the 30s backoff.
      auto t0 = std::chrono::steady_clock::now();
      client->disconnect();
      auto elapsed = std::chrono::steady_clock::now() - t0;
      bodyRequire(r, elapsed < std::chrono::seconds(5),
                  "(h) disconnect() did not interrupt the long backoff promptly");
    },
    20000);
  requireOutcome(outcome);
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
  BodyOutcome outcome = completesWithin(
    [port](BodyResult &r)
    {
      auto client = WebSocketClient::create();
      {
        WsTestServer srv(port);
        bodyRequire(r, client->connect("127.0.0.1", port, "/", autoReconnectOptions(5, 50)),
                    "(h2) connect failed");
        bodyRequire(r,
                    waitFor([&]() { return client->getState() == WebSocketState::CONNECTED; }),
                    "(h2) client never reached CONNECTED");
        // srv destructs here: the server stops, frees the port, and drops the
        // client's connection — the worker begins auto-reconnecting.
      }

      // Half-open listener on the SAME port: the worker's reconnect attempts now
      // TCP-connect successfully but never receive a 101, parking the worker in
      // the handshake-settle wait.
      HalfOpenListener half(port);
      bodyRequire(r, waitFor([&]() { return half.accepted.load() >= 1; }, 10000),
                  "(h2) half-open listener never accepted a reconnect attempt");
      // Let the worker enter the settle-wait after its TCP connect + upgrade send.
      std::this_thread::sleep_for(std::chrono::milliseconds(300));

      auto t0 = std::chrono::steady_clock::now();
      client->disconnect();
      auto elapsed = std::chrono::steady_clock::now() - t0;
      bodyRequire(r, elapsed < std::chrono::seconds(5),
                  "(h2) disconnect() did not interrupt the parked settle-wait promptly");
    },
    25000);
  requireOutcome(outcome);
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
  BodyOutcome outcome = completesWithin(
    [](BodyResult &r)
    {
      for (int i = 0; i < 8; ++i)
      {
        const int port = nextPort();
        auto client = WebSocketClient::create();
        {
          WsTestServer srv(port);
          bodyRequire(r, client->connect("127.0.0.1", port, "/", autoReconnectOptions(1, 5)),
                      "(h3) connect failed");
          bodyRequire(
            r, waitFor([&]() { return client->getState() == WebSocketState::CONNECTED; }),
            "(h3) client never reached CONNECTED");
        } // srv stops -> drops the client -> the worker begins reconnecting
        HalfOpenListener half(port);
        // Worker has TCP-connected to the half-open listener (now at/near the
        // settle-wait entry); disconnect with a tiny varied delay to race it.
        // A missed accept is acceptable (best-effort window setup): the disconnect
        // is still prompt via the rc->cv-covered backoff/top wait, so this cycle
        // just contributes less window coverage — explicitly discard the result.
        // Best-effort window setup (result discarded); keep the bound small so 8
        // iterations cannot accumulate past the watchdog on a slow/ASan host.
        (void)waitFor([&]() { return half.accepted.load() >= 1; }, 3000);
        std::this_thread::sleep_for(std::chrono::milliseconds(i % 4)); // 0..3ms
        auto t0 = std::chrono::steady_clock::now();
        client->disconnect();
        bodyRequire(r, std::chrono::steady_clock::now() - t0 < std::chrono::seconds(5),
                    "(h3) disconnect() racing settle-wait entry was not prompt");
      }
    },
    // 8 iterations, each bounded by connect + waitFor(CONNECTED,5s) +
    // waitFor(accepted,3s) + prompt disconnect(<5s): a comfortable watchdog that
    // still backstops a genuine per-iteration hang.
    120000);
  requireOutcome(outcome);
}
