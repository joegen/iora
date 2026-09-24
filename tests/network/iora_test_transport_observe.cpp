// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_transport_observe.cpp
/// \brief Race-free Transport::observe() (tracker 2026-09-24-2 A6.2/A6.3):
///        the observe()-vs-close ownership handoff delivers each observer exactly
///        once (never zero, never twice), the sentinel-0 "already closed" path,
///        observe from inside an onClose, observe before start() / after stop(),
///        the owns-terminal async delivery + return-value contract, and drain
///        robustness under throwing user callbacks.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/network/transport_impl.hpp"
#include "iora_test_net_utils.hpp"
#include "resolve_stall_harness.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <thread>

using namespace iora::network;
using namespace std::chrono_literals;

namespace
{
// simp-M5: reuse the shared deadline-based poll helper.
bool waitFor(const std::function<bool()> &pred, std::chrono::milliseconds timeout = 2000ms)
{
  return resolvetest::waitFor(pred, timeout);
}

/// \brief A server transport with a single accepted TCP session; the test drives
/// close() on that session and observes the terminal handoff.
struct ObserveFixture
{
  std::shared_ptr<Transport> server = Transport::tcp();
  std::shared_ptr<Transport> client = Transport::tcp();
  std::atomic<SessionId> serverSid{0};
  std::uint16_t port{0};

  ObserveFixture()
  {
    port = testnet::getFreePortTCP();
    server->onAccept([&](SessionId s, const TransportAddress &) { serverSid = s; });
  }

  void startAndConnect()
  {
    REQUIRE(server->start().isOk());
    REQUIRE(server->addListener("127.0.0.1", port).isOk());
    REQUIRE(client->start().isOk());
    REQUIRE(client->connect("127.0.0.1", port).isOk());
    REQUIRE(waitFor([&] { return serverSid.load() != 0; }));
  }

  ~ObserveFixture()
  {
    try
    {
      client->stop();
    }
    catch (...)
    {
    }
    try
    {
      server->stop();
    }
    catch (...)
    {
    }
  }
};
} // namespace

// ───────────────────── AX9.2: exactly-once ownership handoff ────────────────────

TEST_CASE("observe() racing close() delivers exactly once (N iterations)", "[observe][race]")
{
  // Each iteration establishes a session, races observe() (background thread)
  // against close() (main thread), and asserts the observer fires EXACTLY once —
  // never zero (self-fire when the close already ran), never twice (double handoff).
  constexpr int N = 40;
  for (int i = 0; i < N; ++i)
  {
    ObserveFixture f;
    f.startAndConnect();
    SessionId sid = f.serverSid.load();

    std::atomic<int> fires{0};
    std::thread t([&] { f.server->observe(sid, [&](SessionId, const TransportErrorInfo &) { fires++; }); });
    f.server->close(sid);
    t.join();

    REQUIRE(waitFor([&] { return fires.load() >= 1; }));
    CHECK(fires.load() == 1);
  }
}

TEST_CASE("observe() before the close fires via the close handler exactly once", "[observe]")
{
  ObserveFixture f;
  f.startAndConnect();
  SessionId sid = f.serverSid.load();

  std::atomic<int> fires{0};
  ObserverId oid = f.server->observe(sid, [&](SessionId, const TransportErrorInfo &) { fires++; });
  CHECK(oid != 0); // live session: real id

  f.server->close(sid);
  REQUIRE(waitFor([&] { return fires.load() == 1; }));
  CHECK(fires.load() == 1);
}

TEST_CASE("observe() on an already-closed session owns the terminal and delivers async",
          "[observe][owns-terminal]")
{
  ObserveFixture f;
  f.startAndConnect();
  SessionId sid = f.serverSid.load();

  std::atomic<int> globalCloses{0};
  f.server->onClose([&](SessionId, const TransportErrorInfo &) { globalCloses++; });
  f.server->close(sid);
  REQUIRE(waitFor([&] { return globalCloses.load() == 1; }));

  // The session is now gone but the engine is running: observe OWNS the terminal.
  // NB: assert the delivered message on the MAIN thread (capture it here) — Catch2 v2
  // assertion macros are NOT thread-safe, so we must not CHECK inside the callback
  // (which fires on the I/O thread).
  std::atomic<int> fires{0};
  std::string deliveredMsg;
  std::mutex msgMutex;
  ObserverId oid =
    f.server->observe(sid, [&](SessionId, const TransportErrorInfo &info)
                      {
                        {
                          std::lock_guard<std::mutex> lk(msgMutex);
                          deliveredMsg = info.message;
                        }
                        fires++;
                      });
  CHECK(oid != 0);                          // post succeeded -> real id
  REQUIRE(waitFor([&] { return fires.load() == 1; }));
  CHECK(fires.load() == 1);
  {
    std::lock_guard<std::mutex> lk(msgMutex);
    CHECK(deliveredMsg == "session already closed"); // owned terminal carries the reason
  }
  // The entry was removed before the async fire -> unobserve reports "gone".
  CHECK_FALSE(f.server->unobserve(oid));
}

TEST_CASE("observe() from inside the session's own global onClose fires once", "[observe][reentrant]")
{
  ObserveFixture f;
  f.startAndConnect();
  SessionId sid = f.serverSid.load();

  std::atomic<int> reentrantFires{0};
  f.server->onClose([&](SessionId s, const TransportErrorInfo &)
                    {
                      // Inside onClose the session's liveness is already cleared, so
                      // this observe() owns the terminal and delivers it async.
                      f.server->observe(s, [&](SessionId, const TransportErrorInfo &) { reentrantFires++; });
                    });

  f.server->close(sid);
  REQUIRE(waitFor([&] { return reentrantFires.load() == 1; }));
  CHECK(reentrantFires.load() == 1);
}

// ─────────────────────── AX9.2: sentinel-0 (already closed) ─────────────────────

TEST_CASE("observe() before start() returns sentinel 0 and never invokes the callback",
          "[observe][sentinel]")
{
  auto t = Transport::tcp();
  std::atomic<int> fires{0};
  ObserverId oid = t->observe(12345, [&](SessionId, const TransportErrorInfo &) { fires++; });
  CHECK(oid == 0); // engine not running before start()
  std::this_thread::sleep_for(50ms);
  CHECK(fires.load() == 0);
  CHECK_FALSE(t->unobserve(oid)); // nothing retained
}

TEST_CASE("observe() after stop() returns sentinel 0 and retains nothing", "[observe][sentinel]")
{
  ObserveFixture f;
  f.startAndConnect();
  SessionId sid = f.serverSid.load();
  f.client->stop();
  f.server->stop();

  std::atomic<int> fires{0};
  ObserverId oid = f.server->observe(sid, [&](SessionId, const TransportErrorInfo &) { fires++; });
  CHECK(oid == 0);
  std::this_thread::sleep_for(50ms);
  CHECK(fires.load() == 0);
}

TEST_CASE("observe() owned-terminal delivery does not deadlock a caller-held mutex",
          "[observe][deadlock]")
{
  ObserveFixture f;
  f.startAndConnect();
  SessionId sid = f.serverSid.load();
  f.server->onClose([](SessionId, const TransportErrorInfo &) {});
  f.server->close(sid);
  REQUIRE(waitFor([&] { return true; })); // let the close settle
  std::this_thread::sleep_for(30ms);

  std::mutex userMutex;
  std::atomic<int> fires{0};
  ObserverId oid = 0;
  {
    // Observe while HOLDING a mutex the observer also takes. Because the owned
    // terminal is delivered ASYNC on the I/O thread (never inline under the caller),
    // this cannot self-deadlock.
    std::lock_guard<std::mutex> lk(userMutex);
    oid = f.server->observe(sid, [&](SessionId, const TransportErrorInfo &)
                            {
                              std::lock_guard<std::mutex> lk2(userMutex);
                              fires++;
                            });
  }
  REQUIRE(waitFor([&] { return fires.load() == 1; }));
  CHECK(oid != 0);
}

// ─────────────────────── AX9.2/A6.3: throwing-callback drain ────────────────────

TEST_CASE("a throwing global onClose still fires the observers", "[observe][guard]")
{
  ObserveFixture f;
  f.startAndConnect();
  SessionId sid = f.serverSid.load();

  f.server->onClose([](SessionId, const TransportErrorInfo &)
                    { throw std::runtime_error("global onClose throws"); });
  std::atomic<int> obs{0};
  f.server->observe(sid, [&](SessionId, const TransportErrorInfo &) { obs++; });

  f.server->close(sid);
  REQUIRE(waitFor([&] { return obs.load() == 1; }));
  CHECK(obs.load() == 1);
}

TEST_CASE("a throwing observer does not stop later observers firing", "[observe][guard]")
{
  ObserveFixture f;
  f.startAndConnect();
  SessionId sid = f.serverSid.load();

  std::atomic<int> second{0};
  f.server->observe(sid, [](SessionId, const TransportErrorInfo &)
                    { throw std::runtime_error("observer throws"); });
  f.server->observe(sid, [&](SessionId, const TransportErrorInfo &) { second++; });

  f.server->close(sid);
  REQUIRE(waitFor([&] { return second.load() == 1; }));
  CHECK(second.load() == 1);
}

// NOTE on the H1 regression pin: the residual-RunOnIo-invocation fix (steps-4-8 R1
// H1) is pinned DETERMINISTICALLY at the engine level in
// iora_test_udp_connect_then_send.cpp ("UDP shutdownDrain invokes a residual RunOnIo
// ..."). It cannot be pinned through Transport::observe() from inside a drain onClose:
// during the drain the engine is already !isRunning(), so an observe() there takes the
// sentinel-0 path (returns 0, retains nothing) rather than posting a residual terminal.
// The observe()-owned residual only arises from an EXTERNAL thread that reads a stale
// isRunning()==true and posts after process() — an inherently racy interleaving.

TEST_CASE("a throwing observer during stop()-drain still lets a later observe() return 0",
          "[observe][guard][drain]")
{
  ObserveFixture f;
  f.startAndConnect();
  SessionId sid = f.serverSid.load();

  f.server->observe(sid, [](SessionId, const TransportErrorInfo &)
                    { throw std::runtime_error("drain observer throws"); });

  // stop() drains the live session and fires the throwing observer; the drain must
  // survive so the transport tears down cleanly.
  f.client->stop();
  f.server->stop();

  std::atomic<int> fires{0};
  ObserverId oid = f.server->observe(sid, [&](SessionId, const TransportErrorInfo &) { fires++; });
  CHECK(oid == 0);
  std::this_thread::sleep_for(50ms);
  CHECK(fires.load() == 0);
}
