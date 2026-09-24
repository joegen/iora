// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_tcp_connect_then_send.cpp
/// \brief TcpEngine connect-then-send (tracker 2026-09-24-1): a sid returned by
///        connect() is immediately sendable (A2.x, A9.1), connecting-registry
///        hygiene (A9.2), callback-free enqueue (A1.1) and the connect-path
///        exception guard (A2.5).
///
/// The resolve-window cases stall the process-wide blockingIoPool() (PoolStall),
/// so this binary is ISOLATED and LAST-ORDERED in NETWORK_TESTS.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/network/transport.hpp"
#include "tcp_connect_test_fixtures.hpp"
#include "transport_test_seam.hpp"

using namespace tcptest;

// ─────────────────────────── A9.1: connect-then-send ───────────────────────────

TEST_CASE("literal connect + immediate send/sendAsync delivers in order", "[tcp][tls][connect-then-send]")
{
  for (bool tls : {false, true})
  {
    SECTION(tls ? "TLS" : "TCP")
    {
      std::string certFile, keyFile;
      if (tls && !certsOrSkip(certFile, keyFile))
      {
        return;
      }
      SinkServer server(tls, certFile, keyFile);
      Client client(tls);
      REQUIRE(client.tx->start().isOk());

      auto cr = client.tx->connect("127.0.0.1", server.port, tls ? TlsMode::Client : TlsMode::None);
      REQUIRE(cr.isOk());
      SessionId sid = cr.value();

      REQUIRE(client.tx->send(sid, "A|", 2));
      bool asyncOk = false;
      client.tx->sendAsync(sid, "B|", 2, [&](SessionId, const SendResult &r) { asyncOk = r.isOk(); });
      REQUIRE(asyncOk);
      REQUIRE(client.tx->send(sid, "C|", 2));

      REQUIRE(waitFor([&] { return server.data() == "A|B|C|"; }));
      REQUIRE(client.connectCount == 1);
      REQUIRE(client.closeCount == 0);
      REQUIRE(TA::connectingCount(*client.tx) == 0);
    }
  }
}

TEST_CASE("connect + immediate send issued FROM the I/O thread delivers", "[tcp][connect-then-send][iothread]")
{
  for (bool tls : {false, true})
  {
    SECTION(tls ? "TLS" : "TCP")
    {
      std::string certFile, keyFile;
      if (tls && !certsOrSkip(certFile, keyFile))
      {
        return;
      }
      SinkServer server(tls, certFile, keyFile);
      Client client(tls);
      REQUIRE(client.tx->start().isOk());

      bool onIo = false;
      bool connectOk = false;
      bool sendOk = false;
      bool asyncOk = false;
      std::size_t connectingAtSend = 0;
      REQUIRE(runOnIo(*client.tx,
                      [&]
                      {
                        onIo = client.tx->isOnIoThread();
                        auto cr = client.tx->connect("127.0.0.1", server.port,
                                                     tls ? TlsMode::Client : TlsMode::None);
                        connectOk = cr.isOk();
                        if (!connectOk)
                        {
                          return;
                        }
                        // Cmd::Connect cannot have run: we are occupying the I/O thread.
                        connectingAtSend = TA::connectingCount(*client.tx);
                        sendOk = client.tx->send(cr.value(), "io-1|", 5);
                        client.tx->sendAsync(cr.value(), "io-2|", 5,
                                             [&](SessionId, const SendResult &r) { asyncOk = r.isOk(); });
                      }));
      REQUIRE(onIo);
      REQUIRE(connectOk);
      REQUIRE(connectingAtSend == 1);
      REQUIRE(sendOk);
      REQUIRE(asyncOk);
      REQUIRE(waitFor([&] { return server.data() == "io-1|io-2|"; }));
      REQUIRE(client.closeCount == 0);
    }
  }
}

TEST_CASE("named-host (localhost) TCP and TLS immediate send delivers", "[tcp][connect-then-send][resolve]")
{
  for (bool tls : {false, true})
  {
    SECTION(tls ? "TLS" : "TCP")
    {
      std::string certFile, keyFile;
      if (tls && !certsOrSkip(certFile, keyFile))
      {
        return;
      }
      SinkServer server(tls, certFile, keyFile);
      Client client(tls);
      REQUIRE(client.tx->start().isOk());

      auto cr = client.tx->connect("localhost", server.port, tls ? TlsMode::Client : TlsMode::None);
      REQUIRE(cr.isOk());
      REQUIRE(client.tx->send(cr.value(), "n-1|", 4));
      bool asyncOk = false;
      client.tx->sendAsync(cr.value(), "n-2|", 4,
                           [&](SessionId, const SendResult &r) { asyncOk = r.isOk(); });
      REQUIRE(asyncOk);
      REQUIRE(client.tx->send(cr.value(), "n-3|", 4));

      REQUIRE(waitFor([&] { return server.data() == "n-1|n-2|n-3|"; }, 5000ms));
      REQUIRE(client.closeCount == 0);
      REQUIRE(TA::connectingCount(*client.tx) == 0);
    }
  }
}

TEST_CASE("unknown and closed sids still get the synchronous error", "[tcp][connect-then-send][cfh1]")
{
  SinkServer server;
  Client client;
  REQUIRE(client.tx->start().isOk());

  SECTION("unknown sid")
  {
    REQUIRE_FALSE(client.tx->send(987654, "x", 1));
    bool gotErr = false;
    std::string msg;
    client.tx->sendAsync(987654, "x", 1,
                         [&](SessionId, const SendResult &r)
                         {
                           gotErr = r.isErr();
                           if (gotErr)
                           {
                             msg = r.error().message;
                           }
                         });
    REQUIRE(gotErr);
    REQUIRE(msg == "session not connected");
  }

  SECTION("app-closed sid")
  {
    auto cr = client.tx->connect("127.0.0.1", server.port, TlsMode::None);
    REQUIRE(cr.isOk());
    REQUIRE(waitFor([&] { return client.connectCount == 1; }));
    REQUIRE(client.tx->close(cr.value()));
    REQUIRE(waitFor([&] { return client.closesFor(cr.value()) == 1; }));
    REQUIRE_FALSE(client.tx->send(cr.value(), "x", 1));
    bool gotErr = false;
    client.tx->sendAsync(cr.value(), "x", 1, [&](SessionId, const SendResult &r) { gotErr = r.isErr(); });
    REQUIRE(gotErr);
  }

  SECTION("refused sid (pre-insert terminal)")
  {
    auto deadPort = testnet::getFreePortTCP();
    auto cr = client.tx->connect("127.0.0.1", deadPort, TlsMode::None);
    REQUIRE(cr.isOk());
    REQUIRE(waitFor([&] { return client.closesFor(cr.value()) == 1; }));
    REQUIRE(client.closeInfo(cr.value()).code == TransportError::Connect);
    REQUIRE_FALSE(client.tx->send(cr.value(), "x", 1));
    REQUIRE(TA::connectingCount(*client.tx) == 0);
  }
}

TEST_CASE("connect() before start(): start() alone processes it and delivers the pre-start send",
          "[tcp][connect-then-send][lifecycle]")
{
  SinkServer server;
  Client client;

  auto cr = client.tx->connect("127.0.0.1", server.port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(TA::connectingCount(*client.tx) == 1);
  REQUIRE(client.tx->send(cr.value(), "pre|", 4));

  // No command is enqueued after start(): the queued Connect/Send must be
  // processed on the strength of start() alone.
  REQUIRE(client.tx->start().isOk());

  REQUIRE(waitFor([&] { return client.connectCount == 1; }));
  REQUIRE(waitFor([&] { return server.data() == "pre|"; }));
  REQUIRE(TA::connectingCount(*client.tx) == 0);
  REQUIRE(client.closeCount == 0);
}

TEST_CASE("addListener() before start(): start() alone binds the listener", "[tcp][lifecycle]")
{
  TransportConfig cfg{};
  std::atomic<int> accepted{0};
  TcpEngine srv{cfg};
  iora::network::detail::EngineBase::Callbacks cbs{};
  cbs.onAccept = [&](SessionId, const TransportAddress &) { accepted++; };
  srv.setCallbacks(cbs);

  const std::uint16_t port = testnet::getFreePortTCP();
  REQUIRE(srv.addListener("127.0.0.1", port, TlsMode::None).isOk());
  REQUIRE(srv.start().isOk());

  bool connected = false;
  const auto deadline = std::chrono::steady_clock::now() + 3s;
  while (!connected && std::chrono::steady_clock::now() < deadline)
  {
    int c = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(c >= 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    connected = ::connect(c, reinterpret_cast<sockaddr *>(&a), sizeof(a)) == 0;
    ::close(c);
    if (!connected)
    {
      std::this_thread::sleep_for(20ms);
    }
  }
  REQUIRE(connected);
  REQUIRE(waitFor([&] { return accepted.load() >= 1; }));
  srv.stop();
}

TEST_CASE("start() rejects maxWriteQueue == 0 with a Config error", "[tcp][lifecycle][config]")
{
  TransportConfig cfg{};
  cfg.maxWriteQueue = 0;
  TcpEngine tx{cfg};
  auto r = tx.start();
  REQUIRE(r.isErr());
  REQUIRE(r.error().code == TransportError::Config);
  REQUIRE_FALSE(tx.isRunning());
}

// ─────────────────────────── A1.1: callback-free enqueue ───────────────────────────

TEST_CASE("injected enqueue failure: connect() returns err, no callback, registry rolled back",
          "[tcp][enqueue][callback-free]")
{
  SinkServer server;
  Client client;
  REQUIRE(client.tx->start().isOk());

  auto live = client.tx->connect("127.0.0.1", server.port, TlsMode::None);
  REQUIRE(live.isOk());
  REQUIRE(waitFor([&] { return client.connectCount == 1; }));

  TA::injectEnqueueFailure(*client.tx, true);
  auto cr = client.tx->connect("127.0.0.1", server.port, TlsMode::None);
  REQUIRE(cr.isErr());
  REQUIRE(cr.error().code == TransportError::Unknown);
  REQUIRE(TA::connectingCount(*client.tx) == 0);
  REQUIRE_FALSE(client.tx->send(live.value(), "x", 1));
  REQUIRE_FALSE(client.tx->close(live.value()));
  REQUIRE_FALSE(client.tx->setReadEnabled(live.value(), false));
  REQUIRE(client.errorCount == 0);
  REQUIRE(client.tx->lastFatalError().message.find("injected enqueue failure") != std::string::npos);

  TA::injectEnqueueFailure(*client.tx, false);
  REQUIRE(client.tx->send(live.value(), "ok|", 3));
  REQUIRE(waitFor([&] { return server.data() == "ok|"; }));
  REQUIRE(client.errorCount == 0);
}

TEST_CASE("injected enqueue failure under Transport::setReadMode: no caller callback, no deadlock",
          "[tcp][enqueue][callback-free][transport]")
{
  using namespace iora::network;
  struct Probe
  {
    std::atomic<std::thread::id> caller{};
    std::atomic<int> errorsOnCaller{0};
    std::atomic<int> errors{0};
    std::promise<void> done;
  };
  auto probe = std::make_shared<Probe>();

  TransportConfig cfg{};
  cfg.protocol = Protocol::TCP;
  auto eng = std::make_unique<TcpEngine>(cfg);
  TcpEngine *raw = eng.get();
  std::shared_ptr<Transport> t = test::TransportEngineInjector::withEngine(std::move(eng), cfg);
  REQUIRE(t->start().isOk());

  std::weak_ptr<Transport> weak = t;
  t->onError(
    [probe, weak](TransportError, const std::string &)
    {
      probe->errors++;
      if (std::this_thread::get_id() == probe->caller.load())
      {
        probe->errorsOnCaller++;
      }
      // Re-enter Transport (takes syncMutex): deadlocks if invoked under syncMutex.
      if (auto tp = weak.lock())
      {
        (void)tp->setReadMode(4242, ReadMode::Async);
      }
    });

  TA::injectEnqueueFailure(*raw, true);
  auto fut = probe->done.get_future();
  // Detached so a deadlock fails the test (latch timeout) instead of hanging it in
  // a joining future destructor; it owns what it touches.
  std::thread(
    [probe, t]
    {
      probe->caller.store(std::this_thread::get_id());
      (void)t->setReadMode(4241, ReadMode::Disabled);
      probe->done.set_value();
    })
    .detach();
  REQUIRE(fut.wait_for(5s) == std::future_status::ready);
  REQUIRE(probe->errorsOnCaller == 0);
  REQUIRE(probe->errors == 0);
  TA::injectEnqueueFailure(*raw, false);
  t->stop();
}

TEST_CASE("stop() completes when the shutdown enqueue fails", "[tcp][enqueue][callback-free][stop]")
{
  Client client;
  REQUIRE(client.tx->start().isOk());
  TA::injectEnqueueFailure(*client.tx, true);
  auto fut = std::async(std::launch::async, [&] { client.tx->stop(); });
  REQUIRE(fut.wait_for(5s) == std::future_status::ready);
  fut.get();
  REQUIRE_FALSE(client.tx->isRunning());
  TA::injectEnqueueFailure(*client.tx, false);
}

TEST_CASE("timer close whose enqueue fails while the queue is open is retried, never lost",
          "[tcp][enqueue][timer]")
{
  Blackhole bh;
  if (!fillOrSkip(bh))
  {
    return;
  }
  Client client(false, [](TransportConfig &c) { c.connectTimeout = 1000ms; });
  REQUIRE(client.tx->start().isOk());

  auto cr = client.tx->connect("127.0.0.1", bh.lst.port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return TA::connectingCount(*client.tx) == 0; }));
  TA::injectEnqueueFailure(*client.tx, true);

  // Positive barrier: the connect timer fired, its enqueue failed, and at least
  // one retry fired too.
  REQUIRE(waitFor(
    [&] {
      return client.tx->lastFatalError().message.find("injected enqueue failure") != std::string::npos &&
             TA::timersExpired(*client.tx) >= 2;
    },
    3000ms));
  REQUIRE(client.closesFor(cr.value()) == 0);

  TA::injectEnqueueFailure(*client.tx, false);
  REQUIRE(waitFor([&] { return client.closesFor(cr.value()) == 1; }, 2000ms));
  REQUIRE(client.closeInfo(cr.value()).message == "Connect timeout");
  REQUIRE(client.closeInfo(cr.value()).code == TransportError::Connect);
  REQUIRE(client.errorCount == 0);
  REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
}

TEST_CASE("resolve-timeout post whose enqueue fails while the queue is open is retried, never lost",
          "[tcp][enqueue][timer][resolve][isolated]")
{
  Client client(false, [](TransportConfig &c) { c.resolveTimeout = 150ms; });
  REQUIRE(client.tx->start().isOk());
  SinkServer server;

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cr = client.tx->connect("localhost", server.port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(pendingConnectCount(*client.tx) == 1); // precondition: still resolving
  const auto expiredBefore = TA::timersExpired(*client.tx);
  TA::injectEnqueueFailure(*client.tx, true);

  // Positive barrier: the resolve timer fired and at least one retry fired.
  REQUIRE(waitFor([&] { return TA::timersExpired(*client.tx) >= expiredBefore + 2; }, 3000ms));
  REQUIRE(client.closesFor(cr.value()) == 0);

  TA::injectEnqueueFailure(*client.tx, false);
  REQUIRE(waitFor([&] { return client.closesFor(cr.value()) == 1; }, 2000ms));
  REQUIRE(client.closeInfo(cr.value()).code == TransportError::Resolve);
  REQUIRE(client.closeInfo(cr.value()).message == "resolve timeout");
  REQUIRE(TA::connectingCount(*client.tx) == 0);
  stall.release();
  REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
}

// ─────────────────────────── A9.2: registry hygiene ───────────────────────────

TEST_CASE("registry empty after a refused connect", "[tcp][registry]")
{
  Client client;
  REQUIRE(client.tx->start().isOk());
  auto cr = client.tx->connect("127.0.0.1", testnet::getFreePortTCP(), TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return client.closesFor(cr.value()) == 1; }));
  REQUIRE(TA::connectingCount(*client.tx) == 0);
}

TEST_CASE("registry empty after app close during resolve (buffered sends dropped)", "[tcp][registry][resolve][isolated]")
{
  Client client(false, [](TransportConfig &c) { c.resolveTimeout = 30000ms; });
  REQUIRE(client.tx->start().isOk());
  SinkServer server;

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cr = client.tx->connect("localhost", server.port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(client.tx->send(cr.value(), "drop-me", 7));
  REQUIRE(pendingConnectCount(*client.tx) == 1); // precondition: still resolving
  REQUIRE(TA::connectingCount(*client.tx) == 1);

  REQUIRE(client.tx->close(cr.value()));
  REQUIRE(waitFor([&] { return client.closesFor(cr.value()) == 1; }));
  REQUIRE(client.closeInfo(cr.value()).code == TransportError::Unknown);
  REQUIRE(TA::connectingCount(*client.tx) == 0);
  REQUIRE_FALSE(client.tx->send(cr.value(), "x", 1));

  stall.release();
  REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
  REQUIRE(client.connectCount == 0);
  REQUIRE(server.data().empty());
}

TEST_CASE("registry empty after resolve timeout", "[tcp][registry][resolve][isolated]")
{
  Client client(false, [](TransportConfig &c) { c.resolveTimeout = 150ms; });
  REQUIRE(client.tx->start().isOk());
  SinkServer server;

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cr = client.tx->connect("localhost", server.port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(client.tx->send(cr.value(), "drop-me", 7));
  REQUIRE(waitFor([&] { return client.closesFor(cr.value()) == 1; }));
  REQUIRE(client.closeInfo(cr.value()).code == TransportError::Resolve);
  REQUIRE(TA::connectingCount(*client.tx) == 0);

  stall.release();
  REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
  REQUIRE(server.data().empty());
}

TEST_CASE("a throwing pre-insert onClose never skips the following onError", "[tcp][guard][callbacks]")
{
  SECTION("synchronously refused connect (TCP to multicast -> ENETUNREACH)")
  {
    Client client;
    client.throwOnClose = true;
    REQUIRE(client.tx->start().isOk());
    auto cr = client.tx->connect("224.0.0.1", 5060, TlsMode::None);
    REQUIRE(cr.isOk());
    REQUIRE(waitFor([&] { return client.closesFor(cr.value()) == 1; }));
    REQUIRE(client.closeInfo(cr.value()).code == TransportError::Connect);
    REQUIRE(client.closeInfo(cr.value()).sysErrno == ENETUNREACH);
    REQUIRE(client.closeInfo(cr.value()).message.rfind("Connection failed to", 0) == 0);
    REQUIRE(waitFor([&] { return client.hasError(TransportError::Connect, "connect immediately failed"); }));
    REQUIRE(TA::connectingCount(*client.tx) == 0);

    client.throwOnClose = false;
    SinkServer server;
    auto cr2 = client.tx->connect("127.0.0.1", server.port, TlsMode::None);
    REQUIRE(cr2.isOk());
    REQUIRE(client.tx->send(cr2.value(), "alive", 5));
    REQUIRE(waitFor([&] { return server.data() == "alive"; }));
  }
  SECTION("resolve failure")
  {
    Client client(false, [](TransportConfig &c) { c.resolveTimeout = 5000ms; });
    client.throwOnClose = true;
    REQUIRE(client.tx->start().isOk());
    auto cr = client.tx->connect("invalid host name", 5060, TlsMode::None);
    REQUIRE(cr.isOk());
    REQUIRE(waitFor([&] { return client.closesFor(cr.value()) == 1; }, 4000ms));
    REQUIRE(client.closeInfo(cr.value()).code == TransportError::Resolve);
    REQUIRE(client.closeInfo(cr.value()).message != "resolve timeout");
    REQUIRE(waitFor([&] { return client.hasError(TransportError::Resolve, "resolve failed"); }));
    REQUIRE(TA::connectingCount(*client.tx) == 0);
  }
  SECTION("resolve timeout")
  {
    Client client(false, [](TransportConfig &c) { c.resolveTimeout = 150ms; });
    client.throwOnClose = true;
    REQUIRE(client.tx->start().isOk());
    SinkServer server;

    resolvetest::PoolStall stall;
    stall.occupyWorkers();

    auto cr = client.tx->connect("localhost", server.port, TlsMode::None);
    REQUIRE(cr.isOk());
    REQUIRE(waitFor([&] { return client.closesFor(cr.value()) == 1; }));
    REQUIRE(client.closeInfo(cr.value()).code == TransportError::Resolve);
    REQUIRE(waitFor([&] { return client.hasError(TransportError::Resolve, "resolve timeout"); }));
    REQUIRE(TA::connectingCount(*client.tx) == 0);
    stall.release();
  }
}

TEST_CASE("stop() with an in-flight named-host connect + queued sends + connect inside drain onClose",
          "[tcp][registry][resolve][isolated][stop]")
{
  std::atomic<bool> innerIssued{false};
  std::atomic<bool> innerOk{false};
  std::atomic<SessionId> innerSid{0};
  Client client(false, [](TransportConfig &c) { c.resolveTimeout = 30000ms; });
  REQUIRE(client.tx->start().isOk());
  SinkServer server;

  resolvetest::PoolStall stall;
  stall.occupyWorkers();

  auto cr = client.tx->connect("localhost", server.port, TlsMode::None);
  REQUIRE(cr.isOk());
  const SessionId named = cr.value();
  REQUIRE(client.tx->send(named, "q1", 2));
  REQUIRE(client.tx->send(named, "q2", 2));
  REQUIRE(pendingConnectCount(*client.tx) == 1); // precondition: still resolving

  client.setOnCloseHook(
    [&](SessionId sid, const TransportErrorInfo &)
    {
      if (sid == named && !innerIssued.exchange(true))
      {
        auto r = client.tx->connect("127.0.0.1", server.port, TlsMode::None);
        innerOk = r.isOk();
        if (r.isOk())
        {
          innerSid = r.value();
        }
      }
    });

  client.tx->stop();

  REQUIRE(client.closesFor(named) == 1);
  REQUIRE(client.closeInfo(named).code == TransportError::ShuttingDown);
  REQUIRE(innerIssued);
  if (innerOk)
  {
    REQUIRE(client.closesFor(innerSid) == 1);
    REQUIRE(client.closeInfo(innerSid).code == TransportError::ShuttingDown);
  }
  REQUIRE(TA::connectingCount(*client.tx) == 0);
  REQUIRE(client.connectCount == 0);
}

TEST_CASE("stop() with sends queued on a connecting (inserted) sid: exactly one onClose",
          "[tcp][registry][stop]")
{
  Blackhole bh;
  if (!fillOrSkip(bh))
  {
    return;
  }
  Client client(false, [](TransportConfig &c) { c.connectTimeout = 30000ms; });
  REQUIRE(client.tx->start().isOk());

  auto cr = client.tx->connect("127.0.0.1", bh.lst.port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(client.tx->send(cr.value(), "q1", 2));
  REQUIRE(waitFor([&] { return TA::connectingCount(*client.tx) == 0; }));
  REQUIRE(client.tx->send(cr.value(), "q2", 2));

  REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
  const auto code = client.closeInfo(cr.value()).code;
  REQUIRE((code == TransportError::ShuttingDown || code == TransportError::Unknown));
  REQUIRE(client.tx->getStats().bytesOut == 0);
  REQUIRE(TA::connectingCount(*client.tx) == 0);
}

TEST_CASE("registry empty after stop/start, and a restarted engine connect-then-sends", "[tcp][registry][lifecycle]")
{
  SinkServer server;
  Client client;
  REQUIRE(client.tx->start().isOk());
  auto a = client.tx->connect("127.0.0.1", server.port, TlsMode::None);
  REQUIRE(a.isOk());
  client.tx->stop();
  REQUIRE(TA::connectingCount(*client.tx) == 0);

  REQUIRE(client.tx->start().isOk());
  REQUIRE(TA::connectingCount(*client.tx) == 0);
  auto b = client.tx->connect("127.0.0.1", server.port, TlsMode::None);
  REQUIRE(b.isOk());
  REQUIRE(client.tx->send(b.value(), "again|", 6));
  REQUIRE(waitFor([&] { return server.data() == "again|"; }));
  REQUIRE(TA::connectingCount(*client.tx) == 0);
}

// ─────────────────────────── A2.5: connect-path exception guard ───────────────────────────

TEST_CASE("connect-path exception guard: one terminal, no registry/fd/timer leak, loop survives",
          "[tcp][guard]")
{
  struct Point
  {
    const char *name;
    ConnectThrowPoint point;
    const char *host;
    bool tls;
  };
  const Point points[] = {
    {"before-insert (literal)", ConnectThrowPoint::BEFORE_INSERT_LITERAL, "127.0.0.1", false},
    {"before-insert (literal, TLS)", ConnectThrowPoint::BEFORE_INSERT_LITERAL, "127.0.0.1", true},
    {"resume-path before-insert", ConnectThrowPoint::BEFORE_INSERT_RESUME, "localhost", false},
    {"after-insert", ConnectThrowPoint::AFTER_INSERT, "127.0.0.1", false},
    {"named kickoff after pending insert", ConnectThrowPoint::NAMED_KICKOFF_AFTER_PENDING_INSERT,
     "localhost", false},
  };

  for (const auto &p : points)
  {
    SECTION(p.name)
    {
      RawListener lst;
      Client client(p.tls);
      REQUIRE(client.tx->start().isOk());
      REQUIRE(waitFor([&] { return TA::armedTimerCount(*client.tx) == 0; }));
      const std::size_t fdBaseline = countOpenFds();

      TA::injectConnectThrow(*client.tx, p.point);
      auto cr = client.tx->connect(p.host, lst.port, p.tls ? TlsMode::Client : TlsMode::None);
      REQUIRE(cr.isOk());
      REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }));
      REQUIRE(client.closeInfo(cr.value()).code == TransportError::Unknown);
      REQUIRE(client.closeInfo(cr.value()).message == "internal error");
      REQUIRE(client.connectCount == 0);
      REQUIRE(TA::connectingCount(*client.tx) == 0);
      REQUIRE(waitFor([&] { return TA::armedTimerCount(*client.tx) == 0; }));
      REQUIRE(waitFor([&] { return countOpenFds() == fdBaseline; }));
      REQUIRE_FALSE(client.tx->send(cr.value(), "x", 1));

      // Loop survives: a fresh connect completes.
      auto ok = client.tx->connect("127.0.0.1", lst.port, TlsMode::None);
      REQUIRE(ok.isOk());
      REQUIRE(waitFor([&] { return client.connectCount == 1; }));
      REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
    }
  }
}

TEST_CASE("a throwing user onClose on the guard terminal cannot kill the I/O loop", "[tcp][guard]")
{
  RawListener lst;
  Client client;
  REQUIRE(client.tx->start().isOk());
  client.throwOnClose = true;
  TA::injectConnectThrow(*client.tx, ConnectThrowPoint::BEFORE_INSERT_LITERAL);
  auto cr = client.tx->connect("127.0.0.1", lst.port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return client.closesFor(cr.value()) == 1; }));
  client.throwOnClose = false;
  REQUIRE(TA::connectingCount(*client.tx) == 0);

  auto ok = client.tx->connect("127.0.0.1", lst.port, TlsMode::None);
  REQUIRE(ok.isOk());
  REQUIRE(waitFor([&] { return client.connectCount == 1; }));
  REQUIRE(client.closesFor(cr.value()) == 1);
}

// ─────────────────────────── Inline fix: throwing user callbacks ───────────────────────────

TEST_CASE("a throwing onData and a throwing onClose do not stop the engine", "[tcp][guard][callbacks]")
{
  SinkServer server;
  server.throwOnData = true;
  server.throwOnClose = true;

  {
    Client first;
    REQUIRE(first.tx->start().isOk());
    auto a = first.tx->connect("127.0.0.1", server.port, TlsMode::None);
    REQUIRE(a.isOk());
    REQUIRE(first.tx->send(a.value(), "a|", 2));
    REQUIRE(waitFor([&] { return server.data() == "a|"; }));
    REQUIRE(first.tx->close(a.value()));
    REQUIRE(waitFor([&] { return server.closes == 1; }));
  }

  Client second;
  REQUIRE(second.tx->start().isOk());
  auto b = second.tx->connect("127.0.0.1", server.port, TlsMode::None);
  REQUIRE(b.isOk());
  REQUIRE(second.tx->send(b.value(), "b|", 2));
  REQUIRE(waitFor([&] { return server.data() == "a|b|"; }));
  REQUIRE(server.accepted == 2);
}

TEST_CASE("a throwing client onClose on a peer-close path does not stop the engine", "[tcp][guard][callbacks]")
{
  Client client;
  REQUIRE(client.tx->start().isOk());
  client.throwOnClose = true;
  SessionId first = 0;
  {
    SinkServer doomed;
    auto a = client.tx->connect("127.0.0.1", doomed.port, TlsMode::None);
    REQUIRE(a.isOk());
    first = a.value();
    REQUIRE(waitFor([&] { return client.connectCount == 1; }));
  }
  REQUIRE(waitFor([&] { return client.closesFor(first) == 1; }));
  client.throwOnClose = false;

  SinkServer server;
  auto b = client.tx->connect("127.0.0.1", server.port, TlsMode::None);
  REQUIRE(b.isOk());
  REQUIRE(client.tx->send(b.value(), "alive|", 6));
  REQUIRE(waitFor([&] { return server.data() == "alive|"; }));
}

TEST_CASE("a RunOnIo closure throwing a non-std exception does not end the I/O loop", "[tcp][guard][callbacks]")
{
  SinkServer server;
  Client client;
  REQUIRE(client.tx->start().isOk());
  iora::network::detail::EngineBase &base = *client.tx;
  REQUIRE(base.runOnIoThread([] { throw 42; }));
  auto cr = client.tx->connect("127.0.0.1", server.port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(client.tx->send(cr.value(), "after-throw|", 12));
  REQUIRE(waitFor([&] { return server.data() == "after-throw|"; }));
  REQUIRE(client.errorCount >= 1);
}

namespace
{

/// Engine whose beforeSslHandshake seam throws once (the first handshake after
/// arming): an exception escaping a session dispatch.
class ThrowingHandshakeEngine : public TcpEngine
{
public:
  using TcpEngine::TcpEngine;
  std::atomic<bool> armed{false};

protected:
  bool beforeSslHandshake(SessionId sid, const std::string &remote) override
  {
    if (armed.exchange(false))
    {
      throw std::runtime_error("seam throws inside dispatch");
    }
    return TcpEngine::beforeSslHandshake(sid, remote);
  }
};

} // namespace

TEST_CASE("an exception escaping a session dispatch closes that session once; the loop serves others",
          "[tcp][guard][dispatch]")
{
  std::string cert, key;
  if (!certsOrSkip(cert, key))
  {
    return;
  }
  SinkServer server(true, cert, key);
  ThrowingHandshakeEngine *engine = nullptr;
  Client client(true, nullptr, [&](const TransportConfig &c) {
    auto e = std::make_unique<ThrowingHandshakeEngine>(c);
    engine = e.get();
    return e;
  });
  REQUIRE(client.tx->start().isOk());

  auto survivor = client.tx->connect("127.0.0.1", server.port, TlsMode::Client);
  REQUIRE(survivor.isOk());
  REQUIRE(waitFor([&] { return client.connectCount == 1; }));

  engine->armed = true;
  auto victim = client.tx->connect("127.0.0.1", server.port, TlsMode::Client);
  REQUIRE(victim.isOk());
  REQUIRE(waitFor([&] { return client.closesFor(victim.value()) >= 1; }));
  REQUIRE(client.closeInfo(victim.value()).code == TransportError::Unknown);
  REQUIRE(client.closeInfo(victim.value()).message == "internal error");

  REQUIRE(client.tx->send(survivor.value(), "still-served|", 13));
  REQUIRE(waitFor([&] { return server.data() == "still-served|"; }));
  REQUIRE(client.stopAndCountCloses(victim.value()) == 1);
  REQUIRE(client.connectCount == 1);
}

TEST_CASE("throwing test hooks are swallowed: events still dispatch, the session establishes",
          "[tcp][guard][dispatch]")
{
  SinkServer server;
  Client client;
  TA::setSessionEventFilterHook(*client.tx, [](SessionId, std::uint32_t) -> std::uint32_t {
    throw std::runtime_error("filter throws");
  });
  TA::setBeforeTcpEstablishedHook(*client.tx, [](SessionId) { throw std::runtime_error("hook throws"); });
  REQUIRE(client.tx->start().isOk());
  auto cr = client.tx->connect("127.0.0.1", server.port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(client.tx->send(cr.value(), "hooked|", 7));
  REQUIRE(waitFor([&] { return server.data() == "hooked|"; }));
  REQUIRE(client.connectCount == 1);
  REQUIRE(client.closeCount == 0);
}

// ─────────────────────────── A9.4: backpressure ───────────────────────────

TEST_CASE("TLS handshake-queue burst > cap: exactly one onClose(WriteBackpressure, ENOBUFS) at Open, no bytes sent",
          "[tcp][tls][backpressure]")
{
  std::string cert;
  std::string key;
  if (!certsOrSkip(cert, key))
  {
    return;
  }
  std::atomic<SessionId> heldSid{0};
  std::atomic<bool> hold{false};
  SinkServer server(true, cert, key);
  Client client(true, [](TransportConfig &c) { c.maxWriteQueue = 4; });
  // Freeze the session in its TLS handshake phase: from TCP-established on, every
  // epoll event of the sid is held back until released.
  TA::setBeforeTcpEstablishedHook(*client.tx, [&](SessionId sid) {
    heldSid = sid;
    hold = true;
  });
  TA::setSessionEventFilterHook(*client.tx, [&](SessionId sid, std::uint32_t ev) -> std::uint32_t {
    return (hold.load() && sid == heldSid.load()) ? 0u : ev;
  });
  REQUIRE(client.tx->start().isOk());

  auto cr = client.tx->connect("127.0.0.1", server.port, TlsMode::Client);
  REQUIRE(cr.isOk());
  const SessionId sid = cr.value();
  REQUIRE(waitFor([&] { return heldSid.load() == sid; }));
  for (int i = 0; i < 10; ++i)
  {
    REQUIRE(client.tx->send(sid, "burst|", 6));
  }
  bool present = false;
  REQUIRE(runOnIo(*client.tx, [&] { present = TA::hasSession(*client.tx, sid); }));
  REQUIRE(present);
  REQUIRE(client.closesFor(sid) == 0);

  // Release: re-derive the epoll interest (re-arms the held events) so the
  // handshake completes.
  hold = false;
  REQUIRE(client.tx->setReadEnabled(sid, true));
  REQUIRE(waitFor([&] { return client.closesFor(sid) >= 1; }, 5000ms));
  REQUIRE(client.stopAndCountCloses(sid) == 1);
  const auto info = client.closeInfo(sid);
  REQUIRE(info.code == TransportError::WriteBackpressure);
  REQUIRE(info.sysErrno == ENOBUFS);
  REQUIRE(client.connectCount == 0);
  REQUIRE(client.tx->getStats().bytesOut == 0);
  REQUIRE(TA::connectingCount(*client.tx) == 0);
  REQUIRE(server.data().empty());
}

TEST_CASE("named-host pending-buffer burst > cap: exactly one onClose(WriteBackpressure, ENOBUFS), no leak",
          "[tcp][backpressure][resolve][isolated]")
{
  for (bool tls : {false, true})
  {
    SECTION(tls ? "TLS" : "TCP")
    {
      std::string cert;
      std::string key;
      if (tls && !certsOrSkip(cert, key))
      {
        return;
      }
      SinkServer server(tls, cert, key);
      Client client(tls, [](TransportConfig &c) {
        c.resolveTimeout = 30000ms;
        c.maxWriteQueue = 3;
      });
      REQUIRE(client.tx->start().isOk());

      resolvetest::PoolStall stall;
      stall.occupyWorkers();

      auto cr = client.tx->connect("localhost", server.port, tls ? TlsMode::Client : TlsMode::None);
      REQUIRE(cr.isOk());
      for (int i = 0; i < 8; ++i)
      {
        REQUIRE(client.tx->send(cr.value(), "pend|", 5));
      }
      REQUIRE(pendingConnectCount(*client.tx) == 1);
      REQUIRE(client.closesFor(cr.value()) == 0);

      stall.release();
      REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 5000ms));
      REQUIRE(pendingConnectCount(*client.tx) == 0);
      REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
      REQUIRE(client.closeInfo(cr.value()).code == TransportError::WriteBackpressure);
      REQUIRE(client.closeInfo(cr.value()).sysErrno == ENOBUFS);
      REQUIRE(client.connectCount == 0);
      REQUIRE(client.tx->getStats().bytesOut == 0);
      REQUIRE(TA::connectingCount(*client.tx) == 0);
      REQUIRE(server.data().empty());
    }
  }
}

TEST_CASE("setup overflow toward a blackhole keeps the connect running: one onClose(Connect, ETIMEDOUT)",
          "[tcp][backpressure][setup]")
{
  Blackhole bh;
  if (!fillOrSkip(bh))
  {
    return;
  }
  Client client(false, [](TransportConfig &c) {
    c.connectTimeout = 400ms;
    c.maxWriteQueue = 2;
  });
  REQUIRE(client.tx->start().isOk());
  auto cr = client.tx->connect("127.0.0.1", bh.lst.port, TlsMode::None);
  REQUIRE(cr.isOk());
  for (int i = 0; i < 6; ++i)
  {
    REQUIRE(client.tx->send(cr.value(), "over|", 5));
  }
  bool present = false;
  REQUIRE(runOnIo(*client.tx, [&] { present = TA::hasSession(*client.tx, cr.value()); }));
  REQUIRE(present); // the overflowing sends were processed and the connect runs on
  REQUIRE(client.closesFor(cr.value()) == 0);
  REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 3000ms));
  REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
  REQUIRE(client.closeInfo(cr.value()).code == TransportError::Connect);
  REQUIRE(client.closeInfo(cr.value()).sysErrno == ETIMEDOUT);
  REQUIRE(client.tx->getStats().bytesOut == 0);
  REQUIRE(TA::connectingCount(*client.tx) == 0);
}

TEST_CASE("setup overflow toward a slow-accepting listener: one onClose(WriteBackpressure, ENOBUFS) at establishment",
          "[tcp][backpressure][setup]")
{
  Blackhole bh;
  if (!fillOrSkip(bh))
  {
    return;
  }
  Client client(false, [](TransportConfig &c) {
    c.connectTimeout = 5000ms;
    c.maxWriteQueue = 2;
  });
  REQUIRE(client.tx->start().isOk());
  auto cr = client.tx->connect("127.0.0.1", bh.lst.port, TlsMode::None);
  REQUIRE(cr.isOk());
  for (int i = 0; i < 6; ++i)
  {
    REQUIRE(client.tx->send(cr.value(), "slow|", 5));
  }
  bool present = false;
  REQUIRE(runOnIo(*client.tx, [&] { present = TA::hasSession(*client.tx, cr.value()); }));
  REQUIRE(present);
  REQUIRE(client.closesFor(cr.value()) == 0);

  std::vector<int> accepted;
  for (int c = acceptWithin(bh.lst.fd, 0ms); c >= 0; c = acceptWithin(bh.lst.fd, 0ms))
  {
    accepted.push_back(c);
  }
  REQUIRE_FALSE(accepted.empty());

  REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 4500ms));
  REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
  REQUIRE(client.closeInfo(cr.value()).code == TransportError::WriteBackpressure);
  REQUIRE(client.closeInfo(cr.value()).sysErrno == ENOBUFS);
  REQUIRE(client.connectCount == 0);
  REQUIRE(client.tx->getStats().bytesOut == 0);
  REQUIRE(TA::connectingCount(*client.tx) == 0);
  for (int c : accepted)
  {
    ::close(c);
  }
}

TEST_CASE("established TCP overflow closes WriteBackpressure (sysErrno 0) even with closeOnBackpressure=false",
          "[tcp][backpressure][established]")
{
  RawListener lst;
  Client client(false, [](TransportConfig &c) {
    c.maxWriteQueue = 4;
    c.closeOnBackpressure = false;
    c.soSndBuf = 4096;
  });
  REQUIRE(client.tx->start().isOk());
  auto cr = client.tx->connect("127.0.0.1", lst.port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return client.connectCount == 1; }));

  std::vector<std::uint8_t> chunk(64 * 1024, 0x5a);
  for (int i = 0; i < 2000 && client.closesFor(cr.value()) == 0; ++i)
  {
    if (!client.tx->send(cr.value(), chunk.data(), chunk.size()))
    {
      break;
    }
  }
  REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 5000ms));
  REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
  REQUIRE(client.closeInfo(cr.value()).code == TransportError::WriteBackpressure);
  REQUIRE(client.closeInfo(cr.value()).sysErrno == 0);
  REQUIRE(client.tx->getStats().backpressureCloses == 1);
}

TEST_CASE("overflow never drops a partial-write remainder: received bytes are an exact prefix",
          "[tcp][backpressure][established]")
{
  RawListener lst;
  Client client(false, [](TransportConfig &c) {
    c.maxWriteQueue = 2;
    c.closeOnBackpressure = false;
    c.soSndBuf = 4096;
  });
  REQUIRE(client.tx->start().isOk());
  auto cr = client.tx->connect("127.0.0.1", lst.port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return client.connectCount == 1; }));
  int peer = acceptWithin(lst.fd, 2000ms);
  REQUIRE(peer >= 0);
  int rcv = 4096;
  ::setsockopt(peer, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));

  const std::size_t chunkSize = 3000;
  std::size_t offered = 0;
  for (int i = 0; i < 20000 && client.closesFor(cr.value()) == 0; ++i)
  {
    const std::string chunk = patternPayload(offered, chunkSize);
    if (!client.tx->send(cr.value(), chunk.data(), chunk.size()))
    {
      break;
    }
    offered += chunkSize;
  }
  REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 5000ms));
  REQUIRE(client.closeInfo(cr.value()).code == TransportError::WriteBackpressure);

  std::vector<std::uint8_t> rx;
  for (;;)
  {
    pollfd p{peer, POLLIN, 0};
    if (::poll(&p, 1, 2000) <= 0)
    {
      break;
    }
    std::uint8_t buf[65536];
    ssize_t n = ::recv(peer, buf, sizeof(buf), 0);
    if (n <= 0)
    {
      break;
    }
    rx.insert(rx.end(), buf, buf + n);
  }
  ::close(peer);

  REQUIRE_FALSE(rx.empty());
  REQUIRE(rx.size() <= offered);
  std::size_t firstMismatch = rx.size();
  for (std::size_t i = 0; i < rx.size(); ++i)
  {
    if (rx[i] != patternByte(i))
    {
      firstMismatch = i;
      break;
    }
  }
  REQUIRE(firstMismatch == rx.size());
}
