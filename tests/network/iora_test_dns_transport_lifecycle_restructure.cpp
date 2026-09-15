// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_dns_transport_lifecycle_restructure.cpp
/// \brief Lifecycle-teardown RESTRUCTURE regression tests for DnsTransport
///        (tracker 2026-09-13-11): atomic lifecycle state + atomic-published
///        config/transport/timer handles + completion latch with a member-independent
///        thread-identity exemption.
///
/// WHITE-BOX + deterministic, via the DnsTransportTestAccess friend seam. Pins
/// the frozen design (tracker fix_proposal INV-1..5, R3-fixed):
///   - A (deadlock): stop() releases _stateMutex BEFORE joining workers; a re-entrant
///     stop()/updateConfig() fired from THE EXACT worker thread the outer stop() joins
///     must be EXEMPTED (return immediately, never park on _stateCv) for EACH of the
///     three join arms (cleanup / I/O / timer) AND for a driver-thread step-7 callback.
///     Each probe HANGS under a naive/unexempted design and completes after the fix; a
///     bounded wait that elapses is a FAILURE (never raised to mask). Mutation-verified.
///   - C (races): config/handle reads are atomic-published snapshots; a query issued
///     concurrently with stop()/updateConfig() sends-or-fails-clean, never orphans
///     (TSan-verified in the C-race probe target).
///   - H-1: start() that throws during bring-up settles to Stopped + notifies (no
///     stranded Starting hanging a settled-predicate waiter).
///   - H-2: stop() fires collected failures BEFORE publishing Stopped (no dtor/CV
///     destroy overlap).
///   - H (resurrect): start() immediately after a cleanup-thread-driven self-stop leaves
///     exactly one cleanup thread (generation token).
///   - NEW-6 (orphan): a query registering concurrently with stop()'s drain completes or
///     fails cleanly; a blocked sync query() waiter wakes promptly with 'Transport stopped'.
///
/// The friend seam DnsTransportTestAccess is defined here and befriended in
/// dns_transport.hpp. The A-arm deadlock probes and H-2 are mutation-verified (they FAIL
/// against an unexempted / Stopped-before-fire design); the C-race and resurrect probes are
/// TSan targets (this executable is on IORA_SANITIZED_TEST_TARGETS).

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "MockDnsServer.hpp"
#include "dns_transport_test_access.hpp" // shared white-box seam (SM-M1) + completesWithin

#include "iora/network/dns/dns_message.hpp"
#include "iora/network/dns/dns_types.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace iora::network::dns;
using LA = iora::network::dns::DnsTransportTestAccess;

namespace
{
constexpr const char *SERVER_A = "127.0.0.1";
constexpr std::uint16_t PORT_A = 5311;
constexpr std::uint16_t ID_A = 0x4141;
constexpr std::uint16_t ID_B = 0x4242;

DnsConfig makeCfg()
{
  DnsConfig cfg; // default transportMode == Both; white-box tests do not start transports.
  cfg.servers.push_back(DnsServer::fromString("127.0.0.1:53535"));
  return cfg;
}
} // namespace

// =============================================================================
// A (deadlock) — the completion-latch GATE. Each probe drives a re-entrant stop()
// from THE EXACT worker thread an EXTERNAL outer stop() joins, and requires the
// exemption to short-circuit the _stateCv wait. The `while (t->isRunning())` spin
// guarantees the outer stop() won the CAS (is the teardown DRIVER, state==Stopping)
// BEFORE the worker re-enters — the exact interleaving R3-C1 exposed. Each HANGS
// under a naive/unexempted design; a bounded wait that elapses is a FAILURE.
// =============================================================================

// R3-C1 cleanup arm: the exemption identity must come from the STAMPED, member-independent
// _cleanupThreadId, NOT _cleanupThread.get_id() (which stop() step 2 moves out before
// releasing _stateMutex). A re-entrant stop() on the cleanup thread the outer stop() joins
// must return immediately, not park on _stateCv.
TEST_CASE("dns lifecycle: A cleanup-arm cross-thread re-entrant stop() is exempt (R3-C1)",
          "[dns][lifecycle][running]")
{
  auto t = std::make_shared<DnsTransport>(makeCfg());
  LA::setCleanupInterval(*t, std::chrono::milliseconds(10));
  LA::startCleanupOnly(*t); // real cleanup thread; state == Running

  std::atomic<bool> reentered{false};
  auto entered = std::make_shared<std::promise<void>>();
  auto enteredFut = entered->get_future();
  auto gate = std::make_shared<std::promise<void>>();
  auto gateFut = std::make_shared<std::shared_future<void>>(gate->get_future());

  // Expired + retry-exhausted -> the cleanup sweep FAILS+fires this callback ON the cleanup
  // thread W. W signals entry, holds until the outer stop() is the driver, then re-enters.
  LA::registerPending(
    *t, ID_A, SERVER_A, PORT_A,
    [t, entered, gateFut, &reentered](const DnsResult &, const std::exception_ptr &)
    {
      entered->set_value();
      gateFut->wait();
      t->stop();              // re-entrant stop() ON the cleanup thread W
      reentered.store(true);  // reached ONLY if the exemption returned (no CV park)
    },
    LA::configRetryCount(*t), std::chrono::milliseconds(1), std::chrono::milliseconds(60000));

  REQUIRE(enteredFut.wait_for(std::chrono::seconds(3)) == std::future_status::ready);

  auto aDone = std::make_shared<std::promise<void>>();
  auto aFut = aDone->get_future();
  std::thread a([t, aDone]() { t->stop(); aDone->set_value(); });

  while (t->isRunning()) // outer stop() CAS'd Running->Stopping: it is now the driver
  {
    std::this_thread::yield();
  }
  REQUIRE(LA::isStopping(*t));
  gate->set_value(); // release W to re-enter stop() while the driver is mid-teardown

  if (aFut.wait_for(std::chrono::seconds(5)) == std::future_status::ready)
  {
    a.join();
    CHECK(reentered.load());
    CHECK(LA::isStopped(*t));
  }
  else
  {
    a.detach(); // deadlocked (the R3-C1 bug); leak to avoid hanging CI
    FAIL("cleanup-arm re-entrant stop() parked on _stateCv -- R3-C1 deadlock reborn");
  }
}

// Timer arm: the exemption for a re-entrant stop() on the TimerService thread comes from
// loadTimer()->isOnTimerThread() on the LIVE handle (route B keeps it live until step 8).
TEST_CASE("dns lifecycle: A timer-arm cross-thread re-entrant stop() is exempt (isOnTimerThread)",
          "[dns][lifecycle][running]")
{
  auto t = std::make_shared<DnsTransport>(makeCfg());
  LA::setRunning(*t, true); // state Running; timer service live (ctor); no transports

  std::atomic<bool> reentered{false};
  auto entered = std::make_shared<std::promise<void>>();
  auto enteredFut = entered->get_future();
  auto gate = std::make_shared<std::promise<void>>();
  auto gateFut = std::make_shared<std::shared_future<void>>(gate->get_future());

  LA::scheduleOnTimer(*t, std::chrono::milliseconds(5),
                      [t, entered, gateFut, &reentered]()
                      {
                        entered->set_value(); // ON the timer thread
                        gateFut->wait();
                        t->stop();             // re-entrant stop() ON the timer thread
                        reentered.store(true);
                      });

  REQUIRE(enteredFut.wait_for(std::chrono::seconds(3)) == std::future_status::ready);

  auto aDone = std::make_shared<std::promise<void>>();
  auto aFut = aDone->get_future();
  std::thread a([t, aDone]() { t->stop(); aDone->set_value(); });

  while (t->isRunning())
  {
    std::this_thread::yield();
  }
  gate->set_value();

  if (aFut.wait_for(std::chrono::seconds(5)) == std::future_status::ready)
  {
    a.join();
    CHECK(reentered.load());
    CHECK(LA::isStopped(*t));
  }
  else
  {
    a.detach();
    FAIL("timer-arm re-entrant stop() parked on _stateCv -- isOnTimerThread exemption failed");
  }
}

// I/O arm: the exemption for a re-entrant stop() on the transport I/O thread comes from
// loadUdp()->isOnIoThread() on the LIVE handle. Uses a real UDP transport + a mock server so
// the completion callback genuinely fires on the engine I/O thread.
TEST_CASE("dns lifecycle: A IO-arm cross-thread re-entrant stop() is exempt (isOnIoThread)",
          "[dns][lifecycle][running]")
{
  constexpr std::uint16_t MOCK_PORT = 15412; // -j1-serialized (fixed port)
  MockDnsServer::Config scfg;
  scfg.udpPort = MOCK_PORT;
  scfg.tcpPort = MOCK_PORT;
  scfg.enableTcp = false;
  scfg.enableUdp = true;
  scfg.defaultDelay = std::chrono::milliseconds(0);
  MockDnsServer server(scfg);
  REQUIRE(server.start());
  server.addRecord({"io.example.test", "A", "192.0.2.55", 3600});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  DnsConfig cfg;
  cfg.setServers({std::string("127.0.0.1:") + std::to_string(MOCK_PORT)});
  cfg.transportMode = DnsTransportMode::UDP; // single transport -> single I/O-thread arm
  cfg.timeout = std::chrono::milliseconds(3000);
  cfg.retryCount = 0;
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  std::atomic<bool> reentered{false};
  std::atomic<bool> onIo{false};
  auto entered = std::make_shared<std::promise<void>>();
  auto enteredFut = entered->get_future();
  auto gate = std::make_shared<std::promise<void>>();
  auto gateFut = std::make_shared<std::shared_future<void>>(gate->get_future());

  t->queryAsync(
    DnsQuestion("io.example.test", DnsType::A, DnsClass::IN),
    [t, entered, gateFut, &reentered, &onIo](const DnsResult &, const std::exception_ptr &)
    {
      onIo.store(LA::udpOnIoThread(*t)); // non-vacuous: callback truly on the I/O thread
      entered->set_value();
      gateFut->wait();
      t->stop();              // re-entrant stop() ON the transport I/O thread
      reentered.store(true);
    },
    "127.0.0.1", MOCK_PORT);

  REQUIRE(enteredFut.wait_for(std::chrono::seconds(5)) == std::future_status::ready);

  auto aDone = std::make_shared<std::promise<void>>();
  auto aFut = aDone->get_future();
  std::thread a([t, aDone]() { t->stop(); aDone->set_value(); });

  while (t->isRunning())
  {
    std::this_thread::yield();
  }
  gate->set_value();

  if (aFut.wait_for(std::chrono::seconds(5)) == std::future_status::ready)
  {
    a.join();
    CHECK(reentered.load());
    CHECK(onIo.load());
    CHECK(LA::isStopped(*t));
  }
  else
  {
    a.detach();
    FAIL("IO-arm re-entrant stop() parked on _stateCv -- isOnIoThread exemption failed");
  }

  server.stop();
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

// Driver arm: the teardown driver re-enters its OWN stop() from a failure callback fired at
// step 7 (before Stopped is published). It must be exempt via _stoppingThreadId. This is the
// one A-arm that is SAME-thread re-entry (no separate worker to coordinate), so it uses the
// shared completesWithin() helper directly; the cleanup/timer/IO arms cannot — they need the
// concurrent test-thread spin+gate handshake that completesWithin's run-to-completion precludes.
TEST_CASE("dns lifecycle: A driver-thread step-7 callback re-enters stop() and is exempt",
          "[dns][lifecycle]")
{
  auto t = std::make_shared<DnsTransport>(makeCfg());
  LA::setRunning(*t, true); // no transports; drive the drain+fire path

  std::atomic<bool> reentered{false};
  LA::registerPending(*t, ID_A, SERVER_A, PORT_A,
                      [t, &reentered](const DnsResult &, const std::exception_ptr &)
                      {
                        t->stop();             // driver re-enters its own stop() at step 7
                        reentered.store(true);
                      },
                      0, std::chrono::milliseconds(5000), std::chrono::milliseconds(0));

  // stop() runs on completesWithin's worker (which becomes the driver); the step-7 callback
  // fires on that same thread and re-enters stop() -> must be exempt (return), not park.
  const bool ok = completesWithin(std::chrono::seconds(5), [t]() { t->stop(); });
  if (!ok)
  {
    FAIL("driver step-7 re-entrant stop() parked -- _stoppingThreadId exemption failed");
  }
  CHECK(reentered.load());
  CHECK(LA::isStopped(*t));
}

// =============================================================================
// H-1 / H-2 — lifecycle-transition correctness.
// =============================================================================

// H-1 (start-failure settle): a start() that throws during bring-up must settle _state to
// Stopped + notify, NEVER strand Starting (a stranded Starting hangs every settled-predicate
// waiter forever). A stack-owned DnsTransport makes start()'s shared_from_this() throw
// std::bad_weak_ptr deterministically inside the bring-up try-block.
TEST_CASE("dns lifecycle: H-1 start() failure settles to Stopped (no stranded Starting)",
          "[dns][lifecycle]")
{
  DnsConfig cfg = makeCfg();
  DnsTransport t(cfg); // NOT shared_ptr-owned -> start()'s shared_from_this() throws
  bool threw = false;
  try
  {
    t.start();
  }
  catch (const DnsTransportException &)
  {
    threw = true;
  }
  REQUIRE(threw);
  CHECK(LA::isStopped(t));      // settled, NOT stranded in Starting
  CHECK_FALSE(t.isRunning());
  // A subsequent stop() returns immediately (state already Stopped, step-1 early return) —
  // proving no waiter hangs. Called directly (not via completesWithin, which would detach a
  // worker capturing this stack-owned `t` by reference — CP-LOW-2).
  t.stop();
  CHECK(LA::isStopped(t));
}

// H-1 (settled predicate): concurrent start()/stop() must always settle — a stop() that
// observes Starting waits for a SETTLED state (Running||Stopped) then re-evaluates (never a
// bare "until Stopped" target, which hangs when this same start() drives Starting->Running).
TEST_CASE("dns lifecycle: H-1 concurrent start()/stop() always settles (bounded)",
          "[dns][lifecycle][running]")
{
  for (int iter = 0; iter < 30; ++iter)
  {
    DnsConfig cfg;
    cfg.setServers({std::string("127.0.0.1:53535")});
    cfg.transportMode = DnsTransportMode::UDP; // real transport, connect deferred (no server)
    auto t = std::make_shared<DnsTransport>(cfg);

    const bool settled = completesWithin(std::chrono::seconds(5),
                                         [t]()
                                         {
                                           std::thread s([t]() { try { t->start(); } catch (...) {} });
                                           std::thread p([t]() { t->stop(); });
                                           s.join();
                                           p.join();
                                         });
    REQUIRE(settled);
    t->stop(); // idempotent; must not hang
    CHECK(LA::isStopped(*t));
  }
}

// H-2 (fire-before-Stopped ordering): the terminal Stopped store + notify happen AFTER the
// collected failure callbacks fire (step 7 before step 8). A waiter released by the latch
// therefore observes a fully torn-down object (callbacks complete). If Stopped were published
// first, the released waiter could observe an in-flight callback.
TEST_CASE("dns lifecycle: H-2 latch-released waiter observes completed callbacks",
          "[dns][lifecycle][running]")
{
  auto t = std::make_shared<DnsTransport>(makeCfg());
  LA::setRunning(*t, true);

  std::atomic<bool> callbackDone{false};
  LA::registerPending(*t, ID_A, SERVER_A, PORT_A,
                      [&callbackDone](const DnsResult &, const std::exception_ptr &)
                      {
                        std::this_thread::sleep_for(std::chrono::milliseconds(50)); // widen window
                        callbackDone.store(true);
                      },
                      0, std::chrono::milliseconds(5000), std::chrono::milliseconds(0));

  auto aDone = std::make_shared<std::promise<void>>();
  std::thread a([t, aDone]() { t->stop(); aDone->set_value(); });

  while (t->isRunning()) // A is now the driver; B will observe Stopping and wait on the latch
  {
    std::this_thread::yield();
  }

  std::atomic<bool> bSawDone{false};
  auto bDone = std::make_shared<std::promise<void>>();
  auto bFut = bDone->get_future();
  std::thread b([t, &bSawDone, &callbackDone, bDone]()
                {
                  t->stop();                          // waits on the latch until Stopped
                  bSawDone.store(callbackDone.load()); // Stopped => callbacks already fired
                  bDone->set_value();
                });

  REQUIRE(bFut.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
  a.join();
  b.join();
  CHECK(callbackDone.load());
  CHECK(bSawDone.load()); // H-2: Stopped published strictly AFTER the callback fired
}

// =============================================================================
// C (races) — TSan target. Run under `setarch $(uname -m) -R` per the WSL2 rule.
// =============================================================================

// queryAsync (reads _config via getNextServer/prepareQuery + the transport handles) races
// updateConfig (writes _config — the folded 2026-09-13-4 servers-vector race) and stop()
// (writes the handles). All are atomic-published, so this is race-clean under TSan; under a
// normal build it guards against teardown crashes/hangs.
TEST_CASE("dns lifecycle: C config/handle reads race stop()/updateConfig() cleanly (TSan)",
          "[dns][lifecycle][running]")
{
  constexpr std::uint16_t MOCK_PORT = 15414; // -j1-serialized
  MockDnsServer::Config scfg;
  scfg.udpPort = MOCK_PORT;
  scfg.tcpPort = MOCK_PORT;
  scfg.enableTcp = false;
  scfg.enableUdp = true;
  scfg.defaultDelay = std::chrono::milliseconds(20);
  MockDnsServer server(scfg);
  REQUIRE(server.start());
  server.addRecord({"race.example.test", "A", "192.0.2.7", 3600});
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  for (int iter = 0; iter < 8; ++iter)
  {
    DnsConfig cfg;
    cfg.setServers({std::string("127.0.0.1:") + std::to_string(MOCK_PORT)});
    cfg.transportMode = DnsTransportMode::UDP;
    cfg.timeout = std::chrono::milliseconds(50);
    cfg.retryCount = 1;
    auto t = std::make_shared<DnsTransport>(cfg);
    t->start();

    std::atomic<bool> go{false};
    std::vector<std::thread> readers;
    for (int r = 0; r < 4; ++r)
    {
      readers.emplace_back(
        [t, &go]()
        {
          while (!go.load())
          {
            std::this_thread::yield();
          }
          for (int q = 0; q < 20; ++q)
          {
            // Empty server -> getNextServer() reads _config.servers concurrently with the
            // updateConfig() writer (the 2026-09-13-4 torn-vector race the fold closes).
            t->queryAsync(DnsQuestion("race.example.test", DnsType::A, DnsClass::IN),
                          [](const DnsResult &, const std::exception_ptr &) {});
          }
        });
    }
    std::thread cfgWriter(
      [t, &go, MOCK_PORT]()
      {
        while (!go.load())
        {
          std::this_thread::yield();
        }
        for (int u = 0; u < 40; ++u)
        {
          DnsConfig c;
          c.transportMode = DnsTransportMode::UDP;
          c.setServers({std::string("127.0.0.1:") + std::to_string(MOCK_PORT),
                        std::string("127.0.0.2:") + std::to_string(MOCK_PORT)});
          c.timeout = std::chrono::milliseconds(50);
          t->updateConfig(c);
        }
      });

    go.store(true);
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
    t->stop(); // writes the handles while readers snapshot them
    for (auto &th : readers)
    {
      th.join();
    }
    cfgWriter.join();
    CHECK_FALSE(t->isRunning());
  }
  server.stop();
  std::this_thread::sleep_for(std::chrono::milliseconds(150));
}

// C (races) — TCP variant (CP-MED-1): the TCP-path _config reader handleTcpData
// (_config->maxTcpBufferSize) is exercised concurrently with updateConfig() mutating exactly
// that field. Complements the UDP C-race probe so both transport-mode config readers are raced.
TEST_CASE("dns lifecycle: C TCP handleTcpData _config reader races updateConfig cleanly (TSan)",
          "[dns][lifecycle][running]")
{
  constexpr std::uint16_t MOCK_PORT = 15416; // -j1-serialized
  MockDnsServer::Config scfg;
  scfg.udpPort = MOCK_PORT;
  scfg.tcpPort = MOCK_PORT;
  scfg.enableTcp = true;
  scfg.enableUdp = false;
  scfg.defaultDelay = std::chrono::milliseconds(10);
  MockDnsServer server(scfg);
  REQUIRE(server.start());
  server.addRecord({"tcprace.example.test", "A", "192.0.2.9", 3600});
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  for (int iter = 0; iter < 4; ++iter)
  {
    DnsConfig cfg;
    cfg.setServers({std::string("127.0.0.1:") + std::to_string(MOCK_PORT)});
    cfg.transportMode = DnsTransportMode::TCP;
    cfg.timeout = std::chrono::milliseconds(100);
    cfg.retryCount = 0;
    auto t = std::make_shared<DnsTransport>(cfg);
    t->start();

    std::atomic<bool> go{false};
    std::vector<std::thread> readers;
    for (int r = 0; r < 3; ++r)
    {
      readers.emplace_back(
        [t, &go, MOCK_PORT]()
        {
          while (!go.load())
          {
            std::this_thread::yield();
          }
          for (int q = 0; q < 15; ++q)
          {
            t->queryAsync(DnsQuestion("tcprace.example.test", DnsType::A, DnsClass::IN),
                          [](const DnsResult &, const std::exception_ptr &) {}, "127.0.0.1",
                          MOCK_PORT);
          }
        });
    }
    std::thread cfgWriter(
      [t, &go, MOCK_PORT]()
      {
        while (!go.load())
        {
          std::this_thread::yield();
        }
        for (int u = 0; u < 30; ++u)
        {
          DnsConfig c;
          c.transportMode = DnsTransportMode::TCP;
          c.setServers({std::string("127.0.0.1:") + std::to_string(MOCK_PORT)});
          c.timeout = std::chrono::milliseconds(100);
          c.maxTcpBufferSize = (u % 2) ? 4096u : 8192u; // the field handleTcpData reads
          t->updateConfig(c);
        }
      });

    go.store(true);
    std::this_thread::sleep_for(std::chrono::milliseconds(20)); // let TCP responses flow
    t->stop();
    for (auto &th : readers)
    {
      th.join();
    }
    cfgWriter.join();
    CHECK_FALSE(t->isRunning());
  }
  server.stop();
  std::this_thread::sleep_for(std::chrono::milliseconds(150));
}

// =============================================================================
// NEW-6 (registration gate / orphan-on-stop) and H (resurrect generation).
// =============================================================================

// NEW-6 (async register-vs-drain, CP-MED-2): every async query issued concurrently with stop()
// must have its callback fired EXACTLY once — refused by the registration gate, drained by
// stop(), or send-failed — never orphaned. Counts issued vs fired and asserts equality.
TEST_CASE("dns lifecycle: NEW-6 every async query racing stop()'s drain fires (no orphan)",
          "[dns][lifecycle][running]")
{
  for (int iter = 0; iter < 8; ++iter)
  {
    DnsConfig cfg;
    cfg.setServers({std::string("127.0.0.1:9")}); // discard port: no responder
    cfg.transportMode = DnsTransportMode::UDP;
    cfg.timeout = std::chrono::milliseconds(5000);
    cfg.retryCount = 0;
    auto t = std::make_shared<DnsTransport>(cfg);
    t->start();

    constexpr int N = 8;
    std::atomic<int> fired{0};
    std::atomic<bool> go{false};
    std::vector<std::thread> issuers;
    for (int i = 0; i < N; ++i)
    {
      // Distinct black-hole server per issuer -> distinct session, so this test races
      // registration-vs-drain (the NEW-6 property) WITHOUT concurrent same-session sends
      // (which would incidentally exercise an unrelated pre-existing transport-engine race).
      std::string server = "127.0.0." + std::to_string(i + 1) + ":9";
      issuers.emplace_back(
        [t, &fired, &go, server]()
        {
          while (!go.load())
          {
            std::this_thread::yield();
          }
          t->queryAsync(DnsQuestion("nope.example.test", DnsType::A, DnsClass::IN),
                        [&fired](const DnsResult &, const std::exception_ptr &)
                        { fired.fetch_add(1, std::memory_order_relaxed); },
                        server);
        });
    }
    go.store(true);
    std::this_thread::sleep_for(std::chrono::milliseconds(2)); // some register before stop
    t->stop();                                                 // drains -> fires registered queries
    for (auto &th : issuers)
    {
      th.join();
    }
    // Every issued query fires exactly once across all paths -> no orphan.
    for (int w = 0; w < 200 && fired.load() < N; ++w)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CHECK(fired.load() == N);
    CHECK_FALSE(t->isRunning());
  }
}

// A blocked sync query() with a long timeout must be woken PROMPTLY by a concurrent stop()'s
// drain (well under the maxWaitTime), not left to time out — the -7 orphan symptom the
// registration gate + drain close.
TEST_CASE("dns lifecycle: NEW-6 concurrent stop() wakes a blocked sync query() promptly",
          "[dns][lifecycle][running]")
{
  DnsConfig cfg;
  cfg.setServers({std::string("127.0.0.1:9")}); // discard port: no DNS responder
  cfg.transportMode = DnsTransportMode::UDP;
  cfg.timeout = std::chrono::milliseconds(30000); // long -> a full block would be ~30 s
  cfg.retryCount = 0;
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  auto started = std::make_shared<std::promise<void>>();
  auto startedFut = started->get_future();
  std::atomic<bool> threw{false};
  auto qDone = std::make_shared<std::promise<void>>();
  auto qFut = qDone->get_future();
  std::thread q(
    [t, started, &threw, qDone]()
    {
      started->set_value();
      try
      {
        t->query(DnsQuestion("nope.example.test", DnsType::A, DnsClass::IN));
      }
      catch (const std::exception &)
      {
        threw.store(true);
      }
      qDone->set_value();
    });

  startedFut.wait();
  std::this_thread::sleep_for(std::chrono::milliseconds(50)); // ensure it is parked in wait_for
  const auto before = std::chrono::steady_clock::now();
  t->stop(); // drains + fails the in-flight sync query
  REQUIRE(qFut.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
  const auto elapsed = std::chrono::steady_clock::now() - before;
  q.join();

  CHECK(threw.load());
  CHECK(elapsed < std::chrono::seconds(3)); // woken by the drain, not the 30 s timeout
}

// H (resurrect generation) — DETERMINISTIC (TS-M1): a cleanup-thread-driven self-stop detaches
// sweeper #1; an immediate restart mints sweeper #2 and BUMPS the generation. The stale detached
// #1 must observe the generation mismatch and exit rather than loop as a second sweeper.
//
// The self-stop callback HOLDS #1 alive (blocked in the callback, still counted) until the test
// releases it — so the two-sweeper overlap is FORCED deterministically (assert count==2), not
// left to scheduling. The test then proves #1 exits (count settles to exactly 1). Against a
// broken generation guard (#1 checks only _cleanupRunning, which the restart re-set true) #1
// would loop forever and count would stay at 2 -> the settle-to-1 CHECK fails (mutation-caught) —
// closing the "count==1 could be the stale-alone window" false-pass. Retriable queries on both
// sweepers exercise retryQuery->dis(_rng) across the overlap (TS-HIGH-1 _rngMutex, TSan target).
TEST_CASE("dns lifecycle: H resurrect keeps exactly one live cleanup sweeper (deterministic)",
          "[dns][lifecycle][running]")
{
  auto t = std::make_shared<DnsTransport>(makeCfg());
  LA::setCleanupInterval(*t, std::chrono::milliseconds(10));
  LA::startCleanupOnly(*t); // generation 1, sweeper #1
  REQUIRE(LA::cleanupGeneration(*t) == 1);

  // A RETRIABLE query -> sweeper #1's sweep runs retryQuery -> dis(_rng) (exercises _rng).
  LA::registerPending(*t, ID_B, SERVER_A, PORT_A, {}, /*retryCount=*/0,
                      std::chrono::milliseconds(1), std::chrono::milliseconds(60000));

  auto stopped = std::make_shared<std::promise<void>>();
  auto stoppedFut = stopped->get_future();
  auto releaseStale = std::make_shared<std::promise<void>>();
  auto releaseStaleFut = std::make_shared<std::shared_future<void>>(releaseStale->get_future());

  // Retry-EXHAUSTED query: its failure callback runs ON sweeper #1, self-stops (detaching #1),
  // then HOLDS #1 alive in the callback until the test releases it -> deterministic overlap.
  LA::registerPending(*t, ID_A, SERVER_A, PORT_A,
                      [t, stopped, releaseStaleFut](const DnsResult &, const std::exception_ptr &)
                      {
                        t->stop();               // self-stop: detaches #1, _cleanupRunning=false, gen stays 1
                        stopped->set_value();     // #1 is now detached and about to be held
                        releaseStaleFut->wait();  // HOLD #1 alive (still counted) until released
                      },
                      LA::configRetryCount(*t), std::chrono::milliseconds(1),
                      std::chrono::milliseconds(60000));

  REQUIRE(stoppedFut.wait_for(std::chrono::seconds(3)) == std::future_status::ready);
  CHECK(LA::isStopped(*t));
  CHECK(LA::cleanupThreadCount(*t) == 1); // #1 still alive (held in the callback)

  // Restart -> generation 2, sweeper #2. #1 is still held, so both are alive (forced overlap).
  LA::setCleanupInterval(*t, std::chrono::milliseconds(10));
  LA::startCleanupOnly(*t); // generation 2, sweeper #2
  CHECK(LA::cleanupGeneration(*t) == 2);
  LA::registerPending(*t, ID_B, SERVER_A, PORT_A, {}, /*retryCount=*/0,
                      std::chrono::milliseconds(1), std::chrono::milliseconds(60000)); // #2 draws _rng

  // Force + observe the two-sweeper overlap (count reaches 2) BEFORE asserting it drains.
  bool overlapped = false;
  for (int i = 0; i < 400 && !overlapped; ++i)
  {
    if (LA::cleanupThreadCount(*t) == 2)
    {
      overlapped = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  CHECK(overlapped); // both sweepers genuinely coexisted

  // Release #1 -> it returns from the callback, sees gen mismatch (1 != 2), exits.
  releaseStale->set_value();

  // #1 MUST exit -> count settles to exactly 1 (only #2). This is unambiguous now: we already
  // observed count==2, so count==1 here means #1 exited (not the stale-alone window).
  bool settledToOne = false;
  for (int i = 0; i < 400 && !settledToOne; ++i)
  {
    if (LA::cleanupThreadCount(*t) == 1)
    {
      settledToOne = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  CHECK(settledToOne); // resurrect guard bounded the sweepers to one

  t->stop();
  CHECK(LA::isStopped(*t));
  CHECK(LA::cleanupThreadCount(*t) == 0); // the live sweeper joined/exited on stop
}
