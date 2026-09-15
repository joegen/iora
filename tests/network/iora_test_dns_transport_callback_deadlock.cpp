// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_dns_transport_callback_deadlock.cpp
/// \brief Callback-under-lock / fire-outside-locks / exactly-once regression tests for
///        DnsTransport (tracker 2026-09-11-6).
///
/// WHITE-BOX + deterministic. Via the DnsTransportCallbackTestAccess friend seam these
/// drive the private handlers/maps directly and pin the tracker test_plan behavior:
///   - F-2 (handleTcpData collect-then-fire): a mid-stream framing error must NOT drop
///     already-collected complete messages (break-not-return, no-drop); multiple
///     complete messages fire in arrival order.
///   - F-3 (stop() fires OUTSIDE all locks incl. _stateMutex): a stop()-fired failure
///     callback that re-enters updateConfig() (which takes _stateMutex) must NOT
///     deadlock. This probe HANGS under the pre-fix code (fire under _stateMutex) and
///     completes after the fix; a 5 s bounded wait that elapses is a FAILURE (never
///     raised to mask).
///   - F-4b (cleanupExpiredQueries collect-AND-erase, exactly-once): a query that is
///     both expired and answered fires its callback at most once (concurrency stress);
///     a retriable expired query is preserved in the map and its retryCount advances.
///
/// RUNNING-INSTANCE probes (below the deterministic ones) exercise the join-on-self and
/// self-destruct mechanics on the REAL worker threads:
///   - cleanup-arm self-join guard (item 5): a callback fired from the REAL cleanup thread
///     calls stop(); the guard must DETACH (not join) _cleanupThread -- no
///     resource_deadlock_would_occur.
///   - cleanup-thread-last-owner cycle (item 10 + item 5 / F-R3-4): with a weak_ptr capture
///     the cleanup thread's promoted self is the LAST owner; dropping it runs ~DnsTransport
///     on the cleanup thread, whose stop() must detach-not-join. Proves no owning-self cycle
///     (item 10) AND no self-join in the dtor path (item 5).
///   - IO-arm reset()-on-IO-thread (item 6): a query callback fired on the transport I/O
///     thread calls stop(); stop() must SKIP the throwing wrapper stop() but still reset()
///     the sole-owned transport (deferred ~Transport self-destruct) -- clean teardown, no
///     std::logic_error escaping.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "MockDnsServer.hpp"

#include "iora/core/buffer_view.hpp"
#include "iora/network/dns/dns_message.hpp"
#include "iora/network/dns/dns_transport.hpp"
#include "iora/network/dns/dns_types.hpp"
#include "iora/network/transport_types.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace iora
{
namespace network
{
namespace dns
{

/// \brief Friend seam for the callback-under-lock / exactly-once probes.
struct DnsTransportCallbackTestAccess
{
  using T = DnsTransport;

  static void setRunning(T &t, bool v) { t._running.store(v); }

  /// Install an UNSTARTED tcp Transport so handleTcpData's framing-error close(sid) --
  /// which is enqueue-only -- does not deref a null _tcpTransport in white-box driving.
  /// (In production handleTcpData only runs via a live _tcpTransport, so it is never null.)
  static void installTcpTransport(T &t) { t._tcpTransport = Transport::tcp(TransportConfig{}); }

  static int configRetryCount(T &t) { return t._config.retryCount; }

  static void putSession(T &t, bool isTcp, SessionId sid, const std::string &server,
                         std::uint16_t port)
  {
    std::lock_guard<std::mutex> l(t._sessionsMutex);
    t._sessionToServer[std::make_pair(isTcp, sid)] = {server, port};
    t._serverSessions[T::serverKey(server, port, isTcp)] = sid;
  }

  /// Register a pending query with a callback. startTimeOffset shifts startTime into the
  /// past so the query is already expired for cleanup probes.
  static void registerPending(T &t, std::uint16_t id, const std::string &server,
                              std::uint16_t port, T::QueryCallback cb, int retryCount = 0,
                              std::chrono::milliseconds timeout = std::chrono::milliseconds(5000),
                              std::chrono::milliseconds startTimeOffset = std::chrono::milliseconds(0))
  {
    auto q = std::make_shared<T::PendingQuery>(id, timeout, server, port,
                                               std::vector<std::uint8_t>{});
    q->callback = std::move(cb);
    q->retryCount.store(retryCount);
    if (startTimeOffset.count() != 0)
    {
      q->startTime.store(std::chrono::steady_clock::now() - startTimeOffset);
    }
    std::lock_guard<std::mutex> l(t._queriesMutex);
    t._pendingQueries.emplace(T::QueryKey(id, server, port), q);
  }

  static bool hasPending(T &t, std::uint16_t id, const std::string &server, std::uint16_t port)
  {
    std::lock_guard<std::mutex> l(t._queriesMutex);
    return t._pendingQueries.count(T::QueryKey(id, server, port)) != 0;
  }

  static std::uint64_t activeTimerIdOf(T &t, std::uint16_t id, const std::string &server,
                                       std::uint16_t port)
  {
    std::lock_guard<std::mutex> l(t._queriesMutex);
    auto it = t._pendingQueries.find(T::QueryKey(id, server, port));
    return it == t._pendingQueries.end() ? 0 : it->second->activeTimerId.load();
  }

  static int retryCountOf(T &t, std::uint16_t id, const std::string &server, std::uint16_t port)
  {
    std::lock_guard<std::mutex> l(t._queriesMutex);
    auto it = t._pendingQueries.find(T::QueryKey(id, server, port));
    return it == t._pendingQueries.end() ? -1 : it->second->retryCount.load();
  }

  static void feedTcp(T &t, SessionId sid, const std::vector<std::uint8_t> &bytes)
  {
    t.handleTcpData(sid, iora::core::BufferView(bytes.data(), bytes.size()),
                    std::chrono::steady_clock::now());
  }

  static void callCleanup(T &t) { t.cleanupExpiredQueries(); }

  static void callCompleteResult(T &t, std::uint16_t id, const std::string &server,
                                 std::uint16_t port)
  {
    t.completeQuery(T::QueryKey(id, server, port), DnsResult{});
  }

  /// Start ONLY the real cleanup thread (_running=true + the production startCleanupTimer),
  /// WITHOUT creating any transports. Exercises the genuine _cleanupThread + weak_ptr
  /// capture (item 10) so the cleanup-arm self-join guard (item 5) and the
  /// cleanup-thread-last-owner cycle (F-R3-4) run on the real thread with no sockets.
  static void startCleanupOnly(T &t)
  {
    t._running.store(true);
    t.startCleanupTimer();
  }

  /// True iff the UDP transport exists and the caller runs on its I/O thread. Used INSIDE
  /// a query callback to prove the IO-arm probe is non-vacuous (the callback really fired
  /// on the transport I/O thread, so stop()'s item-6 branch is genuinely taken).
  static bool udpCallerOnIoThread(T &t)
  {
    return t._udpTransport && t._udpTransport->isOnIoThread();
  }

  /// Shorten the cleanup-sweep interval (item F seam). MUST be called BEFORE the cleanup
  /// thread starts (startCleanupOnly / start()); read only by that thread. The assert
  /// enforces the set-before-start precondition (L-1/L2): writing it post-start would be a
  /// data race against the cleanup thread's read.
  static void setCleanupInterval(T &t, std::chrono::milliseconds interval)
  {
    assert(!t._running.load() && "setCleanupInterval must be called before start()");
    t._cleanupInterval = interval;
  }
};

} // namespace dns
} // namespace network
} // namespace iora

using namespace iora::network::dns;
using Access = iora::network::dns::DnsTransportCallbackTestAccess;

namespace
{
constexpr const char *SERVER_A = "127.0.0.1";
constexpr std::uint16_t PORT_A = 5311;
constexpr std::uint16_t ID_A = 0x4141;
constexpr std::uint16_t ID_B = 0x4242;

std::vector<std::uint8_t> wireWithId(std::uint16_t id)
{
  return DnsMessage::buildQuery(DnsQuestion("example.test", DnsType::A, DnsClass::IN), id);
}

std::vector<std::uint8_t> framed(const std::vector<std::uint8_t> &msg)
{
  std::vector<std::uint8_t> out;
  out.push_back(static_cast<std::uint8_t>((msg.size() >> 8) & 0xFF));
  out.push_back(static_cast<std::uint8_t>(msg.size() & 0xFF));
  out.insert(out.end(), msg.begin(), msg.end());
  return out;
}

std::shared_ptr<DnsTransport> makeTransport()
{
  DnsConfig cfg; // default transportMode == Both; not start()ed (white-box).
  return std::make_shared<DnsTransport>(cfg);
}

// The default per-config retry limit (a throwaway transport reads the configured value).
int defaultRetryLimit() { return Access::configRetryCount(*makeTransport()); }

// Register a retry-EXHAUSTED, already-EXPIRED query (timeout 1 ms, startTime 60 s in the
// past) so a cleanup sweep FAILS+fires it exactly once. Shared by the exactly-once and
// running-instance probes.
void registerExpiredExhausted(DnsTransport &t, std::uint16_t id, const std::string &server,
                              std::uint16_t port, DnsTransport::QueryCallback cb, int retryLimit)
{
  Access::registerPending(t, id, server, port, std::move(cb), retryLimit,
                          std::chrono::milliseconds(1), std::chrono::milliseconds(60000));
}
} // namespace

// F-2 no-drop: an in-loop framing error (0-length prefix) after a complete message must
// still fire the already-collected message (break, not return). Pins the collect-then-
// fire structure against a return-on-error regression.
TEST_CASE("dns callback-deadlock: F-2 mid-stream framing error does not drop a collected message",
          "[dns][callback-deadlock]")
{
  auto t = makeTransport();
  Access::installTcpTransport(*t); // framing error triggers close(sid) (enqueue-only)
  Access::putSession(*t, /*isTcp=*/true, 1, SERVER_A, PORT_A);
  std::atomic<int> fired{0};
  Access::registerPending(*t, ID_A, SERVER_A, PORT_A,
                          [&fired](const DnsResult &, const std::exception_ptr &) { ++fired; });

  // [ complete msg for ID_A ][ 0x0000 -> invalid length ]
  std::vector<std::uint8_t> buf = framed(wireWithId(ID_A));
  buf.push_back(0x00);
  buf.push_back(0x00);

  Access::feedTcp(*t, 1, buf);

  CHECK(fired.load() == 1);                                   // collected msg was fired
  CHECK_FALSE(Access::hasPending(*t, ID_A, SERVER_A, PORT_A)); // completed
}

// F-2 ordering: two complete messages in one delivery both fire.
TEST_CASE("dns callback-deadlock: F-2 two complete messages both fire",
          "[dns][callback-deadlock]")
{
  auto t = makeTransport();
  Access::putSession(*t, /*isTcp=*/true, 1, SERVER_A, PORT_A);
  std::atomic<int> firedA{0};
  std::atomic<int> firedB{0};
  Access::registerPending(*t, ID_A, SERVER_A, PORT_A,
                          [&firedA](const DnsResult &, const std::exception_ptr &) { ++firedA; });
  Access::registerPending(*t, ID_B, SERVER_A, PORT_A,
                          [&firedB](const DnsResult &, const std::exception_ptr &) { ++firedB; });

  std::vector<std::uint8_t> buf = framed(wireWithId(ID_A));
  auto second = framed(wireWithId(ID_B));
  buf.insert(buf.end(), second.begin(), second.end());

  Access::feedTcp(*t, 1, buf);

  CHECK(firedA.load() == 1);
  CHECK(firedB.load() == 1);
}

// F-3: a stop()-fired failure callback that re-enters updateConfig() (which takes
// _stateMutex) must not deadlock -- proving stop() fires OUTSIDE _stateMutex. HANGS under
// the pre-fix code; a 5 s bounded wait that elapses is a FAILURE.
TEST_CASE("dns callback-deadlock: F-3 stop() fires outside _stateMutex (no re-entrancy deadlock)",
          "[dns][callback-deadlock]")
{
  auto t = makeTransport();
  Access::setRunning(*t, true); // no real transports; drive stop()'s drain+fire path

  DnsConfig reentrantCfg;
  reentrantCfg.servers.push_back(DnsServer::fromString(SERVER_A));

  std::atomic<bool> callbackRan{false};
  Access::registerPending(*t, ID_A, SERVER_A, PORT_A,
                          [t, reentrantCfg, &callbackRan](const DnsResult &,
                                                          const std::exception_ptr &)
                          {
                            // Re-enters _stateMutex via updateConfig(): deadlocks under
                            // the pre-fix "fire under _stateMutex" code.
                            t->updateConfig(reentrantCfg);
                            callbackRan.store(true);
                          });

  auto done = std::make_shared<std::promise<void>>();
  auto fut = done->get_future();
  std::thread th([t, done]() { t->stop(); done->set_value(); });

  if (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready)
  {
    th.join();
    CHECK(callbackRan.load());
    SUCCEED("stop() completed without deadlock");
  }
  else
  {
    th.detach(); // deadlocked (would be the pre-fix bug); leak to avoid hanging CI
    FAIL("stop() did not complete within 5s -- F-3 callback fired under _stateMutex (deadlock)");
  }
}

// F-4b retry-preserved: a retriable expired query stays in the map and its retryCount
// advances (collect-AND-erase must NOT erase retriable entries).
TEST_CASE("dns callback-deadlock: F-4b cleanup preserves a retriable expired query",
          "[dns][callback-deadlock]")
{
  auto t = makeTransport();
  REQUIRE(Access::configRetryCount(*t) > 0); // else this test is vacuous
  std::atomic<int> fired{0};
  Access::registerPending(*t, ID_A, SERVER_A, PORT_A,
                          [&fired](const DnsResult &, const std::exception_ptr &) { ++fired; },
                          /*retryCount=*/0, /*timeout=*/std::chrono::milliseconds(10),
                          /*startTimeOffset=*/std::chrono::milliseconds(60000)); // already expired

  Access::callCleanup(*t);

  CHECK(Access::hasPending(*t, ID_A, SERVER_A, PORT_A)); // retriable -> left in map
  CHECK(Access::retryCountOf(*t, ID_A, SERVER_A, PORT_A) == 1); // retry advanced
  CHECK(fired.load() == 0); // not failed (still retrying)
  // M1 (cpp17-MED, round 2): a cleanup-driven retry must leave a live, cancellable timer id
  // in the map -- retryQuery schedules the retry timer and records its id. A regression that
  // zeroed activeTimerId on the retry path (the removed store(0) clobber) would show 0 here.
  CHECK(Access::activeTimerIdOf(*t, ID_A, SERVER_A, PORT_A) != 0);
}

// F-4b exactly-once: a query that is both expired (retry-exhausted -> cleanup fails it)
// and answered (completeQuery) fires its callback AT MOST once, even when cleanup and
// completeQuery race. Under the pre-fix copy-without-erase, the callback could fire twice.
TEST_CASE("dns callback-deadlock: F-4b expired+answered fires the callback at most once",
          "[dns][callback-deadlock]")
{
  const int retryLimit = defaultRetryLimit();

  for (int iter = 0; iter < 500; ++iter)
  {
    auto t = makeTransport();
    std::atomic<int> fired{0};
    // retry-exhausted + expired -> cleanup will FAIL (erase+fire) it.
    registerExpiredExhausted(*t, ID_A, SERVER_A, PORT_A,
                             [&fired](const DnsResult &, const std::exception_ptr &) { ++fired; },
                             retryLimit);

    std::thread a([&t]() { Access::callCleanup(*t); });
    std::thread b([&t]() { Access::callCompleteResult(*t, ID_A, SERVER_A, PORT_A); });
    a.join();
    b.join();

    REQUIRE(fired.load() <= 1); // exactly-once: never double-fire
    REQUIRE_FALSE(Access::hasPending(*t, ID_A, SERVER_A, PORT_A)); // owned by exactly one path
  }
}

// =============================================================================
// RUNNING-INSTANCE probes (real worker threads; see file header)
// =============================================================================

// item 5 (cleanup-arm self-join guard): a failure callback fired from the REAL cleanup thread
// calls stop(). A thread cannot join itself, so the guard must DETACH _cleanupThread; a naive
// join throws resource_deadlock_would_occur out of stop().
TEST_CASE("dns callback-deadlock: item5 stop() from the cleanup thread detaches (no self-join)",
          "[dns][callback-deadlock][running]")
{
  const int retryLimit = defaultRetryLimit();
  auto t = makeTransport();
  Access::setCleanupInterval(*t, std::chrono::milliseconds(20)); // item F seam: sub-second sweep
  Access::startCleanupOnly(*t); // real cleanup thread, no transports

  std::atomic<bool> callbackRan{false};
  std::atomic<bool> stopThrew{false};
  auto done = std::make_shared<std::promise<void>>();
  auto fut = done->get_future();

  // retry-exhausted + already expired -> cleanup FAILS it and fires this callback ON the
  // cleanup thread; the callback re-enters stop().
  registerExpiredExhausted(*t, ID_A, SERVER_A, PORT_A,
                           [t, &callbackRan, &stopThrew, done](const DnsResult &,
                                                               const std::exception_ptr &)
                           {
                             callbackRan.store(true);
                             try
                             {
                               t->stop();
                             }
                             catch (...)
                             {
                               stopThrew.store(true);
                             }
                             done->set_value();
                           },
                           retryLimit);

  // The first cleanup cycle fires ~20 ms after the thread starts (item F seam); a 3 s bound
  // that elapses is a FAILURE (not raised to mask).
  REQUIRE(fut.wait_for(std::chrono::seconds(3)) == std::future_status::ready);
  CHECK(callbackRan.load());
  CHECK_FALSE(stopThrew.load()); // self-join guard DETACHED instead of joining
  CHECK_FALSE(t->isRunning());   // stop() ran to completion
}

// item 10 (weak capture) + item 5 (detach) / F-R3-4: the cleanup thread promotes a weak_ptr
// per iteration, so its promoted `self` can be the LAST owner. When the test drops its ref
// while the callback holds the iteration open, end-of-iteration drops that last `self` ->
// ~DnsTransport runs ON the cleanup thread, whose stop() must detach-not-join. Proves no
// owning-self cycle (item 10 -- an owning capture would keep the object alive forever) AND no
// self-join in the dtor path (item 5 -- a join in ~DnsTransport would std::terminate).
TEST_CASE("dns callback-deadlock: item10+item5 cleanup thread as last owner tears down cleanly",
          "[dns][callback-deadlock][running]")
{
  const int retryLimit = defaultRetryLimit();
  auto t = makeTransport();
  std::weak_ptr<DnsTransport> weak = t;
  Access::setCleanupInterval(*t, std::chrono::milliseconds(20)); // item F seam: sub-second sweep
  Access::startCleanupOnly(*t);

  auto inCallback = std::make_shared<std::promise<void>>();
  auto inCallbackFut = inCallback->get_future();
  auto release = std::make_shared<std::promise<void>>();
  auto releaseFut = std::make_shared<std::shared_future<void>>(release->get_future());

  // Callback captures NEITHER `t` NOR any DnsTransport ref -- only the loop's promoted `self`
  // keeps the object alive while the callback runs.
  registerExpiredExhausted(*t, ID_A, SERVER_A, PORT_A,
                           [inCallback, releaseFut](const DnsResult &, const std::exception_ptr &)
                           {
                             inCallback->set_value(); // on the cleanup thread; `self` is alive
                             releaseFut->wait();      // hold the iteration open until t is dropped
                             // Return WITHOUT stop(): end-of-iteration drops the last owner.
                           },
                           retryLimit);

  // Wait for the cleanup cycle to ENTER the callback (~20 ms interval, item F seam; 3 s bound).
  REQUIRE(inCallbackFut.wait_for(std::chrono::seconds(3)) == std::future_status::ready);

  t.reset();                   // drop the test's only strong ref; the promoted `self` remains
  CHECK_FALSE(weak.expired()); // still alive: the loop's promoted `self` owns it here
  release->set_value();        // let the callback return -> end-of-iteration drops the last owner

  // ~DnsTransport now runs on the cleanup thread (last owner). Bound the observation at ~3 s.
  bool destroyed = false;
  for (int i = 0; i < 300 && !destroyed; ++i)
  {
    if (weak.expired())
    {
      destroyed = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  CHECK(destroyed); // no owning-self cycle (item 10); dtor did not self-join/terminate (item 5)
}

// item 6 (IO-arm reset-on-IO-thread): a query callback fired on the UDP transport I/O thread
// calls stop(). The wrapper stop() THROWS if called on its own I/O thread, so stop() must SKIP
// it but still reset() the sole-owned transport (deferred ~Transport self-destruct). Clean
// teardown, no std::logic_error escaping.
TEST_CASE("dns callback-deadlock: item6 stop() from the transport I/O thread tears down cleanly",
          "[dns][callback-deadlock][running]")
{
  // Fixed port (L1 / cpp17-LOW): safe only under the mandatory same-repo `ctest -j1`
  // serialization (no dynamic free-port probe here). If the deferred findFreeTcpPort env
  // window lands, route this through it rather than hardcoding another fixed port.
  constexpr std::uint16_t MOCK_UDP_PORT = 15399;

  MockDnsServer::Config scfg;
  scfg.udpPort = MOCK_UDP_PORT;
  scfg.tcpPort = MOCK_UDP_PORT; // unused (TCP disabled)
  scfg.enableTcp = false;
  scfg.enableUdp = true;
  scfg.defaultDelay = std::chrono::milliseconds(0);
  MockDnsServer server(scfg);
  REQUIRE(server.start());
  server.addRecord({"io.example.test", "A", "192.0.2.55", 3600});
  std::this_thread::sleep_for(std::chrono::milliseconds(100)); // startup settle

  DnsConfig cfg;
  cfg.setServers({std::string("127.0.0.1:") + std::to_string(MOCK_UDP_PORT)});
  cfg.transportMode = DnsTransportMode::UDP; // single transport -> single I/O-thread arm
  cfg.timeout = std::chrono::milliseconds(2000);
  cfg.retryCount = 0;
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  std::atomic<bool> callbackRan{false};
  std::atomic<bool> onIoThread{false};
  std::atomic<bool> stopThrew{false};
  auto done = std::make_shared<std::promise<void>>();
  auto fut = done->get_future();

  t->queryAsync(DnsQuestion("io.example.test", DnsType::A, DnsClass::IN),
                [t, &callbackRan, &onIoThread, &stopThrew, done](const DnsResult &,
                                                                 const std::exception_ptr &)
                {
                  callbackRan.store(true);
                  // Non-vacuous: prove the callback truly fired on the transport I/O thread, so
                  // stop()'s item-6 branch is genuinely taken. Read BEFORE stop() nulls it.
                  onIoThread.store(Access::udpCallerOnIoThread(*t));
                  try
                  {
                    t->stop(); // on the I/O thread: must skip the throwing wrapper stop()
                  }
                  catch (...)
                  {
                    stopThrew.store(true);
                  }
                  done->set_value();
                },
                "127.0.0.1", MOCK_UDP_PORT);

  // Localhost + 0 delay -> the response wins the 2 s timeout deterministically (a timeout would
  // fire the callback on the TIMER thread instead, failing onIoThread -- surfaced, not masked).
  REQUIRE(fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
  CHECK(callbackRan.load());
  CHECK(onIoThread.load());      // callback genuinely ran on the transport I/O thread
  CHECK_FALSE(stopThrew.load()); // item-6 guard skipped the throwing wrapper stop()
  CHECK_FALSE(t->isRunning());   // teardown completed

  server.stop();
  // Let the deferred ~Transport self-destruct finish before the fixture tears down.
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

// F-2 cross-thread ABBA (item E / cpp17-MED-1): the two F-2 tests above would pass even if
// handleTcpData fired the completion callback UNDER _tcpBuffersMutex -- they only check that
// the message fires, not the lock discipline. This probe is the discriminator: it forms the
// lock cycle that a fire-under-lock creates and a fire-after-release breaks.
//   thread A: handleTcpData -> (pre-fix) holds _tcpBuffersMutex -> fires callback -> waits on L
//   thread B: holds L -> calls stop() -> wants _tcpBuffersMutex
// Under the pre-fix code A holds _tcpBuffersMutex while B holds L: ABBA deadlock. Under the
// collect-then-fire fix A has RELEASED _tcpBuffersMutex before the callback blocks on L, so B's
// stop() acquires it and the cycle never forms. A 5 s bound that elapses is a FAILURE.
TEST_CASE("dns callback-deadlock: F-2 cross-thread ABBA (callback fired outside _tcpBuffersMutex)",
          "[dns][callback-deadlock]")
{
  auto t = makeTransport();
  Access::setRunning(*t, true); // stop() must proceed past its running-guard
  Access::putSession(*t, /*isTcp=*/true, 1, SERVER_A, PORT_A);

  std::mutex L; // stands in for an arbitrary user lock a callback might take
  std::atomic<bool> callbackEntered{false};

  // Callback: signal entry, then acquire L. Under pre-fix, A still holds _tcpBuffersMutex here.
  Access::registerPending(*t, ID_A, SERVER_A, PORT_A,
                          [&L, &callbackEntered](const DnsResult &, const std::exception_ptr &)
                          {
                            callbackEntered.store(true);
                            std::lock_guard<std::mutex> hold(L); // blocks until B releases L
                          });

  auto aDone = std::make_shared<std::promise<void>>();
  auto bDone = std::make_shared<std::promise<void>>();
  auto aFut = aDone->get_future();
  auto bFut = bDone->get_future();

  // Thread B: take L, wait until the callback has entered (so under pre-fix A is holding
  // _tcpBuffersMutex), THEN call stop() which wants _tcpBuffersMutex.
  std::thread b(
    [&t, &L, &callbackEntered, bDone]()
    {
      std::unique_lock<std::mutex> bl(L);
      while (!callbackEntered.load())
      {
        std::this_thread::yield();
      }
      t->stop(); // wants _tcpBuffersMutex -> blocks forever under the pre-fix ABBA cycle
      bl.unlock();
      bDone->set_value();
    });

  // Thread A: deliver one complete TCP message -> handleTcpData -> fires the callback.
  std::thread a(
    [&t, aDone]()
    {
      Access::feedTcp(*t, 1, framed(wireWithId(ID_A)));
      aDone->set_value();
    });

  const bool aOk = aFut.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
  const bool bOk = bFut.wait_for(std::chrono::seconds(5)) == std::future_status::ready;

  if (aOk && bOk)
  {
    a.join();
    b.join();
    SUCCEED("callback fired outside _tcpBuffersMutex -- no cross-thread ABBA deadlock");
  }
  else
  {
    a.detach();
    b.detach(); // deadlocked (the pre-fix bug); leak to avoid hanging CI
    FAIL("handleTcpData fired the callback under _tcpBuffersMutex -- cross-thread ABBA deadlock");
  }
}

// C1/H-1 cross-thread teardown regression guard (round-3 MED, cpp17+TSA): the phase-split
// stop() (STOP/join all internal threads -> THEN reset all handles) prevents a CROSS-thread
// UAF -- an EXTERNAL thread's stop() resetting _udpTransport/_timerService while a timer/I-O
// thread is mid-deref. Every OTHER running probe calls stop() FROM the internal thread
// (same-thread, cannot observe a reset-vs-deref race), so a reverted PHASE 1/2 order would
// slip past them. This probe drives real timer + I/O threads (retryCount>0 + a fast cleanup
// sweep so retry lambdas fire and re-send -- also exercising the M1 async re-send path) and
// calls stop() from an EXTERNAL thread while queries are in-flight. Under a normal build it
// guards against teardown crashes/hangs/deadlocks; under TSan (setarch -R) a reset-vs-deref
// race from a reverted ordering trips here. Fixed port -> safe only under `ctest -j1`.
TEST_CASE("dns callback-deadlock: C1 external stop() mid-flight tears down cleanly (TSan guard)",
          "[dns][callback-deadlock][running]")
{
  constexpr std::uint16_t XSTOP_PORT = 15401; // -j1-serialized, like item6

  MockDnsServer::Config scfg;
  scfg.udpPort = XSTOP_PORT;
  scfg.tcpPort = XSTOP_PORT; // unused (TCP disabled)
  scfg.enableTcp = false;
  scfg.enableUdp = true;
  scfg.defaultDelay = std::chrono::milliseconds(60); // > query timeout -> forces timeouts+retries
  MockDnsServer server(scfg);
  REQUIRE(server.start());
  server.addRecord({"xstop.example.test", "A", "192.0.2.88", 3600});
  std::this_thread::sleep_for(std::chrono::milliseconds(50)); // startup settle

  for (int iter = 0; iter < 20; ++iter)
  {
    DnsConfig cfg;
    cfg.setServers({std::string("127.0.0.1:") + std::to_string(XSTOP_PORT)});
    cfg.transportMode = DnsTransportMode::UDP;
    cfg.timeout = std::chrono::milliseconds(40); // < server delay -> queries expire -> retries
    cfg.retryCount = 3;
    cfg.initialRetryDelay = std::chrono::milliseconds(5);
    auto t = std::make_shared<DnsTransport>(cfg);
    Access::setCleanupInterval(*t, std::chrono::milliseconds(5)); // fast sweep -> cleanup retries
    t->start();

    // Fan out queries so the timer + I/O threads are actively dereferencing the handles.
    for (int q = 0; q < 8; ++q)
    {
      t->queryAsync(DnsQuestion("xstop.example.test", DnsType::A, DnsClass::IN),
                    [](const DnsResult &, const std::exception_ptr &) {}, "127.0.0.1", XSTOP_PORT);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(15)); // let retries/timeouts arm + fire

    // EXTERNAL-thread stop() while queries are in-flight -- the cross-thread teardown the
    // phase-split protects. A bounded wait that elapses is a teardown hang FAILURE.
    auto done = std::make_shared<std::promise<void>>();
    auto fut = done->get_future();
    std::thread stopper([t, done]() { t->stop(); done->set_value(); });

    const bool ok = fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
    if (ok)
    {
      stopper.join();
      CHECK_FALSE(t->isRunning());
    }
    else
    {
      stopper.detach(); // teardown hung -- leak to avoid hanging CI
      FAIL("external stop() did not complete within 5s -- teardown deadlock/hang");
    }
  }

  server.stop();
  std::this_thread::sleep_for(std::chrono::milliseconds(150)); // let deferred ~Transport finish
}
