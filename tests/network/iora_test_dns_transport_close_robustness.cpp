// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_dns_transport_close_robustness.cpp
/// \brief Regression tests for DnsTransport session-close robustness (tracker 2026-09-11-7):
///        M-1 (fast-fail already-sent in-flight queries on session close, by EXACT sender-sid)
///        and L-3 (reconnect a reaped cached session instead of throwing).
///
/// WHITE-BOX + deterministic, via the shared DnsTransportTestAccess seam. M-1 drives
/// handleClose directly and asserts:
///   * a query whose sentSid == the closed sid is fast-failed exactly once ('session closed');
///   * a query whose sentSid != the closed sid survives — both the other-protocol sibling
///     (sentIsTcp mismatch) and a query on a DIFFERENT live same-endpoint session
///     (cross-session over-match guard, decision Q5).
/// L-3 uses a send()==false injection (black-hole connect) to assert evict+reconnect+buffer
/// with exactly one timeout, and the peer-already-recreated (no second connect) path.
///
/// Scaffold state: placeholder only. Cases are added incrementally as M-1/L-3 land.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "dns_transport_test_access.hpp" // shared white-box seam (SM-M1)

#include "iora/network/dns/dns_message.hpp"
#include "iora/network/dns/dns_types.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using iora::network::SessionId;
using iora::network::dns::DnsConfig;
using iora::network::dns::DnsResult;
using iora::network::dns::DnsTransport;
using Access = iora::network::dns::DnsTransportTestAccess;

namespace
{
std::shared_ptr<DnsTransport> makeTransport()
{
  DnsConfig cfg; // default; NOT start()ed -- white-box (setRunning sets the flag only).
  return std::make_shared<DnsTransport>(cfg);
}
const std::string SERVER = "8.8.8.8";
constexpr std::uint16_t PORT = 53;
} // namespace

// M-1: a session close must FAST-FAIL the already-sent in-flight queries bound to that
// exact session (removed from _pendingQueries + errored), instead of leaving them to
// linger until their per-query timeout. Non-vacuous: on unfixed code handleClose leaves
// _pendingQueries untouched, so hasPending would remain true and this CHECK_FALSE fails.
TEST_CASE("dns close-robustness M-1: close fast-fails a sent in-flight query on that session",
          "[dns][close-robustness]")
{
  auto t = makeTransport();
  Access::setRunning(*t, true);
  Access::putSession(*t, /*isTcp=*/false, /*sid=*/7, SERVER, PORT);

  int cbCount = 0;
  std::string errMsg;
  Access::registerPending(*t, 100, SERVER, PORT,
                          [&](const DnsResult &, const std::exception_ptr &e)
                          {
                            ++cbCount;
                            if (e)
                            {
                              try
                              {
                                std::rethrow_exception(e);
                              }
                              catch (const std::exception &ex)
                              {
                                errMsg = ex.what();
                              }
                            }
                          });
  Access::setSentSession(*t, 100, SERVER, PORT, /*sid=*/7, /*isTcp=*/false);
  REQUIRE(Access::hasPending(*t, 100, SERVER, PORT));

  Access::close(*t, /*sid=*/7, /*isTcp=*/false);

  CHECK_FALSE(Access::hasPending(*t, 100, SERVER, PORT));      // fast-failed + removed
  CHECK(cbCount == 1);                                         // completed exactly once
  CHECK(errMsg.find("session closed") != std::string::npos);  // correct error, not silent
}

// M-1 discriminator (decision Q5, exact-sid selection): a close must NOT fail a query
// sent on a DIFFERENT session -- neither a same-(server,port) query on another sid
// (cross-session over-match) nor the colliding-bare-sid sibling on the OTHER protocol
// (cross-protocol over-match). QueryKey carries no session discriminator, so a coarse
// (server,port) scan would wrongly fail both; the sentSession exact match must not.
TEST_CASE("dns close-robustness M-1: close spares queries on a different session/protocol",
          "[dns][close-robustness]")
{
  auto t = makeTransport();
  Access::setRunning(*t, true);
  Access::putSession(*t, /*isTcp=*/false, /*sid=*/7, SERVER, PORT);

  // (a) same server:port, sent on a DIFFERENT udp sid (a freshly-recreated session).
  Access::registerPending(*t, 200, SERVER, PORT);
  Access::setSentSession(*t, 200, SERVER, PORT, /*sid=*/9, /*isTcp=*/false);
  // (b) same bare sid 7 but on the TCP session (colliding independent sid space).
  Access::registerPending(*t, 201, SERVER, PORT);
  Access::setSentSession(*t, 201, SERVER, PORT, /*sid=*/7, /*isTcp=*/true);

  Access::close(*t, /*sid=*/7, /*isTcp=*/false); // close UDP sid 7 only

  CHECK(Access::hasPending(*t, 200, SERVER, PORT)); // different sid: survives
  CHECK(Access::hasPending(*t, 201, SERVER, PORT)); // different protocol: survives
}

// L-3 state gate (tracker 2026-09-11-7 H-2): when the transport is not Running, a
// reconnect must NOT resurrect session state -- it returns false and the caller degrades
// to the original "failed to send" throw. No session is buffered.
TEST_CASE("dns close-robustness L-3: reconnect degrades (no resurrection) when not Running",
          "[dns][close-robustness]")
{
  auto t = makeTransport(); // NOT started -> _state is not Running
  Access::putSession(*t, /*isTcp=*/false, /*sid=*/7, SERVER, PORT);
  Access::registerPending(*t, 300, SERVER, PORT);

  CHECK_FALSE(Access::reconnectStale(*t, 300, SERVER, PORT, /*failedSid=*/7, /*isTcp=*/false));
  CHECK_FALSE(Access::hasPendingOnConnect(*t, /*isTcp=*/false, 7));
}

// L-3 peer-recreated: if a concurrent path already replaced the mapped session between
// our unlocked send()==false and the reconnect, do NOT connect() a second time -- buffer
// the query onto the CURRENT session.
TEST_CASE("dns close-robustness L-3: peer-recreated session buffers without a second connect",
          "[dns][close-robustness]")
{
  auto t = makeTransport();
  Access::setRunning(*t, true);
  Access::putSession(*t, /*isTcp=*/false, /*current=*/9, SERVER, PORT); // mapped sid = 9, not 7
  Access::registerPending(*t, 301, SERVER, PORT);

  CHECK(Access::reconnectStale(*t, 301, SERVER, PORT, /*failedSid=*/7, /*isTcp=*/false));
  CHECK(Access::serverSessionSid(*t, SERVER, PORT, /*isTcp=*/false) == 9); // unchanged
  CHECK(Access::hasPendingOnConnect(*t, /*isTcp=*/false, 9));              // buffered onto current
}

// L-3 evict + reconnect: on a stale cached session (mapped sid == failedSid), evict the
// three per-session maps and reconnect a fresh session, buffering the query. Requires a
// STARTED transport so connect() succeeds; a black-hole server keeps the fresh session
// from completing/draining, so the assertions read stable synchronous state.
TEST_CASE("dns close-robustness L-3: evicts the stale session and reconnects a fresh one",
          "[dns][close-robustness]")
{
  DnsConfig cfg;
  cfg.servers.push_back(iora::network::dns::DnsServer::fromString("192.0.2.1:53")); // TEST-NET-1
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  Access::putSession(*t, /*isTcp=*/false, /*stale=*/7, "192.0.2.1", 53);
  Access::registerPending(*t, 302, "192.0.2.1", 53);
  Access::setSentSession(*t, 302, "192.0.2.1", 53, /*sid=*/7, /*isTcp=*/false);

  CHECK(Access::reconnectStale(*t, 302, "192.0.2.1", 53, /*failedSid=*/7, /*isTcp=*/false));
  const SessionId newSid = Access::serverSessionSid(*t, "192.0.2.1", 53, /*isTcp=*/false);
  CHECK(newSid != 0); // a session is mapped
  CHECK(newSid != 7); // and it is a FRESH one, not the evicted stale sid
  // Rebound for M-1 (a STABLE fact -- unlike _pendingOnConnect, which the started
  // transport's async handleConnect may already have drained; the deterministic
  // buffering check lives in the peer-recreated case, which uses no real I/O thread).
  CHECK(Access::sentSessionMatches(*t, 302, "192.0.2.1", 53, newSid, /*isTcp=*/false));

  t->stop();
}

// M-1 exactly-once (lock structure): a session close (M-1 fast-fail via completeQuery ->
// takePending) racing a concurrent completion of the SAME query must complete it exactly
// once. Runs under the sanitized target, so TSan also checks the collect-then-fire path.
TEST_CASE("dns close-robustness M-1: close racing a completion fires the callback exactly once",
          "[dns][close-robustness]")
{
  auto t = makeTransport();
  Access::setRunning(*t, true);
  Access::putSession(*t, /*isTcp=*/false, /*sid=*/7, SERVER, PORT);

  std::atomic<int> cbCount{0};
  Access::registerPending(*t, 400, SERVER, PORT,
                          [&](const DnsResult &, const std::exception_ptr &)
                          { cbCount.fetch_add(1, std::memory_order_relaxed); });
  Access::setSentSession(*t, 400, SERVER, PORT, /*sid=*/7, /*isTcp=*/false);

  std::thread closer([&] { Access::close(*t, /*sid=*/7, /*isTcp=*/false); });
  std::thread completer([&] { Access::callCompleteResult(*t, 400, SERVER, PORT); });
  closer.join();
  completer.join();

  CHECK(cbCount.load() == 1); // takePending erase-under-lock => exactly one completion
  CHECK_FALSE(Access::hasPending(*t, 400, SERVER, PORT));
}

// L-3 no re-entry deadlock: the truncation-fallback path calls reconnectStaleSession WHILE
// holding _queriesMutex; reconnectStaleSession must take only _sessionsMutex (order
// _queriesMutex > _sessionsMutex) and never re-lock _queriesMutex. Bounded so a re-entry
// deadlock would fail (not hang the suite).
TEST_CASE("dns close-robustness L-3: reconnect under _queriesMutex does not deadlock",
          "[dns][close-robustness]")
{
  auto t = makeTransport();
  Access::setRunning(*t, true);
  Access::putSession(*t, /*isTcp=*/false, /*current=*/9, SERVER, PORT); // peer-recreated (9 != 7)
  Access::registerPending(*t, 401, SERVER, PORT);

  std::atomic<bool> reconnected{false};
  const bool completed = iora::network::dns::completesWithin(
    std::chrono::seconds(2),
    [&]
    {
      reconnected.store(Access::reconnectStaleHoldingQueriesLock(
        *t, 401, SERVER, PORT, /*failedSid=*/7, /*isTcp=*/false));
    });
  CHECK(completed);          // returned within budget -> no _queriesMutex re-entry deadlock
  CHECK(reconnected.load()); // and it actually did the peer-recreated buffer
}

// L-3 peer-recreated + already-connected (Fix B): must NOT buffer onto an already-connected
// session (a dead-end until timeout, since handleConnect only drains on the onConnect that
// already fired) -- it takes the send-now path instead. sentSession is rebound either way.
TEST_CASE("dns close-robustness L-3: peer-recreated already-connected session is not buffered",
          "[dns][close-robustness]")
{
  auto t = makeTransport();
  Access::setRunning(*t, true);
  Access::putSession(*t, /*isTcp=*/false, /*current=*/9, SERVER, PORT);
  Access::markConnected(*t, /*isTcp=*/false, /*sid=*/9); // session 9 already connected
  Access::registerPending(*t, 402, SERVER, PORT);

  // reconnectStale returns false here: an un-started transport has no handle for the
  // send-now, so it degrades (L-1). The Fix-B invariant under test is that it still does
  // NOT buffer onto the already-connected session (a dead-end) and rebinds sentSession.
  Access::reconnectStale(*t, 402, SERVER, PORT, /*failedSid=*/7, /*isTcp=*/false);
  CHECK_FALSE(Access::hasPendingOnConnect(*t, /*isTcp=*/false, 9)); // NOT buffered (Fix B)
  CHECK(Access::sentSessionMatches(*t, 402, SERVER, PORT, 9, /*isTcp=*/false)); // rebound
}

// L-3 end-to-end integration: a cached, already-connected session whose engine send()
// returns false must drive sendUdpQuery's full path -- L-3 reconnect then FALL THROUGH to
// the shared scheduleQueryTimeout tail (exactly one timeout; no early-return -> no hang;
// no recursive sendUdpQuery -> no double-schedule) -- and must not throw. Needs a started
// transport; a black-hole server keeps the fresh session from completing.
TEST_CASE("dns close-robustness L-3: cached-connected send-fail reconnects with one timeout",
          "[dns][close-robustness]")
{
  DnsConfig cfg;
  cfg.servers.push_back(iora::network::dns::DnsServer::fromString("192.0.2.1:53")); // TEST-NET-1
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  // A cached, already-connected sid the engine does not know -> udp->send() returns false
  // (a NON-empty payload avoids the engine's n==0 short-circuit), so sendUdpQuery takes the
  // send()==false -> L-3 path through its shared scheduleQueryTimeout tail.
  Access::putSession(*t, /*isTcp=*/false, /*staleSid=*/7, "192.0.2.1", 53);
  Access::markConnected(*t, /*isTcp=*/false, /*sid=*/7);
  Access::registerPendingWithData(*t, 500, "192.0.2.1", 53, {0x12, 0x34});
  Access::setSentSession(*t, 500, "192.0.2.1", 53, /*sid=*/7, /*isTcp=*/false);

  REQUIRE_NOTHROW(Access::driveSendUdp(*t, 500, "192.0.2.1", 53));

  const SessionId newSid = Access::serverSessionSid(*t, "192.0.2.1", 53, /*isTcp=*/false);
  CHECK(newSid != 0);
  CHECK(newSid != 7);                                                          // reconnected
  CHECK(Access::sentSessionMatches(*t, 500, "192.0.2.1", 53, newSid, false));  // rebound
  CHECK(Access::activeTimerIdOf(*t, 500, "192.0.2.1", 53) != 0);               // one timeout armed

  t->stop();
}
