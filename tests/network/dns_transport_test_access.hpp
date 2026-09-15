// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file dns_transport_test_access.hpp
/// \brief Shared white-box test seam for DnsTransport (tracker 2026-09-13-11 SM-M1).
///
/// ONE friend struct, reused by every DnsTransport test file (sid-keying, callback-deadlock,
/// lifecycle-restructure), mirroring the tests/web/service_registry_test_access.hpp precedent.
/// Consolidates the accessors those files previously duplicated across three separate friend
/// structs (which had drifted — e.g. one setCleanupInterval carried an un-started assert the
/// other lacked). Test-only; no production code path depends on it.
///
/// USAGE CONTRACT: setCleanupInterval() requires an UN-STARTED instance (asserted, since it is
/// read by the cleanup thread). The handler-driving helpers (feedUdp/feedTcp/close) invoke the
/// private handlers on the caller's thread and must not race a REAL transport I/O thread — see
/// their note; they carry no assert because setRunning() sets the lifecycle flag WITHOUT starting
/// a real I/O thread (the callback-under-lock probes depend on that).

#pragma once

#include "iora/core/buffer_view.hpp"
#include "iora/network/dns/dns_transport.hpp"
#include "iora/network/transport_types.hpp"

#include <cassert>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace iora
{
namespace network
{
namespace dns
{

/// \brief Bounded-wait helper: returns true if \p fn completed within \p budget, false on
///        timeout. A false result is a FAILURE (e.g. a reborn deadlock), never masked by
///        raising the budget. Runs \p fn on a detached-if-timed-out thread so a genuine hang
///        does not wedge the whole suite.
inline bool completesWithin(std::chrono::milliseconds budget, std::function<void()> fn)
{
  auto done = std::make_shared<std::promise<void>>();
  auto fut = done->get_future();
  std::thread(
    [done, fn = std::move(fn)]() mutable
    {
      fn();
      done->set_value();
    })
    .detach();
  return fut.wait_for(budget) == std::future_status::ready;
}

/// \brief Shared white-box accessor for DnsTransport. Befriended once in dns_transport.hpp.
struct DnsTransportTestAccess
{
  using T = DnsTransport;

  // ---- lifecycle state ----
  static void setRunning(T &t, bool v)
  {
    t._state.store(v ? T::Lifecycle::Running : T::Lifecycle::Stopped, std::memory_order_release);
  }
  static bool isStopping(const T &t)
  {
    return t._state.load(std::memory_order_acquire) == T::Lifecycle::Stopping;
  }
  static bool isStopped(const T &t)
  {
    return t._state.load(std::memory_order_acquire) == T::Lifecycle::Stopped;
  }

  // ---- config ----
  static int configRetryCount(const T &t) { return t.loadConfig()->retryCount; }

  // ---- cleanup thread ----
  static void setCleanupInterval(T &t, std::chrono::milliseconds interval)
  {
    assert(!t.isRunning() && "setCleanupInterval must be called before start()");
    t._cleanupInterval = interval;
  }
  static void startCleanupOnly(T &t)
  {
    t._state.store(T::Lifecycle::Running, std::memory_order_release);
    t.startCleanupTimer();
  }
  static std::uint64_t cleanupGeneration(const T &t)
  {
    return t._cleanupGeneration.load(std::memory_order_acquire);
  }
  static int cleanupThreadCount(const T &t)
  {
    return t._cleanupThreadCount.load(std::memory_order_acquire);
  }

  // ---- transports ----
  static void installTcpTransport(T &t) { t._tcpTransport.store(Transport::tcp(TransportConfig{})); }
  /// True iff the UDP transport exists and the caller runs on its I/O thread (proves an
  /// IO-arm probe is non-vacuous). Read BEFORE stop() nulls the handle.
  static bool udpOnIoThread(T &t)
  {
    auto u = t.loadUdp();
    return u && u->isOnIoThread();
  }

  // ---- sessions ----
  static void putSession(T &t, bool isTcp, SessionId sid, const std::string &server,
                         std::uint16_t port)
  {
    std::lock_guard<std::mutex> l(t._sessionsMutex);
    t._sessionToServer[std::make_pair(isTcp, sid)] = {server, port};
    t._serverSessions[T::serverKey(server, port, isTcp)] = sid;
  }
  static bool hasSession(T &t, bool isTcp, SessionId sid)
  {
    std::lock_guard<std::mutex> l(t._sessionsMutex);
    return t._sessionToServer.count(std::make_pair(isTcp, sid)) != 0;
  }
  static bool hasServerSession(T &t, const std::string &server, std::uint16_t port, bool isTcp)
  {
    std::lock_guard<std::mutex> l(t._sessionsMutex);
    return t._serverSessions.count(T::serverKey(server, port, isTcp)) != 0;
  }

  // ---- TCP framing buffers ----
  static void putTcpBuffer(T &t, SessionId sid, const std::vector<std::uint8_t> &bytes)
  {
    std::lock_guard<std::mutex> l(t._tcpBuffersMutex);
    auto &buf = t._tcpBuffers[sid];
    buf.insert(buf.end(), bytes.begin(), bytes.end());
  }
  static bool hasTcpBuffer(T &t, SessionId sid)
  {
    std::lock_guard<std::mutex> l(t._tcpBuffersMutex);
    return t._tcpBuffers.count(sid) != 0;
  }
  static std::size_t tcpBufferSize(T &t, SessionId sid)
  {
    std::lock_guard<std::mutex> l(t._tcpBuffersMutex);
    auto it = t._tcpBuffers.find(sid);
    return it == t._tcpBuffers.end() ? 0 : it->second.size();
  }

  // ---- pending queries ----
  /// Register a pending query. \p cb empty => no callback (sid-keying probes). The trailing
  /// params default to the callback/lifecycle probes' common values; \p startTimeOffset
  /// shifts startTime into the past so the query is already expired for cleanup probes.
  static void registerPending(T &t, std::uint16_t id, const std::string &server,
                              std::uint16_t port, T::QueryCallback cb = {}, int retryCount = 0,
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

  // ---- drive private handlers directly ----
  // These invoke the private I/O-thread handlers on the CALLER's thread. The caller must
  // ensure no REAL transport I/O thread is running concurrently (either an un-started instance,
  // or one whose lifecycle flag was set white-box via setRunning() with no real transport) —
  // running them against a live I/O thread would race the same guarded maps. There is no
  // isRunning() assert: setRunning(true) sets the flag WITHOUT a real I/O thread, which the
  // callback-under-lock probes rely on, so the flag is not a reliable proxy for "has an I/O thread".
  static void feedUdp(T &t, SessionId sid, const std::vector<std::uint8_t> &bytes)
  {
    t.handleUdpData(sid, iora::core::BufferView(bytes.data(), bytes.size()),
                    std::chrono::steady_clock::now());
  }
  static void feedTcp(T &t, SessionId sid, const std::vector<std::uint8_t> &bytes)
  {
    t.handleTcpData(sid, iora::core::BufferView(bytes.data(), bytes.size()),
                    std::chrono::steady_clock::now());
  }
  static void close(T &t, SessionId sid, bool isTcp)
  {
    t.handleClose(sid, TransportErrorInfo{}, isTcp);
  }
  static void callCleanup(T &t) { t.cleanupExpiredQueries(); }
  static void callCompleteResult(T &t, std::uint16_t id, const std::string &server,
                                 std::uint16_t port)
  {
    t.completeQuery(T::QueryKey(id, server, port), DnsResult{});
  }

  // ---- timer ----
  /// Schedule \p fn directly on the live timer service (runs ON the timer thread). Drives a
  /// timer-thread re-entrant stop() deterministically without a real query/response.
  static std::uint64_t scheduleOnTimer(T &t, std::chrono::milliseconds d, std::function<void()> fn)
  {
    return t.loadTimer()->scheduleAfter(d, std::move(fn));
  }
};

} // namespace dns
} // namespace network
} // namespace iora
