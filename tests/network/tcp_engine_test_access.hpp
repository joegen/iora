// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file tcp_engine_test_access.hpp
/// \brief Test-only access to TcpEngine internals (friend of TcpEngine). Keeps the
///        connect-path test seams out of the production API.

#pragma once

#include "iora/network/detail/tcp_engine.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <utility>

namespace iora
{
namespace network
{

struct TcpEngineTestAccess
{
  using ConnectThrowPoint = TcpEngine::ConnectThrowPoint;

  /// Hook run on the I/O thread with the sid just before the TCP-established
  /// transition (plain TCP and TLS). Install before start().
  static void setBeforeTcpEstablishedHook(TcpEngine &e, std::function<void(SessionId)> hook)
  {
    assert(!e._running.load() && "install before start()");
    e._beforeTcpEstablishedHook = std::move(hook);
  }

  /// Filter applied on the I/O thread to every session event mask before dispatch
  /// (return 0 to drop the event). Install before start().
  static void setSessionEventFilterHook(TcpEngine &e,
                                        std::function<std::uint32_t(SessionId, std::uint32_t)> hook)
  {
    assert(!e._running.load() && "install before start()");
    e._sessionEventFilterHook = std::move(hook);
  }

  /// When true every enqueue()/runOnIoThread() push throws internally.
  static void injectEnqueueFailure(TcpEngine &e, bool enabled)
  {
    e._testEnqueueFailure.store(enabled, std::memory_order_relaxed);
  }

  /// Arm a one-shot throw at \p point on the I/O-thread connect path.
  static void injectConnectThrow(TcpEngine &e, ConnectThrowPoint point)
  {
    e._testConnectThrowPoint.store(point, std::memory_order_relaxed);
  }

  static std::size_t connectingCount(const TcpEngine &e)
  {
    std::shared_lock<std::shared_mutex> rl(e._sessionRwMutex);
    return e._connecting.size();
  }

  /// Armed (not yet popped) TimerService records, or 0 without timers.
  static std::size_t armedTimerCount(const TcpEngine &e)
  {
    return e._timerService ? e._timerService->getInFlightCount() : 0;
  }

  /// TimerService timers that have fired so far (0 without timers).
  static std::uint64_t timersExpired(const TcpEngine &e)
  {
    return e._timerService ? e._timerService->getStats().timersExpired.load() : 0;
  }

  /// Named-host connects awaiting resolution. I/O thread only.
  static std::size_t pendingConnectCount(const TcpEngine &e)
  {
    assert(e.isOnIoThread());
    return e._pendingConnects.size();
  }

  /// True iff \p sid is an inserted, not-closed session.
  static bool hasSession(const TcpEngine &e, SessionId sid)
  {
    std::shared_lock<std::shared_mutex> rl(e._sessionRwMutex);
    auto it = e._sessions.find(sid);
    return it != e._sessions.end() && !it->second->closed.load();
  }

  /// Replace the TimerService with one capped at \p n concurrent timers. Before start().
  static void setMaxConcurrentTimers(TcpEngine &e, std::size_t n)
  {
    assert(!e._running.load() && e._timerService && "before start(), timers enabled");
    e._timerService.reset();
    e._timerConfig.limits.maxConcurrentTimers = n;
    e._timerService = std::make_unique<iora::core::TimerService>(e._timerConfig);
  }

  /// Schedule long no-op timers until the TimerService refuses; returns how many.
  static std::size_t fillTimerCapacity(TcpEngine &e)
  {
    std::size_t n = 0;
    while (e._timerService->scheduleAfter(std::chrono::seconds(60), [] {}) != 0)
    {
      ++n;
    }
    return n;
  }

  /// I/O thread: cancel \p sid's connect timer but KEEP its id (the state of a
  /// connect timer that already fired). False if \p sid is not an inserted session.
  static bool cancelConnectTimerKeepId(TcpEngine &e, SessionId sid)
  {
    assert(e.isOnIoThread());
    auto it = e._sessions.find(sid);
    if (it == e._sessions.end() || it->second->connectTimeoutId == 0)
    {
      return false;
    }
    e._timerService->cancel(it->second->connectTimeoutId);
    return true;
  }

  /// Run the TimerService-thread connect-timeout close path for \p sid.
  static void fireConnectTimeoutClose(TcpEngine &e, SessionId sid)
  {
    e.enqueueTimerClose(sid, TransportError::Connect, "Connect timeout",
                        TcpEngine::CloseOrigin::ConnectTimeout, ETIMEDOUT);
  }

  static int handshakeFailureErrno(int sslError, int hsErrno, unsigned long errCode,
                                   bool unexpectedEof)
  {
    return TcpEngine::handshakeFailureErrno(sslError, hsErrno, errCode, unexpectedEof);
  }

  static std::string sslFailureMessage(int sslError, unsigned long errCode, int sysErrno)
  {
    return TcpEngine::sslFailureMessage(sslError, errCode, sysErrno);
  }

  static unsigned long drainSslErrors(bool &unexpectedEof)
  {
    return TcpEngine::drainSslErrors(unexpectedEof);
  }

  static bool isLocalResourceErrno(int e) { return TcpEngine::isLocalResourceErrno(e); }
};

} // namespace network
} // namespace iora
