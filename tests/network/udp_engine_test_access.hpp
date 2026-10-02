// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file udp_engine_test_access.hpp
/// \brief Test-only access to UdpEngine internals (friend of UdpEngine). Keeps the
///        connect-then-send test seams out of the production API. Mirrors
///        tests/network/tcp_engine_test_access.hpp.

#pragma once

#include "iora/network/detail/udp_engine.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <future>
#include <memory>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <type_traits>

namespace iora
{
namespace network
{

struct UdpEngineTestAccess
{
  using ConnectThrowPoint = UdpEngine::ConnectThrowPoint;

  /// Size of the connecting-sid registry (both connect() and connectViaListener()).
  static std::size_t connectingCount(const UdpEngine &e)
  {
    std::shared_lock<std::shared_mutex> rl(e._sessionRwMutex);
    return e._connecting.size();
  }

  /// Named-host connects/vias awaiting resolution. I/O thread only.
  static std::size_t pendingConnectCount(const UdpEngine &e)
  {
    assert(e.isOnIoThread());
    return e._pendingConnects.size();
  }

  /// True iff \p sid is an inserted, not-closed session.
  static bool hasSession(const UdpEngine &e, SessionId sid)
  {
    std::shared_lock<std::shared_mutex> rl(e._sessionRwMutex);
    auto it = e._sessions.find(sid);
    return it != e._sessions.end() && !it->second->closed.load();
  }

  /// When true every enqueue() push throws internally (converted to a false return
  /// by enqueue's noexcept catch — exercises the connect() rollback path).
  static void injectEnqueueFailure(UdpEngine &e, bool enabled)
  {
    e._testEnqueueFailure.store(enabled, std::memory_order_relaxed);
  }

  /// Arm a one-shot throw at \p point on the I/O-thread connect path.
  static void injectConnectThrow(UdpEngine &e, ConnectThrowPoint point)
  {
    e._testConnectThrowPoint.store(point, std::memory_order_relaxed);
  }

  // --- Backpressure seam + I/O-thread-only queue inspection (tracker 2026-09-25-16) ---

  /// Arm the per-session forced-EAGAIN seam: \p sid's send path simulates EAGAIN at
  /// every send site (no syscall) so a deterministic write-queue overflow can be driven
  /// (native-Linux loopback UDP never EAGAINs). Arm BEFORE the test-thread send burst.
  static void armForceEagain(UdpEngine &e, SessionId sid)
  {
    e._testForceEagainSid.store(sid, std::memory_order_relaxed);
  }
  /// Disarm the forced-EAGAIN seam (lets the real drain run).
  static void disarmForceEagain(UdpEngine &e)
  {
    e._testForceEagainSid.store(0, std::memory_order_relaxed);
  }

  /// I/O-thread atomic: disarm the seam and issue ONE send via sendDo in the SAME I/O step,
  /// so no EPOLLOUT drain can interleave. Exercises sendDo's M-5 "queue behind a non-empty
  /// queue" decision with the seam OFF (client-path ordering test, F-2): with M-5 the send
  /// queues behind the pending datagrams; without it, the direct ::send overtakes them.
  static void disarmThenSend(UdpEngine &e, SessionId sid, const std::string &payload)
  {
    onIo(e,
         [&e, sid, payload]()
         {
           e._testForceEagainSid.store(0, std::memory_order_relaxed);
           UdpEngine::SendReq rq;
           rq.sid = sid;
           rq.payload.assign(payload.begin(), payload.end());
           e.sendDo(std::move(rq));
         });
  }

  /// ClientConnected session's own write-queue depth (I/O-thread snapshot; 0 if gone).
  static std::size_t sessionQueueSize(UdpEngine &e, SessionId sid)
  {
    return onIo(e,
                [&e, sid]() -> std::size_t
                {
                  auto it = e._sessions.find(sid);
                  return it == e._sessions.end() ? std::size_t{0} : it->second->wq.size();
                });
  }

  /// Total shared listener write-queue depth (I/O-thread snapshot; 0 if gone).
  static std::size_t listenerQueueSize(UdpEngine &e, ListenerId lid)
  {
    return onIo(e,
                [&e, lid]() -> std::size_t
                {
                  auto it = e._listeners.find(lid);
                  return it == e._listeners.end() ? std::size_t{0} : it->second->wq.size();
                });
  }

  /// Count of datagrams owned by \p sid in listener \p lid's shared queue (I/O-thread).
  /// After a ServerPeer close this MUST be 0 (purge-by-sid): no post-close send.
  static std::size_t listenerQueuedForSid(UdpEngine &e, ListenerId lid, SessionId sid)
  {
    return onIo(e,
                [&e, lid, sid]() -> std::size_t
                {
                  auto it = e._listeners.find(lid);
                  if (it == e._listeners.end())
                  {
                    return 0;
                  }
                  const auto &wq = it->second->wq;
                  return static_cast<std::size_t>(
                    std::count_if(wq.begin(), wq.end(),
                                  [sid](const auto &dg) { return dg.sid == sid; }));
                });
  }

  /// True iff some _peerIndex entry maps to \p sid (I/O-thread). After closing a
  /// via-TWIN, the originally-indexed sibling MUST still be present (H-3 ownership guard).
  static bool peerIndexHasSid(UdpEngine &e, SessionId sid)
  {
    return onIo(e,
                [&e, sid]() -> bool
                {
                  return std::any_of(e._peerIndex.begin(), e._peerIndex.end(),
                                     [sid](const auto &kv) { return kv.second == sid; });
                });
  }

  /// Happens-before barrier: round-trips the I/O thread so all previously-enqueued
  /// commands (incl. a synchronous backpressure close inside sendDo) have completed.
  /// Use instead of a sleep before a negative assertion (a stat read gives no ordering).
  static void ioBarrier(UdpEngine &e) { onIo(e, [] {}); }

private:
  /// Run \p fn on the engine I/O thread and return its result (bounded, exception-safe).
  /// Ownership is SHARED (shared_ptr<promise>): the waiter drops its ref right after posting,
  /// so a dropped/un-run closure makes the future ready immediately with broken_promise
  /// rather than blocking; on not-posted or timeout it THROWS (Catch2 reports it in EVERY
  /// build — asserts would vanish under the default Release/NDEBUG, and a `[&]`-captured
  /// promise would be a use-after-free). fn's exception is propagated. Supports void fn.
  /// Must NOT be called on the I/O thread (a self-post would deadlock) — throws if it is.
  template <typename F> static auto onIo(UdpEngine &e, F fn) -> decltype(fn())
  {
    using R = decltype(fn());
    if (e.isOnIoThread())
    {
      throw std::logic_error("onIo must be called from the test thread, not the I/O thread");
    }
    auto prom = std::make_shared<std::promise<R>>();
    auto fut = prom->get_future();
    bool posted = e.runOnIoThread(
      [prom, fn]()
      {
        try
        {
          if constexpr (std::is_void_v<R>)
          {
            fn();
            prom->set_value();
          }
          else
          {
            prom->set_value(fn());
          }
        }
        catch (...)
        {
          prom->set_exception(std::current_exception());
        }
      });
    if (!posted)
    {
      throw std::runtime_error("onIo: runOnIoThread failed (engine not running?)");
    }
    prom.reset(); // drop the waiter's ref: a dropped closure now fails fast (broken_promise)
    if (fut.wait_for(std::chrono::seconds(2)) != std::future_status::ready)
    {
      throw std::runtime_error("onIo: I/O-thread accessor timed out");
    }
    return fut.get();
  }
};

} // namespace network
} // namespace iora
