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

#include <cassert>
#include <cstddef>
#include <shared_mutex>

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
};

} // namespace network
} // namespace iora
