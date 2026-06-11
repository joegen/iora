// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

/// \file transport_test_seam.hpp
/// \brief TEST-ONLY accessor for Transport's private construction surface (the
///        S-3 DQ-8 / test_seam_M1_M2 seam). Production headers NEVER include this.
///
/// Transport (S-3) is shared-ownership-only with PRIVATE constructors and a PRIVATE
/// withEngine() factory. transport.hpp befriends the struct below by name. This
/// header carries its DEFINITION so engine-level fault-injection tests can reach the
/// private withEngine() factory, and so the C1-CLOSED regression can construct a
/// Transport via a std::shared_ptr with a CUSTOM DELETER (make_shared cannot take a
/// deleter) to observe the exact thread on which ~Transport runs.

#include "iora/network/transport.hpp"
#include "iora/network/transport_impl.hpp"

#include <memory>
#include <utility>

namespace iora
{
namespace network
{
namespace test
{

/// Test-only accessor (befriended by Transport). Reaches Transport's private
/// construction surface; used only by tests.
struct TransportEngineInjector
{
  /// The documented seam (DQ-8): reach the private withEngine() factory to inject an
  /// instrumented/fake EngineBase. Returns the make_shared'd shared_ptr<Transport>.
  static std::shared_ptr<Transport> withEngine(std::unique_ptr<detail::EngineBase> engine,
                                               TransportConfig config)
  {
    return Transport::withEngine(std::move(engine), std::move(config));
  }

  /// Test-only: build a Transport behind a std::shared_ptr that carries a CUSTOM
  /// DELETER. std::make_shared (used by tcp()/udp()) cannot attach a deleter, so the
  /// C1-CLOSED regression needs this to observe the thread on which ~Transport runs.
  /// Uses the private PrivateTag constructor (friend access). enable_shared_from_this
  /// is still wired correctly by the std::shared_ptr(T*, Deleter) constructor, and no
  /// teardown path calls shared_from_this() (DQ-2), so the deferred-self-destruct is
  /// unaffected by the two-allocation (non-make_shared) shape.
  template <typename Deleter>
  static std::shared_ptr<Transport> tcpWithDeleter(TransportConfig config, Deleter deleter)
  {
    config.protocol = Protocol::TCP;
    return std::shared_ptr<Transport>(new Transport(Transport::PrivateTag{}, std::move(config)),
                                      std::move(deleter));
  }
};

} // namespace test
} // namespace network
} // namespace iora
