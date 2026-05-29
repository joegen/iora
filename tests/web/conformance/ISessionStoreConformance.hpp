// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Conformance fixture for iora::web::ISessionStore — the EXECUTABLE form of the
// ISessionStore contract. Lives in iora's tree; instantiated and run by the
// consuming plugin's CI (iora_web_middleware), NOT in iora's gate (R-10).
//
// Usage (downstream):
//   struct MyTraits {
//     static std::shared_ptr<iora::web::ISessionStore> makeStore();
//     static iora::parsers::Json sampleInitial();
//     static iora::parsers::Json sampleUpdate();
//   };
//   TEST_CASE("SessionStore conformance") { iora::web::conformance::runISessionStoreConformance<MyTraits>(); }

#pragma once

#include <catch2/catch.hpp>

#include "iora/web/middleware_interfaces.hpp"

namespace iora
{
namespace web
{
namespace conformance
{

/// \brief Drives the ISessionStore contract:
///  - create() returns a non-empty opaque id and get() round-trips it,
///  - update() mutates an existing session,
///  - destroy() makes get() return nullopt and is idempotent,
///  - get() of an unknown id returns nullopt.
template <typename Traits> inline void runISessionStoreConformance()
{
  auto store = Traits::makeStore();
  REQUIRE(store != nullptr);

  // Unknown id -> nullopt.
  REQUIRE_FALSE(store->get("no-such-session").has_value());

  // create -> get round-trip.
  const std::string id = store->create(Traits::sampleInitial());
  REQUIRE_FALSE(id.empty());
  {
    auto s = store->get(id);
    REQUIRE(s.has_value());
    REQUIRE(s->id == id);
  }

  // update mutates the stored session (still retrievable afterwards).
  store->update(id, Traits::sampleUpdate());
  REQUIRE(store->get(id).has_value());

  // destroy removes it; get -> nullopt.
  store->destroy(id);
  REQUIRE_FALSE(store->get(id).has_value());

  // destroy is idempotent.
  REQUIRE_NOTHROW(store->destroy(id));
}

} // namespace conformance
} // namespace web
} // namespace iora
