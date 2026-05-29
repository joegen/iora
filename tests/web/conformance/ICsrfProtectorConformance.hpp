// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Conformance fixture for iora::web::ICsrfProtector — the EXECUTABLE form of the
// ICsrfProtector contract. Lives in iora's tree; instantiated and run by the
// consuming plugin's CI (iora_web_middleware), NOT in iora's gate (R-10).
//
// Usage (downstream):
//   struct MyTraits {
//     static std::shared_ptr<iora::web::ICsrfProtector> makeProtector();
//     static std::string sessionId();
//   };
//   TEST_CASE("CsrfProtector conformance") { iora::web::conformance::runICsrfProtectorConformance<MyTraits>(); }

#pragma once

#include <catch2/catch.hpp>

#include "iora/web/middleware_interfaces.hpp"

namespace iora
{
namespace web
{
namespace conformance
{

/// \brief Drives the ICsrfProtector contract:
///  - mint() returns a non-empty token,
///  - verify() returns true for a freshly minted token,
///  - verify() returns false for a tampered token and for an empty token.
template <typename Traits> inline void runICsrfProtectorConformance()
{
  auto protector = Traits::makeProtector();
  REQUIRE(protector != nullptr);

  const std::string sid = Traits::sessionId();
  const std::string token = protector->mint(sid);
  REQUIRE_FALSE(token.empty());

  REQUIRE(protector->verify(sid, token));
  REQUIRE_FALSE(protector->verify(sid, token + "-tampered"));
  REQUIRE_FALSE(protector->verify(sid, ""));
}

} // namespace conformance
} // namespace web
} // namespace iora
