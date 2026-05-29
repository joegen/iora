// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Conformance fixture for iora::web::IAuthGuard — the EXECUTABLE form of the
// IAuthGuard contract. This header LIVES in iora's tree but is NOT compiled or
// run in iora's CI gate (iora ships no implementation to instantiate it
// against). It is included and instantiated by the consuming plugin's CI
// (iora_web_middleware), which supplies a Traits type binding the concrete impl
// (R-10).
//
// Usage (downstream):
//   struct MyTraits {
//     static std::shared_ptr<iora::web::IAuthGuard> makeGuard();
//     static iora::network::HttpServer::Request makeAnonymousRequest();
//     static iora::network::HttpServer::Request makeAuthenticatedRequest();
//     static std::string expectedSubject();
//   };
//   TEST_CASE("AuthGuard conformance") { iora::web::conformance::runIAuthGuardConformance<MyTraits>(); }

#pragma once

#include <catch2/catch.hpp>

#include "iora/web/middleware_interfaces.hpp"

namespace iora
{
namespace web
{
namespace conformance
{

/// \brief Drives the IAuthGuard contract:
///  - authenticate() returns nullopt for an anonymous request,
///  - authenticate() returns an Identity (with the expected subject) for a valid
///    request.
template <typename Traits> inline void runIAuthGuardConformance()
{
  auto guard = Traits::makeGuard();
  REQUIRE(guard != nullptr);

  // Anonymous request -> nullopt (NOT an error; the caller decides to challenge).
  {
    auto anon = Traits::makeAnonymousRequest();
    auto id = guard->authenticate(anon);
    REQUIRE_FALSE(id.has_value());
  }

  // Valid request -> Identity with the expected subject.
  {
    auto req = Traits::makeAuthenticatedRequest();
    auto id = guard->authenticate(req);
    REQUIRE(id.has_value());
    REQUIRE(id->subject == Traits::expectedSubject());
  }
}

} // namespace conformance
} // namespace web
} // namespace iora
