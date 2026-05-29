// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Conformance fixture for iora::web::ILoginUiProvider — the EXECUTABLE form of
// the ILoginUiProvider contract. Lives in iora's tree; instantiated and run by
// the consuming plugin's CI (iora_web_middleware), NOT in iora's gate (R-10).
//
// Usage (downstream):
//   struct MyTraits {
//     static std::shared_ptr<iora::web::ILoginUiProvider> makeProvider();
//     static iora::network::HttpServer::Request makeLoginGetRequest();
//     static iora::network::HttpServer::Request makeValidLoginPost();
//   };
//   TEST_CASE("LoginUi conformance") { iora::web::conformance::runILoginUiProviderConformance<MyTraits>(); }

#pragma once

#include <catch2/catch.hpp>

#include "iora/web/middleware_interfaces.hpp"

namespace iora
{
namespace web
{
namespace conformance
{

/// \brief Drives the ILoginUiProvider contract:
///  - renderLoginPage() returns non-empty HTML, with and without an error
///    message,
///  - handleLoginPost() on valid credentials returns a redirect target and sets
///    a session cookie (Set-Cookie) on the response.
template <typename Traits> inline void runILoginUiProviderConformance()
{
  auto provider = Traits::makeProvider();
  REQUIRE(provider != nullptr);

  // renderLoginPage is non-empty with no error and with an error message.
  {
    auto getReq = Traits::makeLoginGetRequest();
    REQUIRE_FALSE(provider->renderLoginPage(getReq, "").empty());
    REQUIRE_FALSE(provider->renderLoginPage(getReq, "Invalid credentials").empty());
  }

  // handleLoginPost on success establishes a session (sets a cookie) and returns
  // a redirect target.
  {
    auto postReq = Traits::makeValidLoginPost();
    iora::network::HttpServer::Response res;
    auto redirect = provider->handleLoginPost(postReq, res);
    REQUIRE(redirect.has_value());
    REQUIRE(res.headers.find("Set-Cookie") != res.headers.end());
  }
}

} // namespace conformance
} // namespace web
} // namespace iora
