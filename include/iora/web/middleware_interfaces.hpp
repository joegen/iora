// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "iora/parsers/json.hpp"
// REQUIRED include, NOT a pragmatic choice (L-1/L-2): HttpServer::Request and
// HttpServer::Response are NESTED structs inside class HttpServer, and a nested
// type CANNOT be forward-declared from outside its enclosing class in C++ — there
// is no syntax to forward-declare HttpServer::Request without the full definition
// of HttpServer. The cost is that this interface header pulls in the HTTP server
// header (and its transitive includes).
#include "iora/network/http_server.hpp"

namespace iora
{
namespace web
{

/// \brief The authenticated principal returned by IAuthGuard::authenticate.
/// 'subject' is the stable user id (e.g. username or OIDC sub); 'claims' is an
/// open Json object (roles, display name, provider-specific attributes). iora
/// never interprets claims; consumers read by key, never by position (Json
/// objects are unordered).
struct Identity
{
  std::string subject;
  iora::parsers::Json claims;
};

/// \brief Server-side session record returned by ISessionStore::get. 'id' is the
/// opaque session identifier (carried in the session cookie by the middleware);
/// 'data' is a Json object of session state iora never inspects.
struct Session
{
  std::string id;
  iora::parsers::Json data;
};

/// \brief Authenticate an inbound request — return the Identity or nullopt if
/// unauthenticated. nullopt is NOT an error; the foundation caller decides to
/// redirect to login, challenge, or 401.
class IAuthGuard
{
public:
  virtual ~IAuthGuard() = default;
  virtual std::optional<Identity> authenticate(const iora::network::HttpServer::Request &req) = 0;
};

/// \brief Create / look up / update / destroy server-side sessions keyed by an
/// opaque session id.
class ISessionStore
{
public:
  virtual ~ISessionStore() = default;
  /// Returns the Session or nullopt if the id is unknown/expired.
  virtual std::optional<Session> get(const std::string &sessionId) = 0;
  /// Persists a new session from the initial Json and returns its opaque id.
  virtual std::string create(const iora::parsers::Json &initial) = 0;
  /// Replaces the stored data for an existing id.
  virtual void update(const std::string &sessionId, const iora::parsers::Json &data) = 0;
  /// Removes the session (idempotent).
  virtual void destroy(const std::string &sessionId) = 0;
};

/// \brief Mint and verify CSRF tokens scoped to a session.
class ICsrfProtector
{
public:
  virtual ~ICsrfProtector() = default;
  /// Returns a fresh CSRF token bound to the session.
  virtual std::string mint(const std::string &sessionId) = 0;
  /// Returns true iff the token is valid for the session.
  virtual bool verify(const std::string &sessionId, const std::string &token) = 0;
};

/// \brief Render the login page and handle login POSTs — OPTIONAL, present only
/// if the middleware ships a login UI. Foundation MUST treat
/// get<ILoginUiProvider>() == nullptr as 'no login UI configured' and degrade
/// gracefully (e.g. fall back to requireBasicAuth).
class ILoginUiProvider
{
public:
  virtual ~ILoginUiProvider() = default;
  /// Returns the HTML for the login form, optionally surfacing errorMessage
  /// (empty string = no error).
  virtual std::string renderLoginPage(const iora::network::HttpServer::Request &req,
                                      const std::string &errorMessage) = 0;
  /// Validates credentials; on success establishes a session and sets the
  /// session cookie on res, returning the post-login redirect target. A value =
  /// redirect URL; nullopt = stay/re-render with an error.
  virtual std::optional<std::string> handleLoginPost(const iora::network::HttpServer::Request &req,
                                                     iora::network::HttpServer::Response &res) = 0;
};

} // namespace web
} // namespace iora
