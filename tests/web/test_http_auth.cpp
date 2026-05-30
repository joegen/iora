// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Unit tests for iora::network::requireBasicAuth (network/http_auth.hpp).
// Tracker: 2026-05-29-5 phase 4.4; architecture: http_basic_auth.json.
//
// The wrapper returns a plain HttpServer::Handler over (Request, Response), so
// the flow is exercised by constructing Request/Response directly and invoking
// the closure — no running server, no ports, fully deterministic.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/core/logger.hpp>
#include <iora/network/http_auth.hpp>
#include <iora/util/base64.hpp>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using iora::network::requireBasicAuth;
using iora::util::Base64;
using Request = iora::network::HttpServer::Request;
using Response = iora::network::HttpServer::Response;
using Handler = iora::network::HttpServer::Handler;

namespace
{
// Base64-encode a credential string for an Authorization header.
std::string enc(const std::string &s)
{
  return Base64::encode(std::vector<std::uint8_t>(s.begin(), s.end()));
}

// Build a GET Request with a given Authorization header value. When headerKey
// is provided it overrides the default "Authorization" key (for the
// case-insensitive-key test).
Request makeReq(const std::string &authValue, bool setHeader = true,
                const std::string &headerKey = "Authorization")
{
  Request req;
  req.method = iora::network::HttpMethod::GET;
  req.path = "/protected";
  if (setHeader)
  {
    req.headers[headerKey] = authValue;
  }
  return req;
}

// An inner handler that records invocation and returns 200.
struct InnerSpy
{
  bool invoked = false;
  Handler handler()
  {
    return [this](const Request &, Response &res)
    {
      invoked = true;
      res.status = 200;
      res.set_content("OK", "text/plain");
    };
  }
};
} // namespace

// ---------------------------------------------------------------------------
// task-4.4.1 — scaffold smoke
// ---------------------------------------------------------------------------

TEST_CASE("requireBasicAuth scaffold builds a Handler", "[http_auth][scaffold]")
{
  InnerSpy spy;
  Handler h = requireBasicAuth(
    "realm", [](const std::string &, const std::string &) { return true; },
    spy.handler());
  Request req = makeReq("Basic " + enc("user:pass"));
  Response res;
  h(req, res);
  REQUIRE(res.status == 200);
  REQUIRE(spy.invoked);
}

// ---------------------------------------------------------------------------
// task-4.4.2 — challenge + verify flow
// ---------------------------------------------------------------------------

TEST_CASE("missing Authorization header -> 401 challenge, inner not invoked",
          "[http_auth][flow]")
{
  InnerSpy spy;
  Handler h = requireBasicAuth(
    "myrealm", [](const std::string &, const std::string &) { return true; },
    spy.handler());
  Request req = makeReq("", /*setHeader=*/false);
  Response res;
  h(req, res);
  REQUIRE(res.status == 401);
  REQUIRE(res.headers["WWW-Authenticate"] == "Basic realm=\"myrealm\"");
  REQUIRE(res.body == "Unauthorized");
  REQUIRE(res.headers["Content-Length"] == std::to_string(std::string("Unauthorized").size()));
  REQUIRE_FALSE(spy.invoked);
}

TEST_CASE("empty Authorization value -> 401 (treated as absent) (web M-5)",
          "[http_auth][flow]")
{
  InnerSpy spy;
  Handler h = requireBasicAuth(
    "r", [](const std::string &, const std::string &) { return true; },
    spy.handler());
  Request req = makeReq(""); // header present but empty
  Response res;
  h(req, res);
  REQUIRE(res.status == 401);
  REQUIRE(res.headers["WWW-Authenticate"] == "Basic realm=\"r\"");
  REQUIRE_FALSE(spy.invoked);
}

TEST_CASE("verify rejects credentials -> 401, inner not invoked", "[http_auth][flow]")
{
  InnerSpy spy;
  Handler h = requireBasicAuth(
    "r", [](const std::string &, const std::string &) { return false; },
    spy.handler());
  Request req = makeReq("Basic " + enc("user:wrong"));
  Response res;
  h(req, res);
  REQUIRE(res.status == 401);
  REQUIRE(res.headers["WWW-Authenticate"] == "Basic realm=\"r\"");
  REQUIRE(res.headers["Content-Length"] == std::to_string(std::string("Unauthorized").size()));
  REQUIRE_FALSE(spy.invoked);
}

TEST_CASE("accepted credentials -> inner invoked, inner status returned", "[http_auth][flow]")
{
  InnerSpy spy;
  std::string gotUser, gotPass;
  Handler h = requireBasicAuth(
    "r",
    [&](const std::string &u, const std::string &p)
    {
      gotUser = u;
      gotPass = p;
      return u == "alice" && p == "secret";
    },
    spy.handler());
  Request req = makeReq("Basic " + enc("alice:secret"));
  Response res;
  h(req, res);
  REQUIRE(res.status == 200);
  REQUIRE(spy.invoked);
  REQUIRE(gotUser == "alice");
  REQUIRE(gotPass == "secret");
}

TEST_CASE("non-Basic scheme -> 401, inner not invoked", "[http_auth][flow]")
{
  InnerSpy spy;
  Handler h = requireBasicAuth(
    "r", [](const std::string &, const std::string &) { return true; },
    spy.handler());
  Request req = makeReq("Bearer xyz");
  Response res;
  h(req, res);
  REQUIRE(res.status == 401);
  REQUIRE(res.headers["WWW-Authenticate"] == "Basic realm=\"r\"");
  REQUIRE_FALSE(spy.invoked);
}

TEST_CASE("scheme matched case-insensitively, verify consulted", "[http_auth][flow]")
{
  for (const std::string &scheme : {std::string("basic"), std::string("BASIC"),
                                    std::string("BaSiC")})
  {
    InnerSpy spy;
    bool verifyCalled = false;
    Handler h = requireBasicAuth(
      "r",
      [&](const std::string &, const std::string &)
      {
        verifyCalled = true;
        return true;
      },
      spy.handler());
    Request req = makeReq(scheme + " " + enc("u:p"));
    Response res;
    h(req, res);
    REQUIRE(verifyCalled);
    REQUIRE(spy.invoked);
    REQUIRE(res.status == 200);
  }
}

TEST_CASE("case-insensitive header KEY accepted (web L-2)", "[http_auth][flow]")
{
  InnerSpy spy;
  Handler h = requireBasicAuth(
    "r", [](const std::string &, const std::string &) { return true; },
    spy.handler());
  // lower-case 'authorization' key — relies on the case-insensitive header map.
  Request req = makeReq("Basic " + enc("u:p"), true, "authorization");
  Response res;
  h(req, res);
  REQUIRE(res.status == 200);
  REQUIRE(spy.invoked);
}

TEST_CASE("multi-space separator accepted (1*SP)", "[http_auth][flow][grammar]")
{
  InnerSpy spy;
  Handler h = requireBasicAuth(
    "r", [](const std::string &, const std::string &) { return true; },
    spy.handler());
  Request req = makeReq("Basic   " + enc("u:p")); // three spaces
  Response res;
  h(req, res);
  REQUIRE(res.status == 200);
  REQUIRE(spy.invoked);
}

TEST_CASE("tab separator REJECTED -> 401 (proves 1*SP not 1*(SP/HTAB), web H-1)",
          "[http_auth][flow][grammar]")
{
  InnerSpy spy;
  Handler h = requireBasicAuth(
    "r", [](const std::string &, const std::string &) { return true; },
    spy.handler());
  Request req = makeReq("Basic\t" + enc("u:p")); // tab after scheme
  Response res;
  h(req, res);
  REQUIRE(res.status == 401);
  REQUIRE(res.headers["WWW-Authenticate"] == "Basic realm=\"r\"");
  REQUIRE_FALSE(spy.invoked);
}

TEST_CASE("scheme is token-bounded, not a prefix (web L-5)", "[http_auth][flow][grammar]")
{
  const std::string b64 = enc("u:p");
  for (const std::string &auth :
       {std::string("BasicX ") + b64, std::string("Basicc ") + b64,
        std::string("Basic") + b64 /* no separator */})
  {
    InnerSpy spy;
    Handler h = requireBasicAuth(
      "r", [](const std::string &, const std::string &) { return true; },
      spy.handler());
    Request req = makeReq(auth);
    Response res;
    h(req, res);
    REQUIRE(res.status == 401);
    REQUIRE_FALSE(spy.invoked);
  }
}

// ---------------------------------------------------------------------------
// task-4.4.3 — credential-parsing edge cases
// ---------------------------------------------------------------------------

TEST_CASE("malformed base64 in header -> 401, inner not invoked", "[http_auth][parse]")
{
  InnerSpy spy;
  Handler h = requireBasicAuth(
    "r", [](const std::string &, const std::string &) { return true; },
    spy.handler());
  Request req = makeReq("Basic !!!notb64!!!");
  Response res;
  h(req, res);
  REQUIRE(res.status == 401);
  REQUIRE(res.headers["WWW-Authenticate"] == "Basic realm=\"r\"");
  REQUIRE(res.headers["Content-Length"] == std::to_string(std::string("Unauthorized").size()));
  REQUIRE_FALSE(spy.invoked);
}

TEST_CASE("Base64URL-alphabet credential rejected by standard decoder (web M-2 finder)",
          "[http_auth][parse]")
{
  InnerSpy spy;
  Handler h = requireBasicAuth(
    "r", [](const std::string &, const std::string &) { return true; },
    spy.handler());
  Request req = makeReq("Basic ab-_"); // token68-valid but '-'/'_' not standard
  Response res;
  h(req, res);
  REQUIRE(res.status == 401);
  REQUIRE(res.headers["WWW-Authenticate"] == "Basic realm=\"r\"");
  REQUIRE_FALSE(spy.invoked);
}

TEST_CASE("trailing SP after padding still decodes, inner runs (web M-1)", "[http_auth][parse]")
{
  InnerSpy spy;
  Handler h = requireBasicAuth(
    "r", [](const std::string &, const std::string &) { return true; },
    spy.handler());
  // "ab:cd" is 5 bytes -> Base64 ends in a single '=' pad; append a trailing
  // space. The credential has a colon so it decodes and runs inner.
  const std::string padded = enc("ab:cd");
  REQUIRE(padded.back() == '='); // guard: the vector genuinely has padding
  Request req = makeReq("Basic " + padded + " ");
  Response res;
  h(req, res);
  REQUIRE(res.status == 200);
  REQUIRE(spy.invoked);
}

TEST_CASE("credential without colon -> 401, inner not invoked", "[http_auth][parse]")
{
  InnerSpy spy;
  Handler h = requireBasicAuth(
    "r", [](const std::string &, const std::string &) { return true; },
    spy.handler());
  Request req = makeReq("Basic " + enc("usernopass"));
  Response res;
  h(req, res);
  REQUIRE(res.status == 401);
  REQUIRE(res.headers["WWW-Authenticate"] == "Basic realm=\"r\"");
  REQUIRE_FALSE(spy.invoked);
}

TEST_CASE("password containing colon split on FIRST colon only", "[http_auth][parse]")
{
  std::string gotUser, gotPass;
  Handler h = requireBasicAuth(
    "r",
    [&](const std::string &u, const std::string &p)
    {
      gotUser = u;
      gotPass = p;
      return true;
    },
    [](const Request &, Response &res) { res.status = 200; });
  Request req = makeReq("Basic " + enc("user:pa:ss"));
  Response res;
  h(req, res);
  REQUIRE(gotUser == "user");
  REQUIRE(gotPass == "pa:ss");
  REQUIRE(res.status == 200);
}

TEST_CASE("empty username and empty password pass correct halves", "[http_auth][parse]")
{
  SECTION("empty username")
  {
    std::string gotUser = "X", gotPass = "X";
    Handler h = requireBasicAuth(
      "r",
      [&](const std::string &u, const std::string &p)
      {
        gotUser = u;
        gotPass = p;
        return true;
      },
      [](const Request &, Response &res) { res.status = 200; });
    Request req = makeReq("Basic " + enc(":pass"));
    Response res;
    h(req, res);
    REQUIRE(gotUser.empty());
    REQUIRE(gotPass == "pass");
  }
  SECTION("empty password")
  {
    std::string gotUser = "X", gotPass = "X";
    Handler h = requireBasicAuth(
      "r",
      [&](const std::string &u, const std::string &p)
      {
        gotUser = u;
        gotPass = p;
        return true;
      },
      [](const Request &, Response &res) { res.status = 200; });
    Request req = makeReq("Basic " + enc("user:"));
    Response res;
    h(req, res);
    REQUIRE(gotUser == "user");
    REQUIRE(gotPass.empty());
  }
}

TEST_CASE("end-to-end: verify receives exactly the decoded halves", "[http_auth][parse]")
{
  std::string gotUser, gotPass;
  Handler h = requireBasicAuth(
    "r",
    [&](const std::string &u, const std::string &p)
    {
      gotUser = u;
      gotPass = p;
      return true;
    },
    [](const Request &, Response &res) { res.status = 200; });
  Request req = makeReq("Basic " + enc("user:pass"));
  Response res;
  h(req, res);
  REQUIRE(gotUser == "user");
  REQUIRE(gotPass == "pass");
}

// ---------------------------------------------------------------------------
// task-4.4.4 — realm rejection, default form, verify-throws (both arms), HR-9
// ---------------------------------------------------------------------------

TEST_CASE("realm with CR/LF/quote/backslash throws at construction (M-8/D-2)",
          "[http_auth][realm]")
{
  auto noop = [](const std::string &, const std::string &) { return true; };
  Handler inner = [](const Request &, Response &) {};
  REQUIRE_THROWS_AS(requireBasicAuth("bad\rrealm", noop, inner), std::invalid_argument);
  REQUIRE_THROWS_AS(requireBasicAuth("bad\nrealm", noop, inner), std::invalid_argument);
  REQUIRE_THROWS_AS(requireBasicAuth("bad\"realm", noop, inner), std::invalid_argument);
  REQUIRE_THROWS_AS(requireBasicAuth("bad\\realm", noop, inner), std::invalid_argument);
  // widened per code-review M-2: other control bytes and DEL are not valid
  // quoted-string qdtext (RFC 9110 §5.6.4) and are also rejected.
  REQUIRE_THROWS_AS(requireBasicAuth(std::string("bad\x01realm"), noop, inner),
                    std::invalid_argument);
  REQUIRE_THROWS_AS(requireBasicAuth(std::string("bad\x1frealm"), noop, inner),
                    std::invalid_argument);
  REQUIRE_THROWS_AS(requireBasicAuth(std::string("bad\x7frealm"), noop, inner),
                    std::invalid_argument);
  REQUIRE_THROWS_AS(requireBasicAuth(std::string("bad\0realm", 9), noop, inner),
                    std::invalid_argument);
  // HTAB (0x09) is technically legal qdtext but is rejected as a < 0x20 byte;
  // pin that documented narrowing so it cannot silently drift.
  REQUIRE_THROWS_AS(requireBasicAuth(std::string("bad\trealm"), noop, inner),
                    std::invalid_argument);
  // benign realm constructs fine and is emitted verbatim.
  REQUIRE_NOTHROW(requireBasicAuth("Admin Area", noop, inner));
  InnerSpy spy;
  Handler h = requireBasicAuth("Admin Area", noop, spy.handler());
  Request req = makeReq("", false);
  Response res;
  h(req, res);
  REQUIRE(res.headers["WWW-Authenticate"] == "Basic realm=\"Admin Area\"");
}

TEST_CASE("default 401 WWW-Authenticate form has no charset, body 'Unauthorized' (L-2)",
          "[http_auth][realm]")
{
  InnerSpy spy;
  Handler h = requireBasicAuth(
    "r", [](const std::string &, const std::string &) { return true; },
    spy.handler());
  Request req = makeReq("", false);
  Response res;
  h(req, res);
  REQUIRE(res.headers["WWW-Authenticate"] == "Basic realm=\"r\"");
  REQUIRE(res.headers["WWW-Authenticate"].find("charset") == std::string::npos);
  REQUIRE(res.body == "Unauthorized");
}

TEST_CASE("verify throwing std::exception -> 500, inner not invoked, what() logged",
          "[http_auth][throws]")
{
  std::vector<std::string> logs;
  iora::core::Logger::setExternalHandler(
    [&](iora::core::Logger::Level, const std::string &formatted, const std::string &)
    { logs.push_back(formatted); });
  iora::core::Logger::setLevel(iora::core::Logger::Level::Error);

  InnerSpy spy;
  Handler h = requireBasicAuth(
    "r",
    [](const std::string &, const std::string &) -> bool
    { throw std::runtime_error("boom-detail"); },
    spy.handler());
  Request req = makeReq("Basic " + enc("user:pass"));
  Response res;
  h(req, res);
  iora::core::Logger::flush();

  REQUIRE(res.status == 500);
  REQUIRE_FALSE(spy.invoked);
  bool sawWhat = false;
  for (const auto &l : logs)
  {
    if (l.find("boom-detail") != std::string::npos)
    {
      sawWhat = true;
    }
  }
  REQUIRE(sawWhat);

  iora::core::Logger::clearExternalHandler();
}

TEST_CASE("verify throwing non-std::exception -> 500 (catch(...) arm, cpp17 M-5)",
          "[http_auth][throws]")
{
  InnerSpy spy;
  Handler h = requireBasicAuth(
    "r", [](const std::string &, const std::string &) -> bool { throw 42; },
    spy.handler());
  Request req = makeReq("Basic " + enc("user:pass"));
  Response res;
  h(req, res);
  REQUIRE(res.status == 500);
  REQUIRE_FALSE(spy.invoked);
}

TEST_CASE("HR-9: decoded credential never appears in logs on verify-throws path",
          "[http_auth][throws][hr9]")
{
  std::vector<std::string> logs;
  iora::core::Logger::setExternalHandler(
    [&](iora::core::Logger::Level, const std::string &formatted, const std::string &raw)
    {
      logs.push_back(formatted);
      logs.push_back(raw);
    });
  iora::core::Logger::setLevel(iora::core::Logger::Level::Error);

  const std::string secretUser = "topsecretuser";
  const std::string secretPass = "topsecretpass";
  InnerSpy spy;
  Handler h = requireBasicAuth(
    "r",
    [](const std::string &, const std::string &) -> bool
    { throw std::runtime_error("verify failed"); },
    spy.handler());
  Request req = makeReq("Basic " + enc(secretUser + ":" + secretPass));
  Response res;
  h(req, res);
  iora::core::Logger::flush();

  REQUIRE(res.status == 500);
  for (const auto &l : logs)
  {
    REQUIRE(l.find(secretUser) == std::string::npos);
    REQUIRE(l.find(secretPass) == std::string::npos);
  }

  iora::core::Logger::clearExternalHandler();
}

TEST_CASE("inner handler exceptions are NOT caught by requireBasicAuth", "[http_auth][throws]")
{
  Handler h = requireBasicAuth(
    "r", [](const std::string &, const std::string &) { return true; },
    [](const Request &, Response &) -> void { throw std::runtime_error("inner boom"); });
  Request req = makeReq("Basic " + enc("user:pass"));
  Response res;
  // The wrapper must let inner's exception propagate (routing safety-net owns it).
  REQUIRE_THROWS_AS(h(req, res), std::runtime_error);
}
