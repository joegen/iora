// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Tests for RFC 9110 §5.3 repeated-header field-line combining: comma-list fields
// (X-Forwarded-For, Forwarded, Via) are combined with ", " in order; all other fields
// keep last-wins (safe-by-default allow-list). Exercises BOTH the request and response
// parse paths (the two parseHeaderLine impls are separate copies) and the direct
// detail::isListValuedHeader / addOrCombineHeader helpers.

#define CATCH_CONFIG_MAIN
#include "iora/parsers/http_message.hpp"
#include <catch2/catch.hpp>
#include <string>

using iora::network::HttpRequest;
using iora::network::HttpResponse;
using iora::network::HttpHeaders;
namespace detail = iora::network::detail;

namespace
{
// HTTP/1.1 requests now require a Host header (RFC 9110 §7.2), so include one.
std::string reqWith(const std::string &headerLines)
{
  return "GET / HTTP/1.1\r\nHost: example.test\r\n" + headerLines + "\r\n";
}
std::string respWith(const std::string &headerLines)
{
  return "HTTP/1.1 200 OK\r\n" + headerLines + "\r\n";
}
} // namespace

// ---------------------------------------------------------------------------
// Combine path (allow-listed comma-list fields) — both parse paths
// ---------------------------------------------------------------------------
TEST_CASE("XFF repeated field-lines combine in order (request + response)", "[http][combine]")
{
  const std::string hdrs = "X-Forwarded-For: 1.2.3.4\r\nX-Forwarded-For: 10.0.0.1\r\n";

  auto req = HttpRequest::fromWireFormat(reqWith(hdrs));
  REQUIRE(req.headers.at("X-Forwarded-For") == "1.2.3.4, 10.0.0.1");

  auto resp = HttpResponse::fromWireFormat(respWith(hdrs));
  REQUIRE(resp.headers.at("X-Forwarded-For") == "1.2.3.4, 10.0.0.1");
}

TEST_CASE("XFF three field-lines combine in order", "[http][combine]")
{
  const std::string hdrs =
    "X-Forwarded-For: a\r\nX-Forwarded-For: b\r\nX-Forwarded-For: c\r\n";
  auto req = HttpRequest::fromWireFormat(reqWith(hdrs));
  REQUIRE(req.headers.at("X-Forwarded-For") == "a, b, c");
}

TEST_CASE("XFF empty list element is skipped (no stray comma)", "[http][combine]")
{
  // 'x' then '' -> 'x'
  auto a = HttpRequest::fromWireFormat(
    reqWith("X-Forwarded-For: 1.2.3.4\r\nX-Forwarded-For:\r\n"));
  REQUIRE(a.headers.at("X-Forwarded-For") == "1.2.3.4");

  // '' then 'x' -> 'x'
  auto b = HttpRequest::fromWireFormat(
    reqWith("X-Forwarded-For:\r\nX-Forwarded-For: 1.2.3.4\r\n"));
  REQUIRE(b.headers.at("X-Forwarded-For") == "1.2.3.4");
}

TEST_CASE("XFF whitespace-only middle element is skipped", "[http][combine]")
{
  // 'a' then '   ' (OWS-trimmed to "") then 'b' -> 'a, b'
  auto req = HttpRequest::fromWireFormat(
    reqWith("X-Forwarded-For: a\r\nX-Forwarded-For:    \r\nX-Forwarded-For: b\r\n"));
  REQUIRE(req.headers.at("X-Forwarded-For") == "a, b");
}

TEST_CASE("Repeated field-name combine is case-insensitive (one entry)", "[http][combine]")
{
  auto req = HttpRequest::fromWireFormat(
    reqWith("x-forwarded-for: a\r\nX-Forwarded-For: b\r\n"));
  REQUIRE(req.headers.size() >= 1);
  REQUIRE(req.headers.at("X-Forwarded-For") == "a, b"); // case-insensitive key lookup
}

TEST_CASE("Single field-line is unchanged (no trailing comma)", "[http][combine]")
{
  auto req = HttpRequest::fromWireFormat(reqWith("X-Forwarded-For: 1.2.3.4\r\n"));
  REQUIRE(req.headers.at("X-Forwarded-For") == "1.2.3.4");
}

TEST_CASE("OWS trimmed per value before combine", "[http][combine]")
{
  auto req = HttpRequest::fromWireFormat(
    reqWith("X-Forwarded-For:   a  \r\nX-Forwarded-For:  b   \r\n"));
  REQUIRE(req.headers.at("X-Forwarded-For") == "a, b");
}

TEST_CASE("Via combines (RFC 9110 7.6.3 #list)", "[http][combine]")
{
  auto resp = HttpResponse::fromWireFormat(respWith("Via: 1.1 a\r\nVia: 1.1 b\r\n"));
  REQUIRE(resp.headers.at("Via") == "1.1 a, 1.1 b");
}

TEST_CASE("Forwarded combines (RFC 7239 4/7.1 #list)", "[http][combine]")
{
  auto req = HttpRequest::fromWireFormat(
    reqWith("Forwarded: for=192.0.2.43\r\nForwarded: for=198.51.100.17\r\n"));
  REQUIRE(req.headers.at("Forwarded") == "for=192.0.2.43, for=198.51.100.17");
}

// ---------------------------------------------------------------------------
// Safe-by-default: non-list fields keep last-wins (discriminating, comma-bearing)
// ---------------------------------------------------------------------------
TEST_CASE("Set-Cookie is NOT comma-combined (last-wins)", "[http][nocombine]")
{
  // Comma-bearing Expires dates make combine-vs-overwrite observable through the map.
  const std::string hdrs =
    "Set-Cookie: id=1; Expires=Wed, 09 Jun 2027 10:18:14 GMT\r\n"
    "Set-Cookie: id=2; Expires=Thu, 10 Jun 2027 10:18:14 GMT\r\n";
  auto resp = HttpResponse::fromWireFormat(respWith(hdrs));
  REQUIRE(resp.headers.at("Set-Cookie") == "id=2; Expires=Thu, 10 Jun 2027 10:18:14 GMT");
}

TEST_CASE("Retry-After is NOT comma-combined (last-wins)", "[http][nocombine]")
{
  const std::string hdrs =
    "Retry-After: Wed, 09 Jun 2027 10:18:14 GMT\r\n"
    "Retry-After: Thu, 10 Jun 2027 10:18:14 GMT\r\n";
  auto resp = HttpResponse::fromWireFormat(respWith(hdrs));
  REQUIRE(resp.headers.at("Retry-After") == "Thu, 10 Jun 2027 10:18:14 GMT");
}

TEST_CASE("Cookie request header is NOT combined (last-wins)", "[http][nocombine]")
{
  auto req = HttpRequest::fromWireFormat(
    reqWith("Cookie: a=1\r\nCookie: b=2\r\n"));
  REQUIRE(req.headers.at("Cookie") == "b=2");
}

TEST_CASE("Content-Length is NOT combined (last-wins, no smuggling)", "[http][nocombine]")
{
  auto req = HttpRequest::fromWireFormat(
    reqWith("Content-Length: 5\r\nContent-Length: 7\r\n"));
  REQUIRE(req.headers.at("Content-Length") == "7"); // NOT "5, 7"
}

TEST_CASE("Date is NOT combined (last-wins)", "[http][nocombine]")
{
  auto resp = HttpResponse::fromWireFormat(respWith(
    "Date: Wed, 09 Jun 2027 10:18:14 GMT\r\nDate: Thu, 10 Jun 2027 10:18:14 GMT\r\n"));
  REQUIRE(resp.headers.at("Date") == "Thu, 10 Jun 2027 10:18:14 GMT");
}

TEST_CASE("X-Forwarded-Proto is NOT combined (single-valued-per-hop, last-wins)",
          "[http][nocombine]")
{
  auto req = HttpRequest::fromWireFormat(
    reqWith("X-Forwarded-Proto: https\r\nX-Forwarded-Proto: http\r\n"));
  REQUIRE(req.headers.at("X-Forwarded-Proto") == "http"); // NOT "https, http"
}

// ---------------------------------------------------------------------------
// Direct helper assertions (prove the branch independent of map collapse)
// ---------------------------------------------------------------------------
TEST_CASE("isListValuedHeader allow/deny set", "[http][helper]")
{
  REQUIRE(detail::isListValuedHeader("X-Forwarded-For"));
  REQUIRE(detail::isListValuedHeader("x-forwarded-for")); // case-insensitive
  REQUIRE(detail::isListValuedHeader("Via"));
  REQUIRE(detail::isListValuedHeader("Forwarded"));

  REQUIRE_FALSE(detail::isListValuedHeader("Set-Cookie"));
  REQUIRE_FALSE(detail::isListValuedHeader("Cookie"));
  REQUIRE_FALSE(detail::isListValuedHeader("Content-Length"));
  REQUIRE_FALSE(detail::isListValuedHeader("Retry-After"));
  REQUIRE_FALSE(detail::isListValuedHeader("Date"));
  REQUIRE_FALSE(detail::isListValuedHeader("Host"));
  REQUIRE_FALSE(detail::isListValuedHeader("X-Forwarded-Host"));
  REQUIRE_FALSE(detail::isListValuedHeader("X-Forwarded-Proto"));
}

TEST_CASE("addOrCombineHeader branches", "[http][helper]")
{
  HttpHeaders h;
  detail::addOrCombineHeader(h, "X-Forwarded-For", "a");
  REQUIRE(h.at("X-Forwarded-For") == "a"); // absent -> insert
  detail::addOrCombineHeader(h, "X-Forwarded-For", "b");
  REQUIRE(h.at("X-Forwarded-For") == "a, b"); // list -> combine
  detail::addOrCombineHeader(h, "X-Forwarded-For", "");
  REQUIRE(h.at("X-Forwarded-For") == "a, b"); // list + empty -> no-op

  detail::addOrCombineHeader(h, "Content-Length", "5");
  detail::addOrCombineHeader(h, "Content-Length", "7");
  REQUIRE(h.at("Content-Length") == "7"); // non-list -> last-wins
}

// ---------------------------------------------------------------------------
// Body-framing independence (defense-in-depth)
// ---------------------------------------------------------------------------
TEST_CASE("Duplicate Content-Length: handler-visible header is last-wins, not combined",
          "[http][framing]")
{
  // NOTE: the HttpServer frames the request body in its OWN header loop BEFORE
  // fromWireFormat, so the parsed headers map is never consulted for body framing.
  // Here we pin that the parsed (handler-visible) Content-Length stays last-wins ("7"),
  // so even a future server-loop refactor that re-read the parsed map could not pick up
  // a combined "5, 7" value.
  auto req = HttpRequest::fromWireFormat(
    "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\nContent-Length: 7\r\n\r\nHELLO!!");
  REQUIRE(req.headers.at("Content-Length") == "7");
}

// ---------------------------------------------------------------------------
// Request correctness enforcement (RFC 9112 §3.2 / §5.2) — added in-scope
// ---------------------------------------------------------------------------
TEST_CASE("HTTP/1.1 request missing Host is rejected (400)", "[http][host]")
{
  REQUIRE_THROWS_AS(
    HttpRequest::fromWireFormat("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"),
    iora::network::HttpRequestError);
}

TEST_CASE("HTTP/1.0 request without Host is accepted", "[http][host]")
{
  auto req = HttpRequest::fromWireFormat("GET / HTTP/1.0\r\nAccept: */*\r\n\r\n");
  REQUIRE(req.version.major == 1);
  REQUIRE(req.version.minor == 0);
}

TEST_CASE("Duplicate Host field-line is rejected (400)", "[http][host]")
{
  bool threw = false;
  try
  {
    HttpRequest::fromWireFormat(
      "GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n");
  }
  catch (const iora::network::HttpRequestError &e)
  {
    threw = true;
    REQUIRE(e.status() == 400);
  }
  REQUIRE(threw);
}

TEST_CASE("Duplicate Host detection is case-insensitive", "[http][host]")
{
  REQUIRE_THROWS_AS(
    HttpRequest::fromWireFormat("GET / HTTP/1.1\r\nHost: a.example\r\nhost: b.example\r\n\r\n"),
    iora::network::HttpRequestError);
}

TEST_CASE("Single Host field-line is accepted", "[http][host]")
{
  auto req = HttpRequest::fromWireFormat("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n");
  REQUIRE(req.headers.at("Host") == "a.example");
}

TEST_CASE("Empty Host field value is rejected (400)", "[http][host]")
{
  bool threw = false;
  try
  {
    HttpRequest::fromWireFormat("GET / HTTP/1.1\r\nHost:\r\n\r\n");
  }
  catch (const iora::network::HttpRequestError &e)
  {
    threw = true;
    REQUIRE(e.status() == 400);
  }
  REQUIRE(threw);
}

TEST_CASE("OWS-only Host field value is rejected (400)", "[http][host]")
{
  REQUIRE_THROWS_AS(HttpRequest::fromWireFormat("GET / HTTP/1.1\r\nHost:    \r\n\r\n"),
                    iora::network::HttpRequestError);
}

TEST_CASE("obs-fold continuation line is rejected (400)", "[http][obsfold]")
{
  bool threw = false;
  try
  {
    // Second line begins with SP -> obsolete line folding.
    HttpRequest::fromWireFormat(
      "GET / HTTP/1.1\r\nHost: example.test\r\nX-Foo: bar\r\n  continued\r\n\r\n");
  }
  catch (const iora::network::HttpRequestError &e)
  {
    threw = true;
    REQUIRE(e.status() == 400);
  }
  REQUIRE(threw);
}

TEST_CASE("HTAB-led obs-fold continuation line is rejected (400)", "[http][obsfold]")
{
  bool threw = false;
  try
  {
    HttpRequest::fromWireFormat("GET / HTTP/1.1\r\nHost: example.test\r\n\tfolded\r\n\r\n");
  }
  catch (const iora::network::HttpRequestError &e)
  {
    threw = true;
    REQUIRE(e.status() == 400);
  }
  REQUIRE(threw);
}

TEST_CASE("obs-fold as the FIRST header line (after request line) is rejected (400)",
          "[http][obsfold]")
{
  // A continuation line with no logical predecessor header is still rejected
  // (the check is positional, not stateful).
  REQUIRE_THROWS_AS(
    HttpRequest::fromWireFormat("GET / HTTP/1.1\r\n folded\r\nHost: example.test\r\n\r\n"),
    iora::network::HttpRequestError);
}
