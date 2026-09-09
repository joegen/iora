// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Hardening coverage for parsers/http_message.hpp surfaced by the parsers doc-review:
//  - chunked-body allocation is bounded against a hostile chunk-size (web-H1);
//  - conflicting Content-Length and Transfer-Encoding+Content-Length are rejected on
//    the request path per RFC 9112 §6.3 (web-M1);
//  - MultipartFormData rejects part parameters that would inject header framing (web-M2);
//  - parseUrl scheme lowering is locale-independent and safe for high bytes (web-L2);
//  - "chunked" is detected only as the FINAL transfer-coding token (web-L4).

#define CATCH_CONFIG_MAIN
#include "iora/parsers/http_message.hpp"
#include <catch2/catch.hpp>
#include <string>

using iora::network::HttpRequest;
using iora::network::HttpRequestError;
using iora::network::HttpResponse;
using iora::network::MultipartFormData;
using iora::network::parseUrl;

namespace
{
std::string respChunked(const std::string &teValue, const std::string &chunkedBody)
{
  return "HTTP/1.1 200 OK\r\nTransfer-Encoding: " + teValue + "\r\n\r\n" + chunkedBody;
}
} // namespace

// ---------------------------------------------------------------------------
// web-H1: chunked-body allocation is bounded against a hostile chunk-size.
// ---------------------------------------------------------------------------
TEST_CASE("parseChunkedBody: valid chunked body decodes", "[http_message][chunked]")
{
  auto r = HttpResponse::fromWireFormat(respChunked("chunked", "5\r\nHello\r\n0\r\n\r\n"));
  REQUIRE(r.body == "Hello");
}

TEST_CASE("parseChunkedBody: oversized chunk-size does not over-allocate", "[http_message][chunked]")
{
  // 0x7fffffffffffffff would allocate ~9 EiB with the old code; the size now
  // exceeds the buffered payload and the parse stops without allocating it.
  auto r = HttpResponse::fromWireFormat(respChunked("chunked", "7fffffffffffffff\r\nx\r\n0\r\n\r\n"));
  REQUIRE(r.body.empty());
}

TEST_CASE("parseChunkedBody: negative/sign-prefixed chunk-size is rejected", "[http_message][chunked]")
{
  // std::stoull(base 16) would accept "-1" as SIZE_MAX; the lead-byte HEXDIG check
  // rejects it before any allocation.
  auto r = HttpResponse::fromWireFormat(respChunked("chunked", "-1\r\nx\r\n0\r\n\r\n"));
  REQUIRE(r.body.empty());
}

// ---------------------------------------------------------------------------
// web-L4: "chunked" only as the final transfer-coding token.
// ---------------------------------------------------------------------------
TEST_CASE("chunked detection uses the final coding token, not a substring",
          "[http_message][chunked]")
{
  // Final token IS chunked -> de-chunked.
  REQUIRE(HttpResponse::fromWireFormat(respChunked("gzip, chunked", "5\r\nHello\r\n0\r\n\r\n")).body ==
          "Hello");
  // "x-chunked" is a different token -> body left as-is.
  REQUIRE(HttpResponse::fromWireFormat(respChunked("x-chunked", "5\r\nHello\r\n0\r\n\r\n")).body ==
          "5\r\nHello\r\n0\r\n\r\n");
  // "chunked" not final -> body left as-is.
  REQUIRE(HttpResponse::fromWireFormat(respChunked("chunked, gzip", "5\r\nHello\r\n0\r\n\r\n")).body ==
          "5\r\nHello\r\n0\r\n\r\n");
}

// ---------------------------------------------------------------------------
// web-M1: conflicting Content-Length / Transfer-Encoding+Content-Length (RFC 9112 §6.3).
// ---------------------------------------------------------------------------
TEST_CASE("request with conflicting Content-Length is rejected 400", "[http_message][smuggling]")
{
  const std::string req = "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n";
  bool threw = false;
  try
  {
    HttpRequest::fromWireFormat(req);
  }
  catch (const HttpRequestError &e)
  {
    threw = true;
    REQUIRE(e.status() == 400);
  }
  REQUIRE(threw);
}

TEST_CASE("request with identical duplicate Content-Length is tolerated", "[http_message][smuggling]")
{
  const std::string req = "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n";
  REQUIRE_NOTHROW(HttpRequest::fromWireFormat(req));
}

TEST_CASE("request with Transfer-Encoding and Content-Length is rejected 400",
          "[http_message][smuggling]")
{
  const std::string req =
    "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n";
  REQUIRE_THROWS_AS(HttpRequest::fromWireFormat(req), HttpRequestError);
}

TEST_CASE("request with a single Content-Length still parses", "[http_message][smuggling]")
{
  const std::string req = "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nbody";
  REQUIRE_NOTHROW(HttpRequest::fromWireFormat(req));
}

// ---------------------------------------------------------------------------
// web-M2: MultipartFormData rejects header-injecting part parameters (RFC 7578 §4.2).
// ---------------------------------------------------------------------------
TEST_CASE("MultipartFormData rejects injection in name/filename/contentType",
          "[http_message][multipart]")
{
  MultipartFormData m;
  REQUIRE_THROWS_AS(m.addField("na\nme", "v"), std::invalid_argument);
  REQUIRE_THROWS_AS(m.addFile("f", "ev\"il.txt", "data"), std::invalid_argument);
  REQUIRE_THROWS_AS(m.addFile("f", "ok.txt", "data", "text/plain\r\nX-Inject: 1"),
                    std::invalid_argument);
}

TEST_CASE("MultipartFormData accepts clean parts and frames them", "[http_message][multipart]")
{
  MultipartFormData m;
  REQUIRE_NOTHROW(m.addField("field", "value"));
  REQUIRE_NOTHROW(m.addFile("file", "ok.txt", "data", "text/plain"));
  const std::string body = m.build();
  REQUIRE(body.find("name=\"field\"") != std::string::npos);
  REQUIRE(body.find("filename=\"ok.txt\"") != std::string::npos);
}

// ---------------------------------------------------------------------------
// web-L2: parseUrl scheme lowering is locale-independent and safe.
// ---------------------------------------------------------------------------
TEST_CASE("parseUrl lower-cases the scheme without touching host case", "[http_message][url]")
{
  auto u = parseUrl("HTTP://Example.COM/path");
  REQUIRE(u.scheme == "http");
  REQUIRE(u.host == "Example.COM");
  auto s = parseUrl("HTTPS://h/");
  REQUIRE(s.scheme == "https");
  REQUIRE(s.isHttps());
}

// ---------------------------------------------------------------------------
// Round-2 review additions.
// ---------------------------------------------------------------------------

// web-H1 boundary: a chunk-size exactly equal to the buffered payload size is
// permitted (the bound is '>' not '>='), and stoull out-of-range (>16 hex digits)
// is handled without escaping fromWireFormat.
TEST_CASE("parseChunkedBody: chunk-size equal to buffer size is accepted", "[http_message][chunked]")
{
  const std::string chunked = "10\r\nABCDEFGHIJKL"; // "10\r\n"(4) + 12 = 16 bytes; 0x10 == 16
  auto r = HttpResponse::fromWireFormat("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked);
  REQUIRE(r.body == "ABCDEFGHIJKL");
}

TEST_CASE("parseChunkedBody: out-of-range (>64-bit) chunk-size is handled", "[http_message][chunked]")
{
  auto r = HttpResponse::fromWireFormat(respChunked("chunked", "fffffffffffffffff\r\nx\r\n0\r\n\r\n"));
  REQUIRE(r.body.empty());
}

// web-L2: a trailing empty list element ("chunked,") still frames as chunked.
TEST_CASE("chunked detection skips a trailing empty list element", "[http_message][chunked]")
{
  REQUIRE(HttpResponse::fromWireFormat(respChunked("chunked,", "5\r\nHello\r\n0\r\n\r\n")).body ==
          "Hello");
}

// web-M1: a single invalid Content-Length value (combined "5, 6", non-digit, empty)
// is rejected 400.
TEST_CASE("request with an invalid single Content-Length value is rejected 400",
          "[http_message][smuggling]")
{
  for (const char *cl : {"5, 6", "abc", "+5", "-1", "0x5", ""})
  {
    const std::string req =
      "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: " + std::string(cl) + "\r\n\r\n";
    REQUIRE_THROWS_AS(HttpRequest::fromWireFormat(req), HttpRequestError);
  }
}

// cpp17-#3b: two Content-Length lines with equal value but different surrounding
// whitespace collapse to one (no 400).
TEST_CASE("request with same-valued Content-Length and differing OWS is tolerated",
          "[http_message][smuggling]")
{
  const std::string req = "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length:  5 \r\n\r\n";
  REQUIRE_NOTHROW(HttpRequest::fromWireFormat(req));
}

// web-M2: whitespace between the header field name and the colon is rejected 400 (RFC 9112 §5.1).
TEST_CASE("request with whitespace before a header colon is rejected 400", "[http_message][smuggling]")
{
  REQUIRE_THROWS_AS(
    HttpRequest::fromWireFormat("GET / HTTP/1.1\r\nHost: h\r\nContent-Length : 5\r\n\r\n"),
    HttpRequestError);
  REQUIRE_THROWS_AS(
    HttpRequest::fromWireFormat("GET / HTTP/1.1\r\nHost\t: h\r\n\r\n"), HttpRequestError);
}

// web-L1: a request Transfer-Encoding whose final coding is not chunked is rejected 400;
// a final chunked coding is accepted.
TEST_CASE("request Transfer-Encoding must end in chunked", "[http_message][smuggling]")
{
  REQUIRE_NOTHROW(
    HttpRequest::fromWireFormat("POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"));
  REQUIRE_NOTHROW(HttpRequest::fromWireFormat(
    "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"));
  REQUIRE_THROWS_AS(
    HttpRequest::fromWireFormat("POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\n\r\n"),
    HttpRequestError);
  REQUIRE_THROWS_AS(HttpRequest::fromWireFormat(
                      "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"),
                    HttpRequestError);
}

// cpp17-#3a: an internal-whitespace-separated Content-Length ("5 6", no comma) is
// rejected (not 1*DIGIT); a legitimate "Content-Length: 0" is accepted.
TEST_CASE("request Content-Length digit validation edge cases", "[http_message][smuggling]")
{
  REQUIRE_THROWS_AS(
    HttpRequest::fromWireFormat("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5 6\r\n\r\n"),
    HttpRequestError);
  REQUIRE_NOTHROW(
    HttpRequest::fromWireFormat("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n"));
}

// web-L1 request-path: a Transfer-Encoding with a trailing empty element ("chunked,")
// is accepted (final coding is chunked); a parameterized final coding is accepted.
TEST_CASE("request Transfer-Encoding trailing-empty and parameterized chunked accepted",
          "[http_message][smuggling]")
{
  REQUIRE_NOTHROW(
    HttpRequest::fromWireFormat("POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked,\r\n\r\n"));
  REQUIRE_NOTHROW(HttpRequest::fromWireFormat(
    "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked;x=y\r\n\r\n"));
}

// cpp17-L2 / web-L3: two Transfer-Encoding field-lines whose (last) final coding is
// chunked are accepted; a last line that is not chunked-final is rejected.
TEST_CASE("request with multiple Transfer-Encoding lines", "[http_message][smuggling]")
{
  REQUIRE_NOTHROW(HttpRequest::fromWireFormat(
    "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"));
  REQUIRE_THROWS_AS(
    HttpRequest::fromWireFormat(
      "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n"),
    HttpRequestError);
}

// web-M3: a quoted media-type parameter in contentType is legitimate and accepted.
TEST_CASE("MultipartFormData accepts a quoted content-type parameter", "[http_message][multipart]")
{
  MultipartFormData m;
  REQUIRE_NOTHROW(m.addFile("f", "ok.txt", "data", "text/plain; charset=\"utf-8\""));
  REQUIRE(m.build().find("charset=\"utf-8\"") != std::string::npos);
}

// web-M4: a backslash in name/filename (quoted-pair breakout) is rejected.
TEST_CASE("MultipartFormData rejects a backslash in filename", "[http_message][multipart]")
{
  MultipartFormData m;
  REQUIRE_THROWS_AS(m.addFile("f", "evil\\", "data"), std::invalid_argument);
  REQUIRE_THROWS_AS(m.addField("na\\me", "v"), std::invalid_argument);
}

// cpp17-#3c: the default contentType is accepted.
TEST_CASE("MultipartFormData addFile default content-type is accepted", "[http_message][multipart]")
{
  MultipartFormData m;
  REQUIRE_NOTHROW(m.addFile("f", "ok.bin", "data"));
  REQUIRE(m.build().find("application/octet-stream") != std::string::npos);
}

// web-L3: an embedded boundary in part content forces the boundary to move.
TEST_CASE("MultipartFormData boundary never appears in part content", "[http_message][multipart]")
{
  MultipartFormData m;
  m.addField("f", m.getBoundary()); // content == current boundary -> must regenerate
  REQUIRE(m.build().find(m.getBoundary()) != std::string::npos);
  // The (possibly-new) boundary must not occur inside the field content region.
  const std::string body = m.build();
  const std::string bnd = m.getBoundary();
  // Count boundary occurrences: 2 separators (open + close) only, none from content.
  std::size_t count = 0;
  for (std::size_t p = body.find(bnd); p != std::string::npos; p = body.find(bnd, p + 1))
  {
    ++count;
  }
  REQUIRE(count == 2);
}
