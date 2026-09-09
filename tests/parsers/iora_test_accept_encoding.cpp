// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Direct unit coverage for the Accept-Encoding acceptability primitive
// (accept_encoding.hpp). Prior to this file, gzipAcceptable and its q-value grammar
// helpers were exercised only transitively via the jsonrpc gzip tests; the RFC 9110
// §12.5.3 grammar bounds (>3 fractional digits, out-of-range q), the x-gzip alias
// (§8.4.1), the '*' fallback/precedence, and the absent-vs-empty distinction had no
// direct assertions. (Doc-review web-M3.)

#define CATCH_CONFIG_MAIN
#include "iora/parsers/accept_encoding.hpp"
#include <catch2/catch.hpp>

using iora::parsers::gzipAcceptable;
namespace aed = iora::parsers::acceptencoding_detail;

TEST_CASE("gzipAcceptable: basic gzip acceptance", "[accept_encoding]")
{
  REQUIRE(gzipAcceptable("gzip"));
  REQUIRE(gzipAcceptable("gzip;q=1"));
  REQUIRE(gzipAcceptable("gzip;q=1.0"));
  REQUIRE(gzipAcceptable("deflate, gzip"));
  REQUIRE(gzipAcceptable("GZIP")); // ASCII case-insensitive
}

TEST_CASE("gzipAcceptable: q=0 and out-of-range q are not acceptable", "[accept_encoding]")
{
  REQUIRE_FALSE(gzipAcceptable("gzip;q=0"));
  REQUIRE_FALSE(gzipAcceptable("gzip;q=0.0"));
  REQUIRE_FALSE(gzipAcceptable("gzip;q=1.5")); // >1.0 is a grammar violation -> 0.0
  REQUIRE_FALSE(gzipAcceptable("gzip;q=0.0000")); // >3 fractional digits -> 0.0
}

TEST_CASE("gzipAcceptable: x-gzip legacy alias (RFC 9110 §8.4.1)", "[accept_encoding]")
{
  REQUIRE(gzipAcceptable("x-gzip"));
  REQUIRE(gzipAcceptable("X-GZIP"));
  REQUIRE_FALSE(gzipAcceptable("x-gzip;q=0"));
}

TEST_CASE("gzipAcceptable: '*' fallback and explicit-gzip precedence", "[accept_encoding]")
{
  REQUIRE(gzipAcceptable("*"));
  REQUIRE_FALSE(gzipAcceptable("*;q=0"));
  // An explicit gzip entry wins over '*' regardless of order.
  REQUIRE_FALSE(gzipAcceptable("gzip;q=0, *"));
  REQUIRE_FALSE(gzipAcceptable("*, gzip;q=0"));
  REQUIRE(gzipAcceptable("gzip;q=1, *;q=0"));
}

TEST_CASE("gzipAcceptable: absent/empty and identity-only resolve to false", "[accept_encoding]")
{
  REQUIRE_FALSE(gzipAcceptable(""));        // empty header value
  REQUIRE_FALSE(gzipAcceptable("   "));     // OWS-only
  REQUIRE_FALSE(gzipAcceptable("identity")); // no gzip / no '*'
  REQUIRE_FALSE(gzipAcceptable("deflate, br"));
}

TEST_CASE("parseQValue grammar bounds (RFC 9110 §12.5.5)", "[accept_encoding]")
{
  REQUIRE(aed::parseQValue("1") == Approx(1.0));
  REQUIRE(aed::parseQValue("0") == Approx(0.0));
  REQUIRE(aed::parseQValue("0.5") == Approx(0.5));
  REQUIRE(aed::parseQValue("0.123") == Approx(0.123));
  REQUIRE(aed::parseQValue("1.5") == Approx(0.0));    // out of range
  REQUIRE(aed::parseQValue("0.1234") == Approx(0.0)); // >3 fractional digits
  REQUIRE(aed::parseQValue("") == Approx(0.0));
  REQUIRE(aed::parseQValue("x") == Approx(0.0));
}

TEST_CASE("qValueOf: absent q defaults to 1.0, malformed q to 0.0", "[accept_encoding]")
{
  REQUIRE(aed::qValueOf("") == Approx(1.0));          // no explicit q
  REQUIRE(aed::qValueOf("q=0.7") == Approx(0.7));
  REQUIRE(aed::qValueOf("charset=utf-8;q=0.3") == Approx(0.3));
  REQUIRE(aed::qValueOf("q=1.5") == Approx(0.0));      // out-of-range q
}
