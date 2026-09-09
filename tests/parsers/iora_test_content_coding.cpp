// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Direct unit coverage for the Content-Encoding list-splitting primitives
// (content_coding.hpp): empty-element skipping (RFC 9110 §5.6.1), the gzip/x-gzip
// equivalence (§8.4.1), and the log-injection scrubbing of sanitizeCodingForLog.
// These were previously covered only transitively via the jsonrpc gzip tests.
// (Doc-review web-M3.)

#define CATCH_CONFIG_MAIN
#include "iora/parsers/content_coding.hpp"
#include <catch2/catch.hpp>
#include <string>
#include <string_view>

using iora::parsers::isGzipContentCoding;
using iora::parsers::sanitizeCodingForLog;
using iora::parsers::splitContentCodings;

TEST_CASE("splitContentCodings: ordered, trimmed, empty-element skipping", "[content_coding]")
{
  REQUIRE(splitContentCodings("gzip") == std::vector<std::string>{"gzip"});
  REQUIRE(splitContentCodings("gzip, deflate") == std::vector<std::string>{"gzip", "deflate"});
  // RFC 9110 §5.6.1: empty list elements (a comma-combining artifact) are dropped.
  REQUIRE(splitContentCodings("gzip,,") == std::vector<std::string>{"gzip"});
  REQUIRE(splitContentCodings(", gzip") == std::vector<std::string>{"gzip"});
  REQUIRE(splitContentCodings("  gzip  ,  deflate  ") ==
          std::vector<std::string>{"gzip", "deflate"});
  REQUIRE(splitContentCodings("").empty());
  REQUIRE(splitContentCodings("   ").empty());
  REQUIRE(splitContentCodings(",,,").empty());
}

TEST_CASE("splitContentCodings: accepts a string_view without materializing", "[content_coding]")
{
  // Regression for the string_view parameter: a view caller must bind directly.
  std::string_view v = "gzip, identity";
  REQUIRE(splitContentCodings(v) == std::vector<std::string>{"gzip", "identity"});
}

TEST_CASE("isGzipContentCoding: gzip and x-gzip, case-insensitive", "[content_coding]")
{
  REQUIRE(isGzipContentCoding("gzip"));
  REQUIRE(isGzipContentCoding("GZIP"));
  REQUIRE(isGzipContentCoding("x-gzip"));
  REQUIRE(isGzipContentCoding("X-Gzip"));
  REQUIRE_FALSE(isGzipContentCoding("deflate"));
  REQUIRE_FALSE(isGzipContentCoding("br"));
  REQUIRE_FALSE(isGzipContentCoding(""));
}

TEST_CASE("sanitizeCodingForLog: scrubs control octets and bounds length", "[content_coding]")
{
  REQUIRE(sanitizeCodingForLog("gzip") == "gzip");
  // CR/LF/tab fold to a single space each (log-line forging defeated).
  REQUIRE(sanitizeCodingForLog("gz\r\nip") == "gz  ip");
  REQUIRE(sanitizeCodingForLog("a\tb") == "a b");
  // Other control octets are dropped entirely.
  REQUIRE(sanitizeCodingForLog(std::string("a\x01\x02" "b")) == "ab");
  // Length bound with an ellipsis marker when truncated.
  const std::string big(200, 'x');
  const std::string scrubbed = sanitizeCodingForLog(big, 8);
  REQUIRE(scrubbed == "xxxxxxxx...");
}
