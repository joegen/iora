// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Unit tests for the SHARED HTTP request-framing primitives in
// iora::network::detail (tracker 2026-09-12-1). These primitives are the single
// source of truth that both the strict parser (HttpRequest::fromWireFormat /
// decodeChunkedRequestBody) and the transport framer (HttpServer::handleData /
// findChunkedRequestEnd) compute their framing DECISION from, so that the two
// layers can never again drift apart on where a request ends (RFC 9112 §6.3/§7.1).
// Each layer keeps its own DISPOSITION (parser throws; framer poisons / needs-more)
// but the shared decision here is what makes cross-layer agreement structural.
//
//   - detail::isHexDigit          — the one ASCII hex-digit predicate.
//   - detail::parseFullUInt       — strict full-token unsigned parse (from_chars).
//   - detail::parseChunkSize      — chunk-size token: ext-strip, OWS, 1*HEXDIG, convert.
//   - detail::chunkDataStep       — tri-state {Ok|NeedMore|Malformed} chunk-data bound.
//   - detail::walkTrailerSection  — tri-state trailer-section walker.
//   - detail::decideRequestFraming — RFC 9112 §6.3 verdict (reason-carrying).

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "iora/parsers/http_message.hpp"

#include <cstdint>
#include <string>

namespace detail = iora::network::detail;

// ── Phase 1: detail::isHexDigit ─────────────────────────────────────────────
TEST_CASE("detail::isHexDigit accepts exactly [0-9A-Fa-f]", "[http_framing_detail][hex]")
{
  for (char c = '0'; c <= '9'; ++c)
  {
    REQUIRE(detail::isHexDigit(c));
  }
  for (char c = 'a'; c <= 'f'; ++c)
  {
    REQUIRE(detail::isHexDigit(c));
  }
  for (char c = 'A'; c <= 'F'; ++c)
  {
    REQUIRE(detail::isHexDigit(c));
  }
}

TEST_CASE("detail::isHexDigit rejects boundary and non-hex bytes", "[http_framing_detail][hex]")
{
  // Boundaries just outside the three ranges.
  REQUIRE_FALSE(detail::isHexDigit('/'));  // '0'-1
  REQUIRE_FALSE(detail::isHexDigit(':'));  // '9'+1
  REQUIRE_FALSE(detail::isHexDigit('`'));  // 'a'-1
  REQUIRE_FALSE(detail::isHexDigit('g'));  // 'f'+1
  REQUIRE_FALSE(detail::isHexDigit('@'));  // 'A'-1
  REQUIRE_FALSE(detail::isHexDigit('G'));  // 'F'+1
  // Sign / whitespace / high-bit bytes std::stoull would otherwise tolerate.
  REQUIRE_FALSE(detail::isHexDigit('+'));
  REQUIRE_FALSE(detail::isHexDigit('-'));
  REQUIRE_FALSE(detail::isHexDigit(' '));
  REQUIRE_FALSE(detail::isHexDigit('\t'));
  REQUIRE_FALSE(detail::isHexDigit('\0'));
  REQUIRE_FALSE(detail::isHexDigit(static_cast<char>(0x80)));
  REQUIRE_FALSE(detail::isHexDigit(static_cast<char>(0xFF)));
}

// ── detail::parseFullUInt ───────────────────────────────────────────────────
TEST_CASE("detail::parseFullUInt strict full-token semantics", "[http_framing_detail][uint]")
{
  auto parse = [](const std::string &s, int base, std::uint64_t &out)
  { return detail::parseFullUInt(s.data(), s.data() + s.size(), base, out); };
  std::uint64_t v = 0;
  REQUIRE((parse("0", 10, v) && v == 0));
  REQUIRE((parse("42", 10, v) && v == 42));
  REQUIRE((parse("05", 10, v) && v == 5));          // leading zero accepted
  REQUIRE((parse("ff", 16, v) && v == 255));
  REQUIRE((parse("18446744073709551615", 10, v) && v == UINT64_MAX)); // 2^64-1
  REQUIRE_FALSE(parse("", 10, v));                   // empty
  REQUIRE_FALSE(parse("+5", 10, v));                 // leading sign
  REQUIRE_FALSE(parse("-1", 10, v));
  REQUIRE_FALSE(parse(" 5", 10, v));                 // leading whitespace
  REQUIRE_FALSE(parse("5 ", 10, v));                 // trailing junk
  REQUIRE_FALSE(parse("5x", 10, v));                 // trailing junk
  REQUIRE_FALSE(parse("18446744073709551616", 10, v)); // 2^64 overflow
  REQUIRE_FALSE(parse("10000000000000000", 16, v));  // 2^64 overflow (hex)
}

// ── Phase 2: detail::parseChunkSize ─────────────────────────────────────────
TEST_CASE("detail::parseChunkSize handles ext, OWS, hex, overflow",
          "[http_framing_detail][chunk]")
{
  // Helper: build "<line>\r\n" and parse [0, crlfPos).
  auto parseLine = [](const std::string &line, std::uint64_t &out)
  {
    const std::string data = line + "\r\n";
    return detail::parseChunkSize(data, 0, line.size(), out);
  };
  std::uint64_t sz = 0;
  REQUIRE((parseLine("5", sz) && sz == 5));
  REQUIRE((parseLine("a", sz) && sz == 10));
  REQUIRE((parseLine("FF", sz) && sz == 255));           // uppercase HEXDIG
  REQUIRE((parseLine("1a", sz) && sz == 26));
  REQUIRE((parseLine("5;ext=foo", sz) && sz == 5));      // chunk-ext stripped
  REQUIRE((parseLine("5 \t", sz) && sz == 5));           // trailing OWS trimmed
  REQUIRE((parseLine("a;x", sz) && sz == 10));
  REQUIRE((parseLine("0", sz) && sz == 0));              // terminating size
  REQUIRE_FALSE(parseLine("", sz));                       // empty token
  REQUIRE_FALSE(parseLine(";ext", sz));                   // ext with no size
  REQUIRE_FALSE(parseLine(" 5", sz));                     // leading OWS not allowed
  REQUIRE_FALSE(parseLine("-1", sz));                     // sign
  REQUIRE_FALSE(parseLine("0x5", sz));                    // 'x' not HEXDIG
  REQUIRE_FALSE(parseLine("g", sz));                      // non-hex
  REQUIRE_FALSE(parseLine("10000000000000000", sz));      // 2^64 overflow
  REQUIRE(parseLine("ffffffffffffffff", sz));             // 2^64-1 in range
  REQUIRE(sz == UINT64_MAX);
}

// ── Phase 2: detail::chunkDataStep (tri-state) ──────────────────────────────
TEST_CASE("detail::chunkDataStep Ok / NeedMore / Malformed", "[http_framing_detail][chunk]")
{
  std::size_t nextPos = 0;
  // Ok: "HELLO\r\n" starting at 0, size 5 -> newPos past CRLF (7).
  {
    const std::string d = "HELLO\r\n";
    REQUIRE(detail::chunkDataStep(d, 0, 5, nextPos) == detail::FramingStep::Ok);
    REQUIRE(nextPos == 7);
  }
  // NeedMore: chunk-data itself not fully present.
  {
    const std::string d = "HEL"; // only 3 of 5 data bytes
    REQUIRE(detail::chunkDataStep(d, 0, 5, nextPos) == detail::FramingStep::NeedMore);
  }
  // NeedMore: data present but the 2 CRLF bytes not yet arrived.
  {
    const std::string d = "HELLO"; // 5 data, 0 of 2 CRLF
    REQUIRE(detail::chunkDataStep(d, 0, 5, nextPos) == detail::FramingStep::NeedMore);
    const std::string d2 = "HELLO\r"; // only 1 of 2 CRLF
    REQUIRE(detail::chunkDataStep(d2, 0, 5, nextPos) == detail::FramingStep::NeedMore);
  }
  // Malformed: the 2 terminator bytes are present but are NOT CRLF.
  {
    const std::string d = "HELLOxy";
    REQUIRE(detail::chunkDataStep(d, 0, 5, nextPos) == detail::FramingStep::Malformed);
  }
  // MSB-set size must NOT wrap: report NeedMore (subtraction bounds), never Ok.
  {
    const std::string d = "HELLO\r\n";
    REQUIRE(detail::chunkDataStep(d, 0, UINT64_MAX, nextPos) == detail::FramingStep::NeedMore);
  }
}

// ── Phase 3: detail::walkTrailerSection (tri-state) ─────────────────────────
TEST_CASE("detail::walkTrailerSection Ok / NeedMore / Malformed", "[http_framing_detail][trailer]")
{
  std::size_t endPos = 0;
  // Ok: no trailers — just the closing empty line at pos 0.
  {
    const std::string d = "\r\n";
    REQUIRE(detail::walkTrailerSection(d, 0, endPos) == detail::FramingStep::Ok);
    REQUIRE(endPos == 2);
  }
  // Ok: one trailer field-line then the closing empty line.
  {
    const std::string d = "X-Trace: abc\r\n\r\n";
    REQUIRE(detail::walkTrailerSection(d, 0, endPos) == detail::FramingStep::Ok);
    REQUIRE(endPos == d.size());
  }
  // Ok: trailing bytes after the closing empty line — walker stops at the boundary
  // (end-policy is the caller's; the walker reports the boundary only).
  {
    const std::string d = "\r\nGET / HTTP/1.1\r\n";
    REQUIRE(detail::walkTrailerSection(d, 0, endPos) == detail::FramingStep::Ok);
    REQUIRE(endPos == 2); // past the empty line, before the pipelined bytes
  }
  // NeedMore: trailer terminator not fully arrived.
  {
    const std::string d = "X-Trace: abc\r\n"; // no closing empty line yet
    REQUIRE(detail::walkTrailerSection(d, 0, endPos) == detail::FramingStep::NeedMore);
    const std::string d2 = ""; // nothing after the 0-size line CRLF yet
    REQUIRE(detail::walkTrailerSection(d2, 0, endPos) == detail::FramingStep::NeedMore);
  }
  // Malformed: obs-fold (SP/HTAB-led) trailer field-line.
  {
    const std::string d = " X-Trace: folded\r\n\r\n";
    REQUIRE(detail::walkTrailerSection(d, 0, endPos) == detail::FramingStep::Malformed);
    const std::string d2 = "\tX-Trace: folded\r\n\r\n";
    REQUIRE(detail::walkTrailerSection(d2, 0, endPos) == detail::FramingStep::Malformed);
  }
}

// ── Phase 4: detail::decideRequestFraming (verdict struct incl. reason + precedence)
// This DIRECTLY pins the HIGH-A unified reason precedence (dup-CL -> INVALID_CL |
// OUT_OF_RANGE_CL -> CL+TE -> non-final-chunked). The cross-layer parity test only
// asserts status/throw, so without this a future precedence reorder (e.g.
// out-of-range-CL+TE regressing to CL_PLUS_TE) would keep every test green while
// silently changing the invariant — exactly the drift this refactor pins.
TEST_CASE("detail::decideRequestFraming verdict kind/length/reason + precedence",
          "[http_framing_detail][verdict]")
{
  using detail::FramingKind;
  using detail::FramingReason;
  // Convenience: decide from a (0/1/2 distinct CL) + optional single value + TE.
  auto decide = [](std::size_t distinctCl, const std::string *cl, bool sawTE,
                   const std::string &te)
  { return detail::decideRequestFraming(distinctCl, cl, sawTE, te); };

  SECTION("None: no framing headers")
  {
    const auto v = decide(0, nullptr, false, "");
    REQUIRE(v.kind == FramingKind::None);
    REQUIRE(v.reason == FramingReason::None);
  }
  SECTION("ContentLength: single valid CL yields the parsed length")
  {
    const std::string cl = "1234";
    const auto v = decide(1, &cl, false, "");
    REQUIRE(v.kind == FramingKind::ContentLength);
    REQUIRE(v.length == 1234u);
    REQUIRE(v.reason == FramingReason::None);
  }
  SECTION("ContentLength: leading-zero CL parses")
  {
    const std::string cl = "05";
    const auto v = decide(1, &cl, false, "");
    REQUIRE(v.kind == FramingKind::ContentLength);
    REQUIRE(v.length == 5u);
  }
  SECTION("Chunked: TE final coding chunked")
  {
    const auto v = decide(0, nullptr, true, "chunked");
    REQUIRE(v.kind == FramingKind::Chunked);
    REQUIRE(v.reason == FramingReason::None);
  }
  SECTION("DuplicateContentLength: >1 distinct value (precedence: beats everything)")
  {
    // distinctCl==2 with TE present -> still DUP_CL (highest precedence).
    const auto v = decide(2, nullptr, true, "chunked");
    REQUIRE(v.kind == FramingKind::Ambiguous);
    REQUIRE(v.reason == FramingReason::DuplicateContentLength);
  }
  SECTION("InvalidContentLength: single non-1*DIGIT CL")
  {
    const std::string cl = "abc";
    const auto v = decide(1, &cl, false, "");
    REQUIRE(v.kind == FramingKind::Ambiguous);
    REQUIRE(v.reason == FramingReason::InvalidContentLength);
  }
  SECTION("OutOfRangeContentLength: single 1*DIGIT CL overflowing uint64")
  {
    const std::string cl = "18446744073709551616"; // 2^64
    const auto v = decide(1, &cl, false, "");
    REQUIRE(v.kind == FramingKind::Ambiguous);
    REQUIRE(v.reason == FramingReason::OutOfRangeContentLength);
  }
  SECTION("Precedence: invalid-CL + TE -> INVALID_CL (CL-validity beats CL+TE)")
  {
    const std::string cl = "abc";
    const auto v = decide(1, &cl, true, "chunked");
    REQUIRE(v.kind == FramingKind::Ambiguous);
    REQUIRE(v.reason == FramingReason::InvalidContentLength);
  }
  SECTION("Precedence: out-of-range-CL + TE -> OUT_OF_RANGE_CL (not CL+TE)")
  {
    const std::string cl = "18446744073709551616";
    const auto v = decide(1, &cl, true, "chunked");
    REQUIRE(v.kind == FramingKind::Ambiguous);
    REQUIRE(v.reason == FramingReason::OutOfRangeContentLength);
  }
  SECTION("ContentLengthWithTransferEncoding: valid CL + TE")
  {
    const std::string cl = "5";
    const auto v = decide(1, &cl, true, "chunked");
    REQUIRE(v.kind == FramingKind::Ambiguous);
    REQUIRE(v.reason == FramingReason::ContentLengthWithTransferEncoding);
  }
  SECTION("NonFinalChunked: TE whose final coding is not chunked")
  {
    const auto v = decide(0, nullptr, true, "gzip");
    REQUIRE(v.kind == FramingKind::Ambiguous);
    REQUIRE(v.reason == FramingReason::NonFinalChunked);
  }
  SECTION("NonFinalChunked: chunked not final (chunked, gzip)")
  {
    const auto v = decide(0, nullptr, true, "chunked, gzip");
    REQUIRE(v.kind == FramingKind::Ambiguous);
    REQUIRE(v.reason == FramingReason::NonFinalChunked);
  }
}
