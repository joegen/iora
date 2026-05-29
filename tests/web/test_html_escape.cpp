// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Unit tests for iora::parsers html_escape (parsers/html_escape.hpp):
// escapeHtml, urlDecode, formDecode, parseFormBody.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/parsers/html_escape.hpp>

#include <string>

using iora::parsers::escapeHtml;
using iora::parsers::formDecode;
using iora::parsers::parseFormBody;
using iora::parsers::urlDecode;

// ---------------------------------------------------------------------------
// escapeHtml (task-2.2)
// ---------------------------------------------------------------------------

TEST_CASE("escapeHtml escapes the five special characters individually", "[html_escape][escape]")
{
  REQUIRE(escapeHtml("&") == "&amp;");
  REQUIRE(escapeHtml("<") == "&lt;");
  REQUIRE(escapeHtml(">") == "&gt;");
  REQUIRE(escapeHtml("\"") == "&quot;");
  REQUIRE(escapeHtml("'") == "&#39;");
  // All-specials concatenation (arch edgeCase).
  REQUIRE(escapeHtml("<>&\"'") == "&lt;&gt;&amp;&quot;&#39;");
}

TEST_CASE("escapeHtml H-4 single-quote attribute breakout is neutralized", "[html_escape][escape][xss]")
{
  // H-4 regression guard: an apostrophe must not survive to terminate a
  // single-quoted attribute. It must become the numeric reference &#39;.
  const std::string payload = "' onmouseover='alert(1)";
  const std::string out = escapeHtml(payload);
  REQUIRE(out.find("&#39;") != std::string::npos);
  REQUIRE(out.find('\'') == std::string::npos);  // no raw single-quote remains
  // The apostrophe is &#39;, never &apos;.
  REQUIRE(out.find("&apos;") == std::string::npos);
}

TEST_CASE("escapeHtml neutralizes a script tag", "[html_escape][escape][xss]")
{
  REQUIRE(escapeHtml("<script>alert(1)</script>") ==
          "&lt;script&gt;alert(1)&lt;/script&gt;");
}

TEST_CASE("escapeHtml does not double-escape (single-pass correctness)", "[html_escape][escape]")
{
  // 'a & b < c' -> 'a &amp; b &lt; c'. The '<' must NEVER appear as '&amp;lt;'
  // (which would only happen if the output were scanned a second time).
  const std::string out = escapeHtml("a & b < c");
  REQUIRE(out == "a &amp; b &lt; c");
  REQUIRE(out.find("&amp;lt;") == std::string::npos);
}

TEST_CASE("escapeHtml is not idempotent", "[html_escape][escape]")
{
  REQUIRE(escapeHtml("&amp;") == "&amp;amp;");
}

TEST_CASE("escapeHtml passes through non-special bytes", "[html_escape][escape]")
{
  REQUIRE(escapeHtml("").empty());
  REQUIRE(escapeHtml("plain ascii 123") == "plain ascii 123");
  // Multi-byte UTF-8 ('São') passes through unchanged (byte-wise).
  REQUIRE(escapeHtml("S\xC3\xA3o") == "S\xC3\xA3o");

  // Embedded NUL preserved (string_view length, not C-string semantics).
  const std::string withNul("a\0b", 3);
  const std::string escaped = escapeHtml(withNul);
  REQUIRE(escaped.size() == 3);
  REQUIRE(escaped[1] == '\0');
  REQUIRE(escaped == withNul);
}

TEST_CASE("escapeHtml preserves a high-bit byte adjacent to a special (L-N2)", "[html_escape][escape]")
{
  // 0xC3 is >= 0x80; with signed char it is negative. A correct byte-wise
  // escaper copies it verbatim regardless of signedness and only specializes
  // the five ASCII characters.
  REQUIRE(escapeHtml(std::string("\xC3<", 2)) == std::string("\xC3&lt;"));
  REQUIRE(escapeHtml(std::string("<\xC3", 2)) == std::string("&lt;\xC3"));
}

// ---------------------------------------------------------------------------
// urlDecode (task-2.3)
// ---------------------------------------------------------------------------

TEST_CASE("urlDecode decodes percent escapes (case-insensitive hex)", "[html_escape][urldecode]")
{
  REQUIRE(urlDecode("%41") == "A");
  REQUIRE(urlDecode("%2f") == "/");
  REQUIRE(urlDecode("%2F") == "/");
  // L-2 web: upper hex range + case-insensitivity in both nibble positions.
  REQUIRE(urlDecode("%Ac") == std::string("\xAC"));
}

TEST_CASE("urlDecode treats '+' literally", "[html_escape][urldecode]")
{
  REQUIRE(urlDecode("a+b") == "a+b");
}

TEST_CASE("urlDecode is lenient on malformed escapes and never throws", "[html_escape][urldecode]")
{
  REQUIRE_NOTHROW(urlDecode("%"));
  REQUIRE(urlDecode("%") == "%");
  REQUIRE(urlDecode("%2") == "%2");
  REQUIRE(urlDecode("%2G") == "%2G");  // bad 2nd nibble
  REQUIRE(urlDecode("%g0") == "%g0");  // L-1 web: bad 1st nibble
  REQUIRE(urlDecode("%%41") == "%A");  // L-1 web: consecutive-'%' recovery
  REQUIRE(urlDecode("%2%") == "%2%");  // L-N1: mid-string recovery, 2nd '%' not consumed
  REQUIRE(urlDecode("100%done") == "100%done");
  REQUIRE(urlDecode("done%") == "done%");  // trailing '%' preserved
}

TEST_CASE("urlDecode decodes %00 to a NUL byte without truncation (M-2 web)", "[html_escape][urldecode]")
{
  const std::string r = urlDecode("a%00b");
  REQUIRE(r.size() == 3);
  REQUIRE(r[1] == '\0');
}

TEST_CASE("urlDecode returns input unchanged when there is nothing to decode", "[html_escape][urldecode]")
{
  REQUIRE(urlDecode("nothing-to-decode") == "nothing-to-decode");
  REQUIRE(urlDecode("").empty());
}

// ---------------------------------------------------------------------------
// formDecode (task-2.4)
// ---------------------------------------------------------------------------

TEST_CASE("formDecode maps '+' to space", "[html_escape][formdecode]")
{
  REQUIRE(formDecode("a+b") == "a b");
  // M-1 web: query-realistic anchor for the M-4/DD-3 claim that query values
  // use the form-urlencoding '+'=space rule (WHATWG URL form-urlencoded parser).
  REQUIRE(formDecode("hello+world") == "hello world");
}

TEST_CASE("formDecode: %20 is space, %2B is a literal '+'", "[html_escape][formdecode]")
{
  REQUIRE(formDecode("a%20b") == "a b");
  REQUIRE(formDecode("a%2Bb") == "a+b");
  REQUIRE(formDecode("a+b%2Bc%20d") == "a b+c d");
}

TEST_CASE("formDecode decodes multibyte UTF-8 byte-wise (L-3 web)", "[html_escape][formdecode]")
{
  REQUIRE(formDecode("S%C3%A3o") == "S\xC3\xA3o");  // 'São'
}

TEST_CASE("formDecode decodes %00 to a NUL byte without truncation (M-2 web)", "[html_escape][formdecode]")
{
  const std::string r = formDecode("a%00b");
  REQUIRE(r.size() == 3);
  REQUIRE(r[1] == '\0');
}

TEST_CASE("formDecode shares lenient malformed handling and never throws", "[html_escape][formdecode]")
{
  REQUIRE_NOTHROW(formDecode("%"));
  REQUIRE(formDecode("%") == "%");
  REQUIRE(formDecode("%2G") == "%2G");
  REQUIRE(formDecode("%g0") == "%g0");
  REQUIRE(formDecode("%%41") == "%A");
}

TEST_CASE("urlDecode vs formDecode differ only on raw '+' (M-3 differential)", "[html_escape][formdecode]")
{
  // With a raw '+': the two functions differ.
  REQUIRE(urlDecode("a+b") == "a+b");
  REQUIRE(formDecode("a+b") == "a b");
  // Without a raw '+': identical (percent handling is shared).
  REQUIRE(urlDecode("a%20b%2Bc") == formDecode("a%20b%2Bc"));
}

// ---------------------------------------------------------------------------
// parseFormBody (task-2.5)
// ---------------------------------------------------------------------------

TEST_CASE("parseFormBody parses a basic body", "[html_escape][formbody]")
{
  const auto m = parseFormBody("a=1&b=2");
  REQUIRE(m.size() == 2);
  REQUIRE(m.at("a") == "1");
  REQUIRE(m.at("b") == "2");
}

TEST_CASE("parseFormBody decodes percent and '+' in keys and values", "[html_escape][formbody]")
{
  const auto m = parseFormBody("na+me=John+Doe&city=S%C3%A3o%20Paulo");
  REQUIRE(m.size() == 2);
  REQUIRE(m.at("na me") == "John Doe");
  REQUIRE(m.at("city") == "S\xC3\xA3o Paulo");  // 'São Paulo'
}

TEST_CASE("parseFormBody splits each field on the FIRST '=' only (L-3)", "[html_escape][formbody]")
{
  const auto m = parseFormBody("token=ab=cd");
  REQUIRE(m.size() == 1);
  REQUIRE(m.at("token") == "ab=cd");  // value retains the inner '='
}

TEST_CASE("parseFormBody collapses duplicate keys last-wins (DD-4)", "[html_escape][formbody]")
{
  const auto m = parseFormBody("x=1&x=2&x=3");
  REQUIRE(m.size() == 1);
  REQUIRE(m.at("x") == "3");
}

TEST_CASE("parseFormBody keeps a bare key as empty value", "[html_escape][formbody]")
{
  const auto m = parseFormBody("flag&x=1");
  REQUIRE(m.size() == 2);
  REQUIRE(m.at("flag") == "");
  REQUIRE(m.at("x") == "1");
}

TEST_CASE("parseFormBody permits an empty key with a value", "[html_escape][formbody]")
{
  const auto m = parseFormBody("=v");
  REQUIRE(m.size() == 1);
  REQUIRE(m.at("") == "v");
}

TEST_CASE("parseFormBody skips empty segments from consecutive '&'", "[html_escape][formbody]")
{
  const auto m = parseFormBody("a=1&&b=2");
  REQUIRE(m.size() == 2);
  REQUIRE(m.at("a") == "1");
  REQUIRE(m.at("b") == "2");
}

TEST_CASE("parseFormBody skips leading/trailing empty segments (L-4 web)", "[html_escape][formbody]")
{
  // '&a=1&' splits to {"", "a=1", ""}; the two empty segments are skipped and
  // must NOT produce a spurious ''->'' entry — distinct from the '=v' case.
  const auto m = parseFormBody("&a=1&");
  REQUIRE(m.size() == 1);
  REQUIRE(m.at("a") == "1");
  REQUIRE(m.find("") == m.end());
}

TEST_CASE("parseFormBody decodes %00 in a value (M-2 web)", "[html_escape][formbody]")
{
  const auto m = parseFormBody("k=%00");
  REQUIRE(m.size() == 1);
  const std::string& v = m.at("k");
  REQUIRE(v.size() == 1);
  REQUIRE(v[0] == '\0');
}

TEST_CASE("parseFormBody on an empty body yields an empty map", "[html_escape][formbody]")
{
  REQUIRE(parseFormBody("").empty());
}

TEST_CASE("parseFormBody is total on adversarial input (L-2)", "[html_escape][formbody]")
{
  // Malformed percent in a value passes through literally; sibling still parsed.
  REQUIRE_NOTHROW(parseFormBody("k=%ZZ&x=1"));
  const auto m1 = parseFormBody("k=%ZZ&x=1");
  REQUIRE(m1.size() == 2);
  REQUIRE(m1.at("k") == "%ZZ");
  REQUIRE(m1.at("x") == "1");

  // Pathological structure: split('&') => ["===","","","==="]; two empty
  // segments skipped, each "===" => key "" value "==" (split-on-first-'='),
  // last-wins => {"":"=="}.
  REQUIRE_NOTHROW(parseFormBody("===&&&==="));
  const auto m2 = parseFormBody("===&&&===");
  REQUIRE(m2.size() == 1);
  REQUIRE(m2.at("") == "==");
}

// ---------------------------------------------------------------------------
// parseFormBody NO-TRIM regression (task-2.6, L-4 no-trim contract)
// ---------------------------------------------------------------------------

TEST_CASE("parseFormBody never trims decoded leading/trailing spaces", "[html_escape][formbody][notrim]")
{
  {
    const auto m = parseFormBody("k=%20v%20");
    REQUIRE(m.at("k") == " v ");  // percent-encoded edge spaces preserved
  }
  {
    const auto m = parseFormBody("k=+v+");
    REQUIRE(m.at("k") == " v ");  // raw '+' decodes to space, preserved at edges
  }
  {
    const auto m = parseFormBody("%20key=val");
    REQUIRE(m.at(" key") == "val");  // leading space in the KEY preserved
  }
}
