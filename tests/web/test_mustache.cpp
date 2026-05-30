// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Unit tests for the iora::parsers Mustache engine (parsers/mustache.hpp).
// See architecture/iora/mustache_engine.json and tracker
// 2026-05-29-3_htmx-support_phase2b_mustache-engine_P2.json.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/parsers/mustache.hpp>

#include <iora/parsers/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using iora::parsers::Json;
using iora::parsers::Mustache;
using iora::parsers::MustacheError;
using iora::parsers::PartialResolver;

namespace
{
// Build a partial resolver from a small fixed map.
PartialResolver mapResolver(std::initializer_list<std::pair<std::string, std::string>> kv)
{
  std::vector<std::pair<std::string, std::string>> table(kv.begin(), kv.end());
  return [table](std::string_view name) -> std::optional<std::string>
  {
    for (const auto& p : table)
    {
      if (p.first == name)
      {
        return p.second;
      }
    }
    return std::nullopt;
  };
}
} // namespace

// ---------------------------------------------------------------------------
// task-3.1 — scaffold
// ---------------------------------------------------------------------------

TEST_CASE("Mustache scaffold compiles and render() is callable", "[mustache][scaffold]")
{
  Json data;
  REQUIRE_NOTHROW(Mustache::render("", data));
  PartialResolver resolver = [](std::string_view) -> std::optional<std::string>
  { return std::nullopt; };
  REQUIRE_NOTHROW(Mustache::render("", data, resolver));
}

// ---------------------------------------------------------------------------
// task-3.2 — interpolation + scalar formatting (M-2 no-throw, RD-13 %g)
// ---------------------------------------------------------------------------

TEST_CASE("interpolation basics", "[mustache][interpolation]")
{
  SECTION("string substitution")
  {
    Json d;
    d["name"] = Json("World");
    REQUIRE(Mustache::render("Hello, {{name}}!", d) == "Hello, World!");
  }
  SECTION("dotted path")
  {
    Json d;
    d["a"]["b"]["c"] = Json("deep");
    REQUIRE(Mustache::render("{{a.b.c}}", d) == "deep");
  }
  SECTION("missing key => empty (no error)")
  {
    Json d;
    REQUIRE(Mustache::render("[{{missing}}]", d) == "[]");
  }
  SECTION("null value => empty")
  {
    Json d;
    d["x"] = Json(nullptr);
    REQUIRE(Mustache::render("[{{x}}]", d) == "[]");
  }
  SECTION("implicit iterator {{.}} in an array section")
  {
    Json d;
    d["items"] = Json::Array{Json("a"), Json("b"), Json("c")};
    REQUIRE(Mustache::render("{{#items}}{{.}}{{/items}}", d) == "abc");
  }
  SECTION("present head, missing tail => empty (no throw) [web M-3]")
  {
    Json d;
    d["a"]["x"] = Json(1); // a exists; a.b does not
    REQUIRE_NOTHROW(Mustache::render("[{{a.b.c}}]", d));
    REQUIRE(Mustache::render("[{{a.b.c}}]", d) == "[]");
  }
  SECTION("no stack re-walk after the first segment [web M-3]")
  {
    // Outer scope has a key "b"; inner head "a" resolves but a.b is missing.
    // The missing tail must NOT pick up the outer "b".
    Json d;
    d["b"] = Json("OUTER");
    d["a"]["x"] = Json(1);
    REQUIRE(Mustache::render("[{{a.b}}]", d) == "[]");
  }
  SECTION("empty-segment dotted path {{a..b}} => empty (no throw) [web M-3]")
  {
    Json d;
    d["a"]["x"] = Json(1);
    REQUIRE_NOTHROW(Mustache::render("[{{a..b}}]", d));
    REQUIRE(Mustache::render("[{{a..b}}]", d) == "[]");
  }
  SECTION("whitespace-trimmed name {{ name }} == {{name}} [cpp M-5 / web L-1]")
  {
    Json d;
    d["name"] = Json("V");
    REQUIRE(Mustache::render("{{ name }}", d) == Mustache::render("{{name}}", d));
    REQUIRE(Mustache::render("{{   name   }}", d) == "V");
  }
}

TEST_CASE("scalar formatting — every Json type via {{var}} does not throw",
          "[mustache][scalar]")
{
  SECTION("string => raw")
  {
    Json d;
    d["v"] = Json("abc");
    REQUIRE(Mustache::render("{{v}}", d) == "abc");
  }
  SECTION("int64 => digits, no quotes")
  {
    Json d;
    d["v"] = Json(static_cast<std::int64_t>(42));
    REQUIRE(Mustache::render("{{v}}", d) == "42");
    Json n;
    n["v"] = Json(static_cast<std::int64_t>(-7));
    REQUIRE(Mustache::render("{{v}}", n) == "-7");
  }
  SECTION("double => snprintf %g (not %f-padded, not to_chars)")
  {
    Json d;
    d["v"] = Json(1.0);
    REQUIRE(Mustache::render("{{v}}", d) == "1");   // not "1.000000"
    Json h;
    h["v"] = Json(1.5);
    REQUIRE(Mustache::render("{{v}}", h) == "1.5");
    Json frac;
    frac["v"] = Json(3.25);
    REQUIRE(Mustache::render("{{v}}", frac) == "3.25");
  }
  SECTION("large-magnitude double => scientific, no truncation [cpp L-2]")
  {
    Json d;
    d["v"] = Json(1e300);
    REQUIRE(Mustache::render("{{v}}", d) == "1e+300");
  }
  SECTION("bool => true/false")
  {
    Json t;
    t["v"] = Json(true);
    REQUIRE(Mustache::render("{{v}}", t) == "true");
    Json f;
    f["v"] = Json(false);
    REQUIRE(Mustache::render("{{v}}", f) == "false");
  }
  SECTION("null => empty")
  {
    Json d;
    d["v"] = Json(nullptr);
    REQUIRE(Mustache::render("{{v}}", d).empty());
  }
  SECTION("array/object in a scalar position => empty, no throw")
  {
    Json arr;
    arr["v"] = Json::Array{Json(1), Json(2)};
    REQUIRE_NOTHROW(Mustache::render("{{v}}", arr));
    REQUIRE(Mustache::render("[{{v}}]", arr) == "[]");

    Json obj;
    obj["v"]["k"] = Json("x");
    REQUIRE_NOTHROW(Mustache::render("{{v}}", obj));
    REQUIRE(Mustache::render("[{{v}}]", obj) == "[]");
  }
  SECTION("no std::bad_variant_access for any scalar type")
  {
    for (Json v : {Json("s"), Json(static_cast<std::int64_t>(1)), Json(2.5),
                   Json(true), Json(nullptr)})
    {
      Json d;
      d["v"] = v;
      REQUIRE_NOTHROW(Mustache::render("{{v}}{{{v}}}{{&v}}", d));
    }
  }
}

// ---------------------------------------------------------------------------
// task-3.3 — escaping (H-4 single-quote + {{{ }}} + {{& }})
// ---------------------------------------------------------------------------

TEST_CASE("escaping — {{var}} HTML-escapes incl. single-quote", "[mustache][escaping]")
{
  SECTION("script payload < > escaped")
  {
    Json d;
    d["x"] = Json("<script>alert(1)</script>");
    REQUIRE(Mustache::render("{{x}}", d) ==
            "&lt;script&gt;alert(1)&lt;/script&gt;");
  }
  SECTION("single-quote => exactly &#39; (decimal, not &#x27;)")
  {
    Json d;
    d["x"] = Json("it's");
    REQUIRE(Mustache::render("{{x}}", d) == "it&#39;s");
  }
  SECTION("& => &amp; and double-quote => &quot;")
  {
    Json d;
    d["x"] = Json("a&b\"c");
    REQUIRE(Mustache::render("{{x}}", d) == "a&amp;b&quot;c");
  }
  SECTION("combined all-five-character payload, byte-exact, no double-escape")
  {
    Json d;
    d["x"] = Json("<a href='q' onmouseover=\"y\">&</a>");
    REQUIRE(Mustache::render("{{x}}", d) ==
            "&lt;a href=&#39;q&#39; onmouseover=&quot;y&quot;&gt;&amp;&lt;/a&gt;");
  }
  SECTION("{{{x}}} emits verbatim")
  {
    Json d;
    d["x"] = Json("<a href='q'>&</a>");
    REQUIRE(Mustache::render("{{{x}}}", d) == "<a href='q'>&</a>");
  }
  SECTION("{{&x}} alternate unescaped form emits verbatim")
  {
    Json d;
    d["x"] = Json("<a href='q'>&</a>");
    REQUIRE(Mustache::render("{{&x}}", d) == "<a href='q'>&</a>");
    REQUIRE(Mustache::render("{{& x }}", d) == "<a href='q'>&</a>");
  }
}

// ---------------------------------------------------------------------------
// task-3.4 — sections (array iteration determinism, scalar/object once,
//            inverted, dotted-path head)
// ---------------------------------------------------------------------------

TEST_CASE("sections — array iteration", "[mustache][sections]")
{
  SECTION("3-element array renders body 3x in vector order")
  {
    Json d;
    d["items"] = Json::Array{Json("a"), Json("b"), Json("c")};
    REQUIRE(Mustache::render("{{#items}}[{{.}}]{{/items}}", d) == "[a][b][c]");
  }
  SECTION("empty array => skipped entirely")
  {
    Json d;
    d["items"] = Json::Array{};
    REQUIRE(Mustache::render("X{{#items}}body{{/items}}Y", d) == "XY");
  }
  SECTION("byte-identical across repeated render() calls (determinism)")
  {
    Json d;
    d["items"] = Json::Array{Json("a"), Json("b"), Json("c"), Json("d")};
    const std::string tmpl = "{{#items}}{{.}},{{/items}}";
    const std::string first = Mustache::render(tmpl, d);
    for (int i = 0; i < 8; ++i)
    {
      REQUIRE(Mustache::render(tmpl, d) == first);
    }
    REQUIRE(first == "a,b,c,d,");
  }
  SECTION("nested array sections")
  {
    Json d;
    Json::Array rows;
    rows.push_back(Json(Json::Array{Json("1"), Json("2")}));
    rows.push_back(Json(Json::Array{Json("3")}));
    d["rows"] = rows;
    // outer iterates rows, inner iterates each row via implicit iterator
    REQUIRE(Mustache::render("{{#rows}}({{#.}}{{.}}{{/.}}){{/rows}}", d) ==
            "(12)(3)");
  }
  SECTION("element-scoped name shadows outer via the context stack")
  {
    Json d;
    d["name"] = Json("OUTER");
    Json inner;
    inner["name"] = Json("INNER");
    d["list"] = Json::Array{inner};
    REQUIRE(Mustache::render("{{#list}}{{name}}{{/list}}", d) == "INNER");
  }
  SECTION("outer name visible from inside an element lacking it")
  {
    Json d;
    d["title"] = Json("T");
    Json inner;
    inner["other"] = Json("o");
    d["list"] = Json::Array{inner};
    REQUIRE(Mustache::render("{{#list}}{{title}}{{/list}}", d) == "T");
  }
}

TEST_CASE("sections — scalar / object render once", "[mustache][sections]")
{
  SECTION("object renders body once, no member iteration")
  {
    Json d;
    d["obj"]["key"] = Json("V");
    REQUIRE(Mustache::render("{{#obj}}[{{key}}]{{/obj}}", d) == "[V]");
  }
  SECTION("flag=true renders once")
  {
    Json d;
    d["flag"] = Json(true);
    REQUIRE(Mustache::render("{{#flag}}yes{{/flag}}", d) == "yes");
  }
  SECTION("non-empty string renders once")
  {
    Json d;
    d["s"] = Json("hi");
    REQUIRE(Mustache::render("{{#s}}once{{/s}}", d) == "once");
  }
  SECTION("section over integer 0 renders once (0 is truthy, L-5)")
  {
    Json d;
    d["count"] = Json(static_cast<std::int64_t>(0));
    REQUIRE(Mustache::render("{{#count}}body{{/count}}", d) == "body");
    Json dd;
    dd["count"] = Json(0.0);
    REQUIRE(Mustache::render("{{#count}}body{{/count}}", dd) == "body");
  }
}

TEST_CASE("inverted sections", "[mustache][inverted]")
{
  auto renders = [](const Json& d) { return Mustache::render("{{^x}}EMPTY{{/x}}", d); };

  SECTION("renders iff x is falsy")
  {
    Json missing;
    REQUIRE(renders(missing) == "EMPTY");

    Json emptyArr;
    emptyArr["x"] = Json::Array{};
    REQUIRE(renders(emptyArr) == "EMPTY");

    Json fls;
    fls["x"] = Json(false);
    REQUIRE(renders(fls) == "EMPTY");

    Json nul;
    nul["x"] = Json(nullptr);
    REQUIRE(renders(nul) == "EMPTY");

    Json emptyStr;
    emptyStr["x"] = Json("");
    REQUIRE(renders(emptyStr) == "EMPTY");
  }
  SECTION("does NOT render for non-falsy")
  {
    Json arr;
    arr["x"] = Json::Array{Json(1)};
    REQUIRE(renders(arr).empty());

    Json tru;
    tru["x"] = Json(true);
    REQUIRE(renders(tru).empty());

    Json obj;
    obj["x"]["k"] = Json("v");
    REQUIRE(renders(obj).empty());
  }
  SECTION("0 / 0.0 do NOT render the inverted body (0 truthy, L-5)")
  {
    Json zi;
    zi["x"] = Json(static_cast<std::int64_t>(0));
    REQUIRE(renders(zi).empty());
    Json zd;
    zd["x"] = Json(0.0);
    REQUIRE(renders(zd).empty());
  }
}

TEST_CASE("sections — dotted-path head [web M-3 / cpp M-4]", "[mustache][sections]")
{
  SECTION("{{#a.b}} over a non-empty array renders per element")
  {
    Json d;
    d["a"]["b"] = Json::Array{Json("x"), Json("y")};
    REQUIRE(Mustache::render("{{#a.b}}{{.}}{{/a.b}}", d) == "xy");
  }
  SECTION("{{#a.b}} over an object renders once")
  {
    Json d;
    d["a"]["b"]["k"] = Json("v");
    REQUIRE(Mustache::render("{{#a.b}}[{{k}}]{{/a.b}}", d) == "[v]");
  }
  SECTION("{{^a.b}} over a missing dotted path renders the body")
  {
    Json d;
    d["a"]["other"] = Json(1);
    REQUIRE(Mustache::render("{{^a.b}}none{{/a.b}}", d) == "none");
  }
  SECTION("{{^a.b}} over a non-falsy dotted value renders nothing")
  {
    Json d;
    d["a"]["b"] = Json::Array{Json(1)};
    REQUIRE(Mustache::render("{{^a.b}}none{{/a.b}}", d).empty());
  }
  SECTION("close {{/a.b}} matches dotted open with no spurious error")
  {
    Json d;
    d["a"]["b"] = Json::Array{Json("z")};
    REQUIRE_NOTHROW(Mustache::render("{{#a.b}}{{.}}{{/a.b}}", d));
  }
}

// ---------------------------------------------------------------------------
// task-3.5 — comments + partials + recursion depth
// ---------------------------------------------------------------------------

TEST_CASE("comments", "[mustache][comments]")
{
  Json d;
  SECTION("comment emits nothing")
  {
    REQUIRE(Mustache::render("a{{!ignored}}b", d) == "ab");
  }
  SECTION("comment with braces/spaces fully consumed")
  {
    REQUIRE(Mustache::render("a{{! some text }}b", d) == "ab");
  }
  SECTION("comment body with a lone '}' consumed")
  {
    REQUIRE(Mustache::render("a{{! x } y }}b", d) == "ab");
  }
  SECTION("comment body with a literal '{{' consumed")
  {
    REQUIRE(Mustache::render("a{{! {{ }}b", d) == "ab");
  }
  SECTION("unterminated comment throws MustacheError [web L-2]")
  {
    REQUIRE_THROWS_AS(Mustache::render("a{{! no close", d), MustacheError);
  }
}

TEST_CASE("partials", "[mustache][partials]")
{
  SECTION("{{>row}} expands via resolver")
  {
    Json d;
    d["name"] = Json("Z");
    auto r = mapResolver({{"row", "<li>{{name}}</li>"}});
    REQUIRE(Mustache::render("{{>row}}", d, r) == "<li>Z</li>");
  }
  SECTION("partial sees the current (shared) context")
  {
    Json d;
    d["greeting"] = Json("hi");
    d["x"] = Json(true);
    auto r = mapResolver({{"p", "[{{greeting}}]"}});
    REQUIRE(Mustache::render("{{#x}}{{>p}}{{/x}}", d, r) == "[hi]");
  }
  SECTION("resolver returns nullopt => MustacheError")
  {
    Json d;
    auto r = mapResolver({{"known", "x"}});
    REQUIRE_THROWS_AS(Mustache::render("{{>unknown}}", d, r), MustacheError);
  }
  SECTION("empty resolver, reached {{>x}} => MustacheError")
  {
    Json d;
    REQUIRE_THROWS_AS(Mustache::render("{{>x}}", d), MustacheError);
  }
  SECTION("template with no partials renders with default resolver")
  {
    Json d;
    d["v"] = Json("ok");
    REQUIRE_NOTHROW(Mustache::render("{{v}}", d));
    REQUIRE(Mustache::render("{{v}}", d) == "ok");
  }
  SECTION("lazy: {{>x}} in a skipped normal section, empty resolver => no throw")
  {
    Json d; // x missing => falsy => section skipped => partial never reached
    REQUIRE_NOTHROW(Mustache::render("{{#x}}{{>foo}}{{/x}}", d));
    REQUIRE(Mustache::render("{{#x}}{{>foo}}{{/x}}", d).empty());
  }
  SECTION("lazy: {{>x}} in a skipped inverted section, empty resolver => no throw")
  {
    Json d;
    d["x"] = Json(true); // truthy => inverted body skipped => partial not reached
    REQUIRE_NOTHROW(Mustache::render("{{^x}}{{>foo}}{{/x}}", d));
    REQUIRE(Mustache::render("{{^x}}{{>foo}}{{/x}}", d).empty());
  }
}

TEST_CASE("recursion depth limit [MEP-7]", "[mustache][depth]")
{
  Json d;
  SECTION("self-referential partial throws")
  {
    auto r = mapResolver({{"self", "x{{>self}}"}});
    REQUIRE_THROWS_AS(Mustache::render("{{>self}}", d, r), MustacheError);
  }
  SECTION("mutually-recursive partials throw")
  {
    auto r = mapResolver({{"a", "{{>b}}"}, {"b", "{{>a}}"}});
    REQUIRE_THROWS_AS(Mustache::render("{{>a}}", d, r), MustacheError);
  }
  SECTION("statically deep-nested sections throw [web M-4]")
  {
    Json td;
    td["a"] = Json(true);
    std::string tmpl;
    for (int i = 0; i < 250; ++i)
    {
      tmpl += "{{#a}}";
    }
    for (int i = 0; i < 250; ++i)
    {
      tmpl += "{{/a}}";
    }
    REQUIRE_THROWS_AS(Mustache::render(tmpl, td), MustacheError);
  }
}

// ---------------------------------------------------------------------------
// task-3.6 — syntax errors => MustacheError
// ---------------------------------------------------------------------------

TEST_CASE("syntax errors => MustacheError", "[mustache][errors]")
{
  Json d;
  REQUIRE_THROWS_AS(Mustache::render("{{#a}}body", d), MustacheError);       // unbalanced
  REQUIRE_THROWS_AS(Mustache::render("{{/a}}", d), MustacheError);           // stray close
  REQUIRE_THROWS_AS(Mustache::render("{{#a}}x{{/b}}", d), MustacheError);    // mismatched
  REQUIRE_THROWS_AS(Mustache::render("{{name", d), MustacheError);           // unterminated
  REQUIRE_THROWS_AS(Mustache::render("{{{name }}", d), MustacheError);       // unterminated triple
}

// ---------------------------------------------------------------------------
// task-3.7 — const-correctness / no mutation (MEP-2 / CONST-TRAP)
// ---------------------------------------------------------------------------

TEST_CASE("const-correctness — render never mutates the data context",
          "[mustache][const]")
{
  SECTION("non-object at a dotted path is not converted / no keys inserted")
  {
    Json d;
    d["s"] = Json("hello");
    const std::string before = d.dump();
    (void)Mustache::render("{{s.x.y}}{{#s.x}}q{{/s.x}}", d);
    REQUIRE(d.dump() == before);
  }
  SECTION("rendering a missing dotted key does not add the key")
  {
    Json d;
    d["a"]["x"] = Json(1);
    const std::string before = d.dump();
    (void)Mustache::render("{{a.b}}{{a.b.c}}", d);
    REQUIRE(d.dump() == before);
  }
}

// ---------------------------------------------------------------------------
// task-3.8 — standalone-line stripping + standalone-partial indentation +
//            XSS-context-boundary awareness
// ---------------------------------------------------------------------------

TEST_CASE("standalone-line whitespace stripping", "[mustache][standalone]")
{
  SECTION("section block leaves no blank lines")
  {
    Json d;
    d["items"] = Json::Array{Json("a"), Json("b")};
    REQUIRE(Mustache::render("<ul>\n{{#items}}\n  <li>{{.}}</li>\n{{/items}}\n</ul>",
                             d) == "<ul>\n  <li>a</li>\n  <li>b</li>\n</ul>");
  }
  SECTION("standalone comment line is removed entirely")
  {
    Json d;
    REQUIRE(Mustache::render("a\n{{!c}}\nb", d) == "a\nb");
  }
  SECTION("standalone tag at beginning-of-input")
  {
    Json d;
    d["a"] = Json(true);
    REQUIRE(Mustache::render("{{#a}}\nX\n{{/a}}\n", d) == "X\n");
  }
  SECTION("standalone tag at end-of-input (no trailing newline)")
  {
    Json d;
    REQUIRE(Mustache::render("X\n{{!c}}", d) == "X\n");
  }
  SECTION("interpolation tags are never standalone")
  {
    Json d;
    d["name"] = Json("v");
    REQUIRE(Mustache::render("{{name}}\n", d) == "v\n");
    REQUIRE(Mustache::render("{{{name}}}\n", d) == "v\n");
    REQUIRE(Mustache::render("{{&name}}\n", d) == "v\n");
  }
  SECTION("inline non-standalone comment trims nothing")
  {
    Json d;
    REQUIRE(Mustache::render("  12 {{!c}}\n", d) == "  12 \n");
  }
  SECTION("section sharing its line with text trims nothing")
  {
    Json d;
    d["a"] = Json(true);
    REQUIRE(Mustache::render("x {{#a}}Y{{/a}} z\n", d) == "x Y z\n");
  }
  SECTION("inverted-section standalone lines [spec inverted.yml]")
  {
    Json d;
    d["boolean"] = Json(false);
    REQUIRE(Mustache::render("| This Is\n{{^boolean}}\n|\n{{/boolean}}\n| A Line",
                             d) == "| This Is\n|\n| A Line");
  }
  SECTION("inverted-section standalone indented lines")
  {
    Json d;
    d["boolean"] = Json(false);
    REQUIRE(Mustache::render(
              "| This Is\n  {{^boolean}}\n|\n  {{/boolean}}\n| A Line", d) ==
            "| This Is\n|\n| A Line");
  }
  SECTION("inverted-section standalone line endings (CRLF) [spec inverted.yml]")
  {
    Json d;
    d["boolean"] = Json(false);
    REQUIRE(Mustache::render("|\r\n{{^boolean}}\r\n{{/boolean}}\r\n|", d) ==
            "|\r\n|");
  }
  SECTION("inverted-section standalone without previous line [spec inverted.yml]")
  {
    Json d;
    d["boolean"] = Json(false);
    REQUIRE(Mustache::render("  {{^boolean}}\n^{{/boolean}}\n/", d) == "^\n/");
  }
  SECTION("inverted-section standalone without newline [spec inverted.yml]")
  {
    Json d;
    d["boolean"] = Json(false);
    REQUIRE(Mustache::render("^{{^boolean}}\n/\n  {{/boolean}}", d) == "^\n/\n");
  }
  SECTION("normal-section standalone indented lines [spec sections.yml]")
  {
    Json d;
    d["boolean"] = Json(true);
    REQUIRE(Mustache::render(
              "| This Is\n  {{#boolean}}\n|\n  {{/boolean}}\n| A Line", d) ==
            "| This Is\n|\n| A Line");
  }
  SECTION("internal whitespace — non-standalone section + inline comment")
  {
    Json d;
    d["boolean"] = Json(true);
    REQUIRE(Mustache::render(
              " | {{#boolean}} {{! Important Whitespace }}\n {{/boolean}} | \n",
              d) == " |  \n  | \n");
  }
  SECTION("multiline standalone comment [spec comments.yml]")
  {
    Json d;
    REQUIRE(Mustache::render(
              "Begin.\n{{!\nSomething's going on here...\n}}\nEnd.", d) ==
            "Begin.\nEnd.");
  }
}

TEST_CASE("set-delimiter tags are rejected [web L-1]", "[mustache][errors]")
{
  Json d;
  d["x"] = Json("v");
  REQUIRE_THROWS_AS(Mustache::render("{{=<% %>=}}{{x}}", d), MustacheError);
}

TEST_CASE("standalone-partial indentation", "[mustache][standalone][partials]")
{
  Json d;
  SECTION("indents the partial source lines, no trailing indented blank line")
  {
    auto r = mapResolver({{"p", "1\n2\n"}});
    const std::string out = Mustache::render("  {{>p}}", d, r);
    REQUIRE(out == "  1\n  2\n");
  }
  SECTION("data-injected newline is NOT re-indented [web wH-2]")
  {
    Json dd;
    dd["content"] = Json("<\n->");
    auto r = mapResolver({{"p", "|\n{{{content}}}\n|\n"}});
    REQUIRE(Mustache::render(" {{>p}}", dd, r) == " |\n <\n->\n |\n");
  }
  SECTION("standalone without trailing newline [web wL-3]")
  {
    auto r = mapResolver({{"p", ">\n>"}});
    REQUIRE(Mustache::render(">\n  {{>p}}", d, r) == ">\n  >\n  >");
  }
  SECTION("standalone without previous line [web H4-2]")
  {
    auto r = mapResolver({{"p", ">\n>"}});
    REQUIRE(Mustache::render("  {{>p}}\n>", d, r) == "  >\n  >>");
  }
  SECTION("standalone CRLF line endings [web H4-3]")
  {
    auto r = mapResolver({{"p", ">"}});
    REQUIRE(Mustache::render("|\r\n{{>p}}\r\n|", d, r) == "|\r\n>|");
  }
  SECTION("non-standalone partial — no indentation [web M5-1]")
  {
    Json dd;
    dd["data"] = Json("|");
    auto r = mapResolver({{"p", ">\n>"}});
    REQUIRE(Mustache::render("  {{data}}  {{>p}}\n", dd, r) == "  |  >\n>\n");
  }
  SECTION("non-standalone partial — padding whitespace + name trim [web L6-1]")
  {
    auto r = mapResolver({{"p", "[]"}});
    REQUIRE(Mustache::render("|{{> p }}|", d, r) == "|[]|");
  }
  SECTION("nested standalone partial — indentation composes [web L6-2]")
  {
    auto r = mapResolver({{"outer", "X\n{{>inner}}\nY\n"}, {"inner", "i\n"}});
    REQUIRE(Mustache::render("  {{>outer}}\n", d, r) == "  X\n  i\n  Y\n");
  }
  SECTION("blank interior line is NOT indented [web M-1, mustache.js parity]")
  {
    // A blank line in the partial source must stay empty, not become a line of
    // trailing whitespace.
    auto r = mapResolver({{"p", "a\n\nb\n"}});
    REQUIRE(Mustache::render("  {{>p}}", d, r) == "  a\n\n  b\n");
  }
}

TEST_CASE("XSS awareness — escaping is HTML-context only [web M-2]", "[mustache][xss]")
{
  SECTION("javascript: URI in an href passes through unchanged")
  {
    Json d;
    d["url"] = Json("javascript:alert(1)");
    REQUIRE(Mustache::render("<a href=\"{{url}}\">x</a>", d) ==
            "<a href=\"javascript:alert(1)\">x</a>");
  }
  SECTION("escapeHtml is not a JS-context escaper")
  {
    // A payload that breaks a JS string WITHOUT any HTML metacharacter passes
    // through {{var}} untouched — proving inline-<script> use is unsafe.
    Json d;
    d["v"] = Json("1;alert(1)//");
    REQUIRE(Mustache::render("<script>var x={{v}};</script>", d) ==
            "<script>var x=1;alert(1)//;</script>");
  }
  SECTION("unescaped {{{v}}} emits </script> verbatim; {{v}} HTML-escapes it")
  {
    Json d;
    d["v"] = Json("</script>");
    REQUIRE(Mustache::render("{{{v}}}", d) == "</script>");
    REQUIRE(Mustache::render("{{v}}", d) == "&lt;/script&gt;");
  }
  SECTION("unquoted-attribute context is not covered [web L-2]")
  {
    // escapeHtml does not escape space or '=', so a value placed in an UNQUOTED
    // attribute can inject a new attribute. Awareness only — not fixed by the
    // engine (always quote interpolated attribute values).
    Json d;
    d["cls"] = Json("x onclick=alert(1)");
    REQUIRE(Mustache::render("<div class={{cls}}>", d) ==
            "<div class=x onclick=alert(1)>");
  }
  SECTION("dangerous URI scheme passes through a quoted attribute [web L-2]")
  {
    // A data:/javascript: scheme with no HTML metacharacters is left intact;
    // {{var}} is not a URL-context escaper.
    Json d;
    d["url"] = Json("data:text/html,pwned");
    REQUIRE(Mustache::render("<img src=\"{{url}}\">", d) ==
            "<img src=\"data:text/html,pwned\">");
  }
}
