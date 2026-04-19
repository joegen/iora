// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Tests for iora::parsers::toml::serializer [[array-of-tables]] emission
// support (tracker 2026-04-19-4). Verifies classification of array-of-tables
// nodes, emission of [[prefix.k]] headers per element with empty-prefix
// recursion, guard against shared_ptr<table> elements in non-array-of-tables
// arrays, empty-array routing to simpleValues, and deep-path round-trip.

#define CATCH_CONFIG_MAIN
#include "iora/parsers/minimal_toml.hpp"
#include <catch2/catch.hpp>
#include <string>

using namespace iora::parsers;

namespace
{
// Count non-overlapping occurrences of 'needle' in 'haystack'.
size_t countSubstr(const std::string &haystack, const std::string &needle)
{
  if (needle.empty())
    return 0;
  size_t count = 0;
  size_t pos = 0;
  while ((pos = haystack.find(needle, pos)) != std::string::npos)
  {
    ++count;
    pos += needle.size();
  }
  return count;
}
} // namespace

// Task 3.1 — Round-trip parse-serialize-reparse with N=3 [[a.b]] entries.
// Textual check: exactly 3 occurrences of '[[a.b]]'. Semantic check: the
// reparse yields an array of size 3 with matching scalars in declaration
// order.
TEST_CASE("serializer round-trips [[a.b]] with N=3 entries",
          "[iora][parsers][toml][serializer][arrayOfTables]")
{
  const std::string original =
      "[[a.b]]\n"
      "x = 1\n"
      "\n"
      "[[a.b]]\n"
      "x = 2\n"
      "\n"
      "[[a.b]]\n"
      "x = 3\n";

  auto root = toml::parse(original);
  const std::string out = toml::serializer::serialize(root);

  REQUIRE(countSubstr(out, "[[a.b]]") == 3);
  // Regression guard for header-emission rule (T4S4-L-2): because the input
  // has no [a] section and the 'a' sub-table holds only an array-of-tables
  // child, the serializer must NOT emit a spurious '[a]' single-bracket
  // header. 'simpleValues' is empty under 'a' so the header guard suppresses.
  REQUIRE(out.find("[a]\n") == std::string::npos);

  auto reparsed = toml::parse(out);
  auto node = reparsed.at_path("a.b");
  REQUIRE(node.is_array());
  const auto *arr = node.as_array();
  REQUIRE(arr != nullptr);
  REQUIRE(arr->size() == 3);

  for (size_t i = 0; i < 3; ++i)
  {
    auto *tblPtr = std::get_if<std::shared_ptr<toml::table>>(&(*arr)[i]);
    REQUIRE(tblPtr != nullptr);
    auto n = (*tblPtr)->at("x");
    auto v = n.as<int64_t>();
    REQUIRE(v.has_value());
    REQUIRE(*v == static_cast<int64_t>(i + 1));
  }
}

// Task 3.2 — Empty array at path a.b routes to simpleValues bucket; output
// contains zero [[a.b]] occurrences and the inline 'b = []' form.
TEST_CASE("serializer routes empty array to simpleValues (not [[...]])",
          "[iora][parsers][toml][serializer][arrayOfTables]")
{
  toml::table root;
  auto aTbl = std::make_shared<toml::table>();
  aTbl->insert("b",
               toml::node(toml::value_type{std::make_shared<toml::array>()}));
  root.insert("a", toml::node(toml::value_type{aTbl}));

  const std::string out = toml::serializer::serialize(root);
  REQUIRE(out.find("[[a.b]]") == std::string::npos);
  REQUIRE(out.find("b = []") != std::string::npos);
}

// Task 3.3 — Mixed structure: [a] with scalar keys + [[a.b]] entries.
// Serialized output preserves both; reparse verifies semantics.
TEST_CASE("serializer round-trips mixed [a] scalars + [[a.b]] entries",
          "[iora][parsers][toml][serializer][arrayOfTables]")
{
  const std::string original =
      "[a]\n"
      "label = \"alpha\"\n"
      "count = 7\n"
      "\n"
      "[[a.b]]\n"
      "k = 1\n"
      "\n"
      "[[a.b]]\n"
      "k = 2\n";

  auto root = toml::parse(original);
  const std::string out = toml::serializer::serialize(root);

  REQUIRE(out.find("[a]") != std::string::npos);
  REQUIRE(countSubstr(out, "[[a.b]]") == 2);

  auto reparsed = toml::parse(out);
  auto labelNode = reparsed.at_path("a.label");
  auto labelVal = labelNode.as<std::string>();
  REQUIRE(labelVal.has_value());
  REQUIRE(*labelVal == "alpha");

  auto countNode = reparsed.at_path("a.count");
  auto countVal = countNode.as<int64_t>();
  REQUIRE(countVal.has_value());
  REQUIRE(*countVal == 7);

  auto arrNode = reparsed.at_path("a.b");
  REQUIRE(arrNode.is_array());
  const auto *arr = arrNode.as_array();
  REQUIRE(arr != nullptr);
  REQUIRE(arr->size() == 2);
}

// Task 3.4 — Guard test: mixed-type array (scalar first, shared_ptr<table>
// second) routes to simpleValues; serializeValueType throws on the table
// element.
TEST_CASE("serializer throws on mixed-type array containing shared_ptr<table>",
          "[iora][parsers][toml][serializer][guard]")
{
  toml::table root;
  auto arr = std::make_shared<toml::array>();
  arr->push_back(toml::value_type{std::string("a")});
  arr->push_back(toml::value_type{std::make_shared<toml::table>()});
  root.insert("mixed", toml::node(toml::value_type{arr}));

  REQUIRE_THROWS_AS(toml::serializer::serialize(root), std::runtime_error);
}

// Task 3.5 — Deep-path round-trip: [[a.b.c]] with N=2 entries must emit
// [[a.b.c]] headers (not [[c]] inside [a.b] block).
TEST_CASE("serializer emits deep-path [[a.b.c]] headers",
          "[iora][parsers][toml][serializer][arrayOfTables]")
{
  const std::string original =
      "[[a.b.c]]\n"
      "n = 10\n"
      "\n"
      "[[a.b.c]]\n"
      "n = 20\n";

  auto root = toml::parse(original);
  const std::string out = toml::serializer::serialize(root);

  REQUIRE(countSubstr(out, "[[a.b.c]]") == 2);
  // Guard: the deep-path prefix must NOT collapse to a shorter form. An
  // isolated "[[c]]" substring on its own line would indicate a bug in
  // fullPrefix computation.
  REQUIRE(out.find("\n[[c]]\n") == std::string::npos);

  auto reparsed = toml::parse(out);
  auto arrNode = reparsed.at_path("a.b.c");
  REQUIRE(arrNode.is_array());
  const auto *arr = arrNode.as_array();
  REQUIRE(arr != nullptr);
  REQUIRE(arr->size() == 2);
}

// Additional coverage: verify the recursive serializeTable call uses empty
// prefix so [[a.b]] blocks do NOT contain a spurious [a.b] single-bracket
// header (the primary H-1 correctness invariant).
TEST_CASE("[[a.b]] block must not contain stray [a.b] single-bracket header",
          "[iora][parsers][toml][serializer][arrayOfTables]")
{
  const std::string original =
      "[[a.b]]\n"
      "k = 1\n"
      "\n"
      "[[a.b]]\n"
      "k = 2\n";

  auto root = toml::parse(original);
  const std::string out = toml::serializer::serialize(root);

  // [[a.b]] must appear exactly twice; [a.b] (single bracket) must not
  // appear at all. Searching for the full token "[a.b]\n" (which is never a
  // prefix of "[[a.b]]\n") catches it at any position including start-of-
  // string, so a single npos check is both necessary and sufficient.
  REQUIRE(countSubstr(out, "[[a.b]]") == 2);
  REQUIRE(out.find("[a.b]\n") == std::string::npos);
}
