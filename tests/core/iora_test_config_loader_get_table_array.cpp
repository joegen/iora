// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Tests for iora::core::ConfigLoader::getTableArray + minimal_toml
// [[array-of-tables]] parser support (P0 PREREQ-1 phase 3). Verifies
// declaration-order preservation, conflict detection with [a.b] and
// scalar keys, the std::optional<std::vector<ConfigSubTable>> return
// contract, and the getTable regression guard on array-of-tables keys.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>
#include <fstream>

using namespace iora::test;

namespace
{
// Helper to write TOML content to a file under a TempDirManager.
void writeToml(const std::string &path, const std::string &content)
{
  std::ofstream f(path);
  f << content;
}
} // namespace

// Task 4.1 — Parse [[a.b]] with N=3 entries; returned vector has 3 elements
// in declaration order with matching per-element scalars.
TEST_CASE("getTableArray returns N entries in declaration order",
          "[iora][ConfigLoader][getTableArray]")
{
  TempDirManager tmp;
  auto path = tmp.filePath("n3.toml");
  writeToml(path,
            "[[a.b]]\n"
            "x = 1\n"
            "y = \"first\"\n"
            "\n"
            "[[a.b]]\n"
            "x = 2\n"
            "y = \"second\"\n"
            "\n"
            "[[a.b]]\n"
            "x = 3\n"
            "y = \"third\"\n");

  iora::core::ConfigLoader loader(path);
  auto arr = loader.getTableArray("a.b");
  REQUIRE(arr.has_value());
  REQUIRE(arr->size() == 3);

  REQUIRE((*arr)[0].getInt("x") == 1);
  REQUIRE((*arr)[0].getString("y") == std::string("first"));
  REQUIRE((*arr)[1].getInt("x") == 2);
  REQUIRE((*arr)[1].getString("y") == std::string("second"));
  REQUIRE((*arr)[2].getInt("x") == 3);
  REQUIRE((*arr)[2].getString("y") == std::string("third"));
}

// Task 4.2 — Single [[a.b]] entry (N=1) produces a 1-element vector,
// NOT a single table, NOT nullopt.
TEST_CASE("getTableArray single entry yields 1-element vector (N=1)",
          "[iora][ConfigLoader][getTableArray]")
{
  TempDirManager tmp;
  auto path = tmp.filePath("n1.toml");
  writeToml(path,
            "[[a.b]]\n"
            "x = 42\n");

  iora::core::ConfigLoader loader(path);
  auto arr = loader.getTableArray("a.b");
  REQUIRE(arr.has_value());
  REQUIRE(arr->size() == 1);
  REQUIRE((*arr)[0].getInt("x") == 42);

  // Confirm this is NOT reported as a scalar table either.
  REQUIRE_FALSE(loader.getTable("a.b").has_value());
}

// Task 4.3 — Each element's scalar getters (int/bool/string/stringArray)
// return expected values declared as inline key-value lines inside [[a.b]].
TEST_CASE("getTableArray element scalar getters",
          "[iora][ConfigLoader][getTableArray]")
{
  TempDirManager tmp;
  auto path = tmp.filePath("scalars.toml");
  writeToml(path,
            "[[servers]]\n"
            "port = 8080\n"
            "enabled = true\n"
            "name = \"alpha\"\n"
            "tags = [\"api\", \"public\"]\n"
            "\n"
            "[[servers]]\n"
            "port = 9090\n"
            "enabled = false\n"
            "name = \"beta\"\n"
            "tags = [\"internal\"]\n");

  iora::core::ConfigLoader loader(path);
  auto arr = loader.getTableArray("servers");
  REQUIRE(arr.has_value());
  REQUIRE(arr->size() == 2);

  REQUIRE((*arr)[0].getInt("port") == 8080);
  REQUIRE((*arr)[0].getBool("enabled") == true);
  REQUIRE((*arr)[0].getString("name") == std::string("alpha"));
  auto tags0 = (*arr)[0].getStringArray("tags");
  REQUIRE(tags0.has_value());
  REQUIRE(tags0->size() == 2);
  REQUIRE((*tags0)[0] == "api");
  REQUIRE((*tags0)[1] == "public");

  REQUIRE((*arr)[1].getInt("port") == 9090);
  REQUIRE((*arr)[1].getBool("enabled") == false);
  REQUIRE((*arr)[1].getString("name") == std::string("beta"));
  auto tags1 = (*arr)[1].getStringArray("tags");
  REQUIRE(tags1.has_value());
  REQUIRE(tags1->size() == 1);
  REQUIRE((*tags1)[0] == "internal");
}

// Task 4.4 — Missing array-of-tables key returns std::nullopt.
TEST_CASE("getTableArray missing key returns nullopt",
          "[iora][ConfigLoader][getTableArray]")
{
  TempDirManager tmp;
  auto path = tmp.filePath("empty.toml");
  writeToml(path,
            "[[present]]\n"
            "x = 1\n");

  iora::core::ConfigLoader loader(path);
  REQUIRE_FALSE(loader.getTableArray("absent").has_value());
  REQUIRE_FALSE(loader.getTableArray("a.absent").has_value());
  REQUIRE_FALSE(loader.getTableArray("a.b.c").has_value());
}

// Task 4.5 — Key exists but is not an array-of-tables: scalar, named
// sub-table, array of strings. All three return nullopt.
TEST_CASE("getTableArray wrong-type key returns nullopt",
          "[iora][ConfigLoader][getTableArray]")
{
  TempDirManager tmp;
  auto path = tmp.filePath("wrongtype.toml");
  writeToml(path,
            "scalar_int = 42\n"
            "scalar_str = \"hello\"\n"
            "arr_of_strs = [\"x\", \"y\"]\n"
            "\n"
            "[sub.table]\n"
            "k = 1\n");

  iora::core::ConfigLoader loader(path);

  // (a) scalar
  REQUIRE_FALSE(loader.getTableArray("scalar_int").has_value());
  REQUIRE_FALSE(loader.getTableArray("scalar_str").has_value());

  // (b) named sub-table (single-bracket header)
  REQUIRE_FALSE(loader.getTableArray("sub").has_value());
  REQUIRE_FALSE(loader.getTableArray("sub.table").has_value());

  // (c) array of strings (not shared_ptr<table>)
  REQUIRE_FALSE(loader.getTableArray("arr_of_strs").has_value());
}

// Task 4.6 — Mixing [a.b] then [[a.b]] produces std::runtime_error.
TEST_CASE("parser rejects [a.b] followed by [[a.b]]",
          "[iora][parsers][toml][arrayOfTables]")
{
  const std::string toml =
      "[a.b]\n"
      "k = 1\n"
      "\n"
      "[[a.b]]\n"
      "x = 2\n";
  REQUIRE_THROWS_AS(iora::parsers::toml::parse(toml), std::runtime_error);
}

// Task 4.7 — Mixing [[a.b]] then [a.b] produces std::runtime_error.
// ensureTable's existing nullptr guard catches this (the pre-existing
// as_table() returns null on a shared_ptr<array> node, triggering throw).
TEST_CASE("parser rejects [[a.b]] followed by [a.b]",
          "[iora][parsers][toml][arrayOfTables]")
{
  const std::string toml =
      "[[a.b]]\n"
      "x = 1\n"
      "\n"
      "[a.b]\n"
      "k = 2\n";
  REQUIRE_THROWS_AS(iora::parsers::toml::parse(toml), std::runtime_error);
}

// Task 4.8 — Scalar key at a.b followed by [[a.b]] produces std::runtime_error.
TEST_CASE("parser rejects scalar a.b followed by [[a.b]]",
          "[iora][parsers][toml][arrayOfTables]")
{
  // Form 1: [a] then b = "x" (putting scalar at a.b), then [[a.b]]
  const std::string form1 =
      "[a]\n"
      "b = \"x\"\n"
      "\n"
      "[[a.b]]\n"
      "k = 1\n";
  REQUIRE_THROWS_AS(iora::parsers::toml::parse(form1), std::runtime_error);
}

// Task 4.9 — Regression guard: getTable on an array-of-tables key returns
// nullopt (it is not a scalar table). Must NOT silently return the first
// element of the array as if it were the sub-table.
TEST_CASE("getTable returns nullopt on array-of-tables key",
          "[iora][ConfigLoader][getTable][arrayOfTables]")
{
  TempDirManager tmp;
  auto path = tmp.filePath("getTable_regression.toml");
  writeToml(path,
            "[[a.b]]\n"
            "x = 1\n"
            "\n"
            "[[a.b]]\n"
            "x = 2\n");

  iora::core::ConfigLoader loader(path);
  REQUIRE_FALSE(loader.getTable("a.b").has_value());

  // The array itself is still reachable via getTableArray.
  auto arr = loader.getTableArray("a.b");
  REQUIRE(arr.has_value());
  REQUIRE(arr->size() == 2);
}

// Task 4.10(a) — Dotted-key getTableArray with EXPLICIT parent headers:
// TOML contains explicit [a] and [a.b] before the [[a.b.c]] entries.
TEST_CASE("getTableArray deep path with explicit parent headers",
          "[iora][ConfigLoader][getTableArray]")
{
  TempDirManager tmp;
  auto path = tmp.filePath("explicit_parents.toml");
  writeToml(path,
            "[a]\n"
            "label = \"root\"\n"
            "\n"
            "[a.b]\n"
            "label = \"mid\"\n"
            "\n"
            "[[a.b.c]]\n"
            "n = 1\n"
            "\n"
            "[[a.b.c]]\n"
            "n = 2\n"
            "\n"
            "[[a.b.c]]\n"
            "n = 3\n");

  iora::core::ConfigLoader loader(path);
  auto arr = loader.getTableArray("a.b.c");
  REQUIRE(arr.has_value());
  REQUIRE(arr->size() == 3);
  REQUIRE((*arr)[0].getInt("n") == 1);
  REQUIRE((*arr)[1].getInt("n") == 2);
  REQUIRE((*arr)[2].getInt("n") == 3);

  // Explicit parent scalars remain accessible via getTable.
  REQUIRE(loader.getString("a.label") == std::string("root"));
  REQUIRE(loader.getString("a.b.label") == std::string("mid"));
}

// Task 4.10(b) — Dotted-key getTableArray with IMPLICIT parent creation:
// TOML contains ONLY [[a.b.c]] entries; ensureTable creates intermediates
// on demand.
TEST_CASE("getTableArray deep path with implicit parent creation",
          "[iora][ConfigLoader][getTableArray]")
{
  TempDirManager tmp;
  auto path = tmp.filePath("implicit_parents.toml");
  writeToml(path,
            "[[a.b.c]]\n"
            "n = 10\n"
            "\n"
            "[[a.b.c]]\n"
            "n = 20\n");

  iora::core::ConfigLoader loader(path);
  auto arr = loader.getTableArray("a.b.c");
  REQUIRE(arr.has_value());
  REQUIRE(arr->size() == 2);
  REQUIRE((*arr)[0].getInt("n") == 10);
  REQUIRE((*arr)[1].getInt("n") == 20);
}

// Additional coverage: parseArraySection whitespace stripping and the
// bracket-termination error paths.
TEST_CASE("parseArraySection strips surrounding whitespace",
          "[iora][parsers][toml][arrayOfTables]")
{
  const std::string toml =
      "[[ a.b ]]\n"
      "x = 1\n";
  auto root = iora::parsers::toml::parse(toml);
  auto n = root.at_path("a.b");
  REQUIRE(n.is_array());
  auto *arr = n.as_array();
  REQUIRE(arr != nullptr);
  REQUIRE(arr->size() == 1);
}

TEST_CASE("parseArraySection rejects unterminated header",
          "[iora][parsers][toml][arrayOfTables]")
{
  REQUIRE_THROWS_AS(iora::parsers::toml::parse("[[a.b\n"),
                    std::runtime_error);
  REQUIRE_THROWS_AS(iora::parsers::toml::parse("[[a.b]\n"),
                    std::runtime_error);
}

// P3S4-M-1 fix — newline inside [[...]] header is a parse error (not
// silently absorbed into the key name).
TEST_CASE("parseArraySection rejects newline inside header",
          "[iora][parsers][toml][arrayOfTables]")
{
  REQUIRE_THROWS_AS(iora::parsers::toml::parse("[[ a.b\n]]\n"),
                    std::runtime_error);
}

// Tracker 2026-04-19-5 — backport of the \n guard to parseSection:
// newline inside a single-bracket [section] header is a parse error.
TEST_CASE("parseSection rejects newline after name",
          "[iora][parsers][toml][section]")
{
  REQUIRE_THROWS_AS(iora::parsers::toml::parse("[ a.b\n]\n"),
                    std::runtime_error);
}

TEST_CASE("parseSection rejects newline immediately after opening bracket",
          "[iora][parsers][toml][section]")
{
  REQUIRE_THROWS_AS(iora::parsers::toml::parse("[\n a.b]\n"),
                    std::runtime_error);
}

TEST_CASE("parseSection rejects newline-only section",
          "[iora][parsers][toml][section]")
{
  REQUIRE_THROWS_AS(iora::parsers::toml::parse("[\n]\n"),
                    std::runtime_error);
}

// Regression guard: empty single-bracket section '[]' must still parse
// (the read loop does not execute for this input, so the newline guard
// cannot affect it).
TEST_CASE("parseSection accepts empty section (regression guard)",
          "[iora][parsers][toml][section]")
{
  REQUIRE_NOTHROW(iora::parsers::toml::parse("[]\nk = 1\n"));
}

// P3S4-H-1 fix — value-array at a key followed by [[key]] header must
// throw (TOML spec: redefining a key as a different type is an error).
// Without this guard, the parser would silently append a shared_ptr<table>
// into the existing string array, producing a malformed mixed array.
TEST_CASE("parser rejects value-array followed by [[key]] at same path",
          "[iora][parsers][toml][arrayOfTables]")
{
  const std::string toml =
      "tags = [\"x\", \"y\"]\n"
      "\n"
      "[[tags]]\n"
      "k = 1\n";
  REQUIRE_THROWS_AS(iora::parsers::toml::parse(toml), std::runtime_error);
}

// Tracker 2026-04-19-6 — CRLF header handling. Both parseSection and
// parseArraySection must reject '\r' inside the header token. Without
// this guard, the '\r' is silently accumulated into the section name
// string (e.g. the key becomes "a.b\r"), and subsequent lookups via the
// expected key "a.b" miss because the stored key contains an invisible
// '\r'. The TOML spec accepts CRLF as valid line termination between
// sections, so these guards only reject '\r' WITHIN the header token.
//
// REQUIRE_THROWS_WITH assertions (added per T6S4-L-3) confirm the thrown
// message identifies the correct failure reason ("Unterminated ..." from
// the post-loop termination check), not some unrelated std::runtime_error
// from elsewhere in the parser.
TEST_CASE("parseSection rejects CRLF inside header",
          "[iora][parsers][toml][section]")
{
  REQUIRE_THROWS_AS(iora::parsers::toml::parse("[ a.b\r\n]\n"),
                    std::runtime_error);
  REQUIRE_THROWS_WITH(iora::parsers::toml::parse("[ a.b\r\n]\n"),
                      Catch::Contains("Unterminated"));
}

TEST_CASE("parseArraySection rejects CRLF inside header",
          "[iora][parsers][toml][arrayOfTables]")
{
  REQUIRE_THROWS_AS(iora::parsers::toml::parse("[[ a.b\r\n]]\n"),
                    std::runtime_error);
  REQUIRE_THROWS_WITH(iora::parsers::toml::parse("[[ a.b\r\n]]\n"),
                      Catch::Contains("Unterminated"));
}

TEST_CASE("parseSection rejects bare CR inside header",
          "[iora][parsers][toml][section]")
{
  REQUIRE_THROWS_AS(iora::parsers::toml::parse("[ a.b\r]"),
                    std::runtime_error);
  REQUIRE_THROWS_WITH(iora::parsers::toml::parse("[ a.b\r]"),
                      Catch::Contains("Unterminated"));
}

TEST_CASE("parseArraySection rejects bare CR inside header",
          "[iora][parsers][toml][arrayOfTables]")
{
  REQUIRE_THROWS_AS(iora::parsers::toml::parse("[[ a.b\r]]"),
                    std::runtime_error);
  REQUIRE_THROWS_WITH(iora::parsers::toml::parse("[[ a.b\r]]"),
                      Catch::Contains("Unterminated"));
}

// Tracker 2026-04-19-6 — T6S4-L-2 fold. CR immediately after the opening
// bracket (parallel to tracker-5's "parseSection rejects newline
// immediately after opening bracket" at line ~340). The code handles
// these correctly via the guard firing on the first loop iteration;
// these tests assert that behavior explicitly for completeness.
TEST_CASE("parseSection rejects CR immediately after opening bracket",
          "[iora][parsers][toml][section]")
{
  REQUIRE_THROWS_AS(iora::parsers::toml::parse("[\r\n]\n"),
                    std::runtime_error);
}

TEST_CASE("parseArraySection rejects CR immediately after opening brackets",
          "[iora][parsers][toml][arrayOfTables]")
{
  REQUIRE_THROWS_AS(iora::parsers::toml::parse("[[\r\n]]\n"),
                    std::runtime_error);
}

// Tracker 2026-04-19-6 — T6S0-M-1 regression guard. Well-formed CRLF
// input (where '\r\n' is the line terminator BETWEEN sections, not
// INSIDE the header token) must still parse correctly after the fix.
// The '\r\n' after ']' / ']]' is consumed by skipWhitespaceAndNewlines
// via std::isspace; the section-header read loop never sees it. This
// test guards against an overly-eager fix that would remove '\r'
// tolerance from skipWhitespaceAndNewlines and break CRLF files.
TEST_CASE("parseSection accepts CRLF between sections (regression guard)",
          "[iora][parsers][toml][section]")
{
  REQUIRE_NOTHROW(iora::parsers::toml::parse("[a.b]\r\nk = 1\r\n"));
}

TEST_CASE("parseArraySection accepts CRLF between sections (regression guard)",
          "[iora][parsers][toml][arrayOfTables]")
{
  REQUIRE_NOTHROW(iora::parsers::toml::parse("[[a.b]]\r\nk = 1\r\n"));
}

// Tracker 2026-04-19-7 — null-byte (\0) header handling. Both parseSection
// and parseArraySection must reject '\0' inside the header token. Without
// this guard, the \0 is silently accumulated into the section name string
// because std::string does NOT terminate on embedded \0 (size() counts
// past null bytes). The resulting key (e.g. "a.b\0c") fails all normal
// string lookups since the caller queries by "a.b.c" or similar.
//
// Test inputs use std::initializer_list<char> construction (T7S4-L-1
// fold) rather than (ptr, len) from a string literal. This avoids
// embedding \0 inside a string literal, which some newer toolchains
// (GCC >= 13, clang >= 16) flag with -Wstring-contains-nul or similar
// diagnostics that would become errors under iora's -Werror policy.
// Initializer-list construction produces the exact same byte sequence
// without a literal-containing-nul.
//
// The fix is safe ONLY because !isEnd() is first in the &&-chain; at EOF,
// peek() returns '\0' as a sentinel (minimal_toml.hpp:259), and
// short-circuit evaluation prevents a false positive rejection. See the
// tracker's non_goals[3] for details.
TEST_CASE("parseSection rejects embedded null byte inside header",
          "[iora][parsers][toml][section]")
{
  const std::string s1{'[', 'a', '.', 'b', '\0', 'c', ']'}; // 7 bytes
  REQUIRE_THROWS_AS(iora::parsers::toml::parse(s1), std::runtime_error);
  REQUIRE_THROWS_WITH(iora::parsers::toml::parse(s1),
                      Catch::Contains("Unterminated"));
}

TEST_CASE("parseArraySection rejects embedded null byte inside header",
          "[iora][parsers][toml][arrayOfTables]")
{
  const std::string s2{'[', '[', 'a', '.', 'b', '\0', 'c', ']', ']'}; // 9
  REQUIRE_THROWS_AS(iora::parsers::toml::parse(s2), std::runtime_error);
  REQUIRE_THROWS_WITH(iora::parsers::toml::parse(s2),
                      Catch::Contains("Unterminated"));
}

// Tracker 2026-04-19-7 — T7S0-L-2 edge-case guard. Null byte immediately
// after opening bracket (empty-name-with-null). Parallel to tracker-6's
// "parseSection rejects CR immediately after opening bracket" pattern.
TEST_CASE("parseSection rejects null byte immediately after opening bracket",
          "[iora][parsers][toml][section]")
{
  const std::string s3{'[', '\0', ']'}; // 3 bytes
  REQUIRE_THROWS_AS(iora::parsers::toml::parse(s3), std::runtime_error);
  REQUIRE_THROWS_WITH(iora::parsers::toml::parse(s3),
                      Catch::Contains("Unterminated"));
}

TEST_CASE("parseArraySection rejects null byte immediately after opening brackets",
          "[iora][parsers][toml][arrayOfTables]")
{
  const std::string s4{'[', '[', '\0', ']', ']'}; // 5 bytes
  REQUIRE_THROWS_AS(iora::parsers::toml::parse(s4), std::runtime_error);
  REQUIRE_THROWS_WITH(iora::parsers::toml::parse(s4),
                      Catch::Contains("Unterminated"));
}
