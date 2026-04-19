// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Tests for iora::core::ConfigLoader::getTable + ConfigSubTable
// (P0 PREREQ-1 phase 2). Verifies nested TOML sub-table access, the
// shared_ptr-based ownership invariant, and single-threaded contract
// (lifetime survives serially-ordered reload()).

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

// Task 3.1 — scalar getters on a sub-table return values declared under [a.b].
TEST_CASE("ConfigSubTable scalar getters return values from [a.b]",
          "[iora][ConfigLoader][getTable]")
{
  TempDirManager tmp;
  auto path = tmp.filePath("scalars.toml");
  writeToml(path,
            "[section]\n"
            "i = 42\n"
            "b = true\n"
            "s = \"hello\"\n"
            "arr = [\"a\", \"b\", \"c\"]\n");

  iora::core::ConfigLoader loader(path);
  auto sub = loader.getTable("section");
  REQUIRE(sub.has_value());
  REQUIRE(sub->valid());

  REQUIRE(sub->getInt("i") == 42);
  REQUIRE(sub->getBool("b") == true);
  REQUIRE(sub->getString("s") == std::string("hello"));
  auto arr = sub->getStringArray("arr");
  REQUIRE(arr.has_value());
  REQUIRE(arr->size() == 3);
  REQUIRE((*arr)[0] == "a");
  REQUIRE((*arr)[2] == "c");
}

// Task 3.2 — nested getTable resolves [a.b.c]: both chained and dotted forms.
TEST_CASE("ConfigSubTable nested getTable resolves [a.b.c] in both forms",
          "[iora][ConfigLoader][getTable]")
{
  TempDirManager tmp;
  auto path = tmp.filePath("nested2.toml");
  writeToml(path,
            "[outer.inner]\n"
            "leaf = 7\n");

  iora::core::ConfigLoader loader(path);

  // Chained form: getTable("outer") → getTable("inner") → getInt("leaf").
  auto outer = loader.getTable("outer");
  REQUIRE(outer.has_value());
  auto inner = outer->getTable("inner");
  REQUIRE(inner.has_value());
  REQUIRE(inner->getInt("leaf") == 7);

  // Flat dotted form: getTable("outer.inner") yields an equivalent view.
  auto direct = loader.getTable("outer.inner");
  REQUIRE(direct.has_value());
  REQUIRE(direct->getInt("leaf") == 7);
}

// Task 3.3 — 3+ levels deep.
TEST_CASE("ConfigSubTable resolves 4-level nested path [a.b.c.d]",
          "[iora][ConfigLoader][getTable]")
{
  TempDirManager tmp;
  auto path = tmp.filePath("deep.toml");
  writeToml(path,
            "[a.b.c.d]\n"
            "value = 100\n");

  iora::core::ConfigLoader loader(path);

  // Chained from root: getTable("a").getTable("b").getTable("c").getTable("d").
  auto a = loader.getTable("a");
  REQUIRE(a.has_value());
  auto b = a->getTable("b");
  REQUIRE(b.has_value());
  auto c = b->getTable("c");
  REQUIRE(c.has_value());
  auto d = c->getTable("d");
  REQUIRE(d.has_value());
  REQUIRE(d->getInt("value") == 100);

  // Flat dotted form.
  auto direct = loader.getTable("a.b.c.d");
  REQUIRE(direct.has_value());
  REQUIRE(direct->getInt("value") == 100);
}

// Task 3.4 — missing sub-table and missing scalar key → nullopt (no throw).
TEST_CASE("ConfigSubTable missing keys return nullopt",
          "[iora][ConfigLoader][getTable]")
{
  TempDirManager tmp;
  auto path = tmp.filePath("sparse.toml");
  writeToml(path,
            "[present]\n"
            "x = 1\n");

  iora::core::ConfigLoader loader(path);

  // Missing sub-table via ConfigLoader.
  REQUIRE_FALSE(loader.getTable("absent").has_value());
  // Missing sub-table via ConfigSubTable::getTable.
  auto present = loader.getTable("present");
  REQUIRE(present.has_value());
  REQUIRE_FALSE(present->getTable("nonexistent").has_value());

  // Missing scalar keys.
  REQUIRE_FALSE(present->getInt("y").has_value());
  REQUIRE_FALSE(present->getBool("y").has_value());
  REQUIRE_FALSE(present->getString("y").has_value());
  REQUIRE_FALSE(present->getStringArray("y").has_value());
}

// Review fold (P2S4-H-1): getStringArray with a non-string element returns
// nullopt instead of throwing — aligns with the class's silent-nullopt
// contract for every other getter, and is a deliberate divergence from
// ConfigLoader::getStringArray (documented in the class comment).
TEST_CASE("ConfigSubTable getStringArray returns nullopt on mixed-type array",
          "[iora][ConfigLoader][getTable]")
{
  TempDirManager tmp;
  auto path = tmp.filePath("mixed_array.toml");
  writeToml(path,
            "[s]\n"
            "mixed = [\"a\", 1, \"c\"]\n");

  iora::core::ConfigLoader loader(path);
  auto sub = loader.getTable("s");
  REQUIRE(sub.has_value());
  REQUIRE_NOTHROW(sub->getStringArray("mixed"));
  REQUIRE_FALSE(sub->getStringArray("mixed").has_value());
}

// Task 3.5 — type-mismatch on scalar getters returns nullopt (no throw).
TEST_CASE("ConfigSubTable scalar type-mismatch returns nullopt",
          "[iora][ConfigLoader][getTable]")
{
  TempDirManager tmp;
  auto path = tmp.filePath("types.toml");
  writeToml(path,
            "[s]\n"
            "int_key = 5\n"
            "bool_key = true\n"
            "str_key = \"text\"\n");

  iora::core::ConfigLoader loader(path);
  auto sub = loader.getTable("s");
  REQUIRE(sub.has_value());

  // int queried as bool → nullopt.
  REQUIRE_FALSE(sub->getBool("int_key").has_value());
  // string queried as int → nullopt.
  REQUIRE_FALSE(sub->getInt("str_key").has_value());
  // bool queried as string → nullopt.
  REQUIRE_FALSE(sub->getString("bool_key").has_value());
  // scalar queried as array → nullopt.
  REQUIRE_FALSE(sub->getStringArray("int_key").has_value());
}

// Task 3.6 — two bracket-section declaration forms resolve identically.
// NOTE: minimal_toml's parseValue does NOT implement inline-table {...}
// syntax (verified at /workspace/iora/include/iora/parsers/minimal_toml.hpp
// parseValue at line ~328). So we compare only two bracket forms: a single
// dotted header [a.b.c] vs three separate headers [a], [a.b], [a.b.c].
TEST_CASE("ConfigSubTable equivalent bracket-section forms resolve identically",
          "[iora][ConfigLoader][getTable]")
{
  TempDirManager tmp;

  auto dottedPath = tmp.filePath("dotted.toml");
  writeToml(dottedPath,
            "[a.b.c]\n"
            "v = 11\n");

  auto separatePath = tmp.filePath("separate.toml");
  writeToml(separatePath,
            "[a]\n"
            "[a.b]\n"
            "[a.b.c]\n"
            "v = 11\n");

  iora::core::ConfigLoader dotted(dottedPath);
  iora::core::ConfigLoader separate(separatePath);

  auto d = dotted.getTable("a.b.c");
  auto s = separate.getTable("a.b.c");
  REQUIRE(d.has_value());
  REQUIRE(s.has_value());
  REQUIRE(d->getInt("v") == 11);
  REQUIRE(s->getInt("v") == 11);
}

// Task 3.7 — lifetime across serially-ordered reload().
// Proves that a ConfigSubTable obtained before reload() continues to return
// the PRE-reload values even after the loader has reloaded a modified file.
// This is a consequence of minimal_toml's shared_ptr<table> ownership model,
// not of any new locking (ConfigLoader is single-threaded by contract).
TEST_CASE("ConfigSubTable survives serially-ordered reload()",
          "[iora][ConfigLoader][getTable]")
{
  TempDirManager tmp;
  auto path = tmp.filePath("reload.toml");

  // v1: x = 1.
  writeToml(path,
            "[s]\n"
            "x = 1\n");

  iora::core::ConfigLoader loader(path);
  auto v1 = loader.getTable("s");
  REQUIRE(v1.has_value());
  REQUIRE(v1->getInt("x") == 1);

  // Rewrite the file with v2: x = 2.
  writeToml(path,
            "[s]\n"
            "x = 2\n");

  // Reload: the loader's internal _table now reflects v2.
  REQUIRE(loader.reload());

  // The freshly-obtained ConfigSubTable sees v2.
  auto v2 = loader.getTable("s");
  REQUIRE(v2.has_value());
  REQUIRE(v2->getInt("x") == 2);

  // The ConfigSubTable obtained BEFORE reload still sees v1 (shared_ptr
  // preserved the old sub-table memory).
  REQUIRE(v1->getInt("x") == 1);
}

// Task 3.8 — copy semantics: copies share underlying sub-table via shared_ptr.
TEST_CASE("ConfigSubTable copy shares the same data",
          "[iora][ConfigLoader][getTable]")
{
  TempDirManager tmp;
  auto path = tmp.filePath("copy.toml");
  writeToml(path,
            "[s]\n"
            "x = 7\n");

  iora::core::ConfigLoader loader(path);
  auto original = loader.getTable("s");
  REQUIRE(original.has_value());

  // Copy — both instances see the same data (shared_ptr semantics).
  iora::core::ConfigSubTable copy = *original;
  REQUIRE(copy.valid());
  REQUIRE(copy.getInt("x") == 7);
  REQUIRE(original->getInt("x") == 7);
}
