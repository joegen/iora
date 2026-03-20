// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for Result<T,E> generic error type

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/core/result.hpp>

#include <memory>
#include <string>

using namespace iora::core;

// ══════════════════════════════════════════════════════════════════════════════
// Primary Template — Factories and Observers
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Result: ok creation and observers", "[result]")
{
  auto r = Result<int, std::string>::ok(42);
  REQUIRE(r.isOk());
  REQUIRE_FALSE(r.isErr());
  REQUIRE(static_cast<bool>(r));
  REQUIRE(r.value() == 42);
}

TEST_CASE("Result: err creation and observers", "[result]")
{
  auto r = Result<int, std::string>::err("fail");
  REQUIRE(r.isErr());
  REQUIRE_FALSE(r.isOk());
  REQUIRE_FALSE(static_cast<bool>(r));
  REQUIRE(r.error() == "fail");
}

TEST_CASE("Result: value() on err throws", "[result]")
{
  auto r = Result<int, std::string>::err("bad");
  REQUIRE_THROWS_AS(r.value(), std::bad_variant_access);
}

TEST_CASE("Result: error() on ok throws", "[result]")
{
  auto r = Result<int, std::string>::ok(1);
  REQUIRE_THROWS_AS(r.error(), std::bad_variant_access);
}

TEST_CASE("Result: valueOr returns value when ok", "[result]")
{
  auto r = Result<int, std::string>::ok(42);
  REQUIRE(r.valueOr(0) == 42);
}

TEST_CASE("Result: valueOr returns fallback when err", "[result]")
{
  auto r = Result<int, std::string>::err("fail");
  REQUIRE(r.valueOr(99) == 99);
}

TEST_CASE("Result: valueOr on rvalue moves value out", "[result]")
{
  auto r = Result<std::string, int>::ok("hello");
  std::string val = std::move(r).valueOr("fallback");
  REQUIRE(val == "hello");
}

// ══════════════════════════════════════════════════════════════════════════════
// T == E (same type)
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Result: T == E works (Result<string, string>)", "[result][same-type]")
{
  auto ok = Result<std::string, std::string>::ok("success");
  auto err = Result<std::string, std::string>::err("failure");

  REQUIRE(ok.isOk());
  REQUIRE(ok.value() == "success");
  REQUIRE(err.isErr());
  REQUIRE(err.error() == "failure");
}

// ══════════════════════════════════════════════════════════════════════════════
// Monadic Operations
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Result: map transforms value", "[result][monadic]")
{
  auto r = Result<int, std::string>::ok(21);
  auto mapped = r.map([](int x) { return x * 2; });
  REQUIRE(mapped.isOk());
  REQUIRE(mapped.value() == 42);
}

TEST_CASE("Result: map propagates error", "[result][monadic]")
{
  auto r = Result<int, std::string>::err("fail");
  auto mapped = r.map([](int x) { return x * 2; });
  REQUIRE(mapped.isErr());
  REQUIRE(mapped.error() == "fail");
}

TEST_CASE("Result: map with void-returning fn returns Result<void,E>", "[result][monadic]")
{
  int sideEffect = 0;
  auto r = Result<int, std::string>::ok(42);
  auto mapped = r.map([&](int x) { sideEffect = x; });
  REQUIRE(mapped.isOk());
  REQUIRE(sideEffect == 42);

  // Error path: fn not called
  sideEffect = 0;
  auto r2 = Result<int, std::string>::err("fail");
  auto mapped2 = r2.map([&](int x) { sideEffect = x; });
  REQUIRE(mapped2.isErr());
  REQUIRE(sideEffect == 0);
}

TEST_CASE("Result: andThen chains operations", "[result][monadic]")
{
  auto r = Result<int, std::string>::ok(10);
  auto chained = r.andThen([](int x) -> Result<std::string, std::string>
  {
    return Result<std::string, std::string>::ok(std::to_string(x));
  });
  REQUIRE(chained.isOk());
  REQUIRE(chained.value() == "10");
}

TEST_CASE("Result: andThen propagates error", "[result][monadic]")
{
  auto r = Result<int, std::string>::err("early fail");
  auto chained = r.andThen([](int x) -> Result<std::string, std::string>
  {
    return Result<std::string, std::string>::ok("should not reach");
  });
  REQUIRE(chained.isErr());
  REQUIRE(chained.error() == "early fail");
}

TEST_CASE("Result: mapError transforms error", "[result][monadic]")
{
  auto r = Result<int, int>::err(404);
  auto mapped = r.mapError([](int code) { return std::to_string(code); });
  REQUIRE(mapped.isErr());
  REQUIRE(mapped.error() == "404");
}

TEST_CASE("Result: mapError propagates value", "[result][monadic]")
{
  auto r = Result<int, int>::ok(42);
  auto mapped = r.mapError([](int code) { return std::to_string(code); });
  REQUIRE(mapped.isOk());
  REQUIRE(mapped.value() == 42);
}

TEST_CASE("Result: inspect calls fn on ok, returns self", "[result][monadic]")
{
  int observed = 0;
  auto r = Result<int, std::string>::ok(42);
  auto& ref = r.inspect([&](int x) { observed = x; });
  REQUIRE(observed == 42);
  REQUIRE(&ref == &r);
}

TEST_CASE("Result: inspect does nothing on err", "[result][monadic]")
{
  int observed = 0;
  auto r = Result<int, std::string>::err("fail");
  r.inspect([&](int x) { observed = x; });
  REQUIRE(observed == 0);
}

// ══════════════════════════════════════════════════════════════════════════════
// Move-Only Types
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Result: non-default-constructible type", "[result][move]")
{
  struct NoDflt
  {
    int x;
    explicit NoDflt(int v) : x(v) {}
  };
  auto r = Result<NoDflt, std::string>::ok(NoDflt{42});
  REQUIRE(r.isOk());
  REQUIRE(r.value().x == 42);

  auto e = Result<NoDflt, std::string>::err("bad");
  REQUIRE(e.isErr());
  REQUIRE(e.error() == "bad");
}

TEST_CASE("Result: move-only type (unique_ptr)", "[result][move]")
{
  auto r = Result<std::unique_ptr<int>, std::string>::ok(std::make_unique<int>(42));
  REQUIRE(r.isOk());
  REQUIRE(*r.value() == 42);

  // Move value out via rvalue overload
  auto ptr = std::move(r).value();
  REQUIRE(*ptr == 42);
}

TEST_CASE("Result: move-only map via rvalue", "[result][move]")
{
  auto r = Result<std::unique_ptr<int>, std::string>::ok(std::make_unique<int>(21));
  auto mapped = std::move(r).map([](std::unique_ptr<int> p)
  {
    return std::make_unique<int>(*p * 2);
  });
  REQUIRE(mapped.isOk());
  REQUIRE(*mapped.value() == 42);
}

TEST_CASE("Result: move-only andThen via rvalue", "[result][move]")
{
  auto r = Result<std::unique_ptr<int>, std::string>::ok(std::make_unique<int>(10));
  auto chained = std::move(r).andThen([](std::unique_ptr<int> p)
    -> Result<std::string, std::string>
  {
    return Result<std::string, std::string>::ok(std::to_string(*p));
  });
  REQUIRE(chained.isOk());
  REQUIRE(chained.value() == "10");
}

// ══════════════════════════════════════════════════════════════════════════════
// Copy Semantics
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Result: copy semantics — copies are independent", "[result][copy]")
{
  auto r1 = Result<int, std::string>::ok(42);
  auto r2 = r1;
  REQUIRE(r2.isOk());
  REQUIRE(r2.value() == 42);
  // Modify original — copy unaffected
  // (r1 is const-like here but we verify r2 is a separate object)
  REQUIRE(&r1.value() != &r2.value());
}

// ══════════════════════════════════════════════════════════════════════════════
// Comparison Operators
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Result: operator== and operator!=", "[result][comparison]")
{
  auto ok1 = Result<int, std::string>::ok(42);
  auto ok2 = Result<int, std::string>::ok(42);
  auto ok3 = Result<int, std::string>::ok(99);
  auto err1 = Result<int, std::string>::err("fail");
  auto err2 = Result<int, std::string>::err("fail");
  auto err3 = Result<int, std::string>::err("other");

  REQUIRE(ok1 == ok2);
  REQUIRE(ok1 != ok3);
  REQUIRE(err1 == err2);
  REQUIRE(err1 != err3);
  REQUIRE(ok1 != err1);
}

// ══════════════════════════════════════════════════════════════════════════════
// Type Aliases
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Result: value_type and error_type aliases", "[result][traits]")
{
  static_assert(std::is_same_v<Result<int, std::string>::value_type, int>);
  static_assert(std::is_same_v<Result<int, std::string>::error_type, std::string>);
  static_assert(std::is_same_v<Result<void, int>::value_type, void>);
  static_assert(std::is_same_v<Result<void, int>::error_type, int>);
  REQUIRE(true); // static_asserts are the real test
}

// ══════════════════════════════════════════════════════════════════════════════
// Constexpr
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Result: observers are noexcept", "[result][constexpr]")
{
  // constexpr construction requires constexpr factory methods, which need
  // constexpr variant::emplace — not fully constexpr in C++17 on all toolchains.
  // Verify noexcept guarantees and runtime correctness instead.
  auto r = Result<int, int>::ok(42);
  static_assert(noexcept(r.isOk()));
  static_assert(noexcept(r.isErr()));
  static_assert(noexcept(static_cast<bool>(r)));
  REQUIRE(r.isOk());
  REQUIRE(r.value() == 42);
}

// ══════════════════════════════════════════════════════════════════════════════
// Result<void, E> Specialization
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Result<void>: ok and err creation", "[result][void]")
{
  auto ok = Result<void, std::string>::ok();
  auto err = Result<void, std::string>::err("fail");

  REQUIRE(ok.isOk());
  REQUIRE_FALSE(ok.isErr());
  REQUIRE(static_cast<bool>(ok));

  REQUIRE(err.isErr());
  REQUIRE(err.error() == "fail");
}

TEST_CASE("Result<void>: error() on ok throws", "[result][void]")
{
  auto r = Result<void, std::string>::ok();
  REQUIRE_THROWS_AS(r.error(), std::bad_variant_access);
}

TEST_CASE("Result<void>: andThen chains", "[result][void]")
{
  auto r = Result<void, std::string>::ok();
  auto chained = r.andThen([]() -> Result<int, std::string>
  {
    return Result<int, std::string>::ok(42);
  });
  REQUIRE(chained.isOk());
  REQUIRE(chained.value() == 42);
}

TEST_CASE("Result<void>: andThen propagates error", "[result][void]")
{
  auto r = Result<void, std::string>::err("early");
  auto chained = r.andThen([]() -> Result<int, std::string>
  {
    return Result<int, std::string>::ok(42);
  });
  REQUIRE(chained.isErr());
  REQUIRE(chained.error() == "early");
}

TEST_CASE("Result<void>: mapError transforms error", "[result][void]")
{
  auto r = Result<void, int>::err(404);
  auto mapped = r.mapError([](int code) { return std::to_string(code); });
  REQUIRE(mapped.isErr());
  REQUIRE(mapped.error() == "404");
}

TEST_CASE("Result<void>: mapError propagates ok", "[result][void]")
{
  auto r = Result<void, int>::ok();
  auto mapped = r.mapError([](int code) { return std::to_string(code); });
  REQUIRE(mapped.isOk());
}

TEST_CASE("Result<void>: inspect calls fn on ok", "[result][void]")
{
  bool called = false;
  auto r = Result<void, std::string>::ok();
  r.inspect([&]() { called = true; });
  REQUIRE(called);
}

TEST_CASE("Result<void>: inspect does nothing on err", "[result][void]")
{
  bool called = false;
  auto r = Result<void, std::string>::err("fail");
  r.inspect([&]() { called = true; });
  REQUIRE_FALSE(called);
}

TEST_CASE("Result<void>: rvalue andThen", "[result][void]")
{
  auto r = Result<void, std::string>::ok();
  auto chained = std::move(r).andThen([]() -> Result<int, std::string>
  {
    return Result<int, std::string>::ok(99);
  });
  REQUIRE(chained.isOk());
  REQUIRE(chained.value() == 99);
}

TEST_CASE("Result<void>: rvalue mapError", "[result][void]")
{
  auto r = Result<void, int>::err(404);
  auto mapped = std::move(r).mapError([](int code) { return std::to_string(code); });
  REQUIRE(mapped.isErr());
  REQUIRE(mapped.error() == "404");
}

TEST_CASE("Result: rvalue mapError on primary template", "[result][monadic]")
{
  auto r = Result<int, int>::err(500);
  auto mapped = std::move(r).mapError([](int code) { return std::to_string(code); });
  REQUIRE(mapped.isErr());
  REQUIRE(mapped.error() == "500");
}

TEST_CASE("Result<void>: operator== and operator!=", "[result][void]")
{
  auto ok1 = Result<void, std::string>::ok();
  auto ok2 = Result<void, std::string>::ok();
  auto err1 = Result<void, std::string>::err("a");
  auto err2 = Result<void, std::string>::err("a");
  auto err3 = Result<void, std::string>::err("b");

  REQUIRE(ok1 == ok2);
  REQUIRE(err1 == err2);
  REQUIRE(err1 != err3);
  REQUIRE(ok1 != err1);
}
