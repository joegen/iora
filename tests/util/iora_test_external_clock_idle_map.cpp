// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.
//
// Coverage for util/external_clock_idle_map.hpp — every testStrategy item of
// architecture/iora/util_external_clock_idle_map.json: caller-clock injection,
// the strict-greater idle boundary, deterministic eviction SET + ORDER (via
// (lastActivity, insertSeq), NOT Key), getOrCreate, idle-refresh semantics,
// copy-then-invoke + per-victim exception isolation across all three eviction
// paths, pointer/reference validity, erase/overwrite silence, drainAll,
// backward/reordered-now safety, the maxEntries LRU bound (+ insertSeq tiebreak
// + the getOrCreate self-eviction exemption, step-0 H1), and the deleted
// special members.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include <iora/util/external_clock_idle_map.hpp>

using iora::util::EvictReason;
using iora::util::ExternalClockIdleMap;

namespace
{

// A plain signed-integer TimePoint (Duration = long long, signed) exercises the
// non-chrono arithmetic path and makes synthetic ticks trivial to reason about.
using Tick = long long;

// Records an eviction so tests can assert both the SET and the ORDER.
struct EvictRec
{
  std::string key;
  std::string value;
  EvictReason reason;
};

// A Key type with Hash + Eq but deliberately NO operator< (round-2 A: the map
// must not require LessThanComparable keys).
struct NoLessKey
{
  int a;
  int b;
  bool operator==(const NoLessKey &o) const { return a == o.a && b == o.b; }
};

} // namespace

namespace std
{
template <>
struct hash<NoLessKey>
{
  std::size_t operator()(const NoLessKey &k) const noexcept
  {
    return std::hash<int>()(k.a) * 1000003u ^ std::hash<int>()(k.b);
  }
};
} // namespace std

// ---------------------------------------------------------------------------
// Special members (round-1 M4): copy and move are unavailable. A POSITIVE
// type-trait assertion (step-0 L4) — not a compile-fail case.
// ---------------------------------------------------------------------------
namespace
{
using StrMap = ExternalClockIdleMap<std::string, std::string, Tick>;
static_assert(!std::is_copy_constructible<StrMap>::value, "copy ctor must be deleted");
static_assert(!std::is_move_constructible<StrMap>::value, "move ctor must be deleted");
static_assert(!std::is_copy_assignable<StrMap>::value, "copy assign must be deleted");
static_assert(!std::is_move_assignable<StrMap>::value, "move assign must be deleted");
} // namespace

TEST_CASE("special members are deleted", "[external_clock_idle_map]")
{
  // The static_asserts above are the real check; this keeps it a visible case.
  REQUIRE_FALSE(std::is_copy_constructible<StrMap>::value);
  REQUIRE_FALSE(std::is_move_constructible<StrMap>::value);
}

// ---------------------------------------------------------------------------
// Clock injection + strict-greater boundary (round-1 L2).
// ---------------------------------------------------------------------------
TEST_CASE("sweep fires exactly at strict-greater idle boundary", "[external_clock_idle_map]")
{
  std::vector<EvictRec> evicted;
  ExternalClockIdleMap<std::string, std::string, Tick> map(
      /*idleTimeout=*/100, [&](const std::string &k, std::string &&v, EvictReason r)
      { evicted.push_back({k, std::move(v), r}); });

  map.put("a", "va", /*now=*/0);

  SECTION("exactly == idleTimeout is NOT evicted")
  {
    REQUIRE(map.sweepExpired(/*now=*/100) == 0); // 100 - 0 == 100, not > 100
    REQUIRE(map.size() == 1);
    REQUIRE(evicted.empty());
  }
  SECTION("strictly greater IS evicted")
  {
    REQUIRE(map.sweepExpired(/*now=*/101) == 1);
    REQUIRE(map.size() == 0);
    REQUIRE(evicted.size() == 1);
    REQUIRE(evicted[0].key == "a");
    REQUIRE(evicted[0].value == "va");
    REQUIRE(evicted[0].reason == EvictReason::IDLE_TIMEOUT);
  }
}

// ---------------------------------------------------------------------------
// Idle-refresh semantics: get/getOrCreate/touch extend; peek/forEach do not.
// ---------------------------------------------------------------------------
TEST_CASE("get/getOrCreate/touch refresh lastActivity; peek/forEach do not",
          "[external_clock_idle_map]")
{
  ExternalClockIdleMap<std::string, int, Tick> map(100, nullptr);
  map.put("k", 1, /*now=*/0);

  SECTION("get refreshes")
  {
    REQUIRE(map.get("k", /*now=*/50) != nullptr);
    REQUIRE(map.sweepExpired(/*now=*/120) == 0); // 120 - 50 = 70, not > 100
    REQUIRE(map.size() == 1);
  }
  SECTION("touch refreshes")
  {
    REQUIRE(map.touch("k", /*now=*/50));
    REQUIRE(map.sweepExpired(/*now=*/120) == 0);
    REQUIRE(map.size() == 1);
  }
  SECTION("getOrCreate on hit refreshes")
  {
    int &ref = map.getOrCreate(
        "k", [] { return 999; }, /*now=*/50);
    REQUIRE(ref == 1); // existing value, factory NOT called
    REQUIRE(map.sweepExpired(/*now=*/120) == 0);
    REQUIRE(map.size() == 1);
  }
  SECTION("peek does NOT refresh")
  {
    REQUIRE(map.peek("k") != nullptr);
    REQUIRE(*map.peek("k") == 1);
    REQUIRE(map.sweepExpired(/*now=*/101) == 1); // 101 - 0 > 100 -> expired
    REQUIRE(map.size() == 0);
  }
  SECTION("forEach does NOT refresh")
  {
    int seen = 0;
    map.forEach([&](const std::string &, const int &v) { seen += v; });
    REQUIRE(seen == 1);
    REQUIRE(map.sweepExpired(/*now=*/101) == 1);
    REQUIRE(map.size() == 0);
  }
}

// ---------------------------------------------------------------------------
// getOrCreate seam: miss inserts via factory + returns a valid reference.
// ---------------------------------------------------------------------------
TEST_CASE("getOrCreate inserts on miss and returns a mutable reference",
          "[external_clock_idle_map]")
{
  ExternalClockIdleMap<std::string, std::string, Tick> map(100, nullptr);

  bool factoryCalled = false;
  std::string &ref = map.getOrCreate(
      "new", [&] { factoryCalled = true; return std::string("made"); }, /*now=*/10);
  REQUIRE(factoryCalled);
  REQUIRE(ref == "made");
  REQUIRE(map.size() == 1);

  // Mutating through the reference is visible in the map.
  ref = "mutated";
  REQUIRE(*map.peek("new") == "mutated");

  // A second getOrCreate on the same key does NOT call the factory again.
  factoryCalled = false;
  std::string &ref2 = map.getOrCreate(
      "new", [&] { factoryCalled = true; return std::string("again"); }, /*now=*/20);
  REQUIRE_FALSE(factoryCalled);
  REQUIRE(ref2 == "mutated");
}

// ---------------------------------------------------------------------------
// Determinism: identical (op, now) sequences evict the identical SET in
// identical callback ORDER (sorted by lastActivity, then insertSeq — NOT Key),
// including a Key with no operator< (round-2 A/B).
// ---------------------------------------------------------------------------
TEST_CASE("sweep victim order is deterministic by (lastActivity, insertSeq)",
          "[external_clock_idle_map]")
{
  std::vector<EvictRec> evicted;
  ExternalClockIdleMap<std::string, std::string, Tick> map(
      10, [&](const std::string &k, std::string &&v, EvictReason)
      { evicted.push_back({k, std::move(v), EvictReason::IDLE_TIMEOUT}); });

  // Insert in an order that does NOT match lastActivity order, and give two
  // entries an identical lastActivity to force the insertSeq tiebreak.
  map.put("late", "1", /*now=*/30);  // seq 0, lastActivity 30
  map.put("early", "2", /*now=*/10); // seq 1, lastActivity 10
  map.put("mid_a", "3", /*now=*/20); // seq 2, lastActivity 20
  map.put("mid_b", "4", /*now=*/20); // seq 3, lastActivity 20 (tie with mid_a)

  // Expire all (now large enough that every delta > 10).
  REQUIRE(map.sweepExpired(/*now=*/1000) == 4);

  // Expected order: early(10) < mid_a(20,seq2) < mid_b(20,seq3) < late(30).
  REQUIRE(evicted.size() == 4);
  REQUIRE(evicted[0].key == "early");
  REQUIRE(evicted[1].key == "mid_a");
  REQUIRE(evicted[2].key == "mid_b");
  REQUIRE(evicted[3].key == "late");
}

TEST_CASE("a Key with no operator< compiles and orders deterministically",
          "[external_clock_idle_map]")
{
  std::vector<std::tuple<int, int>> order;
  ExternalClockIdleMap<NoLessKey, int, Tick> map(
      10, [&](const NoLessKey &k, int &&, EvictReason) { order.push_back({k.a, k.b}); });

  map.put({2, 2}, 0, /*now=*/30);
  map.put({1, 1}, 0, /*now=*/10);
  map.put({3, 3}, 0, /*now=*/20);
  REQUIRE(map.sweepExpired(/*now=*/1000) == 3);

  REQUIRE(order.size() == 3);
  REQUIRE(order[0] == std::make_tuple(1, 1)); // lastActivity 10
  REQUIRE(order[1] == std::make_tuple(3, 3)); // lastActivity 20
  REQUIRE(order[2] == std::make_tuple(2, 2)); // lastActivity 30
}

// ---------------------------------------------------------------------------
// Copy-then-invoke + exception isolation across ALL THREE paths (round-1 H2 /
// round-2 C): a callback that re-enters the map AND throws on one victim still
// completes the eviction of the others.
// ---------------------------------------------------------------------------
TEST_CASE("sweepExpired isolates a throwing, re-entrant callback", "[external_clock_idle_map]")
{
  int calls = 0;
  ExternalClockIdleMap<std::string, int, Tick> *self = nullptr;
  ExternalClockIdleMap<std::string, int, Tick> map(
      10, [&](const std::string &k, int &&, EvictReason)
      {
        ++calls;
        REQUIRE(self->size() == 0); // map already emptied before callbacks
        if (k == "b") { throw std::runtime_error("boom"); }
      });
  self = &map;

  map.put("a", 1, 0);
  map.put("b", 2, 0);
  map.put("c", 3, 0);
  REQUIRE_NOTHROW(map.sweepExpired(/*now=*/100));
  REQUIRE(calls == 3); // all three fired despite the throw on "b"
  REQUIRE(map.size() == 0);
}

TEST_CASE("a non-std throw from the callback is isolated too", "[external_clock_idle_map]")
{
  int calls = 0;
  ExternalClockIdleMap<std::string, int, Tick> map(
      10, [&](const std::string &, int &&, EvictReason)
      {
        ++calls;
        throw 42; // non-std throw
      });
  map.put("a", 1, 0);
  map.put("b", 2, 0);
  REQUIRE_NOTHROW(map.sweepExpired(/*now=*/100));
  REQUIRE(calls == 2);
  REQUIRE(map.size() == 0);
}

TEST_CASE("drainAll isolates a throwing callback", "[external_clock_idle_map]")
{
  int calls = 0;
  ExternalClockIdleMap<std::string, int, Tick> map(
      10, [&](const std::string &k, int &&, EvictReason r)
      {
        ++calls;
        REQUIRE(r == EvictReason::DRAIN);
        if (k == "a") { throw std::runtime_error("boom"); }
      });
  map.put("a", 1, 0);
  map.put("b", 2, 0);
  REQUIRE_NOTHROW(map.drainAll());
  REQUIRE(calls == 2);
  REQUIRE(map.empty());
}

TEST_CASE("put()/LRU_BOUND isolates a throwing callback", "[external_clock_idle_map]")
{
  int calls = 0;
  ExternalClockIdleMap<std::string, int, Tick> map(
      1000, [&](const std::string &, int &&, EvictReason r)
      {
        ++calls;
        REQUIRE(r == EvictReason::LRU_BOUND);
        throw std::runtime_error("boom");
      },
      /*maxEntries=*/1);
  map.put("a", 1, /*now=*/0);
  REQUIRE_NOTHROW(map.put("b", 2, /*now=*/10)); // evicts "a", callback throws
  REQUIRE(calls == 1);
  REQUIRE(map.size() == 1);
  REQUIRE(map.contains("b"));
  REQUIRE_FALSE(map.contains("a"));
}

// ---------------------------------------------------------------------------
// erase()/overwrite silence + empty onEvict still counts (round-1 L4).
// ---------------------------------------------------------------------------
TEST_CASE("erase and overwrite never fire onEvict; empty onEvict still counts",
          "[external_clock_idle_map]")
{
  SECTION("erase is silent")
  {
    int calls = 0;
    ExternalClockIdleMap<std::string, int, Tick> map(
        10, [&](const std::string &, int &&, EvictReason) { ++calls; });
    map.put("a", 1, 0);
    REQUIRE(map.erase("a"));
    REQUIRE_FALSE(map.erase("a")); // absent
    REQUIRE(calls == 0);
  }
  SECTION("overwrite is silent and preserves insertSeq ordering")
  {
    int calls = 0;
    std::vector<std::string> order;
    ExternalClockIdleMap<std::string, int, Tick> map(
        10, [&](const std::string &k, int &&, EvictReason)
        { ++calls; order.push_back(k); });
    map.put("a", 1, /*now=*/0);  // seq 0
    map.put("b", 2, /*now=*/5);  // seq 1
    map.put("a", 9, /*now=*/5);  // overwrite: silent, keeps seq 0, refresh to 5
    REQUIRE(calls == 0);
    REQUIRE(*map.peek("a") == 9);
    // Both now at lastActivity 5; "a" keeps the lower insertSeq (0) so evicts first.
    REQUIRE(map.sweepExpired(/*now=*/100) == 2);
    REQUIRE(order == std::vector<std::string>{"a", "b"});
  }
  SECTION("empty onEvict still evicts and counts")
  {
    ExternalClockIdleMap<std::string, int, Tick> map(10, nullptr);
    map.put("a", 1, 0);
    map.put("b", 2, 0);
    REQUIRE(map.sweepExpired(/*now=*/100) == 2);
    REQUIRE(map.empty());
  }
}

// ---------------------------------------------------------------------------
// drainAll: fires DRAIN for every entry, empties the map; second call is a no-op.
// ---------------------------------------------------------------------------
TEST_CASE("drainAll fires DRAIN for all and is idempotent on empty",
          "[external_clock_idle_map]")
{
  std::vector<EvictRec> evicted;
  ExternalClockIdleMap<std::string, std::string, Tick> map(
      10, [&](const std::string &k, std::string &&v, EvictReason r)
      { evicted.push_back({k, std::move(v), r}); });
  map.put("a", "1", /*now=*/5);
  map.put("b", "2", /*now=*/9);
  REQUIRE(map.drainAll() == 2);
  REQUIRE(map.empty());
  REQUIRE(evicted.size() == 2);
  REQUIRE(evicted[0].reason == EvictReason::DRAIN);
  REQUIRE(evicted[0].key == "a"); // lastActivity 5 < 9
  REQUIRE(evicted[1].key == "b");

  // Second drain is a clean no-op.
  REQUIRE(map.drainAll() == 0);
  REQUIRE(evicted.size() == 2);
}

// ---------------------------------------------------------------------------
// Pointer validity (round-1 M2): a Value* survives other-key ops and rehash;
// asserted by address identity. Invalidated only by erase/evict of THAT key.
// ---------------------------------------------------------------------------
TEST_CASE("get() pointer stays valid across other-key ops and rehash",
          "[external_clock_idle_map]")
{
  ExternalClockIdleMap<int, std::string, Tick> map(1000, nullptr);
  map.put(0, "target", /*now=*/0);
  std::string *p = map.get(0, /*now=*/0);
  REQUIRE(p != nullptr);
  const std::string *addrBefore = p;

  // Force many inserts (rehash) + other-key erases.
  for (int i = 1; i <= 200; ++i)
  {
    map.put(i, "x" + std::to_string(i), /*now=*/0);
  }
  for (int i = 1; i <= 100; ++i)
  {
    map.erase(i);
  }

  std::string *pAfter = map.get(0, /*now=*/0);
  REQUIRE(pAfter == addrBefore); // reference stability: same address
  REQUIRE(*pAfter == "target");  // and same value

  // Erasing THAT key removes it (pointer must no longer be dereferenced).
  REQUIRE(map.erase(0));
  REQUIRE(map.get(0, /*now=*/0) == nullptr);
}

// ---------------------------------------------------------------------------
// Backward/reordered-now safety (round-1 H1): a sweep with now < stored
// lastActivity evicts nothing and does not underflow (signed Duration); a later
// forward sweep still behaves.
// ---------------------------------------------------------------------------
TEST_CASE("backward now evicts nothing and does not corrupt later sweeps",
          "[external_clock_idle_map]")
{
  int calls = 0;
  ExternalClockIdleMap<std::string, int, Tick> map(
      100, [&](const std::string &, int &&, EvictReason) { ++calls; });
  map.put("a", 1, /*now=*/1000);

  REQUIRE(map.sweepExpired(/*now=*/500) == 0); // 500 - 1000 = -500, not > 100
  REQUIRE(map.size() == 1);
  REQUIRE(calls == 0);

  // A forward sweep past the idle window still evicts.
  REQUIRE(map.sweepExpired(/*now=*/1200) == 1); // 1200 - 1000 = 200 > 100
  REQUIRE(calls == 1);
}

// ---------------------------------------------------------------------------
// maxEntries LRU bound: exceeding the cap evicts the min-(lastActivity,insertSeq)
// entry with LRU_BOUND; the victim is the true min even after a backward-now
// insert; the insertSeq tiebreak (step-0 M4) is exercised; maxEntries==0 throws;
// nullopt is unbounded.
// ---------------------------------------------------------------------------
TEST_CASE("maxEntries==0 is rejected at construction", "[external_clock_idle_map]")
{
  REQUIRE_THROWS_AS(
      (ExternalClockIdleMap<std::string, int, Tick>(10, nullptr, /*maxEntries=*/0)),
      std::invalid_argument);
}

TEST_CASE("nullopt maxEntries is unbounded", "[external_clock_idle_map]")
{
  int calls = 0;
  ExternalClockIdleMap<int, int, Tick> map(
      1000, [&](const int &, int &&, EvictReason) { ++calls; }, std::nullopt);
  for (int i = 0; i < 500; ++i)
  {
    map.put(i, i, /*now=*/0);
  }
  REQUIRE(map.size() == 500);
  REQUIRE(calls == 0); // no bound evictions
}

TEST_CASE("LRU bound evicts the minimum-lastActivity victim", "[external_clock_idle_map]")
{
  std::vector<EvictRec> evicted;
  ExternalClockIdleMap<std::string, std::string, Tick> map(
      1000, [&](const std::string &k, std::string &&v, EvictReason r)
      { evicted.push_back({k, std::move(v), r}); },
      /*maxEntries=*/2);

  map.put("old", "1", /*now=*/10);
  map.put("mid", "2", /*now=*/20);
  map.put("new", "3", /*now=*/30); // exceeds cap -> evict min lastActivity = "old"

  REQUIRE(map.size() == 2);
  REQUIRE(evicted.size() == 1);
  REQUIRE(evicted[0].key == "old");
  REQUIRE(evicted[0].reason == EvictReason::LRU_BOUND);
  REQUIRE(map.contains("mid"));
  REQUIRE(map.contains("new"));
}

TEST_CASE("LRU bound breaks equal-lastActivity ties by insertSeq", "[external_clock_idle_map]")
{
  std::vector<std::string> evicted;
  ExternalClockIdleMap<std::string, int, Tick> map(
      1000, [&](const std::string &k, int &&, EvictReason) { evicted.push_back(k); },
      /*maxEntries=*/2);

  map.put("first", 1, /*now=*/50);  // seq 0
  map.put("second", 2, /*now=*/50); // seq 1 (tie on lastActivity)
  map.put("third", 3, /*now=*/50);  // seq 2 -> exceeds cap; victim = lowest seq at t=50

  REQUIRE(evicted == std::vector<std::string>{"first"});
  REQUIRE_FALSE(map.contains("first"));
}

TEST_CASE("LRU victim is the true min even after a backward-now insert",
          "[external_clock_idle_map]")
{
  std::vector<std::string> evicted;
  ExternalClockIdleMap<std::string, int, Tick> map(
      100000, [&](const std::string &k, int &&, EvictReason) { evicted.push_back(k); },
      /*maxEntries=*/2);

  map.put("a", 1, /*now=*/1000);
  map.put("b", 2, /*now=*/2000);
  // A backward-now insert: "c" has the smallest lastActivity (5), so put()
  // (self-eviction tolerated) evicts "c" itself as the true minimum.
  map.put("c", 3, /*now=*/5);
  REQUIRE(evicted == std::vector<std::string>{"c"});
  REQUIRE(map.contains("a"));
  REQUIRE(map.contains("b"));
}

// ---------------------------------------------------------------------------
// getOrCreate self-eviction exemption under a backward `now` (step-0 H1): the
// just-inserted entry that trips the bound is EXEMPT from victim selection, so
// the returned reference is never dangled (no UAF).
// ---------------------------------------------------------------------------
TEST_CASE("getOrCreate under a tripped bound returns a still-valid reference (step-0 H1)",
          "[external_clock_idle_map]")
{
  std::vector<std::string> evicted;
  ExternalClockIdleMap<std::string, std::string, Tick> map(
      100000, [&](const std::string &k, std::string &&, EvictReason) { evicted.push_back(k); },
      /*maxEntries=*/1);

  map.put("old", "keep-far", /*now=*/1000); // lastActivity 1000

  // getOrCreate with a BACKWARD now: "created" would be the unique minimum
  // (lastActivity 1). Without the exemption it would evict itself and dangle the
  // reference. With it, "old" is the victim and the returned reference is valid.
  std::string &ref = map.getOrCreate(
      "created", [] { return std::string("factory-value"); }, /*now=*/1);

  REQUIRE(ref == "factory-value"); // reference is alive and correct
  ref = "mutated-through-ref";     // and writable
  REQUIRE(map.contains("created"));
  REQUIRE(*map.peek("created") == "mutated-through-ref");
  REQUIRE_FALSE(map.contains("old"));
  REQUIRE(evicted == std::vector<std::string>{"old"});
}

// ---------------------------------------------------------------------------
// getOrCreate returned reference stays LIVE and CORRECT across a heavy
// re-entrant callback (HIGH-1, defensive). The production fix binds the mapped
// reference BEFORE enforceBound, so the return is a stable node-reference, not an
// iterator that a callback-triggered rehash could invalidate.
//
// HONESTY NOTE (cpp17 round-2 MEDIUM-1): the maxEntries cap structurally
// prevents a callback-time NET-GROWTH rehash — the only path that fires
// getOrCreate's callback is the cap being tripped, and every re-entrant put in
// the callback self-trims immediately (live size never nets above maxEntries+1,
// and bucket_count is already >= maxEntries+1 after the outer emplace), so no
// rehash occurs during the callback. That makes the exact pre-fix iterator-
// invalidation UB structurally UNREACHABLE via re-entrancy, so no re-entrancy
// test can force it. This test therefore guards what IS verifiable: that after a
// large re-entrant, nested-evicting callback the returned reference is (a) the
// live "target" element (ADDRESS IDENTITY vs a fresh lookup), (b) correct, and
// (c) writable-through — and that the exemption keeps "target" from being its
// own victim. "target" gets the newest lastActivity so it is never a burst
// victim, and it is exempt from the outer bound.
// ---------------------------------------------------------------------------
TEST_CASE("getOrCreate reference is live, correct, and identity-stable across a re-entrant "
          "callback (HIGH-1 defensive)",
          "[external_clock_idle_map]")
{
  ExternalClockIdleMap<std::string, std::string, Tick> *self = nullptr;
  bool bursted = false;
  ExternalClockIdleMap<std::string, std::string, Tick> map(
      1000000, [&](const std::string &, std::string &&, EvictReason r)
      {
        REQUIRE(r == EvictReason::LRU_BOUND);
        if (!bursted)
        {
          bursted = true;
          // Re-enter with a heavy insert burst (nested evictions). Each put uses a
          // small lastActivity, so only burst keys (never "target") are victims.
          for (int i = 0; i < 64; ++i)
          {
            self->put("burst" + std::to_string(i), "v", /*now=*/100 + i);
          }
        }
      },
      /*maxEntries=*/4);
  self = &map;

  map.put("k0", "0", /*now=*/10);
  map.put("k1", "1", /*now=*/11);
  map.put("k2", "2", /*now=*/12);
  map.put("k3", "3", /*now=*/13);

  std::string &ref = map.getOrCreate(
      "target", [] { return std::string("factory"); }, /*now=*/1000000);

  REQUIRE(bursted);
  // Address identity: the returned reference IS the live "target" node. If the
  // return were ever routed through an invalidated iterator (or the exempt entry
  // were wrongly evicted), this diverges or "target" is gone.
  REQUIRE(&ref == map.peek("target"));
  REQUIRE(ref == "factory");   // correct value
  ref = "written-through-ref"; // writable-through
  REQUIRE(map.contains("target"));
  REQUIRE(*map.peek("target") == "written-through-ref");
}

// ---------------------------------------------------------------------------
// Chrono TimePoint path: exercises the DurationIsSigned<Duration::rep> branch of
// the signedness trait and confirms the whole surface works with a real
// std::chrono::time_point.
// ---------------------------------------------------------------------------
TEST_CASE("works with a std::chrono time_point TimePoint", "[external_clock_idle_map]")
{
  using Clock = std::chrono::steady_clock;
  using TP = Clock::time_point;
  const TP base{}; // epoch of the steady clock's time_point

  std::vector<std::string> evicted;
  ExternalClockIdleMap<std::string, int, TP> map(
      std::chrono::seconds(10),
      [&](const std::string &k, int &&, EvictReason) { evicted.push_back(k); });

  map.put("a", 1, base + std::chrono::seconds(0));
  REQUIRE(map.sweepExpired(base + std::chrono::seconds(10)) == 0); // == boundary
  REQUIRE(map.sweepExpired(base + std::chrono::seconds(11)) == 1); // strictly greater
  REQUIRE(evicted == std::vector<std::string>{"a"});
}

// ---------------------------------------------------------------------------
// Move-only Value: confirms move-construction into the callback works and the
// map never copies the value.
// ---------------------------------------------------------------------------
TEST_CASE("supports a move-only Value", "[external_clock_idle_map]")
{
  int drained = 0;
  ExternalClockIdleMap<std::string, std::unique_ptr<int>, Tick> map(
      10, [&](const std::string &, std::unique_ptr<int> &&v, EvictReason)
      { drained += (v ? *v : 0); });

  map.put("a", std::make_unique<int>(7), /*now=*/0);
  std::unique_ptr<int> *p = map.get("a", /*now=*/0);
  REQUIRE(p != nullptr);
  REQUIRE(**p == 7);
  REQUIRE(map.drainAll() == 1);
  REQUIRE(drained == 7);
}
