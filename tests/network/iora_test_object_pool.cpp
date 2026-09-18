// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// Focused tests for iora::network::ObjectPool covering the hardened behavior:
/// the factory runs OUTSIDE the pool lock (no self-deadlock / serialization),
/// acquire() counts every acquisition, clear() accounts destructions, and a
/// null-returning factory is handled gracefully. Broad functional/thread-safety
/// coverage also lives in iora_test_transport_improvements.cpp.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/network/object_pool.hpp"

#include <string>

using iora::network::ObjectPool;
using iora::network::PooledObject;
using iora::network::makePooled;

namespace
{
struct Widget
{
  int id{0};
  std::string data;
};
} // namespace

TEST_CASE("ObjectPool factory runs outside the pool lock (re-entrancy safe)",
          "[pool][deadlock]")
{
  // The factory re-enters the pool via getStats(), which locks the same mutex.
  // If acquire() held the lock across the factory call this would deadlock on
  // the non-recursive std::mutex (and the test would time out). With the
  // factory called off the lock, it completes.
  ObjectPool<Widget> *poolPtr = nullptr;
  auto factory = [&poolPtr]()
  {
    if (poolPtr != nullptr)
    {
      // Re-enter a locking method while "inside" the factory. getStats() takes
      // _mutex, so this deadlocks (and the test times out) if acquire() still
      // held the lock across the factory call.
      (void)poolPtr->getStats();
    }
    return std::make_unique<Widget>();
  };
  ObjectPool<Widget> pool(factory); // empty pool -> next acquire manufactures
  poolPtr = &pool;

  auto obj = pool.acquire(); // must not deadlock
  REQUIRE(obj != nullptr);
}

TEST_CASE("ObjectPool counts acquisitions on both reuse and manufacture paths",
          "[pool][stats]")
{
  auto factory = [] { return std::make_unique<Widget>(); };
  ObjectPool<Widget> pool(factory, nullptr, 1); // 1 pre-created

  auto a = pool.acquire(); // reuse the pre-created object
  auto b = pool.acquire(); // pool empty -> manufacture
  REQUIRE(a != nullptr);
  REQUIRE(b != nullptr);

  auto stats = pool.getStats();
  REQUIRE(stats.totalAcquired == 2); // BOTH paths counted
  REQUIRE(stats.totalCreated == 2);  // 1 pre-created + 1 manufactured
}

TEST_CASE("ObjectPool::clear accounts destroyed objects", "[pool][stats]")
{
  auto factory = [] { return std::make_unique<Widget>(); };
  ObjectPool<Widget> pool(factory, nullptr, 5); // 5 idle objects

  auto stats = pool.getStats();
  REQUIRE(stats.available == 5);
  REQUIRE(stats.totalDestroyed == 0);

  pool.clear();
  stats = pool.getStats();
  REQUIRE(stats.available == 0);
  REQUIRE(stats.totalDestroyed == 5); // clear() now counts the dropped objects
}

TEST_CASE("ObjectPool tolerates a null-returning factory", "[pool][null]")
{
  auto factory = []() -> std::unique_ptr<Widget> { return nullptr; };
  ObjectPool<Widget> pool(factory);

  auto obj = pool.acquire();
  REQUIRE(obj == nullptr);

  auto stats = pool.getStats();
  REQUIRE(stats.totalCreated == 0);  // a null is not counted as created
  REQUIRE(stats.totalAcquired == 0); // nor as acquired
}

TEST_CASE("ObjectPool caps the idle free list and resets on release", "[pool][cap]")
{
  auto factory = [] { return std::make_unique<Widget>(); };
  auto resetter = [](Widget *w)
  {
    w->id = 0;
    w->data.clear();
  };
  ObjectPool<Widget> pool(factory, resetter, 0);
  pool.setMaxPoolSize(1);

  // Hold two objects at once, then release both: only one fits the cap, the
  // other is destroyed on the over-cap release (exercises the cap + accounting).
  auto a = pool.acquire();
  a->id = 7;
  a->data = "dirty";
  auto b = pool.acquire();
  pool.release(std::move(a)); // fits -> back in pool (size 1)
  pool.release(std::move(b)); // over cap -> destroyed

  auto stats = pool.getStats();
  REQUIRE(stats.available == 1);
  REQUIRE(stats.totalDestroyed == 1);

  auto c = pool.acquire(); // reuse the retained, reset object
  REQUIRE(c->id == 0);      // resetter cleared it before it was pooled
  REQUIRE(c->data.empty());
}

TEST_CASE("ObjectPool::setMaxPoolSize trim accounts destroyed", "[pool][cap]")
{
  auto factory = [] { return std::make_unique<Widget>(); };
  ObjectPool<Widget> pool(factory, nullptr, 5); // 5 idle
  pool.setMaxPoolSize(2);                        // trim 3 away
  auto stats = pool.getStats();
  REQUIRE(stats.available == 2);
  REQUIRE(stats.totalDestroyed == 3);
}

TEST_CASE("PooledObject returns to pool, moves, and detaches", "[pool][raii]")
{
  auto factory = [] { return std::make_unique<Widget>(); };
  ObjectPool<Widget> pool(factory, nullptr, 0);

  {
    PooledObject<Widget> p = makePooled(pool);
    REQUIRE(static_cast<bool>(p));
    p->id = 3;
    REQUIRE(p.get()->id == 3);
  } // destructor returns it to the pool
  REQUIRE(pool.getStats().available == 1);

  // Move leaves the source empty and keeps a single return.
  PooledObject<Widget> p1 = makePooled(pool); // reuse the returned one
  PooledObject<Widget> p2 = std::move(p1);
  REQUIRE(static_cast<bool>(p2));
  REQUIRE_FALSE(static_cast<bool>(p1));

  // release() detaches: the object does NOT go back to the pool.
  std::unique_ptr<Widget> escaped = p2.release();
  REQUIRE(escaped != nullptr);
  REQUIRE_FALSE(static_cast<bool>(p2));
  REQUIRE(pool.getStats().available == 0); // nothing returned
}
