// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Concurrency tests for iora::ServiceRegistry. Intended to be built and run
// under ThreadSanitizer (-fsanitize=thread) to prove the shared_mutex read/write
// discipline is race-free. Run with ctest -j1 (web-test convention).

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/core/service_registry.hpp>

#include "web/service_registry_test_access.hpp"

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using iora::ServiceRegistry;

// Coverage note: these tests cover concurrent get vs get and get vs set/unregister
// on a DIFFERENT type. They intentionally do NOT cover concurrent unregisterModule
// vs get of the SAME type: the v1 lifecycle (RD-7) prohibits unloading a module
// while the HTTP server is started, so a get() result is never in flight when a
// module unloads — that drain-before-unload ordering is the only guard for the
// get()-racing-unload residual and is enforced by application_wiring, not here.

// Isolate test cases that share the process-global registry (see the unit-test
// file for rationale): clear it before and after each case.
namespace
{
struct RegistryCleanListener : Catch::TestEventListenerBase
{
  using TestEventListenerBase::TestEventListenerBase;
  void testCaseStarting(Catch::TestCaseInfo const &) override
  {
    iora::ServiceRegistryTestAccess::clearAll();
  }
  void testCaseEnded(Catch::TestCaseStats const &) override
  {
    iora::ServiceRegistryTestAccess::clearAll();
  }
};
} // namespace
CATCH_REGISTER_LISTENER(RegistryCleanListener)

namespace
{
struct IGreeter
{
  virtual ~IGreeter() = default;
  virtual std::string greet() = 0;
};
struct GreeterImpl : IGreeter
{
  std::string greet() override { return "hi"; }
};

struct ICounter
{
  virtual ~ICounter() = default;
  virtual int next() = 0;
};
struct CounterImpl : ICounter
{
  int n = 0;
  int next() override { return ++n; }
};
} // namespace

TEST_CASE("ServiceRegistry concurrency: readers vs writer on a different type",
          "[service_registry][concurrency]")
{
  auto g = std::make_shared<GreeterImpl>();
  ServiceRegistry::set<IGreeter>(g, "modStable");

  std::atomic<bool> stop{false};
  std::thread writer(
    [&]
    {
      while (!stop.load(std::memory_order_relaxed))
      {
        auto c = std::make_shared<CounterImpl>();
        ServiceRegistry::set<ICounter>(c, "modChurn");
        ServiceRegistry::unregister<ICounter>();
      }
    });

  std::atomic<int> reads{0};
  std::vector<std::thread> readers;
  for (int i = 0; i < 8; ++i)
  {
    readers.emplace_back(
      [&]
      {
        for (int j = 0; j < 20000; ++j)
        {
          auto r = ServiceRegistry::get<IGreeter>();
          if (r && r->greet() == "hi")
          {
            reads.fetch_add(1, std::memory_order_relaxed);
          }
          // Racing read of the churning type: may be present or absent, must
          // never tear or race (shared_lock vs the writer's unique_lock).
          auto c = ServiceRegistry::get<ICounter>();
          (void)c;
        }
      });
  }

  for (auto &t : readers)
  {
    t.join();
  }
  stop.store(true);
  writer.join();

  REQUIRE(reads.load() > 0);
  ServiceRegistry::unregister<IGreeter>();
  ServiceRegistry::unregister<ICounter>();
}

TEST_CASE("ServiceRegistry concurrency: concurrent same-type get is consistent",
          "[service_registry][concurrency]")
{
  auto g = std::make_shared<GreeterImpl>();
  ServiceRegistry::set<IGreeter>(g, "modA");

  std::atomic<int> mismatches{0};
  std::vector<std::thread> ts;
  for (int i = 0; i < 16; ++i)
  {
    ts.emplace_back(
      [&]
      {
        for (int j = 0; j < 10000; ++j)
        {
          auto r = ServiceRegistry::get<IGreeter>();
          if (!r || r.get() != g.get())
          {
            mismatches.fetch_add(1, std::memory_order_relaxed);
          }
        }
      });
  }
  for (auto &t : ts)
  {
    t.join();
  }

  REQUIRE(mismatches.load() == 0);
  ServiceRegistry::unregister<IGreeter>();
}

TEST_CASE("ServiceRegistry concurrency: set then concurrent burst-get observes the set",
          "[service_registry][concurrency]")
{
  auto g = std::make_shared<GreeterImpl>();
  ServiceRegistry::set<IGreeter>(g, "modA"); // write completes (under unique_lock) before threads spawn

  std::atomic<int> seen{0};
  std::vector<std::thread> ts;
  for (int i = 0; i < 16; ++i)
  {
    ts.emplace_back(
      [&]
      {
        if (ServiceRegistry::get<IGreeter>() != nullptr)
        {
          seen.fetch_add(1, std::memory_order_relaxed);
        }
      });
  }
  for (auto &t : ts)
  {
    t.join();
  }

  REQUIRE(seen.load() == 16);
  ServiceRegistry::unregister<IGreeter>();
}
