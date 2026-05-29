// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Unit tests for iora::ServiceRegistry (core/service_registry.hpp).

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/core/service_registry.hpp>

#include "web/service_registry_test_access.hpp"

#include <csignal>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

using iora::ServiceRegistry;
using iora::ServiceRegistryTestAccess;

// Isolate test cases that share the process-global registry: clear it before and
// after every case so a REQUIRE failure mid-test cannot leak a stale entry that
// breaks the next case.
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

// Local, self-contained test interfaces (distinct type_index keys). Each test
// uses its own type and cleans up so the process-global registry carries no
// state across cases.
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

struct IThing
{
  virtual ~IThing() = default;
  virtual int value() = 0;
};
struct ThingImpl : IThing
{
  int value() override { return 7; }
};

struct ICoreSvc
{
  virtual ~ICoreSvc() = default;
  virtual int id() = 0;
};
struct CoreSvcImpl : ICoreSvc
{
  int id() override { return 99; }
};

struct IOrphan
{
  virtual ~IOrphan() = default;
  virtual void noop() = 0;
};
struct OrphanImpl : IOrphan
{
  void noop() override {}
};

} // namespace

// ── set / get happy path (testStrategy.unitTests.cases 1, 2, 9) ──────────────

TEST_CASE("ServiceRegistry: set then get returns the same impl", "[service_registry]")
{
  auto impl = std::make_shared<GreeterImpl>();
  ServiceRegistry::set<IGreeter>(impl, "modA");

  auto got = ServiceRegistry::get<IGreeter>();
  REQUIRE(got != nullptr);
  REQUIRE(got.get() == impl.get()); // identity / pointer equality
  REQUIRE(got->greet() == "hi");

  ServiceRegistry::unregister<IGreeter>();
}

TEST_CASE("ServiceRegistry: get of an unregistered type returns nullptr", "[service_registry]")
{
  REQUIRE(ServiceRegistry::get<ICounter>() == nullptr);
}

TEST_CASE("ServiceRegistry: two distinct types are independently retrievable",
          "[service_registry]")
{
  auto g = std::make_shared<GreeterImpl>();
  auto c = std::make_shared<CounterImpl>();
  ServiceRegistry::set<IGreeter>(g, "modA");
  ServiceRegistry::set<ICounter>(c, "modA");

  REQUIRE(ServiceRegistry::get<IGreeter>()->greet() == "hi");
  REQUIRE(ServiceRegistry::get<ICounter>()->next() == 1);
  REQUIRE(ServiceRegistry::get<ICounter>()->next() == 2); // same instance

  ServiceRegistry::unregister<IGreeter>();
  ServiceRegistry::unregister<ICounter>();
}

// ── error policy (testStrategy.unitTests.cases 3, 4 + H-2) ───────────────────

TEST_CASE("ServiceRegistry: set(nullptr) throws invalid_argument, no partial state",
          "[service_registry]")
{
  std::shared_ptr<IGreeter> nullImpl;
  REQUIRE_THROWS_AS(ServiceRegistry::set<IGreeter>(nullImpl, "modA"), std::invalid_argument);
  // The throw precedes the write lock; no entry is created.
  REQUIRE(ServiceRegistry::get<IGreeter>() == nullptr);
}

TEST_CASE("ServiceRegistry: duplicate set throws runtime_error", "[service_registry]")
{
  auto g = std::make_shared<GreeterImpl>();
  ServiceRegistry::set<IGreeter>(g, "modA");

  auto g2 = std::make_shared<GreeterImpl>();
  REQUIRE_THROWS_AS(ServiceRegistry::set<IGreeter>(g2, "modA"), std::runtime_error);

  ServiceRegistry::unregister<IGreeter>();
}

TEST_CASE("ServiceRegistry: set with empty moduleId throws invalid_argument (H-2)",
          "[service_registry]")
{
  auto g = std::make_shared<GreeterImpl>();
  REQUIRE_THROWS_AS(ServiceRegistry::set<IGreeter>(g, ""), std::invalid_argument);
  REQUIRE(ServiceRegistry::get<IGreeter>() == nullptr); // no entry created
}

// ── core sentinel, unregister, unregisterModule (cases 5, 6, 7 + H-1) ────────

TEST_CASE("ServiceRegistry: core-internal set stores the sentinel, exempt + retrievable (H-1)",
          "[service_registry]")
{
  auto core = std::make_shared<CoreSvcImpl>();
  ServiceRegistry::set<ICoreSvc>(core); // core overload -> "\x00core" sentinel
  REQUIRE(ServiceRegistry::get<ICoreSvc>() != nullptr);
  REQUIRE(ServiceRegistry::get<ICoreSvc>()->id() == 99);

  auto a = std::make_shared<CounterImpl>();
  ServiceRegistry::set<ICounter>(a, "modA");

  // unregisterModule of an UNRELATED module iterates every surviving entry. If
  // the core sentinel were the empty string (the H-1 NUL-truncation bug), the
  // core entry would be flagged as an orphaned empty-moduleId survivor and the
  // whole test process would abort. Reaching the assertions below proves the
  // sentinel is non-empty AND exempt from the survivor check.
  ServiceRegistry::unregisterModule("modB");

  REQUIRE(ServiceRegistry::get<ICoreSvc>() != nullptr); // sentinel entry survives
  REQUIRE(ServiceRegistry::get<ICounter>() != nullptr); // modA entry survives

  ServiceRegistry::unregister<ICoreSvc>();
  ServiceRegistry::unregister<ICounter>();
}

TEST_CASE("ServiceRegistry: unregister returns true when present, false when absent",
          "[service_registry]")
{
  auto g = std::make_shared<GreeterImpl>();
  ServiceRegistry::set<IGreeter>(g, "modA");

  REQUIRE(ServiceRegistry::unregister<IGreeter>() == true);
  REQUIRE(ServiceRegistry::get<IGreeter>() == nullptr);
  REQUIRE(ServiceRegistry::unregister<IGreeter>() == false);
}

TEST_CASE("ServiceRegistry: unregisterModule removes all-and-only matching entries",
          "[service_registry]")
{
  auto g = std::make_shared<GreeterImpl>(); // modA
  auto c = std::make_shared<CounterImpl>(); // modA
  auto t = std::make_shared<ThingImpl>();   // modB
  auto core = std::make_shared<CoreSvcImpl>();
  ServiceRegistry::set<IGreeter>(g, "modA");
  ServiceRegistry::set<ICounter>(c, "modA");
  ServiceRegistry::set<IThing>(t, "modB");
  ServiceRegistry::set<ICoreSvc>(core); // sentinel

  ServiceRegistry::unregisterModule("modA");

  REQUIRE(ServiceRegistry::get<IGreeter>() == nullptr); // removed
  REQUIRE(ServiceRegistry::get<ICounter>() == nullptr); // removed
  REQUIRE(ServiceRegistry::get<IThing>() != nullptr);   // other module survives
  REQUIRE(ServiceRegistry::get<ICoreSvc>() != nullptr); // sentinel survives

  ServiceRegistry::unregister<IThing>();
  ServiceRegistry::unregister<ICoreSvc>();
}

TEST_CASE("ServiceRegistry: unregisterModule of a module with zero entries is a no-op",
          "[service_registry]")
{
  REQUIRE_NOTHROW(ServiceRegistry::unregisterModule("does-not-exist"));
}

// ── lifetime contract (testStrategy.unitTests.cases 10) ──────────────────────

TEST_CASE("ServiceRegistry: get keeps the impl alive after unregister (refcount > 1)",
          "[service_registry]")
{
  std::weak_ptr<GreeterImpl> weak;
  {
    auto g = std::make_shared<GreeterImpl>();
    weak = g;
    ServiceRegistry::set<IGreeter>(g, "modA"); // registry now the sole owner after g leaves scope
  }
  REQUIRE_FALSE(weak.expired()); // registry holds it

  auto held = ServiceRegistry::get<IGreeter>(); // refcount: registry + held
  REQUIRE(held != nullptr);

  ServiceRegistry::unregister<IGreeter>(); // registry drops its reference
  REQUIRE_FALSE(weak.expired());           // held still keeps the OBJECT alive
  REQUIRE(held->greet() == "hi");

  held.reset();
  REQUIRE(weak.expired()); // now released
}

// ── AH-2 survivor abort (defensive guard) — fork-based death test ────────────
//
// H-2 makes empty-moduleId entries impossible via the public API, so the AH-2
// survivor-abort path is reachable only by injecting state directly (via the
// test-only ServiceRegistryTestAccess). The guard uses std::abort(), so it is
// NDEBUG-independent; we verify the child process is killed by SIGABRT.

TEST_CASE("ServiceRegistry: orphaned empty-moduleId entry aborts on unregisterModule (AH-2)",
          "[service_registry][death]")
{
  pid_t pid = fork();
  REQUIRE(pid >= 0);
  if (pid == 0)
  {
    // Child: inject an orphaned (empty moduleId, non-core) entry, then run the
    // survivor check. Expected to std::abort(). Restore the default SIGABRT
    // disposition first so Catch2's signal handler does not intercept the abort
    // (which would turn a clean death into noisy child output); the child must
    // terminate with SIGABRT for the parent's checks below.
    std::signal(SIGABRT, SIG_DFL);
    auto o = std::make_shared<OrphanImpl>();
    ServiceRegistryTestAccess::injectEntry<IOrphan>(o, "");
    ServiceRegistry::unregisterModule("unrelated-module");
    _exit(0); // unreachable if the guard fires
  }

  int status = 0;
  REQUIRE(waitpid(pid, &status, 0) == pid);
  REQUIRE(WIFSIGNALED(status));
  REQUIRE(WTERMSIG(status) == SIGABRT);
}
