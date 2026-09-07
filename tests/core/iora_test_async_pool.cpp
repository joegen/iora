#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/core/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <stdexcept>
#include <thread>
#include <type_traits>

using namespace std::chrono_literals;

// DP-3c: PooledFuture's move operations MUST be noexcept (load-bearing for
// std::vector<PooledFuture> relocation of a move-only, copy-deleted type), and
// it MUST be move-only. Pin these invariants at compile time (cpp17 M-2).
static_assert(std::is_nothrow_move_constructible_v<iora::core::PooledFuture<int>>,
              "PooledFuture<int> move-ctor must be noexcept");
static_assert(std::is_nothrow_move_assignable_v<iora::core::PooledFuture<int>>,
              "PooledFuture<int> move-assign must be noexcept");
static_assert(!std::is_copy_constructible_v<iora::core::PooledFuture<int>>,
              "PooledFuture<int> must not be copy-constructible");
static_assert(!std::is_copy_assignable_v<iora::core::PooledFuture<int>>,
              "PooledFuture<int> must not be copy-assignable");
static_assert(std::is_nothrow_move_constructible_v<iora::core::PooledFuture<void>>,
              "PooledFuture<void> move-ctor must be noexcept");
static_assert(std::is_nothrow_move_assignable_v<iora::core::PooledFuture<void>>,
              "PooledFuture<void> move-assign must be noexcept");
static_assert(!std::is_copy_constructible_v<iora::core::PooledFuture<void>>,
              "PooledFuture<void> must not be copy-constructible");
static_assert(!std::is_copy_assignable_v<iora::core::PooledFuture<void>>,
              "PooledFuture<void> must not be copy-assignable");

//
// task-4.2: result future + PooledFuture<void> (value, void, void join-on-dtor)
//
TEST_CASE("async returns a value future", "[async_pool]")
{
  auto f = iora::core::async([]() { return 42; });
  REQUIRE(f.get() == 42);
}

TEST_CASE("async supports void callables", "[async_pool]")
{
  std::atomic<int> v{0};
  auto f = iora::core::async([&v]() { v.store(5); });
  f.get();
  REQUIRE(v.load() == 5);
}

TEST_CASE("PooledFuture<void> joins on destruction", "[async_pool]")
{
  std::atomic<bool> ran{false};
  {
    auto f = iora::core::async(
      [&ran]()
      {
        std::this_thread::sleep_for(30ms);
        ran.store(true);
      });
    // abandon f (no get) -> ~PooledFuture must join
  }
  REQUIRE(ran.load());
}

//
// task-4.3: abandon-safety (decisive, non-vacuous). A mutant that no-ops the
// destructor wait() leaves the write un-done (and, under ASan, would run against
// freed storage). The value assertion catches the mutant deterministically.
//
TEST_CASE("async abandoned future joins before captured state dies", "[async_pool]")
{
  auto probe = std::make_unique<std::atomic<int>>(0);
  std::atomic<int> *raw = probe.get();
  {
    auto f = iora::core::async(
      [raw]()
      {
        std::this_thread::sleep_for(50ms);
        raw->store(42); // if ~f did not join, this races/UAFs against probe below
      });
    // abandon f without get()
  }
  // ~f has joined here; the write is complete and probe is still alive.
  REQUIRE(raw->load() == 42);
  probe.reset();
}

//
// task-4.4: consume path leaves the future !valid() (dtor is a no-op);
// discarded temporary joins at end of full expression (std::async parity).
//
TEST_CASE("async consume path leaves future invalid", "[async_pool]")
{
  auto f = iora::core::async([]() { return 3; });
  REQUIRE(f.valid());
  REQUIRE(f.get() == 3);
  REQUIRE_FALSE(f.valid()); // dtor will be a no-op
}

TEST_CASE("async discarded temporary joins", "[async_pool]")
{
  std::atomic<bool> ran{false};
  iora::core::async(
    [&ran]()
    {
      std::this_thread::sleep_for(20ms);
      ran.store(true);
    }); // temporary PooledFuture destroyed here -> joins
  REQUIRE(ran.load());
}

//
// task-4.5: move-assignment joins the overwritten future (non-vacuous).
// A defaulted move-assign would abandon taskA without joining -> aRan stays false.
//
TEST_CASE("PooledFuture move-assignment joins the overwritten future", "[async_pool]")
{
  std::atomic<bool> aRan{false};
  auto f = iora::core::async(
    [&aRan]()
    {
      std::this_thread::sleep_for(50ms);
      aRan.store(true);
    });
  f = iora::core::async([]() {}); // move-assign must join taskA first
  REQUIRE(aRan.load());
  f.get();
}

//
// task-4.6: default-construct then assign (general drop-in pattern).
//
TEST_CASE("PooledFuture default-construct then assign", "[async_pool]")
{
  iora::core::PooledFuture<int> f;
  REQUIRE_FALSE(f.valid());
  f = iora::core::async([]() { return 11; });
  REQUIRE(f.get() == 11);
}

//
// task-4.7: move-only argument (proves move-invoke parity; would fail via std::bind).
//
TEST_CASE("async forwards a move-only argument", "[async_pool]")
{
  auto p = std::make_unique<int>(7);
  auto f = iora::core::async([](std::unique_ptr<int> up) { return *up; }, std::move(p));
  REQUIRE(f.get() == 7);
}

//
// task-4.8: exception propagation via the future, not at the call site.
//
TEST_CASE("async propagates the task exception through get()", "[async_pool]")
{
  auto f = iora::core::async([]() -> int { throw std::runtime_error("task boom"); });
  REQUIRE_THROWS_AS(f.get(), std::runtime_error);
}

//
// task-4.9: queue-full returns an exceptional future carrying AsyncRejectedError
// (NOT a synchronous throw), the rejected callable NEVER runs, and the reject
// type is distinguishable from a task-internal exception. Deterministic via the
// detail::submitTo seam against a tiny fixed-size pool (all-or-nothing, DP-15).
//
TEST_CASE("submitTo rejects with an exceptional future when the queue is full", "[async_pool]")
{
  iora::core::ThreadPool tiny(1, 1, std::chrono::seconds(30), 1);

  std::promise<void> started;
  auto startedF = started.get_future();
  std::promise<void> gate;
  std::shared_future<void> gateF = gate.get_future().share();

  // Occupy the single worker and wait until it is actually running.
  auto blocker = iora::core::detail::submitTo(tiny,
                                              [&]()
                                              {
                                                started.set_value();
                                                gateF.wait();
                                              });
  startedF.wait(); // worker busy, queue empty

  std::atomic<bool> queuedRan{false};
  auto queued = iora::core::detail::submitTo(tiny, [&]() { queuedRan.store(true); }); // fills 1 slot

  std::atomic<bool> rejectedRan{false};
  auto rejected =
    iora::core::detail::submitTo(tiny, [&]() { rejectedRan.store(true); }); // queue full -> reject

  bool gotRejected = false;
  try
  {
    rejected.get();
  }
  catch (const iora::core::AsyncRejectedError &)
  {
    gotRejected = true;
  }
  REQUIRE(gotRejected);
  REQUIRE_FALSE(rejectedRan.load()); // rejected callable never ran

  gate.set_value();
  blocker.get();
  queued.get();
  REQUIRE(queuedRan.load());
}

TEST_CASE("a task-internal exception is not an AsyncRejectedError", "[async_pool]")
{
  auto f = iora::core::async([]() -> int { throw std::logic_error("boom"); });
  bool gotRejected = false;
  bool gotLogic = false;
  try
  {
    f.get();
  }
  catch (const iora::core::AsyncRejectedError &)
  {
    gotRejected = true;
  }
  catch (const std::logic_error &)
  {
    gotLogic = true;
  }
  REQUIRE(gotLogic);
  REQUIRE_FALSE(gotRejected);
}

//
// task-4.10: launch-policy overload. Always-run for launch::async; deferred is
// only exercised in a release build (in debug, the assert fires by design).
//
TEST_CASE("async launch-policy overload runs like the no-policy overload", "[async_pool]")
{
  auto f = iora::core::async(std::launch::async, []() { return 7; });
  REQUIRE(f.get() == 7);
#ifdef NDEBUG
  // Release contract (DP-4): deferred is accepted but treated as async (still runs).
  auto d = iora::core::async(std::launch::deferred, []() { return 9; });
  REQUIRE(d.get() == 9);
#endif
}

//
// task-4.11: wait_for / wait_until / valid forwarding.
//
TEST_CASE("PooledFuture forwards wait_for/wait_until/valid", "[async_pool]")
{
  auto f = iora::core::async(
    []()
    {
      std::this_thread::sleep_for(50ms);
      return 5;
    });
  REQUIRE(f.valid());
  REQUIRE(f.wait_for(1ms) == std::future_status::timeout);
  REQUIRE(f.wait_until(std::chrono::steady_clock::now() + 1ms) == std::future_status::timeout);
  f.wait();
  REQUIRE(f.wait_for(0ms) == std::future_status::ready);
  REQUIRE(f.get() == 5);
  REQUIRE_FALSE(f.valid());
}

//
// task-4.14: DP-8 bounded-wait guard. The DP-8 invariant (a pool worker must not
// get()/wait()/move-assign-over a PooledFuture for OTHER pool work) is documented
// and satisfied by the HTTP consumers (they run on application threads). Here we
// only assert that a bounded wait_for on a running task returns rather than hangs.
//
TEST_CASE("PooledFuture wait_for is bounded", "[async_pool]")
{
  auto f = iora::core::async(
    []()
    {
      std::this_thread::sleep_for(100ms);
      return 1;
    });
  REQUIRE(f.wait_for(1ms) == std::future_status::timeout);
  REQUIRE(f.get() == 1);
}
