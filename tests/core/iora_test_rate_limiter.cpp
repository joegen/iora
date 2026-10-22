// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for TokenBucket, SlidingWindowCounter, RateLimiterMap

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/core/rate_limiter.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

using namespace iora::core;
using namespace std::chrono_literals;

// ══════════════════════════════════════════════════════════════════════════════
// TokenBucket
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TokenBucket: basic consume", "[rate_limiter][bucket]")
{
  TokenBucket bucket(10.0, 10.0); // 10 tokens/sec, burst 10
  REQUIRE(bucket.tryConsume(1.0));
  REQUIRE(bucket.availableTokens() >= 8.0); // started at 10, consumed 1
}

TEST_CASE("TokenBucket: burst capacity", "[rate_limiter][bucket]")
{
  TokenBucket bucket(10.0, 5.0); // burst 5
  REQUIRE(bucket.tryConsume(5.0)); // consume full burst
  REQUIRE_FALSE(bucket.tryConsume(1.0)); // empty
}

TEST_CASE("TokenBucket: refill over time", "[rate_limiter][bucket]")
{
  TokenBucket bucket(100.0, 10.0); // 100 tokens/sec
  REQUIRE(bucket.tryConsume(10.0)); // drain
  REQUIRE_FALSE(bucket.tryConsume(1.0));

  std::this_thread::sleep_for(50ms); // should replenish ~5 tokens
  REQUIRE(bucket.tryConsume(1.0)); // should succeed now
}

TEST_CASE("TokenBucket: empty returns false", "[rate_limiter][bucket]")
{
  TokenBucket bucket(1.0, 1.0);
  REQUIRE(bucket.tryConsume(1.0));
  REQUIRE_FALSE(bucket.tryConsume(1.0));
}

TEST_CASE("TokenBucket: timeUntilAvailable", "[rate_limiter][bucket]")
{
  TokenBucket bucket(10.0, 10.0);
  bucket.tryConsume(10.0); // drain
  auto wait = bucket.timeUntilAvailable(1.0);
  REQUIRE(wait.count() > 0);
  REQUIRE(wait.count() <= 200); // 1 token at 10/sec = 100ms, with margin
}

TEST_CASE("TokenBucket: non-copyable", "[rate_limiter][bucket]")
{
  static_assert(!std::is_copy_constructible_v<TokenBucket>);
  static_assert(!std::is_copy_assignable_v<TokenBucket>);
  static_assert(std::is_move_constructible_v<TokenBucket>);
  REQUIRE(true);
}

// ══════════════════════════════════════════════════════════════════════════════
// SlidingWindowCounter
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("SlidingWindowCounter: basic acquire", "[rate_limiter][window]")
{
  SlidingWindowCounter counter(5, std::chrono::seconds(1));
  for (int i = 0; i < 5; ++i)
  {
    REQUIRE(counter.tryAcquire());
  }
  REQUIRE_FALSE(counter.tryAcquire()); // window full
}

TEST_CASE("SlidingWindowCounter: window expiry", "[rate_limiter][window]")
{
  SlidingWindowCounter counter(2, std::chrono::seconds(1));
  REQUIRE(counter.tryAcquire());
  REQUIRE(counter.tryAcquire());
  REQUIRE_FALSE(counter.tryAcquire()); // full

  std::this_thread::sleep_for(1100ms); // wait for window to expire
  REQUIRE(counter.tryAcquire()); // should succeed (expired timestamps evicted)
}

TEST_CASE("SlidingWindowCounter: remaining intermediate", "[rate_limiter][window]")
{
  SlidingWindowCounter counter(5, std::chrono::seconds(1));
  REQUIRE(counter.remaining() == 5);
  counter.tryAcquire();
  counter.tryAcquire();
  counter.tryAcquire();
  REQUIRE(counter.remaining() == 2);
}

TEST_CASE("SlidingWindowCounter: remaining at max", "[rate_limiter][window]")
{
  SlidingWindowCounter counter(3, std::chrono::seconds(1));
  counter.tryAcquire();
  counter.tryAcquire();
  counter.tryAcquire();
  REQUIRE(counter.remaining() == 0);
}

TEST_CASE("SlidingWindowCounter: timeUntilAvailable", "[rate_limiter][window]")
{
  SlidingWindowCounter counter(1, std::chrono::seconds(1));
  counter.tryAcquire(); // fill
  auto wait = counter.timeUntilAvailable();
  REQUIRE(wait.count() > 0);
  REQUIRE(wait.count() <= 1100); // within the 1-second window + margin
}

TEST_CASE("SlidingWindowCounter: timeUntilAvailable agrees after a partial rollover",
          "[rate_limiter][window]")
{
  SlidingWindowCounter c(2, std::chrono::seconds(2));
  REQUIRE(c.tryAcquire());
  std::this_thread::sleep_for(1500ms);
  REQUIRE(c.tryAcquire());
  std::this_thread::sleep_for(600ms);
  // The first entry is expired and the second is still active; a host stall
  // long enough to expire both fails here instead of passing vacuously.
  REQUIRE(c.remaining() == 1);
  REQUIRE(c.timeUntilAvailable() == 0ms);
  REQUIRE(c.tryAcquire());
  REQUIRE(c.timeUntilAvailable() > 0ms);
  REQUIRE_FALSE(c.tryAcquire());
}

TEST_CASE("SlidingWindowCounter: maxRequests 0 denies all and reports the window",
          "[rate_limiter][window]")
{
  SlidingWindowCounter c(0, std::chrono::seconds(3));
  REQUIRE_FALSE(c.tryAcquire());
  REQUIRE(c.remaining() == 0);
  REQUIRE(c.timeUntilAvailable() == 3000ms);
}

// ══════════════════════════════════════════════════════════════════════════════
// RateLimiterMap
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("RateLimiterMap: per-key limiting", "[rate_limiter][map]")
{
  RateLimiterMap<std::string> limiter(10.0, 5.0); // 10/sec, burst 5

  // Key A: drain
  for (int i = 0; i < 5; ++i)
  {
    REQUIRE(limiter.tryConsume("keyA"));
  }
  REQUIRE_FALSE(limiter.tryConsume("keyA"));

  // Key B: independent, still has tokens
  REQUIRE(limiter.tryConsume("keyB"));
}

TEST_CASE("RateLimiterMap: auto-creates bucket on first tryConsume", "[rate_limiter][map]")
{
  RateLimiterMap<std::string> limiter(100.0, 10.0);
  REQUIRE(limiter.size() == 0);
  REQUIRE(limiter.tryConsume("newKey"));
  REQUIRE(limiter.size() == 1);
}

TEST_CASE("RateLimiterMap: setKeyRate overrides default", "[rate_limiter][map]")
{
  RateLimiterMap<std::string> limiter(10.0, 10.0); // default burst 10

  limiter.setKeyRate("special", 10.0, 2.0); // burst 2 for this key

  REQUIRE(limiter.tryConsume("special"));
  REQUIRE(limiter.tryConsume("special"));
  REQUIRE_FALSE(limiter.tryConsume("special")); // burst 2 exhausted

  // Default key still has burst 10
  for (int i = 0; i < 10; ++i)
  {
    REQUIRE(limiter.tryConsume("default"));
  }
  REQUIRE_FALSE(limiter.tryConsume("default"));
}

TEST_CASE("RateLimiterMap: setDefaultRate does not affect existing", "[rate_limiter][map]")
{
  RateLimiterMap<std::string> limiter(10.0, 5.0); // burst 5

  limiter.tryConsume("existing"); // creates bucket with burst 5
  limiter.setDefaultRate(10.0, 100.0); // change default burst to 100

  // Existing bucket should still have burst 5 (4 remaining after first consume)
  for (int i = 0; i < 4; ++i)
  {
    REQUIRE(limiter.tryConsume("existing"));
  }
  REQUIRE_FALSE(limiter.tryConsume("existing")); // only 5 total, not 100
}

TEST_CASE("RateLimiterMap: removeKey", "[rate_limiter][map]")
{
  RateLimiterMap<std::string> limiter(10.0, 5.0);

  // Create and drain a bucket
  for (int i = 0; i < 5; ++i) limiter.tryConsume("keyX");
  REQUIRE_FALSE(limiter.tryConsume("keyX"));

  // Remove and re-create: should have fresh tokens
  limiter.removeKey("keyX");
  REQUIRE(limiter.tryConsume("keyX")); // new bucket, full burst
}

TEST_CASE("RateLimiterMap: cleanup evicts only keys idle longer than maxIdle",
          "[rate_limiter][map][cleanup]")
{
  RateLimiterMap<std::string> rl(10.0, 10.0);
  REQUIRE(rl.tryConsume("idle"));
  std::this_thread::sleep_for(1100ms);
  REQUIRE(rl.tryConsume("active"));
  rl.cleanup(std::chrono::seconds(1));
  REQUIRE(rl.size() == 1);
  REQUIRE_FALSE(rl.getKeyRate("idle").has_value());
  REQUIRE(rl.getKeyRate("active").has_value());
}

TEST_CASE("RateLimiterMap: cleanup with idle threshold", "[rate_limiter][map]")
{
  RateLimiterMap<std::string> limiter(10.0, 10.0);

  limiter.tryConsume("willStay");
  limiter.tryConsume("willGo");

  // Sleep to make "willGo" idle
  std::this_thread::sleep_for(200ms);
  limiter.tryConsume("willStay"); // refresh

  // Wait a bit more so willGo is definitely > 200ms idle
  std::this_thread::sleep_for(100ms);

  // Cleanup with 250ms threshold
  // willGo was last accessed ~300ms ago, willStay ~100ms ago
  // This is tricky with sub-second timing... use a generous threshold
  REQUIRE(limiter.size() == 2);
  // Can't reliably test sub-second idle eviction in CI, verify the API works
  limiter.cleanup(std::chrono::seconds(0));
  REQUIRE(limiter.size() == 0); // all evicted with 0s threshold
}

TEST_CASE("RateLimiterMap: concurrent stress", "[rate_limiter][map][stress]")
{
  RateLimiterMap<int> limiter(1000.0, 100.0); // high rate for stress test
  constexpr int numThreads = 8;
  constexpr int opsPerThread = 10000;
  std::atomic<int> consumed{0};

  std::vector<std::thread> threads;
  for (int t = 0; t < numThreads; ++t)
  {
    threads.emplace_back([&, t]()
    {
      for (int i = 0; i < opsPerThread; ++i)
      {
        int key = (t * opsPerThread + i) % 100; // 100 keys
        if (limiter.tryConsume(key))
        {
          consumed.fetch_add(1);
        }
      }
    });
  }

  for (auto& t : threads) t.join();

  REQUIRE(consumed.load() > 0);
  REQUIRE(limiter.size() <= 100); // at most 100 keys
}

TEST_CASE("RateLimiterMap: getKeyRate reflects setKeyRate and is nullopt for an absent key",
          "[rate_limiter][map]")
{
  RateLimiterMap<std::string> rl(5.0, 7.0);
  REQUIRE_FALSE(rl.getKeyRate("absent").has_value()); // no bucket created yet
  rl.setKeyRate("k", 3.0, 9.0);
  auto rb = rl.getKeyRate("k");
  REQUIRE(rb.has_value());
  REQUIRE(rb->first == 3.0);   // verbatim-assigned, exactly representable -> exact ==
  REQUIRE(rb->second == 9.0);
  REQUIRE_FALSE(rl.getKeyRate("still-absent").has_value());
}

TEST_CASE("RateLimiterMap: setDefaultRate publishes (rate,burst) as an atomic pair "
          "(no torn read on a racing bucket create)",
          "[rate_limiter][map][concurrency]")
{
  // A creator racing setDefaultRate must never bake a torn (newRate,oldBurst) or
  // (oldRate,newBurst) pair into a fresh bucket. Two DISTINCT pairs so ANY mix is
  // detectable. Regression guard for 2026-06-04-1 (torn-pair fix): pre-fix a creator
  // can read a mixed pair, post-fix (defaults published together under _defaultsMutex)
  // it never does. Values are assigned verbatim (no arithmetic) so exact == is valid.
  constexpr double R1 = 10.0, B1 = 20.0, R2 = 100.0, B2 = 200.0;
  std::atomic<int> mixed{0};

  for (int round = 0; round < 300; ++round) // repeat to widen the race window
  {
    RateLimiterMap<int> rl(R1, B1); // no auto-cleanup wheel; defaults for the rest
    std::atomic<bool> go{false};

    std::thread flipper(
      [&]()
      {
        while (!go.load()) { std::this_thread::yield(); }
        for (int i = 0; i < 400; ++i)
        {
          rl.setDefaultRate(R2, B2);
          rl.setDefaultRate(R1, B1);
        }
      });

    std::vector<std::thread> creators;
    for (int t = 0; t < 4; ++t)
    {
      creators.emplace_back(
        [&, t]()
        {
          while (!go.load()) { std::this_thread::yield(); }
          for (int i = 0; i < 200; ++i)
          {
            const int key = t * 100000 + i;
            rl.tryConsume(key); // slow path: creates a bucket from the current defaults
            auto rb = rl.getKeyRate(key);
            if (rb)
            {
              const bool p1 = rb->first == R1 && rb->second == B1;
              const bool p2 = rb->first == R2 && rb->second == B2;
              if (!p1 && !p2)
              {
                mixed.fetch_add(1);
              }
            }
          }
        });
    }

    go.store(true);
    flipper.join();
    for (auto& c : creators)
    {
      c.join();
    }
  }

  REQUIRE(mixed.load() == 0); // never a torn (mixed rate/burst) pair
}

// ══════════════════════════════════════════════════════════════════════════════
// Input validation
// ══════════════════════════════════════════════════════════════════════════════

constexpr double QUIET_NAN = std::numeric_limits<double>::quiet_NaN();
constexpr double POS_INF = std::numeric_limits<double>::infinity();

TEST_CASE("TokenBucket: ctor rejects a non-finite or non-positive rate",
          "[rate_limiter][validation]")
{
  for (double r : {0.0, -1.0, QUIET_NAN, POS_INF})
  {
    CAPTURE(r);
    REQUIRE_THROWS_AS(TokenBucket(r, 5.0), std::invalid_argument);
  }
}

TEST_CASE("TokenBucket: ctor rejects a non-finite or negative burst", "[rate_limiter][validation]")
{
  for (double b : {-1.0, QUIET_NAN, POS_INF})
  {
    CAPTURE(b);
    REQUIRE_THROWS_AS(TokenBucket(1.0, b), std::invalid_argument);
  }
}

TEST_CASE("TokenBucket: ctor accepts a tiny rate and a zero burst", "[rate_limiter][validation]")
{
  REQUIRE_NOTHROW(TokenBucket(1e-9, 0.0));
  REQUIRE_NOTHROW(TokenBucket(1.0, 0.0));
}

TEST_CASE("TokenBucket: negative tokens do not mint balance", "[rate_limiter][validation]")
{
  TokenBucket b(1e-3, 10.0);
  REQUIRE(b.tryConsume(10.0));
  REQUIRE_FALSE(b.tryConsume(-5.0));
  REQUIRE_FALSE(b.tryConsume(5.0));
}

TEST_CASE("TokenBucket: NaN and infinite tokens are denied", "[rate_limiter][validation]")
{
  TokenBucket b(10.0, 10.0);
  REQUIRE_FALSE(b.tryConsume(QUIET_NAN));
  REQUIRE_FALSE(b.tryConsume(POS_INF));
}

TEST_CASE("TokenBucket: timeUntilAvailable is max() for a never-satisfiable request",
          "[rate_limiter][validation]")
{
  TokenBucket b(10.0, 5.0);
  for (double t : {-1.0, QUIET_NAN, POS_INF, 8.0})
  {
    CAPTURE(t);
    REQUIRE(b.timeUntilAvailable(t) == std::chrono::milliseconds::max());
  }
}

TEST_CASE("TokenBucket: timeUntilAvailable stays finite at tokens == burst",
          "[rate_limiter][validation]")
{
  TokenBucket b(10.0, 5.0);
  REQUIRE(b.tryConsume(5.0));
  auto w = b.timeUntilAvailable(5.0);
  REQUIRE(w > 0ms);
  REQUIRE(w <= 1000ms);
}

TEST_CASE("TokenBucket: timeUntilAvailable saturates instead of overflowing",
          "[rate_limiter][validation]")
{
  TokenBucket b(1e-16, 10.0);
  REQUIRE(b.tryConsume(10.0));
  REQUIRE(b.timeUntilAvailable(10.0) == std::chrono::milliseconds::max());
}

TEST_CASE("RateLimiterMap: ctor rejects invalid defaults", "[rate_limiter][validation]")
{
  REQUIRE_THROWS_AS(RateLimiterMap<std::string>(0.0, 5.0), std::invalid_argument);
  REQUIRE_THROWS_AS(RateLimiterMap<std::string>(1.0, -1.0), std::invalid_argument);
  REQUIRE_THROWS_AS(RateLimiterMap<std::string>(QUIET_NAN, 5.0), std::invalid_argument);
  REQUIRE_THROWS_AS(RateLimiterMap<std::string>(1.0, POS_INF), std::invalid_argument);
}

TEST_CASE("RateLimiterMap: ctor validates before scheduling auto-cleanup",
          "[rate_limiter][validation]")
{
  TimingWheel wheel(10ms, 64, 1);
  wheel.start();
  REQUIRE_THROWS_AS(RateLimiterMap<std::string>(0.0, 5.0, &wheel), std::invalid_argument);
  REQUIRE(wheel.pendingCount() == 0);
  {
    RateLimiterMap<std::string> ok(1.0, 5.0, &wheel);
    REQUIRE(wheel.pendingCount() == 1);
    wheel.stop();
  }
}

TEST_CASE("RateLimiterMap: setDefaultRate validates both values before assigning",
          "[rate_limiter][validation]")
{
  RateLimiterMap<std::string> m(10.0, 5.0);
  m.setDefaultRate(20.0, 7.0);
  REQUIRE_THROWS_AS(m.setDefaultRate(30.0, -1.0), std::invalid_argument);
  REQUIRE_THROWS_AS(m.setDefaultRate(QUIET_NAN, 9.0), std::invalid_argument);
  REQUIRE(m.tryConsume("new"));
  REQUIRE(m.getKeyRate("new") == std::make_pair(20.0, 7.0));
}

TEST_CASE("RateLimiterMap: setKeyRate rejects invalid values and changes nothing",
          "[rate_limiter][validation]")
{
  RateLimiterMap<std::string> m(10.0, 5.0);
  REQUIRE_THROWS_AS(m.setKeyRate("absent", QUIET_NAN, 5.0), std::invalid_argument);
  REQUIRE_FALSE(m.getKeyRate("absent").has_value());
  m.setKeyRate("k", 2.0, 3.0);
  REQUIRE_THROWS_AS(m.setKeyRate("k", 0.0, 3.0), std::invalid_argument);
  REQUIRE(m.getKeyRate("k") == std::make_pair(2.0, 3.0));
}

TEST_CASE("RateLimiterMap: negative tokens do not mint balance", "[rate_limiter][validation]")
{
  RateLimiterMap<std::string> m(1e-3, 5.0);
  REQUIRE(m.tryConsume("k", 5.0));
  REQUIRE_FALSE(m.tryConsume("k", -5.0));
  REQUIRE_FALSE(m.tryConsume("k", 1.0));
}

// ══════════════════════════════════════════════════════════════════════════════
// cleanup: work between pass 1 and pass 2
// ══════════════════════════════════════════════════════════════════════════════

// One-shot hook run from the key hash. ConcurrentHashMap::shardFor hashes
// before it takes the shard lock, and cleanup's pass 1 (forEach) never hashes,
// so the first hash after arming is pass 2's call for its first key, with no
// lock held. The hook is disarmed before it runs, so its own map calls do not
// re-trigger it. If shardFor ever hashes under the lock, the re-entry
// self-deadlocks and ctest --timeout reports the failure.
struct HookHash
{
  static std::function<void()>& slot()
  {
    static std::function<void()> hook;
    return hook;
  }

  std::size_t operator()(int k) const
  {
    if (slot())
    {
      auto hook = std::exchange(slot(), nullptr);
      hook();
    }
    return std::hash<int>{}(k);
  }
};

TEST_CASE("RateLimiterMap: cleanup keeps a key refreshed between the passes",
          "[rate_limiter][map][cleanup]")
{
  HookHash::slot() = nullptr;
  RateLimiterMap<int, HookHash> rl(1e-3, 3.0);
  REQUIRE(rl.tryConsume(1));
  REQUIRE(rl.tryConsume(1));
  REQUIRE(rl.tryConsume(2));
  std::this_thread::sleep_for(5ms);

  bool fired = false;
  bool touched = false;
  HookHash::slot() = [&]
  {
    fired = true;
    touched = rl.tryConsume(1);
  };
  rl.cleanup(std::chrono::seconds(0));

  REQUIRE(fired);
  REQUIRE(touched);
  REQUIRE(rl.size() == 1);
  REQUIRE_FALSE(rl.getKeyRate(2).has_value());
  REQUIRE(rl.getKeyRate(1).has_value());
  REQUIRE_FALSE(rl.tryConsume(1));
}

TEST_CASE("RateLimiterMap: cleanup keeps a setKeyRate override installed between the passes",
          "[rate_limiter][map][cleanup]")
{
  HookHash::slot() = nullptr;
  RateLimiterMap<int, HookHash> rl(1e-3, 3.0);
  REQUIRE(rl.tryConsume(1));
  std::this_thread::sleep_for(5ms);

  bool fired = false;
  HookHash::slot() = [&]
  {
    fired = true;
    rl.setKeyRate(1, 4.0, 8.0);
  };
  rl.cleanup(std::chrono::seconds(0));

  REQUIRE(fired);
  REQUIRE(rl.getKeyRate(1) == std::make_pair(4.0, 8.0));
}

// ══════════════════════════════════════════════════════════════════════════════
// Auto-cleanup lifetime
// ══════════════════════════════════════════════════════════════════════════════

// Dispatcher that only queues fired callbacks, so a test decides when and on
// which thread each one runs. A popped callback is run after the queue mutex is
// released.
struct CallbackQueue
{
  std::mutex mutex;
  std::condition_variable cv;
  std::deque<TimingWheel::Callback> items;

  TimingWheel::Dispatcher dispatcher()
  {
    return [this](TimingWheel::Callback cb)
    {
      {
        std::lock_guard<std::mutex> lock(mutex);
        items.push_back(std::move(cb));
      }
      cv.notify_all();
    };
  }

  bool waitForSize(std::size_t n)
  {
    std::unique_lock<std::mutex> lock(mutex);
    return cv.wait_for(lock, 5s, [&] { return items.size() >= n; });
  }

  TimingWheel::Callback pop()
  {
    std::lock_guard<std::mutex> lock(mutex);
    auto cb = std::move(items.front());
    items.pop_front();
    return cb;
  }
};

// One-way open/closed handshake between test threads.
struct Gate
{
  std::mutex mutex;
  std::condition_variable cv;
  bool isOpen = false;

  void open()
  {
    {
      std::lock_guard<std::mutex> lock(mutex);
      isOpen = true;
    }
    cv.notify_all();
  }

  void wait()
  {
    std::unique_lock<std::mutex> lock(mutex);
    cv.wait(lock, [&] { return isOpen; });
  }

  bool waitFor()
  {
    std::unique_lock<std::mutex> lock(mutex);
    return cv.wait_for(lock, 5s, [&] { return isOpen; });
  }
};

// Opens the release gate and joins the helper threads on every exit path, so a
// failed REQUIRE never unwinds past a joinable thread or a blocked hook.
struct ThreadGuard
{
  Gate& release;
  std::thread& first;
  std::thread& second;

  ~ThreadGuard()
  {
    release.open();
    if (first.joinable())
    {
      first.join();
    }
    if (second.joinable())
    {
      second.join();
    }
  }
};

// A started wheel whose fired callbacks go to a CallbackQueue. The queue is
// declared first so it outlives the wheel's tick thread.
struct QueuedWheel
{
  CallbackQueue queue;
  TimingWheel wheel{20ms, 64, 1, queue.dispatcher()};

  QueuedWheel()
  {
    wheel.start();
  }

  void runNextFire()
  {
    REQUIRE(queue.waitForSize(1));
    queue.pop()();
  }
};

// Blocks a cleanup pass inside pass 2's first hash on thread `pass`, then
// destroys the map on thread `destroyer` while the pass is still blocked. The
// guard is declared last, so it releases and joins both threads before any
// other member is destroyed.
struct InFlightPassFixture
{
  QueuedWheel qw;
  std::unique_ptr<RateLimiterMap<int, HookHash>> map;
  TimingWheel::Callback fire;
  Gate entered;
  Gate release;
  Gate resetDone;
  std::thread pass;
  std::thread destroyer;
  ThreadGuard guard{release, pass, destroyer};

  void blockPassAndDestroyMap()
  {
    map = std::make_unique<RateLimiterMap<int, HookHash>>(
      1.0, 3.0, &qw.wheel, std::chrono::seconds(1), std::chrono::seconds(0));
    REQUIRE(map->tryConsume(1));
    std::this_thread::sleep_for(5ms);
    REQUIRE(qw.queue.waitForSize(1));
    fire = qw.queue.pop();

    HookHash::slot() = [this]
    {
      entered.open();
      release.wait();
    };
    pass = std::thread([this] { fire(); });
    REQUIRE(entered.waitFor());
    destroyer = std::thread(
      [this]
      {
        map.reset();
        resetDone.open();
      });
    // The destructor must return while the pass is still blocked in the hook.
    REQUIRE(resetDone.waitFor());
  }
};

TEST_CASE("RateLimiterMap: map destroyed while its cleanup entry is pending",
          "[rate_limiter][map][lifetime]")
{
  QueuedWheel qw;
  auto map = std::make_unique<RateLimiterMap<std::string>>(
    10.0, 10.0, &qw.wheel, std::chrono::seconds(1), std::chrono::seconds(0));
  map.reset();
  qw.runNextFire();
  REQUIRE(qw.wheel.pendingCount() == 0);
}

TEST_CASE("RateLimiterMap: map destroyed after its cleanup callback was collected",
          "[rate_limiter][map][lifetime]")
{
  QueuedWheel qw;
  auto map = std::make_unique<RateLimiterMap<std::string>>(
    10.0, 10.0, &qw.wheel, std::chrono::seconds(1), std::chrono::seconds(0));
  REQUIRE(qw.queue.waitForSize(1));
  map.reset();
  qw.queue.pop()();
  REQUIRE(qw.wheel.pendingCount() == 0);
}

TEST_CASE("RateLimiterMap: map destroyed during an in-flight cleanup pass",
          "[rate_limiter][map][lifetime]")
{
  HookHash::slot() = nullptr;
  InFlightPassFixture f;
  f.blockPassAndDestroyMap();

  f.release.open();
  f.pass.join();
  f.destroyer.join();
  f.qw.runNextFire();
  REQUIRE(f.qw.wheel.pendingCount() == 0);
}

TEST_CASE("RateLimiterMap: stopping ends the chain for a fire that overlaps a running pass",
          "[rate_limiter][map][lifetime]")
{
  HookHash::slot() = nullptr;
  InFlightPassFixture f;
  f.blockPassAndDestroyMap();

  // The blocked pass still holds the state, so only the stopping flag can stop
  // the next fire from re-arming.
  f.qw.runNextFire();
  REQUIRE(f.qw.wheel.pendingCount() == 0);
}

TEST_CASE("RateLimiterMap: wheel destroyed before the map", "[rate_limiter][map][lifetime]")
{
  auto wheel = std::make_unique<TimingWheel>(20ms, 64, 1);
  wheel->start();
  auto map = std::make_unique<RateLimiterMap<std::string>>(
    10.0, 10.0, wheel.get(), std::chrono::seconds(1), std::chrono::seconds(0));
  wheel->stop();
  wheel.reset();
  map.reset();
}

TEST_CASE("RateLimiterMap: re-emplacing a map at the same address leaves one cleanup chain",
          "[rate_limiter][map][lifetime]")
{
  QueuedWheel qw;
  std::optional<RateLimiterMap<std::string>> limiter;
  limiter.emplace(10.0, 10.0, &qw.wheel, std::chrono::seconds(1), std::chrono::seconds(0));
  limiter.emplace(10.0, 10.0, &qw.wheel, std::chrono::seconds(1), std::chrono::seconds(0));
  REQUIRE(qw.queue.waitForSize(2));
  qw.queue.pop()();
  qw.queue.pop()();
  REQUIRE(qw.wheel.pendingCount() == 1);
}

TEST_CASE("RateLimiterMap: auto-cleanup runs one pass per fire", "[rate_limiter][map][lifetime]")
{
  QueuedWheel qw;
  RateLimiterMap<std::string> rl(10.0, 10.0, &qw.wheel, std::chrono::seconds(1),
                                 std::chrono::seconds(0));

  REQUIRE(rl.tryConsume("a"));
  std::this_thread::sleep_for(5ms);
  qw.runNextFire();
  REQUIRE(rl.size() == 0);
  REQUIRE(qw.wheel.pendingCount() == 1);

  REQUIRE(rl.tryConsume("b"));
  std::this_thread::sleep_for(5ms);
  qw.runNextFire();
  REQUIRE(rl.size() == 0);
  REQUIRE(qw.wheel.pendingCount() == 1);
}

TEST_CASE("RateLimiterMap: ctor throws when the cleanup wheel is not running",
          "[rate_limiter][map][lifetime]")
{
  TimingWheel wheel(20ms, 64, 1);
  REQUIRE_THROWS_AS(RateLimiterMap<std::string>(1.0, 5.0, &wheel), std::runtime_error);
  REQUIRE(wheel.pendingCount() == 0);

  wheel.start();
  wheel.stop();
  REQUIRE_THROWS_AS(RateLimiterMap<std::string>(1.0, 5.0, &wheel), std::runtime_error);
  REQUIRE(wheel.pendingCount() == 0);

  REQUIRE_NOTHROW(RateLimiterMap<std::string>(1.0, 5.0));
}

static_assert(!std::is_copy_constructible_v<RateLimiterMap<std::string>>);
static_assert(!std::is_move_constructible_v<RateLimiterMap<std::string>>);
static_assert(!std::is_copy_assignable_v<RateLimiterMap<std::string>>);
static_assert(!std::is_move_assignable_v<RateLimiterMap<std::string>>);
