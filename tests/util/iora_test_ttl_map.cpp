// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <atomic>
#include <catch2/catch.hpp>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <iora/core/timer.hpp>
#include <iora/util/ttl_map.hpp>

using namespace std::chrono_literals;

// Detect a ThreadSanitizer build. Under TSan the soak runs 100+ threads on a
// (typically 2-core) box with ~10x instrumentation slowdown, so the wall-clock
// progress/stall assertions must use generous HANG/STARVATION-detector bounds
// (a deadlock or full-scan-under-lock is unbounded; scheduling jitter is not).
// Normal (non-sanitized) builds keep tight SLA bounds.
#if defined(__SANITIZE_THREAD__)
#define IORA_TTLMAP_UNDER_TSAN 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define IORA_TTLMAP_UNDER_TSAN 1
#endif
#endif
#ifndef IORA_TTLMAP_UNDER_TSAN
#define IORA_TTLMAP_UNDER_TSAN 0
#endif

namespace
{
// Worst-case single get() latency we tolerate (a hang detector, not an SLA).
constexpr std::int64_t kMaxGetLatencyUs = IORA_TTLMAP_UNDER_TSAN ? 30'000'000
                                                                 : 2'000'000;
// Wall-clock budget for the dedicated writer's puts (a starvation detector).
constexpr std::int64_t kWriterBudgetMs = IORA_TTLMAP_UNDER_TSAN ? 300000 : 120000;
// Poll iterations (x100ms) to wait for the first real sweep to fire+reap. Scaled
// generously under a sanitizer so instrumentation slowdown is not a false miss.
constexpr int kSweepWaitIters = IORA_TTLMAP_UNDER_TSAN ? 300 : 40;
/// \brief Test fixture owning a TimerService for injection into a TtlMap.
///
/// LIFETIME: the production teardown contract requires the TimerService to be
/// drained/stopped BEFORE the TtlMap is destroyed. The fixture does NOT rely on
/// member declaration order — it exposes stopTimers() and its destructor stops
/// the service defensively. Tests that want the production ordering construct
/// their TtlMap on the heap (unique_ptr) and reset() it before stopTimers().
struct TimerFixture
{
  iora::core::TimerService timers;

  TimerFixture() = default;

  void stopTimers() { timers.stop(); }

  ~TimerFixture() { timers.stop(); }
};

using StrIntCache = iora::util::TtlMap<std::string, int>;
using IntCache = iora::util::TtlMap<int, std::int64_t>;

StrIntCache::Config strCfg(std::chrono::seconds ttl, std::size_t maxEntries,
                           std::chrono::seconds sweep)
{
  StrIntCache::Config c{};
  c.defaultTtl = ttl;
  c.maxEntries = maxEntries;
  c.sweepInterval = sweep;
  return c;
}
} // namespace

// ───────────────────────────────────────────────────────────────────────────
// 2.1 put/get basics + ttl-override-vs-defaultTtl + re-put of an existing key
// ───────────────────────────────────────────────────────────────────────────
TEST_CASE("TtlMap put/get basics, ttl override, in-place re-put")
{
  TimerFixture fx;
  auto cache = std::make_unique<StrIntCache>(strCfg(60s, 16, 60s), fx.timers);

  SECTION("round-trip and miss")
  {
    cache->put("a", 1);
    REQUIRE(cache->get("a").value() == 1);
    REQUIRE_FALSE(cache->get("absent").has_value());
  }

  SECTION("explicit ttl overrides defaultTtl")
  {
    // Long defaultTtl, but an explicit short ttl on "short" must win.
    cache->put("short", 7, std::chrono::seconds(1));
    cache->put("long", 8); // uses 60s defaultTtl
    REQUIRE(cache->get("short").value() == 7);
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    REQUIRE_FALSE(cache->get("short").has_value()); // expired by override
    REQUIRE(cache->get("long").value() == 8);       // still live
  }

  SECTION("re-put of an existing key updates value in place, no size growth")
  {
    cache->put("x", 1);
    cache->put("x", 2);
    cache->put("x", 3);
    REQUIRE(cache->get("x").value() == 3);
    REQUIRE(cache->stats().size == 1); // refreshed in place, not duplicated
  }

  cache.reset();
  fx.stopTimers();
}

// ───────────────────────────────────────────────────────────────────────────
// 2.2 LRU eviction order + boundary + maxEntries==0/1 + termination + 2nd-chance
// ───────────────────────────────────────────────────────────────────────────
TEST_CASE("TtlMap LRU eviction order and maxEntries boundary")
{
  TimerFixture fx;
  // Long TTL + long sweep window so nothing expires and every entry counts as
  // "recent" for this test (eviction is driven purely by capacity + LRU order).
  auto cache = std::make_unique<StrIntCache>(strCfg(600s, 3, 600s), fx.timers);

  // Insert k0,k1,k2 (front=k2, tail=k0). A 4th insert exceeds maxEntries=3.
  cache->put("k0", 0);
  cache->put("k1", 1);
  cache->put("k2", 2);
  REQUIRE(cache->stats().size == 3);

  cache->put("k3", 3); // evicts the LRU tail k0
  REQUIRE(cache->stats().size == 3);
  REQUIRE(cache->stats().evictions == 1);
  REQUIRE_FALSE(cache->get("k0").has_value()); // LRU victim gone
  REQUIRE(cache->get("k3").value() == 3);      // MRU survives

  cache.reset();
  fx.stopTimers();
}

TEST_CASE("TtlMap maxEntries==0 disables the cache")
{
  TimerFixture fx;
  auto cache = std::make_unique<StrIntCache>(strCfg(60s, 0, 60s), fx.timers);
  cache->put("a", 1);
  REQUIRE(cache->stats().size == 0);
  REQUIRE_FALSE(cache->get("a").has_value()); // never stored
  cache.reset();
  fx.stopTimers();
}

TEST_CASE("TtlMap maxEntries==1 evicts the prior entry")
{
  TimerFixture fx;
  auto cache = std::make_unique<StrIntCache>(strCfg(60s, 1, 60s), fx.timers);
  cache->put("a", 1);
  cache->put("b", 2); // distinct new key evicts the prior
  REQUIRE(cache->stats().size == 1);
  REQUIRE_FALSE(cache->get("a").has_value());
  REQUIRE(cache->get("b").value() == 2);
  cache.reset();
  fx.stopTimers();
}

TEST_CASE("TtlMap eviction terminates when all candidates are recent")
{
  TimerFixture fx;
  // sweepInterval (recency window) huge so every just-touched entry is recent.
  auto cache = std::make_unique<StrIntCache>(strCfg(600s, 4, 600s), fx.timers);
  cache->put("k0", 0);
  cache->put("k1", 1);
  cache->put("k2", 2);
  cache->put("k3", 3);
  // Touch every entry so all are "recent" — the second-chance scan can find no
  // non-recent victim within the hop budget and must evict the strict tail.
  REQUIRE(cache->get("k0").has_value());
  REQUIRE(cache->get("k1").has_value());
  REQUIRE(cache->get("k2").has_value());
  REQUIRE(cache->get("k3").has_value());

  cache->put("k4", 4); // size would be 5 > 4 -> must evict exactly one
  REQUIRE(cache->stats().size == 4);          // never left above maxEntries
  REQUIRE(cache->stats().evictions == 1);
  REQUIRE_FALSE(cache->get("k0").has_value()); // strict LRU tail evicted
  REQUIRE(cache->get("k4").value() == 4);

  cache.reset();
  fx.stopTimers();
}

TEST_CASE("TtlMap re-put splices the entry to the LRU front")
{
  TimerFixture fx;
  // Long recency window so EVERY entry is "recent" — eviction then falls to the
  // strict LRU tail, isolating the splice behavior from the second-chance hop.
  // Without the put()-on-existing-key lru.splice, the re-put key would remain
  // at the tail and be the victim; with it, it moves to the front and survives.
  auto cache = std::make_unique<StrIntCache>(strCfg(600s, 3, 600s), fx.timers);
  cache->put("k0", 0); // LRU tail
  cache->put("k1", 1);
  cache->put("k2", 2); // MRU front; order tail->front: k0, k1, k2

  cache->put("k0", 100); // re-put the tail: in-place refresh + splice to front
                         // order tail->front now: k1, k2, k0
  REQUIRE(cache->stats().size == 3);

  cache->put("k3", 3); // size 4 > 3 -> evict strict tail (all recent) == k1
  REQUIRE(cache->get("k0").value() == 100);    // re-put key survived (spliced)
  REQUIRE_FALSE(cache->get("k1").has_value()); // new tail after splice evicted
  REQUIRE(cache->get("k2").has_value());
  REQUIRE(cache->get("k3").value() == 3);

  cache.reset();
  fx.stopTimers();
}

TEST_CASE("TtlMap second-chance spares a just-touched LRU-tail entry")
{
  TimerFixture fx;
  // Short recency window (sweepInterval) so entries become "not recent" after a
  // sleep; long TTL so nothing actually expires.
  auto cache = std::make_unique<StrIntCache>(
      strCfg(600s, 4, std::chrono::seconds(1)), fx.timers);
  cache->put("k0", 0); // becomes the LRU tail
  cache->put("k1", 1);
  cache->put("k2", 2);
  cache->put("k3", 3);

  // Let every entry age past the recency window so they are all "not recent".
  std::this_thread::sleep_for(std::chrono::milliseconds(1300));

  // Touch the LRU tail k0 via get() (updates its recency stamp; get() does NOT
  // splice, so k0 stays at the tail position).
  REQUIRE(cache->get("k0").has_value());

  cache->put("k4", 4); // eviction scans from tail
  // k0 was just touched (recent) -> spared; the first non-recent entry (k1,
  // next from the tail) is the victim instead.
  REQUIRE(cache->get("k0").has_value());       // just-touched tail spared
  REQUIRE_FALSE(cache->get("k1").has_value()); // less-recent neighbor evicted
  REQUIRE(cache->get("k4").value() == 4);
  REQUIRE(cache->stats().size == 4);

  cache.reset();
  fx.stopTimers();
}

// ───────────────────────────────────────────────────────────────────────────
// 2.3 lazy expiry on get() = miss + deferred reap
// ───────────────────────────────────────────────────────────────────────────
TEST_CASE("TtlMap lazy expiry returns miss with deferred physical reap")
{
  TimerFixture fx;
  // Long sweepInterval so the sweeper does NOT reap during the test — only an
  // exclusive op should physically remove the expired node.
  auto cache = std::make_unique<StrIntCache>(strCfg(60s, 16, 600s), fx.timers);

  cache->put("e", 1, std::chrono::seconds(1));
  REQUIRE(cache->stats().size == 1);
  std::this_thread::sleep_for(std::chrono::milliseconds(1200));

  // Expired get() -> miss, but node NOT yet physically removed (deferred reap).
  REQUIRE_FALSE(cache->get("e").has_value());
  REQUIRE(cache->stats().misses >= 1);
  REQUIRE(cache->stats().size == 1); // still present (no erase under shared lock)

  // An exclusive op on a DIFFERENT key does not touch "e"; size stays 1 until
  // "e" itself is overwritten/invalidated or the sweeper runs.
  cache->invalidate("e"); // exclusive op physically reaps it
  REQUIRE(cache->stats().size == 0);

  cache.reset();
  fx.stopTimers();
}

TEST_CASE("TtlMap concurrent get() on the same expired-but-present key is race-free")
{
  TimerFixture fx;
  // Long sweepInterval so expired entries are NOT physically reaped by the
  // sweeper — they remain present, forcing many threads onto the lazy-expiry
  // read path (hpp get(): expired -> miss + deferred reap) on the SAME node
  // concurrently. This deterministically contends the expired-read path that
  // the soak only hits incidentally; under ASan/TSan it proves race-freedom.
  auto cache = std::make_unique<StrIntCache>(strCfg(60s, 256, 3600s), fx.timers);
  for (int i = 0; i < 16; ++i)
  {
    cache->put("hot" + std::to_string(i), i, std::chrono::seconds(1));
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(1200)); // all expired
  REQUIRE(cache->stats().size == 16); // present-but-expired (no sweep, no reap)

  std::atomic<bool> badValue{false}; // any expired get() returned a value
  std::atomic<bool> startGate{false};
  std::vector<std::thread> threads;
  for (int t = 0; t < 16; ++t)
  {
    threads.emplace_back(
        [&]()
        {
          while (!startGate.load(std::memory_order_acquire))
          {
          }
          for (int i = 0; i < 50000; ++i)
          {
            // All threads hammer the same expired keys simultaneously.
            if (cache->get("hot" + std::to_string(i & 0xf)).has_value())
            {
              badValue.store(true, std::memory_order_relaxed);
            }
          }
        });
  }
  startGate.store(true, std::memory_order_release);
  for (auto &th : threads)
  {
    th.join();
  }
  REQUIRE_FALSE(badValue.load()); // expired entries always miss; no torn read
  // The nodes are still present (deferred reap, sweepInterval=3600s).
  REQUIRE(cache->stats().size == 16);

  cache.reset();
  fx.stopTimers();
}

// ───────────────────────────────────────────────────────────────────────────
// 2.4 invalidate() removes; clear() empties + cumulative counters monotonic
// ───────────────────────────────────────────────────────────────────────────
TEST_CASE("TtlMap invalidate and clear")
{
  TimerFixture fx;
  auto cache = std::make_unique<StrIntCache>(strCfg(60s, 16, 600s), fx.timers);

  SECTION("invalidate present and absent keys")
  {
    cache->put("a", 1);
    cache->invalidate("a");
    REQUIRE_FALSE(cache->get("a").has_value());
    REQUIRE(cache->stats().size == 0);
    cache->invalidate("absent"); // no-op, no crash, no underflow
    REQUIRE(cache->stats().size == 0);
  }

  SECTION("clear empties and leaves cumulative counters monotonic")
  {
    cache->put("a", 1);
    cache->put("b", 2);
    REQUIRE(cache->get("a").has_value());        // 1 hit
    REQUIRE_FALSE(cache->get("z").has_value());  // 1 miss
    auto before = cache->stats();
    REQUIRE(before.hits >= 1);
    REQUIRE(before.misses >= 1);

    cache->clear();
    auto after = cache->stats();
    REQUIRE(after.size == 0);
    REQUIRE(after.hits == before.hits);     // cumulative counters NOT reset
    REQUIRE(after.misses == before.misses); // (monotonic across clear)
  }

  cache.reset();
  fx.stopTimers();
}

// ───────────────────────────────────────────────────────────────────────────
// 2.5 chunked sweeper correctness on the injected TimerService
// ───────────────────────────────────────────────────────────────────────────
TEST_CASE("TtlMap periodic sweeper reaps expired entries on the TimerService")
{
  TimerFixture fx;
  // Short sweepInterval + short TTL: entries expire and the sweeper reaps them
  // WITHOUT any get() touching them (proves the sweeper runs on the injected
  // service, not a self-owned thread, and that no public sweep() is needed).
  // sweepInterval is std::chrono::seconds, so 1s is the smallest usable value.
  auto cache =
      std::make_unique<StrIntCache>(strCfg(1s, 4096, 1s), fx.timers);

  for (int i = 0; i < 200; ++i)
  {
    cache->put("k" + std::to_string(i), i);
  }
  REQUIRE(cache->stats().size == 200);

  // Wait long enough for entries to expire (1s) AND a sweep tick (1s) to fire.
  std::this_thread::sleep_for(std::chrono::milliseconds(2600));
  REQUIRE(cache->stats().size == 0); // reaped by the sweeper, no get() needed

  cache.reset();
  fx.stopTimers();
}

// ───────────────────────────────────────────────────────────────────────────
// 2.6 stats counter assertions over a known sequence
// ───────────────────────────────────────────────────────────────────────────
TEST_CASE("TtlMap stats counters over a deterministic sequence")
{
  TimerFixture fx;
  auto cache = std::make_unique<StrIntCache>(strCfg(600s, 2, 600s), fx.timers);

  cache->put("a", 1);
  cache->put("b", 2);
  REQUIRE(cache->get("a").value() == 1); // hit
  REQUIRE(cache->get("b").value() == 2); // hit
  REQUIRE_FALSE(cache->get("c").has_value()); // miss
  cache->put("d", 4); // exceeds maxEntries=2 -> 1 eviction

  auto st = cache->stats();
  REQUIRE(st.hits == 2);
  REQUIRE(st.misses == 1);
  REQUIRE(st.evictions == 1);
  REQUIRE(st.size == 2);

  cache.reset();
  fx.stopTimers();
}

// ───────────────────────────────────────────────────────────────────────────
// 2.7 teardown / sweeper-lifetime (no UAF) — run under ASan + TSan (task 1.7)
// ───────────────────────────────────────────────────────────────────────────
TEST_CASE("TtlMap production teardown: no sweep fires after the drain barrier")
{
  TimerFixture fx;
  // SWEEP COUNTER: the sweeper is the only timer on this service, so
  // TimerService::getStats().timersExecuted counts sweep-handler invocations
  // directly (the arch testStrategy's "sweep counter", not a size proxy).
  // Short sweepInterval so a real sweep DOES fire and reap first (proving the
  // sweeper works), then we assert NO further sweep fires after the drain.
  auto cache = std::make_unique<StrIntCache>(strCfg(1s, 4096, 1s), fx.timers);
  for (int i = 0; i < 100; ++i)
  {
    cache->put("k" + std::to_string(i), i, std::chrono::seconds(1));
  }

  // Wait until at least one sweep has fired AND reaped the expired entries.
  for (int i = 0;
       i < kSweepWaitIters && (fx.timers.getStats().timersExecuted.load() == 0 ||
                               cache->stats().size != 0);
       ++i)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  REQUIRE(fx.timers.getStats().timersExecuted.load() >= 1); // sweeper really ran
  REQUIRE(cache->stats().size == 0);                        // and reaped

  // PRODUCTION ORDER: drain/stop the TimerService (the drain barrier).
  fx.stopTimers();
  const auto sweepsAtDrain = fx.timers.getStats().timersExecuted.load();

  // Re-populate with expired-but-unreaped entries AFTER the barrier (put() does
  // not need the timer). A post-drain sweep — if one wrongly fired — would reap
  // these and advance the sweep counter. Neither must happen.
  for (int i = 0; i < 100; ++i)
  {
    cache->put("p" + std::to_string(i), i, std::chrono::seconds(1));
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(2200)); // > TTL + interval
  REQUIRE(fx.timers.getStats().timersExecuted.load() == sweepsAtDrain); // no sweep
  REQUIRE(cache->stats().size == 100); // entries NOT reaped post-drain

  cache.reset(); // destroy after the service is stopped — clean, no UAF
}

TEST_CASE("TtlMap map-destroyed-while-service-live is safe under load")
{
  // The TtlMap is destroyed WHILE the TimerService is live and load + sweeps
  // are active. Worker threads hold their OWN std::shared_ptr<TtlMap> copies,
  // so when the main reference is dropped the LAST worker to exit runs ~TtlMap
  // ON A WORKER THREAD, concurrently with the live service — exactly the
  // weak_ptr<State>-guarded window. The service is NOT stopped between
  // iterations, so the next 1s tick fires the (now-cancelled) sweep handler
  // whose weak_ptr has expired -> safe no-op, exercising the guard's null path.
  // The 1s minimum sweepInterval makes "destroy exactly mid-sweep" inherently
  // non-deterministic, so this is a statistical probe over many iterations
  // (clean under ASan/TSan == no UAF), complementing the analytical audit.
  TimerFixture fx;
  std::atomic<std::uint64_t> totalOps{0};

  // Each iteration runs just over one sweepInterval so a real sweep FIRES while
  // load is active, then the map is destroyed on a worker thread with the
  // service still live. (The 1s minimum interval is why iterations cannot be
  // shorter and still guarantee an active sweep.)
  constexpr int kIters = 4;
  for (int iter = 0; iter < kIters; ++iter)
  {
    auto cache = std::make_shared<StrIntCache>(strCfg(1s, 1024, 1s), fx.timers);
    for (int i = 0; i < 500; ++i) // prepopulate so the sweeper has real work
    {
      cache->put("k" + std::to_string(i), i, std::chrono::seconds(1));
    }

    std::atomic<bool> stop{false};
    std::vector<std::thread> load;
    for (int t = 0; t < 4; ++t)
    {
      // Capture a shared_ptr COPY by value -> each worker keeps the map alive
      // until it exits; destruction happens off the main thread, under load.
      load.emplace_back(
          [cache, &stop, &totalOps, t]()
          {
            int i = 0;
            while (!stop.load(std::memory_order_relaxed))
            {
              const std::string key = "k" + std::to_string((i++ ^ t) & 0x1ff);
              cache->put(key, i, std::chrono::seconds(1));
              (void)cache->get(key);
              totalOps.fetch_add(1, std::memory_order_relaxed);
            }
          });
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1100)); // >1 sweep tick
    stop.store(true, std::memory_order_relaxed);
    cache.reset(); // drop the MAIN ref while workers still hold theirs + run
    for (auto &th : load)
    {
      th.join(); // last worker to exit destroys the TtlMap (service still live)
    }
    // Service keeps ticking into the next iteration; a late cancelled-handler
    // tick will w.lock() an expired weak_ptr and no-op.
  }

  REQUIRE(totalOps.load() > 0);
  REQUIRE(fx.timers.getStats().timersExecuted.load() > 0); // sweeps did fire
  fx.stopTimers();
}

TEST_CASE("TtlMap teardown under an active sweep is prompt (no full-scan hold)")
{
  // Populate a large expired map so a sweep does multiple batches, run a short
  // sweepInterval so a sweep is firing, then time the drain+destroy. The
  // per-batch stopping re-check + chunked lock release keep teardown bounded;
  // a regression that held the exclusive lock across a full scan would stall
  // drain. NOTE: at unit scale a full scan is sub-millisecond and the 1s
  // minimum interval prevents deterministic mid-sweep interception, so the
  // bound is a generous hang/regression detector, not a tight SLA.
  TimerFixture fx;
  auto cache =
      std::make_unique<StrIntCache>(strCfg(1s, 200000, 1s), fx.timers);
  for (int i = 0; i < 5000; ++i) // ~10 sweep batches of 512
  {
    cache->put("k" + std::to_string(i), i, std::chrono::seconds(1));
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(1100)); // expired + tick

  const auto t0 = std::chrono::steady_clock::now();
  cache.reset();     // ~TtlMap: stopping=true, cancel(sweepId)
  fx.stopTimers();   // drain: must not be delayed by an in-flight full scan
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0)
                      .count();
  INFO("teardown duration (ms): " << ms);
  REQUIRE(ms < 10000); // bounded teardown (hang/regression detector)
}

TEST_CASE("TtlMap destroyed reentrantly from a TimerService callback is UAF-safe")
{
  // C-1 guard: a TtlMap may be destroyed from WITHIN a callback running on its
  // own TimerService thread. ~TtlMap calls timers.cancel() (non-blocking) then
  // _state.reset(); the sweep handler is static + State-only, so even this
  // reentrant teardown is memory-safe. Drive it: a one-shot timer on the SAME
  // service destroys the owning unique_ptr. Clean under ASan == no UAF/deadlock.
  TimerFixture fx;
  auto cache =
      std::make_shared<std::unique_ptr<StrIntCache>>(
          std::make_unique<StrIntCache>(strCfg(1s, 64, 1s), fx.timers));
  (*cache)->put("x", 1);

  std::atomic<bool> destroyed{false};
  fx.timers.scheduleAfter(std::chrono::milliseconds(50),
                          [cache, &destroyed]()
                          {
                            cache->reset(); // ~TtlMap on the timer thread
                            destroyed.store(true, std::memory_order_release);
                          });

  for (int i = 0; i < 50 && !destroyed.load(std::memory_order_acquire); ++i)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  REQUIRE(destroyed.load());
  fx.stopTimers();
}

TEST_CASE("TtlMap reader is not stalled multiple seconds during active sweeps")
{
  TimerFixture fx;
  // Populate a sizeable cache and run a short-interval sweeper; a reader's
  // worst-case wait is one chunk (<=512 erases), so no get() should ever block
  // for seconds. The bound is deliberately generous (detects a pathological
  // full-scan-under-lock stall or a hang, not a tight latency SLA).
  auto cache = std::make_unique<StrIntCache>(
      strCfg(std::chrono::seconds(1), 100000, std::chrono::seconds(1)),
      fx.timers);
  for (int i = 0; i < 20000; ++i)
  {
    cache->put("k" + std::to_string(i), i, std::chrono::seconds(1));
  }

  std::atomic<bool> stop{false};
  std::atomic<std::int64_t> maxLatencyUs{0};
  std::thread reader(
      [&]()
      {
        int i = 0;
        while (!stop.load(std::memory_order_relaxed))
        {
          const std::string key = "k" + std::to_string((i++) % 20000);
          const auto t0 = std::chrono::steady_clock::now();
          (void)cache->get(key);
          const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                              std::chrono::steady_clock::now() - t0)
                              .count();
          std::int64_t prev = maxLatencyUs.load(std::memory_order_relaxed);
          while (us > prev && !maxLatencyUs.compare_exchange_weak(
                                  prev, us, std::memory_order_relaxed))
          {
          }
        }
      });

  // Keep re-populating so the sweeper always has expired entries to reap.
  for (int round = 0; round < 30; ++round)
  {
    for (int i = 0; i < 20000; ++i)
    {
      cache->put("k" + std::to_string(i), i, std::chrono::seconds(1));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  stop.store(true, std::memory_order_relaxed);
  reader.join();

  INFO("max single get() latency (us): " << maxLatencyUs.load());
  REQUIRE(maxLatencyUs.load() < kMaxGetLatencyUs); // no pathological stall/hang

  cache.reset();
  fx.stopTimers();
}

// ───────────────────────────────────────────────────────────────────────────
// 2.8 concurrency soak: 100 threads x 100k ops, self-validating, writer-progress
//     Run under ThreadSanitizer (task 1.7) — a non-TSan soak cannot prove
//     race-freedom. Catch2 assertion macros are NOT thread-safe, so worker
//     threads record failures into atomics; the main thread asserts post-join.
// ───────────────────────────────────────────────────────────────────────────
namespace
{
constexpr int kThreads = 100;
constexpr int kOpsPerThread = 100000;
constexpr int kKeySpace = 512;

std::int64_t makeValue(int key)
{
  return static_cast<std::int64_t>(key) * 1000003LL + 17LL;
}

std::chrono::seconds ttlFor(int key)
{
  // A subset of keys gets a 1s TTL so they frequently expire while being read
  // concurrently (get-vs-get on expired keys); the rest are long-lived.
  return (key % 8 == 0) ? std::chrono::seconds(1) : std::chrono::seconds(30);
}
} // namespace

TEST_CASE("TtlMap concurrency soak with self-validating values")
{
  TimerFixture fx;
  IntCache::Config cfg{};
  cfg.defaultTtl = std::chrono::seconds(30);
  cfg.maxEntries = kKeySpace / 2; // force frequent capacity evictions
  cfg.sweepInterval = std::chrono::seconds(1); // active sweeper during the soak
  auto cache = std::make_unique<IntCache>(cfg, fx.timers);

  std::atomic<bool> torn{false};      // a get() returned a value != f(key)
  std::atomic<bool> startGate{false}; // release all threads together

  auto worker =
      [&](int seed)
      {
        std::mt19937 rng(static_cast<std::uint32_t>(seed * 2654435761u + 1u));
        std::uniform_int_distribution<int> keyDist(0, kKeySpace - 1);
        std::uniform_int_distribution<int> opDist(0, 99);
        while (!startGate.load(std::memory_order_acquire))
        {
        }
        for (int i = 0; i < kOpsPerThread; ++i)
        {
          const int key = keyDist(rng);
          const int roll = opDist(rng);
          if (roll < 80) // 80% reads (the read-heavy design target)
          {
            auto v = cache->get(key);
            if (v && *v != makeValue(key))
            {
              torn.store(true, std::memory_order_relaxed); // torn read detected
            }
          }
          else if (roll < 95) // 15% writes
          {
            cache->put(key, makeValue(key), ttlFor(key));
          }
          else // 5% invalidations
          {
            cache->invalidate(key);
          }
        }
      };

  // Dedicated writer-progress thread: completes kWriterPuts puts on a hot key
  // under contention from 100 workers — must finish within a generous bound
  // (a starvation/deadlock detector, not a perf SLA).
  constexpr int kWriterPuts = 20000;
  std::atomic<bool> writerDone{false};
  std::atomic<std::int64_t> writerElapsedMs{0};
  auto writerProgress =
      [&]()
      {
        while (!startGate.load(std::memory_order_acquire))
        {
        }
        const auto t0 = std::chrono::steady_clock::now();
        for (int i = 0; i < kWriterPuts; ++i)
        {
          cache->put(7, makeValue(7), std::chrono::seconds(30));
        }
        writerElapsedMs.store(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0)
                .count(),
            std::memory_order_relaxed);
        writerDone.store(true, std::memory_order_relaxed);
      };

  // Dedicated reader-stall thread: tracks worst-case get() latency DURING the
  // soak while the short-interval sweeper is actively reaping.
  std::atomic<bool> readerStop{false};
  std::atomic<std::int64_t> maxLatencyUs{0};
  auto readerStall =
      [&]()
      {
        while (!startGate.load(std::memory_order_acquire))
        {
        }
        int i = 0;
        while (!readerStop.load(std::memory_order_relaxed))
        {
          const int key = (i++) % kKeySpace;
          const auto t0 = std::chrono::steady_clock::now();
          (void)cache->get(key);
          const auto us =
              std::chrono::duration_cast<std::chrono::microseconds>(
                  std::chrono::steady_clock::now() - t0)
                  .count();
          std::int64_t prev = maxLatencyUs.load(std::memory_order_relaxed);
          while (us > prev && !maxLatencyUs.compare_exchange_weak(
                                  prev, us, std::memory_order_relaxed))
          {
          }
        }
      };

  std::vector<std::thread> threads;
  threads.reserve(kThreads + 2);
  for (int t = 0; t < kThreads; ++t)
  {
    threads.emplace_back(worker, t);
  }
  std::thread writerThread(writerProgress);
  std::thread readerThread(readerStall);

  const auto wallStart = std::chrono::steady_clock::now();
  startGate.store(true, std::memory_order_release);

  for (auto &th : threads)
  {
    th.join();
  }
  writerThread.join();
  readerStop.store(true, std::memory_order_relaxed);
  readerThread.join();
  const auto wallMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - wallStart)
                          .count();

  INFO("soak wall time (ms): " << wallMs
                               << ", writer elapsed (ms): "
                               << writerElapsedMs.load()
                               << ", max get latency (us): "
                               << maxLatencyUs.load());

  REQUIRE_FALSE(torn.load());          // no torn reads -> no data race on value
  REQUIRE(writerDone.load());          // writer made progress (no starvation)
  REQUIRE(writerElapsedMs.load() < kWriterBudgetMs); // bounded wall-clock
  REQUIRE(maxLatencyUs.load() < kMaxGetLatencyUs);   // reader never stalled
  REQUIRE(cache->stats().size <= cfg.maxEntries); // capacity invariant held

  cache.reset();
  fx.stopTimers();
}

// ───────────────────────────────────────────────────────────────────────────
// 2.9 constructor throws when schedulePeriodic returns 0
// ───────────────────────────────────────────────────────────────────────────
TEST_CASE("TtlMap constructor throws when the sweeper cannot be scheduled")
{
  iora::core::TimerService timers;
  timers.stop(); // drained/stopped -> _accepting == false -> schedulePeriodic 0

  REQUIRE_THROWS_AS(StrIntCache(strCfg(60s, 8, 1s), timers), std::runtime_error);

  // Failure path leaves NO orphan timer scheduled ("no handler was scheduled,
  // so no cleanup needed" — arch constructor contract).
  REQUIRE(timers.getStats().periodicTimersActive.load() == 0);
  REQUIRE(timers.getInFlightCount() == 0);
}
