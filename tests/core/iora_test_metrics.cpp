// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for the Metrics framework (Counter, Gauge, Histogram, MetricsRegistry)

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/core/metrics.hpp>
#include <iora/iora.hpp>
#include <iora/parsers/json.hpp>

#include <atomic>
#include <cmath>
#include <limits>
#include <thread>
#include <vector>

using namespace iora::core;

// ══════════════════════════════════════════════════════════════════════════════
// Counter Tests
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Counter: integer increment and value", "[metrics][counter]")
{
  Counter c("test_counter", {}, "test help");
  REQUIRE(c.value() == 0.0);

  c.increment(uint64_t(1));
  REQUIRE(c.value() == 1.0);

  c.increment(uint64_t(9));
  REQUIRE(c.value() == 10.0);

  REQUIRE(c.intValue() == 10);
}

TEST_CASE("Counter: double increment via CAS loop", "[metrics][counter]")
{
  Counter c("test_counter_double", {}, "");
  c.increment(0.5);
  c.increment(1.7);
  REQUIRE(c.value() == Approx(2.2));
}

TEST_CASE("Counter: combined integer + double value", "[metrics][counter]")
{
  Counter c("test_counter_mixed", {}, "");
  c.increment(uint64_t(10));
  c.increment(0.5);
  REQUIRE(c.value() == Approx(10.5));
  REQUIRE(c.intValue() == 10);
}

TEST_CASE("Counter: type and metadata", "[metrics][counter]")
{
  Labels labels = {{"method", "GET"}};
  Counter c("http_requests", labels, "Total requests");
  REQUIRE(c.type() == MetricType::COUNTER);
  REQUIRE(c.name() == "http_requests");
  REQUIRE(c.labels().size() == 1);
  REQUIRE(c.help() == "Total requests");
}

TEST_CASE("Counter: no reset method exists", "[metrics][counter]")
{
  // Counter is monotonically increasing — no reset().
  // This is a design verification, not a compile-time check.
  // If someone adds reset() in the future, this comment flags the violation.
  Counter c("no_reset", {}, "");
  c.increment(uint64_t(10));
  REQUIRE(c.value() == 10.0);
  // There is no c.reset() to call — by design.
}

TEST_CASE("Counter: stress test — double CAS contention", "[metrics][counter][stress]")
{
  Counter c("stress_double", {}, "");
  constexpr int numThreads = 16;
  constexpr int incrementsPerThread = 100000;

  std::vector<std::thread> threads;
  for (int i = 0; i < numThreads; ++i)
  {
    threads.emplace_back([&c]()
    {
      for (int j = 0; j < incrementsPerThread; ++j)
      {
        c.increment(0.5);
      }
    });
  }
  for (auto& t : threads) t.join();

  double expected = numThreads * incrementsPerThread * 0.5;
  REQUIRE(c.value() == Approx(expected).epsilon(0.001));
}

TEST_CASE("Counter: stress test — 16 threads x 1M increments", "[metrics][counter][stress]")
{
  Counter c("stress_counter", {}, "");
  constexpr int numThreads = 16;
  constexpr uint64_t incrementsPerThread = 1000000;

  std::vector<std::thread> threads;
  for (int i = 0; i < numThreads; ++i)
  {
    threads.emplace_back([&c]()
    {
      for (uint64_t j = 0; j < incrementsPerThread; ++j)
      {
        c.increment(uint64_t(1));
      }
    });
  }
  for (auto& t : threads) t.join();

  REQUIRE(c.intValue() == numThreads * incrementsPerThread);
}

// ══════════════════════════════════════════════════════════════════════════════
// Gauge Tests
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Gauge: set, increment, decrement", "[metrics][gauge]")
{
  Gauge g("test_gauge", {}, "");
  REQUIRE(g.value() == 0.0);

  g.set(42.0);
  REQUIRE(g.value() == 42.0);

  g.increment(8.0);
  REQUIRE(g.value() == Approx(50.0));

  g.decrement(10.0);
  REQUIRE(g.value() == Approx(40.0));
}

TEST_CASE("Gauge: stress test — concurrent set/increment/decrement", "[metrics][gauge][stress]")
{
  Gauge g("stress_gauge", {}, "");
  constexpr int numThreads = 16;
  constexpr int opsPerThread = 100000;

  std::vector<std::thread> threads;
  for (int i = 0; i < numThreads; ++i)
  {
    threads.emplace_back([&g, i]()
    {
      for (int j = 0; j < opsPerThread; ++j)
      {
        if (i % 3 == 0) g.set(static_cast<double>(j));
        else if (i % 3 == 1) g.increment(1.0);
        else g.decrement(1.0);
      }
    });
  }
  for (auto& t : threads) t.join();

  // Just verify no crash and value is finite
  REQUIRE(std::isfinite(g.value()));
}

// ══════════════════════════════════════════════════════════════════════════════
// Histogram Tests
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Histogram: observe and bucket distribution", "[metrics][histogram]")
{
  Histogram h("test_hist", {}, {1.0, 5.0, 10.0}, "");
  h.observe(0.5);   // bucket [0, 1.0)
  h.observe(3.0);   // bucket [1.0, 5.0)
  h.observe(7.0);   // bucket [5.0, 10.0)
  h.observe(15.0);  // bucket [10.0, +Inf)

  auto snap = h.snapshot();
  REQUIRE(snap.count == 4);
  REQUIRE(snap.sum == Approx(25.5));

  // Cumulative: le=1 -> 1, le=5 -> 2, le=10 -> 3, le=+Inf -> 4
  REQUIRE(snap.bucketCounts.size() == 4);
  REQUIRE(snap.bucketCounts[0].second == 1);
  REQUIRE(snap.bucketCounts[1].second == 2);
  REQUIRE(snap.bucketCounts[2].second == 3);
  REQUIRE(snap.bucketCounts[3].second == 4);
}

TEST_CASE("Histogram: boundary-exact values use le semantics", "[metrics][histogram]")
{
  Histogram h("exact_hist", {}, {1.0, 5.0, 10.0}, "");
  h.observe(1.0);   // exactly on boundary — should be in le=1.0 bucket
  h.observe(5.0);   // exactly on boundary — should be in le=5.0 bucket
  h.observe(10.0);  // exactly on boundary — should be in le=10.0 bucket

  auto snap = h.snapshot();
  // Cumulative: le=1 -> 1, le=5 -> 2, le=10 -> 3, le=+Inf -> 3
  REQUIRE(snap.bucketCounts[0].second == 1);  // le=1.0: one value (1.0)
  REQUIRE(snap.bucketCounts[1].second == 2);  // le=5.0: two values (1.0, 5.0)
  REQUIRE(snap.bucketCounts[2].second == 3);  // le=10.0: three values
  REQUIRE(snap.bucketCounts[3].second == 3);  // +Inf: same
}

TEST_CASE("Histogram: default buckets", "[metrics][histogram]")
{
  Histogram h("default_hist", {}, {}, "");
  REQUIRE(h.boundaries().size() == 12);
  REQUIRE(h.boundaries()[0] == Approx(0.001));
}

TEST_CASE("Histogram: empty snapshot", "[metrics][histogram]")
{
  Histogram h("empty_hist", {}, {1.0}, "");
  auto snap = h.snapshot();
  REQUIRE(snap.count == 0);
  REQUIRE(snap.sum == 0.0);
  REQUIRE(snap.bucketCounts[0].second == 0);
  REQUIRE(snap.bucketCounts[1].second == 0);
}

TEST_CASE("Histogram: cumulative snapshot conversion", "[metrics][histogram]")
{
  Histogram h("cum_hist", {}, {1.0, 2.0, 3.0}, "");
  h.observe(0.5);  // bucket 0
  h.observe(1.5);  // bucket 1
  h.observe(2.5);  // bucket 2

  auto snap = h.snapshot();
  // Cumulative: le=1->1, le=2->2, le=3->3, +Inf->3
  REQUIRE(snap.bucketCounts[0].second == 1);
  REQUIRE(snap.bucketCounts[1].second == 2);
  REQUIRE(snap.bucketCounts[2].second == 3);
  REQUIRE(snap.bucketCounts[3].second == 3);
}

TEST_CASE("Histogram: percentile estimation", "[metrics][histogram]")
{
  Histogram h("pct_hist", {}, {1.0, 2.0, 5.0, 10.0}, "");
  for (int i = 0; i < 100; ++i)
  {
    h.observe(static_cast<double>(i) / 10.0); // 0.0 to 9.9
  }
  auto snap = h.snapshot();
  double p50 = snap.percentile(0.5);
  REQUIRE(p50 >= 2.0);
  REQUIRE(p50 <= 7.0);
}

TEST_CASE("Histogram: stress test — concurrent observe", "[metrics][histogram][stress]")
{
  Histogram h("stress_hist", {}, {1.0, 5.0, 10.0}, "");
  constexpr int numThreads = 16;
  constexpr int obsPerThread = 100000;

  std::vector<std::thread> threads;
  for (int i = 0; i < numThreads; ++i)
  {
    threads.emplace_back([&h]()
    {
      for (int j = 0; j < obsPerThread; ++j)
      {
        h.observe(static_cast<double>(j % 15));
      }
    });
  }
  for (auto& t : threads) t.join();

  auto snap = h.snapshot();
  REQUIRE(snap.count == numThreads * obsPerThread);
}

// ══════════════════════════════════════════════════════════════════════════════
// MetricsRegistry Tests
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Registry: same name+labels returns same reference", "[metrics][registry]")
{
  MetricsRegistry registry;
  auto& c1 = registry.counter("test", {{"a", "1"}}, "help");
  auto& c2 = registry.counter("test", {{"a", "1"}});
  REQUIRE(&c1 == &c2);
}

TEST_CASE("Registry: different labels returns different metric", "[metrics][registry]")
{
  MetricsRegistry registry;
  auto& c1 = registry.counter("test", {{"a", "1"}});
  auto& c2 = registry.counter("test", {{"a", "2"}});
  REQUIRE(&c1 != &c2);
}

TEST_CASE("Registry: label ordering normalization", "[metrics][registry]")
{
  MetricsRegistry registry;
  auto& c1 = registry.counter("test", {{"b", "2"}, {"a", "1"}});
  auto& c2 = registry.counter("test", {{"a", "1"}, {"b", "2"}});
  REQUIRE(&c1 == &c2);
}

TEST_CASE("Registry: type conflict throws logic_error", "[metrics][registry]")
{
  MetricsRegistry registry;
  registry.counter("conflict_metric", {});
  REQUIRE_THROWS_AS(registry.gauge("conflict_metric", {}), std::logic_error);
}

TEST_CASE("Registry: maxSeries limit", "[metrics][registry]")
{
  MetricsRegistry registry;
  registry.setMaxSeries(3);
  registry.counter("m1");
  registry.counter("m2");
  registry.counter("m3");
  REQUIRE_THROWS_AS(registry.counter("m4"), std::runtime_error);
}

TEST_CASE("Registry: help text first-writer-wins", "[metrics][registry]")
{
  MetricsRegistry registry;
  registry.counter("test", {}, "first help");
  registry.counter("test", {{"a", "1"}}, "second help");
  REQUIRE(registry.helpText("test") == "first help");
}

TEST_CASE("Registry: metrics cannot be removed — references stay valid", "[metrics][registry]")
{
  MetricsRegistry registry;
  auto& c1 = registry.counter("persistent", {{"a", "1"}});
  c1.increment(uint64_t(42));

  // Register more metrics — original reference must remain valid
  for (int i = 0; i < 100; ++i)
  {
    registry.counter("other_" + std::to_string(i));
  }

  REQUIRE(c1.value() == 42.0);
  REQUIRE(c1.name() == "persistent");
}

TEST_CASE("Registry: size tracking", "[metrics][registry]")
{
  MetricsRegistry registry;
  REQUIRE(registry.size() == 0);
  registry.counter("c1");
  registry.gauge("g1");
  REQUIRE(registry.size() == 2);
}

TEST_CASE("Registry: concurrent registration — no duplicates", "[metrics][registry][stress]")
{
  MetricsRegistry registry;
  constexpr int numThreads = 16;
  std::vector<std::thread> threads;
  std::atomic<int> successCount{0};

  for (int i = 0; i < numThreads; ++i)
  {
    threads.emplace_back([&registry, &successCount]()
    {
      auto& c = registry.counter("shared_counter", {{"env", "test"}}, "help");
      c.increment(uint64_t(1));
      successCount.fetch_add(1);
    });
  }
  for (auto& t : threads) t.join();

  REQUIRE(successCount.load() == numThreads);
  REQUIRE(registry.size() == 1);
  auto& c = registry.counter("shared_counter", {{"env", "test"}});
  REQUIRE(c.intValue() == numThreads);
}

// ══════════════════════════════════════════════════════════════════════════════
// Export Tests
// ══════════════════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════════════════
// IoraService Integration Tests
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("IoraService::metrics() returns registry singleton", "[metrics][service]")
{
  auto& reg1 = iora::IoraService::instanceRef().metrics();
  auto& reg2 = iora::core::MetricsRegistry::instance();
  REQUIRE(&reg1 == &reg2);
}

TEST_CASE("MetricsRegistry available before IoraService::init()", "[metrics][service]")
{
  // MetricsRegistry uses function-local static — available without init()
  auto& registry = iora::core::MetricsRegistry::instance();
  auto& c = registry.counter("pre_init_counter", {}, "test");
  c.increment(uint64_t(1));
  REQUIRE(c.value() == Approx(1.0));
}

// ══════════════════════════════════════════════════════════════════════════════
// Export Tests
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Registry: JSON export", "[metrics][export]")
{
  MetricsRegistry registry;
  registry.counter("http_requests", {{"method", "GET"}}, "Total requests");
  registry.counter("http_requests", {{"method", "GET"}}).increment(uint64_t(42));
  registry.gauge("active_connections", {}, "Current connections");
  registry.gauge("active_connections").set(5.0);

  std::string json = registry.snapshotJson();
  REQUIRE(json.find("\"counters\"") != std::string::npos);
  REQUIRE(json.find("\"gauges\"") != std::string::npos);
  REQUIRE(json.find("\"histograms\"") != std::string::npos);
  REQUIRE(json.find("http_requests") != std::string::npos);
  REQUIRE(json.find("active_connections") != std::string::npos);
}

TEST_CASE("Registry: Prometheus export — counter with _total suffix", "[metrics][export]")
{
  MetricsRegistry registry;
  registry.counter("requests", {{"method", "GET"}}, "Total requests");
  registry.counter("requests", {{"method", "GET"}}).increment(uint64_t(42));

  std::string prom = registry.prometheusExport();
  REQUIRE(prom.find("# TYPE requests_total counter") != std::string::npos);
  REQUIRE(prom.find("requests_total{method=\"GET\"}") != std::string::npos);
}

TEST_CASE("Registry: Prometheus export — no double _total suffix", "[metrics][export]")
{
  MetricsRegistry registry;
  registry.counter("already_total", {});
  std::string prom = registry.prometheusExport();
  REQUIRE(prom.find("already_total_total") == std::string::npos);
  REQUIRE(prom.find("already_total ") != std::string::npos);
}

TEST_CASE("Registry: Prometheus export — histogram buckets", "[metrics][export]")
{
  MetricsRegistry registry;
  auto& h = registry.histogram("latency", {}, {0.1, 0.5, 1.0}, "Request latency");
  h.observe(0.05);
  h.observe(0.3);
  h.observe(0.8);

  std::string prom = registry.prometheusExport();
  REQUIRE(prom.find("# TYPE latency histogram") != std::string::npos);
  REQUIRE(prom.find("latency_bucket{le=\"0.1\"}") != std::string::npos);
  REQUIRE(prom.find("latency_bucket{le=\"+Inf\"}") != std::string::npos);
  REQUIRE(prom.find("latency_sum") != std::string::npos);
  REQUIRE(prom.find("latency_count") != std::string::npos);
}

TEST_CASE("Registry: Prometheus export — label escaping", "[metrics][export]")
{
  MetricsRegistry registry;
  registry.counter("test", {{"path", "/api/\"test\"\n"}});
  std::string prom = registry.prometheusExport();
  REQUIRE(prom.find("\\\"test\\\"") != std::string::npos);
  REQUIRE(prom.find("\\n") != std::string::npos);
}

TEST_CASE("Registry: Prometheus export — name sanitization", "[metrics][export]")
{
  MetricsRegistry registry;
  registry.gauge("my.metric-name", {});
  std::string prom = registry.prometheusExport();
  REQUIRE(prom.find("my_metric_name") != std::string::npos);
}

TEST_CASE("Registry: JSON export escapes metric names", "[metrics][export]")
{
  MetricsRegistry registry;
  // A name containing a quote and a backslash would produce malformed JSON
  // if emitted raw.
  registry.counter("bad\"name\\x", {}, "help");
  std::string json = registry.snapshotJson();

  // The output must parse as valid JSON (an unescaped quote/backslash breaks it).
  REQUIRE_NOTHROW(iora::parsers::Json::parseOrThrow(json));
  // The escaped byte sequence bad\"name\\x must be present verbatim.
  REQUIRE(json.find("bad\\\"name\\\\x") != std::string::npos);
}

TEST_CASE("Registry: large integer values avoid scientific notation",
          "[metrics][export]")
{
  MetricsRegistry registry;
  registry.counter("big_counter", {}).increment(uint64_t(16000000));
  registry.gauge("big_gauge", {}).set(16000000.0);

  std::string prom = registry.prometheusExport();
  std::string json = registry.snapshotJson();

  REQUIRE(prom.find("16000000") != std::string::npos);
  REQUIRE(prom.find("1.6e+07") == std::string::npos);
  REQUIRE(json.find("16000000") != std::string::npos);
  REQUIRE(json.find("1.6e+07") == std::string::npos);
}

TEST_CASE("Registry: Prometheus HELP text is escaped and single-line",
          "[metrics][export]")
{
  MetricsRegistry registry;
  // Help text with a newline and a backslash. Per the Prometheus text format,
  // HELP escapes backslash (\\) and newline (\n) but NOT quotes.
  registry.counter("helped_metric", {}, "line one\nline\\two");
  std::string prom = registry.prometheusExport();

  // The escaped HELP line appears with \n (backslash-n) and \\ (two backslashes),
  // keeping it on a single line.
  REQUIRE(prom.find("# HELP helped_metric_total line one\\nline\\\\two")
          != std::string::npos);
  // A raw newline must NOT appear within the help text.
  REQUIRE(prom.find("line one\nline") == std::string::npos);
}

TEST_CASE("Registry: Prometheus dedups headers by export name",
          "[metrics][export]")
{
  MetricsRegistry registry;
  // Both raw names sanitize to the same export name "my_metric"; Prometheus
  // rejects duplicate # TYPE/# HELP lines for one family.
  registry.gauge("my.metric", {}).set(1.0);
  registry.gauge("my-metric", {}).set(2.0);

  std::string prom = registry.prometheusExport();
  std::size_t first = prom.find("# TYPE my_metric gauge");
  REQUIRE(first != std::string::npos);
  // No second occurrence.
  REQUIRE(prom.find("# TYPE my_metric gauge", first + 1) == std::string::npos);
}

// ══════════════════════════════════════════════════════════════════════════════
// Non-finite input rejection
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Histogram: observe rejects non-finite values", "[metrics][histogram]")
{
  Histogram h("finite_hist", {}, {1.0, 5.0}, "");
  h.observe(std::numeric_limits<double>::quiet_NaN());
  h.observe(std::numeric_limits<double>::infinity());
  h.observe(-std::numeric_limits<double>::infinity());
  h.observe(3.0);  // the only finite observation

  auto snap = h.snapshot();
  REQUIRE(snap.count == 1);
  REQUIRE(std::isfinite(snap.sum));
  REQUIRE(snap.sum == Approx(3.0));
}

TEST_CASE("Counter/Gauge reject non-finite inputs", "[metrics][counter][gauge]")
{
  Counter c("finite_counter", {}, "");
  c.increment(std::numeric_limits<double>::infinity());
  c.increment(std::numeric_limits<double>::quiet_NaN());
  c.increment(2.5);
  REQUIRE(std::isfinite(c.value()));
  REQUIRE(c.value() == Approx(2.5));

  Gauge g("finite_gauge", {}, "");
  g.set(std::numeric_limits<double>::quiet_NaN());
  REQUIRE(g.value() == 0.0);  // rejected — unchanged
  g.set(7.0);
  g.increment(std::numeric_limits<double>::infinity());
  REQUIRE(std::isfinite(g.value()));
  REQUIRE(g.value() == Approx(7.0));
}
