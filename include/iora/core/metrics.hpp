// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace iora {
namespace core {

// ══════════════════════════════════════════════════════════════════════════════
// Core Types
// ══════════════════════════════════════════════════════════════════════════════

/// \brief Label set for dimensional metrics.
/// Sorted by key at registration time. Part of metric identity.
using Labels = std::vector<std::pair<std::string, std::string>>;

/// \brief Discriminator for the three supported metric kinds.
enum class MetricType
{
  COUNTER,
  GAUGE,
  HISTOGRAM
};

/// \brief Identity key for a metric series (name + sorted labels).
struct MetricKey
{
  std::string name;
  Labels labels;

  bool operator==(const MetricKey& other) const
  {
    return name == other.name && labels == other.labels;
  }
};

/// \brief Hash functor for MetricKey using boost-style hash_combine.
struct MetricKeyHash
{
  std::size_t operator()(const MetricKey& key) const
  {
    std::size_t h = std::hash<std::string>{}(key.name);
    for (const auto& [k, v] : key.labels)
    {
      h ^= std::hash<std::string>{}(k) + 0x9e3779b9 + (h << 6) + (h >> 2);
      h ^= std::hash<std::string>{}(v) + 0x9e3779b9 + (h << 6) + (h >> 2);
    }
    return h;
  }
};

/// \brief Abstract base class for all metric types.
/// Defined in iora_core.so (vtable lives in metrics.cpp).
class MetricBase
{
public:
  virtual ~MetricBase();
  virtual MetricType type() const = 0;
  virtual const std::string& name() const = 0;
  virtual const Labels& labels() const = 0;
  virtual const std::string& help() const = 0;
};

// Verify lock-free atomics are available for the double CAS path.
// On 32-bit ARM without 64-bit atomic support, this fires.
static_assert(std::atomic<double>::is_always_lock_free,
  "std::atomic<double> must be lock-free. On this platform, "
  "fall back to fixed-point std::atomic<uint64_t> encoding.");

// ══════════════════════════════════════════════════════════════════════════════
// Counter
// ══════════════════════════════════════════════════════════════════════════════

/// \brief Monotonically increasing counter.
///
/// Dual storage: atomic<uint64_t> for integer increments (fetch_add, always
/// lock-free), atomic<double> for fractional increments (CAS loop).
/// Counter has no reset() — use Gauge with set(0.0) if reset is needed.
///
/// All atomic operations use memory_order_relaxed. Metrics are eventually
/// consistent — no happens-before relationship is established.
class Counter : public MetricBase
{
public:
  Counter(std::string name, Labels labels, std::string help)
    : _name(std::move(name))
    , _labels(std::move(labels))
    , _help(std::move(help))
    , _intValue{0}
    , _doubleValue{0.0}
  {
  }

  MetricType type() const override { return MetricType::COUNTER; }
  const std::string& name() const override { return _name; }
  const Labels& labels() const override { return _labels; }
  const std::string& help() const override { return _help; }

  /// \brief Increment by an integer amount. Always lock-free via fetch_add.
  void increment(std::uint64_t amount = 1)
  {
    _intValue.fetch_add(amount, std::memory_order_relaxed);
  }

  /// \brief Increment by a fractional amount via CAS loop.
  void increment(double amount)
  {
    assert(amount >= 0.0 && "Counter::increment amount must be non-negative");
    double current = _doubleValue.load(std::memory_order_relaxed);
    double desired;
    do
    {
      desired = current + amount;
    } while (!_doubleValue.compare_exchange_weak(
      current, desired,
      std::memory_order_relaxed,
      std::memory_order_relaxed));
  }

  /// \brief Returns the current counter value (sum of integer and double).
  double value() const
  {
    return static_cast<double>(_intValue.load(std::memory_order_relaxed))
         + _doubleValue.load(std::memory_order_relaxed);
  }

  /// \brief Returns just the integer component.
  std::uint64_t intValue() const
  {
    return _intValue.load(std::memory_order_relaxed);
  }

private:
  std::string _name;
  Labels _labels;
  std::string _help;
  std::atomic<std::uint64_t> _intValue;
  std::atomic<double> _doubleValue;
};

// ══════════════════════════════════════════════════════════════════════════════
// Gauge
// ══════════════════════════════════════════════════════════════════════════════

/// \brief Arbitrary-value metric that can go up and down.
///
/// Used for current values: active connections, queue depth, pool utilization.
/// All atomic operations use memory_order_relaxed.
class Gauge : public MetricBase
{
public:
  Gauge(std::string name, Labels labels, std::string help)
    : _name(std::move(name))
    , _labels(std::move(labels))
    , _help(std::move(help))
    , _value{0.0}
  {
  }

  MetricType type() const override { return MetricType::GAUGE; }
  const std::string& name() const override { return _name; }
  const Labels& labels() const override { return _labels; }
  const std::string& help() const override { return _help; }

  /// \brief Set the gauge to an absolute value.
  void set(double value)
  {
    _value.store(value, std::memory_order_relaxed);
  }

  /// \brief Increment the gauge by amount via CAS loop.
  void increment(double amount = 1.0)
  {
    double current = _value.load(std::memory_order_relaxed);
    double desired;
    do
    {
      desired = current + amount;
    } while (!_value.compare_exchange_weak(
      current, desired,
      std::memory_order_relaxed,
      std::memory_order_relaxed));
  }

  /// \brief Decrement the gauge by amount via CAS loop.
  void decrement(double amount = 1.0)
  {
    increment(-amount);
  }

  /// \brief Returns the current gauge value.
  double value() const
  {
    return _value.load(std::memory_order_relaxed);
  }

private:
  std::string _name;
  Labels _labels;
  std::string _help;
  std::atomic<double> _value;
};

// ══════════════════════════════════════════════════════════════════════════════
// Histogram
// ══════════════════════════════════════════════════════════════════════════════

/// \brief Snapshot of a histogram's state at a point in time.
struct HistogramSnapshot
{
  /// \brief (upperBound, cumulativeCount) pairs. Last entry has le=+Inf.
  std::vector<std::pair<double, std::uint64_t>> bucketCounts;
  double sum = 0.0;
  std::uint64_t count = 0;

  /// \brief Estimate a percentile (0.0-1.0) via linear interpolation.
  double percentile(double p) const
  {
    if (count == 0 || bucketCounts.empty())
    {
      return 0.0;
    }

    double target = p * static_cast<double>(count);
    double prevBound = 0.0;
    std::uint64_t prevCount = 0;

    for (const auto& [bound, cumCount] : bucketCounts)
    {
      if (static_cast<double>(cumCount) >= target)
      {
        if (std::isinf(bound))
        {
          return prevBound;
        }
        double fraction = (cumCount == prevCount)
          ? 0.0
          : (target - static_cast<double>(prevCount))
            / static_cast<double>(cumCount - prevCount);
        return prevBound + fraction * (bound - prevBound);
      }
      prevBound = bound;
      prevCount = cumCount;
    }
    return prevBound;
  }
};

/// \brief Tracks the distribution of observed values across configurable
/// bucket boundaries.
///
/// Thread-safe with per-bucket atomics. All operations use relaxed ordering.
class Histogram : public MetricBase
{
public:
  /// \brief Default bucket boundaries for latency tracking (in seconds).
  static inline const std::vector<double> DEFAULT_BUCKETS = {
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
  };

  Histogram(std::string name, Labels labels, std::vector<double> boundaries,
            std::string help)
    : _name(std::move(name))
    , _labels(std::move(labels))
    , _help(std::move(help))
    , _boundaries(boundaries.empty() ? DEFAULT_BUCKETS : std::move(boundaries))
    , _sum{0.0}
    , _count{0}
  {
    std::sort(_boundaries.begin(), _boundaries.end());
    // One bucket per boundary + one for +Inf
    _numBuckets = _boundaries.size() + 1;
    _bucketCounts = std::make_unique<std::atomic<std::uint64_t>[]>(_numBuckets);
    for (std::size_t i = 0; i < _numBuckets; ++i)
    {
      _bucketCounts[i].store(0, std::memory_order_relaxed);
    }
  }

  MetricType type() const override { return MetricType::HISTOGRAM; }
  const std::string& name() const override { return _name; }
  const Labels& labels() const override { return _labels; }
  const std::string& help() const override { return _help; }

  /// \brief Record an observed value.
  /// Finds the bucket via binary search, increments it, updates sum and count.
  void observe(double value)
  {
    // Find bucket: lower_bound gives first boundary >= value.
    // If value == boundary, lower_bound returns that boundary's iterator,
    // so idx equals that boundary's index — correctly counted in the le=boundary
    // bucket per Prometheus conventions. Values strictly greater than all
    // boundaries fall into the +Inf bucket (idx == _boundaries.size()).
    auto it = std::lower_bound(_boundaries.begin(), _boundaries.end(), value);
    std::size_t idx = static_cast<std::size_t>(
      std::distance(_boundaries.begin(), it));
    _bucketCounts[idx].fetch_add(1, std::memory_order_relaxed);

    // Update sum via CAS loop
    double current = _sum.load(std::memory_order_relaxed);
    double desired;
    do
    {
      desired = current + value;
    } while (!_sum.compare_exchange_weak(
      current, desired,
      std::memory_order_relaxed,
      std::memory_order_relaxed));

    _count.fetch_add(1, std::memory_order_relaxed);
  }

  /// \brief Returns a snapshot with cumulative bucket counts.
  /// Internally stores exclusive counts; converts to cumulative here.
  HistogramSnapshot snapshot() const
  {
    HistogramSnapshot s;
    s.bucketCounts.reserve(_boundaries.size() + 1);

    std::uint64_t cumulative = 0;
    for (std::size_t i = 0; i < _boundaries.size(); ++i)
    {
      cumulative += _bucketCounts[i].load(std::memory_order_relaxed);
      s.bucketCounts.emplace_back(_boundaries[i], cumulative);
    }
    // +Inf bucket
    cumulative += _bucketCounts[_numBuckets - 1].load(
      std::memory_order_relaxed);
    s.bucketCounts.emplace_back(
      std::numeric_limits<double>::infinity(), cumulative);

    s.sum = _sum.load(std::memory_order_relaxed);
    s.count = _count.load(std::memory_order_relaxed);
    return s;
  }

  /// \brief Returns the configured bucket boundaries.
  const std::vector<double>& boundaries() const { return _boundaries; }

private:
  std::string _name;
  Labels _labels;
  std::string _help;
  std::vector<double> _boundaries;
  std::size_t _numBuckets = 0;
  std::unique_ptr<std::atomic<std::uint64_t>[]> _bucketCounts;
  std::atomic<double> _sum;
  std::atomic<std::uint64_t> _count;
};

// ══════════════════════════════════════════════════════════════════════════════
// MetricsRegistry
// ══════════════════════════════════════════════════════════════════════════════

/// \brief Central registry for all metrics. Singleton in iora_core.so.
///
/// Metrics are registered once and observed many times. The returned reference
/// bypasses the registry on the observation path (zero lookup overhead).
///
/// Thread safety: shared_mutex with double-checked locking for registration.
/// Observation methods on Counter/Gauge/Histogram are lock-free.
class MetricsRegistry
{
public:
  MetricsRegistry() = default;
  ~MetricsRegistry() = default;

  MetricsRegistry(const MetricsRegistry&) = delete;
  MetricsRegistry& operator=(const MetricsRegistry&) = delete;

  /// \brief Singleton access. Defined in iora_core.so.
#if defined(IORA_CORE_SHARED) || defined(IORA_CORE_BUILDING)
  static MetricsRegistry& instance();
#else
  static MetricsRegistry& instance()
  {
    static MetricsRegistry registry;
    return registry;
  }
#endif

  /// \brief Set the maximum number of metric series. Default 10,000.
  void setMaxSeries(std::size_t max) { _maxSeries = max; }

  /// \brief Get or create a Counter with the given name and labels.
  /// Throws std::logic_error on type conflict.
  /// Throws std::runtime_error if maxSeries exceeded.
  Counter& counter(const std::string& name, Labels labels = {},
                   const std::string& help = {})
  {
    return getOrCreate<Counter>(name, std::move(labels), help,
                                MetricType::COUNTER);
  }

  /// \brief Get or create a Gauge with the given name and labels.
  Gauge& gauge(const std::string& name, Labels labels = {},
               const std::string& help = {})
  {
    return getOrCreate<Gauge>(name, std::move(labels), help,
                              MetricType::GAUGE);
  }

  /// \brief Get or create a Histogram with the given name, labels, and buckets.
  Histogram& histogram(const std::string& name, Labels labels = {},
                       std::vector<double> buckets = {},
                       const std::string& help = {})
  {
    auto sortedLabels = std::move(labels);
    std::sort(sortedLabels.begin(), sortedLabels.end());
    MetricKey key{name, sortedLabels};

    // Fast path: shared lock, check if exists
    {
      std::shared_lock lock(_mutex);
      auto it = _metrics.find(key);
      if (it != _metrics.end())
      {
        if (it->second->type() != MetricType::HISTOGRAM)
        {
          throw std::logic_error(
            "Metric '" + name + "' already registered as a different type");
        }
        return static_cast<Histogram&>(*it->second);
      }
    }

    // Slow path: unique lock, re-check + create
    {
      std::unique_lock lock(_mutex);
      auto it = _metrics.find(key);
      if (it != _metrics.end())
      {
        if (it->second->type() != MetricType::HISTOGRAM)
        {
          throw std::logic_error(
            "Metric '" + name + "' already registered as a different type");
        }
        return static_cast<Histogram&>(*it->second);
      }

      if (_metrics.size() >= _maxSeries)
      {
        throw std::runtime_error(
          "MetricsRegistry: maxSeries limit (" + std::to_string(_maxSeries)
          + ") exceeded registering '" + name + "'");
      }

      updateHelpText(name, help);
      auto metric = std::make_unique<Histogram>(
        name, sortedLabels, std::move(buckets), help);
      auto& ref = *metric;
      _metrics.emplace(std::move(key), std::move(metric));
      return ref;
    }
  }

  /// \brief Export all metrics as JSON string.
  std::string snapshotJson() const
  {
    std::shared_lock lock(_mutex);
    std::ostringstream out;
    out << "{\"counters\":[";
    bool firstCounter = true;
    bool firstGauge = true;
    bool firstHistogram = true;
    std::ostringstream gaugeOut, histOut;

    for (const auto& [key, metric] : _metrics)
    {
      std::string lbls = jsonLabels(metric->labels());
      switch (metric->type())
      {
      case MetricType::COUNTER:
      {
        auto& c = static_cast<Counter&>(*metric);
        if (!firstCounter) out << ",";
        out << "{\"name\":\"" << c.name() << "\",\"labels\":" << lbls
            << ",\"value\":" << formatDouble(c.value()) << "}";
        firstCounter = false;
        break;
      }
      case MetricType::GAUGE:
      {
        auto& g = static_cast<Gauge&>(*metric);
        if (!firstGauge) gaugeOut << ",";
        gaugeOut << "{\"name\":\"" << g.name() << "\",\"labels\":" << lbls
                 << ",\"value\":" << formatDouble(g.value()) << "}";
        firstGauge = false;
        break;
      }
      case MetricType::HISTOGRAM:
      {
        auto& h = static_cast<Histogram&>(*metric);
        auto snap = h.snapshot();
        if (!firstHistogram) histOut << ",";
        histOut << "{\"name\":\"" << h.name() << "\",\"labels\":" << lbls
                << ",\"buckets\":[";
        for (std::size_t i = 0; i < snap.bucketCounts.size(); ++i)
        {
          if (i > 0) histOut << ",";
          auto& [le, count] = snap.bucketCounts[i];
          histOut << "{\"le\":";
          if (std::isinf(le)) histOut << "\"+Inf\"";
          else histOut << "\"" << formatDouble(le) << "\"";
          histOut << ",\"count\":" << count << "}";
        }
        histOut << "],\"sum\":" << formatDouble(snap.sum)
                << ",\"count\":" << snap.count << "}";
        firstHistogram = false;
        break;
      }
      }
    }
    out << "],\"gauges\":[" << gaugeOut.str()
        << "],\"histograms\":[" << histOut.str() << "]}";
    return out.str();
  }

  /// \brief Export all metrics in Prometheus text exposition format.
  std::string prometheusExport() const
  {
    std::shared_lock lock(_mutex);
    std::ostringstream out;

    // Track which families have had their header emitted
    std::unordered_map<std::string, bool> headerEmitted;

    for (const auto& [key, metric] : _metrics)
    {
      std::string sName = sanitizeName(metric->name());

      // Emit # HELP and # TYPE once per family
      if (!headerEmitted[metric->name()])
      {
        std::string exportName = sName;
        std::string typeName;
        switch (metric->type())
        {
        case MetricType::COUNTER:
          typeName = "counter";
          exportName = counterExportName(sName);
          break;
        case MetricType::GAUGE:
          typeName = "gauge";
          break;
        case MetricType::HISTOGRAM:
          typeName = "histogram";
          break;
        }

        auto helpIt = _helpTexts.find(metric->name());
        if (helpIt != _helpTexts.end() && !helpIt->second.empty())
        {
          out << "# HELP " << exportName << " " << helpIt->second << "\n";
        }
        out << "# TYPE " << exportName << " " << typeName << "\n";
        headerEmitted[metric->name()] = true;
      }

      // Emit metric values
      switch (metric->type())
      {
      case MetricType::COUNTER:
      {
        auto& c = static_cast<Counter&>(*metric);
        out << counterExportName(sName) << promLabels(c.labels())
            << " " << formatDouble(c.value()) << "\n";
        break;
      }
      case MetricType::GAUGE:
      {
        auto& g = static_cast<Gauge&>(*metric);
        out << sName << promLabels(g.labels())
            << " " << formatDouble(g.value()) << "\n";
        break;
      }
      case MetricType::HISTOGRAM:
      {
        auto& h = static_cast<Histogram&>(*metric);
        auto snap = h.snapshot();
        for (const auto& [le, count] : snap.bucketCounts)
        {
          std::string leStr = std::isinf(le) ? "+Inf" : formatDouble(le);
          out << sName << "_bucket" << promLabelsWithLe(h.labels(), leStr)
              << " " << count << "\n";
        }
        out << sName << "_sum" << promLabels(h.labels())
            << " " << formatDouble(snap.sum) << "\n";
        out << sName << "_count" << promLabels(h.labels())
            << " " << snap.count << "\n";
        break;
      }
      }
    }
    return out.str();
  }

  /// \brief Returns the number of registered metric series.
  std::size_t size() const
  {
    std::shared_lock lock(_mutex);
    return _metrics.size();
  }

  /// \brief Returns the help text for a metric family (by name).
  std::string helpText(const std::string& name) const
  {
    std::shared_lock lock(_mutex);
    auto it = _helpTexts.find(name);
    return it != _helpTexts.end() ? it->second : "";
  }

private:
  template<typename T>
  T& getOrCreate(const std::string& name, Labels labels,
                  const std::string& help, MetricType expectedType)
  {
    std::sort(labels.begin(), labels.end());
    MetricKey key{name, labels};

    // Fast path: shared lock
    {
      std::shared_lock lock(_mutex);
      auto it = _metrics.find(key);
      if (it != _metrics.end())
      {
        if (it->second->type() != expectedType)
        {
          throw std::logic_error(
            "Metric '" + name + "' already registered as a different type");
        }
        return static_cast<T&>(*it->second);
      }
    }

    // Slow path: unique lock, re-check
    {
      std::unique_lock lock(_mutex);
      auto it = _metrics.find(key);
      if (it != _metrics.end())
      {
        if (it->second->type() != expectedType)
        {
          throw std::logic_error(
            "Metric '" + name + "' already registered as a different type");
        }
        return static_cast<T&>(*it->second);
      }

      if (_metrics.size() >= _maxSeries)
      {
        throw std::runtime_error(
          "MetricsRegistry: maxSeries limit (" + std::to_string(_maxSeries)
          + ") exceeded registering '" + name + "'");
      }

      updateHelpText(name, help);
      auto metric = std::make_unique<T>(name, labels, help);
      auto& ref = *metric;
      _metrics.emplace(std::move(key), std::move(metric));
      return ref;
    }
  }

  /// \brief Help text is per metric family (name). First-writer-wins.
  void updateHelpText(const std::string& name, const std::string& help)
  {
    if (!help.empty())
    {
      _helpTexts.emplace(name, help);
    }
  }

  // ── Export helpers ────────────────────────────────────────────────────────

  static std::string formatDouble(double v)
  {
    if (std::isinf(v)) return v > 0 ? "+Inf" : "-Inf";
    if (std::isnan(v)) return "NaN";
    std::ostringstream oss;
    oss << v;
    return oss.str();
  }

  static std::string sanitizeName(const std::string& name)
  {
    std::string result;
    result.reserve(name.size());
    for (std::size_t i = 0; i < name.size(); ++i)
    {
      char c = name[i];
      if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == ':')
      {
        result += c;
      }
      else if (c >= '0' && c <= '9')
      {
        if (i == 0)
        {
          result += '_';
        }
        result += c;
      }
      else
      {
        result += '_';
      }
    }
    return result;
  }

  static std::string escapeLabel(const std::string& value)
  {
    std::string result;
    result.reserve(value.size());
    for (char c : value)
    {
      switch (c)
      {
      case '\\': result += "\\\\"; break;
      case '"':  result += "\\\""; break;
      case '\n': result += "\\n"; break;
      default:   result += c; break;
      }
    }
    return result;
  }

  /// \brief Append _total for counters, avoiding double-suffix.
  static std::string counterExportName(const std::string& sanitized)
  {
    if (sanitized.size() >= 6
        && sanitized.compare(sanitized.size() - 6, 6, "_total") == 0)
    {
      return sanitized;
    }
    return sanitized + "_total";
  }

  /// \brief Sanitize a label name to match [a-zA-Z_][a-zA-Z0-9_]*
  static std::string sanitizeLabelName(const std::string& name)
  {
    std::string result;
    result.reserve(name.size());
    for (std::size_t i = 0; i < name.size(); ++i)
    {
      char c = name[i];
      if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_')
      {
        result += c;
      }
      else if (c >= '0' && c <= '9')
      {
        if (i == 0)
        {
          result += '_';
        }
        result += c;
      }
      else
      {
        result += '_';
      }
    }
    return result;
  }

  static std::string promLabels(const Labels& labels)
  {
    if (labels.empty())
    {
      return "";
    }
    std::string result = "{";
    for (std::size_t i = 0; i < labels.size(); ++i)
    {
      if (i > 0)
      {
        result += ",";
      }
      result += sanitizeLabelName(labels[i].first)
              + "=\"" + escapeLabel(labels[i].second) + "\"";
    }
    return result + "}";
  }

  static std::string promLabelsWithLe(const Labels& labels, const std::string& le)
  {
    std::string result = "{";
    for (const auto& [k, v] : labels)
    {
      result += sanitizeLabelName(k) + "=\"" + escapeLabel(v) + "\",";
    }
    return result + "le=\"" + le + "\"}";
  }

  static std::string escapeJson(const std::string& value)
  {
    std::string result;
    result.reserve(value.size());
    for (char c : value)
    {
      switch (c)
      {
      case '\\': result += "\\\\"; break;
      case '"':  result += "\\\""; break;
      case '\n': result += "\\n"; break;
      case '\r': result += "\\r"; break;
      case '\t': result += "\\t"; break;
      default:   result += c; break;
      }
    }
    return result;
  }

  static std::string jsonLabels(const Labels& labels)
  {
    std::string result = "{";
    for (std::size_t i = 0; i < labels.size(); ++i)
    {
      if (i > 0)
      {
        result += ",";
      }
      result += "\"" + escapeJson(labels[i].first) + "\":\""
              + escapeJson(labels[i].second) + "\"";
    }
    return result + "}";
  }

  mutable std::shared_mutex _mutex;
  std::unordered_map<MetricKey, std::unique_ptr<MetricBase>, MetricKeyHash> _metrics;
  std::unordered_map<std::string, std::string> _helpTexts;
  std::size_t _maxSeries = 10000;
};

} // namespace core
} // namespace iora
