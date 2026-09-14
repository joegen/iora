// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace iora
{
namespace network
{

struct CircuitBreakerConfig
{
  int failureThreshold{5};                    // Failures to trigger open state
  std::chrono::seconds timeout{60};           // Time to wait before trying again
  int successThreshold{3};                    // Successes needed to close circuit
  std::chrono::seconds statisticsWindow{300}; // Window for calculating failure rate
  double failureRateThreshold{0.5};           // Failure rate (0.0-1.0) to trigger open
  int minimumRequests{10};                    // Minimum requests before considering failure rate
};

enum class CircuitBreakerState
{
  Closed,  // Normal operation
  Open,    // Failing fast, not allowing requests
  HalfOpen // Testing if service has recovered
};

class CircuitBreaker
{
public:
  explicit CircuitBreaker(const CircuitBreakerConfig &config = {})
      : _config(config), _state(CircuitBreakerState::Closed), _failureCount(0), _successCount(0),
        _lastFailureTime(std::chrono::steady_clock::time_point{}), _requestCount(0)
  {
  }

  // Check if request should be allowed
  bool allowRequest()
  {
    auto now = std::chrono::steady_clock::now();

    switch (_state.load(std::memory_order_relaxed))
    {
    case CircuitBreakerState::Closed:
      return true;

    case CircuitBreakerState::Open:
    {
      auto lastFailure = _lastFailureTime.load(std::memory_order_relaxed);
      if (now - lastFailure >= _config.timeout)
      {
        // Transition to half-open
        auto expected = CircuitBreakerState::Open;
        if (_state.compare_exchange_strong(expected, CircuitBreakerState::HalfOpen,
                                           std::memory_order_relaxed))
        {
          _successCount.store(0, std::memory_order_relaxed);
        }
        return true;
      }
      return false;
    }

    case CircuitBreakerState::HalfOpen:
      // Allow limited requests to test recovery
      return true;

    default:
      return false;
    }
  }

  void recordSuccess()
  {
    _requestCount.fetch_add(1, std::memory_order_relaxed);

    auto currentState = _state.load(std::memory_order_relaxed);

    if (currentState == CircuitBreakerState::HalfOpen)
    {
      int successes = _successCount.fetch_add(1, std::memory_order_relaxed) + 1;
      if (successes >= _config.successThreshold)
      {
        // Circuit recovered, close it
        _state.store(CircuitBreakerState::Closed, std::memory_order_relaxed);
        _failureCount.store(0, std::memory_order_relaxed);
        _successCount.store(0, std::memory_order_relaxed);
      }
    }
    else if (currentState == CircuitBreakerState::Closed)
    {
      // Reset failure count on success
      _failureCount.store(0, std::memory_order_relaxed);
    }
  }

  void recordFailure()
  {
    _requestCount.fetch_add(1, std::memory_order_relaxed);

    auto now = std::chrono::steady_clock::now();
    _lastFailureTime.store(now, std::memory_order_relaxed);

    int failures = _failureCount.fetch_add(1, std::memory_order_relaxed) + 1;

    auto currentState = _state.load(std::memory_order_relaxed);

    if (currentState == CircuitBreakerState::HalfOpen)
    {
      // Failed during testing, go back to open
      _state.store(CircuitBreakerState::Open, std::memory_order_relaxed);
      _successCount.store(0, std::memory_order_relaxed);
    }
    else if (currentState == CircuitBreakerState::Closed)
    {
      // Check if we should open the circuit
      if (shouldOpenCircuit(failures))
      {
        _state.store(CircuitBreakerState::Open, std::memory_order_relaxed);
      }
    }
  }

  CircuitBreakerState getState() const { return _state.load(std::memory_order_relaxed); }

  struct Stats
  {
    CircuitBreakerState state;
    int failureCount;
    int successCount;
    std::uint64_t totalRequests;
    std::chrono::milliseconds timeSinceLastFailure;
    double failureRate;
  };

  Stats getStats() const
  {
    auto now = std::chrono::steady_clock::now();
    auto lastFailure = _lastFailureTime.load(std::memory_order_relaxed);
    auto failures = _failureCount.load(std::memory_order_relaxed);
    auto requests = _requestCount.load(std::memory_order_relaxed);

    return {_state.load(std::memory_order_relaxed),
            failures,
            _successCount.load(std::memory_order_relaxed),
            requests,
            std::chrono::duration_cast<std::chrono::milliseconds>(now - lastFailure),
            requests > 0 ? static_cast<double>(failures) / requests : 0.0};
  }

  void updateConfig(const CircuitBreakerConfig &config) { _config = config; }

  void reset()
  {
    _state.store(CircuitBreakerState::Closed, std::memory_order_relaxed);
    _failureCount.store(0, std::memory_order_relaxed);
    _successCount.store(0, std::memory_order_relaxed);
    _requestCount.store(0, std::memory_order_relaxed);
    _lastFailureTime.store(std::chrono::steady_clock::time_point{}, std::memory_order_relaxed);
  }

private:
  bool shouldOpenCircuit(int failures) const
  {
    // Simple threshold-based check
    if (failures >= _config.failureThreshold)
    {
      return true;
    }

    // Failure rate based check
    auto requests = _requestCount.load(std::memory_order_relaxed);
    if (static_cast<int>(requests) >= _config.minimumRequests)
    {
      double failureRate = static_cast<double>(failures) / requests;
      return failureRate >= _config.failureRateThreshold;
    }

    return false;
  }

private:
  CircuitBreakerConfig _config;
  std::atomic<CircuitBreakerState> _state;
  std::atomic<int> _failureCount;
  std::atomic<int> _successCount;
  std::atomic<std::chrono::steady_clock::time_point> _lastFailureTime;
  std::atomic<std::uint64_t> _requestCount;
};

// Circuit breaker manager for different operations/endpoints
class CircuitBreakerManager
{
public:
  using BreakerFactory = std::function<std::unique_ptr<CircuitBreaker>()>;

  explicit CircuitBreakerManager(BreakerFactory factory = nullptr)
      : _factory(factory ? std::move(factory) : []() { return std::make_unique<CircuitBreaker>(); })
  {
  }

  CircuitBreaker &getBreaker(const std::string &name)
  {
    std::lock_guard<std::mutex> lock(_mutex);

    auto it = _breakers.find(name);
    if (it == _breakers.end())
    {
      auto [inserted, success] = _breakers.emplace(name, _factory());
      return *inserted->second;
    }

    return *it->second;
  }

  bool allowRequest(const std::string &name) { return getBreaker(name).allowRequest(); }

  void recordSuccess(const std::string &name) { getBreaker(name).recordSuccess(); }

  void recordFailure(const std::string &name) { getBreaker(name).recordFailure(); }

  CircuitBreakerState getState(const std::string &name) { return getBreaker(name).getState(); }

  void updateConfig(const std::string &name, const CircuitBreakerConfig &config)
  {
    getBreaker(name).updateConfig(config);
  }

  void updateAllConfigs(const CircuitBreakerConfig &config)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    for (auto &[name, breaker] : _breakers)
    {
      breaker->updateConfig(config);
    }
  }

  std::vector<std::string> getBreakerNames() const
  {
    std::vector<std::string> names;
    std::lock_guard<std::mutex> lock(_mutex);

    for (const auto &[name, breaker] : _breakers)
    {
      names.push_back(name);
    }

    return names;
  }

  void reset(const std::string &name) { getBreaker(name).reset(); }

  void resetAll()
  {
    std::lock_guard<std::mutex> lock(_mutex);
    for (auto &[name, breaker] : _breakers)
    {
      breaker->reset();
    }
  }

private:
  mutable std::mutex _mutex;
  std::unordered_map<std::string, std::unique_ptr<CircuitBreaker>> _breakers;
  BreakerFactory _factory;
};

} // namespace network
} // namespace iora