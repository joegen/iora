// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>

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
      : config_(config), state_(CircuitBreakerState::Closed), failureCount_(0), successCount_(0),
        lastFailureTime_(std::chrono::steady_clock::time_point{}), requestCount_(0)
  {
  }

  // Check if request should be allowed
  bool allowRequest()
  {
    auto now = std::chrono::steady_clock::now();

    switch (state_.load(std::memory_order_relaxed))
    {
    case CircuitBreakerState::Closed:
      return true;

    case CircuitBreakerState::Open:
    {
      auto lastFailure = lastFailureTime_.load(std::memory_order_relaxed);
      if (now - lastFailure >= config_.timeout)
      {
        // Transition to half-open
        auto expected = CircuitBreakerState::Open;
        if (state_.compare_exchange_strong(expected, CircuitBreakerState::HalfOpen,
                                           std::memory_order_relaxed))
        {
          successCount_.store(0, std::memory_order_relaxed);
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
    requestCount_.fetch_add(1, std::memory_order_relaxed);

    auto currentState = state_.load(std::memory_order_relaxed);

    if (currentState == CircuitBreakerState::HalfOpen)
    {
      int successes = successCount_.fetch_add(1, std::memory_order_relaxed) + 1;
      if (successes >= config_.successThreshold)
      {
        // Circuit recovered, close it
        state_.store(CircuitBreakerState::Closed, std::memory_order_relaxed);
        failureCount_.store(0, std::memory_order_relaxed);
        successCount_.store(0, std::memory_order_relaxed);
      }
    }
    else if (currentState == CircuitBreakerState::Closed)
    {
      // Reset failure count on success
      failureCount_.store(0, std::memory_order_relaxed);
    }
  }

  void recordFailure()
  {
    requestCount_.fetch_add(1, std::memory_order_relaxed);

    auto now = std::chrono::steady_clock::now();
    lastFailureTime_.store(now, std::memory_order_relaxed);

    int failures = failureCount_.fetch_add(1, std::memory_order_relaxed) + 1;

    auto currentState = state_.load(std::memory_order_relaxed);

    if (currentState == CircuitBreakerState::HalfOpen)
    {
      // Failed during testing, go back to open
      state_.store(CircuitBreakerState::Open, std::memory_order_relaxed);
      successCount_.store(0, std::memory_order_relaxed);
    }
    else if (currentState == CircuitBreakerState::Closed)
    {
      // Check if we should open the circuit
      if (shouldOpenCircuit(failures))
      {
        state_.store(CircuitBreakerState::Open, std::memory_order_relaxed);
      }
    }
  }

  CircuitBreakerState getState() const { return state_.load(std::memory_order_relaxed); }

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
    auto lastFailure = lastFailureTime_.load(std::memory_order_relaxed);
    auto failures = failureCount_.load(std::memory_order_relaxed);
    auto requests = requestCount_.load(std::memory_order_relaxed);

    return {state_.load(std::memory_order_relaxed),
            failures,
            successCount_.load(std::memory_order_relaxed),
            requests,
            std::chrono::duration_cast<std::chrono::milliseconds>(now - lastFailure),
            requests > 0 ? static_cast<double>(failures) / requests : 0.0};
  }

  void updateConfig(const CircuitBreakerConfig &config) { config_ = config; }

  void reset()
  {
    state_.store(CircuitBreakerState::Closed, std::memory_order_relaxed);
    failureCount_.store(0, std::memory_order_relaxed);
    successCount_.store(0, std::memory_order_relaxed);
    requestCount_.store(0, std::memory_order_relaxed);
    lastFailureTime_.store(std::chrono::steady_clock::time_point{}, std::memory_order_relaxed);
  }

private:
  bool shouldOpenCircuit(int failures) const
  {
    // Simple threshold-based check
    if (failures >= config_.failureThreshold)
    {
      return true;
    }

    // Failure rate based check
    auto requests = requestCount_.load(std::memory_order_relaxed);
    if (static_cast<int>(requests) >= config_.minimumRequests)
    {
      double failureRate = static_cast<double>(failures) / requests;
      return failureRate >= config_.failureRateThreshold;
    }

    return false;
  }

private:
  CircuitBreakerConfig config_;
  std::atomic<CircuitBreakerState> state_;
  std::atomic<int> failureCount_;
  std::atomic<int> successCount_;
  std::atomic<std::chrono::steady_clock::time_point> lastFailureTime_;
  std::atomic<std::uint64_t> requestCount_;
};

// Circuit breaker manager for different operations/endpoints
class CircuitBreakerManager
{
public:
  using BreakerFactory = std::function<std::unique_ptr<CircuitBreaker>()>;

  explicit CircuitBreakerManager(BreakerFactory factory = nullptr)
      : factory_(factory ? std::move(factory) : []() { return std::make_unique<CircuitBreaker>(); })
  {
  }

  CircuitBreaker &getBreaker(const std::string &name)
  {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = breakers_.find(name);
    if (it == breakers_.end())
    {
      auto [inserted, success] = breakers_.emplace(name, factory_());
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
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto &[name, breaker] : breakers_)
    {
      breaker->updateConfig(config);
    }
  }

  std::vector<std::string> getBreakerNames() const
  {
    std::vector<std::string> names;
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto &[name, breaker] : breakers_)
    {
      names.push_back(name);
    }

    return names;
  }

  void reset(const std::string &name) { getBreaker(name).reset(); }

  void resetAll()
  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto &[name, breaker] : breakers_)
    {
      breaker->reset();
    }
  }

private:
  mutable std::mutex mutex_;
  std::unordered_map<std::string, std::unique_ptr<CircuitBreaker>> breakers_;
  BreakerFactory factory_;
};

} // namespace network
} // namespace iora