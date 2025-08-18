// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <chrono>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include "transport_types.hpp"

namespace iora
{
namespace network
{

  struct HealthConfig
  {
    std::chrono::seconds heartbeatInterval{30};
    std::chrono::seconds timeoutThreshold{90};
    int maxConsecutiveFailures{3};
    bool enableHeartbeat{true};
  };

  enum class ConnectionState
  {
    Healthy,
    Warning,  // Some issues detected
    Degraded, // Consistent problems
    Critical, // Frequent failures
    Unhealthy // Should be closed
  };

  class ConnectionHealth
  {
  public:
    explicit ConnectionHealth(const HealthConfig& config = {})
      : config_(config),
        lastActivity_(std::chrono::steady_clock::now()),
        consecutiveFailures_(0),
        state_(ConnectionState::Healthy)
    {
    }

    void recordActivity()
    {
      lastActivity_.store(std::chrono::steady_clock::now(),
                          std::memory_order_relaxed);

      // Reset failure count on successful activity
      if (consecutiveFailures_.load(std::memory_order_relaxed) > 0)
      {
        consecutiveFailures_.store(0, std::memory_order_relaxed);
        updateState();
      }
    }

    void recordFailure()
    {
      consecutiveFailures_.fetch_add(1, std::memory_order_relaxed);
      totalFailures_.fetch_add(1, std::memory_order_relaxed);
      updateState();
    }

    void recordSuccess()
    {
      totalSuccesses_.fetch_add(1, std::memory_order_relaxed);
      // Decrease consecutive failures on success
      int current = consecutiveFailures_.load(std::memory_order_relaxed);
      if (current > 0)
      {
        consecutiveFailures_.compare_exchange_weak(
            current, std::max(0, current - 1), std::memory_order_relaxed);
        updateState();
      }
    }

    bool isHealthy() const
    {
      return state_.load(std::memory_order_relaxed) <= ConnectionState::Warning;
    }

    ConnectionState getState() const
    {
      return state_.load(std::memory_order_relaxed);
    }

    bool needsHeartbeat() const
    {
      if (!config_.enableHeartbeat)
        return false;

      auto now = std::chrono::steady_clock::now();
      auto lastActivity = lastActivity_.load(std::memory_order_relaxed);

      return (now - lastActivity) >= config_.heartbeatInterval;
    }

    bool isTimedOut() const
    {
      auto now = std::chrono::steady_clock::now();
      auto lastActivity = lastActivity_.load(std::memory_order_relaxed);

      return (now - lastActivity) >= config_.timeoutThreshold;
    }

    struct Stats
    {
      ConnectionState state;
      int consecutiveFailures;
      std::uint64_t totalSuccesses;
      std::uint64_t totalFailures;
      std::chrono::milliseconds timeSinceLastActivity;
      double successRate; // 0.0 to 1.0
    };

    Stats getStats() const
    {
      auto now = std::chrono::steady_clock::now();
      auto lastActivity = lastActivity_.load(std::memory_order_relaxed);
      auto successes = totalSuccesses_.load(std::memory_order_relaxed);
      auto failures = totalFailures_.load(std::memory_order_relaxed);
      auto total = successes + failures;

      return {state_.load(std::memory_order_relaxed),
              consecutiveFailures_.load(std::memory_order_relaxed),
              successes,
              failures,
              std::chrono::duration_cast<std::chrono::milliseconds>(
                  now - lastActivity),
              total > 0 ? static_cast<double>(successes) / total : 1.0};
    }

    void updateConfig(const HealthConfig& config) { config_ = config; }

  private:
    void updateState()
    {
      int failures = consecutiveFailures_.load(std::memory_order_relaxed);
      ConnectionState newState;

      if (failures == 0)
      {
        newState = ConnectionState::Healthy;
      }
      else if (failures == 1)
      {
        newState = ConnectionState::Warning;
      }
      else if (failures < config_.maxConsecutiveFailures)
      {
        newState = ConnectionState::Degraded;
      }
      else if (failures == config_.maxConsecutiveFailures)
      {
        newState = ConnectionState::Critical;
      }
      else
      {
        newState = ConnectionState::Unhealthy;
      }

      state_.store(newState, std::memory_order_relaxed);
    }

  private:
    HealthConfig config_;
    std::atomic<std::chrono::steady_clock::time_point> lastActivity_;
    std::atomic<int> consecutiveFailures_;
    std::atomic<std::uint64_t> totalSuccesses_{0};
    std::atomic<std::uint64_t> totalFailures_{0};
    std::atomic<ConnectionState> state_;
  };

  // Health monitor for managing multiple connections
  class HealthMonitor
  {
  public:
    explicit HealthMonitor(const HealthConfig& config = {}) : config_(config) {}

    void addConnection(SessionId id)
    {
      std::lock_guard<std::mutex> lock(mutex_);
      connections_[id] = std::make_unique<ConnectionHealth>(config_);
    }

    void removeConnection(SessionId id)
    {
      std::lock_guard<std::mutex> lock(mutex_);
      connections_.erase(id);
    }

    void recordActivity(SessionId id)
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto it = connections_.find(id);
      if (it != connections_.end())
      {
        it->second->recordActivity();
      }
    }

    void recordFailure(SessionId id)
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto it = connections_.find(id);
      if (it != connections_.end())
      {
        it->second->recordFailure();
      }
    }

    void recordSuccess(SessionId id)
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto it = connections_.find(id);
      if (it != connections_.end())
      {
        it->second->recordSuccess();
      }
    }

    std::vector<SessionId> getUnhealthyConnections() const
    {
      std::vector<SessionId> unhealthy;
      std::lock_guard<std::mutex> lock(mutex_);

      for (const auto& [id, health] : connections_)
      {
        if (!health->isHealthy())
        {
          unhealthy.push_back(id);
        }
      }

      return unhealthy;
    }

    std::vector<SessionId> getConnectionsNeedingHeartbeat() const
    {
      std::vector<SessionId> needHeartbeat;
      std::lock_guard<std::mutex> lock(mutex_);

      for (const auto& [id, health] : connections_)
      {
        if (health->needsHeartbeat())
        {
          needHeartbeat.push_back(id);
        }
      }

      return needHeartbeat;
    }

    struct OverallStats
    {
      std::size_t totalConnections;
      std::size_t healthyConnections;
      std::size_t warningConnections;
      std::size_t degradedConnections;
      std::size_t criticalConnections;
      std::size_t unhealthyConnections;
      double overallSuccessRate;
    };

    OverallStats getOverallStats() const
    {
      std::lock_guard<std::mutex> lock(mutex_);

      OverallStats stats{};
      stats.totalConnections = connections_.size();

      std::uint64_t totalSuccesses = 0;
      std::uint64_t totalFailures = 0;

      for (const auto& [id, health] : connections_)
      {
        auto connStats = health->getStats();
        totalSuccesses += connStats.totalSuccesses;
        totalFailures += connStats.totalFailures;

        switch (connStats.state)
        {
        case ConnectionState::Healthy:
          stats.healthyConnections++;
          break;
        case ConnectionState::Warning:
          stats.warningConnections++;
          break;
        case ConnectionState::Degraded:
          stats.degradedConnections++;
          break;
        case ConnectionState::Critical:
          stats.criticalConnections++;
          break;
        case ConnectionState::Unhealthy:
          stats.unhealthyConnections++;
          break;
        }
      }

      auto total = totalSuccesses + totalFailures;
      stats.overallSuccessRate =
          total > 0 ? static_cast<double>(totalSuccesses) / total : 1.0;

      return stats;
    }

    void updateConfig(const HealthConfig& config)
    {
      config_ = config;
      std::lock_guard<std::mutex> lock(mutex_);
      for (auto& [id, health] : connections_)
      {
        health->updateConfig(config);
      }
    }

  private:
    HealthConfig config_;
    mutable std::mutex mutex_;
    std::unordered_map<SessionId, std::unique_ptr<ConnectionHealth>>
        connections_;
  };

} // namespace network
} // namespace iora