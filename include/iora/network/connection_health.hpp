// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include "iora/network/transport_types.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

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
  explicit ConnectionHealth(const HealthConfig &config = {})
      : _config(config), _lastActivity(std::chrono::steady_clock::now()), _consecutiveFailures(0),
        _state(ConnectionState::Healthy)
  {
  }

  void recordActivity()
  {
    _lastActivity.store(std::chrono::steady_clock::now(), std::memory_order_relaxed);

    // Reset failure count on successful activity
    if (_consecutiveFailures.load(std::memory_order_relaxed) > 0)
    {
      _consecutiveFailures.store(0, std::memory_order_relaxed);
      updateState();
    }
  }

  void recordFailure()
  {
    _consecutiveFailures.fetch_add(1, std::memory_order_relaxed);
    _totalFailures.fetch_add(1, std::memory_order_relaxed);
    updateState();
  }

  void recordSuccess()
  {
    _totalSuccesses.fetch_add(1, std::memory_order_relaxed);
    // Decrease consecutive failures on success
    int current = _consecutiveFailures.load(std::memory_order_relaxed);
    if (current > 0)
    {
      _consecutiveFailures.compare_exchange_weak(current, std::max(0, current - 1),
                                                 std::memory_order_relaxed);
      updateState();
    }
  }

  bool isHealthy() const
  {
    return _state.load(std::memory_order_relaxed) <= ConnectionState::Warning;
  }

  ConnectionState getState() const { return _state.load(std::memory_order_relaxed); }

  bool needsHeartbeat() const
  {
    if (!_config.enableHeartbeat)
      return false;

    auto now = std::chrono::steady_clock::now();
    auto lastActivity = _lastActivity.load(std::memory_order_relaxed);

    return (now - lastActivity) >= _config.heartbeatInterval;
  }

  bool isTimedOut() const
  {
    auto now = std::chrono::steady_clock::now();
    auto lastActivity = _lastActivity.load(std::memory_order_relaxed);

    return (now - lastActivity) >= _config.timeoutThreshold;
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
    auto lastActivity = _lastActivity.load(std::memory_order_relaxed);
    auto successes = _totalSuccesses.load(std::memory_order_relaxed);
    auto failures = _totalFailures.load(std::memory_order_relaxed);
    auto total = successes + failures;

    return {_state.load(std::memory_order_relaxed),
            _consecutiveFailures.load(std::memory_order_relaxed),
            successes,
            failures,
            std::chrono::duration_cast<std::chrono::milliseconds>(now - lastActivity),
            total > 0 ? static_cast<double>(successes) / total : 1.0};
  }

  void updateConfig(const HealthConfig &config) { _config = config; }

private:
  void updateState()
  {
    int failures = _consecutiveFailures.load(std::memory_order_relaxed);
    ConnectionState newState;

    if (failures == 0)
    {
      newState = ConnectionState::Healthy;
    }
    else if (failures == 1)
    {
      newState = ConnectionState::Warning;
    }
    else if (failures < _config.maxConsecutiveFailures)
    {
      newState = ConnectionState::Degraded;
    }
    else if (failures == _config.maxConsecutiveFailures)
    {
      newState = ConnectionState::Critical;
    }
    else
    {
      newState = ConnectionState::Unhealthy;
    }

    _state.store(newState, std::memory_order_relaxed);
  }

private:
  HealthConfig _config;
  std::atomic<std::chrono::steady_clock::time_point> _lastActivity;
  std::atomic<int> _consecutiveFailures;
  std::atomic<std::uint64_t> _totalSuccesses{0};
  std::atomic<std::uint64_t> _totalFailures{0};
  std::atomic<ConnectionState> _state;
};

// Health monitor for managing multiple connections
class HealthMonitor
{
public:
  explicit HealthMonitor(const HealthConfig &config = {}) : _config(config) {}

  void addConnection(SessionId id)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _connections[id] = std::make_unique<ConnectionHealth>(_config);
  }

  void removeConnection(SessionId id)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _connections.erase(id);
  }

  void recordActivity(SessionId id)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _connections.find(id);
    if (it != _connections.end())
    {
      it->second->recordActivity();
    }
  }

  void recordFailure(SessionId id)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _connections.find(id);
    if (it != _connections.end())
    {
      it->second->recordFailure();
    }
  }

  void recordSuccess(SessionId id)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _connections.find(id);
    if (it != _connections.end())
    {
      it->second->recordSuccess();
    }
  }

  std::vector<SessionId> getUnhealthyConnections() const
  {
    std::vector<SessionId> unhealthy;
    std::lock_guard<std::mutex> lock(_mutex);

    for (const auto &[id, health] : _connections)
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
    std::lock_guard<std::mutex> lock(_mutex);

    for (const auto &[id, health] : _connections)
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
    std::lock_guard<std::mutex> lock(_mutex);

    OverallStats stats{};
    stats.totalConnections = _connections.size();

    std::uint64_t totalSuccesses = 0;
    std::uint64_t totalFailures = 0;

    for (const auto &[id, health] : _connections)
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
    stats.overallSuccessRate = total > 0 ? static_cast<double>(totalSuccesses) / total : 1.0;

    return stats;
  }

  void updateConfig(const HealthConfig &config)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _config = config;
    for (auto &[id, health] : _connections)
    {
      health->updateConfig(config);
    }
  }

private:
  HealthConfig _config;
  mutable std::mutex _mutex;
  std::unordered_map<SessionId, std::unique_ptr<ConnectionHealth>> _connections;
};

} // namespace network
} // namespace iora