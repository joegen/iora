// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace iora
{
namespace common
{

/// Lifecycle state of a managed component
enum class LifecycleState
{
  Created,   ///< Initial state, not started
  Running,   ///< Normal operation
  Draining,  ///< Rejecting new work, completing in-flight
  Stopped,   ///< All work complete, event loops exited
  Reset      ///< Clean state, ready to restart
};

/// Statistics for drain operations
struct DrainStats
{
  std::uint32_t inFlightAtStart;  ///< Count when drain started
  std::uint32_t remaining;        ///< Count still in-flight
  std::uint32_t cancelled;        ///< Count explicitly cancelled
  std::uint32_t completed;        ///< Count that completed normally

  DrainStats() : inFlightAtStart(0), remaining(0), cancelled(0), completed(0) {}

  DrainStats(std::uint32_t inFlight, std::uint32_t rem, std::uint32_t canc, std::uint32_t comp)
      : inFlightAtStart(inFlight), remaining(rem), cancelled(canc), completed(comp)
  {
  }
};

/// Result of lifecycle operations with timeout support
struct LifecycleResult
{
  bool success;                            ///< Operation succeeded
  LifecycleState newState;                 ///< Resulting state
  std::string message;                     ///< Error/status message
  std::optional<DrainStats> drainStats;    ///< Counts for drain operations

  LifecycleResult() : success(false), newState(LifecycleState::Created), message("") {}

  LifecycleResult(bool succ, LifecycleState state, const std::string &msg)
      : success(succ), newState(state), message(msg)
  {
  }

  LifecycleResult(bool succ, LifecycleState state, const std::string &msg, const DrainStats &stats)
      : success(succ), newState(state), message(msg), drainStats(stats)
  {
  }
};

/// Common lifecycle management interface for all components
///
/// This interface provides a consistent way to manage the lifecycle of components
/// that need graceful shutdown and reset capabilities. Components implementing
/// this interface follow a state machine:
///
///   Created → Running → Draining → Stopped → Reset → (back to Created)
///
/// Key principles:
/// - drain() stops accepting new work and waits for in-flight work to complete
/// - stop() triggers drain of dependencies and exits event loops
/// - reset() returns component to clean state ready for restart
/// - All methods are thread-safe unless documented otherwise
class ILifecycleManaged
{
public:
  virtual ~ILifecycleManaged() = default;

  /// Start the component (Created → Running)
  ///
  /// This method initializes the component and transitions it to the Running state.
  /// After successful start(), the component is ready to accept and process work.
  ///
  /// @return Result indicating success and new state
  /// @throws May throw implementation-specific exceptions on initialization failure
  virtual LifecycleResult start() = 0;

  /// Begin graceful drain (Running → Draining)
  ///
  /// This method stops accepting new work immediately and waits synchronously
  /// for all in-flight work to complete. The behavior during drain depends on
  /// the component type:
  ///
  /// - ThreadPool: Waits for task queue to empty and all workers to become idle
  /// - Timer: Cancels or completes active timers and waits for callbacks to finish
  /// - Higher-level components: Implements component-specific cleanup (e.g., sending
  ///   SIP CANCEL/500 responses)
  ///
  /// This is a blocking call that returns when:
  /// 1. All in-flight work has completed, OR
  /// 2. The timeout expires
  ///
  /// @param timeoutMs Maximum time to wait in milliseconds (0 = wait indefinitely)
  /// @return Result with drain statistics showing completed vs remaining work
  virtual LifecycleResult drain(std::uint32_t timeoutMs = 30000) = 0;

  /// Stop the component (Draining → Stopped)
  ///
  /// This method triggers drain() on all dependencies (if any), then exits
  /// event loops and stops all background threads. It does NOT release resources;
  /// use reset() for that.
  ///
  /// For components with dependencies:
  /// - Transaction Layer calls drain() on Timer and ThreadPool
  /// - Higher layers call drain() on Transaction Layer
  ///
  /// @return Result indicating success and new state
  virtual LifecycleResult stop() = 0;

  /// Reset to clean state (Stopped → Reset)
  ///
  /// This method releases all resources, clears all state, and prepares the
  /// component for a potential restart via start(). After reset():
  /// - All internal data structures are cleared
  /// - All resource handles are released
  /// - Component is ready for start() to be called again
  ///
  /// @return Result indicating success and new state
  virtual LifecycleResult reset() = 0;

  /// Get current lifecycle state
  ///
  /// This method is thread-safe and can be called at any time to query the
  /// component's current state in the lifecycle state machine.
  ///
  /// @return Current lifecycle state
  virtual LifecycleState getState() const = 0;

  /// Get in-flight work count (for monitoring during drain)
  ///
  /// Returns the current count of work items that are either queued or actively
  /// being processed. This is useful for:
  /// - Monitoring drain progress
  /// - Health checks
  /// - Load balancing decisions
  ///
  /// The exact definition of "in-flight" is component-specific:
  /// - ThreadPool: _taskQueue.size() + _activeThreads
  /// - Timer: _activeTimers.size() + _callbacksExecuting
  /// - Transaction Layer: Number of non-terminated transactions
  ///
  /// @return Number of in-flight work items
  virtual std::uint32_t getInFlightCount() const = 0;
};

/// Helper function to convert LifecycleState to string
inline const char *lifecycleStateToString(LifecycleState state)
{
  switch (state)
  {
  case LifecycleState::Created:
    return "Created";
  case LifecycleState::Running:
    return "Running";
  case LifecycleState::Draining:
    return "Draining";
  case LifecycleState::Stopped:
    return "Stopped";
  case LifecycleState::Reset:
    return "Reset";
  default:
    return "Unknown";
  }
}

} // namespace common
} // namespace iora
