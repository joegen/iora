// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include "iora/core/atomic_thread_id.hpp"

#include <algorithm>
#include <atomic>
#include <functional>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

namespace iora {
namespace core {

/// \brief Generic, type-safe finite state machine with fluent builder.
///
/// Template params:
/// - StateEnum: enum class for states
/// - EventEnum: enum class for events
/// - Context: optional event payload type (default void)
///
/// Thread safety: atomic state reads, mutex-protected transitions.
/// Callbacks (guard, onTransition action, onEnter, onExit, onEnterForce,
/// onExitForce, onAnyTransition) run while the transition mutex is held.
/// Calling processEvent or forceState of the same machine from any of them
/// throws std::logic_error; use Builder::thenEvent for a fixed follow-up, or
/// make the call after processEvent returns. Lock order: the mutex is taken
/// before any lock a callback takes; a callback must not take a lock that a
/// caller of this machine may hold while calling processEvent/forceState, and
/// must not wait on another thread that calls into this machine. Callbacks
/// must be short and non-blocking; they delay every other caller.
/// Exceptions: an exception from any callback (including that
/// std::logic_error, if the callback does not catch it) propagates; the mutex
/// and the re-entry stamp are released; the state is as of the last commit (an
/// action that throws after onExit leaves the state at 'from' with onExit
/// already run); the rest of that leg, the observer and the follow-up are
/// skipped.
/// Only obtainable via Builder::build().
template<typename StateEnum, typename EventEnum, typename Context = void>
class StateMachine
{
  // Context-dependent callback types.
  // Cannot use conditional_t<is_void_v<Context>, fn<void()>, fn<void(const Context&)>>
  // because both branches are instantiated and const void& is ill-formed.
  // Use a helper that only forms the reference when Context is non-void.
  template<typename C, typename = void>
  struct ContextTypes
  {
    using GuardFn = std::function<bool(const C&)>;
    using ActionFn = std::function<void(const C&)>;
    using EnterExitFn = std::function<void(const C&)>;
  };

  template<typename C>
  struct ContextTypes<C, std::enable_if_t<std::is_void_v<C>>>
  {
    using GuardFn = std::function<bool()>;
    using ActionFn = std::function<void()>;
    using EnterExitFn = std::function<void()>;
  };

  using GuardFn = typename ContextTypes<Context>::GuardFn;
  using ActionFn = typename ContextTypes<Context>::ActionFn;
  using EnterExitFn = typename ContextTypes<Context>::EnterExitFn;

  // Context-free callbacks (forceState, onAnyTransition)
  using VoidFn = std::function<void()>;
  using TransitionLogFn = std::function<void(StateEnum, EventEnum, StateEnum)>;

  struct TransitionRule
  {
    StateEnum from;
    EventEnum event;
    StateEnum to;
    GuardFn guard;
    ActionFn action;
    std::optional<EventEnum> thenEvent;
  };

public:
  // Deleted default constructor — only obtainable via Builder::build()
  StateMachine() = delete;

  // Non-copyable. Movable only before the machine is shared.
  StateMachine(const StateMachine&) = delete;
  StateMachine& operator=(const StateMachine&) = delete;
  /// \brief The source must be unpublished and quiescent; the move is not
  /// synchronized.
  StateMachine(StateMachine&& other) noexcept
    : _rules(std::move(other._rules))
    , _state(other._state.load(std::memory_order_relaxed))
    , _onEnter(std::move(other._onEnter))
    , _onExit(std::move(other._onExit))
    , _onAnyTransition(std::move(other._onAnyTransition))
    , _forceOnEnter(std::move(other._forceOnEnter))
    , _forceOnExit(std::move(other._forceOnExit))
  {
  }
  StateMachine& operator=(StateMachine&&) = delete;

  // ── Builder ──────────────────────────────────────────────────────────────

  class Builder
  {
  public:
    Builder() = default;

    Builder& initialState(StateEnum state)
    {
      _initialState = state;
      _hasInitialState = true;
      return *this;
    }

    Builder& transition(StateEnum from, EventEnum event, StateEnum to)
    {
      _rules.push_back({from, event, to, nullptr, nullptr, std::nullopt});
      return *this;
    }

    /// \brief Attach a guard to the most recently added transition.
    /// Runs under the transition mutex; see the class thread-safety notes.
    Builder& guard(GuardFn fn)
    {
      if (!_rules.empty())
      {
        _rules.back().guard = std::move(fn);
      }
      return *this;
    }

    /// \brief Attach an action to the most recently added transition.
    /// Runs under the transition mutex; see the class thread-safety notes.
    Builder& onTransition(ActionFn fn)
    {
      if (!_rules.empty())
      {
        _rules.back().action = std::move(fn);
      }
      return *this;
    }

    /// \brief Fire a follow-up event after the transition completes.
    /// The mutex is released before re-entering processEvent. Best effort
    /// under concurrency: another caller can act between the legs, so the
    /// follow-up may match no rule or a different rule; processEvent still
    /// returns true (it reports only the first leg). A thenEvent cycle
    /// recurses without bound and overflows the stack, so do not build one.
    Builder& thenEvent(EventEnum followUp)
    {
      if (!_rules.empty())
      {
        _rules.back().thenEvent = followUp;
      }
      return *this;
    }

    /// \brief Register a per-state entry callback.
    /// Runs under the transition mutex; see the class thread-safety notes.
    Builder& onEnter(StateEnum state, EnterExitFn fn)
    {
      _onEnter.push_back({state, std::move(fn)});
      return *this;
    }

    /// \brief Register a per-state exit callback.
    /// Runs under the transition mutex; see the class thread-safety notes.
    Builder& onExit(StateEnum state, EnterExitFn fn)
    {
      _onExit.push_back({state, std::move(fn)});
      return *this;
    }

    /// \brief Register a context-free entry callback for forceState.
    /// Runs under the transition mutex; see the class thread-safety notes.
    Builder& onEnterForce(StateEnum state, VoidFn fn)
    {
      _forceOnEnter.push_back({state, std::move(fn)});
      return *this;
    }

    /// \brief Register a context-free exit callback for forceState.
    /// Runs under the transition mutex; see the class thread-safety notes.
    Builder& onExitForce(StateEnum state, VoidFn fn)
    {
      _forceOnExit.push_back({state, std::move(fn)});
      return *this;
    }

    /// \brief Register a global transition observer (logging/metrics).
    /// Runs under the transition mutex, once per committed processEvent leg,
    /// after onEnter and before the thenEvent follow-up; calls are serialized
    /// and in commit order. forceState never calls it. Calling processEvent or
    /// forceState of the same machine from it throws std::logic_error.
    Builder& onAnyTransition(TransitionLogFn fn)
    {
      _onAnyTransition = std::move(fn);
      return *this;
    }

    /// \brief Build the state machine. Throws if initialState not set.
    StateMachine build()
    {
      if (!_hasInitialState)
      {
        throw std::logic_error(
          "StateMachine::Builder::build(): initialState not set");
      }

      // Stable sort by (from, event) for equal_range lookup
      std::stable_sort(_rules.begin(), _rules.end(), &StateMachine::ruleLess);

      return StateMachine(
        _initialState,
        std::move(_rules),
        std::move(_onEnter),
        std::move(_onExit),
        std::move(_onAnyTransition),
        std::move(_forceOnEnter),
        std::move(_forceOnExit));
    }

  private:
    StateEnum _initialState{};
    bool _hasInitialState = false;
    std::vector<TransitionRule> _rules;
    std::vector<std::pair<StateEnum, EnterExitFn>> _onEnter;
    std::vector<std::pair<StateEnum, EnterExitFn>> _onExit;
    TransitionLogFn _onAnyTransition;
    std::vector<std::pair<StateEnum, VoidFn>> _forceOnEnter;
    std::vector<std::pair<StateEnum, VoidFn>> _forceOnExit;
  };

  // ── Runtime API ──────────────────────────────────────────────────────────

  /// \brief Current state (atomic, lock-free).
  StateEnum currentState() const noexcept
  {
    return _state.load(std::memory_order_acquire);
  }

  /// \brief Check if in a specific state (atomic, lock-free).
  bool isInState(StateEnum s) const noexcept
  {
    return currentState() == s;
  }

  /// \brief Process an event (Context = void variant).
  template<typename C = Context>
  std::enable_if_t<std::is_void_v<C>, bool>
  processEvent(EventEnum event)
  {
    throwIfReentrant();
    std::optional<EventEnum> followUp;
    {
      OwnerRecordingLock lock(_mutex, _mutexOwner);
      auto current = _state.load(std::memory_order_relaxed);

      // Find matching transition via equal_range
      auto [begin, end] = findRules(current, event);
      const TransitionRule* matched = nullptr;
      for (auto it = begin; it != end; ++it)
      {
        if (!it->guard || it->guard())
        {
          matched = &(*it);
          break;
        }
      }

      if (!matched)
      {
        return false;
      }

      // Execute: onExit → action → state commit → onEnter
      fireOnExit(current);
      if (matched->action)
      {
        matched->action();
      }
      _state.store(matched->to, std::memory_order_release);
      fireOnEnter(matched->to);
      followUp = matched->thenEvent;

      if (_onAnyTransition)
      {
        _onAnyTransition(current, event, matched->to);
      }
    }

    // thenEvent: release mutex, then re-enter
    if (followUp)
    {
      processEvent(*followUp);
    }
    return true;
  }

  /// \brief Process an event with context (Context != void variant).
  template<typename C = Context>
  std::enable_if_t<!std::is_void_v<C>, bool>
  processEvent(EventEnum event, const C& ctx)
  {
    throwIfReentrant();
    std::optional<EventEnum> followUp;
    {
      OwnerRecordingLock lock(_mutex, _mutexOwner);
      auto current = _state.load(std::memory_order_relaxed);

      auto [begin, end] = findRules(current, event);
      const TransitionRule* matched = nullptr;
      for (auto it = begin; it != end; ++it)
      {
        if (!it->guard || it->guard(ctx))
        {
          matched = &(*it);
          break;
        }
      }

      if (!matched)
      {
        return false;
      }

      fireOnExit(current, ctx);
      if (matched->action)
      {
        matched->action(ctx);
      }
      _state.store(matched->to, std::memory_order_release);
      fireOnEnter(matched->to, ctx);
      followUp = matched->thenEvent;

      if (_onAnyTransition)
      {
        _onAnyTransition(current, event, matched->to);
      }
    }

    if (followUp)
    {
      processEvent(*followUp, ctx);
    }
    return true;
  }

  /// \brief Force a state change, bypassing the transition table.
  /// Fires context-free onExitForce/onEnterForce callbacks.
  /// Under mutex.
  void forceState(StateEnum newState)
  {
    throwIfReentrant();
    OwnerRecordingLock lock(_mutex, _mutexOwner);
    auto current = _state.load(std::memory_order_relaxed);
    fireForceOnExit(current);
    _state.store(newState, std::memory_order_release);
    fireForceOnEnter(newState);
  }

private:
  /// Owns the transition lock and the re-entry stamp, so 'lock -> stamp' and
  /// 'clear -> unlock' hold on every exit path.
  class OwnerRecordingLock
  {
  public:
    OwnerRecordingLock(std::mutex& m, iora::core::AtomicThreadId& owner)
      : _lock(m)
      , _owner(owner)
    {
      _owner.stamp();
    }

    ~OwnerRecordingLock()
    {
      _owner.clear();
    }

    OwnerRecordingLock(const OwnerRecordingLock&) = delete;
    OwnerRecordingLock& operator=(const OwnerRecordingLock&) = delete;

  private:
    std::lock_guard<std::mutex> _lock;
    iora::core::AtomicThreadId& _owner;
  };

  void throwIfReentrant() const
  {
    if (_mutexOwner.isCurrentThread())
    {
      throw std::logic_error(
        "StateMachine: processEvent/forceState called from a callback of the same machine; use "
        "Builder::thenEvent for a fixed follow-up, or make the call after processEvent returns");
    }
  }

  StateMachine(
    StateEnum initialState,
    std::vector<TransitionRule> rules,
    std::vector<std::pair<StateEnum, EnterExitFn>> onEnter,
    std::vector<std::pair<StateEnum, EnterExitFn>> onExit,
    TransitionLogFn onAnyTransition,
    std::vector<std::pair<StateEnum, VoidFn>> forceOnEnter,
    std::vector<std::pair<StateEnum, VoidFn>> forceOnExit)
    : _rules(std::move(rules))
    , _state(initialState)
    , _onEnter(std::move(onEnter))
    , _onExit(std::move(onExit))
    , _onAnyTransition(std::move(onAnyTransition))
    , _forceOnEnter(std::move(forceOnEnter))
    , _forceOnExit(std::move(forceOnExit))
  {
  }

  std::pair<
    typename std::vector<TransitionRule>::const_iterator,
    typename std::vector<TransitionRule>::const_iterator>
  findRules(StateEnum state, EventEnum event) const
  {
    TransitionRule key{state, event, {}, nullptr, nullptr, std::nullopt};
    return std::equal_range(_rules.begin(), _rules.end(), key,
      &StateMachine::ruleLess);
  }

  /// \brief Strict-weak ordering on (from, event). Single source of truth for
  /// both the build-time stable_sort and the lookup-time equal_range, so the
  /// two can never drift apart.
  static bool ruleLess(const TransitionRule& a, const TransitionRule& b)
  {
    if (a.from != b.from)
    {
      return a.from < b.from;
    }
    return a.event < b.event;
  }

  // Context-aware onEnter/onExit (for processEvent)
  template<typename... Args>
  void fireOnEnter(StateEnum state, Args&&... args)
  {
    for (const auto& [s, fn] : _onEnter)
    {
      if (s == state && fn)
      {
        fn(std::forward<Args>(args)...);
      }
    }
  }

  template<typename... Args>
  void fireOnExit(StateEnum state, Args&&... args)
  {
    for (const auto& [s, fn] : _onExit)
    {
      if (s == state && fn)
      {
        fn(std::forward<Args>(args)...);
      }
    }
  }

  // Context-free onEnter/onExit (for forceState)
  void fireForceOnEnter(StateEnum state)
  {
    for (const auto& [s, fn] : _forceOnEnter)
    {
      if (s == state && fn)
      {
        fn();
      }
    }
  }

  void fireForceOnExit(StateEnum state)
  {
    for (const auto& [s, fn] : _forceOnExit)
    {
      if (s == state && fn)
      {
        fn();
      }
    }
  }

  std::vector<TransitionRule> _rules;
  std::atomic<StateEnum> _state;
  std::vector<std::pair<StateEnum, EnterExitFn>> _onEnter;
  std::vector<std::pair<StateEnum, EnterExitFn>> _onExit;
  TransitionLogFn _onAnyTransition;
  std::vector<std::pair<StateEnum, VoidFn>> _forceOnEnter;
  std::vector<std::pair<StateEnum, VoidFn>> _forceOnExit;
  // Transition mutex: held while every callback runs. Re-entry, lock-order and exception contract: see the class thread-safety notes.
  mutable std::mutex _mutex;
  // Written only by the _mutex holder: stamped after lock, cleared before unlock.
  iora::core::AtomicThreadId _mutexOwner;
};

} // namespace core
} // namespace iora
