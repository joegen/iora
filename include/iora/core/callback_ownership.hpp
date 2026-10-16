// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>

namespace iora
{
namespace core
{

namespace detail
{

/// \brief Per-thread state shared by CallbackOwner and CallbackGate.
struct CallbackThreadState
{
  std::string owner;
  std::multiset<std::string> admitted;
};

// Declared here, DEFINED ONCE in src/core/iora_core.cpp (PAT-3). Registration
// and dispatch code is compiled into plugin .so files loaded RTLD_LOCAL; a
// header-inline thread_local would give each image its own copy, so a host-side
// Scope would be invisible to a plugin-side registration.
#if defined(IORA_CORE_SHARED) || defined(IORA_CORE_BUILDING)
CallbackThreadState &callbackThreadState();
#else
inline CallbackThreadState &callbackThreadState()
{
  static thread_local CallbackThreadState state;
  return state;
}
#endif

} // namespace detail

/// \brief Names the owner of callbacks registered on the current thread.
class CallbackOwner
{
public:
  /// \brief Owner for a callback registered on this thread now; empty = unowned
  /// (never gated, never removed).
  static const std::string &current() noexcept { return detail::callbackThreadState().owner; }

  /// \brief RAII: while alive, current() returns `owner` on this thread. The
  /// previous value is restored on destruction, so scopes nest.
  class Scope
  {
  public:
    explicit Scope(std::string owner) noexcept : _previous(std::move(owner))
    {
      std::swap(_previous, detail::callbackThreadState().owner);
    }

    ~Scope() noexcept { std::swap(_previous, detail::callbackThreadState().owner); }

    Scope(const Scope &) = delete;
    Scope &operator=(const Scope &) = delete;

  private:
    std::string _previous;
  };
};

/// \brief Per-owner admission gate for owned callbacks. An owner can be closed
/// (later admits fail), drained (wait until no admission is alive) and opened.
class CallbackGate
{
public:
  /// \brief RAII result of admit(). Move-only. Destroy (and move-assign over)
  /// only on the thread that created it.
  class Admission
  {
  public:
    Admission() noexcept = default;

    Admission(Admission &&other) noexcept
        : _owner(std::move(other._owner)), _admitted(other._admitted)
    {
      other._admitted = false;
    }

    Admission &operator=(Admission &&other) noexcept
    {
      if (this != &other)
      {
        release();
        _owner = std::move(other._owner);
        _admitted = other._admitted;
        other._admitted = false;
      }
      return *this;
    }

    Admission(const Admission &) = delete;
    Admission &operator=(const Admission &) = delete;

    ~Admission() { release(); }

    /// \brief True = the callback may run.
    explicit operator bool() const noexcept { return _admitted; }

  private:
    friend class CallbackGate;

    Admission(std::string owner, bool admitted) noexcept
        : _owner(std::move(owner)), _admitted(admitted)
    {
    }

    void release() noexcept
    {
      if (_admitted && !_owner.empty())
      {
        auto &admitted = detail::callbackThreadState().admitted;
        auto it = admitted.find(_owner);
        if (it != admitted.end())
        {
          admitted.erase(it);
        }
        CallbackGate::leave(_owner);
      }
      _admitted = false;
    }

    std::string _owner;
    bool _admitted = false;
  };

  /// \brief Registry side. An empty owner is admitted with no accounting.
  /// Otherwise the result is not admitted if the owner is closed, and is counted
  /// in flight if it is admitted. Strong exception guarantee.
  [[nodiscard]] static Admission admit(const std::string &owner)
  {
    if (owner.empty())
    {
      return Admission(std::string(), true);
    }
    Admission result(owner, false);
    auto &admitted = detail::callbackThreadState().admitted;
    auto mine = admitted.insert(owner);
    bool closed = false;
    try
    {
      auto &g = gate();
      std::lock_guard<std::mutex> lock(g.mutex);
      auto &state = g.owners[owner];
      closed = state.closed;
      if (!closed)
      {
        ++state.inFlight;
      }
    }
    catch (...)
    {
      admitted.erase(mine);
      throw;
    }
    if (closed)
    {
      admitted.erase(mine);
      return result;
    }
    result._admitted = true;
    return result;
  }

  /// \brief Owner-lifecycle side: later admit(owner) calls fail. No-op for an
  /// empty owner.
  static void close(const std::string &owner)
  {
    if (owner.empty())
    {
      return;
    }
    auto &g = gate();
    std::lock_guard<std::mutex> lock(g.mutex);
    g.owners[owner].closed = true;
  }

  /// \brief Owner-lifecycle side: blocks until no admission of owner is alive
  /// (open or closed owner). The caller must hold no lock an admitted callback
  /// could need, and this thread must hold no admission of owner. No-op for an
  /// empty owner.
  static void drain(const std::string &owner)
  {
    if (owner.empty())
    {
      return;
    }
    auto &g = gate();
    std::unique_lock<std::mutex> lock(g.mutex);
    g.drained.wait(lock,
                   [&g, &owner]
                   {
                     auto it = g.owners.find(owner);
                     return it == g.owners.end() || it->second.inFlight == 0;
                   });
  }

  /// \brief Owner-lifecycle side: admit(owner) succeeds again. No-op for an
  /// empty owner. A lock failure leaves the owner closed.
  static void open(const std::string &owner) noexcept
  {
    if (owner.empty())
    {
      return;
    }
    try
    {
      auto &g = gate();
      std::lock_guard<std::mutex> lock(g.mutex);
      auto it = g.owners.find(owner);
      if (it != g.owners.end())
      {
        it->second.closed = false;
        if (it->second.inFlight == 0)
        {
          g.owners.erase(it);
        }
      }
    }
    catch (...)
    {
    }
  }

  /// \brief True while this thread holds an admission of owner, including an
  /// admitted entry whose callback has not run yet.
  static bool admittedOnThisThread(const std::string &owner) noexcept
  {
    return detail::callbackThreadState().admitted.count(owner) > 0;
  }

private:
  struct OwnerState
  {
    std::size_t inFlight = 0;
    bool closed = false;
  };

  // The gate mutex is a LEAF: no other lock is taken while it is held, no
  // callback runs under it, and nothing is logged under it. Registries call
  // admit() under their own mutex (registry -> gate); IoraService calls
  // close()/open() under _loadModulesMutex (L -> gate).
  struct Gate
  {
    std::mutex mutex;
    std::condition_variable drained;
    std::unordered_map<std::string, OwnerState> owners;
  };

#if defined(IORA_CORE_SHARED) || defined(IORA_CORE_BUILDING)
  static Gate &gate();
#else
  // IMMORTAL / deliberately-leaked (R-MEM-1), same as the out-of-line definition
  // in src/core/iora_core.cpp: a drain or leave may run during static
  // destruction.
  static Gate &gate()
  {
    static Gate *g = new Gate();
    return *g;
  }
#endif

  static void leave(const std::string &owner) noexcept
  {
    try
    {
      auto &g = gate();
      std::lock_guard<std::mutex> lock(g.mutex);
      auto it = g.owners.find(owner);
      if (it == g.owners.end() || it->second.inFlight == 0)
      {
        return;
      }
      if (--it->second.inFlight == 0)
      {
        // Notify UNDER the lock: a drain waiter may go on to dlclose the code
        // that owns this gate entry.
        g.drained.notify_all();
        if (!it->second.closed)
        {
          g.owners.erase(it);
        }
      }
    }
    catch (...)
    {
    }
  }
};

} // namespace core
} // namespace iora
