// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <atomic>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace iora {
namespace core {

/// \brief ConnectionId for tracking signal-slot connections.
using ConnectionId = std::uint64_t;

/// \brief Typed signal with COW slot list for zero-allocation emission.
///
/// Supports multiple subscribers, weak_ptr auto-disconnect, per-slot
/// exception handling, and ScopedConnection RAII.
///
/// Thread safety: emit() is lock-free (COW snapshot). connect/disconnect
/// take a mutex. Slots can safely call connect/disconnect on the same
/// Signal during emit without deadlock.
///
/// Non-copyable, non-movable.
template<typename... Args>
class Signal
{
public:
  class ScopedConnection;

  Signal()
    : _slots(std::make_shared<SlotList>())
    , _nextId{1}
    , _needsPrune{false}
  {
  }

  // Non-copyable, non-movable
  Signal(const Signal&) = delete;
  Signal& operator=(const Signal&) = delete;
  Signal(Signal&&) = delete;
  Signal& operator=(Signal&&) = delete;

  ~Signal() = default;

  /// \brief Connect a callable slot. Returns a ConnectionId for disconnect.
  ConnectionId connect(std::function<void(const Args&...)> fn)
  {
    std::lock_guard lock(_mutex);
    auto newList = cloneSlots();
    auto id = _nextId.fetch_add(1, std::memory_order_relaxed);
    newList->push_back(Slot{std::move(fn), std::weak_ptr<void>{}, id, false});
    std::atomic_store(&_slots, std::move(newList));
    return id;
  }

  /// \brief Connect a member function via weak_ptr. Auto-disconnects when
  /// the target object is destroyed.
  template<typename T>
  ConnectionId connect(std::weak_ptr<T> instance,
                       void (T::*method)(const Args&...))
  {
    std::weak_ptr<void> weakRef = instance;
    auto fn = [instance, method](const Args&... args)
    {
      if (auto sp = instance.lock())
      {
        (sp.get()->*method)(args...);
      }
    };
    std::lock_guard lock(_mutex);
    auto newList = cloneSlots();
    auto id = _nextId.fetch_add(1, std::memory_order_relaxed);
    newList->push_back(Slot{std::move(fn), std::move(weakRef), id, true});
    std::atomic_store(&_slots, std::move(newList));
    return id;
  }

  /// \brief Disconnect a slot by ConnectionId. No-op if not found.
  void disconnect(ConnectionId id)
  {
    std::lock_guard lock(_mutex);
    auto newList = cloneSlots();
    newList->erase(
      std::remove_if(newList->begin(), newList->end(),
        [id](const Slot& s) { return s.id == id; }),
      newList->end());
    std::atomic_store(&_slots, std::move(newList));
  }

  /// \brief Disconnect all slots.
  void disconnectAll()
  {
    std::lock_guard lock(_mutex);
    std::atomic_store(&_slots, std::make_shared<SlotList>());
  }

  /// \brief Number of connected slots (includes expired weak_ptr slots
  /// that have not yet been pruned).
  std::size_t connectionCount() const
  {
    auto snapshot = std::atomic_load(&_slots);
    return snapshot->size();
  }

  /// \brief True if no slots connected.
  bool empty() const
  {
    return connectionCount() == 0;
  }

  /// \brief Emit the signal to all connected slots.
  /// Lock-free: reads a COW snapshot. Per-slot try/catch.
  /// Expired weak_ptr slots are skipped and pruned after iteration.
  void emit(const Args&... args)
  {
    auto snapshot = std::atomic_load(&_slots);
    auto exHandler = std::atomic_load(&_exceptionHandler);
    bool anyExpired = false;

    for (const auto& slot : *snapshot)
    {
      if (slot.hasWeakRef)
      {
        if (slot.weakRef.expired())
        {
          anyExpired = true;
          continue;
        }
      }

      try
      {
        slot.function(args...);
      }
      catch (...)
      {
        if (exHandler && *exHandler)
        {
          (*exHandler)(std::current_exception());
        }
      }
    }

    // Prune expired weak_ptr slots if needed
    if (anyExpired)
    {
      bool expected = false;
      if (_needsPrune.compare_exchange_strong(expected, true,
            std::memory_order_relaxed))
      {
        prune();
        _needsPrune.store(false, std::memory_order_relaxed);
      }
    }
  }

  /// \brief Set an exception handler for slot invocation failures.
  /// Default: exceptions are silently swallowed. Thread-safe.
  void setExceptionHandler(std::function<void(std::exception_ptr)> handler)
  {
    auto sp = std::make_shared<std::function<void(std::exception_ptr)>>(
      std::move(handler));
    std::atomic_store(&_exceptionHandler, std::move(sp));
  }

  // ── ScopedConnection ─────────────────────────────────────────────────────

  /// \brief RAII wrapper that disconnects on destruction.
  /// Movable, not copyable. Default-constructible as no-op.
  class ScopedConnection
  {
  public:
    ScopedConnection() noexcept : _signal(nullptr), _id(0) {}

    ScopedConnection(Signal* signal, ConnectionId id) noexcept
      : _signal(signal), _id(id)
    {
    }

    ~ScopedConnection()
    {
      if (_signal && _id != 0)
      {
        _signal->disconnect(_id);
      }
    }

    // Movable
    ScopedConnection(ScopedConnection&& other) noexcept
      : _signal(other._signal), _id(other._id)
    {
      other._signal = nullptr;
      other._id = 0;
    }

    ScopedConnection& operator=(ScopedConnection&& other) noexcept
    {
      if (this != &other)
      {
        if (_signal && _id != 0)
        {
          _signal->disconnect(_id);
        }
        _signal = other._signal;
        _id = other._id;
        other._signal = nullptr;
        other._id = 0;
      }
      return *this;
    }

    // Not copyable
    ScopedConnection(const ScopedConnection&) = delete;
    ScopedConnection& operator=(const ScopedConnection&) = delete;

    /// \brief Release ownership without disconnecting. Caller takes manual control.
    ConnectionId release() noexcept
    {
      auto id = _id;
      _signal = nullptr;
      _id = 0;
      return id;
    }

    /// \brief Disconnect and reset to no-op state.
    void reset()
    {
      if (_signal && _id != 0)
      {
        _signal->disconnect(_id);
      }
      _signal = nullptr;
      _id = 0;
    }

    ConnectionId id() const noexcept { return _id; }

  private:
    Signal* _signal;
    ConnectionId _id;
  };

private:
  struct Slot
  {
    std::function<void(const Args&...)> function;
    std::weak_ptr<void> weakRef;
    ConnectionId id;
    bool hasWeakRef = false;  // true only when connected via weak_ptr
  };

  using SlotList = std::vector<Slot>;

  std::shared_ptr<SlotList> cloneSlots() const
  {
    auto current = std::atomic_load(&_slots);
    return std::make_shared<SlotList>(*current);
  }

  void prune()
  {
    std::lock_guard lock(_mutex);
    auto newList = cloneSlots();
    newList->erase(
      std::remove_if(newList->begin(), newList->end(),
        [](const Slot& s)
        {
          return s.hasWeakRef && s.weakRef.expired();
        }),
      newList->end());
    std::atomic_store(&_slots, std::move(newList));
  }

  std::shared_ptr<SlotList> _slots;
  std::atomic<ConnectionId> _nextId;
  std::atomic<bool> _needsPrune;
  std::mutex _mutex;
  using ExceptionHandler = std::function<void(std::exception_ptr)>;
  std::shared_ptr<ExceptionHandler> _exceptionHandler;
};

} // namespace core
} // namespace iora
