// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace iora
{
namespace network
{

template <typename T> class ObjectPool
{
public:
  using Factory = std::function<std::unique_ptr<T>()>;
  using Resetter = std::function<void(T *)>;

  explicit ObjectPool(Factory factory, Resetter resetter = nullptr, std::size_t initialSize = 0)
      : _factory(std::move(factory)), _resetter(std::move(resetter))
  {
    // Pre-populate pool
    for (std::size_t i = 0; i < initialSize; ++i)
    {
      if (auto obj = _factory())
      {
        _available.push_back(std::move(obj));
        _created.fetch_add(1, std::memory_order_relaxed);
      }
    }
  }

  // Acquire an object from the pool
  std::unique_ptr<T> acquire()
  {
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (!_available.empty())
      {
        auto obj = std::move(_available.back());
        _available.pop_back();
        _acquired.fetch_add(1, std::memory_order_relaxed);
        return obj;
      }
    }

    // Pool empty: manufacture OUTSIDE the lock so a slow or re-entrant factory
    // neither serializes other pool users nor self-deadlocks (contrast the
    // resetter in release(), which also runs off the lock). A factory that
    // returns null is handled gracefully and counts toward nothing.
    auto obj = _factory ? _factory() : nullptr;
    if (obj)
    {
      _created.fetch_add(1, std::memory_order_relaxed);
      _acquired.fetch_add(1, std::memory_order_relaxed);
    }
    return obj;
  }

  // Return an object to the pool
  void release(std::unique_ptr<T> obj)
  {
    if (!obj)
    {
      return;
    }

    // Reset object state if resetter provided (runs BEFORE the lock)
    if (_resetter)
    {
      _resetter(obj.get());
    }

    std::lock_guard<std::mutex> lock(_mutex);

    // Limit pool size to prevent unbounded growth
    if (_available.size() < _maxPoolSize)
    {
      _available.push_back(std::move(obj));
      _released.fetch_add(1, std::memory_order_relaxed);
    }
    else
    {
      // Let object be destroyed
      _destroyed.fetch_add(1, std::memory_order_relaxed);
    }
  }

  // Pool statistics
  struct Stats
  {
    std::size_t available;
    std::size_t totalCreated;
    std::size_t totalAcquired;
    std::size_t totalReleased;
    std::size_t totalDestroyed;
  };

  Stats getStats() const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    return {_available.size(), _created.load(std::memory_order_relaxed),
            _acquired.load(std::memory_order_relaxed), _released.load(std::memory_order_relaxed),
            _destroyed.load(std::memory_order_relaxed)};
  }

  void setMaxPoolSize(std::size_t size)
  {
    std::vector<std::unique_ptr<T>> dead;
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _maxPoolSize = size;
      collectSurplusLocked(_maxPoolSize, dead); // trim to the new cap
    }
    // `dead` destructs here, AFTER the lock is released.
  }

  void clear()
  {
    std::vector<std::unique_ptr<T>> dead;
    {
      std::lock_guard<std::mutex> lock(_mutex);
      collectSurplusLocked(0, dead);
    }
    // `dead` destructs here, AFTER the lock is released.
  }

private:
  // Move every idle object beyond `keep` out of _available into `out`, counting
  // each as destroyed. The caller holds _mutex, but the actual ~T() runs when
  // `out` is destroyed AFTER the lock is released — mirroring release()'s
  // over-cap path — so a re-entrant object destructor cannot deadlock on the
  // non-recursive _mutex. Shared by clear() and setMaxPoolSize().
  void collectSurplusLocked(std::size_t keep, std::vector<std::unique_ptr<T>> &out)
  {
    if (_available.size() <= keep)
    {
      return;
    }
    _destroyed.fetch_add(_available.size() - keep, std::memory_order_relaxed);
    for (std::size_t i = keep; i < _available.size(); ++i)
    {
      out.push_back(std::move(_available[i]));
    }
    _available.resize(keep); // the moved-from tail holds null unique_ptrs
  }

  Factory _factory;
  Resetter _resetter;
  mutable std::mutex _mutex;
  std::vector<std::unique_ptr<T>> _available;
  std::size_t _maxPoolSize{100}; // Prevent unbounded growth

  // Statistics
  std::atomic<std::size_t> _created{0};
  std::atomic<std::size_t> _acquired{0};
  std::atomic<std::size_t> _released{0};
  std::atomic<std::size_t> _destroyed{0};
};

// RAII wrapper for automatic return to pool
template <typename T> class PooledObject
{
public:
  PooledObject(std::unique_ptr<T> obj, ObjectPool<T> *pool) : _obj(std::move(obj)), _pool(pool) {}

  ~PooledObject()
  {
    if (_obj && _pool)
    {
      _pool->release(std::move(_obj));
    }
  }

  // Move-only semantics
  PooledObject(const PooledObject &) = delete;
  PooledObject &operator=(const PooledObject &) = delete;

  PooledObject(PooledObject &&other) noexcept : _obj(std::move(other._obj)), _pool(other._pool)
  {
    other._pool = nullptr;
  }

  PooledObject &operator=(PooledObject &&other) noexcept
  {
    if (this != &other)
    {
      // Return current object to pool
      if (_obj && _pool)
      {
        _pool->release(std::move(_obj));
      }

      _obj = std::move(other._obj);
      _pool = other._pool;
      other._pool = nullptr;
    }
    return *this;
  }

  T *get() const { return _obj.get(); }
  T &operator*() const { return *_obj; }
  T *operator->() const { return _obj.get(); }
  explicit operator bool() const { return static_cast<bool>(_obj); }

  // Release ownership without returning to pool
  std::unique_ptr<T> release()
  {
    _pool = nullptr;
    return std::move(_obj);
  }

private:
  std::unique_ptr<T> _obj;
  ObjectPool<T> *_pool;
};

template <typename T> PooledObject<T> makePooled(ObjectPool<T> &pool)
{
  return PooledObject<T>(pool.acquire(), &pool);
}

} // namespace network
} // namespace iora
