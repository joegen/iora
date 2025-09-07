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
      : factory_(std::move(factory)), resetter_(std::move(resetter))
  {
    // Pre-populate pool
    for (std::size_t i = 0; i < initialSize; ++i)
    {
      if (auto obj = factory_())
      {
        available_.push_back(std::move(obj));
        created_.fetch_add(1, std::memory_order_relaxed);
      }
    }
  }

  // Acquire an object from the pool
  std::unique_ptr<T> acquire()
  {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!available_.empty())
    {
      auto obj = std::move(available_.back());
      available_.pop_back();
      acquired_.fetch_add(1, std::memory_order_relaxed);
      return obj;
    }

    // Pool empty, create new object
    created_.fetch_add(1, std::memory_order_relaxed);
    return factory_();
  }

  // Return an object to the pool
  void release(std::unique_ptr<T> obj)
  {
    if (!obj)
      return;

    // Reset object state if resetter provided
    if (resetter_)
    {
      resetter_(obj.get());
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Limit pool size to prevent unbounded growth
    if (available_.size() < maxPoolSize_)
    {
      available_.push_back(std::move(obj));
      released_.fetch_add(1, std::memory_order_relaxed);
    }
    else
    {
      // Let object be destroyed
      destroyed_.fetch_add(1, std::memory_order_relaxed);
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
    std::lock_guard<std::mutex> lock(mutex_);
    return {available_.size(), created_.load(std::memory_order_relaxed),
            acquired_.load(std::memory_order_relaxed), released_.load(std::memory_order_relaxed),
            destroyed_.load(std::memory_order_relaxed)};
  }

  void setMaxPoolSize(std::size_t size)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    maxPoolSize_ = size;

    // Trim existing pool if it exceeds the new max size
    while (available_.size() > maxPoolSize_)
    {
      available_.pop_back();
      destroyed_.fetch_add(1, std::memory_order_relaxed);
    }
  }

  void clear()
  {
    std::lock_guard<std::mutex> lock(mutex_);
    available_.clear();
  }

private:
  Factory factory_;
  Resetter resetter_;
  mutable std::mutex mutex_;
  std::vector<std::unique_ptr<T>> available_;
  std::size_t maxPoolSize_{100}; // Prevent unbounded growth

  // Statistics
  std::atomic<std::size_t> created_{0};
  std::atomic<std::size_t> acquired_{0};
  std::atomic<std::size_t> released_{0};
  std::atomic<std::size_t> destroyed_{0};
};

// RAII wrapper for automatic return to pool
template <typename T> class PooledObject
{
public:
  PooledObject(std::unique_ptr<T> obj, ObjectPool<T> *pool) : obj_(std::move(obj)), pool_(pool) {}

  ~PooledObject()
  {
    if (obj_ && pool_)
    {
      pool_->release(std::move(obj_));
    }
  }

  // Move-only semantics
  PooledObject(const PooledObject &) = delete;
  PooledObject &operator=(const PooledObject &) = delete;

  PooledObject(PooledObject &&other) noexcept : obj_(std::move(other.obj_)), pool_(other.pool_)
  {
    other.pool_ = nullptr;
  }

  PooledObject &operator=(PooledObject &&other) noexcept
  {
    if (this != &other)
    {
      // Return current object to pool
      if (obj_ && pool_)
      {
        pool_->release(std::move(obj_));
      }

      obj_ = std::move(other.obj_);
      pool_ = other.pool_;
      other.pool_ = nullptr;
    }
    return *this;
  }

  T *get() const { return obj_.get(); }
  T &operator*() const { return *obj_; }
  T *operator->() const { return obj_.get(); }
  explicit operator bool() const { return static_cast<bool>(obj_); }

  // Release ownership without returning to pool
  std::unique_ptr<T> release()
  {
    pool_ = nullptr;
    return std::move(obj_);
  }

private:
  std::unique_ptr<T> obj_;
  ObjectPool<T> *pool_;
};

template <typename T> PooledObject<T> makePooled(ObjectPool<T> &pool)
{
  return PooledObject<T>(pool.acquire(), &pool);
}

} // namespace network
} // namespace iora