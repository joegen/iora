// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <stdexcept>

namespace iora
{
namespace core
{

/// \brief Thread-safe blocking queue with bounded capacity
///
/// A blocking queue that supports multiple producers and consumers with
/// configurable maximum capacity. When the queue is empty, dequeue operations
/// block until an item becomes available or a timeout occurs. When the queue
/// is full, queue operations block until space becomes available.
///
/// Features:
/// - Thread-safe for multiple producers and consumers
/// - Blocking dequeue when empty
/// - Timeout-based dequeue operations
/// - Maximum capacity enforcement
/// - No exceptions thrown from dequeue operations (returns bool)
/// - Graceful shutdown via close()
/// - Move semantics support
///
/// Example usage:
/// \code
///   BlockingQueue<WorkItem> queue(100);
///
///   // Producer
///   WorkItem item;
///   if (queue.queue(item)) {
///     // Successfully queued
///   }
///
///   // Consumer (blocks until item available)
///   WorkItem item;
///   if (queue.dequeue(item)) {
///     // Process item
///   }
///
///   // Consumer with timeout
///   if (queue.dequeue(item, std::chrono::seconds(5))) {
///     // Got item within 5 seconds
///   }
/// \endcode
///
/// \tparam T The type of elements stored in the queue
/// \tparam IdType Optional type for item identification (unused in current implementation)
template <typename T, typename IdType = std::size_t>
class BlockingQueue
{
public:
  /// \brief Constructs a blocking queue with specified maximum capacity
  ///
  /// \param maxSize Maximum number of elements the queue can hold
  /// \throws std::invalid_argument if maxSize is 0
  explicit BlockingQueue(std::size_t maxSize = 1024)
      : _maxSize(maxSize), _closed(false)
  {
    if (maxSize == 0)
    {
      throw std::invalid_argument("BlockingQueue maxSize must be greater than 0");
    }
  }

  /// \brief Destructor - closes the queue and wakes all waiting threads
  ~BlockingQueue()
  {
    close();
  }

  // Delete copy and move constructors/assignment
  BlockingQueue(const BlockingQueue &) = delete;
  BlockingQueue &operator=(const BlockingQueue &) = delete;
  BlockingQueue(BlockingQueue &&) = delete;
  BlockingQueue &operator=(BlockingQueue &&) = delete;

  /// \brief Add an item to the queue (blocking if full)
  ///
  /// Blocks until space is available or the queue is closed.
  ///
  /// \param item The item to add (copied)
  /// \return true if item was queued, false if queue is closed
  bool queue(const T &item)
  {
    std::unique_lock<std::mutex> lock(_mutex);

    // Wait until space available or closed
    _condNotFull.wait(lock, [this]()
    {
      return _queue.size() < _maxSize || _closed.load(std::memory_order_acquire);
    });

    if (_closed.load(std::memory_order_acquire))
    {
      return false;
    }

    _queue.push_back(item);
    lock.unlock();
    _condNotEmpty.notify_one();
    return true;
  }

  /// \brief Add an item to the queue (blocking if full, move version)
  ///
  /// Blocks until space is available or the queue is closed.
  ///
  /// \param item The item to add (moved)
  /// \return true if item was queued, false if queue is closed
  bool queue(T &&item)
  {
    std::unique_lock<std::mutex> lock(_mutex);

    // Wait until space available or closed
    _condNotFull.wait(lock, [this]()
    {
      return _queue.size() < _maxSize || _closed.load(std::memory_order_acquire);
    });

    if (_closed.load(std::memory_order_acquire))
    {
      return false;
    }

    _queue.push_back(std::move(item));
    lock.unlock();
    _condNotEmpty.notify_one();
    return true;
  }

  /// \brief Try to add an item with a timeout
  ///
  /// \param item The item to add
  /// \param timeout Maximum time to wait for space
  /// \return true if item was queued, false if timeout or queue closed
  bool tryQueue(const T &item, std::chrono::milliseconds timeout)
  {
    std::unique_lock<std::mutex> lock(_mutex);

    // Wait until space available, timeout, or closed
    bool success = _condNotFull.wait_for(lock, timeout, [this]()
    {
      return _queue.size() < _maxSize || _closed.load(std::memory_order_acquire);
    });

    if (!success || _closed.load(std::memory_order_acquire))
    {
      return false;
    }

    _queue.push_back(item);
    lock.unlock();
    _condNotEmpty.notify_one();
    return true;
  }

  /// \brief Try to add an item with a timeout (move version)
  ///
  /// \param item The item to add (moved)
  /// \param timeout Maximum time to wait for space
  /// \return true if item was queued, false if timeout or queue closed
  bool tryQueue(T &&item, std::chrono::milliseconds timeout)
  {
    std::unique_lock<std::mutex> lock(_mutex);

    // Wait until space available, timeout, or closed
    bool success = _condNotFull.wait_for(lock, timeout, [this]()
    {
      return _queue.size() < _maxSize || _closed.load(std::memory_order_acquire);
    });

    if (!success || _closed.load(std::memory_order_acquire))
    {
      return false;
    }

    _queue.push_back(std::move(item));
    lock.unlock();
    _condNotEmpty.notify_one();
    return true;
  }

  /// \brief Try to add an item without blocking
  ///
  /// \param item The item to add
  /// \return true if item was queued, false if queue full or closed
  bool tryQueue(const T &item)
  {
    std::unique_lock<std::mutex> lock(_mutex);

    if (_closed.load(std::memory_order_acquire) || _queue.size() >= _maxSize)
    {
      return false;
    }

    _queue.push_back(item);
    lock.unlock();
    _condNotEmpty.notify_one();
    return true;
  }

  /// \brief Try to add an item without blocking (move version)
  ///
  /// \param item The item to add (moved)
  /// \return true if item was queued, false if queue full or closed
  bool tryQueue(T &&item)
  {
    std::unique_lock<std::mutex> lock(_mutex);

    if (_closed.load(std::memory_order_acquire) || _queue.size() >= _maxSize)
    {
      return false;
    }

    _queue.push_back(std::move(item));
    lock.unlock();
    _condNotEmpty.notify_one();
    return true;
  }

  /// \brief Remove an item from the queue (blocking if empty)
  ///
  /// Blocks until an item is available or the queue is closed.
  /// Does not throw exceptions.
  ///
  /// \param[out] out Reference to store the dequeued item
  /// \return true if item was dequeued, false if queue is closed and empty
  bool dequeue(T &out)
  {
    std::unique_lock<std::mutex> lock(_mutex);

    // Wait until item available or closed
    _condNotEmpty.wait(lock, [this]()
    {
      return !_queue.empty() || _closed.load(std::memory_order_acquire);
    });

    // If closed and empty, return false
    if (_queue.empty())
    {
      return false;
    }

    out = std::move(_queue.front());
    _queue.pop_front();
    lock.unlock();
    _condNotFull.notify_one();
    return true;
  }

  /// \brief Remove an item from the queue with timeout
  ///
  /// Blocks until an item is available, timeout occurs, or queue is closed.
  /// Does not throw exceptions.
  ///
  /// \param[out] out Reference to store the dequeued item
  /// \param timeout Maximum time to wait for an item
  /// \return true if item was dequeued, false if timeout or queue closed and empty
  bool dequeue(T &out, std::chrono::milliseconds timeout)
  {
    std::unique_lock<std::mutex> lock(_mutex);

    // Wait until item available, timeout, or closed
    bool success = _condNotEmpty.wait_for(lock, timeout, [this]()
    {
      return !_queue.empty() || _closed.load(std::memory_order_acquire);
    });

    // If timeout or closed and empty, return false
    if (!success || _queue.empty())
    {
      return false;
    }

    out = std::move(_queue.front());
    _queue.pop_front();
    lock.unlock();
    _condNotFull.notify_one();
    return true;
  }

  /// \brief Try to remove an item without blocking
  ///
  /// \param[out] out Reference to store the dequeued item
  /// \return true if item was dequeued, false if queue is empty
  bool tryDequeue(T &out)
  {
    std::unique_lock<std::mutex> lock(_mutex);

    if (_queue.empty())
    {
      return false;
    }

    out = std::move(_queue.front());
    _queue.pop_front();
    lock.unlock();
    _condNotFull.notify_one();
    return true;
  }

  /// \brief Close the queue and wake all waiting threads
  ///
  /// After closing, no new items can be queued. Existing items can still
  /// be dequeued until the queue is empty. All threads blocked on queue()
  /// or dequeue() operations will be woken up.
  void close()
  {
    if (_closed.exchange(true, std::memory_order_acq_rel))
    {
      return; // Already closed
    }

    // Wake all waiting threads
    _condNotEmpty.notify_all();
    _condNotFull.notify_all();
  }

  /// \brief Check if the queue is closed
  ///
  /// \return true if the queue has been closed
  bool isClosed() const
  {
    return _closed.load(std::memory_order_acquire);
  }

  /// \brief Get the current number of items in the queue
  ///
  /// \return Current queue size
  std::size_t size() const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    return _queue.size();
  }

  /// \brief Check if the queue is empty
  ///
  /// \return true if the queue contains no items
  bool empty() const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    return _queue.empty();
  }

  /// \brief Check if the queue is full
  ///
  /// \return true if the queue is at maximum capacity
  bool full() const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    return _queue.size() >= _maxSize;
  }

  /// \brief Get the maximum capacity of the queue
  ///
  /// \return Maximum number of items the queue can hold
  std::size_t capacity() const
  {
    return _maxSize;
  }

private:
  mutable std::mutex _mutex;
  std::condition_variable _condNotEmpty;
  std::condition_variable _condNotFull;
  std::deque<T> _queue;
  const std::size_t _maxSize;
  std::atomic<bool> _closed;
};

} // namespace core
} // namespace iora
