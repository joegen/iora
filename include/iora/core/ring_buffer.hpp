// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <array>
#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>

namespace iora {
namespace core {

// ══════════════════════════════════════════════════════════════════════════════
// RingBuffer<T, Capacity> — Fixed-size lock-free SPSC circular buffer
// ══════════════════════════════════════════════════════════════════════════════

/// \brief Lock-free single-producer/single-consumer circular buffer.
/// Fixed capacity, power-of-two sizing, no heap allocation after construction.
/// Atomic head/tail indices with acquire/release memory ordering.
///
/// Producer calls tryPush/tryPushBatch. Consumer calls tryPop/tryPopBatch/peek.
/// Do NOT use from multiple producers or multiple consumers.
template<typename T, std::size_t Capacity>
class RingBuffer
{
  static_assert(Capacity > 0, "RingBuffer capacity must be greater than zero");
  static_assert((Capacity & (Capacity - 1)) == 0,
    "RingBuffer capacity must be a power of two");

public:
  static constexpr std::size_t kMask = Capacity - 1;

  RingBuffer() noexcept : _head{0}, _tail{0} {}

  // Non-copyable, non-movable (contains atomics)
  RingBuffer(const RingBuffer&) = delete;
  RingBuffer& operator=(const RingBuffer&) = delete;
  RingBuffer(RingBuffer&&) = delete;
  RingBuffer& operator=(RingBuffer&&) = delete;

  /// \brief Try to push an item (copy). Returns false if full.
  bool tryPush(const T& item) noexcept(std::is_nothrow_copy_assignable_v<T>)
  {
    auto head = _head.load(std::memory_order_relaxed);
    auto tail = _tail.load(std::memory_order_relaxed);
    if (head - tail >= Capacity)
    {
      return false;
    }
    _buffer[head & kMask] = item;
    _head.store(head + 1, std::memory_order_release);
    return true;
  }

  /// \brief Try to push an item (move). Returns false if full.
  bool tryPush(T&& item) noexcept(std::is_nothrow_move_assignable_v<T>)
  {
    auto head = _head.load(std::memory_order_relaxed);
    auto tail = _tail.load(std::memory_order_relaxed);
    if (head - tail >= Capacity)
    {
      return false;
    }
    _buffer[head & kMask] = std::move(item);
    _head.store(head + 1, std::memory_order_release);
    return true;
  }

  /// \brief Try to pop an item. Returns false if empty.
  bool tryPop(T& out) noexcept(std::is_nothrow_move_assignable_v<T>)
  {
    auto tail = _tail.load(std::memory_order_relaxed);
    auto head = _head.load(std::memory_order_acquire);
    if (tail >= head)
    {
      return false;
    }
    out = std::move(_buffer[tail & kMask]);
    _tail.store(tail + 1, std::memory_order_release);
    return true;
  }

  /// \brief Peek at the next item without consuming. Returns false if empty.
  bool peek(T& out) const noexcept(std::is_nothrow_copy_assignable_v<T>)
  {
    auto tail = _tail.load(std::memory_order_relaxed);
    auto head = _head.load(std::memory_order_acquire);
    if (tail >= head)
    {
      return false;
    }
    out = _buffer[tail & kMask];
    return true;
  }

  /// \brief Push up to count items. Returns number actually pushed.
  /// Single-load/single-store: loads tail once, stores head once.
  std::size_t tryPushBatch(const T* items, std::size_t count)
    noexcept(std::is_nothrow_copy_assignable_v<T>)
  {
    auto head = _head.load(std::memory_order_relaxed);
    auto tail = _tail.load(std::memory_order_relaxed);
    auto available = Capacity - (head - tail);
    auto toPush = count < available ? count : available;

    for (std::size_t i = 0; i < toPush; ++i)
    {
      _buffer[(head + i) & kMask] = items[i];
    }
    _head.store(head + toPush, std::memory_order_release);
    return toPush;
  }

  /// \brief Pop up to maxCount items. Returns number actually popped.
  /// Single-load/single-store: loads head once, stores tail once.
  std::size_t tryPopBatch(T* out, std::size_t maxCount)
    noexcept(std::is_nothrow_move_assignable_v<T>)
  {
    auto tail = _tail.load(std::memory_order_relaxed);
    auto head = _head.load(std::memory_order_acquire);
    auto available = head - tail;
    auto toPop = maxCount < available ? maxCount : available;

    for (std::size_t i = 0; i < toPop; ++i)
    {
      out[i] = std::move(_buffer[(tail + i) & kMask]);
    }
    _tail.store(tail + toPop, std::memory_order_release);
    return toPop;
  }

  /// \brief Approximate count (relaxed ordering). Not for synchronization.
  std::size_t size() const noexcept
  {
    auto head = _head.load(std::memory_order_relaxed);
    auto tail = _tail.load(std::memory_order_relaxed);
    return head - tail;
  }

  bool empty() const noexcept { return size() == 0; }
  bool full() const noexcept { return size() >= Capacity; }
  constexpr std::size_t capacity() const noexcept { return Capacity; }

  /// \brief Reset buffer to empty state. Requires SPSC quiescence.
  void clear() noexcept
  {
    _head.store(0, std::memory_order_relaxed);
    _tail.store(0, std::memory_order_relaxed);
  }

private:
  // Separate cache lines to avoid false sharing between producer and consumer
  alignas(64) std::atomic<std::size_t> _head;
  alignas(64) std::atomic<std::size_t> _tail;
  alignas(64) std::array<T, Capacity> _buffer;
};

// ══════════════════════════════════════════════════════════════════════════════
// DynamicRingBuffer<T> — Runtime-sized lock-free SPSC circular buffer
// ══════════════════════════════════════════════════════════════════════════════

/// \brief Lock-free SPSC circular buffer with runtime-configurable capacity.
/// Capacity is rounded up to the next power of two. Supports resize().
template<typename T>
class DynamicRingBuffer
{
public:
  explicit DynamicRingBuffer(std::size_t requestedCapacity)
    : _capacity(nextPowerOfTwo(requestedCapacity))
    , _mask(_capacity - 1)
    , _buffer(std::make_unique<T[]>(_capacity))
    , _head{0}
    , _tail{0}
  {
  }

  // Non-copyable, non-movable
  DynamicRingBuffer(const DynamicRingBuffer&) = delete;
  DynamicRingBuffer& operator=(const DynamicRingBuffer&) = delete;
  DynamicRingBuffer(DynamicRingBuffer&&) = delete;
  DynamicRingBuffer& operator=(DynamicRingBuffer&&) = delete;

  bool tryPush(const T& item) noexcept(std::is_nothrow_copy_assignable_v<T>)
  {
    auto head = _head.load(std::memory_order_relaxed);
    auto tail = _tail.load(std::memory_order_relaxed);
    if (head - tail >= _capacity)
    {
      return false;
    }
    _buffer[head & _mask] = item;
    _head.store(head + 1, std::memory_order_release);
    return true;
  }

  bool tryPush(T&& item) noexcept(std::is_nothrow_move_assignable_v<T>)
  {
    auto head = _head.load(std::memory_order_relaxed);
    auto tail = _tail.load(std::memory_order_relaxed);
    if (head - tail >= _capacity)
    {
      return false;
    }
    _buffer[head & _mask] = std::move(item);
    _head.store(head + 1, std::memory_order_release);
    return true;
  }

  bool tryPop(T& out) noexcept(std::is_nothrow_move_assignable_v<T>)
  {
    auto tail = _tail.load(std::memory_order_relaxed);
    auto head = _head.load(std::memory_order_acquire);
    if (tail >= head)
    {
      return false;
    }
    out = std::move(_buffer[tail & _mask]);
    _tail.store(tail + 1, std::memory_order_release);
    return true;
  }

  bool peek(T& out) const noexcept(std::is_nothrow_copy_assignable_v<T>)
  {
    auto tail = _tail.load(std::memory_order_relaxed);
    auto head = _head.load(std::memory_order_acquire);
    if (tail >= head)
    {
      return false;
    }
    out = _buffer[tail & _mask];
    return true;
  }

  std::size_t tryPushBatch(const T* items, std::size_t count)
    noexcept(std::is_nothrow_copy_assignable_v<T>)
  {
    auto head = _head.load(std::memory_order_relaxed);
    auto tail = _tail.load(std::memory_order_relaxed);
    auto available = _capacity - (head - tail);
    auto toPush = count < available ? count : available;
    for (std::size_t i = 0; i < toPush; ++i)
    {
      _buffer[(head + i) & _mask] = items[i];
    }
    _head.store(head + toPush, std::memory_order_release);
    return toPush;
  }

  std::size_t tryPopBatch(T* out, std::size_t maxCount)
    noexcept(std::is_nothrow_move_assignable_v<T>)
  {
    auto tail = _tail.load(std::memory_order_relaxed);
    auto head = _head.load(std::memory_order_acquire);
    auto available = head - tail;
    auto toPop = maxCount < available ? maxCount : available;
    for (std::size_t i = 0; i < toPop; ++i)
    {
      out[i] = std::move(_buffer[(tail + i) & _mask]);
    }
    _tail.store(tail + toPop, std::memory_order_release);
    return toPop;
  }

  std::size_t size() const noexcept
  {
    auto head = _head.load(std::memory_order_relaxed);
    auto tail = _tail.load(std::memory_order_relaxed);
    return head - tail;
  }

  bool empty() const noexcept { return size() == 0; }
  bool full() const noexcept { return size() >= _capacity; }
  std::size_t capacity() const noexcept { return _capacity; }

  void clear() noexcept
  {
    _head.store(0, std::memory_order_relaxed);
    _tail.store(0, std::memory_order_relaxed);
  }

  /// \brief Resize the buffer. NOT thread-safe — requires SPSC quiescence.
  /// Drains existing items into the new buffer preserving FIFO order.
  /// If the new capacity is smaller than the current item count, the oldest
  /// items are dropped and the most recent items are kept.
  /// Returns the number of items dropped (0 if all items fit).
  std::size_t resize(std::size_t newRequestedCapacity)
  {
    auto newCapacity = nextPowerOfTwo(newRequestedCapacity);
    auto newMask = newCapacity - 1;
    auto newBuffer = std::make_unique<T[]>(newCapacity);

    // Drain existing items into new buffer
    auto tail = _tail.load(std::memory_order_relaxed);
    auto head = _head.load(std::memory_order_relaxed);
    std::size_t count = head - tail;
    std::size_t toCopy = count < newCapacity ? count : newCapacity;

    // Copy the most recent items if shrinking
    auto startTail = (count > newCapacity) ? (head - newCapacity) : tail;
    for (std::size_t i = 0; i < toCopy; ++i)
    {
      newBuffer[i] = std::move(_buffer[(startTail + i) & _mask]);
    }

    std::size_t dropped = count - toCopy;

    _buffer = std::move(newBuffer);
    _capacity = newCapacity;
    _mask = newMask;
    _tail.store(0, std::memory_order_relaxed);
    _head.store(toCopy, std::memory_order_relaxed);
    return dropped;
  }

private:
  static std::size_t nextPowerOfTwo(std::size_t v)
  {
    if (v == 0)
    {
      return 1;
    }
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    return v + 1;
  }

  std::size_t _capacity;
  std::size_t _mask;
  std::unique_ptr<T[]> _buffer;
  alignas(64) std::atomic<std::size_t> _head;
  alignas(64) std::atomic<std::size_t> _tail;
};

} // namespace core
} // namespace iora
