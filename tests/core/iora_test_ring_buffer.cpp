// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for RingBuffer<T, Capacity> and DynamicRingBuffer<T>

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/core/ring_buffer.hpp>

#include <memory>
#include <thread>
#include <vector>

using namespace iora::core;

// ══════════════════════════════════════════════════════════════════════════════
// Fixed RingBuffer — Basic Operations
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Fixed: push and pop single item", "[ring_buffer][fixed]")
{
  RingBuffer<int, 4> rb;
  REQUIRE(rb.empty());

  REQUIRE(rb.tryPush(42));
  REQUIRE(rb.size() == 1);

  int val = 0;
  REQUIRE(rb.tryPop(val));
  REQUIRE(val == 42);
  REQUIRE(rb.empty());
}

TEST_CASE("Fixed: full and empty", "[ring_buffer][fixed]")
{
  RingBuffer<int, 4> rb;
  REQUIRE(rb.tryPush(1));
  REQUIRE(rb.tryPush(2));
  REQUIRE(rb.tryPush(3));
  REQUIRE(rb.tryPush(4));
  REQUIRE(rb.full());
  REQUIRE_FALSE(rb.tryPush(5)); // full

  int val;
  REQUIRE(rb.tryPop(val)); REQUIRE(val == 1);
  REQUIRE(rb.tryPop(val)); REQUIRE(val == 2);
  REQUIRE(rb.tryPop(val)); REQUIRE(val == 3);
  REQUIRE(rb.tryPop(val)); REQUIRE(val == 4);
  REQUIRE(rb.empty());
  REQUIRE_FALSE(rb.tryPop(val)); // empty
}

TEST_CASE("Fixed: peek without consuming", "[ring_buffer][fixed]")
{
  RingBuffer<int, 4> rb;

  int val = 0;
  REQUIRE_FALSE(rb.peek(val)); // empty

  rb.tryPush(42);
  REQUIRE(rb.peek(val));
  REQUIRE(val == 42);
  REQUIRE(rb.size() == 1); // not consumed

  REQUIRE(rb.tryPop(val));
  REQUIRE(val == 42);
  REQUIRE(rb.empty());
}

TEST_CASE("Fixed: FIFO order", "[ring_buffer][fixed]")
{
  RingBuffer<int, 8> rb;
  for (int i = 0; i < 8; ++i)
  {
    REQUIRE(rb.tryPush(i));
  }
  for (int i = 0; i < 8; ++i)
  {
    int val;
    REQUIRE(rb.tryPop(val));
    REQUIRE(val == i);
  }
}

TEST_CASE("Fixed: wrap-around", "[ring_buffer][fixed]")
{
  RingBuffer<int, 4> rb;

  // Fill and drain to advance indices past the buffer size
  for (int round = 0; round < 5; ++round)
  {
    for (int i = 0; i < 4; ++i)
    {
      REQUIRE(rb.tryPush(round * 4 + i));
    }
    for (int i = 0; i < 4; ++i)
    {
      int val;
      REQUIRE(rb.tryPop(val));
      REQUIRE(val == round * 4 + i);
    }
  }
}

TEST_CASE("Fixed: capacity and size", "[ring_buffer][fixed]")
{
  RingBuffer<int, 16> rb;
  REQUIRE(rb.capacity() == 16);
  REQUIRE(rb.size() == 0);
  rb.tryPush(1);
  REQUIRE(rb.size() == 1);
  REQUIRE_FALSE(rb.full());
}

TEST_CASE("Fixed: clear", "[ring_buffer][fixed]")
{
  RingBuffer<int, 4> rb;
  rb.tryPush(1);
  rb.tryPush(2);
  REQUIRE(rb.size() == 2);

  rb.clear();
  REQUIRE(rb.empty());
  REQUIRE(rb.size() == 0);

  // Can push again after clear
  REQUIRE(rb.tryPush(3));
  int val;
  REQUIRE(rb.tryPop(val));
  REQUIRE(val == 3);
}

// ══════════════════════════════════════════════════════════════════════════════
// Fixed RingBuffer — Batch Operations
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Fixed: batch push and pop", "[ring_buffer][fixed][batch]")
{
  RingBuffer<int, 8> rb;
  int items[] = {1, 2, 3, 4, 5};

  auto pushed = rb.tryPushBatch(items, 5);
  REQUIRE(pushed == 5);
  REQUIRE(rb.size() == 5);

  int out[5] = {};
  auto popped = rb.tryPopBatch(out, 5);
  REQUIRE(popped == 5);
  for (int i = 0; i < 5; ++i)
  {
    REQUIRE(out[i] == i + 1);
  }
}

TEST_CASE("Fixed: batch partial fill", "[ring_buffer][fixed][batch]")
{
  RingBuffer<int, 4> rb;
  int items[] = {1, 2, 3, 4, 5, 6};

  auto pushed = rb.tryPushBatch(items, 6);
  REQUIRE(pushed == 4); // only 4 fit
  REQUIRE(rb.full());
}

TEST_CASE("Fixed: batch wrap-around", "[ring_buffer][fixed][batch]")
{
  RingBuffer<int, 4> rb;

  // Advance indices by pushing/popping 3 items
  int tmp[] = {10, 20, 30};
  rb.tryPushBatch(tmp, 3);
  int drain[3];
  rb.tryPopBatch(drain, 3);

  // Now head=3, tail=3. Push 4 items that wrap around
  int items[] = {1, 2, 3, 4};
  auto pushed = rb.tryPushBatch(items, 4);
  REQUIRE(pushed == 4);

  int out[4] = {};
  auto popped = rb.tryPopBatch(out, 4);
  REQUIRE(popped == 4);
  for (int i = 0; i < 4; ++i)
  {
    REQUIRE(out[i] == i + 1);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// Fixed RingBuffer — Move-Only Types
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Fixed: move-only type (unique_ptr)", "[ring_buffer][fixed][move]")
{
  RingBuffer<std::unique_ptr<int>, 4> rb;

  REQUIRE(rb.tryPush(std::make_unique<int>(42)));
  REQUIRE(rb.size() == 1);

  std::unique_ptr<int> val;
  REQUIRE(rb.tryPop(val));
  REQUIRE(*val == 42);
}

// ══════════════════════════════════════════════════════════════════════════════
// Fixed RingBuffer — noexcept
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Fixed: noexcept correctness", "[ring_buffer][fixed]")
{
  RingBuffer<int, 4> rb;
  static_assert(noexcept(rb.size()));
  static_assert(noexcept(rb.empty()));
  static_assert(noexcept(rb.full()));
  static_assert(noexcept(rb.capacity()));
  static_assert(noexcept(rb.clear()));
  int val;
  static_assert(noexcept(rb.peek(val))); // int is nothrow_copy_assignable
  REQUIRE(true);
}

// ══════════════════════════════════════════════════════════════════════════════
// DynamicRingBuffer — Basic Operations
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Dynamic: push/pop/peek/clear", "[ring_buffer][dynamic]")
{
  DynamicRingBuffer<int> rb(8);
  REQUIRE(rb.capacity() == 8);
  REQUIRE(rb.empty());

  REQUIRE(rb.tryPush(42));
  int val = 0;
  REQUIRE(rb.peek(val));
  REQUIRE(val == 42);
  REQUIRE(rb.tryPop(val));
  REQUIRE(val == 42);
  REQUIRE(rb.empty());

  rb.tryPush(1);
  rb.tryPush(2);
  rb.clear();
  REQUIRE(rb.empty());
}

TEST_CASE("Dynamic: batch push/pop with wrap-around", "[ring_buffer][dynamic][batch]")
{
  DynamicRingBuffer<int> rb(4);

  // Advance indices
  int tmp[] = {10, 20, 30};
  rb.tryPushBatch(tmp, 3);
  int drain[3];
  rb.tryPopBatch(drain, 3);

  // Wrap-around batch
  int items[] = {1, 2, 3, 4};
  auto pushed = rb.tryPushBatch(items, 4);
  REQUIRE(pushed == 4);

  int out[4] = {};
  auto popped = rb.tryPopBatch(out, 4);
  REQUIRE(popped == 4);
  for (int i = 0; i < 4; ++i)
  {
    REQUIRE(out[i] == i + 1);
  }
}

TEST_CASE("Dynamic: capacity rounding", "[ring_buffer][dynamic]")
{
  DynamicRingBuffer<int> rb(5);
  REQUIRE(rb.capacity() == 8); // rounded up to next power of two

  DynamicRingBuffer<int> rb2(8);
  REQUIRE(rb2.capacity() == 8); // already power of two

  DynamicRingBuffer<int> rb3(1);
  REQUIRE(rb3.capacity() == 1);
}

// ══════════════════════════════════════════════════════════════════════════════
// DynamicRingBuffer — Resize
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Dynamic: resize to larger preserves FIFO", "[ring_buffer][dynamic][resize]")
{
  DynamicRingBuffer<int> rb(4);
  rb.tryPush(1);
  rb.tryPush(2);
  rb.tryPush(3);

  rb.resize(16);
  REQUIRE(rb.capacity() == 16);
  REQUIRE(rb.size() == 3);

  int val;
  REQUIRE(rb.tryPop(val)); REQUIRE(val == 1);
  REQUIRE(rb.tryPop(val)); REQUIRE(val == 2);
  REQUIRE(rb.tryPop(val)); REQUIRE(val == 3);
}

TEST_CASE("Dynamic: resize to smaller but sufficient", "[ring_buffer][dynamic][resize]")
{
  DynamicRingBuffer<int> rb(16);
  rb.tryPush(1);
  rb.tryPush(2);

  rb.resize(4);
  REQUIRE(rb.capacity() == 4);
  REQUIRE(rb.size() == 2);

  int val;
  REQUIRE(rb.tryPop(val)); REQUIRE(val == 1);
  REQUIRE(rb.tryPop(val)); REQUIRE(val == 2);
}

TEST_CASE("Dynamic: resize to smaller than item count loses oldest", "[ring_buffer][dynamic][resize]")
{
  DynamicRingBuffer<int> rb(8);
  for (int i = 1; i <= 6; ++i)
  {
    rb.tryPush(i);
  }
  REQUIRE(rb.size() == 6);

  // Resize to capacity 4 — only the 4 most recent items fit, 2 dropped
  auto dropped = rb.resize(4);
  REQUIRE(dropped == 2);
  REQUIRE(rb.capacity() == 4);
  REQUIRE(rb.size() == 4);

  int val;
  REQUIRE(rb.tryPop(val)); REQUIRE(val == 3); // oldest surviving
  REQUIRE(rb.tryPop(val)); REQUIRE(val == 4);
  REQUIRE(rb.tryPop(val)); REQUIRE(val == 5);
  REQUIRE(rb.tryPop(val)); REQUIRE(val == 6); // newest
}

// ══════════════════════════════════════════════════════════════════════════════
// SPSC Stress Tests
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Stress: SPSC fixed — producer/consumer threads", "[ring_buffer][fixed][stress]")
{
  constexpr std::size_t N = 100000;
  RingBuffer<int, 1024> rb;

  std::thread producer([&]()
  {
    for (int i = 0; i < static_cast<int>(N); ++i)
    {
      while (!rb.tryPush(i))
      {
        // spin
      }
    }
  });

  std::vector<int> received;
  received.reserve(N);

  std::thread consumer([&]()
  {
    int val;
    for (std::size_t count = 0; count < N;)
    {
      if (rb.tryPop(val))
      {
        received.push_back(val);
        ++count;
      }
    }
  });

  producer.join();
  consumer.join();

  REQUIRE(received.size() == N);
  for (std::size_t i = 0; i < N; ++i)
  {
    REQUIRE(received[i] == static_cast<int>(i));
  }
}

TEST_CASE("Stress: SPSC dynamic — producer/consumer threads", "[ring_buffer][dynamic][stress]")
{
  constexpr std::size_t N = 100000;
  DynamicRingBuffer<int> rb(1024);

  std::thread producer([&]()
  {
    for (int i = 0; i < static_cast<int>(N); ++i)
    {
      while (!rb.tryPush(i))
      {
        // spin
      }
    }
  });

  std::vector<int> received;
  received.reserve(N);

  std::thread consumer([&]()
  {
    int val;
    for (std::size_t count = 0; count < N;)
    {
      if (rb.tryPop(val))
      {
        received.push_back(val);
        ++count;
      }
    }
  });

  producer.join();
  consumer.join();

  REQUIRE(received.size() == N);
  for (std::size_t i = 0; i < N; ++i)
  {
    REQUIRE(received[i] == static_cast<int>(i));
  }
}
