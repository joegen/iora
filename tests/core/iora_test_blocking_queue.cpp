// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for BlockingQueue thread-safe queue implementation

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/core/blocking_queue.hpp>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

using namespace iora::core;

// ══════════════════════════════════════════════════════════════════════════
// Test: Basic Queue/Dequeue Operations
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("BlockingQueue basic queue and dequeue", "[blocking_queue][basic]")
{
  BlockingQueue<int> queue(10);

  REQUIRE(queue.empty());
  REQUIRE(queue.size() == 0);
  REQUIRE(queue.capacity() == 10);

  // Queue some items
  REQUIRE(queue.queue(1));
  REQUIRE(queue.queue(2));
  REQUIRE(queue.queue(3));

  REQUIRE(queue.size() == 3);
  REQUIRE_FALSE(queue.empty());

  // Dequeue items
  int value;
  REQUIRE(queue.dequeue(value));
  REQUIRE(value == 1);

  REQUIRE(queue.dequeue(value));
  REQUIRE(value == 2);

  REQUIRE(queue.dequeue(value));
  REQUIRE(value == 3);

  REQUIRE(queue.empty());
  REQUIRE(queue.size() == 0);
}

TEST_CASE("BlockingQueue move semantics", "[blocking_queue][move]")
{
  BlockingQueue<std::string> queue(10);

  std::string item1 = "hello";
  std::string item2 = "world";

  REQUIRE(queue.queue(std::move(item1)));
  REQUIRE(queue.queue(std::move(item2)));

  std::string out;
  REQUIRE(queue.dequeue(out));
  REQUIRE(out == "hello");

  REQUIRE(queue.dequeue(out));
  REQUIRE(out == "world");
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Capacity and Full Queue
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("BlockingQueue capacity enforcement", "[blocking_queue][capacity]")
{
  BlockingQueue<int> queue(3);

  REQUIRE(queue.queue(1));
  REQUIRE(queue.queue(2));
  REQUIRE(queue.queue(3));

  REQUIRE(queue.full());
  REQUIRE(queue.size() == 3);
}

TEST_CASE("BlockingQueue queue blocks when full", "[blocking_queue][blocking][full]")
{
  BlockingQueue<int> queue(2);

  // Fill the queue
  REQUIRE(queue.queue(1));
  REQUIRE(queue.queue(2));
  REQUIRE(queue.full());

  std::atomic<bool> queueCompleted{false};
  std::thread producer(
    [&]()
    {
      // This should block until space is available
      queue.queue(3);
      queueCompleted = true;
    });

  // Give producer time to block
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE_FALSE(queueCompleted.load());

  // Dequeue one item to make space
  int value;
  REQUIRE(queue.dequeue(value));
  REQUIRE(value == 1);

  // Wait for producer to complete
  producer.join();
  REQUIRE(queueCompleted.load());

  // Verify the new item was queued
  REQUIRE(queue.size() == 2);
}

// ══════════════════════════════════════════════════════════════════════════
// Test: tryQueue Operations
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("BlockingQueue tryQueue non-blocking success", "[blocking_queue][tryqueue]")
{
  BlockingQueue<int> queue(5);

  REQUIRE(queue.tryQueue(1));
  REQUIRE(queue.tryQueue(2));
  REQUIRE(queue.size() == 2);
}

TEST_CASE("BlockingQueue tryQueue fails when full", "[blocking_queue][tryqueue][full]")
{
  BlockingQueue<int> queue(2);

  REQUIRE(queue.tryQueue(1));
  REQUIRE(queue.tryQueue(2));
  REQUIRE(queue.full());

  // Should fail immediately without blocking
  REQUIRE_FALSE(queue.tryQueue(3));
  REQUIRE(queue.size() == 2);
}

TEST_CASE("BlockingQueue tryQueue with timeout", "[blocking_queue][tryqueue][timeout]")
{
  BlockingQueue<int> queue(2);

  // Fill queue
  REQUIRE(queue.queue(1));
  REQUIRE(queue.queue(2));

  auto start = std::chrono::steady_clock::now();
  bool result = queue.tryQueue(3, std::chrono::milliseconds(100));
  auto elapsed = std::chrono::steady_clock::now() - start;

  REQUIRE_FALSE(result);
  REQUIRE(elapsed >= std::chrono::milliseconds(100));
  REQUIRE(elapsed < std::chrono::milliseconds(200));
}

TEST_CASE("BlockingQueue tryQueue with timeout succeeds when space available",
          "[blocking_queue][tryqueue][timeout]")
{
  BlockingQueue<int> queue(2);

  // Fill queue
  REQUIRE(queue.queue(1));
  REQUIRE(queue.queue(2));

  // Start thread to dequeue after delay
  std::thread consumer(
    [&]()
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      int value;
      queue.dequeue(value);
    });

  // tryQueue should succeed once space is available
  bool result = queue.tryQueue(3, std::chrono::milliseconds(200));
  REQUIRE(result);

  consumer.join();
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Dequeue Blocking and Timeout
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("BlockingQueue dequeue blocks when empty", "[blocking_queue][blocking][empty]")
{
  BlockingQueue<int> queue(10);

  std::atomic<bool> dequeueCompleted{false};
  std::atomic<int> dequeuedValue{0};

  std::thread consumer(
    [&]()
    {
      int value;
      queue.dequeue(value);
      dequeuedValue = value;
      dequeueCompleted = true;
    });

  // Give consumer time to block
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE_FALSE(dequeueCompleted.load());

  // Queue an item
  REQUIRE(queue.queue(42));

  // Wait for consumer to complete
  consumer.join();
  REQUIRE(dequeueCompleted.load());
  REQUIRE(dequeuedValue.load() == 42);
}

TEST_CASE("BlockingQueue dequeue with timeout", "[blocking_queue][dequeue][timeout]")
{
  BlockingQueue<int> queue(10);

  int value;
  auto start = std::chrono::steady_clock::now();
  bool result = queue.dequeue(value, std::chrono::milliseconds(100));
  auto elapsed = std::chrono::steady_clock::now() - start;

  REQUIRE_FALSE(result);
  REQUIRE(elapsed >= std::chrono::milliseconds(100));
  REQUIRE(elapsed < std::chrono::milliseconds(200));
}

TEST_CASE("BlockingQueue dequeue with timeout succeeds when item available",
          "[blocking_queue][dequeue][timeout]")
{
  BlockingQueue<int> queue(10);

  // Start thread to queue after delay
  std::thread producer(
    [&]()
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      queue.queue(123);
    });

  // Dequeue should succeed once item is available
  int value;
  bool result = queue.dequeue(value, std::chrono::milliseconds(200));
  REQUIRE(result);
  REQUIRE(value == 123);

  producer.join();
}

// ══════════════════════════════════════════════════════════════════════════
// Test: tryDequeue Operations
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("BlockingQueue tryDequeue non-blocking success", "[blocking_queue][trydequeue]")
{
  BlockingQueue<int> queue(10);

  queue.queue(42);

  int value;
  REQUIRE(queue.tryDequeue(value));
  REQUIRE(value == 42);
  REQUIRE(queue.empty());
}

TEST_CASE("BlockingQueue tryDequeue fails when empty", "[blocking_queue][trydequeue][empty]")
{
  BlockingQueue<int> queue(10);

  int value;
  REQUIRE_FALSE(queue.tryDequeue(value));
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Close Operations
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("BlockingQueue close wakes blocked dequeue", "[blocking_queue][close]")
{
  BlockingQueue<int> queue(10);

  std::atomic<bool> dequeueCompleted{false};
  std::atomic<bool> dequeueResult{true};

  std::thread consumer(
    [&]()
    {
      int value;
      dequeueResult = queue.dequeue(value);
      dequeueCompleted = true;
    });

  // Give consumer time to block
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE_FALSE(dequeueCompleted.load());

  // Close the queue
  queue.close();

  // Wait for consumer to complete
  consumer.join();
  REQUIRE(dequeueCompleted.load());
  REQUIRE_FALSE(dequeueResult.load()); // Should return false when closed
}

TEST_CASE("BlockingQueue close wakes blocked queue", "[blocking_queue][close][full]")
{
  BlockingQueue<int> queue(2);

  // Fill the queue
  queue.queue(1);
  queue.queue(2);

  std::atomic<bool> queueCompleted{false};
  std::atomic<bool> queueResult{true};

  std::thread producer(
    [&]()
    {
      queueResult = queue.queue(3);
      queueCompleted = true;
    });

  // Give producer time to block
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE_FALSE(queueCompleted.load());

  // Close the queue
  queue.close();

  // Wait for producer to complete
  producer.join();
  REQUIRE(queueCompleted.load());
  REQUIRE_FALSE(queueResult.load()); // Should return false when closed
}

TEST_CASE("BlockingQueue queue fails after close", "[blocking_queue][close]")
{
  BlockingQueue<int> queue(10);

  queue.close();
  REQUIRE(queue.isClosed());

  REQUIRE_FALSE(queue.queue(1));
  REQUIRE_FALSE(queue.tryQueue(2));
}

TEST_CASE("BlockingQueue can dequeue existing items after close", "[blocking_queue][close]")
{
  BlockingQueue<int> queue(10);

  queue.queue(1);
  queue.queue(2);
  queue.queue(3);

  queue.close();
  REQUIRE(queue.isClosed());

  // Should still be able to dequeue existing items
  int value;
  REQUIRE(queue.dequeue(value));
  REQUIRE(value == 1);

  REQUIRE(queue.dequeue(value));
  REQUIRE(value == 2);

  REQUIRE(queue.dequeue(value));
  REQUIRE(value == 3);

  // Now empty and closed - should return false
  REQUIRE_FALSE(queue.dequeue(value));
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Multi-threaded Concurrency
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("BlockingQueue multiple producers and consumers", "[blocking_queue][concurrent]")
{
  BlockingQueue<int> queue(100);
  const int itemsPerProducer = 100;
  const int numProducers = 4;
  const int numConsumers = 4;
  const int totalItems = itemsPerProducer * numProducers;

  std::atomic<int> producedCount{0};
  std::atomic<int> consumedCount{0};
  std::vector<int> consumedValues;
  std::mutex consumedMutex;

  // Start producers
  std::vector<std::thread> producers;
  for (int p = 0; p < numProducers; ++p)
  {
    producers.emplace_back(
      [&, p]()
      {
        for (int i = 0; i < itemsPerProducer; ++i)
        {
          int value = p * itemsPerProducer + i;
          queue.queue(value);
          producedCount++;
        }
      });
  }

  // Start consumers
  std::vector<std::thread> consumers;
  for (int c = 0; c < numConsumers; ++c)
  {
    consumers.emplace_back(
      [&]()
      {
        while (true)
        {
          int value;
          if (queue.dequeue(value, std::chrono::milliseconds(100)))
          {
            {
              std::lock_guard<std::mutex> lock(consumedMutex);
              consumedValues.push_back(value);
            }
            consumedCount++;
          }
          else
          {
            // Timeout - check if we're done
            if (producedCount.load() == totalItems && queue.empty())
            {
              break;
            }
          }
        }
      });
  }

  // Wait for all producers to finish
  for (auto &t : producers)
  {
    t.join();
  }

  // Wait for all consumers to finish
  for (auto &t : consumers)
  {
    t.join();
  }

  // Verify all items were consumed
  REQUIRE(consumedCount.load() == totalItems);
  REQUIRE(consumedValues.size() == static_cast<size_t>(totalItems));
  REQUIRE(queue.empty());
}

TEST_CASE("BlockingQueue stress test with rapid queue/dequeue", "[blocking_queue][stress]")
{
  BlockingQueue<int> queue(10);
  std::atomic<bool> stop{false};
  std::atomic<int> queuedCount{0};
  std::atomic<int> dequeuedCount{0};

  // Producer thread
  std::thread producer(
    [&]()
    {
      int value = 0;
      while (!stop.load())
      {
        if (queue.tryQueue(value++))
        {
          queuedCount++;
        }
        std::this_thread::yield();
      }
    });

  // Consumer thread
  std::thread consumer(
    [&]()
    {
      int value;
      while (!stop.load())
      {
        if (queue.tryDequeue(value))
        {
          dequeuedCount++;
        }
        std::this_thread::yield();
      }
    });

  // Run for a short time
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  stop = true;

  producer.join();
  consumer.join();

  // Drain remaining items
  int value;
  while (queue.tryDequeue(value))
  {
    dequeuedCount++;
  }

  REQUIRE(queuedCount.load() == dequeuedCount.load());
  REQUIRE(queuedCount.load() > 0);
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Edge Cases
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("BlockingQueue constructor throws on zero capacity", "[blocking_queue][error]")
{
  REQUIRE_THROWS_AS(BlockingQueue<int>(0), std::invalid_argument);
}

TEST_CASE("BlockingQueue FIFO ordering", "[blocking_queue][ordering]")
{
  BlockingQueue<int> queue(10);

  for (int i = 0; i < 10; ++i)
  {
    queue.queue(i);
  }

  for (int i = 0; i < 10; ++i)
  {
    int value;
    REQUIRE(queue.dequeue(value));
    REQUIRE(value == i);
  }
}

TEST_CASE("BlockingQueue with complex types", "[blocking_queue][complex]")
{
  struct ComplexType
  {
    int id;
    std::string name;
    std::vector<int> data;

    bool operator==(const ComplexType &other) const
    {
      return id == other.id && name == other.name && data == other.data;
    }
  };

  BlockingQueue<ComplexType> queue(5);

  ComplexType item1{1, "first", {1, 2, 3}};
  ComplexType item2{2, "second", {4, 5, 6}};

  REQUIRE(queue.queue(item1));
  REQUIRE(queue.queue(item2));

  ComplexType out;
  REQUIRE(queue.dequeue(out));
  REQUIRE(out == item1);

  REQUIRE(queue.dequeue(out));
  REQUIRE(out == item2);
}
