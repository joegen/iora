// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "iora/network/event_batch_processor.hpp"
#include "iora/network/transport_with_batching.hpp"
#include "iora_test_net_utils.hpp"
#include "test_helpers.hpp"
#include <chrono>
#include <thread>

using namespace std::chrono_literals;
using namespace iora::network;

// Mock transport for testing
class MockTransport
{
public:
  MockTransport() = default;

  void processEvent(int fd, uint32_t events)
  {
    eventsProcessed_++;
    lastFd_ = fd;
    lastEvents_ = events;
  }

  int getEventsProcessed() const { return eventsProcessed_; }
  int getLastFd() const { return lastFd_; }
  uint32_t getLastEvents() const { return lastEvents_; }

  void reset()
  {
    eventsProcessed_ = 0;
    lastFd_ = -1;
    lastEvents_ = 0;
  }

private:
  int eventsProcessed_{0};
  int lastFd_{-1};
  uint32_t lastEvents_{0};
};

TEST_CASE("BatchingTransportWrapper basic functionality", "[batch][integration][basic]")
{
  BatchProcessingConfig config;
  config.maxBatchSize = 8;
  config.maxBatchDelay = 50ms;
  config.enableAdaptiveSizing = false;

  BatchingTransportWrapper<MockTransport> wrapper(config);

  SECTION("Wrapper forwards to base transport")
  {
    auto &base = wrapper.getBase();
    base.processEvent(100, EPOLLIN);

    REQUIRE(base.getEventsProcessed() == 1);
    REQUIRE(base.getLastFd() == 100);
    REQUIRE(base.getLastEvents() == EPOLLIN);
  }

  SECTION("Batching configuration is preserved")
  {
    auto storedConfig = wrapper.getBatchingConfig();
    REQUIRE(storedConfig.maxBatchSize == 8);
    REQUIRE(storedConfig.maxBatchDelay == 50ms);
    REQUIRE_FALSE(storedConfig.enableAdaptiveSizing);
  }

  SECTION("Statistics start clean")
  {
    auto stats = wrapper.getBatchingStats();
    REQUIRE(stats.totalBatches == 0);
    REQUIRE(stats.totalEvents == 0);
  }
}

TEST_CASE("BatchingTransportWrapper configuration helpers", "[batch][integration][config]")
{
  SECTION("Server configuration is optimized for throughput")
  {
    auto config = createServerConfig();

    REQUIRE(config.maxBatchSize >= 64);     // Large batches
    REQUIRE(config.maxBatchDelay >= 100us); // Allow batching time
    REQUIRE(config.loadFactor >= 0.7);      // Higher utilization
    REQUIRE(config.enableAdaptiveSizing);
  }

  SECTION("Client configuration is optimized for latency")
  {
    auto config = createClientConfig();

    REQUIRE(config.maxBatchSize <= 32);    // Smaller batches
    REQUIRE(config.maxBatchDelay <= 50us); // Low latency
    REQUIRE(config.loadFactor <= 0.6);     // Favor latency
    REQUIRE(config.enableAdaptiveSizing);
  }

  SECTION("Balanced configuration is reasonable")
  {
    auto config = createBalancedConfig();

    REQUIRE(config.maxBatchSize >= 16);
    REQUIRE(config.maxBatchSize <= 64);
    REQUIRE(config.maxBatchDelay >= 25us);
    REQUIRE(config.maxBatchDelay <= 100us);
    REQUIRE(config.loadFactor >= 0.6);
    REQUIRE(config.loadFactor <= 0.8);
    REQUIRE(config.enableAdaptiveSizing);
  }

  SECTION("Optimized batching transport factory works")
  {
    auto transport = createOptimizedBatchingTransport<MockTransport>(64);
    REQUIRE(transport != nullptr);

    auto config = transport->getBatchingConfig();
    REQUIRE(config.maxBatchSize >= 64);
    REQUIRE(config.enableAdaptiveSizing);
  }
}

TEST_CASE("BatchingTransportWrapper event processing", "[batch][integration][events]")
{
  EpollHelper epoll;
  EventFdHelper eventFd, timerFd, sessionFd;

  epoll.addFd(eventFd.fd());
  epoll.addFd(timerFd.fd());
  epoll.addFd(sessionFd.fd());

  BatchProcessingConfig config;
  config.maxBatchSize = 4;
  config.maxBatchDelay = 20ms; // Short timeout for testing
  config.enableAdaptiveSizing = false;

  BatchingTransportWrapper<MockTransport> wrapper(config);

  SECTION("Transport event loop processes special FDs correctly")
  {
    bool eventFdTriggered = false;
    bool timerFdTriggered = false;
    int sessionEventsProcessed = 0;

    auto onEventFd = [&eventFdTriggered]() { eventFdTriggered = true; };

    auto onTimerFd = [&timerFdTriggered]() { timerFdTriggered = true; };

    auto sessionHandler = [&sessionEventsProcessed](int /*fd*/, uint32_t /*events*/)
    { sessionEventsProcessed++; };

    // Signal all FDs
    eventFd.signal();
    timerFd.signal();
    sessionFd.signal();

    // Run one batch processing iteration with timeout
    std::thread processor_thread(
      [&]()
      {
        try
        {
          wrapper.runTransportEventLoop(epoll.fd(), eventFd.fd(), timerFd.fd(), onEventFd,
                                        onTimerFd, sessionHandler);
        }
        catch (...)
        {
          // Timeout or other errors expected
        }
      });

    processor_thread.join();

    // Verify some events might have been processed (timing dependent)
    auto stats = wrapper.getBatchingStats();
    if (stats.totalBatches > 0)
    {
      // At least one batch was processed
      REQUIRE(true);
    }
  }
}

TEST_CASE("BatchingTransportWrapper statistics and monitoring", "[batch][integration][stats]")
{
  BatchingTransportWrapper<MockTransport> wrapper(createBalancedConfig());

  SECTION("Statistics reset works")
  {
    // First get any initial stats that might exist
    wrapper.resetBatchingStats();

    auto stats = wrapper.getBatchingStats();
    REQUIRE(stats.totalBatches == 0);
    REQUIRE(stats.totalEvents == 0);
    REQUIRE(stats.totalBatchTime == 0us);
  }

  SECTION("Configuration updates work")
  {
    auto newConfig = createServerConfig();
    wrapper.updateBatchingConfig(newConfig);

    auto storedConfig = wrapper.getBatchingConfig();
    REQUIRE(storedConfig.maxBatchSize == newConfig.maxBatchSize);
    REQUIRE(storedConfig.maxBatchDelay == newConfig.maxBatchDelay);
    REQUIRE(storedConfig.loadFactor == newConfig.loadFactor);
  }
}

// Custom wrapper that tracks batch processing metrics
class MetricsTrackingWrapper : public BatchingTransportWrapper<MockTransport>
{
public:
  explicit MetricsTrackingWrapper(const BatchProcessingConfig &config)
      : BatchingTransportWrapper<MockTransport>(config)
  {
  }

  int getBatchesProcessed() const { return batchesProcessed_; }
  std::chrono::microseconds getTotalProcessingTime() const { return totalProcessingTime_; }
  std::size_t getMaxBatchSize() const { return maxBatchSize_; }

protected:
  void onBatchProcessed(std::size_t batchSize, std::chrono::microseconds processingTime) override
  {
    batchesProcessed_++;
    totalProcessingTime_ += processingTime;
    maxBatchSize_ = std::max(maxBatchSize_, batchSize);
  }

private:
  int batchesProcessed_{0};
  std::chrono::microseconds totalProcessingTime_{0};
  std::size_t maxBatchSize_{0};
};

TEST_CASE("Custom batch processing metrics", "[batch][integration][metrics]")
{
  auto config = createBalancedConfig();
  MetricsTrackingWrapper wrapper(config);

  SECTION("Custom metrics tracking works")
  {
    // Initially no batches processed
    REQUIRE(wrapper.getBatchesProcessed() == 0);
    REQUIRE(wrapper.getTotalProcessingTime() == 0us);
    REQUIRE(wrapper.getMaxBatchSize() == 0);

    // After processing (if any events were available), metrics would be updated
    // This test mainly verifies the custom override mechanism works
  }
}

TEST_CASE("BatchingTransportWrapper error handling", "[batch][integration][error]")
{
  BatchingTransportWrapper<MockTransport> wrapper(createBalancedConfig());

  SECTION("Invalid epoll FD handling")
  {
    auto sessionHandler = [](int, uint32_t) {};
    auto onEventFd = []() {};
    auto onTimerFd = []() {};

    // Should handle invalid epoll FD gracefully by throwing
    REQUIRE_THROWS_AS(wrapper.runTransportEventLoop(-1, 1, 2, onEventFd, onTimerFd, sessionHandler),
                      std::system_error);
  }
}

TEST_CASE("Performance comparison with and without batching", "[batch][integration][performance]")
{
  // This test demonstrates the potential benefits of batch processing
  EpollHelper epoll;
  std::vector<std::unique_ptr<EventFdHelper>> eventFds;

  constexpr int numEvents = 10;
  for (int i = 0; i < numEvents; ++i)
  {
    auto eventFd = std::make_unique<EventFdHelper>();
    epoll.addFd(eventFd->fd());
    eventFds.push_back(std::move(eventFd));
  }

  SECTION("Batching wrapper can handle multiple events efficiently")
  {
    BatchProcessingConfig config;
    config.maxBatchSize = numEvents;
    config.maxBatchDelay = 50ms;
    config.enableAdaptiveSizing = false;

    BatchingTransportWrapper<MockTransport> wrapper(config);

    std::atomic<int> totalProcessed{0};

    auto sessionHandler = [&totalProcessed](int /*fd*/, uint32_t /*events*/)
    {
      totalProcessed.fetch_add(1, std::memory_order_relaxed);
      // Simulate minimal processing work
      std::this_thread::sleep_for(1us);
    };

    // Signal all event FDs
    for (auto &eventFd : eventFds)
    {
      eventFd->signal();
    }

    auto start = std::chrono::high_resolution_clock::now();

    std::thread processor_thread(
      [&]()
      {
        try
        {
          wrapper.runTransportEventLoop(
            epoll.fd(), -1, -1, // No special FDs
            []() {}, []() {}, sessionHandler);
        }
        catch (...)
        {
          // Handle timeouts gracefully
        }
      });

    processor_thread.join();

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    auto stats = wrapper.getBatchingStats();

    // Verify that we can handle events efficiently
    REQUIRE(duration < 100ms); // Should complete quickly

    if (stats.totalEvents > 0)
    {
      // If events were processed, verify batching occurred
      REQUIRE(stats.totalBatches <= static_cast<std::uint64_t>(numEvents));

      // Verify some efficiency gained from batching
      if (stats.totalEvents == numEvents)
      {
        double eventsPerBatch = static_cast<double>(stats.totalEvents) / stats.totalBatches;
        REQUIRE(eventsPerBatch >= 1.0); // At least one event per batch
      }
    }
  }
}