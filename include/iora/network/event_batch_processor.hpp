// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include <atomic>
#include <cerrno>
#include <chrono>
#include <functional>
#include <memory>
#include <system_error>
#include <sys/epoll.h>
#include <vector>

namespace iora
{
namespace network
{

// Configuration for batch processing
struct BatchProcessingConfig
{
  std::size_t maxBatchSize{64};                    // Maximum events to process per batch
  std::chrono::microseconds maxBatchDelay{100};    // Maximum time to wait for batch to fill
  std::chrono::microseconds adaptiveThreshold{50}; // Threshold for adaptive batch sizing
  bool enableAdaptiveSizing{true};                 // Enable adaptive batch size adjustment
  double loadFactor{0.75};                         // Target CPU utilization for adaptive sizing
};

// Statistics for batch processing performance
struct BatchProcessingStats
{
  std::uint64_t totalBatches{0};
  std::uint64_t totalEvents{0};
  std::uint64_t maxBatchSize{0};
  std::uint64_t minBatchSize{0};
  std::uint64_t adaptiveAdjustments{0};
  std::chrono::microseconds totalBatchTime{0};
  std::chrono::microseconds avgBatchTime{0};
  double throughputEventsPerSec{0.0};
};

// Event handler types
using EventHandler = std::function<void(int fd, uint32_t events)>;
using BatchCompleteHandler =
  std::function<void(std::size_t batchSize, std::chrono::microseconds processingTime)>;

// Batch event processor
class EventBatchProcessor
{
public:
  explicit EventBatchProcessor(const BatchProcessingConfig &config = {}) : config_(config)
  {
    events_.resize(config_.maxBatchSize);
  }

  // Process events in batches with adaptive sizing
  template <typename SpecialEventHandler>
  void processBatch(int epollFd, const EventHandler &generalHandler,
                    const SpecialEventHandler &specialHandler,
                    const BatchCompleteHandler &onBatchComplete = nullptr)
  {
    auto batchStart = std::chrono::high_resolution_clock::now();

    // Determine batch size (adaptive or fixed)
    std::size_t currentBatchSize = getCurrentBatchSize();

    // Wait for events with timeout
    int timeout = static_cast<int>(config_.maxBatchDelay.count() / 1000); // Convert to ms
    int n = ::epoll_wait(epollFd, events_.data(), static_cast<int>(currentBatchSize), timeout);

    if (n < 0)
    {
      if (errno == EINTR)
        return;
      throw std::system_error(errno, std::system_category(), "epoll_wait failed");
    }

    if (n == 0)
      return; // Timeout with no events

    // Process the batch of events
    std::vector<std::pair<int, uint32_t>> normalEvents;
    normalEvents.reserve(n);

    for (int i = 0; i < n; ++i)
    {
      int fd = events_[i].data.fd;
      uint32_t eventMask = events_[i].events;

      // Handle special file descriptors first (eventfd, timerfd, etc.)
      if (specialHandler(fd, eventMask))
      {
        continue; // Special handler processed this event
      }

      // Queue normal events for batch processing
      normalEvents.emplace_back(fd, eventMask);
    }

    // Process normal events in batch
    for (const auto &[fd, eventMask] : normalEvents)
    {
      generalHandler(fd, eventMask);
    }

    auto batchEnd = std::chrono::high_resolution_clock::now();
    auto batchTime = std::chrono::duration_cast<std::chrono::microseconds>(batchEnd - batchStart);

    // Update statistics
    updateStats(n, batchTime);

    // Adaptive sizing adjustment
    if (config_.enableAdaptiveSizing)
    {
      adjustBatchSize(n, batchTime);
    }

    // Notify batch completion
    if (onBatchComplete)
    {
      onBatchComplete(n, batchTime);
    }
  }

  // Process with predefined special FD handlers
  void processBatchWithSpecialFDs(int epollFd, int eventFd, int timerFd,
                                  const EventHandler &generalHandler,
                                  const std::function<void()> &onEventFd = nullptr,
                                  const std::function<void()> &onTimerFd = nullptr,
                                  const BatchCompleteHandler &onBatchComplete = nullptr)
  {
    auto specialHandler = [eventFd, timerFd, onEventFd, onTimerFd](int fd,
                                                                   uint32_t /*events*/) -> bool
    {
      if (fd == eventFd)
      {
        if (onEventFd)
          onEventFd();
        return true;
      }
      if (fd == timerFd)
      {
        if (onTimerFd)
          onTimerFd();
        return true;
      }
      return false; // Not a special FD
    };

    processBatch(epollFd, generalHandler, specialHandler, onBatchComplete);
  }

  BatchProcessingStats getStats() const
  {
    auto stats = stats_;

    if (stats.totalBatches > 0)
    {
      stats.avgBatchTime =
        std::chrono::microseconds(stats.totalBatchTime.count() / stats.totalBatches);
    }

    if (stats.totalBatchTime.count() > 0)
    {
      double seconds = stats.totalBatchTime.count() / 1000000.0;
      stats.throughputEventsPerSec = stats.totalEvents / seconds;
    }

    return stats;
  }

  void resetStats()
  {
    stats_ = {};
    lastAdjustment_ = std::chrono::steady_clock::now();
  }

  void updateConfig(const BatchProcessingConfig &config)
  {
    config_ = config;
    events_.resize(config_.maxBatchSize);

    // Reset adaptive sizing
    if (config_.enableAdaptiveSizing)
    {
      currentBatchSize_ = config_.maxBatchSize / 2; // Start in middle
    }
    else
    {
      currentBatchSize_ = config_.maxBatchSize;
    }
  }

  BatchProcessingConfig getConfig() const { return config_; }

  // Force a specific batch size for testing
  void setFixedBatchSize(std::size_t size)
  {
    config_.enableAdaptiveSizing = false;
    currentBatchSize_ = std::min(size, config_.maxBatchSize);
  }

private:
  std::size_t getCurrentBatchSize() const
  {
    if (!config_.enableAdaptiveSizing)
    {
      return config_.maxBatchSize;
    }

    return currentBatchSize_;
  }

  void updateStats(int eventCount, std::chrono::microseconds processingTime)
  {
    stats_.totalBatches++;
    stats_.totalEvents += eventCount;
    stats_.totalBatchTime += processingTime;

    if (eventCount > static_cast<int>(stats_.maxBatchSize))
    {
      stats_.maxBatchSize = eventCount;
    }

    if (stats_.minBatchSize == 0 || eventCount < static_cast<int>(stats_.minBatchSize))
    {
      stats_.minBatchSize = eventCount;
    }
  }

  void adjustBatchSize(int actualEvents, std::chrono::microseconds processingTime)
  {
    auto now = std::chrono::steady_clock::now();

    // Only adjust every 100ms to avoid thrashing
    if (now - lastAdjustment_ < std::chrono::milliseconds(100))
    {
      return;
    }

    lastAdjustment_ = now;

    // Calculate utilization based on processing time vs available time
    double utilization = static_cast<double>(processingTime.count()) /
                         static_cast<double>(config_.maxBatchDelay.count());

    bool shouldIncrease = false;
    bool shouldDecrease = false;

    // Increase batch size if:
    // 1. We filled the batch completely AND processing time is acceptable
    // 2. Utilization is below target load factor
    if ((actualEvents == static_cast<int>(currentBatchSize_)) && (utilization < config_.loadFactor))
    {
      shouldIncrease = true;
    }

    // Decrease batch size if:
    // 1. Processing time is too high (above threshold)
    // 2. We consistently get small batches
    if (processingTime > config_.adaptiveThreshold || utilization > config_.loadFactor)
    {
      shouldDecrease = true;
    }

    if (shouldIncrease && currentBatchSize_ < config_.maxBatchSize)
    {
      // Increase by 25% or at least 1
      std::size_t increase = std::max(1UL, currentBatchSize_ / 4);
      currentBatchSize_ = std::min(config_.maxBatchSize, currentBatchSize_ + increase);
      stats_.adaptiveAdjustments++;
    }
    else if (shouldDecrease && currentBatchSize_ > 1)
    {
      // Decrease by 25% but at least keep 1
      std::size_t decrease = std::max(1UL, currentBatchSize_ / 4);
      currentBatchSize_ = std::max(1UL, currentBatchSize_ - decrease);
      stats_.adaptiveAdjustments++;
    }
  }

private:
  BatchProcessingConfig config_;
  std::vector<epoll_event> events_;
  BatchProcessingStats stats_;

  // Adaptive sizing state
  std::size_t currentBatchSize_;
  std::chrono::steady_clock::time_point lastAdjustment_{std::chrono::steady_clock::now()};
};

// Helper function to create processor with common configuration
inline std::unique_ptr<EventBatchProcessor> createOptimizedProcessor(std::size_t expectedLoad = 32)
{
  BatchProcessingConfig config;
  config.maxBatchSize = std::max(8UL, expectedLoad * 2); // 2x expected load
  config.maxBatchDelay = std::chrono::microseconds(50);  // Low latency
  config.adaptiveThreshold = std::chrono::microseconds(25);
  config.enableAdaptiveSizing = true;
  config.loadFactor = 0.7; // Target 70% utilization

  return std::make_unique<EventBatchProcessor>(config);
}

// Helper for high-throughput scenarios
inline std::unique_ptr<EventBatchProcessor> createHighThroughputProcessor()
{
  BatchProcessingConfig config;
  config.maxBatchSize = 128;                             // Large batches
  config.maxBatchDelay = std::chrono::microseconds(200); // Allow more batching
  config.adaptiveThreshold = std::chrono::microseconds(150);
  config.enableAdaptiveSizing = true;
  config.loadFactor = 0.8; // Higher utilization acceptable

  return std::make_unique<EventBatchProcessor>(config);
}

// Helper for low-latency scenarios
inline std::unique_ptr<EventBatchProcessor> createLowLatencyProcessor()
{
  BatchProcessingConfig config;
  config.maxBatchSize = 16;                             // Small batches
  config.maxBatchDelay = std::chrono::microseconds(10); // Very low delay
  config.adaptiveThreshold = std::chrono::microseconds(5);
  config.enableAdaptiveSizing = true;
  config.loadFactor = 0.5; // Prefer low latency over utilization

  return std::make_unique<EventBatchProcessor>(config);
}

} // namespace network
} // namespace iora