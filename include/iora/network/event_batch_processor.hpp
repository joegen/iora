// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <system_error>
#include <utility>
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
using EventHandler = std::function<void(int fd, std::uint32_t events)>;
using BatchCompleteHandler =
  std::function<void(std::size_t batchSize, std::chrono::microseconds processingTime)>;

// Batch event processor
class EventBatchProcessor
{
public:
  explicit EventBatchProcessor(const BatchProcessingConfig &config = {})
    : config_(config), currentBatchSize_(config.enableAdaptiveSizing ? config.maxBatchSize / 2 : config.maxBatchSize)
  {
    if (currentBatchSize_ == 0)
    {
      currentBatchSize_ = 1;
    }
    events_.resize(config_.maxBatchSize);
  }

  // Process events in batches with adaptive sizing
  template <typename SpecialEventHandler>
  void processBatch(int epollFd, const EventHandler &generalHandler,
                    const SpecialEventHandler &specialHandler,
                    const BatchCompleteHandler &onBatchComplete = nullptr)
  {
    auto batchStart = std::chrono::high_resolution_clock::now();

    // Determine batch size (adaptive or fixed), clamped to the actual buffer
    // capacity. currentBatchSize_ can exceed events_.size() on a degenerate
    // config: maxBatchSize==0 sizes events_ to 0 yet the ctor force-bumps
    // currentBatchSize_ to 1. Passing a maxevents larger than the buffer would let
    // epoll_wait write past it (heap overflow / EFAULT); a maxevents of 0 is EINVAL.
    // Clamp, and skip the drain entirely when the buffer is empty (safe no-op).
    const int maxEvents = static_cast<int>(std::min(getCurrentBatchSize(), events_.size()));
    if (maxEvents <= 0)
    {
      return;
    }

    // Wait for events with timeout (round up to at least 1ms to avoid busy-spin)
    int timeout = std::max(1, static_cast<int>((config_.maxBatchDelay.count() + 999) / 1000));
    int n = ::epoll_wait(epollFd, events_.data(), maxEvents, timeout);

    if (n < 0)
    {
      if (errno == EINTR)
        return;
      throw std::system_error(errno, std::system_category(), "epoll_wait failed");
    }

    if (n == 0)
      return; // Timeout with no events

    // Process the batch of events
    std::vector<std::pair<int, std::uint32_t>> normalEvents;
    normalEvents.reserve(n);

    for (int i = 0; i < n; ++i)
    {
      int fd = events_[i].data.fd;
      std::uint32_t eventMask = events_[i].events;

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
                                                                   std::uint32_t /*events*/) -> bool
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

  // Thread-safe snapshot: stats_ is mutated by the owning I/O thread inside
  // processBatch (updateStats/adjustBatchSize), but getStats() is reachable from
  // arbitrary caller threads (the transport engines' public getStats() overrides
  // forward here for off-thread monitoring). Copy stats_ under statsMutex_, then
  // compute the derived fields on the local copy outside the lock.
  BatchProcessingStats getStats() const
  {
    BatchProcessingStats stats;
    {
      std::lock_guard<std::mutex> lock(statsMutex_);
      stats = stats_;
    }

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

  // Owner-thread-only (writes the unguarded lastAdjustment_). The stats_ reset is
  // locked so it cannot race a concurrent getStats() reader.
  void resetStats()
  {
    {
      std::lock_guard<std::mutex> lock(statsMutex_);
      stats_ = {};
    }
    lastAdjustment_ = std::chrono::steady_clock::now();
  }

  // Owner-thread-only (rewrites config_/currentBatchSize_/events_). NOT cross-thread-safe.
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
    // Mirror the ctor's floor: never leave currentBatchSize_ at 0 (maxBatchSize==0,
    // or ==1 with adaptive on), which would wedge the drain to a permanent no-op.
    if (currentBatchSize_ == 0)
    {
      currentBatchSize_ = 1;
    }
  }

  // Owner-thread-only (reads config_). Unlike getStats() this is NOT cross-thread-safe:
  // do not poll it from a monitoring thread while updateConfig()/setFixedBatchSize() may run.
  BatchProcessingConfig getConfig() const { return config_; }

  // Force a specific batch size for testing. Owner-thread-only. Floors to 1 so a
  // setFixedBatchSize(0) — or any size with maxBatchSize==0 — never wedges the drain.
  void setFixedBatchSize(std::size_t size)
  {
    config_.enableAdaptiveSizing = false;
    currentBatchSize_ = std::min(size, config_.maxBatchSize);
    if (currentBatchSize_ == 0)
    {
      currentBatchSize_ = 1;
    }
  }

private:
  std::size_t getCurrentBatchSize() const
  {
    // currentBatchSize_ tracks the effective bound in ALL modes: the adaptive
    // controller updates it when enableAdaptiveSizing is on; the constructor and
    // updateConfig() seed it to maxBatchSize when adaptive is off; and
    // setFixedBatchSize() pins it. Returning it unconditionally is what makes the
    // setFixedBatchSize() pin actually reach epoll_wait (this previously returned
    // config_.maxBatchSize whenever adaptive sizing was off, so the pin was inert).
    return currentBatchSize_;
  }

  void updateStats(int eventCount, std::chrono::microseconds processingTime)
  {
    std::lock_guard<std::mutex> lock(statsMutex_);
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

    // 25% step, at least 1 (shared by the grow and shrink branches).
    const std::size_t step = std::max<std::size_t>(1, currentBatchSize_ / 4);
    bool adjusted = false;
    if (shouldIncrease && currentBatchSize_ < config_.maxBatchSize)
    {
      currentBatchSize_ = std::min(config_.maxBatchSize, currentBatchSize_ + step);
      adjusted = true;
    }
    else if (shouldDecrease && currentBatchSize_ > 1)
    {
      // Floor at 1 on the shrink side.
      currentBatchSize_ = std::max<std::size_t>(1, currentBatchSize_ - step);
      adjusted = true;
    }
    if (adjusted)
    {
      std::lock_guard<std::mutex> lock(statsMutex_);
      stats_.adaptiveAdjustments++;
    }
  }

private:
  BatchProcessingConfig config_;
  std::vector<epoll_event> events_;
  BatchProcessingStats stats_;
  // Guards stats_ ONLY. stats_ is written by the owning I/O thread (updateStats /
  // adjustBatchSize) and read by getStats(), which the transport engines forward
  // from arbitrary monitoring threads — so getStats() is the ONE cross-thread-safe
  // method. Every OTHER method is OWNER-THREAD-ONLY, including resetStats() (it also
  // writes the unguarded lastAdjustment_) and updateConfig()/setFixedBatchSize()
  // (they mutate config_/currentBatchSize_/events_). Those members — config_,
  // currentBatchSize_, events_, lastAdjustment_ — are owner-thread-only and MUST NOT
  // be touched from another thread while the I/O loop runs. resetStats() still locks
  // statsMutex_ for its stats_ reset so that reset cannot race a concurrent getStats().
  mutable std::mutex statsMutex_;

  // Adaptive sizing state
  std::size_t currentBatchSize_{0};
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