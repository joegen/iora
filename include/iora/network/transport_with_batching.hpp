// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include "event_batch_processor.hpp"
#include "transport_types.hpp"
#include <functional>
#include <memory>

namespace iora
{
namespace network
{

// Integration helper for adding batch processing to existing transports
template <typename BaseTransport> class BatchingTransportWrapper
{
public:
  using EventHandler = std::function<void(int fd, uint32_t events)>;

  template <typename... Args>
  explicit BatchingTransportWrapper(const BatchProcessingConfig &batchConfig, Args &&...args)
      : baseTransport_(std::forward<Args>(args)...),
        batchProcessor_(std::make_unique<EventBatchProcessor>(batchConfig))
  {
  }

  // Forward all BaseTransport methods
  auto &getBase() { return baseTransport_; }
  const auto &getBase() const { return baseTransport_; }

  // Enhanced event loop with batching
  template <typename SpecialHandler>
  void runBatchingEventLoop(int epollFd, int eventFd, int timerFd,
                            const EventHandler &sessionHandler,
                            const SpecialHandler &specialHandler)
  {
    auto generalHandler = [&sessionHandler](int fd, uint32_t events)
    { sessionHandler(fd, events); };

    auto specialFdHandler = [eventFd, timerFd, &specialHandler](int fd, uint32_t events) -> bool
    {
      if (fd == eventFd || fd == timerFd)
      {
        return specialHandler(fd, events);
      }
      return false;
    };

    batchProcessor_->processBatch(
      epollFd, generalHandler, specialFdHandler,
      [this](std::size_t batchSize, std::chrono::microseconds processingTime)
      { onBatchProcessed(batchSize, processingTime); });
  }

  // Convenience method for standard transport event loop integration
  void runTransportEventLoop(int epollFd, int eventFd, int timerFd,
                             const std::function<void()> &onEventFd,
                             const std::function<void()> &onTimerFd,
                             const EventHandler &sessionHandler)
  {
    batchProcessor_->processBatchWithSpecialFDs(
      epollFd, eventFd, timerFd, sessionHandler, onEventFd, onTimerFd,
      [this](std::size_t batchSize, std::chrono::microseconds processingTime)
      { onBatchProcessed(batchSize, processingTime); });
  }

  // Batch processing statistics
  BatchProcessingStats getBatchingStats() const { return batchProcessor_->getStats(); }

  void resetBatchingStats() { batchProcessor_->resetStats(); }

  void updateBatchingConfig(const BatchProcessingConfig &config)
  {
    batchProcessor_->updateConfig(config);
  }

  BatchProcessingConfig getBatchingConfig() const { return batchProcessor_->getConfig(); }

protected:
  virtual void onBatchProcessed(std::size_t batchSize, std::chrono::microseconds processingTime)
  {
    // Default implementation - derived classes can override for custom
    // metrics
    (void)batchSize;
    (void)processingTime;
  }

private:
  BaseTransport baseTransport_;
  std::unique_ptr<EventBatchProcessor> batchProcessor_;
};

// Specialization helper for common transport configurations
template <typename BaseTransport>
std::unique_ptr<BatchingTransportWrapper<BaseTransport>>
createOptimizedBatchingTransport(std::size_t expectedLoad = 32)
{
  auto config = BatchProcessingConfig{};
  config.maxBatchSize = std::max(8UL, expectedLoad * 2);
  config.maxBatchDelay = std::chrono::microseconds(50);
  config.enableAdaptiveSizing = true;
  config.loadFactor = 0.7;

  return std::make_unique<BatchingTransportWrapper<BaseTransport>>(config);
}

// Example usage patterns for different scenarios

// High-throughput server configuration
inline BatchProcessingConfig createServerConfig()
{
  BatchProcessingConfig config;
  config.maxBatchSize = 128;
  config.maxBatchDelay = std::chrono::microseconds(200);
  config.adaptiveThreshold = std::chrono::microseconds(100);
  config.enableAdaptiveSizing = true;
  config.loadFactor = 0.8;
  return config;
}

// Low-latency client configuration
inline BatchProcessingConfig createClientConfig()
{
  BatchProcessingConfig config;
  config.maxBatchSize = 16;
  config.maxBatchDelay = std::chrono::microseconds(10);
  config.adaptiveThreshold = std::chrono::microseconds(5);
  config.enableAdaptiveSizing = true;
  config.loadFactor = 0.5;
  return config;
}

// Balanced general-purpose configuration
inline BatchProcessingConfig createBalancedConfig()
{
  BatchProcessingConfig config;
  config.maxBatchSize = 32;
  config.maxBatchDelay = std::chrono::microseconds(50);
  config.adaptiveThreshold = std::chrono::microseconds(25);
  config.enableAdaptiveSizing = true;
  config.loadFactor = 0.7;
  return config;
}

} // namespace network
} // namespace iora