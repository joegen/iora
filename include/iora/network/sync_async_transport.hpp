// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once
#ifndef __linux__
#error "Linux-only (epoll/eventfd/timerfd)"
#endif

/// \file sync_async_transport.hpp
/// \brief Synchronous/asynchronous transport wrapper for SIP and similar
/// protocols \details
///   - Provides both sync and async operations on the same connection
///   - Exclusive read modes prevent simultaneous sync/async read conflicts
///   - Thread-safe synchronous operations with queueing
///   - Cancellable operations without closing connections
///   - Connection health monitoring for application-level decisions
///

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "connection_health.hpp"
#include "iora/core/logger.hpp"
#include "transport_types.hpp"

namespace iora
{
namespace network
{

// Forward declarations
struct UnifiedStats;

/// \brief Basic transport statistics (to avoid circular dependencies)
struct BasicTransportStats
{
  std::uint64_t accepted{0};
  std::uint64_t connected{0};
  std::uint64_t closed{0};
  std::uint64_t errors{0};
  std::uint64_t bytesIn{0};
  std::uint64_t bytesOut{0};
  std::size_t sessionsCurrent{0};
};

/// \brief Base transport interface for SyncAsyncTransport
/// \note Minimal interface to avoid circular dependencies
class ITransportBase
{
public:
  virtual ~ITransportBase() = default;
  virtual bool start() = 0;
  virtual void stop() = 0;
  virtual ListenerId addListener(const std::string &bindIp, std::uint16_t port,
                                 TlsMode tlsMode) = 0;
  virtual SessionId connect(const std::string &host, std::uint16_t port, TlsMode tlsMode) = 0;
  virtual bool send(SessionId sid, const void *data, std::size_t n) = 0;
  virtual bool close(SessionId sid) = 0;

  // Use basic callbacks to avoid dependency on UnifiedCallbacks
  using DataCallback =
    std::function<void(SessionId, const std::uint8_t *, std::size_t, const IoResult &)>;
  using AcceptCallback = std::function<void(SessionId, const std::string &, const IoResult &)>;
  using ConnectCallback = std::function<void(SessionId, const IoResult &)>;
  using CloseCallback = std::function<void(SessionId, const IoResult &)>;
  using ErrorCallback = std::function<void(TransportError, const std::string &)>;

  virtual void setDataCallback(DataCallback cb) = 0;
  virtual void setAcceptCallback(AcceptCallback cb) = 0;
  virtual void setConnectCallback(ConnectCallback cb) = 0;
  virtual void setCloseCallback(CloseCallback cb) = 0;
  virtual void setErrorCallback(ErrorCallback cb) = 0;

  virtual BasicTransportStats getBasicStats() const = 0;
};

/// \brief Token for cancelling synchronous operations
/// \note Non-copyable to ensure clear ownership semantics
class CancellationToken
{
public:
  CancellationToken() : _cancelled(std::make_shared<std::atomic<bool>>(false)) {}

  // Delete copy operations to prevent shared state confusion
  CancellationToken(const CancellationToken &) = delete;
  CancellationToken &operator=(const CancellationToken &) = delete;

  // Allow move operations for transferring ownership
  CancellationToken(CancellationToken &&) = default;
  CancellationToken &operator=(CancellationToken &&) = default;

  /// \brief Cancel any operations using this token
  void cancel()
  {
    _cancelled->store(true);
    std::lock_guard<std::mutex> lock(_mutex);
    for (auto &cv : _waiters)
    {
      cv->notify_all();
    }
  }

  /// \brief Check if token has been cancelled
  bool isCancelled() const { return _cancelled->load(); }

  /// \brief Reset token for reuse
  void reset()
  {
    _cancelled->store(false);
    std::lock_guard<std::mutex> lock(_mutex);
    _waiters.clear();
  }

  /// \brief Register a condition variable to be notified on cancellation
  void registerWaiter(std::shared_ptr<std::condition_variable> cv)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _waiters.push_back(cv);
  }

  /// \brief Unregister a condition variable
  void unregisterWaiter(std::shared_ptr<std::condition_variable> cv)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _waiters.erase(std::remove(_waiters.begin(), _waiters.end(), cv), _waiters.end());
  }

private:
  std::shared_ptr<std::atomic<bool>> _cancelled;
  mutable std::mutex _mutex;
  std::vector<std::shared_ptr<std::condition_variable>> _waiters;
};

/// \brief Source for creating linked cancellation tokens
/// \note Use this when you need hierarchical cancellation (cancel all
/// children)
class CancellationTokenSource
{
public:
  CancellationTokenSource() = default;

  // Non-copyable but movable
  CancellationTokenSource(const CancellationTokenSource &) = delete;
  CancellationTokenSource &operator=(const CancellationTokenSource &) = delete;
  CancellationTokenSource(CancellationTokenSource &&) = default;
  CancellationTokenSource &operator=(CancellationTokenSource &&) = default;

  /// \brief Create a linked token that will be cancelled when source is
  /// cancelled
  std::shared_ptr<CancellationToken> createToken()
  {
    auto token = std::make_shared<CancellationToken>();
    std::lock_guard<std::mutex> lock(_mutex);
    _tokens.push_back(token);
    return token;
  }

  /// \brief Cancel all tokens created from this source
  void cancelAll()
  {
    std::lock_guard<std::mutex> lock(_mutex);
    for (auto &weakToken : _tokens)
    {
      if (auto token = weakToken.lock())
      {
        token->cancel();
      }
    }
    _tokens.clear();
  }

  /// \brief Get the number of active tokens
  size_t activeTokenCount() const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    size_t count = 0;
    for (const auto &weakToken : _tokens)
    {
      if (weakToken.lock())
      {
        count++;
      }
    }
    return count;
  }

private:
  mutable std::mutex _mutex;
  std::vector<std::weak_ptr<CancellationToken>> _tokens;
};

/// \brief Detailed connection health metrics for hybrid transport
struct HybridConnectionHealth
{
  bool isHealthy{true};
  std::chrono::steady_clock::time_point lastActivity;
  std::chrono::steady_clock::time_point lastError;
  std::uint32_t errorCount{0};
  std::uint32_t successCount{0};
  std::chrono::milliseconds averageRtt{0};
  std::size_t pendingOperations{0};
  std::size_t bytesIn{0};
  std::size_t bytesOut{0};
  TransportError lastErrorType{TransportError::None};
  std::string lastErrorMessage;
};

/// \brief Read mode for exclusive access control
enum class ReadMode
{
  Async,   ///< Callback-based reads (default)
  Sync,    ///< Blocking reads via receiveSync()
  Disabled ///< No reads allowed
};

/// \brief Result of a sync operation with detailed error info
struct SyncResult
{
  bool ok{false};
  TransportError error{TransportError::None};
  std::string errorMessage;
  int sysError{0};
  int tlsError{0};
  std::size_t bytesTransferred{0};
  std::chrono::milliseconds duration{0};

  static SyncResult success(std::size_t bytes = 0)
  {
    SyncResult r;
    r.ok = true;
    r.bytesTransferred = bytes;
    return r;
  }

  static SyncResult failure(TransportError err, const std::string &msg, int sysErr = 0,
                            int tlsErr = 0)
  {
    SyncResult r;
    r.ok = false;
    r.error = err;
    r.errorMessage = msg;
    r.sysError = sysErr;
    r.tlsError = tlsErr;
    return r;
  }

  static SyncResult cancelled()
  {
    return failure(TransportError::Cancelled, "Operation cancelled");
  }

  static SyncResult timeout() { return failure(TransportError::Timeout, "Operation timed out"); }
};

/// \brief Synchronous/asynchronous transport providing both sync and async operations
class SyncAsyncTransport
{
public:
  using DataCallback =
    std::function<void(SessionId, const std::uint8_t *, std::size_t, const IoResult &)>;
  using ConnectCallback = std::function<void(SessionId, const IoResult &)>;
  using CloseCallback = std::function<void(SessionId, const IoResult &)>;
  using ErrorCallback = std::function<void(TransportError, const std::string &)>;
  using SendCompleteCallback = std::function<void(SessionId, const SyncResult &)>;

  /// \brief Configuration for sync/async transport
  struct Config
  {
    std::size_t maxPendingSyncOps{32};               ///< Max queued sync operations per session
    std::size_t maxSyncReceiveBuffer{1024 * 1024};   ///< Max buffer for sync receives
    std::chrono::milliseconds defaultTimeout{30000}; ///< Default sync operation timeout
    bool allowReadModeSwitch{true};                  ///< Allow switching between read modes
    bool autoHealthMonitoring{true};                 ///< Automatically track connection health

    /// \brief Default constructor
    Config() = default;

    /// \brief Get default configuration
    static Config defaultConfig() { return Config{}; }
  };

  /// \brief Construct with underlying transport and default configuration
  explicit SyncAsyncTransport(std::unique_ptr<ITransportBase> transport)
      : _transport(std::move(transport)), _config(Config::defaultConfig())
  {
    setupInternalCallbacks();
  }

  /// \brief Construct with underlying transport and configuration
  SyncAsyncTransport(std::unique_ptr<ITransportBase> transport, const Config &config)
      : _transport(std::move(transport)), _config(config)
  {
    setupInternalCallbacks();
  }

  ~SyncAsyncTransport() { stop(); }

  // Disable copy/move
  SyncAsyncTransport(const SyncAsyncTransport &) = delete;
  SyncAsyncTransport &operator=(const SyncAsyncTransport &) = delete;

  /// \brief Start the transport
  bool start()
  {
    std::lock_guard<std::mutex> lock(_mutex);
    if (_running)
    {
      return false;
    }

    if (!_transport->start())
    {
      return false;
    }

    _running = true;
    _processingThread = std::thread([this] { processOperations(); });
    return true;
  }

  /// \brief Stop the transport
  void stop()
  {
    iora::core::Logger::debug("SyncAsyncTransport::stop() - Starting");
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (!_running)
      {
        iora::core::Logger::debug("SyncAsyncTransport::stop() - Already stopped");
        return;
      }
      _running = false;
      _stopCv.notify_all();
    }

    iora::core::Logger::debug("SyncAsyncTransport::stop() - Cancelling all operations");
    // Cancel all pending operations
    cancelAllOperations();

    if (_processingThread.joinable())
    {
      iora::core::Logger::debug("SyncAsyncTransport::stop() - Joining processing thread");
      _processingThread.join();
      iora::core::Logger::debug("SyncAsyncTransport::stop() - Processing thread joined");
    }

    iora::core::Logger::debug("SyncAsyncTransport::stop() - Stopping underlying transport");
    _transport->stop();
    iora::core::Logger::debug("SyncAsyncTransport::stop() - Completed");
  }

  // ===== Read Mode Management =====

  /// \brief Set the read mode for a session (exclusive access)
  /// \return true if mode was successfully set, false if operation in
  /// progress
  bool setReadMode(SessionId sid, ReadMode mode)
  {
    std::lock_guard<std::mutex> lock(_sessionMutex);
    auto &session = getOrCreateSession(sid);

    // Check if there's an active operation preventing mode switch
    if (session.syncReadActive || session.pendingSyncReads > 0)
    {
      if (!_config.allowReadModeSwitch)
      {
        return false;
      }
      // Wait for operations to complete if switching is allowed
      waitForPendingReads(session);
    }

    ReadMode oldMode = session.readMode;
    session.readMode = mode;

    // Clear callback if switching away from async
    if (oldMode == ReadMode::Async && mode != ReadMode::Async)
    {
      session.asyncDataCallback = nullptr;
    }

    return true;
  }

  /// \brief Get current read mode for a session
  ReadMode getReadMode(SessionId sid) const
  {
    std::lock_guard<std::mutex> lock(_sessionMutex);
    auto it = _sessions.find(sid);
    if (it != _sessions.end())
    {
      return it->second.readMode;
    }
    return ReadMode::Async; // Default
  }

  // ===== Async Operations =====

  /// \brief Set async data callback (only works in Async read mode)
  bool setDataCallback(SessionId sid, DataCallback cb)
  {
    std::lock_guard<std::mutex> lock(_sessionMutex);
    auto &session = getOrCreateSession(sid);

    if (session.readMode != ReadMode::Async)
    {
      return false;
    }

    session.asyncDataCallback = cb;
    return true;
  }

  /// \brief Set async connect callback
  void setConnectCallback(ConnectCallback cb)
  {
    std::lock_guard<std::mutex> lock(_callbackMutex);
    _connectCallback = cb;
  }

  /// \brief Set async close callback
  void setCloseCallback(CloseCallback cb)
  {
    std::lock_guard<std::mutex> lock(_callbackMutex);
    _closeCallback = cb;
  }

  /// \brief Set async error callback
  void setErrorCallback(ErrorCallback cb)
  {
    std::lock_guard<std::mutex> lock(_callbackMutex);
    _errorCallback = cb;
  }

  /// \brief Async send with completion callback
  void sendAsync(SessionId sid, const void *data, std::size_t len,
                 SendCompleteCallback cb = nullptr)
  {
    // Direct pass-through to underlying async transport
    bool queued = _transport->send(sid, data, len);

    if (cb)
    {
      if (queued)
      {
        // Track for completion notification if needed
        std::lock_guard<std::mutex> lock(_sessionMutex);
        auto &session = getOrCreateSession(sid);
        session.pendingAsyncSends.push_back(cb);
      }
      else
      {
        cb(sid, SyncResult::failure(TransportError::Unknown, "Failed to queue send"));
      }
    }

    updateHealth(sid, queued, len, true);
  }

  // ===== Sync Operations =====

  /// \brief Synchronous send - blocks until complete or timeout
  SyncResult sendSync(SessionId sid, const void *data, std::size_t len,
                      std::chrono::milliseconds timeout = std::chrono::milliseconds::max())
  {
    if (timeout == std::chrono::milliseconds::max())
    {
      timeout = _config.defaultTimeout;
    }

    core::Logger::debug("SyncAsyncTransport: sendSync starting for session " + std::to_string(sid) +
                        ", len=" + std::to_string(len) +
                        ", timeout=" + std::to_string(timeout.count()) + "ms");

    auto operation = std::make_shared<SyncOperation>();
    operation->type = SyncOperation::Type::Send;
    operation->sessionId = sid;
    operation->data.assign(static_cast<const std::uint8_t *>(data),
                           static_cast<const std::uint8_t *>(data) + len);
    operation->timeout = timeout;
    operation->startTime = std::chrono::steady_clock::now();

    // Queue the operation
    {
      std::lock_guard<std::mutex> lock(_sessionMutex);
      auto &session = getOrCreateSession(sid);

      if (session.pendingSyncOps.size() >= _config.maxPendingSyncOps)
      {
        return SyncResult::failure(TransportError::WriteBackpressure,
                                   "Too many pending operations");
      }

      session.pendingSyncOps.push_back(operation);
      _operationCv.notify_one();
    }

    // Wait for completion
    std::unique_lock<std::mutex> lock(operation->mutex);
    bool completed =
      operation->cv.wait_for(lock, timeout, [operation] { return operation->completed.load(); });

    if (!completed)
    {
      operation->cancelled = true;
      core::Logger::debug("SyncAsyncTransport: sendSync timed out for session " +
                          std::to_string(sid));
      return SyncResult::timeout();
    }

    updateHealth(sid, operation->result.ok, len, true);

    core::Logger::debug("SyncAsyncTransport: sendSync completed for session " +
                        std::to_string(sid) +
                        ", success=" + (operation->result.ok ? "true" : "false") +
                        ", error=" + operation->result.errorMessage);

    return operation->result;
  }

  /// \brief Cancellable synchronous send
  SyncResult
  sendSyncCancellable(SessionId sid, const void *data, std::size_t len, CancellationToken &token,
                      std::chrono::milliseconds timeout = std::chrono::milliseconds::max())
  {
    if (timeout == std::chrono::milliseconds::max())
    {
      timeout = _config.defaultTimeout;
    }

    auto operation = std::make_shared<SyncOperation>();
    operation->type = SyncOperation::Type::Send;
    operation->sessionId = sid;
    operation->data.assign(static_cast<const std::uint8_t *>(data),
                           static_cast<const std::uint8_t *>(data) + len);
    operation->timeout = timeout;
    operation->startTime = std::chrono::steady_clock::now();
    operation->cancellationToken = &token;

    // Register for cancellation
    auto cvPtr =
      std::shared_ptr<std::condition_variable>(&operation->cv, [](std::condition_variable *) {});
    token.registerWaiter(cvPtr);

    // Queue the operation
    {
      std::lock_guard<std::mutex> lock(_sessionMutex);
      auto &session = getOrCreateSession(sid);

      if (session.pendingSyncOps.size() >= _config.maxPendingSyncOps)
      {
        token.unregisterWaiter(cvPtr);
        return SyncResult::failure(TransportError::WriteBackpressure,
                                   "Too many pending operations");
      }

      session.pendingSyncOps.push_back(operation);
      _operationCv.notify_one();
    }

    // Wait for completion or cancellation
    std::unique_lock<std::mutex> lock(operation->mutex);
    bool completed =
      operation->cv.wait_for(lock, timeout, [operation, &token]
                             { return operation->completed.load() || token.isCancelled(); });

    token.unregisterWaiter(cvPtr);

    if (token.isCancelled())
    {
      operation->cancelled = true;
      return SyncResult::cancelled();
    }

    if (!completed)
    {
      operation->cancelled = true;
      return SyncResult::timeout();
    }

    updateHealth(sid, operation->result.ok, len, true);
    return operation->result;
  }

  /// \brief Synchronous receive - blocks until data available or timeout
  /// \note Only works in Sync read mode
  SyncResult receiveSync(SessionId sid, void *buffer, std::size_t &len,
                         std::chrono::milliseconds timeout = std::chrono::milliseconds::max())
  {
    if (timeout == std::chrono::milliseconds::max())
    {
      timeout = _config.defaultTimeout;
    }

    std::unique_lock<std::mutex> lock(_sessionMutex);
    auto &session = getOrCreateSession(sid);

    // Check read mode
    if (session.readMode != ReadMode::Sync)
    {
      return SyncResult::failure(TransportError::Config, "Session not in Sync read mode");
    }

    // Mark sync read as active
    session.syncReadActive = true;
    session.pendingSyncReads++;

    // Wait for data or session closure
    bool hasData = session.readCv.wait_for(
      lock, timeout,
      [&] { return !session.readBuffer.empty() || !_running || session.closed.load(); });

    session.syncReadActive = false;
    session.pendingSyncReads--;

    if (!_running)
    {
      return SyncResult::failure(TransportError::Unknown, "Transport stopped");
    }

    if (session.closed.load())
    {
      core::Logger::debug("SyncAsyncTransport: receiveSync detected closed session " +
                          std::to_string(sid));
      return SyncResult::failure(TransportError::PeerClosed, "Session closed during receive");
    }

    if (!hasData)
    {
      return SyncResult::timeout();
    }

    // Copy data to user buffer
    auto &front = session.readBuffer.front();
    std::size_t copyLen = std::min(len, front.size());
    std::memcpy(buffer, front.data(), copyLen);
    len = copyLen;

    // Remove consumed data
    if (copyLen >= front.size())
    {
      session.readBuffer.pop_front();
    }
    else
    {
      // Partial read - keep remaining data
      front.erase(front.begin(), front.begin() + copyLen);
    }

    // Release the lock before calling updateHealth to avoid deadlock
    lock.unlock();

    updateHealth(sid, true, copyLen, false);
    return SyncResult::success(copyLen);
  }

  /// \brief Cancellable synchronous receive
  SyncResult
  receiveSyncCancellable(SessionId sid, void *buffer, std::size_t &len, CancellationToken &token,
                         std::chrono::milliseconds timeout = std::chrono::milliseconds::max())
  {
    if (timeout == std::chrono::milliseconds::max())
    {
      timeout = _config.defaultTimeout;
    }

    std::unique_lock<std::mutex> lock(_sessionMutex);
    auto &session = getOrCreateSession(sid);

    // Check read mode
    if (session.readMode != ReadMode::Sync)
    {
      return SyncResult::failure(TransportError::Config, "Session not in Sync read mode");
    }

    // Mark sync read as active
    session.syncReadActive = true;
    session.pendingSyncReads++;

    // Register for cancellation
    auto cvPtr =
      std::shared_ptr<std::condition_variable>(&session.readCv, [](std::condition_variable *) {});
    token.registerWaiter(cvPtr);

    // Wait for data or cancellation
    bool hasData = session.readCv.wait_for(
      lock, timeout,
      [&] { return !session.readBuffer.empty() || !_running || token.isCancelled(); });

    token.unregisterWaiter(cvPtr);

    session.syncReadActive = false;
    session.pendingSyncReads--;

    if (token.isCancelled())
    {
      return SyncResult::cancelled();
    }

    if (!_running)
    {
      return SyncResult::failure(TransportError::Unknown, "Transport stopped");
    }

    if (!hasData)
    {
      return SyncResult::timeout();
    }

    // Copy data to user buffer
    auto &front = session.readBuffer.front();
    std::size_t copyLen = std::min(len, front.size());
    std::memcpy(buffer, front.data(), copyLen);
    len = copyLen;

    // Remove consumed data
    if (copyLen >= front.size())
    {
      session.readBuffer.pop_front();
    }
    else
    {
      // Partial read - keep remaining data
      front.erase(front.begin(), front.begin() + copyLen);
    }

    updateHealth(sid, true, copyLen, false);
    return SyncResult::success(copyLen);
  }

  // ===== Connection Management =====

  /// \brief Add a listener
  ListenerId addListener(const std::string &bind, std::uint16_t port, TlsMode tls = TlsMode::None)
  {
    return _transport->addListener(bind, port, tls);
  }

  /// \brief Connect to a remote host
  SessionId connect(const std::string &host, std::uint16_t port, TlsMode tls = TlsMode::None)
  {
    SessionId sid = _transport->connect(host, port, tls);
    if (sid != 0)
    {
      std::lock_guard<std::mutex> lock(_sessionMutex);
      getOrCreateSession(sid); // Initialize session state
    }
    return sid;
  }

  /// \brief Close a session
  bool close(SessionId sid)
  {
    // Clean up session state
    {
      std::lock_guard<std::mutex> lock(_sessionMutex);
      auto it = _sessions.find(sid);
      if (it != _sessions.end())
      {
        // Cancel pending operations
        for (auto &op : it->second.pendingSyncOps)
        {
          op->cancelled = true;
          op->result = SyncResult::failure(TransportError::Unknown, "Session closed");
          op->completed = true;
          op->cv.notify_all();
        }
        it->second.pendingSyncOps.clear();
        it->second.readCv.notify_all();
      }
    }

    return _transport->close(sid);
  }

  /// \brief Cancel all pending sync operations for a session
  void cancelPendingOperations(SessionId sid)
  {
    std::lock_guard<std::mutex> lock(_sessionMutex);
    auto it = _sessions.find(sid);
    if (it != _sessions.end())
    {
      for (auto &op : it->second.pendingSyncOps)
      {
        op->cancelled = true;
        op->result = SyncResult::cancelled();
        op->completed = true;
        op->cv.notify_all();
      }
      it->second.pendingSyncOps.clear();
    }
  }

  /// \brief Get connection health metrics
  HybridConnectionHealth getConnectionHealth(SessionId sid) const
  {
    std::lock_guard<std::mutex> lock(_sessionMutex);
    auto it = _sessions.find(sid);
    if (it != _sessions.end())
    {
      return it->second.health;
    }
    // Return health indicating session doesn't exist (closed/failed)
    HybridConnectionHealth nonExistent{};
    nonExistent.isHealthy = false;
    nonExistent.errorCount = 1;
    nonExistent.lastErrorType = TransportError::PeerClosed;
    nonExistent.lastErrorMessage = "Session does not exist (closed)";
    return nonExistent;
  }

  /// \brief Get access to underlying transport (for stats, etc.)
  ITransportBase *getTransport() const { return _transport.get(); }

  // Note: getStats() method moved to UnifiedSharedTransport to avoid circular
  // dependencies

private:
  struct SyncOperation
  {
    enum class Type
    {
      Send,
      Receive
    };

    Type type;
    SessionId sessionId;
    std::vector<std::uint8_t> data;
    std::chrono::milliseconds timeout;
    std::chrono::steady_clock::time_point startTime;

    std::mutex mutex;
    std::condition_variable cv;
    std::atomic<bool> completed{false};
    std::atomic<bool> cancelled{false};
    SyncResult result;

    CancellationToken *cancellationToken{nullptr};
  };

  struct SessionState
  {
    ReadMode readMode{ReadMode::Async};

    // Async state
    DataCallback asyncDataCallback;
    std::vector<SendCompleteCallback> pendingAsyncSends;

    // Sync state
    std::atomic<bool> syncReadActive{false};
    std::atomic<std::uint32_t> pendingSyncReads{0};
    std::deque<std::vector<std::uint8_t>> readBuffer;
    std::condition_variable readCv;
    std::deque<std::shared_ptr<SyncOperation>> pendingSyncOps;
    std::atomic<bool> closed{false}; // Flag to indicate session is closed

    // Health monitoring
    HybridConnectionHealth health;

    SessionState()
    {
      health.lastActivity = std::chrono::steady_clock::now();
      health.isHealthy = false; // Start as unhealthy until connection completes
    }

    // Non-copyable due to condition_variable
    SessionState(const SessionState &) = delete;
    SessionState &operator=(const SessionState &) = delete;

    // Non-movable due to condition_variable
    SessionState(SessionState &&) = delete;
    SessionState &operator=(SessionState &&) = delete;
  };

  SessionState &getOrCreateSession(SessionId sid)
  {
    auto it = _sessions.find(sid);
    if (it == _sessions.end())
    {
      it = _sessions
             .emplace(std::piecewise_construct, std::forward_as_tuple(sid), std::forward_as_tuple())
             .first;
    }
    return it->second;
  }

  void waitForPendingReads(SessionState &session)
  {
    // Simple spin-wait for pending reads to complete
    // In production, might want a more sophisticated approach
    while (session.syncReadActive || session.pendingSyncReads > 0)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }

  void setupInternalCallbacks()
  {
    // Data callback router
    _transport->setDataCallback(
      [this](SessionId sid, const std::uint8_t *data, std::size_t len, const IoResult &result)
      { handleIncomingData(sid, data, len, result); });

    // Accept callback pass-through
    _transport->setAcceptCallback(
      [this](SessionId sid, const std::string &peer, const IoResult &result)
      {
        if (result.ok)
        {
          std::lock_guard<std::mutex> lock(_sessionMutex);
          getOrCreateSession(sid); // Initialize session state
        }
      });

    // Connect callback pass-through
    _transport->setConnectCallback(
      [this](SessionId sid, const IoResult &result)
      {
        std::lock_guard<std::mutex> lock(_callbackMutex);
        if (_connectCallback)
        {
          _connectCallback(sid, result);
        }

        // Update health
        if (result.ok)
        {
          std::lock_guard<std::mutex> slock(_sessionMutex);
          auto &session = getOrCreateSession(sid);
          session.health.isHealthy = true;
          session.health.lastActivity = std::chrono::steady_clock::now();
        }
      });

    // Close callback pass-through
    _transport->setCloseCallback(
      [this](SessionId sid, const IoResult &result)
      {
        core::Logger::debug("SyncAsyncTransport: Close callback for session " +
                            std::to_string(sid));
        // Clean up session state
        {
          std::lock_guard<std::mutex> lock(_sessionMutex);
          auto it = _sessions.find(sid);
          if (it != _sessions.end())
          {
            core::Logger::debug("SyncAsyncTransport: Waking " +
                                std::to_string(it->second.pendingSyncOps.size()) +
                                " pending sync operations");

            // Mark session as closed before waking operations
            it->second.closed = true;

            // Wake any waiting sync operations
            for (auto &op : it->second.pendingSyncOps)
            {
              op->result = SyncResult::failure(TransportError::PeerClosed, "Connection closed");
              op->completed = true;
              op->cv.notify_all();
            }
            it->second.readCv.notify_all();
            _sessions.erase(it);
          }
        }

        std::lock_guard<std::mutex> lock(_callbackMutex);
        if (_closeCallback)
        {
          _closeCallback(sid, result);
        }
      });

    // Error callback pass-through
    _transport->setErrorCallback(
      [this](TransportError error, const std::string &msg)
      {
        std::lock_guard<std::mutex> lock(_callbackMutex);
        if (_errorCallback)
        {
          _errorCallback(error, msg);
        }
      });
  }

  void handleIncomingData(SessionId sid, const std::uint8_t *data, std::size_t len,
                          const IoResult &result)
  {
    if (len > 0 && len < 200)
    {
      std::string dataStr(reinterpret_cast<const char *>(data), len);
    }

    DataCallback asyncCallback = nullptr;

    // Critical section for session access
    {
      std::lock_guard<std::mutex> lock(_sessionMutex);
      auto it = _sessions.find(sid);
      if (it == _sessions.end())
      {
        return; // Unknown session
      }

      auto &session = it->second;

      // Update health metrics
      if (_config.autoHealthMonitoring)
      {
        session.health.lastActivity = std::chrono::steady_clock::now();
        session.health.bytesIn += len;
        if (result.ok)
        {
          session.health.successCount++;
        }
        else
        {
          session.health.errorCount++;
          session.health.lastError = std::chrono::steady_clock::now();
          session.health.lastErrorType = result.code;
          session.health.lastErrorMessage = result.message;
        }
      }

      // Route based on read mode
      switch (session.readMode)
      {
      case ReadMode::Async:
        if (session.asyncDataCallback)
        {
          // Copy callback to call outside lock
          asyncCallback = session.asyncDataCallback;
        }
        break;

      case ReadMode::Sync:
        // Buffer data for sync reader
        if (len > 0 && result.ok)
        {
          session.readBuffer.emplace_back(data, data + len);
          session.readCv.notify_one();
        }
        break;

      case ReadMode::Disabled:
        // Drop data
        break;
      }
    } // Lock released here

    // Call async callback outside the lock to avoid deadlock
    if (asyncCallback)
    {
      asyncCallback(sid, data, len, result);
    }
  }

  void processOperations()
  {
    while (_running)
    {
      std::unique_lock<std::mutex> lock(_mutex);
      _operationCv.wait_for(lock, std::chrono::milliseconds(100),
                            [this] { return !_running || hasQueuedOperations(); });

      if (!_running)
      {
        break;
      }

      // Process queued sync operations
      processSyncOperations();
    }
  }

  bool hasQueuedOperations()
  {
    std::lock_guard<std::mutex> lock(_sessionMutex);
    for (const auto &[sid, session] : _sessions)
    {
      if (!session.pendingSyncOps.empty())
      {
        return true;
      }
    }
    return false;
  }

  void processSyncOperations()
  {
    std::lock_guard<std::mutex> lock(_sessionMutex);

    for (auto &[sid, session] : _sessions)
    {
      while (!session.pendingSyncOps.empty())
      {
        auto op = session.pendingSyncOps.front();

        // Check if cancelled or timed out
        if (op->cancelled || (std::chrono::steady_clock::now() - op->startTime) > op->timeout)
        {
          op->result = op->cancelled ? SyncResult::cancelled() : SyncResult::timeout();
          op->completed = true;
          op->cv.notify_all();
          session.pendingSyncOps.pop_front();
          continue;
        }

        // Process based on type
        if (op->type == SyncOperation::Type::Send)
        {
          // Execute the send
          bool sent = _transport->send(sid, op->data.data(), op->data.size());

          auto elapsed = std::chrono::steady_clock::now() - op->startTime;
          op->result = sent ? SyncResult::success(op->data.size())
                            : SyncResult::failure(TransportError::Unknown, "Send failed");
          op->result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);

          op->completed = true;
          op->cv.notify_all();
          session.pendingSyncOps.pop_front();
        }
      }
    }
  }

  void cancelAllOperations()
  {
    std::lock_guard<std::mutex> lock(_sessionMutex);
    for (auto &[sid, session] : _sessions)
    {
      for (auto &op : session.pendingSyncOps)
      {
        op->cancelled = true;
        op->result = SyncResult::cancelled();
        op->completed = true;
        op->cv.notify_all();
      }
      session.pendingSyncOps.clear();
      session.readCv.notify_all();
    }
  }

  void updateHealth(SessionId sid, bool success, std::size_t bytes, bool isSend)
  {
    if (!_config.autoHealthMonitoring)
    {
      return;
    }

    std::lock_guard<std::mutex> lock(_sessionMutex);
    auto it = _sessions.find(sid);
    if (it == _sessions.end())
    {
      return;
    }

    auto &health = it->second.health;
    health.lastActivity = std::chrono::steady_clock::now();

    if (isSend)
    {
      health.bytesOut += bytes;
    }
    else
    {
      health.bytesIn += bytes;
    }

    if (success)
    {
      health.successCount++;
      // Simple health calculation
      health.isHealthy = (health.errorCount == 0) || (health.successCount > health.errorCount * 10);
    }
    else
    {
      health.errorCount++;
      health.lastError = std::chrono::steady_clock::now();
      health.isHealthy = false;
    }

    health.pendingOperations = it->second.pendingSyncOps.size();
  }

private:
  std::unique_ptr<ITransportBase> _transport;
  Config _config;

  std::atomic<bool> _running{false};
  std::thread _processingThread;

  mutable std::mutex _mutex;
  mutable std::mutex _sessionMutex;
  mutable std::mutex _callbackMutex;

  std::condition_variable _operationCv;
  std::condition_variable _stopCv;

  std::unordered_map<SessionId, SessionState> _sessions;

  // User callbacks
  ConnectCallback _connectCallback;
  CloseCallback _closeCallback;
  ErrorCallback _errorCallback;
};

} // namespace network
} // namespace iora