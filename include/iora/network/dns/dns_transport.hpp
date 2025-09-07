// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include "dns_message.hpp"
#include "dns_types.hpp"
#include "dns_utils.hpp"
#include "iora/core/logger.hpp"
#include "iora/core/thread_pool.hpp"
#include "iora/core/timer.hpp"
#include "iora/network/unified_shared_transport.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <climits>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <thread>

namespace iora
{
namespace network
{
namespace dns
{

/// \brief DNS transport exceptions
class DnsTransportException : public std::runtime_error
{
public:
  explicit DnsTransportException(const std::string &message)
      : std::runtime_error("DNS Transport Error: " + message)
  {
  }
};

class DnsTimeoutException : public DnsTransportException
{
public:
  explicit DnsTimeoutException(const std::string &message = "DNS query timeout")
      : DnsTransportException(message)
  {
  }
};

class DnsServerException : public DnsTransportException
{
public:
  DnsResponseCode responseCode;

  DnsServerException(DnsResponseCode code, const std::string &message)
      : DnsTransportException("DNS server error (" + std::to_string(static_cast<int>(code)) +
                              "): " + message),
        responseCode(code)
  {
  }
};

/// \brief DNS transport implementation using Iora's UnifiedSharedTransport
class DnsTransport : public std::enable_shared_from_this<DnsTransport>
{
public:
  /// \brief DNS query callback for asynchronous operations (unified)
  using QueryCallback =
    std::function<void(const DnsResult &result, const std::exception_ptr &error)>;

  /// \brief Constructor with configuration
  explicit DnsTransport(const DnsConfig &config = {});

  /// \brief Destructor
  ~DnsTransport();

  /// \brief Start the transport
  /// \throws DnsTransportException on failure
  void start();

  /// \brief Stop the transport
  void stop();

  /// \brief Check if transport is running
  bool isRunning() const;

  /// \brief Send synchronous DNS query
  /// \param question DNS question to resolve
  /// \param server DNS server address (empty = use configured servers)
  /// \param port DNS server port (0 = use configured port)
  /// \return DNS query result
  /// \throws DnsTransportException, DnsTimeoutException, DnsServerException
  DnsResult query(const DnsQuestion &question, const std::string &server = "",
                  std::uint16_t port = 0);

  /// \brief Send asynchronous DNS query
  /// \param question DNS question to resolve
  /// \param callback Response callback
  /// \param server DNS server address (empty = use configured servers)
  /// \param port DNS server port (0 = use configured port)
  void queryAsync(const DnsQuestion &question, QueryCallback callback,
                  const std::string &server = "", std::uint16_t port = 0);

  /// \brief Send multiple questions in one query (synchronous)
  /// \param questions DNS questions to resolve
  /// \param server DNS server address (empty = use configured servers)
  /// \param port DNS server port (0 = use configured port)
  /// \return DNS query result
  DnsResult queryMultiple(const std::vector<DnsQuestion> &questions, const std::string &server = "",
                          std::uint16_t port = 0);

  /// \brief Update configuration
  void updateConfig(const DnsConfig &config);

  /// \brief Get current configuration
  const DnsConfig &getConfig() const { return config_; }

  /// \brief Get transport statistics (thread-safe atomic counters)
  struct Statistics
  {
    std::uint64_t totalQueries{0};
    std::uint64_t udpQueries{0};
    std::uint64_t tcpQueries{0};
    std::uint64_t tcpFallbacks{0};
    std::uint64_t timeouts{0};
    std::uint64_t retries{0};
    std::uint64_t errors{0};
    std::uint64_t truncatedResponses{0};
  };

  Statistics getStatistics() const;
  void resetStatistics();

private:
  /// \brief Composite key for pending queries to avoid ID collisions
  ///
  /// IMPORTANT: Server string normalization rules:
  /// - For pending queries: use raw server string (e.g., "8.8.8.8")
  /// - For session management: UDP uses "server:port", TCP uses "server:port:tcp"
  /// - QueryKey always uses (queryId, server, port) triple without transport suffix
  /// - Server strings must be consistent (same case, format) for proper lookup
  struct QueryKey
  {
    std::uint16_t queryId; ///< DNS query ID (unique per server:port)
    std::string server;    ///< DNS server address (normalized, no transport suffix)
    std::uint16_t port;    ///< DNS server port

    QueryKey(std::uint16_t id, const std::string &srv, std::uint16_t p)
        : queryId(id), server(srv), port(p)
    {
    }

    bool operator<(const QueryKey &other) const
    {
      if (queryId != other.queryId)
        return queryId < other.queryId;
      if (server != other.server)
        return server < other.server;
      return port < other.port;
    }

    bool operator==(const QueryKey &other) const
    {
      return queryId == other.queryId && server == other.server && port == other.port;
    }
  };

  /// \brief Pending query information
  ///
  /// THREAD SAFETY: This structure is accessed from multiple threads:
  /// - Main thread: creates and registers
  /// - Transport callbacks: reads for completion
  /// - Timer callbacks: modifies retryCount and startTime
  /// - Cleanup thread: reads for timeout detection
  struct PendingQuery
  {
    // Immutable fields - set once during construction, never modified
    const std::uint16_t queryId;
    const std::chrono::milliseconds timeout;
    const std::string server;
    const std::uint16_t port;
    const std::vector<std::uint8_t> queryData;

    // Mutable but single-writer fields (only modified by creating thread)
    std::promise<DnsResult> promise;
    QueryCallback callback;
    DnsTransportMode transportMode;
    bool tcpFallback;

    // Thread-safe concurrent fields - accessed from multiple threads
    std::atomic<std::chrono::steady_clock::time_point> startTime;
    std::atomic<int> retryCount;
    std::atomic<std::uint64_t> activeTimerId{0}; // Currently scheduled retry timer (0 = none)

    PendingQuery(std::uint16_t id, std::chrono::milliseconds to, const std::string &srv,
                 std::uint16_t prt, std::vector<std::uint8_t> data)
        : queryId(id), timeout(to), server(srv), port(prt), queryData(std::move(data)),
          transportMode(DnsTransportMode::UDP), tcpFallback(false),
          startTime(std::chrono::steady_clock::now()), retryCount(0)
    {
    }
  };

  /// \brief Send query using UDP transport
  void sendUdpQuery(std::shared_ptr<PendingQuery> query);

  /// \brief Send query using TCP transport
  void sendTcpQuery(std::shared_ptr<PendingQuery> query);

  /// \brief Handle incoming UDP data
  void handleUdpData(SessionId sessionId, const std::uint8_t *data, std::size_t size,
                     const IoResult &result);

  /// \brief Handle incoming TCP data
  void handleTcpData(SessionId sessionId, const std::uint8_t *data, std::size_t size,
                     const IoResult &result);

  /// \brief Handle transport errors
  void handleTransportError(SessionId sessionId, const IoResult &result);

  /// \brief Handle transport connection events
  void handleConnect(SessionId sessionId, const IoResult &result);
  void handleClose(SessionId sessionId, const IoResult &result);

  /// \brief Process DNS response
  void processResponse(const std::uint8_t *data, std::size_t size, DnsTransportMode mode,
                       const std::string &sourceServer, std::uint16_t sourcePort);

  /// \brief Complete pending query
  void completeQuery(const QueryKey &key, const DnsResult &result);
  void completeQuery(const QueryKey &key, const std::exception_ptr &error);

  /// \brief Find pending query by response data (thread-safe)
  /// \param queryId Query ID from DNS response
  /// \param sourceServer Server that sent the response
  /// \param sourcePort Port that sent the response
  /// \return Shared pointer to pending query or nullptr if not found
  std::shared_ptr<PendingQuery> findPendingQuery(std::uint16_t queryId,
                                                 const std::string &sourceServer,
                                                 std::uint16_t sourcePort);

  /// \brief Retry query logic
  void retryQuery(std::shared_ptr<PendingQuery> query, const std::string &reason);

  /// \brief Cleanup expired queries
  void cleanupExpiredQueries();

  /// \brief Start cleanup timer
  void startCleanupTimer();
  /// \brief Schedule timeout timer for a query
  void scheduleQueryTimeout(std::shared_ptr<PendingQuery> query);

  /// \brief Get next DNS server from configured list
  DnsServer getNextServer();

  /// \brief Prepare query data
  std::vector<std::uint8_t> prepareQuery(const std::vector<DnsQuestion> &questions,
                                         std::uint16_t queryId);

  /// \brief Calculate total maximum wait time for synchronous queries including retries
  /// \return Maximum possible duration including initial timeout and all retry delays with jitter
  std::chrono::milliseconds calculateMaxSyncWaitTime() const;

  /// \brief Generate unique query ID for server:port combination
  /// \param server Target server
  /// \param port Target port
  /// \return Unique query ID that doesn't conflict with pending queries to same server
  std::uint16_t generateUniqueQueryId(const std::string &server, std::uint16_t port);

  /// \brief Get transport for mode
  std::shared_ptr<UnifiedSharedTransport> getTransport(DnsTransportMode mode);

  /// \brief Create UDP transport
  std::shared_ptr<UdpTransportAdapter> createUdpTransport();

  /// \brief Create TCP transport
  std::shared_ptr<TcpTlsTransportAdapter> createTcpTransport();

  // Configuration
  DnsConfig config_;

  // Transport instances
  std::shared_ptr<UdpTransportAdapter> udpTransport_;
  std::shared_ptr<TcpTlsTransportAdapter> tcpTransport_;

  // State management
  std::atomic<bool> running_{false};
  mutable std::mutex stateMutex_;

  // Query management
  std::map<QueryKey, std::shared_ptr<PendingQuery>> pendingQueries_;
  mutable std::mutex queriesMutex_;

  // Server selection
  std::atomic<std::size_t> serverIndex_{0};

  // Statistics (thread-safe atomic counters)
  struct InternalStatistics
  {
    std::atomic<std::uint64_t> totalQueries{0};
    std::atomic<std::uint64_t> udpQueries{0};
    std::atomic<std::uint64_t> tcpQueries{0};
    std::atomic<std::uint64_t> tcpFallbacks{0};
    std::atomic<std::uint64_t> timeouts{0};
    std::atomic<std::uint64_t> retries{0};
    std::atomic<std::uint64_t> errors{0};
    std::atomic<std::uint64_t> truncatedResponses{0};
  } stats_;

  // Session management
  std::map<std::string, SessionId> serverSessions_; // server:port -> SessionId
  std::map<SessionId, std::pair<std::string, std::uint16_t>>
    sessionToServer_; // SessionId -> (server, port)
  mutable std::mutex sessionsMutex_;

  // TCP message framing (TCP DNS messages are length-prefixed)
  std::map<SessionId, std::deque<std::uint8_t>> tcpBuffers_;
  mutable std::mutex tcpBuffersMutex_;

  // Cleanup timer
  std::atomic<bool> cleanupRunning_{false};
  std::thread cleanupThread_;
  std::condition_variable cleanupCv_;
  std::mutex cleanupMutex_;

  // Centralized RNG for retry jitter
  mutable std::mt19937 rng_;

  // Timer service for efficient retry scheduling (avoids sleeping in thread pool workers)
  std::shared_ptr<core::TimerService> timerService_;
};

// ==================== Implementation ====================

inline DnsTransport::DnsTransport(const DnsConfig &config) : config_(config)
{
  if (config_.servers.empty())
  {
    throw DnsTransportException("No DNS servers configured");
  }

  // DnsServer structures are already normalized via fromString()
  // No additional normalization needed

  // Initialize RNG for jitter
  std::random_device rd;
  rng_.seed(rd());

  // Initialize timer service for efficient retry scheduling
  core::TimerServiceConfig timerConfig;
  timerConfig.threadName = "DnsRetryTimer";
  timerConfig.enableStatistics = false; // Keep it lightweight
  timerService_ = std::make_shared<core::TimerService>(timerConfig);
}

inline DnsTransport::~DnsTransport() { stop(); }

inline void DnsTransport::start()
{
  std::lock_guard<std::mutex> lock(stateMutex_);

  if (running_.load())
  {
    return; // Already running
  }

  try
  {
    // Create transports based on configuration
    if (config_.transportMode == DnsTransportMode::UDP ||
        config_.transportMode == DnsTransportMode::Both)
    {
      udpTransport_ = createUdpTransport();
      udpTransport_->start();
    }

    if (config_.transportMode == DnsTransportMode::TCP ||
        config_.transportMode == DnsTransportMode::Both)
    {
      tcpTransport_ = createTcpTransport();
      tcpTransport_->start();
    }

    // Timer service is already started by its constructor

    running_.store(true);
    startCleanupTimer();
  }
  catch (const std::exception &e)
  {
    running_.store(false);
    throw DnsTransportException("Failed to start DNS transport: " + std::string(e.what()));
  }
}

inline void DnsTransport::stop()
{
  std::lock_guard<std::mutex> lock(stateMutex_);

  if (!running_.load())
  {
    return; // Already stopped
  }

  running_.store(false);

  // Stop cleanup timer
  cleanupRunning_.store(false);
  cleanupCv_.notify_all();
  if (cleanupThread_.joinable())
  {
    cleanupThread_.join();
  }

  // Stop transports
  if (udpTransport_)
  {
    udpTransport_->stop();
    udpTransport_.reset();
  }

  if (tcpTransport_)
  {
    tcpTransport_->stop();
    tcpTransport_.reset();
  }

  // Complete all pending queries with error
  {
    std::lock_guard<std::mutex> qlock(queriesMutex_);
    auto error = std::make_exception_ptr(DnsTransportException("Transport stopped"));

    for (auto &[key, query] : pendingQueries_)
    {
      if (query->callback)
      {
        try
        {
          query->callback({}, error);
        }
        catch (...)
        {
        }
      }
      try
      {
        query->promise.set_exception(error);
      }
      catch (...)
      {
      }
    }
    pendingQueries_.clear();
  }

  // Clear session mappings
  {
    std::lock_guard<std::mutex> slock(sessionsMutex_);
    serverSessions_.clear();
    sessionToServer_.clear();
  }

  // Clear TCP buffers
  {
    std::lock_guard<std::mutex> tlock(tcpBuffersMutex_);
    tcpBuffers_.clear();
  }

  // Stop timer service and ensure all scheduled retries are cancelled
  if (timerService_)
  {
    timerService_->stop();
    // Reset the shared pointer to ensure clean shutdown
    timerService_.reset();
  }
}

inline bool DnsTransport::isRunning() const { return running_.load(); }

inline DnsResult DnsTransport::query(const DnsQuestion &question, const std::string &server,
                                     std::uint16_t port)
{
  return queryMultiple({question}, server, port);
}

inline DnsResult DnsTransport::queryMultiple(const std::vector<DnsQuestion> &questions,
                                             const std::string &server, std::uint16_t port)
{
  if (!running_.load())
  {
    throw DnsTransportException("Transport not running");
  }

  if (questions.empty())
  {
    throw DnsTransportException("No questions provided");
  }

  // Determine target server and port
  DnsServer targetDnsServer;
  if (server.empty())
  {
    targetDnsServer = getNextServer();
  }
  else
  {
    // Parse provided server string or use provided port
    targetDnsServer = DnsServer::fromString(server);
    if (port != 0)
    {
      targetDnsServer.port = port; // Override port if explicitly provided
    }
  }

  std::string targetServer = targetDnsServer.address;
  std::uint16_t targetPort = targetDnsServer.port;

  // Generate unique query ID for this server:port combination
  std::uint16_t queryId = generateUniqueQueryId(targetServer, targetPort);
  auto queryData = prepareQuery(questions, queryId);

  // Create pending query with immutable fields (thread-safe constructor)
  auto query = std::make_shared<PendingQuery>(queryId, config_.timeout, targetServer, targetPort,
                                              std::move(queryData));
  query->transportMode = config_.transportMode;

  // Create composite key and register pending query
  QueryKey key(queryId, targetServer, targetPort);
  {
    std::lock_guard<std::mutex> lock(queriesMutex_);
    pendingQueries_[key] = query;
  }

  try
  {
    // Send initial query (UDP first if Both mode)
    if (config_.transportMode == DnsTransportMode::TCP)
    {
      sendTcpQuery(query);
    }
    else
    {
      sendUdpQuery(query);
    }

    // Wait for response with proper retry window calculation
    auto future = query->promise.get_future();
    auto maxWaitTime = calculateMaxSyncWaitTime();
    iora::core::Logger::debug(
      "DNS sync query max wait time: " + std::to_string(maxWaitTime.count()) + "ms " +
      "(timeout=" + std::to_string(config_.timeout.count()) + "ms, " +
      "retries=" + std::to_string(config_.retryCount) + ")");
    auto status = future.wait_for(maxWaitTime);

    if (status == std::future_status::timeout)
    {
      // Remove from pending and count timeout for sync queries
      {
        std::lock_guard<std::mutex> lock(queriesMutex_);
        pendingQueries_.erase(key);
      }

      // Atomic increment - no mutex needed
      stats_.timeouts.fetch_add(1, std::memory_order_relaxed);

      throw DnsTimeoutException("Query timeout after " + std::to_string(config_.timeout.count()) +
                                "ms");
    }

    return future.get();
  }
  catch (...)
  {
    // Remove from pending queries on any exception
    {
      std::lock_guard<std::mutex> lock(queriesMutex_);
      pendingQueries_.erase(key);
    }
    throw;
  }
}

inline void DnsTransport::queryAsync(const DnsQuestion &question, QueryCallback callback,
                                     const std::string &server, std::uint16_t port)
{
  if (!running_.load())
  {
    auto error = std::make_exception_ptr(DnsTransportException("Transport not running"));
    callback({}, error);
    return;
  }

  // Determine target server and port
  DnsServer targetDnsServer;
  if (server.empty())
  {
    targetDnsServer = getNextServer();
  }
  else
  {
    // Parse provided server string or use provided port
    targetDnsServer = DnsServer::fromString(server);
    if (port != 0)
    {
      targetDnsServer.port = port; // Override port if explicitly provided
    }
  }

  std::string targetServer = targetDnsServer.address;
  std::uint16_t targetPort = targetDnsServer.port;

  // Generate unique query ID for this server:port combination
  std::uint16_t queryId = generateUniqueQueryId(targetServer, targetPort);
  auto queryData = prepareQuery({question}, queryId);

  // Create pending query with immutable fields (thread-safe constructor)
  auto query = std::make_shared<PendingQuery>(queryId, config_.timeout, targetServer, targetPort,
                                              std::move(queryData));
  query->transportMode = config_.transportMode;
  query->callback = std::move(callback);

  // Create composite key and register pending query
  QueryKey key(queryId, targetServer, targetPort);
  {
    std::lock_guard<std::mutex> lock(queriesMutex_);
    pendingQueries_[key] = query;
  }

  try
  {
    // Send query
    if (config_.transportMode == DnsTransportMode::TCP)
    {
      sendTcpQuery(query);
    }
    else
    {
      sendUdpQuery(query);
    }
  }
  catch (const std::exception &e)
  {
    // Remove from pending and call callback with error
    {
      std::lock_guard<std::mutex> lock(queriesMutex_);
      pendingQueries_.erase(key);
    }

    auto error = std::make_exception_ptr(DnsTransportException(e.what()));
    query->callback({}, error);
  }
}

inline std::shared_ptr<UdpTransportAdapter> DnsTransport::createUdpTransport()
{
  SharedUdpTransport::Config config{};

  auto adapter = std::make_shared<UdpTransportAdapter>(config);

  // Set up callbacks using UnifiedCallbacks with shared_ptr capture for lifetime safety
  UnifiedCallbacks callbacks;
  auto self = shared_from_this(); // Ensure transport remains alive during async operations
  callbacks.onData =
    [self](SessionId sid, const std::uint8_t *data, std::size_t size, const IoResult &result)
  { self->handleUdpData(sid, data, size, result); };
  callbacks.onConnect = [self](SessionId sid, const IoResult &result)
  { self->handleConnect(sid, result); };
  callbacks.onClosed = [self](SessionId sid, const IoResult &result)
  { self->handleClose(sid, result); };
  callbacks.onError = [self](TransportError error, const std::string &message)
  {
    // Handle transport-level errors
  };

  adapter->setCallbacks(callbacks);
  return adapter;
}

inline std::shared_ptr<TcpTlsTransportAdapter> DnsTransport::createTcpTransport()
{
  SharedTransport::Config config{};
  SharedTransport::TlsConfig serverTls{}, clientTls{};

  auto adapter = std::make_shared<TcpTlsTransportAdapter>(config, serverTls, clientTls);

  // Set up callbacks using UnifiedCallbacks with shared_ptr capture for lifetime safety
  UnifiedCallbacks callbacks;
  auto self = shared_from_this(); // Ensure transport remains alive during async operations
  callbacks.onData =
    [self](SessionId sid, const std::uint8_t *data, std::size_t size, const IoResult &result)
  { self->handleTcpData(sid, data, size, result); };
  callbacks.onConnect = [self](SessionId sid, const IoResult &result)
  { self->handleConnect(sid, result); };
  callbacks.onClosed = [self](SessionId sid, const IoResult &result)
  { self->handleClose(sid, result); };
  callbacks.onError = [self](TransportError error, const std::string &message)
  {
    // Handle transport-level errors
  };

  adapter->setCallbacks(callbacks);
  return adapter;
}

inline void DnsTransport::sendUdpQuery(std::shared_ptr<PendingQuery> query)
{
  if (!udpTransport_)
  {
    throw DnsTransportException("UDP transport not available");
  }

  // Log DNS query attempt for debugging server failover
  iora::core::Logger::info("DNS sending UDP query: ID=" + std::to_string(query->queryId) +
                           " server=" + query->server + ":" + std::to_string(query->port) +
                           " retry=" + std::to_string(query->retryCount));

  // Get or create session to DNS server
  std::string serverKey = query->server + ":" + std::to_string(query->port);
  SessionId sessionId = 0;

  {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    auto it = serverSessions_.find(serverKey);
    if (it != serverSessions_.end())
    {
      sessionId = it->second;
    }
    else
    {
      // Create new session
      sessionId = udpTransport_->connect(query->server, query->port, TlsMode::None);
      if (sessionId == 0)
      {
        throw DnsTransportException("Failed to connect to DNS server " + query->server);
      }
      serverSessions_[serverKey] = sessionId;
      sessionToServer_[sessionId] = {query->server, query->port};
    }
  }

  // Send query data
  bool sent = udpTransport_->send(sessionId, query->queryData.data(), query->queryData.size());
  if (!sent)
  {
    iora::core::Logger::error("DNS UDP query failed to send to " + query->server + ":" +
                              std::to_string(query->port));
    throw DnsTransportException("Failed to send UDP query to " + query->server);
  }

  iora::core::Logger::debug("DNS UDP query sent: ID=" + std::to_string(query->queryId) + " to " +
                            query->server + ":" + std::to_string(query->port) +
                            " size=" + std::to_string(query->queryData.size()) + "bytes");

  // Schedule timeout timer for this query
  scheduleQueryTimeout(query);

  // Atomic increments - no mutex needed
  stats_.totalQueries.fetch_add(1, std::memory_order_relaxed);
  stats_.udpQueries.fetch_add(1, std::memory_order_relaxed);
}

inline void DnsTransport::sendTcpQuery(std::shared_ptr<PendingQuery> query)
{
  if (!tcpTransport_)
  {
    throw DnsTransportException("TCP transport not available");
  }

  // Get or create session to DNS server
  std::string serverKey = query->server + ":" + std::to_string(query->port) + ":tcp";
  SessionId sessionId = 0;

  {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    auto it = serverSessions_.find(serverKey);
    if (it != serverSessions_.end())
    {
      sessionId = it->second;
    }
    else
    {
      // Create new session
      sessionId = tcpTransport_->connect(query->server, query->port, TlsMode::None);
      if (sessionId == 0)
      {
        throw DnsTransportException("Failed to connect to DNS server " + query->server);
      }
      serverSessions_[serverKey] = sessionId;
      sessionToServer_[sessionId] = {query->server, query->port};
    }
  }

  // TCP DNS messages are length-prefixed
  std::vector<std::uint8_t> tcpMessage;
  std::uint16_t length = static_cast<std::uint16_t>(query->queryData.size());
  tcpMessage.push_back((length >> 8) & 0xFF);
  tcpMessage.push_back(length & 0xFF);
  tcpMessage.insert(tcpMessage.end(), query->queryData.begin(), query->queryData.end());

  // Send query data
  bool sent = tcpTransport_->send(sessionId, tcpMessage.data(), tcpMessage.size());
  if (!sent)
  {
    iora::core::Logger::error("DNS TCP query failed to send to " + query->server + ":" +
                              std::to_string(query->port));
    throw DnsTransportException("Failed to send TCP query to " + query->server);
  }

  iora::core::Logger::debug("DNS TCP query sent: ID=" + std::to_string(query->queryId) + " to " +
                            query->server + ":" + std::to_string(query->port) +
                            " size=" + std::to_string(length) + "bytes (+" +
                            std::to_string(tcpMessage.size() - length) + " length prefix)");

  // Schedule timeout timer for this query
  scheduleQueryTimeout(query);

  // Atomic increments - no mutex needed
  stats_.totalQueries.fetch_add(1, std::memory_order_relaxed);
  stats_.tcpQueries.fetch_add(1, std::memory_order_relaxed);
  if (query->tcpFallback)
  {
    stats_.tcpFallbacks.fetch_add(1, std::memory_order_relaxed);
    iora::core::Logger::debug(
      "DNS TCP fallback completed for query ID=" + std::to_string(query->queryId) +
      " server=" + query->server + ":" + std::to_string(query->port));
  }
}

inline void DnsTransport::handleUdpData(SessionId sessionId, const std::uint8_t *data,
                                        std::size_t size, const IoResult &result)
{
  if (!result.ok)
  {
    handleTransportError(sessionId, result);
    return;
  }

  // Look up server and port for this session
  std::string server;
  std::uint16_t port;
  {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    auto it = sessionToServer_.find(sessionId);
    if (it != sessionToServer_.end())
    {
      server = it->second.first;
      port = it->second.second;
    }
    else
    {
      iora::core::Logger::error("DNS UDP response from unknown session ID " +
                                std::to_string(sessionId));
      return;
    }
  }

  processResponse(data, size, DnsTransportMode::UDP, server, port);
}

inline void DnsTransport::handleTcpData(SessionId sessionId, const std::uint8_t *data,
                                        std::size_t size, const IoResult &result)
{
  if (!result.ok)
  {
    handleTransportError(sessionId, result);
    return;
  }

  // TCP DNS messages are length-prefixed, may arrive in fragments
  {
    std::lock_guard<std::mutex> lock(tcpBuffersMutex_);
    auto &buffer = tcpBuffers_[sessionId];

    // Prevent unbounded buffer growth using configured limit
    if (buffer.size() + size > config_.maxTcpBufferSize)
    {
      // Clear buffer and close session on excessive buffer growth
      buffer.clear();
      tcpTransport_->close(sessionId);
      return;
    }

    buffer.insert(buffer.end(), data, data + size);

    // Process complete messages
    while (buffer.size() >= 2)
    {
      std::uint16_t messageLength = (buffer[0] << 8) | buffer[1];

      // Validate message length
      static const std::uint16_t MAX_DNS_MESSAGE_SIZE = 65535; // RFC 1035 max
      if (messageLength == 0 || messageLength > MAX_DNS_MESSAGE_SIZE)
      {
        // Invalid message length, clear buffer and close session
        buffer.clear();
        tcpTransport_->close(sessionId);
        return;
      }

      // Check for integer overflow and bounds safety
      // Ensure messageLength is reasonable and won't cause overflow
      const std::size_t maxSafeSize = SIZE_MAX - 2;
      if (messageLength > maxSafeSize || messageLength > config_.maxTcpBufferSize)
      {
        // Message too large, clear buffer and close session
        iora::core::Logger::error(
          "DNS TCP message too large: " + std::to_string(messageLength) +
          " bytes, max=" + std::to_string(std::min(maxSafeSize, config_.maxTcpBufferSize)));
        buffer.clear();
        tcpTransport_->close(sessionId);
        return;
      }

      if (buffer.size() < 2 + static_cast<std::size_t>(messageLength))
      {
        // Incomplete message, wait for more data
        break;
      }

      // Complete message available - look up server and port
      std::string server;
      std::uint16_t port;
      {
        std::lock_guard<std::mutex> slock(sessionsMutex_);
        auto it = sessionToServer_.find(sessionId);
        if (it != sessionToServer_.end())
        {
          server = it->second.first;
          port = it->second.second;
        }
        else
        {
          iora::core::Logger::error("DNS TCP response from unknown session ID " +
                                    std::to_string(sessionId));
          // Remove processed message from buffer using deque's efficient pop_front
          for (std::size_t i = 0; i < 2 + static_cast<std::size_t>(messageLength); ++i)
          {
            buffer.pop_front();
          }
          continue;
        }
      }

      // Create vector from buffer data since deque doesn't have data() method
      std::vector<std::uint8_t> messageData(buffer.begin() + 2, buffer.begin() + 2 + messageLength);
      processResponse(messageData.data(), messageLength, DnsTransportMode::TCP, server, port);

      // Remove processed message from buffer using deque's efficient pop_front
      for (std::size_t i = 0; i < 2 + static_cast<std::size_t>(messageLength); ++i)
      {
        buffer.pop_front();
      }
    }
  }
}

inline void DnsTransport::processResponse(const std::uint8_t *data, std::size_t size,
                                          DnsTransportMode mode, const std::string &sourceServer,
                                          std::uint16_t sourcePort)
{
  try
  {
    DnsResult result = DnsMessage::parse(data, size);
    QueryKey key(result.header.id, sourceServer, sourcePort);

    // Check for truncation (UDP only)
    if (mode == DnsTransportMode::UDP && result.isTruncated())
    {
      // Atomic increment - no mutex needed
      stats_.truncatedResponses.fetch_add(1, std::memory_order_relaxed);

      iora::core::Logger::debug(
        "DNS response truncated (TC=1) for query ID=" + std::to_string(result.header.id) +
        " from " + sourceServer + ":" + std::to_string(sourcePort));

      // Find and retry with TCP if configured
      if (config_.transportMode == DnsTransportMode::Both)
      {
        std::lock_guard<std::mutex> lock(queriesMutex_);
        auto it = pendingQueries_.find(key);
        if (it != pendingQueries_.end() && !it->second->tcpFallback)
        {
          iora::core::Logger::debug("Initiating TCP fallback for truncated response, query ID=" +
                                    std::to_string(result.header.id));
          it->second->tcpFallback = true;
          sendTcpQuery(it->second);
          return; // Don't complete the query yet
        }
      }
      else
      {
        iora::core::Logger::warning("DNS response truncated but TCP fallback not enabled");
      }
    }

    iora::core::Logger::debug("DNS response received: ID=" + std::to_string(result.header.id) +
                              " from " + sourceServer + ":" + std::to_string(sourcePort) + " via " +
                              (mode == DnsTransportMode::TCP ? "TCP" : "UDP") +
                              " rcode=" + std::to_string(static_cast<int>(result.header.rcode)) +
                              " answers=" + std::to_string(result.header.ancount));
    completeQuery(key, result);
  }
  catch (const std::exception &e)
  {
    iora::core::Logger::warning("DNS response parse failed from " + sourceServer + ":" +
                                std::to_string(sourcePort) + " (" + std::to_string(size) +
                                " bytes): " + e.what());

    // If we can extract query ID from malformed response, complete that query
    if (size >= 2)
    {
      std::uint16_t queryId = (data[0] << 8) | data[1];
      QueryKey key(queryId, sourceServer, sourcePort);
      auto error = std::make_exception_ptr(DnsParseException(e.what()));
      completeQuery(key, error);
    }
    else
    {
      iora::core::Logger::error("DNS response too short to extract query ID from " + sourceServer +
                                ":" + std::to_string(sourcePort));
    }
  }
}

inline void DnsTransport::handleTransportError(SessionId sessionId, const IoResult &result)
{
  // Handle transport-level errors by finding queries specific to this session
  std::vector<std::shared_ptr<PendingQuery>> affectedQueries;
  std::string errorServer;
  std::uint16_t errorPort;

  // First, identify which server:port this session corresponds to
  {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    auto it = sessionToServer_.find(sessionId);
    if (it != sessionToServer_.end())
    {
      errorServer = it->second.first;
      errorPort = it->second.second;
    }
    else
    {
      iora::core::Logger::error("Transport error for unknown session ID " +
                                std::to_string(sessionId));
      return;
    }
  }

  // Find queries specifically targeting this server:port
  {
    std::lock_guard<std::mutex> lock(queriesMutex_);
    for (const auto &[key, query] : pendingQueries_)
    {
      if (query->server == errorServer && query->port == errorPort)
      {
        affectedQueries.push_back(query);
      }
    }
  }

  iora::core::Logger::info("DNS transport error for " + errorServer + ":" +
                           std::to_string(errorPort) + " affecting " +
                           std::to_string(affectedQueries.size()) + " queries: " + result.message);

  // Try to retry affected queries
  for (auto &query : affectedQueries)
  {
    if (query->retryCount.load() < config_.retryCount)
    {
      retryQuery(query, "transport error: " + result.message);
    }
    else
    {
      // Max retries exceeded, complete with error
      auto error = std::make_exception_ptr(
        DnsTransportException("Transport error after retries: " + result.message));
      completeQuery(QueryKey(query->queryId, query->server, query->port), error);
    }
  }

  // Atomic increment - no mutex needed
  stats_.errors.fetch_add(1, std::memory_order_relaxed);
}

inline void DnsTransport::handleConnect(SessionId sessionId, const IoResult &result)
{
  // Handle connection events
}

inline void DnsTransport::handleClose(SessionId sessionId, const IoResult &result)
{
  // Remove closed sessions from mappings
  {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    for (auto it = serverSessions_.begin(); it != serverSessions_.end();)
    {
      if (it->second == sessionId)
      {
        it = serverSessions_.erase(it);
      }
      else
      {
        ++it;
      }
    }
    sessionToServer_.erase(sessionId);
  }

  // Clean up TCP buffers
  {
    std::lock_guard<std::mutex> lock(tcpBuffersMutex_);
    tcpBuffers_.erase(sessionId);
  }
}

inline DnsServer DnsTransport::getNextServer()
{
  if (config_.servers.empty())
  {
    throw DnsTransportException("No DNS servers configured");
  }

  std::size_t index = serverIndex_.fetch_add(1) % config_.servers.size();
  DnsServer selectedServer = config_.servers[index];

  iora::core::Logger::info("DNS getNextServer: selected server=" + selectedServer.toString() +
                           " (index=" + std::to_string(index) + " of " +
                           std::to_string(config_.servers.size()) + " servers)");

  return selectedServer;
}

inline std::vector<std::uint8_t>
DnsTransport::prepareQuery(const std::vector<DnsQuestion> &questions, std::uint16_t queryId)
{
  return DnsMessage::buildQuery(questions, config_.recursionDesired, queryId);
}

inline DnsTransport::Statistics DnsTransport::getStatistics() const
{
  // No mutex needed - atomic loads are thread-safe
  Statistics result;
  result.totalQueries = stats_.totalQueries.load(std::memory_order_relaxed);
  result.udpQueries = stats_.udpQueries.load(std::memory_order_relaxed);
  result.tcpQueries = stats_.tcpQueries.load(std::memory_order_relaxed);
  result.tcpFallbacks = stats_.tcpFallbacks.load(std::memory_order_relaxed);
  result.timeouts = stats_.timeouts.load(std::memory_order_relaxed);
  result.retries = stats_.retries.load(std::memory_order_relaxed);
  result.errors = stats_.errors.load(std::memory_order_relaxed);
  result.truncatedResponses = stats_.truncatedResponses.load(std::memory_order_relaxed);
  return result;
}

inline void DnsTransport::resetStatistics()
{
  // No mutex needed - atomic stores are thread-safe
  stats_.totalQueries.store(0, std::memory_order_relaxed);
  stats_.udpQueries.store(0, std::memory_order_relaxed);
  stats_.tcpQueries.store(0, std::memory_order_relaxed);
  stats_.tcpFallbacks.store(0, std::memory_order_relaxed);
  stats_.timeouts.store(0, std::memory_order_relaxed);
  stats_.retries.store(0, std::memory_order_relaxed);
  stats_.errors.store(0, std::memory_order_relaxed);
  stats_.truncatedResponses.store(0, std::memory_order_relaxed);
}

inline void DnsTransport::updateConfig(const DnsConfig &config)
{
  std::lock_guard<std::mutex> lock(stateMutex_);
  config_ = config;

  if (config_.servers.empty())
  {
    throw DnsTransportException("No DNS servers configured");
  }

  // DnsServer structures are already normalized via fromString()
  // No additional normalization needed
}

inline std::chrono::milliseconds DnsTransport::calculateMaxSyncWaitTime() const
{
  // Calculate maximum total wait time for synchronous queries
  // Base timeout for initial attempt
  auto totalWait = config_.timeout;

  // Calculate retry delays with exponential backoff and accurate per-retry jitter
  auto delay = config_.initialRetryDelay;
  std::chrono::milliseconds totalJitter{0};

  for (int retry = 0; retry < config_.retryCount; ++retry)
  {
    totalWait += delay;

    // Calculate jitter for this specific retry delay (more accurate than using maxRetryDelay)
    if (config_.jitterFactor > 0.0)
    {
      // Worst case: this retry gets maximum positive jitter based on actual delay
      auto jitterForThisRetry =
        std::chrono::milliseconds(static_cast<long>(delay.count() * config_.jitterFactor));
      totalJitter += jitterForThisRetry;
    }

    // Apply exponential backoff multiplier
    delay = std::chrono::milliseconds(static_cast<long>(delay.count() * config_.retryMultiplier));

    // Cap at maximum delay
    if (delay > config_.maxRetryDelay)
    {
      delay = config_.maxRetryDelay;
    }
  }

  // Add the accurately calculated jitter
  totalWait += totalJitter;

  // Add safety margin for processing delays
  totalWait += std::chrono::milliseconds(2000); // 2 second margin

  return totalWait;
}

inline std::uint16_t DnsTransport::generateUniqueQueryId(const std::string &server,
                                                         std::uint16_t port)
{
  // Reduce mutex contention by generating candidates outside the lock
  constexpr int BATCH_SIZE = 10;
  constexpr int MAX_BATCHES = 100; // 1000 total attempts

  for (int batch = 0; batch < MAX_BATCHES; ++batch)
  {
    // Generate a batch of candidates outside the lock
    std::array<std::uint16_t, BATCH_SIZE> candidates;
    for (int i = 0; i < BATCH_SIZE; ++i)
    {
      candidates[i] = DnsMessage::generateQueryId();
    }

    // Check candidates in a short critical section
    {
      std::lock_guard<std::mutex> lock(queriesMutex_);
      for (std::uint16_t queryId : candidates)
      {
        QueryKey testKey(queryId, server, port);
        if (pendingQueries_.find(testKey) == pendingQueries_.end())
        {
          return queryId; // Found unique ID
        }
      }
    }
  }

  // Fallback: sequential search for a free ID (pathological case recovery)
  iora::core::Logger::warning(
    "DNS query ID collision after 1000 random attempts, falling back to sequential search");

  {
    std::lock_guard<std::mutex> lock(queriesMutex_);

    // Sequential search through the entire 16-bit space
    for (std::uint32_t id = 1; id <= 65535; ++id)
    {
      std::uint16_t queryId = static_cast<std::uint16_t>(id);
      QueryKey testKey(queryId, server, port);
      if (pendingQueries_.find(testKey) == pendingQueries_.end())
      {
        iora::core::Logger::debug("Found free query ID " + std::to_string(queryId) +
                                  " via sequential search");
        return queryId;
      }
    }
  }

  // This should never happen unless we have 65535 concurrent queries to the same server:port
  throw DnsTransportException("Exhausted all query IDs for server " + server + ":" +
                              std::to_string(port) +
                              " (65535 concurrent queries - system overload)");
}

inline std::shared_ptr<DnsTransport::PendingQuery>
DnsTransport::findPendingQuery(std::uint16_t queryId, const std::string &sourceServer,
                               std::uint16_t sourcePort)
{
  std::lock_guard<std::mutex> lock(queriesMutex_);
  QueryKey key(queryId, sourceServer, sourcePort);
  auto it = pendingQueries_.find(key);
  if (it != pendingQueries_.end())
  {
    return it->second;
  }
  return nullptr;
}

inline void DnsTransport::completeQuery(const QueryKey &key, const DnsResult &result)
{
  std::shared_ptr<PendingQuery> query;

  {
    std::lock_guard<std::mutex> lock(queriesMutex_);
    auto it = pendingQueries_.find(key);
    if (it != pendingQueries_.end())
    {
      query = it->second;
      pendingQueries_.erase(it);
    }
  }

  if (query)
  {
    // Cancel active retry timer if any
    std::uint64_t activeTimer = query->activeTimerId.load(std::memory_order_relaxed);
    if (activeTimer != 0)
    {
      timerService_->cancel(activeTimer);
      query->activeTimerId.store(0, std::memory_order_relaxed);
    }

    // Calculate query duration for performance monitoring (atomic read)
    auto queryDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - query->startTime.load())
                           .count();

    // All DNS protocol responses are valid results (NOERROR, NXDOMAIN, SERVFAIL, etc.)
    // The resolver layer will decide whether to throw exceptions based on response codes
    {
      // Log different response types appropriately
      if (result.header.rcode == DnsResponseCode::NOERROR)
      {
        iora::core::Logger::debug(
          "DNS query completed successfully: ID=" + std::to_string(query->queryId) +
          " server=" + query->server + ":" + std::to_string(query->port) +
          " duration=" + std::to_string(queryDuration) + "ms" +
          " retries=" + std::to_string(query->retryCount.load()) +
          " answers=" + std::to_string(result.header.ancount));
      }
      else if (result.header.rcode == DnsResponseCode::NXDOMAIN)
      {
        iora::core::Logger::info(
          "DNS query completed with NXDOMAIN: ID=" + std::to_string(query->queryId) +
          " server=" + query->server + ":" + std::to_string(query->port) +
          " duration=" + std::to_string(queryDuration) + "ms" + " retries=" +
          std::to_string(query->retryCount.load()) + " rcode=" + result.getResponseCodeString());
      }
      else
      {
        iora::core::Logger::info(
          "DNS query completed with server error: ID=" + std::to_string(query->queryId) +
          " server=" + query->server + ":" + std::to_string(query->port) +
          " duration=" + std::to_string(queryDuration) + "ms" + " retries=" +
          std::to_string(query->retryCount.load()) + " rcode=" + result.getResponseCodeString());
      }

      if (query->callback)
      {
        try
        {
          query->callback(result, nullptr);
        }
        catch (...)
        {
        }
      }
      try
      {
        query->promise.set_value(result);
      }
      catch (...)
      {
      }
    }
  }
  else
  {
    iora::core::Logger::warning(
      "DNS query completion for unknown query: ID=" + std::to_string(key.queryId) +
      " server=" + key.server + ":" + std::to_string(key.port));
  }
}

inline void DnsTransport::completeQuery(const QueryKey &key, const std::exception_ptr &error)
{
  std::shared_ptr<PendingQuery> query;

  {
    std::lock_guard<std::mutex> lock(queriesMutex_);
    auto it = pendingQueries_.find(key);
    if (it != pendingQueries_.end())
    {
      query = it->second;
      pendingQueries_.erase(it);
    }
  }

  if (query)
  {
    // Cancel active retry timer if any
    std::uint64_t activeTimer = query->activeTimerId.load(std::memory_order_relaxed);
    if (activeTimer != 0)
    {
      timerService_->cancel(activeTimer);
      query->activeTimerId.store(0, std::memory_order_relaxed);
    }

    // Calculate query duration for performance monitoring (atomic read)
    auto queryDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - query->startTime.load())
                           .count();

    // Log the error with context
    std::string errorMessage = "unknown error";
    try
    {
      std::rethrow_exception(error);
    }
    catch (const std::exception &e)
    {
      errorMessage = e.what();
    }
    catch (...)
    {
      errorMessage = "non-standard exception";
    }

    iora::core::Logger::error(
      "DNS query failed: ID=" + std::to_string(query->queryId) + " server=" + query->server + ":" +
      std::to_string(query->port) + " duration=" + std::to_string(queryDuration) + "ms" +
      " retries=" + std::to_string(query->retryCount.load()) + " error=" + errorMessage);

    // Atomic increment - no mutex needed
    stats_.errors.fetch_add(1, std::memory_order_relaxed);

    if (query->callback)
    {
      try
      {
        query->callback({}, error);
      }
      catch (...)
      {
      }
    }
    try
    {
      query->promise.set_exception(error);
    }
    catch (...)
    {
    }
  }
}

inline void DnsTransport::startCleanupTimer()
{
  cleanupRunning_.store(true);
  auto self = shared_from_this(); // Ensure transport remains alive during cleanup thread
  cleanupThread_ = std::thread(
    [self]()
    {
      while (self->cleanupRunning_.load())
      {
        std::unique_lock<std::mutex> lock(self->cleanupMutex_);
        if (self->cleanupCv_.wait_for(lock, std::chrono::seconds(10),
                                      [self] { return !self->cleanupRunning_.load(); }))
        {
          break; // Shutdown requested
        }

        self->cleanupExpiredQueries();
      }
    });
}

inline void DnsTransport::scheduleQueryTimeout(std::shared_ptr<PendingQuery> query)
{
  auto self = shared_from_this();

  // Cancel existing timeout timer if any (important for TCP fallback scenarios)
  std::uint64_t existingTimerId = query->activeTimerId.load(std::memory_order_relaxed);
  if (existingTimerId != 0)
  {
    timerService_->cancel(existingTimerId);
    query->activeTimerId.store(0, std::memory_order_relaxed);
  }

  // Schedule a timeout timer for the configured query timeout
  std::uint64_t timerId = timerService_->scheduleAfter(
    query->timeout,
    [self, query]()
    {
      // Check if transport is still running before accessing any members
      if (!self->running_.load())
      {
        return; // Transport has been stopped/destroyed
      }

      // Also check if timer service is still valid (defensive programming)
      if (!self->timerService_)
      {
        return; // Timer service has been destroyed
      }

      // Check if query is still pending (not completed/cancelled)
      QueryKey key(query->queryId, query->server, query->port);

      std::shared_ptr<PendingQuery> pendingQuery;
      {
        std::lock_guard<std::mutex> lock(self->queriesMutex_);
        auto it = self->pendingQueries_.find(key);
        if (it == self->pendingQueries_.end())
        {
          return; // Query already completed or cancelled
        }
        pendingQuery = it->second;

        // Remove from pending queries
        self->pendingQueries_.erase(it);
      }

      // Clear the timer ID since timeout fired
      pendingQuery->activeTimerId.store(0, std::memory_order_relaxed);

      // Complete query with timeout error
      auto error = std::make_exception_ptr(DnsTimeoutException(
        "Query timeout after " + std::to_string(query->timeout.count()) + "ms"));

      if (pendingQuery->callback)
      {
        pendingQuery->callback({}, error);
      }
      else
      {
        // Sync query - set promise
        try
        {
          pendingQuery->promise.set_exception(error);
        }
        catch (const std::future_error &)
        {
          // Promise already set - ignore
        }
      }

      // Update timeout statistics
      self->stats_.timeouts.fetch_add(1, std::memory_order_relaxed);
    });

  // Store timer ID for potential cancellation
  query->activeTimerId.store(timerId, std::memory_order_relaxed);
}

inline void DnsTransport::cleanupExpiredQueries()
{
  auto now = std::chrono::steady_clock::now();
  std::vector<std::pair<QueryKey, std::shared_ptr<PendingQuery>>> expiredQueries;

  // Phase 1: Collect expired queries with minimal lock time
  {
    std::lock_guard<std::mutex> lock(queriesMutex_);
    for (const auto &[key, query] : pendingQueries_)
    {
      if (now - query->startTime.load() > query->timeout)
      {
        expiredQueries.emplace_back(key, query);
      }
    }
  }

  // Phase 2: Process retries/timeouts without holding the main lock
  std::size_t actualTimeouts = 0;
  std::vector<QueryKey> toRemove;
  std::vector<std::shared_ptr<PendingQuery>> toComplete;

  for (const auto &[key, query] : expiredQueries)
  {
    if (query->retryCount.load() < config_.retryCount)
    {
      // Try retry instead of timing out (retryQuery doesn't need the main lock)
      retryQuery(query, "timeout");
    }
    else
    {
      // Mark for timeout completion
      toRemove.push_back(key);
      toComplete.push_back(query);
      actualTimeouts++;
    }
  }

  // Phase 3: Remove timed-out queries with short lock duration
  if (!toRemove.empty())
  {
    std::lock_guard<std::mutex> lock(queriesMutex_);
    for (const auto &key : toRemove)
    {
      pendingQueries_.erase(key);
    }
  }

  // Phase 4: Complete callbacks without holding any locks
  auto error = std::make_exception_ptr(DnsTimeoutException("Query timeout after maximum retries"));
  for (const auto &query : toComplete)
  {
    if (query->callback)
    {
      try
      {
        query->callback({}, error);
      }
      catch (...)
      {
      }
    }
    try
    {
      query->promise.set_exception(error);
    }
    catch (...)
    {
    }
  }

  if (actualTimeouts > 0)
  {
    // Atomic increment - no mutex needed
    stats_.timeouts.fetch_add(actualTimeouts, std::memory_order_relaxed);
  }
}

inline void DnsTransport::retryQuery(std::shared_ptr<PendingQuery> query, const std::string &reason)
{
  if (query->retryCount.load() >= config_.retryCount)
  {
    // Maximum retries exceeded, complete with error
    // Log total attempts made (retryCount + 1 = initial attempt + retries)
    iora::core::Logger::debug(
      "DNS query retry limit exceeded: ID=" + std::to_string(query->queryId) +
      " server=" + query->server + ":" + std::to_string(query->port) + " reason=" + reason +
      " totalAttempts=" + std::to_string(query->retryCount.load() + 1));
    auto error =
      std::make_exception_ptr(DnsTimeoutException("Maximum retries exceeded: " + reason));
    completeQuery(QueryKey(query->queryId, query->server, query->port), error);
    return;
  }

  // Calculate exponential backoff delay with jitter
  auto baseDelay = config_.initialRetryDelay;
  for (int i = 0; i < query->retryCount.load(); ++i)
  {
    baseDelay =
      std::chrono::milliseconds(static_cast<long>(baseDelay.count() * config_.retryMultiplier));
  }

  // Cap at maximum delay
  if (baseDelay > config_.maxRetryDelay)
  {
    baseDelay = config_.maxRetryDelay;
  }

  // Add jitter to prevent thundering herd
  if (config_.jitterFactor > 0.0)
  {
    std::uniform_real_distribution<double> dis(1.0 - config_.jitterFactor,
                                               1.0 + config_.jitterFactor);

    auto jitter = dis(rng_);
    baseDelay = std::chrono::milliseconds(static_cast<long>(baseDelay.count() * jitter));
  }

  // Increment retry count atomically
  int newRetryCount = query->retryCount.fetch_add(1) + 1;

  // Log the upcoming attempt number (retryCount + 1 = initial + retries)
  iora::core::Logger::debug("DNS query retry scheduled: ID=" + std::to_string(query->queryId) +
                            " server=" + query->server + ":" + std::to_string(query->port) +
                            " reason=" + reason +
                            " upcomingAttempt=" + std::to_string(newRetryCount + 1) +
                            " delay=" + std::to_string(baseDelay.count()) + "ms");

  // Schedule retry after delay using timer service (avoids sleeping in worker threads)
  auto self = shared_from_this();
  std::uint64_t timerId = timerService_->scheduleAfter(
    baseDelay,
    [self, query]()
    {
      // Check if transport is still running before accessing any members
      if (!self->running_.load())
      {
        return; // Transport has been stopped/destroyed
      }

      // Check if query is still valid (not completed/cancelled)
      // SAFE: queryId, server, port are const fields, so QueryKey is always consistent
      {
        std::lock_guard<std::mutex> lock(self->queriesMutex_);
        QueryKey key(query->queryId, query->server, query->port);
        auto it = self->pendingQueries_.find(key);
        if (it == self->pendingQueries_.end())
        {
          return; // Query already completed or cancelled
        }
      }

      // Update start time for timeout calculations (fixes retry/timeout race)
      query->startTime.store(std::chrono::steady_clock::now());

      // Retry the query
      try
      {
        if (query->transportMode == DnsTransportMode::UDP)
        {
          self->sendUdpQuery(query);
        }
        else if (query->transportMode == DnsTransportMode::TCP)
        {
          self->sendTcpQuery(query);
        }

        // Atomic increment - no mutex needed
        self->stats_.retries.fetch_add(1, std::memory_order_relaxed);
      }
      catch (const std::exception &e)
      {
        // Retry failed, complete with error
        auto error =
          std::make_exception_ptr(DnsTransportException("Retry failed: " + std::string(e.what())));
        self->completeQuery(QueryKey(query->queryId, query->server, query->port), error);
      }

      // Clear timer ID when callback completes (success or error)
      query->activeTimerId.store(0, std::memory_order_relaxed);
    });

  // Store timer ID for potential cancellation
  query->activeTimerId.store(timerId, std::memory_order_relaxed);
}

} // namespace dns
} // namespace network
} // namespace iora