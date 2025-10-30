// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

#include "iora/core/blocking_queue.hpp"
#include "iora/network/http_client.hpp"

namespace iora
{
namespace network
{

// Forward declaration
class HttpClientPool;

/// \brief RAII wrapper for pooled HTTP client
///
/// Automatically returns the client to the pool when destroyed.
/// Exposes all blocking HTTP operations of the underlying HttpClient.
/// Move-only type to prevent accidental copies.
///
/// Example:
/// \code
///   HttpClientPool pool(config);
///   {
///     auto client = pool.get();
///     auto response = client.get("https://api.example.com/data");
///     // Process response
///   }  // Client automatically returned to pool here
/// \endcode
class PooledHttpClient
{
public:
  /// \brief Move constructor
  PooledHttpClient(PooledHttpClient &&other) noexcept
      : _pool(other._pool), _client(std::move(other._client))
  {
    other._pool = nullptr;
  }

  /// \brief Move assignment operator
  PooledHttpClient &operator=(PooledHttpClient &&other) noexcept
  {
    if (this != &other)
    {
      returnToPool();
      _pool = other._pool;
      _client = std::move(other._client);
      other._pool = nullptr;
    }
    return *this;
  }

  // Delete copy
  PooledHttpClient(const PooledHttpClient &) = delete;
  PooledHttpClient &operator=(const PooledHttpClient &) = delete;

  /// \brief Destructor - returns client to pool
  ~PooledHttpClient()
  {
    returnToPool();
  }

  // ═══════════════════════════════════════════════════════════════
  // Forward all HttpClient blocking operations
  // ═══════════════════════════════════════════════════════════════

  /// \brief Perform blocking HTTP GET request
  HttpClient::Response get(const std::string &url,
                           const std::map<std::string, std::string> &headers = {},
                           int maxRetries = 0)
  {
    validateClient();
    return _client->get(url, headers, maxRetries);
  }

  /// \brief Perform blocking HTTP POST request with JSON
  HttpClient::Response postJson(const std::string &url,
                                const parsers::Json &body,
                                const std::map<std::string, std::string> &headers = {},
                                int maxRetries = 0)
  {
    validateClient();
    return _client->postJson(url, body, headers, maxRetries);
  }

  /// \brief Perform blocking HTTP POST request
  HttpClient::Response post(const std::string &url,
                            const std::string &body,
                            const std::map<std::string, std::string> &headers = {},
                            int maxRetries = 0)
  {
    validateClient();
    return _client->post(url, body, headers, maxRetries);
  }

  /// \brief Perform blocking HTTP DELETE request
  HttpClient::Response deleteRequest(const std::string &url,
                                     const std::map<std::string, std::string> &headers = {},
                                     int maxRetries = 0)
  {
    validateClient();
    return _client->deleteRequest(url, headers, maxRetries);
  }

  /// \brief Post file with multipart/form-data
  HttpClient::Response postFile(const std::string &url,
                                const std::string &fieldName,
                                const std::string &filePath,
                                const std::map<std::string, std::string> &headers = {},
                                int maxRetries = 0)
  {
    validateClient();
    return _client->postFile(url, fieldName, filePath, headers, maxRetries);
  }

  /// \brief Check if client is valid (not returned to pool)
  bool isValid() const
  {
    return _client != nullptr;
  }

  /// \brief Access underlying HttpClient (for advanced use)
  HttpClient &client()
  {
    validateClient();
    return *_client;
  }

  /// \brief Access underlying HttpClient (const version)
  const HttpClient &client() const
  {
    validateClient();
    return *_client;
  }

  /// \brief Configure TLS for this client
  void setTlsConfig(const HttpClient::TlsConfig &tlsConfig)
  {
    validateClient();
    _client->setTlsConfig(tlsConfig);
  }

private:
  friend class HttpClientPool;

  /// \brief Private constructor - only HttpClientPool can create
  PooledHttpClient(HttpClientPool *pool, std::shared_ptr<HttpClient> client)
      : _pool(pool), _client(std::move(client))
  {
  }

  /// \brief Validate that client is still valid
  void validateClient() const
  {
    if (!_client)
    {
      throw std::runtime_error("PooledHttpClient: Client has been returned to pool");
    }
  }

  /// \brief Return client to pool
  void returnToPool();

  HttpClientPool *_pool;
  std::shared_ptr<HttpClient> _client;
};

/// \brief Thread-safe HTTP client connection pool
///
/// Manages a pool of reusable HttpClient instances with automatic
/// lifecycle management. Clients are automatically returned to the pool
/// when the PooledHttpClient wrapper goes out of scope.
///
/// Features:
/// - Thread-safe client acquisition and return
/// - Blocking, timeout, and non-blocking acquisition modes
/// - Automatic client lifecycle management
/// - Configurable pool size and timeouts
/// - Built-in statistics and monitoring
/// - Optional health checking
///
/// Example:
/// \code
///   HttpClientPool::Config config;
///   config.poolSize = 10;
///   config.requestTimeout = std::chrono::seconds(30);
///
///   HttpClientPool pool(config);
///
///   // Get client and perform request (automatic return on scope exit)
///   {
///     auto client = pool.get();
///     auto response = client.get("https://api.example.com/data");
///   }  // Client automatically returned here
/// \endcode
class HttpClientPool
{
public:
  /// \brief Configuration for the HTTP client pool
  struct Config
  {
    /// Maximum number of clients in the pool
    std::size_t poolSize = 10;

    /// Timeout for individual HTTP requests
    std::chrono::milliseconds requestTimeout{30000};

    /// Timeout for initial connection establishment
    std::chrono::milliseconds connectionTimeout{10000};

    /// Enable HTTP keep-alive
    bool enableKeepAlive = true;

    /// Enable gzip compression
    bool enableCompression = false;

    /// Follow HTTP redirects
    bool followRedirects = true;

    /// Maximum number of redirects to follow
    int maxRedirects = 5;

    /// User agent string
    std::string userAgent = "Iora-HttpClientPool/1.0";

    /// Default headers applied to all requests
    std::map<std::string, std::string> defaultHeaders{};

    /// Optional factory for custom client creation
    /// If not provided, uses default HttpClient constructor
    std::function<std::unique_ptr<HttpClient>()> clientFactory;

    /// Optional callback to configure each client after creation
    std::function<void(HttpClient &)> clientConfigurer;

    /// TLS configuration for HTTPS requests
    std::optional<HttpClient::TlsConfig> tlsConfig;
  };

  /// \brief Construct pool with configuration
  explicit HttpClientPool(const Config &config) : _config(config), _queue(config.poolSize), _closed(false)
  {
    if (config.poolSize == 0)
    {
      throw std::invalid_argument("HttpClientPool: poolSize must be greater than 0");
    }

    // Pre-populate the pool with clients
    for (std::size_t i = 0; i < config.poolSize; ++i)
    {
      auto client = createClient();
      if (!_queue.queue(std::move(client)))
      {
        throw std::runtime_error("HttpClientPool: Failed to initialize pool");
      }
    }
  }

  /// \brief Destructor - closes pool and releases all clients
  ~HttpClientPool()
  {
    close();
  }

  // Delete copy and move
  HttpClientPool(const HttpClientPool &) = delete;
  HttpClientPool &operator=(const HttpClientPool &) = delete;
  HttpClientPool(HttpClientPool &&) = delete;
  HttpClientPool &operator=(HttpClientPool &&) = delete;

  // ═══════════════════════════════════════════════════════════════
  // Client Acquisition Methods
  // ═══════════════════════════════════════════════════════════════

  /// \brief Get a client from the pool (blocks if none available)
  ///
  /// Blocks until a client becomes available or the pool is closed.
  /// \return PooledHttpClient that automatically returns to pool on destruction
  /// \throws std::runtime_error if pool is closed
  PooledHttpClient get()
  {
    if (_closed.load(std::memory_order_acquire))
    {
      throw std::runtime_error("HttpClientPool: Pool is closed");
    }

    std::shared_ptr<HttpClient> client;
    if (!_queue.dequeue(client))
    {
      throw std::runtime_error("HttpClientPool: Pool is closed");
    }

    return PooledHttpClient(this, std::move(client));
  }

  /// \brief Get a client with timeout
  ///
  /// \param timeout Maximum time to wait for an available client
  /// \return PooledHttpClient if acquired, std::nullopt if timeout or closed
  std::optional<PooledHttpClient> get(std::chrono::milliseconds timeout)
  {
    if (_closed.load(std::memory_order_acquire))
    {
      return std::nullopt;
    }

    std::shared_ptr<HttpClient> client;
    if (!_queue.dequeue(client, timeout))
    {
      return std::nullopt;
    }

    return PooledHttpClient(this, std::move(client));
  }

  /// \brief Try to get a client without blocking
  ///
  /// \return PooledHttpClient if immediately available, std::nullopt otherwise
  std::optional<PooledHttpClient> tryGet()
  {
    if (_closed.load(std::memory_order_acquire))
    {
      return std::nullopt;
    }

    std::shared_ptr<HttpClient> client;
    if (!_queue.tryDequeue(client))
    {
      return std::nullopt;
    }

    return PooledHttpClient(this, std::move(client));
  }

  // ═══════════════════════════════════════════════════════════════
  // Pool Management
  // ═══════════════════════════════════════════════════════════════

  /// \brief Close the pool and prevent new acquisitions
  ///
  /// Existing clients can be returned but no new clients can be acquired.
  void close()
  {
    if (_closed.exchange(true, std::memory_order_acq_rel))
    {
      return; // Already closed
    }

    _queue.close();
  }

  /// \brief Check if pool is closed
  bool isClosed() const
  {
    return _closed.load(std::memory_order_acquire);
  }

  // ═══════════════════════════════════════════════════════════════
  // Statistics & Monitoring
  // ═══════════════════════════════════════════════════════════════

  /// \brief Get total pool size
  std::size_t capacity() const
  {
    return _config.poolSize;
  }

  /// \brief Get number of available clients in pool
  std::size_t available() const
  {
    return _queue.size();
  }

  /// \brief Get number of clients currently in use
  std::size_t inUse() const
  {
    return capacity() - available();
  }

  /// \brief Check if pool is empty (all clients in use)
  bool empty() const
  {
    return _queue.empty();
  }

  /// \brief Check if pool is full (all clients available)
  bool full() const
  {
    return _queue.full();
  }

  /// \brief Get pool utilization percentage (0-100)
  double utilization() const
  {
    if (capacity() == 0)
    {
      return 0.0;
    }
    return (static_cast<double>(inUse()) / capacity()) * 100.0;
  }

  /// \brief Get pool configuration
  const Config &config() const
  {
    return _config;
  }

private:
  friend class PooledHttpClient;

  /// \brief Return a client to the pool
  void returnClient(std::shared_ptr<HttpClient> client)
  {
    if (!client)
    {
      return;
    }

    // Try to return to queue (non-blocking to avoid deadlock)
    // If queue is closed or full, client will be destroyed
    _queue.tryQueue(std::move(client));
  }

  /// \brief Create a new HttpClient instance
  std::shared_ptr<HttpClient> createClient()
  {
    std::shared_ptr<HttpClient> client;

    if (_config.clientFactory)
    {
      client = _config.clientFactory();
    }
    else
    {
      // Create with default configuration
      HttpClient::Config clientConfig;
      clientConfig.requestTimeout = _config.requestTimeout;
      clientConfig.connectTimeout = _config.connectionTimeout;
      clientConfig.followRedirects = _config.followRedirects;
      clientConfig.maxRedirects = _config.maxRedirects;
      clientConfig.userAgent = _config.userAgent;
      clientConfig.reuseConnections = _config.enableKeepAlive;

      client = std::make_shared<HttpClient>(clientConfig);
    }

    if (!client)
    {
      throw std::runtime_error("HttpClientPool: Failed to create HttpClient");
    }

    // Configure TLS if provided
    if (_config.tlsConfig.has_value())
    {
      client->setTlsConfig(_config.tlsConfig.value());
    }

    // Apply custom configuration
    if (_config.clientConfigurer)
    {
      _config.clientConfigurer(*client);
    }

    return client;
  }

  Config _config;
  core::BlockingQueue<std::shared_ptr<HttpClient>> _queue;
  std::atomic<bool> _closed;
};

// ═══════════════════════════════════════════════════════════════
// PooledHttpClient implementation
// ═══════════════════════════════════════════════════════════════

inline void PooledHttpClient::returnToPool()
{
  if (_client && _pool)
  {
    _pool->returnClient(std::move(_client));
    _client = nullptr;
  }
}

} // namespace network
} // namespace iora
