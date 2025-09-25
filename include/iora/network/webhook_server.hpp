// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once
#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <variant>

#include "iora/core/logger.hpp"
#include "iora/core/thread_pool.hpp"
#include "iora/network/unified_shared_transport.hpp"
#include "iora/parsers/http_message.hpp"
#include "iora/parsers/json.hpp"

namespace iora
{
namespace network
{

/// \brief Lightweight, testable HTTP webhook server for handling REST and
/// JSON endpoints.
class WebhookServer
{
public:
  /// \brief Configuration constants
  static constexpr std::size_t MAX_PENDING_REQUESTS = 1000;              // Maximum queued requests
  static constexpr std::size_t DEFAULT_MAX_JSON_SIZE = 10 * 1024 * 1024; // 10MB default

  /// \brief Explicitly delete copy/move constructors and assignment operators
  WebhookServer(const WebhookServer &) = delete;
  WebhookServer &operator=(const WebhookServer &) = delete;
  WebhookServer(WebhookServer &&) = delete;
  WebhookServer &operator=(WebhookServer &&) = delete;

  /// \brief TLS configuration for the server
  struct TlsConfig
  {
    std::string certFile;
    std::string keyFile;
    std::string caFile;
    bool requireClientCert = false;
  };

  /// \brief JSON parsing configuration
  struct JsonConfig
  {
    std::size_t maxPayloadSize = DEFAULT_MAX_JSON_SIZE; // Maximum JSON payload size in bytes
    parsers::ParseLimits parseLimits; // JSON parsing limits (depth, array size, etc.)
  };

  /// \brief HTTP request wrapper to maintain API compatibility
  struct Request
  {
    HttpMethod method;
    std::string path;
    HttpHeaders headers;
    std::string body;
    std::unordered_map<std::string, std::string> params;
    std::string remote_addr;       // Peer IP address for httplib compatibility
    std::uint16_t remote_port = 0; // Peer port for additional context

    std::string get_header_value(const std::string &key) const
    {
      auto it = headers.find(key);
      return it != headers.end() ? it->second : "";
    }

    bool has_header(const std::string &key) const { return headers.find(key) != headers.end(); }
  };

  /// \brief HTTP response wrapper to maintain API compatibility
  struct Response
  {
    int status = 200;
    HttpHeaders headers;
    std::string body;

    void set_content(const std::string &content, const std::string &contentType)
    {
      body = content;
      headers["Content-Type"] = contentType;
      headers["Content-Length"] = std::to_string(content.size());
    }

    void set_header(const std::string &key, const std::string &value) { headers[key] = value; }
  };

  using Handler = std::function<void(const Request &, Response &)>;
  using JsonHandler = std::function<parsers::Json(const parsers::Json &)>;

  /// \brief Utility class for handlers to check if the server is shutting
  /// down
  ///
  /// Handlers should use this to check for shutdown and exit gracefully:
  /// ```cpp
  /// server.onPost("/api", [&server](const Request& req, Response& res) {
  ///   auto shutdown = server.getShutdownChecker();
  ///
  ///   for (int i = 0; i < 1000; ++i) {
  ///     if (shutdown.isShuttingDown()) {
  ///       res.set_status(503);
  ///       res.set_content("Service shutting down", "text/plain");
  ///       return;
  ///     }
  ///     // Do work...
  ///   }
  /// });
  /// ```
  class ShutdownChecker
  {
    const std::atomic<bool> &_shutdownFlag;

  public:
    explicit ShutdownChecker(const std::atomic<bool> &flag) : _shutdownFlag(flag) {}

    /// \brief Check if the server is shutting down
    /// \return true if shutdown has been initiated
    bool isShuttingDown() const { return _shutdownFlag.load(); }

    /// \brief Throw if shutting down (for exception-based flow control)
    void throwIfShuttingDown() const
    {
      if (isShuttingDown())
      {
        throw std::runtime_error("Server is shutting down");
      }
    }
  };

  static constexpr int DEFAULT_PORT = 8080;

  /// \brief Constructs a WebhookServer with the default bind address and port.
  WebhookServer(const std::string& bindAddress = "0.0.0.0", int port = DEFAULT_PORT)
      : _bindAddress(bindAddress), _port(port), _shutdown(false), _jsonConfig{},
        _threadPool(2, 8, std::chrono::seconds(30))
  {
  }

  ~WebhookServer()
  {
    iora::core::Logger::debug("WebhookServer::~WebhookServer() - Destructor called");
    try
    {
      stop();
    }
    catch (const std::exception &e)
    {
      // Log the error but don't throw from destructor
      iora::core::Logger::error("WebhookServer destructor error: " + std::string(e.what()));
    }
    catch (...)
    {
      // Handle any other exceptions
      iora::core::Logger::error("WebhookServer destructor unknown error");
    }
  }

  /// \brief Sets the port for the server.
  void setPort(int port)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _port = port;
  }

  /// \brief Sets the bind address for the server.
  void setBindAddress(const std::string& bindAddress)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _bindAddress = bindAddress;
  }

  /// \brief Gets the current port.
  int getPort() const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    return _port;
  }

  /// \brief Gets the current bind address.
  std::string getBindAddress() const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    return _bindAddress;
  }

  /// \brief Sets the JSON parsing configuration
  void setJsonConfig(const JsonConfig &config)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _jsonConfig = config;
  }

  /// \brief Gets the current JSON parsing configuration
  JsonConfig getJsonConfig() const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    return _jsonConfig;
  }

  /// \brief Get a ShutdownChecker for use in handlers
  /// \return ShutdownChecker that can be used to check if server is shutting
  /// down
  ShutdownChecker getShutdownChecker() const { return ShutdownChecker(_shutdown); }

  /// \brief Enables TLS with the given configuration. Throws if cert/key
  /// files are missing or invalid.
  void enableTls(const TlsConfig &config)
  {
    std::lock_guard<std::mutex> lock(_mutex);

    // Validate cert/key files exist
    if (config.certFile.empty() || config.keyFile.empty())
    {
      throw std::runtime_error("TLS: certFile and keyFile must be set");
    }

    // Validate certificate file
    {
      std::ifstream certTest(config.certFile, std::ios::binary);
      if (!certTest.good())
      {
        throw std::runtime_error("TLS: certFile '" + config.certFile + "' not readable");
      }

      // Basic validation - check for PEM format
      std::string firstLine;
      std::getline(certTest, firstLine);
      if (firstLine.find("-----BEGIN") == std::string::npos)
      {
        throw std::runtime_error("TLS: certFile '" + config.certFile +
                                 "' does not appear to be in PEM format");
      }

      // Check file size is reasonable
      certTest.seekg(0, std::ios::end);
      auto certSize = certTest.tellg();
      if (certSize <= 0 || certSize > 100 * 1024) // 100KB max
      {
        throw std::runtime_error("TLS: certFile '" + config.certFile +
                                 "' has invalid size: " + std::to_string(certSize) + " bytes");
      }
    }

    // Validate key file
    {
      std::ifstream keyTest(config.keyFile, std::ios::binary);
      if (!keyTest.good())
      {
        throw std::runtime_error("TLS: keyFile '" + config.keyFile + "' not readable");
      }

      // Basic validation - check for PEM format
      std::string firstLine;
      std::getline(keyTest, firstLine);
      if (firstLine.find("-----BEGIN") == std::string::npos)
      {
        throw std::runtime_error("TLS: keyFile '" + config.keyFile +
                                 "' does not appear to be in PEM format");
      }

      // Check file size is reasonable
      keyTest.seekg(0, std::ios::end);
      auto keySize = keyTest.tellg();
      if (keySize <= 0 || keySize > 100 * 1024) // 100KB max
      {
        throw std::runtime_error("TLS: keyFile '" + config.keyFile +
                                 "' has invalid size: " + std::to_string(keySize) + " bytes");
      }
    }

    // Validate CA file if client certificates are required
    if (config.requireClientCert)
    {
      if (config.caFile.empty())
      {
        throw std::runtime_error("TLS: requireClientCert is true but caFile is not set");
      }

      std::ifstream caTest(config.caFile, std::ios::binary);
      if (!caTest.good())
      {
        throw std::runtime_error("TLS: caFile '" + config.caFile + "' not readable");
      }

      // Basic validation - check for PEM format
      std::string firstLine;
      std::getline(caTest, firstLine);
      if (firstLine.find("-----BEGIN") == std::string::npos)
      {
        throw std::runtime_error("TLS: caFile '" + config.caFile +
                                 "' does not appear to be in PEM format");
      }

      // Check file size is reasonable
      caTest.seekg(0, std::ios::end);
      auto caSize = caTest.tellg();
      if (caSize <= 0 || caSize > 100 * 1024) // 100KB max
      {
        throw std::runtime_error("TLS: caFile '" + config.caFile +
                                 "' has invalid size: " + std::to_string(caSize) + " bytes");
      }
    }

    _tlsConfig = config;
    iora::core::Logger::info("WebhookServer: TLS configuration validated successfully");
  }

  /// \brief Registers a GET handler for the given path.
  void onGet(const std::string &path, Handler handler)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _handlers[HttpMethod::GET][path] = std::move(handler);
  }

  /// \brief Registers a GET handler for JSON endpoints.
  void onJsonGet(const std::string &endpoint, JsonHandler handler)
  {
    onGet(endpoint,
          [this, handler](const Request &req, Response &res)
          {
            try
            {
              parsers::Json requestJson;
              if (req.body.empty())
              {
                requestJson = parsers::Json::object();
              }
              else
              {
                if (req.body.size() > _jsonConfig.maxPayloadSize)
                {
                  throw std::runtime_error("JSON payload exceeds maximum size limit of " +
                                           std::to_string(_jsonConfig.maxPayloadSize) + " bytes");
                }
                auto result = parsers::Json::parse(req.body, _jsonConfig.parseLimits);
                if (!result.ok)
                {
                  throw std::runtime_error("JSON parse error: " + result.error.message);
                }
                requestJson = std::move(result.value);
              }
              parsers::Json responseJson = handler(requestJson);
              res.set_content(responseJson.dump(), "application/json");
            }
            catch (const std::exception &ex)
            {
              res.status = 500;
              res.set_content(ex.what(), "text/plain");
              iora::core::Logger::error(std::string("WebhookServer onJsonGet handler error: ") +
                                        ex.what());
            }
          });
  }

  /// \brief Registers a POST handler for the given path.
  void onPost(const std::string &path, Handler handler)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _handlers[HttpMethod::POST][path] = std::move(handler);
  }

  /// \brief Registers a POST handler for JSON endpoints.
  void onJsonPost(const std::string &endpoint, JsonHandler handler)
  {
    onPost(endpoint,
           [this, handler](const Request &req, Response &res)
           {
             try
             {
               if (req.body.size() > _jsonConfig.maxPayloadSize)
               {
                 throw std::runtime_error("JSON payload exceeds maximum size limit of " +
                                          std::to_string(_jsonConfig.maxPayloadSize) + " bytes");
               }
               auto result = parsers::Json::parse(req.body, _jsonConfig.parseLimits);
               if (!result.ok)
               {
                 throw std::runtime_error("JSON parse error: " + result.error.message);
               }
               parsers::Json requestJson = std::move(result.value);
               parsers::Json responseJson = handler(requestJson);
               res.set_content(responseJson.dump(), "application/json");
             }
             catch (const std::exception &ex)
             {
               res.status = 500;
               res.set_content(ex.what(), "text/plain");
               iora::core::Logger::error(std::string("WebhookServer onJsonPost handler error: ") +
                                         ex.what());
             }
           });
  }

  /// \brief Registers a DELETE handler for the given path.
  void onDelete(const std::string &path, Handler handler)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _handlers[HttpMethod::DELETE][path] = std::move(handler);
  }

  /// \brief Starts the server. Throws on error.
  void start()
  {
    std::lock_guard<std::mutex> lock(_mutex);
    try
    {
      _shutdown = false;

      // Configure transport
      UnifiedSharedTransport::Config config;
      config.protocol = UnifiedSharedTransport::Protocol::TCP;
      config.idleTimeout = std::chrono::seconds(600);
      config.maxPendingSyncOps = 32;
      config.defaultSyncTimeout = std::chrono::milliseconds(30000);
      config.enableTcpNoDelay = true;
      config.tcpKeepalive.enable = true;
      config.maxWriteQueue = 1024;

      // Configure TLS if enabled
      if (_tlsConfig.has_value())
      {
        const auto &tlsCfg = _tlsConfig.value();
        config.serverTls.enabled = true;
        config.serverTls.defaultMode = TlsMode::Server;
        config.serverTls.certFile = tlsCfg.certFile;
        config.serverTls.keyFile = tlsCfg.keyFile;
        config.serverTls.caFile = tlsCfg.caFile;
        config.serverTls.verifyPeer = tlsCfg.requireClientCert;
      }

      _transport = std::make_unique<UnifiedSharedTransport>(config);

      // Set up callbacks before starting

      // Accept callback - new connection accepted
      _transport->setAcceptCallback(
        [this](SessionId sid, const std::string &peer, const IoResult &result)
        {
          if (result.ok)
          {
            // Initialize session state and parse peer address
            {
              std::lock_guard<std::mutex> lock(_sessionMutex);
              SessionInfo &info = _sessionInfo[sid];
              info.buffer = "";

              // Parse peer address from format "ip:port"
              auto colonPos = peer.find(':');
              if (colonPos != std::string::npos)
              {
                info.peerAddress = peer.substr(0, colonPos);
                try
                {
                  info.peerPort = static_cast<std::uint16_t>(std::stoi(peer.substr(colonPos + 1)));
                }
                catch (...)
                {
                  info.peerPort = 0;
                }
              }
              else
              {
                info.peerAddress = peer;
                info.peerPort = 0;
              }

              // Log the accepted connection
              iora::core::Logger::info("WebhookServer: Accepted HTTP connection from " +
                                       info.peerAddress + ":" + std::to_string(info.peerPort) +
                                       " (session " + std::to_string(sid) + ")");
            }

            // Set session to async mode for receiving data
            _transport->setReadMode(sid, ReadMode::Async);

            // Set up data callback for this session
            _transport->setDataCallback(sid,
                                        [this](SessionId session, const std::uint8_t *data,
                                               std::size_t len, const IoResult &result)
                                        {
                                          if (result.ok)
                                          {
                                            handleIncomingData(session, data, len);
                                          }
                                        });
          }
        });

      // Close callback - connection closed
      _transport->setCloseCallback(
        [this](SessionId sid, const IoResult &result)
        {
          std::lock_guard<std::mutex> lock(_sessionMutex);
          auto it = _sessionInfo.find(sid);
          if (it != _sessionInfo.end())
          {
            iora::core::Logger::info(
              "WebhookServer: HTTP connection closed from " + it->second.peerAddress + ":" +
              std::to_string(it->second.peerPort) + " (session " + std::to_string(sid) + ")");
            _sessionInfo.erase(it);
          }
          else
          {
            iora::core::Logger::debug("WebhookServer: Connection closed (session " +
                                      std::to_string(sid) + ")");
          }
        });

      // Error callback
      _transport->setErrorCallback(
        [this](TransportError error, const std::string &message)
        { iora::core::Logger::error("WebhookServer transport error: " + message); });

      // Start transport
      if (!_transport->start())
      {
        throw std::runtime_error("Failed to start transport");
      }

      // Add listener
      TlsMode tlsMode = _tlsConfig.has_value() ? TlsMode::Server : TlsMode::None;
      _listenerId = _transport->addListener(_bindAddress, _port, tlsMode);

      iora::core::Logger::info("WebhookServer started on " + _bindAddress + ":" + std::to_string(_port));
    }
    catch (const std::exception &ex)
    {
      iora::core::Logger::error(std::string("WebhookServer start error: ") + ex.what());
      throw;
    }
  }

  /// \brief Stops the server gracefully.
  void stop()
  {
    iora::core::Logger::debug("WebhookServer::stop() - Starting graceful shutdown");

    // Set shutdown flag atomically to stop new request processing
    _shutdown.store(true);

    // Give a brief moment for in-flight requests to see the shutdown flag
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::lock_guard<std::mutex> lock(_mutex);

    iora::core::Logger::debug("WebhookServer::stop() - Stopping transport to "
                              "prevent new connections");
    // Stop transport first to prevent new connections and data
    if (_transport)
    {
      _transport->stop();
      iora::core::Logger::debug("WebhookServer::stop() - Transport stopped gracefully");
    }

    // Clear session information
    {
      std::lock_guard<std::mutex> sessionLock(_sessionMutex);
      _sessionInfo.clear();
      iora::core::Logger::debug("WebhookServer::stop() - Cleared session information");
    }

    // Wait for thread pool tasks to complete with a reasonable timeout
    // Handlers should use getShutdownChecker() to detect shutdown and exit
    // gracefully
    auto startTime = std::chrono::steady_clock::now();
    const auto maxWaitTime = std::chrono::seconds(2); // Reasonable timeout for production

    iora::core::Logger::debug("WebhookServer::stop() - Waiting for handlers to complete (max 2s)");

    while (_threadPool.getPendingTaskCount() > 0 || _threadPool.getActiveThreadCount() > 0)
    {
      auto elapsed = std::chrono::steady_clock::now() - startTime;
      if (elapsed > maxWaitTime)
      {
        auto pendingTasks = _threadPool.getPendingTaskCount();
        auto activeTasks = _threadPool.getActiveThreadCount();
        iora::core::Logger::warning(
          std::string("WebhookServer::stop() - Timeout waiting for handlers. ") +
          "Forcing shutdown with " + std::to_string(pendingTasks) + " pending and " +
          std::to_string(activeTasks) + " active tasks. " +
          "Handlers should use getShutdownChecker() to detect shutdown.");
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    iora::core::Logger::debug("WebhookServer::stop() - Handler wait completed");

    // Now safe to reset the transport since no tasks are using it
    if (_transport)
    {
      iora::core::Logger::debug("WebhookServer::stop() - Resetting transport");
      _transport.reset();
      iora::core::Logger::debug("WebhookServer::stop() - Transport reset complete");
    }

    iora::core::Logger::debug("WebhookServer::stop() - Graceful shutdown complete");
  }

private:
  /// \brief Handle incoming data from a session
  void handleIncomingData(SessionId sid, const std::uint8_t *data, std::size_t len)
  {
    std::string dataStr(reinterpret_cast<const char *>(data), len);

    // Append to session buffer with size limits
    {
      std::lock_guard<std::mutex> lock(_sessionMutex);
      auto it = _sessionInfo.find(sid);
      if (it == _sessionInfo.end())
      {
        return; // Session was closed
      }

      // Check buffer size limit to prevent DoS
      if (it->second.buffer.size() + dataStr.size() > SessionInfo::MAX_BUFFER_SIZE)
      {
        iora::core::Logger::error("WebhookServer: Buffer size limit exceeded for session " +
                                  std::to_string(sid) + " - closing connection");
        _transport->close(sid);
        return;
      }

      it->second.buffer += dataStr;
      dataStr = it->second.buffer; // Work with complete buffer
    }

    // Process all complete requests in the buffer (support pipelining)
    while (true)
    {
      auto headerEnd = dataStr.find("\r\n\r\n");
      if (headerEnd == std::string::npos)
      {
        break; // Need more data for headers
      }

      // Check header size limit
      if (headerEnd > SessionInfo::MAX_HEADER_SIZE)
      {
        iora::core::Logger::error("WebhookServer: Header size limit exceeded for session " +
                                  std::to_string(sid) + " - closing connection");
        _transport->close(sid);
        return;
      }

      std::string headerSection = dataStr.substr(0, headerEnd);
      std::size_t contentLength = 0;
      bool isChunked = false;

      // Parse headers
      std::istringstream headerStream(headerSection);
      std::string line;
      while (std::getline(headerStream, line))
      {
        if (!line.empty() && line.back() == '\r')
        {
          line.pop_back();
        }

        auto colonPos = line.find(':');
        if (colonPos != std::string::npos)
        {
          std::string key = line.substr(0, colonPos);
          std::string value = line.substr(colonPos + 1);

          // Trim whitespace
          key.erase(0, key.find_first_not_of(" \t"));
          key.erase(key.find_last_not_of(" \t") + 1);
          value.erase(0, value.find_first_not_of(" \t"));
          value.erase(value.find_last_not_of(" \t") + 1);

          // Convert key to lowercase for comparison
          std::transform(key.begin(), key.end(), key.begin(), ::tolower);

          if (key == "content-length")
          {
            try
            {
              contentLength = std::stoull(value);
              if (contentLength > SessionInfo::MAX_BODY_SIZE)
              {
                iora::core::Logger::error("WebhookServer: Body size limit exceeded for session " +
                                          std::to_string(sid) + " - closing connection");
                _transport->close(sid);
                return;
              }
            }
            catch (...)
            {
              iora::core::Logger::error("WebhookServer: Invalid "
                                        "content-length header for session " +
                                        std::to_string(sid) + " - closing connection");
              _transport->close(sid);
              return;
            }
          }
          else if (key == "transfer-encoding")
          {
            // Convert value to lowercase for comparison
            std::transform(value.begin(), value.end(), value.begin(), ::tolower);
            if (value.find("chunked") != std::string::npos)
            {
              isChunked = true;
            }
          }
        }
      }

      std::size_t requestEndPos;

      if (isChunked)
      {
        // Handle chunked encoding
        requestEndPos = findChunkedRequestEnd(dataStr, headerEnd + 4);
        if (requestEndPos == std::string::npos)
        {
          break; // Need more data for chunked body
        }
      }
      else
      {
        // Handle content-length or no body
        std::size_t totalExpectedLength = headerEnd + 4 + contentLength;
        if (dataStr.length() < totalExpectedLength)
        {
          break; // Need more data for body
        }
        requestEndPos = totalExpectedLength;
      }

      // Extract complete request
      std::string requestData = dataStr.substr(0, requestEndPos);

      // Remove processed data from buffer
      dataStr = dataStr.substr(requestEndPos);
      {
        std::lock_guard<std::mutex> lock(_sessionMutex);
        auto it = _sessionInfo.find(sid);
        if (it != _sessionInfo.end())
        {
          it->second.buffer = dataStr;
        }
      }

      // Process request in thread pool to avoid blocking transport
      // Use tryEnqueue for backpressure - reject requests if queue is full
      if (!_threadPool.tryEnqueue([this, sid, requestData]()
                                  { processHttpRequest(sid, requestData); }))
      {
        // Thread pool is overloaded, send 503 Service Unavailable
        iora::core::Logger::warning(
          "WebhookServer: Rejecting request due to thread pool overload "
          "(queue: " +
          std::to_string(_threadPool.getPendingTaskCount()) + "/" + std::to_string(1024) +
          ", utilization: " + std::to_string(static_cast<int>(_threadPool.getQueueUtilization())) +
          "%)");
        sendErrorResponse(sid, 503, "Service Unavailable",
                          "Server overloaded - please retry later");
      }
      else if (_threadPool.isUnderHighLoad())
      {
        // Log warning when approaching capacity
        iora::core::Logger::warning(
          "WebhookServer: High load detected (queue utilization: " +
          std::to_string(static_cast<int>(_threadPool.getQueueUtilization())) + "%, " +
          "active threads: " + std::to_string(_threadPool.getActiveThreadCount()) + "/" +
          std::to_string(_threadPool.getTotalThreadCount()) + ")");
      }
    }
  }

  /// \brief Process a complete HTTP request
  void processHttpRequest(SessionId sid, const std::string &requestData)
  {
    iora::core::Logger::debug("WebhookServer::processHttpRequest() - "
                              "Processing request for session " +
                              std::to_string(sid));

    // Check if we're shutting down - with atomic read to avoid lock
    if (_shutdown.load())
    {
      iora::core::Logger::debug("WebhookServer::processHttpRequest() - "
                                "Aborting due to shutdown for session " +
                                std::to_string(sid));

      // Send 503 Service Unavailable during shutdown
      HttpResponse shutdownRes(503, "Service Unavailable");
      shutdownRes.setHeader("Content-Type", "text/plain");
      shutdownRes.body = "Server Shutting Down";
      shutdownRes.setHeader("Content-Length", std::to_string(shutdownRes.body.size()));
      shutdownRes.setHeader("Connection", "close");

      auto shutdownResponseData = std::make_shared<std::string>(shutdownRes.toWireFormat());
      {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_transport)
        {
          _transport->sendAsync(sid, shutdownResponseData->data(), shutdownResponseData->size(),
                                [this, sid](SessionId session, const SyncResult &result)
                                {
                                  // Always close connection during shutdown
                                  std::lock_guard<std::mutex> lock(_mutex);
                                  if (_transport)
                                  {
                                    _transport->close(session);
                                  }
                                });
        }
      }
      return;
    }

    try
    {
      // Parse HTTP request
      HttpRequest httpReq = HttpRequest::fromWireFormat(requestData);

      // Convert to our Request format
      Request req;
      req.method = httpReq.method;
      req.path = httpReq.uri;
      req.headers = httpReq.headers;
      req.body = httpReq.body;

      // Populate peer address information
      {
        std::lock_guard<std::mutex> lock(_sessionMutex);
        auto it = _sessionInfo.find(sid);
        if (it != _sessionInfo.end())
        {
          req.remote_addr = it->second.peerAddress;
          req.remote_port = it->second.peerPort;
        }
      }

      // Log the incoming HTTP request with full context
      std::string methodStr;
      switch (req.method)
      {
      case HttpMethod::GET:
        methodStr = "GET";
        break;
      case HttpMethod::POST:
        methodStr = "POST";
        break;
      case HttpMethod::DELETE:
        methodStr = "DELETE";
        break;
      default:
        methodStr = "UNKNOWN";
        break;
      }

      iora::core::Logger::info("WebhookServer: " + methodStr + " " + req.path + " from " +
                               req.remote_addr + ":" + std::to_string(req.remote_port) +
                               " (session " + std::to_string(sid) +
                               ", body size: " + std::to_string(req.body.size()) + " bytes)");

      // Extract path without query parameters
      auto queryPos = req.path.find('?');
      if (queryPos != std::string::npos)
      {
        // Parse query parameters
        std::string queryString = req.path.substr(queryPos + 1);
        req.path = req.path.substr(0, queryPos);

        // Simple query parameter parsing
        std::istringstream queryStream(queryString);
        std::string param;
        while (std::getline(queryStream, param, '&'))
        {
          auto eqPos = param.find('=');
          if (eqPos != std::string::npos)
          {
            std::string key = param.substr(0, eqPos);
            std::string value = param.substr(eqPos + 1);
            req.params[key] = value;
          }
        }
      }

      // Create response
      Response res;
      res.status = 404;
      res.set_content("Not Found", "text/plain");

      // Find handler with proper HTTP status codes
      {
        std::lock_guard<std::mutex> lock(_mutex);

        // Check if path exists for any method (for 405 Method Not Allowed)
        bool pathExists = false;
        for (const auto &[method, pathHandlers] : _handlers)
        {
          if (pathHandlers.find(req.path) != pathHandlers.end())
          {
            pathExists = true;
            break;
          }
        }

        auto methodIt = _handlers.find(httpReq.method);
        if (methodIt != _handlers.end())
        {
          auto handlerIt = methodIt->second.find(req.path);
          if (handlerIt != methodIt->second.end())
          {
            // Handler found - execute it
            res.status = 200;
            try
            {
              handlerIt->second(req, res);
            }
            catch (const std::exception &e)
            {
              iora::core::Logger::error("WebhookServer: Handler exception for " + req.path + ": " +
                                        e.what());
              res.status = 500;
              res.set_content("Internal Server Error", "text/plain");
            }
          }
          else if (pathExists)
          {
            // Path exists but method not allowed
            res.status = 405;
            res.set_content("Method Not Allowed", "text/plain");
            res.headers["Allow"] = getAllowedMethods(req.path);
          }
          // else: 404 Not Found (default)
        }
        else if (pathExists)
        {
          // Path exists but method not allowed
          res.status = 405;
          res.set_content("Method Not Allowed", "text/plain");
          res.headers["Allow"] = getAllowedMethods(req.path);
        }
        // else: 404 Not Found (default)
      }

      // Determine connection behavior
      bool shouldCloseConnection = false;
      std::string connectionHeader = "keep-alive";

      // Check for HTTP/1.0 or Connection: close
      {
        std::lock_guard<std::mutex> lock(_sessionMutex);
        auto it = _sessionInfo.find(sid);
        if (it != _sessionInfo.end())
        {
          if (it->second.httpVersion == "1.0")
          {
            shouldCloseConnection = true;
            connectionHeader = "close";
          }
          else if (!it->second.connectionKeepAlive)
          {
            shouldCloseConnection = true;
            connectionHeader = "close";
          }
        }
      }

      // Check request headers for connection preference
      auto connectionIt = req.headers.find("Connection");
      if (connectionIt != req.headers.end())
      {
        std::string connValue = connectionIt->second;
        std::transform(connValue.begin(), connValue.end(), connValue.begin(), ::tolower);
        if (connValue == "close")
        {
          shouldCloseConnection = true;
          connectionHeader = "close";
        }
      }

      // Build HTTP response
      HttpResponse httpRes;
      httpRes.statusCode = res.status;
      httpRes.statusText = getStatusText(res.status);
      httpRes.headers = res.headers;
      httpRes.body = res.body;

      // Add server headers
      httpRes.setHeader("Server", "Iora/1.0");
      httpRes.setHeader("Connection", connectionHeader);

      // Send response asynchronously but ensure proper completion
      std::string responseData = httpRes.toWireFormat();

      // Create a shared string to keep the data alive during async send
      auto sharedResponseData = std::make_shared<std::string>(std::move(responseData));

      // Check if transport is still available before sending
      {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_transport && !_shutdown)
        {
          iora::core::Logger::info(
            "WebhookServer: Sending " + std::to_string(res.status) + " response to " +
            req.remote_addr + ":" + std::to_string(req.remote_port) + " (session " +
            std::to_string(sid) + ", " + std::to_string(sharedResponseData->size()) + " bytes)");
          _transport->sendAsync(sid, sharedResponseData->data(), sharedResponseData->size(),
                                [this, sid, shouldCloseConnection,
                                 sharedResponseData](SessionId session, const SyncResult &result)
                                {
                                  if (!result.ok)
                                  {
                                    iora::core::Logger::error("Failed to send HTTP response: " +
                                                              result.errorMessage);
                                    // Close connection on send failure
                                    std::lock_guard<std::mutex> lock(_mutex);
                                    if (_transport && !_shutdown)
                                    {
                                      _transport->close(session);
                                    }
                                  }
                                  else
                                  {
                                    iora::core::Logger::debug("WebhookServer - HTTP response "
                                                              "sent successfully for session " +
                                                              std::to_string(session));
                                    // Close connection if requested
                                    if (shouldCloseConnection)
                                    {
                                      std::lock_guard<std::mutex> lock(_mutex);
                                      if (_transport && !_shutdown)
                                      {
                                        _transport->close(session);
                                      }
                                    }
                                  }
                                });
        }
        else
        {
          iora::core::Logger::debug("WebhookServer::processHttpRequest() - Skipping response send "
                                    "(shutdown=" +
                                    std::to_string(_shutdown) +
                                    ", transport=" + std::to_string(_transport != nullptr) +
                                    ") for session " + std::to_string(sid));
        }
      }
      iora::core::Logger::debug("WebhookServer::processHttpRequest() - "
                                "Completed successfully for session " +
                                std::to_string(sid));
    }
    catch (const std::exception &ex)
    {
      iora::core::Logger::error("Error processing HTTP request: " + std::string(ex.what()));

      // Check if transport is still available before sending error response
      {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_transport && !_shutdown)
        {
          iora::core::Logger::debug("WebhookServer::processHttpRequest() - "
                                    "Sending error response for session " +
                                    std::to_string(sid));

          // Send error response
          HttpResponse errorRes(500, "Internal Server Error");
          errorRes.setHeader("Content-Type", "text/plain");
          errorRes.body = "Internal Server Error";
          errorRes.setHeader("Content-Length", std::to_string(errorRes.body.size()));

          auto errorResponseData = std::make_shared<std::string>(errorRes.toWireFormat());
          _transport->sendAsync(
            sid, errorResponseData->data(), errorResponseData->size(),
            [this, sid, errorResponseData](SessionId session, const SyncResult &result)
            {
              // Close connection after error response is sent
              std::lock_guard<std::mutex> lock(_mutex);
              if (_transport && !_shutdown)
              {
                _transport->close(session);
              }
            });
        }
        else
        {
          iora::core::Logger::debug("WebhookServer::processHttpRequest() - Skipping error response "
                                    "send (shutdown=" +
                                    std::to_string(_shutdown) + ") for session " +
                                    std::to_string(sid));
        }
      }
    }

    iora::core::Logger::debug("WebhookServer::processHttpRequest() - Exiting for session " +
                              std::to_string(sid));
  }

  /// \brief Find the end of a chunked request body
  std::size_t findChunkedRequestEnd(const std::string &data, std::size_t bodyStart) const
  {
    std::size_t pos = bodyStart;

    while (pos < data.length())
    {
      // Find chunk size line
      auto chunkSizeLine = data.find("\r\n", pos);
      if (chunkSizeLine == std::string::npos)
      {
        return std::string::npos; // Need more data
      }

      // Parse chunk size (hex)
      std::string chunkSizeStr = data.substr(pos, chunkSizeLine - pos);
      std::size_t chunkSize;
      try
      {
        chunkSize = std::stoul(chunkSizeStr, nullptr, 16);
      }
      catch (...)
      {
        iora::core::Logger::error("WebhookServer: Invalid chunk size in chunked encoding");
        return std::string::npos;
      }

      pos = chunkSizeLine + 2; // Skip \r\n

      if (chunkSize == 0)
      {
        // Final chunk, look for final \r\n
        auto finalCRLF = data.find("\r\n", pos);
        if (finalCRLF == std::string::npos)
        {
          return std::string::npos; // Need more data
        }
        return finalCRLF + 2;
      }

      // Skip chunk data + trailing \r\n
      pos += chunkSize + 2;
      if (pos > data.length())
      {
        return std::string::npos; // Need more data
      }
    }

    return std::string::npos;
  }

  /// \brief Get allowed methods for a path (for 405 responses)
  std::string getAllowedMethods(const std::string &path) const
  {
    std::vector<std::string> methods;

    for (const auto &[method, pathHandlers] : _handlers)
    {
      if (pathHandlers.find(path) != pathHandlers.end())
      {
        switch (method)
        {
        case HttpMethod::GET:
          methods.push_back("GET");
          break;
        case HttpMethod::POST:
          methods.push_back("POST");
          break;
        case HttpMethod::DELETE:
          methods.push_back("DELETE");
          break;
        case HttpMethod::PUT:
          methods.push_back("PUT");
          break;
        case HttpMethod::HEAD:
          methods.push_back("HEAD");
          break;
        case HttpMethod::OPTIONS:
          methods.push_back("OPTIONS");
          break;
        case HttpMethod::PATCH:
          methods.push_back("PATCH");
          break;
        case HttpMethod::CONNECT:
          methods.push_back("CONNECT");
          break;
        case HttpMethod::TRACE:
          methods.push_back("TRACE");
          break;
        }
      }
    }

    std::string result;
    for (std::size_t i = 0; i < methods.size(); ++i)
    {
      if (i > 0)
        result += ", ";
      result += methods[i];
    }

    return result;
  }

  /// \brief Get status text for HTTP status code
  static std::string getStatusText(int code)
  {
    switch (code)
    {
    case 200:
      return "OK";
    case 201:
      return "Created";
    case 204:
      return "No Content";
    case 400:
      return "Bad Request";
    case 401:
      return "Unauthorized";
    case 403:
      return "Forbidden";
    case 404:
      return "Not Found";
    case 405:
      return "Method Not Allowed";
    case 413:
      return "Payload Too Large";
    case 500:
      return "Internal Server Error";
    case 501:
      return "Not Implemented";
    case 502:
      return "Bad Gateway";
    case 503:
      return "Service Unavailable";
    default:
      return "Unknown";
    }
  }

  /// \brief Send an error response with specified status code and message
  void sendErrorResponse(SessionId sid, int statusCode, const std::string &statusText,
                         const std::string &body = "")
  {
    try
    {
      HttpResponse errorRes(statusCode, statusText);
      std::string responseBody = body.empty() ? statusText : body;
      errorRes.setHeader("Content-Type", "text/plain");
      errorRes.body = responseBody;
      errorRes.setHeader("Content-Length", std::to_string(responseBody.size()));
      errorRes.setHeader("Connection", "close");
      errorRes.setHeader("Server", "Iora WebhookServer");

      auto errorResponseData = std::make_shared<std::string>(errorRes.toWireFormat());

      std::lock_guard<std::mutex> lock(_mutex);
      if (_transport && !_shutdown)
      {
        iora::core::Logger::info("WebhookServer: Sending " + std::to_string(statusCode) + " " +
                                 statusText + " response (session " + std::to_string(sid) + ", " +
                                 std::to_string(errorResponseData->size()) + " bytes)");
        _transport->sendAsync(
          sid, errorResponseData->data(), errorResponseData->size(),
          [this, sid, errorResponseData](SessionId session, const SyncResult &result)
          {
            // Close connection after error response is sent
            if (result.ok)
            {
              iora::core::Logger::debug("WebhookServer: Error response "
                                        "sent successfully to session " +
                                        std::to_string(session));
            }
            else
            {
              iora::core::Logger::error("WebhookServer: Failed to send "
                                        "error response to session " +
                                        std::to_string(session) + ": " + result.errorMessage);
            }

            // Always close the connection after sending error response
            _transport->close(session);

            // Clean up session info
            std::lock_guard<std::mutex> sessionLock(_sessionMutex);
            _sessionInfo.erase(session);
          });
      }
      else
      {
        iora::core::Logger::warning("WebhookServer: Cannot send error response to session " +
                                    std::to_string(sid) +
                                    " - transport unavailable or shutting down");
      }
    }
    catch (const std::exception &e)
    {
      iora::core::Logger::error("WebhookServer: Exception while sending "
                                "error response to session " +
                                std::to_string(sid) + ": " + e.what());
      // Force close the connection if error response fails
      std::lock_guard<std::mutex> lock(_mutex);
      if (_transport)
      {
        _transport->close(sid);
      }
    }
  }

  mutable std::mutex _mutex;
  mutable std::mutex _sessionMutex;

  std::string _bindAddress;
  int _port;
  std::optional<TlsConfig> _tlsConfig;
  std::unique_ptr<UnifiedSharedTransport> _transport;
  ListenerId _listenerId{0};
  std::atomic<bool> _shutdown;
  JsonConfig _jsonConfig;

  // Thread pool for processing requests
  core::ThreadPool _threadPool;

  // Session information tracking
  struct SessionInfo
  {
    std::string buffer;
    std::string peerAddress;
    std::uint16_t peerPort = 0;
    bool connectionKeepAlive = true;
    std::string httpVersion = "1.1"; // Default to HTTP/1.1

    // Buffer management constants
    static constexpr std::size_t MAX_BUFFER_SIZE = 1024 * 1024;    // 1MB max per session
    static constexpr std::size_t MAX_HEADER_SIZE = 64 * 1024;      // 64KB max headers
    static constexpr std::size_t MAX_BODY_SIZE = 10 * 1024 * 1024; // 10MB max body
  };

  // Session tracking for incomplete requests and peer info
  std::unordered_map<SessionId, SessionInfo> _sessionInfo;

  // Handler storage: method -> path -> handler
  std::unordered_map<HttpMethod, std::unordered_map<std::string, Handler>> _handlers;
};

} // namespace network
} // namespace iora