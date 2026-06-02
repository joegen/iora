// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once
#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include "iora/core/logger.hpp"
#include "iora/core/thread_pool.hpp"
#include "iora/network/transport_impl.hpp"
#include "iora/parsers/http_message.hpp"

namespace iora
{
namespace network
{

// Forward declaration for the SSE response-suppression friend grant (RD-17).
// SseStream + the upgradeToSse free function are defined in sse_stream.hpp
// (sse_and_channels.json, a later tier); this declaration lets HttpServer
// grant them access to its protected SSE primitives without a public leak.
class SseStream;

/// \brief Lightweight, testable HTTP server base class for handling REST
/// endpoints.
class HttpServer
{
public:
  /// \brief Configuration constants
  static constexpr std::size_t MAX_PENDING_REQUESTS = 1000;              // Maximum queued requests

  /// \brief Explicitly delete copy/move constructors and assignment operators
  HttpServer(const HttpServer &) = delete;
  HttpServer &operator=(const HttpServer &) = delete;
  HttpServer(HttpServer &&) = delete;
  HttpServer &operator=(HttpServer &&) = delete;

  /// \brief TLS configuration for the server
  struct TlsConfig
  {
    std::string certFile;
    std::string keyFile;
    std::string caFile;
    bool requireClientCert = false;
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

    /// \brief Trailing-wildcard suffix captured by a WILDCARD route match
    /// (e.g. pattern "/static/*" + request "/static/css/app.css" -> "css/app.css").
    /// Empty for EXACT/NAMED matches, for an empty-suffix wildcard match, and
    /// for non-matching requests. Path-traversal hardening is the consumer's
    /// responsibility (a wildcard suffix may begin with '/').
    std::string pathRest;

    /// \brief SessionId of the connection this request arrived on. Default-
    /// initialized to the invalid sentinel (0; transport session ids start at
    /// 1) and populated by the dispatcher on every path, so streaming handlers
    /// (e.g. the SSE upgrade) can recover their own session.
    SessionId sid{};

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

    /// \brief When set true by a handler, the dispatcher sends NOTHING for this
    /// request (no terminal response, no keep-alive/close decision) — used by the
    /// SSE upgrade, which writes its own preamble directly to the socket and takes
    /// over the session. Default false, so existing handlers are unchanged. A
    /// handler that throws clears this flag so a terminal 500 is still sent.
    bool _suppressSend = false;

    void set_content(const std::string &content, const std::string &contentType)
    {
      body = content;
      headers["Content-Type"] = contentType;
      headers["Content-Length"] = std::to_string(content.size());
    }

    void set_header(const std::string &key, const std::string &value) { headers[key] = value; }
  };

  using Handler = std::function<void(const Request &, Response &)>;

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
  ///       res.status = 503;
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

  /// \brief Constructs an HttpServer with the default bind address and port.
  HttpServer(const std::string& bindAddress = "0.0.0.0", int port = DEFAULT_PORT)
      : _bindAddress(bindAddress), _port(port), _shutdown(false),
        _threadPool(2, 8, std::chrono::seconds(30))
  {
  }

  virtual ~HttpServer()
  {
    iora::core::Logger::debug("HttpServer::~HttpServer() - Destructor called");
    try
    {
      stop();
    }
    catch (const std::exception &e)
    {
      // Log the error but don't throw from destructor
      iora::core::Logger::error("HttpServer destructor error: " + std::string(e.what()));
    }
    catch (...)
    {
      // Handle any other exceptions
      iora::core::Logger::error("HttpServer destructor unknown error");
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

  /// \brief Sets the per-connection idle timeout applied at the next start()
  /// (default 600s). The engine GC reaps a session idle longer than this; a long-
  /// lived SSE stream stays alive only while its heartbeat keeps writing (M-3).
  /// Lower values are used by tests to exercise idle reaping in bounded time.
  void setIdleTimeout(std::chrono::seconds timeout)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _idleTimeout = timeout;
  }

  /// \brief Sets the transport GC sweep interval applied at the next start()
  /// (default 5s) — how often idle/stalled sessions are checked.
  void setGcInterval(std::chrono::seconds interval)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _gcInterval = interval;
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
    iora::core::Logger::info("HttpServer: TLS configuration validated successfully");
  }

  /// \brief Registers a GET handler for the given path pattern.
  /// The path may be exact ("/users"), contain named segments ("/users/:id"),
  /// or end in a trailing wildcard ("/static/*"). A malformed pattern throws
  /// std::invalid_argument at registration time.
  void onGet(const std::string &path, Handler handler)
  {
    registerHandler(HttpMethod::GET, path, std::move(handler));
  }

  /// \brief Registers a POST handler for the given path pattern.
  void onPost(const std::string &path, Handler handler)
  {
    registerHandler(HttpMethod::POST, path, std::move(handler));
  }

  /// \brief Registers a PUT handler for the given path pattern.
  void onPut(const std::string &path, Handler handler)
  {
    registerHandler(HttpMethod::PUT, path, std::move(handler));
  }

  /// \brief Registers a PATCH handler for the given path pattern.
  void onPatch(const std::string &path, Handler handler)
  {
    registerHandler(HttpMethod::PATCH, path, std::move(handler));
  }

  /// \brief Registers a DELETE handler for the given path pattern.
  void onDelete(const std::string &path, Handler handler)
  {
    registerHandler(HttpMethod::DELETE, path, std::move(handler));
  }

  /// \brief Registers a fallback handler invoked when no route matches the
  /// request path under any method (404 customization). Replaces the built-in
  /// hard-coded 404 when set. The default handler runs under the same narrowed-
  /// lock discipline and safety net as a matched route.
  void setDefaultHandler(Handler handler)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _defaultHandler = std::move(handler);
  }

  /// \brief Starts the server. Throws on error.
  void start()
  {
    std::lock_guard<std::mutex> lock(_mutex);
    try
    {
      _shutdown = false;

      // Configure transport
      TransportConfig config;
      config.protocol = Protocol::TCP;
      config.idleTimeout = _idleTimeout;
      config.gcInterval = _gcInterval;
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

      _transport = std::make_unique<Transport>(config);

      // Set up callbacks before starting

      // Accept callback - new connection accepted
      _transport->onAccept(
        [this](SessionId sid, const TransportAddress &peerAddr)
        {
          // Initialize session state
          {
            std::lock_guard<std::mutex> lock(_sessionMutex);
            SessionInfo &info = _sessionInfo[sid];
            info.buffer = "";
            info.peerAddress = peerAddr.host;
            info.peerPort = peerAddr.port;

            // Log the accepted connection
            iora::core::Logger::info("HttpServer: Accepted HTTP connection from " +
                                     info.peerAddress + ":" + std::to_string(info.peerPort) +
                                     " (session " + std::to_string(sid) + ")");
          }
        });

      // Global data callback — dispatched per session
      _transport->onData(
        [this](SessionId session, iora::core::BufferView data,
               std::chrono::steady_clock::time_point)
        {
          handleIncomingData(session, data.data(), data.size());
        });

      // Close callback - connection closed
      _transport->onClose(
        [this](SessionId sid, const TransportErrorInfo &)
        {
          std::lock_guard<std::mutex> lock(_sessionMutex);
          auto it = _sessionInfo.find(sid);
          if (it != _sessionInfo.end())
          {
            iora::core::Logger::info(
              "HttpServer: HTTP connection closed from " + it->second.peerAddress + ":" +
              std::to_string(it->second.peerPort) + " (session " + std::to_string(sid) + ")");
            _sessionInfo.erase(it);
            _upgradedSessions.erase(sid);
          }
          else
          {
            _upgradedSessions.erase(sid);
            iora::core::Logger::debug("HttpServer: Connection closed (session " +
                                      std::to_string(sid) + ")");
          }
        });

      // Error callback
      _transport->onError(
        [this](TransportError, const std::string &message)
        { iora::core::Logger::error("HttpServer transport error: " + message); });

      // Start transport
      if (_transport->start().isErr())
      {
        throw std::runtime_error("Failed to start transport");
      }

      // Add listener
      TlsMode tlsMode = _tlsConfig.has_value() ? TlsMode::Server : TlsMode::None;
      auto listenResult = _transport->addListener(_bindAddress, static_cast<std::uint16_t>(_port), tlsMode);
      if (listenResult.isErr())
      {
        throw std::runtime_error("Failed to add listener: " + listenResult.error().message);
      }
      _listenerId = listenResult.value();

      iora::core::Logger::info("HttpServer started on " + _bindAddress + ":" + std::to_string(_port));
    }
    catch (const std::exception &ex)
    {
      iora::core::Logger::error(std::string("HttpServer start error: ") + ex.what());
      throw;
    }
  }

  /// \brief Stops the server gracefully.
  void stop()
  {
    iora::core::Logger::debug("HttpServer::stop() - Starting graceful shutdown");

    // Set shutdown flag atomically to stop new request processing
    _shutdown.store(true);

    // Give a brief moment for in-flight requests to see the shutdown flag
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // SR-22: _mutex MUST NOT be held across the drain loop. An in-flight worker
    // re-acquires _mutex (for sendRaw/closeSession/sendRawForSse and the
    // deferred send-block close); holding _mutex across the drain wait would
    // deadlock it until the timeout (and drop its close). So: take _mutex
    // briefly to stop the transport, release it across the drain wait, then
    // re-acquire it solely for the reset.

    // Phase 1 (brief lock): stop the transport so it accepts no new connections.
    iora::core::Logger::debug("HttpServer::stop() - Stopping transport to "
                              "prevent new connections");
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (_transport)
      {
        _transport->stop();
        iora::core::Logger::debug("HttpServer::stop() - Transport stopped gracefully");
      }
    }

    // Clear session information (standalone _sessionMutex scope, no _mutex held).
    {
      std::lock_guard<std::mutex> sessionLock(_sessionMutex);
      _sessionInfo.clear();
      iora::core::Logger::debug("HttpServer::stop() - Cleared session information");
    }

    // Wait for thread pool tasks to complete with a reasonable timeout, holding
    // NO _mutex so in-flight handlers can acquire it, complete, and drain.
    // Handlers should use getShutdownChecker() to detect shutdown and exit
    // gracefully.
    auto startTime = std::chrono::steady_clock::now();
    const auto maxWaitTime = std::chrono::seconds(2); // Reasonable timeout for production

    iora::core::Logger::debug("HttpServer::stop() - Waiting for handlers to complete (max 2s)");

    while (_threadPool.getPendingTaskCount() > 0 || _threadPool.getActiveThreadCount() > 0)
    {
      auto elapsed = std::chrono::steady_clock::now() - startTime;
      if (elapsed > maxWaitTime)
      {
        auto pendingTasks = _threadPool.getPendingTaskCount();
        auto activeTasks = _threadPool.getActiveThreadCount();
        iora::core::Logger::warning(
          std::string("HttpServer::stop() - Timeout waiting for handlers. ") +
          "Forcing shutdown with " + std::to_string(pendingTasks) + " pending and " +
          std::to_string(activeTasks) + " active tasks. " +
          "Handlers should use getShutdownChecker() to detect shutdown.");
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    iora::core::Logger::debug("HttpServer::stop() - Handler wait completed");

    // Phase 2 (re-acquire): reset the transport. Workers deref _transport only
    // under _mutex with the _transport && !_shutdown guard, so a straggler
    // either completed its guarded access before this reset or sees nullptr
    // after it.
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (_transport)
      {
        iora::core::Logger::debug("HttpServer::stop() - Resetting transport");
        _transport.reset();
        iora::core::Logger::debug("HttpServer::stop() - Transport reset complete");
      }
    }

    iora::core::Logger::debug("HttpServer::stop() - Graceful shutdown complete");
  }

protected:
  // ── Upgrade support for WebSocket and other protocol upgrades ──────────

  /// \brief Mark a session as upgraded (e.g., to WebSocket).
  /// Future data for this session will be routed to onUpgradedData().
  void markSessionUpgraded(SessionId sid)
  {
    std::lock_guard<std::mutex> lock(_sessionMutex);
    _upgradedSessions.insert(sid);
  }

  /// \brief Called when data arrives on an upgraded session.
  /// Override in WebSocketServer to feed into frame parser.
  virtual void onUpgradedData(SessionId sid, const std::uint8_t* data,
                              std::size_t len)
  {
    (void)sid; (void)data; (void)len;
  }

  /// \brief Send raw bytes to a session (for WebSocket frame sending).
  void sendRaw(SessionId sid, const std::uint8_t* data, std::size_t len)
  {
    auto sharedData = std::make_shared<std::string>(
      reinterpret_cast<const char*>(data), len);
    std::lock_guard<std::mutex> lock(_mutex);
    if (_transport && !_shutdown)
    {
      _transport->sendAsync(sid, sharedData->data(), sharedData->size(),
        [sharedData](SessionId, const SendResult&) {});
    }
  }

  /// \brief Close a session's TCP connection. Virtual so the SSE test double can
  /// record explicit-close (RD-19) calls without a live transport.
  virtual void closeSession(SessionId sid)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    if (_transport && !_shutdown)
    {
      _transport->close(sid);
    }
  }

  /// \brief Write raw bytes to a session for an upgraded/SSE stream. Takes
  /// _mutex briefly itself (like sendRaw) — SAFE because, under the narrowed
  /// dispatch lock, the calling handler holds no HttpServer lock. The bytes are
  /// enqueued via the engine per-session write queue and delivered by the I/O
  /// thread. Returns true iff the transport is up and the send command was
  /// ENQUEUED onto the engine command queue — NOT a delivery acknowledgement, and
  /// NOT a per-session liveness check (an enqueue to an already-closed session
  /// still returns true; the I/O thread drops it later). It therefore returns
  /// false only when the transport is down/shutting down. This is the SSE
  /// primitive's SECONDARY write-failure signal (the PRIMARY disconnect signal is
  /// the Transport::observe callback) — SseStream::writeEvent flips its advisory
  /// _open to false when this returns false. The completion lambda
  /// fires SYNCHRONOUSLY on the caller's thread; it keeps the buffer alive and
  /// records delivery into a stack local — it MUST NOT re-acquire _mutex.
  /// Virtual so the SSE test double can capture bytes / simulate failure without
  /// a live transport. Reached by upgradeToSse / SseStream via the friend grant.
  virtual bool sendRawForSse(SessionId sid, const std::uint8_t *data, std::size_t len)
  {
    auto sharedData =
      std::make_shared<std::string>(reinterpret_cast<const char *>(data), len);
    std::lock_guard<std::mutex> lock(_mutex);
    if (_transport && !_shutdown)
    {
      bool delivered = false;
      _transport->sendAsync(sid, sharedData->data(), sharedData->size(),
                            [sharedData, &delivered](SessionId, const SendResult &r)
                            { delivered = r.isOk(); });
      return delivered;
    }
    return false;
  }

  /// \brief Subclass seam mirroring onUpgradeRequest: return true to suppress
  /// the dispatcher's terminal response (the handler has taken over the
  /// session). The in-handler equivalent is Response::_suppressSend. Invoked
  /// post-dispatch with NO _mutex held, so an override may safely call
  /// sendRawForSse / markSessionUpgraded / closeSession.
  virtual bool onResponseSuppressed(SessionId sid, const Request &req, Response &res)
  {
    (void)sid;
    (void)req;
    (void)res;
    return false;
  }

  /// \brief Handle incoming data from a session
  void handleIncomingData(SessionId sid, const std::uint8_t *data, std::size_t len)
  {
    // Check if this session has been upgraded (e.g., to WebSocket).
    // Route directly to onUpgradedData, bypassing HTTP parsing.
    // Check-then-release: do NOT call virtual onUpgradedData under lock
    // (it may access _sessionInfo or _upgradedSessions → deadlock).
    {
      bool isUpgraded = false;
      {
        std::lock_guard<std::mutex> lock(_sessionMutex);
        isUpgraded = _upgradedSessions.count(sid) > 0;
      }
      if (isUpgraded)
      {
        onUpgradedData(sid, data, len);
        return;
      }
    }

    std::string dataStr(reinterpret_cast<const char *>(data), len);

    // Append to session buffer with size limits
    bool bufferLimitExceeded = false;
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
        iora::core::Logger::error("HttpServer: Buffer size limit exceeded for session " +
                                  std::to_string(sid) + " - closing connection");
        // Capture-then-close: closeSession takes _mutex, and the documented lock
        // order is _mutex -> _sessionMutex, so it MUST NOT be called while
        // _sessionMutex is held. Defer the close to after this scope. On this
        // limit path the incoming data is intentionally NOT appended to the
        // buffer (the connection is about to be closed).
        bufferLimitExceeded = true;
      }
      else
      {
        it->second.buffer += dataStr;
        dataStr = it->second.buffer; // Work with complete buffer
      }
    }
    if (bufferLimitExceeded)
    {
      // closeSession guards '_transport && !_shutdown' under _mutex (no unguarded
      // raw _transport deref vs stop()'s reset), with _sessionMutex NOT held.
      closeSession(sid);
      return;
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
        iora::core::Logger::error("HttpServer: Header size limit exceeded for session " +
                                  std::to_string(sid) + " - closing connection");
        // No lock held here; closeSession guards '_transport && !_shutdown' under
        // _mutex (was an unguarded raw _transport->close — UAF risk vs stop()).
        closeSession(sid);
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
                iora::core::Logger::error("HttpServer: Body size limit exceeded for session " +
                                          std::to_string(sid) + " - closing connection");
                // No lock held; guarded close (was unguarded raw _transport->close).
                closeSession(sid);
                return;
              }
            }
            catch (...)
            {
              iora::core::Logger::error("HttpServer: Invalid "
                                        "content-length header for session " +
                                        std::to_string(sid) + " - closing connection");
              // No lock held; guarded close (was unguarded raw _transport->close).
              closeSession(sid);
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
          "HttpServer: Rejecting request due to thread pool overload "
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
          "HttpServer: High load detected (queue utilization: " +
          std::to_string(static_cast<int>(_threadPool.getQueueUtilization())) + "%, " +
          "active threads: " + std::to_string(_threadPool.getActiveThreadCount()) + "/" +
          std::to_string(_threadPool.getTotalThreadCount()) + ")");
      }
    }
  }

  /// \brief Process a complete HTTP request
  void processHttpRequest(SessionId sid, const std::string &requestData)
  {
    iora::core::Logger::debug("HttpServer::processHttpRequest() - "
                              "Processing request for session " +
                              std::to_string(sid));

    // Check if we're shutting down - with atomic read to avoid lock
    if (_shutdown.load())
    {
      iora::core::Logger::debug("HttpServer::processHttpRequest() - "
                                "Aborting due to shutdown for session " +
                                std::to_string(sid));

      // Send 503 Service Unavailable during shutdown
      HttpResponse shutdownRes(503, "Service Unavailable");
      shutdownRes.setHeader("Content-Type", "text/plain");
      shutdownRes.body = "Server Shutting Down";
      shutdownRes.setHeader("Content-Length", std::to_string(shutdownRes.body.size()));
      shutdownRes.setHeader("Connection", "close");

      auto shutdownResponseData = std::make_shared<std::string>(shutdownRes.toWireFormat());
      // SR-7: sendAsync fires its completion synchronously on this thread while
      // _mutex is held, so the completion lambda MUST NOT re-acquire _mutex.
      // Enqueue under _mutex, then close after the lock_guard releases.
      bool shutdownSendOk = false;
      {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_transport)
        {
          _transport->sendAsync(sid, shutdownResponseData->data(), shutdownResponseData->size(),
                                [shutdownResponseData](SessionId, const SendResult &) {});
          shutdownSendOk = true;
        }
      }
      if (shutdownSendOk)
      {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_transport)
        {
          _transport->close(sid);
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
      // Populate the session id once, here, before any dispatch path — so every
      // path (matched, 405, auto-OPTIONS, OPTIONS *, default-handler, and the
      // upgrade check) carries the real sid, never the invalid sentinel (RD-22).
      req.sid = sid;
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
      case HttpMethod::PUT:
        methodStr = "PUT";
        break;
      case HttpMethod::PATCH:
        methodStr = "PATCH";
        break;
      case HttpMethod::DELETE:
        methodStr = "DELETE";
        break;
      default:
        methodStr = "UNKNOWN";
        break;
      }

      iora::core::Logger::info("HttpServer: " + methodStr + " " + req.path + " from " +
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

      // Check for Upgrade header before normal route dispatch
      {
        for (const auto &[hdrKey, hdrVal] : req.headers)
        {
          std::string lowerKey = hdrKey;
          std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
          if (lowerKey == "upgrade")
          {
            Response upgradeRes;
            if (onUpgradeRequest(sid, req, upgradeRes))
            {
              // Build HTTP response for the upgrade
              HttpResponse httpUpgradeRes;
              httpUpgradeRes.statusCode = upgradeRes.status;
              httpUpgradeRes.statusText = getStatusText(upgradeRes.status);
              httpUpgradeRes.headers = upgradeRes.headers;
              httpUpgradeRes.body = upgradeRes.body;

              httpUpgradeRes.setHeader("Server", "Iora/1.0");

              std::string responseData = httpUpgradeRes.toWireFormat();
              auto sharedResponseData = std::make_shared<std::string>(std::move(responseData));

              {
                std::lock_guard<std::mutex> lock(_mutex);
                if (_transport && !_shutdown)
                {
                  _transport->sendAsync(sid, sharedResponseData->data(), sharedResponseData->size(),
                                        [sharedResponseData](SessionId session, const SendResult &result)
                                        {
                                          // Response sent; connection remains open for upgraded protocol
                                        });
                }
              }
              // Buffer-drain: feed any remaining bytes from session buffer
              // to the upgraded protocol handler (e.g., WebSocket frame parser).
              // The client may have sent WebSocket frames in the same TCP segment.
              {
                std::string remaining;
                {
                  std::lock_guard<std::mutex> lock(_sessionMutex);
                  auto it = _sessionInfo.find(sid);
                  if (it != _sessionInfo.end() && !it->second.buffer.empty())
                  {
                    remaining = std::move(it->second.buffer);
                    it->second.buffer.clear();
                  }
                }
                if (!remaining.empty())
                {
                  onUpgradedData(sid,
                    reinterpret_cast<const std::uint8_t*>(remaining.data()),
                    remaining.size());
                }
              }
              return; // Skip normal route dispatch
            }
            break;
          }
        }
      }

      // Tokenize the query-stripped path once; the SAME split rules are used to
      // compile patterns, so request and pattern tokens align (SR-19).
      const std::vector<std::string> reqToks = splitPath(req.path);

      // ── ONE under-lock pass: match, classify, copy out, unlock (RD-9/SR-3) ──
      const DispatchDecision decision = classifyRequest(req.method, req.path, reqToks);

      // Apply captured named-segment params (path wins over a same-named query
      // param, since this runs AFTER the query parse) and the wildcard suffix
      // onto the worker-local Request before invocation.
      for (const auto &kv : decision.paramAdds)
      {
        req.params[kv.first] = kv.second;
      }
      req.pathRest = decision.pathRest;

      // Create response (default 404; overwritten by the category below).
      Response res;
      res.status = 404;
      res.set_content("Not Found", "text/plain");

      // ── Post-lock dispatch: exhaustive switch, NO server lock held ──
      bool ranHandler = false; // true iff a user handler was invoked (MATCHED / NO_ROUTE)
      switch (decision.cat)
      {
      case DispatchDecision::Cat::MATCHED:
        res.status = 200;
        invokeWithSafetyNet(decision.handler, req, res);
        ranHandler = true;
        break;
      case DispatchDecision::Cat::MATCHED_AS_HEAD:
        // Run the GET handler; force a bodyless HEAD response by ignoring any
        // suppression a non-SSE handler set (SR-4). The actual body strip (and
        // the Content-Length reconciliation for a bodyless status) is applied
        // uniformly to EVERY HEAD response below (RFC 9110 §9.3.2 / SR-18).
        res.status = 200;
        invokeWithSafetyNet(decision.handler, req, res);
        if (res._suppressSend)
        {
          iora::core::Logger::warning(
            "HttpServer: handler set _suppressSend during a HEAD dispatch; "
            "ignoring and sending a bodyless HEAD response");
          res._suppressSend = false;
        }
        break;
      case DispatchDecision::Cat::AUTO_OPTIONS:
        // Answered directly by routing: 204 No Content, empty body, omit
        // Content-Length AND the inherited Content-Type, Allow from the routing
        // data (SR-21).
        res.status = 204;
        res.body.clear();
        res.headers.erase("Content-Length");
        res.headers.erase("Content-Type");
        res.headers["Allow"] = decision.allow;
        break;
      case DispatchDecision::Cat::OPTIONS_STAR:
        // Server-wide OPTIONS * — 200 + Content-Length: 0, no Allow, no inherited
        // Content-Type (SR-1).
        res.status = 200;
        res.body.clear();
        res.headers.erase("Allow");
        res.headers.erase("Content-Type");
        res.headers["Content-Length"] = "0";
        break;
      case DispatchDecision::Cat::METHOD_NOT_ALLOWED:
        // Terminal 405; set body via set_content so Content-Length is correct
        // (SR-5 framing). No handler runs and no suppression check.
        res.status = 405;
        res.set_content("Method Not Allowed", "text/plain");
        res.headers["Allow"] = decision.allow;
        break;
      case DispatchDecision::Cat::NO_ROUTE:
        if (decision.hasHandler)
        {
          res.status = 200;
          invokeWithSafetyNet(decision.handler, req, res);
          ranHandler = true;
        }
        else
        {
          res.status = 404;
          res.set_content("Not Found", "text/plain");
        }
        break;
      }

      // Post-dispatch suppression check (MATCHED / NO_ROUTE-with-handler only, on
      // normal return). When the handler took over the session (e.g. SSE), send
      // NOTHING: skip the entire keep-alive/close decision and build/send block
      // below. A handler that threw had its suppression cleared by the safety
      // net, so a terminal 500 is still sent.
      if (ranHandler && (res._suppressSend || onResponseSuppressed(req.sid, req, res)))
      {
        iora::core::Logger::debug(
          "HttpServer::processHttpRequest() - response suppressed for session " +
          std::to_string(sid) + " (handler took over the connection)");
        return;
      }

      // RFC 9110 §9.3.2: a HEAD response MUST carry no body on the wire, on
      // EVERY terminal path (MATCHED_AS_HEAD, 405, NO_ROUTE/404/default). The
      // body is computed then dropped; Content-Length (reflecting the body a GET
      // would return) is preserved for a 2xx/4xx representation. For a bodyless
      // status (304/204) drop any contradictory body Content-Length (SR-18).
      if (req.method == HttpMethod::HEAD)
      {
        res.body.clear();
        if (res.status == 204 || res.status == 304)
        {
          res.headers.erase("Content-Length");
        }
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

      // Check if transport is still available before sending. SR-7: sendAsync
      // fires its completion synchronously on this thread while _mutex is held,
      // so the completion lambda only RECORDS the close intent (capture-only);
      // the actual _transport->close happens after the lock_guard releases.
      bool sendFailed = false;
      bool sendSucceeded = false;
      {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_transport && !_shutdown)
        {
          iora::core::Logger::info(
            "HttpServer: Sending " + std::to_string(res.status) + " response to " +
            req.remote_addr + ":" + std::to_string(req.remote_port) + " (session " +
            std::to_string(sid) + ", " + std::to_string(sharedResponseData->size()) + " bytes)");
          _transport->sendAsync(sid, sharedResponseData->data(), sharedResponseData->size(),
                                [&sendFailed, &sendSucceeded,
                                 sharedResponseData](SessionId session, const SendResult &result)
                                {
                                  if (!result.isOk())
                                  {
                                    iora::core::Logger::error("Failed to send HTTP response: " +
                                                              result.error().message);
                                    sendFailed = true;
                                  }
                                  else
                                  {
                                    iora::core::Logger::debug("HttpServer - HTTP response "
                                                              "sent successfully for session " +
                                                              std::to_string(session));
                                    sendSucceeded = true;
                                  }
                                });
        }
        else
        {
          iora::core::Logger::debug("HttpServer::processHttpRequest() - Skipping response send "
                                    "(shutdown=" +
                                    std::to_string(_shutdown) +
                                    ", transport=" + std::to_string(_transport != nullptr) +
                                    ") for session " + std::to_string(sid));
        }
      }
      // Close the connection (on send failure, or when the response requested
      // close) AFTER releasing _mutex, re-acquiring it unnested and re-checking
      // the guard.
      if (sendFailed || (sendSucceeded && shouldCloseConnection))
      {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_transport && !_shutdown)
        {
          _transport->close(sid);
        }
      }
      iora::core::Logger::debug("HttpServer::processHttpRequest() - "
                                "Completed successfully for session " +
                                std::to_string(sid));
    }
    catch (const std::exception &ex)
    {
      iora::core::Logger::error("Error processing HTTP request: " + std::string(ex.what()));

      // RFC 9110: a request-parse failure maps to a specific status — 400 Bad
      // Request for a malformed method token, 501 Not Implemented for a
      // well-formed but unsupported method (HttpRequestError carries it). Any
      // other exception is a genuine 500.
      int errStatus = 500;
      if (auto *reqErr = dynamic_cast<const HttpRequestError *>(&ex))
      {
        errStatus = reqErr->status();
      }

      // Check if transport is still available before sending error response.
      // SR-7: enqueue under _mutex with a capture-only completion lambda, then
      // perform the (unconditional) post-error close after the lock_guard
      // releases — never re-acquire _mutex inside the synchronous completion.
      bool errorSendOk = false;
      {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_transport && !_shutdown)
        {
          iora::core::Logger::debug("HttpServer::processHttpRequest() - "
                                    "Sending error response for session " +
                                    std::to_string(sid));

          // Send error response
          HttpResponse errorRes(errStatus, getStatusText(errStatus));
          errorRes.setHeader("Content-Type", "text/plain");
          errorRes.setHeader("Connection", "close"); // this path closes the socket after sending
          errorRes.body = getStatusText(errStatus);
          errorRes.setHeader("Content-Length", std::to_string(errorRes.body.size()));

          auto errorResponseData = std::make_shared<std::string>(errorRes.toWireFormat());
          _transport->sendAsync(
            sid, errorResponseData->data(), errorResponseData->size(),
            [errorResponseData](SessionId, const SendResult &) {});
          errorSendOk = true;
        }
        else
        {
          iora::core::Logger::debug("HttpServer::processHttpRequest() - Skipping error response "
                                    "send (shutdown=" +
                                    std::to_string(_shutdown) + ") for session " +
                                    std::to_string(sid));
        }
      }
      if (errorSendOk)
      {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_transport && !_shutdown)
        {
          _transport->close(sid);
        }
      }
    }

    iora::core::Logger::debug("HttpServer::processHttpRequest() - Exiting for session " +
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
        iora::core::Logger::error("HttpServer: Invalid chunk size in chunked encoding");
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

  /// \brief Compute the Allow header value for a request path by evaluating the
  /// SAME precedence-ordered pattern match used for dispatch. For each method
  /// with any matching pattern, the method is listed; HEAD is synthesized
  /// whenever GET matches (auto-HEAD-for-GET), and OPTIONS is self-listed
  /// whenever the path matches under any method (auto-OPTIONS). Methods are
  /// emitted in a fixed canonical order so the result is deterministic. Returns
  /// "" if the path matches no route. MUST be called with _mutex held.
  std::string getAllowedMethods(const std::vector<std::string> &reqToks) const
  {
    bool hasGet = false, hasPost = false, hasPut = false, hasPatch = false, hasDelete = false;
    bool anyMatch = false;
    for (const auto &methodVec : _handlers)
    {
      for (const auto &entry : methodVec.second)
      {
        std::unordered_map<std::string, std::string> caps;
        std::string rest;
        if (patternMatches(entry.first, reqToks, caps, rest))
        {
          anyMatch = true;
          switch (methodVec.first)
          {
          case HttpMethod::GET:
            hasGet = true;
            break;
          case HttpMethod::POST:
            hasPost = true;
            break;
          case HttpMethod::PUT:
            hasPut = true;
            break;
          case HttpMethod::PATCH:
            hasPatch = true;
            break;
          case HttpMethod::DELETE:
            hasDelete = true;
            break;
          default:
            break; // HEAD/OPTIONS/CONNECT/TRACE are not registrable in v1
          }
          break; // one matching pattern per method suffices
        }
      }
    }

    if (!anyMatch)
    {
      return "";
    }

    // Canonical order (SR-2): GET, HEAD, POST, PUT, PATCH, DELETE, [CONNECT,
    // TRACE,] OPTIONS — HEAD synthesized from GET, OPTIONS self-listed. CONNECT
    // and TRACE are intentionally never emitted in v1 (the public registration
    // API exposes no onConnect/onTrace, so they can never match a pattern).
    std::vector<std::string> methods;
    if (hasGet)
    {
      methods.push_back("GET");
      methods.push_back("HEAD");
    }
    if (hasPost)
    {
      methods.push_back("POST");
    }
    if (hasPut)
    {
      methods.push_back("PUT");
    }
    if (hasPatch)
    {
      methods.push_back("PATCH");
    }
    if (hasDelete)
    {
      methods.push_back("DELETE");
    }
    methods.push_back("OPTIONS");

    std::string result;
    for (std::size_t i = 0; i < methods.size(); ++i)
    {
      if (i > 0)
      {
        result += ", ";
      }
      result += methods[i];
    }
    return result;
  }

  /// \brief Get status text for HTTP status code
  static std::string getStatusText(int code)
  {
    switch (code)
    {
    case 101:
      return "Switching Protocols";
    case 200:
      return "OK";
    case 201:
      return "Created";
    case 204:
      return "No Content";
    case 304:
      return "Not Modified";
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
    case 426:
      return "Upgrade Required";
    case 500:
      return "Internal Server Error";
    case 501:
      return "Not Implemented";
    case 502:
      return "Bad Gateway";
    case 503:
      return "Service Unavailable";
    case 505:
      return "HTTP Version Not Supported";
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
      errorRes.setHeader("Server", "Iora HttpServer");

      auto errorResponseData = std::make_shared<std::string>(errorRes.toWireFormat());

      std::lock_guard<std::mutex> lock(_mutex);
      if (_transport && !_shutdown)
      {
        iora::core::Logger::info("HttpServer: Sending " + std::to_string(statusCode) + " " +
                                 statusText + " response (session " + std::to_string(sid) + ", " +
                                 std::to_string(errorResponseData->size()) + " bytes)");
        _transport->sendAsync(
          sid, errorResponseData->data(), errorResponseData->size(),
          [this, sid, errorResponseData](SessionId session, const SendResult &result)
          {
            // Close connection after error response is sent
            if (result.isOk())
            {
              iora::core::Logger::debug("HttpServer: Error response "
                                        "sent successfully to session " +
                                        std::to_string(session));
            }
            else
            {
              iora::core::Logger::error("HttpServer: Failed to send "
                                        "error response to session " +
                                        std::to_string(session) + ": " + result.error().message);
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
        iora::core::Logger::warning("HttpServer: Cannot send error response to session " +
                                    std::to_string(sid) +
                                    " - transport unavailable or shutting down");
      }
    }
    catch (const std::exception &e)
    {
      iora::core::Logger::error("HttpServer: Exception while sending "
                                "error response to session " +
                                std::to_string(sid) + ": " + e.what());
      // Force close the connection if error response fails. The '!_shutdown'
      // half of the canonical guard is intentionally omitted here: this is a
      // best-effort force-close on the error path that must run even during
      // shutdown. Safe — it holds _mutex and null-checks _transport, and
      // stop()'s _transport.reset() is also under _mutex, so no dangling deref.
      std::lock_guard<std::mutex> lock(_mutex);
      if (_transport)
      {
        _transport->close(sid);
      }
    }
  }

  /// \brief Called when an HTTP Upgrade header is detected.
  /// Subclasses can override to handle protocol upgrades (e.g., WebSocket).
  /// \param sid The session ID for the connection
  /// \param req The parsed HTTP request containing the Upgrade header
  /// \param res The response to populate if the upgrade is accepted
  /// \return true if the upgrade was handled (response will be sent, normal routing skipped),
  ///         false to continue with normal route dispatch
  virtual bool onUpgradeRequest(SessionId sid, const Request& req, Response& res) { return false; }

  // RD-17: grant the SSE machinery access to the protected SSE primitives
  // (sendRawForSse / markSessionUpgraded / closeSession) and the private
  // _transport — the same reach WebSocketServer gets by subclassing, with no
  // public transport() leak. SseStream + the upgradeToSse free function are
  // defined in sse_stream.hpp (a later tier). The upgradeToSse friend is an
  // UNQUALIFIED in-class declaration (name injected into iora::network) so it
  // does not require a namespace-scope forward declaration naming the nested
  // Request/Response types (which are incomplete before this class is defined).
  friend class SseStream;
  friend void upgradeToSse(HttpServer &server, const Request &req, Response &res,
                           std::function<void(std::shared_ptr<SseStream>)> onConnect);

private:
  // ── Pattern routing (exact / named-segment / trailing-wildcard) ──────────

  /// \brief Kind of a compiled route pattern.
  enum class PatternKind
  {
    EXACT,
    NAMED,
    WILDCARD
  };

  /// \brief One path segment of a compiled pattern. A NAMED segment carries the
  /// capture name; a literal segment carries its exact text.
  struct Segment
  {
    bool isParam = false;
    std::string literalOrName;
  };

  /// \brief Parsed-once representation of a registered path pattern.
  struct CompiledPattern
  {
    PatternKind kind = PatternKind::EXACT;
    std::string raw; // original registered path (diagnostics + grouping)
    std::vector<Segment> segments;
    bool hasTrailingWildcard = false; // '*' is a terminal marker, not a segment
  };

  /// \brief Split a path on '/', preserving the leading, trailing, AND interior
  /// empty tokens. So "/users" -> {"","users"} (2) and "/users/" ->
  /// {"","users",""} (3) differ by segment count — the load-bearing invariant
  /// for exact-match backward-compat and the wildcard empty-suffix rule. Used
  /// for BOTH patterns and request paths so they tokenize identically.
  static std::vector<std::string> splitPath(const std::string &path)
  {
    std::vector<std::string> out;
    std::string cur;
    for (char c : path)
    {
      if (c == '/')
      {
        out.push_back(cur);
        cur.clear();
      }
      else
      {
        cur.push_back(c);
      }
    }
    out.push_back(cur);
    return out;
  }

  /// \brief True if `s` matches the named-segment identifier grammar
  /// [A-Za-z_][A-Za-z0-9_]*.
  static bool isValidIdentifier(const std::string &s)
  {
    if (s.empty())
    {
      return false;
    }
    const unsigned char first = static_cast<unsigned char>(s[0]);
    if (!(std::isalpha(first) || s[0] == '_'))
    {
      return false;
    }
    for (std::size_t i = 1; i < s.size(); ++i)
    {
      const unsigned char c = static_cast<unsigned char>(s[i]);
      if (!(std::isalnum(c) || s[i] == '_'))
      {
        return false;
      }
    }
    return true;
  }

  /// \brief Compile a registered path to a CompiledPattern. Throws
  /// std::invalid_argument on a malformed pattern (non-terminal '*', '*' mixed
  /// into a segment, or a ':' first-char not followed by a valid identifier).
  static CompiledPattern compilePattern(const std::string &path)
  {
    CompiledPattern cp;
    cp.raw = path;
    const std::vector<std::string> toks = splitPath(path);
    bool hasNamed = false;
    for (std::size_t i = 0; i < toks.size(); ++i)
    {
      const std::string &tok = toks[i];
      if (tok == "*")
      {
        if (i != toks.size() - 1)
        {
          throw std::invalid_argument(
            "HttpServer: '*' wildcard must be the final path segment: " + path);
        }
        cp.hasTrailingWildcard = true;
        continue; // the '*' is a terminal marker, not stored as a segment
      }
      if (tok.find('*') != std::string::npos)
      {
        throw std::invalid_argument(
          "HttpServer: '*' may only appear as a standalone final segment: " + path);
      }
      if (!tok.empty() && tok[0] == ':')
      {
        const std::string name = tok.substr(1);
        if (!isValidIdentifier(name))
        {
          throw std::invalid_argument(
            "HttpServer: malformed named segment '" + tok + "' in path: " + path);
        }
        Segment seg;
        seg.isParam = true;
        seg.literalOrName = name;
        cp.segments.push_back(std::move(seg));
        hasNamed = true;
      }
      else
      {
        Segment seg;
        seg.isParam = false;
        seg.literalOrName = tok;
        cp.segments.push_back(std::move(seg));
      }
    }
    if (cp.hasTrailingWildcard)
    {
      cp.kind = PatternKind::WILDCARD;
    }
    else if (hasNamed)
    {
      cp.kind = PatternKind::NAMED;
    }
    else
    {
      cp.kind = PatternKind::EXACT;
    }
    return cp;
  }

  /// \brief Test whether a compiled pattern matches the request token list. On a
  /// NAMED match, named captures are written into `paramAdds`; on a WILDCARD
  /// match the unmatched suffix (possibly empty, joined with '/') is written
  /// into `pathRest`. Captures are stored RAW (not percent-decoded).
  static bool patternMatches(const CompiledPattern &cp,
                             const std::vector<std::string> &reqToks,
                             std::unordered_map<std::string, std::string> &paramAdds,
                             std::string &pathRest)
  {
    if (cp.kind == PatternKind::WILDCARD)
    {
      // Request must have AT LEAST as many leading segments as the literal
      // prefix ('>=', not '>'), so the suffix may be empty (M-R1).
      if (reqToks.size() < cp.segments.size())
      {
        return false;
      }
      for (std::size_t i = 0; i < cp.segments.size(); ++i)
      {
        if (reqToks[i] != cp.segments[i].literalOrName)
        {
          return false;
        }
      }
      std::string rest;
      for (std::size_t i = cp.segments.size(); i < reqToks.size(); ++i)
      {
        if (i > cp.segments.size())
        {
          rest.push_back('/');
        }
        rest += reqToks[i];
      }
      pathRest = std::move(rest);
      return true;
    }

    // EXACT or NAMED: segment counts must match exactly.
    if (reqToks.size() != cp.segments.size())
    {
      return false;
    }
    std::unordered_map<std::string, std::string> caps;
    for (std::size_t i = 0; i < cp.segments.size(); ++i)
    {
      const Segment &seg = cp.segments[i];
      if (seg.isParam)
      {
        caps[seg.literalOrName] = reqToks[i];
      }
      else if (reqToks[i] != seg.literalOrName)
      {
        return false;
      }
    }
    for (auto &kv : caps)
    {
      paramAdds[kv.first] = kv.second;
    }
    return true;
  }

  /// \brief Precedence-ordered match within one method's pattern vector: EXACT,
  /// then NAMED (registration order), then WILDCARD (registration order), STOP
  /// at first hit. Returns the matching entry index or -1. Must be called with
  /// _mutex held (reads the vector).
  static int matchInMethodVector(
    const std::vector<std::pair<CompiledPattern, Handler>> &vec,
    const std::vector<std::string> &reqToks,
    std::unordered_map<std::string, std::string> &paramAdds, std::string &pathRest)
  {
    for (PatternKind kind : {PatternKind::EXACT, PatternKind::NAMED, PatternKind::WILDCARD})
    {
      for (std::size_t i = 0; i < vec.size(); ++i)
      {
        if (vec[i].first.kind != kind)
        {
          continue;
        }
        std::unordered_map<std::string, std::string> caps;
        std::string rest;
        if (patternMatches(vec[i].first, reqToks, caps, rest))
        {
          paramAdds = std::move(caps);
          pathRest = std::move(rest);
          return static_cast<int>(i);
        }
      }
    }
    return -1;
  }

  /// \brief Compile and register a route. Throws std::invalid_argument on a
  /// malformed pattern (before any table mutation). EXACT re-registration
  /// overwrites the prior handler for the same path; NAMED/WILDCARD append
  /// (registration order is the within-precedence tie-break).
  void registerHandler(HttpMethod method, const std::string &path, Handler handler)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    CompiledPattern cp = compilePattern(path);
    auto &vec = _handlers[method];
    if (cp.kind == PatternKind::EXACT)
    {
      for (auto &entry : vec)
      {
        if (entry.first.kind == PatternKind::EXACT && entry.first.raw == path)
        {
          entry.second = std::move(handler);
          return;
        }
      }
    }
    vec.emplace_back(std::move(cp), std::move(handler));
  }

  /// \brief True if the path matches a pattern under any method. Must be called
  /// with _mutex held.
  bool pathMatchesAnyMethod(const std::vector<std::string> &reqToks) const
  {
    for (const auto &methodVec : _handlers)
    {
      for (const auto &entry : methodVec.second)
      {
        std::unordered_map<std::string, std::string> caps;
        std::string rest;
        if (patternMatches(entry.first, reqToks, caps, rest))
        {
          return true;
        }
      }
    }
    return false;
  }

  /// \brief True if the path matches a pattern under some method OTHER than
  /// `exclude` (used for the 405 decision). Must be called with _mutex held.
  bool pathExistsExcludingMethod(const std::vector<std::string> &reqToks,
                                 HttpMethod exclude) const
  {
    for (const auto &methodVec : _handlers)
    {
      if (methodVec.first == exclude)
      {
        continue;
      }
      for (const auto &entry : methodVec.second)
      {
        std::unordered_map<std::string, std::string> caps;
        std::string rest;
        if (patternMatches(entry.first, reqToks, caps, rest))
        {
          return true;
        }
      }
    }
    return false;
  }

  /// \brief Outcome of the single under-lock dispatch pass: the category, a
  /// copied-out Handler (for MATCHED / MATCHED_AS_HEAD / NO_ROUTE-with-default),
  /// the Allow string (for METHOD_NOT_ALLOWED / AUTO_OPTIONS), and the captured
  /// named-segment params + wildcard suffix. Everything is copied by value, so
  /// it stays valid after _mutex is released.
  struct DispatchDecision
  {
    enum class Cat
    {
      MATCHED,
      MATCHED_AS_HEAD,
      AUTO_OPTIONS,
      OPTIONS_STAR,
      METHOD_NOT_ALLOWED,
      NO_ROUTE
    } cat = Cat::NO_ROUTE;
    Handler handler;
    bool hasHandler = false;
    std::string allow;
    std::unordered_map<std::string, std::string> paramAdds;
    std::string pathRest;
  };

  /// \brief The ONE under-lock pass (RD-9): acquire _mutex once, run the SR-3
  /// decision ladder (OPTIONS * -> auto-OPTIONS -> HEAD-as-GET -> matched ->
  /// 405 -> NO_ROUTE), copy out the resolved handler / Allow / captures, and
  /// release. No relock; getAllowedMethods and the default-handler copy all
  /// happen under this single acquisition. The returned handler is invoked by
  /// the caller with NO lock held.
  DispatchDecision classifyRequest(HttpMethod method, const std::string &reqPath,
                                   const std::vector<std::string> &reqToks)
  {
    DispatchDecision d;
    std::lock_guard<std::mutex> lock(_mutex);

    // (1) Asterisk-form OPTIONS * — server-wide capability probe (SR-1).
    if (method == HttpMethod::OPTIONS && reqPath == "*")
    {
      d.cat = DispatchDecision::Cat::OPTIONS_STAR;
      return d;
    }

    // (2) OPTIONS — answered directly if the path matches under any method.
    if (method == HttpMethod::OPTIONS)
    {
      if (pathMatchesAnyMethod(reqToks))
      {
        d.cat = DispatchDecision::Cat::AUTO_OPTIONS;
        d.allow = getAllowedMethods(reqToks);
        return d;
      }
      // Fall through to NO_ROUTE within this same acquisition (copy out the
      // default handler so an OPTIONS on a no-route path can invoke it).
      d.cat = DispatchDecision::Cat::NO_ROUTE;
      if (_defaultHandler)
      {
        d.handler = _defaultHandler;
        d.hasHandler = true;
      }
      return d;
    }

    // (3) HEAD — fall back to the GET route (auto-HEAD-for-GET, RD-23). The
    // HEAD pattern vector is always empty in v1; check GET. If no GET matches,
    // continue to the generic classification below (so HEAD on a POST-only path
    // becomes a 405, not a wrong 404).
    if (method == HttpMethod::HEAD)
    {
      auto git = _handlers.find(HttpMethod::GET);
      if (git != _handlers.end())
      {
        const int idx =
          matchInMethodVector(git->second, reqToks, d.paramAdds, d.pathRest);
        if (idx >= 0)
        {
          d.cat = DispatchDecision::Cat::MATCHED_AS_HEAD;
          d.handler = git->second[static_cast<std::size_t>(idx)].second;
          d.hasHandler = true;
          return d;
        }
      }
    }

    // (4) Match the request method.
    auto mit = _handlers.find(method);
    if (mit != _handlers.end())
    {
      const int idx = matchInMethodVector(mit->second, reqToks, d.paramAdds, d.pathRest);
      if (idx >= 0)
      {
        d.cat = DispatchDecision::Cat::MATCHED;
        d.handler = mit->second[static_cast<std::size_t>(idx)].second;
        d.hasHandler = true;
        return d;
      }
    }

    // (5) 405 — the path matches under some OTHER method (Allow under the same
    // lock).
    if (pathExistsExcludingMethod(reqToks, method))
    {
      d.cat = DispatchDecision::Cat::METHOD_NOT_ALLOWED;
      d.allow = getAllowedMethods(reqToks);
      return d;
    }

    // (6) NO_ROUTE — copy out the default handler if set (same acquisition).
    d.cat = DispatchDecision::Cat::NO_ROUTE;
    if (_defaultHandler)
    {
      d.handler = _defaultHandler;
      d.hasHandler = true;
    }
    return d;
  }

  /// \brief Invoke a copied-out handler with the request-level safety net, run
  /// with NO _mutex held. Both catch clauses set a production-safe 500 and CLEAR
  /// any suppression (so a partially-suppressing handler that then threw still
  /// gets a terminal 500). The verbose dev-mode body is produced by the
  /// Application layer; HttpServer's net is the last line of defense.
  void invokeWithSafetyNet(const Handler &handler, Request &req, Response &res)
  {
    try
    {
      handler(req, res);
    }
    catch (const std::exception &e)
    {
      iora::core::Logger::error("HttpServer: Handler exception for " + req.path + ": " +
                                e.what());
      res.status = 500;
      res.set_content("Internal Server Error", "text/plain");
      res._suppressSend = false;
    }
    catch (...)
    {
      iora::core::Logger::error("HttpServer: Handler unknown exception for " + req.path);
      res.status = 500;
      res.set_content("Internal Server Error", "text/plain");
      res._suppressSend = false;
    }
  }

  // Lock ordering (HttpServer): when more than one of these is co-held, the
  // total order is _wsMutex/_sseMutex (subclass/friend, OUTER, e.g.
  // WebSocketServer holds _wsMutex across sendRaw which takes _mutex) ->
  // _mutex (HttpServer, inner) -> _sessionMutex (inner). _mutex and
  // _sessionMutex ARE co-held in sendErrorResponse (the synchronous sendAsync
  // completion lambda does _transport->close then _sessionInfo.erase under
  // _sessionMutex while _mutex is still held — order _mutex -> _sessionMutex);
  // there is NO reverse _sessionMutex -> _mutex edge. No HttpServer code holding _mutex may call a
  // subclass/friend (SseStream/upgradeToSse) method that re-takes a higher
  // lock — the dispatch narrowing copies the handler out and invokes it with
  // no lock held. (_sseMutex is PROSPECTIVE — owned by SseStream/sse_stream.hpp,
  // not declared here; the friend grant only makes that edge possible.)
  mutable std::mutex _mutex;
  mutable std::mutex _sessionMutex;

  std::string _bindAddress;
  int _port;
  std::chrono::seconds _idleTimeout{600}; // applied at start(); SSE M-3 survival
  std::chrono::seconds _gcInterval{5};    // applied at start(); engine GC sweep
  std::optional<TlsConfig> _tlsConfig;
  std::unique_ptr<Transport> _transport;
  ListenerId _listenerId{0};
  std::atomic<bool> _shutdown;

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

  // Handler storage: method -> ordered vector of (compiled pattern, handler).
  // Ordered per method so registration order is preserved for the within-
  // precedence tie-break (an unordered_map cannot provide that).
  std::unordered_map<HttpMethod, std::vector<std::pair<CompiledPattern, Handler>>> _handlers;

  // Fallback handler for unmatched routes (NO_ROUTE), set via setDefaultHandler.
  Handler _defaultHandler;

  // Sessions that have been upgraded (e.g., to WebSocket).
  // Data for these sessions is routed to onUpgradedData() instead of HTTP parsing.
  std::unordered_set<SessionId> _upgradedSessions;
};

} // namespace network
} // namespace iora
