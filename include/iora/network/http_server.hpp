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
#include "iora/core/string_utils.hpp"
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
    /// \brief Request parameters: query-string pairs plus captured named route
    /// segments (a path segment wins over a same-named query key). A query name with
    /// no '=' ("?flag") is stored with an empty value. SINGLE-VALUED: duplicate keys
    /// are last-wins ("?a=1&a=2" -> a=="2"); the map cannot represent a multi-valued
    /// parameter (a deliberate limitation of this API shape). Names and values are
    /// stored RAW — they are NOT percent-decoded and '+' is NOT converted to space;
    /// a handler needing decoded values calls parsers::formDecode / parsers::urlDecode.
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

    /// \brief Set-Cookie values emitted as SEPARATE field-lines (RFC 6265 §3). The
    /// single-valued `headers` map holds at most one Set-Cookie, so setting two
    /// cookies via headers silently drops one; use add_cookie for each cookie when a
    /// response needs more than one (e.g. a session cookie plus a CSRF cookie).
    std::vector<std::string> cookies;

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

    /// \brief Move overload: lets a caller hand off an already-materialized body
    /// (e.g. serveStatic's std::string(view) temporary) without an extra copy.
    /// Content-Length is read from content.size() BEFORE the move (a moved-from
    /// string has unspecified length). Existing lvalue callers bind to the
    /// const& overload above; an rvalue temporary binds here automatically.
    void set_content(std::string &&content, const std::string &contentType)
    {
      headers["Content-Type"] = contentType;
      headers["Content-Length"] = std::to_string(content.size());
      body = std::move(content);
    }

    void set_header(const std::string &key, const std::string &value) { headers[key] = value; }

    /// \brief Append one Set-Cookie field-line (the full cookie-string, e.g.
    /// "sid=abc; Path=/; HttpOnly"). Each call adds one Set-Cookie header to the
    /// response, so a handler can set several distinct cookies in one response
    /// (RFC 6265 §3). The value is emitted verbatim (attributes are the caller's
    /// responsibility); a value containing CR/LF/NUL is dropped by the response-
    /// splitting guard rather than emitted.
    void add_cookie(const std::string &setCookieValue) { cookies.push_back(setCookieValue); }
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

      _transport = Transport::tcp(config); // HTTP server is TCP (S-3: shared_ptr factory)

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
        [this](SessionId sid, const TransportErrorInfo &reason)
        {
          bool wasUpgraded = false;
          bool hadInfo = false;
          std::string peerAddress;
          int peerPort = 0;
          {
            std::lock_guard<std::mutex> lock(_sessionMutex);
            wasUpgraded = _upgradedSessions.erase(sid) > 0;
            auto it = _sessionInfo.find(sid);
            if (it != _sessionInfo.end())
            {
              // Move (noexcept) the fields needed for logging out, then erase, so
              // the state teardown completes BEFORE any allocating log-string work
              // and never depends on it.
              hadInfo = true;
              peerAddress = std::move(it->second.peerAddress);
              peerPort = it->second.peerPort;
              _sessionInfo.erase(it);
            }
          }
          // 2026-09-11-23 (CORE): logging runs on the transport I/O thread; a
          // std::bad_alloc from the string concatenation must NOT escape into the
          // engine's top-level catch, which treats it as fatal and tears down the
          // whole loop (dropping every session). Swallow it — the teardown above
          // already completed under the lock (WS-C1).
          try
          {
            if (hadInfo)
            {
              iora::core::Logger::info("HttpServer: HTTP connection closed from " + peerAddress +
                                       ":" + std::to_string(peerPort) + " (session " +
                                       std::to_string(sid) + ")");
            }
            else
            {
              iora::core::Logger::debug("HttpServer: Connection closed (session " +
                                        std::to_string(sid) + ")");
            }
          }
          catch (...)
          {
          }
          // Transport-close teardown hook for upgraded (e.g. WebSocket) sessions,
          // invoked with NO internal lock held so the override may take its own
          // mutex and fire a user callback (copy-then-invoke). On an abrupt
          // RST/FIN with no protocol-level CLOSE — the common real-world case —
          // this is the ONLY event that reaches the protocol server, so it must
          // prune per-session state and fire its close callback here (2026-09-11-16).
          if (wasUpgraded)
          {
            onUpgradedClose(sid, reason);
          }
          // 2026-09-11-23 (CORE) test-only rendezvous seam: fires AFTER the
          // _sessionMutex teardown (and onUpgradedClose) for EVERY transport
          // close, including the a0 case where wasUpgraded is false and
          // onUpgradedClose is not called. No-op in production; a race test
          // overrides it to signal that the I/O thread has finished processing
          // the close, so the worker can be released deterministically.
          onTransportSessionClosed(sid);
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

  /// \brief Stops the server gracefully. Idempotent; safe to call repeatedly.
  /// A subclass that adds state touched by the transport I/O thread or a pool
  /// worker MUST call quiesceTransport() first in its own destructor (see that
  /// method) — this public stop() only delegates there.
  void stop() { quiesceTransport(); }

protected:
  /// \brief Quiesce the transport I/O thread and drain the worker pool, then
  /// release the transport. Idempotent and safe to call from a SUBCLASS
  /// DESTRUCTOR before its own members are torn down: a live I/O-thread
  /// onUpgradedData/onUpgradedClose or an in-flight pool worker must not touch
  /// subclass state after it is destroyed (WS-TS1/WS-TS2). Because ~HttpServer
  /// runs only AFTER the subclass's members are already gone, every HttpServer
  /// subclass adding such state must call this first in its own dtor; the base
  /// dtor's stop() call then early-outs here (nothing left to quiesce).
  void quiesceTransport()
  {
    // Idempotent early-out keyed on _transport alone: _transport is non-null ONLY
    // between a successful start() and the Phase-2 reset below, so a null transport
    // means there is nothing to quiesce — a never-started server, or a second call
    // (a subclass dtor already quiesced, then ~HttpServer's stop()). Snapshot the
    // transport under _mutex so Phase 1 can stop() it WITHOUT holding _mutex.
    std::shared_ptr<Transport> transport;
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (!_transport)
      {
        return;
      }
      transport = _transport;
    }

    iora::core::Logger::debug("HttpServer::quiesceTransport() - Starting graceful shutdown");

    // Set shutdown flag atomically to stop new request processing
    _shutdown.store(true);

    // Give a brief moment for in-flight requests to see the shutdown flag
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // SR-22 / LT-12: _mutex MUST NOT be held across transport->stop() NOR across
    // the drain loop. stop() joins the I/O thread, and the shutdown-drain fires
    // onClose on that thread — which for upgraded sessions reaches onUpgradedClose
    // and takes _wsMutex. A peer thread in sendText/sendClose holds _wsMutex and is
    // waiting on _mutex (the documented _wsMutex -> _mutex send order), so holding
    // _mutex across stop() would close a 3-way deadlock cycle. Likewise an in-flight
    // worker re-acquires _mutex (sendRaw/closeSession/sendRawForSse). So: snapshot
    // the transport under _mutex (above), stop() the copy with NO lock held (the
    // shared_ptr keeps it alive), drain with no lock, then re-acquire _mutex solely
    // for the reset.

    // Phase 1 (no lock held): stop the transport so it accepts no new connections.
    iora::core::Logger::debug("HttpServer::quiesceTransport() - Stopping transport to "
                              "prevent new connections");
    transport->stop();
    iora::core::Logger::debug("HttpServer::quiesceTransport() - Transport stopped gracefully");

    // Clear session information (standalone _sessionMutex scope, no _mutex held).
    {
      std::lock_guard<std::mutex> sessionLock(_sessionMutex);
      _sessionInfo.clear();
      iora::core::Logger::debug("HttpServer::quiesceTransport() - Cleared session information");
    }

    // Wait for thread pool tasks to complete with a reasonable timeout, holding
    // NO _mutex so in-flight handlers can acquire it, complete, and drain.
    // Handlers should use getShutdownChecker() to detect shutdown and exit
    // gracefully.
    auto startTime = std::chrono::steady_clock::now();
    const auto maxWaitTime = std::chrono::seconds(2); // Reasonable timeout for production

    iora::core::Logger::debug("HttpServer::quiesceTransport() - Waiting for handlers to complete (max 2s)");

    while (_threadPool.getPendingTaskCount() > 0 || _threadPool.getActiveThreadCount() > 0)
    {
      auto elapsed = std::chrono::steady_clock::now() - startTime;
      if (elapsed > maxWaitTime)
      {
        auto pendingTasks = _threadPool.getPendingTaskCount();
        auto activeTasks = _threadPool.getActiveThreadCount();
        iora::core::Logger::warning(
          std::string("HttpServer::quiesceTransport() - Timeout waiting for handlers. ") +
          "Forcing shutdown with " + std::to_string(pendingTasks) + " pending and " +
          std::to_string(activeTasks) + " active tasks. " +
          "Handlers should use getShutdownChecker() to detect shutdown.");
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    iora::core::Logger::debug("HttpServer::quiesceTransport() - Handler wait completed");

    // Phase 2 (re-acquire): reset the transport. Workers deref _transport only
    // under _mutex with the _transport && !_shutdown guard, so a straggler
    // either completed its guarded access before this reset or sees nullptr
    // after it.
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (_transport)
      {
        iora::core::Logger::debug("HttpServer::quiesceTransport() - Resetting transport");
        _transport.reset();
        iora::core::Logger::debug("HttpServer::quiesceTransport() - Transport reset complete");
      }
    }

    iora::core::Logger::debug("HttpServer::quiesceTransport() - Graceful shutdown complete");
  }

  /// \brief Noexcept wrapper around quiesceTransport() for subclass destructors.
  /// An HttpServer subclass with state touched by the transport I/O thread or a
  /// pool worker MUST quiesce FIRST in its own destructor (see quiesceTransport),
  /// and that call must not throw from the (noexcept) destructor — quiesceTransport
  /// allocates (logging, engine stop) and can throw. This centralizes the
  /// swallow+log so every such dtor gets the correct incantation; `who` names the
  /// destructor in the log. (~HttpServer wraps its own stop() separately.)
  void quiesceTransportNoexcept(const char *who) noexcept
  {
    try
    {
      quiesceTransport();
    }
    catch (const std::exception &e)
    {
      iora::core::Logger::error(std::string(who) + " error: " + e.what());
    }
    catch (...)
    {
      iora::core::Logger::error(std::string(who) + " unknown error");
    }
  }

  // ── Upgrade support for WebSocket and other protocol upgrades ──────────

  /// \brief Mark a session as upgraded (e.g., to WebSocket).
  /// Future data for this session will be routed to onUpgradedData().
  void markSessionUpgraded(SessionId sid)
  {
    std::lock_guard<std::mutex> lock(_sessionMutex);
    _upgradedSessions.insert(sid);
  }

  /// \brief 2026-09-11-23 (CORE P2): mark a session upgraded ONLY if the transport
  /// session is still live, in one _sessionMutex critical section. Returns false
  /// if the base per-session record (_sessionInfo) is already gone — the transport
  /// closed during the upgrade handshake window. This is authoritative because the
  /// transport onClose lambda erases _upgradedSessions AND _sessionInfo in a single
  /// _sessionMutex section, so _sessionInfo absence here means the close already
  /// ran. Relies on SessionIds being monotonic and never recycled (tcp_engine.hpp
  /// _nextSessionId is fetch_add-only), so a live _sessionInfo entry cannot be a
  /// different connection reusing sid. The plain markSessionUpgraded above is left
  /// unchanged for the SSE upgrade path (sse_stream.hpp) and the test double.
  bool markSessionUpgradedIfLive(SessionId sid)
  {
    std::lock_guard<std::mutex> lock(_sessionMutex);
    if (_sessionInfo.find(sid) == _sessionInfo.end())
    {
      return false;
    }
    _upgradedSessions.insert(sid);
    return true;
  }

  /// \brief 2026-09-11-23 (CORE P10): remove the upgraded-routing marker (used by
  /// the WebSocket abort path when an upgrade is torn down before completion).
  void unmarkSessionUpgraded(SessionId sid)
  {
    std::lock_guard<std::mutex> lock(_sessionMutex);
    _upgradedSessions.erase(sid);
  }

  /// \brief 2026-09-11-23 (CORE) test-only rendezvous seam. Invoked on the I/O
  /// thread at the end of the transport onClose handler for EVERY closed session
  /// (upgraded or not), after the _sessionMutex teardown. No-op in production.
  virtual void onTransportSessionClosed(SessionId /*sid*/) {}

  /// \brief 2026-09-11-23 (CORE) test-only: number of live upgraded-session
  /// markers (_upgradedSessions). Used by the race tests to assert no leak.
  std::size_t upgradedSessionCountForTest() const
  {
    std::lock_guard<std::mutex> lock(_sessionMutex);
    return _upgradedSessions.size();
  }

  /// \brief Called when data arrives on an upgraded session.
  /// Override in WebSocketServer to feed into frame parser.
  virtual void onUpgradedData(SessionId sid, const std::uint8_t* data,
                              std::size_t len)
  {
    (void)sid; (void)data; (void)len;
  }

  /// \brief Called on the transport I/O thread when an UPGRADED session's
  /// transport connection closes — gracefully or abruptly (TCP RST/FIN) with no
  /// protocol-level CLOSE. Override in a protocol server (e.g. WebSocketServer)
  /// to prune per-session state and fire its close callback, which the
  /// protocol-level CLOSE path may never reach on an abrupt disconnect. The
  /// transport close reason is supplied so the override can report an accurate
  /// close code (e.g. a server-initiated ShuttingDown/GCClosed vs a frameless
  /// peer loss). Invoked with NO internal HttpServer lock held (the caller has
  /// released _sessionMutex) so the override may take its own mutex and run a
  /// user callback. The base is a no-op.
  virtual void onUpgradedClose(SessionId sid, const TransportErrorInfo &reason)
  {
    (void)sid; (void)reason;
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
    bool bufferHeaderBlockSeen = false;
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
        // Capture-then-send: sendErrorResponse takes _mutex, and the documented
        // lock order is _mutex -> _sessionMutex, so it MUST NOT be called while
        // _sessionMutex is held. Defer to after this scope. The incoming data is
        // intentionally NOT appended (the connection is about to be closed).
        // Discriminate the status while we hold the buffer: if the header-block
        // terminator has already arrived, this is a body/total overflow (413);
        // otherwise the header block itself is oversized (431). The buffer cap
        // (1 MB) is smaller than the body cap (10 MB), so a 1-10 MB accumulated
        // body trips HERE before the Content-Length body check below.
        bufferLimitExceeded = true;
        // The header-block terminator may straddle the buffer/incoming-segment
        // boundary (the incoming dataStr is intentionally NOT appended on this
        // path), so check the accumulated buffer PLUS the small 3+3-byte overlap
        // with the incoming segment (the terminator is 4 bytes).
        bufferHeaderBlockSeen = it->second.buffer.find("\r\n\r\n") != std::string::npos;
        if (!bufferHeaderBlockSeen)
        {
          const std::size_t tail = std::min<std::size_t>(it->second.buffer.size(), 3);
          const std::string boundary = it->second.buffer.substr(it->second.buffer.size() - tail) +
                                       dataStr.substr(0, std::min<std::size_t>(dataStr.size(), 3));
          bufferHeaderBlockSeen = boundary.find("\r\n\r\n") != std::string::npos;
        }
      }
      else
      {
        it->second.buffer += dataStr;
        dataStr = it->second.buffer; // Work with complete buffer
      }
    }
    if (bufferLimitExceeded)
    {
      // sendErrorResponse guards '_transport && !_shutdown' under _mutex and closes
      // + cleans up the session; _sessionMutex is NOT held here. Header terminator
      // already seen -> body/total overflow -> 413; not yet -> header overflow -> 431.
      const int limitStatus = bufferHeaderBlockSeen ? 413 : 431;
      sendErrorResponse(sid, limitStatus, getStatusText(limitStatus), "", /*headersOnly=*/true);
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

      // Check header size limit -> 431 Request Header Fields Too Large (RFC 6585
      // §5). The header block (terminated at headerEnd) exceeds the cap, so this
      // is unambiguously a header overflow, not a body overflow.
      if (headerEnd > SessionInfo::MAX_HEADER_SIZE)
      {
        iora::core::Logger::error("HttpServer: Header size limit exceeded for session " +
                                  std::to_string(sid) + " - sending 431 and closing");
        // No lock held here; sendErrorResponse guards '_transport && !_shutdown'
        // under _mutex, sends headers-only, then closes + cleans up the session.
        sendErrorResponse(sid, 431, getStatusText(431), "", /*headersOnly=*/true);
        return;
      }

      std::string headerSection = dataStr.substr(0, headerEnd);
      std::size_t contentLength = 0;
      bool isChunked = false;

      // Collect the framing-relevant fields, then decide the body length once
      // below. The framing decision MUST reach the SAME verdict as the strict
      // parser (HttpRequest::fromWireFormat): if the framer picks a different
      // request boundary than the parser, the two disagree on where the request
      // ends (RFC 9112 §6.3 request smuggling). So gather every Content-Length
      // field-line and — exactly as the parser does — the LAST Transfer-Encoding
      // field-line's value (§6.1: the effective coding is the last field-line's
      // final token; an OR over all lines would frame "chunked" then "gzip" as
      // chunked while the parser rejects it).
      std::unordered_set<std::string> clValues;
      bool sawTransferEncoding = false;
      std::string lastTransferEncoding;
      bool malformedHeaderLine = false;
      std::istringstream headerStream(headerSection);
      std::string line;
      bool firstHeaderLine = true;
      while (std::getline(headerStream, line))
      {
        if (!line.empty() && line.back() == '\r')
        {
          line.pop_back();
        }
        if (firstHeaderLine)
        {
          firstHeaderLine = false; // skip the request-line
          continue;
        }

        // Reject the SAME field-line grammar the strict parser rejects, so the
        // framer never HONORS a Content-Length / Transfer-Encoding on a line the
        // parser would 400 (which would make the framer compute a body boundary
        // the parser never assigns -> request-smuggling desync, RFC 9112 §6.3):
        //  - obs-fold: a field-line beginning with SP/HTAB (§5.2), and
        //  - whitespace between the field-name and the colon (§5.1).
        if (!line.empty() && (line.front() == ' ' || line.front() == '\t'))
        {
          malformedHeaderLine = true;
          break;
        }

        auto colonPos = line.find(':');
        if (colonPos != std::string::npos)
        {
          if (colonPos > 0 && (line[colonPos - 1] == ' ' || line[colonPos - 1] == '\t'))
          {
            malformedHeaderLine = true;
            break;
          }
          std::string key = line.substr(0, colonPos);
          std::string value = line.substr(colonPos + 1);

          // Trim OWS
          key.erase(0, key.find_first_not_of(" \t"));
          key.erase(key.find_last_not_of(" \t") + 1);
          value.erase(0, value.find_first_not_of(" \t"));
          value.erase(value.find_last_not_of(" \t") + 1);

          // Match field names case-insensitively via the SAME comparator the
          // parser uses (locale-independent ASCII; no hand-rolled ::tolower).
          if (CaseInsensitiveCompare::equals(key, "Content-Length"))
          {
            clValues.insert(value);
          }
          else if (CaseInsensitiveCompare::equals(key, "Transfer-Encoding"))
          {
            sawTransferEncoding = true;
            lastTransferEncoding = value; // last field-line wins (parser semantics)
          }
        }
      }

      // Reach the parser's framing verdict. Unrecoverable framing errors
      // (RFC 9112 §6.3): a conflicting duplicate Content-Length; Content-Length
      // together with Transfer-Encoding; or a Transfer-Encoding whose final
      // coding is not chunked (§6.1). Any of these makes the request boundary
      // ambiguous, so the framer MUST NOT frame or dispatch anything further on
      // this connection: emit 400 and CLOSE, poisoning it. Framing an empty body
      // and continuing the pipelining loop would dispatch the trailing bytes as a
      // SMUGGLED request (CL.TE / dup-CL desync), because framing (this I/O
      // thread) and handler dispatch (pool) are decoupled — the next request is
      // enqueued before the parser's 400+close for this one runs.
      const bool teFinalChunked =
        sawTransferEncoding && detail::isChunkedFinalCoding(lastTransferEncoding);
      const bool ambiguousFraming = malformedHeaderLine || (clValues.size() > 1) ||
                                    (!clValues.empty() && sawTransferEncoding) ||
                                    (sawTransferEncoding && !teFinalChunked);
      if (ambiguousFraming)
      {
        iora::core::Logger::error("HttpServer: Ambiguous request framing (duplicate "
                                  "Content-Length, Content-Length+Transfer-Encoding, or "
                                  "non-final chunked coding) for session " +
                                  std::to_string(sid) + " - sending 400 and closing");
        // RFC 9110 §15.5.1. sendErrorResponse guards under _mutex, sends
        // headers-only, then closes + cleans up the session. Return WITHOUT
        // framing/dispatching any further buffered bytes on this connection.
        sendErrorResponse(sid, 400, getStatusText(400), "", /*headersOnly=*/true);
        return;
      }

      if (!clValues.empty())
      {
        // Single Content-Length: it MUST be 1*DIGIT (RFC 9112 §6.3). std::stoull
        // is lenient (leading sign/whitespace, "-1" -> ULLONG_MAX), so validate
        // the token strictly before it drives the request boundary.
        const std::string &cl = *clValues.begin();
        const bool valid =
          !cl.empty() && std::all_of(cl.begin(), cl.end(),
                                     [](char c) { return c >= '0' && c <= '9'; });
        if (!valid)
        {
          iora::core::Logger::error("HttpServer: Invalid "
                                    "content-length header for session " +
                                    std::to_string(sid) + " - sending 400 and closing");
          // An invalid Content-Length is a 400 Bad Request (RFC 9112 §6.3 /
          // RFC 9110 §15.5.1); a bare close is indistinguishable from a crash and
          // makes clients retry. Emit the 400 like the adjacent ambiguous-framing
          // path (tracker 2026-07-26-7 covers the DIFFERENT CL+TE case, not this).
          sendErrorResponse(sid, 400, getStatusText(400), "", /*headersOnly=*/true);
          return;
        }
        try
        {
          contentLength = std::stoull(cl);
        }
        catch (...)
        {
          // 1*DIGIT but numerically out of range (> 2^64) -> unframeable -> 400.
          iora::core::Logger::error("HttpServer: Out-of-range "
                                    "content-length header for session " +
                                    std::to_string(sid) + " - sending 400 and closing");
          sendErrorResponse(sid, 400, getStatusText(400), "", /*headersOnly=*/true);
          return;
        }
        if (contentLength > SessionInfo::MAX_BODY_SIZE)
        {
          iora::core::Logger::error("HttpServer: Body size limit exceeded for session " +
                                    std::to_string(sid) + " - sending 413 and closing");
          // Declared Content-Length over the body cap -> 413 Content Too Large
          // (RFC 9110 §15.5.14). No lock held; sendErrorResponse guards under
          // _mutex, sends headers-only, then closes + cleans up the session.
          sendErrorResponse(sid, 413, getStatusText(413), "", /*headersOnly=*/true);
          return;
        }
      }
      // Ambiguous CL/TE combinations already returned above; here CL and TE are
      // mutually exclusive, so chunked framing applies iff TE's final coding is
      // chunked.
      isChunked = teFinalChunked;

      std::size_t requestEndPos;

      if (isChunked)
      {
        // Handle chunked encoding. framingError distinguishes a DEFINITIVELY
        // malformed chunked body (bad chunk-size, missing chunk-data CRLF) from
        // a merely-incomplete one: the parser/decoder answers 400 for the former,
        // so the framer must too (poison the connection) rather than wait forever
        // for bytes that will never make it valid — and must never frame+dispatch
        // the trailing bytes as a smuggled request.
        bool framingError = false;
        requestEndPos = findChunkedRequestEnd(dataStr, headerEnd + 4, framingError);
        if (framingError)
        {
          iora::core::Logger::error("HttpServer: Malformed chunked request framing for session " +
                                    std::to_string(sid) + " - sending 400 and closing");
          sendErrorResponse(sid, 400, getStatusText(400), "", /*headersOnly=*/true);
          return;
        }
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

      // Determine connection persistence for this request (RFC 9112 §9.3): HTTP/1.1+
      // defaults to persistent, HTTP/1.0 (and earlier) to non-persistent; a Connection
      // header token overrides the default — "close" always wins, and "keep-alive"
      // makes an HTTP/1.0 request persistent. The Connection field is a comma-list
      // (RFC 9110 §7.6.1), so it is token-parsed, not exact-matched.
      bool connectionKeepAlive;
      {
        static const std::string kEmpty;
        auto cIt = httpReq.headers.find("Connection");
        const std::string &connValue = (cIt != httpReq.headers.end()) ? cIt->second : kEmpty;
        // major > 1 is defensive: fromWireFormat already 505s any HTTP-version with
        // major != 1 (and 400s HTTP/0.9), so only 1.0 / 1.1 reach here — but the check
        // states the RFC 9112 §9.3 rule directly rather than relying on that upstream.
        const bool isHttp11OrLater =
          httpReq.version.major > 1 ||
          (httpReq.version.major == 1 && httpReq.version.minor >= 1);
        if (connectionListHasToken(connValue, "close"))
        {
          connectionKeepAlive = false;
        }
        else if (isHttp11OrLater)
        {
          connectionKeepAlive = true;
        }
        else
        {
          connectionKeepAlive = connectionListHasToken(connValue, "keep-alive");
        }
      }

      // Populate peer address information. The per-request keep-alive decision above
      // is consumed on this same worker stack at the send path (the local is still in
      // scope); it is NOT written into shared SessionInfo, because pipelined requests
      // on one session run on different pool workers and a shared per-session field
      // would be clobbered by a concurrent sibling's decision (a logical race).
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
        // Split the query on '&' into name[=value] pairs. A pair is split on its
        // FIRST '='; a name with no '=' ("?flag") is stored with an empty value so a
        // handler can test presence of a bare flag (rather than the value being
        // dropped). Empty pairs ("?&a=1", "?a=1&", "?a=1&&b=2") are skipped.
        // NOTE: names and values are stored RAW — they are NOT percent-decoded and
        // '+' is NOT converted to space here; a handler needing decoded values calls
        // parsers::formDecode. (Consistent URI-component decoding is tracked; see the
        // Request::params doc-comment.)
        const std::string queryString = req.path.substr(queryPos + 1);
        req.path = req.path.substr(0, queryPos);
        for (const auto param : core::StringUtils::split(queryString, '&'))
        {
          if (param.empty())
          {
            continue;
          }
          const auto eqPos = param.find('=');
          if (eqPos == std::string_view::npos)
          {
            req.params[std::string(param)] = "";
          }
          else
          {
            req.params[std::string(param.substr(0, eqPos))] = std::string(param.substr(eqPos + 1));
          }
        }
      }

      // Check for Upgrade header before normal route dispatch
      {
        for (const auto &[hdrKey, hdrVal] : req.headers)
        {
          // Match case-insensitively via the shared ASCII comparator (a bare
          // ::tolower on a negative-valued char is UB; locale-independent here).
          if (CaseInsensitiveCompare::equals(hdrKey, "Upgrade"))
          {
            Response upgradeRes;
            if (onUpgradeRequest(sid, req, upgradeRes))
            {
              // 2026-09-11-23 (CORE P7): the upgrade was HANDLED — always skip
              // normal route dispatch (the `return` below) so an aborted /
              // duplicate upgrade can never fall through to an HTTP response on a
              // live WebSocket session. The upgrade override sets
              // Response::_suppressSend=true for the abort (a0 / transport-dead)
              // and duplicate verdicts, in which case the 101 handshake response
              // and the buffer-drain must both be skipped (no live session, or
              // the winning upgrade owns it).
              if (!upgradeRes._suppressSend)
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
                // Buffer-drain: feed any remaining bytes from session buffer to
                // the upgraded protocol handler (e.g., WebSocket frame parser) —
                // the client may have sent WebSocket frames in the same TCP
                // segment. Only on a SUCCESSFUL switch (101): on an upgrade
                // REJECTION (400/403/426) no protocol was switched, so draining
                // would feed pipelined bytes to onUpgradedData which drops them
                // (no _sessions entry) — leave them in the buffer for normal HTTP
                // processing instead (2026-09-11-23 web LOW).
                if (upgradeRes.status == 101)
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

      // Create the response. Each dispatch arm below sets its own status/body;
      // the only branch that wants a 404 body (NO_ROUTE without a handler) sets it
      // itself. NO 404 body is pre-populated here — pre-populating leaked a
      // "Not Found" body plus Content-Length: 9 / Content-Type onto success (201),
      // direct-body, and bodyless (204/304) responses (root_cause). The default
      // status stays 200 (matching the switch arms that run a handler); a status
      // left unset by a bug is caught by the framing normalization below.
      Response res;

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
        // Answered directly by routing: 204 No Content, Allow from the routing data
        // (SR-21). No handler runs, so `res` is empty here — the bodyless
        // normalization below erases body/CL/CT for the 204; only Allow is set.
        res.status = 204;
        res.headers["Allow"] = decision.allow;
        break;
      case DispatchDecision::Cat::OPTIONS_STAR:
        // Server-wide OPTIONS * — 200 + Content-Length: 0 (SR-1). No handler runs,
        // so `res` is empty; Content-Length: 0 is set explicitly for local clarity
        // (the normalization would synthesize it anyway from the empty body).
        res.status = 200;
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
      // Content-Length a GET would return is synthesized here — BEFORE the body is
      // dropped — for a direct-res.body handler that set none (RD-21); the body is
      // then dropped. The bodyless-status erase (a HEAD to a 204/304) is NOT done
      // here — it is left to the single normalization step below (one owner), where
      // the erase correctly wins over this synthesized Content-Length.
      if (req.method == HttpMethod::HEAD)
      {
        // Capture the GET-body length BEFORE dropping the body, whenever the handler
        // set no Content-Length. A handler-set Transfer-Encoding does NOT block this:
        // the non-bodyless normalization below strips a spurious TE and frames by
        // Content-Length, so the HEAD must still report the GET length (RFC 9110
        // §9.3.2), not fall through to Content-Length: 0.
        if (!res.body.empty() && res.headers.find("Content-Length") == res.headers.end())
        {
          res.headers["Content-Length"] = std::to_string(res.body.size());
        }
        res.body.clear();
      }

      // ── Response framing normalization (choke point, RFC 9112 §6.3 / RFC 9110
      // §8.6) ───────────────────────────────────────────────────────────────
      // Runs on EVERY terminal response, on the worker's stack-local `res`, AFTER
      // the suppression early-return above (an SSE / session-hand-off response is
      // never touched) and AFTER the HEAD body-strip, but BEFORE `httpRes.headers =
      // res.headers` below (mutating res after that copy would be lost). NO LOCK IS
      // HELD here — the classify pass released its lock and the next lock is
      // _sessionMutex below; `res` is automatic and its address never escapes, so
      // this is race-free. Do NOT move it into a locked scope or above the
      // suppression gate. The serializer (HttpResponse::toWireFormat) applies the
      // same bodyless suppression as an unbypassable backstop across all five
      // builders; this dispatcher-level step keeps the in-process Response
      // internally consistent for the res.status logging below and any post-dispatch
      // middleware that reads res. (onResponseSuppressed ran ABOVE, before this step,
      // so it observes the raw handler output, not the normalized response.)

      // RFC 9112 §4: status-code is 3DIGIT (100-599 in practice). A handler typo
      // (res.status = 20, 0, 1000) would emit a malformed status line — substitute
      // 500. RFC 9110 §15.2: an interim 1xx is a response a client blocks on
      // awaiting a final; a handler on the NORMAL dispatch path must never emit one
      // (the legitimate 101 upgrade returned earlier). Both are programming errors
      // and both rewrite to 500.
      if (res.status < 200 || res.status > 599)
      {
        const char *why = (res.status < 100 || res.status > 599) ? "an out-of-range status"
                                                                 : "an interim status";
        iora::core::Logger::error(std::string("HttpServer: handler set ") + why + " (" +
                                  std::to_string(res.status) + "); rewriting to 500");
        res.status = 500;
        res.body.clear();
        // Erase ALL four framing/representation fields (not just CL/CT): a handler
        // that set a bad status AND a Transfer-Encoding would otherwise ship a 500
        // with a stale chunked framing and an empty body, hanging the client.
        for (const char *h : iora::network::kBodyFramingHeaders)
        {
          res.headers.erase(h);
        }
      }

      if (iora::network::statusForbidsBody(res.status))
      {
        // Bodyless-by-status (1xx/204/304): drop the body and every body-framing /
        // representation header. RFC 9112 §6.3 rule 1 forbids Content-Length,
        // Transfer-Encoding and Trailer; Content-Type is meaningless / cache-
        // poisoning (RFC 9110 §15.4.5). ERASE — never zero — and it wins over any
        // Content-Length, including one a HEAD synthesized just above. Date and the
        // §15.4.5 304 must-generate set (Cache-Control/ETag/Expires/Vary/
        // Content-Location/Last-Modified) and Allow are NOT touched. (205 is
        // deliberately NOT in statusForbidsBody — see the 205 branch below.)
        res.body.clear();
        for (const char *h : iora::network::kBodyFramingHeaders)
        {
          res.headers.erase(h);
        }
      }
      else if (res.status == 205)
      {
        // 205 Reset Content: RFC 9110 §15.3.6 forbids CONTENT, but RFC 9112 §6.3
        // rule 8 makes a response lacking both CL and TE close-delimited — so a 205
        // needs Content-Length: 0 (NOT a bodyless erase). Drop any handler body and
        // pin CL:0; strip a spurious Transfer-Encoding/Trailer, and drop Content-Type
        // (it describes a representation that no longer exists once the body is gone).
        res.body.clear();
        res.headers.erase("Transfer-Encoding");
        res.headers.erase("Trailer");
        res.headers.erase("Content-Type");
        res.headers["Content-Length"] = "0";
      }
      else
      {
        // A non-bodyless response needs EXACTLY ONE framing mechanism. The server
        // never chunk-encodes a handler body (the whole body sits in res.body and is
        // written inline by toWireFormat), so a handler-set Transfer-Encoding is
        // spurious and MUST NOT coexist with Content-Length (RFC 9112 §6.1 — the
        // classic request-smuggling primitive through a proxy): strip TE/Trailer and
        // frame by Content-Length.
        if (res.headers.find("Transfer-Encoding") != res.headers.end())
        {
          iora::core::Logger::warning(
            "HttpServer: stripping a handler-set Transfer-Encoding on a " +
            std::to_string(res.status) +
            " response (the server frames by Content-Length; RFC 9112 §6.1)");
          res.headers.erase("Transfer-Encoding");
          res.headers.erase("Trailer");
        }
        auto clIt = res.headers.find("Content-Length");
        if (clIt == res.headers.end())
        {
          // No definite length yet (empty-body 200/201/202, a direct-res.body
          // handler, or a just-stripped TE). Synthesize it. A HEAD already
          // synthesized its GET-length Content-Length above (and cleared the body).
          res.headers["Content-Length"] = std::to_string(res.body.size());
        }
        else if (req.method != HttpMethod::HEAD)
        {
          // The server writes the WHOLE res.body inline (toWireFormat), so for a
          // non-HEAD response the only correct Content-Length is res.body.size(). A
          // handler-set value that disagrees would put N octets of framing over M
          // octets of body — a keep-alive desync / response-splitting primitive — so
          // it is OVERWRITTEN (the server-written body is authoritative), with a
          // warning for diagnosis. A HEAD legitimately reports the GET length over an
          // empty body and is excluded above.
          const std::string actual = std::to_string(res.body.size());
          if (clIt->second != actual)
          {
            iora::core::Logger::warning(
              "HttpServer: overwriting a handler-set Content-Length (" + clIt->second +
              ") that does not match the body size (" + actual + ") on a " +
              std::to_string(res.status) + " response (RFC 9110 §8.6)");
            clIt->second = actual;
          }
        }
      }

      // RFC 9110 §5.5 response-splitting guard: a handler must never place CR/LF/NUL
      // into a response header (e.g. a Location/HX-Redirect/Set-Cookie built from
      // unvalidated request input — `?next=%0d%0aSet-Cookie:...`). Drop any such
      // header here (toWireFormat is the unbypassable backstop, but this runs on the
      // handler-set path where the risk is real and gives observability). The log
      // never echoes the offending name/value — only the already-validated request
      // method/path — so it is not itself a log-injection sink.
      for (auto hit = res.headers.begin(); hit != res.headers.end();)
      {
        if (iora::network::headerHasInjection(hit->first) ||
            iora::network::headerHasInjection(hit->second))
        {
          iora::core::Logger::error(
            "HttpServer: dropped a response header containing CR/LF/NUL "
            "(response-splitting attempt) on " +
            toString(req.method) + " " + req.path + " (session " + std::to_string(sid) + ")");
          hit = res.headers.erase(hit);
        }
        else
        {
          ++hit;
        }
      }

      // Same response-splitting guard for the repeatable Set-Cookie lines (they
      // bypass the headers map, so they need their own CR/LF/NUL check here in
      // addition to the toWireFormat backstop). A cookie built from unvalidated
      // input is the canonical Set-Cookie injection sink.
      for (auto cit = res.cookies.begin(); cit != res.cookies.end();)
      {
        if (iora::network::headerHasInjection(*cit))
        {
          iora::core::Logger::error(
            "HttpServer: dropped a Set-Cookie containing CR/LF/NUL "
            "(response-splitting attempt) on " +
            toString(req.method) + " " + req.path + " (session " + std::to_string(sid) + ")");
          cit = res.cookies.erase(cit);
        }
        else
        {
          ++cit;
        }
      }

      // Connection behavior: use the request-local persistence decision (RFC 9112
      // §9.3) computed above on this worker stack — never a shared SessionInfo field
      // (see the note at the peer-address block: a concurrent pipelined sibling would
      // clobber it).
      const bool shouldCloseConnection = !connectionKeepAlive;
      const std::string connectionHeader = shouldCloseConnection ? "close" : "keep-alive";

      // Build HTTP response
      HttpResponse httpRes;
      httpRes.statusCode = res.status;
      httpRes.statusText = getStatusText(res.status);
      httpRes.headers = res.headers;
      httpRes.setCookies = std::move(res.cookies);
      httpRes.body = res.body;

      // Add server headers
      httpRes.setHeader("Server", "Iora/1.0");
      httpRes.setHeader("Connection", connectionHeader);

      // Send response asynchronously but ensure proper completion
      std::string responseData = httpRes.toWireFormat();

      // Create a shared string to keep the data alive during async send
      auto sharedResponseData = std::make_shared<std::string>(std::move(responseData));

      // Check if transport is still available before sending. SR-7: sendAsync
      // fires its completion synchronously on this thread while _mutex is held.
      // The completion records only the send OUTCOME through a shared_ptr captured
      // BY VALUE (not the stack bools by reference) — so there is no dangling
      // reference if a future transport ever completes the send asynchronously,
      // matching the capture-free shutdown/exception/sendErrorResponse paths
      // (task-5.4e). The actual _transport->close happens after the lock releases.
      enum class SendOutcome
      {
        Pending,
        Ok,
        Failed
      };
      auto sendOutcome = std::make_shared<std::atomic<SendOutcome>>(SendOutcome::Pending);
      {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_transport && !_shutdown)
        {
          iora::core::Logger::info(
            "HttpServer: Sending " + std::to_string(res.status) + " response to " +
            req.remote_addr + ":" + std::to_string(req.remote_port) + " (session " +
            std::to_string(sid) + ", " + std::to_string(sharedResponseData->size()) + " bytes)");
          _transport->sendAsync(sid, sharedResponseData->data(), sharedResponseData->size(),
                                [sendOutcome, sharedResponseData](SessionId session,
                                                                  const SendResult &result)
                                {
                                  if (!result.isOk())
                                  {
                                    iora::core::Logger::error("Failed to send HTTP response: " +
                                                              result.error().message);
                                    // relaxed: the atomic carries no dependent data
                                    // and completion is synchronous on this thread.
                                    sendOutcome->store(SendOutcome::Failed,
                                                       std::memory_order_relaxed);
                                  }
                                  else
                                  {
                                    iora::core::Logger::debug("HttpServer - HTTP response "
                                                              "sent successfully for session " +
                                                              std::to_string(session));
                                    sendOutcome->store(SendOutcome::Ok, std::memory_order_relaxed);
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
      const SendOutcome sendResult = sendOutcome->load(std::memory_order_relaxed);
      const bool sendFailed = (sendResult == SendOutcome::Failed);
      const bool sendSucceeded = (sendResult == SendOutcome::Ok);
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

  /// \brief Find the end of a chunked request body. Sets framingError=true when
  /// the body is DEFINITIVELY malformed (bad chunk-size, or a chunk-data run not
  /// terminated by CRLF) — the caller poisons the connection (400+close) rather
  /// than wait for more data or scan past a bad terminator. Returns npos with
  /// framingError=false only for a genuinely incomplete (still-arriving) body.
  std::size_t findChunkedRequestEnd(const std::string &data, std::size_t bodyStart,
                                    bool &framingError) const
  {
    framingError = false;
    std::size_t pos = bodyStart;

    while (pos < data.length())
    {
      // Find chunk size line
      auto chunkSizeLine = data.find("\r\n", pos);
      if (chunkSizeLine == std::string::npos)
      {
        return std::string::npos; // Need more data
      }

      // chunk-size = 1*HEXDIG [ chunk-ext ]; the size ends at the first ';'
      // (chunk-ext) or the CRLF. std::stoul silently accepts a leading sign or
      // whitespace and drives a bogus frame length, so strip any chunk-ext, trim
      // OWS, and validate 1*HEXDIG before parsing.
      std::string chunkSizeStr = data.substr(pos, chunkSizeLine - pos);
      const auto semi = chunkSizeStr.find(';');
      if (semi != std::string::npos)
      {
        chunkSizeStr = chunkSizeStr.substr(0, semi);
      }
      const auto lastNonWs = chunkSizeStr.find_last_not_of(" \t");
      chunkSizeStr.erase(lastNonWs == std::string::npos ? 0 : lastNonWs + 1);
      if (chunkSizeStr.empty() ||
          !std::all_of(chunkSizeStr.begin(), chunkSizeStr.end(),
                       [](char c)
                       {
                         const unsigned char u = static_cast<unsigned char>(c);
                         return (u >= '0' && u <= '9') || (u >= 'a' && u <= 'f') ||
                                (u >= 'A' && u <= 'F');
                       }))
      {
        iora::core::Logger::error("HttpServer: Invalid chunk size in chunked encoding");
        framingError = true;
        return std::string::npos;
      }
      std::size_t chunkSize;
      try
      {
        chunkSize = std::stoull(chunkSizeStr, nullptr, 16);
      }
      catch (...)
      {
        iora::core::Logger::error("HttpServer: Invalid chunk size in chunked encoding");
        framingError = true;
        return std::string::npos;
      }

      pos = chunkSizeLine + 2; // Skip \r\n

      if (chunkSize == 0)
      {
        // Terminating chunk: consume the trailer-section (zero or more field-lines,
        // RFC 9112 §7.1 / §7.1.2) up to the closing empty line. Stopping at the
        // FIRST CRLF after the 0-line under-reads a trailered request and desyncs
        // from decodeChunkedRequestBody (which DOES consume trailers) — both layers
        // must consume the trailer-section identically or they disagree on the
        // request boundary.
        while (true)
        {
          // Reject an obs-fold (SP/HTAB-led) trailer field-line, matching both the
          // decoder (decodeChunkedRequestBody) and the framer's own header-section
          // handling (RFC 9112 §5.2 / §7.1.2). Without this the framer would accept
          // a trailer the decoder 400s, and — because framing and dispatch are
          // decoupled — dispatch the next pipelined request before that 400 closes.
          if (pos < data.length() && (data[pos] == ' ' || data[pos] == '\t'))
          {
            framingError = true;
            return std::string::npos;
          }
          auto tcrlf = data.find("\r\n", pos);
          if (tcrlf == std::string::npos)
          {
            return std::string::npos; // Need more data (trailer not fully arrived)
          }
          const bool emptyLine = (tcrlf == pos);
          pos = tcrlf + 2;
          if (emptyLine)
          {
            return pos; // past the closing empty line
          }
        }
      }

      // Skip chunk data + trailing \r\n. Bound the chunk against the remaining
      // buffer with SUBTRACTION: `pos += chunkSize + 2` wraps size_t when
      // chunkSize has its MSB set (e.g. ffffffffffffffff), bypassing the
      // `pos > length` guard and mis-framing the request (a boundary-confusion /
      // smuggling primitive). `pos <= data.length()` holds, so `remaining` does
      // not underflow; `remaining - chunkSize` is guarded by the prior check.
      const std::size_t remaining = data.length() - pos;
      if (chunkSize > remaining || (remaining - chunkSize) < 2)
      {
        return std::string::npos; // Need more data (chunk data / CRLF not yet arrived)
      }
      // The 2 bytes after chunk-data MUST be CRLF (RFC 9112 §7.1); they are
      // present now. If they are not CRLF the framing is definitively malformed
      // (decodeChunkedRequestBody 400s the same input) — signal a framing error
      // rather than scan past a bad terminator (a framer/decoder desync).
      if (data.compare(pos + chunkSize, 2, "\r\n") != 0)
      {
        framingError = true;
        return std::string::npos;
      }
      pos += chunkSize + 2;
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

  /// \brief RFC 9110 §7.6.1: the Connection header field-value is a comma-separated
  /// list of connection-option tokens. Returns true iff \p connectionValue contains
  /// \p token as a member — each element OWS-trimmed and compared ASCII
  /// case-insensitively. This is NEVER a bare substring match: a substring test would
  /// both false-positive ("not-close" contains "close") and miss a member behind
  /// another token ("keep-alive, close"). Used to honor "keep-alive, close" /
  /// "close, foo" for the RFC 9112 §9.3 persistence decision.
  static bool connectionListHasToken(const std::string &connectionValue, const char *token)
  {
    for (const auto element : core::StringUtils::split(connectionValue, ','))
    {
      if (core::StringUtils::iequals(core::StringUtils::trim(element), token))
      {
        return true;
      }
    }
    return false;
  }

  /// \brief Get the reason phrase for an HTTP status code.
  ///
  /// The reason phrase is advisory (RFC 9112 §4), but a wrong or "Unknown" phrase
  /// on a common status (a 302 redirect, a 415) is a poor default in an HTMX
  /// application. The table below carries every status this server or its handlers
  /// realistically emit; anything not listed falls back to the RFC 9110 §15
  /// class-derived phrase (never "Unknown", which is always wrong for a valid code).
  static std::string getStatusText(int code)
  {
    switch (code)
    {
    // 1xx Informational
    case 100:
      return "Continue";
    case 101:
      return "Switching Protocols";
    // 2xx Successful
    case 200:
      return "OK";
    case 201:
      return "Created";
    case 202:
      return "Accepted";
    case 204:
      return "No Content";
    case 205:
      return "Reset Content";
    case 206:
      return "Partial Content";
    // 3xx Redirection
    case 301:
      return "Moved Permanently";
    case 302:
      return "Found";
    case 303:
      return "See Other";
    case 304:
      return "Not Modified";
    case 307:
      return "Temporary Redirect";
    case 308:
      return "Permanent Redirect";
    // 4xx Client Error
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
    case 409:
      return "Conflict";
    case 410:
      return "Gone";
    case 411:
      return "Length Required";
    case 412:
      return "Precondition Failed";
    case 413:
      return "Content Too Large"; // RFC 9110 §15.5.14 (renamed from "Payload Too Large")
    case 414:
      return "URI Too Long";
    case 415:
      return "Unsupported Media Type";
    case 422:
      return "Unprocessable Content"; // RFC 9110 §15.5.21
    case 426:
      return "Upgrade Required";
    case 428:
      return "Precondition Required";
    case 429:
      return "Too Many Requests";
    case 431:
      return "Request Header Fields Too Large"; // RFC 6585 §5
    case 451:
      return "Unavailable For Legal Reasons";
    // 5xx Server Error
    case 500:
      return "Internal Server Error";
    case 501:
      return "Not Implemented";
    case 502:
      return "Bad Gateway";
    case 503:
      return "Service Unavailable";
    case 504:
      return "Gateway Timeout";
    case 505:
      return "HTTP Version Not Supported";
    default:
      break;
    }
    // Class-derived fallback (RFC 9110 §15): never "Unknown" for a valid code.
    if (code >= 100 && code < 200)
    {
      return "Informational";
    }
    if (code >= 200 && code < 300)
    {
      return "Successful";
    }
    if (code >= 300 && code < 400)
    {
      return "Redirection";
    }
    if (code >= 400 && code < 500)
    {
      return "Client Error";
    }
    if (code >= 500 && code < 600)
    {
      return "Server Error";
    }
    return "Unknown";
  }

  /// \brief Send an error response with a specified status code and close the
  /// connection. When headersOnly is true the response carries no body (just
  /// Content-Length: 0) — used at the request-size limits (431/413), where there
  /// is no useful representation to return and the request is being rejected.
  void sendErrorResponse(SessionId sid, int statusCode, const std::string &statusText,
                         const std::string &body = "", bool headersOnly = false)
  {
    try
    {
      HttpResponse errorRes(statusCode, statusText);
      errorRes.setHeader("Connection", "close");
      errorRes.setHeader("Server", "Iora/1.0"); // match the dispatch path's Server value
      if (headersOnly)
      {
        // No body, but a definite framing length is still required so the client
        // does not wait for a close-delimited body (RFC 9112 §6.3 rule 8).
        errorRes.setHeader("Content-Length", "0");
      }
      else
      {
        std::string responseBody = body.empty() ? statusText : body;
        errorRes.setHeader("Content-Type", "text/plain");
        errorRes.body = responseBody;
        errorRes.setHeader("Content-Length", std::to_string(responseBody.size()));
      }

      auto errorResponseData = std::make_shared<std::string>(errorRes.toWireFormat());

      {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_transport && !_shutdown)
        {
          iora::core::Logger::info("HttpServer: Sending " + std::to_string(statusCode) + " " +
                                   statusText + " response (session " + std::to_string(sid) + ", " +
                                   std::to_string(errorResponseData->size()) + " bytes)");
          // SR-7: sendAsync fires its completion synchronously on this thread while
          // _mutex is held, so the completion lambda must NOT re-acquire _mutex and
          // must NOT capture `this`. It only logs; the connection close and session
          // cleanup are HOISTED below (still under _mutex, honoring the documented
          // _mutex -> _sessionMutex order) so there is no latent use-after-free if a
          // future transport ever completes the send asynchronously (task-5.4e).
          _transport->sendAsync(
            sid, errorResponseData->data(), errorResponseData->size(),
            [errorResponseData](SessionId session, const SendResult &result)
            {
              if (result.isOk())
              {
                iora::core::Logger::debug("HttpServer: Error response sent successfully to "
                                          "session " +
                                          std::to_string(session));
              }
              else
              {
                iora::core::Logger::error("HttpServer: Failed to send error response to "
                                          "session " +
                                          std::to_string(session) + ": " + result.error().message);
              }
            });

          // Always close the connection after an error response. Runs under the
          // _mutex already held (no re-lock, no raw-`this` capture in a callback),
          // then takes _sessionMutex second (documented order) to erase the session.
          _transport->close(sid);
          {
            std::lock_guard<std::mutex> sessionLock(_sessionMutex);
            _sessionInfo.erase(sid);
          }
        }
        else
        {
          iora::core::Logger::warning("HttpServer: Cannot send error response to session " +
                                      std::to_string(sid) +
                                      " - transport unavailable or shutting down");
        }
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
  // _sessionMutex ARE co-held in sendErrorResponse: after enqueuing the send,
  // _transport->close(sid) then _sessionInfo.erase(sid) run under _sessionMutex
  // while _mutex is still held (the completion lambda itself only logs — the
  // close+erase were hoisted OUT of it) — order _mutex -> _sessionMutex; there is
  // NO reverse _sessionMutex -> _mutex edge. No HttpServer code holding _mutex may call a
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
  std::shared_ptr<Transport> _transport;
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
