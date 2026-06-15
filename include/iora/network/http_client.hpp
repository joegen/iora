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
#include <condition_variable>
#include <ctime>
#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <mutex>
#include <optional>
#include <random>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "iora/network/dns_client.hpp"
#include "iora/network/transport_impl.hpp"
#include "iora/parsers/http_message.hpp"
#include "iora/parsers/json.hpp"

namespace iora
{
namespace network
{


/// \brief Modern HTTP client using hybrid transport for sync/async operations
/// \details
///   - Built on Transport for reliable networking
///   - Uses DnsClient for domain resolution
///   - Supports both synchronous and asynchronous operations
///   - Connection pooling with automatic cleanup
///   - TLS/HTTPS support via transport layer
///
/// THREADING CONTRACT (sync request path): concurrent same-host requests on a
/// SHARED HttpClient instance are SAFE but SERIALIZED. Each request acquires an
/// exclusive per-host:port connection lease (ConnectionLease) that spans the
/// ENTIRE request/response exchange (connect, send, receive, parse, eviction);
/// a second thread targeting the same host:port blocks until the first releases
/// the lease (bounded by Config::leaseAcquireTimeout). This matches RFC 7230
/// §6.3 (Persistence): without pipelining, a persistent connection carries one
/// request/response exchange at a time, so serializing same-host requests onto a
/// single cached connection is the correct single-connection model. It prevents
/// the request/response interleaving and use-after-evict that a naive shared
/// instance would suffer. Requests to DIFFERENT host:port values run
/// concurrently. For real same-host parallelism (multiple simultaneous
/// connections), use HttpClientPool, which gives each worker an independent
/// HttpClient.
///
/// dropConnection() relies on SessionId monotonicity (never reused) so an
/// async transport close for an evicted id cannot tear down a later reused id.
class HttpClient
{
public:
  /// \brief TLS configuration for HTTPS requests
  struct TlsConfig
  {
    std::string caFile;
    std::string clientCertFile;
    std::string clientKeyFile;
    bool verifyPeer = true;
  };

  /// \brief HTTP response structure
  struct Response
  {
    int statusCode = 0;
    std::string statusText;
    /// HTTP version from the response status line (e.g. "1.1", "1.0"). Used to
    /// apply the version-default connection-persistence rule (RFC 7230 §6.3):
    /// HTTP/1.0 defaults to close unless it sent "Connection: keep-alive".
    std::string httpVersion;
    // Case-insensitive per RFC 7230 §3.2 (field names are case-insensitive): a
    // server may send "connection:" / "Content-Length:" in any case, so lookups
    // (e.g. responseRequestsClose, body framing) MUST be case-insensitive.
    std::map<std::string, std::string, CaseInsensitiveCompare> headers;
    std::string body;
    bool success() const { return statusCode >= 200 && statusCode < 300; }
  };

  /// \brief JSON parsing configuration
  struct JsonConfig
  {
    std::size_t maxPayloadSize =
      10 * 1024 * 1024;               // Maximum JSON payload size in bytes (10MB default)
    parsers::ParseLimits parseLimits; // JSON parsing limits (depth, array size, etc.)
  };

  /// \brief Configuration for HTTP client
  struct Config
  {
    std::chrono::milliseconds connectTimeout;
    std::chrono::milliseconds requestTimeout;
    int maxRedirects;
    bool followRedirects;
    std::string userAgent;
    bool reuseConnections;
    std::chrono::seconds connectionIdleTimeout;
    /// Maximum time a request blocks waiting to acquire the exclusive per-host
    /// connection lease before failing with a distinct timeout error. Zero (the
    /// default) means wait indefinitely, preserving pre-lease blocking semantics.
    std::chrono::milliseconds leaseAcquireTimeout;
    JsonConfig jsonConfig; // JSON parsing configuration

    Config()
        : connectTimeout(2000), requestTimeout(3000), maxRedirects(5), followRedirects(true),
          userAgent("Iora-HttpClient/1.0"), reuseConnections(true), connectionIdleTimeout(300),
          leaseAcquireTimeout(0), jsonConfig{}
    {
    }

    /// \brief Create a config optimized for localhost/testing
    static Config forLocalhost()
    {
      Config c;
      c.connectTimeout = std::chrono::milliseconds(100);
      c.requestTimeout = std::chrono::milliseconds(200);
      return c;
    }
  };

private:
  void ensureInitialized() const
  {
    if (!_transport)
    {
      // Create TCP transport for HTTP/HTTPS
      TransportConfig transportConfig;
      transportConfig.protocol = Protocol::TCP;
      transportConfig.connectTimeout =
        std::chrono::duration_cast<std::chrono::milliseconds>(_config.connectTimeout);
      transportConfig.defaultSyncTimeout = _config.requestTimeout;
      transportConfig.idleTimeout = _config.connectionIdleTimeout;

      // Enable TLS for HTTPS with current TLS configuration
      transportConfig.clientTls.enabled = true;
      transportConfig.clientTls.defaultMode = TlsMode::Client;
      transportConfig.clientTls.verifyPeer = _tlsConfig.verifyPeer;

      _transport = Transport::tcp(transportConfig); // HTTP client is TCP (S-3: shared_ptr factory)
      auto startResult = _transport->start();
      if (startResult.isErr())
      {
        throw std::runtime_error("Failed to start HTTP client transport layer");
      }

      // Create DNS client for domain resolution
      _dnsClient = std::make_unique<DnsClient>();
      _dnsClient->start();
    }
  }

  mutable std::mutex _mutex;
  Config _config;
  TlsConfig _tlsConfig;

  // Transport and DNS client (initialized lazily)
  mutable std::shared_ptr<Transport> _transport;
  mutable std::unique_ptr<DnsClient> _dnsClient;

  /// \brief Cached live connection for a host:port.
  struct ConnectionEntry
  {
    SessionId id{0};
    std::chrono::steady_clock::time_point lastUsed{};
  };

  // Connection cache: host:port -> live cached connection. Mutated ONLY under
  // _mutex.
  mutable std::unordered_map<std::string, ConnectionEntry> _connections;
  // Hosts (host:port) whose connection slot is currently leased by an in-flight
  // exchange. Exactly one lease per host:port at a time (LEASE-1: single writer
  // per connection). Mutated ONLY under _mutex.
  mutable std::unordered_set<std::string> _leasedHosts;
  // Signals lease release (and shutdown) to threads blocked in acquireLease.
  mutable std::condition_variable _cv;
  // Set by cleanup()/~HttpClient so blocked lease waiters wake and fail rather
  // than deadlock (DD-A8).
  mutable bool _closing{false};

  /// \brief URL parsing structure
  struct ParsedUrl
  {
    std::string scheme;
    std::string host;
    std::uint16_t port;
    std::string path;
    std::string query;

    bool isHttps() const { return scheme == "https"; }
    std::string getPathWithQuery() const
    {
      if (query.empty())
        return path.empty() ? "/" : path;
      return (path.empty() ? "/" : path) + "?" + query;
    }
    std::string getHostPort() const { return host + ":" + std::to_string(port); }
  };

  /// \brief Move-only RAII guard for an exclusive per-host:port connection lease.
  ///
  /// Acquired in executeRequest right after acquireLease and held for the entire
  /// exchange. Its destructor releases the lease (clears the leased flag and
  /// notifies waiters) on EVERY scope exit — normal return AND every exception
  /// path — so a throwing request can never leave a host's lease permanently
  /// held (which would deadlock all future same-host requests). The lease is
  /// released here and ONLY here (no hand-placed release elsewhere). noexcept
  /// so it is safe to run during stack unwinding.
  class ConnectionLease
  {
  public:
    ConnectionLease() = default;
    ConnectionLease(HttpClient *owner, std::string hostPort)
        : _owner(owner), _hostPort(std::move(hostPort))
    {
    }

    ConnectionLease(ConnectionLease &&other) noexcept
        : _owner(other._owner), _hostPort(std::move(other._hostPort))
    {
      other._owner = nullptr;
    }

    ConnectionLease &operator=(ConnectionLease &&other) noexcept
    {
      if (this != &other)
      {
        release();
        _owner = other._owner;
        _hostPort = std::move(other._hostPort);
        other._owner = nullptr;
      }
      return *this;
    }

    ConnectionLease(const ConnectionLease &) = delete;
    ConnectionLease &operator=(const ConnectionLease &) = delete;

    ~ConnectionLease() { release(); }

    void release() noexcept
    {
      if (_owner)
      {
        // releaseLease locks _mutex; std::mutex::lock can in principle throw
        // (std::system_error) but only on unrecoverable mutex corruption /
        // deadlock detection. Letting that terminate() is preferable to leaking
        // the lease (which would permanently deadlock all future same-host
        // requests), so release() is correctly noexcept.
        _owner->releaseLease(_hostPort);
        _owner = nullptr;
      }
    }

  private:
    HttpClient *_owner{nullptr};
    std::string _hostPort;
  };

public:
  /// \brief Constructor with optional configuration
  explicit HttpClient(const Config &config = Config{}) : _config(config)
  {
    // Transport and DNS client are created lazily to allow TLS config to be
    // set first
  }

  ~HttpClient() { cleanup(); }

  // HttpClient is non-copyable AND non-movable: it owns a std::mutex,
  // std::condition_variable, and live lease/connection state. A std::mutex/CV
  // member is itself non-movable, so a `= default` move would be implicitly
  // DELETED anyway — declaring `= delete` makes the non-movability explicit and
  // avoids a misleading interface. Heap-store via std::shared_ptr<HttpClient>
  // (as HttpClientPool does) when movability is needed.
  HttpClient(const HttpClient &) = delete;
  HttpClient &operator=(const HttpClient &) = delete;
  HttpClient(HttpClient &&) = delete;
  HttpClient &operator=(HttpClient &&) = delete;

  /// \brief Set TLS configuration
  void setTlsConfig(const TlsConfig &config)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _tlsConfig = config;
    // TLS config is applied per-connection during connect
  }

  /// \brief Set DNS servers for domain resolution
  /// \param servers List of DNS server addresses (e.g., {"8.8.8.8", "1.1.1.1:53", "192.168.1.1"})
  /// \note Servers without explicit port use default port 53. Must be set before making requests.
  void setDnsServers(const std::vector<std::string> &servers)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    ensureInitialized();
    _dnsClient->setDnsServers(servers);
  }

  /// \brief Add DNS server to existing configuration
  /// \param server DNS server address (e.g., "8.8.8.8" or "1.1.1.1:53")
  void addDnsServer(const std::string &server)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    ensureInitialized();
    _dnsClient->addDnsServer(server);
  }

  /// \brief Get current DNS servers
  /// \return Vector of DNS server addresses in "address:port" format
  std::vector<std::string> getDnsServers()
  {
    std::lock_guard<std::mutex> lock(_mutex);
    ensureInitialized();
    return _dnsClient->getDnsServers();
  }

  /// \brief Perform synchronous GET request
  Response get(const std::string &url, const std::map<std::string, std::string> &headers = {},
               int retries = 0)
  {
    return performRequest("GET", url, "", headers, retries);
  }

  /// \brief Perform synchronous POST request with JSON body
  Response postJson(const std::string &url, const parsers::Json &body,
                    const std::map<std::string, std::string> &headers = {}, int retries = 0)
  {
    std::map<std::string, std::string> jsonHeaders = headers;
    jsonHeaders["Content-Type"] = "application/json";
    std::string jsonBody = body.dump();
    return performRequest("POST", url, jsonBody, jsonHeaders, retries);
  }

  /// \brief Perform synchronous POST request with string body
  Response post(const std::string &url, const std::string &body,
                const std::map<std::string, std::string> &headers = {}, int retries = 0)
  {
    return performRequest("POST", url, body, headers, retries);
  }

  /// \brief Perform synchronous DELETE request
  Response deleteRequest(const std::string &url,
                         const std::map<std::string, std::string> &headers = {}, int retries = 0)
  {
    return performRequest("DELETE", url, "", headers, retries);
  }

  /// \brief Perform asynchronous GET request
  std::future<Response> getAsync(const std::string &url,
                                 const std::map<std::string, std::string> &headers = {},
                                 int retries = 0)
  {
    return std::async(std::launch::async,
                      [this, url, headers, retries]() { return get(url, headers, retries); });
  }

  /// \brief Perform asynchronous POST request with JSON body
  std::future<Response> postJsonAsync(const std::string &url, const parsers::Json &body,
                                      const std::map<std::string, std::string> &headers = {},
                                      int retries = 0)
  {
    return std::async(std::launch::async, [this, url, body, headers, retries]()
                      { return postJson(url, body, headers, retries); });
  }

  /// \brief Stream HTTP response via callback (for server-sent events, etc.)
  void postStream(const std::string &url, const parsers::Json &body,
                  const std::map<std::string, std::string> &headers,
                  const std::function<void(const std::string &)> &onChunk, int retries = 0)
  {
    std::map<std::string, std::string> streamHeaders = headers;
    streamHeaders["Accept"] = "text/event-stream";
    streamHeaders["Cache-Control"] = "no-cache";

    Response response = postJson(url, body, streamHeaders, retries);
    if (!response.success())
    {
      throw std::runtime_error("HTTP request failed: " + std::to_string(response.statusCode));
    }

    // Split response body into lines and call onChunk for each
    std::istringstream stream(response.body);
    std::string line;
    while (std::getline(stream, line))
    {
      onChunk(line);
    }
  }

  /// \brief Upload file via multipart form data
  Response postFile(const std::string &url, const std::string &fieldName,
                    const std::string &filePath,
                    const std::map<std::string, std::string> &headers = {}, int retries = 0)
  {
    // Read file content
    std::ifstream file(filePath, std::ios::binary);
    if (!file)
    {
      throw std::runtime_error("Cannot read file: " + filePath);
    }

    std::string fileContent((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
    file.close();

    // Extract filename from path
    std::string filename = filePath;
    auto pos = filename.find_last_of("/\\");
    if (pos != std::string::npos)
    {
      filename = filename.substr(pos + 1);
    }

    // Create multipart form data
    std::string boundary = "----IoraBoundary" + std::to_string(std::time(nullptr));
    std::ostringstream body;
    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"" << fieldName << "\"; filename=\"" << filename
         << "\"\r\n";
    body << "Content-Type: application/octet-stream\r\n\r\n";
    body << fileContent;
    body << "\r\n--" << boundary << "--\r\n";

    std::map<std::string, std::string> multipartHeaders = headers;
    multipartHeaders["Content-Type"] = "multipart/form-data; boundary=" + boundary;

    return performRequest("POST", url, body.str(), multipartHeaders, retries);
  }

  /// \brief Parse JSON response or throw on error (with default config)
  static parsers::Json parseJsonOrThrow(const Response &response)
  {
    JsonConfig defaultConfig;
    return parseJsonOrThrow(response, defaultConfig);
  }

  /// \brief Parse JSON response or throw on error (with custom config)
  static parsers::Json parseJsonOrThrow(const Response &response, const JsonConfig &jsonConfig)
  {
    if (!response.success())
    {
      throw std::runtime_error("HTTP failed with status: " + std::to_string(response.statusCode));
    }

    if (response.body.size() > jsonConfig.maxPayloadSize)
    {
      throw std::runtime_error("JSON response exceeds maximum size limit of " +
                               std::to_string(jsonConfig.maxPayloadSize) + " bytes");
    }

    auto result = parsers::Json::parse(response.body, jsonConfig.parseLimits);
    if (!result.ok)
    {
      throw std::runtime_error("JSON parse error: " + result.error.message);
    }
    return std::move(result.value);
  }

  /// \brief Cleanup connections and resources.
  ///
  /// PRECONDITION: callers must not invoke cleanup() (or destroy the client)
  /// while requests are still in flight on OTHER threads. cleanup() wakes
  /// threads blocked in acquireLease (they fail fast), but a thread already past
  /// the lease and mid-I/O (connectSync/sendSync/receiveSync) will have its
  /// transport stopped underneath it — it surfaces an error rather than crashing,
  /// but join all request threads before cleanup/destruction for clean shutdown.
  void cleanup()
  {
    std::lock_guard<std::mutex> lock(_mutex);

    // Wake any threads blocked in acquireLease so a destruct/cleanup during a
    // contended wait fails fast instead of deadlocking (DD-A8).
    _closing = true;
    _cv.notify_all();

    // Close all connections. Guard on _transport for consistency with stop()
    // below (a non-empty cache implies an initialized transport, but keep the
    // guard so the loop and stop() agree).
    if (_transport)
    {
      for (const auto &[hostPort, entry] : _connections)
      {
        _transport->close(entry.id);
      }
      _transport->stop();
    }
    _connections.clear();

    if (_dnsClient)
    {
      _dnsClient->stop();
    }
  }

private:
  /// \brief Immutable, compile-once regexes shared by all requests.
  ///
  /// std::regex compilation invokes std::ctype<char>::narrow, which lazily fills
  /// a per-facet cache on first use; two threads compiling regexes concurrently
  /// race on that cache (value-benign but a real data race flagged by TSan).
  /// Compiling each regex exactly once inside a function-local static — whose
  /// initialization is serialized by the C++11 "magic static" guard — warms the
  /// ctype cache on a single thread and avoids per-request recompilation. All
  /// subsequent uses are const reads (regex_match/regex_search on a const regex
  /// is thread-safe).
  struct CompiledRegexes
  {
    std::regex url{
      R"(^(https?):\/\/([^:\/\s]+)(?::(\d+))?(\/?[^?\s]*)(?:\?([^#\s]*))?(?:#.*)?$)"};
    std::regex ipv4{R"(^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$)"};
    std::regex contentLength{R"(Content-Length:\s*(\d+))", std::regex_constants::icase};
    std::regex chunked{R"(Transfer-Encoding:\s*chunked)", std::regex_constants::icase};
    std::regex status{R"(HTTP/(\d\.\d)\s+(\d+)\s*(.*))"};
  };

  static const CompiledRegexes &compiledRegexes()
  {
    static const CompiledRegexes regexes;
    return regexes;
  }

  /// \brief Parse URL into components
  ParsedUrl parseUrl(const std::string &url) const
  {
    ParsedUrl parsed;

    std::smatch match;
    if (!std::regex_match(url, match, compiledRegexes().url))
    {
      throw std::invalid_argument("Invalid URL format: " + url);
    }

    parsed.scheme = match[1].str();
    parsed.host = match[2].str();

    // Default ports
    if (match[3].matched)
    {
      parsed.port = static_cast<std::uint16_t>(std::stoi(match[3].str()));
    }
    else
    {
      parsed.port = (parsed.scheme == "https") ? 443 : 80;
    }

    parsed.path = match[4].str();
    if (parsed.path.empty())
      parsed.path = "/";

    parsed.query = match[5].str();

    return parsed;
  }

  /// \brief Acquire the exclusive connection lease for \p hostPort.
  ///
  /// Blocks until no other thread holds the lease for this host:port (or the
  /// client is shutting down). The wait uses a predicate loop (LEASE-2:
  /// spurious-wakeup safe) and is bounded by Config::leaseAcquireTimeout when
  /// that is non-zero (LEASE/INV-5), surfacing a DISTINCT timeout error rather
  /// than hanging. Returns an RAII guard whose destruction releases the lease.
  /// \throws std::runtime_error on lease-acquire timeout or on shutdown.
  ConnectionLease acquireLease(const std::string &hostPort)
  {
    std::unique_lock<std::mutex> lock(_mutex);
    auto available = [&] { return _closing || _leasedHosts.find(hostPort) == _leasedHosts.end(); };

    if (_config.leaseAcquireTimeout.count() > 0)
    {
      if (!_cv.wait_for(lock, _config.leaseAcquireTimeout, available))
      {
        throw std::runtime_error("HttpClient: timed out acquiring connection lease for " +
                                 hostPort);
      }
    }
    else
    {
      _cv.wait(lock, available);
    }

    if (_closing)
    {
      throw std::runtime_error("HttpClient: shutting down; cannot acquire connection lease for " +
                               hostPort);
    }

    _leasedHosts.insert(hostPort);
    return ConnectionLease(this, hostPort);
  }

  /// \brief Release the lease for \p hostPort and wake waiters.
  /// Called ONLY from ConnectionLease's destructor/move (RAII). noexcept.
  ///
  /// MUST be notify_all, NOT notify_one: a single _cv serves waiters for ALL
  /// host:port values. notify_one could wake a waiter for a DIFFERENT,
  /// still-leased host (whose predicate is false), which re-parks, while the
  /// waiter for the just-freed host is never woken — a lost wakeup. notify_all
  /// wakes every waiter so the one(s) blocked on this host re-evaluate.
  void releaseLease(const std::string &hostPort) noexcept
  {
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _leasedHosts.erase(hostPort);
    }
    _cv.notify_all();
  }

  /// \brief Resolve \p parsedUrl's host to an address string (lock-free).
  ///
  /// DnsClient is internally synchronized (its cache uses an ExpiringCache with
  /// its own mutex), so this is safe to call without _mutex held — required by
  /// LEASE-7 (do not hold _mutex across I/O). Falls back to the literal hostname
  /// if resolution fails (the transport layer may still resolve it).
  std::string resolveHostAddress(const ParsedUrl &parsedUrl) const
  {
    if (isIPAddress(parsedUrl.host))
    {
      return parsedUrl.host;
    }
    if (parsedUrl.host == "localhost")
    {
      return "127.0.0.1";
    }
    try
    {
      auto result = _dnsClient->resolveHost(parsedUrl.host);
      if (!result.ipv4.empty())
      {
        return result.ipv4[0]; // Use first IPv4 address
      }
      if (!result.ipv6.empty())
      {
        return result.ipv6[0]; // Use first IPv6 address
      }
    }
    catch (const std::exception &)
    {
      // DNS resolution failed; fall through to the literal hostname.
    }
    return parsedUrl.host;
  }

  /// \brief Reuse a cached connection for \p parsedUrl, or open a fresh one.
  ///
  /// MUST be called while holding the lease for parsedUrl.getHostPort(): the
  /// lease guarantees this thread is the sole owner of the host's connection
  /// slot, so _mutex is taken only for short bookkeeping (cache lookup/publish)
  /// and is RELEASED across DNS resolution and connectSync (LEASE-7 — the lease,
  /// not the mutex, serializes same-host work; holding _mutex across I/O would
  /// block lease releases and other hosts' bookkeeping).
  SessionId acquireConnection(const ParsedUrl &parsedUrl)
  {
    const std::string hostPort = parsedUrl.getHostPort();

    // (1) Reuse a live, non-idle cached connection (short critical section).
    {
      std::lock_guard<std::mutex> lock(_mutex);
      auto it = _connections.find(hostPort);
      if (it != _connections.end())
      {
        auto now = std::chrono::steady_clock::now();
        if (now - it->second.lastUsed < _config.connectionIdleTimeout)
        {
          it->second.lastUsed = now;
          return it->second.id;
        }
        // Idle: close and evict, then fall through to reconnect.
        _transport->close(it->second.id);
        _connections.erase(it);
      }
    }

    // (2) Resolve the hostname (no _mutex held — LEASE-7).
    std::string resolvedHost = resolveHostAddress(parsedUrl);

    // (3) Open a new connection synchronously (no _mutex held — LEASE-7). Safe
    //     because the lease makes this thread the exclusive owner of hostPort's
    //     slot, so no other thread races this connect/publish.
    TlsMode tlsMode = parsedUrl.isHttps() ? TlsMode::Client : TlsMode::None;

    // Use shorter timeout for localhost — connection refused should be instant.
    auto timeout = (resolvedHost == "127.0.0.1" || resolvedHost == "::1")
      ? std::min(_config.connectTimeout, std::chrono::milliseconds(200))
      : _config.connectTimeout;

    auto connectResult = _transport->connectSync(resolvedHost, parsedUrl.port, tlsMode, timeout);
    if (connectResult.isErr())
    {
      throw std::runtime_error("Connection failed to " + hostPort + ": " +
                               connectResult.error().message);
    }
    SessionId sessionId = connectResult.value();

    // (4) Publish the new connection (short critical section).
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _connections[hostPort] = ConnectionEntry{sessionId, std::chrono::steady_clock::now()};
    }

    return sessionId;
  }

  /// \brief Close \p sessionId and evict it from the connection cache.
  ///
  /// The cache (acquireConnection) hands out a cached connection whenever one
  /// exists for the host:port and is within the idle timeout — independent of
  /// reuseConnections. Three cases require explicit eviction or a later request
  /// would reuse a dead socket (manifesting as "connection closed" then a run of
  /// "HTTP response timeout"):
  ///   1. reuseConnections == false: the request was sent with "Connection:
  ///      close", so the server closes the socket after responding. The cached
  ///      entry must be dropped so the next request opens a fresh connection.
  ///   2. the server's response signalled "Connection: close" (DD-A9).
  ///   3. a send/receive/parse failure: the peer may have closed the connection,
  ///      so it must not be reused (and a retry must get a fresh socket).
  ///
  /// SAFETY (async close vs. id reuse): _transport->close() only enqueues the
  /// teardown on the I/O thread (it does NOT block on I/O), which is why calling
  /// it while _mutex is held here — and on the idle-eviction path in
  /// acquireConnection — does not violate LEASE-7. SessionId is a monotonically increasing
  /// uint64 counter (tcp_engine/udp_engine: _nextSessionId{1}, post-increment) and
  /// is NEVER reused, so a still-pending close for this evicted id cannot tear
  /// down a later connection that happens to reuse the value. This is the same
  /// guarantee acquireConnection's idle-eviction close relies on.
  /// NOTE (lease interaction): dropConnection evicts the cached CONNECTION only;
  /// it does NOT touch the host's lease. The caller still holds the lease via
  /// its ConnectionLease guard and releases it exactly once on scope exit
  /// (RAII). After eviction, the next lease holder for this host finds no cached
  /// connection and opens a FRESH one (LEASE-4: drop-then-reconnect).
  void dropConnection(const std::string &hostPort, SessionId sessionId)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _connections.find(hostPort);
    if (it != _connections.end() && it->second.id == sessionId)
    {
      _connections.erase(it);
    }
    _transport->close(sessionId);
  }

  /// \brief Check if string is an IP address
  bool isIPAddress(const std::string &str) const
  {
    // Simple IPv4 check (could be enhanced for IPv6)
    return std::regex_match(str, compiledRegexes().ipv4);
  }

  /// \brief Perform HTTP request with retry logic
  Response performRequest(const std::string &method, const std::string &url,
                          const std::string &body,
                          const std::map<std::string, std::string> &headers, int retries)
  {
    {
      std::lock_guard<std::mutex> lock(_mutex);
      ensureInitialized();
    }

    // Log the outgoing request
    iora::core::Logger::info("HttpClient: " + method + " " + url +
                             " (body size: " + std::to_string(body.size()) + " bytes)");

    int attempt = 0;
    while (true)
    {
      try
      {
        auto response = executeRequest(method, url, body, headers);

        // Log the response
        iora::core::Logger::info(
          "HttpClient: Received " + std::to_string(response.statusCode) + " response from " + url +
          " (body size: " + std::to_string(response.body.size()) + " bytes)");

        return response;
      }
      catch (const std::exception &e)
      {
        if (attempt >= retries)
        {
          iora::core::Logger::error("HttpClient: Request to " + url + " failed after " +
                                    std::to_string(attempt + 1) + " attempts: " + e.what());
          throw;
        }

        // Log retry attempt
        iora::core::Logger::debug("HttpClient: Retrying request to " + url + " (attempt " +
                                  std::to_string(attempt + 1) + "/" + std::to_string(retries + 1) +
                                  "): " + e.what());

        // Exponential backoff with jitter. Use a thread-local PRNG so concurrent
        // retries on a shared instance do not race on a global PRNG and do not
        // draw identical backoff sequences (which would re-synchronize retry
        // storms) — DD-A10.
        static thread_local std::mt19937 jitterRng(
          std::random_device{}() ^
          static_cast<std::mt19937::result_type>(
            std::hash<std::thread::id>{}(std::this_thread::get_id())));
        std::uniform_int_distribution<int> jitterDist(0, 99);
        int backoffMs = (1 << attempt) * 100 + jitterDist(jitterRng);
        std::this_thread::sleep_for(std::chrono::milliseconds(backoffMs));
        attempt++;
      }
    }
  }

  /// \brief Execute single HTTP request
  Response executeRequest(const std::string &method, const std::string &url,
                          const std::string &body,
                          const std::map<std::string, std::string> &headers)
  {
    auto parsedUrl = parseUrl(url);
    const std::string hostPort = parsedUrl.getHostPort();

    // Use normal timeout - optimization will be handled at transport level
    std::chrono::milliseconds sendTimeout = _config.requestTimeout;

    // Acquire the exclusive per-host connection lease for the WHOLE exchange
    // (INV-2: connect, send, receive, parse, eviction). The RAII guard releases
    // it on every scope exit, including any throw below or from acquireConnection.
    //
    // DD-A7 (no self-deadlock): executeRequest acquires the lease exactly once
    // and never re-enters acquireLease for the same host (HttpClient does not
    // follow redirects). The retry loop lives in performRequest, which calls
    // executeRequest afresh per attempt, so the lease is fully released between
    // attempts and a retry never blocks on a lease this thread already holds.
    ConnectionLease lease = acquireLease(hostPort);

    auto sessionId = acquireConnection(parsedUrl);

    // Set session to sync mode BEFORE sending request so response data gets
    // buffered correctly
    if (!_transport->setReadMode(sessionId, ReadMode::Sync))
    {
      dropConnection(hostPort, sessionId);
      throw std::runtime_error("Failed to set session to sync read mode");
    }

    // Build HTTP request
    std::ostringstream request;
    request << method << " " << parsedUrl.getPathWithQuery() << " HTTP/1.1\r\n";
    request << "Host: " << parsedUrl.host << "\r\n";
    request << "User-Agent: " << _config.userAgent << "\r\n";
    request << "Connection: " << (_config.reuseConnections ? "keep-alive" : "close") << "\r\n";

    // Add custom headers
    for (const auto &[name, value] : headers)
    {
      request << name << ": " << value << "\r\n";
    }

    // Add body if present
    if (!body.empty())
    {
      request << "Content-Length: " << body.size() << "\r\n";
    }

    request << "\r\n";
    if (!body.empty())
    {
      request << body;
    }

    std::string requestStr = request.str();

    // Send request synchronously
    auto sendResult = _transport->sendSync(
      sessionId,
      iora::core::BufferView{reinterpret_cast<const std::uint8_t*>(requestStr.data()), requestStr.size()},
      sendTimeout);
    if (sendResult.isErr())
    {
      // The connection is unusable — evict it so it is never reused / so a retry
      // opens a fresh socket.
      dropConnection(hostPort, sessionId);
      throw std::runtime_error("Failed to send HTTP request: " + sendResult.error().message);
    }

    // Receive response synchronously by accumulating data until we have a
    // complete HTTP response
    std::string responseData;
    char buffer[8192];

    try
    {
      while (true)
      {
        std::size_t len = sizeof(buffer);

        auto recvResult = _transport->receiveSync(sessionId, buffer, len, sendTimeout);

        if (recvResult.isOk() && len > 0)
        {
          responseData.append(buffer, len);

          // Check if we have complete HTTP response
          if (isCompleteHttpResponse(responseData))
          {
            break;
          }
        }
        else if (recvResult.isErr() && recvResult.error().code == TransportError::Timeout)
        {
          throw std::runtime_error("HTTP response timeout");
        }
        else if (recvResult.isErr() && recvResult.error().code == TransportError::BufferOverflow)
        {
          throw std::runtime_error("HTTP response exceeded sync receive buffer (overflow)");
        }
        else if (recvResult.isErr() && recvResult.error().code == TransportError::ShuttingDown)
        {
          throw std::runtime_error("HTTP transport shutting down before response complete");
        }
        else if (recvResult.isErr())
        {
          throw std::runtime_error("Connection closed before receiving complete HTTP response");
        }
        // receiveSync no longer returns ok(0): with the spurious-wake fold-back
        // it returns only on data / Timeout / PeerClosed / BufferOverflow /
        // ShuttingDown, all handled above. (len==0 on an ok result cannot occur.)
      }

      Response resp = parseHttpResponse(responseData);
      if (_config.reuseConnections && !responseRequestsClose(resp))
      {
        // Keep the connection warm (async mode) for the next request. If the
        // mode switch fails the socket is suspect — evict rather than cache a
        // known-bad connection that the next reuse would have to discover.
        if (!_transport->setReadMode(sessionId, ReadMode::Async))
        {
          dropConnection(hostPort, sessionId);
        }
      }
      else
      {
        // Evict the cached entry — otherwise the next request reuses a dead
        // socket and times out. Two cases:
        //   - client requested "Connection: close" (reuseConnections == false);
        //   - the server's RESPONSE carried "Connection: close" (or an HTTP/1.0
        //     response without keep-alive). Per RFC 7230 §6.6, a recipient that
        //     sees a close signal MUST NOT reuse the connection (DD-A9).
        dropConnection(hostPort, sessionId);
      }
      return resp;
    }
    catch (...)
    {
      // A receive/parse failure means the connection is suspect (the peer may
      // have closed it). Evict it so no later request — including a retry —
      // reuses a dead socket.
      dropConnection(hostPort, sessionId);
      throw;
    }
  }

  /// \brief Decide whether a parsed response signals the connection must close.
  ///
  /// RFC 7230 §6.1/§6.6: the "Connection" header is a comma-separated token
  /// list; a "close" token means the sender will close after this message and
  /// the recipient MUST NOT reuse the connection. An explicit "keep-alive"
  /// token keeps it open. Absent any Connection header, HTTP/1.1 defaults to
  /// persistent and HTTP/1.0 defaults to close (DD-A9).
  bool responseRequestsClose(const Response &resp) const
  {
    auto it = resp.headers.find("Connection");
    if (it != resp.headers.end())
    {
      // Connection is a comma-separated list of tokens (RFC 7230 §6.1); match on
      // tokenized, OWS-trimmed, ASCII-case-folded EQUALITY — never a substring
      // search, which would false-match "close" inside another option token such
      // as "X-Close-Hint". ASCII-only folding (not std::tolower, which reads the
      // global C locale) keeps this locale-independent and race-free.
      bool sawKeepAlive = false;
      const std::string &value = it->second;
      std::size_t pos = 0;
      while (pos <= value.size())
      {
        std::size_t comma = value.find(',', pos);
        std::size_t end = (comma == std::string::npos) ? value.size() : comma;
        std::size_t a = value.find_first_not_of(" \t", pos);
        std::size_t b = value.find_last_not_of(" \t", end == 0 ? 0 : end - 1);
        if (a != std::string::npos && a < end && b != std::string::npos && b >= a)
        {
          std::string token = value.substr(a, b - a + 1);
          std::transform(token.begin(), token.end(), token.begin(),
                         [](char c)
                         { return CaseInsensitiveCompare::asciiLower(
                             static_cast<unsigned char>(c)); });
          if (token == "close")
          {
            return true; // a "close" token wins outright
          }
          if (token == "keep-alive")
          {
            sawKeepAlive = true;
          }
        }
        if (comma == std::string::npos)
        {
          break;
        }
        pos = comma + 1;
      }
      if (sawKeepAlive)
      {
        return false;
      }
    }
    // No explicit Connection directive: HTTP/1.0 defaults to close, HTTP/1.1
    // defaults to persistent (RFC 7230 §6.3).
    return resp.httpVersion == "1.0";
  }

  /// \brief Check if we have a complete HTTP response
  bool isCompleteHttpResponse(const std::string &data) const
  {
    // Look for end of headers
    auto headerEnd = data.find("\r\n\r\n");
    if (headerEnd == std::string::npos)
    {
      return false; // Headers not complete
    }

    // Parse headers to check for Content-Length or Transfer-Encoding
    std::string headers = data.substr(0, headerEnd);
    std::string body = data.substr(headerEnd + 4);

    // Look for Content-Length
    std::smatch match;
    if (std::regex_search(headers, match, compiledRegexes().contentLength))
    {
      std::size_t contentLength = std::stoul(match[1].str());
      return body.size() >= contentLength;
    }

    // Look for Transfer-Encoding: chunked
    if (std::regex_search(headers, compiledRegexes().chunked))
    {
      // Simple chunked detection - look for final chunk (0\r\n\r\n)
      return data.find("0\r\n\r\n") != std::string::npos;
    }

    // No content length specified, assume complete (HTTP/1.0 style)
    return true;
  }

  /// \brief Parse HTTP response from raw data
  Response parseHttpResponse(const std::string &data) const
  {
    Response response;

    // Find end of headers
    auto headerEnd = data.find("\r\n\r\n");
    if (headerEnd == std::string::npos)
    {
      throw std::runtime_error("Invalid HTTP response: no header separator found");
    }

    std::string headerSection = data.substr(0, headerEnd);
    std::string bodySection = data.substr(headerEnd + 4);

    // Parse status line
    std::istringstream headerStream(headerSection);
    std::string statusLine;
    std::getline(headerStream, statusLine);

    // Remove trailing \r if present
    if (!statusLine.empty() && statusLine.back() == '\r')
    {
      statusLine.pop_back();
    }

    // Parse HTTP version, status code, and text
    std::smatch statusMatch;
    if (std::regex_match(statusLine, statusMatch, compiledRegexes().status))
    {
      response.httpVersion = statusMatch[1].str();
      response.statusCode = std::stoi(statusMatch[2].str());
      response.statusText = statusMatch[3].str();
    }
    else
    {
      throw std::runtime_error("Invalid HTTP status line: " + statusLine);
    }

    // Parse headers
    std::string headerLine;
    while (std::getline(headerStream, headerLine))
    {
      if (!headerLine.empty() && headerLine.back() == '\r')
      {
        headerLine.pop_back();
      }

      auto colonPos = headerLine.find(':');
      if (colonPos != std::string::npos)
      {
        std::string name = headerLine.substr(0, colonPos);
        std::string value = headerLine.substr(colonPos + 1);

        // Trim whitespace
        name.erase(0, name.find_first_not_of(" \t"));
        name.erase(name.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);

        response.headers[name] = value;
      }
    }

    // Handle body based on Content-Length or Transfer-Encoding
    auto contentLengthIt = response.headers.find("Content-Length");
    if (contentLengthIt != response.headers.end())
    {
      std::size_t contentLength = std::stoul(contentLengthIt->second);
      response.body = bodySection.substr(0, contentLength);
    }
    else
    {
      auto transferEncodingIt = response.headers.find("Transfer-Encoding");
      if (transferEncodingIt != response.headers.end() &&
          transferEncodingIt->second.find("chunked") != std::string::npos)
      {
        response.body = decodeChunkedBody(bodySection);
      }
      else
      {
        response.body = bodySection;
      }
    }

    return response;
  }

  /// \brief Decode chunked transfer encoding
  std::string decodeChunkedBody(const std::string &chunkedData) const
  {
    std::string result;
    std::istringstream stream(chunkedData);
    std::string line;

    while (std::getline(stream, line))
    {
      // Remove \r if present
      if (!line.empty() && line.back() == '\r')
      {
        line.pop_back();
      }

      // Parse chunk size (hex)
      std::size_t chunkSize = std::stoul(line, nullptr, 16);
      if (chunkSize == 0)
      {
        break; // End of chunks
      }

      // Read chunk data
      std::string chunkData(chunkSize, '\0');
      stream.read(&chunkData[0], chunkSize);
      result += chunkData;

      // Skip trailing CRLF
      std::getline(stream, line);
    }

    return result;
  }
};

} // namespace network
} // namespace iora