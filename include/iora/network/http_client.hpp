// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstdint>
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
/// \brief Thrown on a deterministic HTTP response-framing/parse violation
/// (RFC 9112 §6.3/§7.1): malformed chunk framing, Content-Length overflow, both
/// Content-Length and Transfer-Encoding present, conflicting duplicate
/// Content-Length, obs-fold header, oversized response, or an unsupported HTTP
/// version. Distinct from transport-level failures (timeout, connection reset)
/// so the retry loop can treat framing errors as NON-retryable: re-sending the
/// request cannot fix a deterministic parse error and (for non-idempotent
/// methods) would be unsafe.
class HttpFramingError : public std::runtime_error
{
public:
  explicit HttpFramingError(const std::string &what) : std::runtime_error(what) {}
};

/// \brief Thrown when a request failed BEFORE any byte was transmitted (a
/// connect/DNS resolution failure, or a sync-read-mode set failure — all of
/// which occur before the request is built or sent). Per RFC 9110 §9.2.2 such a
/// request was provably not processed, so the retry loop may safely re-send it
/// for ANY method (idempotent or not).
///
/// INVARIANT: this is a DIRECT subclass of std::runtime_error, never a subclass
/// of HttpFramingError. performRequest catches HttpFramingError first, so a
/// not-sent error must not be reachable through that branch.
class HttpRequestNotSentError : public std::runtime_error
{
public:
  explicit HttpRequestNotSentError(const std::string &what) : std::runtime_error(what) {}
};

/// \brief Thrown when an in-flight request is aborted because the HttpClient is
/// permanently closing (cleanup()/cancelInFlight()/~HttpClient). It is a DIRECT
/// subclass of std::runtime_error and a SIBLING of HttpFramingError and
/// HttpRequestNotSentError (never a subclass of either), so the mutual order of
/// the three catch clauses is irrelevant but ALL must precede any generic
/// `catch (const std::exception &)` on the propagation path.
///
/// TWO contracts:
///   (1) NEVER-RETRIED: the client is permanently closing, so every retry
///       re-fails identically. performRequest rethrows it without retrying.
///   (2) SEND-AMBIGUITY (RFC 9110 §9.2.2): this ONE type is raised both when the
///       request was PROVABLY NOT SENT (the publish-recheck, the pre-init gate,
///       and the acquireLease shutdown throw) AND when it MAY have been sent and
///       processed server-side before the connection was cut (a mid-body
///       cancel). It makes NO guarantee about whether the request reached or was
///       processed by the server; a caller MUST treat a cancelled request that
///       had already been sent as an UNKNOWN server-side outcome and never
///       assume "not processed". A single type is intentional: the sole consumer
///       (a client being destroyed) cannot act on the distinction, so the safe
///       (provably-not-sent) retry is deliberately forgone on those paths.
class HttpClientCancelledError : public std::runtime_error
{
public:
  using std::runtime_error::runtime_error;
};

/// \brief Thrown by acquireLease when Config::leaseAcquireTimeout elapses before
/// the exclusive per-host connection lease becomes available. A subclass of
/// HttpRequestNotSentError (hence an INDIRECT subclass of std::runtime_error) and
/// a SIBLING of HttpFramingError and HttpClientCancelledError — never a subclass
/// of those two.
///
/// The failure provably never touched the wire — acquireLease runs before any
/// connect or send — so a consumer may safely retry it for ANY method. It is
/// given a DISTINCT type so a caller can classify it by TYPE rather than by a
/// brittle substring match on the message: the message reads "timed out", which
/// the common find("timeout") predicate misses (tracker 2026-07-26-2 task-7.8 /
/// HD-7 Secondary row).
///
/// It IS a subclass of HttpRequestNotSentError: a lease-acquire timeout fires
/// before any connect or send, so the request provably never reached the wire and
/// is safely retryable for ANY method per RFC 9110 §9.2.2 — exactly the contract
/// HttpRequestNotSentError carries. performRequest's retry classification
/// (dynamic_cast<HttpRequestNotSentError*>) therefore retries it even for a
/// non-idempotent POST, while a caller wanting to count it distinctly still keys
/// on the more-derived HttpLeaseAcquireTimeoutError type. [Decision 2026-09-03,
/// arch DD-lease-acquire-not-sent: derive-from-not-sent SUPERSEDES the earlier
/// preserve-prior-sibling choice, which forwent that safe POST retry.]
class HttpLeaseAcquireTimeoutError : public HttpRequestNotSentError
{
public:
  explicit HttpLeaseAcquireTimeoutError(const std::string &what)
      : HttpRequestNotSentError(what)
  {
  }
};

/// \brief Thrown when the response read times out — the request was fully written
/// and the server MAY have applied it before the reply arrived, so this is a
/// POSSIBLY-SENT failure.
///
/// INVARIANT (tracker 2026-09-03-2): a DIRECT subclass of std::runtime_error and a
/// SIBLING of HttpRequestNotSentError / HttpFramingError / HttpClientCancelledError
/// — NEVER a subclass of any of them. It must NOT be a HttpRequestNotSentError (a
/// response-read timeout is not provably-not-sent, so it must stay non-retryable for
/// a non-idempotent method), and it must NOT be a HttpFramingError (performRequest
/// catches HttpFramingError first and never retries it — that would wrongly make a
/// response-read timeout on an IDEMPOTENT method non-retryable). It therefore falls
/// through to performRequest's generic gate, where `isIdempotentMethod(method) ||
/// isRequestProvablyNotSent(e)` retries it for an idempotent method (RFC 9110 §9.2.2
/// "means to know that the request semantics are actually idempotent") and not for a
/// POST. Given a distinct type so a caller can classify a response-read timeout by
/// TYPE rather than by a brittle substring on the message; the message text
/// ("HTTP response timeout") is preserved for any legacy substring consumer.
class HttpResponseTimeoutError : public std::runtime_error
{
public:
  explicit HttpResponseTimeoutError(const std::string &what) : std::runtime_error(what) {}
};

/// \brief Build the `Host` request field line (with trailing CRLF) per RFC 9110
/// §7.2 (Host = uri-host [ ':' port ]). The port is appended only when it is not
/// the scheme default, matching RFC 9110 §4.2.3 normalisation (a default port is
/// omitted). This is a deliberate deviation from the letter of RFC 9112 §3.2,
/// which wants the port whenever the URI carried one; HttpClient::ParsedUrl backs
/// an absent port with the scheme default, so it cannot tell an explicit `:80`
/// from an absent port, and the normalised form is the interop-safe one.
/// Extracted as a pure free function so all three cases (default, non-default,
/// https) are unit-testable without a socket (tracker 2026-07-26-10 task-1.7(a)).
/// PRECONDITION: `host` must already be a validated uri-host — the sole
/// production caller passes ParsedUrl::host from parseUrl, whose regex forbids
/// CR/LF and ':'. This helper does NOT sanitize: a CR/LF in `host` would inject
/// headers (the caller-header CRLF class is tracker-10 defect_7), and a bare IPv6
/// literal would need bracketing (`[::1]`) which parseUrl does not yet parse
/// (tracker-10 task-1.6) — neither is reachable through the current parse path.
inline std::string formatHostHeaderField(const std::string &host, std::uint16_t port, bool isHttps)
{
  const std::uint16_t defaultPort = isHttps ? 443 : 80;
  std::string line = "Host: " + host;
  if (port != defaultPort)
  {
    line += ":" + std::to_string(port);
  }
  line += "\r\n";
  return line;
}

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
    /// Hard cap on total received response bytes (headers + body), enforced
    /// DURING receipt to bound memory for a huge/absent-length/close-delimited
    /// server (RFC 9112 §6.3 close-delimited has no length). Distinct from
    /// jsonConfig.maxPayloadSize (a post-receipt JSON cap); the effective cap
    /// used is max(maxResponseBytes, jsonConfig.maxPayloadSize). Raise it for
    /// consumers that legitimately download large bodies.
    std::size_t maxResponseBytes;
    JsonConfig jsonConfig; // JSON parsing configuration

    Config()
        : connectTimeout(2000), requestTimeout(3000), maxRedirects(5), followRedirects(true),
          userAgent("Iora-HttpClient/1.0"), reuseConnections(true), connectionIdleTimeout(300),
          leaseAcquireTimeout(0), maxResponseBytes(16 * 1024 * 1024), jsonConfig{}
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

  // ── RFC 9112 §6.3/§7.1 response framing types (declared before the methods
  //    that use them in signatures — complete-class context covers bodies, not
  //    return/parameter types) ─────────────────────────────────────────────────

  /// \brief Body-length framing mode determined once from the header field map.
  enum class BodyMode
  {
    NoBody,         ///< HEAD / 1xx / 204 / 304 (RFC 9112 §6.3 rule 1)
    ContentLength,  ///< exactly N octets (rule 6)
    Chunked,        ///< chunked transfer coding (rule 4, chunked final)
    CloseDelimited  ///< read until connection close (rule 8 / non-final T-E)
  };

  struct Framing
  {
    BodyMode mode{BodyMode::CloseDelimited};
    std::uint64_t contentLength{0};
  };

  enum class FrameStatus
  {
    NeedMore,  ///< not an error — keep reading
    Complete,  ///< full message framed
    Malformed  ///< deterministic framing violation -> HttpFramingError
  };

  /// \brief Incremental chunked-decode state carried across receive iterations.
  struct ChunkState
  {
    std::size_t pos{0};        ///< absolute offset of the next unparsed byte
    std::string decoded;       ///< accumulated decoded body
    std::size_t messageEnd{0}; ///< offset just past the final CRLF (set on Complete)
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
  // Set by cleanup()/cancelInFlight()/~HttpClient so blocked lease waiters wake
  // and fail rather than deadlock (DD-A8). std::atomic so the receive loop and
  // the pre-send generic catch can read it WITHOUT _mutex (LEASE-7 forbids
  // holding _mutex across I/O) without a data race. Write-once monotonic
  // (false->true, never reset). DISCIPLINE (exhaustive, greppable): every STORE
  // is under _mutex with _cv.notify_all() under the lock (so the acquireLease CV
  // wait/notify handshake has no lost wakeup); reads that already hold _mutex
  // (acquireLease predicate/post-wait, performRequest pre-init, acquireConnection
  // publish-recheck) read it plainly under the lock. The LOCK-FREE reads (no
  // _mutex held) are exactly two sites, both using
  // _closing.load(std::memory_order_acquire): (1) executeRequest's pre-send
  // generic catch (inline, it converts e.what()); (2) executeRequest's local
  // `throwIfClosing` lambda, which is the single load routed to by all four
  // exchange-abort exits (send-failure and the receive-loop
  // PeerClosed/ShuttingDown/catch-all branches).
  mutable std::atomic<bool> _closing{false};

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

  /// \brief Classify whether an HTTP method is idempotent per RFC 9110 §9.2.2.
  /// \details GET, HEAD, PUT, DELETE, OPTIONS, and TRACE are idempotent; every
  ///   other token — POST, PATCH, CONNECT, extension methods, and any
  ///   non-canonical casing — is treated as non-idempotent (the safe default).
  ///   The match is EXACT and case-sensitive: RFC 9110 §9.1 declares the method
  ///   token case-sensitive, and HttpClient emits the caller's method verbatim,
  ///   so a non-canonical token (e.g. "get") is a distinct, unregistered method
  ///   and must not be assumed idempotent. Pure and stateless.
  static bool isIdempotentMethod(const std::string &method)
  {
    return method == "GET" || method == "HEAD" || method == "PUT" || method == "DELETE" ||
           method == "OPTIONS" || method == "TRACE";
  }

  /// \brief True iff \p e proves the request never reached the wire (RFC 9110
  /// §9.2.2 "some means to detect that the original request was never applied"), so
  /// it is safe to auto-retry even a non-idempotent method. This is the SINGLE home
  /// of the not-sent taxonomy: it matches HttpRequestNotSentError and, by
  /// inheritance, its subclass HttpLeaseAcquireTimeoutError, while EXCLUDING the
  /// siblings HttpClientCancelledError, HttpFramingError and HttpResponseTimeoutError
  /// (a response-read timeout is possibly-sent). Used by performRequest's own gate
  /// AND by JsonRpcClient's retry loop (which bypasses performRequest via
  /// postJson(...,0)), so the two never drift (tracker 2026-09-03-2). Pointer-form
  /// dynamic_cast: nullptr on failure, no std::bad_cast, includes subclasses.
  static bool isRequestProvablyNotSent(const std::exception &e)
  {
    return dynamic_cast<const HttpRequestNotSentError *>(&e) != nullptr;
  }

  /// \brief Perform synchronous GET request
  Response get(const std::string &url, const std::map<std::string, std::string> &headers = {},
               int retries = 0)
  {
    return performRequest("GET", url, "", headers, retries);
  }

  /// \brief Perform synchronous HEAD request. The response carries no body
  /// (RFC 9112 §6.3 rule 1), even when the server echoes a Content-Length.
  Response head(const std::string &url, const std::map<std::string, std::string> &headers = {},
                int retries = 0)
  {
    return performRequest("HEAD", url, "", headers, retries);
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

  /// \brief Cancel all in-flight work WITHOUT tearing down the transport/DNS.
  ///
  /// Sets the closing flag (so new work is refused and blocked acquireLease
  /// waiters wake and fail), wakes lease waiters, and closes every cached
  /// transport session — which unwinds any thread parked in receiveSync on that
  /// session (Transport::close is thread-safe and carries no I/O-thread guard).
  /// It deliberately does NOT stop the transport or DNS client: an in-flight
  /// thread must still unwind THROUGH them. This is the first half of cleanup().
  ///
  /// IDEMPOTENT: tracker 2026-07-26-2's destructor calls this explicitly and then
  /// again transitively via ~HttpClient -> cleanup(); a second call is a no-op
  /// (_closing already true, _connections already empty).
  ///
  /// noexcept: the only throw source is std::mutex::lock (std::system_error on
  /// unrecoverable corruption); notify_all, Transport::close (its enqueue
  /// self-catches) and _connections.clear() do not throw. Terminate-on-corruption
  /// beats leaking (mirrors ConnectionLease::release()).
  ///
  /// DRAIN BOUND: this wakes only threads parked in receiveSync (via the session
  /// close) and in acquireLease (via the CV). A thread parked in DNS resolution,
  /// connectSync or sendSync has no published session for the close-loop to see
  /// and unwinds only on its OWN timeout (DNS / connectTimeout / requestTimeout).
  void cancelInFlight() noexcept
  {
    std::lock_guard<std::mutex> lock(_mutex);

    // Refuse new work and wake blocked acquireLease waiters (DD-A8).
    _closing = true;
    _cv.notify_all();

    // Close all cached sessions so any thread parked in receiveSync on one
    // unwinds. Guard on _transport for parity with cleanup()/stop().
    if (_transport)
    {
      for (const auto &[hostPort, entry] : _connections)
      {
        _transport->close(entry.id);
      }
    }
    _connections.clear();
  }

  /// \brief Cleanup connections and resources.
  ///
  /// PRECONDITION: callers must not invoke cleanup() (or destroy the client)
  /// while requests are still in flight on OTHER threads. cleanup() wakes
  /// threads blocked in acquireLease (they fail fast), but a thread already past
  /// the lease and mid-I/O (connectSync/sendSync/receiveSync) will have its
  /// transport stopped underneath it — it surfaces an error rather than crashing,
  /// but join all request threads before cleanup/destruction for clean shutdown.
  ///
  /// This is cancelInFlight() plus the teardown tail. NOTE the tail (stopping the
  /// transport and DNS client) runs OUTSIDE _mutex — cancelInFlight() releases
  /// the lock before returning. This narrows the lock scope relative to the
  /// former single-lock cleanup(), which is safe under the no-concurrent-caller
  /// precondition above and because _closing (set inside cancelInFlight) already
  /// gates all new work before the tail runs.
  void cleanup()
  {
    cancelInFlight();

    if (_transport)
    {
      _transport->stop();
    }

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
  /// \throws HttpLeaseAcquireTimeoutError on lease-acquire timeout — a subclass of
  ///   HttpRequestNotSentError (the request never reached the wire), so HttpClient
  ///   retries it for ANY method per RFC 9110 §9.2.2 and a caller may also classify
  ///   it by its own more-derived type. HttpClientCancelledError on shutdown (never
  ///   retried).
  ConnectionLease acquireLease(const std::string &hostPort)
  {
    std::unique_lock<std::mutex> lock(_mutex);
    auto available = [&] { return _closing || _leasedHosts.find(hostPort) == _leasedHosts.end(); };

    if (_config.leaseAcquireTimeout.count() > 0)
    {
      if (!_cv.wait_for(lock, _config.leaseAcquireTimeout, available))
      {
        throw HttpLeaseAcquireTimeoutError(
          "HttpClient: timed out acquiring connection lease for " + hostPort);
      }
    }
    else
    {
      _cv.wait(lock, available);
    }

    if (_closing)
    {
      throw HttpClientCancelledError(
        "HttpClient: shutting down; cannot acquire connection lease for " + hostPort);
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

  /// \brief The outcome of acquireConnection: the session plus whether it is a
  /// REUSED pooled connection (true) or a freshly-opened one (false). executeRequest
  /// probes only a reused connection for a pre-write peer close (tracker 2026-09-03-2)
  /// — a fresh connect has no pending EOF, so probing it would only add latency.
  struct AcquiredConnection
  {
    SessionId id;
    bool reused;
  };

  /// \brief Reuse a cached connection for \p parsedUrl, or open a fresh one.
  ///
  /// MUST be called while holding the lease for parsedUrl.getHostPort(): the
  /// lease guarantees this thread is the sole owner of the host's connection
  /// slot, so _mutex is taken only for short bookkeeping (cache lookup/publish)
  /// and is RELEASED across DNS resolution and connectSync (LEASE-7 — the lease,
  /// not the mutex, serializes same-host work; holding _mutex across I/O would
  /// block lease releases and other hosts' bookkeeping).
  AcquiredConnection acquireConnection(const ParsedUrl &parsedUrl)
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
          return {it->second.id, /*reused=*/true};
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

    // (4) Publish the new connection (short critical section) with a
    //     publish-then-recheck against cancellation. Both this publish and
    //     cancelInFlight()'s close-loop run under _mutex, and _closing is set
    //     under _mutex before that loop, so serialization admits exactly two
    //     orders: canceller-first (we observe _closing here, close our own
    //     just-created session, and throw) or publisher-first (the cancel loop
    //     then sees the published session and closes it). No interleaving leaves
    //     a live session. Same register-or-observe-tombstone shape the transport
    //     uses (transport_impl.hpp).
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (_closing)
      {
        _transport->close(sessionId);
        throw HttpClientCancelledError("HttpClient: cancelled during connect for " + hostPort);
      }
      _connections[hostPort] = ConnectionEntry{sessionId, std::chrono::steady_clock::now()};
    }

    return {sessionId, /*reused=*/false};
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
      // Refuse before lazily building a fresh transport: a cancelled client must
      // not initialise and start a new exchange (read under _mutex, task-1.5).
      if (_closing)
      {
        throw HttpClientCancelledError("HttpClient: cancelled; not issuing " + method + " " + url);
      }
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
      catch (const HttpFramingError &e)
      {
        // Deterministic framing/parse violation (DD-11): retrying cannot fix it
        // and, for non-idempotent methods, would be unsafe. Never retry.
        iora::core::Logger::error("HttpClient: Request to " + url +
                                  " failed with a non-retryable framing error: " + e.what());
        throw;
      }
      catch (const HttpClientCancelledError &)
      {
        // The client is permanently closing: every retry re-fails identically,
        // so never retry (task-1.6). This guard MUST precede the generic
        // catch(std::exception&) below (HttpClientCancelledError IS-A
        // std::exception); its order relative to the HttpFramingError guard is
        // irrelevant (siblings).
        throw;
      }
      catch (const std::exception &e)
      {
        // Only retry when it is safe: the method is idempotent (RFC 9110 §9.2.2),
        // OR the request provably never reached the wire (HttpRequestNotSentError
        // from the pre-send region). A non-idempotent method that failed once the
        // request may have been transmitted must NOT be auto-retried — the server
        // may have already processed it, and re-sending would double-submit
        // (duplicate orders/charges/state mutations).
        const bool retryEligible = isIdempotentMethod(method) || isRequestProvablyNotSent(e);
        if (!retryEligible)
        {
          iora::core::Logger::warning(
            "HttpClient: " + method + " " + url +
            " failed after the request may have been sent; not auto-retried "
            "(non-idempotent method, RFC 9110 §9.2.2): " + e.what());
          throw;
        }

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

    // Single point of truth for the lock-free cancellation check on the
    // exchange-abort exits below (send-failure and the receive-loop
    // PeerClosed/ShuttingDown/catch-all branches). Consolidating the
    // load(acquire) here means a future edit cannot reintroduce a divergent
    // memory order at one of the sites. The pre-send generic catch above reads
    // _closing inline because it converts e.what() and lives in a different try.
    auto throwIfClosing = [this](const char *msg)
    {
      if (_closing.load(std::memory_order_acquire))
      {
        throw HttpClientCancelledError(msg);
      }
    };

    // Pre-send region (INVARIANT: transmits NO request byte — the request is not
    // even built until below). A failure here — connect/DNS resolution, or the
    // sync-mode toggle — means the request was provably not sent, so it is safe
    // to retry for ANY method (RFC 9110 §9.2.2). Rethrow such failures as
    // HttpRequestNotSentError so performRequest can distinguish them from
    // possibly-sent failures. The HttpFramingError guard comes FIRST so a (today
    // impossible) framing error in this region is never downgraded to retryable.
    // NOTE: parseUrl and acquireLease (above) sit BEFORE this wrap deliberately.
    // parseUrl's throw is left possibly-sent, which fails safe (it is
    // deterministic: a retry re-fails identically). acquireLease throws
    // HttpLeaseAcquireTimeoutError, itself an HttpRequestNotSentError, so it is
    // already classified not-sent and retry-eligible for any method (it never
    // touched the wire) without passing through this wrap. Neither risks a
    // double-submit. Re-verify this invariant if acquireConnection/setReadMode
    // ever change.
    SessionId sessionId{};
    try
    {
      const AcquiredConnection acquired = acquireConnection(parsedUrl);
      sessionId = acquired.id;

      // Set session to sync mode BEFORE sending request so response data gets
      // buffered correctly
      if (!_transport->setReadMode(sessionId, ReadMode::Sync))
      {
        dropConnection(hostPort, sessionId);
        throw std::runtime_error("Failed to set session to sync read mode");
      }

      // Pre-write liveness probe on a REUSED pooled socket (tracker 2026-09-03-2).
      // A keep-alive socket the peer closed while idle is still cached (within
      // connectionIdleTimeout); writing to it buffers locally and fails only on the
      // subsequent read — a POSSIBLY-SENT failure that must NOT be retried for a
      // non-idempotent POST. Detecting the close BEFORE writing any byte turns the
      // common idle-close case into a provably-not-sent HttpRequestNotSentError
      // (this catch's else-branch), so the JSON-RPC retry loop can safely retry it
      // on a fresh socket. A near-zero-timeout receiveSync distinguishes a dead
      // socket (PeerClosed — the transport left a closed tombstone in the sync
      // buffer at onClose) from a healthy quiescent one (Timeout, returned
      // immediately on the past deadline). BEST-EFFORT ONLY: peer close is observed
      // asynchronously, so this can return Timeout for a socket that has in fact
      // died (FIN not yet reflected, or its tombstone GC'd by an unrelated session's
      // close) — in which case the write proceeds and the post-write failure is
      // (correctly) not retried. The double-submit SAFETY guarantee rests on the
      // retry gate keying on HttpRequestNotSentError, NEVER on this probe. A fresh
      // connection is not probed (no pending EOF; probing only adds latency).
      // dropConnection MUST run before every throwing outcome so the not-sent retry
      // opens a FRESH socket rather than re-acquiring this same dead cached one.
      if (acquired.reused)
      {
        char probeByte = 0;
        std::size_t probeLen = sizeof(probeByte);
        auto probe =
          _transport->receiveSync(sessionId, &probeByte, probeLen, std::chrono::milliseconds(0));
        // The one "socket is healthy, keep it" outcome: an immediate Timeout (no
        // pending bytes, not closed). Every other outcome is handled below.
        const bool healthyQuiescent =
          probe.isErr() && probe.error().code == TransportError::Timeout;
        if (!healthyQuiescent)
        {
          // Any non-Timeout outcome means the reused socket is unusable BEFORE we
          // wrote a byte: PeerClosed (idle close), Ok-with-bytes (an unsolicited
          // server message such as 408 + Connection: close, RFC 9110 §15.5.9, or a
          // stale tail — reused connections are cached surplus-free, so these bytes
          // are never our own response), BufferOverflow (corrupt sync buffer),
          // Cancelled/ShuttingDown, or any other error. Evict, then throw a plain
          // runtime_error: the outer catches below re-classify it as
          // HttpClientCancelledError when _closing, else HttpRequestNotSentError —
          // correct for every pre-write outcome (no request byte was sent).
          dropConnection(hostPort, sessionId);
          const std::string detail =
            probe.isErr() ? probe.error().message : "unexpected bytes on idle connection";
          throw std::runtime_error("Reused connection is dead before send: " + detail);
        }
      }
    }
    catch (const HttpFramingError &)
    {
      throw;
    }
    catch (const HttpClientCancelledError &)
    {
      // Belt-and-braces (task-1.4 C-1): a cancellation raised at the
      // publish-recheck (acquireConnection) propagates as-is rather than being
      // laundered into the retryable HttpRequestNotSentError below. NOTE this is
      // defense-in-depth and NOT independently mutation-testable: it fires only
      // when _closing is true, and the generic catch below re-checks _closing
      // (monotonic) and would rethrow the same cancelled type — so removing this
      // guard is observationally equivalent for every reachable throw. It is
      // kept so correctness does not rely on _closing staying monotonic.
      throw;
    }
    catch (const std::exception &e)
    {
      // Publisher-first cancel: the publish succeeded (with _closing still
      // false), the canceller then closed the just-published session, and this
      // setReadMode/connect failure is that close surfacing. Surface it as a
      // (non-retryable) cancellation, not a retryable not-sent (task-1.4 H-3).
      // Lock-free read — no _mutex held here (enumerated in _closing's
      // discipline).
      if (_closing.load(std::memory_order_acquire))
      {
        throw HttpClientCancelledError(e.what());
      }
      throw HttpRequestNotSentError(e.what());
    }

    // Build HTTP request
    std::ostringstream request;
    request << method << " " << parsedUrl.getPathWithQuery() << " HTTP/1.1\r\n";
    // Host carries the port for a non-default port (tracker 2026-07-26-10
    // task-1.7(a) / defect_11) — this formerly emitted parsedUrl.host alone and
    // broke name-based vhosts and gateways. See formatHostHeaderField for the RFC
    // rule and the documented normalisation deviation.
    request << formatHostHeaderField(parsedUrl.host, parsedUrl.port, parsedUrl.isHttps());
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
      // If we are closing, this failure is a cancellation-induced close, not a
      // retryable transport error (task-1.7).
      throwIfClosing("HttpClient: cancelled while sending request");
      // sendSync errs ONLY when the transport failed to ENQUEUE the bytes — nothing
      // reached the socket, a provably-not-sent condition (RFC 9110 §9.2.2), so it
      // is safe to retry for ANY method. Raise HttpRequestNotSentError rather than a
      // generic runtime_error (tracker 2026-09-03-2); the TYPE now carries the
      // not-sent semantics. The message string is preserved BYTE-IDENTICALLY because
      // it is a cross-repo contract: tmc_edge_proxy TmcClient::classifyTransportError
      // documents and unit-tests this exact "what()" text. NOTE the asymmetry is
      // deliberate: sendSync returning OK does NOT prove transmission (async socket
      // write), so a later receive-side failure stays possibly-sent and non-retryable.
      throw HttpRequestNotSentError("Failed to send HTTP request: " + sendResult.error().message);
    }

    // Receive the response, framing it per RFC 9112 §6.3 as bytes arrive.
    // effectiveCap bounds the raw accumulation buffer AT ALL TIMES (DD-10).
    const std::size_t effectiveCap =
      std::max(_config.maxResponseBytes, _config.jsonConfig.maxPayloadSize);
    std::string responseData;
    char buffer[8192];
    bool headersDone = false;
    std::size_t headerScanPos = 0;
    std::size_t bodyStart = 0;
    Response resp;
    Framing framing;
    ChunkState chunkState;
    bool forceEvict = false;
    bool complete = false;

    try
    {
      while (!complete)
      {
        std::size_t len = sizeof(buffer);
        auto recvResult = _transport->receiveSync(sessionId, buffer, len, sendTimeout);

        if (recvResult.isOk() && len > 0)
        {
          responseData.append(buffer, len);
          if (responseData.size() > effectiveCap)
          {
            throw HttpFramingError("HTTP response exceeded the configured response cap");
          }
          complete = frameResponse(method, responseData, headersDone, headerScanPos, bodyStart,
                                   resp, framing, chunkState, forceEvict, effectiveCap);
        }
        else if (recvResult.isErr() && recvResult.error().code == TransportError::Timeout)
        {
          // POSSIBLY-SENT: the request was fully written, so a response-read timeout
          // must stay non-retryable for a non-idempotent method. Typed so a caller
          // classifies it by TYPE, not a substring; message preserved for any legacy
          // substring consumer (tracker 2026-09-03-2).
          throw HttpResponseTimeoutError("HTTP response timeout");
        }
        else if (recvResult.isErr() && recvResult.error().code == TransportError::BufferOverflow)
        {
          // Terminal, deterministic stream corruption (the transport's sync
          // buffer overflowed and dropped bytes; the flag is never cleared). A
          // retry would re-send and re-fail, so this is a non-retryable framing
          // error (DD-11) — an oversized response, like the receive cap.
          throw HttpFramingError("HTTP response exceeded the sync receive buffer (overflow)");
        }
        else if (recvResult.isErr() && recvResult.error().code == TransportError::ShuttingDown)
        {
          // Defense-in-depth: cancelInFlight() (which does NOT stop the transport)
          // wakes a parked receiveSync with PeerClosed, so this ShuttingDown guard
          // is reached only if the transport is being stopped under a parked
          // receive — the concurrent-teardown scenario cleanup()'s precondition
          // forbids and tracker 2026-07-26-2's blocking destructor is what makes
          // safe. Its discriminating test therefore lands with that tracker.
          throwIfClosing("HttpClient: cancelled (transport shutting down)");
          throw std::runtime_error("HTTP transport shutting down before response complete");
        }
        else if (recvResult.isErr() && recvResult.error().code == TransportError::PeerClosed)
        {
          // A cancellation-induced close is INDISTINGUISHABLE at the framing
          // layer from a legitimate close-delimited end-of-body (RFC 9112 §6.3:
          // "no way to distinguish a successfully completed, close-delimited
          // message from a partially received message"). The local closing flag
          // is the only correct discriminator, so guard ALL framing modes BEFORE
          // the end-of-body test: if we are closing, this close is a
          // cancellation, never a (possibly truncated) 200 (task-1.7).
          throwIfClosing("HttpClient: cancelled before response complete (peer closed)");
          // Graceful peer close (receiveSync drains buffered bytes before
          // reporting PeerClosed). For a close-delimited body this IS the
          // end-of-body (RFC 9112 §6.3 rule 8); otherwise it is a truncation.
          if (headersDone && framing.mode == BodyMode::CloseDelimited)
          {
            resp.body = responseData.substr(bodyStart);
            forceEvict = true; // a close-delimited connection is never reusable
            complete = true;
          }
          else
          {
            throw std::runtime_error("Connection closed before receiving complete HTTP response");
          }
        }
        else if (recvResult.isErr())
        {
          // Catch-all for any other transport error code. A cancellation is not
          // guaranteed to surface as PeerClosed, so guard this exit too
          // (task-1.7) — otherwise a cancel arriving here escapes as a retryable
          // generic error. Defense-in-depth: no cancel path observed reaches this
          // branch today (cancelInFlight wakes receiveSync with PeerClosed), so
          // like the ShuttingDown guard its discriminating test lands with
          // tracker 2026-07-26-2. Worst case if unguarded is one ~100 ms backoff
          // before acquireLease's per-attempt _closing recheck re-classifies it.
          throwIfClosing("HttpClient: cancelled before response complete (transport error)");
          throw std::runtime_error(
            "Connection closed before receiving complete HTTP response (transport error " +
            std::to_string(static_cast<int>(recvResult.error().code)) + ": " +
            recvResult.error().message + ")");
        }
      }

      // Reuse the connection only if the client allows it, the server did not
      // signal close, there are no surplus bytes, and the body was not
      // close-delimited (DD-6/DD-9/DD-A9).
      const bool reusable = _config.reuseConnections && !responseRequestsClose(resp) &&
                            !forceEvict && framing.mode != BodyMode::CloseDelimited;
      if (reusable)
      {
        // Keep the connection warm (async mode). If the mode switch fails the
        // socket is suspect — evict rather than cache a known-bad connection.
        if (!_transport->setReadMode(sessionId, ReadMode::Async))
        {
          dropConnection(hostPort, sessionId);
        }
      }
      else
      {
        dropConnection(hostPort, sessionId);
      }
      return resp;
    }
    catch (...)
    {
      // A receive/parse/framing failure means the connection is suspect. Evict
      // it so no later request — including a retry — reuses a dead socket.
      dropConnection(hostPort, sessionId);
      throw;
    }
  }

  /// \brief Frame the accumulated response bytes (RFC 9112 §6.3). Parses the
  /// header block once headers complete, skips interim 1xx responses (DD-12),
  /// then evaluates body completeness per the framing mode. Returns true when a
  /// complete final response is framed (resp.body set; forceEvict set on surplus
  /// or close-delimited). Returns false to read more. Throws HttpFramingError on
  /// a deterministic framing violation.
  bool frameResponse(const std::string &method, std::string &data, bool &headersDone,
                     std::size_t &headerScanPos, std::size_t &bodyStart, Response &resp,
                     Framing &framing, ChunkState &chunkState, bool &forceEvict,
                     std::size_t effectiveCap) const
  {
    while (true)
    {
      if (!headersDone)
      {
        // Incremental header-terminator search: resume from headerScanPos so a
        // header block delivered in many small reads is not re-scanned from 0
        // each iteration (O(n^2) / CPU-amplification). Back up 3 bytes so a
        // "\r\n\r\n" straddling a previous append boundary is still found.
        std::size_t he = data.find("\r\n\r\n", headerScanPos);
        if (he == std::string::npos)
        {
          headerScanPos = (data.size() >= 3) ? data.size() - 3 : 0;
          return false; // need more header bytes (bounded by the caller's cap)
        }
        resp = Response{};
        parseHeaderBlock(data.substr(0, he), resp);
        if (resp.statusCode >= 100 && resp.statusCode < 200)
        {
          // Interim 1xx response (RFC 9112 §15.2): discard it wholesale and
          // continue scanning the remaining bytes for the final response. The
          // discarded bytes do not count against the cap once removed; the scan
          // cursor resets since the buffer shifted.
          data.erase(0, he + 4);
          headerScanPos = 0;
          continue;
        }
        headersDone = true;
        bodyStart = he + 4;
        framing = determineFraming(method, resp, effectiveCap);
        chunkState = ChunkState{};
        chunkState.pos = bodyStart;
      }

      switch (framing.mode)
      {
      case BodyMode::NoBody:
        resp.body.clear();
        if (data.size() > bodyStart)
        {
          forceEvict = true; // unexpected bytes after a bodyless response
        }
        return true;
      case BodyMode::ContentLength:
        if (data.size() - bodyStart < framing.contentLength)
        {
          return false;
        }
        // Narrowing is safe: contentLength <= effectiveCap <= SIZE_MAX (rejected
        // up front in determineFraming if it exceeds the cap).
        resp.body = data.substr(bodyStart, static_cast<std::size_t>(framing.contentLength));
        if (data.size() > bodyStart + framing.contentLength)
        {
          forceEvict = true; // surplus beyond the framed message
        }
        return true;
      case BodyMode::Chunked:
      {
        FrameStatus fs = advanceChunked(data, effectiveCap, chunkState);
        if (fs == FrameStatus::NeedMore)
        {
          return false;
        }
        if (fs == FrameStatus::Malformed)
        {
          throw HttpFramingError("malformed chunked response body");
        }
        resp.body = chunkState.decoded;
        if (data.size() > chunkState.messageEnd)
        {
          forceEvict = true;
        }
        return true;
      }
      case BodyMode::CloseDelimited:
        return false; // completes only on PeerClosed (handled by the caller)
      }
      return false;
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

  // ── RFC 9112 §6.3/§7.1 response message-body framing ───────────────────────

  static bool isHexDigit(char c)
  {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  }

  /// \brief Parse [b,e) as a full-token unsigned integer (DD-8). Rejects any
  /// trailing junk, leading sign/whitespace, and overflow. No exceptions, no
  /// locale (std::from_chars). Returns false on any violation.
  static bool parseFullUInt(const char *b, const char *e, int base, std::uint64_t &out)
  {
    if (b == e)
    {
      return false;
    }
    auto r = std::from_chars(b, e, out, base);
    return r.ec == std::errc() && r.ptr == e;
  }

  static bool ciEquals(const std::string &a, const std::string &b)
  {
    if (a.size() != b.size())
    {
      return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i)
    {
      if (CaseInsensitiveCompare::asciiLower(static_cast<unsigned char>(a[i])) !=
          CaseInsensitiveCompare::asciiLower(static_cast<unsigned char>(b[i])))
      {
        return false;
      }
    }
    return true;
  }

  /// \brief Parse a Content-Length value, honoring RFC 9112 §6.3 rule 5: a
  /// comma-separated list is valid only if every element is a valid, identical
  /// number (-> that value); any invalid or differing element is a framing error.
  std::uint64_t parseContentLength(const std::string &v) const
  {
    std::uint64_t result = 0;
    bool have = false;
    std::size_t pos = 0;
    while (pos <= v.size())
    {
      std::size_t comma = v.find(',', pos);
      std::size_t end = (comma == std::string::npos) ? v.size() : comma;
      std::size_t a = v.find_first_not_of(" \t", pos);
      std::size_t b = (end == 0) ? std::string::npos : v.find_last_not_of(" \t", end - 1);
      std::uint64_t val = 0;
      if (a == std::string::npos || a >= end || b == std::string::npos || b < a ||
          !parseFullUInt(v.data() + a, v.data() + b + 1, 10, val))
      {
        throw HttpFramingError("invalid Content-Length: " + v);
      }
      if (have && val != result)
      {
        throw HttpFramingError("conflicting Content-Length list: " + v);
      }
      result = val;
      have = true;
      if (comma == std::string::npos)
      {
        break;
      }
      pos = comma + 1;
    }
    if (!have)
    {
      throw HttpFramingError("empty Content-Length");
    }
    return result;
  }

  /// \brief True if the FINAL coding in a Transfer-Encoding list is "chunked"
  /// (RFC 9112 §6.1: codings are listed in applied order; the last is outermost
  /// on the wire). Tokenized, OWS-trimmed, ASCII-case-folded equality.
  bool transferEncodingFinalIsChunked(const std::string &v) const
  {
    std::string lastToken;
    std::size_t pos = 0;
    while (pos <= v.size())
    {
      std::size_t comma = v.find(',', pos);
      std::size_t end = (comma == std::string::npos) ? v.size() : comma;
      std::size_t a = v.find_first_not_of(" \t", pos);
      std::size_t b = (end == 0) ? std::string::npos : v.find_last_not_of(" \t", end - 1);
      if (a != std::string::npos && a < end && b != std::string::npos && b >= a)
      {
        lastToken = v.substr(a, b - a + 1);
      }
      if (comma == std::string::npos)
      {
        break;
      }
      pos = comma + 1;
    }
    return ciEquals(lastToken, "chunked");
  }

  /// \brief Parse the status line + header fields of \p headerSection into
  /// \p resp, enforcing RFC 9112: HTTP/1.x only (DD-13), reject obs-fold (§5.2),
  /// reject conflicting duplicate Content-Length (§6.3 rule 5). Throws
  /// HttpFramingError on any violation.
  void parseHeaderBlock(const std::string &hs, Response &resp) const
  {
    std::size_t nl = hs.find("\r\n");
    std::string statusLine = (nl == std::string::npos) ? hs : hs.substr(0, nl);

    if (statusLine.rfind("HTTP/", 0) != 0)
    {
      throw HttpFramingError("invalid HTTP status line: " + statusLine);
    }
    std::size_t sp1 = statusLine.find(' ');
    if (sp1 == std::string::npos || sp1 <= 5)
    {
      throw HttpFramingError("invalid HTTP status line: " + statusLine);
    }
    std::string version = statusLine.substr(5, sp1 - 5);
    if (version != "1.0" && version != "1.1")
    {
      throw HttpFramingError("unsupported HTTP version: " + version);
    }
    std::size_t codeStart = sp1 + 1;
    std::size_t sp2 = statusLine.find(' ', codeStart);
    std::size_t codeEnd = (sp2 == std::string::npos) ? statusLine.size() : sp2;
    std::uint64_t code = 0;
    if (!parseFullUInt(statusLine.data() + codeStart, statusLine.data() + codeEnd, 10, code) ||
        code > 999)
    {
      throw HttpFramingError("invalid status code in: " + statusLine);
    }
    resp.httpVersion = version;
    resp.statusCode = static_cast<int>(code);
    resp.statusText = (sp2 == std::string::npos) ? "" : statusLine.substr(sp2 + 1);

    if (nl == std::string::npos)
    {
      return; // status line only, no header fields
    }
    std::size_t pos = nl + 2;
    bool haveCL = false;
    std::string clValue;
    while (pos < hs.size())
    {
      std::size_t lnl = hs.find("\r\n", pos);
      std::size_t lineEnd = (lnl == std::string::npos) ? hs.size() : lnl;
      if (lineEnd == pos)
      {
        pos = lineEnd + 2;
        continue;
      }
      if (hs[pos] == ' ' || hs[pos] == '\t')
      {
        throw HttpFramingError("obs-fold header line is not allowed");
      }
      std::size_t colon = hs.find(':', pos);
      if (colon == std::string::npos || colon >= lineEnd)
      {
        throw HttpFramingError("malformed header line (no colon)");
      }
      std::string name = hs.substr(pos, colon - pos);
      std::string value = hs.substr(colon + 1, lineEnd - (colon + 1));
      auto trim = [](std::string &s)
      {
        std::size_t a = s.find_first_not_of(" \t");
        if (a == std::string::npos)
        {
          s.clear();
          return;
        }
        std::size_t b = s.find_last_not_of(" \t");
        s = s.substr(a, b - a + 1);
      };
      trim(name);
      trim(value);
      if (ciEquals(name, "Content-Length"))
      {
        if (haveCL && value != clValue)
        {
          throw HttpFramingError("conflicting duplicate Content-Length");
        }
        haveCL = true;
        clValue = value;
      }
      resp.headers[name] = value;
      pos = (lnl == std::string::npos) ? hs.size() : lnl + 2;
    }
  }

  /// \brief Determine the body framing mode once, in RFC 9112 §6.3 rule order.
  Framing determineFraming(const std::string &method, const Response &resp,
                           std::size_t effectiveCap) const
  {
    // Rule 2: a 2xx to CONNECT is a tunnel — declared non-goal (this client
    // never issues CONNECT). Treat defensively as a framing error if it appears.
    if (method == "CONNECT")
    {
      throw HttpFramingError("CONNECT tunnel responses are not supported");
    }
    const int sc = resp.statusCode;
    // Rule 1: HEAD and 1xx/204/304 have no body regardless of header fields.
    if (method == "HEAD" || sc == 204 || sc == 304 || (sc >= 100 && sc < 200))
    {
      return {BodyMode::NoBody, 0};
    }
    auto teIt = resp.headers.find("Transfer-Encoding");
    const bool hasTE = teIt != resp.headers.end();
    auto clIt = resp.headers.find("Content-Length");
    const bool hasCL = clIt != resp.headers.end();
    // Rule 3: both present -> reject (request/response smuggling).
    if (hasTE && hasCL)
    {
      throw HttpFramingError("response has both Content-Length and Transfer-Encoding");
    }
    // Rule 4: Transfer-Encoding present -> chunked iff it is the final coding,
    // else close-delimited (the outer non-chunked coding is not self-delimiting).
    if (hasTE)
    {
      if (transferEncodingFinalIsChunked(teIt->second))
      {
        return {BodyMode::Chunked, 0};
      }
      return {BodyMode::CloseDelimited, 0};
    }
    // Rules 5/6: Content-Length -> read exactly N (validated, capped).
    if (hasCL)
    {
      std::uint64_t n = parseContentLength(clIt->second);
      // Up-front reject of an oversized declared length. The mid-receive cap
      // (on headers+body) is the authoritative bound; this check measures the
      // body alone, so the effective body limit is effectiveCap minus the header
      // bytes. Both are conservative — they only ever reject, never truncate.
      if (n > effectiveCap)
      {
        throw HttpFramingError("Content-Length exceeds the response cap");
      }
      return {BodyMode::ContentLength, n};
    }
    // Rule 8: otherwise close-delimited.
    return {BodyMode::CloseDelimited, 0};
  }

  /// \brief Advance the incremental chunked parser over \p buf (RFC 9112 §7.1).
  /// Resumes at st.pos so only newly-arrived bytes are scanned (no O(n^2)).
  /// Tolerates BWS around chunk-ext (§7.1.1/§5.6.3 recipient MUST), ignores
  /// chunk extensions, requires CRLF terminators (rejects lone LF / bare CR),
  /// and consumes the trailer-section through the final CRLF.
  FrameStatus advanceChunked(const std::string &buf, std::size_t effectiveCap, ChunkState &st) const
  {
    while (true)
    {
      std::size_t nl = buf.find('\n', st.pos);
      if (nl == std::string::npos)
      {
        return FrameStatus::NeedMore;
      }
      if (nl == 0 || buf[nl - 1] != '\r')
      {
        return FrameStatus::Malformed; // lone LF / bare-CR-less terminator
      }
      std::size_t lineEnd = nl - 1; // index of '\r'
      std::size_t p = st.pos;
      std::size_t hexEnd = p;
      while (hexEnd < lineEnd && isHexDigit(buf[hexEnd]))
      {
        ++hexEnd;
      }
      if (hexEnd == p)
      {
        return FrameStatus::Malformed; // no chunk-size digits
      }
      std::uint64_t chunkSize = 0;
      if (!parseFullUInt(buf.data() + p, buf.data() + hexEnd, 16, chunkSize) ||
          chunkSize > effectiveCap)
      {
        return FrameStatus::Malformed; // overflow / too large
      }
      // After the hex run, the next significant char must be ';' (chunk-ext) or
      // the CRLF. BWS is permitted ONLY before a ';' (RFC 9112 §7.1.1 + RFC 9110
      // §5.6.3 recipient-MUST-tolerate); whitespace before the CRLF with no
      // chunk-ext (e.g. "5 \r\n"), or any other junk, is malformed.
      std::size_t q = hexEnd;
      bool sawBws = false;
      while (q < lineEnd && (buf[q] == ' ' || buf[q] == '\t'))
      {
        ++q;
        sawBws = true;
      }
      if (q < lineEnd)
      {
        if (buf[q] != ';')
        {
          return FrameStatus::Malformed; // junk after chunk-size
        }
        // ';' begins a chunk-ext — ignored (skipped to CRLF below).
      }
      else if (sawBws)
      {
        return FrameStatus::Malformed; // trailing WS before CRLF with no chunk-ext
      }
      std::size_t dataStart = nl + 1;
      if (chunkSize == 0)
      {
        // last-chunk: consume trailer-section field-lines through the final CRLF.
        std::size_t tp = dataStart;
        while (true)
        {
          std::size_t tnl = buf.find('\n', tp);
          if (tnl == std::string::npos)
          {
            return FrameStatus::NeedMore;
          }
          if (tnl == 0 || buf[tnl - 1] != '\r')
          {
            return FrameStatus::Malformed;
          }
          if (tnl - 1 == tp) // empty line (CRLF) terminates the body
          {
            st.messageEnd = tnl + 1;
            return FrameStatus::Complete;
          }
          tp = tnl + 1;
        }
      }
      // Need chunkSize data octets followed by CRLF. Use subtraction-based
      // bounds (never `dataStart + chunkSize + 2`, which can integer-overflow
      // for a chunkSize near SIZE_MAX when a caller has raised the cap).
      if (buf.size() < dataStart || buf.size() - dataStart < chunkSize ||
          buf.size() - dataStart - chunkSize < 2)
      {
        return FrameStatus::NeedMore;
      }
      if (buf[dataStart + chunkSize] != '\r' || buf[dataStart + chunkSize + 1] != '\n')
      {
        return FrameStatus::Malformed;
      }
      st.decoded.append(buf, dataStart, static_cast<std::size_t>(chunkSize));
      st.pos = dataStart + chunkSize + 2;
    }
  }
};

} // namespace network
} // namespace iora