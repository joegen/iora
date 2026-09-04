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

#include "iora/crypto/secure_rng.hpp"
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

/// \brief Thrown when a CALLER-SUPPLIED request header name or value fails RFC
/// 9110 validation: a name that is not a valid token (§5.6.2 tchar) or a value
/// carrying a forbidden octet (§5.5 field-value grammar — any octet < 0x20 other
/// than HTAB, or 0x7F/DEL). A DIRECT subclass of HttpFramingError so
/// performRequest's `catch (const HttpFramingError &)` rejects it WITHOUT retry:
/// a header-injection / non-token name is a deterministic caller error, not a
/// transient failure, and must never be re-sent on an idempotent method. It is
/// deliberately NOT an HttpRequestNotSentError subclass — the "not sent => safe
/// to retry ANY method" contract must not be misapplied to a caller bug
/// (tracker 2026-07-26-10 task-1.2 / defect_1 / defect_3).
class HttpInvalidHeaderError : public HttpFramingError
{
public:
  explicit HttpInvalidHeaderError(const std::string &what) : HttpFramingError(what) {}
};

/// \brief Thrown by parseUrl for a URL it refuses: a malformed URL, a URL
/// carrying userinfo (`user@` / `user:pass@` — credentials must never land in
/// the request-target, RFC 9112 §3.2), a bracketed IPv6 literal (not parsed —
/// see the decision in parseUrl), or a port outside 1..65535 or that overflows
/// (defect_7 / defect_15). It is a subclass of std::invalid_argument so the
/// cross-repo contract that a malformed URL surfaces as std::invalid_argument is
/// preserved (tmc_edge_proxy TmcStatefulPrimitives catches std::invalid_argument
/// to turn it into a fail action; the malformed-URL what() string is kept
/// byte-identical). performRequest adds a dedicated non-retry catch for this
/// type BEFORE its generic catch, so a deterministic URL fault is NOT retried on
/// an idempotent method (it previously escaped as a raw std::invalid_argument /
/// std::out_of_range into the retry path). Kept OUT of the HttpFramingError
/// hierarchy precisely to remain a std::invalid_argument for that contract
/// (tracker 2026-07-26-10 task-1.6).
class HttpInvalidUrlError : public std::invalid_argument
{
public:
  explicit HttpInvalidUrlError(const std::string &what) : std::invalid_argument(what) {}
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

/// \brief Thrown when a single request/response exchange exceeds
/// Config::totalRequestTimeout — the whole-exchange deadline computed once
/// BEFORE connect (defect_14, a client-side slowloris bound). Distinct from the
/// PER-iteration HttpResponseTimeoutError: a peer that trickles one byte per
/// window (or floods well-formed interim 1xx responses) resets the per-iteration
/// timer forever, so only an outer deadline bounds it.
///
/// It is a subclass of HttpFramingError specifically so performRequest's
/// `catch (const HttpFramingError &)` rejects it WITHOUT retry: the deadline is a
/// deterministic terminal condition for THIS attempt, and re-sending after
/// exponential backoff would just re-incur it (and for a non-idempotent method
/// would be unsafe). Making it non-retryable is what bounds total wall-clock to
/// ~1x the deadline rather than (retries+1)x (task-1.10).
class HttpExchangeDeadlineError : public HttpFramingError
{
public:
  explicit HttpExchangeDeadlineError(const std::string &what) : HttpFramingError(what) {}
};

/// \brief Thrown when the transport connect phase (TCP handshake, and for an https
/// endpoint the TLS handshake) exceeds its deadline — i.e. connectSync returns
/// TransportError::Timeout. The request was PROVABLY NOT SENT (no request byte is
/// written until after a connection is established), so it is safely retryable for
/// ANY method per RFC 9110 §9.2.2.
///
/// It IS a subclass of HttpRequestNotSentError, exactly like HttpLeaseAcquireTimeoutError
/// and for the same reason: this failure never reached the wire. Retry classification
/// (isRequestProvablyNotSent, a dynamic_cast to HttpRequestNotSentError) therefore
/// treats it identically to the plain HttpRequestNotSentError it replaces on the
/// connect-timeout path — NO retry-behaviour change. It is given a DISTINCT type
/// SOLELY so a caller can classify a connect timeout by TYPE for a timeoutRequests
/// metric (tracker 2026-09-03-3); the classification is keyed on the structured
/// TransportError::Timeout code, never on the message text. The transport's own
/// message is passed through unaltered (e.g. "...connectSync timed out" from the
/// connectSync deadline, or "...Connect timeout" from the tcp_engine watchdog — both
/// set code == Timeout), but that text is DEFENSIVE-ONLY: no consumer keys on it, and
/// none should — a substring match on transport messages is exactly the fragility this
/// typing exists to remove.
///
/// INVARIANT: same visibility/inline shape as its sibling timeout types so the
/// dynamic_cast in the separately-compiled jsonrpc_client module resolves across the
/// shared-object boundary (the existing typed timeouts already rely on this RTTI
/// unification).
class HttpConnectTimeoutError : public HttpRequestNotSentError
{
public:
  explicit HttpConnectTimeoutError(const std::string &what) : HttpRequestNotSentError(what) {}
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

/// \brief RFC 9110 §5.6.2 tchar: the characters permitted in a header field
/// NAME (token = 1*tchar). Implemented as an ALLOW-LIST — a deny-list of
/// separators is error-prone and leaks '<', '>', DEL and high bytes (tracker
/// 2026-07-26-10 task-1.2 / web L2). tchar = DIGIT / ALPHA /
/// "!#$%&'*+-.^_`|~".
inline bool isHttpTokenChar(unsigned char c)
{
  if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
  {
    return true;
  }
  switch (c)
  {
    case '!': case '#': case '$': case '%': case '&': case '\'': case '*':
    case '+': case '-': case '.': case '^': case '_': case '`': case '|': case '~':
      return true;
    default:
      return false;
  }
}

/// \brief A valid header field NAME is a non-empty RFC 9110 §5.6.2 token.
/// Rejects an empty name, any whitespace (incl. a trailing space before the
/// colon — RFC 9112 §5.1), and every separator/control octet (tracker
/// 2026-07-26-10 defect_3 / defect_10). Extracted as a pure free function so it
/// is unit-testable without a socket.
inline bool isValidHttpFieldName(const std::string &name)
{
  if (name.empty())
  {
    return false;
  }
  for (char ch : name)
  {
    if (!isHttpTokenChar(static_cast<unsigned char>(ch)))
    {
      return false;
    }
  }
  return true;
}

/// \brief A valid header field VALUE per RFC 9110 §5.5: field-vchar (VCHAR
/// %x21-7E / obs-text %x80-FF) optionally interleaved with SP / HTAB. So REJECT
/// any octet < 0x20 other than HTAB (0x09), PLUS 0x7F (DEL); obs-text
/// (0x80-0xFF) is permitted. This rejects CR, LF and NUL (header / request-line
/// injection) AND the historically line-terminator-treated VT (0x0B) / FF
/// (0x0C) that a naive CR/LF/NUL filter passes (tracker 2026-07-26-10 defect_1 /
/// task-1.2). Leading/trailing OWS is NOT stripped here (recipients strip it;
/// documented no-op).
inline bool isValidHttpFieldValue(const std::string &value)
{
  for (char ch : value)
  {
    const unsigned char c = static_cast<unsigned char>(ch);
    if (c == '\t')
    {
      continue; // HTAB is permitted between field-vchar runs
    }
    if (c < 0x20 || c == 0x7F)
    {
      return false;
    }
  }
  return true;
}

/// \brief ASCII case-insensitive string equality (RFC 9110 §5.1: field names
/// are compared case-insensitively). A free function so the request-side
/// controlled-header guard below and HttpClient's response-side parser share
/// ONE implementation (tracker 2026-07-26-10 task-1.3).
inline bool ciEqualsAscii(const std::string &a, const std::string &b)
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

/// \brief The request header field names HttpClient controls itself and a
/// caller MUST NOT supply. Supplying any produces a duplicate or conflicting
/// framing field — the CL/CL desync (RFC 9112 §6.3), the TE.CL desync (§6.1/
/// §6.2), a duplicate Host a server answers 400 (§3.2) — or a connection /
/// expectation control HttpClient owns (Connection is driven by
/// Config::reuseConnections, not a header; Expect:100-continue cannot be
/// honored because HttpClient sends the full request + body in one shot,
/// RFC 9110 §10.1.1, so REJECT is the conservative client policy). The
/// TE-family (Transfer-Encoding, TE, Trailer, Upgrade) is rejected outright:
/// §6.1 says a client must not send Transfer-Encoding unless it knows the
/// server handles HTTP/1.1, and HttpClient cannot chunk (tracker
/// 2026-07-26-10 task-1.3 / defect_2 / defect_4). Matched ASCII
/// case-insensitively because the caller map is a case-SENSITIVE std::map, so a
/// mixed-case `content-length:` / `TRANSFER-ENCODING:` would otherwise bypass
/// the guard and reinstate the desync.
///
/// DELIBERATELY ABSENT: Content-Encoding / Accept-Encoding — JsonRpcClient
/// self-injects `Content-Encoding: gzip` into the caller map AFTER its own
/// validation (task-1.1 FLAG-1), so rejecting content-coding here would break
/// JSON-RPC request-gzip; that stays a JsonRpcClient-layer concern. User-Agent
/// is also absent: HttpClient lets the caller OVERRIDE it (emitted downstream
/// only when the caller supplied none) rather than rejecting. Proxy-Connection
/// and Keep-Alive are non-framing hop-by-hop headers with no in-tree caller
/// (task-1.1 sweep) and no smuggling primitive, so they are not rejected (YAGNI
/// — the guard is scoped to framing-critical/owned controls, not general
/// duplicate suppression: a caller's non-controlled ci-duplicate X-Foo/x-foo
/// still emits both lines, which is acceptable).
inline bool isFramingControlledHeaderName(const std::string &name)
{
  static const char *const kControlled[] = {
      "Host", "Content-Length", "Connection", "Transfer-Encoding",
      "TE",   "Trailer",        "Upgrade",    "Expect"};
  for (const char *candidate : kControlled)
  {
    if (ciEqualsAscii(name, candidate))
    {
      return true;
    }
  }
  return false;
}

/// \brief Set a library-owned header on a case-SENSITIVE request-header map,
/// first removing ANY ASCII case-variant of \p name the caller may have
/// supplied. A plain `headers[name] = value` on a case-sensitive std::map would
/// leave a mixed-case caller key (e.g. "content-type") live alongside the
/// canonical one, emitting TWO field-lines on the wire — a duplicate
/// representation/framing field (defect_2 class). Used where the library's value
/// is authoritative and unconditional (postFile / postJson Content-Type); it is
/// NOT the caller-overridable path (postStream sets its SSE defaults only when
/// absent). (tracker 2026-07-26-10 task-1.5 / task-1.4 round-2 review.)
inline void setLibraryOwnedHeader(std::map<std::string, std::string> &headers,
                                  const std::string &name, const std::string &value)
{
  for (auto it = headers.begin(); it != headers.end();)
  {
    if (ciEqualsAscii(it->first, name))
    {
      it = headers.erase(it);
    }
    else
    {
      ++it;
    }
  }
  headers[name] = value;
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
    /// Per-connect timeout. NOTE (defect_9): silently clamped to
    /// min(connectTimeout, 200ms) for loopback (127.0.0.1 / ::1, and the
    /// hostname "localhost" which resolveHostAddress maps to 127.0.0.1) — a
    /// loopback connect resolves near-instantly, so this value is NOT observable
    /// against loopback. To exercise a real connect timeout, target a
    /// non-routable address such as 192.0.2.1 (TEST-NET-1).
    std::chrono::milliseconds connectTimeout;
    std::chrono::milliseconds requestTimeout;
    /// RESERVED AND INERT (defect_5): HttpClient does NOT follow redirects — no
    /// Location / 3xx handling exists. These two fields are retained only for
    /// source/ABI compatibility with HttpClientPool::Config, which mirrors them;
    /// nothing reads them. followRedirects defaults to FALSE so the config does
    /// not advertise a capability the client lacks (it formerly defaulted true).
    /// Do not add redirect logic keyed on these without a design pass.
    int maxRedirects;
    bool followRedirects;
    std::string userAgent;
    bool reuseConnections;
    std::chrono::seconds connectionIdleTimeout;
    /// Maximum time a request blocks waiting to acquire the exclusive per-host
    /// connection lease before failing with a distinct timeout error. Zero (the
    /// default) means wait indefinitely, preserving pre-lease blocking semantics.
    std::chrono::milliseconds leaseAcquireTimeout;
    /// Whole-exchange deadline for a single request attempt (defect_14). Unlike
    /// requestTimeout, which re-arms per receiveSync iteration and so is reset by
    /// any byte from a slow-trickle / interim-1xx-flooding peer, this bounds the
    /// TOTAL time from just before connect through the final byte. Computed ONCE
    /// per attempt, so a slow connect composes with a slow body. On expiry the
    /// attempt throws HttpExchangeDeadlineError (NON-retryable), bounding total
    /// wall-clock to ~1x this value. Zero (the DEFAULT) DISABLES the bound
    /// (opt-in — preserves the prior unbounded behavior; set a positive value to
    /// harden a live client against a client-side slowloris).
    std::chrono::milliseconds totalRequestTimeout;
    /// Hard cap on total received response bytes (headers + body), enforced
    /// DURING receipt to bound memory for a huge/absent-length/close-delimited
    /// server (RFC 9112 §6.3 close-delimited has no length). Distinct from
    /// jsonConfig.maxPayloadSize (a post-receipt JSON cap); the effective cap
    /// used is max(maxResponseBytes, jsonConfig.maxPayloadSize). Raise it for
    /// consumers that legitimately download large bodies.
    std::size_t maxResponseBytes;
    JsonConfig jsonConfig; // JSON parsing configuration

    Config()
        : connectTimeout(2000), requestTimeout(3000), maxRedirects(5), followRedirects(false),
          userAgent("Iora-HttpClient/1.0"), reuseConnections(true), connectionIdleTimeout(300),
          leaseAcquireTimeout(0), totalRequestTimeout(0), maxResponseBytes(16 * 1024 * 1024),
          jsonConfig{}
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
    /// \brief The connection-cache / lease key. SCHEME-QUALIFIED (defect_12):
    /// an https:// request MUST NOT reuse a plaintext session opened for an
    /// http:// request to the same host:port (a silent TLS downgrade). Keying on
    /// `scheme://host:port` makes the TLS-mode invariant STRUCTURAL rather than
    /// checked. This is the SOLE key source — `_connections`, `_leasedHosts`,
    /// the lease acquire/release and dropConnection all derive their key from
    /// here, so re-keying here re-keys every site atomically (a partial re-key
    /// would let an http and an https request to one authority hold distinct
    /// leases yet collide on a shared cache slot, each closing the other's
    /// SessionId — an unsynchronized double-close across the released _mutex).
    /// The connect authority does NOT come from here (connectSync takes the
    /// resolved host + numeric port directly), so the scheme prefix never leaks
    /// onto the wire; it only appears in this key and in diagnostic strings.
    std::string getHostPort() const
    {
      return scheme + "://" + host + ":" + std::to_string(port);
    }
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

  /// \brief True for a method whose semantics anticipate a request body
  /// (POST/PUT/PATCH). RFC 9110 §8.6 advises a user agent send Content-Length: 0
  /// for such a method even when the body is empty, so a peer does not wait for
  /// content or mis-frame (defect_13). EXACT, case-sensitive match (RFC 9110
  /// §9.1 method tokens are case-sensitive), consistent with isIdempotentMethod.
  static bool methodAnticipatesContent(const std::string &method)
  {
    return method == "POST" || method == "PUT" || method == "PATCH";
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
    // Library owns Content-Type here; drop any case-variant caller key so a
    // mixed-case "content-type" cannot produce a duplicate line (task-1.4 review).
    setLibraryOwnedHeader(jsonHeaders, "Content-Type", "application/json");
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
    // The SSE defaults are caller-OVERRIDABLE (task-1.5 / defect_6; mirrors the
    // postJson change in tracker 2026-07-26-5 task-3.1): set them only when the
    // caller supplied none, so a caller-provided Accept / Cache-Control survives
    // rather than being silently overwritten. Matched case-insensitively so a
    // lowercase caller key is not duplicated on the wire.
    bool hasAccept = false;
    bool hasCacheControl = false;
    for (const auto &[name, value] : headers)
    {
      if (ciEqualsAscii(name, "Accept"))
      {
        hasAccept = true;
      }
      else if (ciEqualsAscii(name, "Cache-Control"))
      {
        hasCacheControl = true;
      }
    }
    if (!hasAccept)
    {
      streamHeaders["Accept"] = "text/event-stream";
    }
    if (!hasCacheControl)
    {
      streamHeaders["Cache-Control"] = "no-cache";
    }

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

    // Reject a quote, CR, LF or NUL in the caller-controlled part-header fields
    // (defect_6). RFC 7578 §4.2 defines NO escaping mechanism for these inside
    // name=""/filename="", so REJECT rather than escape — consistent with
    // task-1.2's throw-not-strip decision. A CRLF would inject additional
    // part-headers; a quote would break out of the quoted-string
    // (RFC 9110 §5.6.4). HttpInvalidHeaderError is non-retryable.
    auto rejectMultipartField = [](const std::string &field, const char *label)
    {
      for (char ch : field)
      {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (c == '"' || c == '\r' || c == '\n' || c == '\0')
        {
          throw HttpInvalidHeaderError(
              std::string("postFile ") + label +
              " contains a character forbidden in a multipart part-header "
              "(quote, CR, LF or NUL)");
        }
      }
    };
    rejectMultipartField(fieldName, "fieldName");
    rejectMultipartField(filename, "filename");

    // Generate a HIGH-ENTROPY random boundary (defect_17) — the former
    // clock-derived "----IoraBoundary<time>" was second-granularity and fully
    // predictable. RFC 2046 §5.1.1 makes the boundary's NON-APPEARANCE in the
    // content a MUST, so VERIFY the chosen boundary does not occur in
    // fileContent and regenerate on collision; a probabilistic "entropy makes
    // collision negligible" argument does not satisfy the MUST for arbitrary
    // binary uploads. Use the shared crypto::SecureRng (do NOT hand-roll RNG).
    auto makeBoundary = []()
    {
      std::uint8_t raw[18];
      iora::crypto::SecureRng::fill(raw, sizeof(raw));
      static const char kHex[] = "0123456789abcdef";
      std::string b = "----IoraBoundary";
      for (unsigned char byte : raw)
      {
        b += kHex[byte >> 4];
        b += kHex[byte & 0x0F];
      }
      return b; // 16 + 36 = 52 chars, within RFC 2046's 70-char limit
    };
    std::string boundary = makeBoundary();
    while (fileContent.find(boundary) != std::string::npos)
    {
      boundary = makeBoundary();
    }

    // Create multipart form data
    std::ostringstream body;
    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"" << fieldName << "\"; filename=\"" << filename
         << "\"\r\n";
    body << "Content-Type: application/octet-stream\r\n\r\n";
    body << fileContent;
    body << "\r\n--" << boundary << "--\r\n";

    std::map<std::string, std::string> multipartHeaders = headers;
    // The generated Content-Type carries the boundary and MUST be the only one
    // on the wire — drop any case-variant caller key first, or a mixed-case
    // "content-type" would emit a second line whose (absent/mismatched) boundary
    // corrupts the multipart framing (task-1.5 unconditional-CT invariant).
    setLibraryOwnedHeader(multipartHeaders, "Content-Type",
                          "multipart/form-data; boundary=" + boundary);

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

  /// \brief Parse URL into components.
  ///
  /// SCHEME CASE (decision, task-1.6): the scheme is matched case-SENSITIVELY —
  /// only lowercase `http` / `https` parse; `HTTP://…` is rejected as a
  /// malformed URL. (parsers::parseUrl lowercases the scheme; that divergence is
  /// left as-is here — harmonizing it would reach across into the parsers layer
  /// and tracker -2's origin key, out of this task's scope.)
  ///
  /// USERINFO / IPv6 (defect_7): the raw authority is inspected BEFORE trusting
  /// the regex's host capture, because the host character class stops at ':' and
  /// '/', so `user:pass@host` would otherwise fold the credentials into the path
  /// (request-target) and `[::1]:8080` would yield host="[". Userinfo is
  /// REJECTED (credentials must never reach the request-target). A bracketed
  /// IPv6 literal is REJECTED rather than parsed: parsing it would couple to
  /// bracket-aware changes in formatHostHeaderField and getHostPort (both do
  /// `host + ":" + port`) for a form no in-tree caller uses (YAGNI). Both throw
  /// HttpInvalidUrlError (a std::invalid_argument, non-retryable).
  ParsedUrl parseUrl(const std::string &url) const
  {
    ParsedUrl parsed;

    std::smatch match;
    if (!std::regex_match(url, match, compiledRegexes().url))
    {
      throw HttpInvalidUrlError("Invalid URL format: " + url);
    }

    // Inspect the raw authority (between "://" and the first '/', '?' or '#')
    // for userinfo and IPv6 brackets — independent of the regex host class.
    const std::size_t authStart = url.find("://") + 3;
    const std::size_t authEnd = url.find_first_of("/?#", authStart);
    const std::string authority =
      url.substr(authStart, authEnd == std::string::npos ? std::string::npos : authEnd - authStart);
    if (authority.find('@') != std::string::npos)
    {
      throw HttpInvalidUrlError("Invalid URL: userinfo (user@ / user:pass@) is not "
                                "permitted; credentials must not appear in the "
                                "request-target (RFC 9112 §3.2): " + url);
    }
    if (!authority.empty() && authority.front() == '[')
    {
      throw HttpInvalidUrlError("Invalid URL: bracketed IPv6 literals are not "
                                "supported: " + url);
    }

    parsed.scheme = match[1].str();
    parsed.host = match[2].str();

    // Default ports
    if (match[3].matched)
    {
      // Parse strictly and validate the 1..65535 range. The old
      // static_cast<uint16_t>(std::stoi(...)) truncated :65536 to port 0 (the
      // client then connected to port 0) and let an unbounded digit run throw
      // std::out_of_range into the retry path (defect_15).
      const std::string portStr = match[3].str();
      unsigned long portVal = 0;
      const char *first = portStr.data();
      const char *last = first + portStr.size();
      const auto res = std::from_chars(first, last, portVal);
      if (res.ec != std::errc() || res.ptr != last || portVal < 1 || portVal > 65535)
      {
        throw HttpInvalidUrlError("Invalid URL: port must be 1..65535: " + url);
      }
      parsed.port = static_cast<std::uint16_t>(portVal);
    }
    else
    {
      parsed.port = (parsed.scheme == "https") ? 443 : 80;
    }

    parsed.path = match[4].str();
    if (parsed.path.empty())
    {
      parsed.path = "/";
    }

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

    // LOOPBACK CONNECT-TIMEOUT CLAMP (defect_9): for 127.0.0.1 / ::1 the connect
    // timeout is clamped to min(connectTimeout, 200ms) — a loopback connect
    // either succeeds or is refused almost instantly, so a long timeout only
    // delays a refusal. CONSEQUENCE: Config::connectTimeout is NOT observable
    // against loopback (the address every in-tree test uses); a test that needs
    // to exercise a real connect-timeout must target a non-loopback,
    // non-routable address (e.g. 192.0.2.1, TEST-NET-1). resolveHostAddress also
    // maps the hostname "localhost" to 127.0.0.1 (:1227), so "localhost" is
    // clamped too. This is documented on Config::connectTimeout as well.
    auto timeout = (resolvedHost == "127.0.0.1" || resolvedHost == "::1")
      ? std::min(_config.connectTimeout, std::chrono::milliseconds(200))
      : _config.connectTimeout;

    auto connectResult = _transport->connectSync(resolvedHost, parsedUrl.port, tlsMode, timeout);
    if (connectResult.isErr())
    {
      const std::string detail =
        "Connection failed to " + hostPort + ": " + connectResult.error().message;
      // A connect-phase TIMEOUT is provably-not-sent (no request byte is written
      // until after connect), so surface it as HttpConnectTimeoutError — a
      // HttpRequestNotSentError subclass, so retry semantics are unchanged, but a
      // distinct TYPE the timeoutRequests classifier can key on (tracker
      // 2026-09-03-3). Discriminate on the STRUCTURED transport code, never the
      // message text: BOTH connect-timeout producers surface as
      // TransportError::Timeout here — the connectSync wait_for deadline
      // (transport_impl.hpp) and the tcp_engine CloseOrigin::ConnectTimeout watchdog
      // (delivered via onClose). Every other connect failure stays a plain
      // runtime_error, flattened to HttpRequestNotSentError by the generic pre-send
      // catch below: a refusal/reset is TransportError::Connect and a resolution
      // failure is TransportError::Resolve — neither is a timeout (DNS/resolution is
      // a distinct failure domain, deliberately NOT counted; tracker 2026-09-03-3
      // DQ-2 scope_out).
      if (connectResult.error().code == TransportError::Timeout)
      {
        throw HttpConnectTimeoutError(detail);
      }
      throw std::runtime_error(detail);
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
      catch (const HttpInvalidUrlError &e)
      {
        // A deterministic URL fault (malformed, userinfo, IPv6 literal, bad
        // port). Retrying re-parses and re-throws identically, and for a
        // non-idempotent method would be unsafe — never retry (task-1.6). This
        // guard MUST precede the generic catch(std::exception&): HttpInvalidUrlError
        // is a std::invalid_argument (a std::exception), which the generic gate
        // would otherwise retry on an idempotent method.
        iora::core::Logger::error("HttpClient: Request to " + url +
                                  " failed with a non-retryable URL error: " + e.what());
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
    // Validate the CALLER-supplied headers BEFORE acquiring a lease or
    // connecting, so a CR/LF-injection value or a non-token name never reaches
    // the wire and no connection is spent on a doomed request (tracker
    // 2026-07-26-10 task-1.2 / defect_1 / defect_3). The throw is
    // HttpInvalidHeaderError (an HttpFramingError), which performRequest rejects
    // WITHOUT retry — a deterministic caller error is never re-sent. This gate
    // covers ONLY the caller `headers` map; the library's own Host / Content-
    // Length / Content-Type are emitted downstream, after this point (task-1.1
    // FLAG-2). The error message never echoes the raw invalid value (it could
    // carry the control octets), and echoes the name only after it validated.
    for (const auto &namedHeader : headers)
    {
      if (!isValidHttpFieldName(namedHeader.first))
      {
        throw HttpInvalidHeaderError(
            "caller-supplied request header name is not a valid RFC 9110 token");
      }
      if (!isValidHttpFieldValue(namedHeader.second))
      {
        throw HttpInvalidHeaderError(
            "caller-supplied request header value contains a forbidden octet: '" +
            namedHeader.first + "'");
      }
      // Reject the framing/connection-control fields HttpClient emits itself.
      // A caller-supplied Host / Content-Length / Connection / Transfer-Encoding
      // / TE / Trailer / Upgrade / Expect would produce a duplicate or
      // conflicting framing field (CL/CL and TE.CL desync, RFC 9112 §6.1-§6.3;
      // a second Host, §3.2) — the request-smuggling primitive this guard
      // closes. Matched case-INSENSITIVELY: the caller map is case-sensitive, so
      // a mixed-case name would otherwise slip past. THROW is safe for every
      // in-tree caller (task-1.1 sweep found none supplies these); content-coding
      // is intentionally NOT rejected here (task-1.1 FLAG-1). See
      // isFramingControlledHeaderName (tracker 2026-07-26-10 task-1.3 / defect_2
      // / defect_4).
      if (isFramingControlledHeaderName(namedHeader.first))
      {
        throw HttpInvalidHeaderError(
            "caller supplied a request header HttpClient controls itself; it is "
            "framing-critical or connection-managed and must not be set by a "
            "caller: '" +
            namedHeader.first + "'");
      }
    }

    auto parsedUrl = parseUrl(url);
    const std::string hostPort = parsedUrl.getHostPort();

    // Use normal timeout - optimization will be handled at transport level
    std::chrono::milliseconds sendTimeout = _config.requestTimeout;

    // Whole-exchange deadline (defect_14 / task-1.10): computed ONCE, HERE,
    // BEFORE the lease/connect, so a slow connect composes with a slow-trickle
    // body against a single bound. Zero disables it (opt-in). The trip is an
    // explicit non-retryable throw at the receive-loop top (below); this is only
    // the anchor time.
    const bool haveDeadline = _config.totalRequestTimeout.count() > 0;
    const std::chrono::steady_clock::time_point exchangeDeadline =
      std::chrono::steady_clock::now() + _config.totalRequestTimeout;

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
      // Preserve a typed connect timeout (tracker 2026-09-03-3). It is already a
      // HttpRequestNotSentError subclass, so re-wrapping it below would keep the
      // not-sent/retry semantics but ERASE the timeout type the timeoutRequests
      // classifier keys on. Placed AFTER the _closing check so a concurrent
      // cancellation still takes precedence (HttpClientCancelledError), preserving
      // the existing ordering. Only the connect timeout transits this catch —
      // lease-acquire timeouts are thrown before this try and response-read timeouts
      // in the receive region — so no other type needs preserving here.
      if (dynamic_cast<const HttpConnectTimeoutError *>(&e) != nullptr)
      {
        throw;
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
    // User-Agent is caller-OVERRIDABLE (task-1.3): emit the library default only
    // when the caller did not supply its own, so an override yields ONE line
    // rather than a duplicate. Unlike the framing-critical fields (rejected
    // above), a caller User-Agent is harmless and defensibly the caller's to set.
    bool callerSuppliedUserAgent = false;
    for (const auto &[name, value] : headers)
    {
      if (ciEqualsAscii(name, "User-Agent"))
      {
        callerSuppliedUserAgent = true;
        break;
      }
    }
    if (!callerSuppliedUserAgent)
    {
      request << "User-Agent: " << _config.userAgent << "\r\n";
    }
    request << "Connection: " << (_config.reuseConnections ? "keep-alive" : "close") << "\r\n";

    // Add custom headers
    for (const auto &[name, value] : headers)
    {
      request << name << ": " << value << "\r\n";
    }

    // Emit Content-Length for the body. RFC 9110 §8.6: a user agent SHOULD send
    // Content-Length: 0 for a method whose semantics anticipate content
    // (POST/PUT/PATCH) even when the body is empty, so the peer does not wait
    // for a body or mis-frame the exchange (defect_13). A body-less GET/HEAD/etc.
    // carries no Content-Length, as before.
    if (!body.empty())
    {
      request << "Content-Length: " << body.size() << "\r\n";
    }
    else if (methodAnticipatesContent(method))
    {
      request << "Content-Length: 0\r\n";
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
        // WHOLE-EXCHANGE DEADLINE TRIP (task-1.10) — the SOLE trip mechanism, an
        // explicit check BEFORE receiveSync, evaluated every iteration (which is
        // also every interim-1xx continuation: frameResponse discards a 1xx and
        // returns here, so the next byte forces another loop turn). A trickle or
        // 1xx flood delivers data faster than sendTimeout, so the per-iteration
        // timeout never fires — only this bound stops it. NON-retryable
        // (HttpExchangeDeadlineError IS-A HttpFramingError), so an idempotent
        // trickle GET is not retried and total wall-clock stays ~1x the deadline.
        if (haveDeadline && std::chrono::steady_clock::now() >= exchangeDeadline)
        {
          throw HttpExchangeDeadlineError("HTTP total request deadline exceeded");
        }

        std::size_t len = sizeof(buffer);
        // Clamp the per-iteration receive wait to the remaining budget so a
        // single receiveSync cannot overshoot the deadline by up to a full
        // sendTimeout. OVERSHOOT-LIMITER ONLY — never the trip: floor strictly
        // positive (never hand poll() 0/negative — 0 is the near-zero probe,
        // negative is block-forever). A Timeout produced by THIS clamp loops back
        // so the top check throws the non-retryable deadline error, rather than
        // surfacing as the RETRYABLE HttpResponseTimeoutError (which on an
        // idempotent method would re-enable the slowloris amplification).
        std::chrono::milliseconds recvTimeout = sendTimeout;
        bool clampedByDeadline = false;
        if (haveDeadline)
        {
          const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            exchangeDeadline - std::chrono::steady_clock::now());
          if (remaining < recvTimeout)
          {
            recvTimeout = (remaining.count() > 0) ? remaining : std::chrono::milliseconds(1);
            clampedByDeadline = true;
          }
        }
        auto recvResult = _transport->receiveSync(sessionId, buffer, len, recvTimeout);

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
          // A timeout produced by the deadline clamp is NOT the per-iteration
          // silent-server timeout: loop so the top-of-loop deadline check throws
          // the NON-retryable HttpExchangeDeadlineError (task-1.10). Only a
          // timeout at the FULL, unclamped sendTimeout is the genuine
          // silent-server case below.
          if (clampedByDeadline)
          {
            continue;
          }
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
          // Interim 1xx response (RFC 9110 §15.2 — RFC 9112 has no §15): discard
          // it wholesale and
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
          const std::string token = value.substr(a, b - a + 1);
          if (ciEqualsAscii(token, "close"))
          {
            return true; // a "close" token wins outright
          }
          if (ciEqualsAscii(token, "keep-alive"))
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

  static bool ciEquals(const std::string &a, const std::string &b) { return ciEqualsAscii(a, b); }

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
  /// reject conflicting duplicate Content-Length (§6.3 rule 5), reject a
  /// duplicate Transfer-Encoding response field-line (defect_18), and COMBINE
  /// repeated list-valued field-lines (Content-Encoding / Accept-Encoding) into
  /// an ordered comma-list (RFC 9110 §5.3, defect_8). Throws HttpFramingError on
  /// any violation.
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
    bool haveTE = false;
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
      // OWS-before-colon (defect_10): trim(name) removes any trailing SP/HTAB
      // between the field-name and the colon. RFC 9112 §5.1 requires a SERVER to
      // reject such whitespace and a PROXY to strip it; a user agent parsing a
      // RESPONSE accepting it (as here) is lenient, not wrong (recipients strip).
      // DECISION (task-1.7(c)): ACCEPT with this recorded rationale — a leading
      // OWS is impossible here (an obs-fold continuation is rejected above at the
      // SP/HTAB-first-char guard), so trim(name) only ever removes the §5.1
      // whitespace-before-colon, matching Postel-robust client parsing.
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
      // Transfer-Encoding response duplicate (defect_18): a client only RECEIVES
      // responses (never forwards them), so more than one Transfer-Encoding
      // field-line on a response is overwhelmingly attack or misconfiguration.
      // REJECT any duplicate (unlike Content-Length, which rejects only a
      // CONFLICTING value: RFC 9112 §6.1 forbids applying chunked more than once,
      // so even identical duplicate TE lines are malformed). A SINGLE TE line —
      // including an internal comma-list like "gzip, chunked" — is unaffected and
      // frames exactly as before (determineFraming untouched). TE is kept OUT of
      // isListValuedHeader: this is an independent reject, not the CE combine path.
      if (ciEquals(name, "Transfer-Encoding"))
      {
        if (haveTE)
        {
          throw HttpFramingError("more than one Transfer-Encoding response field-line");
        }
        haveTE = true;
      }
      // Combine repeated list-valued response field-lines into an ordered
      // comma-list (defect_8): Content-Encoding / Accept-Encoding are #list-valued
      // (RFC 9110 §5.3/§8.4), so "Content-Encoding: gzip" then
      // "Content-Encoding: identity" must present as "gzip, identity" (arrival
      // order preserved, so a decoder strips codings outermost-first), NOT
      // last-wins "identity". The shared allow-list-driven helper keeps every
      // non-list field (incl. the singleton Content-Length checked above)
      // last-wins, so this changes only list-valued duplicates.
      detail::addOrCombineHeader(resp.headers, name, value);
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