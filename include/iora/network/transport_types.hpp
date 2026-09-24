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

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "iora/core/buffer_view.hpp"
#include "iora/core/result.hpp"
#include "iora/network/event_batch_processor.hpp"

namespace iora
{
namespace network
{

using SessionId = std::uint64_t;
using ListenerId = std::uint64_t;
using ByteBuffer = std::vector<std::uint8_t>;
using MonoClock = std::chrono::steady_clock;
using MonoTime = std::chrono::time_point<MonoClock>;

enum class Role
{
  ServerPeer,
  ClientConnected
};

enum class TlsMode
{
  None,
  Server,
  Client
};

enum class TransportError
{
  None = 0,
  Socket,
  Resolve,
  Bind,
  Listen,
  Accept,
  Connect,
  TLSHandshake,
  TLSIO,
  PeerClosed,
  WriteBackpressure,
  Config,
  GCClosed,
  Cancelled,
  Timeout,
  BufferOverflow, // Sync receive buffer exceeded maxSyncReceiveBuffer (data dropped)
  ShuttingDown,   // Transport is being torn down; sync op released without completing
  TooManyPendingSyncOps, // Concurrent parked sync ops reached maxPendingSyncOps
  // Local CONNECTION-ADMISSION exhaustion: a new session was refused because a
  // local admission limit (maxSessions now; fd/memory later) was reached. This is
  // NOT a per-target transport failure (Connect/Resolve) and NOT a misconfiguration
  // (Config). It is distinct from the resource-flavored siblings above
  // (WriteBackpressure / BufferOverflow / TooManyPendingSyncOps), which concern an
  // ESTABLISHED session's data plane, not session admission. SIP consumers map this
  // to 503 Service Unavailable + a bounded Retry-After WITHOUT RFC 3263 failover
  // (a local, sheddable condition; see iora_sip transport session-cap handling).
  // EMISSION SCOPE (2026-09-16): currently emitted by the UDP engine's cap sites
  // (client connect() and connectViaListener). The TCP/TLS engine also enforces
  // maxSessions but still reports its accept-time rejection via TransportError::Accept;
  // migrating the TCP/TLS cap sites to this discriminator is a tracked follow-on
  // (coding_trackers tasks/iora/backlog/2026-09-16-2).
  // Appended before Unknown to preserve existing enum ordinals (some operator-facing
  // logs stringify static_cast<int>(code)). NOTE: both append-before-Unknown (as
  // ResourceLimit above) and append-after-Unknown (as NotConnected below) preserve
  // every PRIOR ordinal; NotConnected is appended AFTER Unknown specifically so that
  // Unknown's OWN ordinal also stays stable for any consumer that persists/stringifies
  // static_cast<int>(code).
  ResourceLimit,
  Unknown,
  // A synchronous send targeted a session that is not connected (an unknown, closed, or
  // cap-rejected sid). Distinct from Socket ('send enqueue failed'): NotConnected is the
  // structured "no live session" signal the UDP/TCP engines report from their
  // single-decision send path (trySend -> {Ok, NotConnected, EnqueueFailed}); iora_sip's
  // isTransientSessionNotConnected carve-out is rekeyed onto it. Appended AFTER Unknown to
  // keep Unknown's ordinal stable (see the note above).
  NotConnected
};

struct IoResult
{
  bool ok{true};
  TransportError code{TransportError::None};
  std::string message;
  int sysErrno{0};
  int tlsError{0};

  static IoResult success() { return {true, TransportError::None, "", 0, 0}; }

  static IoResult failure(TransportError c, const std::string &m, int se = 0, int te = 0)
  {
    return {false, c, m, se, te};
  }
};

// Enhanced error reporting with severity and context
enum class ErrorSeverity
{
  Warning,
  Recoverable,
  Fatal
};

struct TransportEvent
{
  TransportError code{TransportError::None};
  ErrorSeverity severity{ErrorSeverity::Warning};
  std::string context;
  std::string details;
  SessionId sessionId{0};
  std::chrono::system_clock::time_point timestamp{std::chrono::system_clock::now()};
  int sysErrno{0};
  int tlsError{0};

  static TransportEvent warning(TransportError code, const std::string &ctx,
                                const std::string &details = "")
  {
    return {code, ErrorSeverity::Warning, ctx, details, 0, std::chrono::system_clock::now(), 0, 0};
  }

  static TransportEvent error(TransportError code, const std::string &ctx,
                              const std::string &details = "", int sysErr = 0)
  {
    return {code, ErrorSeverity::Recoverable,       ctx,    details,
            0,    std::chrono::system_clock::now(), sysErr, 0};
  }

  static TransportEvent fatal(TransportError code, const std::string &ctx,
                              const std::string &details = "", int sysErr = 0)
  {
    return {code, ErrorSeverity::Fatal, ctx, details, 0, std::chrono::system_clock::now(), sysErr,
            0};
  }
};

// Synchronous result for listener operations
struct ListenerResult
{
  ListenerId id{0};
  IoResult result;
  std::string bindAddress;

  static ListenerResult success(ListenerId lid, const std::string &addr)
  {
    return {lid, IoResult::success(), addr};
  }

  static ListenerResult failure(TransportError code, const std::string &msg, int sysErr = 0)
  {
    return {0, IoResult::failure(code, msg, sysErr), ""};
  }
};

/// \brief Basic transport stats for legacy compatibility.
/// Used by the old adapter layer.
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

// ══════════════════════════════════════════════════════════════════════════════
// New Transport API Types (Phase 1 of transport refactor)
// The types above (IoResult, ListenerResult, TransportEvent, BasicTransportStats)
// are legacy and will be removed when engines are fully migrated.
// ══════════════════════════════════════════════════════════════════════════════

using iora::core::Result;

enum class Protocol
{
  TCP,
  UDP
};

enum class ReadMode
{
  Async,
  Sync,
  /// \brief Write-only: suppress inbound-data delivery on this session.
  /// CONTRACT (DR-1, tracker 2026-09-11-19, human sign-off 2026-09-14): the
  /// application expects no further inbound data on this session; a peer close
  /// (a graceful FIN half-close) while reads are disabled TERMINATES the session
  /// (onClose PeerClosed) and DISCARDS any unread buffered inbound bytes rather
  /// than preserving them for a later re-enable. Peer-disconnect detection for a
  /// read-disabled session therefore rides EPOLLRDHUP (the TCP engine arms it
  /// independently of EPOLLIN, which is withheld here), not the EPOLLIN/EOF read
  /// path. The SSE write-only stream (sse_stream.hpp upgradeToSse) is the sole
  /// user. See Transport::setReadMode.
  Disabled
};

/// \brief READ-HALF-CLOSE CONTRACT (tracker 2026-09-14-4, human sign-off 2026-09-16).
/// For a read-ENABLED session (the normal request/response case), the TCP engine
/// treats read-half EOF as terminal: recv()==0 (plaintext) and the TLS analogues
/// (SSL_ERROR_ZERO_RETURN from a peer close_notify; a bare FIN without close_notify
/// surfacing via the TLSIO error branch) all close the session immediately. A client
/// that finishes its request and then shutdown(SHUT_WR) — a legitimate TCP half-close
/// ("done sending; still reading the response") — therefore has its session torn down
/// before a pending/in-flight response is written, and that response is DROPPED. In
/// other words: iora does NOT support HTTP request half-close. This is a DELIBERATE,
/// documented non-conformance with RFC 9112 §9.6 (Tear-down) — which states a client
/// half-close "does not imply that the client is no longer interested in a response" —
/// accepted because (a) no first-party or deployed consumer relies on request
/// half-close, and (b) deferring the close would add a leak/grace-timer state machine
/// to the transport's teardown-race-sensitive core. The http_server layer logs the
/// resulting pre-response send failure (with an RFC 9112 §9.6 hint) so the otherwise
/// silent truncation is diagnosable. Deferred-close support (the §9.6-conformant
/// behavior) is a CONDITIONAL follow-on: coding_trackers tasks/iora/backlog/2026-09-16-1.
///
/// CONTRAST with ReadMode::Disabled above: same wire signal (peer FIN), OPPOSITE
/// correctness. A read-DISABLED (SSE/write-only) session owes no response, so its peer
/// FIN (detected via EPOLLRDHUP) CORRECTLY closes; a read-ENABLED session DOES owe a
/// response, so closing on its peer FIN drops that response — the defect this contract
/// documents. The two paths are handled separately and must stay separate.
///
/// SECOND §9.6 ASPECT (staged close, distinct latent non-conformance). RFC 9112 §9.6
/// also directs a server to close "in stages" — half-close its write side, then keep
/// reading — so an immediate full close cannot make the peer's TCP stack RST-discard a
/// still-unread final response from the client's receive buffer (the RST is triggered
/// when the fully-closed socket then receives further client data, e.g. a pipelined
/// request). iora closeNow()s in a
/// single step rather than staging. This is a SEPARATE §9.6 gap from the request
/// half-close above; the §9.6-conformant staged/deferred close is tracked with the
/// deferred-close follow-on: coding_trackers tasks/iora/backlog/2026-09-16-1.

struct TransportAddress
{
  std::string host;
  std::uint16_t port{0};

  bool operator==(const TransportAddress &other) const
  {
    return host == other.host && port == other.port;
  }

  bool operator!=(const TransportAddress &other) const { return !(*this == other); }
};

/// \brief Structured transport error.
///
/// \c tlsError is OVERLOADED and must not be used to classify a failure: it may
/// carry an OpenSSL ERR_get_error() code, an X509 verify result
/// (X509_V_ERR_*), or an injected test code -- and the SSL_get_error() values
/// SSL_ERROR_SYSCALL/SSL_ERROR_ZERO_RETURN (5/6) collide with X509_V_ERR 5/6.
///
/// \c sysErrno is the discriminator. TcpEngine sets it from the errno captured
/// immediately after the failing syscall, from getsockopt(SO_ERROR) for an
/// event-only trigger (EPOLLHUP/EPOLLERR/EPOLLRDHUP), or explicitly for timer
/// and app closes (never from ambient errno). Client-role (outbound) setup-phase
/// closes:
///   - Connect: the TCP phase failed (sysErrno != 0); a connect timeout reports
///     ETIMEDOUT.
///   - ResourceLimit: local resource exhaustion before the connect was issued
///     (socket() EMFILE/ENFILE/ENOBUFS/ENOMEM, connect() EADDRNOTAVAIL; errno kept).
///   - TLSHandshake + ETIMEDOUT: handshake timeout.
///   - TLSHandshake + ECONNRESET/EPIPE/...: transport abort (SSL_ERROR_SYSCALL errno).
///   - TLSHandshake + ECONNABORTED: EOF without an alert.
///   - TLSHandshake + 0: alert received (incl. close_notify), verify/certificate
///     failure, "no peer certificate", or any other TLS-protocol failure.
///   - WriteBackpressure + ENOBUFS: the setup succeeded but a setup-phase buffer
///     had overflowed maxWriteQueue: ZERO bytes were sent and the buffered requests
///     were discarded -- failover-safe. An established-session overflow reports
///     WriteBackpressure with sysErrno 0 (bytes may have been sent).
/// CONTRACT (client-role TLSHandshake): sysErrno != 0 <=> transport abort
/// (timeout = ETIMEDOUT; RST/EPIPE/EOF/any socket errno); sysErrno == 0 <=>
/// TLS-protocol failure. The discriminator is client-role only: a server-role
/// (accepted) session's TLSHandshake close always reports sysErrno 0, and the
/// setup-phase relabel (Connect/TLSHandshake) is not applied to it.
/// SCOPE (important for a reachability/failover consumer): this server-role
/// sysErrno-0 invariant is TLSHandshake-CODE-scoped -- i.e. the handshake phase
/// only. A server-role (inbound/accepted) session that COMPLETES its handshake and
/// is then reset/broken by the peer closes with code PeerClosed/Socket/TLSIO
/// carrying a LIVE errno (ECONNRESET/EPIPE/...). So a peer-unreachable classifier
/// must NOT infer "outbound probe" from sysErrno alone: gate the transport-abort
/// discriminator on session DIRECTION (inbound vs outbound) -- direction, not just
/// phase, is the real discriminator. An inbound session close is never a
/// peer-reachability signal in any phase.
struct TransportErrorInfo
{
  TransportError code{TransportError::Unknown};
  std::string message;
  int sysErrno{0};
  int tlsError{0};
};

/// \brief True iff a failed connectSync result is a connect-phase TIMEOUT: the
/// connectSync deadline (TransportError::Timeout), the engine connect watchdog
/// (TransportError::Connect with sysErrno ETIMEDOUT) or the engine TLS handshake
/// watchdog (TransportError::TLSHandshake with sysErrno ETIMEDOUT). A refusal, reset,
/// handshake/verify failure or resolution failure is not a timeout.
inline bool isConnectPhaseTimeout(const TransportErrorInfo &err) noexcept
{
  if (err.code == TransportError::Timeout)
  {
    return true;
  }
  return err.sysErrno == ETIMEDOUT &&
         (err.code == TransportError::Connect || err.code == TransportError::TLSHandshake);
}

using ObserverId = std::uint64_t;

/// \brief Per-connection TLS client identity options (data-only seam).
///
/// Threaded through the public connect API into the engine so the TLS client
/// handshake can (a) present the reference identity via SNI and (b) verify the
/// server certificate against it (RFC 6125/9525). The reference identity
/// (verifyName) is DISTINCT from the connect address: both consumers pre-resolve
/// to an IP literal before connect(), so the connect address is not the domain.
///
/// Data-only by design: no std::function, no OpenSSL type — transport_types.hpp
/// is OpenSSL-include-free and is included by non-TLS TUs (udp_engine.hpp,
/// sse_stream.hpp, connection_health.hpp, sockaddr_utils.hpp).
/// See architecture/iora/transport_tls_sni_identity.json (C1).
struct TlsClientOptions
{
  /// Reference identity (a DNS A-label, e.g. "example.com", or empty). Empty =>
  /// the transport falls back to inspecting the connect address (IP literal =>
  /// no SNI + iPAddress match; resolved name => SNI + DNS match). An IP literal
  /// here is routed to the no-SNI/iPAddress branch, never sent as SNI.
  std::string verifyName;
  /// OpenSSL X509_CHECK_FLAG_* bitmask applied to the identity match. 0 = none.
  /// HTTPS callers pass kHttpsHostFlags.
  unsigned x509HostFlags{0};
};

/// \brief HTTPS host-verification flags (RFC 9525 §6.3), as a macro-free
/// constant so consumers (http_client.hpp) can pass it WITHOUT an <openssl/*>
/// include. NEVER_CHECK_SUBJECT (0x20): CN MUST NOT identify a service.
/// NO_PARTIAL_WILDCARDS (0x4): reject partial wildcards. NO_WILDCARDS stays
/// UNSET so a single-label wildcard still matches one label. The value is locked
/// to the real OpenSSL macros by a static_assert in detail/tcp_engine.hpp (which
/// includes <openssl/x509v3.h>); do not change it here without updating that.
static constexpr unsigned kHttpsHostFlags = 0x20u | 0x4u;

/// \brief SIP/SIPS host-verification flags (RFC 5922 §7.1/§7.2), as a macro-free
/// constant so consumers (SipTransport.hpp) can pass it WITHOUT an <openssl/*>
/// include. NO_WILDCARDS (0x2): §7.2 PROHIBITS wildcard matching (the opposite of
/// web PKI). NEVER_CHECK_SUBJECT (0x20): SIP identity is SAN-based (§7.1 prefers
/// subjectAltName; CN is only a backward-compat fallback when no SAN appears) —
/// we disable CN entirely, stricter than §7.1. This is the strict default. The
/// value is locked to the real OpenSSL
/// macros by a static_assert in detail/tcp_engine.hpp (which includes
/// <openssl/x509v3.h>); do not change it here without updating that.
static constexpr unsigned kSipHostFlags = 0x2u | 0x20u;

/// \brief Per-peer opt-in relaxation of kSipHostFlags for trusted wildcard-cert
/// SIP trunks (e.g. Twilio *.pstn.us1.twilio.com). NO_WILDCARDS is UNSET so
/// wildcard SANs match; NEVER_CHECK_SUBJECT stays set (SAN-only always).
/// NOTE: NO_PARTIAL_WILDCARDS (0x4) is deliberately NOT set, so this is a MAX-
/// permissive opt-in — MORE permissive than kHttpsHostFlags (0x24u, which sets
/// NO_PARTIAL_WILDCARDS to reject partial wildcards): it accepts partial wildcards
/// (e.g. sip*.example.com) as well as full-label ones. This is NEVER a global
/// relaxation — the SIP layer selects it only for a peer with an explicit
/// trusted-wildcard config flag. Locked to the real OpenSSL macro by a
/// static_assert in detail/tcp_engine.hpp.
static constexpr unsigned kSipHostFlagsAllowWildcards = 0x20u;

// Result<T,E> aliases for Transport API return types.
// IoResult alias: deferred until legacy IoResult struct (above) is removed from
// engine internals. The legacy struct is used only by TcpEngine::lastFatalError().
using SendResult = Result<std::size_t, TransportErrorInfo>;
using ReceiveResult = Result<std::size_t, TransportErrorInfo>;
using StartResult = Result<void, TransportErrorInfo>;
using ListenResult = Result<ListenerId, TransportErrorInfo>;
using ConnectResult = Result<SessionId, TransportErrorInfo>;

// Sentinel default for the primary sync ops' `timeout` parameter: a negative
// duration means "use TransportConfig::defaultSyncTimeout", resolved at the top of
// each op's definition (where the config is available). SIP presets tune
// defaultSyncTimeout (Timer B/F = 32000 ms TCP, T1 = 500 ms UDP); before this the
// sync ops hardcoded 30000 ms and ignored the config. The *Cancellable variants are
// ITransport methods with no config access, so they keep the literal 30000 default.
static constexpr std::chrono::milliseconds kUseConfigSyncTimeout{-1};

// The historical 30 s fallback sync timeout: the *Cancellable variants' literal
// default (they have no config access), their negative/sentinel clamp target, and
// resolveSyncTimeout's floor when config.defaultSyncTimeout is misconfigured to a
// non-positive value (F-2). One constant so the policy value cannot drift.
static constexpr std::chrono::milliseconds kFallbackSyncTimeout{30000};

// Callback typedefs for Transport API.
// AcceptCallback and ConnectCallback fire only on success (no error parameter).
using AcceptCallback =
  std::function<void(SessionId sid, const TransportAddress &peerAddr)>;
using ConnectCallback =
  std::function<void(SessionId sid, const TransportAddress &peerAddr)>;
using DataCallback =
  std::function<void(SessionId sid, iora::core::BufferView data,
                     std::chrono::steady_clock::time_point receiveTime)>;
using CloseCallback =
  std::function<void(SessionId sid, const TransportErrorInfo &reason)>;
using ErrorCallback =
  std::function<void(TransportError code, const std::string &message)>;
using SendCompleteCallback =
  std::function<void(SessionId sid, const SendResult &result)>;
using SessionCleanupCallback = std::function<void(void *userData)>;

class CancellationToken
{
public:
  CancellationToken() = default;

  CancellationToken(const CancellationToken &) = delete;
  CancellationToken &operator=(const CancellationToken &) = delete;
  CancellationToken(CancellationToken &&) = delete;
  CancellationToken &operator=(CancellationToken &&) = delete;

  void cancel()
  {
    _cancelled.store(true, std::memory_order_release);
    std::lock_guard<std::mutex> lock(_mutex);
    for (auto &cv : _waiters)
    {
      cv->notify_all();
    }
  }

  bool isCancelled() const { return _cancelled.load(std::memory_order_acquire); }

  /// \brief Reset the token for reuse.
  /// MUST NOT be called while any sync operation is in flight using this
  /// token — doing so removes their waiter registration, causing cancel()
  /// to silently fail to wake them. Create a new token instead if unsure.
  void reset()
  {
    _cancelled.store(false, std::memory_order_release);
    std::lock_guard<std::mutex> lock(_mutex);
    _waiters.clear();
  }

  void registerWaiter(std::shared_ptr<std::condition_variable> cv)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _waiters.push_back(std::move(cv));
  }

  void unregisterWaiter(const std::shared_ptr<std::condition_variable> &cv)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _waiters.erase(std::remove(_waiters.begin(), _waiters.end(), cv), _waiters.end());
  }

private:
  std::atomic<bool> _cancelled{false};
  mutable std::mutex _mutex;
  std::vector<std::shared_ptr<std::condition_variable>> _waiters;
};

/// \brief Transport configuration. Single config type replacing the 4 existing
/// config types from the old architecture.
struct TransportConfig
{
  Protocol protocol{Protocol::TCP};

  // === Timeouts ===
  std::chrono::seconds idleTimeout{600};
  std::chrono::seconds maxConnAge{std::chrono::seconds::zero()};
  std::chrono::milliseconds connectTimeout{30000};
  std::chrono::milliseconds handshakeTimeout{30000};
  // Off-thread name-resolution timeout (event-driven doConnect). count()==0
  // disables it; SIP transports MUST NOT disable it (a disabled resolve-timeout
  // is an aggregate-budget violation — see the iora_sip budget assert, tracker
  // 2026-09-06-4 task-5.2). See architecture/iora/transport_dns_resolve.json C6.
  std::chrono::milliseconds resolveTimeout{5000};
  std::chrono::milliseconds writeStallTimeout{0};
  std::chrono::seconds gcInterval{5};

  // === I/O ===
  int epollMaxEvents{256};
  std::size_t ioReadChunk{64 * 1024};
  /// \brief Per-session write-queue cap (queued payloads); MUST be >= 1
  /// (TcpEngine::start() rejects 0 with TransportError::Config). Enforced on the
  /// I/O thread, so an overflow is reported ASYNCHRONOUSLY: send() has already
  /// returned true and the session later closes via onClose. TCP/TLS sessions
  /// never silently drop: overflow always terminates the session. An established
  /// session closes with WriteBackpressure; a setup-phase buffer (TCP connect, TLS
  /// handshake, named-host resolve) discards the overflowing payload and closes
  /// WriteBackpressure + ENOBUFS at setup completion, before any byte is sent (a
  /// failed setup still reports Connect/TLSHandshake).
  std::size_t maxWriteQueue{1024};
  /// \brief Datagram (UDP) sessions only: on write-queue overflow, true closes the
  /// session (WriteBackpressure); false drops the OLDEST queued datagram and keeps
  /// the new one. TcpEngine ignores it: TCP/TLS sessions always close on overflow
  /// (see maxWriteQueue).
  bool closeOnBackpressure{true};
  bool useEdgeTriggered{true};

  // === Socket ===
  bool enableTcpNoDelay{true};
  int soRcvBuf{0};
  int soSndBuf{0};
  std::uint8_t dscpValue{0};
  bool enableHighResolutionTimers{true};
  int listenBacklog{256};

  struct TcpKeepalive
  {
    bool enable{false};
    int idle{60};
    int interval{10};
    int count{3};
  } tcpKeepalive;

  /// \brief Maximum concurrent sessions; 0 means unlimited.
  ///
  /// Enforced by BOTH the UDP and TCP/TLS engines (the TCP engine rejects the
  /// accepted fd once the cap is reached). It is the only bound on aggregate
  /// per-session receive memory, so leaving it at 0 on a stream transport means
  /// the effective ceiling is the process fd limit.
  std::size_t maxSessions{0};

  // === Sync operations ===
  std::size_t maxPendingSyncOps{32};
  std::size_t maxSyncReceiveBuffer{1024 * 1024};
  std::size_t syncBufferGcThreshold{1024};
  std::chrono::milliseconds defaultSyncTimeout{30000};
  bool allowReadModeSwitch{true};

  // === TLS ===
  struct TlsConfig
  {
    bool enabled{false};
    TlsMode defaultMode{TlsMode::None};
    std::string certFile;
    std::string keyFile;
    std::string caFile;
    std::string caPath;
    std::string ciphers;
    std::string alpn;
    int minVersion{0}; // 0 = default, use OpenSSL TLS_method(). Non-zero values map to SSL_CTX_set_min_proto_version().
    bool verifyPeer{false};
    int verifyDepth{4};
  };

  TlsConfig serverTls;
  TlsConfig clientTls;

  // === Batching ===
  struct BatchConfig
  {
    bool enabled{false};
    std::size_t maxBatchSize{64};
    std::chrono::microseconds maxBatchDelay{100};
    std::chrono::microseconds adaptiveThreshold{50};
    bool enableAdaptiveSizing{true};
    double loadFactor{0.75};
  } batching;

  // === Rate limiting ===
  double acceptRateLimit{0.0};
  double perIpAcceptRateLimit{0.0};
  double sendRateLimit{0.0};

  // === Optional metrics ===
  // MetricsRegistry* is passed separately (not stored in Config) to avoid
  // including metrics.hpp here. Set via Transport constructor parameter.

  // === Factory presets ===

  static TransportConfig forSipTcp()
  {
    TransportConfig c;
    c.protocol = Protocol::TCP;
    c.idleTimeout = std::chrono::seconds(3600);
    c.enableTcpNoDelay = true;
    c.tcpKeepalive.enable = true;
    c.tcpKeepalive.idle = 120;
    c.maxPendingSyncOps = 64;
    c.defaultSyncTimeout = std::chrono::milliseconds(32000);
    c.dscpValue = 24; // CS3 call-signaling (Cisco QoS convention; note RFC 4594 proper
                      // assigns CS5 to Signaling and CS3 to Broadcast Video)
    return c;
  }

  static TransportConfig forSipUdp()
  {
    TransportConfig c;
    c.protocol = Protocol::UDP;
    c.idleTimeout = std::chrono::seconds(32);
    c.maxSessions = 10000;
    c.maxPendingSyncOps = 64;
    c.defaultSyncTimeout = std::chrono::milliseconds(500);
    c.dscpValue = 24; // CS3 call-signaling (Cisco QoS convention; note RFC 4594 proper
                      // assigns CS5 to Signaling and CS3 to Broadcast Video)
    return c;
  }

  static TransportConfig forHighThroughput()
  {
    TransportConfig c;
    c.protocol = Protocol::TCP;
    c.batching.enabled = true;
    c.batching.maxBatchSize = 128;
    c.batching.maxBatchDelay = std::chrono::microseconds(200);
    c.maxWriteQueue = 4096;
    c.soRcvBuf = 262144;
    c.soSndBuf = 262144;
    return c;
  }

  static TransportConfig forLowLatency()
  {
    TransportConfig c;
    c.protocol = Protocol::TCP;
    c.batching.enabled = false;
    c.enableTcpNoDelay = true;
    c.useEdgeTriggered = true;
    c.maxWriteQueue = 256;
    return c;
  }

  static TransportConfig minimal()
  {
    return TransportConfig{};
  }
};

/// \brief Transport statistics. Single stats type replacing the 3 existing
/// stats types (BasicTransportStats, UnifiedStats).
struct TransportStats
{
  std::uint64_t accepted{0};
  std::uint64_t connected{0};
  std::uint64_t closed{0};
  std::uint64_t errors{0};
  std::uint64_t tlsHandshakes{0};
  std::uint64_t tlsFailures{0};
  std::uint64_t bytesIn{0};
  std::uint64_t bytesOut{0};
  std::uint64_t epollWakeups{0};
  std::uint64_t commands{0};
  std::uint64_t gcRuns{0};
  std::uint64_t gcClosedIdle{0};
  std::uint64_t gcClosedAged{0};
  std::uint64_t backpressureCloses{0};
  std::size_t sessionsCurrent{0};
  std::size_t sessionsPeak{0};
  std::optional<BatchProcessingStats> batchingStats;
};

} // namespace network
} // namespace iora