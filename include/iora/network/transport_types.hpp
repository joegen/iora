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
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "iora/core/buffer_view.hpp"
#include "iora/core/result.hpp"

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
  Unknown
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
/// Used by SharedTransport::getBasicStats() and the old adapter layer.
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
  Disabled
};

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

struct TransportErrorInfo
{
  TransportError code{TransportError::Unknown};
  std::string message;
  int sysErrno{0};
  int tlsError{0};
};

using ObserverId = std::uint64_t;

// Result<T,E> aliases for Transport API return types.
// Note: IoResult alias deferred to Phase 3 (name conflicts with legacy IoResult struct above).
using SendResult = Result<std::size_t, TransportErrorInfo>;
using StartResult = Result<void, TransportErrorInfo>;
using ListenResult = Result<ListenerId, TransportErrorInfo>;
using ConnectResult = Result<SessionId, TransportErrorInfo>;

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
  CancellationToken() : _cancelled(std::make_shared<std::atomic<bool>>(false)) {}

  CancellationToken(const CancellationToken &) = delete;
  CancellationToken &operator=(const CancellationToken &) = delete;
  CancellationToken(CancellationToken &&) = default;
  CancellationToken &operator=(CancellationToken &&) = default;

  void cancel()
  {
    _cancelled->store(true, std::memory_order_release);
    std::lock_guard<std::mutex> lock(_mutex);
    for (auto &cv : _waiters)
    {
      cv->notify_all();
    }
  }

  bool isCancelled() const { return _cancelled->load(std::memory_order_acquire); }

  /// \brief Reset the token for reuse.
  /// MUST NOT be called while any sync operation is in flight using this
  /// token — doing so removes their waiter registration, causing cancel()
  /// to silently fail to wake them. Create a new token instead if unsure.
  void reset()
  {
    _cancelled->store(false, std::memory_order_release);
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
  std::shared_ptr<std::atomic<bool>> _cancelled;
  mutable std::mutex _mutex;
  std::vector<std::shared_ptr<std::condition_variable>> _waiters;
};

/// \brief Transport configuration. Single config type replacing the 4 existing
/// config types (SharedTransport::Config, SharedUdpTransport::Config,
/// SyncAsyncTransport::Config, UnifiedSharedTransport::Config).
struct TransportConfig
{
  Protocol protocol{Protocol::TCP};

  // === Timeouts ===
  std::chrono::seconds idleTimeout{600};
  std::chrono::seconds maxConnAge{std::chrono::seconds::zero()};
  std::chrono::milliseconds connectTimeout{30000};
  std::chrono::milliseconds handshakeTimeout{30000};
  std::chrono::milliseconds writeStallTimeout{0};
  std::chrono::seconds gcInterval{5};

  // === I/O ===
  int epollMaxEvents{256};
  std::size_t ioReadChunk{64 * 1024};
  std::size_t maxWriteQueue{1024};
  bool closeOnBackpressure{true};
  bool useEdgeTriggered{true};

  // === Socket ===
  bool enableTcpNoDelay{true};
  int soRcvBuf{0};
  int soSndBuf{0};
  std::uint8_t dscpValue{0};
  bool enableHighResolutionTimers{true};

  struct TcpKeepalive
  {
    bool enable{false};
    int idle{60};
    int interval{10};
    int count{3};
  } tcpKeepalive;

  // === UDP-specific ===
  std::size_t maxSessions{0};
  int listenBacklog{0};

  // === Sync operations ===
  std::size_t maxPendingSyncOps{32};
  std::size_t maxSyncReceiveBuffer{1024 * 1024};
  std::chrono::milliseconds defaultSyncTimeout{30000};
  bool allowReadModeSwitch{true};
  bool autoHealthMonitoring{true};

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
    c.autoHealthMonitoring = true;
    c.dscpValue = 24; // CS3
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
    c.autoHealthMonitoring = true;
    c.dscpValue = 24; // CS3
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
  // batchingStats: std::optional<BatchProcessingStats> deferred to Phase 4
  // (batching integration). Will be added when EventBatchProcessor is wired
  // into the engine. Default: std::nullopt when batching disabled.
};

} // namespace network
} // namespace iora