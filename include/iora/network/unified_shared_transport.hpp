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

/// \file unified_shared_transport.hpp
/// \brief Unified transport facade providing both sync and async operations for
/// TCP/UDP \details
///   - Built on top of SyncAsyncTransport for sync/async capabilities
///   - Normalizes TCP/TLS and UDP transports behind a single interface
///   - Provides exclusive read modes, cancellation, and health monitoring
///   - Thread-safe with operation queueing
///

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <variant>

#include "sync_async_transport.hpp"
#include "shared_transport.hpp"
#include "shared_transport_udp.hpp"

namespace iora
{
namespace network
{

  /// \brief Exception thrown when an operation is not supported by the chosen
  /// protocol
  class UnsupportedOperation : public std::logic_error
  {
  public:
    explicit UnsupportedOperation(const std::string& what)
      : std::logic_error(what)
    {
    }
  };

  /// \brief Transport capabilities flags
  enum class Capability : std::uint32_t
  {
    None = 0u,
    HasTls = 1u << 0,
    IsConnectionOriented = 1u << 1,
    HasConnectViaListener = 1u << 2,
    SupportsKeepalive = 1u << 3,
    SupportsBatchSend = 1u << 4,
    SupportsSyncOperations =
        1u << 5, // All transports now support this via SyncAsyncTransport
    SupportsReadModes =
        1u << 6 // All transports now support this via SyncAsyncTransport
  };

  inline constexpr Capability operator|(Capability a, Capability b)
  {
    return static_cast<Capability>(static_cast<std::uint32_t>(a) |
                                   static_cast<std::uint32_t>(b));
  }

  inline constexpr Capability operator&(Capability a, Capability b)
  {
    return static_cast<Capability>(static_cast<std::uint32_t>(a) &
                                   static_cast<std::uint32_t>(b));
  }

  inline constexpr bool any(Capability c)
  {
    return static_cast<std::uint32_t>(c) != 0u;
  }

  /// \brief Unified statistics structure
  struct UnifiedStats
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
  };

  /// \brief Unified configuration supporting both TCP and UDP
  using UnifiedConfig =
      std::variant<SharedTransport::Config, SharedUdpTransport::Config>;

  /// \brief Unified TLS configuration
  using UnifiedTlsConfig =
      std::variant<SharedTransport::TlsConfig, SharedUdpTransport::TlsConfig>;

  /// \brief Unified callbacks for transport events
  struct UnifiedCallbacks
  {
    std::function<void(SessionId, const std::string&, const IoResult&)>
        onAccept;
    std::function<void(SessionId, const IoResult&)> onConnect;
    std::function<void(SessionId, const std::uint8_t*, std::size_t,
                       const IoResult&)>
        onData;
    std::function<void(SessionId, const IoResult&)> onClosed;
    std::function<void(TransportError, const std::string&)> onError;
  };

  /// \brief Abstract transport interface
  class ITransport : public ITransportBase
  {
  public:
    virtual ~ITransport() = default;
    virtual void setCallbacks(const UnifiedCallbacks& cbs) = 0;
    virtual SessionId connectViaListener(ListenerId lid,
                                         const std::string& host,
                                         std::uint16_t port) = 0;
    virtual void reconfigure(const UnifiedConfig& cfg) = 0;
    virtual UnifiedStats stats() const = 0;
    virtual Capability caps() const = 0;
  };

  /// \brief TCP/TLS transport adapter implementing ITransport interface
  class TcpTlsTransportAdapter final : public ITransport
  {
  public:
    TcpTlsTransportAdapter(const SharedTransport::Config& cfg,
                           const SharedTransport::TlsConfig& srvTls,
                           const SharedTransport::TlsConfig& cliTls)
      : _impl(cfg, srvTls, cliTls)
    {
    }

    void setCallbacks(const UnifiedCallbacks& cbs) override
    {
      SharedTransport::Callbacks t{};
      t.onAccept = cbs.onAccept;
      t.onConnect = cbs.onConnect;
      t.onData = cbs.onData;
      t.onClosed = cbs.onClosed;
      t.onError = cbs.onError;
      _impl.setCallbacks(t);
    }

    bool start() override { return _impl.start(); }
    void stop() override { _impl.stop(); }

    ListenerId addListener(const std::string& bindIp, std::uint16_t port,
                           TlsMode tlsMode) override
    {
      return _impl.addListener(bindIp, port, tlsMode);
    }

    SessionId connect(const std::string& host, std::uint16_t port,
                      TlsMode tlsMode) override
    {
      return _impl.connect(host, port, tlsMode);
    }

    SessionId connectViaListener(ListenerId, const std::string&,
                                 std::uint16_t) override
    {
      throw UnsupportedOperation(
          "connectViaListener is not supported on TCP/TLS");
    }

    bool send(SessionId sid, const void* data, std::size_t n) override
    {
      return _impl.send(sid, data, n);
    }

    bool close(SessionId sid) override { return _impl.close(sid); }

    void reconfigure(const UnifiedConfig& cfg) override
    {
      if (auto p = std::get_if<SharedTransport::Config>(&cfg))
      {
        _impl.reconfigure(*p);
        return;
      }
      throw UnsupportedOperation("Provided UDP config to TCP/TLS transport");
    }

    UnifiedStats stats() const override
    {
      auto s = _impl.stats();
      UnifiedStats u{};
      u.accepted = s.accepted;
      u.connected = s.connected;
      u.closed = s.closed;
      u.errors = s.errors;
      u.tlsHandshakes = s.tlsHandshakes;
      u.tlsFailures = s.tlsFailures;
      u.bytesIn = s.bytesIn;
      u.bytesOut = s.bytesOut;
      u.epollWakeups = s.epollWakeups;
      u.commands = s.commands;
      u.gcRuns = s.gcRuns;
      u.gcClosedIdle = s.gcClosedIdle;
      u.gcClosedAged = s.gcClosedAged;
      u.backpressureCloses = s.backpressureCloses;
      u.sessionsCurrent = s.sessionsCurrent;
      u.sessionsPeak = s.sessionsPeak;
      return u;
    }

    Capability caps() const override
    {
      return Capability::HasTls | Capability::IsConnectionOriented |
             Capability::SupportsKeepalive;
    }

    // ITransportBase callback setters (delegate directly to SharedTransport to
    // preserve existing callbacks)
    void setDataCallback(DataCallback cb) override
    {
      _impl.setDataCallback(cb);
    }

    void setAcceptCallback(AcceptCallback cb) override
    {
      _impl.setAcceptCallback(cb);
    }

    void setConnectCallback(ConnectCallback cb) override
    {
      _impl.setConnectCallback(cb);
    }

    void setCloseCallback(CloseCallback cb) override
    {
      _impl.setCloseCallback(cb);
    }

    void setErrorCallback(ErrorCallback cb) override
    {
      _impl.setErrorCallback(cb);
    }

    BasicTransportStats getBasicStats() const override
    {
      auto s = _impl.stats();
      BasicTransportStats basic{};
      basic.accepted = s.accepted;
      basic.connected = s.connected;
      basic.closed = s.closed;
      basic.errors = s.errors;
      basic.bytesIn = s.bytesIn;
      basic.bytesOut = s.bytesOut;
      basic.sessionsCurrent = s.sessionsCurrent;
      return basic;
    }

    SharedTransport& impl() { return _impl; }
    const SharedTransport& impl() const { return _impl; }

  private:
    SharedTransport _impl;
  };

  /// \brief UDP transport adapter implementing ITransport interface
  class UdpTransportAdapter final : public ITransport
  {
  public:
    explicit UdpTransportAdapter(const SharedUdpTransport::Config& cfg)
      : _impl(cfg, _dummyTls, _dummyTls)
    {
    }

    void setCallbacks(const UnifiedCallbacks& cbs) override
    {
      SharedUdpTransport::Callbacks u{};
      u.onAccept = cbs.onAccept;
      u.onConnect = cbs.onConnect;
      u.onData = cbs.onData;
      u.onClosed = cbs.onClosed;
      u.onError = cbs.onError;
      _impl.setCallbacks(u);
    }

    bool start() override { return _impl.start(); }
    void stop() override { _impl.stop(); }

    ListenerId addListener(const std::string& bindIp, std::uint16_t port,
                           TlsMode tlsMode) override
    {
      if (tlsMode != TlsMode::None)
      {
        throw UnsupportedOperation("TLS/DTLS is not supported on UDP");
      }
      return _impl.addListener(bindIp, port, TlsMode::None);
    }

    SessionId connect(const std::string& host, std::uint16_t port,
                      TlsMode tlsMode) override
    {
      if (tlsMode != TlsMode::None)
      {
        throw UnsupportedOperation("TLS/DTLS is not supported on UDP");
      }
      return _impl.connect(host, port, TlsMode::None);
    }

    SessionId connectViaListener(ListenerId lid, const std::string& host,
                                 std::uint16_t port) override
    {
      return _impl.connectViaListener(lid, host, port);
    }

    bool send(SessionId sid, const void* data, std::size_t n) override
    {
      return _impl.send(sid, data, n);
    }

    bool close(SessionId sid) override { return _impl.close(sid); }

    void reconfigure(const UnifiedConfig& cfg) override
    {
      if (auto p = std::get_if<SharedUdpTransport::Config>(&cfg))
      {
        _impl.reconfigure(*p);
        return;
      }
      throw UnsupportedOperation("Provided TCP/TLS config to UDP transport");
    }

    UnifiedStats stats() const override
    {
      auto s = _impl.stats();
      UnifiedStats u{};
      u.accepted = s.accepted;
      u.connected = s.connected;
      u.closed = s.closed;
      u.errors = s.errors;
      u.tlsHandshakes = s.tlsHandshakes;
      u.tlsFailures = s.tlsFailures;
      u.bytesIn = s.bytesIn;
      u.bytesOut = s.bytesOut;
      u.epollWakeups = s.epollWakeups;
      u.commands = s.commands;
      u.gcRuns = s.gcRuns;
      u.gcClosedIdle = s.gcClosedIdle;
      u.gcClosedAged = s.gcClosedAged;
      u.backpressureCloses = s.backpressureCloses;
      u.sessionsCurrent = s.sessionsCurrent;
      u.sessionsPeak = s.sessionsPeak;
      return u;
    }

    Capability caps() const override
    {
      return Capability::HasConnectViaListener | Capability::SupportsBatchSend;
    }

    // ITransportBase callback setters (delegate to setCallbacks)
    void setDataCallback(DataCallback cb) override
    {
      UnifiedCallbacks cbs;
      cbs.onData = cb;
      setCallbacks(cbs);
    }

    void setAcceptCallback(AcceptCallback cb) override
    {
      UnifiedCallbacks cbs;
      cbs.onAccept = [cb](SessionId sid, const std::string& peer,
                          const IoResult& result) { cb(sid, peer, result); };
      setCallbacks(cbs);
    }

    void setConnectCallback(ConnectCallback cb) override
    {
      UnifiedCallbacks cbs;
      cbs.onConnect = cb;
      setCallbacks(cbs);
    }

    void setCloseCallback(CloseCallback cb) override
    {
      UnifiedCallbacks cbs;
      cbs.onClosed = cb;
      setCallbacks(cbs);
    }

    void setErrorCallback(ErrorCallback cb) override
    {
      UnifiedCallbacks cbs;
      cbs.onError = cb;
      setCallbacks(cbs);
    }

    BasicTransportStats getBasicStats() const override
    {
      auto s = _impl.stats();
      BasicTransportStats basic{};
      basic.accepted = s.accepted;
      basic.connected = s.connected;
      basic.closed = s.closed;
      basic.errors = s.errors;
      basic.bytesIn = s.bytesIn;
      basic.bytesOut = s.bytesOut;
      basic.sessionsCurrent = s.sessionsCurrent;
      return basic;
    }

    SharedUdpTransport& impl() { return _impl; }
    const SharedUdpTransport& impl() const { return _impl; }

  private:
    SharedUdpTransport::TlsConfig _dummyTls{};
    SharedUdpTransport _impl;
  };

  /// \brief Unified transport providing sync/async operations for both TCP and
  /// UDP
  class UnifiedSharedTransport
  {
  public:
    /// \brief Transport protocol type
    enum class Protocol
    {
      TCP,
      UDP
    };

    /// \brief Unified configuration combining transport and hybrid settings
    struct Config
    {
      Protocol protocol{Protocol::TCP};

      // === Network Layer Settings ===
      std::chrono::seconds idleTimeout{600};
      std::chrono::seconds maxConnAge{std::chrono::seconds::zero()};
      std::chrono::seconds connectTimeout{30};
      std::chrono::seconds handshakeTimeout{30};
      std::chrono::seconds writeStallTimeout{0};
      std::chrono::seconds gcInterval{5};

      // Socket options
      bool enableTcpNoDelay{true};
      int soRcvBuf{0};
      int soSndBuf{0};
      bool useEdgeTriggered{true};
      bool closeOnBackpressure{true};

      // TCP-specific options
      struct TcpKeepalive
      {
        bool enable{false};
        int idleSec{60};
        int intvlSec{10};
        int cnt{3};
      } tcpKeepalive;

      // UDP-specific options
      std::size_t maxSessions{0}; // UDP only
      int listenBacklog{0};       // UDP only

      // === Sync/Async Layer Settings ===
      std::size_t maxPendingSyncOps{32};
      std::size_t maxSyncReceiveBuffer{1024 * 1024};
      std::chrono::milliseconds defaultSyncTimeout{30000};
      bool allowReadModeSwitch{true};
      bool autoHealthMonitoring{true};

      // === I/O Settings ===
      int epollMaxEvents{256};
      std::size_t ioReadChunk{64 * 1024};
      std::size_t maxWriteQueue{1024};

      // === TLS Settings ===
      struct TlsConfig
      {
        bool enabled{false};
        TlsMode defaultMode{TlsMode::None};
        std::string certFile;
        std::string keyFile;
        std::string caFile;
        std::string ciphers;
        std::string alpn;
        bool verifyPeer{false};
      } serverTls, clientTls;

      /// \brief Create config optimized for SIP over TCP
      static Config forSipTcp(const std::string& bindAddr = "0.0.0.0",
                              std::uint16_t port = 5060, bool enableTls = false)
      {
        Config config;
        config.protocol = Protocol::TCP;
        config.idleTimeout =
            std::chrono::seconds(3600);    // Long-lived SIP connections
        config.enableTcpNoDelay = true;    // Low latency
        config.tcpKeepalive.enable = true; // Detect dead peers
        config.tcpKeepalive.idleSec = 120; // SIP keepalive
        config.maxPendingSyncOps = 64;     // Many transactions
        config.defaultSyncTimeout = std::chrono::milliseconds(32000); // Timer B
        config.autoHealthMonitoring = true;

        if (enableTls)
        {
          config.serverTls.enabled = true;
          config.serverTls.defaultMode = TlsMode::Server;
          config.clientTls.enabled = true;
          config.clientTls.defaultMode = TlsMode::Client;
        }

        return config;
      }

      /// \brief Create config optimized for SIP over UDP
      static Config forSipUdp(const std::string& bindAddr = "0.0.0.0",
                              std::uint16_t port = 5060)
      {
        Config config;
        config.protocol = Protocol::UDP;
        config.idleTimeout = std::chrono::seconds(32); // Timer B
        config.maxSessions = 10000;                    // Many peers
        config.maxPendingSyncOps = 64;                 // Many transactions
        config.defaultSyncTimeout =
            std::chrono::milliseconds(500); // Faster for UDP
        config.autoHealthMonitoring = true;
        return config;
      }

      /// \brief Create minimal config for testing
      static Config minimal(Protocol protocol = Protocol::TCP)
      {
        Config config;
        config.protocol = protocol;
        config.idleTimeout = std::chrono::seconds(60);
        config.maxPendingSyncOps = 8;
        config.defaultSyncTimeout = std::chrono::milliseconds(1000);
        return config;
      }
    };

    /// \brief Construct unified transport with specified configuration
    explicit UnifiedSharedTransport(const Config& config)
      : _protocol(config.protocol), _config(config)
    {
      initializeTransport();
    }

    /// \brief Create transport with unified configuration
    static std::unique_ptr<UnifiedSharedTransport> create(const Config& config)
    {
      return std::make_unique<UnifiedSharedTransport>(config);
    }

    /// \brief Create TCP transport with minimal configuration
    static std::unique_ptr<UnifiedSharedTransport> createTcp()
    {
      return std::make_unique<UnifiedSharedTransport>(
          Config::minimal(Protocol::TCP));
    }

    /// \brief Create UDP transport with minimal configuration
    static std::unique_ptr<UnifiedSharedTransport> createUdp()
    {
      return std::make_unique<UnifiedSharedTransport>(
          Config::minimal(Protocol::UDP));
    }

    /// \brief Create SIP-optimized TCP transport
    static std::unique_ptr<UnifiedSharedTransport>
    createSipTcp(const std::string& bindAddr = "0.0.0.0",
                 std::uint16_t port = 5060, bool enableTls = false)
    {
      auto config = Config::forSipTcp(bindAddr, port, enableTls);
      auto transport = std::make_unique<UnifiedSharedTransport>(config);

      if (port > 0)
      {
        transport->start();
        transport->addListener(bindAddr, port,
                               enableTls ? TlsMode::Server : TlsMode::None);
      }

      return transport;
    }

    /// \brief Create SIP-optimized UDP transport
    static std::unique_ptr<UnifiedSharedTransport>
    createSipUdp(const std::string& bindAddr = "0.0.0.0",
                 std::uint16_t port = 5060)
    {
      auto config = Config::forSipUdp(bindAddr, port);
      auto transport = std::make_unique<UnifiedSharedTransport>(config);

      if (port > 0)
      {
        transport->start();
        transport->addListener(bindAddr, port);
      }

      return transport;
    }

    ~UnifiedSharedTransport() { stop(); }

    // Delete copy/move
    UnifiedSharedTransport(const UnifiedSharedTransport&) = delete;
    UnifiedSharedTransport& operator=(const UnifiedSharedTransport&) = delete;

    // ===== Lifecycle Management =====

    /// \brief Start the transport
    bool start()
    {
      if (!_hybrid)
      {
        return false;
      }
      return _hybrid->start();
    }

    /// \brief Stop the transport
    void stop()
    {
      iora::core::Logger::debug("UnifiedSharedTransport::stop() - Starting");
      if (_hybrid)
      {
        iora::core::Logger::debug(
            "UnifiedSharedTransport::stop() - Calling hybrid->stop()");
        _hybrid->stop();
        iora::core::Logger::debug(
            "UnifiedSharedTransport::stop() - hybrid->stop() completed");
      }
      iora::core::Logger::debug("UnifiedSharedTransport::stop() - Completed");
    }

    /// \brief Check if transport is running
    bool isRunning() const { return _hybrid != nullptr; }

    // ===== Read Mode Management (via SyncAsyncTransport) =====

    /// \brief Set the read mode for a session (exclusive access)
    bool setReadMode(SessionId sid, ReadMode mode)
    {
      return _hybrid->setReadMode(sid, mode);
    }

    /// \brief Get current read mode for a session
    ReadMode getReadMode(SessionId sid) const
    {
      return _hybrid->getReadMode(sid);
    }

    // ===== Async Operations (via SyncAsyncTransport) =====

    /// \brief Set async data callback (only works in Async read mode)
    bool setDataCallback(SessionId sid, SyncAsyncTransport::DataCallback cb)
    {
      return _hybrid->setDataCallback(sid, cb);
    }

    /// \brief Set async accept callback for incoming connections
    void setAcceptCallback(
        std::function<void(SessionId, const std::string&, const IoResult&)> cb)
    {
      _hybrid->getTransport()->setAcceptCallback(cb);
    }

    /// \brief Set async connect callback
    void setConnectCallback(SyncAsyncTransport::ConnectCallback cb)
    {
      _hybrid->setConnectCallback(cb);
    }

    /// \brief Set async close callback
    void setCloseCallback(SyncAsyncTransport::CloseCallback cb)
    {
      _hybrid->setCloseCallback(cb);
    }

    /// \brief Set async error callback
    void setErrorCallback(SyncAsyncTransport::ErrorCallback cb)
    {
      _hybrid->setErrorCallback(cb);
    }

    /// \brief Async send with optional completion callback
    void sendAsync(SessionId sid, const void* data, std::size_t len,
                   SyncAsyncTransport::SendCompleteCallback cb = nullptr)
    {
      _hybrid->sendAsync(sid, data, len, cb);
    }

    // ===== Sync Operations (via SyncAsyncTransport) =====

    /// \brief Synchronous send - blocks until complete or timeout
    SyncResult sendSync(
        SessionId sid, const void* data, std::size_t len,
        std::chrono::milliseconds timeout = std::chrono::milliseconds::max())
    {
      return _hybrid->sendSync(sid, data, len, timeout);
    }

    /// \brief Cancellable synchronous send
    SyncResult sendSyncCancellable(
        SessionId sid, const void* data, std::size_t len,
        CancellationToken& token,
        std::chrono::milliseconds timeout = std::chrono::milliseconds::max())
    {
      return _hybrid->sendSyncCancellable(sid, data, len, token, timeout);
    }

    /// \brief Synchronous receive - blocks until data available or timeout
    /// \note Only works in Sync read mode
    SyncResult receiveSync(
        SessionId sid, void* buffer, std::size_t& len,
        std::chrono::milliseconds timeout = std::chrono::milliseconds::max())
    {
      return _hybrid->receiveSync(sid, buffer, len, timeout);
    }

    /// \brief Cancellable synchronous receive
    SyncResult receiveSyncCancellable(
        SessionId sid, void* buffer, std::size_t& len, CancellationToken& token,
        std::chrono::milliseconds timeout = std::chrono::milliseconds::max())
    {
      return _hybrid->receiveSyncCancellable(sid, buffer, len, token, timeout);
    }

    // ===== Connection Management =====

    /// \brief Add a listener
    ListenerId addListener(const std::string& bind, std::uint16_t port,
                           TlsMode tls = TlsMode::None)
    {
      if (_protocol == Protocol::UDP && tls != TlsMode::None)
      {
        throw UnsupportedOperation("TLS/DTLS is not supported on UDP");
      }
      return _hybrid->addListener(bind, port, tls);
    }

    /// \brief Connect to a remote host
    SessionId connect(const std::string& host, std::uint16_t port,
                      TlsMode tls = TlsMode::None)
    {
      if (_protocol == Protocol::UDP && tls != TlsMode::None)
      {
        throw UnsupportedOperation("TLS/DTLS is not supported on UDP");
      }
      return _hybrid->connect(host, port, tls);
    }

    /// \brief Connect via a specific listener (UDP only)
    SessionId connectViaListener(ListenerId lid, const std::string& host,
                                 std::uint16_t port)
    {
      if (_protocol != Protocol::UDP)
      {
        throw UnsupportedOperation(
            "connectViaListener is only supported on UDP");
      }

      // Need to access the underlying UDP transport
      // This is a limitation - SyncAsyncTransport doesn't expose this method
      // We'll need to add it to SyncAsyncTransport or use a workaround
      throw UnsupportedOperation(
          "connectViaListener not yet implemented in SyncAsyncTransport");
    }

    /// \brief Close a session
    bool close(SessionId sid) { return _hybrid->close(sid); }

    /// \brief Cancel all pending sync operations for a session
    void cancelPendingOperations(SessionId sid)
    {
      _hybrid->cancelPendingOperations(sid);
    }

    // ===== Health and Statistics =====

    /// \brief Get connection health metrics
    HybridConnectionHealth getConnectionHealth(SessionId sid) const
    {
      return _hybrid->getConnectionHealth(sid);
    }

    /// \brief Get transport statistics
    UnifiedStats getStats() const
    {
      // Get basic stats from underlying transport and convert to UnifiedStats
      auto basic = _hybrid->getTransport()->getBasicStats();

      UnifiedStats unified{};
      unified.accepted = basic.accepted;
      unified.connected = basic.connected;
      unified.closed = basic.closed;
      unified.errors = basic.errors;
      unified.bytesIn = basic.bytesIn;
      unified.bytesOut = basic.bytesOut;
      unified.sessionsCurrent = basic.sessionsCurrent;

      return unified;
    }

    // ===== Protocol Information =====

    /// \brief Get the current protocol
    Protocol getProtocol() const { return _protocol; }

    /// \brief Get transport capabilities
    Capability getCapabilities() const
    {
      Capability caps =
          Capability::SupportsSyncOperations | Capability::SupportsReadModes;

      if (_protocol == Protocol::TCP)
      {
        caps = caps | Capability::HasTls | Capability::IsConnectionOriented |
               Capability::SupportsKeepalive;
      }
      else // UDP
      {
        caps = caps | Capability::HasConnectViaListener |
               Capability::SupportsBatchSend;
      }

      return caps;
    }

    /// \brief Check if a specific capability is supported
    bool hasCapability(Capability cap) const
    {
      return any(getCapabilities() & cap);
    }

    /// \brief Reconfigure the transport at runtime
    void reconfigure(const UnifiedConfig& config)
    {
      if (_protocol == Protocol::TCP)
      {
        if (!std::holds_alternative<SharedTransport::Config>(config))
        {
          throw UnsupportedOperation(
              "Cannot reconfigure TCP transport with UDP config");
        }
      }
      else // UDP
      {
        if (!std::holds_alternative<SharedUdpTransport::Config>(config))
        {
          throw UnsupportedOperation(
              "Cannot reconfigure UDP transport with TCP config");
        }
      }

      // Update config - SyncAsyncTransport doesn't expose reconfigure yet
      // This would need to be added to SyncAsyncTransport
    }

  private:
    void initializeTransport()
    {
      std::unique_ptr<ITransport> baseTransport;

      if (_protocol == Protocol::TCP)
      {
        // Convert unified config to TCP-specific config
        SharedTransport::Config tcpConfig;
        tcpConfig.epollMaxEvents = _config.epollMaxEvents;
        tcpConfig.ioReadChunk = _config.ioReadChunk;
        tcpConfig.maxWriteQueue = _config.maxWriteQueue;
        tcpConfig.closeOnBackpressure = _config.closeOnBackpressure;
        tcpConfig.idleTimeout = _config.idleTimeout;
        tcpConfig.maxConnAge = _config.maxConnAge;
        tcpConfig.handshakeTimeout = _config.handshakeTimeout;
        tcpConfig.gcInterval = _config.gcInterval;
        tcpConfig.connectTimeout = _config.connectTimeout;
        tcpConfig.writeStallTimeout = _config.writeStallTimeout;
        tcpConfig.useEdgeTriggered = _config.useEdgeTriggered;
        tcpConfig.enableTcpNoDelay = _config.enableTcpNoDelay;
        tcpConfig.soRcvBuf = _config.soRcvBuf;
        tcpConfig.soSndBuf = _config.soSndBuf;
        tcpConfig.tcpKeepalive.enable = _config.tcpKeepalive.enable;
        tcpConfig.tcpKeepalive.idleSec = _config.tcpKeepalive.idleSec;
        tcpConfig.tcpKeepalive.intvlSec = _config.tcpKeepalive.intvlSec;
        tcpConfig.tcpKeepalive.cnt = _config.tcpKeepalive.cnt;

        // Convert TLS config
        SharedTransport::TlsConfig serverTls;
        serverTls.enabled = _config.serverTls.enabled;
        serverTls.defaultMode = _config.serverTls.defaultMode;
        serverTls.certFile = _config.serverTls.certFile;
        serverTls.keyFile = _config.serverTls.keyFile;
        serverTls.caFile = _config.serverTls.caFile;
        serverTls.ciphers = _config.serverTls.ciphers;
        serverTls.alpn = _config.serverTls.alpn;
        serverTls.verifyPeer = _config.serverTls.verifyPeer;

        SharedTransport::TlsConfig clientTls;
        clientTls.enabled = _config.clientTls.enabled;
        clientTls.defaultMode = _config.clientTls.defaultMode;
        clientTls.certFile = _config.clientTls.certFile;
        clientTls.keyFile = _config.clientTls.keyFile;
        clientTls.caFile = _config.clientTls.caFile;
        clientTls.ciphers = _config.clientTls.ciphers;
        clientTls.alpn = _config.clientTls.alpn;
        clientTls.verifyPeer = _config.clientTls.verifyPeer;

        baseTransport = std::make_unique<TcpTlsTransportAdapter>(
            tcpConfig, serverTls, clientTls);
      }
      else // UDP
      {
        // Convert unified config to UDP-specific config
        SharedUdpTransport::Config udpConfig;
        udpConfig.epollMaxEvents = _config.epollMaxEvents;
        udpConfig.ioReadChunk = _config.ioReadChunk;
        udpConfig.maxWriteQueue = _config.maxWriteQueue;
        udpConfig.idleTimeout = _config.idleTimeout;
        udpConfig.maxConnAge = _config.maxConnAge;
        udpConfig.handshakeTimeout = _config.handshakeTimeout;
        udpConfig.gcInterval = _config.gcInterval;
        udpConfig.listenBacklog = _config.listenBacklog;
        udpConfig.maxSessions = _config.maxSessions;
        udpConfig.useEdgeTriggered = _config.useEdgeTriggered;
        udpConfig.closeOnBackpressure = _config.closeOnBackpressure;
        udpConfig.soRcvBuf = _config.soRcvBuf;
        udpConfig.soSndBuf = _config.soSndBuf;
        udpConfig.connectTimeout = _config.connectTimeout;
        udpConfig.writeStallTimeout = _config.writeStallTimeout;

        baseTransport = std::make_unique<UdpTransportAdapter>(udpConfig);
      }

      // Convert hybrid config
      SyncAsyncTransport::Config hybridConfig;
      hybridConfig.maxPendingSyncOps = _config.maxPendingSyncOps;
      hybridConfig.maxSyncReceiveBuffer = _config.maxSyncReceiveBuffer;
      hybridConfig.defaultTimeout = _config.defaultSyncTimeout;
      hybridConfig.allowReadModeSwitch = _config.allowReadModeSwitch;
      hybridConfig.autoHealthMonitoring = _config.autoHealthMonitoring;

      _hybrid = std::make_unique<SyncAsyncTransport>(std::move(baseTransport),
                                                  hybridConfig);
    }

  private:
    Protocol _protocol;
    Config _config;
    std::unique_ptr<SyncAsyncTransport> _hybrid;
  };

  // Note: SIP convenience functions are now built into the class as static
  // methods:
  // - UnifiedSharedTransport::createSipTcp()
  // - UnifiedSharedTransport::createSipUdp()

} // namespace network
} // namespace iora