#pragma once
#ifndef __linux__
#error "Linux-only (epoll/eventfd/timerfd)"
#endif

/// \file detail/tcp_engine.hpp
/// \brief EngineBase adapter wrapping SharedTransport for the new Transport API.
/// \details
///   - Composition-based: owns a SharedTransport instance
///   - Bridges legacy callback/return types to new EngineBase interface
///   - SharedTransport is unchanged — backward compatibility preserved
///   - Will be replaced by direct EngineBase implementation when SharedTransport
///     is refactored in-place (Phase 7)
///

#include "iora/network/detail/engine_base.hpp"
#include "iora/network/shared_transport.hpp"

#include <memory>
#include <string>

namespace iora
{
namespace network
{
namespace detail
{

class TcpEngine final : public EngineBase
{
public:
  explicit TcpEngine(const TransportConfig &config)
    : _config(config)
  {
    SharedTransport::Config legacyCfg;
    legacyCfg.epollMaxEvents = config.epollMaxEvents;
    legacyCfg.ioReadChunk = config.ioReadChunk;
    legacyCfg.maxWriteQueue = config.maxWriteQueue;
    legacyCfg.closeOnBackpressure = config.closeOnBackpressure;
    legacyCfg.idleTimeout = config.idleTimeout;
    legacyCfg.maxConnAge = config.maxConnAge;
    legacyCfg.handshakeTimeout = config.handshakeTimeout;
    legacyCfg.connectTimeout = config.connectTimeout;
    legacyCfg.writeStallTimeout = config.writeStallTimeout;
    legacyCfg.gcInterval = config.gcInterval;
    legacyCfg.enableHighResolutionTimers = config.enableHighResolutionTimers;
    legacyCfg.useEdgeTriggered = config.useEdgeTriggered;
    legacyCfg.enableTcpNoDelay = config.enableTcpNoDelay;
    legacyCfg.soRcvBuf = config.soRcvBuf;
    legacyCfg.soSndBuf = config.soSndBuf;
    legacyCfg.tcpKeepalive.enable = config.tcpKeepalive.enable;
    legacyCfg.tcpKeepalive.idleSec = config.tcpKeepalive.idle;
    legacyCfg.tcpKeepalive.intvlSec = config.tcpKeepalive.interval;
    legacyCfg.tcpKeepalive.cnt = config.tcpKeepalive.count;

    SharedTransport::TlsConfig srvTls;
    convertTls(config.serverTls, srvTls);
    SharedTransport::TlsConfig cliTls;
    convertTls(config.clientTls, cliTls);

    _impl = std::make_unique<SharedTransport>(legacyCfg, srvTls, cliTls);
  }

  // Engine injection for testing — wraps an existing SharedTransport (subclass)
  explicit TcpEngine(std::unique_ptr<SharedTransport> impl, const TransportConfig &config)
    : _config(config), _impl(std::move(impl))
  {
  }

  ~TcpEngine() override = default;

  // ── Lifecycle ──────────────────────────────────────────────────────────────

  StartResult start() override
  {
    if (_impl->start())
    {
      return StartResult::ok();
    }
    auto fatal = _impl->lastFatalError();
    return StartResult::err(
      TransportErrorInfo{fatal.code, fatal.message, fatal.sysErrno, fatal.tlsError});
  }

  void stop() override { _impl->stop(); }

  bool isRunning() const override { return _impl->isRunning(); }

  TransportErrorInfo lastError() const override
  {
    auto fatal = _impl->lastFatalError();
    return TransportErrorInfo{fatal.code, fatal.message, fatal.sysErrno, fatal.tlsError};
  }

  // ── Connection Management ──────────────────────────────────────────────────

  ListenResult addListener(const std::string &bindIp, std::uint16_t port,
                           TlsMode tlsMode) override
  {
    ListenerId lid = _impl->addListener(bindIp, port, tlsMode);
    return ListenResult::ok(lid);
  }

  ConnectResult connect(const std::string &host, std::uint16_t port, TlsMode tlsMode) override
  {
    SessionId sid = _impl->connect(host, port, tlsMode);
    return ConnectResult::ok(sid);
  }

  ConnectResult connectViaListener(ListenerId, const std::string &, std::uint16_t) override
  {
    return ConnectResult::err(
      TransportErrorInfo{TransportError::Config, "connectViaListener not supported on TCP/TLS"});
  }

  bool close(SessionId sid) override { return _impl->close(sid); }

  // ── Data Operations ────────────────────────────────────────────────────────

  bool send(SessionId sid, const void *data, std::size_t len) override
  {
    return _impl->send(sid, data, len);
  }

  void sendAsync(SessionId sid, const void *data, std::size_t len,
                 SendCompleteCallback cb) override
  {
    bool ok = _impl->send(sid, data, len);
    if (cb)
    {
      if (ok)
      {
        cb(sid, SendResult::ok(len));
      }
      else
      {
        cb(sid, SendResult::err(TransportErrorInfo{TransportError::Socket, "send enqueue failed"}));
      }
    }
  }

  // ── Callbacks ──────────────────────────────────────────────────────────────

  void setCallbacks(Callbacks cbs) override
  {
    SharedTransport::Callbacks legacy;

    auto engineOnAccept = std::move(cbs.onAccept);
    auto engineOnConnect = std::move(cbs.onConnect);
    auto engineOnData = std::move(cbs.onData);
    auto engineOnClose = std::move(cbs.onClose);
    auto engineOnError = std::move(cbs.onError);

    if (engineOnAccept)
    {
      legacy.onAccept = [cb = std::move(engineOnAccept)](SessionId sid, const std::string &peer,
                                                         const IoResult &)
      {
        auto colon = peer.rfind(':');
        TransportAddress addr;
        if (colon != std::string::npos)
        {
          addr.host = peer.substr(0, colon);
          try
          {
            addr.port = static_cast<std::uint16_t>(std::stoi(peer.substr(colon + 1)));
          }
          catch (...)
          {
            addr.port = 0;
          }
        }
        else
        {
          addr.host = peer;
        }
        cb(sid, addr);
      };
    }

    if (engineOnConnect)
    {
      legacy.onConnect = [cb = std::move(engineOnConnect)](SessionId sid, const IoResult &)
      { cb(sid, TransportAddress{}); };
    }

    if (engineOnData)
    {
      legacy.onData = [cb = std::move(engineOnData)](SessionId sid, const std::uint8_t *data,
                                                     std::size_t len, const IoResult &)
      { cb(sid, iora::core::BufferView{data, len}, std::chrono::steady_clock::now()); };
    }

    if (engineOnClose)
    {
      legacy.onClosed = [cb = std::move(engineOnClose)](SessionId sid, const IoResult &r)
      { cb(sid, TransportErrorInfo{r.code, r.message, r.sysErrno, r.tlsError}); };
    }

    if (engineOnError)
    {
      legacy.onError = std::move(engineOnError);
    }

    _impl->setCallbacks(legacy);
  }

  // ── Stats ──────────────────────────────────────────────────────────────────

  TransportStats getStats() const override
  {
    auto s = _impl->stats();
    TransportStats ts;
    ts.accepted = s.accepted;
    ts.connected = s.connected;
    ts.closed = s.closed;
    ts.errors = s.errors;
    ts.tlsHandshakes = s.tlsHandshakes;
    ts.tlsFailures = s.tlsFailures;
    ts.bytesIn = s.bytesIn;
    ts.bytesOut = s.bytesOut;
    ts.epollWakeups = s.epollWakeups;
    ts.commands = s.commands;
    ts.gcRuns = s.gcRuns;
    ts.gcClosedIdle = s.gcClosedIdle;
    ts.gcClosedAged = s.gcClosedAged;
    ts.backpressureCloses = s.backpressureCloses;
    ts.sessionsCurrent = s.sessionsCurrent;
    ts.sessionsPeak = s.sessionsPeak;
    return ts;
  }

  // ── Address Introspection ──────────────────────────────────────────────────

  TransportAddress getListenerAddress(ListenerId) const override
  {
    // SharedTransport does not expose listener address directly.
    // This will be implemented when SharedTransport gains the method,
    // or when TcpEngine replaces SharedTransport entirely (Phase 7).
    return {};
  }

  TransportAddress getLocalAddress(SessionId) const override
  {
    // SharedTransport does not expose per-session local address.
    // Will be implemented in Phase 7 when TcpEngine has direct session access.
    return {};
  }

  TransportAddress getRemoteAddress(SessionId) const override
  {
    // SharedTransport does not expose structured remote address.
    // Will be implemented in Phase 7 when TcpEngine has direct session access.
    return {};
  }

  // ── DSCP ───────────────────────────────────────────────────────────────────

  bool setDscp(SessionId, std::uint8_t) override
  {
    // SharedTransport does not expose per-session socket fd.
    // Will be implemented in Phase 7 when TcpEngine has direct session access.
    return false;
  }

  // ── I/O Thread Identification ────────────────────────────────────────────────

  std::thread::id getIoThreadId() const override { return _impl->getIoThreadId(); }
  void detachForTermination() override { _impl->detachForTermination(); }

  // ── Access to underlying SharedTransport (for testing/backward compat) ─────

  SharedTransport &impl() { return *_impl; }
  const SharedTransport &impl() const { return *_impl; }

private:
  static void convertTls(const TransportConfig::TlsConfig &src, SharedTransport::TlsConfig &dst)
  {
    dst.enabled = src.enabled;
    dst.defaultMode = src.defaultMode;
    dst.certFile = src.certFile;
    dst.keyFile = src.keyFile;
    dst.caFile = src.caFile;
    dst.ciphers = src.ciphers;
    dst.alpn = src.alpn;
    dst.verifyPeer = src.verifyPeer;
  }

  TransportConfig _config;
  std::unique_ptr<SharedTransport> _impl;
};

} // namespace detail
} // namespace network
} // namespace iora
