#pragma once
#ifndef __linux__
#error "Linux-only (epoll/eventfd/timerfd)"
#endif

/// \file detail/udp_engine.hpp
/// \brief EngineBase adapter wrapping SharedUdpTransport for the new Transport API.

#include "iora/network/detail/engine_base.hpp"
#include "iora/network/shared_transport_udp.hpp"

#include <memory>
#include <string>

namespace iora
{
namespace network
{
namespace detail
{

class UdpEngine final : public EngineBase
{
public:
  explicit UdpEngine(const TransportConfig &config)
    : _config(config)
  {
    SharedUdpTransport::Config legacyCfg;
    legacyCfg.epollMaxEvents = config.epollMaxEvents;
    legacyCfg.ioReadChunk = config.ioReadChunk;
    legacyCfg.maxWriteQueue = config.maxWriteQueue;
    legacyCfg.idleTimeout = config.idleTimeout;
    legacyCfg.maxConnAge = config.maxConnAge;
    legacyCfg.handshakeTimeout = std::chrono::duration_cast<std::chrono::seconds>(config.handshakeTimeout);
    legacyCfg.gcInterval = config.gcInterval;
    legacyCfg.maxSessions = config.maxSessions;
    legacyCfg.listenBacklog = config.listenBacklog;
    legacyCfg.useEdgeTriggered = config.useEdgeTriggered;
    legacyCfg.closeOnBackpressure = config.closeOnBackpressure;
    legacyCfg.soRcvBuf = config.soRcvBuf;
    legacyCfg.soSndBuf = config.soSndBuf;
    legacyCfg.connectTimeout = std::chrono::duration_cast<std::chrono::seconds>(config.connectTimeout);
    legacyCfg.writeStallTimeout = std::chrono::duration_cast<std::chrono::seconds>(config.writeStallTimeout);

    SharedUdpTransport::TlsConfig dummyTls;
    _impl = std::make_unique<SharedUdpTransport>(legacyCfg, dummyTls, dummyTls);
  }

  ~UdpEngine() override = default;

  // ── Lifecycle ──────────────────────────────────────────────────────────────

  StartResult start() override
  {
    if (_impl->start())
    {
      return StartResult::ok();
    }
    return StartResult::err(TransportErrorInfo{TransportError::Config, "UDP transport start failed"});
  }

  void stop() override { _impl->stop(); }
  bool isRunning() const override { return _impl->isRunning(); }

  TransportErrorInfo lastError() const override
  {
    return TransportErrorInfo{TransportError::None, ""};
  }

  // ── Connection Management ──────────────────────────────────────────────────

  ListenResult addListener(const std::string &bindIp, std::uint16_t port,
                           TlsMode tlsMode) override
  {
    if (tlsMode != TlsMode::None)
    {
      return ListenResult::err(
        TransportErrorInfo{TransportError::Config, "TLS/DTLS not supported on UDP"});
    }
    ListenerId lid = _impl->addListener(bindIp, port, TlsMode::None);
    return ListenResult::ok(lid);
  }

  ConnectResult connect(const std::string &host, std::uint16_t port, TlsMode tlsMode) override
  {
    if (tlsMode != TlsMode::None)
    {
      return ConnectResult::err(
        TransportErrorInfo{TransportError::Config, "TLS/DTLS not supported on UDP"});
    }
    SessionId sid = _impl->connect(host, port, TlsMode::None);
    return ConnectResult::ok(sid);
  }

  ConnectResult connectViaListener(ListenerId lid, const std::string &host,
                                   std::uint16_t port) override
  {
    SessionId sid = _impl->connectViaListener(lid, host, port);
    return ConnectResult::ok(sid);
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
    SharedUdpTransport::Callbacks legacy;

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

  // ── Address Introspection (stub — implemented in Phase 7) ──────────────────

  TransportAddress getListenerAddress(ListenerId) const override { return {}; }
  TransportAddress getLocalAddress(SessionId) const override { return {}; }
  TransportAddress getRemoteAddress(SessionId) const override { return {}; }

  // ── DSCP (stub — implemented in Phase 7) ───────────────────────────────────

  bool setDscp(SessionId, std::uint8_t) override { return false; }

  // ── I/O Thread Identification ──────────────────────────────────────────────

  std::thread::id getIoThreadId() const override { return _impl->getIoThreadId(); }
  void detachForTermination() override { _impl->detachForTermination(); }

  // ── Access to underlying SharedUdpTransport ────────────────────────────────

  SharedUdpTransport &impl() { return *_impl; }
  const SharedUdpTransport &impl() const { return *_impl; }

private:
  TransportConfig _config;
  std::unique_ptr<SharedUdpTransport> _impl;
};

} // namespace detail
} // namespace network
} // namespace iora
