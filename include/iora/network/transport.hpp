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

/// \file transport.hpp
/// \brief Single entry point for iora's transport layer.
/// \details
///   - ITransport: pure virtual interface — the entire public API contract
///   - Transport: concrete implementation (TCP or UDP, one protocol per instance)
///   - Does NOT include engine headers (epoll, OpenSSL) — see transport_impl.hpp
///

#include "iora/network/transport_types.hpp"

#include <chrono>
#include <memory>
#include <string>

namespace iora
{
namespace network
{

// Forward declaration — defined in detail/engine_base.hpp.
// Transport owns a unique_ptr<EngineBase>. Consumers never interact with engines.
namespace detail
{
class EngineBase;
} // namespace detail

// CancellationToken and ReadMode are defined in transport_types.hpp (included above).

/// \brief Abstract transport interface — the single public API contract.
///
/// Transport (production) and TestTransport (test double) both implement this.
/// Higher layers accept ITransport& so they can be tested without real sockets.
///
/// Callback contract: callbacks are invoked from the I/O thread. They must not
/// block, must not call stop(), and must not call addListener(). Expensive work
/// should be posted to a work queue.
class ITransport
{
public:
  virtual ~ITransport() = default;

  // ===== Lifecycle =====
  virtual StartResult start() = 0;
  virtual void stop() = 0;
  virtual bool isRunning() const = 0;
  virtual TransportErrorInfo lastError() const = 0;

  // ===== Connection Management =====
  virtual ListenResult addListener(const std::string &bindIp, std::uint16_t port,
                                   TlsMode tls = TlsMode::None) = 0;
  virtual ConnectResult connect(const std::string &host, std::uint16_t port,
                                TlsMode tls = TlsMode::None) = 0;
  virtual ConnectResult connectViaListener(ListenerId lid, const std::string &host,
                                           std::uint16_t port) = 0;
  virtual bool close(SessionId sid) = 0;

  // ===== Async Data Operations =====
  // Primary overloads use BufferView (zero-copy). Raw pointer+size convenience below.
  virtual bool send(SessionId sid, iora::core::BufferView data) = 0;
  virtual void sendAsync(SessionId sid, iora::core::BufferView data,
                         SendCompleteCallback cb = nullptr) = 0;

  // Convenience overloads — construct BufferView from raw pointer+size.
  virtual bool send(SessionId sid, const void *data, std::size_t len)
  {
    return send(sid, iora::core::BufferView{static_cast<const std::uint8_t *>(data), len});
  }

  virtual void sendAsync(SessionId sid, const void *data, std::size_t len,
                         SendCompleteCallback cb = nullptr)
  {
    sendAsync(sid, iora::core::BufferView{static_cast<const std::uint8_t *>(data), len}, cb);
  }

  // ===== Sync Connection Operations =====
  virtual ConnectResult connectSync(const std::string &host, std::uint16_t port,
                                    TlsMode tls = TlsMode::None,
                                    std::chrono::milliseconds timeout =
                                      std::chrono::milliseconds{30000}) = 0;

  virtual ConnectResult connectSyncCancellable(const std::string &host, std::uint16_t port,
                                               CancellationToken &token,
                                               TlsMode tls = TlsMode::None,
                                               std::chrono::milliseconds timeout =
                                                 std::chrono::milliseconds{30000});

  // ===== Sync Data Operations =====
  virtual SendResult sendSync(SessionId sid, iora::core::BufferView data,
                              std::chrono::milliseconds timeout =
                                std::chrono::milliseconds{30000}) = 0;

  virtual SendResult receiveSync(SessionId sid, void *buffer, std::size_t &len,
                                 std::chrono::milliseconds timeout =
                                   std::chrono::milliseconds{30000}) = 0;

  virtual SendResult sendSyncCancellable(SessionId sid, iora::core::BufferView data,
                                         CancellationToken &token,
                                         std::chrono::milliseconds timeout =
                                           std::chrono::milliseconds{30000});

  virtual SendResult receiveSyncCancellable(SessionId sid, void *buffer, std::size_t &len,
                                            CancellationToken &token,
                                            std::chrono::milliseconds timeout =
                                              std::chrono::milliseconds{30000});

  // ===== Read Modes =====
  virtual bool setReadMode(SessionId sid, ReadMode mode) = 0;
  virtual bool getReadMode(SessionId sid, ReadMode &mode) const = 0;

  // ===== Callbacks (individual setters per DQ4) =====
  virtual void onAccept(AcceptCallback cb) = 0;
  virtual void onConnect(ConnectCallback cb) = 0;
  virtual void onData(DataCallback cb) = 0;
  virtual void onClose(CloseCallback cb) = 0;
  virtual void onError(ErrorCallback cb) = 0;

  // ===== Per-Session Observers =====
  virtual ObserverId observe(SessionId sid, CloseCallback cb) = 0;
  virtual bool unobserve(ObserverId id) = 0;

  // ===== Session Introspection =====
  virtual TransportAddress getListenerAddress(ListenerId lid) const = 0;
  virtual TransportAddress getLocalAddress(SessionId sid) const = 0;
  virtual TransportAddress getRemoteAddress(SessionId sid) const = 0;
  virtual void setSessionData(SessionId sid, void *data,
                              SessionCleanupCallback cleanup = nullptr) = 0;
  virtual void *getSessionData(SessionId sid) const = 0;

  // ===== Stats =====
  virtual TransportStats getStats() const = 0;
  virtual Protocol getProtocol() const = 0;
};

/// \brief Concrete transport implementation — single protocol per instance.
///
/// Owns an internal engine (SharedTransport or UdpEngine) via unique_ptr<EngineBase>.
/// Implements ITransport. Non-copyable, movable.
///
/// Construction:
///   Transport(TransportConfig config)                          — normal construction
///   Transport(std::unique_ptr<detail::EngineBase> engine,
///             TransportConfig config)                          — engine injection (testing)
///   Transport::tcp(TransportConfig config = {})                — TCP factory
///   Transport::udp(TransportConfig config = {})                — UDP factory
///
/// Method definitions are in transport_impl.hpp (include in exactly one TU).
class Transport final : public ITransport
{
public:
  explicit Transport(TransportConfig config);
  Transport(std::unique_ptr<detail::EngineBase> engine, TransportConfig config);
  ~Transport();

  Transport(Transport &&other) noexcept;
  Transport &operator=(Transport &&other) noexcept;
  Transport(const Transport &) = delete;
  Transport &operator=(const Transport &) = delete;

  // Factory methods — protocol-only, never start or bind (HR-3).
  // SIP presets are on TransportConfig::forSipTcp(), etc.
  static Transport tcp(TransportConfig config = {});
  static Transport udp(TransportConfig config = {});

  // ===== ITransport Implementation =====
  StartResult start() override;
  void stop() override;
  bool isRunning() const override;
  TransportErrorInfo lastError() const override;

  ListenResult addListener(const std::string &bindIp, std::uint16_t port,
                           TlsMode tls = TlsMode::None) override;
  ConnectResult connect(const std::string &host, std::uint16_t port,
                        TlsMode tls = TlsMode::None) override;
  ConnectResult connectViaListener(ListenerId lid, const std::string &host,
                                   std::uint16_t port) override;
  bool close(SessionId sid) override;

  bool send(SessionId sid, iora::core::BufferView data) override;
  void sendAsync(SessionId sid, iora::core::BufferView data,
                 SendCompleteCallback cb = nullptr) override;
  using ITransport::send;     // Bring in raw-pointer convenience overloads
  using ITransport::sendAsync;

  ConnectResult connectSync(const std::string &host, std::uint16_t port,
                            TlsMode tls = TlsMode::None,
                            std::chrono::milliseconds timeout =
                              std::chrono::milliseconds{30000}) override;

  SendResult sendSync(SessionId sid, iora::core::BufferView data,
                      std::chrono::milliseconds timeout =
                        std::chrono::milliseconds{30000}) override;
  SendResult receiveSync(SessionId sid, void *buffer, std::size_t &len,
                         std::chrono::milliseconds timeout =
                           std::chrono::milliseconds{30000}) override;

  bool setReadMode(SessionId sid, ReadMode mode) override;
  bool getReadMode(SessionId sid, ReadMode &mode) const override;

  void onAccept(AcceptCallback cb) override;
  void onConnect(ConnectCallback cb) override;
  void onData(DataCallback cb) override;
  void onClose(CloseCallback cb) override;
  void onError(ErrorCallback cb) override;

  ObserverId observe(SessionId sid, CloseCallback cb) override;
  bool unobserve(ObserverId id) override;

  TransportAddress getListenerAddress(ListenerId lid) const override;
  TransportAddress getLocalAddress(SessionId sid) const override;
  TransportAddress getRemoteAddress(SessionId sid) const override;
  void setSessionData(SessionId sid, void *data,
                      SessionCleanupCallback cleanup = nullptr) override;
  void *getSessionData(SessionId sid) const override;

  TransportStats getStats() const override;
  Protocol getProtocol() const override;

private:
  struct Impl;
  std::unique_ptr<Impl> _impl;
};

} // namespace network
} // namespace iora
