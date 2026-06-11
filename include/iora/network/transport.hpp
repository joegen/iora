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

// Test-only DI seam (DQ-8): forward declaration ONLY. Transport befriends this
// struct so engine-level fault-injection tests can reach the private withEngine()
// factory. Its DEFINITION lives in a test-only header (e.g.
// tests/network/transport_test_seam.hpp) that includes transport.hpp — production
// headers must NEVER include the test header.
namespace test
{
struct TransportEngineInjector;
} // namespace test

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

  virtual ReceiveResult receiveSync(SessionId sid, void *buffer, std::size_t &len,
                                    std::chrono::milliseconds timeout =
                                      std::chrono::milliseconds{30000}) = 0;

  virtual SendResult sendSyncCancellable(SessionId sid, iora::core::BufferView data,
                                         CancellationToken &token,
                                         std::chrono::milliseconds timeout =
                                           std::chrono::milliseconds{30000});

  virtual ReceiveResult receiveSyncCancellable(SessionId sid, void *buffer, std::size_t &len,
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
/// Owns an internal engine (TcpEngine or UdpEngine) via unique_ptr<EngineBase>.
/// Implements ITransport.
///
/// SHARED-OWNERSHIP-ONLY (S-3): a Transport exists ONLY inside a
/// std::shared_ptr<Transport>. Constructors are tag-gated private; the only
/// handles are the factories' shared_ptr returns; move and copy are deleted; the
/// class derives from std::enable_shared_from_this<Transport>. Any thread invoking
/// a method on a Transport therefore co-owns it for the call's duration, so an
/// I/O-thread callback can never drop the LAST reference mid-call — ~Transport can
/// never run on the I/O thread concurrently with another thread's call (closes C-1
/// structurally). The lone I/O-thread ~Transport path is a SOLE owner dropping its
/// last ref inside its own callback (single-threaded; handled by deferred-self-destruct).
///
/// Reference-cycle invariant: a callback (engine or user) must NEVER capture an
/// owning std::shared_ptr<Transport> of its OWN Transport — that makes the Transport
/// own itself. Capture the Impl `this` (as today) or a std::weak_ptr promoted per-use.
///
/// Construction (shared_ptr-returning factories; never start or bind):
///   Transport::tcp(TransportConfig config = {})                — TCP factory
///   Transport::udp(TransportConfig config = {})                — UDP factory
///
/// Method definitions are in transport_impl.hpp (include in exactly one TU).
class Transport final : public ITransport, public std::enable_shared_from_this<Transport>
{
private:
  // Passkey (DQ-1): makes the constructors effectively private — only Transport's
  // own factory members can name PrivateTag — while still permitting
  // std::make_shared (single allocation; enable_shared_from_this-compatible).
  struct PrivateTag
  {
  };

public:
  // Tag-gated constructors: callable only where PrivateTag is nameable, i.e. inside
  // Transport's own factory members (tcp/udp/withEngine in transport_impl.hpp). This
  // is NOT a public construction surface — use the factories.
  Transport(PrivateTag, TransportConfig config);
  Transport(PrivateTag, std::unique_ptr<detail::EngineBase> engine, TransportConfig config);
  ~Transport();

  // Shared-ownership only (HR-1/HR-2): move and copy are deleted. Deleting move
  // assignment removes the entire operator= teardown path (the most hazardous code).
  Transport(Transport &&) = delete;
  Transport &operator=(Transport &&) = delete;
  Transport(const Transport &) = delete;
  Transport &operator=(const Transport &) = delete;

  // Factory methods — return std::shared_ptr<Transport>; protocol-only, never start
  // or bind (HR-3). SIP presets are on TransportConfig::forSipTcp(), etc.
  static std::shared_ptr<Transport> tcp(TransportConfig config = {});
  static std::shared_ptr<Transport> udp(TransportConfig config = {});

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
  ReceiveResult receiveSync(SessionId sid, void *buffer, std::size_t &len,
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
  // DI / fault-injection seam (DQ-8): PRIVATE factory returning shared_ptr —
  // replaces the old public engine-injection constructor. Reached by engine-level
  // fault-injection tests via the friend accessor below; production code uses
  // tcp()/udp().
  static std::shared_ptr<Transport> withEngine(std::unique_ptr<detail::EngineBase> engine,
                                               TransportConfig config);

  // Test-only accessor for the private withEngine() factory. The struct itself is
  // forward-declared above and defined only in a test-only header — production
  // headers never include it.
  friend struct iora::network::test::TransportEngineInjector;

  struct Impl;
  std::unique_ptr<Impl> _impl;
};

} // namespace network
} // namespace iora
