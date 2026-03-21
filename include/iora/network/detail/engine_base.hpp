#pragma once
#ifndef __linux__
#error "Linux-only (epoll/eventfd/timerfd)"
#endif

#include "iora/core/buffer_view.hpp"
#include "iora/network/transport_types.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace iora
{
namespace network
{
namespace detail
{

class EngineBase
{
public:
  virtual ~EngineBase() = default;

  struct Callbacks
  {
    std::function<void(SessionId, const TransportAddress &)> onAccept;
    std::function<void(SessionId, const TransportAddress &)> onConnect;
    std::function<void(SessionId, iora::core::BufferView, std::chrono::steady_clock::time_point)>
      onData;
    std::function<void(SessionId, const TransportErrorInfo &)> onClose;
    std::function<void(TransportError, const std::string &)> onError;
  };

  // Lifecycle
  virtual StartResult start() = 0;
  virtual void stop() = 0;
  virtual bool isRunning() const = 0;
  virtual TransportErrorInfo lastError() const = 0;

  // Connection management
  virtual ListenResult addListener(const std::string &bindIp, std::uint16_t port,
                                   TlsMode tlsMode) = 0;
  virtual ConnectResult connect(const std::string &host, std::uint16_t port,
                                TlsMode tlsMode) = 0;
  virtual ConnectResult connectViaListener(ListenerId lid, const std::string &host,
                                           std::uint16_t port) = 0;
  virtual bool close(SessionId sid) = 0;

  // Data operations (raw pointer — Transport wraps in BufferView at the public API level)
  virtual bool send(SessionId sid, const void *data, std::size_t len) = 0;
  virtual void sendAsync(SessionId sid, const void *data, std::size_t len,
                         SendCompleteCallback cb) = 0;

  // Callbacks (set once before start)
  virtual void setCallbacks(Callbacks cbs) = 0;

  // Stats
  virtual TransportStats getStats() const = 0;

  // Address introspection
  virtual TransportAddress getListenerAddress(ListenerId lid) const = 0;
  virtual TransportAddress getLocalAddress(SessionId sid) const = 0;
  virtual TransportAddress getRemoteAddress(SessionId sid) const = 0;

  // DSCP (per-session runtime change)
  virtual bool setDscp(SessionId sid, std::uint8_t dscp) = 0;

  // I/O thread identification (for deadlock detection in sync operations)
  virtual std::thread::id getIoThreadId() const = 0;

  // Emergency detach for destruction from I/O thread.
  // Sets _running=false and detaches the I/O thread so that the engine's
  // destructor doesn't deadlock trying to join the current thread.
  virtual void detachForTermination() = 0;
};

} // namespace detail
} // namespace network
} // namespace iora
