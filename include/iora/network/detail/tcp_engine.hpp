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

/// \file detail/tcp_engine.hpp
/// \brief Header-only, Linux-only epoll-based TCP/TLS engine (EngineBase implementation).
/// \details
///   - Single I/O thread (epoll + eventfd + timerfd)
///   - Async accept/connect/read/write with internal session GC
///   - Optional TLS (OpenSSL) for server and client
///   - Safety-net timeouts: idle/connect/handshake/write-stall/max-age
///   - EngineBase::Callbacks with TransportAddress/TransportErrorInfo/BufferView signatures
///   - Thread-safe public API (signals I/O thread via eventfd)
///

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "iora/core/logger.hpp"
#include "iora/core/timer.hpp"
#include "iora/network/detail/engine_base.hpp"
#include "iora/network/event_batch_processor.hpp"
#include "iora/network/transport_types.hpp"
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace iora
{
namespace network
{

/// \brief Shared TCP/TLS transport (single-threaded epoll loop).
/// \note Linux-only.
///
/// \par Subclassing Support
/// This class supports subclassing for testing purposes. Protected virtual hooks
/// are provided to enable fault injection at the TLS layer:
/// - beforeSslHandshake() - called before SSL_do_handshake()
/// - afterSslHandshake() - called after SSL_do_handshake() completes
/// - beforeSslRead() - called before SSL_read()
/// - beforeSslWrite() - called before SSL_write()
///
/// All hooks are called from the I/O thread context. Subclasses must be thread-safe
/// if they access shared state. The destructor is virtual to support proper cleanup.
///
/// \see TlsFaultInjectionTransport in tests/sipp_integration/ for usage example.
class TcpEngine : public detail::EngineBase
{
public:
  /// \brief Construct from TransportConfig.
  explicit TcpEngine(const TransportConfig &config)
      : _config(config)
  {
    // Ensure OpenSSL is initialized once per process
    std::call_once(_sslGlobalInitFlag, initSslGlobal);

    // Initialize high-resolution timer service if enabled
    if (_config.enableHighResolutionTimers)
    {
      _timerConfig.limits.maxConcurrentTimers = 10000;
      _timerConfig.enableStatistics = true;
      _timerConfig.threadName = "TcpEngineTimer";
      _timerService = std::make_unique<iora::core::TimerService>(_timerConfig);
    }
  }

  /// \brief Destructor; calls stop() if needed.
  /// \note Virtual to support subclassing for fault injection testing.
  virtual ~TcpEngine() { stop(); }

  TcpEngine(const TcpEngine &) = delete;
  TcpEngine &operator=(const TcpEngine &) = delete;

  /// \brief Emergency detach for destruction from I/O thread.
  /// Sets _running to false and detaches the I/O thread so that
  /// ~TcpEngine's stop() becomes a no-op (CAS fails, thread
  /// not joinable). The I/O thread exits its loop naturally when it
  /// sees _running == false. This is a last-resort safety net for
  /// the case where Transport is destroyed from within a callback.
  void detachForTermination() override
  {
    _running.store(false, std::memory_order_release);
    if (_loop.joinable())
    {
      _loop.detach();
    }
  }

  /// \brief Install callbacks (may be called before or after start()).
  void setCallbacks(detail::EngineBase::Callbacks cbs) override
  {
    std::lock_guard<std::mutex> g(_cbMutex);
    _cbs = std::move(cbs);
  }

  /// \brief Start I/O thread and initialize TLS contexts.
  /// \return StartResult::ok() on success; StartResult::err() on failure.
  StartResult start() override
  {
    bool exp = false;
    if (!_running.compare_exchange_strong(exp, true))
    {
      return StartResult::err(
        TransportErrorInfo{TransportError::Config, "already running"});
    }

    if (!initTls())
    {
      _running.store(false);
      return StartResult::err(lastError());
    }

    _epollFd = ::epoll_create1(EPOLL_CLOEXEC);
    if (_epollFd < 0)
    {
      setLastFatal(IoResult::failure(TransportError::Config, "epoll_create1: " + lastErr(), errno));
      err(TransportError::Config, "epoll_create1: " + lastErr());
      _running.store(false);
      freeTls();
      return StartResult::err(lastError());
    }

    _eventFd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (_eventFd < 0)
    {
      setLastFatal(IoResult::failure(TransportError::Config, "eventfd: " + lastErr(), errno));
      err(TransportError::Config, "eventfd: " + lastErr());
      cleanupStartFail();
      return StartResult::err(lastError());
    }
    addEpoll(_eventFd, EPOLLIN);

    _timerFd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (_timerFd < 0)
    {
      setLastFatal(
        IoResult::failure(TransportError::Config, "timerfd_create: " + lastErr(), errno));
      err(TransportError::Config, "timerfd_create: " + lastErr());
      cleanupStartFail();
      return StartResult::err(lastError());
    }
    addEpoll(_timerFd, EPOLLIN);
    armGc(_config.gcInterval);

    if (_config.batching.enabled)
    {
      BatchProcessingConfig batchCfg;
      batchCfg.maxBatchSize = _config.batching.maxBatchSize;
      batchCfg.maxBatchDelay = _config.batching.maxBatchDelay;
      batchCfg.adaptiveThreshold = _config.batching.adaptiveThreshold;
      batchCfg.enableAdaptiveSizing = _config.batching.enableAdaptiveSizing;
      batchCfg.loadFactor = _config.batching.loadFactor;
      _batchProcessor = std::make_unique<EventBatchProcessor>(batchCfg);
    }

    try
    {
      _loop = std::thread([this]
      {
        // Block SIGPIPE on this I/O thread only. SSL_write uses the underlying
        // send() without MSG_NOSIGNAL, so writing to a closed peer can deliver
        // SIGPIPE. Blocking it per-thread avoids process-wide side effects.
        sigset_t sigpipeSet;
        sigemptyset(&sigpipeSet);
        sigaddset(&sigpipeSet, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &sigpipeSet, nullptr);
        loop();
      });
    }
    catch (const std::exception &ex)
    {
      setLastFatal(
        IoResult::failure(TransportError::Config, std::string("thread start: ") + ex.what()));
      cleanupStartFail();
      return StartResult::err(lastError());
    }

    return StartResult::ok();
  }

  /// \brief Stop I/O thread and release resources.
  void stop() override
  {
    bool exp = true;
    if (!_running.compare_exchange_strong(exp, false))
    {
      return;
    }
    enqueue(Command::shutdown());
    if (_loop.joinable())
    {
      _loop.join();
    }
  }

  /// \brief Add a listening socket (IPv4/IPv6), optionally with TLS for
  /// server.
  ListenResult addListener(const std::string &bind, std::uint16_t port, TlsMode tls) override
  {
    ListenerCfg lc;
    lc.id = _nextListenerId++;
    lc.addr = bind;
    lc.port = port;
    lc.tls = tls;

    if (_running.load())
    {
      // Synchronous: wait for I/O thread to complete the bind so the listener
      // is ready to accept connections when this method returns.
      auto ready = std::make_shared<std::promise<bool>>();
      auto fut = ready->get_future();
      enqueue(Command::addListener(lc, std::move(ready)));
      bool ok = fut.get(); // blocks until I/O thread processes the command
      if (!ok)
      {
        return ListenResult::err(
          TransportErrorInfo{TransportError::Bind,
            "bind/listen failed on " + bind + ":" + std::to_string(port)});
      }
      return ListenResult::ok(lc.id);
    }
    else
    {
      enqueue(Command::addListener(lc));
    }
    return ListenResult::ok(lc.id);
  }

  /// \brief Begin an outbound connection (async); result via onConnect.
  ConnectResult connect(const std::string &host, std::uint16_t port, TlsMode tls) override
  {
    SessionId sid = _nextSessionId++;
    ConnectReq cr{sid, host, port, tls};
    enqueue(Command::connect(cr));
    return ConnectResult::ok(sid);
  }

  /// \brief Queue a send on a session (non-blocking; may enqueue on EAGAIN).
  bool send(SessionId sid, const void *data, std::size_t n) override
  {
    if (n == 0)
    {
      return true;
    }
    IORA_LOG_DEBUG("[SHARED-TRANSPORT] send() called for sid=" << sid << ", size=" << n);
    ByteBuffer b(n);
    std::memcpy(b.data(), data, n);
    SendReq sr;
    sr.sid = sid;
    sr.payload = std::move(b);
    bool result = enqueue(Command::send(std::move(sr)));
    IORA_LOG_DEBUG("[SHARED-TRANSPORT] send() enqueue " << (result ? "succeeded" : "failed") << " for sid=" << sid);
    return result;
  }

  /// \brief Close a session (idempotent). onClose will fire.
  bool close(SessionId sid) override { return enqueue(Command::close(sid)); }

  /// \brief Snapshot of counters.
  TransportStats getStats() const override
  {
    TransportStats ts;
    ts.accepted = _atomicStats.accepted.load();
    ts.connected = _atomicStats.connected.load();
    ts.closed = _atomicStats.closed.load();
    ts.errors = _atomicStats.errors.load();
    ts.tlsHandshakes = _atomicStats.tlsHandshakes.load();
    ts.tlsFailures = _atomicStats.tlsFailures.load();
    ts.bytesIn = _atomicStats.bytesIn.load();
    ts.bytesOut = _atomicStats.bytesOut.load();
    ts.epollWakeups = _atomicStats.epollWakeups.load();
    ts.commands = _atomicStats.commands.load();
    ts.gcRuns = _atomicStats.gcRuns.load();
    ts.gcClosedIdle = _atomicStats.gcClosedIdle.load();
    ts.gcClosedAged = _atomicStats.gcClosedAged.load();
    ts.backpressureCloses = _atomicStats.backpressureCloses.load();
    ts.sessionsCurrent = _atomicStats.sessionsCurrent.load();
    ts.sessionsPeak = _atomicStats.sessionsPeak.load();
    if (_batchProcessor)
    {
      ts.batchingStats = _batchProcessor->getStats();
    }
    return ts;
  }

  /// \brief Sticky last fatal error (since process start). Valid after
  /// start() failure.
  IoResult lastFatalError() const
  {
    std::lock_guard<std::mutex> g(_fatalMx);
    return _lastFatal;
  }

  /// \brief Check if the transport I/O loop is running.
  bool isRunning() const override { return _running.load(std::memory_order_acquire); }

  /// \brief Get I/O thread ID for deadlock detection
  /// \return Thread ID of the I/O event loop thread, or default-constructed ID if not running
  /// \note Used by SyncAsyncTransport to detect when sendSync() is called from I/O thread context
  std::thread::id getIoThreadId() const override
  {
    return _loop.get_id();
  }

  // ── EngineBase overrides ──────────────────────────────────────────────────

  TransportErrorInfo lastError() const override
  {
    auto fatal = lastFatalError();
    return TransportErrorInfo{fatal.code, fatal.message, fatal.sysErrno, fatal.tlsError};
  }

  ConnectResult connectViaListener(ListenerId, const std::string &, std::uint16_t) override
  {
    return ConnectResult::err(
      TransportErrorInfo{TransportError::Config, "connectViaListener not supported on TCP/TLS"});
  }

  void sendAsync(SessionId sid, const void *data, std::size_t len,
                 SendCompleteCallback cb) override
  {
    bool ok = send(sid, data, len);
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

  TransportAddress getListenerAddress(ListenerId lid) const override
  {
    std::shared_lock<std::shared_mutex> rl(_sessionRwMutex);
    auto it = _listeners.find(lid);
    if (it == _listeners.end() || it->second->fd < 0)
    {
      return {};
    }
    sockaddr_storage ss{};
    socklen_t sl = sizeof(ss);
    if (::getsockname(it->second->fd, reinterpret_cast<sockaddr *>(&ss), &sl) != 0)
    {
      return {};
    }
    return addressFromSockaddr(ss);
  }

  TransportAddress getLocalAddress(SessionId sid) const override
  {
    std::shared_lock<std::shared_mutex> rl(_sessionRwMutex);
    auto it = _sessions.find(sid);
    if (it == _sessions.end() || it->second->fd < 0)
    {
      return {};
    }
    sockaddr_storage ss{};
    socklen_t sl = sizeof(ss);
    if (::getsockname(it->second->fd, reinterpret_cast<sockaddr *>(&ss), &sl) != 0)
    {
      return {};
    }
    return addressFromSockaddr(ss);
  }

  TransportAddress getRemoteAddress(SessionId sid) const override
  {
    std::shared_lock<std::shared_mutex> rl(_sessionRwMutex);
    auto it = _sessions.find(sid);
    if (it == _sessions.end() || it->second->fd < 0 || it->second->peerLen == 0)
    {
      return {};
    }
    return addressFromSockaddr(it->second->peer);
  }

  bool setDscp(SessionId sid, std::uint8_t dscp) override
  {
    std::shared_lock<std::shared_mutex> rl(_sessionRwMutex);
    auto it = _sessions.find(sid);
    if (it == _sessions.end() || it->second->fd < 0)
    {
      return false;
    }
    int fd = it->second->fd;
    sockaddr_storage ss{};
    socklen_t sl = sizeof(ss);
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&ss), &sl) != 0)
    {
      return false;
    }
    int val = static_cast<int>(dscp) << 2;
    if (ss.ss_family == AF_INET6)
    {
      return ::setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &val, sizeof(val)) == 0;
    }
    return ::setsockopt(fd, IPPROTO_IP, IP_TOS, &val, sizeof(val)) == 0;
  }

protected:
  // ===== Virtual hooks for fault injection (B6 TLS testing) =====
  // These hooks allow subclasses to intercept SSL operations for testing.
  // Return false from before* hooks to simulate failure.
  // Default implementations are pass-through (no fault injection).

  /// \brief Called before SSL_do_handshake() is invoked
  /// \param sid Session ID for the connection
  /// \param remoteAddr Remote address string (host:port), may be empty if not yet resolved
  /// \return true to proceed with handshake, false to simulate failure
  /// \note Called from I/O thread - must be thread-safe if accessing shared state.
  ///       Invocations on the same session are sequential (never concurrent).
  virtual bool beforeSslHandshake(SessionId sid, const std::string& remoteAddr)
  {
    (void)sid;
    (void)remoteAddr;
    return true;
  }

  /// \brief Called after SSL_do_handshake() completes or fails
  /// \param sid Session ID for the connection
  /// \param success true if handshake succeeded, false if it failed
  /// \param sslError SSL_get_error() result if handshake failed
  /// \return true to accept the result (success or failure), false to override with injected failure
  /// \note Called from I/O thread - must be thread-safe if accessing shared state.
  ///       Invocations on the same session are sequential (never concurrent).
  ///       The default implementation accepts whatever result SSL_do_handshake() returned.
  ///       Subclasses can return false to inject failure even when handshake succeeded.
  virtual bool afterSslHandshake(SessionId sid, bool success, int sslError)
  {
    (void)sid;
    (void)success;
    (void)sslError;
    return true;  // Accept the natural result (success or failure)
  }

  /// \brief Called before SSL_read() is invoked
  /// \param sid Session ID for the connection
  /// \return true to proceed with read, false to simulate read failure
  /// \note Called from I/O thread - must be thread-safe if accessing shared state.
  ///       May be called multiple times per session as data arrives.
  virtual bool beforeSslRead(SessionId sid)
  {
    (void)sid;
    return true;
  }

  /// \brief Called before SSL_write() is invoked
  /// \param sid Session ID for the connection
  /// \param dataSize Size of data being written
  /// \return true to proceed with write, false to simulate write failure
  /// \note Called from I/O thread - must be thread-safe if accessing shared state.
  ///       May be called multiple times per session as data is sent.
  virtual bool beforeSslWrite(SessionId sid, std::size_t dataSize)
  {
    (void)sid;
    (void)dataSize;
    return true;
  }

  /// \brief Get SSL error code to inject when hook returns false
  /// \return SSL error code (default: SSL_ERROR_SSL for generic failure)
  virtual int getInjectedSslError() const
  {
    return SSL_ERROR_SSL;
  }

  /// \brief Get error message to use when hook injection fails
  /// \return Error message string
  virtual std::string getInjectedErrorMessage() const
  {
    return "Injected TLS fault for testing";
  }

private:
  // ===== helpers =====

  static std::string lastErr()
  {
    int e = errno;
    char buf[128];
#if defined(__GLIBC__) && !defined(__APPLE__)
    ::strerror_r(e, buf, sizeof(buf));
    return std::string(buf);
#else
    return std::string(std::strerror(e));
#endif
  }

  bool addEpoll(int fd, std::uint32_t ev)
  {
    epoll_event e{};
    e.events = ev;
    e.data.fd = fd;
    return ::epoll_ctl(_epollFd, EPOLL_CTL_ADD, fd, &e) == 0;
  }

  bool modEpoll(int fd, std::uint32_t ev)
  {
    epoll_event e{};
    e.events = ev;
    e.data.fd = fd;
    return ::epoll_ctl(_epollFd, EPOLL_CTL_MOD, fd, &e) == 0;
  }

  void delEpoll(int fd) { ::epoll_ctl(_epollFd, EPOLL_CTL_DEL, fd, nullptr); }

  static std::string keyFromSockaddr(const sockaddr_storage &ss)
  {
    char h[NI_MAXHOST]{}, s[NI_MAXSERV]{};
    socklen_t sl = (ss.ss_family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    if (::getnameinfo(reinterpret_cast<const sockaddr *>(&ss), sl, h, sizeof(h), s, sizeof(s),
                      NI_NUMERICHOST | NI_NUMERICSERV) == 0)
    {
      std::string out(h);
      out.push_back(':');
      out.append(s);
      return out;
    }
    return {};
  }

  static TransportAddress addressFromSockaddr(const sockaddr_storage &ss)
  {
    TransportAddress addr;
    char host[NI_MAXHOST]{};
    if (ss.ss_family == AF_INET)
    {
      auto *sa4 = reinterpret_cast<const sockaddr_in *>(&ss);
      ::inet_ntop(AF_INET, &sa4->sin_addr, host, sizeof(host));
      addr.host = host;
      addr.port = ntohs(sa4->sin_port);
    }
    else if (ss.ss_family == AF_INET6)
    {
      auto *sa6 = reinterpret_cast<const sockaddr_in6 *>(&ss);
      ::inet_ntop(AF_INET6, &sa6->sin6_addr, host, sizeof(host));
      addr.host = host;
      addr.port = ntohs(sa6->sin6_port);
    }
    return addr;
  }

  void armGc(std::chrono::seconds sec)
  {
    itimerspec its{};
    its.it_interval.tv_sec = sec.count();
    its.it_value.tv_sec = sec.count();
    ::timerfd_settime(_timerFd, 0, &its, nullptr);
  }

  void cleanupStartFail()
  {
    if (_timerFd >= 0)
    {
      ::close(_timerFd);
      _timerFd = -1;
    }
    if (_eventFd >= 0)
    {
      ::close(_eventFd);
      _eventFd = -1;
    }
    if (_epollFd >= 0)
    {
      ::close(_epollFd);
      _epollFd = -1;
    }
    freeTls();
    _running.store(false);
  }

  void err(TransportError te, const std::string &m)
  {
    _atomicStats.errors++;
    decltype(_cbs.onError) cb;
    { std::lock_guard<std::mutex> g(_cbMutex); cb = _cbs.onError; }
    if (cb) cb(te, m);
  }

  void setLastFatal(const IoResult &r) const
  {
    std::lock_guard<std::mutex> g(_fatalMx);
    _lastFatal = r;
  }

  struct ListenerCfg
  {
    ListenerId id{};
    std::string addr;
    std::uint16_t port{};
    TlsMode tls{TlsMode::None};
  };

  struct ConnectReq
  {
    SessionId sid{};
    std::string host;
    std::uint16_t port{};
    TlsMode tls{TlsMode::None};
  };

  struct SendReq
  {
    SessionId sid{};
    ByteBuffer payload;
  };

  enum class Cmd
  {
    Shutdown,
    AddListener,
    Connect,
    Send,
    Close
  };

  enum class CloseOrigin
  {
    App,              // User-initiated close()
    ConnectTimeout,   // Timer: connect timeout
    HandshakeTimeout, // Timer: TLS handshake timeout
    WriteStall        // Timer: write stall timeout
  };

  struct Command
  {
    Cmd t;
    ListenerCfg l;
    ConnectReq c;
    SendReq s;
    SessionId closeSid{};
    TransportError closeReason{TransportError::Unknown};
    std::string closeMsg;
    CloseOrigin closeOrigin{CloseOrigin::App};
    std::shared_ptr<std::promise<bool>> listenerReady; // signals when addListener bind completes

    static Command shutdown() { return Command{Cmd::Shutdown}; }
    static Command addListener(const ListenerCfg &lc,
                               std::shared_ptr<std::promise<bool>> ready = nullptr)
    {
      Command x{Cmd::AddListener};
      x.l = lc;
      x.listenerReady = std::move(ready);
      return x;
    }
    static Command connect(const ConnectReq &cr)
    {
      Command x{Cmd::Connect};
      x.c = cr;
      return x;
    }
    static Command send(SendReq &&sr)
    {
      Command x{Cmd::Send};
      x.s = std::move(sr);
      return x;
    }
    static Command close(SessionId sid, TransportError reason = TransportError::Unknown,
                         const std::string &msg = "closed by app",
                         CloseOrigin origin = CloseOrigin::App)
    {
      Command x{Cmd::Close};
      x.closeSid = sid;
      x.closeReason = reason;
      x.closeMsg = msg;
      x.closeOrigin = origin;
      return x;
    }
  };

  bool enqueue(const Command &cmd)
  {
    try
    {
      {
        std::lock_guard<std::mutex> g(_cmdMutex);
        _cmds.push_back(cmd);
        _atomicStats.commands++;
      }
      std::uint64_t one = 1;
      (void)::write(_eventFd, &one, sizeof(one));
      return true;
    }
    catch (const std::exception &ex)
    {
      setLastFatal(
        IoResult::failure(TransportError::Unknown, std::string("enqueue(copy): ") + ex.what()));
      decltype(_cbs.onError) cb;
      { std::lock_guard<std::mutex> g(_cbMutex); cb = _cbs.onError; }
      if (cb) cb(TransportError::Unknown, std::string("enqueue(copy): ") + ex.what());
      return false;
    }
  }

  bool enqueue(Command &&cmd)
  {
    try
    {
      {
        std::lock_guard<std::mutex> g(_cmdMutex);
        _cmds.push_back(std::move(cmd));
        _atomicStats.commands++;
      }
      std::uint64_t one = 1;
      (void)::write(_eventFd, &one, sizeof(one));
      return true;
    }
    catch (const std::exception &ex)
    {
      setLastFatal(
        IoResult::failure(TransportError::Unknown, std::string("enqueue(move): ") + ex.what()));
      decltype(_cbs.onError) cb;
      { std::lock_guard<std::mutex> g(_cbMutex); cb = _cbs.onError; }
      if (cb) cb(TransportError::Unknown, std::string("enqueue(move): ") + ex.what());
      return false;
    }
  }

  void drainEvt()
  {
    std::uint64_t n = 0;
    while (::read(_eventFd, &n, sizeof(n)) > 0)
    {
    }
  }

  void drainTim()
  {
    std::uint64_t n = 0;
    while (::read(_timerFd, &n, sizeof(n)) > 0)
    {
    }
  }

  enum class TlsState
  {
    None,
    Handshake,
    Open
  };

  struct Session
  {
    SessionId id{};
    int fd{-1};
    sockaddr_storage peer{};
    socklen_t peerLen{0};
    std::string peerKey;

    TlsMode tlsMode{TlsMode::None};
    SSL *ssl{nullptr};
    TlsState tlsState{TlsState::None};
    MonoTime tlsStart{};
    // Track SSL_ERROR_WANT_WRITE during handshake and renegotiation.
    // I/O thread only - not thread-safe, accessed exclusively from epoll loop.
    bool tlsWantWrite{false};

    std::deque<ByteBuffer> wq;
    bool wantWrite{false};
    bool closed{false};

    MonoTime created{}, lastActivity{};

    // Safety-net tracking
    bool connectPending{false};
    MonoTime connectStart{};
    MonoTime lastWriteProgress{};
    // High-resolution timer IDs (0 = not scheduled)
    std::uint64_t connectTimeoutId{0};
    std::uint64_t handshakeTimeoutId{0};
    std::uint64_t writeStallTimeoutId{0};
  };

  // ===== High-resolution timer helpers (after Session struct) =====

  void scheduleConnectTimeout(Session *s)
  {
    if (!_timerService || _config.connectTimeout.count() == 0 || s->connectTimeoutId != 0)
    {
      return;
    }

    s->connectTimeoutId = _timerService->scheduleAfter(_config.connectTimeout, [this, sid = s->id]()
                                                       { handleConnectTimeout(sid); });
  }

  void scheduleHandshakeTimeout(Session *s)
  {
    if (!_timerService || _config.handshakeTimeout.count() == 0 || s->handshakeTimeoutId != 0)
    {
      return;
    }

    s->handshakeTimeoutId = _timerService->scheduleAfter(
      _config.handshakeTimeout, [this, sid = s->id]() { handleHandshakeTimeout(sid); });
  }

  void scheduleWriteStallTimeout(Session *s)
  {
    if (!_timerService || _config.writeStallTimeout.count() == 0 || s->writeStallTimeoutId != 0)
    {
      return;
    }

    s->writeStallTimeoutId = _timerService->scheduleAfter(
      _config.writeStallTimeout, [this, sid = s->id]() { handleWriteStallTimeout(sid); });
  }

  void cancelConnectTimeout(Session *s)
  {
    if (_timerService && s->connectTimeoutId != 0)
    {
      _timerService->cancel(s->connectTimeoutId);
      s->connectTimeoutId = 0;
    }
  }

  void cancelHandshakeTimeout(Session *s)
  {
    if (_timerService && s->handshakeTimeoutId != 0)
    {
      _timerService->cancel(s->handshakeTimeoutId);
      s->handshakeTimeoutId = 0;
    }
  }

  void cancelWriteStallTimeout(Session *s)
  {
    if (_timerService && s->writeStallTimeoutId != 0)
    {
      _timerService->cancel(s->writeStallTimeoutId);
      s->writeStallTimeoutId = 0;
    }
  }

  void cancelAllTimers(Session *s)
  {
    cancelConnectTimeout(s);
    cancelHandshakeTimeout(s);
    cancelWriteStallTimeout(s);
  }

  void handleConnectTimeout(SessionId sid)
  {
    enqueue(Command::close(sid, TransportError::Timeout, "Connect timeout", CloseOrigin::ConnectTimeout));
  }

  void handleHandshakeTimeout(SessionId sid)
  {
    enqueue(Command::close(sid, TransportError::TLSHandshake, "TLS handshake timeout", CloseOrigin::HandshakeTimeout));
  }

  void handleWriteStallTimeout(SessionId sid)
  {
    enqueue(Command::close(sid, TransportError::Timeout, "Write stall timeout", CloseOrigin::WriteStall));
  }

  struct Listener
  {
    ListenerId id{};
    int fd{-1};
    std::string bind;
    TlsMode tls{TlsMode::None};
  };

  struct Tag
  {
    bool isListener{false};
    Listener *lst{nullptr};
    Session *sess{nullptr};
  };

  void loop()
  {
    if (_batchProcessor)
      loopBatched();
    else
      loopUnbatched();
  }

  void handleFdEvent(int fd, std::uint32_t events)
  {
    auto it = _fdTags.find(fd);
    if (it == _fdTags.end())
      return;
    Tag *t = it->second.get();
    if (t->isListener)
      onListener(t->lst);
    else
      onSession(t->sess, events);
  }

  void shutdownDrain()
  {
    // Draining on shutdown
    process();
    // Collect sessions to close to avoid iterator invalidation
    std::vector<Session *> toClose;
    toClose.reserve(_sessions.size());
    for (auto &kv : _sessions)
      toClose.push_back(kv.second.get());

    // Close all sessions safely (but don't erase from _sessions yet)
    for (auto *s : toClose)
    {
      if (!s || s->closed)
        continue;
      s->closed = true;
      delEpoll(s->fd);
      // SSL_shutdown before close(fd) — same ordering as closeNow
      if (s->ssl)
      {
        ::SSL_shutdown(s->ssl);
        ::SSL_free(s->ssl);
        s->ssl = nullptr;
      }
      ::close(s->fd);
      _atomicStats.closed++;
      _atomicStats.sessionsCurrent--;
      decltype(_cbs.onClose) closeCb;
      { std::lock_guard<std::mutex> g(_cbMutex); closeCb = _cbs.onClose; }
      if (closeCb)
      {
        closeCb(s->id, TransportErrorInfo{TransportError::Unknown, "shutdown", 0, 0});
      }
    }
    {
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      _sessions.clear();
    }

    // Close listeners
    std::vector<Listener *> listenersToClose;
    listenersToClose.reserve(_listeners.size());
    for (auto &kv : _listeners)
      listenersToClose.push_back(kv.second.get());

    for (auto *lst : listenersToClose)
      closeListenerNow(lst);
    {
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      _listeners.clear();
    }
    if (_timerFd >= 0)
    {
      delEpoll(_timerFd);
      ::close(_timerFd);
      _timerFd = -1;
    }
    if (_eventFd >= 0)
    {
      delEpoll(_eventFd);
      ::close(_eventFd);
      _eventFd = -1;
    }
    if (_epollFd >= 0)
    {
      ::close(_epollFd);
      _epollFd = -1;
    }
    freeTls();
  }

  void loopUnbatched()
  {
    std::vector<epoll_event> evs((std::size_t)_config.epollMaxEvents);
    while (_running.load())
    {
      int n = ::epoll_wait(_epollFd, evs.data(), (int)evs.size(), -1);
      if (n < 0)
      {
        if (errno == EINTR)
        {
          continue;
        }
        err(TransportError::Unknown, "epoll_wait: " + lastErr());
        continue;
      }
      _atomicStats.epollWakeups++;

      for (int i = 0; i < n; ++i)
      {
        int fd = evs[(std::size_t)i].data.fd;
        std::uint32_t events = evs[(std::size_t)i].events;

        if (fd == _eventFd)
        {
          drainEvt();
          process();
          continue;
        }
        if (fd == _timerFd)
        {
          drainTim();
          runGc();
          continue;
        }

        handleFdEvent(fd, events);
      }
    }
    shutdownDrain();
  }

  void loopBatched()
  {
    while (_running.load())
    {
      try
      {
        _batchProcessor->processBatchWithSpecialFDs(
          _epollFd, _eventFd, _timerFd,
          // generalHandler — handles session/listener fds
          [this](int fd, std::uint32_t events)
          {
            handleFdEvent(fd, events);
          },
          // onEventFd
          [this]()
          {
            drainEvt();
            process();
          },
          // onTimerFd
          [this]()
          {
            drainTim();
            runGc();
          }
        );
        _atomicStats.epollWakeups++;
      }
      catch (const std::system_error &)
      {
        // epoll_wait EINTR handled inside processBatch
        continue;
      }
    }
    shutdownDrain();
  }

  void process()
  {
    std::deque<Command> q;
    {
      std::lock_guard<std::mutex> g(_cmdMutex);
      q.swap(_cmds);
    }

    for (auto &c : q)
    {
      try
      {
        switch (c.t)
        {
        case Cmd::Shutdown:
          _running.store(false);
          break;
        case Cmd::AddListener:
        {
          bool ok = doAddListener(c.l);
          if (c.listenerReady)
          {
            c.listenerReady->set_value(ok);
          }
          break;
        }
        case Cmd::Connect:
          doConnect(c.c);
          break;
        case Cmd::Send:
          doSend(std::move(c.s));
          break;
        case Cmd::Close:
        {
          auto it = _sessions.find(c.closeSid);
          if (it != _sessions.end())
          {
            auto *s = it->second.get();
            // For timer-originated closes, verify the condition still applies.
            // The timer fires on the TimerService thread and enqueues a close
            // command. By the time the I/O thread processes it, the session
            // may have completed the operation that triggered the timeout.
            if (c.closeOrigin == CloseOrigin::ConnectTimeout)
            {
              if (!s->connectPending) break; // Connect completed, ignore stale timeout
            }
            else if (c.closeOrigin == CloseOrigin::HandshakeTimeout)
            {
              if (s->tlsState != TlsState::Handshake) break; // Handshake completed
            }
            else if (c.closeOrigin == CloseOrigin::WriteStall)
            {
              if (s->wq.empty()) break; // Write queue drained
            }
            closeNow(s, c.closeReason, c.closeMsg, 0);
          }
          break;
        }
        }
      }
      catch (const std::exception &ex)
      {
        // Fulfill any pending addListener promise to prevent caller deadlock
        if (c.listenerReady)
        {
          try { c.listenerReady->set_value(false); } catch (...) {}
        }
        decltype(_cbs.onError) cb;
        { std::lock_guard<std::mutex> g(_cbMutex); cb = _cbs.onError; }
        if (cb) cb(TransportError::Unknown, std::string("cmd dispatch: ") + ex.what());
      }
    }
  }

  bool doAddListener(const ListenerCfg &lc)
  {
    int sfd = -1;
    sockaddr_storage ss{};
    socklen_t sl = 0;

    in6_addr t6{};
    if (::inet_pton(AF_INET6, lc.addr.c_str(), &t6) == 1)
    {
      sfd = ::socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      if (sfd < 0)
      {
        err(TransportError::Socket, "socket v6: " + lastErr());
        return false;
      }
      int v6only = 0;
      ::setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
      sockaddr_in6 sa6{};
      sa6.sin6_family = AF_INET6;
      sa6.sin6_port = htons(lc.port);
      sa6.sin6_addr = t6;
      std::memcpy(&ss, &sa6, sizeof(sa6));
      sl = sizeof(sa6);
    }
    else
    {
      in_addr t4{};
      if (::inet_pton(AF_INET, lc.addr.c_str(), &t4) != 1)
      {
        err(TransportError::Bind, "inet_pton failed");
        return false;
      }
      sfd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      if (sfd < 0)
      {
        err(TransportError::Socket, "socket v4: " + lastErr());
        return false;
      }
      int one = 1;
      ::setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
      ::setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
      sockaddr_in sa4{};
      sa4.sin_family = AF_INET;
      sa4.sin_port = htons(lc.port);
      sa4.sin_addr = t4;
      std::memcpy(&ss, &sa4, sizeof(sa4));
      sl = sizeof(sa4);
    }

    if (_config.soRcvBuf > 0)
      ::setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, &_config.soRcvBuf, sizeof(int));
    if (_config.soSndBuf > 0)
      ::setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &_config.soSndBuf, sizeof(int));

    if (::bind(sfd, reinterpret_cast<sockaddr *>(&ss), sl) < 0)
    {
      err(TransportError::Bind, "bind: " + lastErr());
      ::close(sfd);
      return false;
    }
    if (::listen(sfd, 256) < 0)
    {
      err(TransportError::Listen, "listen: " + lastErr());
      ::close(sfd);
      return false;
    }

    auto lst = std::make_unique<Listener>();
    lst->id = lc.id;
    lst->fd = sfd;
    lst->bind = lc.addr + ":" + std::to_string(lc.port);
    lst->tls = lc.tls;
    std::uint32_t ev = EPOLLIN;
    if (_config.useEdgeTriggered)
      ev |= EPOLLET;
    addEpoll(sfd, ev);

    Listener *rawLst = lst.get();
    {
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      _listeners.emplace(lst->id, std::move(lst));
    }

    auto tag = std::make_unique<Tag>();
    tag->isListener = true;
    tag->lst = rawLst;
    _fdTags.emplace(sfd, std::move(tag));

    return true;
  }

  void onListener(Listener *lst)
  {
    for (;;)
    {
      sockaddr_storage peer{};
      socklen_t pl = sizeof(peer);
      int cfd =
        ::accept4(lst->fd, reinterpret_cast<sockaddr *>(&peer), &pl, SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (cfd < 0)
      {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
          break;
        }
        err(TransportError::Accept, "accept4: " + lastErr());
        break;
      }
      applySockOpts(cfd);

      SessionId sid = _nextSessionId++;
      auto s = std::make_unique<Session>();
      s->id = sid;
      s->fd = cfd;
      std::memcpy(&s->peer, &peer, pl);
      s->peerLen = pl;
      s->peerKey = keyFromSockaddr(peer);
      s->created = MonoClock::now();
      s->lastActivity = s->created;
      s->lastWriteProgress = s->created;

      if (lst->tls == TlsMode::Server && _config.serverTls.enabled && _sslSrv)
      {
        s->tlsMode = TlsMode::Server;
        s->ssl = ::SSL_new(_sslSrv);
        if (!s->ssl)
        {
          err(TransportError::TLSHandshake, "SSL_new(server) failed");
          ::close(cfd);
          continue; // not inserted anywhere yet
        }
        ::SSL_set_fd(s->ssl, cfd);
        ::SSL_set_accept_state(s->ssl);
        s->tlsState = TlsState::Handshake;
        s->tlsStart = MonoClock::now();
        scheduleHandshakeTimeout(s.get());
      }

      std::string peerKey = s->peerKey;
      Session *sPtr = s.get();
      {
        std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
        _sessions.emplace(sid, std::move(s));
      }
      bumpSess();

      std::uint32_t ev = EPOLLIN;
      if (_config.useEdgeTriggered)
        ev |= EPOLLET;
      addEpoll(cfd, ev);

      auto tg = std::make_unique<Tag>();
      tg->isListener = false;
      tg->sess = sPtr;
      _fdTags.emplace(cfd, std::move(tg));

      _atomicStats.accepted++;
      decltype(_cbs.onAccept) acceptCb;
      { std::lock_guard<std::mutex> g(_cbMutex); acceptCb = _cbs.onAccept; }
      if (acceptCb) acceptCb(sid, addressFromSockaddr(peer));
    }
  }

  bool doConnect(const ConnectReq &cr)
  {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo *res = nullptr;
    std::string ps = std::to_string(cr.port);

    // CRITICAL FIX: Skip getaddrinfo() for IP addresses to prevent I/O thread
    // from hanging For IP addresses, we can directly use them without DNS
    // resolution
    int rc = 0;

    // Check if host is already an IP address (IPv4 or IPv6)
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
    bool isIPv4 = (inet_pton(AF_INET, cr.host.c_str(), &(sa4.sin_addr)) == 1);
    bool isIPv6 = (inet_pton(AF_INET6, cr.host.c_str(), &(sa6.sin6_addr)) == 1);

    bool manualAddrinfo = false;
    addrinfo manualHints{};

    if (isIPv4 || isIPv6)
    {
      // For IP addresses, use stack-allocated addrinfo instead of heap allocation
      manualAddrinfo = true;
      std::memset(&manualHints, 0, sizeof(manualHints));
      manualHints.ai_family = isIPv4 ? AF_INET : AF_INET6;
      manualHints.ai_socktype = SOCK_STREAM;
      manualHints.ai_protocol = IPPROTO_TCP;
      manualHints.ai_next = nullptr;

      if (isIPv4)
      {
        manualHints.ai_addrlen = sizeof(sockaddr_in);
        std::memset(&sa4, 0, sizeof(sa4));
        sa4.sin_family = AF_INET;
        sa4.sin_port = htons(cr.port);
        inet_pton(AF_INET, cr.host.c_str(), &(sa4.sin_addr));
        manualHints.ai_addr = reinterpret_cast<sockaddr *>(&sa4);
      }
      else
      {
        manualHints.ai_addrlen = sizeof(sockaddr_in6);
        std::memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons(cr.port);
        inet_pton(AF_INET6, cr.host.c_str(), &(sa6.sin6_addr));
        manualHints.ai_addr = reinterpret_cast<sockaddr *>(&sa6);
      }

      res = &manualHints;
      rc = 0; // Success
    }
    else
    {
      // For hostnames, use getaddrinfo with timeout
      auto dnsTimeout = std::chrono::seconds(2);
      auto dnsResult =
        std::async(std::launch::async,
                   [&]() { return ::getaddrinfo(cr.host.c_str(), ps.c_str(), &hints, &res); });

      auto dnsStatus = dnsResult.wait_for(dnsTimeout);
      if (dnsStatus == std::future_status::timeout)
      {
        std::string timeoutMsg = "DNS_TIMEOUT_FIX_TRIGGERED: getaddrinfo timeout after " +
                                 std::to_string(dnsTimeout.count()) + "s for " + cr.host + ":" + ps;
        decltype(_cbs.onClose) closeCb;
        { std::lock_guard<std::mutex> g(_cbMutex); closeCb = _cbs.onClose; }
        if (closeCb) closeCb(cr.sid, TransportErrorInfo{TransportError::Resolve, timeoutMsg});
        err(TransportError::Resolve, timeoutMsg);
        return false;
      }

      rc = dnsResult.get();
    }
    if (rc != 0 || !res)
    {
      decltype(_cbs.onClose) closeCb;
      { std::lock_guard<std::mutex> g(_cbMutex); closeCb = _cbs.onClose; }
      if (closeCb)
      {
        closeCb(cr.sid, TransportErrorInfo{TransportError::Resolve,
                                            std::string("getaddrinfo: ") + gai_strerror(rc)});
      }
      err(TransportError::Resolve, "getaddrinfo failed");
      return false;
    }

    int cfd = -1;
    addrinfo *chosen = nullptr;
    for (addrinfo *ai = res; ai; ai = ai->ai_next)
    {
      cfd = ::socket(ai->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      if (cfd < 0)
      {
        continue;
      }
      applySockOpts(cfd);
      int connectResult = ::connect(cfd, ai->ai_addr, ai->ai_addrlen);
      if (connectResult == 0 || errno == EINPROGRESS)
      {
        chosen = ai;
        break;
      }
      // CRITICAL FIX for SIP: Immediately handle connection refused for local
      // connections This prevents hanging when connecting to non-existent
      // local ports
      if (errno == ECONNREFUSED || errno == ENETUNREACH || errno == EHOSTUNREACH)
      {
        // Save errno before system calls clobber it
        int connectErrno = errno;
        std::string connectErr = lastErr();

        ::close(cfd);
        cfd = -1;

        // Clean up addrinfo before returning
        if (!manualAddrinfo)
        {
          ::freeaddrinfo(res);
        }

        // Report immediate failure
        decltype(_cbs.onClose) closeCb;
        { std::lock_guard<std::mutex> g(_cbMutex); closeCb = _cbs.onClose; }
        if (closeCb)
        {
          std::string errMsg =
            "Connection refused to " + cr.host + ":" + ps + " - " + connectErr;
          closeCb(cr.sid, TransportErrorInfo{TransportError::Connect, errMsg, connectErrno, 0});
        }
        err(TransportError::Connect, "connect immediately failed: " + connectErr);
        return false;
      }
      ::close(cfd);
      cfd = -1;
    }

    // Save errno from the connect loop BEFORE cleanup calls clobber it.
    int loopErrno = errno;
    std::string loopErr = lastErr();

    // Save peer address from chosen entry BEFORE freeing the addrinfo chain.
    // chosen points into res, so it becomes dangling after freeaddrinfo/delete.
    sockaddr_storage savedPeer{};
    socklen_t savedPeerLen = 0;
    if (chosen)
    {
      savedPeerLen = (socklen_t)chosen->ai_addrlen;
      std::memcpy(&savedPeer, chosen->ai_addr, savedPeerLen);
    }

    // Clean up addrinfo (stack-allocated manualHints needs no cleanup)
    if (!manualAddrinfo)
    {
      ::freeaddrinfo(res);
    }
    res = nullptr;
    chosen = nullptr; // dangling after free — use savedPeer instead

    if (cfd < 0)
    {
      decltype(_cbs.onClose) closeCb;
      { std::lock_guard<std::mutex> g(_cbMutex); closeCb = _cbs.onClose; }
      if (closeCb)
      {
        closeCb(cr.sid, TransportErrorInfo{TransportError::Connect, loopErr, loopErrno, 0});
      }
      err(TransportError::Connect, "connect: " + loopErr);
      return false;
    }

    auto s = std::make_unique<Session>();
    s->id = cr.sid;
    s->fd = cfd;
    s->created = MonoClock::now();
    s->lastActivity = s->created;
    s->lastWriteProgress = s->created;
    s->connectPending = true;
    s->connectStart = MonoClock::now();
    scheduleConnectTimeout(s.get());

    if (savedPeerLen > 0)
    {
      s->peerLen = savedPeerLen;
      s->peerKey = keyFromSockaddr(savedPeer);
      std::memcpy(&s->peer, &savedPeer, savedPeerLen);
    }

    if (cr.tls == TlsMode::Client && _config.clientTls.enabled && _sslCli)
    {
      s->tlsMode = TlsMode::Client;
      s->ssl = ::SSL_new(_sslCli);
      if (!s->ssl)
      {
        err(TransportError::TLSHandshake, "SSL_new(client) failed");
        ::close(cfd);
        return false; // not inserted yet => no tags to clean
      }
      ::SSL_set_fd(s->ssl, cfd);
      ::SSL_set_connect_state(s->ssl);
      s->tlsState = TlsState::Handshake;
      s->tlsStart = MonoClock::now();
      s->tlsWantWrite = true; // Client needs to send ClientHello first
      scheduleHandshakeTimeout(s.get());
    }

    Session *sPtr = s.get();
    {
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      _sessions.emplace(s->id, std::move(s));
    }
    bumpSess();

    std::uint32_t ev = EPOLLIN | EPOLLOUT;
    if (_config.useEdgeTriggered)
      ev |= EPOLLET;
    addEpoll(cfd, ev);
    auto tg = std::make_unique<Tag>();
    tg->isListener = false;
    tg->sess = sPtr;
    _fdTags.emplace(cfd, std::move(tg));

    // DEFENSE-IN-DEPTH: Check if socket is already writable (handles immediate connects)
    // This prevents edge-triggered epoll from missing the initial EPOLLOUT event
    // when the TCP handshake completes before the first epoll_wait()
    // Only do this for non-TLS connections; TLS needs handshake to complete first
    if (cr.tls == TlsMode::None)
    {
      int err = 0;
      socklen_t el = sizeof(err);
      int rc = ::getsockopt(cfd, SOL_SOCKET, SO_ERROR, &err, &el);
      if (rc < 0)
      {
        // getsockopt() syscall failed - socket is invalid
        int gso_errno = errno;
        IORA_LOG_ERROR("[IMMEDIATE-CONNECT] getsockopt() failed for sid=" << cr.sid
                       << ", errno=" << gso_errno);
        closeNow(sPtr, TransportError::Socket,
                 std::string("getsockopt failed: ") + std::strerror(gso_errno), gso_errno);
        return true;
      }
      else if (err == 0)
      {
        // SO_ERROR is 0, but must verify connection is truly established using getpeername()
        // For non-routable addresses, SO_ERROR may be 0 before network error is detected
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);
        if (::getpeername(cfd, reinterpret_cast<struct sockaddr *>(&addr), &addrlen) == 0)
        {
          IORA_LOG_DEBUG("[IMMEDIATE-CONNECT] Connection truly established for sid=" << cr.sid);
          // Connection completed immediately - manually trigger the connect callback
          decltype(_cbs.onConnect) connectCb;
          { std::lock_guard<std::mutex> g(_cbMutex); connectCb = _cbs.onConnect; }
          if (connectCb)
          {
            _atomicStats.connected++;
            connectCb(cr.sid, addressFromSockaddr(sPtr->peer));
          }
          sPtr->connectPending = false;
          sPtr->lastWriteProgress = MonoClock::now();
          cancelConnectTimeout(sPtr);
        }
        else
        {
          // getpeername() failed - check errno to determine if connection has definitely failed
          int gp_errno = errno;
          if (gp_errno == ECONNREFUSED || gp_errno == ENETUNREACH ||
              gp_errno == EHOSTUNREACH || gp_errno == ETIMEDOUT)
          {
            IORA_LOG_DEBUG("[IMMEDIATE-CONNECT-FAIL] getpeername() detected connection failure for sid="
                           << cr.sid << ", errno=" << gp_errno);
            closeNow(sPtr, TransportError::Connect, std::strerror(gp_errno), gp_errno);
            return true;
          }
          // else ENOTCONN or other transient error - connection not yet established, wait for epoll/timeout
          IORA_LOG_DEBUG("[IMMEDIATE-CONNECT] getpeername() returned errno=" << gp_errno
                         << " for sid=" << cr.sid << ", waiting for epoll/timeout");
        }
      }
      else
      {
        IORA_LOG_DEBUG("[IMMEDIATE-CONNECT-FAIL] SO_ERROR indicates connection failed for sid=" << cr.sid
                       << ", error=" << std::strerror(err));
        // Connection failed immediately - clean up and invoke failure callback
        closeNow(sPtr, TransportError::Connect, std::strerror(err), err);
        return true;
      }
    }

    return true;
  }

  void onSession(Session *s, std::uint32_t events)
  {
    if (!s || s->closed)
    {
      return;
    }

    IORA_LOG_DEBUG("[EPOLL-EVENT] onSession called for sid=" << s->id
                   << ", events=0x" << std::hex << events << std::dec
                   << ", connectPending=" << s->connectPending
                   << ", tlsMode=" << static_cast<int>(s->tlsMode));

    if (events & EPOLLOUT)
    {
      IORA_LOG_DEBUG("[EPOLL-EVENT] EPOLLOUT detected for sid=" << s->id
                     << ", checking for connection errors");
      int err = 0;
      socklen_t el = sizeof(err);
      if (::getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err != 0)
      {
        IORA_LOG_DEBUG("[EPOLL-EVENT] Connection error detected: " << std::strerror(err));
        errno = err; // Ensure closeNow's savedErrno captures the SO_ERROR value
        closeNow(s, TransportError::Connect, std::strerror(err), 0);
        return;
      }
      IORA_LOG_DEBUG("[EPOLL-EVENT] No connection errors detected");
    }

    if (s->tlsMode != TlsMode::None && s->tlsState == TlsState::Handshake)
    {
      IORA_LOG_DEBUG("[EPOLL-EVENT] TLS handshake in progress for sid=" << s->id);
      SessionId sid = s->id;
      if (!driveHandshake(s))
      {
        return; // still in progress or closed
      }
      // Handshake completed — driveHandshake called readAvail internally,
      // which may have called closeNow (freeing s). Re-lookup before
      // falling through to writePending.
      auto it = _sessions.find(sid);
      if (it == _sessions.end())
      {
        return;
      }
      s = it->second.get();
    }
    else
    {
      IORA_LOG_DEBUG("[EPOLL-EVENT] Not in TLS handshake, checking EPOLLOUT for connect callback");
      if (events & EPOLLOUT)
      {
        IORA_LOG_DEBUG("[EPOLL-EVENT] EPOLLOUT is set, connectPending=" << s->connectPending);
        // P2 fix: Only handle non-TLS connections here; TLS goes through handshake state machine
        if (s->connectPending && s->tlsMode == TlsMode::None)
        {
          // CRITICAL: SO_ERROR == 0 doesn't mean connection is established!
          // For non-routable addresses, SO_ERROR returns 0 initially before network error is detected.
          // Must use getpeername() to verify connection is truly established.
          int err = 0;
          socklen_t el = sizeof(err);
          int rc = ::getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &el);
          if (rc < 0)
          {
            // getsockopt() syscall failed - socket is invalid
            int gso_errno = errno;
            IORA_LOG_ERROR("[EPOLL-EVENT] getsockopt() failed for sid=" << s->id
                           << ", errno=" << gso_errno);
            closeNow(s, TransportError::Socket,
                     std::string("getsockopt failed: ") + std::strerror(gso_errno), gso_errno);
            return;
          }
          else if (err == 0)
          {
            // SO_ERROR is 0, but verify connection is truly established using getpeername()
            struct sockaddr_storage addr;
            socklen_t addrlen = sizeof(addr);
            if (::getpeername(s->fd, reinterpret_cast<struct sockaddr *>(&addr), &addrlen) == 0)
            {
              IORA_LOG_DEBUG("[EPOLL-EVENT] Connection truly established for sid=" << s->id);
              decltype(_cbs.onConnect) connectCb;
              { std::lock_guard<std::mutex> g(_cbMutex); connectCb = _cbs.onConnect; }
              if (connectCb)
              {
                _atomicStats.connected++;
                connectCb(s->id, addressFromSockaddr(s->peer));
              }
              s->connectPending = false;
              s->lastWriteProgress = MonoClock::now();
              cancelConnectTimeout(s);
              updateInterest(s);
            }
            else
            {
              // getpeername() failed - check errno to determine if connection has definitely failed
              int gp_errno = errno;
              if (gp_errno == ECONNREFUSED || gp_errno == ENETUNREACH ||
                  gp_errno == EHOSTUNREACH || gp_errno == ETIMEDOUT)
              {
                IORA_LOG_DEBUG("[EPOLL-EVENT] getpeername() detected connection failure for sid="
                               << s->id << ", errno=" << gp_errno);
                closeNow(s, TransportError::Connect, std::strerror(gp_errno), gp_errno);
                return;
              }
              // else ENOTCONN or other transient error - connection not yet established, wait for timeout
              IORA_LOG_DEBUG("[EPOLL-EVENT] getpeername() returned errno=" << gp_errno
                             << " for sid=" << s->id << ", waiting for timeout");
            }
          }
          else
          {
            // SO_ERROR indicates connection failed
            IORA_LOG_DEBUG("[EPOLL-EVENT] SO_ERROR indicates connection failed for sid=" << s->id
                           << ", error=" << std::strerror(err));
            closeNow(s, TransportError::Connect, std::strerror(err), err);
            return;
          }
        }
        else
        {
          IORA_LOG_DEBUG("[EPOLL-EVENT] connectPending is false, skipping connect callback");
        }
      }
      else
      {
        IORA_LOG_DEBUG("[EPOLL-EVENT] EPOLLOUT not set in events mask");
      }
    }

    // Handle error conditions first (connection closed, etc.)
    if (events & (EPOLLHUP | EPOLLERR))
    {
      core::Logger::debug("Transport: Detected EPOLLHUP/EPOLLERR for session " +
                          std::to_string(s->id) + ", events=0x" + std::to_string(events));
      closeNow(s, TransportError::PeerClosed, "Connection closed by peer (EPOLLHUP/EPOLLERR)", 0);
      return;
    }

    if (events & EPOLLIN)
    {
      SessionId sid = s->id;
      readAvail(s);
      // readAvail may have called closeNow, freeing s. Re-lookup before
      // touching s again.
      auto it = _sessions.find(sid);
      if (it == _sessions.end())
      {
        return;
      }
      s = it->second.get();
    }
    if (events & EPOLLOUT)
    {
      writePending(s);
    }
  }

  bool driveHandshake(Session *s)
  {
    // Only check timeout here if high-resolution timers are not available
    if (!_timerService && _config.handshakeTimeout.count() > 0 &&
        (MonoClock::now() - s->tlsStart) >
          std::chrono::duration_cast<std::chrono::seconds>(_config.handshakeTimeout))
    {
      closeNow(s, TransportError::TLSHandshake, "TLS handshake timeout", 0);
      return false;
    }

    // B6 Hook: Allow subclass to inject fault before handshake
    if (!beforeSslHandshake(s->id, s->peerKey))
    {
      closeNow(s, TransportError::TLSHandshake, getInjectedErrorMessage(), getInjectedSslError());
      _atomicStats.tlsFailures++;
      return false;
    }

    int rc = ::SSL_do_handshake(s->ssl);
    if (rc == 1)
    {
      // B6 Hook: Allow subclass to reject successful handshake
      if (!afterSslHandshake(s->id, true, 0))
      {
        closeNow(s, TransportError::TLSHandshake, getInjectedErrorMessage(), getInjectedSslError());
        _atomicStats.tlsFailures++;
        return false;
      }

      s->tlsState = TlsState::Open;
      s->tlsWantWrite = false; // Reset handshake tracking
      _atomicStats.tlsHandshakes++;
      cancelHandshakeTimeout(s);

      decltype(_cbs.onConnect) connectCb;
      { std::lock_guard<std::mutex> g(_cbMutex); connectCb = _cbs.onConnect; }
      if (connectCb)
      {
        _atomicStats.connected++;
        connectCb(s->id, addressFromSockaddr(s->peer));
      }
      s->connectPending = false;
      s->lastWriteProgress = MonoClock::now();
      cancelConnectTimeout(s);
      updateInterest(s);

      // BUGFIX: Immediately check for pending data after TLS handshake
      // completion This fixes edge-triggered epoll missing initial data from
      // server
      readAvail(s);

      return true;
    }

    int errc = ::SSL_get_error(s->ssl, rc);

    // B6 Hook: Allow subclass to override error handling
    if (!afterSslHandshake(s->id, false, errc))
    {
      closeNow(s, TransportError::TLSHandshake, getInjectedErrorMessage(), getInjectedSslError());
      _atomicStats.tlsFailures++;
      return false;
    }

    if (errc == SSL_ERROR_WANT_READ || errc == SSL_ERROR_WANT_WRITE)
    {
      // Track what SSL needs to prevent edge-triggered epoll CPU busy loop.
      // Without this, EPOLL_CTL_MOD re-arms EPOLLOUT, which fires immediately
      // if socket is writable, causing 100% CPU spin during handshake.
      s->tlsWantWrite = (errc == SSL_ERROR_WANT_WRITE);
      updateInterest(s);
      return false;
    }

    unsigned long e = ::ERR_get_error();
    char msg[256];
    ::ERR_error_string_n(e, msg, sizeof(msg));
    closeNow(s, TransportError::TLSHandshake, msg, (int)e);
    _atomicStats.tlsFailures++;
    return false;
  }

  void readAvail(Session *s)
  {
    for (;;)
    {
      std::vector<std::uint8_t> buf;
      buf.resize(_config.ioReadChunk);
      int n = 0;
      if (s->tlsMode != TlsMode::None && s->tlsState == TlsState::Open)
      {
        // B6 Hook: Allow subclass to inject read fault
        if (!beforeSslRead(s->id))
        {
          closeNow(s, TransportError::TLSIO, getInjectedErrorMessage(), getInjectedSslError());
          return;
        }

        n = ::SSL_read(s->ssl, buf.data(), (int)buf.size());
        if (n <= 0)
        {
          int ge = ::SSL_get_error(s->ssl, n);
          if (ge == SSL_ERROR_WANT_READ || ge == SSL_ERROR_WANT_WRITE)
          {
            // Track SSL state for renegotiation - prevents epoll busy loop
            // during mid-connection renegotiation (not just initial handshake)
            s->tlsWantWrite = (ge == SSL_ERROR_WANT_WRITE);
            updateInterest(s);
            break;
          }
          if (ge == SSL_ERROR_ZERO_RETURN)
          {
            closeNow(s, TransportError::PeerClosed, "TLS peer closed", 0);
            return;
          }
          unsigned long e = ::ERR_get_error();
          char msg[256];
          ::ERR_error_string_n(e, msg, sizeof(msg));
          closeNow(s, TransportError::TLSIO, msg, (int)e);
          return;
        }
      }
      else
      {
        n = ::recv(s->fd, buf.data(), (int)buf.size(), 0);
        IORA_LOG_DEBUG("[RECV] recv() called for sid=" << s->id << ", returned n=" << n << ", errno=" << errno);
        if (n < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
          {
            IORA_LOG_DEBUG("[RECV] EAGAIN/EWOULDBLOCK for sid=" << s->id << ", breaking from read loop");
            break;
          }
          closeNow(s, TransportError::Socket, lastErr(), 0);
          return;
        }
        if (n == 0)
        {
          core::Logger::debug("Transport: recv() returned 0 for session " + std::to_string(s->id) +
                              " - peer closed connection");
          closeNow(s, TransportError::PeerClosed, "peer closed", 0);
          return;
        }
      }

      if (n > 0)
      {
        _atomicStats.bytesIn += n;
        s->lastActivity = MonoClock::now();
        decltype(_cbs.onData) dataCb;
        { std::lock_guard<std::mutex> g(_cbMutex); dataCb = _cbs.onData; }
        if (dataCb)
        {
          IORA_LOG_DEBUG("[RECV] Calling onData callback for sid=" << s->id << ", bytes=" << n);
          dataCb(s->id, iora::core::BufferView{buf.data(), (std::size_t)n}, std::chrono::steady_clock::now());
        }
        else
        {
          IORA_LOG_WARN("[RECV] onData callback is NULL for sid=" << s->id << ", dropping " << n << " bytes");
        }
      }
      else
      {
        break;
      }
    }
  }

  void writePending(Session *s)
  {
    while (!s->wq.empty())
    {
      ByteBuffer &d = s->wq.front();
      int n = 0;
      if (s->tlsMode != TlsMode::None && s->tlsState == TlsState::Open)
      {
        // B6 Hook: Allow subclass to inject write fault
        if (!beforeSslWrite(s->id, d.size()))
        {
          closeNow(s, TransportError::TLSIO, getInjectedErrorMessage(), getInjectedSslError());
          return;
        }

        n = ::SSL_write(s->ssl, d.data(), (int)d.size());
        if (n <= 0)
        {
          int ge = ::SSL_get_error(s->ssl, n);
          if (ge == SSL_ERROR_WANT_WRITE || ge == SSL_ERROR_WANT_READ)
          {
            s->wantWrite = true;
            // Track SSL state for renegotiation - prevents epoll busy loop
            s->tlsWantWrite = (ge == SSL_ERROR_WANT_WRITE);
            updateInterest(s);
            break;
          }
          unsigned long e = ::ERR_get_error();
          char msg[256];
          ::ERR_error_string_n(e, msg, sizeof(msg));
          closeNow(s, TransportError::TLSIO, msg, (int)e);
          return;
        }
      }
      else
      {
        n = ::send(s->fd, d.data(), (int)d.size(), MSG_NOSIGNAL);
        if (n < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
          {
            s->wantWrite = true;
            updateInterest(s);
            break;
          }
          closeNow(s, TransportError::Socket, lastErr(), 0);
          return;
        }
      }

      if (n >= 0)
      {
        _atomicStats.bytesOut += n;
        s->lastWriteProgress = MonoClock::now();

        // Handle partial writes - only remove sent bytes from buffer
        if (static_cast<size_t>(n) < d.size())
        {
          IORA_LOG_DEBUG("[IO-THREAD] writePending() PARTIAL WRITE for sid=" << s->id
                        << ": sent " << n << " of " << d.size() << " bytes");
          // Remove the sent bytes from the front of the buffer
          d.erase(d.begin(), d.begin() + n);
          // Keep trying to write - socket may accept more data
          s->wantWrite = true;
          updateInterest(s);
          break;  // Exit loop, will retry on next EPOLLOUT
        }
        else
        {
          // Full buffer sent - remove it from queue
          s->wq.pop_front();
        }
      }
    }

    if (s->wq.empty())
    {
      s->wantWrite = false;
      cancelWriteStallTimeout(s);
      updateInterest(s);
    }
  }

  void updateInterest(Session *s)
  {
    std::uint32_t ev = EPOLLIN;
    if (_config.useEdgeTriggered)
      ev |= EPOLLET;
    // CRITICAL FIX: Keep EPOLLOUT registered while connection is pending
    // This ensures we receive the EPOLLOUT event when TCP handshake completes,
    // even in edge-triggered mode where events can be missed if we unregister too early
    //
    // TLS HANDSHAKE FIX: During TLS handshake, only set EPOLLOUT when SSL actually
    // needs to write (SSL_ERROR_WANT_WRITE). Previously we always set EPOLLOUT during
    // handshake, which caused edge-triggered epoll to re-arm and fire immediately
    // (since socket is always writable), creating a tight CPU-burning loop.
    bool needWrite = s->wantWrite || !s->wq.empty();
    if (s->tlsState == TlsState::Handshake)
    {
      // During TLS handshake, only use tlsWantWrite for EPOLLOUT decision
      // Don't use connectPending - that's only for TCP connect phase
      needWrite = needWrite || s->tlsWantWrite;
    }
    else
    {
      // For non-TLS or established TLS connections, use connectPending
      needWrite = needWrite || s->connectPending;
    }
    if (needWrite)
    {
      ev |= EPOLLOUT;
    }
    modEpoll(s->fd, ev);
  }

  void doSend(SendReq &&sr)
  {
    IORA_LOG_DEBUG("[IO-THREAD] doSend() called for sid=" << sr.sid << ", payload size=" << sr.payload.size());

    auto it = _sessions.find(sr.sid);
    if (it == _sessions.end())
    {
      IORA_LOG_DEBUG("[IO-THREAD] doSend() - session " << sr.sid << " not found");
      return;
    }
    Session *s = it->second.get();
    if (s->closed)
    {
      IORA_LOG_DEBUG("[IO-THREAD] doSend() - session " << sr.sid << " is closed");
      return;
    }

    IORA_LOG_DEBUG("[IO-THREAD] doSend() - session " << sr.sid << " wq.size=" << s->wq.size()
                  << ", tlsMode=" << (int)s->tlsMode << ", fd=" << s->fd);

    if (s->wq.empty())
    {
      int n = 0;
      if (s->tlsMode != TlsMode::None && s->tlsState == TlsState::Open)
      {
        // B6 Hook: Allow subclass to inject write fault
        if (!beforeSslWrite(s->id, sr.payload.size()))
        {
          closeNow(s, TransportError::TLSIO, getInjectedErrorMessage(), getInjectedSslError());
          return;
        }

        IORA_LOG_DEBUG("[IO-THREAD] About to call SSL_write for sid=" << sr.sid << ", size=" << sr.payload.size());
        n = ::SSL_write(s->ssl, sr.payload.data(), (int)sr.payload.size());
        IORA_LOG_DEBUG("[IO-THREAD] SSL_write returned " << n << " for sid=" << sr.sid);
        if (n > 0)
        {
          _atomicStats.bytesOut += n;
          s->lastActivity = MonoClock::now();
          s->lastWriteProgress = MonoClock::now();

          // Check if partial write occurred - queue remaining bytes
          if (static_cast<size_t>(n) < sr.payload.size())
          {
            IORA_LOG_DEBUG("[IO-THREAD] SSL PARTIAL WRITE for sid=" << sr.sid << ": sent " << n
                         << " of " << sr.payload.size() << " bytes, queuing remaining "
                         << (sr.payload.size() - n) << " bytes");
            // Queue the unsent portion for later transmission
            ByteBuffer remaining(sr.payload.begin() + n, sr.payload.end());
            s->wq.emplace_front(std::move(remaining));
            s->wantWrite = true;
            updateInterest(s);
          }
          return;
        }
        int ge = ::SSL_get_error(s->ssl, n);
        if (!(ge == SSL_ERROR_WANT_WRITE || ge == SSL_ERROR_WANT_READ))
        {
          unsigned long e = ::ERR_get_error();
          char msg[256];
          ::ERR_error_string_n(e, msg, sizeof(msg));
          IORA_LOG_DEBUG("[IO-THREAD] SSL error for sid=" << sr.sid << ", error=" << msg);
          closeNow(s, TransportError::TLSIO, msg, (int)e);
          return;
        }
        IORA_LOG_DEBUG("[IO-THREAD] SSL_write would block for sid=" << sr.sid << ", queuing data");
      }
      else
      {
        n = ::send(s->fd, sr.payload.data(), (int)sr.payload.size(), MSG_NOSIGNAL);
        IORA_LOG_DEBUG("[IO-THREAD] ::send() for sid=" << sr.sid << " returned " << n
                      << " (requested " << sr.payload.size() << " bytes)");
        if (n >= 0)
        {
          _atomicStats.bytesOut += n;
          s->lastActivity = MonoClock::now();
          s->lastWriteProgress = MonoClock::now();

          // Check if partial write occurred - queue remaining bytes
          if (static_cast<size_t>(n) < sr.payload.size())
          {
            IORA_LOG_DEBUG("[IO-THREAD] PARTIAL WRITE for sid=" << sr.sid << ": sent " << n
                         << " of " << sr.payload.size() << " bytes, queuing remaining "
                         << (sr.payload.size() - n) << " bytes");
            // Queue the unsent portion for later transmission
            ByteBuffer remaining(sr.payload.begin() + n, sr.payload.end());
            s->wq.emplace_front(std::move(remaining));
            s->wantWrite = true;
            updateInterest(s);
          }
          return;
        }
        if (!(errno == EAGAIN || errno == EWOULDBLOCK))
        {
          IORA_LOG_DEBUG("[IO-THREAD] Socket error for sid=" << sr.sid << ", errno=" << errno << ", msg=" << lastErr());
          closeNow(s, TransportError::Socket, lastErr(), 0);
          return;
        }
        IORA_LOG_DEBUG("[IO-THREAD] send() would block (EAGAIN/EWOULDBLOCK) for sid=" << sr.sid << ", queuing data");
      }
    }

    IORA_LOG_DEBUG("[IO-THREAD] Queueing data for sid=" << sr.sid << ", current wq.size=" << s->wq.size());
    s->wq.emplace_back(std::move(sr.payload));
    if (s->wq.size() == 1)
    {
      // First item in queue - schedule write stall timeout
      scheduleWriteStallTimeout(s);
    }
    if (s->wq.size() > _config.maxWriteQueue)
    {
      _atomicStats.backpressureCloses++;
      if (_config.closeOnBackpressure)
      {
        IORA_LOG_DEBUG("[IO-THREAD] Write queue overflow for sid=" << sr.sid << ", closing connection");
        closeNow(s, TransportError::WriteBackpressure, "write queue overflow", 0);
        return;
      }
      else
      {
        IORA_LOG_DEBUG("[IO-THREAD] Write queue overflow for sid=" << sr.sid << ", dropping oldest");
        s->wq.pop_front();
      }
    }
    s->wantWrite = true;
    updateInterest(s);
    IORA_LOG_DEBUG("[IO-THREAD] doSend() completed for sid=" << sr.sid << ", final wq.size=" << s->wq.size());
  }

  void closeNow(Session *s, TransportError why, const std::string &msg, int tlsErr)
  {
    if (!s || s->closed)
    {
      return;
    }
    IORA_LOG_DEBUG("[IO-THREAD] closeNow called for session " << s->id << ", reason: " << msg);
    s->closed = true;
    cancelAllTimers(s);

    // Save caller's errno before system calls that overwrite it
    int savedErrno = errno;

    // Save fields before erasing session from map
    int fd = s->fd;
    SessionId sid = s->id;
    SSL *ssl = s->ssl;
    s->ssl = nullptr; // Take ownership to prevent double-free

    delEpoll(fd);

    auto tagIt = _fdTags.find(fd);
    if (tagIt != _fdTags.end())
    {
      _fdTags.erase(tagIt);
    }

    // Remove from session map under write lock (before closing fd)
    {
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      _sessions.erase(sid);
    }
    // s is now dangling — use only saved locals below

    // SSL_shutdown BEFORE close(fd) — send close_notify on the live fd.
    // After ::close(fd), the fd number may be reused by another connection.
    if (ssl)
    {
      ::SSL_shutdown(ssl);
      ::SSL_free(ssl);
    }

    ::close(fd);

    _atomicStats.closed++;
    _atomicStats.sessionsCurrent--;

    decltype(_cbs.onClose) closeCb;
    { std::lock_guard<std::mutex> g(_cbMutex); closeCb = _cbs.onClose; }

    if (closeCb)
    {
      closeCb(sid, TransportErrorInfo{why, msg, savedErrno, tlsErr});
    }
  }

  void closeListenerNow(Listener *lst)
  {
    delEpoll(lst->fd);
    ::close(lst->fd);
    auto it = _fdTags.find(lst->fd);
    if (it != _fdTags.end())
    {
      _fdTags.erase(it);
    }
  }

  void runGc()
  {
    _atomicStats.gcRuns++;
    const auto now = MonoClock::now();
    const bool age = _config.maxConnAge.count() > 0;

    std::vector<SessionId> toClose;
    toClose.reserve(_sessions.size());

    for (auto &kv : _sessions)
    {
      Session *s = kv.second.get();
      if (s->closed)
      {
        continue;
      }

      if (_config.idleTimeout.count() > 0 && (now - s->lastActivity) > _config.idleTimeout)
      {
        toClose.push_back(s->id);
        _atomicStats.gcClosedIdle++;
        continue;
      }

      if (age && (now - s->created) > _config.maxConnAge)
      {
        toClose.push_back(s->id);
        _atomicStats.gcClosedAged++;
        continue;
      }

      // Use high-resolution timers if available, otherwise fall back to GC-based timeout checking
      if (!_timerService)
      {
        if (s->tlsMode != TlsMode::None && s->tlsState == TlsState::Handshake &&
            _config.handshakeTimeout.count() > 0 &&
            (now - s->tlsStart) >
              std::chrono::duration_cast<std::chrono::seconds>(_config.handshakeTimeout))
        {
          toClose.push_back(s->id);
          continue;
        }

        // Safety-net: connect timeout
        if (_config.connectTimeout.count() > 0 && s->connectPending &&
            (now - s->connectStart) >
              std::chrono::duration_cast<std::chrono::seconds>(_config.connectTimeout))
        {
          toClose.push_back(s->id);
          continue;
        }

        // Safety-net: write stall with queued data
        if (_config.writeStallTimeout.count() > 0 && !s->wq.empty() &&
            (now - s->lastWriteProgress) >
              std::chrono::duration_cast<std::chrono::seconds>(_config.writeStallTimeout))
        {
          toClose.push_back(s->id);
          continue;
        }
      }
    }

    for (auto sid : toClose)
    {
      auto it = _sessions.find(sid);
      if (it != _sessions.end())
      {
        closeNow(it->second.get(), TransportError::GCClosed, "GC safety-net timeout", 0);
      }
    }
  }

  void bumpSess()
  {
    auto cur = _atomicStats.sessionsCurrent.fetch_add(1) + 1;
    auto pk = _atomicStats.sessionsPeak.load();
    while (cur > pk && !_atomicStats.sessionsPeak.compare_exchange_weak(pk, cur))
    {
    }
  }

  void applySockOpts(int fd)
  {
    if (_config.enableTcpNoDelay)
    {
      int one = 1;
      (void)::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    if (_config.soRcvBuf > 0)
    {
      (void)::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &_config.soRcvBuf, sizeof(int));
    }
    if (_config.soSndBuf > 0)
    {
      (void)::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &_config.soSndBuf, sizeof(int));
    }
    if (_config.tcpKeepalive.enable)
    {
      int one = 1;
      (void)::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
      (void)::setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &_config.tcpKeepalive.idle, sizeof(int));
      (void)::setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &_config.tcpKeepalive.interval, sizeof(int));
      (void)::setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &_config.tcpKeepalive.count, sizeof(int));
    }
  }

  // ===== TLS ctx =====

  static void buildAlpnWire(const std::string &list, std::vector<unsigned char> &out)
  {
    out.clear();
    std::size_t i = 0;
    while (i < list.size())
    {
      std::size_t j = list.find(';', i);
      if (j == std::string::npos)
      {
        j = list.size();
      }
      std::size_t len = j - i;
      if (len > 0 && len <= 255)
      {
        out.push_back((unsigned char)len);
        out.insert(out.end(), list.begin() + i, list.begin() + j);
      }
      i = j + 1;
    }
  }

  bool initTls()
  {
    // Server
    if (_config.serverTls.enabled && _config.serverTls.defaultMode == TlsMode::Server)
    {
      _sslSrv = ::SSL_CTX_new(TLS_server_method());
      if (!_sslSrv)
      {
        setLastFatal(IoResult::failure(TransportError::Config, "SSL_CTX_new(server) failed"));
        err(TransportError::Config, "SSL_CTX_new(server)");
        return false;
      }
      if (!_config.serverTls.ciphers.empty())
      {
        ::SSL_CTX_set_cipher_list(_sslSrv, _config.serverTls.ciphers.c_str());
      }
      if (!_config.serverTls.certFile.empty() && !_config.serverTls.keyFile.empty())
      {
        // Validate files exist before attempting to load (clearer error messages)
        if (::access(_config.serverTls.certFile.c_str(), R_OK) != 0)
        {
          setLastFatal(IoResult::failure(TransportError::Config,
            "Server cert file not readable: " + _config.serverTls.certFile));
          err(TransportError::Config, "server cert not readable: " + _config.serverTls.certFile);
          return false;
        }
        if (::access(_config.serverTls.keyFile.c_str(), R_OK) != 0)
        {
          setLastFatal(IoResult::failure(TransportError::Config,
            "Server key file not readable: " + _config.serverTls.keyFile));
          err(TransportError::Config, "server key not readable: " + _config.serverTls.keyFile);
          return false;
        }
        if (::SSL_CTX_use_certificate_file(_sslSrv, _config.serverTls.certFile.c_str(), SSL_FILETYPE_PEM) !=
              1 ||
            ::SSL_CTX_use_PrivateKey_file(_sslSrv, _config.serverTls.keyFile.c_str(), SSL_FILETYPE_PEM) != 1)
        {
          setLastFatal(IoResult::failure(TransportError::Config, "load server cert/key failed"));
          err(TransportError::Config, "load server cert/key");
          return false;
        }
      }
      if (_config.serverTls.verifyPeer)
      {
        ::SSL_CTX_set_verify(_sslSrv, SSL_VERIFY_PEER, nullptr);
        if (!_config.serverTls.caFile.empty())
        {
          if (::SSL_CTX_load_verify_locations(_sslSrv, _config.serverTls.caFile.c_str(), nullptr) != 1)
          {
            setLastFatal(IoResult::failure(TransportError::Config, "server load CA failed"));
            err(TransportError::Config, "server load CA");
            return false;
          }
        }
        else
        {
          ::SSL_CTX_set_default_verify_paths(_sslSrv);
        }
      }
      if (!_config.serverTls.alpn.empty())
      {
        _alpnPref.clear();
        buildAlpnWire(_config.serverTls.alpn, _alpnPref);
        (void)::SSL_CTX_set_alpn_select_cb(
          _sslSrv,
          [](SSL *, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
             unsigned int inlen, void *arg) -> int
          {
            auto *pref = static_cast<std::vector<unsigned char> *>(arg);
            if (pref && !pref->empty() && in && inlen > 0)
            {
              // Minimal: pick the first protocol advertised by the client.
              // (Replace with real preference matching if needed.)
              const unsigned char *p = in;
              unsigned int left = inlen;
              while (left > 0)
              {
                unsigned int l = *p++;
                if (l > 0 && left >= (1 + l))
                {
                  *out = p - 1;
                  *outlen = (unsigned char)(l + 1);
                  return SSL_TLSEXT_ERR_OK;
                }
                p += l;
                left -= (1 + l);
              }
            }
            return SSL_TLSEXT_ERR_NOACK;
          },
          &_alpnPref);
      }
    }

    // Client
    if (_config.clientTls.enabled && _config.clientTls.defaultMode == TlsMode::Client)
    {
      _sslCli = ::SSL_CTX_new(TLS_client_method());
      if (!_sslCli)
      {
        setLastFatal(IoResult::failure(TransportError::Config, "SSL_CTX_new(client) failed"));
        err(TransportError::Config, "SSL_CTX_new(client)");
        return false;
      }
      if (!_config.clientTls.ciphers.empty())
      {
        ::SSL_CTX_set_cipher_list(_sslCli, _config.clientTls.ciphers.c_str());
      }
      // Load client certificate and key for mutual TLS
      if (!_config.clientTls.certFile.empty())
      {
        // Validate file exists before attempting to load (clearer error messages)
        if (::access(_config.clientTls.certFile.c_str(), R_OK) != 0)
        {
          setLastFatal(IoResult::failure(TransportError::Config,
            "Client cert file not readable: " + _config.clientTls.certFile));
          err(TransportError::Config, "client cert not readable: " + _config.clientTls.certFile);
          return false;
        }
        if (::SSL_CTX_use_certificate_file(_sslCli, _config.clientTls.certFile.c_str(), SSL_FILETYPE_PEM) !=
            1)
        {
          setLastFatal(IoResult::failure(TransportError::Config, "client load cert failed"));
          err(TransportError::Config, "client load cert");
          return false;
        }
      }
      if (!_config.clientTls.keyFile.empty())
      {
        // Validate file exists before attempting to load (clearer error messages)
        if (::access(_config.clientTls.keyFile.c_str(), R_OK) != 0)
        {
          setLastFatal(IoResult::failure(TransportError::Config,
            "Client key file not readable: " + _config.clientTls.keyFile));
          err(TransportError::Config, "client key not readable: " + _config.clientTls.keyFile);
          return false;
        }
        if (::SSL_CTX_use_PrivateKey_file(_sslCli, _config.clientTls.keyFile.c_str(), SSL_FILETYPE_PEM) != 1)
        {
          setLastFatal(IoResult::failure(TransportError::Config, "client load key failed"));
          err(TransportError::Config, "client load key");
          return false;
        }
        if (::SSL_CTX_check_private_key(_sslCli) != 1)
        {
          setLastFatal(IoResult::failure(TransportError::Config, "client cert/key mismatch"));
          err(TransportError::Config, "client cert/key mismatch");
          return false;
        }
      }
      if (_config.clientTls.verifyPeer)
      {
        ::SSL_CTX_set_verify(_sslCli, SSL_VERIFY_PEER, nullptr);
        if (!_config.clientTls.caFile.empty())
        {
          if (::SSL_CTX_load_verify_locations(_sslCli, _config.clientTls.caFile.c_str(), nullptr) != 1)
          {
            setLastFatal(IoResult::failure(TransportError::Config, "client load CA failed"));
            err(TransportError::Config, "client load CA");
            return false;
          }
        }
        else
        {
          ::SSL_CTX_set_default_verify_paths(_sslCli);
        }
      }
      if (!_config.clientTls.alpn.empty())
      {
        std::vector<unsigned char> wire;
        buildAlpnWire(_config.clientTls.alpn, wire);
        (void)::SSL_CTX_set_alpn_protos(_sslCli, wire.data(), (unsigned int)wire.size());
      }
    }

    return true;
  }

  void freeTls()
  {
    if (_sslSrv)
    {
      ::SSL_CTX_free(_sslSrv);
      _sslSrv = nullptr;
    }
    if (_sslCli)
    {
      ::SSL_CTX_free(_sslCli);
      _sslCli = nullptr;
    }
  }

  struct AtomicStats
  {
    std::atomic<std::uint64_t> accepted{0}, connected{0}, closed{0}, errors{0}, tlsHandshakes{0},
      tlsFailures{0}, bytesIn{0}, bytesOut{0}, epollWakeups{0}, commands{0}, gcRuns{0},
      gcClosedIdle{0}, gcClosedAged{0}, backpressureCloses{0};
    std::atomic<std::size_t> sessionsCurrent{0}, sessionsPeak{0};
  };

  TransportConfig _config{};
  mutable AtomicStats _atomicStats{};

  std::atomic<bool> _running{false};
  int _epollFd{-1}, _eventFd{-1}, _timerFd{-1};
  std::thread _loop;

  // Lock ordering: _cbMutex and _sessionRwMutex are never held simultaneously.
  // _cbMutex protects callback copies (acquired/released before any _sessionRwMutex use).
  // _sessionRwMutex protects session/listener maps (shared_lock for reads, unique_lock for mutations).
  std::mutex _cbMutex;
  detail::EngineBase::Callbacks _cbs{};

  mutable std::shared_mutex _sessionRwMutex;

  std::mutex _cmdMutex;
  std::deque<Command> _cmds;

  std::unordered_map<ListenerId, std::unique_ptr<Listener>> _listeners;
  std::unordered_map<SessionId, std::unique_ptr<Session>> _sessions;
  std::unordered_map<int, std::unique_ptr<Tag>> _fdTags;

  std::atomic<SessionId> _nextSessionId{1};
  std::atomic<ListenerId> _nextListenerId{1};

  // TLS contexts and per-instance ALPN preference
  SSL_CTX *_sslSrv{nullptr};
  SSL_CTX *_sslCli{nullptr};
  std::vector<unsigned char> _alpnPref;

  // Sticky fatal (for start/init failures)
  mutable std::mutex _fatalMx;
  mutable IoResult _lastFatal{IoResult::success()};

  // High-resolution timer service
  std::unique_ptr<iora::core::TimerService> _timerService;
  iora::core::TimerServiceConfig _timerConfig;

  // Batch processor (created when batching is enabled)
  std::unique_ptr<EventBatchProcessor> _batchProcessor;

  // Static SSL initialization coordination
  static std::once_flag _sslGlobalInitFlag;
  static std::atomic<int> debugInstanceCount;
  static void initSslGlobal();
};

// Static member definitions
inline std::once_flag TcpEngine::_sslGlobalInitFlag;
inline std::atomic<int> TcpEngine::debugInstanceCount{0};

inline void TcpEngine::initSslGlobal()
{
  // Initialize OpenSSL library once per process
  // This prevents deadlocks when multiple transports initialize
  // simultaneously
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  // For OpenSSL < 1.1.0
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
#else
  // For OpenSSL >= 1.1.0, automatic initialization is handled by library
  // But we can still call OPENSSL_init_ssl for explicit control
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
#endif
}

} // namespace network
} // namespace iora