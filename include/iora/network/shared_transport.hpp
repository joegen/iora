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

/// \file iora_shared_transport.hpp
/// \brief Header-only, Linux-only epoll-based shared TCP/TLS transport.
/// \details
///   - Single I/O thread (epoll + eventfd + timerfd)
///   - Async accept/connect/read/write with internal session GC
///   - Optional TLS (OpenSSL) for server and client
///   - Safety-net timeouts: idle/connect/handshake/write-stall/max-age
///   - Rich IoResult on all callbacks
///   - Thread-safe public API (signals I/O thread via eventfd)
///

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
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
#include "transport_types.hpp"
#include "sync_async_transport.hpp"
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace iora
{
namespace network
{

/// \brief Shared TCP/TLS transport (single-threaded epoll loop).
/// \note Linux-only.
class SharedTransport
{
public:
  /// \brief Runtime configuration.
  struct Config
  {
    int epollMaxEvents{256};
    std::size_t ioReadChunk{64 * 1024};
    std::size_t maxWriteQueue{1024};
    bool closeOnBackpressure{true};

    std::chrono::seconds idleTimeout{600};
    std::chrono::seconds maxConnAge{std::chrono::seconds::zero()};
    // High-resolution timers (milliseconds precision)
    std::chrono::milliseconds handshakeTimeout{30000};
    std::chrono::milliseconds connectTimeout{30000};
    std::chrono::milliseconds writeStallTimeout{0};
    std::chrono::seconds gcInterval{5};    // Keep for legacy cleanup
    bool enableHighResolutionTimers{true}; // Enable TimerService integration

    bool useEdgeTriggered{true};
    bool enableTcpNoDelay{true};
    int soRcvBuf{0};
    int soSndBuf{0};

    struct TcpKeepalive
    {
      bool enable{false};
      int idleSec{60};
      int intvlSec{10};
      int cnt{3};
    } tcpKeepalive;
  };

  /// \brief TLS configuration (OpenSSL).
  struct TlsConfig
  {
    bool enabled{false};
    TlsMode defaultMode{TlsMode::None};
    std::string certFile;
    std::string keyFile;
    std::string caFile;
    std::string ciphers;
    std::string alpn; ///< semicolon-separated, e.g. "h2;http/1.1"
    bool verifyPeer{false};
  };

  /// \brief Callback bundle (all optional).
  struct Callbacks
  {
    std::function<void(SessionId, const std::string &, const IoResult &)> onAccept;
    std::function<void(SessionId, const IoResult &)> onConnect;
    std::function<void(SessionId, const std::uint8_t *, std::size_t, const IoResult &)> onData;
    std::function<void(SessionId, const IoResult &)> onClosed;
    std::function<void(TransportError, const std::string &)> onError;
  };

  /// \brief Basic counters (monotonic).
  struct Stats
  {
    std::uint64_t accepted{0}, connected{0}, closed{0}, errors{0}, tlsHandshakes{0}, tlsFailures{0},
      bytesIn{0}, bytesOut{0}, epollWakeups{0}, commands{0}, gcRuns{0}, gcClosedIdle{0},
      gcClosedAged{0}, backpressureCloses{0};
    std::size_t sessionsCurrent{0}, sessionsPeak{0};
  };

  /// \brief Construct with config and TLS contexts.
  SharedTransport(const Config &cfg, const TlsConfig &srv, const TlsConfig &cli)
      : _cfg(cfg), _srvTls(srv), _cliTls(cli)
  {
    // Ensure OpenSSL is initialized once per process
    std::call_once(_sslGlobalInitFlag, initSslGlobal);

    // Initialize high-resolution timer service if enabled
    if (_cfg.enableHighResolutionTimers)
    {
      _timerConfig.limits.maxConcurrentTimers = 10000;
      _timerConfig.enableStatistics = true;
      _timerConfig.threadName = "SharedTransportTimer";
      _timerService = std::make_unique<iora::core::TimerService>(_timerConfig);
    }
  }

  /// \brief Destructor; calls stop() if needed.
  ~SharedTransport() { stop(); }

  SharedTransport(const SharedTransport &) = delete;
  SharedTransport &operator=(const SharedTransport &) = delete;

  /// \brief Install callbacks (may be called before or after start()).
  void setCallbacks(const Callbacks &cbs)
  {
    std::lock_guard<std::mutex> g(_cbMutex);
    _cbs = cbs;
  }

  // ITransportBase interface implementation - individual callback setters
  // These methods preserve existing callbacks and only update the specific
  // one
  void setDataCallback(
    std::function<void(SessionId, const std::uint8_t *, std::size_t, const IoResult &)> cb)
  {
    std::lock_guard<std::mutex> g(_cbMutex);
    _cbs.onData = cb;
  }

  void setAcceptCallback(std::function<void(SessionId, const std::string &, const IoResult &)> cb)
  {
    std::lock_guard<std::mutex> g(_cbMutex);
    _cbs.onAccept = cb;
  }

  void setConnectCallback(std::function<void(SessionId, const IoResult &)> cb)
  {
    std::lock_guard<std::mutex> g(_cbMutex);
    _cbs.onConnect = cb;
  }

  void setCloseCallback(std::function<void(SessionId, const IoResult &)> cb)
  {
    std::lock_guard<std::mutex> g(_cbMutex);
    _cbs.onClosed = cb;
  }

  void setErrorCallback(std::function<void(TransportError, const std::string &)> cb)
  {
    std::lock_guard<std::mutex> g(_cbMutex);
    _cbs.onError = cb;
  }

  /// \brief Start I/O thread and initialize TLS contexts.
  /// \return true on success; false on failure (inspect lastFatalError()).
  bool start()
  {
    bool exp = false;
    if (!_running.compare_exchange_strong(exp, true))
    {
      return false;
    }

    if (!initTls())
    {
      _running.store(false);
      return false;
    }

    _epollFd = ::epoll_create1(EPOLL_CLOEXEC);
    if (_epollFd < 0)
    {
      setLastFatal(IoResult::failure(TransportError::Config, "epoll_create1: " + lastErr(), errno));
      err(TransportError::Config, "epoll_create1: " + lastErr());
      _running.store(false);
      freeTls();
      return false;
    }

    _eventFd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (_eventFd < 0)
    {
      setLastFatal(IoResult::failure(TransportError::Config, "eventfd: " + lastErr(), errno));
      err(TransportError::Config, "eventfd: " + lastErr());
      cleanupStartFail();
      return false;
    }
    addEpoll(_eventFd, EPOLLIN);

    _timerFd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (_timerFd < 0)
    {
      setLastFatal(
        IoResult::failure(TransportError::Config, "timerfd_create: " + lastErr(), errno));
      err(TransportError::Config, "timerfd_create: " + lastErr());
      cleanupStartFail();
      return false;
    }
    addEpoll(_timerFd, EPOLLIN);
    armGc(_cfg.gcInterval);

    try
    {
      _loop = std::thread([this] { loop(); });
    }
    catch (const std::exception &ex)
    {
      setLastFatal(
        IoResult::failure(TransportError::Config, std::string("thread start: ") + ex.what()));
      cleanupStartFail();
      return false;
    }

    return true;
  }

  /// \brief Stop I/O thread and release resources.
  void stop()
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
  ListenerId addListener(const std::string &bind, std::uint16_t port, TlsMode tls)
  {
    ListenerCfg lc;
    lc.id = _nextListenerId++;
    lc.addr = bind;
    lc.port = port;
    lc.tls = tls;
    enqueue(Command::addListener(lc));
    return lc.id;
  }

  /// \brief Begin an outbound connection (async); result via onConnect.
  SessionId connect(const std::string &host, std::uint16_t port, TlsMode tls)
  {
    SessionId sid = _nextSessionId++;
    ConnectReq cr{sid, host, port, tls};
    enqueue(Command::connect(cr));
    return sid;
  }

  /// \brief Queue a send on a session (non-blocking; may enqueue on EAGAIN).
  bool send(SessionId sid, const void *data, std::size_t n)
  {
    if (n == 0)
    {
      return true;
    }
    ByteBuffer b(n);
    std::memcpy(b.data(), data, n);
    SendReq sr;
    sr.sid = sid;
    sr.payload = std::move(b);
    return enqueue(Command::send(std::move(sr)));
  }

  /// \brief Close a session (idempotent). onClosed will fire.
  bool close(SessionId sid) { return enqueue(Command::close(sid)); }

  /// \brief Reconfigure runtime knobs; safe while running.
  void reconfigure(const Config &c) { enqueue(Command::reconf(c)); }

  /// \brief Snapshot of counters.
  Stats stats() const
  {
    Stats copy;
    copy.accepted = _atomicStats.accepted.load();
    copy.connected = _atomicStats.connected.load();
    copy.closed = _atomicStats.closed.load();
    copy.errors = _atomicStats.errors.load();
    copy.tlsHandshakes = _atomicStats.tlsHandshakes.load();
    copy.tlsFailures = _atomicStats.tlsFailures.load();
    copy.bytesIn = _atomicStats.bytesIn.load();
    copy.bytesOut = _atomicStats.bytesOut.load();
    copy.epollWakeups = _atomicStats.epollWakeups.load();
    copy.commands = _atomicStats.commands.load();
    copy.gcRuns = _atomicStats.gcRuns.load();
    copy.gcClosedIdle = _atomicStats.gcClosedIdle.load();
    copy.gcClosedAged = _atomicStats.gcClosedAged.load();
    copy.backpressureCloses = _atomicStats.backpressureCloses.load();
    copy.sessionsCurrent = _atomicStats.sessionsCurrent.load();
    copy.sessionsPeak = _atomicStats.sessionsPeak.load();
    return copy;
  }

  /// \brief Basic stats for ITransportBase compatibility
  BasicTransportStats getBasicStats() const
  {
    BasicTransportStats basic{};
    basic.accepted = _atomicStats.accepted.load();
    basic.connected = _atomicStats.connected.load();
    basic.closed = _atomicStats.closed.load();
    basic.errors = _atomicStats.errors.load();
    basic.bytesIn = _atomicStats.bytesIn.load();
    basic.bytesOut = _atomicStats.bytesOut.load();
    basic.sessionsCurrent = _atomicStats.sessionsCurrent.load();
    return basic;
  }

  /// \brief Sticky last fatal error (since process start). Valid after
  /// start() failure.
  IoResult lastFatalError() const
  {
    std::lock_guard<std::mutex> g(_fatalMx);
    return _lastFatal;
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
    std::lock_guard<std::mutex> g(_cbMutex);
    if (_cbs.onError)
    {
      _cbs.onError(te, m);
    }
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
    Close,
    Reconf
  };

  struct Command
  {
    Cmd t;
    ListenerCfg l;
    ConnectReq c;
    SendReq s;
    SessionId closeSid{};
    Config cfg;

    static Command shutdown() { return Command{Cmd::Shutdown}; }
    static Command addListener(const ListenerCfg &lc)
    {
      Command x{Cmd::AddListener};
      x.l = lc;
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
    static Command close(SessionId sid)
    {
      Command x{Cmd::Close};
      x.closeSid = sid;
      return x;
    }
    static Command reconf(const Config &cfg)
    {
      Command x{Cmd::Reconf};
      x.cfg = cfg;
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
      std::lock_guard<std::mutex> g(_cbMutex);
      if (_cbs.onError)
      {
        _cbs.onError(TransportError::Unknown, std::string("enqueue(copy): ") + ex.what());
      }
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
      std::lock_guard<std::mutex> g(_cbMutex);
      if (_cbs.onError)
      {
        _cbs.onError(TransportError::Unknown, std::string("enqueue(move): ") + ex.what());
      }
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
    if (!_timerService || _cfg.connectTimeout.count() == 0 || s->connectTimeoutId != 0)
    {
      return;
    }

    s->connectTimeoutId = _timerService->scheduleAfter(_cfg.connectTimeout, [this, sid = s->id]()
                                                       { handleConnectTimeout(sid); });
  }

  void scheduleHandshakeTimeout(Session *s)
  {
    if (!_timerService || _cfg.handshakeTimeout.count() == 0 || s->handshakeTimeoutId != 0)
    {
      return;
    }

    s->handshakeTimeoutId = _timerService->scheduleAfter(
      _cfg.handshakeTimeout, [this, sid = s->id]() { handleHandshakeTimeout(sid); });
  }

  void scheduleWriteStallTimeout(Session *s)
  {
    if (!_timerService || _cfg.writeStallTimeout.count() == 0 || s->writeStallTimeoutId != 0)
    {
      return;
    }

    s->writeStallTimeoutId = _timerService->scheduleAfter(
      _cfg.writeStallTimeout, [this, sid = s->id]() { handleWriteStallTimeout(sid); });
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
    auto it = _sessions.find(sid);
    if (it != _sessions.end())
    {
      auto *s = it->second.get();
      s->connectTimeoutId = 0; // Mark as expired
      if (s->connectPending)
      {
        closeNow(s, TransportError::Timeout, "Connect timeout", 0);
      }
    }
  }

  void handleHandshakeTimeout(SessionId sid)
  {
    auto it = _sessions.find(sid);
    if (it != _sessions.end())
    {
      auto *s = it->second.get();
      s->handshakeTimeoutId = 0; // Mark as expired
      if (s->tlsState == TlsState::Handshake)
      {
        closeNow(s, TransportError::TLSHandshake, "TLS handshake timeout", 0);
      }
    }
  }

  void handleWriteStallTimeout(SessionId sid)
  {
    auto it = _sessions.find(sid);
    if (it != _sessions.end())
    {
      auto *s = it->second.get();
      s->writeStallTimeoutId = 0; // Mark as expired
      if (!s->wq.empty())
      {
        closeNow(s, TransportError::Timeout, "Write stall timeout", 0);
      }
    }
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
    std::vector<epoll_event> evs((std::size_t)_cfg.epollMaxEvents);
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

        auto it = _fdTags.find(fd);
        if (it == _fdTags.end())
        {
          continue;
        }
        Tag *t = it->second.get();
        if (t->isListener)
        {
          onListener(t->lst);
        }
        else
        {
          onSession(t->sess, events);
        }
      }
    }

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
      ::close(s->fd);
      if (s->ssl)
      {
        ::SSL_free(s->ssl);
        s->ssl = nullptr;
      }
      _atomicStats.closed++;
      _atomicStats.sessionsCurrent--;
      {
        std::lock_guard<std::mutex> g(_cbMutex);
        if (_cbs.onClosed)
        {
          IoResult r = IoResult::failure(TransportError::Unknown, "shutdown", 0, 0);
          _cbs.onClosed(s->id, r);
        }
      }
    }
    _sessions.clear();

    // Close listeners
    std::vector<Listener *> listenersToClose;
    listenersToClose.reserve(_listeners.size());
    for (auto &kv : _listeners)
      listenersToClose.push_back(kv.second.get());

    for (auto *lst : listenersToClose)
      closeListenerNow(lst);
    _listeners.clear();
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
          doAddListener(c.l);
          break;
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
            closeNow(it->second.get(), TransportError::Unknown, "closed by app", 0);
          }
          break;
        }
        case Cmd::Reconf:
          _cfg = c.cfg;
          armGc(_cfg.gcInterval);
          break;
        }
      }
      catch (const std::exception &ex)
      {
        std::lock_guard<std::mutex> g(_cbMutex);
        if (_cbs.onError)
        {
          _cbs.onError(TransportError::Unknown, std::string("cmd dispatch: ") + ex.what());
        }
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

    if (_cfg.soRcvBuf > 0)
      ::setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, &_cfg.soRcvBuf, sizeof(int));
    if (_cfg.soSndBuf > 0)
      ::setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &_cfg.soSndBuf, sizeof(int));

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
    if (_cfg.useEdgeTriggered)
      ev |= EPOLLET;
    addEpoll(sfd, ev);

    auto tag = std::make_unique<Tag>();
    tag->isListener = true;
    tag->lst = lst.get();
    _fdTags.emplace(sfd, std::move(tag));

    _listeners.emplace(lst->id, std::move(lst));
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

      if (lst->tls == TlsMode::Server && _srvTls.enabled && _sslSrv)
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

      _sessions.emplace(sid, std::move(s));
      bumpSess();

      std::uint32_t ev = EPOLLIN;
      if (_cfg.useEdgeTriggered)
        ev |= EPOLLET;
      addEpoll(cfd, ev);

      auto tg = std::make_unique<Tag>();
      tg->isListener = false;
      tg->sess = _sessions[sid].get();
      _fdTags.emplace(cfd, std::move(tg));

      _atomicStats.accepted++;
      std::lock_guard<std::mutex> g(_cbMutex);
      if (_cbs.onAccept)
      {
        _cbs.onAccept(sid, _sessions[sid]->peerKey, IoResult::success());
      }
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

    if (isIPv4 || isIPv6)
    {
      // For IP addresses, create minimal addrinfo structure manually
      res = new addrinfo();
      memset(res, 0, sizeof(addrinfo));
      res->ai_family = isIPv4 ? AF_INET : AF_INET6;
      res->ai_socktype = SOCK_STREAM;
      res->ai_protocol = IPPROTO_TCP;

      if (isIPv4)
      {
        res->ai_addrlen = sizeof(sockaddr_in);
        auto *addr4 = new sockaddr_in();
        memset(addr4, 0, sizeof(sockaddr_in));
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(cr.port);
        addr4->sin_addr = sa4.sin_addr;
        res->ai_addr = reinterpret_cast<sockaddr *>(addr4);
      }
      else
      {
        res->ai_addrlen = sizeof(sockaddr_in6);
        auto *addr6 = new sockaddr_in6();
        memset(addr6, 0, sizeof(sockaddr_in6));
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(cr.port);
        addr6->sin6_addr = sa6.sin6_addr;
        res->ai_addr = reinterpret_cast<sockaddr *>(addr6);
      }
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
        std::lock_guard<std::mutex> g(_cbMutex);
        std::string timeoutMsg = "DNS_TIMEOUT_FIX_TRIGGERED: getaddrinfo timeout after " +
                                 std::to_string(dnsTimeout.count()) + "s for " + cr.host + ":" + ps;
        if (_cbs.onConnect)
        {
          _cbs.onConnect(cr.sid, IoResult::failure(TransportError::Resolve, timeoutMsg));
        }
        err(TransportError::Resolve, timeoutMsg);
        return false;
      }

      rc = dnsResult.get();
    }
    if (rc != 0 || !res)
    {
      std::lock_guard<std::mutex> g(_cbMutex);
      if (_cbs.onConnect)
      {
        _cbs.onConnect(cr.sid, IoResult::failure(TransportError::Resolve,
                                                 std::string("getaddrinfo: ") + gai_strerror(rc)));
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
        // Connection definitively failed - don't retry other addresses for
        // same host
        ::close(cfd);
        cfd = -1;

        // Clean up addrinfo before returning
        if (isIPv4 || isIPv6)
        {
          if (res && res->ai_addr)
          {
            delete res->ai_addr;
          }
          delete res;
        }
        else
        {
          ::freeaddrinfo(res);
        }

        // Report immediate failure
        std::lock_guard<std::mutex> g(_cbMutex);
        if (_cbs.onConnect)
        {
          std::string errMsg =
            "Connection refused to " + cr.host + ":" + ps.c_str() + " - " + lastErr();
          _cbs.onConnect(cr.sid, IoResult::failure(TransportError::Connect, errMsg, errno, 0));
        }
        err(TransportError::Connect, "connect immediately failed: " + lastErr());
        return false;
      }
      ::close(cfd);
      cfd = -1;
    }

    // Custom cleanup for manually created addrinfo structure
    if (isIPv4 || isIPv6)
    {
      if (res && res->ai_addr)
      {
        delete res->ai_addr;
      }
      delete res;
    }
    else
    {
      ::freeaddrinfo(res);
    }

    if (cfd < 0)
    {
      std::lock_guard<std::mutex> g(_cbMutex);
      if (_cbs.onConnect)
      {
        _cbs.onConnect(cr.sid, IoResult::failure(TransportError::Connect, lastErr(), errno, 0));
      }
      err(TransportError::Connect, "connect: " + lastErr());
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

    if (chosen)
    {
      sockaddr_storage peer{};
      socklen_t pl = (socklen_t)chosen->ai_addrlen;
      std::memcpy(&peer, chosen->ai_addr, pl);
      s->peerLen = pl;
      s->peerKey = keyFromSockaddr(peer);
      std::memcpy(&s->peer, &peer, pl);
    }

    if (cr.tls == TlsMode::Client && _cliTls.enabled && _sslCli)
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
      scheduleHandshakeTimeout(s.get());
    }

    _sessions.emplace(s->id, std::move(s));
    bumpSess();

    std::uint32_t ev = EPOLLIN | EPOLLOUT;
    if (_cfg.useEdgeTriggered)
      ev |= EPOLLET;
    addEpoll(cfd, ev);
    auto tg = std::make_unique<Tag>();
    tg->isListener = false;
    tg->sess = _sessions[cr.sid].get();
    _fdTags.emplace(cfd, std::move(tg));
    return true;
  }

  void onSession(Session *s, std::uint32_t events)
  {
    if (!s || s->closed)
    {
      return;
    }

    if (events & EPOLLOUT)
    {
      int err = 0;
      socklen_t el = sizeof(err);
      if (::getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err != 0)
      {
        closeNow(s, TransportError::Connect, std::strerror(err), 0);
        return;
      }
    }

    if (s->tlsMode != TlsMode::None && s->tlsState == TlsState::Handshake)
    {
      if (!driveHandshake(s))
      {
        return;
      } // progressed or closed; if still handshaking, return
    }
    else
    {
      if (events & EPOLLOUT)
      {
        std::lock_guard<std::mutex> g(_cbMutex);
        if (_cbs.onConnect)
        {
          _atomicStats.connected++;
          _cbs.onConnect(s->id, IoResult::success());
        }
        s->connectPending = false;
        s->lastWriteProgress = MonoClock::now();
        cancelConnectTimeout(s);
        updateInterest(s);
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
      readAvail(s);
    }
    if (events & EPOLLOUT)
    {
      writePending(s);
    }
  }

  bool driveHandshake(Session *s)
  {
    // Only check timeout here if high-resolution timers are not available
    if (!_timerService && _cfg.handshakeTimeout.count() > 0 &&
        (MonoClock::now() - s->tlsStart) >
          std::chrono::duration_cast<std::chrono::seconds>(_cfg.handshakeTimeout))
    {
      closeNow(s, TransportError::TLSHandshake, "TLS handshake timeout", 0);
      return false;
    }

    int rc = ::SSL_do_handshake(s->ssl);
    if (rc == 1)
    {
      s->tlsState = TlsState::Open;
      _atomicStats.tlsHandshakes++;
      cancelHandshakeTimeout(s);

      {
        std::lock_guard<std::mutex> g(_cbMutex);
        if (_cbs.onConnect)
        {
          _atomicStats.connected++;
          _cbs.onConnect(s->id, IoResult::success());
        }
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
    if (errc == SSL_ERROR_WANT_READ || errc == SSL_ERROR_WANT_WRITE)
    {
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
      buf.resize(_cfg.ioReadChunk);
      int n = 0;
      if (s->tlsMode != TlsMode::None && s->tlsState == TlsState::Open)
      {
        n = ::SSL_read(s->ssl, buf.data(), (int)buf.size());
        if (n <= 0)
        {
          int ge = ::SSL_get_error(s->ssl, n);
          if (ge == SSL_ERROR_WANT_READ || ge == SSL_ERROR_WANT_WRITE)
          {
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
        if (n < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
          {
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
        std::lock_guard<std::mutex> g(_cbMutex);
        if (_cbs.onData)
        {
          _cbs.onData(s->id, buf.data(), (std::size_t)n, IoResult::success());
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
        n = ::SSL_write(s->ssl, d.data(), (int)d.size());
        if (n <= 0)
        {
          int ge = ::SSL_get_error(s->ssl, n);
          if (ge == SSL_ERROR_WANT_WRITE || ge == SSL_ERROR_WANT_READ)
          {
            s->wantWrite = true;
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
        n = ::send(s->fd, d.data(), (int)d.size(), 0);
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
        s->wq.pop_front();
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
    if (_cfg.useEdgeTriggered)
      ev |= EPOLLET;
    if (s->wantWrite || !s->wq.empty() || s->tlsState == TlsState::Handshake)
    {
      ev |= EPOLLOUT;
    }
    modEpoll(s->fd, ev);
  }

  void doSend(SendReq &&sr)
  {
    auto it = _sessions.find(sr.sid);
    if (it == _sessions.end())
    {
      return;
    }
    Session *s = it->second.get();
    if (s->closed)
    {
      return;
    }

    if (s->wq.empty())
    {
      int n = 0;
      if (s->tlsMode != TlsMode::None && s->tlsState == TlsState::Open)
      {
        n = ::SSL_write(s->ssl, sr.payload.data(), (int)sr.payload.size());
        if (n > 0)
        {
          _atomicStats.bytesOut += n;
          s->lastActivity = MonoClock::now();
          s->lastWriteProgress = MonoClock::now();
          return;
        }
        int ge = ::SSL_get_error(s->ssl, n);
        if (!(ge == SSL_ERROR_WANT_WRITE || ge == SSL_ERROR_WANT_READ))
        {
          unsigned long e = ::ERR_get_error();
          char msg[256];
          ::ERR_error_string_n(e, msg, sizeof(msg));
          closeNow(s, TransportError::TLSIO, msg, (int)e);
          return;
        }
      }
      else
      {
        n = ::send(s->fd, sr.payload.data(), (int)sr.payload.size(), 0);
        if (n >= 0)
        {
          _atomicStats.bytesOut += n;
          s->lastActivity = MonoClock::now();
          s->lastWriteProgress = MonoClock::now();
          return;
        }
        if (!(errno == EAGAIN || errno == EWOULDBLOCK))
        {
          closeNow(s, TransportError::Socket, lastErr(), 0);
          return;
        }
      }
    }

    s->wq.emplace_back(std::move(sr.payload));
    if (s->wq.size() == 1)
    {
      // First item in queue - schedule write stall timeout
      scheduleWriteStallTimeout(s);
    }
    if (s->wq.size() > _cfg.maxWriteQueue)
    {
      _atomicStats.backpressureCloses++;
      if (_cfg.closeOnBackpressure)
      {
        closeNow(s, TransportError::WriteBackpressure, "write queue overflow", 0);
        return;
      }
      else
      {
        s->wq.pop_front();
      }
    }
    s->wantWrite = true;
    updateInterest(s);
  }

  void closeNow(Session *s, TransportError why, const std::string &msg, int tlsErr)
  {
    if (!s || s->closed)
    {
      return;
    }
    core::Logger::debug("Transport: closeNow called for session " + std::to_string(s->id) +
                        ", reason: " + msg);
    s->closed = true;
    cancelAllTimers(s);

    delEpoll(s->fd);
    ::close(s->fd);

    auto tagIt = _fdTags.find(s->fd);
    if (tagIt != _fdTags.end())
    {
      _fdTags.erase(tagIt);
    }

    if (s->ssl)
    {
      ::SSL_shutdown(s->ssl);
      ::SSL_free(s->ssl);
      s->ssl = nullptr;
    }

    _atomicStats.closed++;
    _atomicStats.sessionsCurrent--;

    {
      std::lock_guard<std::mutex> g(_cbMutex);

      // CRITICAL FIX: If connection was still pending, this is a failed
      // connect, not a closed connection
      if (s->connectPending && _cbs.onConnect)
      {
        // Failed connection - call onConnect with failure
        IoResult r = IoResult::failure(why, msg, errno, tlsErr);
        _cbs.onConnect(s->id, r);
      }
      else if (_cbs.onClosed)
      {
        // Established connection was closed - call onClosed
        IoResult r = (why == TransportError::None && msg.empty())
                       ? IoResult::success()
                       : IoResult::failure(why, msg, errno, tlsErr);
        _cbs.onClosed(s->id, r);
      }
    }

    _sessions.erase(s->id);
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
    const bool age = _cfg.maxConnAge.count() > 0;

    std::vector<SessionId> toClose;
    toClose.reserve(_sessions.size());

    for (auto &kv : _sessions)
    {
      Session *s = kv.second.get();
      if (s->closed)
      {
        continue;
      }

      if (_cfg.idleTimeout.count() > 0 && (now - s->lastActivity) > _cfg.idleTimeout)
      {
        toClose.push_back(s->id);
        _atomicStats.gcClosedIdle++;
        continue;
      }

      if (age && (now - s->created) > _cfg.maxConnAge)
      {
        toClose.push_back(s->id);
        _atomicStats.gcClosedAged++;
        continue;
      }

      // Use high-resolution timers if available, otherwise fall back to GC-based timeout checking
      if (!_timerService)
      {
        if (s->tlsMode != TlsMode::None && s->tlsState == TlsState::Handshake &&
            _cfg.handshakeTimeout.count() > 0 &&
            (now - s->tlsStart) >
              std::chrono::duration_cast<std::chrono::seconds>(_cfg.handshakeTimeout))
        {
          toClose.push_back(s->id);
          continue;
        }

        // Safety-net: connect timeout
        if (_cfg.connectTimeout.count() > 0 && s->connectPending &&
            (now - s->connectStart) >
              std::chrono::duration_cast<std::chrono::seconds>(_cfg.connectTimeout))
        {
          toClose.push_back(s->id);
          continue;
        }

        // Safety-net: write stall with queued data
        if (_cfg.writeStallTimeout.count() > 0 && !s->wq.empty() &&
            (now - s->lastWriteProgress) >
              std::chrono::duration_cast<std::chrono::seconds>(_cfg.writeStallTimeout))
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
    if (_cfg.enableTcpNoDelay)
    {
      int one = 1;
      (void)::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    if (_cfg.soRcvBuf > 0)
    {
      (void)::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &_cfg.soRcvBuf, sizeof(int));
    }
    if (_cfg.soSndBuf > 0)
    {
      (void)::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &_cfg.soSndBuf, sizeof(int));
    }
    if (_cfg.tcpKeepalive.enable)
    {
      int one = 1;
      (void)::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
      (void)::setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &_cfg.tcpKeepalive.idleSec, sizeof(int));
      (void)::setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &_cfg.tcpKeepalive.intvlSec, sizeof(int));
      (void)::setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &_cfg.tcpKeepalive.cnt, sizeof(int));
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
    if (_srvTls.enabled && _srvTls.defaultMode == TlsMode::Server)
    {
      _sslSrv = ::SSL_CTX_new(TLS_server_method());
      if (!_sslSrv)
      {
        setLastFatal(IoResult::failure(TransportError::Config, "SSL_CTX_new(server) failed"));
        err(TransportError::Config, "SSL_CTX_new(server)");
        return false;
      }
      if (!_srvTls.ciphers.empty())
      {
        ::SSL_CTX_set_cipher_list(_sslSrv, _srvTls.ciphers.c_str());
      }
      if (!_srvTls.certFile.empty() && !_srvTls.keyFile.empty())
      {
        if (::SSL_CTX_use_certificate_file(_sslSrv, _srvTls.certFile.c_str(), SSL_FILETYPE_PEM) !=
              1 ||
            ::SSL_CTX_use_PrivateKey_file(_sslSrv, _srvTls.keyFile.c_str(), SSL_FILETYPE_PEM) != 1)
        {
          setLastFatal(IoResult::failure(TransportError::Config, "load server cert/key failed"));
          err(TransportError::Config, "load server cert/key");
          return false;
        }
      }
      if (_srvTls.verifyPeer)
      {
        ::SSL_CTX_set_verify(_sslSrv, SSL_VERIFY_PEER, nullptr);
        if (!_srvTls.caFile.empty())
        {
          if (::SSL_CTX_load_verify_locations(_sslSrv, _srvTls.caFile.c_str(), nullptr) != 1)
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
      if (!_srvTls.alpn.empty())
      {
        _alpnPref.clear();
        buildAlpnWire(_srvTls.alpn, _alpnPref);
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
    if (_cliTls.enabled && _cliTls.defaultMode == TlsMode::Client)
    {
      _sslCli = ::SSL_CTX_new(TLS_client_method());
      if (!_sslCli)
      {
        setLastFatal(IoResult::failure(TransportError::Config, "SSL_CTX_new(client) failed"));
        err(TransportError::Config, "SSL_CTX_new(client)");
        return false;
      }
      if (!_cliTls.ciphers.empty())
      {
        ::SSL_CTX_set_cipher_list(_sslCli, _cliTls.ciphers.c_str());
      }
      if (_cliTls.verifyPeer)
      {
        ::SSL_CTX_set_verify(_sslCli, SSL_VERIFY_PEER, nullptr);
        if (!_cliTls.caFile.empty())
        {
          if (::SSL_CTX_load_verify_locations(_sslCli, _cliTls.caFile.c_str(), nullptr) != 1)
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
      if (!_cliTls.alpn.empty())
      {
        std::vector<unsigned char> wire;
        buildAlpnWire(_cliTls.alpn, wire);
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

private:
  struct AtomicStats
  {
    std::atomic<std::uint64_t> accepted{0}, connected{0}, closed{0}, errors{0}, tlsHandshakes{0},
      tlsFailures{0}, bytesIn{0}, bytesOut{0}, epollWakeups{0}, commands{0}, gcRuns{0},
      gcClosedIdle{0}, gcClosedAged{0}, backpressureCloses{0};
    std::atomic<std::size_t> sessionsCurrent{0}, sessionsPeak{0};
  };

  Config _cfg{};
  TlsConfig _srvTls{}, _cliTls{};
  mutable AtomicStats _atomicStats{};

  std::atomic<bool> _running{false};
  int _epollFd{-1}, _eventFd{-1}, _timerFd{-1};
  std::thread _loop;

  std::mutex _cbMutex;
  Callbacks _cbs{};

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

  // Static SSL initialization coordination
  static std::once_flag _sslGlobalInitFlag;
  static std::atomic<int> debugInstanceCount;
  static void initSslGlobal();
};

// Static member definitions
std::once_flag SharedTransport::_sslGlobalInitFlag;
std::atomic<int> SharedTransport::debugInstanceCount{0};

void SharedTransport::initSslGlobal()
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