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

#include "iora/network/circuit_breaker.hpp"
#include "iora/network/connection_health.hpp"
#include "iora/network/detail/engine_base.hpp"
#include "iora/network/event_batch_processor.hpp"
#include "iora/network/object_pool.hpp"
#include "iora/network/transport_types.hpp"
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <csignal>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <shared_mutex>
#include <optional>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>

namespace iora
{
namespace network
{

class UdpEngine : public detail::EngineBase
{
public:
  /// \brief Construct from TransportConfig.
  explicit UdpEngine(const TransportConfig &config)
      : _config(config), _sessionPool([]() { return std::make_unique<Session>(); },
                                [](Session *s)
                                {
                                  if (s)
                                  {
                                    s->id = 0;
                                    s->role = Role::ServerPeer;
                                    s->fd = -1;
                                    s->owner = 0;
                                    s->pkey.clear();
                                    s->plen = 0;
                                    s->closed = false;
                                    s->connectPending = false;
                                    s->wantWrite = false;
                                    s->wq.clear();
                                  }
                                },
                                10) // Initial pool size
        ,
        _listenerPool([]() { return std::make_unique<Listener>(); },
                      [](Listener *l)
                      {
                        if (l)
                        {
                          l->id = 0;
                          l->fd = -1;
                          l->bind.clear();
                          l->wantWrite = false;
                          l->wq.clear();
                        }
                      },
                      2) // Initial pool size
  {
  }

  ~UdpEngine() noexcept
  {
    try
    {
      stop();
    }
    catch (...)
    {
      // ignore exceptions in destructor
    }
  }

  UdpEngine(const UdpEngine &) = delete;
  UdpEngine &operator=(const UdpEngine &) = delete;

  void detachForTermination() override
  {
    _running.store(false, std::memory_order_release);
    if (_loop.joinable())
    {
      _loop.detach();
    }
  }

  void setCallbacks(detail::EngineBase::Callbacks cbs) override
  {
    std::lock_guard<std::mutex> g(_cbMutex);
    _cbs = std::move(cbs);
  }

  StartResult start() override
  {
    bool exp = false;
    if (!_running.compare_exchange_strong(exp, true))
      return StartResult::err(TransportErrorInfo{TransportError::Config, "already running"});
    _epollFd = ::epoll_create1(EPOLL_CLOEXEC);
    if (_epollFd < 0)
    {
      error(TransportError::Config, "epoll_create1: " + lastErr());
      _running.store(false);
      return StartResult::err(TransportErrorInfo{TransportError::Config, "epoll_create1: " + lastErr()});
    }
    _eventFd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (_eventFd < 0)
    {
      error(TransportError::Config, "eventfd: " + lastErr());
      cleanupFail();
      return StartResult::err(TransportErrorInfo{TransportError::Config, "eventfd: " + lastErr()});
    }
    addEpoll(_eventFd, EPOLLIN);
    _timerFd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (_timerFd < 0)
    {
      error(TransportError::Config, "timerfd_create: " + lastErr());
      cleanupFail();
      return StartResult::err(TransportErrorInfo{TransportError::Config, "timerfd_create: " + lastErr()});
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
    _loop = std::thread([this]
    {
      sigset_t sigpipeSet;
      sigemptyset(&sigpipeSet);
      sigaddset(&sigpipeSet, SIGPIPE);
      pthread_sigmask(SIG_BLOCK, &sigpipeSet, nullptr);
      loop();
    });
    return StartResult::ok();
  }
  void stop() override
  {
    bool exp = true;
    if (!_running.compare_exchange_strong(exp, false))
      return;
    enqueue(Cmd::shutdown());
    if (_loop.joinable())
      _loop.join();
  }

  ListenResult addListener(const std::string &bind, std::uint16_t port, TlsMode tls) override
  {
    if (tls != TlsMode::None)
    {
      error(TransportError::Config, "UDP does not support TLS/DTLS");
      return ListenResult::err(
        TransportErrorInfo{TransportError::Config, "TLS/DTLS not supported on UDP"});
    }
    ListenerCfg lc;
    lc.id = _nextListenerId++;
    lc.addr = bind;
    lc.port = port;

    if (_running.load())
    {
      auto ready = std::make_shared<std::promise<bool>>();
      auto fut = ready->get_future();
      enqueue(Cmd::addListener(lc, std::move(ready)));
      bool ok = fut.get();
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
      enqueue(Cmd::addListener(lc));
    }
    return ListenResult::ok(lc.id);
  }

  ConnectResult connect(const std::string &host, std::uint16_t port, TlsMode tls) override
  {
    if (tls != TlsMode::None)
    {
      return ConnectResult::err(
        TransportErrorInfo{TransportError::Config, "TLS/DTLS not supported on UDP"});
    }
    SessionId sid = _nextSessionId++;
    ConnectReq cr;
    cr.sid = sid;
    cr.host = host;
    cr.port = port;
    enqueue(Cmd::connect(cr));
    return ConnectResult::ok(sid);
  }
  ConnectResult connectViaListener(ListenerId lid, const std::string &host, std::uint16_t port) override
  {
    SessionId sid = _nextSessionId++;
    ViaReq vr{sid, lid, host, port};
    enqueue(Cmd::via(vr));
    return ConnectResult::ok(sid);
  }
  bool send(SessionId sid, const void *p, std::size_t n) override
  {
    if (n == 0)
      return true;
    ByteBuffer b(n);
    std::memcpy(b.data(), p, n);
    SendReq sr;
    sr.sid = sid;
    sr.payload = std::move(b);
    return enqueue(Cmd::send(std::move(sr)));
  }
  bool close(SessionId sid) override { return enqueue(Cmd::close(sid)); }
  bool isRunning() const override { return _running.load(std::memory_order_acquire); }
  std::thread::id getIoThreadId() const override { return _loop.get_id(); }
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

  // ── EngineBase overrides ──────────────────────────────────────────────────

  TransportErrorInfo lastError() const override
  {
    std::lock_guard<std::mutex> lock(_errorMutex);
    if (_lastError.empty())
    {
      return TransportErrorInfo{TransportError::None, ""};
    }
    return TransportErrorInfo{TransportError::Unknown, _lastError};
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
    if (it == _sessions.end())
    {
      return {};
    }
    const auto *s = it->second.get();
    int fd;
    if (s->role == Role::ServerPeer)
    {
      // ServerPeer sessions share the listener's fd
      auto lit = _listeners.find(s->owner);
      if (lit == _listeners.end() || lit->second->fd < 0)
      {
        return {};
      }
      fd = lit->second->fd;
    }
    else
    {
      fd = s->fd;
      if (fd < 0)
      {
        return {};
      }
    }
    sockaddr_storage ss{};
    socklen_t sl = sizeof(ss);
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&ss), &sl) != 0)
    {
      return {};
    }
    return addressFromSockaddr(ss);
  }

  TransportAddress getRemoteAddress(SessionId sid) const override
  {
    std::shared_lock<std::shared_mutex> rl(_sessionRwMutex);
    auto it = _sessions.find(sid);
    if (it == _sessions.end())
    {
      return {};
    }
    const auto *s = it->second.get();
    if (s->role == Role::ClientConnected)
    {
      // Connected UDP socket — use getpeername
      if (s->fd < 0)
      {
        return {};
      }
      sockaddr_storage ss{};
      socklen_t sl = sizeof(ss);
      if (::getpeername(s->fd, reinterpret_cast<sockaddr *>(&ss), &sl) != 0)
      {
        return {};
      }
      return addressFromSockaddr(ss);
    }
    // ServerPeer — use stored peer address
    if (s->plen == 0)
    {
      return {};
    }
    return addressFromSockaddr(s->peer);
  }

  bool setDscp(SessionId sid, std::uint8_t dscp) override
  {
    std::shared_lock<std::shared_mutex> rl(_sessionRwMutex);
    auto it = _sessions.find(sid);
    if (it == _sessions.end())
    {
      return false;
    }
    const auto *s = it->second.get();
    int fd;
    if (s->role == Role::ServerPeer)
    {
      auto lit = _listeners.find(s->owner);
      if (lit == _listeners.end() || lit->second->fd < 0)
      {
        return false;
      }
      fd = lit->second->fd;
    }
    else
    {
      fd = s->fd;
      if (fd < 0)
      {
        return false;
      }
    }
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

private:
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
  void armGc(std::chrono::seconds s)
  {
    itimerspec its{};
    its.it_interval.tv_sec = s.count();
    its.it_value.tv_sec = s.count();
    ::timerfd_settime(_timerFd, 0, &its, nullptr);
  }
  static std::string key(const sockaddr_storage &ss)
  {
    char h[NI_MAXHOST]{}, sv[NI_MAXSERV]{};
    socklen_t sl = (ss.ss_family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    if (getnameinfo(reinterpret_cast<const sockaddr *>(&ss), sl, h, sizeof(h), sv, sizeof(sv),
                    NI_NUMERICHOST | NI_NUMERICSERV) == 0)
    {
      std::string o(h);
      o.push_back(':');
      o.append(sv);
      return o;
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
  int sockAf(int fd)
  {
    sockaddr_storage ss{};
    socklen_t sl = sizeof(ss);
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&ss), &sl) == 0)
      return ss.ss_family;
    return AF_UNSPEC;
  }
  void error(TransportError e, const std::string &m)
  {
    _atomicStats.errors++;
    decltype(_cbs.onError) cb;
    { std::lock_guard<std::mutex> g(_cbMutex); cb = _cbs.onError; }
    if (cb)
      cb(e, m);
  }

  enum class CmdType
  {
    Shutdown,
    AddListener,
    Connect,
    Via,
    Send,
    Close
  };
  struct ListenerCfg
  {
    ListenerId id{};
    std::string addr;
    std::uint16_t port{};
  };
  struct ConnectReq
  {
    SessionId sid{};
    std::string host;
    std::uint16_t port{};
  };
  struct ViaReq
  {
    SessionId sid{};
    ListenerId lid{};
    std::string host;
    std::uint16_t port{};
  };
  struct SendReq
  {
    SessionId sid{};
    ByteBuffer payload;
  };
  struct Cmd
  {
    CmdType t;
    ListenerCfg l;
    ConnectReq c;
    ViaReq v;
    SendReq s;
    SessionId closeSid{};
    std::shared_ptr<std::promise<bool>> listenerReady;
    static Cmd shutdown()
    {
      Cmd x;
      x.t = CmdType::Shutdown;
      return x;
    }
    static Cmd addListener(const ListenerCfg &lc,
                           std::shared_ptr<std::promise<bool>> ready = nullptr)
    {
      Cmd x;
      x.t = CmdType::AddListener;
      x.l = lc;
      x.listenerReady = std::move(ready);
      return x;
    }
    static Cmd connect(const ConnectReq &cr)
    {
      Cmd x;
      x.t = CmdType::Connect;
      x.c = cr;
      return x;
    }
    static Cmd via(const ViaReq &v)
    {
      Cmd x;
      x.t = CmdType::Via;
      x.v = v;
      return x;
    }
    static Cmd send(SendReq &&sr)
    {
      Cmd x;
      x.t = CmdType::Send;
      x.s = std::move(sr);
      return x;
    }
    static Cmd close(SessionId sid)
    {
      Cmd x;
      x.t = CmdType::Close;
      x.closeSid = sid;
      return x;
    }
  };
  bool enqueue(const Cmd &c)
  {
    {
      std::lock_guard<std::mutex> g(_qmx);
      _q.push_back(c);
      _atomicStats.commands++;
    }
    std::uint64_t one = 1;
    (void)::write(_eventFd, &one, sizeof(one));
    return true;
  }
  bool enqueue(Cmd &&c)
  {
    {
      std::lock_guard<std::mutex> g(_qmx);
      _q.push_back(std::move(c));
      _atomicStats.commands++;
    }
    std::uint64_t one = 1;
    (void)::write(_eventFd, &one, sizeof(one));
    return true;
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

  struct OutDg
  {
    sockaddr_storage to{};
    socklen_t toLen{0};
    ByteBuffer payload;
  };
  struct Listener
  {
    ListenerId id{};
    int fd{-1};
    std::string bind;
    std::deque<OutDg> wq;
    bool wantWrite{false};
  };
  struct Session
  {
    SessionId id{};
    Role role{Role::ServerPeer};
    int fd{-1};
    ListenerId owner{};
    sockaddr_storage peer{};
    socklen_t plen{0};
    std::string pkey;
    std::deque<ByteBuffer> wq;
    bool wantWrite{false};
    bool closed{false};
    MonoTime created{}, lastActivity{};
    // NEW: safety-net tracking
    bool connectPending{false};
    MonoTime connectStart{};
    MonoTime lastWriteProgress{};
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
    auto it = _tags.find(fd);
    if (it == _tags.end())
      return;
    Tag *t = it->second.get();
    if (t->isListener)
      onListener(t->lst, events);
    else
      onClient(t->sess, events);
  }

  void shutdownDrain()
  {
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
      if (s->role == Role::ClientConnected)
      {
        delEpoll(s->fd);
        ::close(s->fd);
        _tags.erase(s->fd);
      }
      else
      {
        _peerIndex.erase(s->pkey);
      }
      _atomicStats.closed++;
      _atomicStats.sessionsCurrent--;
      decltype(_cbs.onClose) closeCb;
      { std::lock_guard<std::mutex> g(_cbMutex); closeCb = _cbs.onClose; }
      if (closeCb)
      {
        closeCb(s->id, TransportErrorInfo{TransportError::Unknown, "shutdown"});
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
  }

  void loopUnbatched()
  {
    std::vector<epoll_event> evs((size_t)_config.epollMaxEvents);
    while (_running.load())
    {
      int n = ::epoll_wait(_epollFd, evs.data(), (int)evs.size(), -1);
      if (n < 0)
      {
        if (errno == EINTR)
          continue;
        error(TransportError::Unknown, "epoll_wait: " + lastErr());
        continue;
      }
      _atomicStats.epollWakeups++;
      for (int i = 0; i < n; ++i)
      {
        int fd = evs[(size_t)i].data.fd;
        std::uint32_t events = evs[(size_t)i].events;
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
    std::deque<Cmd> l;
    {
      std::lock_guard<std::mutex> g(_qmx);
      l.swap(_q);
    }
    for (auto &c : l)
    {
      try
      {
        switch (c.t)
        {
        case CmdType::Shutdown:
          _running.store(false);
          break;
        case CmdType::AddListener:
        {
          bool ok = addListenerDo(c.l);
          if (c.listenerReady)
          {
            c.listenerReady->set_value(ok);
          }
          break;
        }
        case CmdType::Connect:
          connectDo(c.c);
          break;
        case CmdType::Via:
          viaDo(c.v);
          break;
        case CmdType::Send:
          sendDo(std::move(c.s));
          break;
        case CmdType::Close:
        {
          auto it = _sessions.find(c.closeSid);
          if (it != _sessions.end())
            closeNow(it->second.get(), TransportError::Unknown, "closed by app", 0);
        }
        break;
        }
      }
      catch (const std::exception &ex)
      {
        if (c.listenerReady)
        {
          try { c.listenerReady->set_value(false); } catch (...) {}
        }
        decltype(_cbs.onError) cb;
        { std::lock_guard<std::mutex> g(_cbMutex); cb = _cbs.onError; }
        if (cb)
        {
          cb(TransportError::Unknown, std::string("cmd dispatch: ") + ex.what());
        }
      }
    }
  }

  bool addListenerDo(const ListenerCfg &lc)
  {
    int sfd = -1;
    sockaddr_storage ss{};
    socklen_t sl = 0;
    in6_addr t6{};
    if (::inet_pton(AF_INET6, lc.addr.c_str(), &t6) == 1)
    {
      sfd = ::socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      if (sfd < 0)
      {
        error(TransportError::Socket, "socket v6: " + lastErr());
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
        error(TransportError::Bind, "inet_pton failed");
        return false;
      }
      sfd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      if (sfd < 0)
      {
        error(TransportError::Socket, "socket v4: " + lastErr());
        return false;
      }
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
      error(TransportError::Bind, "bind: " + lastErr());
      ::close(sfd);
      return false;
    }
    auto lst = std::make_unique<Listener>();
    lst->id = lc.id;
    lst->fd = sfd;
    lst->bind = lc.addr + ":" + std::to_string(lc.port);
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
    _tags.emplace(sfd, std::move(tag));
    return true;
  }

  void onListener(Listener *lst, std::uint32_t events)
  {
    if (events & EPOLLIN)
      readFromListener(lst);
    if (events & EPOLLOUT)
      flushListener(lst);
  }

  void readFromListener(Listener *lst)
  {
    for (;;)
    {
      std::vector<std::uint8_t> buf;
      buf.resize(_config.ioReadChunk);
      sockaddr_storage from{};
      socklen_t fl = sizeof(from);
      int n = ::recvfrom(lst->fd, buf.data(), (int)buf.size(), 0,
                         reinterpret_cast<sockaddr *>(&from), &fl);
      if (n > 0)
      {
        _atomicStats.bytesIn += n;
        std::string k = key(from);
        SessionId sid = 0;
        auto it = _peerIndex.find(k);
        if (it == _peerIndex.end())
        {
          if (_config.maxSessions && _atomicStats.sessionsCurrent.load() >= _config.maxSessions)
            continue;
          sid = _nextSessionId++;
          auto s = std::make_unique<Session>();
          s->id = sid;
          s->role = Role::ServerPeer;
          s->fd = lst->fd;
          s->owner = lst->id;
          std::memcpy(&s->peer, &from, fl);
          s->plen = fl;
          s->pkey = k;
          s->created = MonoClock::now();
          s->lastActivity = s->created;
          s->lastWriteProgress = s->created;
          {
            std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
            _sessions.emplace(sid, std::move(s));
          }
          _peerIndex.emplace(k, sid);
          _atomicStats.accepted++;
          bumpSess();
          decltype(_cbs.onAccept) acceptCb;
          { std::lock_guard<std::mutex> g(_cbMutex); acceptCb = _cbs.onAccept; }
          if (acceptCb)
            acceptCb(sid, addressFromSockaddr(from));
        }
        else
        {
          sid = it->second;
        }
        auto &sp = _sessions[sid];
        sp->lastActivity = MonoClock::now();
        decltype(_cbs.onData) dataCb;
        { std::lock_guard<std::mutex> g(_cbMutex); dataCb = _cbs.onData; }
        if (dataCb)
          dataCb(sid, iora::core::BufferView{buf.data(), static_cast<std::size_t>(n)},
                 std::chrono::steady_clock::now());
        continue;
      }
      if (n < 0)
      {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          break;
        error(TransportError::Socket, "recvfrom: " + lastErr());
        break;
      }
      // n==0 acceptable
    }
  }

  void flushListener(Listener *lst)
  {
    while (!lst->wq.empty())
    {
      auto &d = lst->wq.front();
      int n = ::sendto(lst->fd, d.payload.data(), (int)d.payload.size(), MSG_NOSIGNAL,
                       reinterpret_cast<sockaddr *>(&d.to), d.toLen);
      if (n >= 0)
      {
        _atomicStats.bytesOut += n;
        lst->wq.pop_front();
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        lst->wantWrite = true;
        updateListener(lst);
        break;
      }
      error(TransportError::Socket, "sendto: " + lastErr());
      lst->wq.pop_front();
    }
    if (lst->wq.empty())
    {
      lst->wantWrite = false;
      updateListener(lst);
    }
  }

  void updateListener(Listener *lst)
  {
    std::uint32_t ev = EPOLLIN;
    if (_config.useEdgeTriggered)
      ev |= EPOLLET;
    if (lst->wantWrite && !lst->wq.empty())
      ev |= EPOLLOUT;
    modEpoll(lst->fd, ev);
  }

  bool connectDo(const ConnectReq &cr)
  {
    addrinfo *res = nullptr;
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    std::string ps = std::to_string(cr.port);
    int rc = ::getaddrinfo(cr.host.c_str(), ps.c_str(), &hints, &res);
    if (rc != 0 || !res)
    {
      decltype(_cbs.onClose) closeCb;
      { std::lock_guard<std::mutex> g(_cbMutex); closeCb = _cbs.onClose; }
      if (closeCb)
        closeCb(cr.sid,
                TransportErrorInfo{TransportError::Resolve,
                                   std::string("getaddrinfo: ") + gai_strerror(rc)});
      error(TransportError::Resolve, "getaddrinfo failed");
      return false;
    }
    int sfd = -1;
    for (addrinfo *ai = res; ai; ai = ai->ai_next)
    {
      sfd = ::socket(ai->ai_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      if (sfd < 0)
        continue;
      if (_config.soRcvBuf > 0)
        ::setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, &_config.soRcvBuf, sizeof(int));
      if (_config.soSndBuf > 0)
        ::setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &_config.soSndBuf, sizeof(int));
      if (::connect(sfd, ai->ai_addr, ai->ai_addrlen) == 0)
      {
        break;
      }
      ::close(sfd);
      sfd = -1;
    }
    // Save errno before freeaddrinfo may clobber it
    int connectErrno = errno;
    std::string connectErr = lastErr();
    ::freeaddrinfo(res);
    if (sfd < 0)
    {
      decltype(_cbs.onClose) closeCb;
      { std::lock_guard<std::mutex> g(_cbMutex); closeCb = _cbs.onClose; }
      if (closeCb)
        closeCb(cr.sid,
                TransportErrorInfo{TransportError::Connect, connectErr, connectErrno});
      error(TransportError::Connect, "UDP connect: " + connectErr);
      return false;
    }
    auto s = std::make_unique<Session>();
    s->id = cr.sid;
    s->role = Role::ClientConnected;
    s->fd = sfd;
    s->created = MonoClock::now();
    s->lastActivity = s->created;
    s->lastWriteProgress = s->created;
    s->connectPending = false; // UDP connect immediate
    std::uint32_t ev = EPOLLIN;
    if (_config.useEdgeTriggered)
      ev |= EPOLLET;
    addEpoll(sfd, ev);
    Session *sPtr = s.get();
    {
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      _sessions.emplace(s->id, std::move(s));
    }
    auto tag = std::make_unique<Tag>();
    tag->isListener = false;
    tag->sess = sPtr;
    _tags.emplace(sfd, std::move(tag));
    bumpSess();
    {
      _atomicStats.connected++;
      decltype(_cbs.onConnect) connectCb;
      { std::lock_guard<std::mutex> g(_cbMutex); connectCb = _cbs.onConnect; }
      if (connectCb)
      {
        sockaddr_storage peerSs{};
        socklen_t peerSl = sizeof(peerSs);
        TransportAddress peerAddr;
        if (::getpeername(sfd, reinterpret_cast<sockaddr *>(&peerSs), &peerSl) == 0)
        {
          peerAddr = addressFromSockaddr(peerSs);
        }
        connectCb(cr.sid, peerAddr);
      }
    }
    return true;
  }

  bool viaDo(const ViaReq &vr)
  {
    auto lit = _listeners.find(vr.lid);
    if (lit == _listeners.end())
    {
      decltype(_cbs.onClose) closeCb;
      { std::lock_guard<std::mutex> g(_cbMutex); closeCb = _cbs.onClose; }
      if (closeCb)
        closeCb(vr.sid, TransportErrorInfo{TransportError::Config, "listener not found"});
      return false;
    }
    Listener *lst = lit->second.get();
    int af = sockAf(lst->fd);
    if (af != AF_INET && af != AF_INET6)
    {
      decltype(_cbs.onClose) closeCb;
      { std::lock_guard<std::mutex> g(_cbMutex); closeCb = _cbs.onClose; }
      if (closeCb)
        closeCb(
          vr.sid, TransportErrorInfo{TransportError::Config, "listener AF unknown/unsupported"});
      return false;
    }
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    addrinfo *res = nullptr;
    std::string ps = std::to_string(vr.port);
    int rc = ::getaddrinfo(vr.host.c_str(), ps.c_str(), &hints, &res);
    if (rc != 0 || !res)
    {
      decltype(_cbs.onClose) closeCb;
      { std::lock_guard<std::mutex> g(_cbMutex); closeCb = _cbs.onClose; }
      if (closeCb)
        closeCb(vr.sid,
                TransportErrorInfo{TransportError::Resolve,
                                   std::string("getaddrinfo: ") + gai_strerror(rc)});
      error(TransportError::Resolve, "getaddrinfo failed");
      return false;
    }
    const addrinfo *chosen = nullptr;
    for (const addrinfo *ai = res; ai; ai = ai->ai_next)
    {
      if (ai->ai_family == af && ai->ai_socktype == SOCK_DGRAM)
      {
        chosen = ai;
        break;
      }
    }
    if (!chosen)
    {
      ::freeaddrinfo(res);
      std::string m = (af == AF_INET) ? "AF mismatch: listener IPv4, remote IPv6 only"
                                      : "AF mismatch: listener IPv6, remote IPv4 only";
      decltype(_cbs.onClose) closeCb;
      { std::lock_guard<std::mutex> g(_cbMutex); closeCb = _cbs.onClose; }
      if (closeCb)
        closeCb(vr.sid, TransportErrorInfo{TransportError::Config, m});
      return false;
    }
    sockaddr_storage to{};
    socklen_t tl = 0;
    if (chosen->ai_family == AF_INET6)
    {
      std::memcpy(&to, chosen->ai_addr, sizeof(sockaddr_in6));
      tl = sizeof(sockaddr_in6);
    }
    else
    {
      std::memcpy(&to, chosen->ai_addr, sizeof(sockaddr_in));
      tl = sizeof(sockaddr_in);
    }
    ::freeaddrinfo(res);
    std::string k = key(to);
    auto pit = _peerIndex.find(k);
    bool peerExists = (pit != _peerIndex.end());
    // Note: Even if peer exists, we must create a Session for the new SessionId.
    // This enables self-loopback (same address as listener) and multiple logical
    // connections to the same remote peer. The _peerIndex maps peer address to
    // ONE SessionId for incoming data dispatch; applications must demultiplex.
    if (_config.maxSessions && _atomicStats.sessionsCurrent.load() >= _config.maxSessions)
    {
      decltype(_cbs.onClose) closeCb;
      { std::lock_guard<std::mutex> g(_cbMutex); closeCb = _cbs.onClose; }
      if (closeCb)
        closeCb(vr.sid, TransportErrorInfo{TransportError::Config, "session cap reached"});
      return false;
    }
    auto s = std::make_unique<Session>();
    s->id = vr.sid;
    s->role = Role::ServerPeer;
    s->fd = lst->fd;
    s->owner = lst->id;
    std::memcpy(&s->peer, &to, tl);
    s->plen = tl;
    s->pkey = k;
    s->created = MonoClock::now();
    s->lastActivity = s->created;
    s->lastWriteProgress = s->created;
    s->connectPending = false;
    {
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      _sessions.emplace(s->id, std::move(s));
    }
    if (!peerExists)
    {
      _peerIndex.emplace(k, vr.sid);
    }
    bumpSess();
    decltype(_cbs.onConnect) connectCb;
    { std::lock_guard<std::mutex> g(_cbMutex); connectCb = _cbs.onConnect; }
    if (connectCb)
      connectCb(vr.sid, addressFromSockaddr(to));
    return true;
  }

  void onClient(Session *s, std::uint32_t events)
  {
    if (events & EPOLLIN)
    {
      for (;;)
      {
        std::vector<std::uint8_t> buf;
        buf.resize(_config.ioReadChunk);
        int n = ::recv(s->fd, buf.data(), (int)buf.size(), 0);
        if (n > 0)
        {
          _atomicStats.bytesIn += n;
          s->lastActivity = MonoClock::now();
          decltype(_cbs.onData) dataCb;
          { std::lock_guard<std::mutex> g(_cbMutex); dataCb = _cbs.onData; }
          if (dataCb)
            dataCb(s->id, iora::core::BufferView{buf.data(), static_cast<std::size_t>(n)},
                   std::chrono::steady_clock::now());
          continue;
        }
        if (n == 0)
        {
          decltype(_cbs.onData) dataCb;
          { std::lock_guard<std::mutex> g(_cbMutex); dataCb = _cbs.onData; }
          if (dataCb)
            dataCb(s->id, iora::core::BufferView{nullptr, 0},
                   std::chrono::steady_clock::now());
          break;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          break;
        closeNow(s, TransportError::Socket, lastErr(), 0);
        return;
      }
    }
    if (events & EPOLLOUT)
      writeClient(s);
  }

  void writeClient(Session *s)
  {
    while (!s->wq.empty())
    {
      ByteBuffer &d = s->wq.front();
      int n = ::send(s->fd, d.data(), (int)d.size(), MSG_NOSIGNAL);
      if (n >= 0)
      {
        _atomicStats.bytesOut += n;
        s->lastWriteProgress = MonoClock::now();
        s->wq.pop_front();
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        s->wantWrite = true;
        updateClient(s);
        break;
      }
      closeNow(s, TransportError::Socket, lastErr(), 0);
      return;
    }
    if (s->wq.empty())
    {
      s->wantWrite = false;
      updateClient(s);
    }
  }
  void updateClient(Session *s)
  {
    std::uint32_t ev = EPOLLIN;
    if (_config.useEdgeTriggered)
      ev |= EPOLLET;
    if (s->wantWrite && !s->wq.empty())
      ev |= EPOLLOUT;
    modEpoll(s->fd, ev);
  }

  void sendDo(SendReq &&sr)
  {
    auto it = _sessions.find(sr.sid);
    if (it == _sessions.end())
      return;
    Session *s = it->second.get();
    if (s->closed)
      return;
    if (s->role == Role::ClientConnected)
    {
      int n = ::send(s->fd, sr.payload.data(), (int)sr.payload.size(), MSG_NOSIGNAL);
      if (n >= 0)
      {
        _atomicStats.bytesOut += n;
        s->lastActivity = MonoClock::now();
        s->lastWriteProgress = MonoClock::now();
        return;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        s->wq.emplace_back(std::move(sr.payload));
        if (s->wq.size() > _config.maxWriteQueue)
        {
          _atomicStats.backpressureCloses++;
          if (_config.closeOnBackpressure)
          {
            closeNow(s, TransportError::WriteBackpressure, "client write queue overflow", 0);
            return;
          }
          else
          {
            s->wq.pop_front();
          }
        }
        s->wantWrite = true;
        updateClient(s);
        return;
      }
      closeNow(s, TransportError::Socket, lastErr(), 0);
      return;
    }
    auto lit = _listeners.find(s->owner);
    if (lit == _listeners.end())
    {
      closeNow(s, TransportError::Unknown, "listener gone", 0);
      return;
    }
    Listener *lst = lit->second.get();
    int n = ::sendto(lst->fd, sr.payload.data(), (int)sr.payload.size(), MSG_NOSIGNAL,
                     reinterpret_cast<sockaddr *>(&s->peer), s->plen);
    if (n >= 0)
    {
      _atomicStats.bytesOut += n;
      s->lastActivity = MonoClock::now();
      s->lastWriteProgress = MonoClock::now();
      return;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK)
    {
      OutDg d{};
      std::memcpy(&d.to, &s->peer, s->plen);
      d.toLen = s->plen;
      d.payload = std::move(sr.payload);
      lst->wq.emplace_back(std::move(d));
      if (lst->wq.size() > _config.maxWriteQueue)
      {
        _atomicStats.backpressureCloses++;
        if (_config.closeOnBackpressure)
        {
          closeNow(s, TransportError::WriteBackpressure, "listener write queue overflow", 0);
        }
        else
        {
          lst->wq.pop_front();
        }
      }
      lst->wantWrite = true;
      updateListener(lst);
      return;
    }
    closeNow(s, TransportError::Socket, lastErr(), 0);
  }

  void closeNow(Session *s, TransportError why, const std::string &m, int)
  {
    if (!s || s->closed)
      return;
    // Save errno before system calls clobber it
    int savedErrno = errno;
    s->closed = true;

    // Save fields before erasing session from map
    SessionId sid = s->id;
    int fd = s->fd;
    Role role = s->role;
    std::string pkey = s->pkey;

    if (role == Role::ClientConnected)
    {
      delEpoll(fd);
      ::close(fd);
      _tags.erase(fd);
    }
    else
    {
      _peerIndex.erase(pkey);
    }

    _atomicStats.closed++;
    _atomicStats.sessionsCurrent--;

    // Remove from session map under write lock
    {
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      _sessions.erase(sid);
    }
    // s is now dangling — use only saved locals below

    decltype(_cbs.onClose) closeCb;
    { std::lock_guard<std::mutex> g(_cbMutex); closeCb = _cbs.onClose; }
    if (closeCb)
    {
      closeCb(sid, TransportErrorInfo{why, m, savedErrno});
    }
  }
  void closeListenerNow(Listener *lst)
  {
    delEpoll(lst->fd);
    ::close(lst->fd);
    _tags.erase(lst->fd);
  }

  void runGc()
  {
    _atomicStats.gcRuns++;
    const auto now = MonoClock::now();
    const bool age = _config.maxConnAge.count() > 0;
    std::vector<SessionId> to;
    to.reserve(_sessions.size());
    for (auto &kv : _sessions)
    {
      Session *s = kv.second.get();
      if (s->closed)
        continue;
      if (_config.idleTimeout.count() > 0 && (now - s->lastActivity) > _config.idleTimeout)
      {
        to.push_back(s->id);
        _atomicStats.gcClosedIdle++;
        continue;
      }
      if (age && (now - s->created) > _config.maxConnAge)
      {
        to.push_back(s->id);
        _atomicStats.gcClosedAged++;
        continue;
      }
      // NEW: safety-net connect timeout (mostly moot for UDP client)
      if (_config.connectTimeout.count() > 0 && s->connectPending &&
          (now - s->connectStart) >
            std::chrono::duration_cast<std::chrono::seconds>(_config.connectTimeout))
      {
        to.push_back(s->id);
        continue;
      }
      // NEW: safety-net write stall (applies to client-connected sessions)
      if (_config.writeStallTimeout.count() > 0 && !s->wq.empty() &&
          (now - s->lastWriteProgress) >
            std::chrono::duration_cast<std::chrono::seconds>(_config.writeStallTimeout))
      {
        to.push_back(s->id);
        continue;
      }
    }
    for (auto sid : to)
    {
      auto it = _sessions.find(sid);
      if (it != _sessions.end())
        closeNow(it->second.get(), TransportError::GCClosed, "GC safety-net timeout", 0);
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

  void cleanupFail()
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
    _running.store(false);
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
  std::mutex _qmx;
  std::deque<Cmd> _q;
  std::unordered_map<ListenerId, std::unique_ptr<Listener>> _listeners;
  std::unordered_map<SessionId, std::unique_ptr<Session>> _sessions;
  std::unordered_map<std::string, SessionId> _peerIndex;
  std::unordered_map<int, std::unique_ptr<Tag>> _tags;
  std::atomic<SessionId> _nextSessionId{1};
  std::atomic<ListenerId> _nextListenerId{1};

  // New improvements
  ObjectPool<Session> _sessionPool;
  ObjectPool<Listener> _listenerPool;
  HealthMonitor _healthMonitor;
  CircuitBreakerManager _circuitBreakers;

  // Batch processor (created when batching is enabled)
  std::unique_ptr<EventBatchProcessor> _batchProcessor;

  mutable std::mutex _errorMutex;
  std::string _lastError;

  void setLastError(const std::string &err)
  {
    std::lock_guard<std::mutex> lock(_errorMutex);
    _lastError = err;
  }
};

} // namespace network
} // namespace iora