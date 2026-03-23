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
#include "iora/network/object_pool.hpp"
#include "iora/network/transport_types.hpp"
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
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

class SharedUdpTransport : public detail::EngineBase
{
public:
  /// \brief Returns the last error message from a failed operation.
  std::string lastErrorMessage() const
  {
    std::lock_guard<std::mutex> lock(_errorMutex);
    return _lastError;
  }

  struct Config
  {
    int epollMaxEvents = 128;
    std::size_t ioReadChunk = 64 * 1024;
    std::size_t maxWriteQueue = 256;
    std::chrono::seconds idleTimeout{600};
    std::chrono::seconds maxConnAge{std::chrono::seconds::zero()};
    std::chrono::seconds handshakeTimeout{30}; // parity
    std::chrono::seconds gcInterval{5};
    int listenBacklog = 0;
    std::size_t maxSessions = 0;
    bool useEdgeTriggered = true;
    bool closeOnBackpressure = true;
    int soRcvBuf = 0, soSndBuf = 0;
    // NEW: safety-net timers
    std::chrono::seconds connectTimeout{30};
    std::chrono::seconds writeStallTimeout{0};
  };
  struct TlsConfig
  {
    bool enabled = false;
    TlsMode defaultMode = TlsMode::None;
    std::string certFile, keyFile, caFile, ciphers, alpn;
    bool verifyPeer = false;
  };
  struct Callbacks
  {
    std::function<void(SessionId, const std::string &, const IoResult &)> onAccept;
    std::function<void(SessionId, const IoResult &)> onConnect;
    std::function<void(SessionId, const std::uint8_t *, std::size_t, const IoResult &)> onData;
    std::function<void(SessionId, const IoResult &)> onClosed;
    std::function<void(TransportError, const std::string &)> onError;
  };
  struct Stats
  {
    std::uint64_t accepted{0}, connected{0}, closed{0}, errors{0}, tlsHandshakes{0}, tlsFailures{0},
      bytesIn{0}, bytesOut{0}, epollWakeups{0}, commands{0}, gcRuns{0}, gcClosedIdle{0},
      gcClosedAged{0}, backpressureCloses{0};
    std::size_t sessionsCurrent{0}, sessionsPeak{0};
  };

  SharedUdpTransport(const Config &cfg, const TlsConfig &, const TlsConfig &)
      : _cfg(cfg), _sessionPool([]() { return std::make_unique<Session>(); },
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

  /// \brief Construct from TransportConfig (EngineBase-compatible config).
  explicit SharedUdpTransport(const TransportConfig &config)
    : SharedUdpTransport(configFromTransport(config), TlsConfig{}, TlsConfig{})
  {
  }

  ~SharedUdpTransport() noexcept
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

  SharedUdpTransport(const SharedUdpTransport &) = delete;
  SharedUdpTransport &operator=(const SharedUdpTransport &) = delete;

  void detachForTermination() override
  {
    _running.store(false, std::memory_order_release);
    if (_loop.joinable())
    {
      _loop.detach();
    }
  }

  void setCallbacks(const Callbacks &c)
  {
    std::lock_guard<std::mutex> g(_cb);
    _cbs = c;
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
    armGc(_cfg.gcInterval);
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

  ListenResult addListener(const std::string &bind, uint16_t port, TlsMode tls) override
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

  // New synchronous interface - validates immediately
  ListenerResult addListenerSync(const std::string &bind, uint16_t port, TlsMode tls)
  {
    if (tls != TlsMode::None)
    {
      return ListenerResult::failure(TransportError::Config, "UDP does not support TLS/DTLS");
    }

    // Immediate validation by attempting bind
    auto result = validateBind(bind, port);
    if (!result.result.ok)
    {
      return result;
    }

    // If validation passed, create listener normally
    ListenerCfg lc;
    lc.id = _nextListenerId++;
    lc.addr = bind;
    lc.port = port;
    enqueue(Cmd::addListener(lc));

    return ListenerResult::success(lc.id, bind + ":" + std::to_string(port));
  }
  ConnectResult connect(const std::string &host, uint16_t port, TlsMode tls) override
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
  ConnectResult connectViaListener(ListenerId lid, const std::string &host, uint16_t port) override
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
  void reconfigure(const Config &cfg) { enqueue(Cmd::reconf(cfg)); }
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
    return ts;
  }

  // ── EngineBase overrides ──────────────────────────────────────────────────

  TransportErrorInfo lastError() const override
  {
    auto msg = lastErrorMessage();
    if (msg.empty())
    {
      return TransportErrorInfo{TransportError::None, ""};
    }
    return TransportErrorInfo{TransportError::Unknown, msg};
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

  void setCallbacks(detail::EngineBase::Callbacks cbs) override
  {
    Callbacks legacy;

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
      auto closeCb = engineOnClose;
      legacy.onConnect = [connectCb = std::move(engineOnConnect), closeCb](SessionId sid,
                                                                           const IoResult &r)
      {
        if (r.ok)
        {
          connectCb(sid, TransportAddress{});
        }
        else if (closeCb)
        {
          closeCb(sid, TransportErrorInfo{r.code, r.message, r.sysErrno, r.tlsError});
        }
      };
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

    setCallbacks(legacy);
  }

  TransportAddress getListenerAddress(ListenerId) const override { return {}; }
  TransportAddress getLocalAddress(SessionId) const override { return {}; }
  TransportAddress getRemoteAddress(SessionId) const override { return {}; }
  bool setDscp(SessionId, std::uint8_t) override { return false; }

private:
  static Config configFromTransport(const TransportConfig &tc)
  {
    Config c;
    c.epollMaxEvents = tc.epollMaxEvents;
    c.ioReadChunk = tc.ioReadChunk;
    c.maxWriteQueue = tc.maxWriteQueue;
    c.idleTimeout = tc.idleTimeout;
    c.maxConnAge = tc.maxConnAge;
    c.handshakeTimeout = std::chrono::duration_cast<std::chrono::seconds>(tc.handshakeTimeout);
    c.gcInterval = tc.gcInterval;
    c.maxSessions = tc.maxSessions;
    c.listenBacklog = tc.listenBacklog;
    c.useEdgeTriggered = tc.useEdgeTriggered;
    c.closeOnBackpressure = tc.closeOnBackpressure;
    c.soRcvBuf = tc.soRcvBuf;
    c.soSndBuf = tc.soSndBuf;
    c.connectTimeout = std::chrono::duration_cast<std::chrono::seconds>(tc.connectTimeout);
    c.writeStallTimeout = std::chrono::duration_cast<std::chrono::seconds>(tc.writeStallTimeout);
    return c;
  }

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
  bool addEpoll(int fd, uint32_t ev)
  {
    epoll_event e{};
    e.events = ev;
    e.data.fd = fd;
    return ::epoll_ctl(_epollFd, EPOLL_CTL_ADD, fd, &e) == 0;
  }
  bool modEpoll(int fd, uint32_t ev)
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
    std::lock_guard<std::mutex> g(_cb);
    if (_cbs.onError)
      _cbs.onError(e, m);
  }

  enum class CmdType
  {
    Shutdown,
    AddListener,
    Connect,
    Via,
    Send,
    Close,
    Reconf
  };
  struct ListenerCfg
  {
    ListenerId id{};
    std::string addr;
    uint16_t port{};
  };
  struct ConnectReq
  {
    SessionId sid{};
    std::string host;
    uint16_t port{};
  };
  struct ViaReq
  {
    SessionId sid{};
    ListenerId lid{};
    std::string host;
    uint16_t port{};
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
    Config cfg;
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
    static Cmd reconf(const Config &cfg)
    {
      Cmd x;
      x.t = CmdType::Reconf;
      x.cfg = cfg;
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
    uint64_t one = 1;
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
    uint64_t one = 1;
    (void)::write(_eventFd, &one, sizeof(one));
    return true;
  }
  void drainEvt()
  {
    uint64_t n = 0;
    while (::read(_eventFd, &n, sizeof(n)) > 0)
    {
    }
  }
  void drainTim()
  {
    uint64_t n = 0;
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
    std::vector<epoll_event> evs((size_t)_cfg.epollMaxEvents);
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
        uint32_t events = evs[(size_t)i].events;
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
        auto it = _tags.find(fd);
        if (it == _tags.end())
          continue;
        Tag *t = it->second.get();
        if (t->isListener)
          onListener(t->lst, events);
        else
          onClient(t->sess, events);
      }
    }
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
      {
        std::lock_guard<std::mutex> g(_cb);
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
          try { c.listenerReady->set_value(ok); } catch (...) {}
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
      case CmdType::Reconf:
        _cfg = c.cfg;
        armGc(_cfg.gcInterval);
        break;
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
    if (_cfg.soRcvBuf > 0)
      ::setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, &_cfg.soRcvBuf, sizeof(int));
    if (_cfg.soSndBuf > 0)
      ::setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &_cfg.soSndBuf, sizeof(int));
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
    uint32_t ev = EPOLLIN;
    if (_cfg.useEdgeTriggered)
      ev |= EPOLLET;
    addEpoll(sfd, ev);
    auto tag = std::make_unique<Tag>();
    tag->isListener = true;
    tag->lst = lst.get();
    _tags.emplace(sfd, std::move(tag));
    _listeners.emplace(lst->id, std::move(lst));
    return true;
  }

  void onListener(Listener *lst, uint32_t events)
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
      buf.resize(_cfg.ioReadChunk);
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
          if (_cfg.maxSessions && _atomicStats.sessionsCurrent.load() >= _cfg.maxSessions)
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
          _sessions.emplace(sid, std::move(s));
          _peerIndex.emplace(k, sid);
          _atomicStats.accepted++;
          bumpSess();
          {
            std::lock_guard<std::mutex> g(_cb);
            if (_cbs.onAccept)
              _cbs.onAccept(sid, k, IoResult::success());
          }
        }
        else
        {
          sid = it->second;
        }
        auto &sp = _sessions[sid];
        sp->lastActivity = MonoClock::now();
        {
          std::lock_guard<std::mutex> g(_cb);
          if (_cbs.onData)
            _cbs.onData(sid, buf.data(), (size_t)n, IoResult::success());
        }
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
    uint32_t ev = EPOLLIN;
    if (_cfg.useEdgeTriggered)
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
      {
        std::lock_guard<std::mutex> g(_cb);
        if (_cbs.onConnect)
          _cbs.onConnect(cr.sid,
                         IoResult::failure(TransportError::Resolve,
                                           std::string("getaddrinfo: ") + gai_strerror(rc)));
      }
      error(TransportError::Resolve, "getaddrinfo failed");
      return false;
    }
    int sfd = -1;
    for (addrinfo *ai = res; ai; ai = ai->ai_next)
    {
      sfd = ::socket(ai->ai_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      if (sfd < 0)
        continue;
      if (_cfg.soRcvBuf > 0)
        ::setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, &_cfg.soRcvBuf, sizeof(int));
      if (_cfg.soSndBuf > 0)
        ::setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &_cfg.soSndBuf, sizeof(int));
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
      {
        std::lock_guard<std::mutex> g(_cb);
        if (_cbs.onConnect)
          _cbs.onConnect(cr.sid, IoResult::failure(TransportError::Connect, connectErr, connectErrno, 0));
      }
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
    uint32_t ev = EPOLLIN;
    if (_cfg.useEdgeTriggered)
      ev |= EPOLLET;
    addEpoll(sfd, ev);
    auto tag = std::make_unique<Tag>();
    tag->isListener = false;
    tag->sess = s.get();
    _tags.emplace(sfd, std::move(tag));
    _sessions.emplace(s->id, std::move(s));
    bumpSess();
    {
      std::lock_guard<std::mutex> g(_cb);
      if (_cbs.onConnect)
      {
        _atomicStats.connected++;
        _cbs.onConnect(cr.sid, IoResult::success());
      }
    }
    return true;
  }

  bool viaDo(const ViaReq &vr)
  {
    auto lit = _listeners.find(vr.lid);
    if (lit == _listeners.end())
    {
      {
        std::lock_guard<std::mutex> g(_cb);
        if (_cbs.onConnect)
          _cbs.onConnect(vr.sid, IoResult::failure(TransportError::Config, "listener not found"));
      }
      return false;
    }
    Listener *lst = lit->second.get();
    int af = sockAf(lst->fd);
    if (af != AF_INET && af != AF_INET6)
    {
      {
        std::lock_guard<std::mutex> g(_cb);
        if (_cbs.onConnect)
          _cbs.onConnect(
            vr.sid, IoResult::failure(TransportError::Config, "listener AF unknown/unsupported"));
      }
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
      {
        std::lock_guard<std::mutex> g(_cb);
        if (_cbs.onConnect)
          _cbs.onConnect(vr.sid,
                         IoResult::failure(TransportError::Resolve,
                                           std::string("getaddrinfo: ") + gai_strerror(rc)));
      }
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
      {
        std::lock_guard<std::mutex> g(_cb);
        if (_cbs.onConnect)
          _cbs.onConnect(vr.sid, IoResult::failure(TransportError::Config, m));
      }
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
    if (_cfg.maxSessions && _atomicStats.sessionsCurrent.load() >= _cfg.maxSessions)
    {
      {
        std::lock_guard<std::mutex> g(_cb);
        if (_cbs.onConnect)
          _cbs.onConnect(vr.sid, IoResult::failure(TransportError::Config, "session cap reached"));
      }
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
    _sessions.emplace(s->id, std::move(s));
    if (!peerExists)
    {
      _peerIndex.emplace(k, vr.sid);
    }
    bumpSess();
    {
      std::lock_guard<std::mutex> g(_cb);
      if (_cbs.onConnect)
        _cbs.onConnect(vr.sid, IoResult::success());
    }
    return true;
  }

  void onClient(Session *s, uint32_t events)
  {
    if (events & EPOLLIN)
    {
      for (;;)
      {
        std::vector<std::uint8_t> buf;
        buf.resize(_cfg.ioReadChunk);
        int n = ::recv(s->fd, buf.data(), (int)buf.size(), 0);
        if (n > 0)
        {
          _atomicStats.bytesIn += n;
          s->lastActivity = MonoClock::now();
          {
            std::lock_guard<std::mutex> g(_cb);
            if (_cbs.onData)
              _cbs.onData(s->id, buf.data(), (size_t)n, IoResult::success());
          }
          continue;
        }
        if (n == 0)
        {
          {
            std::lock_guard<std::mutex> g(_cb);
            if (_cbs.onData)
              _cbs.onData(s->id, nullptr, 0, IoResult::success());
          }
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
    uint32_t ev = EPOLLIN;
    if (_cfg.useEdgeTriggered)
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
        if (s->wq.size() > _cfg.maxWriteQueue)
        {
          _atomicStats.backpressureCloses++;
          if (_cfg.closeOnBackpressure)
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
      if (lst->wq.size() > _cfg.maxWriteQueue)
      {
        _atomicStats.backpressureCloses++;
        if (_cfg.closeOnBackpressure)
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
    {
      std::lock_guard<std::mutex> g(_cb);
      if (_cbs.onClosed)
      {
        IoResult r = (why == TransportError::None && m.empty())
                       ? IoResult::success()
                       : IoResult::failure(why, m, savedErrno, 0);
        _cbs.onClosed(s->id, r);
      }
    }
    _sessions.erase(s->id);
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
    const bool age = _cfg.maxConnAge.count() > 0;
    std::vector<SessionId> to;
    to.reserve(_sessions.size());
    for (auto &kv : _sessions)
    {
      Session *s = kv.second.get();
      if (s->closed)
        continue;
      if (_cfg.idleTimeout.count() > 0 && (now - s->lastActivity) > _cfg.idleTimeout)
      {
        to.push_back(s->id);
        _atomicStats.gcClosedIdle++;
        continue;
      }
      if (age && (now - s->created) > _cfg.maxConnAge)
      {
        to.push_back(s->id);
        _atomicStats.gcClosedAged++;
        continue;
      }
      // NEW: safety-net connect timeout (mostly moot for UDP client)
      if (_cfg.connectTimeout.count() > 0 && s->connectPending &&
          (now - s->connectStart) > _cfg.connectTimeout)
      {
        to.push_back(s->id);
        continue;
      }
      // NEW: safety-net write stall (applies to client-connected sessions)
      if (_cfg.writeStallTimeout.count() > 0 && !s->wq.empty() &&
          (now - s->lastWriteProgress) > _cfg.writeStallTimeout)
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

private:
  // Helper method for synchronous bind validation
  ListenerResult validateBind(const std::string &addr, uint16_t port)
  {
    int sfd = -1;
    sockaddr_storage ss{};
    socklen_t sl = 0;
    in6_addr t6{};

    try
    {
      if (::inet_pton(AF_INET6, addr.c_str(), &t6) == 1)
      {
        sfd = ::socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (sfd < 0)
        {
          return ListenerResult::failure(TransportError::Socket, "socket v6: " + lastErr(), errno);
        }
        auto *sa6 = reinterpret_cast<sockaddr_in6 *>(&ss);
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = ::htons(port);
        std::memcpy(&sa6->sin6_addr, &t6, sizeof(t6));
        sl = sizeof(sockaddr_in6);
      }
      else
      {
        sfd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (sfd < 0)
        {
          return ListenerResult::failure(TransportError::Socket, "socket v4: " + lastErr(), errno);
        }
        auto *sa4 = reinterpret_cast<sockaddr_in *>(&ss);
        sa4->sin_family = AF_INET;
        sa4->sin_port = ::htons(port);
        if (::inet_pton(AF_INET, addr.c_str(), &sa4->sin_addr) != 1)
        {
          ::close(sfd);
          return ListenerResult::failure(TransportError::Config, "invalid address: " + addr);
        }
        sl = sizeof(sockaddr_in);
      }

      // Try to bind to validate the address/port
      if (::bind(sfd, reinterpret_cast<sockaddr *>(&ss), sl) < 0)
      {
        int bindError = errno;
        ::close(sfd);
        return ListenerResult::failure(TransportError::Bind, "bind validation failed: " + lastErr(),
                                       bindError);
      }

      // Success - close the validation socket
      ::close(sfd);
      return ListenerResult::success(0, addr + ":" + std::to_string(port));
    }
    catch (...)
    {
      if (sfd >= 0)
        ::close(sfd);
      return ListenerResult::failure(TransportError::Unknown, "bind validation exception");
    }
  }

  struct AtomicStats
  {
    std::atomic<std::uint64_t> accepted{0}, connected{0}, closed{0}, errors{0}, tlsHandshakes{0},
      tlsFailures{0}, bytesIn{0}, bytesOut{0}, epollWakeups{0}, commands{0}, gcRuns{0},
      gcClosedIdle{0}, gcClosedAged{0}, backpressureCloses{0};
    std::atomic<std::size_t> sessionsCurrent{0}, sessionsPeak{0};
  };

  Config _cfg{};
  mutable AtomicStats _atomicStats{};
  std::atomic<bool> _running{false};
  int _epollFd{-1}, _eventFd{-1}, _timerFd{-1};
  std::thread _loop;
  std::mutex _cb;
  Callbacks _cbs{};
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