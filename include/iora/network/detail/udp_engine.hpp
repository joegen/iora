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

#include "iora/core/errno_utils.hpp"
#include "iora/network/detail/engine_base.hpp"
#include "iora/network/detail/fd_closer.hpp"
#include "iora/network/name_resolver.hpp"
#include "iora/network/event_batch_processor.hpp"
#include "iora/network/sockaddr_utils.hpp"
#include "iora/network/transport_types.hpp"
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cassert>
#include <cstdio>
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
#include <unordered_set>
#include <utility>

namespace iora
{
namespace network
{

class UdpEngine : public detail::EngineBase
{
public:
  /// \brief Construct from TransportConfig.
  explicit UdpEngine(const TransportConfig &config) : _config(config)
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

  /// \brief Deferred self-destruction; see EngineBase. Called ONLY on the I/O
  /// thread, before detachForTermination(); same-thread write/read, no lock.
  void scheduleSelfDestruct(std::function<void()> deleter) override
  {
    assert(std::this_thread::get_id() == _loop.get_id() &&
           "scheduleSelfDestruct must be called on the I/O thread");
    _selfDestruct = std::move(deleter);
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
    // Reopen the command queue (a prior stop()->shutdownDrain() set this true to
    // reject post-teardown enqueues — DD-5). A fresh _eventFd is created below.
    // LIFECYCLE CONTRACT: start()/stop() are not concurrent with each other or
    // with enqueue() (the _running CAS gates the lifecycle; callers do not
    // enqueue during start/restart), so the brief interval between this reset
    // and the _eventFd recreation — queue open but _eventFd still -1 — is not
    // reachable by a concurrent enqueuer.
    {
      std::lock_guard<std::mutex> g(_qmx);
      _qClosed = false;
    }

    // RE-CREATE the post gate BEFORE _eventFd/_epollFd/_timerFd/_loop, co-located
    // with the _qClosed reset. UDP has its OWN start() (task-4.4) — the TCP
    // start-guard does NOT cover it. Without this, every post-restart UDP
    // named-host resolve would drop against a permanently-closed gate (spurious
    // onClose(Resolve)). See EnginePostGate.
    _postGuard = std::make_shared<detail::EnginePostGate>();
    _postGuard->engine = this;

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
      // Publish this thread as the I/O thread FIRST, before any dispatch.
      stampIoThread();
      // try/catch so the deferred self-destruct deleter runs on EVERY loop()
      // exit; moved to a local and invoked LAST (delete-this-at-thread-end).
      try
      {
        loop();
      }
      catch (...)
      {
        std::fprintf(stderr, "WARNING: UdpEngine I/O loop terminated by exception.\n");
      }
      // Clear the I/O-thread stamp AFTER the loop unwinds, BEFORE self-destruct.
      clearIoThread();
      std::function<void()> sd;
      sd.swap(_selfDestruct);
      if (sd)
      {
        sd();
      }
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
      // Pass a COPY of the promise into the command (do NOT move it away): the
      // _running.load() above and the enqueue below are not atomic, so the
      // engine may be torn down in between. If enqueue() returns false the queue
      // is closed and the command was NOT queued — the (now-gone) loop would
      // never fulfill the promise, so we must still hold `ready` and return
      // locally without blocking in fut.get() (DD-5/DD-13). On the success path
      // the I/O thread fulfills the promise (bind result), or shutdownDrain's
      // drain-and-fail fails it if teardown raced after a successful push.
      if (!enqueue(Cmd::addListener(lc, ready)))
      {
        return ListenResult::err(
          TransportErrorInfo{TransportError::ShuttingDown,
            "addListener: transport shutting down"});
      }
      bool ok = fut.get(); // I/O thread fulfills it (bind result or shutdown-fail)
      if (!ok)
      {
        // Distinguish a real bind failure (while running) from a teardown-race
        // drain-fail (after stop() cleared _running) — cpp17 L-1 analog.
        if (!_running.load())
        {
          return ListenResult::err(
            TransportErrorInfo{TransportError::ShuttingDown,
              "addListener: transport shutting down"});
        }
        return ListenResult::err(
          TransportErrorInfo{TransportError::Bind,
            "bind/listen failed on " + bind + ":" + std::to_string(port)});
      }
      return ListenResult::ok(lc.id);
    }
    else
    {
      // _running already false: surface the closed-queue reject rather than
      // returning ok for a listener that will never bind (lost-completion).
      if (!enqueue(Cmd::addListener(lc)))
      {
        return ListenResult::err(
          TransportErrorInfo{TransportError::ShuttingDown,
            "addListener: transport shutting down"});
      }
    }
    return ListenResult::ok(lc.id);
  }

  using detail::EngineBase::connect; // un-hide the 3-arg non-pure default

  // Primitive 4-arg override. opts is inert on UDP (no TLS) — rejected below.
  ConnectResult connect(const std::string &host, std::uint16_t port, TlsMode tls,
                        const TlsClientOptions &opts) override
  {
    (void)opts; // UDP has no TLS; identity options are not applicable
    if (tls != TlsMode::None)
    {
      return ConnectResult::err(
        TransportErrorInfo{TransportError::Config, "TLS/DTLS not supported on UDP"});
    }
    SessionId sid = _nextSessionId++;
    return insertConnectingAndEnqueue(
      sid, [&] { return Cmd::connect(ConnectReq{sid, host, port}); },
      "connect: transport shutting down");
  }
  ConnectResult connectViaListener(ListenerId lid, const std::string &host, std::uint16_t port) override
  {
    SessionId sid = _nextSessionId++;
    // UDP-specific: unlike TCP (a not-supported stub), connectViaListener genuinely
    // enqueues here; same A3.1a ordering via the shared helper.
    return insertConnectingAndEnqueue(
      sid, [&] { return Cmd::via(ViaReq{sid, lid, host, port}); },
      "connectViaListener: transport shutting down");
  }
  /// \brief A3.1a shared front-end (steps-4-8 R1 simp-L2): build the command (inside
  /// the try, so a throwing ConnectReq/ViaReq construction is also caught), insert the
  /// sid into _connecting under the write lock, RELEASE, then enqueue on the noexcept
  /// path. The returned sid is immediately sendable (datagrams buffer in the
  /// PendingConnect entry until the session materializes). On enqueue-false (queue
  /// closed, DD-5) or a throw, roll the _connecting entry back via a SEPARATE
  /// eraseConnecting critical section — NEVER hold _sessionRwMutex across enqueue
  /// (that would nest _sessionRwMutex->_qmx). FAILURE-CODE PARITY (documented choice):
  /// UDP reports a single ShuttingDown on any enqueue-false (queue closed, or a rare
  /// allocation throw converted to false by enqueue's noexcept catch). TCP distinguishes
  /// queue-closed vs Unknown; the two public entry points keep their own message.
  template <typename BuildCmd>
  ConnectResult insertConnectingAndEnqueue(SessionId sid, BuildCmd buildCmd,
                                           const char *shuttingDownMsg)
  {
    bool inserted = false;
    try
    {
      Cmd cmd = buildCmd();
      {
        std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
        _connecting.insert(sid);
      }
      inserted = true;
      if (enqueue(std::move(cmd)))
      {
        return ConnectResult::ok(sid);
      }
    }
    catch (...)
    {
    }
    if (inserted)
    {
      // steps-4-8 R3 (TS LOW): the rollback erases _connecting and fires NO onClose.
      // That owes no terminal because an err-returned sid NEVER escapes to
      // observer-capable code — connect()/connectViaListener() return this sid to the
      // caller ONLY via ConnectResult::ok; an err result hands the sid to nobody, so
      // no legitimate observe(sid) can exist. Re-audit if any future path observes a
      // sid before its ConnectResult is known.
      eraseConnecting(sid);
    }
    return ConnectResult::err(TransportErrorInfo{TransportError::ShuttingDown, shuttingDownMsg});
  }
  /// \brief Single sendability decision (A3.3): make it ONCE so a close racing
  /// between two separate checks cannot mis-report. Ok = accepted; NotConnected =
  /// unknown/closed/cap-rejected sid; EnqueueFailed = queue closed at teardown.
  enum class SendOutcome
  {
    Ok,
    NotConnected,
    EnqueueFailed
  };
  SendOutcome trySend(SessionId sid, const void *p, std::size_t n)
  {
    // CF-H1: reject an unknown/closed session at enqueue time rather than enqueuing
    // a command sendDo would silently drop (which returned true — masking a dead
    // connection from SIP RFC 3263 failover). ONE sessionSendable acquisition. The
    // sendability check precedes the n==0 short-circuit (matching TCP) so a 0-length
    // send to an UNKNOWN sid reports NotConnected, not a spurious Ok (steps-4-8 R1 L1).
    if (!sessionSendable(sid))
    {
      return SendOutcome::NotConnected;
    }
    if (n == 0)
    {
      return SendOutcome::Ok;
    }
    ByteBuffer b(n);
    std::memcpy(b.data(), p, n);
    SendReq sr;
    sr.sid = sid;
    sr.payload = std::move(b);
    return enqueue(Cmd::send(std::move(sr))) ? SendOutcome::Ok : SendOutcome::EnqueueFailed;
  }
  bool send(SessionId sid, const void *p, std::size_t n) override
  {
    return trySend(sid, p, n) == SendOutcome::Ok;
  }
  bool close(SessionId sid) override { return enqueue(Cmd::close(sid)); }
  bool isRunning() const override { return _running.load(std::memory_order_acquire); }
  std::thread::id getIoThreadId() const override { return _loop.get_id(); }
  TransportStats getStats() const override
  {
    TransportStats ts;
    ts.accepted = _atomicStats.accepted.load(std::memory_order_relaxed);
    ts.connected = _atomicStats.connected.load(std::memory_order_relaxed);
    ts.closed = _atomicStats.closed.load(std::memory_order_relaxed);
    ts.errors = _atomicStats.errors.load(std::memory_order_relaxed);
    ts.tlsHandshakes = _atomicStats.tlsHandshakes.load(std::memory_order_relaxed);
    ts.tlsFailures = _atomicStats.tlsFailures.load(std::memory_order_relaxed);
    ts.bytesIn = _atomicStats.bytesIn.load(std::memory_order_relaxed);
    ts.bytesOut = _atomicStats.bytesOut.load(std::memory_order_relaxed);
    ts.epollWakeups = _atomicStats.epollWakeups.load(std::memory_order_relaxed);
    ts.commands = _atomicStats.commands.load(std::memory_order_relaxed);
    ts.gcRuns = _atomicStats.gcRuns.load(std::memory_order_relaxed);
    ts.gcClosedIdle = _atomicStats.gcClosedIdle.load(std::memory_order_relaxed);
    ts.gcClosedAged = _atomicStats.gcClosedAged.load(std::memory_order_relaxed);
    ts.backpressureCloses = _atomicStats.backpressureCloses.load(std::memory_order_relaxed);
    ts.sessionsCurrent = _atomicStats.sessionsCurrent.load(std::memory_order_relaxed);
    ts.sessionsPeak = _atomicStats.sessionsPeak.load(std::memory_order_relaxed);
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

  /// \note The completion callback fires synchronously on the caller's thread
  /// after the send command is enqueued (not after wire delivery). This is
  /// intentional — the result reflects whether the command was accepted by
  /// the I/O thread's queue, not whether data reached the peer.
  void sendAsync(SessionId sid, const void *data, std::size_t len,
                 SendCompleteCallback cb) override
  {
    // CF-H1 + A3.3 single-decision send: make ONE sendability decision (trySend) so
    // a close racing between two checks cannot yield the wrong code. The decision is
    // taken under the session read lock, released BEFORE cb runs (never invoke a user
    // callback while holding _sessionRwMutex). Completion stays SYNCHRONOUS on the
    // caller thread, the contract Transport::sendSync relies on (see EngineBase).
    const SendOutcome oc = trySend(sid, data, len);
    if (!cb)
    {
      return;
    }
    if (oc == SendOutcome::Ok)
    {
      cb(sid, SendResult::ok(len));
      return;
    }
    // Both NotConnected and EnqueueFailed (queue closed at teardown) report the
    // structured NotConnected code — the session is not reachable. This replaces the
    // former Socket "session not connected" / "send enqueue failed" pair.
    cb(sid, SendResult::err(TransportErrorInfo{TransportError::NotConnected, "session not connected"}));
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
    int fd = backingFdFor(s);
    if (fd < 0)
    {
      return {};
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
    int fd = backingFdFor(s);
    if (fd < 0)
    {
      return false;
    }
    return applyDscpToFd(fd, dscp);
  }

  /// \brief No-op on UDP (C5). UDP multiplexes many virtual sessions over ONE
  /// shared socket, so EPOLLIN cannot be removed for an individual session without
  /// disabling read for all of them; the transport layer keeps dropping reads at
  /// the callback for UDP ReadMode::Disabled. Returns false (not applied).
  bool setReadEnabled(SessionId sid, bool enabled) override
  {
    (void)sid;
    (void)enabled;
    return false;
  }

  /// \brief TEST-ONLY (CF-M4): return the socket fd carrying session \p sid, or
  /// -1 if unknown/unbacked. Lets a test getsockopt(IP_TOS/IPV6_TCLASS) on the
  /// socket to verify the DSCP mark was applied at creation (see
  /// iora_test_engine_introspection). Mirrors setDscp's fd resolution: a
  /// ClientConnected session uses its own fd; a ServerPeer session multiplexes
  /// over its owning listener's shared socket, so that listener fd is returned
  /// (the socket the DSCP mark was actually applied to). Takes the session read
  /// lock. NOT part of the production API — never used outside tests.
  int testGetSessionFd(SessionId sid) const
  {
    std::shared_lock<std::shared_mutex> rl(_sessionRwMutex);
    auto it = _sessions.find(sid);
    if (it == _sessions.end())
    {
      return -1;
    }
    const auto *s = it->second.get();
    return backingFdFor(s);
  }

  /// \brief TEST-ONLY (tracker 2026-09-15-3): number of fd->Tag entries. Used to assert
  /// that shutdownDrain/closeNow erase a session's/listener's fd-tag (no stale Tag::sess
  /// survives). Call only when the I/O thread is stopped (no lock taken). NOT production API.
  std::size_t testTagCount() const { return _tags.size(); }

  /// \brief TEST-ONLY (tracker 2026-09-15-3): install a hook invoked with the fd number
  /// immediately before each getter-reachable teardown ::close (session closeNow /
  /// shutdownDrain, listener drain), so a deterministic fd-reuse test can dup2() a
  /// sentinel onto the fd and confirm the session/listener is already out of its map.
  /// MUST be installed before start() -- the hook is read lock-free on the I/O thread.
  /// The hook MUST be noexcept: it runs in detail::FdCloser's noexcept destructor during
  /// shutdownDrain, so a throwing hook would std::terminate.
  /// Empty in production (one null-function check per teardown close). NOT production API.
  void testSetPreCloseHook(std::function<void(int)> hook)
  {
    assert(!_running.load(std::memory_order_acquire) &&
           "testSetPreCloseHook must be called before start()");
    _preCloseHook = std::move(hook);
  }

private:
  static std::string lastErr() { return iora::core::errnoMessage(errno); }
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
  /// \brief Forwards to the shared iora::network::applyDscpToFd (see the
  /// tcp_engine twin — both were byte-identical private copies, the same
  /// anti-pattern already retired for addressFromSockaddr). CF-L1. Shared by the
  /// per-session setDscp() API and the at-creation application of
  /// config.dscpValue.
  static bool applyDscpToFd(int fd, std::uint8_t dscp)
  {
    return iora::network::applyDscpToFd(fd, dscp);
  }

  // Forward declaration of the nested Session (defined below): backingFdFor takes a
  // `const Session *` PARAMETER, whose type must be declared here even though the
  // body is parsed in complete-class context.
  struct Session;

  /// \brief Resolve the socket fd that actually backs session \p s: a ServerPeer
  /// multiplexes over its owning listener's shared socket (that listener's fd);
  /// any other role uses the session's own fd. Returns -1 if unbacked (owning
  /// listener gone). The caller MUST already hold \c _sessionRwMutex (shared) —
  /// this reads \c _listeners. Deduplicates the resolution formerly copied into
  /// getLocalAddress, setDscp, and testGetSessionFd (CF-L1 twin).
  int backingFdFor(const Session *s) const
  {
    if (s->role == Role::ServerPeer)
    {
      auto lit = _listeners.find(s->owner);
      return (lit == _listeners.end()) ? -1 : lit->second->fd;
    }
    return s->fd;
  }

  /// \brief CF-H1: is \p sid a currently-known, not-closed session? Takes the
  /// session read lock briefly. send()/sendAsync() call this to reject an
  /// unknown/closed session synchronously at enqueue time — enqueuing a Send
  /// command that sendDo then silently drops reported false success and masked
  /// connection failure (defeating SIP RFC 3263 failover). This is the SAME
  /// validity notion sendDo uses: present in _sessions AND !closed. UDP sessions
  /// are virtual over the shared socket, but the engine DOES keep a per-session
  /// registry (_sessions) with a per-session closed flag, so the check is
  /// meaningful for both ClientConnected and ServerPeer sessions. A close racing
  /// right after this check is the accepted narrow TOCTOU.
  bool sessionSendable(SessionId sid) const
  {
    std::shared_lock<std::shared_mutex> rl(_sessionRwMutex);
    auto it = _sessions.find(sid);
    if (it != _sessions.end() && !it->second->closed.load(std::memory_order_relaxed))
    {
      return true;
    }
    // A sid returned by connect()/connectViaListener() is immediately sendable while
    // still connecting: its datagrams buffer in the PendingConnect entry (A3.1b).
    return _connecting.find(sid) != _connecting.end();
  }

  /// \brief Is \p sid live for observer purposes: an open session OR still
  /// connecting? Read under the SAME lock as sessionSendable (_sessionRwMutex),
  /// which is the load-bearing synchronizer for Transport::observe()'s exactly-once
  /// terminal handoff — the map/registry-presence check (NOT the relaxed `closed`
  /// flag) is what pairs with A2.1 (liveness cleared happens-before onClose). A
  /// future "optimization" that drops the map-presence check silently breaks
  /// exactly-once. Pure virtual on EngineBase; both engines implement it.
  bool isSessionLive(SessionId sid) const override
  {
    // steps-4-8 R1 simp-M3: identical predicate to sessionSendable — delegate so the
    // one map/registry-presence check has a single source of truth (the two names are
    // kept to document caller intent: "may I accept a send" vs "is this session alive
    // for observer purposes"). That _sessionRwMutex-guarded presence check — NOT the
    // relaxed `closed` flag — is the load-bearing synchronizer for observe()
    // exactly-once (A2.1); a future edit that "optimizes" it silently breaks it.
    return sessionSendable(sid);
  }
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

  /// Forwards to the shared iora::network::addressFromSockaddr. This was a
  /// private copy identical to tcp_engine's; both are retired in favour of the
  /// one public implementation (a third consumer could not reach either).
  static TransportAddress addressFromSockaddr(const sockaddr_storage &ss)
  {
    return iora::network::addressFromSockaddr(ss);
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
    _atomicStats.errors.fetch_add(1, std::memory_order_relaxed);
    // steps-4-8 R1 simp-M2: reuse the EngineBase copy-then-invoke helper (matches the
    // TcpEngine sibling) — invokeUserCallback swallows+logs a throwing user callback.
    invokeUserCallback(copyCallback(_cbMutex, _cbs.onError), e, m);
  }

  /// \brief Erase \p sid from the connecting registry; true iff it was present.
  /// A SEPARATE _sessionRwMutex critical section — the connect() rollback path uses
  /// it AFTER releasing the insert lock, never nesting _sessionRwMutex->_qmx.
  bool eraseConnecting(SessionId sid) noexcept
  {
    std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
    return _connecting.erase(sid) == 1;
  }

  /// \brief Erase \p sid's _pendingConnects entry; true iff it was present. I/O
  /// thread only. UDP has NO TimerService — the resolve-timeout is a GC-observed
  /// deadline, so dropping the entry disarms it (no timer to cancel, unlike TCP).
  bool takePending(SessionId sid) noexcept { return _pendingConnects.erase(sid) == 1; }

  /// \brief Fire the SINGLE pre-insert terminal for a sid that never reached
  /// _sessions (I/O thread). ORDER: copy onClose, RELEASE the pending + connecting
  /// registry ownership (liveness cleared happens-before onClose, A2.1), THEN
  /// exactly one onClose(\p info). Returns false, firing nothing, if the sid owned
  /// neither (a terminal already fired). Erasing the pending entry drops any
  /// datagrams still buffered in it (A3.1b). Mirrors tcp_engine preInsertTerminal.
  /// OOM WINDOW (steps-4-8 R2 cpp17 L-1, accepted): the copyCallback runs BEFORE the
  /// erases because A2.1 requires the erase to happen-before the onClose when the copy
  /// SUCCEEDS. If the copy throws (extreme bad_alloc) on a non-drain terminal, the
  /// registry entry is left un-erased and stays sendable/live for a dead sid until the
  /// next shutdownDrain final-sweep clears it — a narrow CF-H1/observe-leak window
  /// bounded by the drain sweep; the copy-first order is the required trade for A2.1.
  bool preInsertTerminal(SessionId sid, const TransportErrorInfo &info)
  {
    // steps-4-8 R1 simp-M2: use the EngineBase copy-then-invoke helper (matches the
    // TcpEngine sibling). invokeUserCallback swallows+logs a throwing onClose, so a
    // user handler that throws here CANNOT skip the caller's subsequent error()
    // (the uniform "onClose + error() both fire on resolve/connect terminals" policy).
    const auto closeCb = copyCallback(_cbMutex, _cbs.onClose);
    const bool pending = takePending(sid);
    const bool connecting = eraseConnecting(sid);
    if (!pending && !connecting)
    {
      return false;
    }
    invokeUserCallback(closeCb, sid, info);
    return true;
  }

  /// \brief A3.1b: replay datagrams buffered during a named-host resolve window, in
  /// order, through the role-correct send path (ClientConnected -> ::send/s->wq;
  /// ServerPeer -> ::sendto/lst->wq). Called after onConnect at both insert sites.
  void replayPendingWq(SessionId sid, std::deque<ByteBuffer> &pendingWq)
  {
    for (auto &payload : pendingWq)
    {
      SendReq rsr;
      rsr.sid = sid;
      rsr.payload = std::move(payload);
      sendDo(std::move(rsr));
    }
  }

  friend struct UdpEngineTestAccess;

  /// I/O-thread points at which the connect path throws once (test seam, AX9.1b).
  enum class ConnectThrowPoint
  {
    NONE,
    BEFORE_INSERT_LITERAL,           // connectDo literal branch, before connectFromAddrs
    BEFORE_INSERT_RESUME,            // resumeConnect/resumeVia, before *FromAddrs
    VIA_KICKOFF_AFTER_PENDING_INSERT // viaDo, after _pendingConnects insert
  };
  std::atomic<ConnectThrowPoint> _testConnectThrowPoint{ConnectThrowPoint::NONE};
  std::atomic<bool> _testEnqueueFailure{false};

  /// \brief Test seam: throw ONCE if the armed point matches (then disarm).
  void testMaybeThrowAt(ConnectThrowPoint point)
  {
    ConnectThrowPoint expected = point;
    if (_testConnectThrowPoint.load(std::memory_order_relaxed) == expected &&
        _testConnectThrowPoint.compare_exchange_strong(expected, ConnectThrowPoint::NONE,
                                                       std::memory_order_relaxed))
    {
      throw std::runtime_error("injected connect-path throw");
    }
  }

  /// \brief A3.1c exception guard around the I/O-thread connect path (the Cmd entry
  /// AND the RunOnIo->resume entry). On an UNEXPECTED throw the connecting-sid /
  /// pending ownership must not leak: fire exactly ONE terminal iff we still own the
  /// sid (preInsertTerminal erases _connecting AND _pendingConnects, returning false
  /// if a terminal already fired); if the sid already reached _sessions, route through
  /// closeNow instead. Never a second terminal after an in-path onClose.
  template <typename F> void withConnectGuard(SessionId sid, F &&fn)
  {
    try
    {
      fn();
    }
    catch (...)
    {
      try
      {
        if (!preInsertTerminal(sid, TransportErrorInfo{TransportError::Unknown, "internal error"}))
        {
          auto it = _sessions.find(sid);
          if (it != _sessions.end())
          {
            closeNow(it->second.get(), TransportError::Unknown, "internal error", 0);
          }
        }
      }
      catch (...)
      {
      }
    }
  }

  enum class CmdType
  {
    Shutdown,
    AddListener,
    Connect,
    Via,
    Send,
    Close,
    RunOnIo // generic "run this closure on the I/O thread" (runOnIoThread seam)
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
    // Inert on UDP (no TLS): present only to satisfy the shared 4-arg connect
    // primitive signature (arch C1, kept per step-0 L-a). Never read.
    std::string verifyName;
    unsigned x509HostFlags{0};
  };
  struct ViaReq
  {
    SessionId sid{};
    ListenerId lid{};
    std::string host;
    std::uint16_t port{};
  };
  /// \brief I/O-thread-only record of a named-host connect/via awaiting
  /// off-thread resolution. Single-owner one-shot terminal event for that sid;
  /// exactly one of {resume, resolve-timeout GC scan, teardown/close} erases it
  /// and fires. UDP has NO TimerService, so the timeout is an absolute
  /// resolveDeadline observed by the I/O-thread GC scan (runGc). A default
  /// (zero) deadline means "no resolve-timeout armed". The connect-vs-via resume
  /// path lives in the continuation closure, not here, so this entry is uniform.
  struct PendingConnect
  {
    MonoTime resolveDeadline{}; // absolute; default (epoch) == disabled
    // A3.1b: datagrams sent to this sid while it is still resolving (sendable via
    // _connecting, no Session yet). Bounded by maxWriteQueue with an UNCONDITIONAL
    // drop-OLDEST that always keeps >=1 (no Session exists, so no closeOnBackpressure
    // path applies; a UDP retransmit burst leaves >=1 deliverable). MOVED OUT before
    // the pending entry is erased and replayed in order after the session is inserted;
    // dropped if a pre-insert terminal fires instead.
    //
    // SIP-LAYER SOUNDNESS (why drop-oldest keeps this recoverable): the common case
    // is an initial request + its Timer-A/E retransmits, each re-emitted by the owning
    // client transaction (INVITE Timer A uncapped -> Timer B, s17.1.1.2; non-INVITE
    // Timer E capped at T2, s17.1.2.2) and absorbed as a byte-identical retransmit by
    // the peer server transaction (s17.2.1/s17.2.2/s17.2.3) -> a dropped copy is bounded
    // latency, not loss. CAVEAT (steps-4-8 R2 sip-M2): SipUdpTransport coalesces one
    // UDP session PER DESTINATION ADDRESS, so when a dialog's remote target diverges to
    // a fresh FQDN next-hop (Contact/loose-route with no Record-Route), the FIRST
    // datagram on a brand-new session can be an ACK-for-2xx or an in-dialog request.
    // In-dialog requests (BYE/re-INVITE/UPDATE) ARE client transactions -> Timer A/E
    // still recovers them; but an ACK-for-2xx is generated end-to-end by the UAC core
    // and is NOT retransmitted by any client transaction (RFC 3261 s13.2.2.4) -> a
    // dropped ACK-for-2xx is recovered only by the UAS retransmitting the 2xx
    // (s13.3.1.4 / s17.2.1). The floor-at-1 policy preserves the LONE-datagram case
    // (the realistic ACK shape), and the SIP default maxWriteQueue (1024) means
    // overflow-drop effectively never fires; so practical loss is negligible. But if a
    // design change ever raised the pre-establishment buffer pressure, this ACK path is
    // where drop-oldest stops being lossless — flag it.
    std::deque<ByteBuffer> wq;
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
    std::function<void()> fn; // CmdType::RunOnIo payload (std::function keeps Cmd copyable)
    static Cmd shutdown()
    {
      Cmd x;
      x.t = CmdType::Shutdown;
      return x;
    }
    static Cmd runOnIo(std::function<void()> fn)
    {
      Cmd x;
      x.t = CmdType::RunOnIo;
      x.fn = std::move(fn);
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
  // The CmdType::RunOnIo payload is a std::function<void()> member, so Cmd stays
  // copyable — the command deque copies/moves entries (arch C2; tracker task-1.6
  // / testStrategy c1_c3_unit "RunOnIo keeps Command/Cmd copyable").
  static_assert(std::is_copy_constructible<Cmd>::value,
                "Cmd must remain copyable after adding the RunOnIo fn member");
  /// \brief EngineBase seam: post \p fn onto the I/O thread as a RunOnIo command.
  /// NOEXCEPT and callback-free — on any failure (queue closed, or allocation)
  /// it returns false and fires NO user callback; a dropped resolve post is
  /// backstopped by the resolve-timeout (#10/#14). ALWAYS posts, never inline.
  /// (Unlike the plain enqueue, this catches to honor the noexcept contract.)
  bool runOnIoThread(std::function<void()> fn) noexcept override
  {
    try
    {
      std::lock_guard<std::mutex> g(_qmx);
      if (_qClosed)
      {
        return false;
      }
      _q.push_back(Cmd::runOnIo(std::move(fn)));
      _atomicStats.commands.fetch_add(1, std::memory_order_relaxed);
      if (_eventFd >= 0)
      {
        std::uint64_t one = 1;
        (void)::write(_eventFd, &one, sizeof(one));
      }
      return true;
    }
    catch (...)
    {
      return false;
    }
  }
  // Push a command and wake the I/O loop. The deque push, the _qClosed check, and
  // the _eventFd wakeup ::write all happen UNDER _qmx so they are atomic w.r.t.
  // shutdownDrain()'s `close(_eventFd); _eventFd=-1` (also under _qmx). Returns false
  // WITHOUT pushing if the queue was closed by teardown (DD-1/DD-2/DD-5). A3.1a:
  // enqueue CATCHES a throwing push_back and returns false (instead of propagating)
  // so connect()/connectViaListener() roll the _connecting entry back on the SAME
  // path as the queue-closed reject. The single rvalue-ref overload is the only one
  // (steps-4-8 R1 simp-M1: every caller passes an rvalue — a factory prvalue or an
  // explicit std::move — so the former const& overload was dead code, deleted).
  bool enqueue(Cmd &&c) noexcept
  {
    try
    {
      std::lock_guard<std::mutex> g(_qmx);
      if (_qClosed)
      {
        return false;
      }
      if (_testEnqueueFailure.load(std::memory_order_relaxed))
      {
        throw std::runtime_error("injected enqueue failure"); // caught below -> false
      }
      _q.push_back(std::move(c));
      _atomicStats.commands.fetch_add(1, std::memory_order_relaxed);
      if (_eventFd >= 0)
      {
        std::uint64_t one = 1;
        (void)::write(_eventFd, &one, sizeof(one));
      }
      return true;
    }
    catch (...)
    {
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
    // Cross-thread liveness flag (tracker 2026-09-15-3): read lock-free on the CALLER
    // thread in sessionSendable() while the I/O thread writes it in closeNow()/
    // shutdownDrain(). Atomic (relaxed) makes that read/write well-defined -- it is an
    // advisory liveness gate that publishes no companion state (the I/O thread
    // re-validates under the map at sendDo). The check-then-set in closeNow/shutdownDrain
    // is a plain relaxed store (not a CAS), safe ONLY because BOTH are I/O-thread-confined
    // and never run concurrently; a future caller-thread close path must use a CAS.
    std::atomic<bool> closed{false};
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
    // INVARIANT: shutdownDrain runs only on the I/O loop thread (called at the
    // end of loop()). It is NOT asserted via _loop.get_id()/getIoThreadId(): on
    // the self-destruct teardown path, detachForTermination() detaches _loop
    // from inside the onClose callback BEFORE the loop exits and reaches
    // shutdownDrain, so _loop.get_id() is the null id here and such an assert
    // would spuriously fire (DD-12). The _timerFd/_epollFd confinement and the
    // _eventFd-close serialization below rely on this invariant.

    // A6.3 (ii): BACKSTOP guard armed BEFORE process(). shutdownDrain's OWN
    // allocation sites (toClose.reserve/push_back, fdsToClose, pendingSids, the
    // unique_locks) can throw and unwind PAST the _qClosed teardown block below
    // with _qClosed still false — then a later runOnIoThread posts into a dead
    // queue (breaks observe() exactly-once) and receiveSync waiters never wake.
    // This forces _qClosed=true + _eventFd closed on ANY unwinding exit, IDEMPOTENT
    // vs the normal-path teardown block (after which it is a no-op). It is a
    // BACKSTOP, not a substitute for the per-callback-site try/catch in (i).
    // ACCEPTED LIMITATION (steps-4-8 R3 TS LOW, spec A6.3 "(ii) alone skips remaining
    // onCloses + the residual promise drain"): the backstop guarantees _qClosed (so a
    // later runOnIoThread returns false rather than posting into a dead queue), but it
    // does NOT drain residual promise-bearing commands or fire remaining session-drain
    // onCloses. So if a bad_alloc unwinds one of shutdownDrain's OWN allocation sites
    // (toClose/fdsToClose/pendingSids reserves, a unique_lock) BEFORE the normal
    // residual drain at the bottom, a synchronous addListener caller's future may hang
    // and a residual observe owned-terminal may not fire. This is the accepted
    // OOM-during-teardown trade (the (i) per-site guards keep the common callback-throw
    // path reaching the normal drain); the allocation-unwind path is not covered.
    auto closeQueueBackstop = [this]() noexcept
    {
      try
      {
        std::lock_guard<std::mutex> g(_qmx);
        _qClosed = true;
        if (_eventFd >= 0)
        {
          delEpoll(_eventFd);
          ::close(_eventFd);
          _eventFd = -1;
        }
      }
      catch (...)
      {
      }
    };
    struct QGuard
    {
      std::function<void()> fn;
      ~QGuard() { if (fn) { fn(); } }
    } qGuard{closeQueueBackstop};

    process();
    // Collect sessions to close to avoid iterator invalidation
    std::vector<Session *> toClose;
    toClose.reserve(_sessions.size());
    for (auto &kv : _sessions)
      toClose.push_back(kv.second.get());

    // fd-reuse fix (tracker 2026-09-15-3): DETACH (delEpoll + tag-erase) sessions and
    // listeners and COLLECT their fds, but do NOT ::close yet. The fds are closed only
    // AFTER both maps are cleared under the write lock (fdsToClose destructs at scope
    // end), so a cross-thread getter holding the shared lock cannot syscall on a
    // closed/reused fd. ServerPeer sessions alias the shared listener fd (s->fd ==
    // lst->fd), so ONLY ClientConnected session fds are collected here -- the shared
    // listener fd is collected exactly once via the listener loop below.
    std::vector<detail::FdCloser> fdsToClose;
    fdsToClose.reserve(toClose.size() + _listeners.size());

    // Close all sessions safely (but don't erase from _sessions yet)
    for (auto *s : toClose)
    {
      if (!s || s->closed.load(std::memory_order_relaxed))
        continue;
      s->closed.store(true, std::memory_order_relaxed);
      if (s->role == Role::ClientConnected)
      {
        delEpoll(s->fd);
        _tags.erase(s->fd);
        fdsToClose.emplace_back(s->fd, &_preCloseHook); // ::close after _sessions.clear()
      }
      else
      {
        _peerIndex.erase(s->pkey); // ServerPeer: aliases the listener fd -- never close here
      }
      _atomicStats.closed.fetch_add(1, std::memory_order_relaxed);
      _atomicStats.sessionsCurrent.fetch_sub(1, std::memory_order_relaxed);
      // A6.4: session drain reports ShuttingDown (was Unknown "shutdown"), matching
      // the pending drain. A6.3 + simp-M2: invokeUserCallback copies onClose under
      // _cbMutex and swallows+logs a throwing handler, so one session's throw cannot
      // skip the rest or unwind past the teardown.
      invokeUserCallback(copyCallback(_cbMutex, _cbs.onClose), s->id,
                         TransportErrorInfo{TransportError::ShuttingDown, "shutdown"});
    }
    {
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      _sessions.clear();
    }

    // Detach listeners (delEpoll + tag-erase + collect fd), then clear _listeners under
    // the write lock, then close (fdsToClose destructor). Do NOT deref lst->fd after the
    // clear -- _listeners.clear() destroys the Listener.
    for (auto &kv : _listeners)
    {
      Listener *lst = kv.second.get();
      delEpoll(lst->fd);
      _tags.erase(lst->fd);
      fdsToClose.emplace_back(lst->fd, &_preCloseHook);
    }
    {
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      _listeners.clear();
    }
    // fdsToClose destructs at scope end (after both maps cleared) -> all fds ::close()d.
    if (_timerFd >= 0)
    {
      delEpoll(_timerFd);
      ::close(_timerFd);
      _timerFd = -1;
    }

    // (a) CLOSE THE POST GATE — a STANDALONE gate->m section, BEFORE the _qmx
    // teardown block and never nested inside it (HR-2: gate->m outside _qmx).
    // After this, resolver continuations drop instead of posting a resume
    // (#8/#13). UDP has its OWN shutdownDrain (task-4.5) — the TCP hook does not
    // cover it; omitting this leaves the off-thread resolve UAF-unsafe at
    // teardown.
    {
      std::lock_guard<std::mutex> gg(_postGuard->m);
      _postGuard->closed = true;
      _postGuard->engine = nullptr;
    }

    // (b) DRAIN in-flight named-host resolves (#7b): COLLECT-THEN-FIRE. Route each
    // pending sid through preInsertTerminal (A3.1a) so the ONE onClose(ShuttingDown)
    // fires AFTER erasing BOTH _pendingConnects AND _connecting — else a racing
    // observe() sees isSessionLive==true after the onClose (A2.1/A6.1 violation ->
    // observer leak/double-classify). Outside gate->m and the _qmx teardown block
    // (#14/HR-3). A6.3: guard each terminal so a throw on one does not skip the rest
    // and cannot unwind past the teardown block.
    if (!_pendingConnects.empty())
    {
      std::vector<SessionId> pendingSids;
      pendingSids.reserve(_pendingConnects.size());
      for (auto &kv : _pendingConnects)
      {
        pendingSids.push_back(kv.first);
      }
      for (SessionId sid : pendingSids)
      {
        if (_pendingConnects.count(sid) != 0)
        {
          try
          {
            preInsertTerminal(sid, TransportErrorInfo{TransportError::ShuttingDown, "shutdown"});
          }
          catch (...)
          {
          }
        }
      }
    }

    // Close _eventFd and the command queue together under _qmx so the close is
    // mutually exclusive with enqueue()'s wakeup ::write (DD-1) and no further
    // command can be queued after teardown (DD-5). Any promise-bearing command
    // still queued here (pushed after the process() above but before the queue
    // closed) is drained and its promise FAILED outside the lock, so a
    // synchronous addListener caller's fut.get() returns instead of blocking
    // forever (DD-5/DD-13). _qmx stays a leaf: swap under the lock and fulfill
    // promises after releasing (set_value runs no user code).
    std::deque<Cmd> residual;
    {
      std::lock_guard<std::mutex> g(_qmx);
      _qClosed = true;
      residual.swap(_q);
      if (_eventFd >= 0)
      {
        delEpoll(_eventFd);
        ::close(_eventFd);
        _eventFd = -1;
      }
    }
    for (auto &c : residual)
    {
      if (c.listenerReady)
      {
        try { c.listenerReady->set_value(false); } catch (...) {}
      }
      // A6.3 R3 HIGH-1: a residual Cmd::Connect/Cmd::Via landed in _q in the
      // post-process()/pre-_qClosed window returned ok(sid) + inserted sid into
      // _connecting, then would be silently DROPPED here (no terminal) — neither
      // onConnect nor onClose fires (lost completion, DD-5) AND a racing observe()
      // that saw isSessionLive(sid)==true leaks. Fire the ONE onClose(ShuttingDown)
      // per residual connect sid through preInsertTerminal (erase _connecting first),
      // guarded, BEFORE the final clear() sweep. Mirrors tcp_engine :1838-1849.
      if (c.t == CmdType::Connect)
      {
        try
        {
          preInsertTerminal(c.c.sid, TransportErrorInfo{TransportError::ShuttingDown, "shutdown"});
        }
        catch (...)
        {
        }
      }
      else if (c.t == CmdType::Via)
      {
        try
        {
          preInsertTerminal(c.v.sid, TransportErrorInfo{TransportError::ShuttingDown, "shutdown"});
        }
        catch (...)
        {
        }
      }
      else if (c.t == CmdType::RunOnIo && c.fn)
      {
        // A6.3 (steps-4-8 R1 H1): INVOKE residual RunOnIo closures — do NOT drop
        // them. A Transport::observe() owned-terminal is delivered via runOnIoThread;
        // one posted in the post-process()/pre-_qClosed window lands here as a
        // residual command. Dropping it strands the observer callback (zero fires,
        // breaking A6.2 exactly-once) and leaks the SSE stream. _qClosed is already
        // set, so the closure runs against a dead queue safely (a stranded resolver
        // resume no-ops — _pendingConnects is drained). Guarded so one throw cannot
        // skip the rest or unwind past the final sweep.
        try
        {
          c.fn();
        }
        catch (...)
        {
        }
      }
    }
    // A3.1a(6) / TS3-R3-1: unconditional final sweep. preInsertTerminal releases its
    // registry entry AFTER the allocating copy, so a swallowed bad_alloc above could
    // leave a _connecting/_pendingConnects entry behind. Clear both so the drain
    // leaves them provably empty. NO end-of-drain assert (a concurrent connect()
    // legitimately holds an entry until its enqueue sees _qClosed and rolls back).
    {
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      _connecting.clear();
    }
    _pendingConnects.clear();
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
      _atomicStats.epollWakeups.fetch_add(1, std::memory_order_relaxed);
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
        _atomicStats.epollWakeups.fetch_add(1, std::memory_order_relaxed);
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
          // A3.1c: guard the connect dispatch so a throw cannot leak the _connecting
          // entry connect() inserted (fire exactly one terminal, no registry leak).
          withConnectGuard(c.c.sid, [&]() { connectDo(c.c); });
          break;
        case CmdType::RunOnIo:
          if (c.fn)
          {
            c.fn();
          }
          break;
        case CmdType::Via:
          withConnectGuard(c.v.sid, [&]() { viaDo(c.v); });
          break;
        case CmdType::Send:
          sendDo(std::move(c.s));
          break;
        case CmdType::Close:
        {
          // Close DURING the resolve window (task-4.6): the session was never
          // created (resolution still in flight OR the literal path has not run
          // connectDo yet), so route through the ONE pre-insert terminal helper —
          // it erases _pendingConnects AND _connecting and fires the single
          // onClose. A later resumeConnect/resumeVia then finds no entry and no-ops.
          // (Also covers the sid-in-_connecting-only case a bare _pendingConnects
          // lookup missed, which previously leaked.)
          if (preInsertTerminal(c.closeSid, TransportErrorInfo{TransportError::Unknown, "closed by app"}))
          {
            break;
          }
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
        // steps-4-8 R2 (cpp17 H-1 / simp): report via error() (copyCallback +
        // invokeUserCallback) — a throwing onError is swallowed+logged. R3 (cpp17 LOW):
        // the message build + copyCallback can themselves throw bad_alloc, so wrap the
        // report so an OOM here cannot re-escape process() and unwind the loop / skip
        // the drain.
        try { error(TransportError::Unknown, std::string("cmd dispatch: ") + ex.what()); }
        catch (...) {}
      }
      catch (...)
      {
        // A6.3 (i): a NON-std throw must NOT escape process() — when process() runs
        // inside shutdownDrain a throw here would unwind past the _qClosed/_eventFd
        // teardown block, leaving a later runOnIoThread to post into a dead queue
        // (breaks observe() exactly-once) and receiveSync waiters unwoken.
        if (c.listenerReady)
        {
          try { c.listenerReady->set_value(false); } catch (...) {}
        }
        try { error(TransportError::Unknown, "cmd dispatch: non-standard exception"); }
        catch (...) {}
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
    // Apply the configured DSCP mark to the shared listener/data socket at
    // creation (C1). UDP multiplexes server-peer sessions over this one socket,
    // so the mark is per-socket, not per-session; 0 leaves default best-effort.
    // The SIP UDP preset (forSipUdp) sets dscpValue=24 (CS3) for signaling QoS.
    if (_config.dscpValue != 0)
    {
      (void)applyDscpToFd(sfd, _config.dscpValue);
    }
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
    {
      ev |= EPOLLET;
    }
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
    {
      readFromListener(lst);
    }
    if (events & EPOLLOUT)
    {
      flushListener(lst);
    }
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
        _atomicStats.bytesIn.fetch_add(n, std::memory_order_relaxed);
        std::string k = key(from);
        SessionId sid = 0;
        auto it = _peerIndex.find(k);
        if (it == _peerIndex.end())
        {
          if (sessionCapReached())
          {
            continue; // no SessionId yet -> silent drop (peer retransmits)
          }
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
          _atomicStats.accepted.fetch_add(1, std::memory_order_relaxed);
          bumpSess();
          // steps-4-8 R2 (simp/cpp17): route onAccept through invokeUserCallback so a
          // throwing user handler cannot unwind the I/O loop (mirror tcp_engine).
          invokeUserCallback(copyCallback(_cbMutex, _cbs.onAccept), sid,
                             addressFromSockaddr(from));
        }
        else
        {
          sid = it->second;
        }
        // steps-4-8 R3 (cpp17/TS LOW): use const find() (not non-const operator[])
        // on the I/O thread — operator[] is a non-const member and would be a formal
        // data race against caller-thread sessionSendable/isSessionLive readers holding
        // a shared_lock (the sid always pre-exists here, so find never misses).
        auto sit = _sessions.find(sid);
        if (sit == _sessions.end())
        {
          continue; // defensive: never expected (sid just inserted / in _peerIndex)
        }
        sit->second->lastActivity = MonoClock::now();
        invokeUserCallback(copyCallback(_cbMutex, _cbs.onData), sid,
                           iora::core::BufferView{buf.data(), static_cast<std::size_t>(n)},
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
        _atomicStats.bytesOut.fetch_add(n, std::memory_order_relaxed);
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
    {
      ev |= EPOLLET;
    }
    if (lst->wantWrite && !lst->wq.empty())
    {
      ev |= EPOLLOUT;
    }
    modEpoll(lst->fd, ev);
  }

  /// \brief True iff host is a numeric IPv4/IPv6 literal (no DNS needed).
  static bool isIpLiteral(const std::string &host)
  {
    struct in_addr a4;
    struct in6_addr a6;
    return ::inet_pton(AF_INET, host.c_str(), &a4) == 1 ||
           ::inet_pton(AF_INET6, host.c_str(), &a6) == 1;
  }

  /// \brief Build the resolver continuation (runs on a blockingIoPool thread).
  /// Captures a shared_ptr copy of the post gate + the sid's resume action; it
  /// builds the resume closure OUTSIDE gate->m, then posts it onto the I/O thread
  /// iff the gate is still open (#4/#5/#8/#14). NO user callback runs under
  /// gate->m; runOnIoThread is noexcept/callback-free. The connect-vs-via resume
  /// path is encoded in \p onResolved.
  std::function<void(iora::network::ResolveResult)> makeResolveContinuation(
    std::function<void(std::shared_ptr<iora::network::OwnedAddrInfo>, int)> onResolved)
  {
    auto gate = _postGuard; // shared_ptr copy — keeps the gate alive
    return [gate, onResolved = std::move(onResolved)](iora::network::ResolveResult r)
    {
      // Built OUTSIDE gate->m; on bad_alloc here r (and its addrs) frees on
      // unwind and the resolve-deadline GC scan backstops the terminal (#16).
      std::function<void()> resume =
        [onResolved, addrs = r.addrs, gai = r.gaiCode] { onResolved(addrs, gai); };
      std::lock_guard<std::mutex> g(gate->m);
      if (gate->closed)
      {
        return; // engine torn down: drop; addrs frees when r/resume drop
      }
      gate->engine->runOnIoThread(std::move(resume));
    };
  }

  /// \brief Resolve a LITERAL-IP host synchronously into \p out (numeric
  /// getaddrinfo returns immediately, no DNS). Shared by connectDo/viaDo. On
  /// failure fires onClose(Resolve) + error and returns false. The caller owns
  /// \p out (connectFromAddrs/viaFromAddrs never free). AI_NUMERICHOST|
  /// AI_NUMERICSERV makes the "never block the I/O thread on ::getaddrinfo"
  /// guarantee defensive-by-construction (sip-voip L-1; simpl L1).
  bool resolveLiteralSync(const std::string &host, const std::string &port, SessionId sid,
                          iora::network::OwnedAddrInfo &out)
  {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    addrinfo *res = nullptr;
    const int rc = ::getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
    out = iora::network::OwnedAddrInfo(res);
    if (rc != 0 || !res)
    {
      // rc==0 with a null chain is defensive; gai_strerror(0)="Success" would
      // mislead, so use a fixed string for it (cpp17-#2, mirrors sip-L-4).
      const std::string msg = (rc != 0) ? std::string("getaddrinfo: ") + gai_strerror(rc)
                                        : "resolve returned no addresses";
      // A3.1a: fire the ONE pre-insert terminal (erase _connecting -> onClose(Resolve))
      // through preInsertTerminal so a racing observe() cannot see the sid live after
      // its onClose (A2.1). error()/onError is kept as a SEPARATE diagnostic channel
      // (the uniform policy across all four resolve/connect terminals). Shared by
      // connectDo AND viaDo — both have the sid in _connecting.
      preInsertTerminal(sid, TransportErrorInfo{TransportError::Resolve, msg});
      error(TransportError::Resolve, "getaddrinfo failed");
      return false;
    }
    return true;
  }

  /// \brief Fire the single terminal for a FAILED named-host resolve (I/O
  /// thread): compute the operator-facing message, then copy-then-invoke onClose
  /// (Resolve) outside _cbMutex + error(). Shared by resumeConnect/resumeVia
  /// (simpl R2-L3). gai==0 with a null/empty chain is defensive (getaddrinfo
  /// returns an EAI_* code with a null chain), so a fixed string replaces
  /// resolveErrorMessage(0)="Success" there (sip-L-4).
  void emitResolveFailure(SessionId sid, int gai)
  {
    const std::string msg =
      (gai != 0) ? iora::network::resolveErrorMessage(gai) : "resolve returned no addresses";
    // A3.1a: resumeConnect/resumeVia have already erased _pendingConnects (moving any
    // buffered wq out), so takePending finds nothing here — eraseConnecting fires the
    // ONE terminal. error() is kept as the separate diagnostic channel.
    preInsertTerminal(sid, TransportErrorInfo{TransportError::Resolve, msg});
    error(TransportError::Resolve, std::string("resolve failed: ") + msg);
  }

  /// \brief Named-host resolve hints (AF_UNSPEC UDP). AI_ADDRCONFIG: on an
  /// IPv4-only host, do NOT return AAAA for a dual-stack FQDN, otherwise the
  /// single-address terminal-on-failure connect hits ENETUNREACH on the AAAA
  /// without trying the reachable A record (sip-voip M-1). Loopback is exempt in
  /// glibc, so localhost/ip6-localhost resolution is unaffected.
  static addrinfo namedResolveHints()
  {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_ADDRCONFIG;
    return hints;
  }

  /// \brief KICKOFF: literal-IP short-circuit stays synchronous; a named host is
  /// resolved OFF the I/O thread, event-driven, then resumed via resumeConnect.
  bool connectDo(const ConnectReq &cr)
  {
    std::string ps = std::to_string(cr.port);

    // Literal IP short-circuit — SYNCHRONOUS (no DNS).
    if (isIpLiteral(cr.host))
    {
      iora::network::OwnedAddrInfo owned;
      if (!resolveLiteralSync(cr.host, ps, cr.sid, owned))
      {
        return false;
      }
      testMaybeThrowAt(ConnectThrowPoint::BEFORE_INSERT_LITERAL);
      return connectFromAddrs(cr, owned.get());
    }

    // Named host: resolve OFF the I/O thread, EVENT-DRIVEN. Record the
    // single-owner pending entry with an absolute resolve-deadline (observed by
    // the runGc scan; UDP has no TimerService), then kick off the async resolve.
    addrinfo hints = namedResolveHints();
    PendingConnect pc;
    if (_config.resolveTimeout.count() > 0)
    {
      pc.resolveDeadline = MonoClock::now() + _config.resolveTimeout;
    }
    _pendingConnects[cr.sid] = pc;

    const SessionId sid = cr.sid;
    std::string host = cr.host;
    const std::uint16_t port = cr.port;
    resolveHostAsync(cr.host, ps, hints,
                     makeResolveContinuation(
                       [this, sid, host, port](std::shared_ptr<iora::network::OwnedAddrInfo> addrs,
                                               int gai)
                       { resumeConnect(sid, host, port, addrs, gai); }));
    return true;
  }

  /// \brief RESUME a named-host connect (I/O thread). Single-owner one-shot:
  /// connect ONLY if this call erased the pending entry.
  void resumeConnect(SessionId sid, const std::string &host, std::uint16_t port,
                     std::shared_ptr<iora::network::OwnedAddrInfo> addrs, int gai)
  {
    auto it = _pendingConnects.find(sid);
    if (it == _pendingConnects.end())
    {
      return; // resolve-timeout or close already fired the terminal
    }
    // A3.1b: MOVE the buffered datagrams out BEFORE erasing the pending entry, then
    // pass them to connectFromAddrs to replay in order at insert. On resolve failure
    // the moved-out buffer is simply dropped.
    std::deque<ByteBuffer> pendingWq = std::move(it->second.wq);
    _pendingConnects.erase(it);
    if (gai != 0 || !addrs || !addrs->get())
    {
      emitResolveFailure(sid, gai);
      return;
    }
    // A3.1c: the resume path runs inside a RunOnIo command whose process() catch does
    // NOT clean the _connecting entry — guard connectFromAddrs so a throw here fires
    // the ONE terminal instead of leaking the sid.
    withConnectGuard(sid,
                     [&]()
                     {
                       testMaybeThrowAt(ConnectThrowPoint::BEFORE_INSERT_RESUME);
                       connectFromAddrs(ConnectReq{sid, host, port}, addrs->get(),
                                        std::move(pendingWq));
                     });
  }

  /// \brief Connect using an EXTERNALLY-owned addrinfo chain. NEVER calls
  /// ::freeaddrinfo — the caller owns res (an OwnedAddrInfo for the literal path,
  /// a shared_ptr<OwnedAddrInfo> for the resume path); a free here would
  /// double-free (#6). Runs on the I/O thread. \p pendingWq carries datagrams
  /// buffered during a named-host resolve (empty on the literal path).
  bool connectFromAddrs(const ConnectReq &cr, addrinfo *res,
                        std::deque<ByteBuffer> pendingWq = {})
  {
    // Admission cap (tracker 2026-09-14-1): reject a new client connect() at the
    // aggregate session cap BEFORE materializing any fd/epoll/session — placing this
    // before the ::socket loop avoids leaking an fd / orphaning an uncounted session
    // on rejection (mirrors the earliest-check inbound and connectViaListener sites).
    // See sessionCapReached() for the shared-aggregate + I/O-thread-serialization notes.
    if (rejectAtSessionCap(cr.sid))
    {
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
    // Save errno from the connect loop. NO ::freeaddrinfo — the caller owns res
    // (#6, cpp17 H3).
    int connectErrno = errno;
    std::string connectErr = lastErr();
    if (sfd < 0)
    {
      // A3.1a: erase _connecting -> onClose(Connect) via the ONE terminal helper
      // (resumeConnect already erased _pendingConnects, so takePending is a no-op).
      // pendingWq destructs here, dropping the buffered datagrams. error() kept.
      preInsertTerminal(cr.sid, TransportErrorInfo{TransportError::Connect, connectErr, connectErrno});
      error(TransportError::Connect, "UDP connect: " + connectErr);
      return false;
    }
    // A3.1c: RAII-guard the connected fd until the _sessions insert commits, so a
    // throw on the make_unique/addEpoll/emplace path below cannot leak it. Released
    // (fd=-1) once _tags/_sessions own the fd.
    detail::FdCloser fdGuard(sfd, &_preCloseHook);
    // Apply the configured DSCP mark to the connected client socket at creation
    // (C1); 0 leaves default best-effort marking.
    if (_config.dscpValue != 0)
    {
      (void)applyDscpToFd(sfd, _config.dscpValue);
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
    {
      ev |= EPOLLET;
    }
    addEpoll(sfd, ev);
    Session *sPtr = s.get();
    {
      // A3.1a: erase _connecting WITH the _sessions insert in ONE unique-lock
      // section — the sid transitions from "connecting" to "live" atomically, so a
      // concurrent sessionSendable/isSessionLive never sees it in neither set.
      // ORDER (steps-4-8 R2 TS-H1, mirror tcp_engine :2789-2790): the THROWING
      // _sessions.emplace runs FIRST; the noexcept _connecting.erase(integral) runs
      // SECOND. If emplace throws (bad_alloc), _connecting stays populated so
      // withConnectGuard -> preInsertTerminal fires the ONE terminal (no lost
      // completion / observer leak). Erase-first would clear _connecting and then
      // never insert, leaving the guard with nothing to fire.
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      _sessions.emplace(s->id, std::move(s));
      _connecting.erase(cr.sid);
    }
    // A3.1c + steps-4-8 R1 TS-M2: disarm the fd guard the INSTANT the session owns
    // the fd (the _sessions.emplace above), BEFORE the allocating _tags insert. A
    // bad_alloc in make_unique<Tag>/_tags.emplace now unwinds through withConnectGuard
    // -> closeNow (sid is in _sessions) which closes the fd exactly ONCE; a late
    // disarm here would let fdGuard double-close it. Mirrors TCP's disarm placement.
    fdGuard.fd = -1;
    auto tag = std::make_unique<Tag>();
    tag->isListener = false;
    tag->sess = sPtr;
    _tags.emplace(sfd, std::move(tag));
    bumpSess();
    {
      _atomicStats.connected.fetch_add(1, std::memory_order_relaxed);
      // steps-4-8 R2 (simp/cpp17/TS): route onConnect through invokeUserCallback
      // (mirror tcp_engine) — a throwing onConnect is swallowed+logged and does NOT
      // propagate into withConnectGuard (which would spuriously tear the just-connected
      // session down, diverging from TCP).
      const auto connectCb = copyCallback(_cbMutex, _cbs.onConnect);
      if (connectCb)
      {
        sockaddr_storage peerSs{};
        socklen_t peerSl = sizeof(peerSs);
        TransportAddress peerAddr;
        if (::getpeername(sfd, reinterpret_cast<sockaddr *>(&peerSs), &peerSl) == 0)
        {
          peerAddr = addressFromSockaddr(peerSs);
        }
        invokeUserCallback(connectCb, cr.sid, peerAddr);
      }
    }
    // A3.1b: replay datagrams buffered during the resolve window, in order, through
    // the role-correct send path (replaying via sendDo — rather than moving raw bytes
    // into s->wq — also attempts an immediate ::send and routes the ServerPeer twin
    // to its listener queue).
    replayPendingWq(cr.sid, pendingWq);
    return true;
  }

  /// \brief KICKOFF (connectViaListener, SESSION-CREATION — NOT a per-datagram
  /// send): literal-IP short-circuit stays synchronous; a named host is resolved
  /// OFF the I/O thread, then resumed via resumeVia. The listener is RE-LOOKED-UP
  /// and the AF-match done at RESUME against the listener's CURRENT AF (avoids a
  /// kickoff-snapshot TOCTOU on a listener rebind). NO per-destination coalescing
  /// (this is one session per ViaReq).
  bool viaDo(const ViaReq &vr)
  {
    std::string ps = std::to_string(vr.port);

    // Literal IP short-circuit — SYNCHRONOUS (no DNS).
    if (isIpLiteral(vr.host))
    {
      iora::network::OwnedAddrInfo owned;
      if (!resolveLiteralSync(vr.host, ps, vr.sid, owned))
      {
        return false;
      }
      return viaFromAddrs(vr.sid, vr.lid, owned.get());
    }

    // Named host: resolve OFF the I/O thread, reusing the connect-site
    // _pendingConnects single-owner one-shot machinery.
    addrinfo hints = namedResolveHints();
    PendingConnect pc;
    if (_config.resolveTimeout.count() > 0)
    {
      pc.resolveDeadline = MonoClock::now() + _config.resolveTimeout;
    }
    _pendingConnects[vr.sid] = pc;
    testMaybeThrowAt(ConnectThrowPoint::VIA_KICKOFF_AFTER_PENDING_INSERT);

    const SessionId sid = vr.sid;
    const ListenerId lid = vr.lid;
    resolveHostAsync(vr.host, ps, hints,
                     makeResolveContinuation(
                       [this, sid, lid](std::shared_ptr<iora::network::OwnedAddrInfo> addrs, int gai)
                       { resumeVia(sid, lid, addrs, gai); }));
    return true;
  }

  /// \brief RESUME a named-host via-listener connect (I/O thread). Single-owner
  /// one-shot: build the session ONLY if this call erased the pending entry.
  void resumeVia(SessionId sid, ListenerId lid,
                 std::shared_ptr<iora::network::OwnedAddrInfo> addrs, int gai)
  {
    auto it = _pendingConnects.find(sid);
    if (it == _pendingConnects.end())
    {
      return; // resolve-timeout or close already fired the terminal
    }
    // A3.1b: MOVE the buffered datagrams out BEFORE erasing the pending entry.
    std::deque<ByteBuffer> pendingWq = std::move(it->second.wq);
    _pendingConnects.erase(it);
    if (gai != 0 || !addrs || !addrs->get())
    {
      emitResolveFailure(sid, gai);
      return;
    }
    withConnectGuard(sid,
                     [&]()
                     {
                       testMaybeThrowAt(ConnectThrowPoint::BEFORE_INSERT_RESUME);
                       viaFromAddrs(sid, lid, addrs->get(), std::move(pendingWq));
                     });
  }

  /// \brief Create a via-listener peer session from an EXTERNALLY-owned addrinfo
  /// chain: RE-LOOK-UP the listener (lid), AF-match the resolved chain against
  /// the listener's CURRENT AF, then create the peer session on the LISTENER fd
  /// (source-port preserved, RFC 3581). NEVER calls ::freeaddrinfo — the caller
  /// owns res (#6). Every post-resolution terminal is a one-shot eraser-fire:
  /// listener-gone / AF-mismatch / session-cap -> onClose(Config); success ->
  /// onConnect. Runs on the I/O thread.
  bool viaFromAddrs(SessionId sid, ListenerId lid, addrinfo *res,
                    std::deque<ByteBuffer> pendingWq = {})
  {
    auto lit = _listeners.find(lid);
    if (lit == _listeners.end())
    {
      // A3.1a: route every via pre-insert terminal through preInsertTerminal (erase
      // _connecting -> onClose once); pendingWq destructs, dropping the buffer.
      preInsertTerminal(sid, TransportErrorInfo{TransportError::Config, "listener not found"});
      return false;
    }
    Listener *lst = lit->second.get();
    int af = sockAf(lst->fd);
    if (af != AF_INET && af != AF_INET6)
    {
      preInsertTerminal(sid,
                        TransportErrorInfo{TransportError::Config, "listener AF unknown/unsupported"});
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
      // NO ::freeaddrinfo — caller owns res (#6).
      std::string m = (af == AF_INET) ? "AF mismatch: listener IPv4, remote IPv6 only"
                                      : "AF mismatch: listener IPv6, remote IPv4 only";
      preInsertTerminal(sid, TransportErrorInfo{TransportError::Config, m});
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
    // NO ::freeaddrinfo — caller owns res (#6).
    std::string k = key(to);
    auto pit = _peerIndex.find(k);
    bool peerExists = (pit != _peerIndex.end());
    // Note: Even if peer exists, we must create a Session for the new SessionId.
    // This enables self-loopback (same address as listener) and multiple logical
    // connections to the same remote peer. The _peerIndex maps peer address to
    // ONE SessionId for incoming data dispatch; applications must demultiplex.
    if (rejectAtSessionCap(sid))
    {
      return false;
    }
    auto s = std::make_unique<Session>();
    s->id = sid;
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
      // A3.1a: erase _connecting WITH the _sessions insert in ONE unique-lock
      // section (atomic connecting -> live transition; see connectFromAddrs). ORDER
      // (steps-4-8 R2 TS-H1): throwing emplace FIRST, noexcept erase SECOND, so a
      // bad_alloc leaves _connecting populated for the guard terminal.
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      _sessions.emplace(s->id, std::move(s));
      _connecting.erase(sid);
    }
    if (!peerExists)
    {
      _peerIndex.emplace(k, sid);
    }
    bumpSess();
    // steps-4-8 R2: onConnect via invokeUserCallback (see connectFromAddrs).
    invokeUserCallback(copyCallback(_cbMutex, _cbs.onConnect), sid, addressFromSockaddr(to));
    // A3.1b: replay datagrams buffered during the resolve window, in order (ServerPeer
    // -> ::sendto on the listener fd / the owning listener's write queue).
    replayPendingWq(sid, pendingWq);
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
          _atomicStats.bytesIn.fetch_add(n, std::memory_order_relaxed);
          s->lastActivity = MonoClock::now();
          // steps-4-8 R2 (simp/cpp17): onData via invokeUserCallback — a throwing
          // handler on the read path (onClient has NO outer try) would otherwise
          // std::terminate the process (mirror tcp_engine).
          invokeUserCallback(copyCallback(_cbMutex, _cbs.onData), s->id,
                             iora::core::BufferView{buf.data(), static_cast<std::size_t>(n)},
                             std::chrono::steady_clock::now());
          continue;
        }
        if (n == 0)
        {
          invokeUserCallback(copyCallback(_cbMutex, _cbs.onData), s->id,
                             iora::core::BufferView{nullptr, 0}, std::chrono::steady_clock::now());
          break;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
          break;
        }
        closeNow(s, TransportError::Socket, lastErr(), 0);
        return;
      }
    }
    if (events & EPOLLOUT)
    {
      writeClient(s);
    }
  }

  void writeClient(Session *s)
  {
    while (!s->wq.empty())
    {
      ByteBuffer &d = s->wq.front();
      int n = ::send(s->fd, d.data(), (int)d.size(), MSG_NOSIGNAL);
      if (n >= 0)
      {
        _atomicStats.bytesOut.fetch_add(n, std::memory_order_relaxed);
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
    {
      ev |= EPOLLET;
    }
    if (s->wantWrite && !s->wq.empty())
    {
      ev |= EPOLLOUT;
    }
    modEpoll(s->fd, ev);
  }

  void sendDo(SendReq &&sr)
  {
    auto it = _sessions.find(sr.sid);
    if (it == _sessions.end())
    {
      // A3.1b: the sid may be a named-host/Via connect still resolving (sendable via
      // _connecting, no Session yet). Buffer the datagram in its PendingConnect entry
      // to replay in order after insert. Overflow drops OLDEST but always keeps >=1
      // (unconditional pop_front — no Session exists, so no closeOnBackpressure path;
      // a UDP retransmit burst leaves >=1 deliverable, and RFC 3261 s17 retransmission
      // + peer server-transaction absorption recover a dropped pre-establishment copy).
      auto pit = _pendingConnects.find(sr.sid);
      if (pit != _pendingConnects.end())
      {
        pit->second.wq.emplace_back(std::move(sr.payload));
        while (pit->second.wq.size() > _config.maxWriteQueue && pit->second.wq.size() > 1)
        {
          pit->second.wq.pop_front();
        }
      }
      // A sid that passed sessionSendable (in _connecting) but is in NEITHER _sessions
      // NOR _pendingConnects does not occur on the normal FIFO path — Cmd::connect/
      // Cmd::via is dequeued (inserting the session for a literal host, or recording the
      // _pendingConnects entry for a named host) BEFORE any racing Cmd::send. It CAN
      // occur benignly on the connect-throw terminal path (steps-4-8 R2 sip-L1): send()
      // passes sessionSendable, connectDo/resume throws, withConnectGuard ->
      // preInsertTerminal -> eraseConnecting removes the entry before this queued
      // Cmd::send's sendDo runs -> the datagram is dropped here AFTER the session's ONE
      // terminal already fired (correct: it would be dropped regardless). Re-verify
      // before reordering command dispatch.
      return;
    }
    Session *s = it->second.get();
    if (s->closed.load(std::memory_order_relaxed))
      return;
    if (s->role == Role::ClientConnected)
    {
      int n = ::send(s->fd, sr.payload.data(), (int)sr.payload.size(), MSG_NOSIGNAL);
      if (n >= 0)
      {
        _atomicStats.bytesOut.fetch_add(n, std::memory_order_relaxed);
        s->lastActivity = MonoClock::now();
        s->lastWriteProgress = MonoClock::now();
        return;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        s->wq.emplace_back(std::move(sr.payload));
        if (s->wq.size() > _config.maxWriteQueue)
        {
          _atomicStats.backpressureCloses.fetch_add(1, std::memory_order_relaxed);
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
      _atomicStats.bytesOut.fetch_add(n, std::memory_order_relaxed);
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
        _atomicStats.backpressureCloses.fetch_add(1, std::memory_order_relaxed);
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
    if (!s || s->closed.load(std::memory_order_relaxed))
      return;
    // Save errno before system calls clobber it
    int savedErrno = errno;
    s->closed.store(true, std::memory_order_relaxed);

    // Save fields before erasing session from map
    SessionId sid = s->id;
    int fd = s->fd;
    Role role = s->role;
    std::string pkey = s->pkey;

    int fdToClose = -1;
    if (role == Role::ClientConnected)
    {
      delEpoll(fd);
      _tags.erase(fd);
      fdToClose = fd; // ::close AFTER the erase (fd-reuse fix, tracker 2026-09-15-3)
    }
    else
    {
      _peerIndex.erase(pkey); // ServerPeer: aliases the listener fd -- never close here
    }

    _atomicStats.closed.fetch_add(1, std::memory_order_relaxed);
    _atomicStats.sessionsCurrent.fetch_sub(1, std::memory_order_relaxed);

    // Remove from session map under write lock
    {
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      _sessions.erase(sid);
    }
    // s is now dangling — use only saved locals below.
    // fd-reuse fix (tracker 2026-09-15-3): ::close the ClientConnected fd only AFTER the
    // session is erased from the map, so a cross-thread getter holding the shared lock
    // cannot syscall on a closed/possibly-reused fd. A scoped detail::FdCloser (the single
    // close primitive shared with shutdownDrain) runs the pre-close seam + ::close here,
    // before the onClose callback below; fdToClose == -1 (ServerPeer) is a no-op.
    {
      detail::FdCloser closer(fdToClose, &_preCloseHook);
    }

    // steps-4-8 R2 (simp/cpp17): onClose via invokeUserCallback — closeNow is called
    // from the read/write/GC paths that have NO outer try, so a throwing onClose would
    // otherwise unwind the I/O loop and skip shutdownDrain (mirror tcp_engine).
    invokeUserCallback(copyCallback(_cbMutex, _cbs.onClose), sid,
                       TransportErrorInfo{why, m, savedErrno});
  }
  void runGc()
  {
    _atomicStats.gcRuns.fetch_add(1, std::memory_order_relaxed);
    const auto now = MonoClock::now();
    const bool age = _config.maxConnAge.count() > 0;
    std::vector<SessionId> to;
    to.reserve(_sessions.size());
    for (auto &kv : _sessions)
    {
      Session *s = kv.second.get();
      if (s->closed.load(std::memory_order_relaxed))
        continue;
      if (_config.idleTimeout.count() > 0 && (now - s->lastActivity) > _config.idleTimeout)
      {
        to.push_back(s->id);
        _atomicStats.gcClosedIdle.fetch_add(1, std::memory_order_relaxed);
        continue;
      }
      if (age && (now - s->created) > _config.maxConnAge)
      {
        to.push_back(s->id);
        _atomicStats.gcClosedAged.fetch_add(1, std::memory_order_relaxed);
        continue;
      }
      // NEW: safety-net connect timeout (mostly moot for UDP client)
      if (_config.connectTimeout.count() > 0 && s->connectPending &&
          (now - s->connectStart) > _config.connectTimeout)
      {
        to.push_back(s->id);
        continue;
      }
      // NEW: safety-net write stall (applies to client-connected sessions)
      if (_config.writeStallTimeout.count() > 0 && !s->wq.empty() &&
          (now - s->lastWriteProgress) > _config.writeStallTimeout)
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

    // Resolve-deadline scan (task-4.2): UDP has no TimerService, so a named-host
    // resolve-timeout is observed HERE, up to one gcInterval late (effective
    // window [resolveTimeout, resolveTimeout+gcInterval]). COLLECT-THEN-FIRE —
    // never erase _pendingConnects during iteration (#15).
    std::vector<SessionId> expiredResolves;
    for (auto &kv : _pendingConnects)
    {
      const MonoTime dl = kv.second.resolveDeadline;
      if (dl != MonoTime{} && now >= dl)
      {
        expiredResolves.push_back(kv.first);
      }
    }
    for (auto sid : expiredResolves)
    {
      resolveTimeoutOnIo(sid);
    }
  }

  /// \brief Resolve-timeout apply (I/O thread). One-shot eraser: fire
  /// onClose(Resolve) iff this call erased the entry.
  void resolveTimeoutOnIo(SessionId sid)
  {
    // A3.1a: erase _pendingConnects AND _connecting -> onClose(Resolve) via the ONE
    // terminal helper. preInsertTerminal returns false (fires nothing) if resume/close
    // already won the race and cleared both — in which case we skip error() too.
    if (preInsertTerminal(sid, TransportErrorInfo{TransportError::Resolve, "resolve timeout"}))
    {
      error(TransportError::Resolve, "resolve timeout");
    }
  }

  /// \brief True when the aggregate session cap is reached. Shared by all three
  /// session-creation paths (readFromListener inbound, connectFromAddrs client
  /// connect, viaFromAddrs connectViaListener). Race-free: sessionsCurrent is
  /// mutated ONLY on the I/O thread (bumpSess / the two fetch_sub decrements), and
  /// every caller of this predicate runs on the I/O thread — so the check-then-bump
  /// is serialized, not a TOCTOU. `relaxed` is the weakest correct order given the
  /// single-writer-thread confinement. The cap is a SHARED aggregate across all
  /// three paths, so sizing maxSessions must account for every path.
  bool sessionCapReached() const
  {
    return _config.maxSessions &&
           _atomicStats.sessionsCurrent.load(std::memory_order_relaxed) >= _config.maxSessions;
  }

  /// \brief Reject a pending session creation at the cap via a copy-then-invoke
  /// onClose(ResourceLimit). Returns true iff rejected (caller returns false).
  /// NOT used by readFromListener, which has no SessionId yet at rejection time and
  /// silently drops (`continue`) — it calls sessionCapReached() directly.
  bool rejectAtSessionCap(SessionId sid)
  {
    if (!sessionCapReached())
    {
      return false;
    }
    // A3.1a: erase _connecting -> onClose(ResourceLimit) via the ONE terminal helper
    // (both callers — connectFromAddrs, viaFromAddrs — hold a _connecting entry).
    preInsertTerminal(sid, TransportErrorInfo{TransportError::ResourceLimit, "session cap reached"});
    return true;
  }

  void bumpSess()
  {
    // relaxed: single-I/O-thread mutation (see sessionCapReached); matches the
    // fetch_sub decrement sites and the cap-check loads (thread-safety L-2).
    auto cur = _atomicStats.sessionsCurrent.fetch_add(1, std::memory_order_relaxed) + 1;
    auto pk = _atomicStats.sessionsPeak.load(std::memory_order_relaxed);
    while (cur > pk && !_atomicStats.sessionsPeak.compare_exchange_weak(pk, cur, std::memory_order_relaxed))
    {
    }
  }

  // Start-failure cleanup. Runs on the caller's thread DURING start(), BEFORE
  // the I/O loop thread is launched, so it is single-threaded w.r.t. the engine
  // and the _eventFd close here cannot race enqueue() — no _qmx needed (unlike
  // shutdownDrain's close, which races live enqueuers). DD-6.
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
  // _eventFd is the ONLY descriptor WRITTEN off the I/O thread (the enqueue()
  // wakeup ::write). That off-thread write and the shutdownDrain() ::close are
  // serialized under _qmx (see enqueue/shutdownDrain); it is created EFD_NONBLOCK
  // so the wakeup write held under _qmx is bounded and cannot block. The I/O
  // thread's own ::read of _eventFd in drainEvt() is NOT under _qmx — it is
  // I/O-thread-confined (same thread that closes it), so it cannot race. _timerFd
  // and _epollFd are likewise I/O-thread-confined (all accessors run on the loop
  // thread) and need no lock; do not add an off-thread accessor for any of them
  // without revisiting this invariant.
  int _epollFd{-1}, _eventFd{-1}, _timerFd{-1};
  std::thread _loop;
  // Deferred self-destruct deleter (delete-this-at-thread-end). Written/read
  // ONLY on the I/O thread (set pre-detach, run post-loop()); no synchronization.
  std::function<void()> _selfDestruct;
  // Lock ordering: _qmx, _cbMutex, _sessionRwMutex and _errorMutex are all
  // mutually-exclusive LEAVES — at most one is held at a time, never nested.
  // - _cbMutex protects callback copies (copy-then-invoke: acquired/released
  //   before any callback fires and before any _sessionRwMutex use).
  // - _sessionRwMutex protects session/listener maps AND the _connecting
  //   connecting-sid registry (shared for reads, unique for mutations).
  // - _qmx protects the command queue (_q) AND serializes the _eventFd wakeup-
  //   write (enqueue) against the _eventFd close (shutdownDrain), plus the
  //   _qClosed teardown flag. process() swaps _q out under _qmx then RELEASES
  //   before dispatching handlers, so command handlers never run with _qmx held.
  //   NEVER acquire another lock while holding _qmx.
  // - _errorMutex protects the sticky last-error string.
  //
  // CONNECT-THEN-SEND ORDER (A-ext): connect()/connectViaListener() take
  //   _sessionRwMutex(insert into _connecting) -> RELEASE -> _qmx(enqueue) in that
  //   SEQUENTIAL, never-co-held order; the send path takes _sessionRwMutex
  //   (sessionSendable/isSessionLive) then, released, _qmx (enqueue). Both engine
  //   leaves stay leaves. The external nesting is acyclic:
  //   - SipUdpTransport::_sessionMutex WRAPS both legs sequentially (getOrCreateSession
  //     calls connectViaListener then, released, sendSync) -> _sessionMutex ->
  //     _sessionRwMutex -> RELEASE -> _qmx. The engine fires every consumer callback
  //     (connectFromAddrs/viaFromAddrs onConnect, closeNow/preInsertTerminal onClose)
  //     AFTER releasing _sessionRwMutex, so there is NO _sessionRwMutex->_sessionMutex
  //     back-edge.
  //   - Transport observe(): SseServer::_mutex -> observerMutex -> _sessionRwMutex
  //     (isSessionLive) -> RELEASE -> _qmx (runOnIoThread). All acyclic; engine locks
  //     are leaves.
  std::mutex _cbMutex;
  detail::EngineBase::Callbacks _cbs{};

  mutable std::shared_mutex _sessionRwMutex;
  // Connecting-sid registry (guarded by _sessionRwMutex). A SINGLE unified set for
  // BOTH connect() and connectViaListener(): holds a sid from the moment either
  // enqueues its Cmd until the session is inserted into _sessions, OR a pre-insert
  // terminal fires (preInsertTerminal), OR the connect() call is still in flight.
  // sessionSendable()/isSessionLive() read exactly this one set so a connect()'d sid
  // is immediately sendable (its datagrams buffer in the PendingConnect entry until
  // the session materializes). Invariant (A2.1): the registry entry is cleared
  // happens-before its onClose dispatch, which is what makes observe() exactly-once.
  std::unordered_set<SessionId> _connecting;
  std::mutex _qmx;
  std::deque<Cmd> _q;
  // Set true under _qmx by shutdownDrain() once the I/O loop has exited and the
  // command queue is being torn down. enqueue() observes it under _qmx and
  // refuses to push (and skips the wakeup write) so no command is queued that
  // the (now-gone) loop will never process — see DD-5 in tracker 2026-06-14-1.
  bool _qClosed{false};
  std::unordered_map<ListenerId, std::unique_ptr<Listener>> _listeners;
  std::unordered_map<SessionId, std::unique_ptr<Session>> _sessions;
  std::unordered_map<std::string, SessionId> _peerIndex;
  std::unordered_map<int, std::unique_ptr<Tag>> _tags;
  // TEST-ONLY seam (tracker 2026-09-15-3): see testSetPreCloseHook. Empty in production;
  // installed before start(), then read-only on the I/O thread (no locking needed).
  std::function<void(int)> _preCloseHook;
  // Named-host connect/via awaiting off-thread resolution. I/O-THREAD-ONLY —
  // every mutation (connectDo/viaDo kickoff, resumeConnect/resumeVia,
  // resolveTimeoutOnIo via the GC scan, Close drain, shutdownDrain) runs on the
  // I/O loop thread, so no lock is taken.
  std::unordered_map<SessionId, PendingConnect> _pendingConnects;
  std::atomic<SessionId> _nextSessionId{1};
  std::atomic<ListenerId> _nextListenerId{1};

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