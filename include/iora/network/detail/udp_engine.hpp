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
#include <algorithm>
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
      // Block SIGPIPE on this I/O thread, as the FIRST action before any dispatch.
      // Defense-in-depth parity with TcpEngine: all sends here already pass MSG_NOSIGNAL
      // and UDP has no TLS/SSL write path, so there is no current SIGPIPE source -- but a
      // thread-directed SIGPIPE blocked here stays pending, is never unblocked/drained,
      // and is discarded at thread exit (library-safe, no process-wide disposition
      // change). A thread/child process created from an I/O-thread callback inherits this
      // blocked mask (survives exec), so reset SIGPIPE in a fork+exec child. (2026-09-25-17)
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

  /// \brief DP-SS1: mint a session id ONLY (no _connecting insert, no enqueue). See
  /// EngineBase::allocateSid. Not yet sendable until connectWith() (a premature send()
  /// is rejected, not dropped — trySend finds it in neither _sessions nor _connecting).
  SessionId allocateSid() override { return _nextSessionId++; }

  /// \brief DP-SS2: enqueue the connect for a caller-supplied \p sid (from
  /// allocateSid()) via the shared helper (insert _connecting -> release -> enqueue),
  /// with the single-shot guard (DP-SS6). Register-before-connect ordering + err XOR
  /// onClose (DP-SS3/DP-SS4). See EngineBase::connectWith.
  ConnectResult connectWith(SessionId sid, const std::string &host, std::uint16_t port,
                            TlsMode tls, const TlsClientOptions &opts) override
  {
    (void)opts; // UDP has no TLS; identity options are not applicable
    if (tls != TlsMode::None)
    {
      return ConnectResult::err(
        TransportErrorInfo{TransportError::Config, "TLS/DTLS not supported on UDP"});
    }
    return insertConnectingAndEnqueue(
      sid, [&] { return Cmd::connect(ConnectReq{sid, host, port}); },
      "connectWith: transport shutting down", /*checkInUse=*/true);
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
                                           const char *shuttingDownMsg, bool checkInUse = false)
  {
    // Defensive: reject the invalid-sid sentinel (0) on the connectWith path (checkInUse);
    // connect()/connectViaListener() mint via _nextSessionId (starts at 1) so it never fires.
    if (checkInUse && sid == 0)
    {
      return ConnectResult::err(TransportErrorInfo{TransportError::Unknown, "connectWith: invalid sid"});
    }
    bool inserted = false;
    bool inUse = false;
    try
    {
      Cmd cmd = buildCmd();
      {
        std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
        // DP-SS6 single-shot: connectWith() rejects a sid already connecting/known so
        // a second Via/Connect cannot double-enqueue. connect()/connectViaListener()
        // pass false (fresh sid cannot collide) — behaviour unchanged (DP-SS7).
        if (checkInUse && (_connecting.find(sid) != _connecting.end() ||
                           _sessions.find(sid) != _sessions.end()))
        {
          inUse = true;
        }
        else
        {
          _connecting.insert(sid);
          inserted = true;
        }
      }
      if (inUse)
      {
        return ConnectResult::err(
          TransportErrorInfo{TransportError::Unknown, "connectWith: sid already in use"});
      }
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
      // The rollback erases _connecting and fires NO onClose. This upholds DP-SS4
      // (err XOR onClose for a registered sid): via connectWith() the caller obtained
      // this sid from allocateSid() and MAY have registered against it BEFORE this call
      // (register-before-connect) — so an err-returned sid CAN have escaped to observer-
      // capable code. Correctness therefore rests not on "the sid escaped to nobody" but
      // on the XOR: no Connect Cmd was enqueued (enqueue returned false / threw before
      // push), so no doConnect and no onClose can ever fire for this sid; we return err
      // and the caller un-registers on err. (connect()/connectViaListener() pass
      // checkInUse=false and never hand out an err sid, so the guarantee holds a fortiori
      // for them.) See tcp connectEnqueue + EngineBase::connectWith for the twin wording.
      eraseConnecting(sid);
    }
    // FAILURE-CODE PARITY (documented, pre-split choice, now also on the connectWith
    // path): UDP folds every enqueue-false — closed queue OR a caught allocation throw —
    // to a single ShuttingDown, whereas TCP's connectEnqueue distinguishes ShuttingDown
    // (queue closed) from Unknown (caught throw). Both satisfy DP-SS4; a caller keying on
    // the exact code should not rely on cross-engine equality of the enqueue-fail code.
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
    // Outward presentation: unmap a v4-mapped listener bind (tracker 2026-10-04-2 DP1).
    return iora::network::unmappedAddressFromSockaddr(ss);
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
    // Wildcard-bind reply-source (tracker 2026-10-04-2): on a 0.0.0.0/:: bind getsockname
    // returns the wildcard, but 2026-10-03-1 captured the real per-session local in
    // Session::localSrc. Report it (with the bound port from getsockname), presented UNMAPPED.
    // The localSrc read is well-defined under this shared_lock: the only published-session
    // writer (adoptWildcardVia) publishes it under _sessionRwMutex unique_lock (DP6). Read
    // localSrc and the port in this ONE lock scope (no second acquisition — fd-reuse hazard,
    // tracker 2026-09-15-3). AF_UNSPEC (specific bind / unadopted via / non-unicast) falls through
    // to the (also unmapped) getsockname result, i.e. the wildcard = no pinned local (DP5). An
    // unknown/reaped sid returned {} above (not in _sessions, or backing fd gone).
    if (s->localSrc.family != AF_UNSPEC)
    {
      const std::uint16_t portNbo =
        (ss.ss_family == AF_INET6)
          ? reinterpret_cast<const sockaddr_in6 *>(&ss)->sin6_port
          : reinterpret_cast<const sockaddr_in *>(&ss)->sin_port;
      return iora::network::unmappedAddressFromSockaddr(sockaddrFromLocalSrc(s->localSrc, portNbo));
    }
    return iora::network::unmappedAddressFromSockaddr(ss);
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
  /// Composite peer-index key: "<lid>|<host:port>" for a specific bind (tracker 2026-10-02-3), or
  /// "<lid>|<local>|<host:port>" for a wildcard bind (tracker 2026-10-03-1 — <local> is the captured
  /// local dest, "" for a non-unicast arrival, or the "<via>" sentinel for an unadopted via). Keyed
  /// by (ListenerId, [localAddr,] peerAddr) so the SAME peer source ip:port reaching two of our
  /// listeners — or two of our local addresses on one wildcard listener — does NOT collapse to one
  /// session (cross-listener misrouting + wrong reply source port/IP). '|' never appears in numeric
  /// host:port output (IPv6 included), so the key is unambiguous. Builds directly into one buffer
  /// (no intermediate string on the inbound
  /// hot path). Returns EMPTY when getnameinfo fails, so callers test a single value and never
  /// index a degenerate "<lid>|" bucket that would collapse unrelated peers — with
  /// NI_NUMERICHOST|NI_NUMERICSERV on a valid AF_INET/AF_INET6 sockaddr this failure is
  /// effectively unreachable, so the empty-key drop/reject paths are DEFENSIVE (L-8 accepted
  /// as defensive 2026-10-03, no fault-injection seam).
  static std::string peerKey(ListenerId lid, const sockaddr_storage &ss,
                             const char *localSeg = nullptr)
  {
    char h[NI_MAXHOST]{}, sv[NI_MAXSERV]{};
    socklen_t sl = (ss.ss_family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    if (getnameinfo(reinterpret_cast<const sockaddr *>(&ss), sl, h, sizeof(h), sv, sizeof(sv),
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0)
    {
      return {};
    }
    std::string k = std::to_string(lid);
    k.push_back('|');
    // Wildcard binds (tracker 2026-10-03-1) carry the captured local-dest segment between the two
    // '|' so the SAME peer reaching two of our local IPs does not collapse: lid|<local>|host:port.
    // A nullptr localSeg (specific bind) keeps the original lid|host:port byte-for-byte. An EMPTY
    // localSeg (a non-unicast arrival on a wildcard bind) yields lid||host:port — distinct from
    // both the specific-bind key and the via sentinel, and never a via-adopt target. '<'/'>' and
    // '|' never appear in inet_ntop numeric output, so the via sentinel cannot collide.
    if (localSeg != nullptr)
    {
      k.append(localSeg);
      k.push_back('|');
    }
    k.append(h);
    k.push_back(':');
    k.append(sv);
    return k;
  }

  /// Sentinel local segment for a connectViaListener session on a WILDCARD bind that has not yet
  /// received a datagram (tracker 2026-10-03-1 DD5): its local dest is unknown until the first
  /// inbound adopts it. '<'/'>' cannot appear in inet_ntop output, so the key is collision-free.
  static constexpr const char *VIA_LOCAL_SENTINEL = "<via>";

  /// Captured local destination address for wildcard-bind reply-source selection (RFC 3581 §4,
  /// tracker 2026-10-03-1). family == AF_UNSPEC means "send unpinned" (specific bind, multicast/
  /// broadcast dest, unadopted via, or no/truncated cmsg). Trivially copyable so it rides in OutDg
  /// and the purge-by-sid remove_if without special handling.
  // NOTE: in_pktinfo / in6_pktinfo (used by classifyLocalSrc / udpSendTo below) require _GNU_SOURCE
  // in glibc; g++ predefines it, and this engine is already Linux-only (epoll/timerfd), so no #ifdef.
  struct LocalSrc
  {
    sa_family_t family{AF_UNSPEC};
    union
    {
      in_addr v4;
      in6_addr v6; // native v6 OR v4-mapped (::ffff:a.b.c.d) on a dual-stack socket
    } addr{};
  };
  // DD2 + the purge-by-sid remove_if (OutDg carries a LocalSrc) depend on trivial copyability.
  static_assert(std::is_trivially_copyable<LocalSrc>::value, "LocalSrc must be trivially copyable");

  /// Three-valued classifier verdict (tracker 2026-10-03-1 DD3/M-A): a DROP (absent/truncated
  /// cmsg) must NOT be confused with a valid-but-unpinned non-unicast arrival.
  enum class LocalSrcVerdict
  {
    PINNED,
    UNPINNED_NON_UNICAST,
    DROP
  };
  struct LocalSrcResult
  {
    LocalSrcVerdict verdict{LocalSrcVerdict::DROP};
    LocalSrc src{};
  };

  /// A v4 arrival is non-unicast (no valid reply source) if the header dest is multicast or the
  /// limited broadcast, OR differs from ipi_spec_dst — the last clause catches subnet-directed
  /// broadcast, since the kernel sets ipi_spec_dst == ipi_addr only for a local-unicast delivery
  /// (fib_compute_spec_dst / RTCF_LOCAL). Byte-order-correct (tracker 2026-10-03-1 LOW-1).
  static bool isNonUnicastV4(const in_pktinfo &pi)
  {
    return IN_MULTICAST(ntohl(pi.ipi_addr.s_addr)) ||
           pi.ipi_addr.s_addr == htonl(INADDR_BROADCAST) ||
           pi.ipi_addr.s_addr != pi.ipi_spec_dst.s_addr;
  }

  static in6_addr v4MappedV6(in_addr v4)
  {
    in6_addr out{};
    out.s6_addr[10] = 0xff;
    out.s6_addr[11] = 0xff;
    std::memcpy(&out.s6_addr[12], &v4.s_addr, sizeof(v4.s_addr));
    return out;
  }

  /// Numeric text of a captured local for the peer-index key, written into \p out (inet_ntop only —
  /// never getnameinfo; never emits '<'/'>'/'|'). A stack buffer, NOT a std::string, so the inbound
  /// hot path makes no heap allocation per datagram (a v4-mapped/v6 literal exceeds SSO). Empty on
  /// AF_UNSPEC. CANONICAL FORM (tracker 2026-10-03-1 DD4): a v4-mapped local renders as
  /// "::ffff:a.b.c.d" — this exact spelling is the key form that sibling 2026-10-03-2 (dual-stack
  /// ::→IPv4 origination) MUST match so the two tasks' keys interoperate.
  static void localToText(const LocalSrc &ls, char (&out)[INET6_ADDRSTRLEN])
  {
    out[0] = '\0';
    if (ls.family == AF_INET)
    {
      ::inet_ntop(AF_INET, &ls.addr.v4, out, INET6_ADDRSTRLEN);
    }
    else if (ls.family == AF_INET6)
    {
      ::inet_ntop(AF_INET6, &ls.addr.v6, out, INET6_ADDRSTRLEN);
    }
  }

  /// PURE classification of a received datagram's local destination from its control messages
  /// (tracker 2026-10-03-1 DD3; static + msghdr-driven so it is unit-testable with synthesized
  /// cmsgs). sockFamily is the LISTENER socket family. DROP when the required pktinfo cmsg is
  /// absent/truncated (never route such a datagram); UNPINNED_NON_UNICAST for a multicast/
  /// broadcast dest; PINNED with the local unicast source otherwise. On a dual-stack AF_INET6
  /// socket a v4 arrival is sourced from IP_PKTINFO.ipi_spec_dst (stored v4-mapped) — NEVER from
  /// IPV6_PKTINFO.ipi6_addr (that is the mapped HEADER dest a directed broadcast would poison); a
  /// v4-mapped IPV6_PKTINFO with no IP_PKTINFO is therefore a DROP, not a fallback (LOW-2).
  static LocalSrcResult classifyLocalSrc(int sockFamily, msghdr &msg)
  {
    if ((msg.msg_flags & MSG_CTRUNC) != 0)
    {
      return {LocalSrcVerdict::DROP, {}};
    }
    bool have4 = false, have6 = false;
    in_pktinfo pi4{};
    in6_pktinfo pi6{};
    for (cmsghdr *c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c))
    {
      if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO)
      {
        std::memcpy(&pi4, CMSG_DATA(c), sizeof(pi4));
        have4 = true;
      }
      else if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO)
      {
        std::memcpy(&pi6, CMSG_DATA(c), sizeof(pi6));
        have6 = true;
      }
    }
    if (sockFamily == AF_INET)
    {
      if (!have4)
      {
        return {LocalSrcVerdict::DROP, {}};
      }
      if (isNonUnicastV4(pi4))
      {
        return {LocalSrcVerdict::UNPINNED_NON_UNICAST, {}};
      }
      LocalSrc s;
      s.family = AF_INET;
      s.addr.v4 = pi4.ipi_spec_dst;
      return {LocalSrcVerdict::PINNED, s};
    }
    // AF_INET6 listener (possibly dual-stack): a v4 arrival is identified by an IP_PKTINFO cmsg.
    if (have4)
    {
      if (isNonUnicastV4(pi4))
      {
        return {LocalSrcVerdict::UNPINNED_NON_UNICAST, {}};
      }
      LocalSrc s;
      s.family = AF_INET6;
      s.addr.v6 = v4MappedV6(pi4.ipi_spec_dst);
      return {LocalSrcVerdict::PINNED, s};
    }
    if (!have6)
    {
      return {LocalSrcVerdict::DROP, {}};
    }
    if (IN6_IS_ADDR_V4MAPPED(&pi6.ipi6_addr))
    {
      // v4 arrival but IP_PKTINFO absent: ipi6_addr is the mapped HEADER dest, not a trustworthy
      // local source — DROP rather than fall back (LOW-2; unreachable once addListenerDo's checked
      // IP_PKTINFO setsockopt succeeds on a dual-stack socket).
      return {LocalSrcVerdict::DROP, {}};
    }
    if (IN6_IS_ADDR_MULTICAST(&pi6.ipi6_addr))
    {
      return {LocalSrcVerdict::UNPINNED_NON_UNICAST, {}};
    }
    LocalSrc s;
    s.family = AF_INET6;
    s.addr.v6 = pi6.ipi6_addr;
    return {LocalSrcVerdict::PINNED, s};
  }

  /// Send on an unconnected UDP fd, selecting the reply SOURCE address when \p ls is pinned
  /// (tracker 2026-10-03-1 DD6). ifindex is left 0 (L-D: echoing the received ifindex pins egress
  /// and breaks policy routing; the dest's sin6_scope_id still supplies the oif for a link-local
  /// peer). AF_UNSPEC → plain ::sendto (specific binds / non-unicast / unadopted via).
  static ssize_t udpSendTo(int fd, const void *data, std::size_t len, const sockaddr *to,
                           socklen_t tolen, const LocalSrc &ls)
  {
    if (ls.family == AF_UNSPEC)
    {
      return ::sendto(fd, data, len, MSG_NOSIGNAL, to, tolen);
    }
    msghdr msg{};
    iovec iov{};
    iov.iov_base = const_cast<void *>(data);
    iov.iov_len = len;
    msg.msg_name = const_cast<sockaddr *>(to);
    msg.msg_namelen = tolen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    union
    {
      cmsghdr align;
      std::uint8_t buf[CMSG_SPACE(sizeof(in6_pktinfo))];
    } control;
    // Zero the WHOLE control buffer (value-init of a union only inits the first member, leaving the
    // CMSG_SPACE padding uninitialized → valgrind flags sendmsg; cpp17 L3). memset covers all bytes.
    std::memset(&control, 0, sizeof(control));
    msg.msg_control = control.buf;
    if (ls.family == AF_INET)
    {
      msg.msg_controllen = CMSG_SPACE(sizeof(in_pktinfo));
      cmsghdr *c = CMSG_FIRSTHDR(&msg);
      c->cmsg_level = IPPROTO_IP;
      c->cmsg_type = IP_PKTINFO;
      c->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
      in_pktinfo pi{};
      pi.ipi_spec_dst = ls.addr.v4; // ipi_ifindex = 0
      std::memcpy(CMSG_DATA(c), &pi, sizeof(pi));
    }
    else
    {
      msg.msg_controllen = CMSG_SPACE(sizeof(in6_pktinfo));
      cmsghdr *c = CMSG_FIRSTHDR(&msg);
      c->cmsg_level = IPPROTO_IPV6;
      c->cmsg_type = IPV6_PKTINFO;
      c->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
      in6_pktinfo pi{};
      pi.ipi6_addr = ls.addr.v6; // ipi6_ifindex = 0
      std::memcpy(CMSG_DATA(c), &pi, sizeof(pi));
    }
    return ::sendmsg(fd, &msg, MSG_NOSIGNAL);
  }

  /// Forwards to the shared iora::network::addressFromSockaddr. This was a
  /// private copy identical to tcp_engine's; both are retired in favour of the
  /// one public implementation (a third consumer could not reach either).
  static TransportAddress addressFromSockaddr(const sockaddr_storage &ss)
  {
    return iora::network::addressFromSockaddr(ss);
  }

  /// Build a sockaddr_storage from a captured LocalSrc plus a network-order port, for the
  /// getLocalAddress captured-local branch (tracker 2026-10-04-2). A v4-mapped LocalSrc (a
  /// dual-stack v4 arrival, classifyLocalSrc) stays mapped here and is unmapped for
  /// presentation by iora::network::unmappedAddressFromSockaddr (sockaddr_utils.hpp — the
  /// shared outward-presentation helper). AF_UNSPEC yields a zeroed storage (unused — the
  /// caller only reaches this when family != AF_UNSPEC).
  static sockaddr_storage sockaddrFromLocalSrc(const LocalSrc &ls, std::uint16_t portNbo)
  {
    sockaddr_storage ss{};
    if (ls.family == AF_INET)
    {
      auto *sa4 = reinterpret_cast<sockaddr_in *>(&ss);
      sa4->sin_family = AF_INET;
      sa4->sin_port = portNbo;
      sa4->sin_addr = ls.addr.v4;
    }
    else if (ls.family == AF_INET6)
    {
      auto *sa6 = reinterpret_cast<sockaddr_in6 *>(&ss);
      sa6->sin6_family = AF_INET6;
      sa6->sin6_port = portNbo;
      sa6->sin6_addr = ls.addr.v6;
    }
    return ss;
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

  /// Test seam (tracker 2026-09-25-16): when set to a session id, that session's send
  /// path simulates EAGAIN at EVERY send site (sendDo client/listener, writeClient,
  /// flushListener) WITHOUT a syscall, so a deterministic write-queue overflow can be
  /// driven host-independently (native-Linux loopback UDP never EAGAINs: loopback_xmit
  /// skb_orphan()s the skb, releasing the sender's SO_SNDBUF accounting in-syscall).
  /// Arm it BEFORE the test-thread send burst (the enqueue()/_qmx -> process()/_qmx edge
  /// publishes it to the I/O thread), so relaxed is sufficient; 0 == disarmed. Session-
  /// scoped (not engine-wide) so the fixture's auto-echo on other sessions is unaffected.
  std::atomic<SessionId> _testForceEagainSid{0};

  /// \brief Test seam: true iff \p sid is the armed forced-EAGAIN session; sets errno=EAGAIN.
  /// The caller MUST use this to REPLACE the ::send/::sendto (never after it) — otherwise
  /// the datagram would be both sent AND queued (double delivery).
  bool testForceEagain(SessionId sid)
  {
    // sid != 0 guard: 0 is the disarmed sentinel AND the default OutDg/Session sid, so an
    // untagged datagram must never be held (would hang in production under a stale arm).
    if (sid != 0 && _testForceEagainSid.load(std::memory_order_relaxed) == sid)
    {
      errno = EAGAIN;
      return true;
    }
    return false;
  }

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
    // Owning session (tracker 2026-09-25-16 H-2): the SHARED listener queue holds
    // datagrams from every ServerPeer on the listener, so purge-on-close and the
    // per-session forced-EAGAIN seam key on the owner sid, NOT the peer address
    // (several logical sessions may share one peer address).
    SessionId sid{};
    // Reply source for a wildcard-bind send (tracker 2026-10-03-1 DD2): SNAPSHOTTED from the
    // session at enqueue (not looked up by sid at flush) because an adopt can change the session's
    // local between enqueue and flush, and it avoids an _sessions lookup per flushed datagram.
    LocalSrc localSrc{};
  };
  struct Listener
  {
    ListenerId id{};
    int fd{-1};
    std::string bind;
    std::deque<OutDg> wq;
    bool wantWrite{false};
    // Wildcard bind (0.0.0.0 / ::) → IP_PKTINFO capture is on and the peer-index key carries the
    // captured local segment (tracker 2026-10-03-1 DD1). sockFamily is the listener socket's AF
    // (AF_INET / AF_INET6), used by classifyLocalSrc to pick the pktinfo field.
    bool wildcard{false};
    int sockFamily{AF_UNSPEC};
    // Last successful ::sendto on this listener's shared fd (L-8, tracker 2026-09-25-16).
    // The shared write queue stalls as a UNIT, so the write-stall backstop keys on this
    // per-listener clock (not per-session), and reclaims the owner of the front (blocking)
    // datagram. Seeded at creation so a never-draining listener is reclaimed after one
    // writeStallTimeout, not immediately.
    MonoTime lastWriteProgress{};
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
    // Captured local destination for wildcard-bind reply-source selection (tracker 2026-10-03-1).
    // Set at inbound capture and at via-adopt; AF_UNSPEC = send unpinned.
    // THREAD-SAFETY (tracker 2026-10-04-2 DP6): single writer = the I/O thread. A write to a
    // PUBLISHED session (present in _sessions) MUST hold _sessionRwMutex unique (adoptWildcardVia);
    // a pre-publish write (the fresh-ServerPeer path below, before the publishing emplace) needs no
    // lock; I/O-thread reads are lock-free; an OFF-THREAD read (getLocalAddress) holds
    // _sessionRwMutex shared. (Was "I/O-thread-only (DD10)" until getLocalAddress gained a
    // caller-thread read.)
    LocalSrc localSrc{};
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
    // ClientConnected-only write-stall clock (drives the runGc per-session write-stall check
    // against s->wq). A ServerPeer's pending datagrams live in the SHARED listener queue, so
    // its stall clock is Listener::lastWriteProgress, NOT this field (simpl L-1).
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
        // ServerPeer: aliases the listener fd -- never close here. No per-session peer-index
        // erase here: shutdownDrain closes EVERY session, so _peerIndex is cleared wholesale
        // after the loop (below) -- correct and avoids an O(N^2) per-session twin-list scan
        // during teardown (tracker 2026-10-02-3).
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
    // All sessions are now closed; drop the peer index wholesale (tracker 2026-10-02-3).
    // _peerIndex is I/O-thread-only state, so it needs no lock here.
    _peerIndex.clear();

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
    bool wildcard = false; // 0.0.0.0 / :: / ::ffff:0.0.0.0 — drives pktinfo capture (DD1)
    int sockFamily = AF_UNSPEC;
    in6_addr t6{};
    if (::inet_pton(AF_INET6, lc.addr.c_str(), &t6) == 1)
    {
      sockFamily = AF_INET6;
      wildcard = IN6_IS_ADDR_UNSPECIFIED(&t6) ||
                 (IN6_IS_ADDR_V4MAPPED(&t6) && std::memcmp(&t6.s6_addr[12], "\0\0\0\0", 4) == 0);
      sfd = ::socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      if (sfd < 0)
      {
        error(TransportError::Socket, "socket v6: " + lastErr());
        return false;
      }
      int v6only = 0;
      // LOW-4 (tracker 2026-10-03-1): a silent V6ONLY=0 failure disables dual-stack (v4 never
      // reaches the listener), which also breaks v4-mapped source capture — fail the listener.
      if (::setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) < 0)
      {
        error(TransportError::Socket, "setsockopt IPV6_V6ONLY: " + lastErr());
        ::close(sfd);
        return false;
      }
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
      sockFamily = AF_INET;
      wildcard = (t4.s_addr == htonl(INADDR_ANY));
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
    // RFC 3581 §4 address-half (tracker 2026-10-03-1 DD1): on a WILDCARD bind, enable per-datagram
    // local-destination delivery so replies can egress from the address the request arrived on. A
    // specific bind sets nothing (its source is already pinned by the bind). The setsockopt calls
    // are CHECKED — a silent failure plus the drop-on-missing-cmsg rule would black-hole the
    // listener (M-4). On a dual-stack v6 socket IP_PKTINFO is also set so IPv4 arrivals deliver an
    // IP_PKTINFO cmsg (classifyLocalSrc prefers it over the mapped IPV6_PKTINFO header dest).
    if (wildcard)
    {
      int on = 1;
      bool ok = true;
      if (sockFamily == AF_INET6)
      {
        ok = ::setsockopt(sfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) == 0 &&
             ::setsockopt(sfd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) == 0;
      }
      else
      {
        ok = ::setsockopt(sfd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) == 0;
      }
      if (!ok)
      {
        error(TransportError::Socket, "setsockopt PKTINFO: " + lastErr());
        ::close(sfd);
        return false;
      }
    }
    auto lst = std::make_unique<Listener>();
    lst->id = lc.id;
    lst->fd = sfd;
    lst->bind = lc.addr + ":" + std::to_string(lc.port);
    lst->wildcard = wildcard;
    lst->sockFamily = sockFamily;
    lst->lastWriteProgress = MonoClock::now(); // seed the write-stall clock (L-8)
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

  /// Adopt a wildcard connectViaListener session onto the (listener,local,peer) key the first
  /// UNICAST inbound arrived on (tracker 2026-10-03-1 DD5). A via on a wildcard bind is inserted
  /// under the sentinel key lid|<via>|peer because its local dest is unknown until inbound. On an
  /// exact-key miss, if that sentinel bucket exists and is NON-EMPTY, move the WHOLE twin list onto
  /// \p newKey (preserving the twins-share-one-key contract), rewrite each twin's pkey + localSrc,
  /// and return its front() in \p outFront. Returns false (→ fresh accept) when there is nothing to
  /// adopt. EXCEPTION-SAFE: all allocation happens in step 1 before any mutation; after the
  /// operator[] rehash the ONLY throwing step is the _sessionRwMutex unique_lock acquisition, taken
  /// BEFORE dst.swap (tracker 2026-10-04-2 / TS L-1) — if lock() throws, only Step 2's empty dst
  /// bucket exists (the lazily-reclaimed "empty vector = miss" state); everything inside the locked
  /// section is noexcept (vector/string swap, map erase, trivially-copyable assign).
  /// Rewriting pkey is MANDATORY — closeNow erases _peerIndex by s->pkey, so a stale back-key would
  /// leave a dead sid at front() and black-hole the peer. The per-twin localSrc write is published
  /// under _sessionRwMutex unique_lock for the caller-thread getLocalAddress reader (DP6); all other
  /// adopt state (_peerIndex, the pkey back-key) is I/O-thread-only.
  bool adoptWildcardVia(ListenerId lid, const sockaddr_storage &peer, const std::string &newKey,
                        const LocalSrc &local, SessionId &outFront)
  {
    std::string sentinelKey = peerKey(lid, peer, VIA_LOCAL_SENTINEL);
    if (sentinelKey.empty())
    {
      return false;
    }
    auto sit = _peerIndex.find(sentinelKey);
    if (sit == _peerIndex.end() || sit->second.empty())
    {
      return false;
    }
    // Step 1 (may throw; NOTHING mutated yet): collect the twin Session*s and pre-build one pkey
    // string per twin so the noexcept step below only swaps.
    std::vector<Session *> sessions;
    std::vector<std::string> keyCopies;
    sessions.reserve(sit->second.size());
    keyCopies.reserve(sit->second.size());
    for (SessionId id : sit->second)
    {
      auto s = _sessions.find(id);
      if (s != _sessions.end())
      {
        sessions.push_back(s->second.get());
        keyCopies.push_back(newKey);
      }
    }
    // Step 2: create the destination bucket (may rehash — invalidates ITERATORS, not references).
    auto &dst = _peerIndex[newKey];
    // Step 3: re-find the sentinel bucket after the operator[] rehash.
    sit = _peerIndex.find(sentinelKey);
    if (sit == _peerIndex.end())
    {
      return false; // defensive: cannot happen (we just confirmed it)
    }
    // Step 4: publish the twin rewrites under _sessionRwMutex unique_lock so the caller-thread
    // getLocalAddress shared_lock read of localSrc is well-defined (tracker 2026-10-04-2 DP6).
    // Acquired BEFORE dst.swap (TS L-1): lock() is the last throwing step, and if it throws nothing
    // past Step 2 has mutated. Inside the lock everything is noexcept — on an exact miss dst is empty
    // so swap moves the twin list wholesale. _peerIndex mutation rides along under the leaf lock
    // (harmless; _peerIndex is otherwise I/O-thread-only). No callback runs under the lock.
    {
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      dst.swap(sit->second);
      _peerIndex.erase(sit);
      for (std::size_t i = 0; i < sessions.size(); ++i)
      {
        sessions[i]->pkey.swap(keyCopies[i]);
        sessions[i]->localSrc = local;
      }
    }
    // cpp17 L-1: step 1 only rewrote pkey for LIVE sids; drop any stale sid the swap carried over so
    // front() is always a live session (closeNow keeps _peerIndex↔_sessions consistent, so this is
    // defensive — but it makes the dst.empty() guard below genuinely reachable). remove_if is
    // noexcept here (no allocation); _sessions.find is a const lookup.
    dst.erase(std::remove_if(dst.begin(), dst.end(),
                             [this](SessionId id) { return _sessions.find(id) == _sessions.end(); }),
              dst.end());
    if (dst.empty())
    {
      _peerIndex.erase(newKey);
      return false;
    }
    outFront = dst.front();
    return true;
  }

  void readFromListener(Listener *lst)
  {
    // Hot path (tracker 2026-10-02-3 M-D): allocate the receive buffer ONCE per call, not per
    // datagram. recvmsg overwrites it each iteration and onData's BufferView is valid only for
    // the synchronous callback, so reuse is safe (mirrors tcp_engine).
    std::vector<std::uint8_t> buf(_config.ioReadChunk);
    // Hoist the recvmsg scaffolding beside buf (tracker 2026-10-03-1 DD8-9): on a wildcard bind we
    // read IP_PKTINFO/IPV6_PKTINFO (the local destination) alongside the datagram so the reply can
    // egress from it (RFC 3581 §4 address-half). The control buffer is aligned for cmsghdr and
    // sized for both pktinfo flavours (a dual-stack socket may deliver either).
    msghdr msg{};
    iovec iov{};
    union
    {
      cmsghdr align;
      std::uint8_t b[CMSG_SPACE(sizeof(in6_pktinfo)) + CMSG_SPACE(sizeof(in_pktinfo))];
    } control{};
    for (;;)
    {
      sockaddr_storage from{};
      iov.iov_base = buf.data();
      iov.iov_len = buf.size();
      msg.msg_name = &from;
      msg.msg_namelen = sizeof(from);         // RESET per iteration (recvmsg overwrites it)
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;
      msg.msg_control = control.b;
      msg.msg_controllen = sizeof(control.b); // RESET per iteration
      msg.msg_flags = 0;
      ssize_t n = ::recvmsg(lst->fd, &msg, 0);
      if (n > 0)
      {
        // M-A (tracker 2026-10-02-3): a bad_alloc on the per-datagram create path must NOT
        // escape readFromListener. loopUnbatched has no try, so an escaped throw exits the I/O
        // loop WITHOUT running shutdownDrain -> the engine goes silently dead (no onClose).
        // State stays consistent (reserve-before-publish below), and an empty index slot left
        // by a mid-create throw is reclaimed lazily (the next datagram from this peer treats an
        // empty vector as a miss and reuses it), so dropping this datagram is safe.
        try
        {
          _atomicStats.bytesIn.fetch_add(n, std::memory_order_relaxed);
          // On a WILDCARD bind, capture the local destination so the reply egresses from it; a
          // specific bind has no pktinfo and keys/sends byte-identical to before (DD1/DD3/DD4).
          LocalSrc localSrc{};
          const char *localSeg = nullptr;
          char localBuf[INET6_ADDRSTRLEN]; // outlives localSeg's use below (peerKey + adopt)
          if (lst->wildcard)
          {
            LocalSrcResult lr = classifyLocalSrc(lst->sockFamily, msg);
            if (lr.verdict == LocalSrcVerdict::DROP)
            {
              continue; // absent/truncated pktinfo on a wildcard socket -> drop (defensive)
            }
            if (lr.verdict == LocalSrcVerdict::PINNED)
            {
              localSrc = lr.src;
              localToText(localSrc, localBuf);
              localSeg = localBuf; // wildcard PINNED -> lid|<local>|host:port
            }
            else
            {
              localSeg = ""; // UNPINNED_NON_UNICAST -> lid||host:port (unpinned reply, never adopts)
            }
          }
          std::string k = peerKey(lst->id, from, localSeg);
          if (k.empty())
          {
            continue; // unkeyable source (getnameinfo failed) -> drop (defensive; NI_NUMERIC*)
          }
          SessionId sid = 0;
          auto it = _peerIndex.find(k);
          if (it != _peerIndex.end() && !it->second.empty())
          {
            sid = it->second.front(); // exact (listener,local,peer) hit -> oldest surviving twin
          }
          else if (lst->wildcard && localSrc.family != AF_UNSPEC &&
                   adoptWildcardVia(lst->id, from, k, localSrc, sid))
          {
            // A wildcard via to this peer had no local yet; the first UNICAST inbound adopts the
            // whole twin list onto this (listener,local,peer) key (DD5) -> sid is the promoted
            // front, each twin's pkey + localSrc rewritten. Dispatch below.
          }
          else
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
            std::memcpy(&s->peer, &from, msg.msg_namelen);
            s->plen = msg.msg_namelen;
            s->pkey = k;
            s->localSrc = localSrc;
            s->created = MonoClock::now();
            s->lastActivity = s->created;
            s->lastWriteProgress = s->created;
            // Exception-safety (tracker 2026-10-02-3): take the (listener,peer) twin list and
            // reserve BEFORE publishing the session + bumping the counter, so the push_back
            // after the bump cannot throw (a throwing insert after the bump would, on the
            // closeNow unwind, fetch_sub an un-incremented sessionsCurrent and wrap it -> the
            // cap trips forever). Grow geometrically (L-6) so k twins cost O(k), not O(k^2).
            auto &vec = _peerIndex[k];
            if (vec.size() == vec.capacity())
            {
              vec.reserve(std::max<std::size_t>(4, vec.capacity() * 2));
            }
            {
              std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
              _sessions.emplace(sid, std::move(s));
            }
            bumpSess();
            vec.push_back(sid); // noexcept: spare capacity ensured above
            _atomicStats.accepted.fetch_add(1, std::memory_order_relaxed);
            // steps-4-8 R2 (simp/cpp17): route onAccept through invokeUserCallback so a
            // throwing user handler cannot unwind the I/O loop (mirror tcp_engine).
            invokeUserCallback(copyCallback(_cbMutex, _cbs.onAccept), sid,
                               addressFromSockaddr(from));
          }
          // steps-4-8 R3 (cpp17/TS LOW): use const find() (not non-const operator[]) on the
          // I/O thread — operator[] would be a formal data race vs caller-thread shared_lock
          // readers (the sid always pre-exists here, so find never misses).
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
        catch (...)
        {
          continue; // drop this datagram, keep the I/O loop alive (see M-A comment above)
        }
      }
      if (n < 0)
      {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          break;
        error(TransportError::Socket, "recvmsg: " + lastErr());
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
      // Seam (tracker 2026-09-25-16): a held datagram at the FRONT stalls the whole shared
      // queue (head-of-line), exactly as a real listener-socket EAGAIN would; datagrams
      // behind it drain only once it is gone. udpSendTo selects d.localSrc as the reply source on
      // a wildcard bind (RFC 3581 §4, tracker 2026-10-03-1 DD6); AF_UNSPEC → plain ::sendto.
      ssize_t n = testForceEagain(d.sid)
                    ? -1
                    : udpSendTo(lst->fd, d.payload.data(), d.payload.size(),
                                reinterpret_cast<sockaddr *>(&d.to), d.toLen, d.localSrc);
      if (n >= 0)
      {
        const auto now = MonoClock::now();
        _atomicStats.bytesOut.fetch_add(n, std::memory_order_relaxed);
        lst->lastWriteProgress = now; // per-listener write-stall clock (L-8)
        // Mirror the direct path (sip LOW-2): refresh the owning session's activity clock so a
        // backpressure-drained ServerPeer is not idle-reaped sooner than one that sent directly.
        auto sit = _sessions.find(d.sid);
        if (sit != _sessions.end())
        {
          sit->second->lastActivity = now;
        }
        lst->wq.pop_front();
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        lst->wantWrite = true;
        updateListener(lst);
        break;
      }
      // DD7 (tracker 2026-10-03-1): a PINNED-source send that fails (the source is no longer local —
      // VIP failover / addr removal) must CLOSE that session, not silently fall back to the kernel
      // source (which would recreate the asymmetry this task removes). Close on ANY non-EAGAIN error
      // from a pinned send — matching the direct path's close-on-non-EAGAIN (sip LOW-4 / cpp17 L4),
      // rather than enumerating errnos (EINVAL/EADDRNOTAVAIL for non-local; EHOSTUNREACH/EPERM also
      // possible). An UNPINNED send keeps the pre-existing error()+drop behavior. Copy sid + errno
      // BEFORE pop_front (which destroys d) — closeNow takes a Session* and purges that sid's other
      // datagrams by remove_if (invalidating deque refs), so nothing may touch d afterwards (M-1).
      int err = errno;
      SessionId sid = d.sid;
      bool pinned = d.localSrc.family != AF_UNSPEC;
      lst->wq.pop_front();
      errno = err;
      if (pinned)
      {
        auto sit = _sessions.find(sid);
        if (sit != _sessions.end())
        {
          closeNow(sit->second.get(), TransportError::Socket, lastErr(), 0);
        }
        continue;
      }
      error(TransportError::Socket, "sendto: " + lastErr());
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
  /// without trying the reachable A record (sip-voip M-1). NOTE: glibc does NOT
  /// count the loopback address toward AI_ADDRCONFIG, so on a host with a GLOBAL
  /// IPv6 address "localhost"/"ip6-localhost" DO resolve to ::1 first — a connected
  /// UDP socket to a dead ::1 even "connects"; the kernel later surfaces ICMP
  /// port-unreachable as ECONNREFUSED on send/recv, but this engine does not handle it,
  /// so the datagram's loss goes unreported (tracker 2026-09-25-15).
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
    // Use the cached listener family (set at addListenerDo) instead of a per-via getsockname
    // (simpl L-2): ListenerId↔fd is 1:1, so lst->sockFamily is authoritative.
    int af = lst->sockFamily;
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
    // On a WILDCARD bind the via's local dest is unknown until the first inbound adopts it, so key
    // it under the sentinel segment (tracker 2026-10-03-1 DD5); a specific bind keeps lid|host:port.
    // The via session's localSrc stays AF_UNSPEC (origination sends use the kernel source until
    // adoption — the HE follow-up pins originated requests).
    const char *viaLocalSeg = lst->wildcard ? VIA_LOCAL_SENTINEL : nullptr;
    std::string k = peerKey(lst->id, to, viaLocalSeg);
    if (k.empty())
    {
      // Unkeyable destination (getnameinfo failed): reject BEFORE the cap check, while
      // _connecting still holds this sid for the terminal (tracker 2026-10-02-3).
      preInsertTerminal(sid, TransportErrorInfo{TransportError::Config, "unkeyable peer address"});
      return false;
    }
    // _peerIndex is keyed by (listener, [local,] peer) and holds the twin SessionIds sharing that
    // key in insertion order; front() is the inbound-dispatch target. We still create a Session
    // for every SessionId (self-loopback + multiple logical sessions to one peer); a via to a
    // peer already indexed on ANOTHER listener now gets its OWN (listener,peer) entry rather
    // than silently sharing the first listener's (tracker 2026-10-02-3). Apps demultiplex.
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
    // Exception-safety (tracker 2026-10-02-3): reserve the twin-list slot BEFORE publishing +
    // bumping, so the push_back after the bump cannot throw (see readFromListener). Grow
    // geometrically (L-6) so k twins to one peer cost O(k), not O(k^2).
    auto &vec = _peerIndex[k];
    if (vec.size() == vec.capacity())
    {
      vec.reserve(std::max<std::size_t>(4, vec.capacity() * 2));
    }
    {
      // A3.1a: erase _connecting WITH the _sessions insert in ONE unique-lock
      // section (atomic connecting -> live transition; see connectFromAddrs). ORDER
      // (steps-4-8 R2 TS-H1): throwing emplace FIRST, noexcept erase SECOND, so a
      // bad_alloc leaves _connecting populated for the guard terminal.
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      _sessions.emplace(s->id, std::move(s));
      _connecting.erase(sid);
    }
    bumpSess();
    vec.push_back(sid); // noexcept: capacity reserved above
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
      // Hot path (tracker 2026-10-02-3 M-D): allocate the receive buffer ONCE per call, not per
      // datagram (the BufferView is valid only during the synchronous onData, so reuse is safe;
      // mirrors readFromListener / tcp_engine).
      std::vector<std::uint8_t> buf(_config.ioReadChunk);
      for (;;)
      {
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
      // Seam (tracker 2026-09-25-16): hold the drain too while this session is armed,
      // so a forced overflow is not silently emptied by the EPOLLOUT flush.
      int n = testForceEagain(s->id)
                ? -1
                : ::send(s->fd, d.data(), (int)d.size(), MSG_NOSIGNAL);
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

  // Overflow accounting shared by the client (s->wq) and listener (lst->wq) send paths.
  // Returns true if the session was CLOSED by overflow (caller must then return at once —
  // s is dangling). The backpressureCloses OVERFLOW counter is incremented ahead of the
  // close/drop choice in BOTH modes (stat_contract). In drop-oldest mode the front is
  // popped; on a SHARED listener queue that may be a DIFFERENT peer's oldest datagram
  // (documented victim policy, TransportConfig::closeOnBackpressure). In close mode there
  // is NO extra pop here — closeNow purges this session's datagrams by sid (M-1).
  template <typename Q> bool closedOnOverflow(Session *s, Q &q, const char *why)
  {
    if (q.size() <= _config.maxWriteQueue)
    {
      return false;
    }
    _atomicStats.backpressureCloses.fetch_add(1, std::memory_order_relaxed);
    if (_config.closeOnBackpressure)
    {
      closeNow(s, TransportError::WriteBackpressure, why, 0);
      return true;
    }
    q.pop_front();
    return false;
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
    {
      return;
    }
    if (s->role == Role::ClientConnected)
    {
      // M-5 (tracker 2026-09-25-16): send directly ONLY when nothing is queued ahead; a
      // direct ::send past a non-empty queue would overtake datagrams still awaiting the
      // EPOLLOUT drain. Otherwise fall through to enqueue (FIFO). testForceEagain is the
      // per-session seam; it REPLACES the syscall (never follows it), so no double send.
      if (s->wq.empty())
      {
        int n = testForceEagain(s->id)
                  ? -1
                  : ::send(s->fd, sr.payload.data(), (int)sr.payload.size(), MSG_NOSIGNAL);
        if (n >= 0)
        {
          const auto now = MonoClock::now();
          _atomicStats.bytesOut.fetch_add(n, std::memory_order_relaxed);
          s->lastActivity = now;
          s->lastWriteProgress = now;
          return;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
          closeNow(s, TransportError::Socket, lastErr(), 0);
          return;
        }
        // EAGAIN, empty->blocked: seed the stall clock NOW so an idle-then-blocked session
        // gets a full writeStallTimeout window rather than a reclaim at the next GC tick
        // (M-2/MEDIUM-1 A). The window measures time-since-blocked, not time-since-last-send.
        s->lastWriteProgress = MonoClock::now();
      }
      s->wq.emplace_back(std::move(sr.payload));
      if (closedOnOverflow(s, s->wq, "client write queue overflow"))
      {
        return;
      }
      s->wantWrite = true;
      updateClient(s);
      return;
    }
    auto lit = _listeners.find(s->owner);
    if (lit == _listeners.end())
    {
      closeNow(s, TransportError::Unknown, "listener gone", 0);
      return;
    }
    Listener *lst = lit->second.get();
    // M-5: same FIFO rule on the SHARED listener queue — direct send only when empty. On a wildcard
    // bind udpSendTo selects the captured local as the reply source (RFC 3581 §4); AF_UNSPEC → plain
    // ::sendto (tracker 2026-10-03-1 DD6). A source-not-local error is a non-EAGAIN error, so the
    // existing close-on-non-EAGAIN branch already closes the session (DD7).
    if (lst->wq.empty())
    {
      ssize_t n = testForceEagain(s->id)
                    ? -1
                    : udpSendTo(lst->fd, sr.payload.data(), sr.payload.size(),
                                reinterpret_cast<sockaddr *>(&s->peer), s->plen, s->localSrc);
      if (n >= 0)
      {
        const auto now = MonoClock::now();
        _atomicStats.bytesOut.fetch_add(n, std::memory_order_relaxed);
        s->lastActivity = now;
        // ServerPeers use the per-listener stall clock, NOT s->lastWriteProgress (simpl
        // L-1: that field is the ClientConnected-only stall clock and is never read here).
        lst->lastWriteProgress = now; // per-listener write-stall clock (L-8)
        return;
      }
      if (errno != EAGAIN && errno != EWOULDBLOCK)
      {
        closeNow(s, TransportError::Socket, lastErr(), 0);
        return;
      }
      // EAGAIN, empty->blocked: seed the per-listener stall clock NOW (M-2/MEDIUM-1 A).
      lst->lastWriteProgress = MonoClock::now();
    }
    OutDg d{};
    std::memcpy(&d.to, &s->peer, s->plen);
    d.toLen = s->plen;
    d.payload = std::move(sr.payload);
    d.sid = s->id;          // H-2: tag the owner for purge-by-sid on close
    d.localSrc = s->localSrc; // DD2/DD6: snapshot the reply source for the flush path
    lst->wq.emplace_back(std::move(d));
    // On a close-mode overflow closeNow purges this session's datagrams by sid (bounds the
    // shared queue; M-1 — no extra pop). The listener keeps EPOLLOUT armed from the prior
    // queued sends, so other peers still drain.
    if (closedOnOverflow(s, lst->wq, "listener write queue overflow"))
    {
      return;
    }
    lst->wantWrite = true;
    updateListener(lst);
  }

  void closeNow(Session *s, TransportError why, const std::string &m, int)
  {
    if (!s || s->closed.load(std::memory_order_relaxed))
    {
      return;
    }
    // Save errno before system calls clobber it
    int savedErrno = errno;
    s->closed.store(true, std::memory_order_relaxed);

    // Save fields before erasing session from map
    SessionId sid = s->id;
    int fd = s->fd;
    Role role = s->role;
    std::string pkey = s->pkey;
    ListenerId owner = s->owner;

    int fdToClose = -1;
    if (role == Role::ClientConnected)
    {
      delEpoll(fd);
      _tags.erase(fd);
      fdToClose = fd; // ::close AFTER the erase (fd-reuse fix, tracker 2026-09-15-3)
    }
    else
    {
      // ServerPeer: aliases the listener fd -- never close here.
      // Remove THIS sid from its (listener,peer) twin list; drop the whole entry when the list
      // empties (tracker 2026-10-02-3, F-6/L-5 — mirror of H-3). Erasing a non-front twin
      // leaves front() (the dispatch target) intact; erasing front() promotes the next-oldest
      // surviving twin with NO scan and NO spurious onAccept. Erase the map entry whenever the
      // vector is empty after the remove, whether or not sid was found (defensive/idempotent).
      // NOTE: a slot reserved-then-abandoned by a mid-create throw (readFromListener's catch /
      // viaFromAddrs via withConnectGuard) is NOT cleaned here (closeNow only runs for a
      // published session); it is reclaimed lazily — the next inbound datagram for that key
      // treats the empty vector as a miss and reuses it — or wholesale at shutdownDrain.
      auto pi = _peerIndex.find(pkey);
      if (pi != _peerIndex.end())
      {
        auto &vec = pi->second;
        vec.erase(std::remove(vec.begin(), vec.end(), sid), vec.end());
        if (vec.empty())
        {
          _peerIndex.erase(pi);
        }
      }
      // H-2/M-2 (tracker 2026-09-25-16): purge THIS session's datagrams from the SHARED
      // listener write queue BEFORE the session is erased — on EVERY ServerPeer close
      // path (backpressure/GC/explicit/socket), so nothing is sent to a closed session
      // and the shared queue stays bounded. Keyed by sid (NOT peer address) so sibling
      // sessions to the same peer are untouched. I/O-thread-only: lst->wq needs no lock.
      auto lit = _listeners.find(owner);
      if (lit != _listeners.end())
      {
        Listener *lst = lit->second.get();
        auto &wq = lst->wq;
        wq.erase(std::remove_if(wq.begin(), wq.end(),
                                [sid](const OutDg &dg) { return dg.sid == sid; }),
                 wq.end());
        // F-8: if the purge emptied the queue, disarm EPOLLOUT so we don't take one
        // spurious writable wake on a now-idle listener fd.
        if (wq.empty() && lst->wantWrite)
        {
          lst->wantWrite = false;
          updateListener(lst);
        }
      }
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
      // NEW: safety-net write stall (ClientConnected only: it owns s->wq, stamped on drain
      // by writeClient). ServerPeers share the per-listener queue and are handled by the
      // per-listener sweep below (L-8, tracker 2026-09-25-16).
      if (_config.writeStallTimeout.count() > 0 && !s->wq.empty() &&
          (now - s->lastWriteProgress) > _config.writeStallTimeout)
      {
        to.push_back(s->id);
        continue;
      }
    }
    // L-8 (tracker 2026-09-25-16): the SHARED listener write queue stalls as a UNIT. If a
    // listener has made no write progress for writeStallTimeout while its queue is
    // non-empty, reclaim the owner of the FRONT datagram — NOT every peer with a queued
    // datagram (that would false-close healthy sessions draining behind the front). NOTE:
    // on a real shared-socket EAGAIN the stall is socket-wide (SO_SNDBUF/qdisc), so this is
    // a VICTIM policy (reclaim the oldest-queued session), not culprit-finding — closing it
    // frees its queued datagrams but does not unwedge the socket. Re-seed the clock after a
    // reclaim so the NEXT head gets a full writeStallTimeout window, bounding closes to one
    // per writeStallTimeout rather than one per gcInterval (M-2/MEDIUM-1 B).
    if (_config.writeStallTimeout.count() > 0)
    {
      for (auto &lkv : _listeners)
      {
        Listener *lst = lkv.second.get();
        if (!lst->wq.empty() &&
            (now - lst->lastWriteProgress) > _config.writeStallTimeout)
        {
          to.push_back(lst->wq.front().sid);
          lst->lastWriteProgress = now; // re-arm the window for the next head (M-2 B)
        }
      }
    }
    for (auto sid : to)
    {
      auto it = _sessions.find(sid);
      if (it != _sessions.end())
      {
        closeNow(it->second.get(), TransportError::GCClosed, "GC safety-net timeout", 0);
      }
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
  //   connecting-sid registry (shared for reads, unique for mutations), AND
  //   Session::localSrc as a cross-thread field (tracker 2026-10-04-2 DP6): the
  //   I/O thread publishes a PUBLISHED session's localSrc under unique (adoptWildcardVia),
  //   the off-thread getLocalAddress reads it under shared. Reader sections are bounded
  //   to O(1) map work plus at most one getsockname syscall and run NO blocking/callback
  //   under the lock; the shared_mutex is reader-preferring on glibc, so adding a hot
  //   caller-thread getter (iora_sip may call getLocalAddress per message) widens the
  //   reader population the I/O thread's adopt unique_lock contends with — accepted risk
  //   given the bounded reader sections (TS L-3).
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
  // Keyed by peerKey(listener,peer); value is the twin SessionIds sharing that (listener,peer)
  // in insertion order, front() = the inbound-dispatch target (tracker 2026-10-02-3).
  std::unordered_map<std::string, std::vector<SessionId>> _peerIndex;
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