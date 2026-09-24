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
#include <cassert>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
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

#include "iora/core/errno_utils.hpp"
#include "iora/core/logger.hpp"
#include "iora/core/string_utils.hpp" // StringUtils::toLower (locale-independent ASCII, SNI norm)
#include "iora/core/timer.hpp"
#include "iora/network/detail/engine_base.hpp"
#include "iora/network/detail/fd_closer.hpp"
#include "iora/network/event_batch_processor.hpp"
#include "iora/network/name_resolver.hpp"
#include "iora/network/sockaddr_utils.hpp"
#include "iora/network/transport_types.hpp"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h> // X509_CHECK_FLAG_*, X509_VERIFY_PARAM_set_hostflags/set1_ip_asc (M-A)

#include <cctype> // std::tolower for SNI/host normalization

namespace iora
{
namespace network
{

// Lock the macro-free kHttpsHostFlags (transport_types.hpp, OpenSSL-include-free)
// to the real OpenSSL host-check flags. This TU includes <openssl/x509v3.h>; the
// consumer (http_client.hpp) does not, so the constant lets it stay OpenSSL-free.
// Parentheses around the OR are MANDATORY ('==' binds tighter than '|').
static_assert(kHttpsHostFlags ==
                (X509_CHECK_FLAG_NEVER_CHECK_SUBJECT | X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS),
              "kHttpsHostFlags must equal NEVER_CHECK_SUBJECT|NO_PARTIAL_WILDCARDS");

// Lock the macro-free SIP host-check constants (transport_types.hpp) to the real
// OpenSSL flags. kSipHostFlags is the strict RFC 5922 §7.2 default (NO wildcards,
// SAN-only); kSipHostFlagsAllowWildcards is the per-peer opt-in relaxation
// (wildcards permitted — full-label AND partial, since NO_PARTIAL_WILDCARDS is
// unset; still SAN-only). See transport_types.hpp for the canonical rationale.
// Parentheses around the OR are MANDATORY ('==' binds tighter than '|').
static_assert(kSipHostFlags ==
                (X509_CHECK_FLAG_NO_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT),
              "kSipHostFlags must equal NO_WILDCARDS|NEVER_CHECK_SUBJECT");
static_assert(kSipHostFlagsAllowWildcards == X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,
              "kSipHostFlagsAllowWildcards must equal NEVER_CHECK_SUBJECT");

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

  /// \brief Register a deleter run by the detached I/O thread after loop()
  /// returns (deferred self-destruction; see EngineBase). Called ONLY on the
  /// I/O thread, before detachForTermination() — the write and the epilogue
  /// read are same-thread, so no synchronization is used.
  void scheduleSelfDestruct(std::function<void()> deleter) override
  {
    assert(std::this_thread::get_id() == _loop.get_id() &&
           "scheduleSelfDestruct must be called on the I/O thread");
    _selfDestruct = std::move(deleter);
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

    // Reopen the command queue (a prior stop()->shutdownDrain() set this true to
    // reject post-teardown enqueues — see DD-5). A fresh _eventFd is created
    // below, so the queue accepts commands again for this run.
    // LIFECYCLE CONTRACT: start()/stop() are not concurrent with each other or
    // with enqueue() (the _running CAS gates the lifecycle; callers do not
    // enqueue during start/restart). So the brief interval between this reset
    // (_cmdsClosed=false) and the _eventFd recreation below — where the queue is
    // open but _eventFd is still -1 from the prior shutdownDrain — is not
    // reachable by a concurrent enqueuer.
    {
      std::lock_guard<std::mutex> g(_cmdMutex);
      _cmdsClosed = false;
    }

    // RE-CREATE the post gate BEFORE _eventFd/_epollFd/_loop, co-located with the
    // _cmdsClosed reset. A resolver continuation left over from a prior run keeps
    // its OLD (closed) gate and drops; continuations from this run see this fresh
    // (open) gate. Without this, every post-restart named-host resolve would drop
    // against a permanently-closed gate (spurious onClose(Resolve)).
    _postGuard = std::make_shared<detail::EnginePostGate>();
    _postGuard->engine = this;

    if (_config.maxWriteQueue == 0)
    {
      setLastFatal(IoResult::failure(TransportError::Config, "maxWriteQueue must be >= 1"));
      _running.store(false);
      return StartResult::err(lastError());
    }

    if (!initTls())
    {
      _running.store(false);
      return StartResult::err(lastError());
    }

    _epollFd = ::epoll_create1(EPOLL_CLOEXEC);
    if (_epollFd < 0)
    {
      startSyscallFailed("epoll_create1: ", errno);
      _running.store(false);
      freeTls();
      return StartResult::err(lastError());
    }

    _eventFd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (_eventFd < 0)
    {
      startSyscallFailed("eventfd: ", errno);
      cleanupStartFail();
      return StartResult::err(lastError());
    }
    addEpoll(_eventFd, EPOLLIN);
    // Commands queued before start() (connect()/addListener() on a stopped
    // engine) were pushed while _eventFd was -1, so no wakeup was written for
    // them: signal the fresh eventfd so the first epoll_wait processes them.
    {
      std::lock_guard<std::mutex> g(_cmdMutex);
      if (!_cmds.empty())
      {
        std::uint64_t one = 1;
        (void)::write(_eventFd, &one, sizeof(one));
      }
    }

    _timerFd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (_timerFd < 0)
    {
      startSyscallFailed("timerfd_create: ", errno);
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
        // Publish this thread as the I/O thread FIRST, before any dispatch, so
        // isOnIoThread() is valid for the whole loop lifetime.
        stampIoThread();
        // try/catch so the deferred self-destruct deleter runs on EVERY loop()
        // exit, incl. an exception escaping loop()/shutdownDrain (else the owning
        // Impl would leak). The deleter is moved to a local and invoked LAST:
        // it deletes the owning object (which contains this engine), so nothing
        // may touch `this` or any member after it runs (delete-this-at-thread-end).
        try
        {
          loop();
        }
        catch (...)
        {
          std::fprintf(stderr, "WARNING: TcpEngine I/O loop terminated by exception.\n");
        }
        // Clear the I/O-thread stamp AFTER the loop has unwound and BEFORE the
        // self-destruct deleter runs (it may free the object holding _ioThreadId).
        clearIoThread();
        std::function<void()> sd;
        sd.swap(_selfDestruct);
        if (sd)
        {
          sd();
        }
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
    if (!enqueue(Command::shutdown()))
    {
      std::lock_guard<std::mutex> g(_cmdMutex);
      if (_eventFd >= 0)
      {
        std::uint64_t one = 1;
        (void)::write(_eventFd, &one, sizeof(one));
      }
    }
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
      // Pass a COPY of the promise into the command (do NOT move it away): the
      // _running.load() above and the enqueue below are not atomic, so the
      // engine may be torn down in between. If enqueue() returns false the queue
      // is closed and the command was NOT queued — the (now-gone) loop would
      // never fulfill the promise, so we must still hold `ready` to fail the
      // future locally and avoid blocking forever in fut.get() (DD-5/DD-13,
      // tracker 2026-06-14-1). On the success path the I/O thread fulfills the
      // promise (bind result), or shutdownDrain()'s drain-and-fail step fails it
      // if teardown raced after a successful push.
      if (!enqueue(Command::addListener(lc, ready)))
      {
        return ListenResult::err(
          TransportErrorInfo{TransportError::ShuttingDown,
            "addListener: transport shutting down"});
      }
      bool ok = fut.get(); // I/O thread fulfills it (bind result or shutdown-fail)
      if (!ok)
      {
        // The promise is failed either by a real bind failure (I/O thread, while
        // running) or by shutdownDrain's drain-and-fail on a teardown race (after
        // stop() cleared _running). Distinguish so the caller gets ShuttingDown
        // rather than a misleading Bind on teardown (cpp17 L-1).
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
      if (!enqueue(Command::addListener(lc)))
      {
        return ListenResult::err(
          TransportErrorInfo{TransportError::ShuttingDown,
            "addListener: transport shutting down"});
      }
    }
    return ListenResult::ok(lc.id);
  }

  using EngineBase::connect; // un-hide the 3-arg non-pure default (base delegates)

  /// \brief Begin an outbound connection (async); result via onConnect.
  /// Primitive 4-arg override — carries per-connection TLS identity options.
  /// The returned sid is immediately sendable (bytes are buffered FIFO until TCP
  /// established; TLS: until handshake Open). A setup failure is reported ONLY
  /// via onClose (never synchronously); an err() result means nothing was queued.
  ConnectResult connect(const std::string &host, std::uint16_t port, TlsMode tls,
                        const TlsClientOptions &opts) override
  {
    SessionId sid = _nextSessionId++;
    bool inserted = false;
    bool queueClosed = false;
    try
    {
      ConnectReq cr{sid, host, port, tls, opts.verifyName, opts.x509HostFlags};
      Command cmd = Command::connect(cr);
      {
        std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
        _connecting.insert(sid);
      }
      inserted = true;
      // Surface the closed-queue reject (DD-5): if the transport is tearing down,
      // enqueue() returns false and the connect command is dropped — returning
      // ok(sid) here would promise a connection that will never complete or fire
      // onConnect/onClose (lost-completion). Mirror send()/close() and report it.
      if (enqueue(std::move(cmd)))
      {
        return ConnectResult::ok(sid);
      }
      queueClosed = cmdQueueClosed();
    }
    catch (...)
    {
    }
    if (inserted)
    {
      eraseConnecting(sid);
    }
    if (queueClosed)
    {
      return ConnectResult::err(
        TransportErrorInfo{TransportError::ShuttingDown, "connect: transport shutting down"});
    }
    return ConnectResult::err(TransportErrorInfo{TransportError::Unknown, "connect failed"});
  }

  /// \brief Queue a send on a session (non-blocking; may enqueue on EAGAIN).
  bool send(SessionId sid, const void *data, std::size_t n) override
  {
    if (n == 0)
    {
      return true;
    }
    // CF-H1: reject an unknown/closed session at enqueue time rather than
    // enqueuing a command doSend would silently drop (which returned true —
    // masking a dead connection from SIP RFC 3263 failover). A sid returned by
    // connect() is immediately sendable: bytes are buffered FIFO until the
    // session is established (TLS: until handshake Open) and setup failures
    // surface only via onClose. true means accepted, not delivered; a close
    // queued before this Send drops it (accepted TOCTOU); a stream write-queue
    // overflow closes the session (WriteBackpressure).
    if (!sessionSendable(sid))
    {
      return false;
    }
    return enqueueSend(sid, data, n);
  }

  /// \brief Close a session (idempotent). onClose will fire.
  bool close(SessionId sid) override { return enqueue(Command::close(sid)); }

  /// \brief Snapshot of counters.
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

  /// \note The completion callback fires synchronously on the caller's thread
  /// after the send command is enqueued (not after wire delivery). This is
  /// intentional — the result reflects whether the command was accepted by
  /// the I/O thread's queue, not whether data reached the peer.
  void sendAsync(SessionId sid, const void *data, std::size_t len,
                 SendCompleteCallback cb) override
  {
    // CF-H1: validate synchronously — do NOT report OK for an unknown/closed
    // session (a connecting sid returned by connect() IS sendable: its bytes are
    // buffered FIFO until established / TLS Open; OK means accepted, not
    // delivered). The decision is copied out from under the session read lock and
    // the lock released BEFORE cb runs (never invoke a user callback while
    // holding _sessionRwMutex). Completion stays SYNCHRONOUS on the caller
    // thread, the contract Transport::sendSync relies on (see EngineBase).
    // ONE sessionSendable acquisition: a close racing after it still reports OK
    // (the accepted TOCTOU, see sessionSendable).
    if (!sessionSendable(sid))
    {
      if (cb)
      {
        cb(sid,
           SendResult::err(TransportErrorInfo{TransportError::Socket, "session not connected"}));
      }
      return;
    }
    const bool ok = len == 0 || enqueueSend(sid, data, len);
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
    return applyDscpToFd(it->second->fd, dscp);
  }

  /// \brief Enqueue an EPOLLIN enable/disable change for a session (C5). epoll_ctl
  /// MUST run on the I/O thread, so this posts a command; the actual modEpoll runs
  /// in doSetReadEnabled(). Returns true iff the command was queued.
  bool setReadEnabled(SessionId sid, bool enabled) override
  {
    return enqueue(Command::setReadEnabled(sid, enabled));
  }

  /// \brief TEST-ONLY (CF-M4): return the raw socket fd backing session \p sid,
  /// or -1 if unknown. Lets a test getsockopt(IP_TOS/IPV6_TCLASS) on the socket to
  /// verify the DSCP mark was applied at session creation (see
  /// iora_test_engine_introspection). Takes the session read lock. NOT part of
  /// the production API — never used outside tests.
  int testGetSessionFd(SessionId sid) const
  {
    std::shared_lock<std::shared_mutex> rl(_sessionRwMutex);
    auto it = _sessions.find(sid);
    if (it == _sessions.end())
    {
      return -1;
    }
    return it->second->fd;
  }

  /// \brief TEST-ONLY (tracker 2026-09-15-3): number of fd->Tag entries. Used to assert
  /// that shutdownDrain erases a drained session's fd-tag (no stale Tag::sess survives).
  /// Call only when the I/O thread is stopped (no lock taken). NOT production API.
  std::size_t testFdTagCount() const { return _fdTags.size(); }

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

  /// \brief Fetch the peer certificate for the completion-gate presence check.
  /// \return the peer X509* (caller owns; X509_free), or nullptr if none was
  ///   presented. Default = SSL_get1_peer_certificate (OpenSSL >=1.1.0) with a
  ///   pre-1.1.0 fallback.
  /// \note Test seam ONLY (fault injection), matching the beforeSslHandshake/
  ///   afterSslHandshake B6 hooks. A test subclass returns nullptr to exercise the
  ///   completion gate's no-peer-cert backstop — the anonymous/PSK case for which
  ///   OpenSSL's SSL_VERIFY_PEER is IGNORED (so this gate, not the CTX, is the sole
  ///   rejecter) and which a compliant client cannot negotiate black-box. Added
  ///   with human sign-off 2026-09-11 (steps-4-8 M-A). Production never overrides.
  virtual X509 *fetchPeerCertificate(SSL *ssl)
  {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return ::SSL_get_peer_certificate(ssl);
#else
    return ::SSL_get1_peer_certificate(ssl);
#endif
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
  /// Test-only access (tests/network/tcp_engine_test_access.hpp): the test seams
  /// below are reachable only through it, never through the production API.
  friend struct TcpEngineTestAccess;

  /// I/O-thread points at which the connect path throws once (test seam).
  enum class ConnectThrowPoint
  {
    NONE,
    BEFORE_INSERT_LITERAL,
    BEFORE_INSERT_RESUME,
    AFTER_INSERT,
    NAMED_KICKOFF_AFTER_PENDING_INSERT
  };

  // ===== helpers =====

  static std::string lastErr() { return iora::core::errnoMessage(errno); }

  /// \brief start() syscall failure: \p savedErrno is the errno captured once,
  /// immediately after the failing call (the diagnostics below may clobber errno).
  void startSyscallFailed(const char *what, int savedErrno)
  {
    const std::string msg = what + iora::core::errnoMessage(savedErrno);
    setLastFatal(IoResult::failure(TransportError::Config, msg, savedErrno));
    err(TransportError::Config, msg);
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

  /// \brief Forwards to the shared iora::network::applyDscpToFd (see the
  /// udp_engine twin — both were byte-identical private copies, the same
  /// anti-pattern already retired for addressFromSockaddr). CF-L1. Shared by the
  /// per-session setDscp() API and the at-creation application of
  /// config.dscpValue in applySockOpts().
  static bool applyDscpToFd(int fd, std::uint8_t dscp)
  {
    return iora::network::applyDscpToFd(fd, dscp);
  }

  /// \brief CF-H1: is \p sid sendable — a known, not-closed session OR a sid in the
  /// connecting registry (connect() returned it, setup still pending)? Both checks
  /// run under ONE shared-lock acquisition. send()/sendAsync() call this to reject
  /// an unknown/closed session synchronously at enqueue time — enqueuing a Send
  /// command that doSend then silently drops reported false success and masked
  /// connection failure (defeating SIP RFC 3263 failover). A sid returned by
  /// connect() is immediately sendable: its bytes are buffered FIFO until
  /// established (TLS: until handshake Open), setup failures surface only via
  /// onClose, and a stream overflow closes the session (WriteBackpressure).
  /// Completion means accepted, not delivered. A close racing right after this
  /// check (a close queued before the Send drops it) is the accepted narrow
  /// TOCTOU: it shrinks the false-OK window from "always" to a rare race, and
  /// cannot be closed without holding _sessionRwMutex across enqueue+dispatch.
  bool sessionSendable(SessionId sid) const
  {
    std::shared_lock<std::shared_mutex> rl(_sessionRwMutex);
    auto it = _sessions.find(sid);
    if (it != _sessions.end() && !it->second->closed.load(std::memory_order_relaxed))
    {
      return true;
    }
    return _connecting.find(sid) != _connecting.end();
  }

  /// \brief Copy \p n > 0 bytes into a Send command and enqueue it (no
  /// sendability check — the caller has done it). True iff queued.
  bool enqueueSend(SessionId sid, const void *data, std::size_t n)
  {
    IORA_LOG_DEBUG("[SHARED-TRANSPORT] send() called for sid=" << sid << ", size=" << n);
    SendReq sr;
    sr.sid = sid;
    sr.payload.resize(n);
    std::memcpy(sr.payload.data(), data, n);
    const bool result = enqueue(Command::send(std::move(sr)));
    IORA_LOG_DEBUG("[SHARED-TRANSPORT] send() enqueue " << (result ? "succeeded" : "failed")
                   << " for sid=" << sid);
    return result;
  }

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

  /// Forwards to the shared iora::network::addressFromSockaddr (see the
  /// udp_engine twin — both were byte-identical private copies).
  static TransportAddress addressFromSockaddr(const sockaddr_storage &ss)
  {
    return iora::network::addressFromSockaddr(ss);
  }

  void armGc(std::chrono::seconds sec)
  {
    itimerspec its{};
    its.it_interval.tv_sec = sec.count();
    its.it_value.tv_sec = sec.count();
    ::timerfd_settime(_timerFd, 0, &its, nullptr);
  }

  // Start-failure cleanup. Runs on the caller's thread DURING start(), BEFORE
  // the I/O loop thread is launched, so it is single-threaded w.r.t. the engine
  // and the _eventFd close here cannot race enqueue() — no _cmdMutex needed
  // (unlike shutdownDrain's close, which races live enqueuers). DD-6.
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
    _atomicStats.errors.fetch_add(1, std::memory_order_relaxed);
    invokeUserCallback(copyCallback(_cbMutex, _cbs.onError), te, m);
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
    // Per-connection TLS client identity (data-only seam; arch C1). Carried by
    // value from the public connect API (and through the off-thread-resolve
    // resume chain) to the SSL setup site (connectFromAddrs) for SNI + identity
    // binding. Empty verifyName => the setup site inspects the connect address.
    std::string verifyName;
    unsigned x509HostFlags{0};
  };

  /// \brief I/O-thread-only record of a named-host connect awaiting off-thread
  /// resolution. It is the SINGLE-OWNER one-shot terminal event for that sid —
  /// exactly one of {resume, resolve-timeout, teardown/close} erases it and
  /// fires the terminal; the others no-op. Holds only the resolve-timeout handle
  /// (no owned resource, no connectSync handle — connectSync is a Transport-layer
  /// CV). The UDP engine's counterpart carries an absolute resolveDeadline
  /// instead (it has no TimerService).
  struct PendingConnect
  {
    std::uint64_t resolveTimeoutId{0}; // TimerService id; 0 == none armed
    // The buffer overflowed maxWriteQueue (see Session::setupOverflowed).
    bool setupOverflowed{false};
    // Sends accepted for the sid while it resolves, in FIFO order. Moved into
    // Session::wq by connectFromAddrs; dropped (the failure surfaces via onClose)
    // on close-during-pending, resolve failure/timeout and shutdown drain. Must
    // survive per-address failover (F2, tracker 2026-09-06-3).
    std::deque<ByteBuffer> buffer;
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
    SetReadEnabled, // C5: enable/disable EPOLLIN for a session (I/O-thread epoll_ctl)
    RunOnIo // generic "run this closure on the I/O thread" (runOnIoThread seam)
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
    int closeErrno{0};
    CloseOrigin closeOrigin{CloseOrigin::App};
    SessionId readSid{};              // Cmd::SetReadEnabled target session
    bool readEnabledVal{true};        // Cmd::SetReadEnabled desired EPOLLIN state
    std::shared_ptr<std::promise<bool>> listenerReady; // signals when addListener bind completes
    std::function<void()> fn; // Cmd::RunOnIo payload (std::function keeps Command copyable)

    static Command shutdown() { return Command{Cmd::Shutdown}; }
    static Command setReadEnabled(SessionId sid, bool enabled)
    {
      Command x{Cmd::SetReadEnabled};
      x.readSid = sid;
      x.readEnabledVal = enabled;
      return x;
    }
    static Command runOnIo(std::function<void()> fn)
    {
      Command x{Cmd::RunOnIo};
      x.fn = std::move(fn);
      return x;
    }
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
                         CloseOrigin origin = CloseOrigin::App, int sysErrno = 0)
    {
      Command x{Cmd::Close};
      x.closeSid = sid;
      x.closeReason = reason;
      x.closeMsg = msg;
      x.closeErrno = sysErrno;
      x.closeOrigin = origin;
      return x;
    }
  };

  // The Cmd::RunOnIo payload is a std::function<void()> member, so Command stays
  // copyable — the command deque copies/moves entries (arch C2; tracker task-1.6
  // / testStrategy c1_c3_unit "RunOnIo keeps Command/Cmd copyable").
  static_assert(std::is_copy_constructible<Command>::value,
                "Command must remain copyable after adding the RunOnIo fn member");

  /// \brief Push \p cmd and wake the I/O loop, all UNDER _cmdMutex so the push,
  /// the _cmdsClosed check and the _eventFd wakeup ::write are atomic w.r.t.
  /// shutdownDrain()'s `close(_eventFd); _eventFd=-1` (also under _cmdMutex). The
  /// wakeup write is safe under the lock because _eventFd is EFD_NONBLOCK; it is
  /// skipped while _eventFd is -1 (before start(), which signals any queued
  /// commands itself). Returns false WITHOUT pushing if teardown closed the queue
  /// (DD-1/DD-2/DD-5, tracker 2026-06-14-1). Throws on allocation failure or an
  /// injected enqueue failure (test seam).
  bool pushLockedAndWake(Command &&cmd)
  {
    std::lock_guard<std::mutex> g(_cmdMutex);
    if (_cmdsClosed)
    {
      return false;
    }
    if (_testEnqueueFailure.load(std::memory_order_relaxed))
    {
      throw std::runtime_error("injected enqueue failure");
    }
    _cmds.push_back(std::move(cmd));
    _atomicStats.commands.fetch_add(1, std::memory_order_relaxed);
    if (_eventFd >= 0)
    {
      std::uint64_t one = 1;
      (void)::write(_eventFd, &one, sizeof(one));
    }
    return true;
  }

  /// \brief EngineBase seam: post \p fn onto the I/O thread as a RunOnIo command.
  /// NOEXCEPT and callback-free — on any failure (closed, or allocation) it
  /// returns false and fires NO user callback; a dropped resolve post is
  /// backstopped by the resolve-timeout (#10/#14). ALWAYS posts, never inline.
  bool runOnIoThread(std::function<void()> fn) noexcept override
  {
    try
    {
      return pushLockedAndWake(Command::runOnIo(std::move(fn)));
    }
    catch (...)
    {
      return false;
    }
  }

  /// \brief Queue \p cmd for the I/O thread. CALLBACK-FREE: enqueue() never
  /// invokes a user callback. It is reached from connect/send/close/setReadEnabled
  /// (possibly under Transport's syncMutex) and from timer closes on the
  /// TimerService thread. On the exception path it records the sticky last-fatal
  /// diagnostic (outside _cmdMutex: the lock_guard has unwound before the handler
  /// runs) and returns false; the ordinary queue-closed path returns false without
  /// touching the sticky diagnostic.
  bool enqueue(Command &&cmd) noexcept
  {
    try
    {
      return pushLockedAndWake(std::move(cmd));
    }
    catch (const std::exception &ex)
    {
      recordEnqueueFailure("enqueue: ", ex.what());
      return false;
    }
    catch (...)
    {
      recordEnqueueFailure("enqueue: ", "unknown exception");
      return false;
    }
  }

  void recordEnqueueFailure(const char *where, const char *what) noexcept
  {
    try
    {
      setLastFatal(IoResult::failure(TransportError::Unknown, std::string(where) + what));
    }
    catch (...)
    {
    }
  }

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

  /// \brief Erase \p sid from the connecting registry; true iff it was present.
  bool eraseConnecting(SessionId sid) noexcept
  {
    std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
    return _connecting.erase(sid) == 1;
  }

  /// \brief Erase \p sid's _pendingConnects entry, cancelling its resolve timer;
  /// true iff it was present. I/O thread only.
  bool takePending(SessionId sid) noexcept
  {
    auto pit = _pendingConnects.find(sid);
    if (pit == _pendingConnects.end())
    {
      return false;
    }
    if (_timerService && pit->second.resolveTimeoutId != 0)
    {
      try
      {
        _timerService->cancel(pit->second.resolveTimeoutId);
      }
      catch (...)
      {
      }
    }
    _pendingConnects.erase(pit);
    return true;
  }

  /// \brief Terminal for a sid that never reached _sessions (I/O thread). ORDER:
  /// every allocating step first -- the onClose copy here, \p info by the caller --
  /// then the noexcept ownership release (the _pendingConnects entry and the
  /// connecting-registry entry), then exactly one onClose(\p info). A throw
  /// therefore leaves the sid owned for the connect guard / teardown drain. Returns
  /// false, firing nothing, if the sid owned neither (a terminal already fired).
  bool preInsertTerminal(SessionId sid, const TransportErrorInfo &info)
  {
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

  bool cmdQueueClosed()
  {
    std::lock_guard<std::mutex> g(_cmdMutex);
    return _cmdsClosed;
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
    // Track SSL_ERROR_WANT_WRITE during handshake and renegotiation.
    // I/O thread only - not thread-safe, accessed exclusively from epoll loop.
    bool tlsWantWrite{false};

    std::deque<ByteBuffer> wq;
    bool wantWrite{false};
    // Cross-thread liveness flag (tracker 2026-09-15-3): read lock-free on the CALLER
    // thread in sessionSendable() while the I/O thread writes it in closeNow()/
    // shutdownDrain(). Atomic (relaxed) makes that read/write well-defined -- an advisory
    // liveness gate publishing no companion state (the I/O thread re-validates under the
    // map at doSend). The check-then-set in closeNow/shutdownDrain is a plain relaxed
    // store (not a CAS), safe ONLY because BOTH are I/O-thread-confined and never run
    // concurrently; a future caller-thread close path must use a CAS.
    std::atomic<bool> closed{false};
    // C5: when false, EPOLLIN is withheld from this session's epoll interest so
    // the read/re-arm path (updateInterest) does not deliver read events for a
    // ReadMode::Disabled session. I/O thread only. Defaults enabled.
    bool readEnabled{true};

    MonoTime created{}, lastActivity{};

    // Safety-net tracking
    // connectPending spans the WHOLE outbound setup (TCP connect + TLS handshake):
    // it exempts setup sessions from idle expiry (runGc) and keeps EPOLLOUT armed
    // outside the handshake (updateInterest).
    bool connectPending{false};
    // tcpConnectPending spans ONLY the TCP phase (set at connect start, cleared at
    // TCP-established for BOTH plain TCP and TLS, before any handshake is driven).
    // Per-reader decision:
    //  - stale-ConnectTimeout filter (process Cmd::Close) -> tcpConnectPending
    //  - GC connect-timeout expiry (runGc)                  -> tcpConnectPending
    //  - GC / no-timer handshake expiry gate                -> !tcpConnectPending
    //  - doSend / writePending ::send withholding            -> tcpConnectPending
    //  - onSession TCP-phase probe (SO_ERROR + getpeername) -> tcpConnectPending
    //  - closeNow setup-close code (setupCloseCode)          -> tcpConnectPending
    //  - updateInterest handshake-phase EPOLLOUT            -> tcpConnectPending
    // SETUP-CLOSE INVARIANT (closeNow, client role only): a peer/network/error/
    // timer-driven close while tcpConnectPending reports TransportError::Connect;
    // else while a TLS client is in the handshake it reports
    // TransportError::TLSHandshake (tcpConnectPending wins: a TLS client enters
    // Handshake at connect start). BY-CODE EXEMPTION: the relabel keys on the
    // requested code, not the caller -- Unknown (app close, connect-guard internal
    // error), ShuttingDown, WriteBackpressure, ResourceLimit and GCClosed are never
    // relabelled, so NEVER pass Unknown for a peer/network close (it would escape
    // the relabel and break the failover contract).
    // FAILOVER-SAFETY INVARIANT: a Connect or TLSHandshake close means ZERO request
    // bytes reached the kernel -- ::send is withheld during the TCP phase and TLS
    // withholds application data until Open -- so the request is safe to fail over.
    bool tcpConnectPending{false};
    MonoTime connectStart{};
    // Stamped at TCP-established (start of the TLS handshake phase; the accept time
    // for a server-side TLS session). The handshake budget runs from here, so the
    // TLS setup budget is connectTimeout + handshakeTimeout.
    MonoTime handshakeStart{};
    // A setup-phase buffer (TCP-phase wq, TLS handshake queue, or the named-host
    // pending buffer) overflowed maxWriteQueue: the overflowing payload was
    // discarded and the session closes WriteBackpressure at setup completion,
    // before any byte is flushed. A setup failure still reports Connect/TLSHandshake.
    bool setupOverflowed{false};
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

  /// \brief Write-stall deadline check (I/O thread, on a fired write-stall timer).
  /// The stall window runs from Session::lastWriteProgress, as on the GC path: if
  /// bytes were written less than writeStallTimeout ago the timer is re-armed for
  /// the remainder of the window and true is returned (no close). The spent (just-
  /// fired) timer id is dropped to 0 BEFORE scheduling the replacement, so a
  /// throwing scheduleAfter (bad_alloc) OR a refused one (id 0, TimerService at
  /// capacity) both leave writeStallTimeoutId 0 and runGc applies the write-stall
  /// deadline instead of a stale non-zero id suppressing the GC fallback.
  bool rearmWriteStallOnProgress(Session *s)
  {
    const auto sinceProgress = MonoClock::now() - s->lastWriteProgress;
    if (!_timerService || sinceProgress >= _config.writeStallTimeout)
    {
      return false;
    }
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                             _config.writeStallTimeout - sinceProgress) +
                           std::chrono::milliseconds(1);
    // Drop the spent timer id first (cancel of an already-fired timer is a no-op);
    // if scheduleAfter throws, the assignment below never runs and the id stays 0.
    cancelWriteStallTimeout(s);
    s->writeStallTimeoutId = _timerService->scheduleAfter(
      remaining, [this, sid = s->id]() { handleWriteStallTimeout(sid); });
    return true;
  }

  void cancelAllTimers(Session *s)
  {
    cancelConnectTimeout(s);
    cancelHandshakeTimeout(s);
    cancelWriteStallTimeout(s);
  }

  /// \brief True while a TLS session (either role) is in its handshake.
  static bool inHandshake(const Session *s)
  {
    return s->tlsMode != TlsMode::None && s->tlsState == TlsState::Handshake;
  }

  /// \brief True once the session may put application bytes on the wire: TCP
  /// established (plain TCP) or handshake Open (TLS). Until then every queued
  /// payload is a setup-phase buffer.
  static bool sessionWritable(const Session *s)
  {
    return !s->tcpConnectPending && (s->tlsMode == TlsMode::None || s->tlsState == TlsState::Open);
  }

  /// \brief Close code for a close of \p s requested as \p why (setup-close
  /// invariant, see Session::tcpConnectPending). Client role only: a server-role
  /// (accepted) session keeps \p why. The by-code exemptions are never relabelled.
  static TransportError setupCloseCode(const Session *s, TransportError why)
  {
    if (why == TransportError::Unknown || why == TransportError::ShuttingDown ||
        why == TransportError::WriteBackpressure || why == TransportError::ResourceLimit ||
        why == TransportError::GCClosed)
    {
      return why;
    }
    if (s->tcpConnectPending)
    {
      return TransportError::Connect;
    }
    if (s->tlsMode == TlsMode::Client && s->tlsState == TlsState::Handshake)
    {
      return TransportError::TLSHandshake;
    }
    return why;
  }

  /// \brief True for a socket()/connect() errno that reports LOCAL resource
  /// exhaustion (descriptor limits, buffer/memory pressure, no free local
  /// address/port) rather than a failure to reach the peer.
  static bool isLocalResourceErrno(int e)
  {
    return e == EMFILE || e == ENFILE || e == ENOBUFS || e == ENOMEM || e == EADDRNOTAVAIL;
  }

  /// \brief sysErrno for an EVENT-ONLY close trigger (EPOLLHUP/EPOLLERR/EPOLLRDHUP):
  /// the pending socket error via getsockopt(SO_ERROR) (read-and-clear, so this is
  /// fetched once, before any other syscall on the fd).
  static int eventCloseErrno(const Session *s)
  {
    int soErr = 0;
    socklen_t el = sizeof(soErr);
    if (::getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &soErr, &el) != 0)
    {
      soErr = errno;
    }
    return soErr;
  }

  void handleConnectTimeout(SessionId sid)
  {
    enqueueTimerClose(sid, TransportError::Connect, "Connect timeout", CloseOrigin::ConnectTimeout,
                      ETIMEDOUT);
  }

  void handleHandshakeTimeout(SessionId sid)
  {
    enqueueTimerClose(sid, TransportError::TLSHandshake, "TLS handshake timeout",
                      CloseOrigin::HandshakeTimeout, ETIMEDOUT);
  }

  void handleWriteStallTimeout(SessionId sid)
  {
    enqueueTimerClose(sid, TransportError::Timeout, "Write stall timeout", CloseOrigin::WriteStall,
                      0);
  }

  static constexpr std::chrono::milliseconds TIMER_CLOSE_RETRY_DELAY{10};

  /// \brief TimerService thread: enqueue a timer-originated close. A failed
  /// enqueue while the command queue is still OPEN (a transient exception, e.g.
  /// bad_alloc) reschedules a short retry so the timeout is never silently lost;
  /// a closed queue (teardown) drops it — shutdownDrain terminates the session.
  /// If the retry itself cannot be scheduled (TimerService at capacity, or a
  /// throw), the session is marked so the next runGc applies that deadline.
  void enqueueTimerClose(SessionId sid, TransportError reason, const char *msg,
                         CloseOrigin origin, int sysErrno)
  {
    bool queued = false;
    try
    {
      queued = enqueue(Command::close(sid, reason, msg, origin, sysErrno));
    }
    catch (...)
    {
    }
    if (queued || !_timerService || cmdQueueClosed())
    {
      return;
    }
    std::uint64_t retryId = 0;
    try
    {
      retryId = _timerService->scheduleAfter(
        TIMER_CLOSE_RETRY_DELAY, [this, sid, reason, msg, origin, sysErrno]()
        { enqueueTimerClose(sid, reason, msg, origin, sysErrno); });
    }
    catch (...)
    {
    }
    if (retryId == 0)
    {
      markTimerCloseLost(sid, origin);
    }
  }

  /// \brief Record that the timer-originated close of \p sid (\p origin) could
  /// neither be enqueued nor retried. runGc drains these marks on the I/O thread
  /// and clears the matching timer id, so its GC deadline check takes over.
  void markTimerCloseLost(SessionId sid, CloseOrigin origin) noexcept
  {
    try
    {
      std::lock_guard<std::mutex> g(_lostTimerMutex);
      _lostTimerCloses.emplace_back(sid, origin);
    }
    catch (...)
    {
    }
  }

  /// \brief I/O thread (runGc): clear the timer id of every session whose
  /// timer-originated close was lost (markTimerCloseLost).
  void applyLostTimerCloses()
  {
    std::vector<std::pair<SessionId, CloseOrigin>> lost;
    {
      std::lock_guard<std::mutex> g(_lostTimerMutex);
      lost.swap(_lostTimerCloses);
    }
    for (const auto &l : lost)
    {
      auto it = _sessions.find(l.first);
      if (it == _sessions.end())
      {
        continue;
      }
      Session *s = it->second.get();
      if (l.second == CloseOrigin::ConnectTimeout)
      {
        cancelConnectTimeout(s);
      }
      else if (l.second == CloseOrigin::HandshakeTimeout)
      {
        cancelHandshakeTimeout(s);
      }
      else if (l.second == CloseOrigin::WriteStall)
      {
        cancelWriteStallTimeout(s);
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
    if (_batchProcessor)
    {
      loopBatched();
    }
    else
    {
      loopUnbatched();
    }
  }

  /// \brief Dispatch one epoll event. An exception escaping a session dispatch
  /// closes THAT session (Unknown, "internal error") and the loop continues; one
  /// escaping a listener dispatch is dropped (the listener stays armed).
  void handleFdEvent(int fd, std::uint32_t events)
  {
    auto it = _fdTags.find(fd);
    if (it == _fdTags.end())
    {
      return;
    }
    Tag *t = it->second.get();
    if (t->isListener)
    {
      try
      {
        onListener(t->lst);
      }
      catch (...)
      {
      }
      return;
    }
    const SessionId sid = t->sess->id;
    events = filterSessionEvents(sid, events);
    if (events == 0)
    {
      return;
    }
    try
    {
      onSession(t->sess, events);
    }
    catch (...)
    {
      closeAfterDispatchThrow(sid);
    }
  }

  /// \brief Close \p sid (Unknown, "internal error") after an exception escaped
  /// its dispatch; a no-op if the dispatch already closed it.
  void closeAfterDispatchThrow(SessionId sid) noexcept
  {
    try
    {
      auto it = _sessions.find(sid);
      if (it != _sessions.end())
      {
        closeNow(it->second.get(), TransportError::Unknown, "internal error", 0, 0);
      }
    }
    catch (...)
    {
    }
  }

  /// \brief Swallowing wrapper for the test event filter: a throwing filter
  /// delivers \p events unchanged.
  std::uint32_t filterSessionEvents(SessionId sid, std::uint32_t events) noexcept
  {
    if (!_sessionEventFilterHook)
    {
      return events;
    }
    try
    {
      return _sessionEventFilterHook(sid, events);
    }
    catch (...)
    {
      return events;
    }
  }

  void shutdownDrain()
  {
    // INVARIANT: shutdownDrain runs only on the I/O loop thread (called from
    // loopUnbatched/loopBatched at the end of loop()). It is NOT asserted via
    // _loop.get_id()/getIoThreadId(): on the self-destruct teardown path,
    // detachForTermination() detaches _loop from inside the onClose callback
    // BEFORE the loop exits and reaches shutdownDrain, so _loop.get_id() is the
    // null id here and such an assert would spuriously fire (DD-12). The I/O-
    // thread confinement of _timerFd/_epollFd and the _eventFd-close serialization
    // below rely on this invariant.
    // Draining on shutdown
    process();
    // Collect sessions to close to avoid iterator invalidation
    std::vector<Session *> toClose;
    toClose.reserve(_sessions.size());
    for (auto &kv : _sessions)
    {
      toClose.push_back(kv.second.get());
    }

    // fd-reuse fix (tracker 2026-09-15-3): detach sessions/listeners and COLLECT their
    // fds; ::close them only AFTER both maps are cleared under the write lock (fdsToClose
    // destructs at scope end), so a cross-thread getter holding the shared lock cannot
    // syscall on a closed/reused fd. (TCP: every Session owns its own fd -- no ServerPeer
    // aliasing, so no role guard.)
    std::vector<detail::FdCloser> fdsToClose;
    fdsToClose.reserve(toClose.size() + _listeners.size());

    // Close all sessions safely (but don't erase from _sessions yet)
    for (auto *s : toClose)
    {
      if (!s || s->closed.load(std::memory_order_relaxed))
      {
        continue;
      }
      s->closed.store(true, std::memory_order_relaxed);
      cancelAllTimersNoThrow(s);
      delEpoll(s->fd);
      // Erase the fd->Tag entry too (mirrors closeNow and the listener loop below):
      // _sessions.clear() destroys the Session, so a surviving _fdTags entry would
      // dangle its Tag::sess. _fdTags is never bulk-cleared and start() does not reset
      // it, so on restart a reused fd number would keep the stale tag (emplace does not
      // overwrite) and handleFdEvent would dereference the freed Session (UAF).
      _fdTags.erase(s->fd); // erase-by-key: no-op if absent (matches the UDP _tags.erase idiom)
      // SSL_shutdown before close(fd) — same ordering as closeNow (still on the live fd)
      if (s->ssl)
      {
        ::SSL_shutdown(s->ssl);
        ::SSL_free(s->ssl);
        s->ssl = nullptr;
      }
      fdsToClose.emplace_back(s->fd, &_preCloseHook); // ::close after _sessions.clear()
      _atomicStats.closed.fetch_add(1, std::memory_order_relaxed);
      _atomicStats.sessionsCurrent.fetch_sub(1, std::memory_order_relaxed);
      // TS-3: guard each drain terminal so an allocation failure (e.g. a large
      // onClose std::function copy) on one session cannot truncate the drain and
      // skip the remaining sessions' onClose. The fd/SSL for THIS session were
      // already released above, so a throw here loses at most one onClose.
      try
      {
        invokeUserCallback(copyCallback(_cbMutex, _cbs.onClose), s->id,
                           TransportErrorInfo{TransportError::Unknown, "shutdown", 0, 0});
      }
      catch (...)
      {
      }
    }
    {
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      _sessions.clear();
    }

    // Detach listeners (delEpoll + _fdTags erase + collect fd), then clear _listeners
    // under the write lock, then close (fdsToClose destructor). Do NOT deref lst->fd
    // after the clear -- _listeners.clear() destroys the Listener.
    for (auto &kv : _listeners)
    {
      Listener *lst = kv.second.get();
      delEpoll(lst->fd);
      _fdTags.erase(lst->fd);
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

    // (a) CLOSE THE POST GATE — a STANDALONE gate->m section, BEFORE the
    // _cmdMutex teardown block and never nested inside it (HR-2: gate->m is
    // strictly OUTSIDE _cmdMutex). closed and engine are set together, so a
    // resolver continuation seeing !closed always finds engine alive; after this
    // point continuations drop instead of posting a resume (#8/#13).
    {
      std::lock_guard<std::mutex> gg(_postGuard->m);
      _postGuard->closed = true;
      _postGuard->engine = nullptr;
    }

    // (b) DRAIN in-flight named-host resolves (#7b): COLLECT-THEN-FIRE. Fire
    // exactly one onClose(ShuttingDown) per pending sid (preInsertTerminal:
    // copy-then-invoke, release before firing so a re-entrant callback cannot
    // double-fire an entry), OUTSIDE gate->m and outside the _cmdMutex teardown
    // block (#14/HR-3).
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
          // TS-3: guard each terminal so an allocation failure on one pending sid
          // does not skip the remaining pending sids' onClose.
          try
          {
            preInsertTerminal(sid, TransportErrorInfo{TransportError::ShuttingDown, "shutdown", 0, 0});
          }
          catch (...)
          {
          }
        }
      }
    }

    // Close _eventFd and the command queue together under _cmdMutex so the
    // close is mutually exclusive with enqueue()'s wakeup ::write (DD-1) and no
    // further command can be queued after teardown (DD-5). Any promise-bearing
    // command still queued here (pushed after the process() above but before the
    // queue closed) is drained and its promise FAILED outside the lock, so a
    // synchronous addListener caller's fut.get() returns instead of blocking
    // forever (DD-5/DD-13). _cmdMutex stays a leaf: we swap under the lock and
    // fulfill promises after releasing (set_value runs no user code).
    std::deque<Command> residual;
    {
      std::lock_guard<std::mutex> g(_cmdMutex);
      _cmdsClosed = true;
      residual.swap(_cmds);
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
        try
        {
          c.listenerReady->set_value(false);
        }
        catch (...)
        {
        }
      }
      if (c.t == Cmd::Connect)
      {
        // TS-3: guard each residual terminal so an allocation failure on one does
        // not skip the remaining residual Connect commands' onClose.
        try
        {
          preInsertTerminal(c.c.sid, TransportErrorInfo{TransportError::ShuttingDown, "shutdown", 0, 0});
        }
        catch (...)
        {
        }
      }
    }
    // TS3-R3-1: unconditional final sweep. preInsertTerminal releases its registry
    // entry AFTER the allocating copyCallback, so a swallowed bad_alloc above could
    // leave a _pendingConnects/_connecting entry behind. Clear both registries so
    // the drain leaves them provably empty (a monotonic sid is never re-issued, but
    // a resurrected entry would still violate the drain-empties invariant).
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
      _atomicStats.epollWakeups.fetch_add(1, std::memory_order_relaxed);

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
        case Cmd::RunOnIo:
          if (c.fn)
          {
            c.fn();
          }
          break;
        case Cmd::Send:
          doSend(std::move(c.s));
          break;
        case Cmd::Close:
        {
          // Close DURING the resolve window: the session was never inserted into
          // _sessions (resolution is still in flight), so consult _pendingConnects
          // FIRST. If found, cancel the resolve timeout, erase, fire the single
          // terminal onClose; the later resumeConnect finds no entry and no-ops.
          if (_pendingConnects.count(c.closeSid) != 0)
          {
            preInsertTerminal(c.closeSid,
                              TransportErrorInfo{c.closeReason, c.closeMsg, c.closeErrno, 0});
            break;
          }
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
              if (!s->tcpConnectPending)
              {
                break; // TCP phase completed, ignore stale timeout
              }
            }
            else if (c.closeOrigin == CloseOrigin::HandshakeTimeout)
            {
              if (s->tlsState != TlsState::Handshake)
              {
                break; // Handshake completed
              }
            }
            else if (c.closeOrigin == CloseOrigin::WriteStall)
            {
              // Queue drained, or setup not complete (a slow connect never closes as
              // a write stall).
              if (s->wq.empty() || !sessionWritable(s))
              {
                break;
              }
              // Write progress since the timer was armed: re-arm for the rest of
              // the window measured from lastWriteProgress (the GC path's rule).
              if (rearmWriteStallOnProgress(s))
              {
                break;
              }
            }
            closeNow(s, c.closeReason, c.closeMsg, c.closeErrno, 0);
          }
          break;
        }
        case Cmd::SetReadEnabled:
          doSetReadEnabled(c.readSid, c.readEnabledVal);
          break;
        }
      }
      catch (const std::exception &ex)
      {
        dispatchFailed(c, ex.what());
      }
      catch (...)
      {
        dispatchFailed(c, "unknown exception");
      }
    }
  }

  /// \brief A command handler threw: fail any addListener promise (so a caller
  /// blocked in fut.get() returns) and report onError. Never throws.
  void dispatchFailed(Command &c, const char *what) noexcept
  {
    if (c.listenerReady)
    {
      try
      {
        c.listenerReady->set_value(false);
      }
      catch (...)
      {
      }
    }
    try
    {
      invokeUserCallback(copyCallback(_cbMutex, _cbs.onError), TransportError::Unknown,
                         std::string("cmd dispatch: ") + what);
    }
    catch (...)
    {
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
    if (::listen(sfd, _config.listenBacklog) < 0)
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
      // Bound concurrent accepted sessions. Each one owns a receive buffer that a
      // peer controls the size of, so an unbounded session count makes every
      // per-session memory cap meaningless in aggregate — the real ceiling would
      // be the process fd limit. Mirrors the UDP engine's cap; 0 means unlimited.
      if (_config.maxSessions && _atomicStats.sessionsCurrent.load(std::memory_order_relaxed) >= _config.maxSessions)
      {
        ::close(cfd);
        err(TransportError::Accept, "maxSessions reached; connection rejected");
        continue;
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
        s->handshakeStart = MonoClock::now();
        scheduleHandshakeTimeout(s.get());
      }

      std::string peerKey = s->peerKey;
      Session *sPtr = s.get();
      {
        std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
        _sessions.emplace(sid, std::move(s));
      }
      bumpSess();

      // EPOLLRDHUP armed at accept time for uniform peer-half-close detection
      // (defense-in-depth; updateInterest is the load-bearing site since modEpoll
      // replaces the full mask — tracker 2026-09-11-19).
      std::uint32_t ev = EPOLLIN | EPOLLRDHUP;
      if (_config.useEdgeTriggered)
      {
        ev |= EPOLLET;
      }
      addEpoll(cfd, ev);

      auto tg = std::make_unique<Tag>();
      tg->isListener = false;
      tg->sess = sPtr;
      _fdTags.emplace(cfd, std::move(tg));

      _atomicStats.accepted.fetch_add(1, std::memory_order_relaxed);
      invokeUserCallback(copyCallback(_cbMutex, _cbs.onAccept), sid, addressFromSockaddr(peer));
    }
  }

  /// \brief KICKOFF: literal-IP short-circuit stays synchronous; a named host
  /// is resolved OFF the I/O thread, event-driven, then resumed via
  /// resumeConnect. Enqueue-only contract preserved (returns without blocking).
  bool doConnect(const ConnectReq &cr)
  {
    try
    {
      return doConnectImpl(cr);
    }
    catch (...)
    {
      connectGuardFail(cr.sid);
      return false;
    }
  }

  bool doConnectImpl(const ConnectReq &cr)
  {
    // Literal IP short-circuit — SYNCHRONOUS, no resolver. Build a STACK-owned
    // addrinfo and connect directly; connectFromAddrs never frees it.
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
    const bool isIPv4 = (inet_pton(AF_INET, cr.host.c_str(), &(sa4.sin_addr)) == 1);
    const bool isIPv6 = (inet_pton(AF_INET6, cr.host.c_str(), &(sa6.sin6_addr)) == 1);
    if (isIPv4 || isIPv6)
    {
      addrinfo manualHints{};
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
      return connectFromAddrs(cr, &manualHints, std::deque<ByteBuffer>{}, false, false);
    }

    // NAMED host: resolve OFF the I/O thread, EVENT-DRIVEN. Arm the resolve
    // timeout, record the single-owner pending entry, kick off the async
    // resolve, and RETURN (enqueue-only contract). The old
    // std::async(launch::async) + wait_for(2s) block is DELETED: it blocked the
    // epoll I/O thread, had an illusory timeout (the ~future joins the still-
    // running getaddrinfo), and leaked the addrinfo on the timeout path
    // (#12; cpp17 L3/L4; ts F3).
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    // AI_ADDRCONFIG: on an IPv4-only host, do NOT return AAAA for a dual-stack
    // FQDN — otherwise RFC 6724 orders the AAAA first and the single-address,
    // terminal-on-failure connect hits ENETUNREACH (a terminal fast-fail) without
    // ever trying the reachable A record (sip-voip M-1). Loopback is exempt in
    // glibc, so localhost/ip6-localhost resolution is unaffected. Resolution-time
    // filtering, orthogonal to F2 multi-address failover.
    hints.ai_flags = AI_ADDRCONFIG;

    PendingConnect &pc = _pendingConnects[cr.sid];
    if (_timerService && _config.resolveTimeout.count() > 0)
    {
      pc.resolveTimeoutId = _timerService->scheduleAfter(
        _config.resolveTimeout, [this, sid = cr.sid] { handleResolveTimeout(sid); });
    }
    testMaybeThrowAt(ConnectThrowPoint::NAMED_KICKOFF_AFTER_PENDING_INSERT);

    resolveHostAsync(cr.host, std::to_string(cr.port), hints, makeResolveContinuation(cr));
    return true;
  }

  /// \brief Build the resolver continuation (runs on a blockingIoPool thread).
  /// Captures only owned state by value + a shared_ptr copy of the post gate; it
  /// builds the resume closure OUTSIDE gate->m, then posts it onto the I/O thread
  /// iff the gate is still open (#4/#5/#8/#14). NO user callback runs under
  /// gate->m; runOnIoThread is noexcept/callback-free.
  std::function<void(iora::network::ResolveResult)> makeResolveContinuation(const ConnectReq &cr)
  {
    auto gate = _postGuard; // shared_ptr copy — keeps the gate alive
    SessionId sid = cr.sid;
    std::string host = cr.host;
    std::uint16_t port = cr.port;
    TlsMode tls = cr.tls;
    // Carry the TLS client identity BY VALUE through all resume capture layers so
    // the resumed named-host path reaches the setup site with it (arch C1 HI-1).
    std::string verifyName = cr.verifyName;
    unsigned x509HostFlags = cr.x509HostFlags;
    return [this, gate, sid, host = std::move(host), port, tls,
            verifyName = std::move(verifyName), x509HostFlags](iora::network::ResolveResult r)
    {
      // Built OUTSIDE gate->m; on bad_alloc here r (and its addrs) frees on
      // unwind and the resolve-timeout backstops the missing terminal (#16).
      std::function<void()> resume =
        [this, sid, host, port, tls, verifyName, x509HostFlags, addrs = r.addrs, gai = r.gaiCode]
        { resumeConnect(sid, host, port, tls, verifyName, x509HostFlags, addrs, gai); };
      std::lock_guard<std::mutex> g(gate->m);
      if (gate->closed)
      {
        return; // engine torn down: drop; addrs frees when r/resume drop
      }
      gate->engine->runOnIoThread(std::move(resume));
    };
  }

  /// \brief RESUME (I/O thread). Single-owner one-shot: connect ONLY if this call
  /// erased the pending entry; a stale sid (already resolved/closed/torn down)
  /// no-ops and lets \p addrs free.
  void resumeConnect(SessionId sid, const std::string &host, std::uint16_t port, TlsMode tls,
                     const std::string &verifyName, unsigned x509HostFlags,
                     std::shared_ptr<iora::network::OwnedAddrInfo> addrs, int gai)
  {
    try
    {
      auto it = _pendingConnects.find(sid);
      if (it == _pendingConnects.end())
      {
        return; // resolve-timeout or close already fired the terminal
      }
      if (_timerService && it->second.resolveTimeoutId != 0)
      {
        _timerService->cancel(it->second.resolveTimeoutId);
      }
      std::deque<ByteBuffer> buffered = std::move(it->second.buffer);
      const bool setupOverflowed = it->second.setupOverflowed;
      _pendingConnects.erase(it);

      if (gai != 0 || !addrs || !addrs->get())
      {
        // gai==0 with a null/empty chain is defensive (glibc returns EAI_* + null
        // together); resolveErrorMessage(0) would say "Success", so use a fixed
        // string for that path (sip-voip L-4).
        const std::string msg =
          (gai != 0) ? iora::network::resolveErrorMessage(gai) : "resolve returned no addresses";
        buffered.clear();
        preInsertTerminal(sid, TransportErrorInfo{TransportError::Resolve, msg});
        err(TransportError::Resolve, std::string("resolve failed: ") + msg);
        return;
      }
      connectFromAddrs(ConnectReq{sid, host, port, tls, verifyName, x509HostFlags}, addrs->get(),
                       std::move(buffered), setupOverflowed, true);
    }
    catch (...)
    {
      connectGuardFail(sid);
    }
  }

  /// \brief Resolve-timeout, TimerService thread. MARSHALS to the I/O thread —
  /// never mutates _pendingConnects directly. #8b: this-lifetime is bounded by
  /// ~TimerService joining the timer thread before _cmds/_cmdMutex/_eventFd are
  /// destroyed (they are declared BEFORE _timerService, so ~TimerService runs
  /// first). #16: if BOTH this post and the resolver post fail on bad_alloc, an
  /// async connect observer gets no terminal until teardown drains
  /// _pendingConnects.
  void handleResolveTimeout(SessionId sid)
  {
    if (runOnIoThread([this, sid] { resolveTimeoutOnIo(sid); }) || !_timerService ||
        cmdQueueClosed())
    {
      return;
    }
    try
    {
      (void)_timerService->scheduleAfter(TIMER_CLOSE_RETRY_DELAY,
                                         [this, sid]() { handleResolveTimeout(sid); });
    }
    catch (...)
    {
    }
  }

  /// \brief Resolve-timeout apply (I/O thread). One-shot eraser: fire
  /// onClose(Resolve) iff this call erased the entry; a resume that already won
  /// leaves nothing to do.
  void resolveTimeoutOnIo(SessionId sid)
  {
    try
    {
      if (_pendingConnects.count(sid) == 0)
      {
        return; // resume/close won the race
      }
      preInsertTerminal(sid, TransportErrorInfo{TransportError::Resolve, "resolve timeout"});
      err(TransportError::Resolve, "resolve timeout");
    }
    catch (...)
    {
      connectGuardFail(sid);
    }
  }

  /// \brief RAII owner of an outbound socket, its SSL object and its armed timers
  /// until the Session is inserted into _sessions (after which closeNow owns them).
  /// release() is the explicit early cleanup of a pre-insert terminal; disarm()
  /// hands ownership to _sessions. Nothing leaks if the connect path unwinds.
  struct PreInsertResources
  {
    TcpEngine *engine;
    int fd{-1};
    Session *session{nullptr};

    explicit PreInsertResources(TcpEngine *e) : engine(e) {}
    ~PreInsertResources() { release(); }
    PreInsertResources(const PreInsertResources &) = delete;
    PreInsertResources &operator=(const PreInsertResources &) = delete;

    void release() noexcept
    {
      if (session)
      {
        try
        {
          engine->cancelAllTimers(session);
        }
        catch (...)
        {
        }
        if (session->ssl)
        {
          ::SSL_free(session->ssl);
          session->ssl = nullptr;
        }
        session = nullptr;
      }
      if (fd >= 0)
      {
        ::close(fd);
        fd = -1;
      }
    }

    void disarm() noexcept
    {
      session = nullptr;
      fd = -1;
    }
  };

  /// \brief Exception guard terminal for the I/O-thread connect path (doConnect,
  /// resumeConnect, connectFromAddrs). Fires exactly one onClose(Unknown,
  /// "internal error") iff this call removed the sid from the connecting registry
  /// or from _pendingConnects; a sid already in _sessions is closed via closeNow;
  /// otherwise a terminal already fired and nothing is done. Never throws.
  void connectGuardFail(SessionId sid) noexcept
  {
    try
    {
      if (preInsertTerminal(sid, TransportErrorInfo{TransportError::Unknown, "internal error", 0, 0}))
      {
        return;
      }
      auto it = _sessions.find(sid);
      if (it != _sessions.end())
      {
        closeNow(it->second.get(), TransportError::Unknown, "internal error", 0, 0);
      }
    }
    catch (...)
    {
    }
  }

  /// \brief Connect using an EXTERNALLY-owned addrinfo chain (single-address,
  /// terminal-on-failure — core scope; F2 adds multi-address failover). NEVER
  /// calls ::freeaddrinfo — the caller owns \p res (a stack addrinfo for the
  /// literal path, or a shared_ptr<OwnedAddrInfo> for the resume path); a free
  /// here would double-free (#6, cpp17 H3). Runs on the I/O thread. \p buffered
  /// holds sends accepted while a named host resolved (empty on the literal path);
  /// they are moved into Session::wq in order. \p setupOverflowed carries the
  /// pending buffer's overflow mark into Session::setupOverflowed.
  bool connectFromAddrs(const ConnectReq &cr, addrinfo *res, std::deque<ByteBuffer> &&buffered,
                        bool setupOverflowed, bool viaResume)
  {
    try
    {
      return connectFromAddrsImpl(cr, res, std::move(buffered), setupOverflowed, viaResume);
    }
    catch (...)
    {
      connectGuardFail(cr.sid);
      return false;
    }
  }

  bool connectFromAddrsImpl(const ConnectReq &cr, addrinfo *res, std::deque<ByteBuffer> &&buffered,
                            bool setupOverflowed, bool viaResume)
  {
    std::string ps = std::to_string(cr.port);

    // Declared BEFORE `held` so the Session outlives it on unwind (held.release()
    // reads the Session's timers and SSL object).
    std::unique_ptr<Session> s;
    PreInsertResources held(this);
    addrinfo *chosen = nullptr;
    int loopErrno = 0;
    for (addrinfo *ai = res; ai; ai = ai->ai_next)
    {
      held.fd = ::socket(ai->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      if (held.fd < 0)
      {
        loopErrno = errno;
        continue;
      }
      applySockOpts(held.fd);
      int connectResult = ::connect(held.fd, ai->ai_addr, ai->ai_addrlen);
      loopErrno = connectResult == 0 ? 0 : errno;
      if (connectResult == 0 || loopErrno == EINPROGRESS)
      {
        chosen = ai;
        break;
      }
      // CRITICAL FIX for SIP: Immediately handle connection refused for local
      // connections This prevents hanging when connecting to non-existent
      // local ports
      if (loopErrno == ECONNREFUSED || loopErrno == ENETUNREACH || loopErrno == EHOSTUNREACH)
      {
        const int connectErrno = loopErrno;
        const std::string connectErr = iora::core::errnoMessage(loopErrno);

        held.release();

        // NO ::freeaddrinfo — the caller owns res (#6, cpp17 H3).
        const char *what =
          connectErrno == ECONNREFUSED ? "Connection refused to " : "Connection failed to ";
        preInsertTerminal(cr.sid,
                          TransportErrorInfo{TransportError::Connect,
                                             what + cr.host + ":" + ps + " - " + connectErr,
                                             connectErrno, 0});
        err(TransportError::Connect, "connect immediately failed: " + connectErr);
        return false;
      }
      held.release();
    }

    std::string loopErr = iora::core::errnoMessage(loopErrno);

    // Copy the peer address out of the chosen entry. NO ::freeaddrinfo — the
    // caller owns res (#6, cpp17 H3); chosen stays valid for the caller's frame,
    // but we use the copied savedPeer from here on regardless.
    sockaddr_storage savedPeer{};
    socklen_t savedPeerLen = 0;
    if (chosen)
    {
      savedPeerLen = (socklen_t)chosen->ai_addrlen;
      std::memcpy(&savedPeer, chosen->ai_addr, savedPeerLen);
    }

    if (held.fd < 0)
    {
      // Local resource exhaustion (fd limits, buffer/memory, no local address) is
      // not a failure to reach the peer: ResourceLimit, errno kept.
      const TransportError code =
        isLocalResourceErrno(loopErrno) ? TransportError::ResourceLimit : TransportError::Connect;
      preInsertTerminal(cr.sid, TransportErrorInfo{code, loopErr, loopErrno, 0});
      err(code, "connect: " + loopErr);
      return false;
    }
    const int cfd = held.fd;

    s = std::make_unique<Session>();
    held.session = s.get();
    s->id = cr.sid;
    s->fd = cfd;
    s->created = MonoClock::now();
    s->lastActivity = s->created;
    s->lastWriteProgress = s->created;
    s->connectPending = true;
    s->tcpConnectPending = true;
    s->connectStart = MonoClock::now();
    s->wq = std::move(buffered);
    s->setupOverflowed = setupOverflowed;
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

      // Single PRE-INSERTION fail-closed terminal for TLS-client setup. The session
      // is not yet in _sessions / epoll, so closeNow MUST NOT be used here (it would
      // decrement sessionsCurrent for a never-counted session and delEpoll an
      // unregistered fd). ORDER: release resources (connect timer, SSL object, fd)
      // -> erase the connecting registry -> fire exactly one onClose(TLSHandshake).
      // Shared by the SSL_new failure and every identity-binding failure so the
      // fail-closed path cannot drift (arch FAIL-CLOSED-IDENTITY-BINDING).
      auto failClosedPreInsertion = [&](const char *why)
      {
        _atomicStats.tlsFailures.fetch_add(1, std::memory_order_relaxed);
        held.release();
        preInsertTerminal(cr.sid, TransportErrorInfo{TransportError::TLSHandshake, why});
        err(TransportError::TLSHandshake, why);
      };

      s->ssl = ::SSL_new(_sslCli);
      if (!s->ssl)
      {
        // A connectSync parked on this sid must still get a terminal (the session
        // was never inserted, so a later doClose finds nothing).
        failClosedPreInsertion("SSL_new(client) failed");
        return false; // not inserted yet => no tags to clean
      }
      ::SSL_set_fd(s->ssl, cfd);
      ::SSL_set_connect_state(s->ssl);

      // ── TLS client SNI + certificate-identity binding (RFC 6125/9525) ──
      // Per-connection calls on s->ssl only (never the shared _sslCli CTX). The
      // reference identity (cr.verifyName) is DISTINCT from the connect address
      // (cr.host is a pre-resolved IP on the resolved path). Identity follows
      // verifyPeer. See architecture/iora/transport_tls_sni_identity.json (C1).
      // refName: verifyName if set, else fall back to the connect address (LO-2).
      const std::string &refName = !cr.verifyName.empty() ? cr.verifyName : cr.host;
      if (_config.clientTls.verifyPeer)
      {
        // NORMALIZE FIRST (strip a trailing FQDN '.', ASCII-lowercase via
        // StringUtils::toLower — locale-independent), THEN classify. Normalizing
        // before the IP check ensures a dot-suffixed IP literal ("127.0.0.1.") is
        // recognized as an IP and routed to the no-SNI/set1_ip_asc branch, never sent
        // as SNI (cpp17 R2 #1; SNI-IS-FOR-NAMED-HOSTS-ONLY, RFC 6066 §3). Matching is
        // case-insensitive; the SNI on the wire is the normalized form. Never a ':port'.
        std::string name = refName;
        if (!name.empty() && name.back() == '.') { name.pop_back(); }
        name = iora::core::StringUtils::toLower(name);

        // IP literal (both AF families) -> iPAddress match, NO SNI. inet_pton is
        // recomputed here on the normalized string.
        auto isIpLiteral = [](const std::string &v) -> bool
        {
          unsigned char buf[16];
          return !v.empty() && (::inet_pton(AF_INET, v.c_str(), buf) == 1 ||
                                ::inet_pton(AF_INET6, v.c_str(), buf) == 1);
        };
        X509_VERIFY_PARAM *vp = ::SSL_get0_param(s->ssl);
        if (isIpLiteral(name))
        {
          if (::X509_VERIFY_PARAM_set1_ip_asc(vp, name.c_str()) != 1)
          {
            failClosedPreInsertion("TLS identity binding failed (set1_ip_asc)");
            return false;
          }
        }
        else
        {
          if (::SSL_set_tlsext_host_name(s->ssl, name.c_str()) != 1)
          {
            failClosedPreInsertion("TLS SNI set failed");
            return false;
          }
          ::X509_VERIFY_PARAM_set_hostflags(vp, cr.x509HostFlags);
          if (::SSL_set1_host(s->ssl, name.c_str()) != 1)
          {
            failClosedPreInsertion("TLS identity binding failed (set1_host)");
            return false;
          }
        }
      }
      else
      {
        // verifyPeer=false: no SNI, no identity verification (explicitly insecure
        // / test-only). Warn so the insecure mode is visible in operator logs.
        IORA_LOG_WARN("TLS client identity verification disabled (verifyPeer=false) for "
                      + refName);
      }

      s->tlsState = TlsState::Handshake;
      s->tlsWantWrite = true; // Client needs to send ClientHello first
    }

    testMaybeThrowAt(viaResume ? ConnectThrowPoint::BEFORE_INSERT_RESUME
                               : ConnectThrowPoint::BEFORE_INSERT_LITERAL);

    Session *sPtr = s.get();
    {
      std::unique_lock<std::shared_mutex> wl(_sessionRwMutex);
      // operator[] default-constructs the (null) slot then move-assigns, all under
      // this one unique lock, so a shared-lock reader never observes a null entry.
      _sessions[cr.sid] = std::move(s);
      _connecting.erase(cr.sid);
    }
    held.disarm();
    bumpSess();

    // EPOLLRDHUP armed for uniform peer-half-close detection (defense-in-depth;
    // updateInterest is the load-bearing site since modEpoll replaces the full
    // mask — tracker 2026-09-11-19).
    std::uint32_t ev = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
    if (_config.useEdgeTriggered)
    {
      ev |= EPOLLET;
    }
    addEpoll(cfd, ev);
    auto tg = std::make_unique<Tag>();
    tg->isListener = false;
    tg->sess = sPtr;
    _fdTags.emplace(cfd, std::move(tg));

    testMaybeThrowAt(ConnectThrowPoint::AFTER_INSERT);

    // DEFENSE-IN-DEPTH: Check if the TCP connect already completed (handles
    // immediate connects) for BOTH plain TCP and TLS. This prevents edge-triggered
    // epoll from missing the initial EPOLLOUT event when the TCP handshake
    // completes before the first epoll_wait(). For TLS only the TCP phase is
    // completed here; the handshake is then driven by the pending EPOLLOUT.
    int soErr = 0;
    probeTcpEstablished(sPtr, "[IMMEDIATE-CONNECT]", soErr);
    return true;
  }

  /// \brief TCP-phase completion probe (SO_ERROR, then getpeername) for a session
  /// still in its TCP phase. Returns false iff the session was closed (caller must
  /// not touch \p s again). On success runs onTcpEstablished + updateInterest;
  /// a transient "not yet connected" leaves the session pending. \p soErrOut
  /// receives the SO_ERROR value the probe consumed (read-and-clear).
  bool probeTcpEstablished(Session *s, const char *tag, int &soErrOut)
  {
    int &soErr = soErrOut;
    soErr = 0;
    socklen_t el = sizeof(soErr);
    int rc = ::getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &soErr, &el);
    if (rc < 0)
    {
      // getsockopt() syscall failed - socket is invalid
      int gso_errno = errno;
      IORA_LOG_ERROR(tag << " getsockopt() failed for sid=" << s->id << ", errno=" << gso_errno);
      closeNow(s, TransportError::Socket,
               std::string("getsockopt failed: ") + iora::core::errnoMessage(gso_errno), gso_errno,
               0);
      return false;
    }
    if (soErr != 0)
    {
      IORA_LOG_DEBUG(tag << " SO_ERROR indicates connection failed for sid=" << s->id
                     << ", error=" << iora::core::errnoMessage(soErr));
      closeNow(s, TransportError::Connect, iora::core::errnoMessage(soErr), soErr, 0);
      return false;
    }
    // SO_ERROR == 0 doesn't mean the connection is established: for non-routable
    // addresses SO_ERROR may be 0 before the network error is detected, so verify
    // with getpeername().
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    if (::getpeername(s->fd, reinterpret_cast<struct sockaddr *>(&addr), &addrlen) == 0)
    {
      IORA_LOG_DEBUG(tag << " TCP connection established for sid=" << s->id);
      if (!onTcpEstablished(s))
      {
        return false;
      }
      updateInterest(s);
      return true;
    }
    int gp_errno = errno;
    if (gp_errno == ECONNREFUSED || gp_errno == ENETUNREACH || gp_errno == EHOSTUNREACH ||
        gp_errno == ETIMEDOUT)
    {
      IORA_LOG_DEBUG(tag << " getpeername() detected connection failure for sid=" << s->id
                     << ", errno=" << gp_errno);
      closeNow(s, TransportError::Connect, iora::core::errnoMessage(gp_errno), gp_errno, 0);
      return false;
    }
    // else ENOTCONN or other transient error - not yet established, wait for epoll/timeout
    IORA_LOG_DEBUG(tag << " getpeername() returned errno=" << gp_errno << " for sid=" << s->id
                   << ", waiting for epoll/timeout");
    return true;
  }

  /// \brief TCP-established transition for BOTH plain TCP and TLS. Clears the TCP
  /// phase, cancels the connect timer and stamps handshakeStart. For TLS it arms
  /// the handshake timer (budget = connectTimeout + handshakeTimeout); for plain
  /// TCP this is also setup completion (completeSetup). Returns false iff \p s was
  /// closed.
  bool onTcpEstablished(Session *s)
  {
    if (_beforeTcpEstablishedHook)
    {
      invokeUserCallback(_beforeTcpEstablishedHook, s->id);
    }
    s->tcpConnectPending = false;
    s->handshakeStart = MonoClock::now();
    cancelConnectTimeout(s);
    if (s->tlsMode != TlsMode::None)
    {
      scheduleHandshakeTimeout(s);
      return true;
    }
    return completeSetup(s);
  }

  /// \brief Setup completion (plain TCP at TCP-established, TLS at handshake Open):
  /// state is mutated BEFORE onConnect is invoked. A setup-overflowed session
  /// closes WriteBackpressure + ENOBUFS instead (zero bytes sent, buffered requests
  /// discarded), before any byte is flushed. Queued bytes are flushed by the
  /// EPOLLOUT path. Returns false iff \p s was closed.
  bool completeSetup(Session *s)
  {
    s->connectPending = false;
    s->lastWriteProgress = MonoClock::now();
    if (s->setupOverflowed)
    {
      _atomicStats.backpressureCloses.fetch_add(1, std::memory_order_relaxed);
      closeNow(s, TransportError::WriteBackpressure, "write queue overflow", ENOBUFS, 0);
      return false;
    }
    if (!s->wq.empty())
    {
      scheduleWriteStallTimeout(s);
    }
    const auto connectCb = copyCallback(_cbMutex, _cbs.onConnect);
    if (connectCb)
    {
      _atomicStats.connected.fetch_add(1, std::memory_order_relaxed);
      invokeUserCallback(connectCb, s->id, addressFromSockaddr(s->peer));
    }
    return true;
  }

  void onSession(Session *s, std::uint32_t events)
  {
    if (!s || s->closed.load(std::memory_order_relaxed))
    {
      return;
    }

    IORA_LOG_DEBUG("[EPOLL-EVENT] onSession called for sid=" << s->id
                   << ", events=0x" << std::hex << events << std::dec
                   << ", tcpConnectPending=" << s->tcpConnectPending
                   << ", tlsMode=" << static_cast<int>(s->tlsMode));

    // TCP phase, BOTH plain TCP and TLS (A1.2): on ANY event, first probe
    // establishment (SO_ERROR, then getpeername): an EPOLLIN must never recv() on,
    // or drive a TLS handshake over, a socket whose connect is unconfirmed. Gated on
    // tcpConnectPending so a TLS handshake's or an ESTABLISHED session's async
    // socket error is never mislabeled Connect (tracker 2026-09-11-19 cpp17-#1):
    // those surface via the handshake, EPOLLHUP|EPOLLERR or the read/write paths.
    if (s->tcpConnectPending)
    {
      int probeSoErr = 0;
      if (!probeTcpEstablished(s, "[EPOLL-EVENT]", probeSoErr))
      {
        return;
      }
      if (s->tcpConnectPending)
      {
        // Still in the TCP phase: no read, no handshake, no flush; only a
        // peer/network error terminates it, always with a non-zero sysErrno.
        if (events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP))
        {
          int e = eventCloseErrno(s);
          if (e == 0)
          {
            e = probeSoErr != 0 ? probeSoErr : ECONNABORTED;
          }
          closeNow(s, TransportError::PeerClosed,
                   (events & (EPOLLHUP | EPOLLERR)) ? "Connection closed by peer (EPOLLHUP/EPOLLERR)"
                                                    : "Connection closed by peer (EPOLLRDHUP)",
                   e, 0);
        }
        return;
      }
    }

    if (inHandshake(s))
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

    // Handle error conditions first (connection closed, etc.)
    if (events & (EPOLLHUP | EPOLLERR))
    {
      core::Logger::debug("Transport: Detected EPOLLHUP/EPOLLERR for session " +
                          std::to_string(s->id) + ", events=0x" + std::to_string(events));
      closeNow(s, TransportError::PeerClosed, "Connection closed by peer (EPOLLHUP/EPOLLERR)",
               eventCloseErrno(s), 0);
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
    // Peer half-close (FIN) — the sole disconnect signal for a read-DISABLED
    // (write-only, e.g. SSE) session, whose EPOLLIN is withheld so the EOF-read
    // path above never runs for it (tracker 2026-09-11-19). This branch MUST come
    // AFTER the EPOLLIN drain + re-lookup: a read-ENABLED peer FIN co-delivers
    // EPOLLIN, so readAvail fully drains the inbound bytes and closes on recv()==0
    // (freeing s -> the re-lookup returns above) BEFORE this branch is reached —
    // so no inbound data is truncated, and this branch is effectively
    // read-disabled-only. It MUST return immediately after closeNow: closeNow
    // erases + frees the Session, so falling through to the EPOLLOUT/writePending
    // block below would dereference freed memory (use-after-free).
    if (events & EPOLLRDHUP)
    {
      closeNow(s, TransportError::PeerClosed, "Connection closed by peer (EPOLLRDHUP)",
               eventCloseErrno(s), 0);
      return;
    }
    if (events & EPOLLOUT)
    {
      writePending(s);
    }
  }

  /// \brief Close a failed TLS handshake (TLSHandshake) and count the failure.
  void failHandshake(Session *s, const std::string &msg, int sysErrno, int tlsErr)
  {
    closeNow(s, TransportError::TLSHandshake, msg, sysErrno, tlsErr);
    _atomicStats.tlsFailures.fetch_add(1, std::memory_order_relaxed);
  }

  bool driveHandshake(Session *s)
  {
    // Only check timeout here if high-resolution timers are not available. Reached
    // only after the TCP phase (onSession gates the handshake on !tcpConnectPending),
    // so the budget runs from handshakeStart.
    if (!_timerService && _config.handshakeTimeout.count() > 0 &&
        (MonoClock::now() - s->handshakeStart) > _config.handshakeTimeout)
    {
      closeNow(s, TransportError::TLSHandshake, "TLS handshake timeout", ETIMEDOUT, 0);
      return false;
    }

    // B6 Hook: Allow subclass to inject fault before handshake
    if (!beforeSslHandshake(s->id, s->peerKey))
    {
      failHandshake(s, getInjectedErrorMessage(), 0, getInjectedSslError());
      return false;
    }

    ::ERR_clear_error();
    errno = 0;
    int rc = ::SSL_do_handshake(s->ssl);
    const int hsErrno = errno;
    if (rc == 1)
    {
      // B6 Hook: Allow subclass to reject successful handshake
      if (!afterSslHandshake(s->id, true, 0))
      {
        failHandshake(s, getInjectedErrorMessage(), 0, getInjectedSslError());
        return false;
      }

      // ── TLS client certificate-identity gate (RFC 6125/9525) ──
      // Runs at handshake success, BEFORE onConnect below, so a failure yields
      // exactly ONE onClose(TLSHandshake) and never a preceding onConnect. This
      // is POST-insertion (session is in _sessions + epoll), so closeNow is the
      // correct terminal here. Client-role guarded (R2-H1): driveHandshake is
      // shared with server-accepted sessions (SSL_set_accept_state), which do not
      // present a client cert by default — an unguarded peer-cert demand would
      // reject every inbound TLS handshake on a dual-role engine.
      // WHY BOTH CHECKS ARE GENUINE BACKSTOPS (not redundant with SSL_VERIFY_PEER):
      //  - A cert PRESENT but failing chain/hostname aborts at SSL_do_handshake
      //    (rc!=1) under SSL_VERIFY_PEER + SSL_set1_host, so the vr!=X509_V_OK check
      //    is defense-in-depth for that case.
      //  - A cert-less / ANONYMOUS handshake: per the OpenSSL contract SSL_VERIFY_PEER
      //    is IGNORED when no certificate is sent, and SSL_get_verify_result() returns
      //    X509_V_OK — so if an anon/PSK suite is negotiated the handshake COMPLETES
      //    (rc==1) and THIS gate's !pc check is the SOLE rejecter. A compliant client
      //    aborts anon at negotiation (verified: a TLS alert, rc!=1), so the !pc branch
      //    is not reachable black-box; it is exercised via the fetchPeerCertificate
      //    test seam (steps-4-8 M-A, human sign-off 2026-09-11). See
      //    architecture/iora/transport_tls_sni_identity.json PEER-CERT-PRESENCE.
      if (s->tlsMode == TlsMode::Client && _config.clientTls.enabled &&
          _config.clientTls.verifyPeer)
      {
        X509 *pc = fetchPeerCertificate(s->ssl); // test seam; default = SSL_get1_peer_certificate
        if (!pc)
        {
          failHandshake(s, "no peer certificate", 0, 0);
          return false;
        }
        long vr = ::SSL_get_verify_result(s->ssl);
        if (vr != X509_V_OK)
        {
          ::X509_free(pc);
          failHandshake(s, ::X509_verify_cert_error_string(vr), 0, static_cast<int>(vr));
          return false;
        }
        ::X509_free(pc);
      }

      s->tlsState = TlsState::Open;
      s->tlsWantWrite = false; // Reset handshake tracking
      _atomicStats.tlsHandshakes.fetch_add(1, std::memory_order_relaxed);
      cancelHandshakeTimeout(s);
      if (!completeSetup(s))
      {
        return false;
      }
      // Arms EPOLLOUT when the handshake queue holds bytes to flush.
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
      failHandshake(s, getInjectedErrorMessage(), 0, getInjectedSslError());
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

    bool unexpectedEof = false;
    const unsigned long e = drainSslErrors(unexpectedEof);
    failHandshake(s, sslFailureMessage(errc, e, hsErrno),
                  handshakeFailureErrno(errc, hsErrno, e, unexpectedEof), (int)e);
    return false;
  }

  /// \brief Close message for a failed SSL call. SSL_ERROR_SYSCALL leaves the
  /// OpenSSL error queue empty (ERR_error_string would read
  /// "error:00000000:lib(0)::reason(0)"), so it reports the syscall errno text, or
  /// "unexpected EOF" when errno is 0; otherwise the queued OpenSSL error string.
  static std::string sslFailureMessage(int sslError, unsigned long errCode, int sysErrno)
  {
    if (sslError == SSL_ERROR_SYSCALL && errCode == 0)
    {
      return sysErrno != 0 ? iora::core::errnoMessage(sysErrno) : std::string("unexpected EOF");
    }
    char msg[256];
    ::ERR_error_string_n(errCode, msg, sizeof(msg));
    return msg;
  }

  /// \brief Pop the whole OpenSSL error queue: returns the FIRST (earliest) error
  /// code (0 if the queue is empty) and sets \p unexpectedEof if ANY queued error
  /// is SSL_R_UNEXPECTED_EOF_WHILE_READING.
  static unsigned long drainSslErrors(bool &unexpectedEof)
  {
    unexpectedEof = false;
    const unsigned long first = ::ERR_get_error();
    for (unsigned long e = first; e != 0; e = ::ERR_get_error())
    {
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
      if (ERR_GET_REASON(e) == SSL_R_UNEXPECTED_EOF_WHILE_READING)
      {
        unexpectedEof = true;
      }
#endif
    }
    return first;
  }

  /// \brief Raw classification of a failed SSL_do_handshake into a sysErrno:
  /// SSL_ERROR_SYSCALL with an errno -> that errno; EOF without an alert (a queued
  /// SSL_R_UNEXPECTED_EOF_WHILE_READING, or SSL_ERROR_SYSCALL with neither an errno
  /// nor a queued error) -> ECONNABORTED; an alert, close_notify, verify failure, or
  /// SSL_ERROR_SYSCALL with a queued protocol error -> 0. This is role-AGNOSTIC: it
  /// is the transport-abort discriminator only for an OUTBOUND (client-role) session;
  /// closeNow applies the role scope (a server-role TLSHandshake close is zeroed
  /// centrally there), so the discriminator never leaks into an inbound session.
  static int handshakeFailureErrno(int sslError, int hsErrno, unsigned long errCode,
                                   bool unexpectedEof)
  {
    if (sslError == SSL_ERROR_SYSCALL && hsErrno != 0)
    {
      return hsErrno;
    }
    if (unexpectedEof)
    {
      return ECONNABORTED;
    }
    if (sslError == SSL_ERROR_SYSCALL && errCode == 0)
    {
      return ECONNABORTED;
    }
    return 0;
  }

  /// \brief Close \p s with TLSIO for a failed SSL_read/SSL_write (\p sslError from
  /// SSL_get_error, \p sysErrno the errno captured right after the call).
  void closeTlsIo(Session *s, int sslError, int sysErrno)
  {
    const unsigned long e = ::ERR_get_error();
    closeNow(s, TransportError::TLSIO, sslFailureMessage(sslError, e, sysErrno),
             sslError == SSL_ERROR_SYSCALL ? sysErrno : 0, (int)e);
  }

  void readAvail(Session *s)
  {
    std::vector<std::uint8_t> buf(_config.ioReadChunk);
    for (;;)
    {
      int n = 0;
      if (s->tlsMode != TlsMode::None && s->tlsState == TlsState::Open)
      {
        // B6 Hook: Allow subclass to inject read fault
        if (!beforeSslRead(s->id))
        {
          closeNow(s, TransportError::TLSIO, getInjectedErrorMessage(), 0, getInjectedSslError());
          return;
        }

        errno = 0;
        n = ::SSL_read(s->ssl, buf.data(), (int)buf.size());
        const int readErrno = errno;
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
            closeNow(s, TransportError::PeerClosed, "TLS peer closed", 0, 0);
            return;
          }
          closeTlsIo(s, ge, readErrno);
          return;
        }
      }
      else
      {
        n = ::recv(s->fd, buf.data(), (int)buf.size(), 0);
        const int recvErrno = errno;
        IORA_LOG_DEBUG("[RECV] recv() called for sid=" << s->id << ", returned n=" << n << ", errno=" << recvErrno);
        if (n < 0)
        {
          if (recvErrno == EAGAIN || recvErrno == EWOULDBLOCK)
          {
            IORA_LOG_DEBUG("[RECV] EAGAIN/EWOULDBLOCK for sid=" << s->id << ", breaking from read loop");
            break;
          }
          closeNow(s, TransportError::Socket, iora::core::errnoMessage(recvErrno), recvErrno, 0);
          return;
        }
        if (n == 0)
        {
          core::Logger::debug("Transport: recv() returned 0 for session " + std::to_string(s->id) +
                              " - peer closed connection");
          closeNow(s, TransportError::PeerClosed, "peer closed", 0, 0);
          return;
        }
      }

      if (n > 0)
      {
        _atomicStats.bytesIn.fetch_add(n, std::memory_order_relaxed);
        s->lastActivity = MonoClock::now();
        const auto dataCb = copyCallback(_cbMutex, _cbs.onData);
        if (dataCb)
        {
          IORA_LOG_DEBUG("[RECV] Calling onData callback for sid=" << s->id << ", bytes=" << n);
          invokeUserCallback(dataCb, s->id, iora::core::BufferView{buf.data(), (std::size_t)n},
                             std::chrono::steady_clock::now());
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
          closeNow(s, TransportError::TLSIO, getInjectedErrorMessage(), 0, getInjectedSslError());
          return;
        }

        errno = 0;
        n = ::SSL_write(s->ssl, d.data(), (int)d.size());
        const int writeErrno = errno;
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
          closeTlsIo(s, ge, writeErrno);
          return;
        }
      }
      else
      {
        n = ::send(s->fd, d.data(), (int)d.size(), MSG_NOSIGNAL);
        const int sendErrno = errno;
        if (n < 0)
        {
          if (sendErrno == EAGAIN || sendErrno == EWOULDBLOCK)
          {
            s->wantWrite = true;
            updateInterest(s);
            break;
          }
          closeNow(s, TransportError::Socket, iora::core::errnoMessage(sendErrno), sendErrno, 0);
          return;
        }
      }

      if (n >= 0)
      {
        _atomicStats.bytesOut.fetch_add(n, std::memory_order_relaxed);
        s->lastWriteProgress = MonoClock::now();
        // Write progress counts as activity: a write-only, actively-flushing session
        // receiving no inbound bytes must not be idle-GC'd mid-flush (matches
        // queueRemainderAfterWrite, which sets both).
        s->lastActivity = s->lastWriteProgress;

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
    // C5: withhold EPOLLIN while read is disabled for this session. This is the
    // single EPOLLIN re-arm site for established sessions, so gating here keeps a
    // ReadMode::Disabled session from re-arming read events. EPOLLOUT (needWrite)
    // and the edge-triggered flag below are unaffected.
    std::uint32_t ev = 0;
    // Peer half-close (FIN) detection is a connection-lifecycle event, armed
    // INDEPENDENTLY of the C5 application-data read-gate below (tracker
    // 2026-09-11-19). A read-disabled (write-only, e.g. SSE) session withholds
    // EPOLLIN, so EPOLLRDHUP is its ONLY peer-FIN signal; without it a graceful
    // client close is invisible to epoll and the disconnect observer never fires.
    // Harmless for read-enabled sessions: their FIN co-delivers EPOLLIN and is
    // drained+closed via readAvail's EOF path before the RDHUP branch is reached.
    ev |= EPOLLRDHUP;
    // C5 read-gate (braced per R-FMT-5, CF-L4). CF-M2: during the TLS handshake
    // force EPOLLIN regardless of readEnabled — handshake reads
    // (SSL_ERROR_WANT_READ) are protocol-level, not application data, so
    // withholding EPOLLIN mid-handshake would starve them and stall the session
    // until the handshake timeout. The C5 read-disable only suppresses delivery
    // of APPLICATION data.
    if (s->readEnabled || inHandshake(s))
    {
      ev |= EPOLLIN;
    }
    if (_config.useEdgeTriggered)
    {
      ev |= EPOLLET;
    }
    // EPOLLOUT policy. Outside the TLS handshake: pending writes, or the TCP
    // connect still pending (keep EPOLLOUT armed so the connect completion is seen
    // even in edge-triggered mode). DURING the TLS handshake (either role): ONLY the
    // TCP connect or SSL's own SSL_ERROR_WANT_WRITE -- never queued application
    // bytes, which cannot be flushed before Open. Arming EPOLLOUT on a writable fd
    // mid-handshake makes every EPOLL_CTL_MOD re-fire immediately (a busy loop);
    // the Open transition re-derives the interest and arms EPOLLOUT for the flush.
    const bool needWrite = inHandshake(s)
                             ? (s->tcpConnectPending || s->tlsWantWrite)
                             : (s->wantWrite || !s->wq.empty() || s->connectPending);
    if (needWrite)
    {
      ev |= EPOLLOUT;
    }
    modEpoll(s->fd, ev);
  }

  /// \brief C5 (I/O thread): apply a read enable/disable for a session. Sets the
  /// per-session readEnabled flag then re-derives the epoll interest via
  /// updateInterest, which withholds/restores EPOLLIN while preserving EPOLLOUT
  /// (iff a write is pending) and the edge-triggered flag (iff config).
  void doSetReadEnabled(SessionId sid, bool enabled)
  {
    auto it = _sessions.find(sid);
    if (it == _sessions.end())
    {
      return;
    }
    Session *s = it->second.get();
    if (s->closed.load(std::memory_order_relaxed))
    {
      return;
    }
    s->readEnabled = enabled;
    updateInterest(s);
  }

  void doSend(SendReq &&sr)
  {
    IORA_LOG_DEBUG("[IO-THREAD] doSend() called for sid=" << sr.sid << ", payload size=" << sr.payload.size());

    auto it = _sessions.find(sr.sid);
    if (it == _sessions.end())
    {
      // Named host still resolving: buffer in FIFO order behind the connect.
      auto pit = _pendingConnects.find(sr.sid);
      if (pit != _pendingConnects.end())
      {
        // Setup-phase buffer: an overflow marks the entry and discards the new
        // payload; the session closes WriteBackpressure at setup completion.
        if (pit->second.buffer.size() >= _config.maxWriteQueue)
        {
          pit->second.setupOverflowed = true;
          return;
        }
        pit->second.buffer.emplace_back(std::move(sr.payload));
        return;
      }
      IORA_LOG_DEBUG("[IO-THREAD] doSend() - session " << sr.sid << " not found");
      return;
    }
    Session *s = it->second.get();
    if (s->closed.load(std::memory_order_relaxed))
    {
      IORA_LOG_DEBUG("[IO-THREAD] doSend() - session " << sr.sid << " is closed");
      return;
    }

    IORA_LOG_DEBUG("[IO-THREAD] doSend() - session " << sr.sid << " wq.size=" << s->wq.size()
                  << ", tlsMode=" << (int)s->tlsMode << ", fd=" << s->fd);

    // Setup phase: queue, never ::send, and leave the epoll interest alone. While
    // the TCP connect is pending EPOLLOUT is already armed and the flush happens at
    // TCP-established (a failed connect then surfaces as onClose(Connect), never
    // Socket). During the TLS handshake no raw bytes may be sent (the peer's
    // SSL_accept would fail on non-TLS data) and EPOLLOUT must not be armed for
    // them (busy loop, see updateInterest); the flush happens at Open. A
    // setup-phase overflow marks the session and discards the new payload; the
    // connect/handshake keeps running so a dead peer still reports
    // Connect/TLSHandshake, and a successful setup closes WriteBackpressure before
    // any byte is flushed.
    if (!sessionWritable(s))
    {
      IORA_LOG_DEBUG("[IO-THREAD] setup in progress for sid=" << sr.sid
                    << ", queuing " << sr.payload.size() << " bytes until writable");
      if (s->wq.size() >= _config.maxWriteQueue)
      {
        s->setupOverflowed = true;
        return;
      }
      s->wq.emplace_back(std::move(sr.payload));
      return;
    }

    if (s->wq.empty())
    {
      int n = 0;
      if (s->tlsMode != TlsMode::None && s->tlsState == TlsState::Open)
      {
        // B6 Hook: Allow subclass to inject write fault
        if (!beforeSslWrite(s->id, sr.payload.size()))
        {
          closeNow(s, TransportError::TLSIO, getInjectedErrorMessage(), 0, getInjectedSslError());
          return;
        }

        IORA_LOG_DEBUG("[IO-THREAD] About to call SSL_write for sid=" << sr.sid << ", size=" << sr.payload.size());
        errno = 0;
        n = ::SSL_write(s->ssl, sr.payload.data(), (int)sr.payload.size());
        const int writeErrno = errno;
        IORA_LOG_DEBUG("[IO-THREAD] SSL_write returned " << n << " for sid=" << sr.sid);
        if (n > 0)
        {
          queueRemainderAfterWrite(s, sr.payload, n);
          return;
        }
        int ge = ::SSL_get_error(s->ssl, n);
        if (!(ge == SSL_ERROR_WANT_WRITE || ge == SSL_ERROR_WANT_READ))
        {
          IORA_LOG_DEBUG("[IO-THREAD] SSL error for sid=" << sr.sid << ", ssl_error=" << ge);
          closeTlsIo(s, ge, writeErrno);
          return;
        }
        IORA_LOG_DEBUG("[IO-THREAD] SSL_write would block for sid=" << sr.sid << ", queuing data");
      }
      else
      {
        n = ::send(s->fd, sr.payload.data(), (int)sr.payload.size(), MSG_NOSIGNAL);
        const int sendErrno = errno;
        IORA_LOG_DEBUG("[IO-THREAD] ::send() for sid=" << sr.sid << " returned " << n
                      << " (requested " << sr.payload.size() << " bytes)");
        if (n >= 0)
        {
          queueRemainderAfterWrite(s, sr.payload, n);
          return;
        }
        if (!(sendErrno == EAGAIN || sendErrno == EWOULDBLOCK))
        {
          IORA_LOG_DEBUG("[IO-THREAD] Socket error for sid=" << sr.sid << ", errno=" << sendErrno);
          closeNow(s, TransportError::Socket, iora::core::errnoMessage(sendErrno), sendErrno, 0);
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
    // Stream sessions never drop queued bytes: overflow of an established
    // session's queue closes it (closeOnBackpressure is forced on for TCP/TLS).
    if (s->wq.size() > _config.maxWriteQueue)
    {
      _atomicStats.backpressureCloses.fetch_add(1, std::memory_order_relaxed);
      IORA_LOG_DEBUG("[IO-THREAD] Write queue overflow for sid=" << sr.sid << ", closing connection");
      closeNow(s, TransportError::WriteBackpressure, "write queue overflow", 0, 0);
      return;
    }
    s->wantWrite = true;
    updateInterest(s);
    IORA_LOG_DEBUG("[IO-THREAD] doSend() completed for sid=" << sr.sid << ", final wq.size=" << s->wq.size());
  }

  /// \brief Account a direct write of \p n >= 0 bytes of \p payload (doSend, empty
  /// queue) and queue any unsent remainder at the FRONT of wq, arming the
  /// write-stall timer and EPOLLOUT for it.
  void queueRemainderAfterWrite(Session *s, const ByteBuffer &payload, int n)
  {
    _atomicStats.bytesOut.fetch_add(n, std::memory_order_relaxed);
    s->lastActivity = MonoClock::now();
    s->lastWriteProgress = s->lastActivity;
    if (static_cast<std::size_t>(n) >= payload.size())
    {
      return;
    }
    IORA_LOG_DEBUG("[IO-THREAD] PARTIAL WRITE for sid=" << s->id << ": sent " << n << " of "
                   << payload.size() << " bytes, queuing remaining " << (payload.size() - n)
                   << " bytes");
    s->wq.emplace_front(payload.begin() + n, payload.end());
    scheduleWriteStallTimeout(s);
    s->wantWrite = true;
    updateInterest(s);
  }

  /// \brief Terminal close of an inserted session. \p sysErrno is supplied by the
  /// caller (never ambient errno): the errno captured immediately after the
  /// failing syscall, SO_ERROR for an event-only trigger, or an explicit value for
  /// timer/app closes. The reported code follows the setup-close invariant
  /// (setupCloseCode); a server-role TLSHandshake close reports sysErrno 0 (the
  /// transport-abort discriminator is client-role only). ORDER: the allocating
  /// steps (onClose copy, TransportErrorInfo) run BEFORE the session is marked
  /// closed and erased, so a throw leaves it intact and owned; then the release,
  /// then exactly one onClose.
  void closeNow(Session *s, TransportError why, const std::string &msg, int sysErrno, int tlsErr)
  {
    if (!s || s->closed.load(std::memory_order_relaxed))
    {
      return;
    }
    IORA_LOG_DEBUG("[IO-THREAD] closeNow called for session " << s->id << ", reason: " << msg);
    const TransportError code = setupCloseCode(s, why);
    // Producer invariant (A4.6): the TLS transport-abort discriminator -- a non-zero
    // sysErrno on a TLSHandshake close -- is meaningful ONLY for an outbound
    // (client-role) session; it is what iora_sip's reachability probe consumes. A
    // server-role (accepted) handshake abort has no reachability consumer, so its
    // sysErrno is zeroed HERE, centrally, covering the real syscall errno, the
    // handshake-timeout ETIMEDOUT and the EOF synthesis alike. This is what keeps an
    // unauthenticated inbound RST/EOF from ever injecting a peer-down signal into
    // failover (RFC 3261 s16.7 blast radius).
    if (code == TransportError::TLSHandshake && s->tlsMode != TlsMode::Client)
    {
      sysErrno = 0;
    }
    const auto closeCb = copyCallback(_cbMutex, _cbs.onClose);
    const TransportErrorInfo info{code, msg, sysErrno, tlsErr};

    s->closed.store(true, std::memory_order_relaxed);
    cancelAllTimersNoThrow(s);

    // Save fields before erasing session from map
    const int fd = s->fd;
    const SessionId sid = s->id;
    SSL *ssl = s->ssl;
    s->ssl = nullptr; // Take ownership to prevent double-free

    delEpoll(fd);
    _fdTags.erase(fd); // erase-by-key: no-op if absent

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

    // A scoped detail::FdCloser runs the pre-close seam + ::close here (fd-reuse fix,
    // tracker 2026-09-15-3) — the single close primitive shared with shutdownDrain.
    {
      detail::FdCloser closer(fd, &_preCloseHook);
    }

    _atomicStats.closed.fetch_add(1, std::memory_order_relaxed);
    _atomicStats.sessionsCurrent.fetch_sub(1, std::memory_order_relaxed);

    invokeUserCallback(closeCb, sid, info);
  }

  /// \brief cancelAllTimers for a terminal path that must not unwind.
  void cancelAllTimersNoThrow(Session *s) noexcept
  {
    try
    {
      cancelAllTimers(s);
    }
    catch (...)
    {
    }
  }

  struct GcClose
  {
    SessionId sid;
    TransportError reason;
    const char *msg;
    int sysErrno;
  };

  void runGc()
  {
    _atomicStats.gcRuns.fetch_add(1, std::memory_order_relaxed);
    try
    {
      applyLostTimerCloses();
    }
    catch (...)
    {
    }
    const auto now = MonoClock::now();
    const bool age = _config.maxConnAge.count() > 0;

    std::vector<GcClose> toClose;
    try
    {
      collectGcCloses(now, age, toClose);
    }
    catch (...)
    {
    }

    for (const auto &gc : toClose)
    {
      auto it = _sessions.find(gc.sid);
      if (it == _sessions.end())
      {
        continue;
      }
      try
      {
        closeNow(it->second.get(), gc.reason, gc.msg, gc.sysErrno, 0);
      }
      catch (...)
      {
        closeAfterDispatchThrow(gc.sid);
      }
    }
  }

  /// \brief runGc scan: append every session past a GC deadline to \p toClose.
  void collectGcCloses(MonoTime now, bool age, std::vector<GcClose> &toClose)
  {
    toClose.reserve(_sessions.size());
    for (auto &kv : _sessions)
    {
      Session *s = kv.second.get();
      if (s->closed.load(std::memory_order_relaxed))
      {
        continue;
      }

      // Idle expiry exempts sessions still in setup, so the connect/handshake
      // budgets own them: outbound TCP connect + TLS handshake (connectPending),
      // AND inbound (accepted) TLS handshake (inHandshake -- an accepted session is
      // never connectPending, so !connectPending alone would let idleTimeout <
      // handshakeTimeout close it as GCClosed instead of TLSHandshake). A4.4.
      if (_config.idleTimeout.count() > 0 && !s->connectPending && !inHandshake(s) &&
          (now - s->lastActivity) > _config.idleTimeout)
      {
        toClose.push_back({s->id, TransportError::GCClosed, "GC safety-net timeout", 0});
        _atomicStats.gcClosedIdle.fetch_add(1, std::memory_order_relaxed);
        continue;
      }

      if (age && (now - s->created) > _config.maxConnAge)
      {
        toClose.push_back({s->id, TransportError::GCClosed, "GC safety-net timeout", 0});
        _atomicStats.gcClosedAged.fetch_add(1, std::memory_order_relaxed);
        continue;
      }

      // Deadline fallback: applied to a phase whose high-resolution timer is not
      // armed -- timers disabled, or its id is 0 because the TimerService refused
      // it (capacity) or its timer-originated close was lost.
      // Connect timeout (TCP phase, from connectStart).
      if (_config.connectTimeout.count() > 0 && s->tcpConnectPending &&
          (!_timerService || s->connectTimeoutId == 0) &&
          (now - s->connectStart) > _config.connectTimeout)
      {
        toClose.push_back({s->id, TransportError::Connect, "Connect timeout", ETIMEDOUT});
        continue;
      }

      // TLS handshake timeout (after the TCP phase, from handshakeStart).
      if (inHandshake(s) && !s->tcpConnectPending && _config.handshakeTimeout.count() > 0 &&
          (!_timerService || s->handshakeTimeoutId == 0) &&
          (now - s->handshakeStart) > _config.handshakeTimeout)
      {
        toClose.push_back({s->id, TransportError::TLSHandshake, "TLS handshake timeout", ETIMEDOUT});
        continue;
      }

      // Write stall with queued data, only once the session is writable.
      if (_config.writeStallTimeout.count() > 0 && sessionWritable(s) && !s->wq.empty() &&
          (!_timerService || s->writeStallTimeoutId == 0) &&
          (now - s->lastWriteProgress) > _config.writeStallTimeout)
      {
        toClose.push_back({s->id, TransportError::Timeout, "Write stall timeout", 0});
        continue;
      }
    }
  }

  void bumpSess()
  {
    auto cur = _atomicStats.sessionsCurrent.fetch_add(1) + 1;
    auto pk = _atomicStats.sessionsPeak.load(std::memory_order_relaxed);
    while (cur > pk && !_atomicStats.sessionsPeak.compare_exchange_weak(pk, cur, std::memory_order_relaxed))
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
    // Apply the configured DSCP mark to the DATA socket at creation (C1). Called
    // for every accepted server-peer fd and every connected client fd; 0 leaves
    // the default best-effort marking. This is the production path — the SIP
    // presets (forSipTcp) set dscpValue=24 (CS3) for signaling QoS.
    if (_config.dscpValue != 0)
    {
      (void)applyDscpToFd(fd, _config.dscpValue);
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

  // Apply a HARD TLS 1.2 minimum-version floor to a context: an operator may
  // RAISE the minimum (e.g. TLS 1.3) but never lower it below 1.2 (BCP 195 /
  // RFC 9325). configuredMin == 0 (unset) floors to 1.2; a positive value below
  // 1.2 is clamped up.
  static void applyTls12Floor(::SSL_CTX *ctx, int configuredMin)
  {
    const int minVer = configuredMin < TLS1_2_VERSION ? TLS1_2_VERSION : configuredMin;
    ::SSL_CTX_set_min_proto_version(ctx, minVer);
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
        // Fail fast on a server cert/key MISMATCH (each file loaded but the
        // private key does not match the leaf certificate). The client context
        // already does this; without it a mismatch would bind a listener that
        // fails every handshake instead of failing at startup.
        if (::SSL_CTX_check_private_key(_sslSrv) != 1)
        {
          setLastFatal(IoResult::failure(TransportError::Config, "server cert/key mismatch"));
          err(TransportError::Config, "server cert/key mismatch");
          return false;
        }
        // Fail fast on an EXPIRED server certificate (validity is otherwise
        // load-time-invisible — it would only surface at the first handshake).
        // X509_cmp_time(t, nullptr) compares t against the current time and
        // returns 0 on a parse error, so treat 0 (unparseable) and <0 (notAfter
        // already in the past) as failure. (Not-yet-valid / notBefore is handled
        // separately — see tracker 2026-06-29-4 — to avoid a boot clock-skew
        // foot-gun.)
        if (X509 *serverCert = ::SSL_CTX_get0_certificate(_sslSrv))
        {
          int cmp = ::X509_cmp_time(::X509_get0_notAfter(serverCert), nullptr);
          if (cmp == 0 || cmp < 0)
          {
            setLastFatal(IoResult::failure(TransportError::Config,
              "server cert expired or has an unparseable notAfter"));
            err(TransportError::Config, "server cert expired/unparseable notAfter");
            return false;
          }
        }
      }
      if (_config.serverTls.verifyPeer)
      {
        ::SSL_CTX_set_verify(_sslSrv, SSL_VERIFY_PEER, nullptr);
        if (!_config.serverTls.caFile.empty() || !_config.serverTls.caPath.empty())
        {
          if (::SSL_CTX_load_verify_locations(_sslSrv,
                _config.serverTls.caFile.empty() ? nullptr : _config.serverTls.caFile.c_str(),
                _config.serverTls.caPath.empty() ? nullptr : _config.serverTls.caPath.c_str()) != 1)
          {
            setLastFatal(IoResult::failure(TransportError::Config, "server load CA failed"));
            err(TransportError::Config, "server load CA");
            return false;
          }
        }
        else
        {
          // Server-side client-cert verification (mTLS) with no explicit trust
          // anchor would silently fall back to the system root store, accepting
          // any publicly-rooted client cert. Fail fast — this is a
          // misconfiguration. (Client-side verification against system roots is
          // legitimate and is left unchanged below.)
          setLastFatal(IoResult::failure(TransportError::Config,
            "server verifyPeer set with no CA file/path"));
          err(TransportError::Config, "server verifyPeer with no CA");
          return false;
        }
      }
      if (_config.serverTls.verifyDepth > 0)
      {
        ::SSL_CTX_set_verify_depth(_sslSrv, _config.serverTls.verifyDepth);
      }
      applyTls12Floor(_sslSrv, _config.serverTls.minVersion);
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
        if (!_config.clientTls.caFile.empty() || !_config.clientTls.caPath.empty())
        {
          if (::SSL_CTX_load_verify_locations(_sslCli,
                _config.clientTls.caFile.empty() ? nullptr : _config.clientTls.caFile.c_str(),
                _config.clientTls.caPath.empty() ? nullptr : _config.clientTls.caPath.c_str()) != 1)
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
      if (_config.clientTls.verifyDepth > 0)
      {
        ::SSL_CTX_set_verify_depth(_sslCli, _config.clientTls.verifyDepth);
      }
      applyTls12Floor(_sslCli, _config.clientTls.minVersion);
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
  // _eventFd is the ONLY descriptor written off the I/O thread (the enqueue()
  // wakeup ::write). Its write and the shutdownDrain() ::close are serialized
  // under _cmdMutex (see enqueue/shutdownDrain); it is created EFD_NONBLOCK so
  // the wakeup write held under _cmdMutex is bounded and cannot block. _timerFd
  // and _epollFd are I/O-thread-confined (all accessors run on the loop thread)
  // and therefore need no lock; do not add an off-thread accessor for them
  // without revisiting this invariant.
  int _epollFd{-1}, _eventFd{-1}, _timerFd{-1};
  std::thread _loop;
  // Deferred self-destruct deleter (delete-this-at-thread-end). Written and read
  // ONLY on the I/O thread (set in scheduleSelfDestruct pre-detach; run in the
  // loop-lambda epilogue post-loop()); no synchronization — see EngineBase.
  std::function<void()> _selfDestruct;

  // Lock ordering: _cmdMutex, _cbMutex, _sessionRwMutex, _fatalMx and
  // _lostTimerMutex are mutually-exclusive LEAVES — at most one is held at a time;
  // no nesting among them. connect() takes _sessionRwMutex (registry insert),
  // RELEASES it, and only then takes _cmdMutex (enqueue) — sequential, never
  // co-held. The ONE nesting edge into a leaf is the post gate:
  //   - gate->m -> _cmdMutex: the resolver continuation (blockingIoPool thread)
  //     calls runOnIoThread while holding _postGuard->m (makeResolveContinuation);
  //     shutdownDrain takes gate->m in its own section, never with _cmdMutex held.
  // TimerService edges: the engine calls TimerService::scheduleAfter/cancel (its
  // internal mutex) from the I/O thread with NO engine lock held; timer callbacks
  // run on the TimerService thread without that mutex and take only _cmdMutex
  // (enqueue / runOnIoThread) or _lostTimerMutex (markTimerCloseLost), so no
  // engine lock is ever held while a TimerService lock is acquired or vice versa.
  // External edges into these leaves (callers' locks held across an engine call):
  //   - Transport syncMutex -> _sessionRwMutex, then (released) _cmdMutex:
  //     Transport::connectSync holds syncMutex across engine->connect().
  //   - iora_sip _connectionMutex -> _sessionRwMutex, released, then _cmdMutex
  //     (sequential): SipTransport calls connect()/send() under _connectionMutex.
  //   No engine lock is ever held while a caller's lock is acquired, so these
  //   edges cannot close a cycle.
  // - _cbMutex protects callback copies (copy-then-invoke: acquired/released
  //   before any callback fires and before any _sessionRwMutex use).
  // - _sessionRwMutex protects session/listener maps and the _connecting
  //   registry (shared for reads, unique for mutations).
  // - _cmdMutex protects the command queue (_cmds) AND serializes the _eventFd
  //   wakeup-write (enqueue) against the _eventFd close (shutdownDrain), plus
  //   the _cmdsClosed teardown flag. process() swaps _cmds out under _cmdMutex
  //   then RELEASES before dispatching handlers, so command handlers never run
  //   with _cmdMutex held. NEVER acquire another lock while holding _cmdMutex.
  // - _fatalMx protects the sticky-fatal slot.
  std::mutex _cbMutex;
  detail::EngineBase::Callbacks _cbs{};

  mutable std::shared_mutex _sessionRwMutex;

  std::mutex _cmdMutex;
  std::deque<Command> _cmds;
  // Set true under _cmdMutex by shutdownDrain() once the I/O loop has exited and
  // the command queue is being torn down. enqueue() observes it under _cmdMutex
  // and refuses to push (and skips the wakeup write) so no command is queued
  // that the (now-gone) loop will never process — see DD-5 in tracker 2026-06-14-1.
  bool _cmdsClosed{false};

  std::unordered_map<ListenerId, std::unique_ptr<Listener>> _listeners;
  std::unordered_map<SessionId, std::unique_ptr<Session>> _sessions;
  // Connecting-sid registry (guarded by _sessionRwMutex). Invariant: holds only
  // sids whose Cmd::Connect / resolve is pending or whose connect() call is still
  // in flight. Inserted by connect() before the enqueue; erased in the SAME
  // unique-lock critical section as the _sessions insert, or at every pre-insert
  // terminal BEFORE its onClose is invoked. Makes a sid returned by connect()
  // immediately sendable (sessionSendable).
  std::unordered_set<SessionId> _connecting;
  std::unordered_map<int, std::unique_ptr<Tag>> _fdTags;
  // TEST-ONLY seam (tracker 2026-09-15-3): see testSetPreCloseHook. Empty in production;
  // installed before start(), then read-only on the I/O thread (no locking needed).
  std::function<void(int)> _preCloseHook;
  // TEST-ONLY seams (set through TcpEngineTestAccess before start(), then read
  // lock-free on the I/O thread). _beforeTcpEstablishedHook runs with the sid just
  // before the TCP-established transition; _sessionEventFilterHook maps each session
  // epoll event mask before dispatch (0 drops the event). Both are invoked through
  // swallowing wrappers. Empty in production.
  std::function<void(SessionId)> _beforeTcpEstablishedHook;
  std::function<std::uint32_t(SessionId, std::uint32_t)> _sessionEventFilterHook;
  // TEST-ONLY seams (toggled after start(), hence atomic relaxed). Inert in production.
  std::atomic<bool> _testEnqueueFailure{false};
  std::atomic<ConnectThrowPoint> _testConnectThrowPoint{ConnectThrowPoint::NONE};

  std::atomic<SessionId> _nextSessionId{1};
  std::atomic<ListenerId> _nextListenerId{1};

  // TLS contexts and per-instance ALPN preference
  SSL_CTX *_sslSrv{nullptr};
  SSL_CTX *_sslCli{nullptr};
  std::vector<unsigned char> _alpnPref;

  // Sticky fatal (for start/init failures)
  mutable std::mutex _fatalMx;
  mutable IoResult _lastFatal{IoResult::success()};

  // Timer-originated closes that could be neither enqueued nor retried (see
  // markTimerCloseLost). _lostTimerMutex is a leaf: written on the TimerService
  // thread, drained by runGc on the I/O thread; never held with another lock.
  std::mutex _lostTimerMutex;
  std::vector<std::pair<SessionId, CloseOrigin>> _lostTimerCloses;

  // High-resolution timer service
  std::unique_ptr<iora::core::TimerService> _timerService;
  iora::core::TimerServiceConfig _timerConfig;

  // Named-host connects awaiting off-thread resolution. I/O-THREAD-ONLY — every
  // mutation (doConnect kickoff, resumeConnect, resolveTimeoutOnIo, doClose
  // drain, shutdownDrain) runs on the I/O loop thread, so no lock is taken.
  std::unordered_map<SessionId, PendingConnect> _pendingConnects;

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