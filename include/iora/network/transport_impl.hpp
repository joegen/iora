#pragma once
#ifndef __linux__
#error "Linux-only (epoll/eventfd/timerfd)"
#endif

/// \file transport_impl.hpp
/// \brief Transport method definitions. Include in exactly ONE translation unit.
/// \details Contains engine headers (epoll, OpenSSL) — do NOT include broadly.

#include "iora/network/transport.hpp"
#include "iora/network/detail/tcp_engine.hpp"
#include "iora/network/detail/udp_engine.hpp"
// ReadMode and CancellationToken are now in transport_types.hpp (included via transport.hpp)

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <vector>

namespace iora
{
namespace network
{

// ══════════════════════════════════════════════════════════════════════════════
// Transport::Impl — all internal state
// ══════════════════════════════════════════════════════════════════════════════

struct Transport::Impl
{
  TransportConfig config;
  std::unique_ptr<detail::EngineBase> engine;

  // ── Lock ordering ──────────────────────────────────────────────────────────
  // If multiple Transport-level locks are ever needed (they shouldn't be),
  // the order is: callbackMutex → syncMutex → observerMutex → userDataMutex.
  //
  // In practice, no code path acquires more than one Transport-level lock.
  // Each lock is acquired briefly (to copy data), then released BEFORE
  // invoking any user callback. This is the core invariant (HR-6).
  //
  // Engine-internal locks (held by I/O thread) may be active when engine
  // callbacks fire. Transport callback handlers then acquire Transport locks
  // briefly to copy state, release them, then invoke user callbacks with
  // zero locks held.
  // ──────────────────────────────────────────────────────────────────────────

  // Lock order 1: Protects global callback storage.
  // Acquired by: callback setters (onAccept, onConnect, ...) and internal
  //   dispatch handlers (to copy callback before invocation).
  // NEVER held during user callback invocation.
  std::mutex callbackMutex;
  AcceptCallback onAcceptCb;
  ConnectCallback onConnectCb;
  DataCallback onDataCb;
  CloseCallback onCloseCb;
  ErrorCallback onErrorCb;

  // Lock order 3: Protects observer maps (_observers, _observerToSession).
  // Acquired by: observe(), unobserve(), and close handler (to copy observer
  //   list before invocation).
  // NEVER held during observer callback invocation (copy-then-iterate, HR-7).
  std::mutex observerMutex;
  std::unordered_map<SessionId, std::vector<std::pair<ObserverId, CloseCallback>>> observers;
  std::unordered_map<ObserverId, SessionId> observerToSession;
  std::atomic<ObserverId> nextObserverId{1};

  // Lock order 4: Protects user data map (_sessionData).
  // Acquired by: setSessionData(), getSessionData(), and close handler
  //   (to extract and remove data before cleanup invocation).
  // NEVER held during cleanup callback invocation.
  struct UserData
  {
    void *data{nullptr};
    SessionCleanupCallback cleanup;
  };
  std::mutex userDataMutex;
  std::unordered_map<SessionId, UserData> sessionData;

  // Lock order 2: Protects sync operation state (_pendingConnects, _readModes,
  //   _receiveBuffers).
  // Acquired by: connectSync (to register/check pending ops), receiveSync
  //   (to access receive buffer), setReadMode (to update mode and flush),
  //   getReadMode (to read current mode), and I/O thread data handler
  //   (to check mode and buffer data).
  // NEVER held during user callback invocation. setReadMode releases
  //   syncMutex before flushing buffered data via onData callback.
  struct SyncConnectOp
  {
    std::condition_variable cv;
    bool done{false};
    ConnectResult result{ConnectResult::err(TransportErrorInfo{TransportError::Timeout, "pending"})};
  };
  std::mutex syncMutex;
  std::unordered_map<SessionId, std::shared_ptr<SyncConnectOp>> pendingConnects;

  // Read modes (protected by syncMutex)
  std::unordered_map<SessionId, ReadMode> readModes;

  // Sync receive buffers (protected by syncMutex)
  struct SyncReceiveBuffer
  {
    std::vector<std::uint8_t> data;
    std::condition_variable cv;
    bool hasData{false};
    bool closed{false};
  };
  std::unordered_map<SessionId, std::shared_ptr<SyncReceiveBuffer>> receiveBuffers;

  void setupEngineCallbacks()
  {
    detail::EngineBase::Callbacks cbs;

    cbs.onAccept = [this](SessionId sid, const TransportAddress &addr)
    {
      AcceptCallback cb;
      {
        std::lock_guard<std::mutex> lk(callbackMutex);
        cb = onAcceptCb;
      }
      if (cb)
      {
        cb(sid, addr);
      }
    };

    cbs.onConnect = [this](SessionId sid, const TransportAddress &addr)
    {
      // Check if this is a connectSync — deliver to waiting caller, NOT global callback
      {
        std::shared_ptr<SyncConnectOp> op;
        {
          std::lock_guard<std::mutex> lk(syncMutex);
          auto it = pendingConnects.find(sid);
          if (it != pendingConnects.end())
          {
            op = it->second;
            op->result = ConnectResult::ok(sid);
            op->done = true;
            pendingConnects.erase(it);
          }
        }
        // Notify outside syncMutex — avoids the woken thread immediately
        // blocking on syncMutex reacquisition inside cv.wait_for().
        if (op)
        {
          op->cv.notify_one();
          return; // Do NOT fire global onConnect
        }
        // Not a connectSync session — fall through to global callback
      }

      ConnectCallback cb;
      {
        std::lock_guard<std::mutex> lk(callbackMutex);
        cb = onConnectCb;
      }
      if (cb)
      {
        cb(sid, addr);
      }
    };

    cbs.onData = [this](SessionId sid, iora::core::BufferView data,
                        std::chrono::steady_clock::time_point receiveTime)
    {
      // Read mode and handle Sync/Disabled under a single lock acquisition
      // to prevent TOCTOU race with concurrent setReadMode calls.
      {
        std::lock_guard<std::mutex> lk(syncMutex);
        auto modeIt = readModes.find(sid);
        ReadMode mode = (modeIt != readModes.end()) ? modeIt->second : ReadMode::Async;

        if (mode == ReadMode::Sync)
        {
          auto bufIt = receiveBuffers.find(sid);
          if (bufIt != receiveBuffers.end())
          {
            if (bufIt->second->data.size() + data.size() > config.maxSyncReceiveBuffer)
            {
              return; // Drop — buffer full. Prevents unbounded memory growth.
            }
            bufIt->second->data.insert(bufIt->second->data.end(), data.data(),
                                       data.data() + data.size());
            bufIt->second->hasData = true;
            bufIt->second->cv.notify_one();
          }
          return;
        }

        if (mode == ReadMode::Disabled)
        {
          // TODO(Phase 7): Call engine->setReadEnabled(sid, false) to remove fd
          // from EPOLLIN, preventing unnecessary reads. Currently drops data here
          // which is functionally correct but wastes CPU on recv() syscalls.
          return;
        }
      } // syncMutex released before user callback

      // Async mode — deliver to user callback
      DataCallback cb;
      {
        std::lock_guard<std::mutex> lk(callbackMutex);
        cb = onDataCb;
      }
      if (cb)
      {
        cb(sid, data, receiveTime);
      }
    };

    cbs.onClose = [this](SessionId sid, const TransportErrorInfo &reason)
    {
      // Session close flow (architecture doc steps):
      // 1. Check if this is a connectSync session — deliver to waiting caller
      //    and suppress global onClose (same pattern as onConnect suppression).
      //    Without this, a failed connectSync (e.g., ECONNREFUSED) would fire
      //    the global onClose for a sid the user never received.
      {
        std::shared_ptr<SyncConnectOp> op;
        {
          std::lock_guard<std::mutex> lk(syncMutex);
          auto connIt = pendingConnects.find(sid);
          if (connIt != pendingConnects.end())
          {
            op = connIt->second;
            op->result = ConnectResult::err(reason);
            op->done = true;
            pendingConnects.erase(connIt);
          }
        }
        // Notify outside syncMutex — same pattern as onConnect.
        if (op)
        {
          op->cv.notify_one();
          // No global onClose, no observers, no tombstone — connectSync
          // session never escaped to user code, so nothing to clean up.
          return;
        }
      }

      // 2. Invoke global onClose FIRST
      CloseCallback closeCb;
      {
        std::lock_guard<std::mutex> lk(callbackMutex);
        closeCb = onCloseCb;
      }
      if (closeCb)
      {
        closeCb(sid, reason);
      }

      // 3-5. Invoke per-session observers (copy-then-iterate, HR-7)
      std::vector<std::pair<ObserverId, CloseCallback>> sessionObservers;
      {
        std::lock_guard<std::mutex> lk(observerMutex);
        auto it = observers.find(sid);
        if (it != observers.end())
        {
          sessionObservers = it->second; // Copy
          // Clean up observer maps
          for (auto &[obsId, _] : it->second)
          {
            observerToSession.erase(obsId);
          }
          observers.erase(it);
        }
      }
      for (auto &[obsId, obsCb] : sessionObservers)
      {
        if (obsCb)
        {
          obsCb(sid, reason);
        }
      }

      // 6. Wake pending receiveSync or leave a tombstone for late callers.
      // Tombstones prevent a race where onClose fires before setReadMode/
      // receiveSync — without them, receiveSync would wait forever on a
      // closed session. Tombstones are cleaned up by receiveSync when it
      // detects the closed flag.
      //
      // To prevent unbounded tombstone growth from async-only sessions
      // (which never call receiveSync), we periodically GC stale tombstones.
      // A tombstone is stale if it is closed and has no pending data.
      {
        std::lock_guard<std::mutex> lk(syncMutex);
        auto bufIt = receiveBuffers.find(sid);
        if (bufIt != receiveBuffers.end())
        {
          bufIt->second->closed = true;
          bufIt->second->cv.notify_one();
        }
        else
        {
          auto tomb = std::make_shared<SyncReceiveBuffer>();
          tomb->closed = true;
          receiveBuffers[sid] = tomb;
        }
        readModes.erase(sid);

        // GC stale tombstones when map grows beyond threshold.
        // Stale = closed with no pending data and no waiters (hasData==false).
        // This caps memory to O(threshold + concurrent closes between GCs).
        const std::size_t gcThreshold = config.syncBufferGcThreshold;
        if (receiveBuffers.size() > gcThreshold)
        {
          for (auto it = receiveBuffers.begin(); it != receiveBuffers.end();)
          {
            if (it->first != sid && it->second->closed && !it->second->hasData)
            {
              it = receiveBuffers.erase(it);
            }
            else
            {
              ++it;
            }
          }
        }
      }

      // 7. User data cleanup LAST (HR-11)
      UserData ud;
      {
        std::lock_guard<std::mutex> lk(userDataMutex);
        auto it = sessionData.find(sid);
        if (it != sessionData.end())
        {
          ud = it->second;
          sessionData.erase(it);
        }
      }
      if (ud.cleanup && ud.data)
      {
        ud.cleanup(ud.data);
      }
    };

    cbs.onError = [this](TransportError code, const std::string &msg)
    {
      ErrorCallback cb;
      {
        std::lock_guard<std::mutex> lk(callbackMutex);
        cb = onErrorCb;
      }
      if (cb)
      {
        cb(code, msg);
      }
    };

    engine->setCallbacks(std::move(cbs));
  }
};

// ══════════════════════════════════════════════════════════════════════════════
// Transport method definitions
// ══════════════════════════════════════════════════════════════════════════════

inline Transport::Transport(TransportConfig config)
  : _impl(std::make_unique<Impl>())
{
  _impl->config = std::move(config);
  if (_impl->config.protocol == Protocol::TCP)
  {
    _impl->engine = std::make_unique<TcpEngine>(_impl->config);
  }
  else
  {
    _impl->engine = std::make_unique<UdpEngine>(_impl->config);
  }
  _impl->setupEngineCallbacks();
}

inline Transport::Transport(std::unique_ptr<detail::EngineBase> engine, TransportConfig config)
  : _impl(std::make_unique<Impl>())
{
  _impl->config = std::move(config);
  _impl->engine = std::move(engine);
  _impl->setupEngineCallbacks();
}

inline Transport::~Transport()
{
  if (!_impl || !_impl->engine)
  {
    return;
  }
  if (!_impl->engine->isRunning())
  {
    return;
  }
  if (std::this_thread::get_id() == _impl->engine->getIoThreadId())
  {
    // PROGRAMMING ERROR: Transport destroyed from the I/O thread (e.g.,
    // last shared_ptr dropped inside a callback). Cannot stop/join the
    // I/O thread from itself.
    // Safety net: detach the I/O thread so the engine destructor's stop()
    // becomes a no-op (CAS on _running fails, _loop is not joinable).
    // The detached I/O thread will exit its loop naturally when it sees
    // _running == false.
    std::fprintf(stderr,
      "WARNING: Transport destroyed from I/O thread. "
      "Detaching I/O thread to prevent deadlock. "
      "Fix: ensure Transport outlives all callbacks.\n");
    _impl->engine->detachForTermination();
    return;
  }
  _impl->engine->stop();
}

inline Transport::Transport(Transport &&other) noexcept
  : _impl(std::move(other._impl))
{
  if (_impl && _impl->engine)
  {
    _impl->setupEngineCallbacks(); // Re-register callbacks to point to this object's Impl
  }
}

inline Transport &Transport::operator=(Transport &&other) noexcept
{
  if (this != &other)
  {
    if (_impl && _impl->engine && _impl->engine->isRunning())
    {
      if (std::this_thread::get_id() == _impl->engine->getIoThreadId())
      {
        std::fprintf(stderr,
          "WARNING: Transport move-assigned from I/O thread. "
          "Detaching old I/O thread to prevent deadlock.\n");
        _impl->engine->detachForTermination();
      }
      else
      {
        _impl->engine->stop();
      }
    }
    _impl = std::move(other._impl);
    if (_impl && _impl->engine)
    {
      _impl->setupEngineCallbacks();
    }
  }
  return *this;
}

inline Transport Transport::tcp(TransportConfig config)
{
  config.protocol = Protocol::TCP;
  return Transport(std::move(config));
}

inline Transport Transport::udp(TransportConfig config)
{
  config.protocol = Protocol::UDP;
  return Transport(std::move(config));
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

inline StartResult Transport::start()
{
  return _impl->engine->start();
}

inline void Transport::stop()
{
  if (_impl && _impl->engine)
  {
    if (_impl->engine->isRunning() &&
        std::this_thread::get_id() == _impl->engine->getIoThreadId())
    {
      throw std::logic_error("stop() called from I/O thread — would deadlock. "
                             "Post to a worker thread instead.");
    }
    _impl->engine->stop();
  }
}

inline bool Transport::isRunning() const
{
  return _impl && _impl->engine && _impl->engine->isRunning();
}

inline TransportErrorInfo Transport::lastError() const
{
  if (!_impl || !_impl->engine)
  {
    return TransportErrorInfo{TransportError::Config, "transport not initialized"};
  }
  return _impl->engine->lastError();
}

// ── Connection Management ────────────────────────────────────────────────────

inline ListenResult Transport::addListener(const std::string &bindIp, std::uint16_t port,
                                           TlsMode tls)
{
  if (_impl->engine->isRunning() &&
      std::this_thread::get_id() == _impl->engine->getIoThreadId())
  {
    throw std::logic_error("addListener() called from I/O thread — not permitted. "
                           "Call before start() or from a worker thread.");
  }
  return _impl->engine->addListener(bindIp, port, tls);
}

inline ConnectResult Transport::connect(const std::string &host, std::uint16_t port, TlsMode tls)
{
  return _impl->engine->connect(host, port, tls);
}

inline ConnectResult Transport::connectViaListener(ListenerId lid, const std::string &host,
                                                   std::uint16_t port)
{
  return _impl->engine->connectViaListener(lid, host, port);
}

inline bool Transport::close(SessionId sid)
{
  return _impl->engine->close(sid);
}

// ── Async Data Operations ────────────────────────────────────────────────────

inline bool Transport::send(SessionId sid, iora::core::BufferView data)
{
  return _impl->engine->send(sid, data.data(), data.size());
}

inline void Transport::sendAsync(SessionId sid, iora::core::BufferView data,
                                 SendCompleteCallback cb)
{
  _impl->engine->sendAsync(sid, data.data(), data.size(), std::move(cb));
}

// ── Sync Connection ──────────────────────────────────────────────────────────

inline ConnectResult Transport::connectSync(const std::string &host, std::uint16_t port,
                                            TlsMode tls, std::chrono::milliseconds timeout)
{
  if (_impl->engine->isRunning() &&
      std::this_thread::get_id() == _impl->engine->getIoThreadId())
  {
    throw std::logic_error("connectSync() called from I/O thread — would deadlock. "
                           "Use connect() (async) instead, or post to a worker thread.");
  }

  // For UDP, connect is immediate — no handshake
  if (_impl->config.protocol == Protocol::UDP)
  {
    return _impl->engine->connect(host, port, tls);
  }

  // Acquire syncMutex BEFORE calling engine->connect(). This ensures the
  // I/O thread's onConnect callback (which acquires syncMutex) cannot fire
  // until we have registered in pendingConnects and entered cv.wait_for()
  // (which atomically releases syncMutex). engine->connect() only acquires
  // the engine's internal _cmdMutex (atomic++ + push + eventfd write ≈ μs),
  // not syncMutex — no AB-BA deadlock risk, no convoy under concurrency.
  auto op = std::make_shared<Impl::SyncConnectOp>();
  std::unique_lock<std::mutex> lk(_impl->syncMutex);

  auto result = _impl->engine->connect(host, port, tls);
  if (result.isErr())
  {
    return result;
  }
  SessionId sid = result.value();

  _impl->pendingConnects[sid] = op;
  if (op->cv.wait_for(lk, timeout, [&op] { return op->done; }))
  {
    return std::move(op->result);
  }

  // Timeout — keep pendingConnects[sid] entry so onClose finds it and suppresses
  // the global onClose callback (the user never received this sid). The entry's
  // shared_ptr<SyncConnectOp> keeps op alive until the I/O thread's onClose
  // handler erases it — the local op going out of scope here is safe.
  // Release syncMutex BEFORE calling engine methods to avoid AB-BA deadlock.
  lk.unlock();
  _impl->engine->close(sid);
  return ConnectResult::err(TransportErrorInfo{TransportError::Timeout, "connectSync timed out"});
}

// ── Sync Data Operations ─────────────────────────────────────────────────────

inline SendResult Transport::sendSync(SessionId sid, iora::core::BufferView data,
                                      std::chrono::milliseconds timeout)
{
  if (_impl->engine->isRunning() &&
      std::this_thread::get_id() == _impl->engine->getIoThreadId())
  {
    throw std::logic_error("sendSync() called from I/O thread — would deadlock. "
                           "Use send() (async) instead.");
  }

  // Simple implementation: delegate to engine's sync send.
  // The engine's send() is non-blocking (enqueues), so this blocks until
  // the data is actually enqueued. For true blocking-until-sent semantics,
  // Phase 7 will add proper completion tracking.
  bool ok = _impl->engine->send(sid, data.data(), data.size());
  if (ok)
  {
    return SendResult::ok(data.size());
  }
  return SendResult::err(TransportErrorInfo{TransportError::Socket, "send failed"});
}

inline ReceiveResult Transport::receiveSync(SessionId sid, void *buffer, std::size_t &len,
                                            std::chrono::milliseconds timeout)
{
  if (_impl->engine->isRunning() &&
      std::this_thread::get_id() == _impl->engine->getIoThreadId())
  {
    throw std::logic_error("receiveSync() called from I/O thread — would deadlock. "
                           "Use ReadMode::Async with onData() callback instead.");
  }

  std::shared_ptr<Impl::SyncReceiveBuffer> buf;
  {
    std::lock_guard<std::mutex> lk(_impl->syncMutex);
    auto it = _impl->receiveBuffers.find(sid);
    if (it == _impl->receiveBuffers.end())
    {
      // Create buffer on first receiveSync for this session
      buf = std::make_shared<Impl::SyncReceiveBuffer>();
      _impl->receiveBuffers[sid] = buf;
    }
    else
    {
      buf = it->second;
    }
  }

  std::unique_lock<std::mutex> lk(_impl->syncMutex);
  if (!buf->cv.wait_for(lk, timeout, [&buf] { return buf->hasData || buf->closed; }))
  {
    // Clean up tombstone on timeout to prevent leak
    if (buf->closed)
    {
      _impl->receiveBuffers.erase(sid);
      _impl->readModes.erase(sid);
    }
    return ReceiveResult::err(TransportErrorInfo{TransportError::Timeout, "receiveSync timed out"});
  }
  if (buf->closed)
  {
    // Clean up tombstone to prevent unbounded receiveBuffers growth
    _impl->receiveBuffers.erase(sid);
    _impl->readModes.erase(sid);
    return ReceiveResult::err(TransportErrorInfo{TransportError::PeerClosed, "session closed"});
  }

  std::size_t copyLen = std::min(len, buf->data.size());
  std::memcpy(buffer, buf->data.data(), copyLen);
  buf->data.erase(buf->data.begin(), buf->data.begin() + static_cast<std::ptrdiff_t>(copyLen));
  buf->hasData = !buf->data.empty();
  len = copyLen;
  return ReceiveResult::ok(copyLen);
}

// ── Read Modes ───────────────────────────────────────────────────────────────

inline bool Transport::setReadMode(SessionId sid, ReadMode mode)
{
  if (!_impl->config.allowReadModeSwitch)
  {
    return false;
  }

  // Step 1: Determine old mode and handle simple transitions under syncMutex
  ReadMode oldMode = ReadMode::Async;
  {
    std::lock_guard<std::mutex> lk(_impl->syncMutex);
    auto it = _impl->readModes.find(sid);
    if (it != _impl->readModes.end())
    {
      oldMode = it->second;
    }

    // If NOT switching from Sync to Async, update mode directly
    if (!(oldMode == ReadMode::Sync && mode == ReadMode::Async))
    {
      _impl->readModes[sid] = mode;

      // If switching to Sync, ensure receive buffer exists
      if (mode == ReadMode::Sync)
      {
        if (_impl->receiveBuffers.find(sid) == _impl->receiveBuffers.end())
        {
          _impl->receiveBuffers[sid] = std::make_shared<Impl::SyncReceiveBuffer>();
        }
      }
      return true; // Early return for non-flush transitions
    }
  } // syncMutex released

  // Step 2: Sync→Async transition with ordered flush.
  // Keep mode as Sync during flush so the I/O thread continues buffering
  // any data that arrives mid-flush. Drain in a loop until empty.
  DataCallback cb;
  {
    std::lock_guard<std::mutex> cbLk(_impl->callbackMutex);
    cb = _impl->onDataCb;
  }

  for (;;)
  {
    std::vector<std::uint8_t> flushData;
    {
      std::lock_guard<std::mutex> lk(_impl->syncMutex);
      auto bufIt = _impl->receiveBuffers.find(sid);
      if (bufIt != _impl->receiveBuffers.end() && !bufIt->second->data.empty())
      {
        flushData = std::move(bufIt->second->data);
        bufIt->second->data.clear();
        bufIt->second->hasData = false;
      }
      else
      {
        // Buffer is empty — atomically switch mode to Async while holding lock.
        // The I/O thread will see Async mode on the next data arrival.
        _impl->readModes[sid] = ReadMode::Async;
        break;
      }
    } // syncMutex released before callback invocation (HR-6)

    if (cb && !flushData.empty())
    {
      cb(sid, iora::core::BufferView{flushData.data(), flushData.size()},
         std::chrono::steady_clock::now());
    }
  }

  return true;
}

inline bool Transport::getReadMode(SessionId sid, ReadMode &mode) const
{
  std::lock_guard<std::mutex> lk(_impl->syncMutex);
  auto it = _impl->readModes.find(sid);
  if (it == _impl->readModes.end())
  {
    return false;
  }
  mode = it->second;
  return true;
}

// ── Callbacks ────────────────────────────────────────────────────────────────

inline void Transport::onAccept(AcceptCallback cb)
{
  std::lock_guard<std::mutex> lk(_impl->callbackMutex);
  _impl->onAcceptCb = std::move(cb);
}

inline void Transport::onConnect(ConnectCallback cb)
{
  std::lock_guard<std::mutex> lk(_impl->callbackMutex);
  _impl->onConnectCb = std::move(cb);
}

inline void Transport::onData(DataCallback cb)
{
  std::lock_guard<std::mutex> lk(_impl->callbackMutex);
  _impl->onDataCb = std::move(cb);
}

inline void Transport::onClose(CloseCallback cb)
{
  std::lock_guard<std::mutex> lk(_impl->callbackMutex);
  _impl->onCloseCb = std::move(cb);
}

inline void Transport::onError(ErrorCallback cb)
{
  std::lock_guard<std::mutex> lk(_impl->callbackMutex);
  _impl->onErrorCb = std::move(cb);
}

// ── Observers ────────────────────────────────────────────────────────────────

inline ObserverId Transport::observe(SessionId sid, CloseCallback cb)
{
  ObserverId id = _impl->nextObserverId.fetch_add(1, std::memory_order_relaxed);
  std::lock_guard<std::mutex> lk(_impl->observerMutex);
  _impl->observers[sid].emplace_back(id, std::move(cb));
  _impl->observerToSession[id] = sid;
  return id;
}

inline bool Transport::unobserve(ObserverId id)
{
  std::lock_guard<std::mutex> lk(_impl->observerMutex);
  auto sessIt = _impl->observerToSession.find(id);
  if (sessIt == _impl->observerToSession.end())
  {
    return false;
  }
  SessionId sid = sessIt->second;
  _impl->observerToSession.erase(sessIt);

  auto obsIt = _impl->observers.find(sid);
  if (obsIt != _impl->observers.end())
  {
    auto &vec = obsIt->second;
    vec.erase(std::remove_if(vec.begin(), vec.end(),
                             [id](const auto &p) { return p.first == id; }),
              vec.end());
    if (vec.empty())
    {
      _impl->observers.erase(obsIt);
    }
  }
  return true;
}

// ── Session Introspection ────────────────────────────────────────────────────

inline TransportAddress Transport::getListenerAddress(ListenerId lid) const
{
  return _impl->engine->getListenerAddress(lid);
}

inline TransportAddress Transport::getLocalAddress(SessionId sid) const
{
  return _impl->engine->getLocalAddress(sid);
}

inline TransportAddress Transport::getRemoteAddress(SessionId sid) const
{
  return _impl->engine->getRemoteAddress(sid);
}

inline void Transport::setSessionData(SessionId sid, void *data, SessionCleanupCallback cleanup)
{
  std::lock_guard<std::mutex> lk(_impl->userDataMutex);
  _impl->sessionData[sid] = {data, std::move(cleanup)};
}

inline void *Transport::getSessionData(SessionId sid) const
{
  std::lock_guard<std::mutex> lk(_impl->userDataMutex);
  auto it = _impl->sessionData.find(sid);
  if (it == _impl->sessionData.end())
  {
    return nullptr;
  }
  return it->second.data;
}

// ── Stats ────────────────────────────────────────────────────────────────────

inline TransportStats Transport::getStats() const
{
  return _impl->engine->getStats();
}

inline Protocol Transport::getProtocol() const
{
  return _impl->config.protocol;
}

// ══════════════════════════════════════════════════════════════════════════════
// ITransport default implementations for cancellable methods
// ══════════════════════════════════════════════════════════════════════════════

inline ConnectResult ITransport::connectSyncCancellable(
  const std::string &host, std::uint16_t port, CancellationToken &token, TlsMode tls,
  std::chrono::milliseconds timeout)
{
  if (token.isCancelled())
  {
    return ConnectResult::err(TransportErrorInfo{TransportError::Cancelled, "cancelled"});
  }
  // Sub-timeout loop: break the total timeout into intervals of at most 100ms
  // so that cancel() is checked between iterations. connectSync handles the
  // internal waiting, so each sub-call is capped.
  constexpr auto subInterval = std::chrono::milliseconds{100};
  auto deadline = std::chrono::steady_clock::now() + timeout;
  auto remaining = timeout;

  // For connectSync, we can only call it once (it initiates the connection).
  // Use the full timeout but poll cancellation via a short sub-timeout.
  // The first call starts the connection attempt.
  auto subTimeout = std::min(remaining, subInterval);
  auto result = connectSync(host, port, tls, subTimeout);
  if (result.isOk())
  {
    return result;
  }
  if (result.error().code != TransportError::Timeout)
  {
    return result; // Non-timeout error — return immediately
  }

  // The initial connectSync timed out with the sub-interval. For TCP, the
  // connection attempt is already in flight. We can't call connectSync again
  // (it would start a second connection). The connectSync implementation
  // handles this correctly — the sub-timeout just determines how long we
  // waited. Since connectSync already cleaned up and returned Timeout, the
  // session is closed. We need to retry the full connect.
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (token.isCancelled())
    {
      return ConnectResult::err(TransportErrorInfo{TransportError::Cancelled, "cancelled"});
    }
    remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
      deadline - std::chrono::steady_clock::now());
    if (remaining <= std::chrono::milliseconds::zero())
    {
      break;
    }
    subTimeout = std::min(remaining, subInterval);
    result = connectSync(host, port, tls, subTimeout);
    if (result.isOk() || result.error().code != TransportError::Timeout)
    {
      return result;
    }
  }
  return ConnectResult::err(TransportErrorInfo{TransportError::Timeout, "connectSync timed out"});
}

inline SendResult ITransport::sendSyncCancellable(
  SessionId sid, iora::core::BufferView data, CancellationToken &token,
  std::chrono::milliseconds timeout)
{
  if (token.isCancelled())
  {
    return SendResult::err(TransportErrorInfo{TransportError::Cancelled, "cancelled"});
  }
  // sendSync is non-blocking (enqueue-based), so it completes quickly.
  // Check cancellation before and after — no sub-timeout loop needed.
  auto result = sendSync(sid, data, timeout);
  if (token.isCancelled() && result.isOk())
  {
    return SendResult::err(TransportErrorInfo{TransportError::Cancelled, "cancelled after send"});
  }
  return result;
}

inline ReceiveResult ITransport::receiveSyncCancellable(
  SessionId sid, void *buffer, std::size_t &len, CancellationToken &token,
  std::chrono::milliseconds timeout)
{
  if (token.isCancelled())
  {
    return ReceiveResult::err(TransportErrorInfo{TransportError::Cancelled, "cancelled"});
  }
  // Sub-timeout loop: break the total timeout into intervals so that
  // cancel() is detected between iterations.
  constexpr auto subInterval = std::chrono::milliseconds{100};
  auto deadline = std::chrono::steady_clock::now() + timeout;

  while (std::chrono::steady_clock::now() < deadline)
  {
    if (token.isCancelled())
    {
      return ReceiveResult::err(TransportErrorInfo{TransportError::Cancelled, "cancelled"});
    }
    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
      deadline - std::chrono::steady_clock::now());
    if (remaining <= std::chrono::milliseconds::zero())
    {
      break;
    }
    auto subTimeout = std::min(remaining, subInterval);
    auto result = receiveSync(sid, buffer, len, subTimeout);
    if (result.isOk())
    {
      return result;
    }
    if (result.error().code != TransportError::Timeout)
    {
      return result; // Non-timeout error (PeerClosed, etc.) — return immediately
    }
  }
  return ReceiveResult::err(TransportErrorInfo{TransportError::Timeout, "receiveSync timed out"});
}

} // namespace network
} // namespace iora
