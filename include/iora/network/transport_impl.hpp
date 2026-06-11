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
#include <cassert>
#include <chrono>
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

  // Lock order 2: Protects sync operation state and the teardown handshake.
  //   syncMutex guards: pendingConnects, readModes, receiveBuffers, every
  //   SyncReceiveBuffer field ({data, hasData, closed, waiters, flushing,
  //   overflow}), every SyncConnectOp field ({done, result}), and the
  //   teardown state {shuttingDown, activeFlushes, activeConnects}.
  // Acquired by: connectSync (register/wait), receiveSync (buffer access/wait),
  //   setReadMode (mode update + flush), getReadMode (read mode), the I/O
  //   thread data/close handlers, and the teardown handshake in ~Transport /
  //   operator=.
  // NEVER held during user callback invocation. setReadMode releases syncMutex
  //   before flushing buffered data via the onData callback.
  //
  // TEARDOWN HANDSHAKE (INV-5/INV-7): three classes of EXTERNAL (non-I/O)
  // thread park while holding syncMutex across a lock release and must be
  // waited out before _impl is destroyed, or destroying syncMutex /
  // receiveBuffers / pendingConnects under them is a use-after-free:
  //   (a) receiveSync waiters on a SyncReceiveBuffer::cv  -> counted by `waiters`
  //   (b) connectSync waiters on a SyncConnectOp::cv       -> counted by `activeConnects`
  //   (c) setReadMode Sync->Async flushers (release the lock for onData)
  //                                                        -> counted by `activeFlushes`
  // An exhaustive grep proves these are the only such classes (exactly two
  // condition_variable members + the flush lock-release; getReadMode /
  // non-flush setReadMode / sendSync take the lock single-shot, no CV wait).
  // Teardown sets `shuttingDown` (as the FIRST action, an ENTRY FENCE per
  // INV-8), notifies every parked CV, then waits on teardownCv until
  // waiters==0 && activeConnects==0 && activeFlushes==0.
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

  // Sync receive buffers (protected by syncMutex).
  // INV-1: hasData == !data.empty() at all observable points.
  // INV-2: a buffer's MAP ENTRY survives as long as a waiter is parked on it
  //   (the `waiters` count gates GC; never use shared_ptr::use_count()).
  struct SyncReceiveBuffer
  {
    std::vector<std::uint8_t> data;
    std::condition_variable cv;
    bool hasData{false};
    bool closed{false};
    std::size_t waiters{0}; // parked receiveSync callers (INV-2/INV-6)
    bool flushing{false};   // an in-progress setReadMode Sync->Async flush owns this entry (C-1)
    bool overflow{false};   // a Sync-mode append exceeded maxSyncReceiveBuffer (N-2).
                            // TERMINAL for the buffer: once set it is never cleared
                            // (dropped bytes corrupt the stream irrecoverably), so a
                            // retry on the same session re-reports BufferOverflow.
                            // The caller must close the session. The closed entry is
                            // still GC-reclaimable (overflow does not block the GC gate).
  };
  std::unordered_map<SessionId, std::shared_ptr<SyncReceiveBuffer>> receiveBuffers;

  // Teardown handshake state (all guarded by syncMutex except teardownCv).
  // `activeReceives` is the Impl-level AGGREGATE of parked receiveSync waiters
  // (the per-buffer SyncReceiveBuffer::waiters drives the GC gate; this drives
  // the teardown gate). receiveSync bumps BOTH under the lock.
  bool shuttingDown{false};   // entry fence + wake signal during teardown (INV-5/INV-8)
  std::size_t activeReceives{0}; // parked receiveSync waiters, aggregate (INV-5)
  std::size_t activeFlushes{0}; // in-progress setReadMode flushers (INV-5)
  std::size_t activeConnects{0}; // parked connectSync waiters (INV-5/C-4)
  std::condition_variable teardownCv; // signalled by each guard's destructor when its counter hits the gate

  // RAII guard for a parked receiveSync / connectSync caller. The owner MUST
  // hold syncMutex continuously for the guard's whole lifetime (both calls park
  // on a CV that atomically releases/re-acquires syncMutex). On destruction —
  // under the still-held lock — it decrements its counter and wakes the teardown
  // handshake. Declare AFTER the unique_lock so it destructs FIRST (decrement
  // runs while the lock is still held). Balanced on every exit incl. throw.
  struct ParkGuard
  {
    std::size_t &counter;
    std::condition_variable &teardownCv;
    ParkGuard(std::size_t &c, std::condition_variable &tcv) : counter(c), teardownCv(tcv) { ++counter; }
    ~ParkGuard()
    {
      --counter;
      teardownCv.notify_one(); // single teardown waiter (L-3/L6-1)
    }
    ParkGuard(const ParkGuard &) = delete;
    ParkGuard &operator=(const ParkGuard &) = delete;
  };

  // RAII guard for an in-progress setReadMode Sync->Async flush. The CTOR assumes
  // the caller already holds syncMutex (it is constructed inside the same locked
  // scope that fetched `buf`, so marking `flushing` happens with no gap in which
  // GC could erase the entry — closes the pre-guard window) and sets
  // flushing + ++activeFlushes. The DTOR takes the lock itself (the flush loop
  // releases syncMutex for the onData callback, so no lock is held at scope exit)
  // and clears flushing / decrements activeFlushes / wakes teardown. Increment and
  // decrement are thus owned by ONE object (no leak gap, L-2). The dtor's lock
  // scope is independent of the loop's per-iteration locks — no double-lock.
  struct FlushGuard
  {
    std::mutex &m;
    std::size_t &activeFlushes;
    std::condition_variable &teardownCv;
    std::shared_ptr<SyncReceiveBuffer> buf;
    // Precondition: caller holds `mm`.
    FlushGuard(std::mutex &mm, std::size_t &af, std::condition_variable &tcv,
               std::shared_ptr<SyncReceiveBuffer> b)
      : m(mm), activeFlushes(af), teardownCv(tcv), buf(std::move(b))
    {
      buf->flushing = true;
      ++activeFlushes;
    }
    ~FlushGuard()
    {
      std::lock_guard<std::mutex> lk(m);
      buf->flushing = false;
      --activeFlushes;
      teardownCv.notify_one();
    }
    FlushGuard(const FlushGuard &) = delete;
    FlushGuard &operator=(const FlushGuard &) = delete;
  };

  // Run the teardown handshake under the assumption the caller is about to
  // destroy/replace _impl. Sets shuttingDown (entry fence), wakes every parked
  // CV, and blocks until all three external-thread counters reach zero so no
  // thread is still touching _impl. `notifyReceive` controls whether the
  // receiveSync CVs are woken here: on the NORMAL teardown path the caller
  // passes false and lets engine->stop()'s onClose drain+wake parked receiveSync
  // waiters first (preserves drain-before-close, INV-5b); the ALREADY-STOPPED
  // and EMERGENCY-DETACH paths pass true (no onClose will fire). connectSync
  // CVs are ALWAYS woken (connectSync has no data to drain).
  void teardownWaitOut(bool notifyReceive)
  {
    std::unique_lock<std::mutex> lk(syncMutex);
    shuttingDown = true; // set-then-notify under the lock (mirrors `closed`)
    for (auto &kv : pendingConnects)
    {
      kv.second->cv.notify_all();
    }
    if (notifyReceive)
    {
      for (auto &kv : receiveBuffers)
      {
        kv.second->cv.notify_all();
      }
    }
    teardownCv.wait(lk, [this]
                    { return activeReceives == 0 && activeConnects == 0 && activeFlushes == 0; });
  }

  // Set the entry fence (shuttingDown) and wake parked connectSync waiters, but
  // NOT receiveSync waiters. Used on the NORMAL teardown path so engine->stop()'s
  // onClose can deliver+drain a parked receiveSync's tail bytes before it sees
  // the teardown signal (drain-before-close, INV-5b). connectSync has no data to
  // drain, so it is always safe to wake here.
  void setTeardownFence()
  {
    std::lock_guard<std::mutex> lk(syncMutex);
    shuttingDown = true;
    for (auto &kv : pendingConnects)
    {
      kv.second->cv.notify_all();
    }
  }

  // Full teardown for the current _impl, covering all paths (INV-5a/5b). The
  // caller (Transport::~Transport / operator=) guarantees `engine` is present.
  // Gated on engine PRESENCE, never on isRunning() — a parked waiter/flusher/
  // connector can outlive isRunning()==false, and destroying _impl under it is a
  // use-after-free.
  void performTeardown()
  {
    // performTeardown handles ONLY the non-I/O-thread teardown paths. The
    // I/O-thread (self-destruction) case is handled by Transport::~Transport /
    // operator= via deferred self-destruction (they own the unique_ptr and can
    // release it). If performTeardown were ever entered on the I/O thread it
    // would self-join on engine->stop() (NORMAL) or self-wait on teardownCv
    // (ALREADY-STOPPED) — so assert against it.
    assert(std::this_thread::get_id() != engine->getIoThreadId() &&
           "performTeardown must not run on the I/O thread — ~Transport/operator= handle that");

    if (!engine->isRunning())
    {
      // ALREADY-STOPPED (on a non-I/O thread): onClose already fired externally
      // for sessions that had one; wake any still-parked waiter and wait everyone
      // out. No stop()/detach needed (a stop() would be a CAS no-op, L-2).
      teardownWaitOut(/*notifyReceive=*/true);
      return;
    }
    // NORMAL (running, non-I/O thread): fence first (wakes connectSync, NOT
    // receiveSync), then engine->stop() WITHOUT holding syncMutex (shutdownDrain's
    // onClose needs it) so already-parked receiveSync waiters wake via `closed`,
    // DRAIN THEIR TAIL, and return PeerClosed (drain-before-close, INV-5b). Then
    // wait everyone out WITHOUT re-notifying the receive CVs (notifyReceive=false,
    // H-1): re-notifying here would let a parked waiter wake on `shuttingDown` and
    // skip the drain when stop() degenerated to a CAS no-op. connectSync waiters
    // were already woken by the fence; the gate still counts them.
    setTeardownFence();
    engine->stop();
    teardownWaitOut(/*notifyReceive=*/false);
  }

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
            // During teardown, only skip the append when NO waiter will drain
            // it (H-A). If a receiveSync is parked (waiters>0), we MUST buffer so
            // it can drain its tail before close — the NORMAL teardown path sets
            // shuttingDown before stop(), and stop()'s shutdownDrain delivers the
            // final bytes through here; dropping them would defeat the
            // drain-before-close guarantee (INV-5b/H-1).
            if (shuttingDown && bufIt->second->waiters == 0)
            {
              return; // M-3: don't grow a buffer no one will drain
            }
            if (bufIt->second->data.size() + data.size() > config.maxSyncReceiveBuffer)
            {
              // Overflow: surface a distinct error to the parked waiter instead
              // of silently dropping (which would only fail at the caller's
              // timeout with no diagnostic). N-2.
              bufIt->second->overflow = true;
              bufIt->second->cv.notify_all();
              return;
            }
            bufIt->second->data.insert(bufIt->second->data.end(), data.data(),
                                       data.data() + data.size());
            bufIt->second->hasData = true; // INV-1: hasData == !data.empty()
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
          // notify_all (not _one): a closed session must wake every parked
          // waiter even though the single-waiter contract normally means one.
          // M-5.
          bufIt->second->cv.notify_all();
        }
        else
        {
          auto tomb = std::make_shared<SyncReceiveBuffer>();
          tomb->closed = true;
          receiveBuffers[sid] = tomb;
        }
        readModes.erase(sid);

        // GC stale tombstones when map grows beyond threshold. A tombstone is
        // reclaimable only if closed, drained (!hasData), with NO parked waiter
        // (waiters==0) and NO in-progress flush (!flushing) — erasing a buffer
        // a waiter/flusher still references via the map would orphan it and
        // drop a not-yet-delivered onData (M-2/C-1).
        const std::size_t gcThreshold = config.syncBufferGcThreshold;
        if (receiveBuffers.size() > gcThreshold)
        {
          for (auto it = receiveBuffers.begin(); it != receiveBuffers.end();)
          {
            if (it->first != sid && it->second->closed && !it->second->hasData &&
                it->second->waiters == 0 && !it->second->flushing)
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
  // I/O-THREAD SELF-DESTRUCTION (destroyed from within one of our own callbacks):
  // ~Impl would free the engine + syncMutex + maps while the I/O thread is still
  // unwinding the engine's dispatch on its own stack (UAF). Defer Impl deletion to
  // the detached engine thread's post-loop() epilogue (delete-this-at-thread-end).
  // First wait out all EXTERNAL sync waiters (they run on user threads, wake via
  // notify, exit independently), then release _impl, hand it to the engine to
  // delete after loop() returns, and detach. Gated on isRunning() && id-match:
  // if !isRunning() the I/O thread is gone so we can't be on it.
  if (std::this_thread::get_id() == _impl->engine->getIoThreadId())
  {
    // We are on the I/O thread (destroyed from within one of our own callbacks).
    if (!_impl->engine->isRunning())
    {
      // UNSUPPORTED (C-1): _running was cleared by a CONCURRENT stop()/teardown
      // on ANOTHER thread (the only way _running goes false on the I/O thread
      // before our own detach). That other thread holds an in-flight reference
      // into this Transport (e.g. it is blocked in engine->stop()/_loop.join()),
      // so the engine is being torn down by two conflicting paths — join-vs-detach
      // and the other thread's use of the about-to-be-freed engine cannot be
      // reconciled. Deleting a Transport from a callback while another thread
      // concurrently operates on it violates the object's lifetime contract.
      // Fail loudly rather than corrupt memory (silent UAF in release builds).
      std::fprintf(stderr, "FATAL: Transport destroyed from its own I/O thread while "
                           "another thread is concurrently stopping/destroying it. "
                           "Unsupported: the Transport must outlive all concurrent "
                           "method calls. Aborting to avoid memory corruption.\n");
      std::abort();
    }
#ifdef IORA_DISABLE_SELFDESTRUCT_DEFERRAL
    // RETAINED NEGATIVE CONTROL (test-only): synchronous teardown on the I/O
    // thread reproduces the heap-use-after-free (engine freed under its own
    // running dispatch). A build with this macro MUST fail S4 under ASan —
    // proving the deferral below is what prevents the UAF (guards TD-INV-4).
    _impl->teardownWaitOut(/*notifyReceive=*/true);
    _impl->engine->detachForTermination();
    return; // ~Impl runs now -> UAF
#else
    std::fprintf(stderr, "WARNING: Transport destroyed from I/O thread. Deferring "
                         "destruction to the detached I/O thread. "
                         "Fix: ensure Transport outlives all callbacks.\n");
    _impl->teardownWaitOut(/*notifyReceive=*/true);
    Impl *raw = _impl.release();              // ~Impl must NOT run now
    raw->engine->scheduleSelfDestruct([raw] { delete raw; }); // run post-loop()
    raw->engine->detachForTermination();
    return;
#endif
  }
  // Non-I/O-thread teardown: handshake (gated on engine PRESENCE, not isRunning())
  // waits out external sync waiters, then ~Impl frees state synchronously here.
  _impl->performTeardown();
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
    // Tear down the OLD _impl before the move overwrites it (same hazards as
    // ~Transport). On the I/O thread, defer its deletion (delete-this-at-thread-end)
    // and fall through — NO early return — to install the new impl. Off the I/O
    // thread, performTeardown waits out waiters and the subsequent move runs ~Impl
    // synchronously.
    if (_impl && _impl->engine)
    {
      if (std::this_thread::get_id() == _impl->engine->getIoThreadId())
      {
        if (!_impl->engine->isRunning())
        {
          // UNSUPPORTED (C-1): concurrent stop()/teardown from another thread —
          // see the matching ~Transport branch. Fail loudly, not silent UAF.
          std::fprintf(stderr, "FATAL: Transport move-assigned from its own I/O thread while "
                               "another thread is concurrently stopping/destroying it. "
                               "Unsupported. Aborting to avoid memory corruption.\n");
          std::abort();
        }
        std::fprintf(stderr, "WARNING: Transport move-assigned from I/O thread. "
                             "Deferring old-impl destruction to the detached I/O thread.\n");
        _impl->teardownWaitOut(/*notifyReceive=*/true);
        Impl *raw = _impl.release();
        raw->engine->scheduleSelfDestruct([raw] { delete raw; });
        raw->engine->detachForTermination();
      }
      else
      {
        _impl->performTeardown();
      }
    }
    _impl = std::move(other._impl);
    if (_impl && _impl->engine)
    {
      // Move hygiene (L-4): a live, never-torn-down source must not carry a
      // stuck shuttingDown/active* state that would instantly fail every
      // subsequent sync op on this object.
      assert(!_impl->shuttingDown && _impl->activeReceives == 0 &&
             _impl->activeConnects == 0 && _impl->activeFlushes == 0 &&
             "move-assigned from a torn-down Transport");
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
  // Acquire syncMutex BEFORE calling engine->connect() and hold it CONTINUOUSLY
  // through entry into wait_for (INV-8). This serializes connectSync against the
  // teardown handshake on the same mutex: teardown either wins the lock first
  // (we then hit the entry fence below and never call engine->connect()) or we
  // win first (we register + park + are counted in activeConnects before
  // teardown's notify), so connectSync is never both uncounted and unreachable,
  // and engine->connect() is never issued on a torn-down engine (engine->connect
  // has no _running guard). Do NOT narrow this lock scope (M-NEW-2/M-A).
  auto op = std::make_shared<Impl::SyncConnectOp>();
  std::unique_lock<std::mutex> lk(_impl->syncMutex);

  // Entry fence (INV-8): reject before engine->connect() and before counting.
  if (_impl->shuttingDown)
  {
    return ConnectResult::err(
      TransportErrorInfo{TransportError::ShuttingDown, "transport shutting down"});
  }

  auto result = _impl->engine->connect(host, port, tls);
  if (result.isErr())
  {
    // Defensive: the current TcpEngine::connect() always returns ok(sid) and
    // reports failures asynchronously via onClose, so this branch is unreachable
    // for TCP today. It guards future engines / a connect() that gains a
    // synchronous-failure mode. Returns before the connect guard is constructed,
    // so a synchronous failure is never parked and never counted (M-NEW-1/L-5/L-A).
    return result;
  }
  SessionId sid = result.value();

  _impl->pendingConnects[sid] = op;
  // Count this parked connectSync for the teardown gate. The guard is
  // constructed ONLY here, on the success path after registration, and must
  // OUTLIVE the timeout-path engine->close(sid) below so _impl->engine stays
  // alive during that call (its dtor — the activeConnects decrement — is the
  // LAST _impl-touching action of connectSync, L6-1). Declared after `lk` so it
  // destructs first (decrement under the still-held lock).
  Impl::ParkGuard connectGuard(_impl->activeConnects, _impl->teardownCv);

  // Wait predicate adds shuttingDown so teardown wakes a parked connectSync even
  // on the emergency-detach path (which fires no onClose). C-4.
  op->cv.wait_for(lk, timeout, [&op, this] { return op->done || _impl->shuttingDown; });

  if (op->done)
  {
    return std::move(op->result);
  }

  if (_impl->shuttingDown)
  {
    // Woken by teardown. Do NOT erase pendingConnects (teardown owns and is
    // iterating the maps, L-NEW-1) and do NOT touch engine->close (engine is
    // being torn down, M-1). The guard decrements activeConnects on return.
    return ConnectResult::err(
      TransportErrorInfo{TransportError::ShuttingDown, "transport shutting down"});
  }

  // Timeout — keep pendingConnects[sid] entry so onClose finds it and suppresses
  // the global onClose callback (the user never received this sid). The entry's
  // shared_ptr<SyncConnectOp> keeps op alive until the I/O thread's onClose
  // handler erases it. NO LEAK (M-2/H-1): a sid returned by engine->connect()
  // always receives an onClose — either (a) doConnect FAILED, in which case every
  // failure path fires onClose directly (incl. the SSL_new path, fixed in
  // tcp_engine.hpp), which erases pendingConnects[sid] and wakes us (we then
  // return via the op->done branch above, not here); or (b) doConnect SUCCEEDED
  // and inserted the session, so this Close (FIFO-ordered after the Connect) is
  // found by doClose -> closeNow -> onClose, erasing pendingConnects[sid]. The
  // only no-onClose case is the engine already being stopped (teardown), where
  // the handshake + ~Impl reap the entry. Release syncMutex BEFORE calling engine
  // methods to avoid
  // AB-BA deadlock. connectGuard is still in scope (activeConnects>0) across the
  // close() call, keeping _impl->engine alive (L6-1). RE-ACQUIRE the lock before
  // returning so connectGuard's dtor (the activeConnects decrement, a syncMutex-
  // guarded mutation) runs UNDER the lock — it destructs before `lk` because it
  // is declared after it.
  lk.unlock();
  _impl->engine->close(sid);
  lk.lock();
  // We have ISSUED engine->close(sid) — the session is being torn down. Even if a
  // late onConnect set op->done==true in the unlock window, we MUST NOT return
  // ok(sid) for a session we just closed (H-1/M-A): that would hand the caller a
  // live-looking handle to a dead session. Report the truthful outcome: timeout
  // (the connect did not complete within the deadline and was closed), or
  // ShuttingDown if teardown began. The pre-close op->done check above already
  // returned ok for a connect that genuinely succeeded before the timeout.
  if (_impl->shuttingDown)
  {
    return ConnectResult::err(
      TransportErrorInfo{TransportError::ShuttingDown, "transport shutting down"});
  }
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

  // Single continuous lock acquisition: find-or-create, the entry-fence/
  // single-waiter checks, the parked wait, and the drain all happen under one
  // unique_lock (M-3). The CV wait atomically releases/re-acquires it. No user
  // callback is invoked here (drain is a memcpy), so HR-6 is preserved.
  std::unique_lock<std::mutex> lk(_impl->syncMutex);

  // Entry fence (INV-8): if teardown has begun, reject before parking so the
  // teardown handshake's gate cannot be re-armed by a fresh waiter.
  if (_impl->shuttingDown)
  {
    return ReceiveResult::err(
      TransportErrorInfo{TransportError::ShuttingDown, "transport shutting down"});
  }

  std::shared_ptr<Impl::SyncReceiveBuffer> buf;
  {
    auto it = _impl->receiveBuffers.find(sid);
    if (it == _impl->receiveBuffers.end())
    {
      buf = std::make_shared<Impl::SyncReceiveBuffer>();
      _impl->receiveBuffers[sid] = buf;
    }
    else
    {
      buf = it->second;
    }
  }

  // Single-waiter contract (INV-6): reject a second concurrent waiter on the
  // same session loudly rather than relying on notify_one to reach it. Also
  // reject overlap with an in-progress Sync->Async flush on this session (M-2).
  if (buf->waiters > 0 || buf->flushing)
  {
    return ReceiveResult::err(TransportErrorInfo{
      TransportError::Cancelled,
      buf->flushing ? "receiveSync overlaps a setReadMode flush on this session"
                    : "receiveSync already in progress for this session (single-waiter contract)"});
  }

  // Park: bump the per-buffer GC gate (buf->waiters) AND the Impl-level teardown
  // gate (activeReceives) TOGETHER. These two counters MUST be incremented and
  // decremented in lockstep — the teardown gate (activeReceives==0) and the GC
  // gate (waiters==0) diverging is a latent UAF vector (INV-7/M-1). Every
  // receiveSync park site must construct BOTH guards; do not add a park path that
  // bumps only one. Both destruct (decrement + wake teardown) under the still-held
  // lock because they are declared after `lk` (implGuard first, then bufGuard).
  Impl::ParkGuard bufGuard(buf->waiters, _impl->teardownCv);
  Impl::ParkGuard implGuard(_impl->activeReceives, _impl->teardownCv);
  assert(buf->waiters == 1 && "single-waiter contract (INV-6): exactly one receiveSync parks");

  // Fold the spurious-wake case back into the wait loop (L-1): wait_until with a
  // fixed deadline returns only on data/close/overflow/shuttingDown or timeout.
  // A past deadline returns immediately with the predicate's current value, so
  // there is no negative-duration and no infinite loop.
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  const bool signalled = buf->cv.wait_until(lk, deadline,
                                            [&buf, this]
                                            {
                                              return buf->hasData || buf->closed ||
                                                     buf->overflow || _impl->shuttingDown;
                                            });
  if (!signalled)
  {
    // Pure timeout (predicate false under the lock — the old `if (buf->closed)`
    // cleanup branch here was dead code and is removed, M-1). The buffer is left
    // in the map; the onClose GC reclaims it once the session closes.
    return ReceiveResult::err(TransportErrorInfo{TransportError::Timeout, "receiveSync timed out"});
  }

  // Drain any buffered bytes FIRST, even if the peer has also closed or teardown
  // has begun. A peer can deliver the final bytes and the FIN together, so
  // returning PeerClosed/teardown before these bytes would silently lose the
  // tail of the response. PeerClosed is reported only once fully drained.
  if (!buf->data.empty())
  {
    std::size_t copyLen = std::min(len, buf->data.size());
    std::memcpy(buffer, buf->data.data(), copyLen);
    buf->data.erase(buf->data.begin(), buf->data.begin() + static_cast<std::ptrdiff_t>(copyLen));
    buf->hasData = !buf->data.empty();
    assert(buf->hasData == !buf->data.empty()); // INV-1
    len = copyLen;
    return ReceiveResult::ok(copyLen);
  }

  // Buffer drained. Surface overflow before close so callers can distinguish a
  // dropped-data condition from a clean EOF (N-2).
  if (buf->overflow)
  {
    return ReceiveResult::err(TransportErrorInfo{TransportError::BufferOverflow,
                                                 "sync receive buffer overflow (data dropped)"});
  }

  if (buf->closed)
  {
    // Fully drained and the peer has closed — signal EOF and reclaim the entry.
    // Safe to erase: this is the only/last waiter (INV-6), and the guards will
    // decrement after this scope. buf (shared_ptr) keeps the object alive.
    _impl->receiveBuffers.erase(sid);
    _impl->readModes.erase(sid);
    return ReceiveResult::err(TransportErrorInfo{TransportError::PeerClosed, "session closed"});
  }

  // Woken by teardown with nothing buffered (do NOT erase — teardown owns the
  // maps and the teardownWaitOut loop is iterating them, INV-5/L-NEW-1).
  return ReceiveResult::err(
    TransportErrorInfo{TransportError::ShuttingDown, "transport shutting down"});
}

// ── Read Modes ───────────────────────────────────────────────────────────────

inline bool Transport::setReadMode(SessionId sid, ReadMode mode)
{
  // I/O-thread guard (TD-INV-5): a Sync->Async flush invokes the user onData
  // callback, which could delete the Transport on the I/O thread; the resulting
  // teardown handshake would then wait on activeFlushes==0 for THIS thread's own
  // flush -> self-deadlock. Reject on the I/O thread, like the other sync ops.
  // MUST precede the allowReadModeSwitch check so the throw is reached regardless.
  if (_impl->engine->isRunning() &&
      std::this_thread::get_id() == _impl->engine->getIoThreadId())
  {
    throw std::logic_error("setReadMode() called from I/O thread — not permitted. "
                           "Switch read mode from a non-I/O thread.");
  }

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

  // Fetch the buffer and mark it as being flushed UNDER THE SAME LOCK (no gap in
  // which GC could erase the entry before it is marked `flushing`). Marking
  // `flushing` excludes the entry from GC (C-1) and bumping `activeFlushes` makes
  // the teardown handshake wait this flusher out before destroying _impl
  // (C-3b/INV-5) — the flush releases syncMutex for the onData callback below and
  // re-acquires it, so it is an external thread touching _impl. FlushGuard is
  // cleanup-only (its dtor clears flushing / decrements activeFlushes).
  std::shared_ptr<Impl::SyncReceiveBuffer> buf;
  std::unique_ptr<Impl::FlushGuard> flushGuard;
  {
    std::lock_guard<std::mutex> lk(_impl->syncMutex);
    if (_impl->shuttingDown)
    {
      return false; // entry fence (INV-8): no flush during teardown
    }
    auto bufIt = _impl->receiveBuffers.find(sid);
    if (bufIt == _impl->receiveBuffers.end())
    {
      _impl->readModes[sid] = ReadMode::Async; // nothing buffered to flush
      return true;
    }
    buf = bufIt->second;
    // Construct the guard UNDER the fetch lock (its ctor sets flushing +
    // ++activeFlushes with no GC window) — increment and decrement owned by one
    // RAII object (L-2). It outlives this scope via the unique_ptr; its dtor
    // re-acquires the lock to clean up.
    flushGuard =
      std::make_unique<Impl::FlushGuard>(_impl->syncMutex, _impl->activeFlushes,
                                         _impl->teardownCv, buf);
  }

  for (;;)
  {
    std::vector<std::uint8_t> flushData;
    {
      std::lock_guard<std::mutex> lk(_impl->syncMutex);
      // Bail if teardown began mid-flush: the handshake is waiting on
      // activeFlushes==0 and will own the maps. The FlushGuard dtor clears
      // flushing/activeFlushes and wakes it.
      if (_impl->shuttingDown)
      {
        return false;
      }
      if (!buf->data.empty())
      {
        flushData = std::move(buf->data);
        buf->data.clear();
        buf->hasData = false; // INV-1
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
