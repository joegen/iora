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
#include <unordered_set>
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
  // Specifically: no path holds both callbackMutex and syncMutex simultaneously —
  // callbacks are copied under callbackMutex and released before syncMutex is taken
  // (and vice-versa) — so the ordering above is a defensive convention, never a
  // live constraint.
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
  //   sendSync (register/wait), setReadMode (mode update + flush), getReadMode
  //   (read mode), the I/O thread data/close handlers, and the teardown
  //   handshake in ~Transport (move/copy are deleted; there is no operator=).
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

  // Sids owned by a TIMED-OUT connectSync that has issued its own engine->close(sid)
  // (protected by syncMutex). The onClose global-suppression normally keys on
  // pendingConnects[sid], but a connect that SUCCEEDS in the tiny window between the
  // caller's timeout and its close lets onConnect erase that entry first — so the
  // close's onClose would no longer find it and would fire the global onClose for a
  // sid the user never received (Finding 1). This marker SURVIVES onConnect and is
  // consumed by onClose, closing that race for both TCP and UDP.
  std::unordered_set<SessionId> syncOwnedSuppress;

  // Sync send completion ops (protected by syncMutex). Like pendingConnects, a
  // parked sendSync registers here so the teardown handshake can wake it — sendSync
  // has no data to drain, so its CV is ALWAYS woken on teardown (both the fence and
  // the wait-out), exactly like connectSync. Keyed by a monotonic op id because
  // multiple sendSync calls may be in flight concurrently on one session.
  struct SyncSendOp
  {
    std::condition_variable cv;
    bool done{false};
    SendResult result{SendResult::err(TransportErrorInfo{TransportError::Timeout, "pending"})};
  };
  std::unordered_map<std::uint64_t, std::shared_ptr<SyncSendOp>> pendingSends;
  std::uint64_t nextSendOpId{1};

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
  std::size_t activeSends{0};    // parked sendSync waiters (INV-5)
  std::size_t pendingSyncOps{0}; // in-flight parked sync ops (connect/receive/send)
                                 // for the maxPendingSyncOps cap (0 = unlimited, C2)
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

  // RAII counter for the maxPendingSyncOps cap (C2). The owner holds syncMutex for
  // the whole lifetime (constructed under the entry lock; declared AFTER the
  // unique_lock so it destructs FIRST, under the still-held lock). Purely the
  // concurrent-op cap — NOT part of the teardown gate, so no teardownCv notify.
  struct PendingSyncGuard
  {
    std::size_t &counter;
    explicit PendingSyncGuard(std::size_t &c) : counter(c) { ++counter; }
    ~PendingSyncGuard() { --counter; }
    PendingSyncGuard(const PendingSyncGuard &) = delete;
    PendingSyncGuard &operator=(const PendingSyncGuard &) = delete;
  };

  // True iff the concurrent parked-sync-op cap (config.maxPendingSyncOps; 0 =
  // unlimited) is reached. Caller MUST hold syncMutex (reads pendingSyncOps). C2.
  bool syncCapReached() const
  {
    return config.maxPendingSyncOps != 0 && pendingSyncOps >= config.maxPendingSyncOps;
  }

  // Resolve a sync-op timeout parameter. The sentinel kUseConfigSyncTimeout (any
  // negative value) means "use the configured default"; a misconfigured non-positive
  // config.defaultSyncTimeout is floored to 30 s so it can never silently degrade a
  // sync op to a non-blocking poll (F-2). An explicit non-negative timeout (including
  // 0 = non-blocking) is respected as-is.
  std::chrono::milliseconds resolveSyncTimeout(std::chrono::milliseconds t) const
  {
    if (t < std::chrono::milliseconds::zero())
    {
      return config.defaultSyncTimeout > std::chrono::milliseconds::zero()
               ? config.defaultSyncTimeout
               : kFallbackSyncTimeout;
    }
    return t;
  }

  // Wake every parked connectSync AND sendSync waiter. Both classes have no data to
  // drain, so teardown always wakes them (unlike receiveSync, which is drained first
  // on the NORMAL path). Caller MUST hold syncMutex. C4/L3.
  void wakeConnectAndSendWaiters()
  {
    for (auto &kv : pendingConnects)
    {
      kv.second->cv.notify_all();
    }
    for (auto &kv : pendingSends)
    {
      kv.second->cv.notify_all();
    }
  }

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
    wakeConnectAndSendWaiters();
    if (notifyReceive)
    {
      for (auto &kv : receiveBuffers)
      {
        kv.second->cv.notify_all();
      }
    }
    teardownCv.wait(lk, [this] {
      return activeReceives == 0 && activeConnects == 0 && activeFlushes == 0 && activeSends == 0;
    });
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
    wakeConnectAndSendWaiters();
  }

  // Full teardown for the current _impl, covering all paths (INV-5a/5b). The
  // caller (Transport::~Transport / operator=) guarantees `engine` is present.
  // Gated on engine PRESENCE, never on isRunning() — a parked waiter/flusher/
  // connector can outlive isRunning()==false, and destroying _impl under it is a
  // use-after-free.
  void performTeardown()
  {
    // performTeardown handles ONLY the non-I/O-thread teardown paths. The
    // I/O-thread (self-destruction) case is handled by Transport::~Transport
    // via deferred self-destruction (it owns the unique_ptr and can release
    // it). If performTeardown were ever entered on the I/O thread it
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
          // setReadMode removed the fd from EPOLLIN via engine->setReadEnabled (C5),
          // so on TCP no further reads are scheduled. This callback-level drop
          // remains the fallback for (a) bytes already in flight when read was
          // disabled and (b) UDP, whose shared socket cannot disable read per
          // session (setReadEnabled is a no-op there).
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
        bool suppressOwned = false;
        {
          std::lock_guard<std::mutex> lk(syncMutex);
          auto connIt = pendingConnects.find(sid);
          if (connIt != pendingConnects.end())
          {
            op = connIt->second;
            op->result = ConnectResult::err(reason);
            op->done = true;
            pendingConnects.erase(connIt);
            syncOwnedSuppress.erase(sid); // also clear any timeout marker (no leak)
          }
          else if (syncOwnedSuppress.erase(sid) > 0)
          {
            // A timed-out connectSync issued close(sid) and marked it, and a racing
            // onConnect already consumed pendingConnects[sid] (Finding 1). Suppress
            // the global onClose for this user-never-received sid.
            suppressOwned = true;
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
        if (suppressOwned)
        {
          // Same as above: the sid never escaped to user code (its connectSync timed
          // out and closed it), so suppress the global onClose/observers/tombstone.
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

inline Transport::Transport(PrivateTag, TransportConfig config)
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

inline Transport::Transport(PrivateTag, std::unique_ptr<detail::EngineBase> engine,
                            TransportConfig config)
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
  // I/O-THREAD SELF-DESTRUCTION: reached ONLY by dropping the LAST
  // shared_ptr<Transport> reference from within one of our own I/O-thread
  // callbacks — i.e. a SOLE owner (single-threaded). ~Impl would free the engine +
  // syncMutex + maps while the I/O thread is still unwinding the engine's dispatch
  // on its own stack (UAF), so we defer Impl deletion to the detached engine
  // thread's post-loop() epilogue (delete-this-at-thread-end): wait out external
  // sync waiters, release _impl, hand it to the engine to delete after loop()
  // returns, and detach.
  //
  // The branch is gated on thread-identity ALONE. There is intentionally NO
  // isRunning() assert in EITHER polarity, because BOTH _running values are
  // legitimate here:
  //   (a) shutdownDrain path  — the Shutdown command clears _running ON the I/O
  //       thread (tcp_engine.hpp:1130-1131) BEFORE shutdownDrain fires onClose
  //       (tcp_engine.hpp:1076), so _running == FALSE.
  //   (b) peer-close-while-running path — closeNow (tcp_engine.hpp:1170) and the
  //       connect-error sites (tcp_engine.hpp:1607/1641/1654) fire the same onClose
  //       with _running still TRUE.
  // An assert(isRunning()) would spuriously abort (a); an assert(!isRunning())
  // would spuriously abort (b). The branch condition (we are on the I/O thread) is
  // the only invariant.
  //
  // The genuinely CONCURRENT C-1 race (another thread mid-stop()) is excluded
  // STRUCTURALLY by shared ownership, NOT by _running: a concurrent stopper is
  // blocked in engine->stop()/_loop.join() holding its OWN shared_ptr<Transport>
  // across the entire onClose, so this onClose drop can never be the LAST reference
  // while a stopper exists — therefore ~Transport never runs on the I/O thread
  // concurrently with another thread's call (join-ordering co-ownership).
  if (std::this_thread::get_id() == _impl->engine->getIoThreadId())
  {
#ifdef IORA_DISABLE_SELFDESTRUCT_DEFERRAL
    // RETAINED NEGATIVE CONTROL (test-only): synchronous teardown on the I/O
    // thread reproduces the heap-use-after-free (engine freed under its own
    // running dispatch). A build with this macro MUST ASan-fault on the sole-owner
    // reset-in-callback scenario — proving the deferral below is what prevents the
    // UAF (guards TD-INV-4).
    _impl->teardownWaitOut(/*notifyReceive=*/true);
    _impl->engine->detachForTermination();
    return; // ~Impl runs now -> UAF
#else
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

// Move and copy are deleted (HR-1/HR-2): Transport is shared-ownership-only. The
// former move-ctor and move-assignment teardown paths (and the operator= interim
// std::abort) no longer exist — a Transport is never moved, only shared.

inline std::shared_ptr<Transport> Transport::tcp(TransportConfig config)
{
  config.protocol = Protocol::TCP;
  // make_shared (single allocation; enable_shared_from_this-compatible). PrivateTag
  // is nameable here (this is a Transport member), so the tag-gated ctor is callable.
  return std::make_shared<Transport>(PrivateTag{}, std::move(config));
}

inline std::shared_ptr<Transport> Transport::udp(TransportConfig config)
{
  config.protocol = Protocol::UDP;
  return std::make_shared<Transport>(PrivateTag{}, std::move(config));
}

inline std::shared_ptr<Transport> Transport::withEngine(std::unique_ptr<detail::EngineBase> engine,
                                                        TransportConfig config)
{
  return std::make_shared<Transport>(PrivateTag{}, std::move(engine), std::move(config));
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
    // Guard on thread-identity ALONE (HR-5/DQ-4), uniform with the sync ops. The
    // isRunning() conjunct is intentionally dropped so the guard also fires during
    // shutdownDrain (_running==false) — a callback that reaches stop() on the I/O
    // thread would self-join engine->stop(); rejecting it is the documented
    // contract and removes the guard asymmetry with connectSync/receiveSync/
    // sendSync/setReadMode.
    if (std::this_thread::get_id() == _impl->engine->getIoThreadId())
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

inline bool Transport::isOnIoThread() const noexcept
{
  return _impl && _impl->engine && _impl->engine->isOnIoThread();
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
  // Guard on thread-identity ALONE (HR-5/DQ-4), uniform with stop()/the sync ops:
  // reject a call from the I/O thread regardless of running state (dropping the
  // isRunning() conjunct also avoids the unverified addListener-during-drain path).
  if (std::this_thread::get_id() == _impl->engine->getIoThreadId())
  {
    throw std::logic_error("addListener() called from I/O thread — not permitted. "
                           "Call before start() or from a worker thread.");
  }
  return _impl->engine->addListener(bindIp, port, tls);
}

inline ConnectResult Transport::connect(const std::string &host, std::uint16_t port, TlsMode tls)
{
  return connect(host, port, tls, TlsClientOptions{});
}

inline ConnectResult Transport::connect(const std::string &host, std::uint16_t port, TlsMode tls,
                                        const TlsClientOptions &opts)
{
  return _impl->engine->connect(host, port, tls, opts);
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
  return connectSync(host, port, tls, TlsClientOptions{}, timeout);
}

inline ConnectResult Transport::connectSync(const std::string &host, std::uint16_t port,
                                            TlsMode tls, const TlsClientOptions &opts,
                                            std::chrono::milliseconds timeout)
{
  // Guard on thread-identity ALONE (HR-5/DQ-4): getIoThreadId()==_loop.get_id() is
  // the default std::thread::id pre-start/post-detach, so it matches only the real
  // running I/O thread. Dropping the isRunning() conjunct closes the window where
  // _running==false but an I/O-thread callback (during shutdownDrain) still calls a
  // guarded op that would deadlock.
  if (std::this_thread::get_id() == _impl->engine->getIoThreadId())
  {
    throw std::logic_error("connectSync() called from I/O thread — would deadlock. "
                           "Use connect() (async) instead, or post to a worker thread.");
  }

  // Resolve the sentinel/default timeout (M-3/F-2). UDP no longer short-circuits
  // here: it parks in pendingConnects like TCP and returns only once the session is
  // registered (onConnect fires after the I/O thread inserts it), so the returned
  // sid is immediately usable by a subsequent sync send. Otherwise the enqueue-time
  // sessionSendable check (CF-H1) would race the async UDP session insert (F-1).
  timeout = _impl->resolveSyncTimeout(timeout);

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

  // Concurrent-op cap (C2): reject when maxPendingSyncOps parked sync ops are
  // already in flight (0 = unlimited). capGuard is declared after `lk` so it
  // decrements under the still-held lock at every exit, incl. the final
  // unlock/close/relock window (lk is re-locked before return).
  if (_impl->syncCapReached())
  {
    return ConnectResult::err(
      TransportErrorInfo{TransportError::TooManyPendingSyncOps, "maxPendingSyncOps reached"});
  }
  Impl::PendingSyncGuard capGuard(_impl->pendingSyncOps);

  auto result = _impl->engine->connect(host, port, tls, opts);
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
  //
  // Finding 1: mark this sid sync-owned (suppress globals) UNDER the lock BEFORE
  // releasing it to issue close(sid). A racing onConnect can complete the connect and
  // erase pendingConnects[sid] before our close's onClose runs; the marker survives
  // onConnect so onClose still suppresses the global onClose for this
  // user-never-received sid.
  _impl->syncOwnedSuppress.insert(sid);
  lk.unlock();
  try
  {
    _impl->engine->close(sid);
  }
  catch (...)
  {
    // Symmetry with sendSync (CF-M1 / R2-LOW): re-acquire syncMutex before unwinding
    // so connectGuard/capGuard decrement + the teardownCv notify run UNDER the lock.
    // engine->close() -> enqueue() swallows std::exception today, but the
    // Command::close argument is constructed BEFORE enqueue's try and could throw
    // (bad_alloc) — do not rely on std::string SSO making the message non-allocating.
    lk.lock();
    throw;
  }
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
  // Guard on thread-identity ALONE (HR-5/DQ-4) — see connectSync for rationale.
  if (std::this_thread::get_id() == _impl->engine->getIoThreadId())
  {
    throw std::logic_error("sendSync() called from I/O thread — would deadlock. "
                           "Use send()/sendAsync() instead, or post to a worker thread.");
  }

  timeout = _impl->resolveSyncTimeout(timeout); // sentinel -> config default; <=0 floored (M-3/F-2)

  // Block until the async send is ACCEPTED/COMPLETED by the engine (or `timeout`
  // elapses), honoring the timeout — the former implementation ignored it and
  // returned as soon as the bytes were enqueued. "Completion" is whatever the
  // engine's SendCompleteCallback signals: for the current TCP/UDP engines that is
  // the synchronous, post-copy acceptance of the bytes into the engine (NOT wire
  // transmission or a TLS flush), so today the completion is effectively immediate
  // (UDP always; TCP on enqueue) and the timeout rarely elapses — the parked-waiter
  // machinery below is forward-correct for a future engine that defers completion.
  // Mirrors connectSync: register a completion op under syncMutex (so the teardown
  // handshake can wake it — sendSync has no data to drain, so it is always woken on
  // teardown), park on the op's CV, and count the parked sender in the teardown gate
  // via a ParkGuard on activeSends.
  auto op = std::make_shared<Impl::SyncSendOp>();
  std::unique_lock<std::mutex> lk(_impl->syncMutex);

  // Entry fence (INV-8): reject before registering/counting.
  if (_impl->shuttingDown)
  {
    return SendResult::err(
      TransportErrorInfo{TransportError::ShuttingDown, "transport shutting down"});
  }

  // Concurrent-op cap (C2): reject rather than block when maxPendingSyncOps parked
  // sync ops are already in flight (0 = unlimited). Checked under the SAME lock as
  // the increment so a race cannot exceed the cap.
  if (_impl->syncCapReached())
  {
    return SendResult::err(
      TransportErrorInfo{TransportError::TooManyPendingSyncOps, "maxPendingSyncOps reached"});
  }

  const std::uint64_t opId = _impl->nextSendOpId++;
  _impl->pendingSends[opId] = op;
  // Declared AFTER `lk` so both destruct under the still-held lock (LIFO: capGuard,
  // then sendGuard which also wakes the teardown handshake).
  Impl::ParkGuard sendGuard(_impl->activeSends, _impl->teardownCv);
  Impl::PendingSyncGuard capGuard(_impl->pendingSyncOps);

  // Issue the async send WITHOUT holding syncMutex: the engine may fire the
  // completion SYNCHRONOUSLY on this thread (http_server SR-7), and the completion
  // callback re-acquires syncMutex — invoking it under the held lock would
  // self-deadlock. The op (shared_ptr) is captured so the callback stays valid even
  // if we return (timeout) before it fires; capturing `this` is safe because the
  // engine — and thus _impl — outlives every completion (the I/O thread is joined
  // before ~Impl, and the activeSends gate blocks teardown until we return).
  lk.unlock();
  try
  {
    _impl->engine->sendAsync(sid, data.data(), data.size(),
                             [op, this](SessionId, const SendResult &result)
                             {
                               {
                                 std::lock_guard<std::mutex> cbLk(_impl->syncMutex);
                                 if (!op->done)
                                 {
                                   op->result = result;
                                   op->done = true;
                                 }
                               }
                               // Notify OUTSIDE syncMutex (mirrors onConnect/onClose)
                               // so the woken thread does not immediately re-block on
                               // the mutex it is about to reacquire (CF-L5).
                               op->cv.notify_one();
                             });
  }
  catch (...)
  {
    // Re-acquire syncMutex before unwinding so sendGuard/capGuard (declared after
    // `lk`) decrement activeSends/pendingSyncOps and fire teardownCv UNDER the lock;
    // otherwise a concurrent teardown could lose the wake and hang, plus a data race
    // on the non-atomic counters (CF-M1). Also erase this op's pendingSends entry —
    // else it is orphaned (holding `op` alive) until ~Impl (R2-LOW). TcpEngine::send
    // allocates a ByteBuffer OUTSIDE enqueue's catch, so sendAsync can throw (e.g.
    // bad_alloc); connectSync's structurally-identical engine->close() window is
    // wrapped the same way for symmetry.
    lk.lock();
    _impl->pendingSends.erase(opId);
    throw;
  }
  lk.lock();

  op->cv.wait_for(lk, timeout, [&op, this] { return op->done || _impl->shuttingDown; });

  _impl->pendingSends.erase(opId);

  if (op->done)
  {
    return std::move(op->result);
  }
  if (_impl->shuttingDown)
  {
    return SendResult::err(
      TransportErrorInfo{TransportError::ShuttingDown, "transport shutting down"});
  }
  return SendResult::err(TransportErrorInfo{TransportError::Timeout, "sendSync timed out"});
}

inline ReceiveResult Transport::receiveSync(SessionId sid, void *buffer, std::size_t &len,
                                            std::chrono::milliseconds timeout)
{
  // Guard on thread-identity ALONE (HR-5/DQ-4) — see connectSync for rationale.
  if (std::this_thread::get_id() == _impl->engine->getIoThreadId())
  {
    throw std::logic_error("receiveSync() called from I/O thread — would deadlock. "
                           "Use ReadMode::Async with onData() callback instead.");
  }

  timeout = _impl->resolveSyncTimeout(timeout); // sentinel -> config default; <=0 floored (M-3/F-2)

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

  // Concurrent-op cap (C2): reject when maxPendingSyncOps parked sync ops are
  // already in flight (0 = unlimited). capGuard is declared before the park guards
  // so it decrements last (outermost), under the still-held lock.
  if (_impl->syncCapReached())
  {
    return ReceiveResult::err(
      TransportErrorInfo{TransportError::TooManyPendingSyncOps, "maxPendingSyncOps reached"});
  }
  Impl::PendingSyncGuard capGuard(_impl->pendingSyncOps);

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
  // Guard on thread-identity ALONE (HR-5/DQ-4) — see connectSync for rationale.
  if (std::this_thread::get_id() == _impl->engine->getIoThreadId())
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

      // C5: toggle the fd's EPOLLIN registration when crossing the Disabled
      // boundary so Disabled mode stops incurring recv() syscalls. TCP removes the
      // fd from EPOLLIN via an engine command; UDP's shared socket cannot disable
      // read per session (setReadEnabled returns false there) so the onData drop
      // remains the fallback. Enqueues an engine command — safe under syncMutex (it
      // does not re-acquire syncMutex), like connectSync's engine->connect().
      if (mode == ReadMode::Disabled && oldMode != ReadMode::Disabled)
      {
        _impl->engine->setReadEnabled(sid, false);
      }
      else if (mode != ReadMode::Disabled && oldMode == ReadMode::Disabled)
      {
        _impl->engine->setReadEnabled(sid, true);
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
  std::chrono::milliseconds timeout, const TlsClientOptions &opts)
{
  if (token.isCancelled())
  {
    return ConnectResult::err(TransportErrorInfo{TransportError::Cancelled, "cancelled"});
  }
  // *Cancellable variants have no config access; clamp a negative/sentinel timeout to
  // the 30 s literal default (avoids computing a past deadline that would return an
  // immediate Timeout). They do NOT honor config.defaultSyncTimeout — use the
  // non-cancellable connectSync/sendSync/receiveSync for config-tuned timeouts (F-3).
  if (timeout < std::chrono::milliseconds::zero())
  {
    timeout = kFallbackSyncTimeout;
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
  auto result = connectSync(host, port, tls, opts, subTimeout);
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
    result = connectSync(host, port, tls, opts, subTimeout);
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
  // No config access here; clamp a negative/sentinel timeout to the 30 s literal
  // default (F-3). sendSync itself resolves config for a non-negative value.
  if (timeout < std::chrono::milliseconds::zero())
  {
    timeout = kFallbackSyncTimeout;
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
  // *Cancellable variants have no config access; clamp a negative/sentinel timeout to
  // the 30 s literal default (avoids a past deadline → immediate Timeout without ever
  // polling). They do NOT honor config.defaultSyncTimeout — use receiveSync for that (F-3).
  if (timeout < std::chrono::milliseconds::zero())
  {
    timeout = kFallbackSyncTimeout;
  }
  // Sub-timeout loop: break the total timeout into intervals so that
  // cancel() is detected between iterations.
  constexpr auto subInterval = std::chrono::milliseconds{100};
  auto deadline = std::chrono::steady_clock::now() + timeout;

  // do/while guarantees at least one receiveSync poll even for an explicit
  // timeout==0 (a non-blocking receive) — matching connectSyncCancellable, which
  // always makes one attempt. A plain while(now<deadline) would do zero polls at
  // timeout==0 (cpp17 R3-LOW).
  do
  {
    if (token.isCancelled())
    {
      return ReceiveResult::err(TransportErrorInfo{TransportError::Cancelled, "cancelled"});
    }
    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
      deadline - std::chrono::steady_clock::now());
    // Clamp negative remaining to zero so subTimeout is a valid (non-blocking) poll.
    auto subTimeout =
      std::min(std::max(remaining, std::chrono::milliseconds::zero()), subInterval);
    auto result = receiveSync(sid, buffer, len, subTimeout);
    if (result.isOk())
    {
      return result;
    }
    if (result.error().code != TransportError::Timeout)
    {
      return result; // Non-timeout error (PeerClosed, etc.) — return immediately
    }
  } while (std::chrono::steady_clock::now() < deadline);
  return ReceiveResult::err(TransportErrorInfo{TransportError::Timeout, "receiveSync timed out"});
}

} // namespace network
} // namespace iora
