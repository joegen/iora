// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include "iora/network/websocket_frame.hpp"
#include "iora/network/transport_impl.hpp"
#include "iora/crypto/secure_rng.hpp"
#include "iora/util/base64.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace iora {
namespace network {

/// \brief WebSocket connection states.
enum class WebSocketState
{
  DISCONNECTED,
  CONNECTING,
  CONNECTED,
  CLOSING,
  CLOSED
};

/// \brief WebSocket client with auto-reconnect (OPTION C: shared_ptr-managed).
///
/// Performs the HTTP upgrade handshake, exchanges frames (client-side masking),
/// and optionally auto-reconnects with exponential backoff.
///
/// OWNERSHIP MODEL (S-3 phase-2, Option C):
///   * A WebSocketClient exists only inside a std::shared_ptr — it derives
///     std::enable_shared_from_this, its constructor is private (passkey-gated),
///     and the ONLY construction surface is the static create() factory. Copy
///     AND move are deleted.
///   * Every transport callback (onData/onClose/onError) and the single
///     long-lived reconnect worker capture a std::weak_ptr<WebSocketClient> and
///     promote `self = weak.lock(); if (!self) return;` BEFORE touching any
///     member. shared_from_this() is FORBIDDEN here (UB at refcount 0); only
///     weak_from_this() is used, and only post-construction (in doConnect()),
///     never in the constructor.
///   * The promoted `self` pins the client for the whole callback frame (and the
///     whole reconnect attempt), so a user callback that drops the last external
///     shared_ptr cannot free the client mid-use — ~WebSocketClient is deferred
///     until the frame unwinds (it may then run on the I/O or worker thread; the
///     dtor is noexcept and self-contained and handles both).
///   * USER-CALLBACK CONTRACT (HR-11): user callbacks MUST capture the client via
///     std::weak_ptr, never an owning std::shared_ptr. An owning capture stored
///     in a callback is a self-owning cycle that leaks the client + its worker
///     thread. This is the one invariant the compiler cannot enforce.
///
/// THREADING / LOCKS:
///   * _transportMutex (leaf) guards the member group
///     {_transport, _sessionId, _rc handle, _reconnectWorker thread object} as a
///     consistent unit (AP-16 — orthogonal to esft lifetime). Copy-then-invoke:
///     reads snapshot the {transport,sessionId} pair under the lock and deref
///     OUTSIDE it; writes set the pair under the lock; the worker thread object
///     uses move-out-then-join-outside-lock.
///   * rc->m (leaf, inside ReconnectControl) guards the reconnect worker's wakeup
///     state.
///   * _dataMutex (leaf) guards the receive/fragment buffers + negotiated proto.
///   * The three leaf locks are mutually independent — never nested, never held
///     simultaneously, never held across
///     stop()/close()/sendAsync()/reset()/doConnect()/join()/weak.lock().
///   * _connectMutex guards the blocking-connect handshake CV. It is released
///     before any stop()/teardown (connect() / reconnectAttempt never hold it
///     across teardownTransport).
class WebSocketClient final : public std::enable_shared_from_this<WebSocketClient>
{
public:
  using TextCallback = std::function<void(const std::string&)>;
  using BinaryCallback = std::function<void(const std::vector<std::uint8_t>&)>;
  using ConnectCallback = std::function<void(const std::string& subprotocol)>;
  using CloseCallback = std::function<void(std::uint16_t code, const std::string& reason)>;
  using ErrorCallback = std::function<void(const std::string& message)>;
  using StateCallback = std::function<void(WebSocketState)>;

  struct Options
  {
    bool autoReconnect;
    std::chrono::milliseconds initialReconnectDelay;
    std::chrono::milliseconds maxReconnectDelay;
    std::vector<std::string> subprotocols;
    std::chrono::seconds pingInterval;
    std::unordered_map<std::string, std::string> headers; // custom upgrade headers
    TlsMode tlsMode;

    Options()
      : autoReconnect(false)
      , initialReconnectDelay(1000)
      , maxReconnectDelay(30000)
      , pingInterval(30)
      , tlsMode(TlsMode::None)
    {
    }
  };

private:
  // Passkey: only WebSocket::create() can name PrivateTag, so the public ctor is
  // unreachable from outside the class — every instance is born via create() and
  // therefore lives inside a std::shared_ptr (precondition for weak_from_this()).
  struct PrivateTag
  {
  };

public:
  /// \brief Internal constructor — use create(). The PrivateTag passkey makes
  /// this unreachable from outside the class even though it is public (make_shared
  /// requires a public constructor).
  explicit WebSocketClient(PrivateTag)
    : _sessionId{0}
    , _state{WebSocketState::DISCONNECTED}
  {
  }

  /// \brief The ONLY way to construct a WebSocketClient. Returns a shared_ptr;
  /// the instance must be held via shared_ptr for its whole lifetime (the
  /// reconnect worker and transport callbacks rely on weak_from_this()).
  /// create() does nothing but make_shared — it must not capture weak_from_this()
  /// before make_shared completes.
  static std::shared_ptr<WebSocketClient> create()
  {
    return std::make_shared<WebSocketClient>(PrivateTag{});
  }

  ~WebSocketClient()
  {
    // noexcept, self-contained, the UNIVERSAL REAPER. May run on a user thread
    // (normal), the I/O thread, or the worker thread (a promoted-self callback
    // that drops the last strong ref). It NEVER calls the public disconnect()
    // (which can be reached on the I/O thread, where stop() would throw and the
    // legacy 50ms sleep would block the loop).
    try
    {
      // (1+2) Reap the worker FIRST so the std::thread member is non-joinable
      //       before its implicit destructor runs (else std::terminate). Because
      //       a mid-attempt worker holds a strong self, the dtor is reached only
      //       when the worker is idle — the join (off-thread case) reaps a
      //       CV-idle worker that wakes -> weak.lock() (maybe null) -> returns.
      reapWorker(/*isDtor=*/true);
      // (3) Own teardown. gracefulClose=false: do not enqueue sends from a dying
      //     object; on the I/O thread the last-Transport-ref drop terminates the
      //     loop via ~Transport deferred-self-destruct.
      teardownTransport(/*gracefulClose=*/false);
    }
    catch (...)
    {
      // A throw must never escape a destructor.
    }
  }

  WebSocketClient(const WebSocketClient&) = delete;
  WebSocketClient& operator=(const WebSocketClient&) = delete;
  WebSocketClient(WebSocketClient&&) = delete;
  WebSocketClient& operator=(WebSocketClient&&) = delete;

  // ── Callbacks ──────────────────────────────────────────────────────────
  //
  // PRECONDITION (M-1): these setters MUST be called BEFORE connect() and never
  // mutated afterward. The callback members are std::function and are read
  // lock-free from the I/O and reconnect-worker threads (handleData/handleFrame/
  // handleDisconnect/setState); installing them before connect() establishes the
  // happens-before (connect() synchronizes-with the I/O/worker threads it
  // spawns). Mutating a callback after connect() is a data race (UB) — there is
  // no synchronization on these members by design, as the set-once-before-connect
  // contract makes one unnecessary.
  //
  // User callbacks MUST weak-capture the client (HR-11): capturing an owning
  // shared_ptr<WebSocketClient> forms a self-owning cycle that leaks the client
  // and its worker thread.

  void setOnConnect(ConnectCallback cb) { _onConnect = std::move(cb); }
  void setOnTextMessage(TextCallback cb) { _onTextMessage = std::move(cb); }
  void setOnBinaryMessage(BinaryCallback cb) { _onBinaryMessage = std::move(cb); }
  void setOnClose(CloseCallback cb) { _onClose = std::move(cb); }
  void setOnError(ErrorCallback cb) { _onError = std::move(cb); }
  void setOnStateChange(StateCallback cb) { _onStateChange = std::move(cb); }

  // ── Connect / Disconnect ───────────────────────────────────────────────

  /// \brief Connect to a WebSocket server. Blocks until the handshake completes
  /// (CONNECTED) or fails/times out (DISCONNECTED). Always called on a user
  /// thread (it blocks on _connectCv, so never the I/O or worker thread).
  ///
  /// \note autoReconnect governs reconnection AFTER a successful connection
  /// drops — it does NOT silently retry a failed initial connect. If the initial
  /// handshake fails or times out, connect() reaps the worker, tears down, and
  /// returns false (no background retry); the caller decides whether to call
  /// connect() again. This keeps the blocking contract predictable (a false
  /// return means no live connection and no hidden background activity).
  /// \param host Server hostname or IP
  /// \param port Server port
  /// \param path Request path (e.g., "/ws")
  /// \param options Connection options
  /// \param timeoutMs Maximum time to wait for connection + upgrade.
  /// \return true if connected, false if failed or timed out.
  bool connect(const std::string& host, std::uint16_t port,
               const std::string& path = "/",
               const Options& options = Options(),
               std::chrono::milliseconds timeoutMs = std::chrono::milliseconds(10000))
  {
    // Reap-then-respawn (coalescing_C). Step boundaries are explicit so
    // _transportMutex is NEVER held across the old-worker join.
    // (1) under the lock: copy the old control block + move the worker out.
    std::shared_ptr<ReconnectControl> oldRc;
    std::thread reap;
    {
      std::lock_guard<std::mutex> lk(_transportMutex);
      oldRc = _rc;
      reap = std::move(_reconnectWorker);
    }
    // (2)(3) signal the OLD block to exit BEFORE joining (so a CV-idle worker
    //        wakes and exits, and an in-flight worker observes shouldRun==false
    //        at its publish gate and abandons).
    if (oldRc)
    {
      {
        std::lock_guard<std::mutex> lk(oldRc->m);
        oldRc->shouldRun.store(false);
      }
      oldRc->cv.notify_one();
      // Wake an old worker parked in the handshake-settle wait (_connectCv, not
      // oldRc->cv) so the join below is prompt, not bounded by
      // kHandshakeSettleTimeout (H-3). The empty _connectMutex critical section
      // before notify closes the lost-wakeup window (H-3-R2): it forces this
      // notify to be ordered AFTER a racing worker has either re-read shouldRun
      // (set above) or fully blocked on _connectCv. No lock held here (oldRc->m
      // scope closed), so it nests nothing.
      {
        std::lock_guard<std::mutex> lk(_connectMutex);
      }
      _connectCv.notify_all();
    }
    // (4) join the moved-out worker OUTSIDE any lock.
    if (reap.joinable())
    {
      reap.join();
    }

    // Tear down any existing transport before reconfiguring (user thread, so
    // stop() runs). No-op on the first connect().
    teardownTransport(/*gracefulClose=*/true);

    // (5) the old worker is gone — safe to (re)assign the connection params.
    _host = host;
    _port = port;
    _path = path;
    _options = options;

    // (6) fresh control block for this connect cycle.
    {
      std::lock_guard<std::mutex> lk(_transportMutex);
      _rc = std::make_shared<ReconnectControl>();
    }

    // (7) initial attempt on the calling thread. doConnect's bool return is
    //     intentionally not consulted (H-2): every failure path inside doConnect
    //     calls setState(DISCONNECTED) first, which the _connectCv predicate at
    //     step (9) observes — the CV-settled _state is the authoritative result,
    //     and a failed initial connect is reaped via the !connected branch below.
    std::shared_ptr<ReconnectControl> rc;
    {
      std::lock_guard<std::mutex> lk(_transportMutex);
      rc = _rc;
    }
    doConnect(rc);

    // (8) spawn the long-lived reconnect worker (capturing weak_from_this() +
    //     the fresh control block) when auto-reconnect is enabled.
    if (_options.autoReconnect)
    {
      std::weak_ptr<WebSocketClient> weak = weak_from_this();
      std::lock_guard<std::mutex> lk(_transportMutex);
      _reconnectWorker = std::thread(&WebSocketClient::reconnectWorkerLoop, weak, rc);
    }

    // (9) block until the handshake settles or times out. _connectMutex is
    //     released before any teardown (it must not be held across stop()).
    bool connected;
    {
      std::unique_lock<std::mutex> lock(_connectMutex);
      _connectCv.wait_for(lock, timeoutMs, [this]()
      {
        auto s = _state.load();
        return s == WebSocketState::CONNECTED || s == WebSocketState::DISCONNECTED
            || s == WebSocketState::CLOSED;
      });
      connected = (_state.load() == WebSocketState::CONNECTED);
    }

    if (!connected)
    {
      // Timeout or failure — clean up (the worker may be mid-attempt). No lock
      // held here.
      reapWorker(/*isDtor=*/false);
      teardownTransport(/*gracefulClose=*/false);
      setState(WebSocketState::DISCONNECTED);
      return false;
    }
    return _state.load() == WebSocketState::CONNECTED;
  }

  /// \brief Disconnect gracefully (close handshake). Safe to call from any
  /// thread (user / I/O / worker). Reaps the worker (skipping the join when on
  /// the I/O or worker thread — the dtor/connect() reap it later) then tears the
  /// transport down with a best-effort CLOSE frame.
  void disconnect(std::uint16_t code = 1000, const std::string& reason = "")
  {
    reapWorker(/*isDtor=*/false);
    teardownTransport(/*gracefulClose=*/true, code, reason);
    setState(WebSocketState::CLOSED);
  }

  // ── Send ───────────────────────────────────────────────────────────────
  //
  // The `_state == CONNECTED` early-out in each send method is ADVISORY (a cheap
  // non-synchronizing fast-path). The AUTHORITATIVE gate is the {_transport,
  // _sessionId} snapshot taken under _transportMutex in sendRawBytes(): if a
  // reconnect tears the transport down between the state check and the snapshot,
  // sendRawBytes sees a null transport / zero session and no-ops — there is no
  // torn send. So the state-check-then-act here is not a TOCTOU bug.

  void sendText(const std::string& text)
  {
    if (_state.load() != WebSocketState::CONNECTED) return;
    auto frame = WebSocketFrame::makeText(text);
    generateMaskKey(frame.maskKey);
    auto wire = frame.serialize(true); // client MUST mask
    sendRawBytes(wire.data(), wire.size());
  }

  void sendBinary(const std::vector<std::uint8_t>& data)
  {
    if (_state.load() != WebSocketState::CONNECTED) return;
    auto frame = WebSocketFrame::makeBinary(data);
    generateMaskKey(frame.maskKey);
    auto wire = frame.serialize(true);
    sendRawBytes(wire.data(), wire.size());
  }

  void sendPing(const std::vector<std::uint8_t>& payload = {})
  {
    if (_state.load() != WebSocketState::CONNECTED) return;
    auto frame = WebSocketFrame::makePing(payload);
    generateMaskKey(frame.maskKey);
    auto wire = frame.serialize(true);
    sendRawBytes(wire.data(), wire.size());
  }

  void sendClose(std::uint16_t code = 1000, const std::string& reason = "")
  {
    // Intentionally NO _state==CONNECTED advisory early-out (unlike sendText/etc.):
    // a CLOSE must be attempt-able during CLOSED/teardown. The authoritative gate
    // is still the {_transport,_sessionId} snapshot in sendRawBytes() — a null
    // transport no-ops, so this is safe to call from any state.
    auto frame = WebSocketFrame::makeClose(code, reason);
    generateMaskKey(frame.maskKey);
    auto wire = frame.serialize(true);
    sendRawBytes(wire.data(), wire.size());
  }

  // ── State ──────────────────────────────────────────────────────────────

  WebSocketState getState() const { return _state.load(); }
  std::string negotiatedProtocol() const
  {
    std::lock_guard<std::mutex> lock(_dataMutex);
    return _negotiatedProtocol;
  }

private:
  /// \brief Heap control block for the reconnect worker, co-owned by the worker's
  /// strong _rc copy so the CV/mutex outlive the client on the detach path.
  /// `clientAlive` is intentionally absent — weak.lock() subsumes it (it fuses
  /// liveness with lifetime extension, with no TOCTOU). `shouldRun` is retained
  /// because weak expiry does NOT wake a CV-blocked worker: disconnect()/dtor must
  /// set shouldRun=false + notify so the idle worker re-evaluates and exits.
  struct ReconnectControl
  {
    std::mutex m;                      // LEAF lock — never held across
                                       // stop()/reset()/doConnect()/weak.lock();
                                       // released before _transportMutex is taken.
    std::condition_variable cv;
    bool requested = false;            // guarded by m
    // shouldRun is std::atomic so the worker reads it lock-free in the post-wake
    // exit check; it is WRITTEN under m to pair with the notify (no lost wakeup —
    // lost_wakeup_ordering_M1). Default seq_cst is acceptable on this COLD
    // reconnect-teardown path: the m-guarded store + lock-free load establishes
    // the needed happens-before, and m provides the ordering for `requested`.
    std::atomic<bool> shouldRun{true};
  };

  // Upper bound a reconnect attempt waits for the upgrade handshake to settle
  // (CONNECTED / DISCONNECTED / CLOSED) before treating the attempt as failed.
  static constexpr std::chrono::milliseconds kHandshakeSettleTimeout{10000};

  /// \brief The reconnect worker loop. Static (captures NO raw this): it holds a
  /// weak_ptr<WebSocketClient> and a STRONG shared_ptr<ReconnectControl>, and
  /// promotes `self` per attempt. MANDATORY ORDER (F-C4 — headline invariant):
  /// wait on the rc-only predicate -> unlock -> check shouldRun -> weak.lock()
  /// GATE -> only after a non-null self touch ANY self-> member.
  static void reconnectWorkerLoop(std::weak_ptr<WebSocketClient> weak,
                                  std::shared_ptr<ReconnectControl> rc)
  {
    // Backoff state. freshCycle == true means "start backoff from initial" (a new
    // disconnect after a successful connect); a failed attempt keeps backing off.
    bool freshCycle = true;
    std::chrono::milliseconds delay{0};

    for (;;)
    {
      {
        std::unique_lock<std::mutex> lk(rc->m);
        // Level-triggered predicate (rc-only): a requestReconnect() that set
        // `requested` before the worker first reached wait() is observed on the
        // FIRST evaluation (no edge assumption, no lost wakeup).
        rc->cv.wait(lk, [&rc]() { return rc->requested || !rc->shouldRun.load(); });
        rc->requested = false;
      }
      if (!rc->shouldRun.load()) return;

      // weak.lock() GATE — lock-free, never under rc->m. Promote BEFORE touching
      // any self-> member (including the _options backoff read).
      auto self = weak.lock();
      if (!self) return;

      if (freshCycle)
      {
        delay = self->_options.initialReconnectDelay;
        freshCycle = false;
      }

      // Interruptible backoff sleep — `self` pins the client through the sleep,
      // so the client cannot be destroyed mid-sleep; it is released at the loop
      // bottom (between attempts) so a last-ref drop then lets the next
      // weak.lock() return null and the worker exit.
      {
        std::unique_lock<std::mutex> lk(rc->m);
        rc->cv.wait_for(lk, delay, [&rc]() { return !rc->shouldRun.load(); });
      }
      if (!rc->shouldRun.load()) return;

      const bool connected = self->reconnectAttempt(rc);
      if (connected)
      {
        freshCycle = true; // reset backoff for the next disconnect cycle
        continue;          // `self` released here -> client destroyable while idle
      }

      // Failure: exponential backoff, then re-arm to retry without an external
      // request (WORKER-INTERNAL RETRY — set `requested` on the captured rc
      // directly; only I/O-thread callbacks call requestReconnect()).
      delay = std::min(delay * 2, self->_options.maxReconnectDelay);
      {
        std::lock_guard<std::mutex> lk(rc->m);
        rc->requested = true;
      }
      // `self` released at the loop bottom; re-promoted next iteration.
    }
  }

  /// \brief One reconnect attempt: tear down the prior transport, build+publish a
  /// fresh one, send the upgrade, and wait for the handshake to settle. Always
  /// runs on the worker thread (so stop() inside teardownTransport runs). The
  /// caller (reconnectWorkerLoop) holds the promoted `self` across this whole
  /// call, so the client cannot be destroyed mid-attempt (invariants 4 & 13).
  bool reconnectAttempt(const std::shared_ptr<ReconnectControl>& rc)
  {
    teardownTransport(/*gracefulClose=*/false);
    if (!rc->shouldRun.load()) return false;
    if (!doConnect(rc)) return false;

    // Wait for the upgrade response to settle the state. _connectMutex is NOT
    // held across any stop()/teardown. The predicate ALSO observes
    // rc->shouldRun: a concurrent disconnect()/dtor/connect() clears shouldRun
    // and notifies _connectCv (see reapWorker / connect() reap), so this wait is
    // interruptible — it does not block the closer for the full
    // kHandshakeSettleTimeout against a half-open server that accepts TCP but
    // never sends the 101 (H-3).
    {
      std::unique_lock<std::mutex> lock(_connectMutex);
      _connectCv.wait_for(lock, kHandshakeSettleTimeout, [this, &rc]()
      {
        auto s = _state.load();
        return s == WebSocketState::CONNECTED || s == WebSocketState::DISCONNECTED
            || s == WebSocketState::CLOSED || !rc->shouldRun.load();
      });
    }
    if (!rc->shouldRun.load()) return false;
    return _state.load() == WebSocketState::CONNECTED;
  }

  /// \brief Build a fresh transport into a LOCAL, register weak-promoted
  /// callbacks on it, start+connect, PUBLISH the (transport,sessionId) pair under
  /// _transportMutex (re-checking shouldRun inside the critical section — the
  /// publish gate), then send the upgrade request. Returns true if the upgrade
  /// was sent (the handshake then completes asynchronously via onData); false on
  /// any failure or if the publish was abandoned. \param rc the control block
  /// whose shouldRun arms the publish gate (resurrect-after-disconnect guard).
  ///
  /// THREAD CONTEXT (invariant 14 reconciliation): doConnect runs ONLY on the
  /// connect() user thread (initial attempt) or the reconnect WORKER thread —
  /// NEVER the engine I/O thread (t->sendSync below blocks the caller on the I/O
  /// thread, so the caller cannot be it). The published member is a COPY of the
  /// local `t`, so the local co-owns the transport until this function returns;
  /// that is safe because the local always drops off the I/O thread, so it can
  /// never be the I/O-thread last-ref drop that the loop-termination path
  /// (~Transport deferred-self-destruct) depends on — that last-ref drop only
  /// ever happens in teardownTransport via the member reset.
  bool doConnect(const std::shared_ptr<ReconnectControl>& rc)
  {
    setState(WebSocketState::CONNECTING);

    TransportConfig config;
    config.protocol = Protocol::TCP;
    config.enableTcpNoDelay = true;

    auto t = Transport::tcp(config); // WS is TCP; build into a LOCAL (S-3 publish)

    // The prior teardownTransport (in reconnectAttempt / connect()) stopped+joined
    // any old transport's I/O thread BEFORE this runs, so no concurrent I/O-thread
    // reader of these buffers/flags exists when they are reset here (M-4).
    {
      std::lock_guard<std::mutex> lock(_dataMutex);
      _buffer.clear();
      _fragmentBuffer.clear();
      _fragmentOpcode = WsOpcode::CONTINUATION;
    }
    _upgradeComplete.store(false);
    _closeEchoed.store(false); // re-arm the one-shot CLOSE echo for this connection

    // Register the global callbacks on the LOCAL transport. Each weak-captures
    // the client (NEVER an owning shared_ptr<Transport> of its own _transport —
    // the reference-cycle invariant) and promotes `self` before any member
    // access; weak_from_this() is captured here (post-construction), never in the
    // ctor.
    std::weak_ptr<WebSocketClient> weak = weak_from_this();

    t->onData(
      [weak](SessionId s, iora::core::BufferView data,
             std::chrono::steady_clock::time_point)
      {
        auto self = weak.lock();
        if (!self) return;
        // Record the I/O thread id FIRST (before any user callback it may
        // transitively invoke) so teardown/reap can gate stop()/join off it.
        self->_ioThreadId.store(std::this_thread::get_id(),
                                std::memory_order_relaxed);
        self->handleData(s, data.data(), data.size());
      });

    t->onClose(
      [weak](SessionId, const TransportErrorInfo&)
      {
        auto self = weak.lock();
        if (!self) return;
        self->_ioThreadId.store(std::this_thread::get_id(),
                                std::memory_order_relaxed);
        self->handleDisconnect();
      });

    t->onError(
      [weak](TransportError, const std::string& message)
      {
        auto self = weak.lock();
        if (!self) return;
        self->_ioThreadId.store(std::this_thread::get_id(),
                                std::memory_order_relaxed);
        if (self->_onError) self->_onError(message);
      });

    if (t->start().isErr())
    {
      setState(WebSocketState::DISCONNECTED);
      if (_onError) _onError("Failed to start transport");
      try { t->stop(); } catch (...) {} // worker/connect thread (not I/O) -> safe
      return false;
    }

    auto connectResult = t->connect(_host, _port, _options.tlsMode);
    if (connectResult.isErr())
    {
      setState(WebSocketState::DISCONNECTED);
      if (_onError)
        _onError("Failed to connect to " + _host + ":" + std::to_string(_port));
      try { t->stop(); } catch (...) {}
      return false;
    }
    SessionId sid = connectResult.value();

    // PUBLISH the (transport,sessionId) pair in ONE critical section, gated on
    // shouldRun: if a concurrent disconnect()/dtor cleared shouldRun, ABANDON the
    // publish (resurrect-after-disconnect guard — publish gate, invariant 15).
    bool published = false;
    {
      std::lock_guard<std::mutex> lock(_transportMutex);
      if (!rc || rc->shouldRun.load())
      {
        _transport = t;
        _sessionId = sid;
        published = true;
      }
    }
    if (!published)
    {
      try { t->stop(); } catch (...) {} // tear down the just-built local OUTSIDE the lock
      return false;
    }

    // Send the upgrade request synchronously (sendSync blocks until sent). The
    // server's 101 — which triggers the _wsKey read in handleData — cannot arrive
    // before this send completes, so _wsKey is published-before-read via the
    // round-trip (companion_wsKey_L1NEW: documented-serialized, no lock needed).
    auto upgradeReq = buildUpgradeRequest();
    auto result = t->sendSync(
      sid,
      iora::core::BufferView{reinterpret_cast<const std::uint8_t*>(upgradeReq.data()),
                             upgradeReq.size()},
      std::chrono::milliseconds(5000));

    if (result.isErr())
    {
      setState(WebSocketState::DISCONNECTED);
      if (_onError) _onError("Failed to send upgrade: " + result.error().message);
      teardownTransport(/*gracefulClose=*/false); // clears the published member
      return false;
    }

    // Data is already flowing via the global onData callback set before start.
    return true;
  }

  std::string buildUpgradeRequest()
  {
    // Generate random 16-byte key, Base64 encode. _wsKey is read by handleData()
    // on the I/O thread; the synchronous upgrade round-trip establishes the
    // happens-before (the 101 cannot precede this send) — documented-serialized.
    std::uint8_t keyBytes[16];
    crypto::SecureRng::fill(keyBytes, sizeof(keyBytes));
    _wsKey = util::Base64::encode(keyBytes, sizeof(keyBytes));

    std::ostringstream req;
    req << "GET " << _path << " HTTP/1.1\r\n";
    req << "Host: " << _host << ":" << _port << "\r\n";
    req << "Upgrade: websocket\r\n";
    req << "Connection: Upgrade\r\n";
    req << "Sec-WebSocket-Key: " << _wsKey << "\r\n";
    req << "Sec-WebSocket-Version: 13\r\n";

    if (!_options.subprotocols.empty())
    {
      req << "Sec-WebSocket-Protocol: ";
      for (std::size_t i = 0; i < _options.subprotocols.size(); ++i)
      {
        if (i > 0) req << ", ";
        req << _options.subprotocols[i];
      }
      req << "\r\n";
    }

    // Custom headers
    for (const auto& [key, value] : _options.headers)
    {
      req << key << ": " << value << "\r\n";
    }

    req << "\r\n";
    return req.str();
  }

  void handleData(SessionId, const std::uint8_t* data, std::size_t len)
  {
    // Move-parse-callback pattern: buffer ops under lock, callbacks outside.
    // Same pattern as server's onUpgradedData to avoid deadlock.

    // Step 1: append data and move buffer out under lock
    std::vector<std::uint8_t> localBuffer;
    {
      std::lock_guard<std::mutex> lock(_dataMutex);
      _buffer.insert(_buffer.end(), data, data + len);
      localBuffer = std::move(_buffer);
      _buffer.clear();
    }

    // Step 2: Parse HTTP upgrade response (if not yet completed)
    if (!_upgradeComplete.load())
    {
      std::string response(localBuffer.begin(), localBuffer.end());
      auto headerEnd = response.find("\r\n\r\n");
      if (headerEnd == std::string::npos)
      {
        // Incomplete — put back
        std::lock_guard<std::mutex> lock(_dataMutex);
        _buffer.insert(_buffer.begin(), localBuffer.begin(), localBuffer.end());
        return;
      }

      // The 101 status must be on the STATUS LINE (response must START with it),
      // not merely appear somewhere in the response body/headers.
      if (response.rfind("HTTP/1.1 101", 0) != 0)
      {
        setState(WebSocketState::DISCONNECTED);
        // Report the status line only (avoid splicing binary/partial frame bytes).
        if (_onError)
          _onError("Upgrade failed: " + response.substr(0, response.find("\r\n")));
        return;
      }

      static const std::string kGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
      unsigned char sha1Out[20];
      // _wsKey read: serialized with its write by the upgrade round-trip.
      crypto::SecureRng::sha1(_wsKey + kGuid, sha1Out);
      std::string expectedAccept = util::Base64::encode(sha1Out, 20);

      // Compare against the trimmed Sec-WebSocket-Accept HEADER VALUE (within the
      // header section), not a substring match over the whole response.
      static const std::string kAcceptHdr = "Sec-WebSocket-Accept:";
      std::string acceptValue;
      auto acceptPos = response.find(kAcceptHdr);
      if (acceptPos != std::string::npos && acceptPos < headerEnd)
      {
        auto valStart = acceptPos + kAcceptHdr.size();
        auto valEnd = response.find("\r\n", valStart);
        if (valEnd == std::string::npos) valEnd = headerEnd; // defensive (always found)
        acceptValue = response.substr(valStart, valEnd - valStart);
        auto b = acceptValue.find_first_not_of(" \t");
        auto e = acceptValue.find_last_not_of(" \t");
        acceptValue = (b == std::string::npos)
                        ? std::string()
                        : acceptValue.substr(b, e - b + 1);
      }
      if (acceptValue != expectedAccept)
      {
        setState(WebSocketState::DISCONNECTED);
        if (_onError) _onError("Invalid Sec-WebSocket-Accept");
        return;
      }

      // Extract negotiated subprotocol — scoped to the header section (the
      // receive buffer may concatenate post-handshake frame bytes that contain
      // this ASCII run) and compared as a trimmed header value, like the Accept
      // header above (not a whole-response substring).
      std::string proto;
      static const std::string kProtoHdr = "Sec-WebSocket-Protocol:";
      auto protoPos = response.find(kProtoHdr);
      if (protoPos != std::string::npos && protoPos < headerEnd)
      {
        auto valStart = protoPos + kProtoHdr.size();
        auto valEnd = response.find("\r\n", valStart);
        if (valEnd == std::string::npos) valEnd = headerEnd; // defensive (always found)
        proto = response.substr(valStart, valEnd - valStart);
        auto b = proto.find_first_not_of(" \t");
        auto e = proto.find_last_not_of(" \t");
        proto = (b == std::string::npos) ? std::string() : proto.substr(b, e - b + 1);
      }

      {
        std::lock_guard<std::mutex> lock(_dataMutex);
        _negotiatedProtocol = proto;
      }

      _upgradeComplete.store(true);
      setState(WebSocketState::CONNECTED);

      // Callback outside lock
      if (_onConnect)
      {
        _onConnect(proto);
      }

      // Remove HTTP response, keep remaining WebSocket data
      localBuffer.erase(localBuffer.begin(),
                        localBuffer.begin() + headerEnd + 4);
    }

    // Step 3: Parse WebSocket frames (outside lock)
    std::size_t offset = 0;
    while (offset < localBuffer.size())
    {
      core::BufferView view(localBuffer.data() + offset,
                            localBuffer.size() - offset);
      std::size_t consumed = 0;
      auto frame = WebSocketFrame::parse(view, consumed);
      if (!frame) break;
      offset += consumed;

      // handleFrame fires callbacks — must be outside lock
      handleFrame(*frame);
    }

    // Step 4: Put unconsumed remainder back under lock
    if (offset < localBuffer.size())
    {
      std::lock_guard<std::mutex> lock(_dataMutex);
      std::vector<std::uint8_t> remainder(
        localBuffer.begin() + offset, localBuffer.end());
      remainder.insert(remainder.end(), _buffer.begin(), _buffer.end());
      _buffer = std::move(remainder);
    }
  }

  void handleFrame(const WebSocketFrame& frame)
  {
    switch (frame.opcode)
    {
    case WsOpcode::TEXT:
    case WsOpcode::BINARY:
    case WsOpcode::CONTINUATION:
    {
      handleDataFrame(frame);
      break;
    }
    case WsOpcode::PING:
    {
      // Auto-respond with Pong (masked)
      auto pong = WebSocketFrame::makePong(frame.payload);
      generateMaskKey(pong.maskKey);
      auto wire = pong.serialize(true);
      sendRawBytes(wire.data(), wire.size());
      break;
    }
    case WsOpcode::PONG:
    {
      // No-op
      break;
    }
    case WsOpcode::CLOSE:
    {
      auto [code, reason] = frame.closePayload();

      // Echo the CLOSE frame back per RFC 6455 §5.5.1 EXACTLY ONCE. A one-shot
      // atomic CAS is the authoritative gate (M-2): the prior `_state != CLOSING`
      // check was dead (CLOSING is never stored), so a peer that sent two CLOSE
      // frames in one TCP segment would have been echoed twice. _closeEchoed is
      // reset per connection in doConnect().
      if (!_closeEchoed.exchange(true))
      {
        sendClose(code, reason);
      }

      setState(WebSocketState::CLOSED);
      if (_onClose)
      {
        _onClose(code, reason);
      }
      break;
    }
    default:
      break;
    }
  }

  void handleDataFrame(const WebSocketFrame& frame)
  {
    bool isStart = (frame.opcode == WsOpcode::TEXT || frame.opcode == WsOpcode::BINARY);
    bool isCont = (frame.opcode == WsOpcode::CONTINUATION);

    // Mutate the fragment-reassembly state under _dataMutex (it is also cleared by
    // doConnect() on the connect/worker thread); move the completed payload out
    // and release the lock BEFORE invoking the user callback (copy-then-invoke).
    WsOpcode opcode = WsOpcode::CONTINUATION;
    std::vector<std::uint8_t> payload;
    bool deliver = false;
    {
      std::lock_guard<std::mutex> lock(_dataMutex);
      if (isStart)
      {
        _fragmentOpcode = frame.opcode;
        _fragmentBuffer = frame.payload;
      }
      else if (isCont)
      {
        _fragmentBuffer.insert(_fragmentBuffer.end(),
                               frame.payload.begin(), frame.payload.end());
      }

      if (frame.fin)
      {
        opcode = _fragmentOpcode;
        payload = std::move(_fragmentBuffer);
        _fragmentBuffer.clear();
        _fragmentOpcode = WsOpcode::CONTINUATION;
        deliver = true;
      }
    }

    if (deliver)
    {
      if (opcode == WsOpcode::TEXT)
      {
        if (_onTextMessage)
        {
          std::string text(payload.begin(), payload.end());
          _onTextMessage(text);
        }
      }
      else if (opcode == WsOpcode::BINARY)
      {
        if (_onBinaryMessage)
        {
          _onBinaryMessage(payload);
        }
      }
    }
  }

  /// \brief Transport onClose handler — runs on the I/O thread (with `self`
  /// already promoted by the onClose lambda). Signals the reconnect worker; never
  /// joins or tears down on the I/O thread.
  void handleDisconnect()
  {
    auto prevState = _state.load();
    // CLOSED means we already initiated/completed a close: a subsequent transport
    // drop must NOT trigger auto-reconnect. (WebSocketState::CLOSING is a reserved
    // enumerator that is never stored, so it is not tested here — see L-3.)
    if (prevState == WebSocketState::CLOSED)
    {
      setState(WebSocketState::CLOSED);
      return;
    }

    setState(WebSocketState::DISCONNECTED);
    // _options is read lock-free here on the I/O thread (M-3). It is written only
    // by connect() (single-controller), which first tears down + stop()+joins the
    // OLD transport's I/O thread before rewriting _options — so the old I/O thread
    // that runs this handler has finished before any rewrite. The new connection's
    // I/O thread is spawned after the write, giving the happens-before. This read
    // is therefore race-free under the single-controller connect() precondition.
    if (_options.autoReconnect)
    {
      requestReconnect();
    }
  }

  /// \brief Non-blocking reconnect signal — called ONLY from I/O-thread transport
  /// callbacks (which have already promoted `self`). Reads _rc under
  /// _transportMutex (AP-16), sets `requested` under rc->m before notify (no lost
  /// wakeup); _transportMutex is released before rc->m is taken (never nested).
  void requestReconnect()
  {
    std::shared_ptr<ReconnectControl> rc;
    {
      std::lock_guard<std::mutex> lk(_transportMutex);
      rc = _rc;
    }
    if (rc)
    {
      {
        std::lock_guard<std::mutex> lk(rc->m);
        rc->requested = true;
      }
      rc->cv.notify_one();
    }
  }

  /// \brief The single teardown path for the transport. noexcept (a throw out of
  /// a noexcept dtor/teardown = std::terminate). Snapshots+clears
  /// (_transport,_sessionId) and resets _ioThreadId under _transportMutex, then
  /// OUTSIDE the lock: optional CLOSE frame, enqueue-only close(sid) (safe on the
  /// I/O thread), and stop() ONLY when NOT on the I/O thread. On the I/O thread
  /// stop() is SKIPPED UNCONDITIONALLY — the loop terminator is the last-ref drop
  /// of the snapshot `t` (-> ~Transport deferred-self-destruct), not stop().
  ///
  /// LEGAL I/O-thread entry points: ONLY the dispatched transport callbacks
  /// onClose (handleDisconnect) and onError, whose frames sit on the loop's
  /// event-processing stack so `while(_running)` re-checks on unwind without a
  /// fresh epoll wakeup. A future I/O-thread path that drops the last Transport
  /// ref OUTSIDE callback dispatch would leave the loop blocked in epoll_wait —
  /// catch it in review.
  void teardownTransport(bool gracefulClose, std::uint16_t code = 1000,
                         const std::string& reason = "") noexcept
  {
    try
    {
      std::shared_ptr<Transport> t;
      SessionId sid = 0;
      bool onIo = false;
      {
        std::lock_guard<std::mutex> lock(_transportMutex);
        // Capture onIo INSIDE the lock (before the reset below) so the read is
        // ordered against any prior teardown's _ioThreadId reset by the same
        // mutex — closes the recycled-id window without relying on an incidental
        // caller-side acquisition. Symmetric with the reap gate in reapWorker.
        onIo = (std::this_thread::get_id() ==
                _ioThreadId.load(std::memory_order_relaxed));
        t = _transport;
        sid = _sessionId;
        _transport.reset();
        _sessionId = 0;
        // Reset so the reap gate cannot match a recycled thread id from a
        // destroyed engine (each reconnect builds a fresh I/O thread).
        _ioThreadId.store(std::thread::id{}, std::memory_order_relaxed);
      }
      if (!t) return;

      // Best-effort CLOSE frame, then the transport-level close, then (off-IO)
      // stop(). ORDER: CLOSE frame enqueue BEFORE close(sid) so the FIN follows
      // the close-frame enqueue. The _state read here is a best-effort advisory
      // (L-2): a stale value at worst sends/skips a courtesy CLOSE frame — the
      // transport teardown below is unconditional and authoritative.
      if (gracefulClose && _state.load() == WebSocketState::CONNECTED && sid != 0)
      {
        auto frame = WebSocketFrame::makeClose(code, reason);
        generateMaskKey(frame.maskKey);
        auto wire = frame.serialize(true);
        auto shared = std::make_shared<std::vector<std::uint8_t>>(std::move(wire));
        t->sendAsync(sid, shared->data(), shared->size(),
                     [shared](SessionId, const SendResult&) {});
      }
      if (sid != 0)
      {
        t->close(sid); // enqueue-only — SAFE on the I/O thread
      }
      if (!onIo)
      {
        try { t->stop(); } catch (...) {}
      }
      // Drop `t` here: on the I/O thread this is the last Transport ref ->
      // ~Transport deferred-self-destruct terminates the loop on unwind.
    }
    catch (...)
    {
    }
  }

  /// \brief Signal-then-reap the worker. noexcept. SIGNAL-BEFORE-GATE is
  /// load-bearing (invariant 18): shouldRun=false + notify happens BEFORE the
  /// onIo/onWorker gate, so an in-flight worker observes shouldRun==false at its
  /// publish gate and abandons even when the join is SKIPPED. Reap is gated off
  /// the I/O AND worker threads (deadlock/terminate avoidance): join when safe,
  /// detach (never abort) on those threads when isDtor (so the std::thread member
  /// is non-joinable before its implicit dtor); a non-dtor caller on those
  /// threads leaves the worker for connect()/the dtor to reap.
  void reapWorker(bool isDtor) noexcept
  {
    try
    {
      // (1) SIGNAL exit FIRST (arms the publish gate even if the join is skipped).
      std::shared_ptr<ReconnectControl> rc;
      {
        std::lock_guard<std::mutex> lk(_transportMutex);
        rc = _rc;
      }
      if (rc)
      {
        {
          std::lock_guard<std::mutex> lk(rc->m);
          rc->shouldRun.store(false);
        }
        rc->cv.notify_one();
      }
      // Also wake a worker parked in reconnectAttempt's handshake-settle wait
      // (it blocks on _connectCv, NOT rc->cv) so the join below cannot stall for
      // kHandshakeSettleTimeout against a half-open server (H-3). The settle-wait
      // predicate reads rc->shouldRun (cleared above, under rc->m), but the wait
      // blocks on _connectMutex. Since shouldRun is published BEFORE the empty
      // _connectMutex critical section below, that empty CS is sufficient to
      // close the lost-wakeup window (H-3-R2): it orders this notify either
      // before the waiter's predicate re-check (it then reads shouldRun==false
      // and never blocks) or after the waiter is fully blocked (notify
      // delivered). Holding _connectMutex ACROSS the notify is not required (and
      // would only force the woken worker to re-block on it). No lock is held
      // here (the _transportMutex and rc->m scopes above have closed).
      {
        std::lock_guard<std::mutex> lk(_connectMutex);
      }
      _connectCv.notify_all();

      // (2) Reap, gated off the I/O and worker threads.
      std::thread reap;
      {
        std::lock_guard<std::mutex> lk(_transportMutex);
        const auto thisId = std::this_thread::get_id();
        const bool onIo = (thisId == _ioThreadId.load(std::memory_order_relaxed));
        const auto workerId = _reconnectWorker.get_id();
        const bool onWorker =
          (workerId != std::thread::id{} && thisId == workerId);
        if (!onIo && !onWorker)
        {
          reap = std::move(_reconnectWorker); // join OUTSIDE the lock
        }
        else if (isDtor && _reconnectWorker.joinable())
        {
          // Well-defined; never abort. The detached idle worker is UAF-free via
          // the immortal control block + weak.lock().
          _reconnectWorker.detach();
        }
      }
      if (reap.joinable())
      {
        reap.join();
      }
    }
    catch (...)
    {
    }
  }

  void sendRawBytes(const std::uint8_t* data, std::size_t len)
  {
    // Copy-then-invoke: snapshot the (transport,sessionId) pair under the lock as
    // a consistent unit, deref OUTSIDE the lock.
    std::shared_ptr<Transport> t;
    SessionId sid = 0;
    {
      std::lock_guard<std::mutex> lock(_transportMutex);
      t = _transport;
      sid = _sessionId;
    }
    if (t && sid != 0)
    {
      auto shared = std::make_shared<std::vector<std::uint8_t>>(data, data + len);
      t->sendAsync(sid, shared->data(), shared->size(),
                   [shared](SessionId, const SendResult&) {});
    }
  }

  void generateMaskKey(std::uint8_t key[4])
  {
    crypto::SecureRng::fill(key, 4);
  }

  void setState(WebSocketState newState)
  {
    // Store under _connectMutex to pair with the CV notify (no lost wakeup for a
    // blocked connect()/reconnectAttempt waiter). setState is NEVER called while
    // _connectMutex is already held by the same thread (connect()/reconnectAttempt
    // release it before any path that re-enters setState).
    {
      std::lock_guard<std::mutex> lk(_connectMutex);
      _state.store(newState);
    }
    _connectCv.notify_all();

    if (_onStateChange)
    {
      _onStateChange(newState);
    }
  }

  // ── Members ──────────────────────────────────────────────────────────────

  // Connection params — (re)assigned by connect() AFTER the old worker is reaped
  // and the old transport is torn down, then stable for the whole connect cycle
  // (read by doConnect()/the worker without a lock; publish discipline relies on
  // connect() being called from a single user thread, never concurrently).
  std::string _host;
  std::uint16_t _port = 0;
  std::string _path;
  Options _options;

  // Transport member group — guarded as a unit by _transportMutex (AP-16). esft
  // makes the OWNER shared; it does NOT make a concurrently read-vs-reassign
  // shared_ptr/std::thread MEMBER safe — that is what this mutex is for. The two
  // dimensions are orthogonal and both required.
  std::mutex _transportMutex; // LEAF lock — never held across
                              // stop()/close()/sendAsync()/reset()/doConnect()/rc->m/
                              // join()/weak.lock(); copy-then-invoke for reads,
                              // move-out-then-join-outside-lock for the worker thread.
  std::shared_ptr<Transport> _transport;
  SessionId _sessionId; // plain SessionId (mutex-guarded), NOT atomic — read
                        // together with _transport as a consistent pair (the id is
                        // REUSED across reconnects, so a torn pair is unsafe).
  std::shared_ptr<ReconnectControl> _rc; // the control-block handle (this member)
  std::thread _reconnectWorker;          // the single long-lived reconnect worker
  std::atomic<std::thread::id> _ioThreadId{std::thread::id{}}; // set first in each
                              // I/O callback; reset to id{} in teardownTransport.
                              // Accessed with memory_order_relaxed: it is a pure
                              // IDENTITY token (an equality probe "am I the I/O
                              // thread?"), not a publication channel — no other
                              // data is ordered through it (self's happens-before
                              // comes from weak.lock()). The only correctness-
                              // critical read (teardown/reap running ON the I/O
                              // thread, avoiding a self-join) is satisfied by
                              // same-thread program order: the callback stores the
                              // id as its first statement, sequenced-before the
                              // teardown/reap call on that same thread. A cross-
                              // thread read can only ever yield onIo=false (a
                              // different thread's id never matches), which is the
                              // correct answer. The id{} reset (under
                              // _transportMutex) closes the recycled-id window.

  // State
  std::atomic<WebSocketState> _state;
  std::string _wsKey; // documented-serialized via the synchronous upgrade
                      // round-trip (write in buildUpgradeRequest, read in handleData).
  std::string _negotiatedProtocol; // _dataMutex

  // Receive buffer (protected by _dataMutex)
  mutable std::mutex _dataMutex; // LEAF lock — independent of _transportMutex/rc->m.
  std::vector<std::uint8_t> _buffer;
  std::atomic<bool> _upgradeComplete{false};
  // One-shot CLOSE-echo gate (M-2): set via exchange(true) the first time a peer
  // CLOSE is echoed, re-armed in doConnect() per connection. Replaces the dead
  // _state==CLOSING guard (CLOSING is never stored — it is a reserved state).
  std::atomic<bool> _closeEchoed{false};

  // Fragment reassembly (protected by _dataMutex)
  std::vector<std::uint8_t> _fragmentBuffer;
  WsOpcode _fragmentOpcode = WsOpcode::CONTINUATION;

  // Connect-handshake synchronization. NOT one of the leaf group locks; released
  // before any stop()/teardown (never held across them).
  std::mutex _connectMutex;
  std::condition_variable _connectCv;

  // Callbacks (set before connect(); user callbacks MUST weak-capture — HR-11).
  ConnectCallback _onConnect;
  TextCallback _onTextMessage;
  BinaryCallback _onBinaryMessage;
  CloseCallback _onClose;
  ErrorCallback _onError;
  StateCallback _onStateChange;
};

} // namespace network
} // namespace iora
