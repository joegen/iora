// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include "iora/network/http_server.hpp"
#include "iora/network/websocket_frame.hpp"
#include "iora/core/string_utils.hpp"
#include "iora/crypto/secure_rng.hpp"
#include "iora/util/base64.hpp"

#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace iora {
namespace network {

/// \brief WebSocket server extending HttpServer via onUpgradeRequest().
///
/// Handles RFC 6455 handshake, frame parsing, fragment reassembly,
/// Ping/Pong, close handshake. Callbacks: onConnect, onMessage, onClose, onError.
class WebSocketServer : public HttpServer
{
public:
  using MessageCallback = std::function<void(SessionId, const std::string&)>;
  using BinaryCallback = std::function<void(SessionId, const std::vector<std::uint8_t>&)>;
  using ConnectCallback = std::function<void(SessionId, const std::string& subprotocol)>;
  using CloseCallback = std::function<void(SessionId, std::uint16_t code, const std::string& reason)>;
  using ErrorCallback = std::function<void(SessionId, const std::string& message)>;
  using SubprotocolCallback = std::function<std::string(const std::vector<std::string>&)>;
  using OriginCallback = std::function<bool(SessionId, const std::string& origin)>;

  WebSocketServer(const std::string& bindAddress = "0.0.0.0", int port = DEFAULT_PORT)
    : HttpServer(bindAddress, port)
    , _maxFrameSize(16 * 1024 * 1024) // 16MB default
  {
  }

  /// \brief WS-TS1: quiesce the transport I/O thread (which drives
  /// onUpgradedData/onUpgradedClose into _sessions/_wsMutex) and drain the pool
  /// BEFORE this subclass's members are destroyed. ~HttpServer runs only after
  /// the derived members are already gone, so the base stop() alone would leave
  /// a live I/O-thread frame dispatch racing the destruction of _sessions. Must
  /// come first in this dtor. quiesceTransport() allocates (logging, engine stop)
  /// and can throw; this is the call that does the real work (the base dtor's
  /// stop() then early-outs), so it — not the base — uses quiesceTransportNoexcept
  /// to keep a THROWN exception from escaping this noexcept destructor. That wrapper
  /// does NOT prevent std::abort(): if a handler runs past drainDeadline(),
  /// quiesceTransport()'s circuit breaker aborts the process (see
  /// HttpServer::quiesceTransport).
  ~WebSocketServer() override
  {
    quiesceTransportNoexcept("~WebSocketServer");
  }

  // ── Callback Registration ──────────────────────────────────────────────
  //
  // CONTRACT: register all callbacks BEFORE start(). After start() they are read
  // (unlocked) on the transport I/O thread for every frame/close, so mutating a
  // callback concurrently with a live connection is a data race on the
  // std::function. The dispatch sites snapshot the callback before invoking it
  // (copy-then-invoke, outside any lock); they do NOT synchronize it against a
  // concurrent setter.
  //
  // A CLOSE is reported to the application on exactly one channel: a normal or
  // abrupt close fires _onClose once (see onUpgradedClose / the inbound-CLOSE
  // path); a PROTOCOL-ERROR close (unmasked/reserved/oversize/invalid-UTF-8/
  // bad-CLOSE) fires _onError and is its terminal signal — it deliberately does
  // NOT also fire _onClose. An application that frees per-session state must treat
  // _onError as a terminal close signal too, not rely on _onClose alone.

  void setOnConnect(ConnectCallback cb) { _onConnect = std::move(cb); }
  void setOnTextMessage(MessageCallback cb) { _onTextMessage = std::move(cb); }
  void setOnBinaryMessage(BinaryCallback cb) { _onBinaryMessage = std::move(cb); }
  void setOnClose(CloseCallback cb) { _onClose = std::move(cb); }
  void setOnError(ErrorCallback cb) { _onError = std::move(cb); }
  void setSubprotocolCallback(SubprotocolCallback cb) { _subprotocolCb = std::move(cb); }
  void setOriginCallback(OriginCallback cb) { _originCb = std::move(cb); }

  void setMaxFrameSize(std::size_t maxBytes) { _maxFrameSize = maxBytes; }

  /// \brief 2026-09-11-23 (CORE): fault-injection seam phases inside
  /// onUpgradeRequest, used by the race tests to serialize the pool worker
  /// against the transport I/O thread. Production builds never override the hook.
  enum class WsUpgradePhase
  {
    BeforeMark,      // pending entry created; markSessionUpgradedIfLive not yet called
    AfterMark,       // upgraded + live; _onConnect not yet fired
    BeforeCommit     // _onConnect delivered; P3 commit not yet run
  };

  // ── Session Send Methods ───────────────────────────────────────────────

  /// \brief Returns true iff the session is present AND its CLOSE frame has not
  /// been sent — a CHEAP liveness early-out for WsChannel.publish (web-M7, OQ-6).
  /// Best-effort: a true result can go stale immediately. The data-after-close
  /// GUARANTEE is the closeSent recheck inside sendText/sendBinary/sendPing.
  /// Virtual so a WsChannel test double can simulate session liveness; an
  /// override MUST preserve the closeSent-aware semantics.
  virtual bool isSessionActive(SessionId sid) const
  {
    std::lock_guard<std::mutex> lock(_wsMutex);
    auto it = _sessions.find(sid);
    return it != _sessions.end() && !it->second.closeSent;
  }

  /// \brief Send a text message to a WebSocket session. AUTHORITATIVE
  /// data-after-close prevention (web-M7, RFC 6455 §5.5.1): the closeSent recheck
  /// and the send are ATOMIC under _wsMutex w.r.t. sendClose / the inbound-CLOSE
  /// echo (which flip closeSent under _wsMutex), so a DATA frame can NEVER follow
  /// a CLOSE frame. Holds _wsMutex across sendRaw (which takes HttpServer::_mutex)
  /// — the SAME _wsMutex -> _mutex order as the inbound-CLOSE echo; no new cycle.
  /// Virtual so a WsChannel test double can capture sends; an override MUST
  /// preserve the closeSent recheck.
  virtual void sendText(SessionId sid, const std::string& text)
  {
    std::lock_guard<std::mutex> lock(_wsMutex);
    auto it = _sessions.find(sid);
    if (it == _sessions.end() || it->second.closeSent)
    {
      return; // drop: unknown or closing session
    }
    auto frame = WebSocketFrame::makeText(text);
    auto wire = frame.serialize(false); // server does NOT mask
    sendRaw(sid, wire.data(), wire.size());
  }

  /// \brief Send a binary message to a WebSocket session (see sendText for the
  /// web-M7 send-boundary closeSent recheck contract). Virtual for testability.
  virtual void sendBinary(SessionId sid, const std::vector<std::uint8_t>& data)
  {
    std::lock_guard<std::mutex> lock(_wsMutex);
    auto it = _sessions.find(sid);
    if (it == _sessions.end() || it->second.closeSent)
    {
      return; // drop: unknown or closing session
    }
    auto frame = WebSocketFrame::makeBinary(data);
    auto wire = frame.serialize(false);
    sendRaw(sid, wire.data(), wire.size());
  }

  /// \brief Send a Ping to a WebSocket session (see sendText for the web-M7
  /// send-boundary closeSent recheck contract). Virtual for testability.
  virtual void sendPing(SessionId sid, const std::vector<std::uint8_t>& payload = {})
  {
    std::lock_guard<std::mutex> lock(_wsMutex);
    auto it = _sessions.find(sid);
    if (it == _sessions.end() || it->second.closeSent)
    {
      return; // drop: unknown or closing session
    }
    auto frame = WebSocketFrame::makePing(payload);
    auto wire = frame.serialize(false);
    sendRaw(sid, wire.data(), wire.size());
  }

  /// \brief Send a Close frame to a WebSocket session. IDEMPOTENT and
  /// session-checked: if the session is unknown OR a CLOSE has already been sent,
  /// this returns WITHOUT putting a second CLOSE on the wire. Every error-close
  /// call site therefore fires at most one Close frame — the closeSent flag is the
  /// single wire-level gate shared with the inbound-CLOSE echo.
  void sendClose(SessionId sid, std::uint16_t code = 1000,
                 const std::string& reason = "")
  {
    // Hold _wsMutex across serialize + sendRaw (as sendText/sendBinary/sendPing
    // do) so the closeSent claim and the wire-write are atomic w.r.t. the
    // inbound-CLOSE teardown, closing a benign echo-drop race. Preserves the
    // _wsMutex -> HttpServer::_mutex lock order established by sendText.
    std::lock_guard<std::mutex> lock(_wsMutex);
    auto it = _sessions.find(sid);
    if (it == _sessions.end() || it->second.closeSent)
    {
      return; // unknown session, or a CLOSE was already sent — send at most once
    }
    it->second.closeSent = true;

    auto frame = WebSocketFrame::makeClose(code, reason);
    auto wire = frame.serialize(false);
    sendRaw(sid, wire.data(), wire.size());
  }

protected:
  /// \brief 2026-09-11-23 (CORE) test-only fault-injection seam. No-op in
  /// production; a test subclass overrides it to drive a transport close (and a
  /// rendezvous latch) at a precise phase of onUpgradeRequest, making the
  /// upgrade-vs-close race deterministic. Runs on the pool worker.
  virtual void onUpgradeRacePhase(SessionId /*sid*/, WsUpgradePhase /*phase*/) {}

  /// \brief 2026-09-11-23 (CORE) test-only: number of live WS sessions
  /// (_sessions). Used by the race tests to assert no session leak.
  std::size_t wsSessionCountForTest() const
  {
    std::lock_guard<std::mutex> lock(_wsMutex);
    return _sessions.size();
  }

  // ── HTTP Upgrade Hook ──────────────────────────────────────────────────

  bool onUpgradeRequest(SessionId sid, const Request& req, Response& res) override
  {
    // Validate required headers
    auto upgradeVal = req.get_header_value("Upgrade");
    auto connectionVal = req.get_header_value("Connection");
    auto wsKey = req.get_header_value("Sec-WebSocket-Key");
    auto wsVersion = req.get_header_value("Sec-WebSocket-Version");

    // Case-insensitive check for "websocket" in Upgrade (WS-W7: reuse the
    // foundation ASCII case-fold instead of a hand-rolled std::transform lambda).
    if (!iora::core::StringUtils::iequals(upgradeVal, "websocket"))
    {
      return false; // not a WebSocket upgrade
    }

    // Validate Connection contains "Upgrade" (case-insensitive)
    std::string connLower = iora::core::StringUtils::toLower(connectionVal);
    if (connLower.find("upgrade") == std::string::npos)
    {
      res.status = 400;
      res.set_content("Missing Connection: Upgrade", "text/plain");
      return true;
    }

    if (wsKey.empty())
    {
      res.status = 400;
      res.set_content("Missing Sec-WebSocket-Key", "text/plain");
      return true;
    }

    if (wsVersion != "13")
    {
      res.status = 426;
      res.set_header("Sec-WebSocket-Version", "13");
      res.set_content("Unsupported WebSocket version", "text/plain");
      return true;
    }

    // Origin validation (RFC 6455 Section 10.2)
    if (_originCb)
    {
      auto origin = req.get_header_value("Origin");
      if (!_originCb(sid, origin))
      {
        res.status = 403;
        res.set_content("Origin not allowed", "text/plain");
        return true;
      }
    }

    // Compute Sec-WebSocket-Accept
    static const std::string kGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string concat = wsKey + kGuid;
    unsigned char sha1Out[20];
    crypto::SecureRng::sha1(concat, sha1Out);
    std::string accept = util::Base64::encode(sha1Out, 20);

    // Negotiate subprotocol
    std::string negotiatedProtocol;
    auto requestedProtocols = req.get_header_value("Sec-WebSocket-Protocol");
    if (!requestedProtocols.empty() && _subprotocolCb)
    {
      // Parse comma-separated protocol list, reusing the foundation split/trim
      // (StringUtils, already used for the case-folds above) instead of a
      // hand-rolled istringstream + find_first/last_not_of.
      std::vector<std::string> protocols;
      for (std::string_view tok : iora::core::StringUtils::split(requestedProtocols, ','))
      {
        std::string_view t = iora::core::StringUtils::trim(tok);
        if (!t.empty())
        {
          protocols.emplace_back(t);
        }
      }
      negotiatedProtocol = _subprotocolCb(protocols);
    }

    // Build 101 Switching Protocols response
    res.status = 101;
    res.set_header("Upgrade", "websocket");
    res.set_header("Connection", "Upgrade");
    res.set_header("Sec-WebSocket-Accept", accept);
    if (!negotiatedProtocol.empty())
    {
      res.set_header("Sec-WebSocket-Protocol", negotiatedProtocol);
    }

    // 2026-09-11-23 (CORE): establish the session lifecycle so it is serialized
    // against the transport I/O thread's onUpgradedClose.
    //
    // P1 + P13: create an ALWAYS-PRESENT pending entry (connectDelivered=false)
    // BEFORE marking the session upgraded, via emplace so a racing concurrent
    // upgrade for the same sid cannot clobber the winner. Because the I/O thread
    // routes close/data to a session only after _upgradedSessions contains sid
    // (set below, after this create), once the I/O thread can observe the session
    // the _sessions entry already exists — so a later "absent" in onUpgradedClose
    // means unambiguously "already destroyed".
    {
      std::lock_guard<std::mutex> lock(_wsMutex);
      // try_emplace default-constructs WsSessionState in place only when sid is
      // absent — the P13 "insert iff not already upgrading/upgraded" duplicate
      // guard, with no temporary + move.
      if (!_sessions.try_emplace(sid).second)
      {
        // P13: a concurrent/duplicate upgrade for this sid is already in progress
        // or complete. Suppress the 101 AND normal HTTP route dispatch (return
        // true so the caller does not fall through to route dispatch, which would
        // inject an HTTP response into the live WebSocket byte stream). Fire
        // nothing — the winner owns the lifecycle.
        res._suppressSend = true;
        return true;
      }
    }

    onUpgradeRacePhase(sid, WsUpgradePhase::BeforeMark);

    // P2 + P10: the ENTIRE mark->commit window is exception-safe under one guard.
    // EVERY throwing op in it — the _upgradedSessions insert inside
    // markSessionUpgradedIfLive, the allocating _onClose snapshot copy, and the
    // user _onConnect — must, if it throws before connectDelivered is committed,
    // run the abort-equivalent teardown on BOTH maps, or the always-present
    // pending _sessions entry leaks with no onClose (the exact failure class this
    // fix exists to kill). `committed` disarms the guard once the noexcept commit
    // critical section has run (the session is then either live or already erased
    // with its deferred close taken), so a throw from the post-commit user
    // _onClose invocation does not re-abort an already-handled session.
    bool committed = false;
    try
    {
      // P2: mark upgraded with a fused liveness check. If the transport already
      // closed during the handshake window (its onClose erased _sessionInfo under
      // _sessionMutex), abort: erase the pending entry and suppress the 101 (the
      // a0 window — close-before-mark). The transport is already gone here, so no
      // closeSession is owed — a plain return (not the abort guard) is enough.
      if (!markSessionUpgradedIfLive(sid))
      {
        std::lock_guard<std::mutex> lock(_wsMutex);
        _sessions.erase(sid);
        res._suppressSend = true; // P7 verdict v1: caller skips the 101 + drain
        return true;
      }

      onUpgradeRacePhase(sid, WsUpgradePhase::AfterMark);

      // Snapshot the close callback (a std::function copy that MAY allocate)
      // BEFORE firing _onConnect: once onConnect is delivered, a transport close
      // deferred during it is then GUARANTEED a callback to fire (no lost-close-
      // under-OOM window), and the commit critical section stays noexcept.
      CloseCallback closeCb = _onClose;

      // P3: fire _onConnect (copy-then-invoke, OUTSIDE any lock) while
      // connectDelivered is still false.
      if (ConnectCallback cb = _onConnect)
      {
        cb(sid, negotiatedProtocol);
      }

      onUpgradeRacePhase(sid, WsUpgradePhase::BeforeCommit);

      // P3 commit (NOEXCEPT critical section — only flag sets, a uint read, a
      // string MOVE, and erase). Set connectDelivered; if a transport close was
      // deferred while we delivered onConnect, take its code/reason, erase, and
      // fire _onClose exactly once AFTER onConnect.
      bool fireClose = false;
      std::uint16_t closeCode = 0;
      std::string closeReason;
      {
        std::lock_guard<std::mutex> lock(_wsMutex);
        auto it = _sessions.find(sid);
        if (it != _sessions.end())
        {
          it->second.connectDelivered = true;
          if (it->second.deferredClose)
          {
            fireClose = true;
            closeCode = it->second.deferredCloseCode;
            closeReason = std::move(it->second.deferredCloseReason);
            _sessions.erase(it);
          }
        }
      }
      committed = true; // past the abort window: session is live, or erased above

      if (fireClose)
      {
        // A transport close was deferred while we delivered onConnect. The
        // session is already erased; skip the 101 + drain (P7) — the peer is
        // gone — and fire _onClose exactly once, AFTER onConnect.
        res._suppressSend = true;
        if (closeCb)
        {
          closeCb(sid, closeCode, closeReason);
        }
      }
    }
    catch (...)
    {
      // A throw before the commit (the mark insert, the closeCb copy, or the user
      // _onConnect) must not leak the pending session. Tear down BOTH maps + the
      // transport, then RETHROW so the exception is still logged by the pool /
      // processHttpRequest (the session is already fully torn down, so the outer
      // 500-send is dropped on the closing socket). P10.ii.
      if (!committed)
      {
        abortUpgradedSession(sid);
      }
      throw;
    }

    return true;
  }

  // ── Upgraded Data Handler ──────────────────────────────────────────────

  void onUpgradedData(SessionId sid, const std::uint8_t* data,
                      std::size_t len) override
  {
    // Move buffer out under lock to avoid TOCTOU race with concurrent calls.
    // Parse on the moved buffer, then put unconsumed remainder back.
    std::vector<std::uint8_t> localBuffer;
    {
      std::lock_guard<std::mutex> lock(_wsMutex);
      auto it = _sessions.find(sid);
      if (it == _sessions.end())
      {
        return;
      }
      it->second.buffer.insert(it->second.buffer.end(), data, data + len);
      localBuffer = std::move(it->second.buffer);
      it->second.buffer.clear();
    }

    // Parse frames from the local buffer (outside lock)
    std::size_t offset = 0;
    while (offset < localBuffer.size())
    {
      // Wrap the per-frame parse + dispatch so a std::bad_alloc / any codec throw
      // closes THIS ONE session and breaks the loop — it MUST NOT escape into the
      // transport I/O thread (WS-C1 defense-in-depth).
      try
      {
        core::BufferView view(localBuffer.data() + offset,
                              localBuffer.size() - offset);
        std::size_t consumed = 0;
        WsParseError perr;
        auto frame = WebSocketFrame::parse(view, consumed, _maxFrameSize, &perr);

        if (!frame)
        {
          if (perr.isError)
          {
            sendClose(sid, perr.closeCode, "");
            if (_onError)
            {
              _onError(sid, "protocol error: frame rejected (1002/1009)");
            }
            eraseAndCloseSession(sid);
          }
          break;
        }

        offset += consumed;
        // handleFrame returns true when it tore the session down (inbound CLOSE,
        // unmasked frame, reserved opcode, fragment / oversize / UTF-8 error).
        // Stop parsing immediately so no further frame is dispatched on — or data
        // accumulated for — a closed session (WS HIGH: double-callback / data-
        // after-close).
        if (handleFrame(sid, *frame))
        {
          break;
        }
      }
      catch (...)
      {
        // The recovery itself allocates (sendClose serialize / make_shared) and
        // can throw std::bad_alloc; wrap it so nothing escapes into the transport
        // I/O thread and defeats this catch (WS-C1 defense-in-depth).
        try
        {
          sendClose(sid, 1009, "");
          eraseAndCloseSession(sid);
        }
        catch (...)
        {
        }
        break;
      }
    }

    // Put unconsumed remainder back
    if (offset < localBuffer.size())
    {
      std::lock_guard<std::mutex> lock(_wsMutex);
      auto it = _sessions.find(sid);
      if (it != _sessions.end())
      {
        // Prepend remainder before any data that arrived during parsing
        auto& buf = it->second.buffer;
        std::vector<std::uint8_t> remainder(
          localBuffer.begin() + offset, localBuffer.end());
        remainder.insert(remainder.end(), buf.begin(), buf.end());
        buf = std::move(remainder);
      }
    }
  }

  /// \brief Transport-close teardown (2026-09-11-16 / 2026-09-11-23 CORE). On an
  /// abrupt client disconnect (TCP RST/FIN with no WS CLOSE frame — client crash,
  /// kill -9, network drop) the protocol layer never runs its CLOSE path, so the
  /// session leaks and the app's onClose never fires. The base transport onClose
  /// routes here for upgraded sessions. This runs on the I/O thread and may race
  /// the upgrade handshake on a pool worker, so it does NOT unconditionally fire:
  /// it defers to deferOrFireClose, which fires _onClose exactly once and only
  /// after _onConnect has been delivered (connectDelivered), guaranteeing
  /// onConnect-strictly-before-onClose. Map the transport reason to an accurate
  /// application close code (RFC 6455 §7.4.1): a whole-server going-away -> 1001;
  /// any other transport close with no close handshake (peer loss, write-stall
  /// timeout, idle-GC reap) -> 1006. Both are callback-only codes, NEVER on the wire.
  void onUpgradedClose(SessionId sid, const TransportErrorInfo &reason) override
  {
    const std::uint16_t code = isServerInitiatedClose(reason.code) ? 1001 : 1006;
    const char *const why = (code == 1001) ? "going away" : "abnormal closure";
    deferOrFireClose(sid, code, why);
  }

  /// \brief True when a transport close means this endpoint is "going away" — a
  /// whole-server stop() — so the application close code is RFC 6455 §7.4.1 1001.
  /// A global stop() is detected via the shutdown flag (the engine's shutdown-drain
  /// reports TransportError::Unknown, not a distinct code, so the flag — not the
  /// code — is the reliable discriminator). Every other engine-initiated per-session
  /// close exchanges NO close frame (PeerClosed, a write-stall Timeout, an idle-GC
  /// reap), which is 1006 "abnormal closure", not 1001 — so they are NOT mapped to
  /// 1001 here. TransportError::ShuttingDown is kept as a belt-and-suspenders match
  /// for the flag.
  bool isServerInitiatedClose(TransportError code) const
  {
    return getShutdownChecker().isShuttingDown() || code == TransportError::ShuttingDown;
  }

private:
  /// \brief 2026-09-11-23 (CORE P5): deliver a TRANSPORT-close _onClose callback,
  /// gated on connectDelivered so it never precedes _onConnect. Runs on the I/O
  /// thread (from onUpgradedClose). If the session's onConnect has NOT yet been
  /// delivered (the close raced the upgrade handshake), DEFER: record the code/
  /// reason on the pending entry and let the upgrade worker fire _onClose exactly
  /// once after onConnect (P3 commit). If connectDelivered, fire now
  /// (copy-then-invoke, OUTSIDE _wsMutex) and erase the entry — membership is the
  /// at-most-once guard. Absence of the entry means already-destroyed (a WS-level
  /// CLOSE / protocol-error erase, or the worker's deferred fire) -> nothing owed.
  /// Only the TRANSPORT-close path is gated in the core; the inbound-WS-frame and
  /// outbound ordering in the handshake window are tracker 2026-09-12-2.
  void deferOrFireClose(SessionId sid, std::uint16_t code, const std::string &reason)
  {
    // WS-C1: this runs on the transport I/O thread, whose top-level catch treats
    // any escaped exception as fatal (it tears down the whole engine loop, dropping
    // EVERY session). Both allocating operations here — the deferredCloseReason
    // copy under the lock and the _onClose snapshot copy — can throw std::bad_alloc,
    // so the whole body is wrapped to swallow it (mirroring onUpgradedData's
    // per-frame guard). Losing one session's close callback under OOM is strictly
    // better than terminating the I/O loop.
    try
    {
      bool fire = false;
      {
        std::lock_guard<std::mutex> lock(_wsMutex);
        auto it = _sessions.find(sid);
        if (it == _sessions.end())
        {
          return; // already destroyed
        }
        if (it->second.connectDelivered)
        {
          fire = true;
          _sessions.erase(it);
        }
        else if (!it->second.deferredClose)
        {
          // First-writer-wins: only one transport close can reach here per session
          // (the base onClose erases _upgradedSessions, gating a second call), so a
          // single record suffices; the guard also keeps a follow-on call harmless.
          it->second.deferredClose = true;
          it->second.deferredCloseCode = code;
          it->second.deferredCloseReason = reason;
        }
      }
      if (fire)
      {
        // Snapshot + invoke OUTSIDE the lock, and only when actually firing (no
        // wasted std::function copy / bad_alloc surface on the defer path).
        if (CloseCallback cb = _onClose)
        {
          cb(sid, code, reason);
        }
      }
    }
    catch (...)
    {
      // Never let an allocation failure escape into the transport I/O loop.
    }
  }

  /// \brief 2026-09-11-23 (CORE P10): abort-equivalent teardown for an upgraded
  /// session whose onConnect delivery did not complete (a throwing _onConnect).
  /// Erase _sessions FIRST (keeps the session routing "upgraded" so an inbound
  /// byte arriving in the gap hits onUpgradedData and safely drops on the miss,
  /// rather than being misrouted to the HTTP parser), THEN unmark the routing
  /// gate, THEN tear the transport down. Fires no callback (a thrown onConnect is
  /// not a completed connect, so no onClose is owed). The two erases are separate
  /// sequential critical sections — the two mutexes are never co-held (P6).
  void abortUpgradedSession(SessionId sid)
  {
    {
      std::lock_guard<std::mutex> lock(_wsMutex);
      _sessions.erase(sid);
    }
    unmarkSessionUpgraded(sid);
    closeSession(sid);
  }

  /// \brief Erase the per-session state under _wsMutex then tear the transport
  /// session down — the shared teardown for a protocol-error / bad-alloc close,
  /// mirroring the inbound-CLOSE handling.
  void eraseAndCloseSession(SessionId sid)
  {
    {
      std::lock_guard<std::mutex> lock(_wsMutex);
      _sessions.erase(sid);
    }
    closeSession(sid);
  }

  /// \brief Dispatch one parsed frame. Returns true iff the session was torn down
  /// and the parse loop MUST stop (no further frame may be dispatched on it).
  /// Normal data / ping / pong return false.
  bool handleFrame(SessionId sid, const WebSocketFrame& frame)
  {
    // WS-M1 (RFC 6455 §5.1): the server MUST close on ANY unmasked client frame.
    if (!frame.masked)
    {
      sendClose(sid, 1002, "Unmasked frame");
      if (_onError)
      {
        _onError(sid, "client frame not masked");
      }
      eraseAndCloseSession(sid);
      return true;
    }

    switch (frame.opcode)
    {
    case WsOpcode::TEXT:
    case WsOpcode::BINARY:
    case WsOpcode::CONTINUATION:
    {
      return handleDataFrame(sid, frame);
    }
    case WsOpcode::PING:
    {
      // Auto-respond with Pong
      auto pong = WebSocketFrame::makePong(frame.payload);
      auto wire = pong.serialize(false);
      sendRaw(sid, wire.data(), wire.size());
      return false;
    }
    case WsOpcode::PONG:
    {
      // No-op — application can track keep-alive if needed
      return false;
    }
    case WsOpcode::CLOSE:
    {
      // Validate the inbound CLOSE payload (RFC 6455 §5.5.1 / §7.4). A malformed
      // length (1 byte), an invalid/reserved code, or a non-UTF-8 reason is a
      // protocol error: close with the failCode and tear down WITHOUT firing the
      // normal _onClose echo.
      auto v = frame.validateClose();
      if (!v.ok)
      {
        sendClose(sid, v.failCode, "");
        if (_onError)
        {
          _onError(sid, "invalid CLOSE frame");
        }
        eraseAndCloseSession(sid);
        return true;
      }

      auto [code, reason] = frame.closePayload();

      // WS-M4 + WS-L1: echo computed from the RECEIVED close (never blindly
      // reflect the peer's code), closeSent-guarded so we echo at most once.
      {
        std::lock_guard<std::mutex> lock(_wsMutex);
        auto it = _sessions.find(sid);
        if (it != _sessions.end() && !it->second.closeSent)
        {
          it->second.closeSent = true;
          auto response = WebSocketFrame::makeCloseEcho(frame);
          auto wire = response.serialize(false);
          sendRaw(sid, wire.data(), wire.size());
        }
      }

      // Copy-then-invoke outside any lock, matching onUpgradedClose (no lock is
      // held here either); correctness against a concurrent setOnClose rests on
      // the register-before-start() contract.
      if (CloseCallback cb = _onClose)
      {
        cb(sid, code, reason);
      }

      {
        std::lock_guard<std::mutex> lock(_wsMutex);
        _sessions.erase(sid);
      }

      closeSession(sid);
      return true;
    }
    default:
    {
      // Unknown/reserved opcode. parse() already rejects reserved opcodes (1002),
      // so this is a safety net: close and tear down through the shared path so
      // fragment state is dropped with the session entry.
      sendClose(sid, 1002, "Unsupported opcode");
      if (_onError)
      {
        _onError(sid, "Received reserved/unknown opcode");
      }
      eraseAndCloseSession(sid);
      return true;
    }
    }
  }

  /// \brief Accumulate/deliver a data frame. Returns true iff the session was torn
  /// down (fragment / oversize / UTF-8 protocol error) and the parse loop must
  /// stop; false on a normal (possibly incomplete-message) data frame.
  bool handleDataFrame(SessionId sid, const WebSocketFrame& frame)
  {
    bool isStart = (frame.opcode == WsOpcode::TEXT || frame.opcode == WsOpcode::BINARY);
    bool isContinuation = (frame.opcode == WsOpcode::CONTINUATION);

    // Accumulate under lock, then deliver outside lock
    bool messageComplete = false;
    bool tooLarge = false;
    bool fragmentError = false; // WS-M5 fragmentation-sequence violation
    WsOpcode messageOpcode = WsOpcode::CONTINUATION;
    std::vector<std::uint8_t> messagePayload;

    {
      std::lock_guard<std::mutex> lock(_wsMutex);
      auto it = _sessions.find(sid);
      if (it == _sessions.end())
      {
        return true; // session already gone — stop the parse loop
      }
      auto& session = it->second;

      // WS-M5: enforce the fragmentation sequence. A new data frame (TEXT/BINARY)
      // arriving mid-fragment, or a CONTINUATION with no fragment in progress, is
      // a protocol error (RFC 6455 §5.4).
      if (isStart)
      {
        if (session.fragmentInProgress)
        {
          fragmentError = true; // new data frame mid-fragment
        }
        else
        {
          session.fragmentOpcode = frame.opcode;
          session.fragmentBuffer = frame.payload;
          session.fragmentInProgress = !frame.fin;
        }
      }
      else if (isContinuation)
      {
        if (!session.fragmentInProgress)
        {
          fragmentError = true; // stray continuation
        }
        else
        {
          session.fragmentBuffer.insert(session.fragmentBuffer.end(),
                                         frame.payload.begin(), frame.payload.end());
          if (frame.fin)
          {
            session.fragmentInProgress = false;
          }
        }
      }

      if (!fragmentError)
      {
        if (session.fragmentBuffer.size() > _maxFrameSize)
        {
          tooLarge = true;
        }
        else if (frame.fin)
        {
          messageComplete = true;
          messageOpcode = session.fragmentOpcode;
          messagePayload = std::move(session.fragmentBuffer);
          session.fragmentBuffer.clear();
          session.fragmentOpcode = WsOpcode::CONTINUATION;
        }
      }
    }

    // Fire callbacks outside lock. Every error path routes through
    // eraseAndCloseSession (which drops the whole session entry, including
    // fragmentBuffer) so a torn-down session can never keep accumulating data.
    if (fragmentError)
    {
      sendClose(sid, 1002, "Protocol error");
      if (_onError)
      {
        _onError(sid, "fragmentation protocol error");
      }
      eraseAndCloseSession(sid);
      return true;
    }

    if (tooLarge)
    {
      sendClose(sid, 1009, "Message Too Big");
      if (_onError)
      {
        _onError(sid, "Message exceeded maxFrameSize");
      }
      eraseAndCloseSession(sid);
      return true;
    }

    if (messageComplete)
    {
      if (messageOpcode == WsOpcode::TEXT)
      {
        if (!WebSocketFrame::isValidUtf8(messagePayload))
        {
          sendClose(sid, 1007, "Invalid UTF-8");
          if (_onError)
          {
            _onError(sid, "invalid UTF-8 in text message");
          }
          eraseAndCloseSession(sid);
          return true;
        }

        if (_onTextMessage)
        {
          std::string text(messagePayload.begin(), messagePayload.end());
          _onTextMessage(sid, text);
        }
      }
      else if (messageOpcode == WsOpcode::BINARY)
      {
        if (_onBinaryMessage)
        {
          _onBinaryMessage(sid, messagePayload);
        }
      }
    }
    return false;
  }

  struct WsSessionState
  {
    // Inbound accumulation buffer. Its growth is bounded: parse() rejects any
    // frame whose declared length exceeds maxFrameSize (close 1009) BEFORE the
    // payload is accumulated, so a peer cannot grow this without bound.
    std::vector<std::uint8_t> buffer;
    std::vector<std::uint8_t> fragmentBuffer;
    WsOpcode fragmentOpcode = WsOpcode::CONTINUATION;
    bool fragmentInProgress = false; // WS-M5: a fragmented message is mid-assembly
    bool closeSent = false; // prevents double close-frame echo
    // 2026-09-11-23 (CORE): serialize the upgrade handshake (pool worker) against
    // the transport I/O thread's onUpgradedClose. All four flags are plain and
    // guarded EXCLUSIVELY by _wsMutex (the mutex supplies happens-before); never
    // read or written outside _wsMutex, never made atomic.
    bool connectDelivered = false;    // _onConnect has been delivered to the app
    bool deferredClose = false;       // a transport close was observed pre-connect
    std::uint16_t deferredCloseCode = 0;
    std::string deferredCloseReason;
  };

  mutable std::mutex _wsMutex; // mutable so the const isSessionActive can lock it
  std::unordered_map<SessionId, WsSessionState> _sessions;
  std::size_t _maxFrameSize;

  // Callbacks
  ConnectCallback _onConnect;
  MessageCallback _onTextMessage;
  BinaryCallback _onBinaryMessage;
  CloseCallback _onClose;
  ErrorCallback _onError;
  SubprotocolCallback _subprotocolCb;
  OriginCallback _originCb;
};

} // namespace network
} // namespace iora
