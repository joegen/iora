// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Server-Sent Events delivery primitive for iora HTMX support:
// SseStream (handle), upgradeToSse (free function), and SseManager (registry +
// shared-TimerService heartbeat).
//
// Tracker: 2026-05-29-7 (htmx-support phase 6).
// Architecture: architecture/iora/sse_and_channels.json.
//
// SessionId-retention model (NOT fd hand-off, C-2): upgradeToSse enqueues the
// 200 + text/event-stream preamble via the protected HttpServer::sendRawForSse
// (reached by friend access, RD-17), sets Response::_suppressSend, and returns
// the worker thread; subsequent events ride the engine per-session write queue.

#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "iora/core/logger.hpp"
#include "iora/core/timer.hpp"
#include "iora/network/http_server.hpp"
#include "iora/network/transport.hpp"
#include "iora/network/transport_types.hpp"

namespace iora
{
namespace network
{

/// \brief Initial SSE reconnection delay (ms) emitted as the preamble's first
/// body line. This is a FIXED base by design; the reconnection-storm jitter
/// (base + rand[0, base], RD-8/R-2) is applied by the consumer that owns the
/// fleet of streams — wired in the phase-8 application layer (application_wiring),
/// which can call SseStream::writeRetry with a per-client jittered value using a
/// thread-safe RNG (L-2). writeRetry itself is a plain emitter (no jitter).
static constexpr std::uint32_t kDefaultSseRetryMs = 3000;

namespace detail
{

/// \brief Thread-safe reentrant UTC time conversion — the UTC analogue of
/// core::detail::localTimeReentrant (logger.hpp). std::gmtime is FORBIDDEN here:
/// it returns a shared static std::tm and the SSE preamble is built on HttpServer
/// worker threads concurrently (thread-H4 / cpp17-H2). Returns true on success.
inline bool gmTimeReentrant(const std::time_t *t, std::tm *out)
{
#ifdef _WIN32
  return ::gmtime_s(out, t) == 0;
#else
  return ::gmtime_r(t, out) != nullptr;
#endif
}

/// \brief Append a 2-digit zero-padded value (mod 100, so any input yields
/// exactly two characters — no buffer-overflow analysis surprises).
inline void appendTwoDigits(std::string &s, int v)
{
  const int n = ((v % 100) + 100) % 100;
  s += static_cast<char>('0' + (n / 10));
  s += static_cast<char>('0' + (n % 10));
}

/// \brief Format an epoch instant as an RFC 9110 §5.6.7 IMF-fixdate
/// ("Sun, 31 May 2026 12:00:00 GMT" — fixed 29 chars, UTC/GMT, C-locale ENGLISH
/// day/month abbreviations independent of the process locale). Uses the reentrant
/// gmTimeReentrant conversion and hand-rolled tables — NOT strftime-with-locale,
/// and NOT snprintf (whose worst-case-width analysis trips -Wformat-truncation).
inline std::string formatHttpDate(std::time_t t)
{
  static const char *const kDays[] = {"Sun", "Mon", "Tue", "Wed",
                                       "Thu", "Fri", "Sat"};
  static const char *const kMonths[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  std::tm tmv{};
  if (!gmTimeReentrant(&t, &tmv))
  {
    return std::string("Thu, 01 Jan 1970 00:00:00 GMT");
  }
  const int wday = (tmv.tm_wday >= 0 && tmv.tm_wday < 7) ? tmv.tm_wday : 0;
  const int mon = (tmv.tm_mon >= 0 && tmv.tm_mon < 12) ? tmv.tm_mon : 0;
  int year = tmv.tm_year + 1900;
  if (year < 0)
  {
    year = 0;
  }
  year %= 10000; // keep the fixed 4-digit field
  std::string s;
  s.reserve(29);
  s += kDays[wday];
  s += ", ";
  appendTwoDigits(s, tmv.tm_mday);
  s += ' ';
  s += kMonths[mon];
  s += ' ';
  s += static_cast<char>('0' + (year / 1000) % 10);
  s += static_cast<char>('0' + (year / 100) % 10);
  s += static_cast<char>('0' + (year / 10) % 10);
  s += static_cast<char>('0' + year % 10);
  s += ' ';
  appendTwoDigits(s, tmv.tm_hour);
  s += ':';
  appendTwoDigits(s, tmv.tm_min);
  s += ':';
  appendTwoDigits(s, tmv.tm_sec);
  s += " GMT";
  return s;
}

} // namespace detail

/// \brief A lightweight handle to a single SSE connection: a SessionId plus a
/// back-pointer to the owning HttpServer (SseStream is a FRIEND of HttpServer per
/// RD-17, so it reaches the protected sendRawForSse/closeSession by SessionId),
/// a STANDALONE advisory atomic open flag, and a close-latch (a std::mutex
/// guarding _closed + the _onClose slot so onClose fires EXACTLY ONCE). NOT a
/// socket owner. Held by std::shared_ptr so the SseManager registry, each channel
/// subscriber list, and the disconnect-observer closure can co-own one stream;
/// the last holder's destructor is side-effect-free (it does NOT close the
/// session — close is explicit or disconnect-driven).
class SseStream
{
public:
  /// \brief Construct an open stream bound to (server, sid). Fully initialized
  /// (close-latch ready, _open=true) so the disconnect observer registered AFTER
  /// construction may fire markClosed() concurrently without a torn read (RD-17,
  /// thread-H1).
  SseStream(HttpServer &server, SessionId sid)
      : _sid(sid), _server(&server), _open(true), _closed(false)
  {
  }

  ~SseStream() = default;

  SseStream(const SseStream &) = delete;
  SseStream &operator=(const SseStream &) = delete;

  // ── SSE wire-format formatters (pure; unit-tested without a transport) ───

  /// \brief Assemble one SSE event in wire format. 'event: <name>\n' is omitted
  /// when name is empty; the data is split on '\r\n', '\r', AND '\n' (RD-8) into
  /// one 'data: <line>\n' per logical line (single-space separator, web-H1), with
  /// a trailing blank '\n'. Empty data still yields exactly one 'data: \n' line
  /// (web-L1). UTF-8 passes through byte-for-byte.
  static std::string formatEvent(std::string_view name, std::string_view data)
  {
    std::string out;
    out.reserve(name.size() + data.size() + 32);
    if (!name.empty())
    {
      out += "event: ";
      // SSE FIELD-INJECTION HARDENING (web-W1): a '\r'/'\n' in the event name
      // would terminate the 'event:' field early and inject arbitrary SSE fields
      // (the SSE analogue of HTTP header CRLF injection). The name is an
      // identifier, never multi-line, so strip CR/LF rather than escape (SSE has
      // no in-line escape — a newline IS the field terminator).
      appendStripped(out, name);
      out += '\n';
    }
    appendDataLines(out, data);
    out += '\n';
    return out;
  }

  /// \brief Assemble an SSE comment line ': <text>\n\n'. Comments are IGNORED by
  /// the EventSource client (diagnostic-only, web-M1) — used for ':keepalive' and
  /// the final ':shutting down' marker.
  static std::string formatComment(std::string_view text)
  {
    std::string out;
    out.reserve(text.size() + 4);
    out += ": ";
    // SSE field-injection hardening (web-W1): strip CR/LF so a comment cannot
    // inject additional SSE fields/events.
    appendStripped(out, text);
    out += "\n\n";
    return out;
  }

  /// \brief Assemble an SSE 'retry: <ms>\n\n' field. Digits-only by construction.
  static std::string formatRetry(std::uint32_t ms)
  {
    return "retry: " + std::to_string(ms) + "\n\n";
  }

  // ── Writes (fire-and-forget; ride sendRawForSse -> engine write queue) ───

  /// \brief Emit one SSE event. No-op if the stream is already closed; a write
  /// that the transport cannot enqueue flips the advisory _open to false (the
  /// SECONDARY disconnect signal — the primary is the observe callback).
  void writeEvent(std::string_view name, std::string_view data)
  {
    if (!_open.load(std::memory_order_relaxed))
    {
      return;
    }
    writeRaw(formatEvent(name, data));
  }

  /// \brief Emit an SSE comment (':keepalive' heartbeat, ':shutting down').
  void writeComment(std::string_view text)
  {
    if (!_open.load(std::memory_order_relaxed))
    {
      return;
    }
    writeRaw(formatComment(text));
  }

  /// \brief Re-tune the client reconnection delay. Plain emitter — jitter (if
  /// any) is the caller's job and MUST use a thread-safe RNG (L-2).
  void writeRetry(std::uint32_t ms)
  {
    if (!_open.load(std::memory_order_relaxed))
    {
      return;
    }
    writeRaw(formatRetry(ms));
  }

  /// \brief Advisory liveness (relaxed). Becomes false after a write failure or
  /// after the disconnect observer fires. Carries no happens-before for other
  /// fields — a best-effort prune hint only (RD-16).
  bool isOpen() const { return _open.load(std::memory_order_relaxed); }

  /// \brief EXPLICIT close (RD-19 path b). Sets _open false, calls
  /// closeSession(_sid) on the owning server (it takes _mutex independently —
  /// safe because explicit close() runs on the handler thread or the TimerService
  /// heartbeat callback, neither holding an HttpServer lock), then fires onClose
  /// exactly once via the close-latch. Idempotent.
  void close()
  {
    _open.store(false, std::memory_order_relaxed);
    std::function<void()> cb;
    {
      std::lock_guard<std::mutex> lock(_closeMutex);
      if (_closed)
      {
        // Lost the latch — already closed by a prior close() or by the
        // observer-driven markClosed(). Do NOT call closeSession: if the observer
        // won, the engine is ALREADY closing this session, and a second
        // closeSession would be the double-close M-6 forbids. Idempotent.
        return;
      }
      _closed = true;
      cb = _onClose;
    }
    // Won the latch on the EXPLICIT path (RD-19 path b): close the session, but
    // ONLY here (first explicit close). closeSession is called OUTSIDE _closeMutex
    // (lock ordering — keeps _closeMutex a LEAF) and never when the observer
    // already closed the stream (M-6: never closeSession a session the engine is
    // concurrently closing). [NOTE: the architecture's literal close() pseudocode
    // called closeSession before the latch unconditionally; that contradicts its
    // own M-6/RD-19 invariant and is corrected here to fire exactly once on the
    // winning explicit close.]
    if (_server != nullptr)
    {
      _server->closeSession(_sid);
    }
    if (cb)
    {
      cb();
    }
  }

  /// \brief OBSERVER-DRIVEN close (RD-19 path a). Invoked from the
  /// Transport::observe disconnect callback (which runs with NO transport lock
  /// held). Marks closed + fires onClose exactly once via the close-latch but
  /// does NOT call closeSession (the engine is already closing the session —
  /// M-6). Public so the upgradeToSse observer closure can invoke it; idempotent
  /// with close() via the shared latch.
  void markClosed()
  {
    _open.store(false, std::memory_order_relaxed);
    std::function<void()> cb;
    {
      std::lock_guard<std::mutex> lock(_closeMutex);
      if (_closed)
      {
        return;
      }
      _closed = true;
      cb = _onClose;
    }
    if (cb)
    {
      cb();
    }
  }

  /// \brief Register the close callback (the Application attaches the
  /// SSE-subscriber gauge-decrement here, OQ-8). RD-22: if the stream is ALREADY
  /// closed at registration time, cb fires IMMEDIATELY/synchronously on the
  /// registering thread OUTSIDE the latch (closing the gauge-leak window); else
  /// it is stored under the latch and fires exactly once at close time. The
  /// _closeMutex guards BOTH _closed and _onClose so registration is race-free
  /// against a concurrent close (a bare atomic test-and-set would miss/double).
  /// SINGLE-SLOT (thread-L1): there is one _onClose slot; a second registration
  /// before the latch fires OVERWRITES the first (last-wins) — matching
  /// WebSocketServer::setOnClose. v1 attaches exactly one callback (the OQ-8
  /// gauge decrement), so last-wins is the intended contract, not a defect.
  void onClose(std::function<void()> cb)
  {
    {
      std::lock_guard<std::mutex> lock(_closeMutex);
      if (!_closed)
      {
        _onClose = std::move(cb);
        return;
      }
    }
    // Already closed: fire immediately, outside the latch (RD-22).
    if (cb)
    {
      cb();
    }
  }

  /// \brief The engine session this stream writes to (no fd).
  SessionId sessionId() const { return _sid; }

private:
  /// \brief Append a single-line field value with all '\r'/'\n' removed (web-W1
  /// SSE field-injection hardening for the event name and comment text).
  static void appendStripped(std::string &out, std::string_view value)
  {
    for (char c : value)
    {
      if (c != '\r' && c != '\n')
      {
        out += c;
      }
    }
  }

  /// \brief Append one 'data: <line>\n' per logical line, splitting on '\r\n',
  /// '\r', AND '\n' (RD-8); ALWAYS emits at least one data line (web-L1).
  static void appendDataLines(std::string &out, std::string_view data)
  {
    const std::size_t n = data.size();
    std::size_t i = 0;
    std::size_t lineStart = 0;
    bool emittedAny = false;
    while (i < n)
    {
      const char c = data[i];
      if (c == '\n' || c == '\r')
      {
        out += "data: ";
        out.append(data.data() + lineStart, i - lineStart);
        out += '\n';
        emittedAny = true;
        if (c == '\r' && i + 1 < n && data[i + 1] == '\n')
        {
          i += 2;
        }
        else
        {
          ++i;
        }
        lineStart = i;
      }
      else
      {
        ++i;
      }
    }
    if (lineStart < n || !emittedAny)
    {
      out += "data: ";
      out.append(data.data() + lineStart, n - lineStart);
      out += '\n';
    }
  }

  /// \brief Hand an assembled, locally-owned buffer to sendRawForSse (cpp17-M2:
  /// the buffer outlives the call; the engine copies into its per-session queue).
  /// A failed enqueue flips _open false (relaxed) — the secondary signal.
  void writeRaw(const std::string &buf)
  {
    if (_server == nullptr)
    {
      _open.store(false, std::memory_order_relaxed);
      return;
    }
    const bool ok = _server->sendRawForSse(
      _sid, reinterpret_cast<const std::uint8_t *>(buf.data()), buf.size());
    if (!ok)
    {
      _open.store(false, std::memory_order_relaxed);
    }
  }

  SessionId _sid;
  HttpServer *_server;
  std::atomic<bool> _open;
  std::mutex _closeMutex;          // close-latch: guards _closed AND _onClose
  bool _closed;                    // guarded by _closeMutex
  std::function<void()> _onClose;  // guarded by _closeMutex; fired outside it
};

/// \brief Convert the current GET request into a long-lived SSE stream using the
/// SessionId-retention model, then return the worker thread. NO fd transfer.
///
/// RD-21: NO-OP when req.method != GET (an auto-HEAD dispatch to a GET handler
/// that calls upgradeToSse just yields a normal bodyless HEAD response — no
/// preamble, no _suppressSend). Friend of HttpServer (declaration owned by
/// routing_extension.json), so it reaches the protected sendRawForSse /
/// markSessionUpgraded and the private _transport.
///
/// The consumer's onConnect registers the stream with the SseManager AND
/// subscribes it to a channel (cpp17-H1) — upgradeToSse does neither (the 4-arg
/// signature has no SseManager). onConnect runs on the worker thread and MUST be
/// cheap and non-blocking.
inline void upgradeToSse(HttpServer &server, const HttpServer::Request &req,
                         HttpServer::Response &res,
                         std::function<void(std::shared_ptr<SseStream>)> onConnect)
{
  // Step 1 (RD-21): SSE is GET-only. A non-GET request (e.g. an auto-HEAD
  // dispatch to the GET handler) is a NO-OP — no preamble, no _suppressSend.
  if (req.method != HttpMethod::GET)
  {
    return;
  }
  // (Accept: text/event-stream is advisory and not enforced; a Last-Event-ID
  //  request header is silently ignored — v1 does not replay events, web-M3.)

  // Construct the stream FIRST (thread-H1): from the instant the disconnect
  // observer is registered below, markClosed() may fire concurrently, so the
  // close-latch must be initialized before observe.
  auto stream = std::make_shared<SseStream>(server, req.sid);

  // Step 2 (RD-1/RD-18): build the preamble and ENQUEUE it via sendRawForSse —
  // no flush. The initial 'retry:' is the FIRST SSE BODY line, AFTER the blank
  // line that terminates the HTTP head (web-H1/M4). No 'Connection' header
  // (web-M5); Cache-Control carries no-transform (web-M6); Date is a MUST
  // (web-H2, RFC 9110 §6.6.1) formatted as a reentrant IMF-fixdate. No
  // Content-Length, no chunked framing (open-ended body).
  std::string preamble;
  preamble += "HTTP/1.1 200 OK\r\n";
  preamble += "Content-Type: text/event-stream; charset=utf-8\r\n";
  preamble += "Cache-Control: no-cache, no-transform\r\n";
  preamble += "X-Accel-Buffering: no\r\n";
  preamble += "Date: ";
  preamble += detail::formatHttpDate(std::time(nullptr));
  preamble += "\r\n";
  preamble += "\r\n"; // HTTP header terminator
  preamble += "retry: ";
  preamble += std::to_string(kDefaultSseRetryMs);
  preamble += "\n\n"; // first SSE body line (LF endings)
  server.sendRawForSse(req.sid,
                       reinterpret_cast<const std::uint8_t *>(preamble.data()),
                       preamble.size());

  // Step 3 (M-5/RD-2): take the session out of HTTP request-parsing; the SSE GET
  // is the terminal request on its connection (pipelined-after bytes are
  // parsed-then-ignored, not drained).
  server.markSessionUpgraded(req.sid);

  // Steps 4-5: take _mutex and re-check '_transport && !_shutdown' before
  // dereferencing the private _transport — the SAME invariant sendRaw /
  // closeSession use. A worker running upgradeToSse can straggle past stop()'s
  // bounded drain wait and race _transport.reset() (also under _mutex), so an
  // unguarded raw deref here would be a use-after-free (the defect class of
  // tracker 2026-05-30-2). _mutex is the outermost lock; setReadMode/observe take
  // only the transport's own internal locks, so no inversion. The observer
  // closure must NOT be invoked under _mutex — but observe() only REGISTERS it
  // (the engine dispatches markClosed later, lock-free), so registration under
  // _mutex is safe.
  {
    std::lock_guard<std::mutex> lock(server._mutex);
    if (server._transport && !server._shutdown)
    {
      // Step 4 (M-3): stop app-data reads on this write-only session. NOTE this
      // does NOT exempt the 600s idleTimeout — the 15s heartbeat keeps it alive.
      server._transport->setReadMode(req.sid, ReadMode::Disabled);
      // Step 5 (thread-H1/H2/M3): register the disconnect observer. The closure
      // captures the shared_ptr BY VALUE (strong ref) so the stream survives an
      // in-flight publish; the engine auto-purges per-session observers on close,
      // so no explicit unobserve is needed. The returned ObserverId is discarded.
      server._transport->observe(
        req.sid, [stream](SessionId, const TransportErrorInfo &) { stream->markClosed(); });
    }
  }

  // Step 6 (RD-1/H-5): suppress the worker's terminal response — clean
  // all-or-nothing (the preamble was already written in step 2).
  res._suppressSend = true;

  // Step 7 (cpp17-H1): hand the stream to the consumer, which registers it with
  // the SseManager and subscribes it to a channel. markClosed() may already have
  // fired concurrently, so onConnect's onClose(cb) relies on RD-22 immediate-fire.
  if (onConnect)
  {
    onConnect(stream);
  }

  // Step 8: return — the worker goes back to the pool; the session stays open.
}

/// \brief A registry of live SSE streams plus ONE periodic heartbeat/bookkeeping
/// task scheduled on a SHARED, INJECTED core::TimerService — NOT a dedicated
/// thread (RD-24). It is a SCHEDULER, not a socket owner: it performs NO blocking
/// socket I/O (writes ride the engine queue via SseStream::writeComment).
///
/// LIFETIME (thread-safety H-1): TimerService::cancel() does NOT join a heartbeat
/// callback already in flight, and the architecture's lifetime model has the
/// injected TimerService OUTLIVE this manager. To make destruction race-free, the
/// heartbeat-touched state lives in a heap Registry owned by std::shared_ptr; the
/// timer callback captures a std::weak_ptr<Registry> and promotes it per tick — an
/// in-flight tick keeps the Registry alive via its locked strong ref, and a tick
/// dispatched after the manager is gone simply finds the Registry expired and
/// bails. No use-after-free regardless of cancel/destruction ordering.
class SseManager
{
public:
  /// \brief Construct with the owning server and an INJECTED, STARTED
  /// core::TimerService whose lifetime outlives this manager (cpp17-H1). The
  /// heartbeat interval is constructor-configurable so tests can shorten it (L-2).
  /// `server` is accepted for the canonical signature but not retained — the
  /// manager never calls into the server directly (writes go through SseStream).
  SseManager(HttpServer &server, core::TimerService &timer,
             std::chrono::milliseconds interval = std::chrono::milliseconds(15000))
      : _timer(timer), _interval(interval), _registry(std::make_shared<Registry>())
  {
    (void)server;
  }

  ~SseManager() { cancelSchedule(); }

  SseManager(const SseManager &) = delete;
  SseManager &operator=(const SseManager &) = delete;

  /// \brief Register a live stream (called by the consumer's onConnect, NOT by
  /// upgradeToSse — cpp17-H1). Arms the heartbeat lazily on the FIRST stream.
  void add(std::shared_ptr<SseStream> stream)
  {
    if (!stream)
    {
      return;
    }
    {
      std::lock_guard<std::mutex> lock(_registry->mutex);
      _registry->streams.push_back(std::move(stream));
    }
    // cpp17-M2: arm OUTSIDE the registry leaf mutex (schedulePeriodic takes the
    // TimerService's own lock; arming under the registry mutex would make it
    // non-leaf). _scheduleMutex serializes arm vs cancel and is never held while
    // the registry mutex is held, so the registry mutex stays a strict LEAF.
    armHeartbeat();
  }

  /// \brief Deregister a stream (disconnect observer or a closed-stream sweep).
  void remove(const std::shared_ptr<SseStream> &stream)
  {
    std::lock_guard<std::mutex> lock(_registry->mutex);
    auto &v = _registry->streams;
    v.erase(std::remove(v.begin(), v.end(), stream), v.end());
  }

  /// \brief Number of registered streams (source for the OQ-8 gauge).
  std::size_t streamCount() const
  {
    std::lock_guard<std::mutex> lock(_registry->mutex);
    return _registry->streams.size();
  }

  /// \brief Graceful shutdown (shutdownOrdering): SET draining FIRST, then WAIT
  /// for any in-flight heartbeat tick to finish (thread-H3 / M-1: this is what
  /// guarantees no ':keepalive' can interleave AFTER ':shutting down' — the
  /// draining flag alone does not, because a tick already past its entry check
  /// could otherwise still write). Then write a final ':shutting down' marker and
  /// close() each live stream WHILE the transport is up, then CANCEL the schedule.
  void shutdown()
  {
    Registry &reg = *_registry;
    // Set draining (seq_cst) BEFORE reading ticksInFlight; the tick increments
    // ticksInFlight (seq_cst) BEFORE reading draining. This handshake makes it
    // impossible for a tick to write a ':keepalive' that this shutdown's wait
    // missed (see heartbeatTick).
    reg.draining.store(true, std::memory_order_seq_cst);
    while (reg.ticksInFlight.load(std::memory_order_seq_cst) > 0)
    {
      std::this_thread::yield();
    }
    std::vector<std::shared_ptr<SseStream>> snapshot;
    {
      std::lock_guard<std::mutex> lock(reg.mutex);
      snapshot = reg.streams;
    }
    for (auto &s : snapshot)
    {
      // No isOpen() guard: writeComment/close are no-ops on an already-closed
      // stream, so a stream closed by a racing observer still gets a best-effort
      // final marker attempt without a TOCTOU (thread-L2).
      s->writeComment("shutting down");
      s->close();
    }
    cancelSchedule();
    {
      std::lock_guard<std::mutex> lock(reg.mutex);
      reg.streams.clear();
    }
  }

private:
  /// \brief Heartbeat-touched state, heap-owned so an in-flight tick can keep it
  /// alive via a locked weak_ptr after the manager is destroyed (thread H-1).
  struct Registry
  {
    std::mutex mutex;                                  // registry LEAF lock
    std::vector<std::shared_ptr<SseStream>> streams;   // guarded by mutex
    std::atomic<bool> draining{false};
    std::atomic<int> ticksInFlight{0};
  };

  void armHeartbeat()
  {
    std::lock_guard<std::mutex> lock(_scheduleMutex);
    if (_armed || _registry->draining.load(std::memory_order_seq_cst))
    {
      // Already armed, or shutdown has begun — do not (re-)arm. Combined with
      // shutdown() setting draining before it cancels under _scheduleMutex, this
      // closes the add()-vs-shutdown re-arm leak (thread M-2): an arm that wins
      // the mutex before draining schedules and is cancelled by the later
      // cancelSchedule(); an arm that loses sees draining and never schedules.
      return;
    }
    std::weak_ptr<Registry> weak = _registry;
    const std::chrono::milliseconds interval = _interval;
    _scheduleId = _timer.schedulePeriodic(interval, [weak]() { heartbeatTick(weak); });
    _armed = true; // deliberately one-shot even on failure (id==0 below): a
                   // mis-wired STOPPED TimerService is a hard configuration error
                   // we surface loudly, not something a later add() should retry.
    if (_scheduleId == 0)
    {
      // cpp17-L2: a mis-wired owner that injects a STOPPED TimerService gets no
      // heartbeat — fail loudly rather than silently running heartbeat-less.
      iora::core::Logger::error(
        "SseManager: schedulePeriodic returned 0 (TimerService stopped?) — "
        "heartbeat will not run");
    }
  }

  void cancelSchedule()
  {
    std::lock_guard<std::mutex> lock(_scheduleMutex);
    if (_scheduleId != 0)
    {
      _timer.cancel(_scheduleId);
      _scheduleId = 0;
    }
  }

  /// \brief Heartbeat (M-3 idle-survival). Static + weak_ptr-promoted so it never
  /// touches a destroyed manager: bails if the Registry has expired (thread H-1).
  /// Checks draining (thread-H3), copy-then-iterates a registry snapshot (NO lock
  /// held during writeComment), then prunes closed streams (bookkeeping, M-6 —
  /// never calls closeSession; the engine/observer already closed them).
  static void heartbeatTick(const std::weak_ptr<Registry> &weak)
  {
    std::shared_ptr<Registry> reg = weak.lock();
    if (!reg)
    {
      return; // manager (and Registry) gone — bail, no use-after-free
    }
    // Increment ticksInFlight (seq_cst) BEFORE reading draining: see shutdown()
    // for the handshake that guarantees no ':keepalive' lands after shutdown's
    // wait. The guard decrements on every exit path.
    reg->ticksInFlight.fetch_add(1, std::memory_order_seq_cst);
    struct InFlightGuard
    {
      std::atomic<int> &c;
      ~InFlightGuard() { c.fetch_sub(1, std::memory_order_seq_cst); }
    } guard{reg->ticksInFlight};

    if (reg->draining.load(std::memory_order_seq_cst))
    {
      return;
    }
    std::vector<std::shared_ptr<SseStream>> snapshot;
    {
      std::lock_guard<std::mutex> lock(reg->mutex);
      snapshot = reg->streams;
    }
    for (auto &s : snapshot)
    {
      if (s->isOpen())
      {
        s->writeComment("keepalive");
      }
    }
    std::size_t dropped = 0;
    {
      std::lock_guard<std::mutex> lock(reg->mutex);
      auto &v = reg->streams;
      const std::size_t before = v.size();
      v.erase(std::remove_if(v.begin(), v.end(),
                             [](const std::shared_ptr<SseStream> &s)
                             { return !s->isOpen(); }),
              v.end());
      dropped = before - v.size();
    }
    if (dropped > 0)
    {
      iora::core::Logger::warning("SseManager: reaped " + std::to_string(dropped) +
                                  " closed SSE stream(s)");
    }
  }

  core::TimerService &_timer;
  std::chrono::milliseconds _interval;
  std::shared_ptr<Registry> _registry;
  std::mutex _scheduleMutex;     // serializes arm vs cancel; never nests the registry mutex
  bool _armed = false;           // guarded by _scheduleMutex
  std::uint64_t _scheduleId = 0; // guarded by _scheduleMutex
};

} // namespace network
} // namespace iora
