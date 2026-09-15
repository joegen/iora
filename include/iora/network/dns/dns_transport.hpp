// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include "dns_message.hpp"
#include "dns_types.hpp"
#include "dns_utils.hpp"
#include "iora/core/atomic_shared_ptr.hpp"
#include "iora/core/atomic_thread_id.hpp"
#include "iora/core/logger.hpp"
#include "iora/core/thread_pool.hpp"
#include "iora/core/timer.hpp"
#include "iora/network/transport_impl.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <climits>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <thread>
#include <vector>

namespace iora
{
namespace network
{
namespace dns
{

/// \brief DNS transport exceptions
class DnsTransportException : public std::runtime_error
{
public:
  explicit DnsTransportException(const std::string &message)
      : std::runtime_error("DNS Transport Error: " + message)
  {
  }
};

class DnsTimeoutException : public DnsTransportException
{
public:
  explicit DnsTimeoutException(const std::string &message = "DNS query timeout")
      : DnsTransportException(message)
  {
  }
};

class DnsServerException : public DnsTransportException
{
public:
  DnsResponseCode responseCode;

  DnsServerException(DnsResponseCode code, const std::string &message)
      : DnsTransportException("DNS server error (" + std::to_string(static_cast<int>(code)) +
                              "): " + message),
        responseCode(code)
  {
  }
};

// Shared white-box test seam (SM-M1, tracker 2026-09-13-11): ONE friend struct reused by
// every DnsTransport test file (sid-keying, callback-deadlock, lifecycle-restructure),
// forward-declared here, befriended below, defined only by tests/network/
// dns_transport_test_access.hpp. Consolidates the accessors those files previously
// duplicated across three separate friend structs. No production code depends on it.
struct DnsTransportTestAccess;

/// \brief DNS transport implementation using Iora's Transport
class DnsTransport : public std::enable_shared_from_this<DnsTransport>
{
public:
  /// \brief DNS query callback for asynchronous operations (unified)
  using QueryCallback =
    std::function<void(const DnsResult &result, const std::exception_ptr &error)>;

  /// \brief Constructor with configuration.
  /// \warning A DnsTransport MUST be owned by a std::shared_ptr (construct via
  ///          std::make_shared<DnsTransport>(...)). start() calls shared_from_this()
  ///          when wiring the underlying Transport's callbacks; a stack- or
  ///          unique_ptr-owned instance throws std::bad_weak_ptr from start().
  explicit DnsTransport(const DnsConfig &config = {});

  /// \brief Destructor
  ~DnsTransport();

  /// \brief Start the transport
  /// \throws DnsTransportException on failure
  void start();

  /// \brief Stop the transport
  void stop();

  /// \brief Check if transport is running
  bool isRunning() const;

  /// \brief Send synchronous DNS query
  /// \param question DNS question to resolve
  /// \param server DNS server address (empty = use configured servers)
  /// \param port DNS server port (0 = use configured port)
  /// \return DNS query result
  /// \throws DnsTransportException, DnsTimeoutException, DnsServerException
  DnsResult query(const DnsQuestion &question, const std::string &server = "",
                  std::uint16_t port = 0);

  /// \brief Send asynchronous DNS query
  /// \param question DNS question to resolve
  /// \param callback Response callback
  /// \param server DNS server address (empty = use configured servers)
  /// \param port DNS server port (0 = use configured port)
  void queryAsync(const DnsQuestion &question, QueryCallback callback,
                  const std::string &server = "", std::uint16_t port = 0);

  /// \brief Send multiple questions in one query (synchronous)
  /// \param questions DNS questions to resolve
  /// \param server DNS server address (empty = use configured servers)
  /// \param port DNS server port (0 = use configured port)
  /// \return DNS query result
  DnsResult queryMultiple(const std::vector<DnsQuestion> &questions, const std::string &server = "",
                          std::uint16_t port = 0);

  /// \brief Update configuration
  void updateConfig(const DnsConfig &config);

  /// \brief Get current configuration snapshot.
  ///
  /// Returns a std::shared_ptr<const DnsConfig> (NOT a reference into a member): the
  /// config is atomic-published (INV-2, tracker 2026-09-13-11), so a `const DnsConfig&`
  /// accessor would dangle the instant a concurrent updateConfig() swaps the snapshot.
  /// The returned snapshot is immutable and pins its config for the caller's use.
  std::shared_ptr<const DnsConfig> getConfig() const { return loadConfig(); }

  /// \brief Get transport statistics (thread-safe atomic counters)
  struct Statistics
  {
    std::uint64_t totalQueries{0};
    std::uint64_t udpQueries{0};
    std::uint64_t tcpQueries{0};
    std::uint64_t tcpFallbacks{0};
    std::uint64_t timeouts{0};
    std::uint64_t retries{0};
    std::uint64_t errors{0};
    std::uint64_t truncatedResponses{0};
  };

  Statistics getStatistics() const;
  void resetStatistics();

private:
  // Shared white-box test seam: the DnsTransport regression tests drive the private
  // I/O-thread handlers and inspect the per-session / lifecycle state directly, so
  // sid-collision, callback-under-lock, and teardown-lifecycle scenarios reproduce
  // deterministically without real sockets or timing. Defined in tests/network/
  // dns_transport_test_access.hpp. Test-only; no production code path depends on it.
  friend struct DnsTransportTestAccess;

  /// \brief Composite key for pending queries to avoid ID collisions
  ///
  /// IMPORTANT: Server string normalization rules:
  /// - For pending queries: use raw server string (e.g., "8.8.8.8")
  /// - For session management: UDP uses "server:port", TCP uses "server:port:tcp"
  /// - QueryKey always uses (queryId, server, port) triple without transport suffix
  /// - Server strings must be consistent (same case, format) for proper lookup
  struct QueryKey
  {
    std::uint16_t queryId; ///< DNS query ID (unique per server:port)
    std::string server;    ///< DNS server address (normalized, no transport suffix)
    std::uint16_t port;    ///< DNS server port

    QueryKey(std::uint16_t id, const std::string &srv, std::uint16_t p)
        : queryId(id), server(srv), port(p)
    {
    }

    bool operator<(const QueryKey &other) const
    {
      if (queryId != other.queryId)
        return queryId < other.queryId;
      if (server != other.server)
        return server < other.server;
      return port < other.port;
    }

    bool operator==(const QueryKey &other) const
    {
      return queryId == other.queryId && server == other.server && port == other.port;
    }
  };

  /// \brief Pack (isTcp, sid) into one 64-bit value for PendingQuery::sentSession.
  ///
  /// Stored in a std::atomic<uint64_t> (lock-free -- no libatomic) so the (sid,isTcp)
  /// pair is never read torn during a UDP->TCP fallback: a torn pair could false-match a
  /// session close and spuriously fail a live query. SessionIds are minted from a
  /// monotonic counter starting at 1 (udp/tcp _nextSessionId) and never approach 2^63, so
  /// the top bit safely carries the protocol flag. Packed value 0 == never sent (a real
  /// session sid is always >= 1, so a never-sent query never matches a real close).
  static constexpr std::uint64_t SENT_TCP_BIT = 1ULL << 63;
  static std::uint64_t packSentSession(SessionId sid, bool isTcp)
  {
    assert(sid < SENT_TCP_BIT && "SessionId must not use bit 63 (packed protocol flag)");
    return (isTcp ? SENT_TCP_BIT : 0ULL) | static_cast<std::uint64_t>(sid);
  }

  /// \brief Pending query information
  ///
  /// THREAD SAFETY: This structure is accessed from multiple threads:
  /// - Main thread: creates and registers
  /// - Transport callbacks: reads for completion
  /// - Timer callbacks: modifies retryCount and startTime
  /// - Cleanup thread: reads for timeout detection
  struct PendingQuery
  {
    // Immutable fields - set once during construction, never modified
    const std::uint16_t queryId;
    const std::chrono::milliseconds timeout;
    const std::string server;
    const std::uint16_t port;
    const std::vector<std::uint8_t> queryData;

    // Mutable, single-writer fields (set once by the creating thread before
    // registration; not modified afterward).
    std::promise<DnsResult> promise;
    QueryCallback callback;
    DnsTransportMode transportMode;
    // tcpFallback: set true from the I/O thread (processResponse) under
    // _queriesMutex when a truncated UDP answer is retried over TCP; read under
    // _queriesMutex. NOT single-writer despite the group heading above.
    bool tcpFallback;

    // Thread-safe concurrent fields - accessed from multiple threads
    std::atomic<std::chrono::steady_clock::time_point> startTime;
    std::atomic<int> retryCount;
    std::atomic<std::uint64_t> activeTimerId{0}; // Currently scheduled retry timer (0 = none)
    // The session this query is currently bound to; written at each (re)send,
    // read by handleClose M-1. Packed atomic uint64 (see packSentSession) so the
    // (sid,isTcp) pair is never read torn; lock-free (no libatomic). 0 == never sent.
    std::atomic<std::uint64_t> sentSession{0};

    PendingQuery(std::uint16_t id, std::chrono::milliseconds to, const std::string &srv,
                 std::uint16_t prt, std::vector<std::uint8_t> data)
        : queryId(id), timeout(to), server(srv), port(prt), queryData(std::move(data)),
          transportMode(DnsTransportMode::UDP), tcpFallback(false),
          startTime(std::chrono::steady_clock::now()), retryCount(0)
    {
    }
  };

  /// \brief Send query using UDP transport
  void sendUdpQuery(std::shared_ptr<PendingQuery> query);

  /// \brief Send query using TCP transport
  void sendTcpQuery(std::shared_ptr<PendingQuery> query);

  /// \brief L-3 (tracker 2026-09-11-7): a cached session's send() failed because the
  /// engine reaped it without an onClose reaching handleClose. Evict the stale
  /// (isTcp,failedSid) mapping and reconnect, buffering \p query for handleConnect
  /// (rebinding its sentSession), instead of throwing. Runs on the caller/timer thread.
  /// Takes only _sessionsMutex (never _queriesMutex -- a caller may already hold it).
  /// \return true if the query was (re)buffered on a live/new session; false if the
  ///         transport is stopping or the reconnect failed (caller degrades to throw).
  bool reconnectStaleSession(const std::shared_ptr<PendingQuery> &query, bool isTcp,
                             SessionId failedSid);

  /// \brief Connect a new session to \p server : \p port and register it in
  /// _serverSessions/_sessionToServer. REQUIRES _sessionsMutex held. Re-checks
  /// _state==Running (tracker 2026-09-11-7 item 7) so a send racing stop() cannot
  /// resurrect the session maps after stop()'s clear. \return the new SessionId, or 0 if
  /// the transport is stopping/unavailable or connect() failed.
  SessionId connectAndRegisterSession(bool isTcp, const std::string &server, std::uint16_t port,
                                      const std::string &sk);

  /// \brief Idempotently buffer \p query for handleConnect on session \p sid (dedup L-2).
  /// REQUIRES _sessionsMutex held.
  void bufferOnConnect(bool isTcp, SessionId sid, const std::shared_ptr<PendingQuery> &query);

  /// \brief Frame \p query per protocol (TCP is length-prefixed) and send it on
  /// \p sessionId. Never called under a lock (copy-then-send). \return the transport
  /// send() result; the caller logs and relies on the already-scheduled timeout/retry on
  /// failure. Shared by handleConnect (drain) and reconnectStaleSession (send-now).
  bool sendQueryOnSession(const std::shared_ptr<Transport> &transport,
                          const std::shared_ptr<PendingQuery> &query, SessionId sessionId,
                          bool isTcp);

  /// \brief Handle incoming UDP data
  void handleUdpData(SessionId sessionId, iora::core::BufferView data,
                     std::chrono::steady_clock::time_point receiveTime);

  /// \brief Handle incoming TCP data
  void handleTcpData(SessionId sessionId, iora::core::BufferView data,
                     std::chrono::steady_clock::time_point receiveTime);

  /// \brief Handle transport connection events
  ///
  /// \param isTcp true when invoked by the TCP transport, false for UDP. Required
  ///        because the two engines mint colliding SessionIds and the same
  ///        handler is wired to both transports' onConnect/onClose callbacks; the
  ///        protocol bit disambiguates the per-session connect-deferral state and
  ///        selects the correct framing / transport when draining buffered queries.
  void handleConnect(SessionId sessionId, const TransportAddress &addr, bool isTcp);
  void handleClose(SessionId sessionId, const TransportErrorInfo &reason, bool isTcp);

  /// \brief Process DNS response
  void processResponse(const std::uint8_t *data, std::size_t size, DnsTransportMode mode,
                       const std::string &sourceServer, std::uint16_t sourcePort);

  /// \brief Complete pending query
  void completeQuery(const QueryKey &key, const DnsResult &result);
  void completeQuery(const QueryKey &key, const std::exception_ptr &error);

  /// \brief Atomically find+erase a pending query by key (returns nullptr if absent)
  std::shared_ptr<PendingQuery> takePending(const QueryKey &key);

  /// \brief Registration gate (NEW-6): insert \p query into _pendingQueries iff the
  /// transport is still Running, atomically under _queriesMutex. Returns false (no insert)
  /// when a concurrent stop() has left Running, so the caller fails the query fast. The
  /// _queriesMutex release/acquire carries stop()'s step-1 Stopping store, so a registration
  /// serialized after the drain observes non-Running and is refused — never orphaned.
  bool registerPendingIfRunning(const QueryKey &key, const std::shared_ptr<PendingQuery> &query);

  /// \brief Atomically claim and cancel a query's active retry timer, if any
  void cancelActiveTimer(const std::shared_ptr<PendingQuery> &query);

  /// \brief Fire one query's failure callback + promise (both exception-guarded)
  void failOne(const std::shared_ptr<PendingQuery> &query, const std::exception_ptr &error);

  /// \brief Fire a collected batch of query failures with no DnsTransport lock held
  void failCollected(const std::vector<std::shared_ptr<PendingQuery>> &queries,
                     const std::exception_ptr &error);

  /// \brief Fire one raw callback's failure (guarded), for sites with no PendingQuery yet
  void failCallback(const QueryCallback &callback, const std::exception_ptr &error);

  /// \brief Stop (join) a transport, skipping the throwing wrapper stop() on its own I/O
  /// thread (item 6). Does NOT reset -- teardown resets all handles only after every join.
  void stopTransportGuarded(std::shared_ptr<Transport> &transport);

  /// \brief Find pending query by response data (thread-safe)
  /// \param queryId Query ID from DNS response
  /// \param sourceServer Server that sent the response
  /// \param sourcePort Port that sent the response
  /// \return Shared pointer to pending query or nullptr if not found
  std::shared_ptr<PendingQuery> findPendingQuery(std::uint16_t queryId,
                                                 const std::string &sourceServer,
                                                 std::uint16_t sourcePort);

  /// \brief Retry query logic
  void retryQuery(std::shared_ptr<PendingQuery> query, const std::string &reason);

  /// \brief Cleanup expired queries
  void cleanupExpiredQueries();

  /// \brief Start cleanup timer
  void startCleanupTimer();
  /// \brief Schedule timeout timer for a query
  void scheduleQueryTimeout(std::shared_ptr<PendingQuery> query);

  /// \brief Get next DNS server from configured list
  DnsServer getNextServer();

  /// \brief Prepare query data
  std::vector<std::uint8_t> prepareQuery(const std::vector<DnsQuestion> &questions,
                                         std::uint16_t queryId);

  /// \brief Calculate total maximum wait time for synchronous queries including retries
  /// \return Maximum possible duration including initial timeout and all retry delays with jitter
  std::chrono::milliseconds calculateMaxSyncWaitTime() const;

  /// \brief Generate unique query ID for server:port combination
  /// \param server Target server
  /// \param port Target port
  /// \return Unique query ID that doesn't conflict with pending queries to same server
  std::uint16_t generateUniqueQueryId(const std::string &server, std::uint16_t port);

  /// \brief Get transport for mode
  std::shared_ptr<Transport> getTransport(DnsTransportMode mode);

  /// \brief Create UDP transport
  std::shared_ptr<Transport> createUdpTransport();

  /// \brief Create TCP transport
  std::shared_ptr<Transport> createTcpTransport();

  /// \brief Build the _serverSessions string key for a (server, port, protocol).
  ///        UDP => "server:port"; TCP => "server:port:tcp". Single source of the
  ///        ":tcp" suffix convention, reused by sendUdpQuery/sendTcpQuery/handleClose
  ///        so the protocol-qualified key is constructed identically everywhere.
  static std::string serverKey(const std::string &server, std::uint16_t port, bool isTcp);

  // ---------------------------------------------------------------------------
  // Lifecycle + atomic-published shared state (tracker 2026-09-13-11).
  //
  // INV-1 (single lifecycle atomic): _state subsumes the old _running flag.
  // INV-2 (atomic-published shared state): _config, _udpTransport, _tcpTransport and
  //   _timerService are held in iora::core::AtomicSharedPtr slots, published via the
  //   C++17 std::atomic_load/store/exchange free functions it wraps (std::atomic<shared_ptr>
  //   is C++20 — NOT used). The wrapper has NO raw accessor, so a read/write that bypasses
  //   the atomic idiom is a COMPILE error, not a silent data race — the grep gate is
  //   mechanical. Every reader snapshots ONCE into a local via the load* helpers below.
  //   _stateMutex does NOT guard these four members.
  // ---------------------------------------------------------------------------
  // Lifecycle states. PascalCase enumerators intentionally follow the established
  // lifecycle/mode-enum precedent (iora::common::LifecycleState, DnsTransportMode) rather
  // than the ALL_UPPERCASE R-NS-5 default — consistency with the sibling enums wins here
  // (human style call, 2026-09-15).
  enum class Lifecycle
  {
    Stopped,
    Starting,
    Running,
    Stopping
  };

  /// \brief Snapshot the atomic-published config (INV-2). Read ONCE per operation.
  std::shared_ptr<const DnsConfig> loadConfig() const { return _config.load(); }
  /// \brief Snapshot the atomic-published UDP transport handle (INV-2).
  std::shared_ptr<Transport> loadUdp() const { return _udpTransport.load(); }
  /// \brief Snapshot the atomic-published TCP transport handle (INV-2).
  std::shared_ptr<Transport> loadTcp() const { return _tcpTransport.load(); }
  /// \brief Snapshot the atomic-published timer-service handle (INV-2).
  std::shared_ptr<core::TimerService> loadTimer() const { return _timerService.load(); }

  /// \brief Is the calling thread one the in-progress teardown JOINS, or the teardown
  ///        driver itself? MUST be called with _stateMutex held (INV-3a, R3-C1 fix).
  ///
  /// The identities come from STABLE, member-INDEPENDENT sources so the exemption still
  /// fires after stop() has moved the cleanup thread out and is mid-join:
  ///   - driver: _stoppingThreadId, recorded under _stateMutex at CAS-to-Stopping;
  ///   - cleanup: _cleanupThreadId, a stamped AtomicThreadId set by the cleanup lambda at
  ///     entry (NOT _cleanupThread.get_id(), which stop() step 2 moves out before releasing);
  ///   - I/O: the LIVE transport handles (route B keeps them live until stop() step 8);
  ///   - timer: the LIVE timer handle's isOnTimerThread().
  /// Returns true => the caller must NEVER park on _stateCv (that would be the reborn
  /// callback-under-lock deadlock, now on the CV instead of the mutex).
  ///
  /// The stamped-id reads (_cleanupThreadId, and isOnIoThread/isOnTimerThread) are relaxed
  /// and need no happens-before of their own: each id is only ever equality-compared against
  /// its own stamping thread, so the comparison is self-consistent via that thread's program
  /// order (a false positive is impossible — no other thread's id can equal the stamper's).
  bool isTeardownExemptLocked(std::thread::id me) const
  {
    if (_stoppingThreadId != std::thread::id{} && me == _stoppingThreadId)
    {
      return true;
    }
    if (_cleanupThreadId.matches(me))
    {
      return true;
    }
    if (auto u = loadUdp())
    {
      if (u->isOnIoThread())
      {
        return true;
      }
    }
    if (auto t = loadTcp())
    {
      if (t->isOnIoThread())
      {
        return true;
      }
    }
    if (auto tm = loadTimer())
    {
      if (tm->isOnTimerThread())
      {
        return true;
      }
    }
    return false;
  }

  /// \brief Settle a failed start() to Stopped + notify. MUST be called with _stateMutex
  /// held (H-1): both start() catch clauses use it so a bring-up throw never strands
  /// Starting (which would hang every settled-predicate waiter forever).
  void settleStartFailureLocked()
  {
    _state.store(Lifecycle::Stopped, std::memory_order_release);
    _stateCv.notify_all();
  }

  // Configuration (atomic-published — INV-2). Access via loadConfig() / _config.store()
  // on updateConfig()/start(). The AtomicSharedPtr wrapper makes a raw access a compile
  // error (mechanical grep gate).
  iora::core::AtomicSharedPtr<const DnsConfig> _config;

  // Transport instances (atomic-published — INV-2). Access via loadUdp()/loadTcp() /
  // .store()/.exchange(); the wrapper forbids raw access at compile time.
  iora::core::AtomicSharedPtr<Transport> _udpTransport;
  iora::core::AtomicSharedPtr<Transport> _tcpTransport;

  // ---------------------------------------------------------------------------
  // LOCK ORDERING (HR-2) — acquire outer -> inner; never acquire an outer lock
  // while holding an inner one:
  //   _stateMutex  >  _cleanupMutex  >  _tcpBuffersMutex  >  _queriesMutex  >  _sessionsMutex
  //
  // OUTERMOST: _stateMutex (start/stop/updateConfig transitions). RESTRUCTURED (tracker
  // 2026-09-13-11): stop() no longer holds _stateMutex across the worker joins — that was
  // the callback-under-lock teardown deadlock. It now CASes to Stopping, snapshots the
  // handles, RELEASES _stateMutex, and joins the workers with NO lock held; a completion
  // latch on _stateCv (with a thread-identity exemption) restores the join-before-return
  // property the mutex used to give. So _stateMutex is co-held ONLY with _cleanupMutex (the
  // tiny flag store in stop() step 2) — establishing _stateMutex > _cleanupMutex — and with
  // nothing else. updateConfig is DE-LATCHED: it takes NO lifecycle lock at all (atomic
  // publish). NEVER acquire _stateMutex from inside any inner critical section — the query
  // hot paths read _state lock-free (acquire) and never take _stateMutex. The cleanup thread
  // takes _cleanupMutex ONLY for the CV wait (nothing inner held under it, and it never takes
  // _stateMutex), so the _stateMutex > _cleanupMutex edge is acyclic. stop() must NOT hold
  // _cleanupMutex across the cleanup-thread join (the thread needs it to exit wait_for): the
  // flag store is a tiny separate critical section, and notify + the join run outside it.
  //
  // INNER co-holds (at most two inner locks held at once): handleTcpData holds
  // _tcpBuffersMutex across _sessionsMutex (the _sessionToServer read) ONLY — it now
  // COLLECTS complete messages under _tcpBuffersMutex and calls processResponse ->
  // completeQuery (_queriesMutex) OUTSIDE the lock (item 1), so _tcpBuffersMutex is no
  // longer co-held with _queriesMutex. The cleanup thread releases _cleanupMutex before
  // cleanupExpiredQueries() (item 3), so _cleanupMutex is no longer co-held with
  // _queriesMutex. The UDP-truncation TCP fallback (processResponse, mode==UDP, reached
  // only from handleUdpData) holds _queriesMutex across sendTcpQuery's _sessionsMutex.
  // handleClose deliberately uses THREE sequential, NON-co-held critical sections
  // (_sessionsMutex, then _tcpBuffersMutex, then completeQuery's _queriesMutex) and MUST
  // NOT merge them: co-holding _sessionsMutex (acquired first, so outer) with
  // _tcpBuffersMutex or _queriesMutex (inner) would invert this order and can deadlock.
  // ---------------------------------------------------------------------------

  // State management (INV-1/INV-3, tracker 2026-09-13-11).
  // _state is the single lifecycle atomic (subsumes the old _running). _stateMutex +
  // _stateCv serialize lifecycle TRANSITIONS and provide the join-before-return
  // completion latch: a concurrent stop()/start()/dtor that observes a transient state
  // waits on _stateCv for a SETTLED state (Running||Stopped), UNLESS it is exempt
  // (isTeardownExemptLocked). _stoppingThreadId (guarded by _stateMutex) records the
  // teardown driver for the exemption. Query fast paths read _state lock-free (acquire);
  // they never take _stateMutex (no lock-order inversion against the hot path).
  std::atomic<Lifecycle> _state{Lifecycle::Stopped};
  mutable std::mutex _stateMutex;
  std::condition_variable _stateCv;
  std::thread::id _stoppingThreadId; // guarded by _stateMutex

  // Query management
  std::map<QueryKey, std::shared_ptr<PendingQuery>> _pendingQueries;
  mutable std::mutex _queriesMutex;

  // Server selection
  std::atomic<std::size_t> _serverIndex{0};

  // Statistics (thread-safe atomic counters)
  struct InternalStatistics
  {
    std::atomic<std::uint64_t> totalQueries{0};
    std::atomic<std::uint64_t> udpQueries{0};
    std::atomic<std::uint64_t> tcpQueries{0};
    std::atomic<std::uint64_t> tcpFallbacks{0};
    std::atomic<std::uint64_t> timeouts{0};
    std::atomic<std::uint64_t> retries{0};
    std::atomic<std::uint64_t> errors{0};
    std::atomic<std::uint64_t> truncatedResponses{0};
  } _stats;

  // Session management
  std::map<std::string, SessionId> _serverSessions; // server:port[:tcp] -> SessionId
  // (isTcp, SessionId) -> (server, port). Keyed by the protocol bit because the UDP
  // and TCP engines mint SessionIds from independent counters both starting at 1, so
  // a bare SessionId aliases a colliding UDP/TCP session pair (tracker 2026-09-11-5).
  std::map<std::pair<bool, SessionId>, std::pair<std::string, std::uint16_t>> _sessionToServer;
  mutable std::mutex _sessionsMutex;

  // Per-session connect-deferral state (CF-H1). The transport now REJECTS a send
  // to a session that is not yet registered/connected (sessionSendable == present
  // in the engine's _sessions AND !closed). connect() only enqueues the session;
  // it is inserted asynchronously on the I/O thread, and onConnect fires AFTER the
  // insert. So a query issued for a NEW or still-connecting session is buffered
  // here and (re)sent from handleConnect once the session is registered. Both
  // containers are guarded by _sessionsMutex (the same mutex guarding
  // _serverSessions/_sessionToServer); no lock is held across a transport->send().
  //
  // Keyed by (isTcp, SessionId): the UDP and TCP engines mint SessionIds from
  // independent counters (both start at 1 — see udp_engine.hpp/tcp_engine.hpp
  // _nextSessionId{1}), so a UDP sid and a TCP sid CAN collide. handleConnect is
  // shared by both transports and receives only the sid, so a bare-sid key would
  // let a UDP connect event drain a colliding TCP session's buffer (wrong framing,
  // session not yet connected) and vice versa. The protocol bit in the key makes
  // these structures collision-safe.
  std::set<std::pair<bool, SessionId>> _connectedSessions;
  std::map<std::pair<bool, SessionId>, std::vector<std::shared_ptr<PendingQuery>>>
    _pendingOnConnect;

  // TCP message framing (TCP DNS messages are length-prefixed)
  std::map<SessionId, std::deque<std::uint8_t>> _tcpBuffers;
  mutable std::mutex _tcpBuffersMutex;

  // Cleanup timer
  std::atomic<bool> _cleanupRunning{false};
  std::thread _cleanupThread;
  std::condition_variable _cleanupCv;
  std::mutex _cleanupMutex;
  // Resurrect-guard generation (H, INV / tracker 2026-09-13-11). startCleanupTimer()
  // bumps this and the new thread captures the fresh value; a stale detached cleanup
  // thread (self-stop path) observes a generation mismatch and exits even if a restart
  // has re-set _cleanupRunning=true, so at most one live sweeper survives a restart.
  std::atomic<std::uint64_t> _cleanupGeneration{0};
  // Live cleanup-thread count (incremented at each sweeper's loop entry, decremented at its
  // exit). Bounds how many sweepers are simultaneously alive — the observable the resurrect
  // guard exists to keep at 1. Read by the lifecycle test seam to assert a stale detached
  // sweeper has exited after a restart.
  std::atomic<int> _cleanupThreadCount{0};
  // Stamped, member-INDEPENDENT cleanup-thread identity for the teardown-latch exemption
  // (R3-C1). Stamped by the cleanup lambda at entry / clearIfCurrent() at exit; read by
  // isTeardownExemptLocked(). NOT _cleanupThread.get_id() (stop() moves that out before
  // releasing _stateMutex, so a re-entrant worker would read an emptied slot).
  iora::core::AtomicThreadId _cleanupThreadId;
  // Cleanup-sweep interval (item F / cpp17-LOW-1): production default 10s; the test seam
  // (DnsTransportTestAccess) shortens it so the running-instance probes finish in
  // sub-second bounds instead of ~15s. Set BEFORE start(); read only by the cleanup thread.
  std::chrono::milliseconds _cleanupInterval{std::chrono::seconds(10)};

  // Centralized RNG for retry jitter. Guarded by _rngMutex (TS-HIGH-1): although in steady
  // state only the single cleanup thread draws from it (via retryQuery), the resurrect
  // window can transiently overlap a stale detached sweeper with a fresh one — the
  // generation token bounds thread COUNT but does not preempt an in-flight sweep, so two
  // threads could draw concurrently. mt19937 is non-atomic, so an unguarded concurrent draw
  // is a data race (UB). _rngMutex is an INNERMOST leaf (nothing is acquired under it), so
  // it does not participate in the documented lock order.
  mutable std::mutex _rngMutex;
  mutable std::mt19937 _rng;

  // Timer service for efficient retry scheduling (atomic-published — INV-2). Access via
  // loadTimer() / _timerService.store()/.exchange(); the wrapper forbids raw access.
  iora::core::AtomicSharedPtr<core::TimerService> _timerService;
};

// ==================== Implementation ====================

inline DnsTransport::DnsTransport(const DnsConfig &config)
{
  if (config.servers.empty())
  {
    throw DnsTransportException("No DNS servers configured");
  }

  // DnsServer structures are already normalized via fromString()
  // No additional normalization needed

  // Publish the immutable config snapshot (INV-2). No other thread can observe this
  // object during construction, so the store is uniform-style rather than a
  // synchronization requirement here.
  _config.store(std::make_shared<const DnsConfig>(config));

  // Initialize RNG for jitter
  std::random_device rd;
  _rng.seed(rd());

  // Initialize (publish) the timer service for efficient retry scheduling. start()
  // re-creates it if a prior stop() cleared the handle (restart), and stop() joins it.
  core::TimerServiceConfig timerConfig;
  timerConfig.threadName = "DnsRetryTimer";
  timerConfig.enableStatistics = false; // Keep it lightweight
  _timerService.store(std::make_shared<core::TimerService>(timerConfig));
}

inline DnsTransport::~DnsTransport() { stop(); }

inline void DnsTransport::start()
{
  std::unique_lock<std::mutex> lock(_stateMutex);
  const std::thread::id me = std::this_thread::get_id();

  // Reach a decision: return (already running / exempt re-entry), or claim Starting.
  for (;;)
  {
    Lifecycle s = _state.load(std::memory_order_acquire);
    if (s == Lifecycle::Running)
    {
      return; // Already running
    }
    if (s == Lifecycle::Stopped)
    {
      _state.store(Lifecycle::Starting, std::memory_order_release);
      break;
    }
    // Starting || Stopping.
    if (isTeardownExemptLocked(me))
    {
      // A driver/worker re-entrant restart WHILE a teardown (or another start) is in
      // flight is a documented no-op (R3-L2): the caller runs on a thread the in-flight
      // transition joins, so it must never park on _stateCv (that is the reborn
      // callback-under-lock deadlock). The in-flight transition owns the outcome.
      return;
    }
    // A genuinely independent caller waits for a SETTLED state, then re-evaluates
    // (never a single transient target — a bare "until Stopped" hangs when this same
    // start() is what drives Starting->Running).
    _stateCv.wait(lock,
                  [this]
                  {
                    Lifecycle x = _state.load(std::memory_order_acquire);
                    return x == Lifecycle::Running || x == Lifecycle::Stopped;
                  });
  }

  // state == Starting, _stateMutex held. Bring-up on locals; publish only on full success.
  try
  {
    auto cfg = loadConfig();

    std::shared_ptr<Transport> udp;
    std::shared_ptr<Transport> tcp;
    if (cfg->transportMode == DnsTransportMode::UDP ||
        cfg->transportMode == DnsTransportMode::Both)
    {
      udp = createUdpTransport();
      auto sr = udp->start();
      if (sr.isErr())
      {
        throw DnsTransportException("Failed to start UDP transport: " + sr.error().message);
      }
    }

    if (cfg->transportMode == DnsTransportMode::TCP ||
        cfg->transportMode == DnsTransportMode::Both)
    {
      tcp = createTcpTransport();
      auto sr = tcp->start();
      if (sr.isErr())
      {
        throw DnsTransportException("Failed to start TCP transport: " + sr.error().message);
      }
    }

    // (Re)create the timer service if a prior stop() cleared the handle (restart). On a
    // first start the constructor's live service is kept.
    auto timer = loadTimer();
    if (!timer)
    {
      core::TimerServiceConfig timerConfig;
      timerConfig.threadName = "DnsRetryTimer";
      timerConfig.enableStatistics = false;
      timer = std::make_shared<core::TimerService>(timerConfig);
    }

    // Publish the handles (release), then flip to Running + notify + start the cleanup
    // sweeper — ALL in this one _stateMutex critical section (M-1: a woken stop() waiter
    // must not observe Running before startCleanupTimer has run / race it).
    _udpTransport.store(udp);
    _tcpTransport.store(tcp);
    _timerService.store(timer);
    _state.store(Lifecycle::Running, std::memory_order_release);
    _stateCv.notify_all();
    startCleanupTimer();
  }
  catch (const std::exception &e)
  {
    // H-1: NEVER strand Starting — a stranded Starting hangs every settled-predicate
    // waiter. Settle to Stopped + notify UNDER the lock, then rethrow. The partially
    // created transport locals are destroyed on unwind (never published to the members).
    settleStartFailureLocked();
    throw DnsTransportException("Failed to start DNS transport: " + std::string(e.what()));
  }
  catch (...)
  {
    // H-1 (ANY throw): a non-std exception must ALSO settle to Stopped + notify, never
    // strand Starting. Re-raise the original (no .what() to wrap).
    settleStartFailureLocked();
    throw;
  }
}

inline void DnsTransport::stop()
{
  // Release-before-join teardown with a completion latch (INV-3, tracker 2026-09-13-11).
  // The old design held _stateMutex across every worker join, so a worker whose fired
  // callback re-entered stop()/updateConfig() (which took _stateMutex) deadlocked. This
  // rewrite CASes to Stopping, snapshots the handles, RELEASES _stateMutex, THEN joins;
  // a re-entrant stop()/start() on a joined worker (or the driver itself) is EXEMPTED and
  // returns immediately instead of parking on _stateCv. Steps:
  //   (1) become the teardown driver (CAS Running->Stopping) or return/wait;
  //   (2) stop the cleanup sweeper (flag + notify) and MOVE its thread to a local;
  //   (3) snapshot the handles to locals, LEAVING the members live (route B / R3-C1) so
  //       the exemption's isOnIoThread/isOnTimerThread reach live objects during the join;
  //   (4) RELEASE _stateMutex;
  //   (5) join/detach the workers with NO lock held;
  //   (6) collect pending queries + clear session/buffer state;
  //   (7) FIRE the collected failures with NO lock held, BEFORE publishing Stopped (H-2);
  //   (8) re-lock: publish Stopped + null the handle members + notify, all under _stateMutex.
  std::vector<std::shared_ptr<PendingQuery>> toFail;
  std::shared_ptr<Transport> udp;
  std::shared_ptr<Transport> tcp;
  std::shared_ptr<core::TimerService> timer;
  std::thread cleanupLocal;
  bool timerStopped = false;

  {
    std::unique_lock<std::mutex> lock(_stateMutex);
    const std::thread::id me = std::this_thread::get_id();

    // Step 1 — reach a decision.
    for (;;)
    {
      Lifecycle s = _state.load(std::memory_order_acquire);
      if (s == Lifecycle::Stopped)
      {
        return; // Already stopped.
      }
      if (s == Lifecycle::Running)
      {
        _state.store(Lifecycle::Stopping, std::memory_order_release);
        _stoppingThreadId = me;
        break; // We are the teardown driver.
      }
      // Starting || Stopping.
      if (isTeardownExemptLocked(me))
      {
        // A joined worker (or the driver) re-entering stop() must NEVER park on _stateCv:
        // the join it would wait on can only complete after its own return (R3-C1).
        return;
      }
      _stateCv.wait(lock,
                    [this]
                    {
                      Lifecycle x = _state.load(std::memory_order_acquire);
                      return x == Lifecycle::Running || x == Lifecycle::Stopped;
                    });
      // Re-evaluate: a start() may have driven Starting->Running (we then tear that down).
    }

    // Step 2 — stop the cleanup sweeper. Flip the flag UNDER _cleanupMutex so the wakeup
    // cannot be lost against the cleanup thread's predicate re-check, notify, then MOVE the
    // thread to a local (joined lock-free at step 5). Do NOT hold _cleanupMutex across the
    // join. _cleanupThreadId (the stamped exemption id) is member-independent and survives
    // this move, so a re-entrant stop() from the cleanup thread is still exempt at step 1.
    {
      std::lock_guard<std::mutex> clk(_cleanupMutex);
      _cleanupRunning.store(false);
    }
    _cleanupCv.notify_all();
    cleanupLocal = std::move(_cleanupThread);

    // Step 3 — snapshot the handles into locals; LEAVE the members live (route B / R3-C1).
    udp = loadUdp();
    tcp = loadTcp();
    timer = loadTimer();
  } // Step 4 — _stateMutex RELEASED here.

  // Step 5 — join/detach the workers with NO DnsTransport lock held. A worker whose
  // callback re-enters stop()/updateConfig() now takes _stateMutex freely and is exempted.
  if (cleanupLocal.joinable())
  {
    // Self-join guard: stop() may run ON the cleanup thread (a fired sweep callback). A
    // thread cannot join itself; detach instead (it already observed _cleanupRunning==false).
    if (cleanupLocal.get_id() == std::this_thread::get_id())
    {
      cleanupLocal.detach();
    }
    else
    {
      cleanupLocal.join();
    }
  }
  if (timer)
  {
    try
    {
      timer->stop();
      timerStopped = true;
    }
    catch (...)
    {
      // Timer-arm self-join (tracker 2026-09-13-5): stop() reached from a fired timer
      // callback joins its own thread -> throws. Swallow and leave the timer member intact
      // (skip its null at step 8) — the deeper fix is -5's, out of scope here (INV-5).
    }
  }
  stopTransportGuarded(udp);
  stopTransportGuarded(tcp);

  // Step 6 — collect pending queries (do NOT fire) and clear session/buffer state.
  {
    std::lock_guard<std::mutex> qlock(_queriesMutex);
    toFail.reserve(_pendingQueries.size());
    for (auto &[key, query] : _pendingQueries)
    {
      toFail.push_back(query);
    }
    _pendingQueries.clear();
  }
  {
    // The buffered queries in _pendingOnConnect are also registered in _pendingQueries
    // (collected/failed above), so dropping the buffer here loses nothing.
    std::lock_guard<std::mutex> slock(_sessionsMutex);
    _serverSessions.clear();
    _sessionToServer.clear();
    _connectedSessions.clear();
    _pendingOnConnect.clear();
  }
  {
    std::lock_guard<std::mutex> tlock(_tcpBuffersMutex);
    _tcpBuffers.clear();
  }

  // Step 7 — FIRE the collected failures with NO lock held, BEFORE publishing Stopped
  // (H-2 ordering): a dtor/stop() waiter released by Stopped must not be able to destroy
  // _stateCv while a callback here is still running.
  auto error = std::make_exception_ptr(DnsTransportException("Transport stopped"));
  failCollected(toFail, error);

  // Step 8 — publish the terminal state + null the handle members + notify, all under
  // _stateMutex (notify-under-lock). Only now (after every join + callback) do the members
  // go null, so a genuinely external waiter released here observes a fully torn-down object.
  {
    std::lock_guard<std::mutex> lock(_stateMutex);
    _udpTransport.store(std::shared_ptr<Transport>{});
    _tcpTransport.store(std::shared_ptr<Transport>{});
    if (timerStopped)
    {
      // Timer-arm self-join leaves the member intact (INV-5): a stop() on the timer thread
      // did not actually join it, so nulling it would drop a still-live service.
      _timerService.store(std::shared_ptr<core::TimerService>{});
    }
    _stoppingThreadId = std::thread::id{};
    _state.store(Lifecycle::Stopped, std::memory_order_release);
    _stateCv.notify_all();
  }
}

inline bool DnsTransport::isRunning() const
{
  return _state.load(std::memory_order_acquire) == Lifecycle::Running;
}

inline DnsResult DnsTransport::query(const DnsQuestion &question, const std::string &server,
                                     std::uint16_t port)
{
  return queryMultiple({question}, server, port);
}

inline DnsResult DnsTransport::queryMultiple(const std::vector<DnsQuestion> &questions,
                                             const std::string &server, std::uint16_t port)
{
  if (!isRunning())
  {
    throw DnsTransportException("Transport not running");
  }

  if (questions.empty())
  {
    throw DnsTransportException("No questions provided");
  }

  auto cfg = loadConfig(); // INV-2: one config snapshot for this operation.

  // Determine target server and port
  DnsServer targetDnsServer;
  if (server.empty())
  {
    targetDnsServer = getNextServer();
  }
  else
  {
    // Parse provided server string or use provided port
    targetDnsServer = DnsServer::fromString(server);
    if (port != 0)
    {
      targetDnsServer.port = port; // Override port if explicitly provided
    }
  }

  std::string targetServer = targetDnsServer.address;
  std::uint16_t targetPort = targetDnsServer.port;

  // Generate unique query ID for this server:port combination
  std::uint16_t queryId = generateUniqueQueryId(targetServer, targetPort);
  auto queryData = prepareQuery(questions, queryId);

  // Create pending query with immutable fields (thread-safe constructor)
  auto query = std::make_shared<PendingQuery>(queryId, cfg->timeout, targetServer, targetPort,
                                              std::move(queryData));
  query->transportMode = cfg->transportMode;

  // Register pending query via the NEW-6 registration gate (closes -7's orphan-on-stop):
  // a query racing stop()'s drain either registers (and is drained/failed) or is refused
  // here — never orphaned past the drain.
  QueryKey key(queryId, targetServer, targetPort);
  if (!registerPendingIfRunning(key, query))
  {
    throw DnsTransportException("Transport stopped");
  }

  try
  {
    // Send initial query (UDP first if Both mode)
    if (cfg->transportMode == DnsTransportMode::TCP)
    {
      sendTcpQuery(query);
    }
    else
    {
      sendUdpQuery(query);
    }

    // Wait for response with proper retry window calculation
    auto future = query->promise.get_future();
    auto maxWaitTime = calculateMaxSyncWaitTime();
    iora::core::Logger::debug(
      "DNS sync query max wait time: " + std::to_string(maxWaitTime.count()) + "ms " +
      "(timeout=" + std::to_string(cfg->timeout.count()) + "ms, " +
      "retries=" + std::to_string(cfg->retryCount) + ")");
    auto status = future.wait_for(maxWaitTime);

    if (status == std::future_status::timeout)
    {
      // Count the timeout, then throw -- the single catch(...) below owns removal + timer
      // cancellation (simplification L1/L2: no separate erase here, no double-erase).
      _stats.timeouts.fetch_add(1, std::memory_order_relaxed);
      throw DnsTimeoutException("Query timeout after " + std::to_string(cfg->timeout.count()) +
                                "ms");
    }

    return future.get();
  }
  catch (...)
  {
    // Single cleanup path for every failure: remove from pending AND cancel the query's
    // still-scheduled retry/timeout timer (simplification L1 -- match the completeQuery
    // idiom; leaving the timer armed would fire a dead callback later).
    {
      std::lock_guard<std::mutex> lock(_queriesMutex);
      _pendingQueries.erase(key);
    }
    cancelActiveTimer(query);
    throw;
  }
}

inline void DnsTransport::queryAsync(const DnsQuestion &question, QueryCallback callback,
                                     const std::string &server, std::uint16_t port)
{
  if (!isRunning())
  {
    auto error = std::make_exception_ptr(DnsTransportException("Transport not running"));
    failCallback(callback, error);
    return;
  }

  auto cfg = loadConfig(); // INV-2: one config snapshot for this operation.

  // Determine target server and port
  DnsServer targetDnsServer;
  if (server.empty())
  {
    targetDnsServer = getNextServer();
  }
  else
  {
    // Parse provided server string or use provided port
    targetDnsServer = DnsServer::fromString(server);
    if (port != 0)
    {
      targetDnsServer.port = port; // Override port if explicitly provided
    }
  }

  std::string targetServer = targetDnsServer.address;
  std::uint16_t targetPort = targetDnsServer.port;

  // Generate unique query ID for this server:port combination
  std::uint16_t queryId = generateUniqueQueryId(targetServer, targetPort);
  auto queryData = prepareQuery({question}, queryId);

  // Create pending query with immutable fields (thread-safe constructor)
  auto query = std::make_shared<PendingQuery>(queryId, cfg->timeout, targetServer, targetPort,
                                              std::move(queryData));
  query->transportMode = cfg->transportMode;
  query->callback = std::move(callback);

  // Register pending query via the NEW-6 registration gate (see queryMultiple). On refusal
  // fire the callback OUTSIDE _queriesMutex (copy-then-invoke / HR-3).
  QueryKey key(queryId, targetServer, targetPort);
  if (!registerPendingIfRunning(key, query))
  {
    auto error = std::make_exception_ptr(DnsTransportException("Transport stopped"));
    failOne(query, error);
    return;
  }

  try
  {
    // Send query
    if (cfg->transportMode == DnsTransportMode::TCP)
    {
      sendTcpQuery(query);
    }
    else
    {
      sendUdpQuery(query);
    }
  }
  catch (const std::exception &e)
  {
    // Remove from pending and call callback with error
    {
      std::lock_guard<std::mutex> lock(_queriesMutex);
      _pendingQueries.erase(key);
    }

    auto error = std::make_exception_ptr(DnsTransportException(e.what()));
    failOne(query, error);
  }
}

inline std::shared_ptr<Transport> DnsTransport::createUdpTransport()
{
  TransportConfig config;

  auto transport = Transport::udp(config); // S-3: shared_ptr factory (sets protocol internally)

  // Capture a WEAK ref (not an owning shared_from_this()) and promote per-use. The
  // Transport is OWNED by this DnsTransport (_udpTransport/_tcpTransport), so an owning
  // capture here would form a DnsTransport<->Transport reference cycle that never
  // collects (~DnsTransport — which resets the transports — could never run). The arch
  // reference-cycle designPrinciple requires a weak_ptr promoted per-use. lock() also
  // makes a late callback during teardown a clean no-op.
  std::weak_ptr<DnsTransport> weak = shared_from_this();
  transport->onData(
    [weak](SessionId sid, iora::core::BufferView data,
           std::chrono::steady_clock::time_point receiveTime)
    { if (auto self = weak.lock()) { self->handleUdpData(sid, data, receiveTime); } });
  transport->onConnect(
    [weak](SessionId sid, const TransportAddress &addr)
    { if (auto self = weak.lock()) { self->handleConnect(sid, addr, /*isTcp=*/false); } });
  transport->onClose(
    [weak](SessionId sid, const TransportErrorInfo &reason)
    { if (auto self = weak.lock()) { self->handleClose(sid, reason, /*isTcp=*/false); } });
  transport->onError(
    [weak](TransportError, const std::string &)
    {
      // Handle transport-level errors
    });

  return transport;
}

inline std::shared_ptr<Transport> DnsTransport::createTcpTransport()
{
  TransportConfig config;

  auto transport = Transport::tcp(config); // S-3: shared_ptr factory (sets protocol internally)

  // Weak capture + per-use lock() — see createUdpTransport for the reference-cycle
  // rationale (DnsTransport owns the Transport; an owning self-capture would leak).
  std::weak_ptr<DnsTransport> weak = shared_from_this();
  transport->onData(
    [weak](SessionId sid, iora::core::BufferView data,
           std::chrono::steady_clock::time_point receiveTime)
    { if (auto self = weak.lock()) { self->handleTcpData(sid, data, receiveTime); } });
  transport->onConnect(
    [weak](SessionId sid, const TransportAddress &addr)
    { if (auto self = weak.lock()) { self->handleConnect(sid, addr, /*isTcp=*/true); } });
  transport->onClose(
    [weak](SessionId sid, const TransportErrorInfo &reason)
    { if (auto self = weak.lock()) { self->handleClose(sid, reason, /*isTcp=*/true); } });
  transport->onError(
    [weak](TransportError, const std::string &)
    {
      // Handle transport-level errors
    });

  return transport;
}

inline std::string DnsTransport::serverKey(const std::string &server, std::uint16_t port,
                                           bool isTcp)
{
  std::string key = server + ":" + std::to_string(port);
  if (isTcp)
  {
    key += ":tcp";
  }
  return key;
}

inline void DnsTransport::sendUdpQuery(std::shared_ptr<PendingQuery> query)
{
  auto udp = loadUdp(); // INV-2: one handle snapshot; a mid/post-stop send fails cleanly.
  if (!udp)
  {
    throw DnsTransportException("UDP transport not available");
  }

  // Log DNS query attempt for debugging server failover
  iora::core::Logger::info("DNS sending UDP query: ID=" + std::to_string(query->queryId) +
                           " server=" + query->server + ":" + std::to_string(query->port) +
                           " retry=" + std::to_string(query->retryCount));

  // Get or create session to DNS server
  std::string sk = serverKey(query->server, query->port, false);
  SessionId sessionId = 0;
  bool sendNow = false;

  {
    std::lock_guard<std::mutex> lock(_sessionsMutex);
    auto it = _serverSessions.find(sk);
    if (it != _serverSessions.end())
    {
      sessionId = it->second;
      // Cached session: send immediately only if it has already fired onConnect.
      // If it is still connecting, CF-H1 would reject an immediate send, so defer.
      sendNow = _connectedSessions.count(std::make_pair(false, sessionId)) != 0;
    }
    else
    {
      // New session. connectAndRegisterSession re-checks _state==Running under
      // _sessionsMutex (tracker 2026-09-11-7 item 7), so a cache-miss send racing stop()
      // cannot resurrect the session maps after stop()'s clear. connect() only enqueues
      // the session (registered async on the I/O thread); the send is deferred to
      // handleConnect (an immediate send would be rejected by CF-H1).
      sessionId = connectAndRegisterSession(false, query->server, query->port, sk);
      if (sessionId == 0)
      {
        throw DnsTransportException("Failed to connect to DNS server " + query->server);
      }
      sendNow = false;
    }

    if (!sendNow)
    {
      // Buffer while awaiting connect, populated under _sessionsMutex BEFORE release so
      // handleConnect cannot drain an empty buffer and lose this query.
      bufferOnConnect(false, sessionId, query);
    }
  }

  // Record the session this query is now bound to (sent-now OR buffered for
  // handleConnect), for handleClose M-1 fast-fail (tracker 2026-09-11-7).
  query->sentSession.store(packSentSession(sessionId, false), std::memory_order_relaxed);

  // copy-then-send: _sessionsMutex is released above; never send under the lock.
  if (sendNow)
  {
    bool sent = sendQueryOnSession(udp, query, sessionId, /*isTcp=*/false);
    if (sent)
    {
      iora::core::Logger::debug("DNS UDP query sent: ID=" + std::to_string(query->queryId) +
                                " to " + query->server + ":" + std::to_string(query->port) +
                                " size=" + std::to_string(query->queryData.size()) + "bytes");
    }
    else
    {
      // L-3 (tracker 2026-09-11-7): the cached session was reaped by the engine
      // without an onClose reaching handleClose. Reconnect + buffer for handleConnect
      // instead of throwing, then fall through to the shared scheduleQueryTimeout+stats
      // tail so the query is armed exactly once. Only throw if the transport is stopping.
      iora::core::Logger::debug("DNS UDP cached session " + std::to_string(sessionId) +
                                " send failed; reconnecting to " + query->server);
      if (!reconnectStaleSession(query, false, sessionId))
      {
        iora::core::Logger::error("DNS UDP query failed to send to " + query->server + ":" +
                                  std::to_string(query->port));
        throw DnsTransportException("Failed to send UDP query to " + query->server);
      }
    }
  }
  else
  {
    iora::core::Logger::debug(
      "DNS UDP query deferred until connect: ID=" + std::to_string(query->queryId) + " to " +
      query->server + ":" + std::to_string(query->port) +
      " size=" + std::to_string(query->queryData.size()) + "bytes");
  }

  // Schedule timeout timer + stats whether sent now or deferred, so a session that
  // never connects still times out (and is retried by the cleanup thread) and the
  // deferred send in handleConnect does NOT double-count stats or reschedule.
  scheduleQueryTimeout(query);

  // Atomic increments - no mutex needed
  _stats.totalQueries.fetch_add(1, std::memory_order_relaxed);
  _stats.udpQueries.fetch_add(1, std::memory_order_relaxed);
}

inline void DnsTransport::sendTcpQuery(std::shared_ptr<PendingQuery> query)
{
  auto tcp = loadTcp(); // INV-2: one handle snapshot; a mid/post-stop send fails cleanly.
  if (!tcp)
  {
    throw DnsTransportException("TCP transport not available");
  }

  // Get or create session to DNS server
  std::string sk = serverKey(query->server, query->port, true);
  SessionId sessionId = 0;
  bool sendNow = false;

  {
    std::lock_guard<std::mutex> lock(_sessionsMutex);
    auto it = _serverSessions.find(sk);
    if (it != _serverSessions.end())
    {
      sessionId = it->second;
      // Cached session: send immediately only if it has already fired onConnect.
      // If it is still connecting, CF-H1 would reject an immediate send, so defer.
      sendNow = _connectedSessions.count(std::make_pair(true, sessionId)) != 0;
    }
    else
    {
      // New session. connectAndRegisterSession re-checks _state==Running under
      // _sessionsMutex (tracker 2026-09-11-7 item 7), so a cache-miss send racing stop()
      // cannot resurrect the session maps after stop()'s clear. connect() only enqueues
      // the session; TCP needs the 3-way handshake before onConnect fires, so the send
      // is deferred to handleConnect (an immediate send would be rejected by CF-H1).
      sessionId = connectAndRegisterSession(true, query->server, query->port, sk);
      if (sessionId == 0)
      {
        throw DnsTransportException("Failed to connect to DNS server " + query->server);
      }
      sendNow = false;
    }

    if (!sendNow)
    {
      // Buffer while awaiting connect (populated under the lock before release, so
      // handleConnect cannot drain an empty buffer). handleConnect re-frames with the
      // 2-byte length prefix, exactly as the immediate-send path below does.
      bufferOnConnect(true, sessionId, query);
    }
  }

  // Record the session this query is now bound to (sent-now OR buffered for
  // handleConnect), for handleClose M-1 fast-fail (tracker 2026-09-11-7).
  query->sentSession.store(packSentSession(sessionId, true), std::memory_order_relaxed);

  // TCP DNS messages are length-prefixed
  std::uint16_t length = static_cast<std::uint16_t>(query->queryData.size());

  // copy-then-send: _sessionsMutex is released above; never send under the lock.
  if (sendNow)
  {
    bool sent = sendQueryOnSession(tcp, query, sessionId, /*isTcp=*/true);
    if (sent)
    {
      iora::core::Logger::debug("DNS TCP query sent: ID=" + std::to_string(query->queryId) +
                                " to " + query->server + ":" + std::to_string(query->port) +
                                " size=" + std::to_string(length) + "bytes (+2 length prefix)");
    }
    else
    {
      // L-3 (tracker 2026-09-11-7): reconnect a reaped cached session + buffer for
      // handleConnect instead of throwing; fall through to the shared timeout+stats
      // tail. Only throw if the transport is stopping (degrade).
      iora::core::Logger::debug("DNS TCP cached session " + std::to_string(sessionId) +
                                " send failed; reconnecting to " + query->server);
      if (!reconnectStaleSession(query, true, sessionId))
      {
        iora::core::Logger::error("DNS TCP query failed to send to " + query->server + ":" +
                                  std::to_string(query->port));
        throw DnsTransportException("Failed to send TCP query to " + query->server);
      }
    }
  }
  else
  {
    iora::core::Logger::debug(
      "DNS TCP query deferred until connect: ID=" + std::to_string(query->queryId) + " to " +
      query->server + ":" + std::to_string(query->port) +
      " size=" + std::to_string(length) + "bytes");
  }

  // Schedule timeout timer for this query (whether sent now or deferred)
  scheduleQueryTimeout(query);

  // Atomic increments - no mutex needed
  _stats.totalQueries.fetch_add(1, std::memory_order_relaxed);
  _stats.tcpQueries.fetch_add(1, std::memory_order_relaxed);
  if (query->tcpFallback)
  {
    _stats.tcpFallbacks.fetch_add(1, std::memory_order_relaxed);
    iora::core::Logger::debug(
      "DNS TCP fallback completed for query ID=" + std::to_string(query->queryId) +
      " server=" + query->server + ":" + std::to_string(query->port));
  }
}

inline SessionId DnsTransport::connectAndRegisterSession(bool isTcp, const std::string &server,
                                                         std::uint16_t port, const std::string &sk)
{
  // REQUIRES _sessionsMutex held by the caller.
  // State gate (tracker 2026-09-11-7 item 7): re-check under _sessionsMutex so a send
  // racing stop() cannot resurrect the session maps after stop()'s step-6 clear. stop()
  // stores a non-Running lifecycle (release) before clearing the maps under the same
  // mutex, so an insert here either precedes the clear (and is wiped) or observes
  // non-Running (and is rejected).
  if (_state.load(std::memory_order_acquire) != Lifecycle::Running)
  {
    return 0;
  }
  auto transport = isTcp ? loadTcp() : loadUdp();
  if (!transport)
  {
    return 0;
  }
  auto cr = transport->connect(server, port, TlsMode::None);
  if (cr.isErr())
  {
    return 0;
  }
  const SessionId sid = cr.value();
  _serverSessions[sk] = sid;
  _sessionToServer[std::make_pair(isTcp, sid)] = {server, port};
  return sid;
}

inline void DnsTransport::bufferOnConnect(bool isTcp, SessionId sid,
                                          const std::shared_ptr<PendingQuery> &query)
{
  // REQUIRES _sessionsMutex held. Dedup (L-2): a retry timer can re-issue a query while
  // the session is still connecting; buffering twice would double-send on connect.
  auto &bucket = _pendingOnConnect[std::make_pair(isTcp, sid)];
  if (std::find(bucket.begin(), bucket.end(), query) == bucket.end())
  {
    bucket.push_back(query);
  }
}

inline bool DnsTransport::reconnectStaleSession(const std::shared_ptr<PendingQuery> &query,
                                                bool isTcp, SessionId failedSid)
{
  const std::string sk = serverKey(query->server, query->port, isTcp);
  SessionId targetSid = 0;
  bool sendNowOnTarget = false;
  {
    std::lock_guard<std::mutex> lock(_sessionsMutex);
    // State gate (tracker 2026-09-11-7 H-2): never resurrect per-session state after
    // stop() has begun. stop() stores a non-Running lifecycle BEFORE it clears the
    // session maps under _sessionsMutex, so reading _state inside this same critical
    // section serializes against that clear -- an insert here either precedes the clear
    // (and is wiped) or observes non-Running (and degrades). connectAndRegisterSession
    // re-checks it too; this top gate additionally guards the peer-recreated buffer path.
    if (_state.load(std::memory_order_acquire) != Lifecycle::Running)
    {
      return false;
    }
    auto it = _serverSessions.find(sk);
    if (it != _serverSessions.end() && it->second != failedSid)
    {
      // Peer-recreated: a concurrent path already evicted+recreated the session between
      // our unlocked send()==false and here. Do NOT connect() again. If the current
      // session is ALREADY connected, send immediately below (copy-then-send), mirroring
      // the normal cached path -- buffering onto an already-connected session is a
      // dead-end until timeout, since handleConnect only drains on the onConnect that
      // already fired (tracker 2026-09-11-7 L-3 peer-recreated edge, Fix B).
      targetSid = it->second;
      sendNowOnTarget = _connectedSessions.count(std::make_pair(isTcp, targetSid)) != 0;
    }
    else
    {
      // The stale session is still mapped (or already gone): evict the three per-session
      // maps keyed on (isTcp,failedSid), then reconnect. A fresh session is never yet
      // connected, so it is always buffered for handleConnect.
      if (it != _serverSessions.end())
      {
        _serverSessions.erase(it);
      }
      _connectedSessions.erase(std::make_pair(isTcp, failedSid));
      _sessionToServer.erase(std::make_pair(isTcp, failedSid));

      targetSid = connectAndRegisterSession(isTcp, query->server, query->port, sk);
      if (targetSid == 0)
      {
        return false; // transport gone / connect failed -- caller reports the send failure
      }
    }

    // Buffer for handleConnect (dedup) unless we will send immediately below.
    if (!sendNowOnTarget)
    {
      bufferOnConnect(isTcp, targetSid, query);
    }
  }
  // Rebind the query to the (re)connected session so a later handleClose selects it by
  // exact sender session (M-1).
  query->sentSession.store(packSentSession(targetSid, isTcp), std::memory_order_relaxed);

  // copy-then-send: send immediately on an already-connected peer-recreated session. A
  // send failure is left to the already-scheduled timeout/retry (as handleConnect does).
  if (sendNowOnTarget)
  {
    auto transport = isTcp ? loadTcp() : loadUdp();
    if (!transport)
    {
      return false; // transport stopping -- degrade (the query is covered by stop()'s drain)
    }
    if (!sendQueryOnSession(transport, query, targetSid, isTcp))
    {
      iora::core::Logger::error("DNS reconnect send-now failed on peer-recreated session: ID=" +
                                std::to_string(query->queryId) + " to " + query->server + ":" +
                                std::to_string(query->port) + (isTcp ? " (TCP)" : " (UDP)"));
    }
  }
  return true;
}

inline void DnsTransport::handleUdpData(SessionId sessionId, iora::core::BufferView data,
                                        std::chrono::steady_clock::time_point)
{
  // Look up server and port for this session
  std::string server;
  std::uint16_t port;
  {
    std::lock_guard<std::mutex> lock(_sessionsMutex);
    auto it = _sessionToServer.find(std::make_pair(false, sessionId));
    if (it != _sessionToServer.end())
    {
      server = it->second.first;
      port = it->second.second;
    }
    else
    {
      iora::core::Logger::error("DNS UDP response from unknown session ID " +
                                std::to_string(sessionId));
      return;
    }
  }

  processResponse(data.data(), data.size(), DnsTransportMode::UDP, server, port);
}

inline void DnsTransport::handleTcpData(SessionId sessionId, iora::core::BufferView data,
                                        std::chrono::steady_clock::time_point)
{
  // F-2 (RESOLVED-SAFE): the _tcpTransport->close(sessionId) calls below run from
  // inside this onData callback (the I/O thread). This is SAFE because
  // Transport::close(sid) is ENQUEUE-ONLY — TcpEngine::close() is
  // `return enqueue(Command::close(sid));` (detail/tcp_engine.hpp), taking no
  // dispatch-path lock; the close is processed on the next loop iteration. No
  // re-entrant lock, no deadlock. If a future engine change makes close()
  // synchronous, revisit these in-onData close sites.
  // TCP DNS messages are length-prefixed, may arrive in fragments. F-2 (tracker
  // 2026-09-11-6 item 1): COLLECT every complete message under _tcpBuffersMutex into a
  // local, then processResponse each OUTSIDE the lock -- mirroring handleUdpData -- so a
  // user callback is never invoked while _tcpBuffersMutex (which blocks the whole TCP
  // receive path) is held (HR-3 lock-across-user-code / cross-thread ABBA).
  struct ReadyMessage
  {
    std::vector<std::uint8_t> bytes;
    std::string server;
    std::uint16_t port;
  };
  std::vector<ReadyMessage> ready;

  // INV-2 snapshots: one config + one TCP-handle snapshot for this call. A null handle
  // (transport torn down by a concurrent stop()) makes the close sites clean no-ops.
  auto cfg = loadConfig();
  auto tcp = loadTcp();

  {
    std::lock_guard<std::mutex> lock(_tcpBuffersMutex);
    auto &buffer = _tcpBuffers[sessionId];

    // Prevent unbounded buffer growth using configured limit
    if (buffer.size() + data.size() > cfg->maxTcpBufferSize)
    {
      // Clear buffer and close session on excessive buffer growth. Nothing has been
      // collected yet, so an early return here drops no completions.
      buffer.clear();
      if (tcp)
      {
        tcp->close(sessionId);
      }
      return;
    }

    buffer.insert(buffer.end(), data.data(), data.data() + data.size());

    // Frame-abort cleanup shared by the length-validation branches (simplification L3):
    // clear the buffer + close the session. Callers BREAK (not return) so any messages
    // already collected this call are still fired below (no-drop).
    auto abortFraming = [&]()
    {
      buffer.clear();
      if (tcp)
      {
        tcp->close(sessionId);
      }
    };

    // Process complete messages
    while (buffer.size() >= 2)
    {
      std::uint16_t messageLength = (buffer[0] << 8) | buffer[1];

      // A zero-length TCP frame is invalid. (messageLength is std::uint16_t, so the RFC-1035
      // 65535 maximum is a structural upper bound it can never exceed -- cpp17-L4: the old
      // "> 65535" / "> SIZE_MAX-2" guards were always false and are removed.)
      if (messageLength == 0)
      {
        abortFraming();
        break;
      }

      // Reject a frame larger than the configured TCP buffer cap.
      if (messageLength > cfg->maxTcpBufferSize)
      {
        iora::core::Logger::error(
          "DNS TCP message too large: " + std::to_string(messageLength) +
          " bytes, max=" + std::to_string(cfg->maxTcpBufferSize));
        abortFraming();
        break;
      }

      if (buffer.size() < 2 + static_cast<std::size_t>(messageLength))
      {
        // Incomplete message, wait for more data
        break;
      }

      // Complete message available - look up server and port
      std::string server;
      std::uint16_t port;
      {
        std::lock_guard<std::mutex> slock(_sessionsMutex);
        auto it = _sessionToServer.find(std::make_pair(true, sessionId));
        if (it != _sessionToServer.end())
        {
          server = it->second.first;
          port = it->second.second;
        }
        else
        {
          iora::core::Logger::error("DNS TCP response from unknown session ID " +
                                    std::to_string(sessionId));
          // Remove processed message from buffer using deque's efficient pop_front.
          // Pop-and-skip WITHOUT adding to `ready` (keep it out of the fired set).
          for (std::size_t i = 0; i < 2 + static_cast<std::size_t>(messageLength); ++i)
          {
            buffer.pop_front();
          }
          continue;
        }
      }

      // Collect the complete message (owned copy) + its resolved (server,port).
      ready.push_back(ReadyMessage{
        std::vector<std::uint8_t>(buffer.begin() + 2, buffer.begin() + 2 + messageLength),
        std::move(server), port});

      // Remove processed message from buffer using deque's efficient pop_front
      for (std::size_t i = 0; i < 2 + static_cast<std::size_t>(messageLength); ++i)
      {
        buffer.pop_front();
      }
    }
  } // _tcpBuffersMutex released before firing

  // Fire outside _tcpBuffersMutex, in arrival order.
  for (auto &m : ready)
  {
    processResponse(m.bytes.data(), m.bytes.size(), DnsTransportMode::TCP, m.server, m.port);
  }
}

inline void DnsTransport::processResponse(const std::uint8_t *data, std::size_t size,
                                          DnsTransportMode mode, const std::string &sourceServer,
                                          std::uint16_t sourcePort)
{
  bool parsed = false;
  try
  {
    DnsResult result = DnsMessage::parse(data, size);
    parsed = true; // the parse stage succeeded -- a later throw is NOT a parse error
    QueryKey key(result.header.id, sourceServer, sourcePort);

    // Check for truncation (UDP only)
    if (mode == DnsTransportMode::UDP && result.isTruncated())
    {
      // Atomic increment - no mutex needed
      _stats.truncatedResponses.fetch_add(1, std::memory_order_relaxed);

      iora::core::Logger::debug(
        "DNS response truncated (TC=1) for query ID=" + std::to_string(result.header.id) +
        " from " + sourceServer + ":" + std::to_string(sourcePort));

      // Find and retry with TCP if configured
      if (loadConfig()->transportMode == DnsTransportMode::Both)
      {
        std::lock_guard<std::mutex> lock(_queriesMutex);
        auto it = _pendingQueries.find(key);
        if (it != _pendingQueries.end() && !it->second->tcpFallback)
        {
          iora::core::Logger::debug("Initiating TCP fallback for truncated response, query ID=" +
                                    std::to_string(result.header.id));
          it->second->tcpFallback = true;
          sendTcpQuery(it->second);
          return; // Don't complete the query yet
        }
      }
      else
      {
        iora::core::Logger::warning("DNS response truncated but TCP fallback not enabled");
      }
    }

    iora::core::Logger::debug("DNS response received: ID=" + std::to_string(result.header.id) +
                              " from " + sourceServer + ":" + std::to_string(sourcePort) + " via " +
                              (mode == DnsTransportMode::TCP ? "TCP" : "UDP") +
                              " rcode=" + std::to_string(static_cast<int>(result.header.rcode)) +
                              " answers=" + std::to_string(result.header.ancount));
    completeQuery(key, result);
  }
  catch (const DnsTransportException &e)
  {
    // A send failure surfaced from the truncation TCP-fallback path (sendTcpQuery ->
    // L-3 reconnect failed, tracker 2026-09-11-7) unwinds here. The parse SUCCEEDED (we
    // have a valid response header), so this is NOT a parse error -- complete the query
    // with the ORIGINAL transport error rather than mislabeling it as DnsParseException.
    iora::core::Logger::warning("DNS TCP-fallback send failed for response from " + sourceServer +
                                ":" + std::to_string(sourcePort) + ": " + e.what());
    if (size >= 2)
    {
      std::uint16_t queryId = (data[0] << 8) | data[1];
      completeQuery(QueryKey(queryId, sourceServer, sourcePort), std::current_exception());
    }
  }
  catch (const std::exception &e)
  {
    iora::core::Logger::warning("DNS response parse failed from " + sourceServer + ":" +
                                std::to_string(sourcePort) + " (" + std::to_string(size) +
                                " bytes): " + e.what());

    // If we can extract query ID from malformed response, complete that query
    if (size >= 2)
    {
      std::uint16_t queryId = (data[0] << 8) | data[1];
      QueryKey key(queryId, sourceServer, sourcePort);
      // A post-parse throw that reaches here (parsed==true; a DnsTransportException is
      // already handled by the catch above) is NOT a parse error -- surface the raw
      // exception rather than mislabeling it DnsParseException (tracker 2026-09-11-7 L-2).
      auto error = parsed ? std::current_exception()
                          : std::make_exception_ptr(DnsParseException(e.what()));
      completeQuery(key, error);
    }
    else
    {
      iora::core::Logger::error("DNS response too short to extract query ID from " + sourceServer +
                                ":" + std::to_string(sourcePort));
    }
  }
}

// handleTransportError removed — new Transport API delivers errors via onClose/onError
// callbacks, not via data callback IoResult. The onClose handler (handleClose) cleans up
// sessions; the onError handler can be enhanced to retry pending queries if needed.

inline bool DnsTransport::sendQueryOnSession(const std::shared_ptr<Transport> &transport,
                                             const std::shared_ptr<PendingQuery> &query,
                                             SessionId sessionId, bool isTcp)
{
  // copy-then-send: never called under a lock. Frame per protocol (sids can collide
  // across the two engines, so the protocol bit selects the framing + transport).
  if (isTcp)
  {
    // TCP DNS messages are length-prefixed (same framing as sendTcpQuery).
    std::vector<std::uint8_t> tcpMessage;
    const std::uint16_t length = static_cast<std::uint16_t>(query->queryData.size());
    tcpMessage.push_back((length >> 8) & 0xFF);
    tcpMessage.push_back(length & 0xFF);
    tcpMessage.insert(tcpMessage.end(), query->queryData.begin(), query->queryData.end());
    return transport->send(sessionId, tcpMessage.data(), tcpMessage.size());
  }
  return transport->send(sessionId, query->queryData.data(), query->queryData.size());
}

inline void DnsTransport::handleConnect(SessionId sessionId, const TransportAddress &, bool isTcp)
{
  // Runs on the transport I/O thread AFTER the engine has registered the session,
  // so a send() here passes CF-H1's sessionSendable check. Mark the session
  // connected and drain any queries buffered while it was connecting.
  std::vector<std::shared_ptr<PendingQuery>> toSend;
  {
    std::lock_guard<std::mutex> lock(_sessionsMutex);
    _connectedSessions.insert(std::make_pair(isTcp, sessionId));
    auto it = _pendingOnConnect.find(std::make_pair(isTcp, sessionId));
    if (it != _pendingOnConnect.end())
    {
      toSend = std::move(it->second);
      _pendingOnConnect.erase(it);
    }
  }

  if (toSend.empty())
  {
    return;
  }

  // copy-then-send: _sessionsMutex released above; never send under the lock.
  // Select the transport + framing from the protocol bit (sids can collide across
  // the two engines, so we must not send a UDP datagram on the TCP transport or
  // vice versa). Timeout/stats were already handled when the query was buffered,
  // so a send failure here is left to the already-scheduled timeout/retry path.
  std::shared_ptr<Transport> transport = isTcp ? loadTcp() : loadUdp(); // INV-2 snapshot
  if (!transport)
  {
    return; // Transport torn down; buffered queries will time out.
  }

  for (auto &query : toSend)
  {
    // Skip a query that already completed/timed-out while buffered (L-1): sending it
    // would be a wasted DNS query (its late response is dropped as "unknown query").
    {
      std::lock_guard<std::mutex> qlock(_queriesMutex);
      if (_pendingQueries.find(QueryKey(query->queryId, query->server, query->port)) ==
          _pendingQueries.end())
      {
        continue;
      }
    }
    const bool sent = sendQueryOnSession(transport, query, sessionId, isTcp);

    if (!sent)
    {
      iora::core::Logger::error(
        "DNS deferred query failed to send on connect: ID=" + std::to_string(query->queryId) +
        " to " + query->server + ":" + std::to_string(query->port) +
        (isTcp ? " (TCP)" : " (UDP)"));
      // Leave it to the scheduled timeout/retry — do not throw on the I/O thread.
    }
    else
    {
      iora::core::Logger::debug(
        "DNS deferred query sent on connect: ID=" + std::to_string(query->queryId) + " to " +
        query->server + ":" + std::to_string(query->port) + (isTcp ? " (TCP)" : " (UDP)"));
    }
  }
}

inline void DnsTransport::handleClose(SessionId sessionId, const TransportErrorInfo &, bool isTcp)
{
  std::vector<std::shared_ptr<PendingQuery>> orphaned;

  // Remove closed sessions from mappings. PROTOCOL-AWARE teardown (tracker
  // 2026-09-11-5): _sessionToServer is keyed by (isTcp,sid) and _serverSessions by a
  // protocol-qualified string key, so a colliding sibling session of the OTHER
  // protocol (same bare sid) must NOT be torn down. Reconstruct the exact serverKey
  // from the (isTcp,sid) mapping BEFORE erasing it (erasing first would make the
  // lookup miss and leak the _serverSessions entry -> later dead-sid reuse).
  {
    std::lock_guard<std::mutex> lock(_sessionsMutex);
    auto sit = _sessionToServer.find(std::make_pair(isTcp, sessionId));
    if (sit != _sessionToServer.end())
    {
      auto sk = serverKey(sit->second.first, sit->second.second, isTcp);
      auto ssit = _serverSessions.find(sk);
      if (ssit != _serverSessions.end() && ssit->second == sessionId)
      {
        _serverSessions.erase(ssit);
      }
      _sessionToServer.erase(sit); // erase LAST, after serverKey reconstruction
    }

    // Drop the per-session connect-deferral state (keyed by protocol+sid). Take
    // ownership of any queries still awaiting connect so they can be failed after
    // the lock is released (copy-then-invoke).
    _connectedSessions.erase(std::make_pair(isTcp, sessionId));
    auto pit = _pendingOnConnect.find(std::make_pair(isTcp, sessionId));
    if (pit != _pendingOnConnect.end())
    {
      orphaned = std::move(pit->second);
      _pendingOnConnect.erase(pit);
    }
  }

  // Clean up TCP buffers. _tcpBuffers is a TCP-only map (populated solely by
  // handleTcpData with TCP sids), so a UDP close must NOT erase a colliding live TCP
  // session's partially-reassembled message (tracker 2026-09-11-5).
  if (isTcp)
  {
    std::lock_guard<std::mutex> lock(_tcpBuffersMutex);
    _tcpBuffers.erase(sessionId);
  }

  // Fail (do not silently drop) any query buffered on a session that closed before
  // connecting. completeQuery takes _queriesMutex (never held with _sessionsMutex)
  // and is a no-op for a query already completed/timed-out, so a stale buffered
  // entry is harmless. This mirrors the existing "failed to send" error handling.
  if (!orphaned.empty())
  {
    auto error = std::make_exception_ptr(DnsTransportException(
      "DNS session closed before connect (" + std::string(isTcp ? "TCP" : "UDP") + ")"));
    for (auto &query : orphaned)
    {
      completeQuery(QueryKey(query->queryId, query->server, query->port), error);
    }
  }

  // M-1 (tracker 2026-09-11-7): fast-fail already-SENT in-flight queries bound to the
  // closed session, instead of letting them linger until their per-query timeout. A
  // query is selected by EXACT sender session (sentSession == (isTcp,sessionId)), which
  // avoids failing a sibling query on the OTHER protocol or a DIFFERENT live session to
  // the same server:port (QueryKey carries no session discriminator). Lock discipline:
  // collect keys under _queriesMutex as a SEPARATE, non-co-held critical section (the
  // _sessionsMutex section above is already released), then fire completeQuery OUTSIDE
  // the lock -- it re-takes _queriesMutex via takePending (exactly-once erase + timer
  // cancel) and no-ops for a query a concurrent path already completed.
  std::vector<QueryKey> inFlightKeys;
  {
    std::lock_guard<std::mutex> lock(_queriesMutex);
    const std::uint64_t closedPacked = packSentSession(sessionId, isTcp);
    for (const auto &kv : _pendingQueries)
    {
      if (kv.second->sentSession.load(std::memory_order_relaxed) == closedPacked)
      {
        inFlightKeys.push_back(kv.first);
      }
    }
  }
  if (!inFlightKeys.empty())
  {
    auto error = std::make_exception_ptr(DnsTransportException(
      "DNS session closed (" + std::string(isTcp ? "TCP" : "UDP") + ") with in-flight query"));
    for (const auto &key : inFlightKeys)
    {
      completeQuery(key, error);
    }
  }
}

inline DnsServer DnsTransport::getNextServer()
{
  // INV-2 (L-1): pin ONE config snapshot so the size, the index, and the element are read
  // from the same immutable servers vector — a concurrent updateConfig() cannot tear it.
  auto cfg = loadConfig();
  if (cfg->servers.empty())
  {
    throw DnsTransportException("No DNS servers configured");
  }

  std::size_t index = _serverIndex.fetch_add(1) % cfg->servers.size();
  DnsServer selectedServer = cfg->servers[index];

  iora::core::Logger::info("DNS getNextServer: selected server=" + selectedServer.toString() +
                           " (index=" + std::to_string(index) + " of " +
                           std::to_string(cfg->servers.size()) + " servers)");

  return selectedServer;
}

inline std::vector<std::uint8_t>
DnsTransport::prepareQuery(const std::vector<DnsQuestion> &questions, std::uint16_t queryId)
{
  return DnsMessage::buildQuery(questions, loadConfig()->recursionDesired, queryId);
}

inline DnsTransport::Statistics DnsTransport::getStatistics() const
{
  // No mutex needed - atomic loads are thread-safe
  Statistics result;
  result.totalQueries = _stats.totalQueries.load(std::memory_order_relaxed);
  result.udpQueries = _stats.udpQueries.load(std::memory_order_relaxed);
  result.tcpQueries = _stats.tcpQueries.load(std::memory_order_relaxed);
  result.tcpFallbacks = _stats.tcpFallbacks.load(std::memory_order_relaxed);
  result.timeouts = _stats.timeouts.load(std::memory_order_relaxed);
  result.retries = _stats.retries.load(std::memory_order_relaxed);
  result.errors = _stats.errors.load(std::memory_order_relaxed);
  result.truncatedResponses = _stats.truncatedResponses.load(std::memory_order_relaxed);
  return result;
}

inline void DnsTransport::resetStatistics()
{
  // No mutex needed - atomic stores are thread-safe
  _stats.totalQueries.store(0, std::memory_order_relaxed);
  _stats.udpQueries.store(0, std::memory_order_relaxed);
  _stats.tcpQueries.store(0, std::memory_order_relaxed);
  _stats.tcpFallbacks.store(0, std::memory_order_relaxed);
  _stats.timeouts.store(0, std::memory_order_relaxed);
  _stats.retries.store(0, std::memory_order_relaxed);
  _stats.errors.store(0, std::memory_order_relaxed);
  _stats.truncatedResponses.store(0, std::memory_order_relaxed);
}

inline void DnsTransport::updateConfig(const DnsConfig &config)
{
  // DE-LATCHED (M-2): updateConfig changes no lifecycle state, so it takes NEITHER
  // _stateMutex NOR _stateCv (folding tracker 2026-09-13-4). It validates first, then
  // atomically publishes an immutable snapshot (INV-2) that every reader picks up via
  // loadConfig(). Validate-before-publish (the old code assigned then threw, leaving an
  // empty config live).
  if (config.servers.empty())
  {
    throw DnsTransportException("No DNS servers configured");
  }

  // DnsServer structures are already normalized via fromString()
  // No additional normalization needed
  _config.store(std::make_shared<const DnsConfig>(config));
}

inline std::chrono::milliseconds DnsTransport::calculateMaxSyncWaitTime() const
{
  // INV-2 (L-1): pin ONE config snapshot — this reads six config fields, which must all
  // come from the same immutable config a concurrent updateConfig() cannot tear.
  auto cfg = loadConfig();

  // Calculate maximum total wait time for synchronous queries
  // Base timeout for initial attempt
  auto totalWait = cfg->timeout;

  // Calculate retry delays with exponential backoff and accurate per-retry jitter
  auto delay = cfg->initialRetryDelay;
  std::chrono::milliseconds totalJitter{0};

  for (int retry = 0; retry < cfg->retryCount; ++retry)
  {
    totalWait += delay;

    // Calculate jitter for this specific retry delay (more accurate than using maxRetryDelay)
    if (cfg->jitterFactor > 0.0)
    {
      // Worst case: this retry gets maximum positive jitter based on actual delay
      auto jitterForThisRetry =
        std::chrono::milliseconds(static_cast<long>(delay.count() * cfg->jitterFactor));
      totalJitter += jitterForThisRetry;
    }

    // Apply exponential backoff multiplier
    delay = std::chrono::milliseconds(static_cast<long>(delay.count() * cfg->retryMultiplier));

    // Cap at maximum delay
    if (delay > cfg->maxRetryDelay)
    {
      delay = cfg->maxRetryDelay;
    }
  }

  // Add the accurately calculated jitter
  totalWait += totalJitter;

  // Add safety margin for processing delays
  totalWait += std::chrono::milliseconds(2000); // 2 second margin

  return totalWait;
}

inline std::uint16_t DnsTransport::generateUniqueQueryId(const std::string &server,
                                                         std::uint16_t port)
{
  // Reduce mutex contention by generating candidates outside the lock
  constexpr int BATCH_SIZE = 10;
  constexpr int MAX_BATCHES = 100; // 1000 total attempts

  for (int batch = 0; batch < MAX_BATCHES; ++batch)
  {
    // Generate a batch of candidates outside the lock
    std::array<std::uint16_t, BATCH_SIZE> candidates;
    for (int i = 0; i < BATCH_SIZE; ++i)
    {
      candidates[i] = DnsMessage::generateQueryId();
    }

    // Check candidates in a short critical section
    {
      std::lock_guard<std::mutex> lock(_queriesMutex);
      for (std::uint16_t queryId : candidates)
      {
        QueryKey testKey(queryId, server, port);
        if (_pendingQueries.find(testKey) == _pendingQueries.end())
        {
          return queryId; // Found unique ID
        }
      }
    }
  }

  // Fallback: sequential search for a free ID (pathological case recovery)
  iora::core::Logger::warning(
    "DNS query ID collision after 1000 random attempts, falling back to sequential search");

  {
    std::lock_guard<std::mutex> lock(_queriesMutex);

    // Sequential search through the entire 16-bit space
    for (std::uint32_t id = 1; id <= 65535; ++id)
    {
      std::uint16_t queryId = static_cast<std::uint16_t>(id);
      QueryKey testKey(queryId, server, port);
      if (_pendingQueries.find(testKey) == _pendingQueries.end())
      {
        iora::core::Logger::debug("Found free query ID " + std::to_string(queryId) +
                                  " via sequential search");
        return queryId;
      }
    }
  }

  // This should never happen unless we have 65535 concurrent queries to the same server:port
  throw DnsTransportException("Exhausted all query IDs for server " + server + ":" +
                              std::to_string(port) +
                              " (65535 concurrent queries - system overload)");
}

inline std::shared_ptr<DnsTransport::PendingQuery>
DnsTransport::findPendingQuery(std::uint16_t queryId, const std::string &sourceServer,
                               std::uint16_t sourcePort)
{
  std::lock_guard<std::mutex> lock(_queriesMutex);
  QueryKey key(queryId, sourceServer, sourcePort);
  auto it = _pendingQueries.find(key);
  if (it != _pendingQueries.end())
  {
    return it->second;
  }
  return nullptr;
}

inline std::shared_ptr<DnsTransport::PendingQuery>
DnsTransport::takePending(const QueryKey &key)
{
  std::lock_guard<std::mutex> lock(_queriesMutex);
  auto it = _pendingQueries.find(key);
  if (it == _pendingQueries.end())
  {
    return nullptr;
  }
  auto query = it->second;
  _pendingQueries.erase(it);
  return query;
}

inline bool DnsTransport::registerPendingIfRunning(const QueryKey &key,
                                                   const std::shared_ptr<PendingQuery> &query)
{
  std::lock_guard<std::mutex> lock(_queriesMutex);
  if (_state.load(std::memory_order_acquire) != Lifecycle::Running)
  {
    return false;
  }
  _pendingQueries[key] = query;
  return true;
}

inline void DnsTransport::cancelActiveTimer(const std::shared_ptr<PendingQuery> &query)
{
  // Atomically CLAIM the timer id (item I / TSA-LOW-2: exchange, not load-then-store, so a
  // concurrent completeQuery cannot read the same non-zero id and double-cancel it). Guard
  // _timerService -- a concurrent stop() may have reset it (M-D).
  std::uint64_t activeTimer = query->activeTimerId.exchange(0, std::memory_order_relaxed);
  if (activeTimer != 0)
  {
    if (auto timer = loadTimer()) // INV-2: a concurrent stop() may have nulled the handle.
    {
      timer->cancel(activeTimer);
    }
  }
}

inline void DnsTransport::failOne(const std::shared_ptr<PendingQuery> &query,
                                  const std::exception_ptr &error)
{
  if (query->callback)
  {
    try
    {
      query->callback({}, error);
    }
    catch (...)
    {
    }
  }
  try
  {
    query->promise.set_exception(error);
  }
  catch (...)
  {
  }
}

inline void DnsTransport::failCollected(const std::vector<std::shared_ptr<PendingQuery>> &queries,
                                        const std::exception_ptr &error)
{
  for (auto &query : queries)
  {
    failOne(query, error);
  }
}

inline void DnsTransport::failCallback(const QueryCallback &callback,
                                       const std::exception_ptr &error)
{
  if (callback)
  {
    try
    {
      callback({}, error);
    }
    catch (...)
    {
    }
  }
}

inline void DnsTransport::stopTransportGuarded(std::shared_ptr<Transport> &transport)
{
  // IO-arm self-join guard (item 6): the Transport wrapper stop() THROWS std::logic_error if
  // called on its own I/O thread, so SKIP stop() there (the later reset() still frees it via
  // ~Transport's deferred self-destruct). Off the I/O thread this is the normal join-on-stop.
  //
  // CONTRACT (cpp17-L2): an OFF-I/O-thread stop() is expected to be non-throwing (it only
  // joins an engine loop). stop() deliberately does NOT catch here: if this join threw, the
  // I/O thread might still be alive and a subsequent reset() would race it -- swallowing the
  // throw would be UNSAFE (reset-after-failed-join), so the throw must propagate rather than
  // be masked. The only expected throw is the on-own-I/O-thread case, which is skipped above.
  if (transport && !transport->isOnIoThread())
  {
    transport->stop();
  }
}

inline void DnsTransport::completeQuery(const QueryKey &key, const DnsResult &result)
{
  std::shared_ptr<PendingQuery> query = takePending(key);

  if (query)
  {
    cancelActiveTimer(query);

    // Calculate query duration for performance monitoring (atomic read)
    auto queryDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - query->startTime.load())
                           .count();

    // All DNS protocol responses are valid results (NOERROR, NXDOMAIN, SERVFAIL, etc.)
    // The resolver layer will decide whether to throw exceptions based on response codes
    {
      // Log different response types appropriately
      if (result.header.rcode == DnsResponseCode::NOERROR)
      {
        iora::core::Logger::debug(
          "DNS query completed successfully: ID=" + std::to_string(query->queryId) +
          " server=" + query->server + ":" + std::to_string(query->port) +
          " duration=" + std::to_string(queryDuration) + "ms" +
          " retries=" + std::to_string(query->retryCount.load()) +
          " answers=" + std::to_string(result.header.ancount));
      }
      else if (result.header.rcode == DnsResponseCode::NXDOMAIN)
      {
        iora::core::Logger::info(
          "DNS query completed with NXDOMAIN: ID=" + std::to_string(query->queryId) +
          " server=" + query->server + ":" + std::to_string(query->port) +
          " duration=" + std::to_string(queryDuration) + "ms" + " retries=" +
          std::to_string(query->retryCount.load()) + " rcode=" + result.getResponseCodeString());
      }
      else
      {
        iora::core::Logger::info(
          "DNS query completed with server error: ID=" + std::to_string(query->queryId) +
          " server=" + query->server + ":" + std::to_string(query->port) +
          " duration=" + std::to_string(queryDuration) + "ms" + " retries=" +
          std::to_string(query->retryCount.load()) + " rcode=" + result.getResponseCodeString());
      }

      if (query->callback)
      {
        try
        {
          query->callback(result, nullptr);
        }
        catch (...)
        {
        }
      }
      try
      {
        query->promise.set_value(result);
      }
      catch (...)
      {
      }
    }
  }
  else
  {
    iora::core::Logger::warning(
      "DNS query completion for unknown query: ID=" + std::to_string(key.queryId) +
      " server=" + key.server + ":" + std::to_string(key.port));
  }
}

inline void DnsTransport::completeQuery(const QueryKey &key, const std::exception_ptr &error)
{
  std::shared_ptr<PendingQuery> query = takePending(key);

  if (query)
  {
    cancelActiveTimer(query);

    // Calculate query duration for performance monitoring (atomic read)
    auto queryDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - query->startTime.load())
                           .count();

    // Log the error with context
    std::string errorMessage = "unknown error";
    try
    {
      std::rethrow_exception(error);
    }
    catch (const std::exception &e)
    {
      errorMessage = e.what();
    }
    catch (...)
    {
      errorMessage = "non-standard exception";
    }

    iora::core::Logger::error(
      "DNS query failed: ID=" + std::to_string(query->queryId) + " server=" + query->server + ":" +
      std::to_string(query->port) + " duration=" + std::to_string(queryDuration) + "ms" +
      " retries=" + std::to_string(query->retryCount.load()) + " error=" + errorMessage);

    // Atomic increment - no mutex needed
    _stats.errors.fetch_add(1, std::memory_order_relaxed);

    failOne(query, error);
  }
}

inline void DnsTransport::startCleanupTimer()
{
  _cleanupRunning.store(true);
  // Resurrect-guard generation (H / phase 4): bump and capture the fresh value. A stale
  // detached cleanup thread from a prior self-stop captured an OLDER generation, so it
  // exits at its next check even if this restart re-set _cleanupRunning=true — at most one
  // live sweeper survives a restart (LOW-4: bumped HERE by the next start(), not at detach).
  const std::uint64_t myGeneration =
    _cleanupGeneration.fetch_add(1, std::memory_order_acq_rel) + 1;
  // Capture a weak_ptr, NOT an owning shared_from_this() (tracker 2026-09-11-6 item 10):
  // an owning capture forms a DnsTransport -> _cleanupThread -> self reference cycle, so a
  // DnsTransport dropped without an explicit stop() would never be destroyed. Promote to
  // a local shared_ptr per iteration; the promotion pins the object for the whole
  // iteration (including any stop() a fired callback triggers) and fails once the object
  // is gone, so the detached thread exits without touching freed state.
  std::weak_ptr<DnsTransport> weakSelf = weak_from_this();
  _cleanupThread = std::thread(
    [weakSelf, myGeneration]()
    {
      // Stamp this thread's id for the teardown-latch exemption (R3-C1). Uses the
      // member-INDEPENDENT _cleanupThreadId (NOT _cleanupThread.get_id(), which stop() step 2
      // moves out before releasing _stateMutex). clearIfCurrent() on exit so a resurrected
      // sibling that already re-stamped its own id is not clobbered.
      {
        auto self = weakSelf.lock();
        if (!self)
        {
          return;
        }
        self->_cleanupThreadId.stamp();
        self->_cleanupThreadCount.fetch_add(1, std::memory_order_relaxed);
      }
      struct StampGuard
      {
        std::weak_ptr<DnsTransport> w;
        ~StampGuard()
        {
          if (auto s = w.lock())
          {
            s->_cleanupThreadId.clearIfCurrent();
            s->_cleanupThreadCount.fetch_sub(1, std::memory_order_relaxed);
          }
        }
      } stampGuard{weakSelf};

      for (;;)
      {
        auto self = weakSelf.lock();
        // Exit on shutdown OR on a generation mismatch (a restart minted a newer sweeper).
        if (!self || !self->_cleanupRunning.load() ||
            self->_cleanupGeneration.load(std::memory_order_acquire) != myGeneration)
        {
          break;
        }

        {
          std::unique_lock<std::mutex> lock(self->_cleanupMutex);
          if (self->_cleanupCv.wait_for(lock, self->_cleanupInterval,
                                        [&self] { return !self->_cleanupRunning.load(); }))
          {
            break; // Shutdown requested
          }
          // Release _cleanupMutex BEFORE cleanupExpiredQueries (item 3 / F-4a): its
          // callbacks must not run while the CV mutex is held (HR-3 lock-across-user-code);
          // nothing inside cleanupExpiredQueries needs _cleanupMutex.
          lock.unlock();
        }

        self->cleanupExpiredQueries();
        // `self` is dropped here at end of iteration.
      }
    });
}

inline void DnsTransport::scheduleQueryTimeout(std::shared_ptr<PendingQuery> query)
{
  // Defensive: if the timer service is already gone (stop() in progress), do not
  // schedule -- the pending query will be drained by stop() (M-D null-guard). INV-2 snapshot.
  auto timer = loadTimer();
  if (!timer)
  {
    return;
  }

  // Capture a weak_ptr, NOT owning self (item 10): an owning capture into a timer lambda
  // held by _timerService forms the DnsTransport -> _timerService -> lambda -> self cycle.
  std::weak_ptr<DnsTransport> weakSelf = weak_from_this();

  // Cancel existing timeout timer if any (important for TCP fallback scenarios)
  cancelActiveTimer(query);

  // Schedule a timeout timer for the configured query timeout
  std::uint64_t timerId = timer->scheduleAfter(
    query->timeout,
    [weakSelf, query]()
    {
      auto self = weakSelf.lock();
      // Check if transport is still alive/running before accessing any members
      if (!self || !self->isRunning())
      {
        return; // Transport has been stopped/destroyed
      }

      // Also check if timer service is still valid (defensive programming) — INV-2 snapshot.
      if (!self->loadTimer())
      {
        return; // Timer service has been destroyed
      }

      // Check if query is still pending (not completed/cancelled)
      QueryKey key(query->queryId, query->server, query->port);

      std::shared_ptr<PendingQuery> pendingQuery = self->takePending(key);
      if (!pendingQuery)
      {
        return; // Query already completed or cancelled
      }

      // Clear the timer ID since timeout fired
      pendingQuery->activeTimerId.store(0, std::memory_order_relaxed);

      // Complete query with timeout error
      auto error = std::make_exception_ptr(DnsTimeoutException(
        "Query timeout after " + std::to_string(query->timeout.count()) + "ms"));

      // Fire via the shared guarded helper (item 9 + S-3): matches completeQuery's error
      // path -- callback (guarded) then promise.set_exception (guarded). Guards against an
      // uncaught user-callback throw escaping the timer lambda (-> std::terminate); for an
      // async query the promise has no future consumer, so setting it is a harmless no-op.
      self->failOne(pendingQuery, error);

      // Update timeout statistics
      self->_stats.timeouts.fetch_add(1, std::memory_order_relaxed);
    });

  // Store timer ID for potential cancellation
  query->activeTimerId.store(timerId, std::memory_order_relaxed);
}

inline void DnsTransport::cleanupExpiredQueries()
{
  auto now = std::chrono::steady_clock::now();
  auto cfg = loadConfig(); // INV-2: one config snapshot for this sweep.
  std::vector<std::shared_ptr<PendingQuery>> retryList;
  std::vector<std::shared_ptr<PendingQuery>> failList;

  // Collect-AND-ERASE under _queriesMutex (tracker 2026-09-11-6 item 4 -- exactly-once):
  // partition the expired queries in ONE critical section. Non-retriable ones are ERASED
  // here so exactly one path owns and fires them (a concurrent completeQuery's atomic
  // find+erase can no longer race the old copy-then-later-erase, which double-fired the
  // callback). Retriable queries STAY in the map -- retryQuery re-sends and the eventual
  // response / next timeout must still find the entry.
  {
    std::lock_guard<std::mutex> lock(_queriesMutex);
    for (auto it = _pendingQueries.begin(); it != _pendingQueries.end();)
    {
      auto &query = it->second;
      if (now - query->startTime.load() > query->timeout)
      {
        if (query->retryCount.load() < cfg->retryCount)
        {
          retryList.push_back(query);
          ++it;
        }
        else
        {
          failList.push_back(query);
          it = _pendingQueries.erase(it);
        }
      }
      else
      {
        ++it;
      }
    }
  }

  // Process ALL retries FIRST, then fire failures (item 4 / M-D ordering): retryQuery
  // touches _timerService (scheduleAfter), and a failList callback may call stop() which
  // nulls _timerService. Doing every _timerService-touching retry before any fail fire
  // removes the null-deref hazard. retryQuery runs OUTSIDE _queriesMutex (it re-locks it
  // via completeQuery on the retry-limit path).
  for (auto &query : retryList)
  {
    retryQuery(query, "timeout");
  }

  // Fire timeouts without holding any lock.
  auto error = std::make_exception_ptr(DnsTimeoutException("Query timeout after maximum retries"));
  failCollected(failList, error);

  if (!failList.empty())
  {
    // Atomic increment - no mutex needed
    _stats.timeouts.fetch_add(failList.size(), std::memory_order_relaxed);
  }
}

inline void DnsTransport::retryQuery(std::shared_ptr<PendingQuery> query, const std::string &reason)
{
  // Defensive (M-D): if the timer service is gone (stop() in progress / a prior fail
  // callback called stop()), do not touch it -- leave the query in the map for stop()'s
  // drain to fail. This makes the cleanup retryList-before-failList ordering robust.
  // INV-2 snapshots: one timer handle + one config for this retry.
  auto timer = loadTimer();
  if (!timer)
  {
    return;
  }
  auto cfg = loadConfig();

  if (query->retryCount.load() >= cfg->retryCount)
  {
    // Maximum retries exceeded, complete with error
    // Log total attempts made (retryCount + 1 = initial attempt + retries)
    iora::core::Logger::debug(
      "DNS query retry limit exceeded: ID=" + std::to_string(query->queryId) +
      " server=" + query->server + ":" + std::to_string(query->port) + " reason=" + reason +
      " totalAttempts=" + std::to_string(query->retryCount.load() + 1));
    auto error =
      std::make_exception_ptr(DnsTimeoutException("Maximum retries exceeded: " + reason));
    completeQuery(QueryKey(query->queryId, query->server, query->port), error);
    return;
  }

  // Calculate exponential backoff delay with jitter
  auto baseDelay = cfg->initialRetryDelay;
  for (int i = 0; i < query->retryCount.load(); ++i)
  {
    baseDelay =
      std::chrono::milliseconds(static_cast<long>(baseDelay.count() * cfg->retryMultiplier));
  }

  // Cap at maximum delay
  if (baseDelay > cfg->maxRetryDelay)
  {
    baseDelay = cfg->maxRetryDelay;
  }

  // Add jitter to prevent thundering herd. Draw under _rngMutex (TS-HIGH-1): the resurrect
  // window can transiently overlap two cleanup sweepers, and a concurrent draw from the
  // non-atomic mt19937 would be a data race. The lock scopes ONLY the draw (an innermost
  // leaf), not the schedule below.
  if (cfg->jitterFactor > 0.0)
  {
    std::uniform_real_distribution<double> dis(1.0 - cfg->jitterFactor, 1.0 + cfg->jitterFactor);

    double jitter;
    {
      std::lock_guard<std::mutex> rngLock(_rngMutex);
      jitter = dis(_rng);
    }
    baseDelay = std::chrono::milliseconds(static_cast<long>(baseDelay.count() * jitter));
  }

  // Reset the expiry clock at retry-scheduling time (item G / cpp17-LOW-2): the query
  // stays in _pendingQueries during the backoff, so without this the NEXT cleanup sweep
  // (which fires when now - startTime > timeout) would re-expire it before the scheduled
  // re-send runs and burn retryCount prematurely. The retry lambda refreshes startTime
  // again when it actually re-sends (post-backoff).
  query->startTime.store(std::chrono::steady_clock::now());

  // Increment retry count atomically
  int newRetryCount = query->retryCount.fetch_add(1) + 1;

  // Log the upcoming attempt number (retryCount + 1 = initial + retries)
  iora::core::Logger::debug("DNS query retry scheduled: ID=" + std::to_string(query->queryId) +
                            " server=" + query->server + ":" + std::to_string(query->port) +
                            " reason=" + reason +
                            " upcomingAttempt=" + std::to_string(newRetryCount + 1) +
                            " delay=" + std::to_string(baseDelay.count()) + "ms");

  // Schedule retry after delay using timer service (avoids sleeping in worker threads).
  // Weak capture (item 10) to avoid the DnsTransport -> _timerService -> lambda -> self cycle.
  std::weak_ptr<DnsTransport> weakSelf = weak_from_this();
  std::uint64_t timerId = timer->scheduleAfter(
    baseDelay,
    [weakSelf, query]()
    {
      auto self = weakSelf.lock();
      // Check if transport is still alive/running before accessing any members
      if (!self || !self->isRunning())
      {
        return; // Transport has been stopped/destroyed
      }

      // Check if query is still valid (not completed/cancelled)
      // SAFE: queryId, server, port are const fields, so QueryKey is always consistent
      {
        std::lock_guard<std::mutex> lock(self->_queriesMutex);
        QueryKey key(query->queryId, query->server, query->port);
        auto it = self->_pendingQueries.find(key);
        if (it == self->_pendingQueries.end())
        {
          return; // Query already completed or cancelled
        }
      }

      // Update start time for timeout calculations (fixes retry/timeout race)
      query->startTime.store(std::chrono::steady_clock::now());

      // Retry the query
      try
      {
        if (query->transportMode == DnsTransportMode::UDP)
        {
          self->sendUdpQuery(query);
        }
        else if (query->transportMode == DnsTransportMode::TCP)
        {
          self->sendTcpQuery(query);
        }

        // Atomic increment - no mutex needed
        self->_stats.retries.fetch_add(1, std::memory_order_relaxed);
      }
      catch (const std::exception &e)
      {
        // Retry failed, complete with error
        auto error =
          std::make_exception_ptr(DnsTransportException("Retry failed: " + std::string(e.what())));
        self->completeQuery(QueryKey(query->queryId, query->server, query->port), error);
      }

      // Do NOT clear activeTimerId here (M1 / cpp17-MED): on the SUCCESS path
      // sendUdpQuery/sendTcpQuery -> scheduleQueryTimeout has just stored a FRESH timeout
      // timer id into activeTimerId; a store(0) here would clobber it, leaving a live,
      // un-cancellable timeout timer (completeQuery would read 0 and not cancel it). On the
      // ERROR path completeQuery already claimed+cancelled the id via cancelActiveTimer, so
      // clearing it here is redundant. Either way this store(0) is wrong -- removed.
    });

  // Store timer ID for potential cancellation
  query->activeTimerId.store(timerId, std::memory_order_relaxed);
}

} // namespace dns
} // namespace network
} // namespace iora