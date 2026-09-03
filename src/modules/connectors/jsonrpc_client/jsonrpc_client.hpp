// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
// Used by the blocking quiesce: _quiesceCv, and the interruptible retry
// backoff in sendJsonWithRetries_ that waits on it.
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "iora/iora.hpp"
// For iora::core::StringUtils::iequals (ASCII, locale-independent header-name
// folding in mergeHeaders_ — cpp17 LOW-5); not pulled in transitively by iora.hpp.
#include "iora/core/string_utils.hpp"
// For iora::network::isHttpToken / isValidFieldValue (RFC 9110 header-name/value
// grammar reused in the constructor + mergeHeaders_ validation — task-7.3b).
#include "iora/parsers/http_message.hpp"

namespace iora
{
namespace modules
{
namespace connectors
{

/// \brief Test-only observation seam for the connection pool internals.
/// \details Forward-declared here and befriended by JsonRpcClient,
/// JsonRpcClientImpl and detail::EndpointPool so tests can read otherwise-private
/// pool state (per-connection identity, in-use flags, totals) under the client
/// mutex. The type itself is defined only in the test translation unit; the
/// declaration is unconditional (never #ifdef-guarded) so the class layout is
/// identical in every TU — an #ifdef would make the definition differ between
/// translation units, an ODR violation the moment any consumer is compiled
/// without the macro.
struct JsonRpcClientTestAccess;

/// \brief Forward declaration of the implementation body (task-4.1c).
/// \details detail::ConnectionLease holds a std::shared_ptr<JsonRpcClientImpl>
/// keep-alive, so it needs the name before the class is defined. The type is
/// namespace-scope (namespace connectors), so a shared_ptr member to it carries
/// no enclosing-private-type hazard; the full definition follows the detail
/// namespace and the lease destructor is defined out of line once it is
/// complete.
class JsonRpcClientImpl;

/// \brief Base exception for JSON-RPC client errors.
class JsonRpcError : public std::runtime_error
{
public:
  explicit JsonRpcError(const std::string &what) : std::runtime_error(what) {}
};

/// \brief Thrown when a pool has reached its configured maximum size and no
/// connection is available.
class PoolExhaustedError : public JsonRpcError
{
public:
  explicit PoolExhaustedError(const std::string &what) : JsonRpcError(what) {}
};

/// \brief Thrown (sync), or delivered via onError / promise.set_exception
/// (async), when a call is REFUSED or INTERRUPTED because the client is closing
/// (blocking quiesce, CR-4 / HD-1). A call that has NOT yet begun when the
/// destructor latches is refused with this; a call already admitted is waited
/// for, not refused. Derives from JsonRpcError so an existing catch(JsonRpcError)
/// still classifies it as a failed request.
class ClientShutdownError : public JsonRpcError
{
public:
  explicit ClientShutdownError(const std::string &what) : JsonRpcError(what) {}
};

/// \brief Thrown when a JSON-RPC response contains an error object.
class RemoteError : public JsonRpcError
{
public:
  RemoteError(int code, const std::string &message, iora::parsers::Json data)
      : JsonRpcError("JSON-RPC remote error: (" + std::to_string(code) + ") " + message),
        _code(code), _message(message), _data(std::move(data))
  {
  }

  int code() const noexcept { return _code; }

  const std::string &message() const noexcept { return _message; }

  const iora::parsers::Json &data() const noexcept { return _data; }

private:
  int _code;
  std::string _message;
  iora::parsers::Json _data;
};

/// \brief JSON-RPC client configuration.
struct Config
{
  /// \brief Maximum number of connections per endpoint.
  std::size_t maxConnectionsPerEndpoint{8};

  /// \brief Global maximum number of connections across all endpoints (0 =
  /// unlimited).
  std::size_t globalMaxConnections{0};

  /// \brief Maximum number of endpoint pools (unique endpoints) (0 =
  /// unlimited).
  std::size_t maxEndpointPools{0};

  /// \brief Idle timeout after which connections are eligible for eviction
  /// by purgeIdle(). Governs the wrapper HttpClient OBJECT's lifetime only.
  std::chrono::milliseconds idleTimeout{std::chrono::seconds(30)};

  /// \brief Socket-level idle timeout: how long a POOLED HttpClient keeps its
  /// underlying TCP socket open between requests before the transport recycles
  /// it. DISTINCT from idleTimeout (which evicts the wrapper OBJECT); drives
  /// HttpClient::Config::connectionIdleTimeout (task-7.1a). Defaults to 3 s
  /// (task-7.6): strictly BELOW the common server keep-alive floor — Node.js
  /// server.keepAliveTimeout and Apache KeepAliveTimeout both default to 5 s
  /// (nginx keepalive_timeout is 75 s, far above). The 2 s gap below the 5 s floor
  /// must ABSORB the one-way response latency: the server starts its keep-alive
  /// timer at send-complete, the client its socket-idle timer one latency later at
  /// receive-complete, so the client fires first only while that sub-floor gap
  /// exceeds the latency — which at LAN/localhost scales it comfortably does. So
  /// the client recycles a pooled socket BEFORE a conforming server at or above
  /// that floor would close it. This REDUCES the keep-alive reuse race;
  /// it is not an absolute guarantee: an intermediary (proxy/LB) with a sub-3 s
  /// idle timeout can still close a socket the client then reuses. That reset is
  /// retried on a fresh socket, but ONLY the closed-while-idle-before-the-write
  /// case is provably-not-applied and therefore safe to retry per RFC 9110
  /// §9.2.2; the retry loop does NOT currently restrict itself to that case (it
  /// retries any exception, a double-submit hazard for non-idempotent POST) —
  /// see tracker 2026-09-03-2. The window only lowers how often the race is hit.
  /// TRADEOFF: against a
  /// long-keep-alive peer (nginx 75 s, ALB/GCP LBs) a workload with request gaps
  /// > 3 s pays a fresh TCP connect (and TLS handshake for https) per burst where
  /// a longer window would have reused the socket; raise this for such peers.
  /// It maps through the seconds-granular max(1 s, cast<seconds>) rule
  /// (task-7.1a) — truncation is toward zero (4900 ms -> 4 s), and a sub-second
  /// value floors to 1 s rather than disabling reuse.
  std::chrono::milliseconds socketIdleTimeout{std::chrono::seconds(3)};

  /// \brief HTTP request timeout for individual JSON-RPC calls.
  std::chrono::milliseconds requestTimeout{std::chrono::seconds(30)};

  /// \brief Connection timeout for initial HTTP connection establishment.
  std::chrono::milliseconds connectionTimeout{std::chrono::seconds(10)};

  /// \brief Maximum number of retry attempts for failed requests.
  std::size_t maxRetries{3};

  /// \brief Backoff multiplier for retry attempts (exponential backoff).
  double retryBackoffMultiplier{2.0};

  /// \brief Initial retry delay in milliseconds.
  std::chrono::milliseconds initialRetryDelay{std::chrono::milliseconds(100)};

  /// \brief Maximum retry delay in milliseconds.
  std::chrono::milliseconds maxRetryDelay{std::chrono::seconds(5)};

  /// \brief Enable connection keep-alive for HTTP/1.1.
  bool enableKeepAlive{true};

  /// \brief Default HTTP headers applied to every request; call-specific
  /// headers can override. Empty by default (task-7.2d): the constructor
  /// contributes no entry, and the client's only wire contribution is
  /// `Accept-Encoding: identity`, added per request in mergeHeaders_ (task-7.2b).
  std::vector<std::pair<std::string, std::string>> defaultHeaders{};

  /// \brief Optional factory for creating HttpClient instances (injectable
  /// for tests).
  /// \details RE-ENTRANCY CONTRACT (phase 6): since the CR-3 fix this runs on
  /// the CALLING thread with NO client lock held, so it MAY call back into the
  /// client — that is the point of the fix. Two caveats it is now the caller's
  /// job to respect:
  ///   * A re-entrant acquire for the SAME endpoint sees the in-flight
  ///     reservation in the per-endpoint cap, so on a cap-1 endpoint it throws
  ///     PoolExhaustedError. That is correct behaviour, not a defect.
  ///   * A factory that unconditionally re-enters and creates ANOTHER
  ///     connection recurses. Before phase 6 that self-deadlocked on the mutex;
  ///     now it recurses until a cap refuses it, or overflows the stack if no
  ///     cap bounds it. Bound your own re-entrancy.
  /// Destroying the client from inside this callback is detected as a
  /// self-destruct and calls std::terminate (task-3.2).
  ///
  /// \details SIGNATURE (task-7.1b, HD-7 row (5)): the factory receives the
  /// derived HttpClient::Config the client built from THIS Config's six knobs
  /// (requestTimeout, connectionTimeout, enableKeepAlive, socketIdleTimeout, the
  /// consumed User-Agent, and leaseAcquireTimeout). A custom factory that ignores
  /// it silently discards those knobs — the exact defect phase 7 removes — so
  /// honour it: `std::make_unique<HttpClient>(derived)` and override only what you
  /// must (e.g. TLS). Post task-7.5 the first parameter is the parsed ORIGIN
  /// (scheme://host:port), not the caller's full URL. This header is
  /// plugin-internal (src/modules/); tracker 2026-07-26-1 must make ~HttpClient
  /// virtual (its task F-3) BEFORE promoting this header to a public API, since a
  /// derived HttpClient destroyed through the base unique_ptr is UB while
  /// ~HttpClient is non-virtual.
  using HttpClientFactory = std::function<std::unique_ptr<iora::network::HttpClient>(
    const std::string &origin, const iora::network::HttpClient::Config &derived)>;
  HttpClientFactory httpClientFactory{};

  /// \brief Optional hook to configure a freshly created HttpClient (e.g.,
  /// TLS). \details Called after httpClientFactory() returns and before
  /// first use. The same phase-6 re-entrancy contract as httpClientFactory
  /// above applies verbatim. Post task-7.5 the first parameter is the parsed
  /// ORIGIN (scheme://host:port), not the caller's full URL — the same string
  /// the factory received.
  std::function<void(const std::string &origin, iora::network::HttpClient &client)>
    httpClientConfigurer{};
};

/// \brief JSON-RPC client statistics.
/// \details EVERY access uses std::memory_order_relaxed (simpl LOW-4 / iteration 2), matching
/// _nextId and the iora Counter/Gauge idiom. These are eventually-consistent
/// aggregates: no reader treats them as synchronization variables, and
/// getStats() already documents that it must not race destruction. Leaving them
/// at the default seq_cst bought a full barrier per counter bump on every
/// request path while guaranteeing an ordering nothing consumes — and it could
/// not have guaranteed a coherent multi-field snapshot anyway, since getStats()
/// reads the ten fields without a lock.
struct ClientStats
{
  std::atomic<std::uint64_t> totalRequests{0};
  std::atomic<std::uint64_t> successfulRequests{0};
  std::atomic<std::uint64_t> failedRequests{0};
  std::atomic<std::uint64_t> timeoutRequests{0};
  std::atomic<std::uint64_t> retriedRequests{0};
  std::atomic<std::uint64_t> batchRequests{0};
  std::atomic<std::uint64_t> notificationRequests{0};
  std::atomic<std::uint64_t> poolExhaustions{0};
  std::atomic<std::uint64_t> connectionsCreated{0};
  std::atomic<std::uint64_t> connectionsEvicted{0};

  /// \brief Reset all counters.
  void reset()
  {
    totalRequests.store(0, std::memory_order_relaxed);
    successfulRequests.store(0, std::memory_order_relaxed);
    failedRequests.store(0, std::memory_order_relaxed);
    timeoutRequests.store(0, std::memory_order_relaxed);
    retriedRequests.store(0, std::memory_order_relaxed);
    batchRequests.store(0, std::memory_order_relaxed);
    notificationRequests.store(0, std::memory_order_relaxed);
    poolExhaustions.store(0, std::memory_order_relaxed);
    connectionsCreated.store(0, std::memory_order_relaxed);
    connectionsEvicted.store(0, std::memory_order_relaxed);
  }
};

/// \brief Plain-integer, copyable snapshot of ClientStats (task-3.3(ii)).
/// \details getStats() returns this BY VALUE. ClientStats itself holds
/// std::atomics and is non-copyable, and a reference into JsonRpcClientImpl
/// cannot safely outlive a concurrent destructor — so the accessor is NOT
/// counted (task-3.3(ii)) and instead hands back an atomic-free snapshot.
/// Callers read the plain fields directly (no .load()).
struct ClientStatsSnapshot
{
  std::uint64_t totalRequests{0};
  std::uint64_t successfulRequests{0};
  std::uint64_t failedRequests{0};
  std::uint64_t timeoutRequests{0};
  std::uint64_t retriedRequests{0};
  std::uint64_t batchRequests{0};
  std::uint64_t notificationRequests{0};
  std::uint64_t poolExhaustions{0};
  std::uint64_t connectionsCreated{0};
  std::uint64_t connectionsEvicted{0};
};

/// \brief Batch request item for efficient bulk operations.
struct BatchItem
{
  std::string method;
  iora::parsers::Json params;
  std::optional<std::uint64_t> id; // None for notifications

  BatchItem(std::string method, iora::parsers::Json params)
      : method(std::move(method)), params(std::move(params))
  {
  }

  BatchItem(std::string method, iora::parsers::Json params, std::uint64_t id)
      : method(std::move(method)), params(std::move(params)), id(id)
  {
  }
};

namespace detail
{
class PooledConnection
{
public:
  explicit PooledConnection(std::unique_ptr<iora::network::HttpClient> client)
      : _client(std::move(client)), _inUse(false), _lastUsed(std::chrono::steady_clock::now())
  {
  }

  iora::network::HttpClient &client() { return *_client; }

  void markInUse() { _inUse = true; }

  void markFree()
  {
    _inUse = false;
    _lastUsed = std::chrono::steady_clock::now();
  }

  bool inUse() const { return _inUse; }

  std::chrono::steady_clock::time_point lastUsed() const { return _lastUsed; }

private:
  std::unique_ptr<iora::network::HttpClient> _client;
  bool _inUse;
  std::chrono::steady_clock::time_point _lastUsed;
};

class EndpointPool
{
public:
  explicit EndpointPool(const std::string &endpoint)
      : _endpoint(endpoint), _lastTouched(std::chrono::steady_clock::now())
  {
  }

  /// \brief Acquire a free connection, returning an owning handle (CR-1: the
  /// object IS its own identity, so a lease can never be aliased onto a
  /// different connection by a vector shift). Returns nullptr if none is free.
  /// \details Idle connections that have expired are removed during the scan.
  /// Their owning shared_ptr is MOVED into `evicted` rather than destroyed here:
  /// ~PooledConnection runs ~HttpClient, which joins I/O threads, and this
  /// method runs under JsonRpcClientImpl::_mutex — so the caller destroys
  /// `evicted` only after releasing that mutex (thread-safety T6-2, the
  /// destruction analogue of copy-then-invoke).
  /// \param evictedCount OUT: the number of idle-expired connections erased here
  /// (H-2/task-5.2). The caller applies `_totalConnections -= evictedCount` and
  /// `_stats.connectionsEvicted.fetch_add(evictedCount` unconditionally — a dedicated
  /// out-parameter, NOT the return value (which carries the reused connection),
  /// and NOT derived from `evicted` (a shared bin the caller also fills from
  /// tryEvictOneIdleConnLruLocked_, which would double-subtract — H-4). This
  /// method never touches _stats itself (it holds none): counting here AND at the
  /// call site would double-count.
  std::shared_ptr<PooledConnection>
  tryAcquireFree(std::chrono::milliseconds idleTimeout,
                 std::vector<std::shared_ptr<PooledConnection>> &evicted,
                 std::size_t &evictedCount)
  {
    evictedCount = 0;
    const auto now = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < _connections.size();)
    {
      auto &pc = _connections[i];
      if (!pc->inUse())
      {
        if ((now - pc->lastUsed()) > idleTimeout)
        {
          evicted.push_back(std::move(_connections[i]));
          _connections.erase(_connections.begin() + static_cast<long>(i));
          ++evictedCount;
          continue;
        }
        pc->markInUse();
        touch();
        return pc;
      }
      ++i;
    }
    return nullptr;
  }

  /// \brief Number of creations RESERVED on this pool but not yet published —
  /// i.e. currently inside phase-6's unlocked construction window (task-6.1a).
  /// \details A PLAIN member, never an atomic: like _connections it is read and
  /// written ONLY under JsonRpcClientImpl::_mutex, consistent with the file's
  /// single-mutex model. It participates in BOTH capacity predicates and in
  /// recalcTotalLocked_, and it PINS the pool: a pool with pendingCreates() > 0
  /// is never erased from _pools (architecture designPrinciple #8, invariant I2
  /// — see retireIfEmptyAndUnpinnedLocked_ and the eviction candidacy filter).
  std::size_t pendingCreates() const { return _pendingCreates; }

  /// \brief Reserve capacity for ONE creation about to run outside the lock.
  /// \details Called under _mutex immediately BEFORE the caller releases it
  /// (task-6.1b). Two things are reserved at once:
  ///   * the ACCOUNTING slot — ++_pendingCreates, so a concurrent acquire_ on
  ///     this endpoint counts this in-flight creation in its cap checks and
  ///     cannot overshoot maxConnectionsPerEndpoint by racing our unlock;
  ///   * the STORAGE — _connections.reserve(size() + pendingCreates), which is
  ///     HUMAN DECISION 2026-08-01 "REMEDY B". Reserving here makes the later
  ///     publishCreate() push_back NOTHROW (it cannot reallocate), so on the
  ///     publish path ~PooledConnection/~HttpClient — which joins I/O threads —
  ///     can never run under _mutex during unwinding (T6-2) and no publish-time
  ///     throw can strand a size()==0 pool (designPrinciple #7).
  /// Strongly exception-safe WITHOUT a catch block, by ordering: the capacity
  /// reserve is the only step that can throw, so it runs FIRST. If it does, the
  /// counter has not moved and the pool is byte-for-byte as it was. The caller
  /// still retires a pool this leaves empty-and-unpinned (task-6.1b(e)).
  void reserveCreate()
  {
    // size + (pendingCreates after this call) — i.e. room for every reservation
    // currently outstanding plus the one being taken now.
    _connections.reserve(_connections.size() + _pendingCreates + 1);
    ++_pendingCreates;
  }

  /// \brief Publish a connection built OUTSIDE the lock, consuming its
  /// reservation (task-6.1b(f)(i)). Replaces the pre-phase-6 createAndAcquire,
  /// which ran the user factory UNDER _mutex — the CR-3 shape itself.
  /// \details NOTHROW by construction: reserveCreate() already sized
  /// _connections, so this push_back cannot reallocate, and copying a
  /// shared_ptr is noexcept. The capacity assert below is that claim made
  /// checkable rather than merely asserted in prose — if a future change ever
  /// breaks the REMEDY-B invariant, push_back would throw HERE, before the
  /// decrement, leaving the pool pinned forever with no counter disagreement
  /// for the tripwire to catch (silent under NDEBUG). connectionsCreated is
  /// counted HERE, at PUBLISH, not at reservation — task-6.3 asserts a
  /// rolled-back creation leaves it unchanged. Must hold JsonRpcClientImpl::_mutex.
  void publishCreate(const std::shared_ptr<PooledConnection> &pc, ClientStats &stats)
  {
    assert(_pendingCreates > 0); // publishing without a reservation would underflow
    assert(_connections.size() < _connections.capacity()); // REMEDY B: push_back is nothrow
    pc->markInUse();
    _connections.push_back(pc);
    --_pendingCreates;
    touch();
    stats.connectionsCreated.fetch_add(1, std::memory_order_relaxed);
  }

  /// \brief Release a reservation whose creation failed or was abandoned
  /// (task-6.1c). A counter decrement — never element removal — which is
  /// precisely why the pendingCreates route was chosen over a placeholder
  /// element: there is no half-constructed object for a concurrent purgeIdle or
  /// eviction to observe. The reserved _connections capacity is deliberately
  /// NOT given back: capacity is monotone, so a later reserveCreate() on this
  /// pool simply finds it already sufficient. Must hold _mutex.
  /// \details The assert is load-bearing, not decoration: _pendingCreates is
  /// unsigned, so ONE unmatched decrement wraps it to SIZE_MAX, and a pool with
  /// pendingCreates() != 0 is excluded at every pin site FOREVER — never
  /// retired, never an eviction candidate, permanently occupying a
  /// maxEndpointPools slot, with recalcTotalLocked_ overflowing on top. Silent
  /// under NDEBUG until the pool refuses every later endpoint.
  void rollbackCreate()
  {
    assert(_pendingCreates > 0);
    --_pendingCreates;
  }

  /// \brief Mark a leased connection free again. Handle-based (CR-1c): the lease
  /// owns `handle`, so this is well-defined even if `handle` was already erased
  /// from _connections by a concurrent purge — it degrades to a plain markFree
  /// on a still-owned object. Must be called under JsonRpcClientImpl::_mutex
  /// (thread-safety M-3: _inUse/_lastUsed are plain, read by other threads).
  void release(const std::shared_ptr<PooledConnection> &handle)
  {
    handle->markFree();
    touch();
  }

  std::size_t purgeIdle(std::chrono::milliseconds idleTimeout,
                        std::vector<std::shared_ptr<PooledConnection>> &evicted)
  {
    const auto now = std::chrono::steady_clock::now();
    std::size_t count = 0;

    for (std::size_t i = 0; i < _connections.size();)
    {
      auto &pc = _connections[i];
      if (!pc->inUse() && ((now - pc->lastUsed()) > idleTimeout))
      {
        // Collect-then-destroy under the caller's mutex (T6-2): move out, erase
        // the (now-empty) slot, let the caller destroy after unlocking.
        evicted.push_back(std::move(_connections[i]));
        _connections.erase(_connections.begin() + static_cast<long>(i));
        ++count;
      }
      else
      {
        ++i;
      }
    }
    if (count > 0)
    {
      touch();
    }
    return count;
  }

  /// \brief Visit every idle connection as its owning handle (never a position:
  /// an index handed out here would be invalidated by any concurrent erase —
  /// CR-1). `fn` receives (const std::shared_ptr<PooledConnection>&, lastUsed).
  template <typename Fn> void forEachIdle(Fn &&fn)
  {
    for (const auto &pc : _connections)
    {
      if (!pc->inUse())
      {
        fn(pc, pc->lastUsed());
      }
    }
  }

  /// \brief Remove `handle` from this pool, moving its owning reference into
  /// `evicted` for destruction after the caller releases the mutex (T6-2).
  /// \details THROWS std::logic_error (never assert — task-4.2: a use-after-free
  /// guard must survive NDEBUG) when `handle` is not present, and (task-4.3)
  /// when it is still in use — this is the one erase path that was previously
  /// unguarded. The other two erase paths gate on !inUse() themselves:
  /// tryAcquireFree only erases connections it has just tested !inUse(), and
  /// purgeIdle gates on !pc->inUse() && expired.
  void erase(const std::shared_ptr<PooledConnection> &handle,
             std::vector<std::shared_ptr<PooledConnection>> &evicted)
  {
    auto it = std::find(_connections.begin(), _connections.end(), handle);
    if (it == _connections.end())
    {
      throw std::logic_error("EndpointPool::erase: connection handle not present in pool");
    }
    if ((*it)->inUse())
    {
      throw std::logic_error("EndpointPool::erase: refusing to erase an in-use connection");
    }
    evicted.push_back(std::move(*it));
    _connections.erase(it);
    touch();
  }

  /// \brief True iff this pool holds at least one connection and none is in use
  /// (task-5.1, DP-3). The `size() > 0` requirement is load-bearing: an EMPTY
  /// pool has nothing to reuse, so treating it as "all idle" would make it an
  /// eviction candidate at both acquire_ eviction sites — letting
  /// evictOneIdlePoolLruLocked_ select a pool the caller may be mid-acquire on,
  /// or letting an empty pool linger and occupy a maxEndpointPools slot. See the
  /// designPrinciple: no size()==0 pool persists across an acquire_/purgeIdleCore_
  /// return-or-throw (enforced with the Option-A retire at acquire_'s throw).
  bool allIdle() const
  {
    if (_connections.empty())
    {
      return false;
    }
    for (const auto &pc : _connections)
    {
      if (pc->inUse())
      {
        return false;
      }
    }
    return true;
  }

  /// \brief Visit EVERY connection's HttpClient (in-use or idle) — used by the
  /// blocking-quiesce destructor's STEP 2 to cancelInFlight() each pooled
  /// client so a request parked in receiveSync/acquireLease unwinds. Must be
  /// called under JsonRpcClientImpl::_mutex.
  template <typename Fn> void forEachClient(Fn &&fn)
  {
    for (const auto &pc : _connections)
    {
      fn(pc->client());
    }
  }

  void touch() { _lastTouched = std::chrono::steady_clock::now(); }

  std::chrono::steady_clock::time_point lastTouched() const { return _lastTouched; }

  std::size_t size() const { return _connections.size(); }

  const std::string &endpoint() const { return _endpoint; }

private:
  // Qualified deliberately: an unqualified `friend struct
  // JsonRpcClientTestAccess;` written inside namespace detail would name
  // detail::JsonRpcClientTestAccess (nearest-enclosing-namespace rule), a
  // different, never-defined type — so the test could not read _connections.
  friend struct ::iora::modules::connectors::JsonRpcClientTestAccess;

  std::string _endpoint;
  // shared_ptr, not unique_ptr (CR-1/task-4.1a): a ConnectionLease holds an
  // owning handle to its connection, so identity is the object itself. An erase
  // drops the pool's reference; a lease that outlives the erase keeps the
  // connection alive, and markFree() on a detached connection stays well-defined.
  std::vector<std::shared_ptr<PooledConnection>> _connections;
  // task-6.1a: creations reserved but not yet published. Plain, not atomic —
  // see pendingCreates() above. Zero except inside acquire_'s unlocked
  // construction window.
  std::size_t _pendingCreates{0};
  std::chrono::steady_clock::time_point _lastTouched;
};

/// \brief RAII handle to one pooled connection; releases it (under the client
/// mutex) on destruction.
/// \details Holds ONLY owning references (task-4.1c): a shared_ptr keep-alive to
/// the owning JsonRpcClientImpl (which keeps its _mutex and _pools map alive so
/// the destructor can never touch freed state — CR-1c), the connection's pool,
/// and the connection itself. No raw pointers, no vector index — so a lease can
/// never be aliased onto a different connection (CR-1) nor dereference a freed
/// pool/mutex (CR-1c). Releasing into a pool that no longer contains the
/// connection reduces to conn->markFree() on a still-owned object plus a
/// best-effort pool touch.
class ConnectionLease
{
public:
  ConnectionLease() = delete;

  ConnectionLease(std::shared_ptr<JsonRpcClientImpl> impl, std::shared_ptr<EndpointPool> pool,
                  std::shared_ptr<PooledConnection> conn)
      : _impl(std::move(impl)), _pool(std::move(pool)), _conn(std::move(conn))
  {
  }

  // A moved-from lease is inert because moving _impl leaves the source's _impl
  // null (guaranteed by shared_ptr's move ctor), and the destructor no-ops on a
  // null _impl. So the default member-wise move is exactly right — no separate
  // "active" flag is needed to track liveness.
  ConnectionLease(ConnectionLease &&) noexcept = default;
  ConnectionLease &operator=(ConnectionLease &&) = delete;
  ConnectionLease(const ConnectionLease &) = delete;
  ConnectionLease &operator=(const ConnectionLease &) = delete;

  /// Defined out of line below, once JsonRpcClientImpl is complete: the body
  /// releases the connection under Impl::_mutex, so it needs the full type.
  ~ConnectionLease();

  iora::network::HttpClient &client() { return _conn->client(); }

private:
  // Declaration order is load-bearing (thread-safety L-5 / T5-17). Members are
  // destroyed in reverse declaration order, AFTER the destructor body runs.
  //   _impl  FIRST  -> destroyed LAST: the destructor body releases the
  //          connection under JsonRpcClientImpl::_mutex through _impl, so Impl
  //          (and its mutex and pool map) must still be alive for the whole body.
  //   _conn  LAST   -> destroyed FIRST.
  // Do NOT move the lock acquisition into any member's destructor: the lock must
  // be taken by the destructor body while _impl is still guaranteed live here.
  std::shared_ptr<JsonRpcClientImpl> _impl;
  std::shared_ptr<EndpointPool> _pool;
  std::shared_ptr<PooledConnection> _conn;
};
} // namespace detail

/// \brief Implementation body of the JSON-RPC 2.0 client (pImpl target).
/// \details Holds ALL client state and every operation the public facade or an
/// async task invokes. It derives from std::enable_shared_from_this and is
/// constructed only via std::make_shared (through create()): async work captures
/// a std::shared_ptr<JsonRpcClientImpl> by value, so the implementation outlives
/// any task still referencing it, and a later phase (task-4.1c) can hand a
/// ConnectionLease a shared_ptr to this object. The private PrivateTag makes
/// create() the single construction path — a stack or bare-new instance would
/// break shared_from_this().
class JsonRpcClientImpl : public std::enable_shared_from_this<JsonRpcClientImpl>
{
  // Passkey. PrivateTag is private, so only create() (a member) can name it;
  // the constructor is public solely so std::make_shared can call it. This
  // guarantees every JsonRpcClientImpl is heap-owned by a shared_ptr, which
  // shared_from_this() (and task-4.1c's ConnectionLease) require.
  struct PrivateTag
  {
  };

  // ==========================================================================
  // Blocking-quiesce primitive (SHAPE-B, task-3.1 — the single authority).
  // Compiler+ASan-proven by coding_trackers tools/proofs/quiesce_shapeb_probe.cpp
  // and inflight_probe.cpp. These three types are IMPLEMENTATION DETAIL of this
  // header (private nested — round-2 LOW-2): the promoted public surface never
  // names them; the test seam observes {_inFlight, _closing, _owners} instead.
  // Their inline bodies reach this class's later-declared quiesce state
  // (_quiesceMutex/_quiesceCv/_inFlight/_owners/_closing) via a complete-class
  // context, and — being nested — have access to those private members.
  // ==========================================================================

  /// \brief The single admission decision, NON-throwing (round-7 T7-4): gate +
  /// increment are ONE atomic step under _quiesceMutex; a refused guard sets
  /// _entered=false and never increments (so _inFlight is balanced and never
  /// underflows to SIZE_MAX). The dtor decrements and notifies UNDER the lock
  /// (round-2 C-1): the five SYNCHRONOUS entry points hold a bare CountGuard on
  /// a raw Impl* with NO keep-alive, so notifying after releasing _quiesceMutex
  /// would let the quiescing destructor free Impl (hence _quiesceCv) in the gap.
  class CountGuard
  {
  public:
    explicit CountGuard(JsonRpcClientImpl *impl) : _impl(impl)
    {
      std::lock_guard<std::mutex> lk(_impl->_quiesceMutex);
      if (_impl->_closing.load(std::memory_order_relaxed)) // read under _quiesceMutex => relaxed ok
      {
        return; // REFUSED: _entered stays false, no increment
      }
      ++_impl->_inFlight;
      _entered = true;
    }
    CountGuard(const CountGuard &) = delete;
    CountGuard &operator=(const CountGuard &) = delete;
    CountGuard(CountGuard &&) = delete;
    CountGuard &operator=(CountGuard &&) = delete;
    ~CountGuard()
    {
      if (!_entered)
      {
        return;
      }
      std::lock_guard<std::mutex> lk(_impl->_quiesceMutex); // notify UNDER the lock (C-1)
      --_impl->_inFlight;
      _impl->_quiesceCv.notify_all();
    }
    bool entered() const noexcept { return _entered; }

  private:
    JsonRpcClientImpl *_impl;
    bool _entered{false};
  };

  /// \brief Self-destruct discriminator, DECOUPLED from CountGuard (task-3.1(c)).
  /// Registers the CURRENTLY-executing thread in _owners for the duration of the
  /// counted work. ALWAYS a body-local of the executing context, so it is
  /// constructed AND destroyed on the SAME thread — which is what makes
  /// owners.erase(this_thread) always match.
  class OwnerScope
  {
  public:
    explicit OwnerScope(JsonRpcClientImpl *impl) : _impl(impl)
    {
      std::lock_guard<std::mutex> lk(_impl->_quiesceMutex);
      _impl->_owners.push_back(std::this_thread::get_id());
    }
    OwnerScope(const OwnerScope &) = delete;
    OwnerScope &operator=(const OwnerScope &) = delete;
    OwnerScope(OwnerScope &&) = delete;
    OwnerScope &operator=(OwnerScope &&) = delete;
    ~OwnerScope()
    {
      std::lock_guard<std::mutex> lk(_impl->_quiesceMutex);
      const auto id = std::this_thread::get_id();
      auto it = std::find(_impl->_owners.begin(), _impl->_owners.end(), id);
      if (it != _impl->_owners.end())
      {
        _impl->_owners.erase(it);
      }
    }

  private:
    JsonRpcClientImpl *_impl;
  };

  /// \brief The heap object for an ASYNC counted call. ONE
  /// shared_ptr<InFlightToken> is captured by the enqueued closure; the token
  /// holds a shared_ptr<Impl>, so Impl (and its embedded quiesce state) always
  /// outlives any task that outlives the client — no separate detached quiesce
  /// struct is needed (SHAPE-B key insight).
  ///
  /// DECLARATION ORDER IS LOAD-BEARING (destroyed in reverse): _impl LAST
  /// (keep-alive through the notify), _guard SECOND (decrement+notify), the
  /// callables FIRST (C4-1: user-held state torn down BEFORE the waiter is
  /// released). Templated on the RPC result type so the future-returning
  /// overloads (round-3 H-1) can plumb a typed std::promise through _onSuccess /
  /// _onError WITHOUT ThreadPool::enqueueWithResult / packaged_task: the
  /// overload creates the promise, hands its future to the caller before
  /// enqueue, and the callables set_value / set_exception. The callback overload
  /// carries plain user std::functions on the same channels. runBody() is
  /// nullary — the RPC request travels captured inside _perform (round-2 M-1),
  /// so the enqueued closure captures ONLY the token.
  template <typename Result> class InFlightToken
  {
  public:
    InFlightToken(std::shared_ptr<JsonRpcClientImpl> impl,
                  std::function<Result(JsonRpcClientImpl *)> perform,
                  std::function<void(Result)> onSuccess,
                  std::function<void(std::exception_ptr)> onError)
        : _impl(std::move(impl)), _guard(_impl.get()), _perform(std::move(perform)),
          _onSuccess(std::move(onSuccess)), _onError(std::move(onError))
    {
    }
    InFlightToken(const InFlightToken &) = delete;
    InFlightToken &operator=(const InFlightToken &) = delete;
    InFlightToken(InFlightToken &&) = delete;
    InFlightToken &operator=(InFlightToken &&) = delete;

    /// \brief Admission result: true if the CountGuard entered (was not refused
    /// by the closing gate).
    bool entered() const noexcept { return _guard.entered(); }

    /// \brief Run the RPC body on a worker thread. OwnerScope registers THIS
    /// worker as an executor for the duration of the body (including the user
    /// callback), reaching Impl via _impl. The token already counted at
    /// construction, so runBody() takes NO CountGuard (task-3.3).
    void runBody()
    {
      OwnerScope owner(_impl.get());
      try
      {
        Result r = _perform(_impl.get());
        // The RPC succeeded; deliver the result with its OWN guard (cpp17 L-1)
        // so a throwing user onSuccess is NOT misreported as a failed call
        // routed to onError. Only _perform's exceptions reach the error channel
        // (the outer catch). A throwing onSuccess is swallowed for the same
        // reason as onError (TS-4): it must not escape into the worker.
        if (_onSuccess)
        {
          try
          {
            _onSuccess(std::move(r));
          }
          catch (...)
          {
          }
        }
      }
      catch (...)
      {
        deliverError_(std::current_exception());
      }
    }

    /// \brief Caller-side failure channel (round-3 M-1): route a refusal or an
    /// enqueue failure through the SAME error callable the body would use. Never
    /// runs the RPC; never enqueued afterwards.
    void fail(std::exception_ptr e) { deliverError_(std::move(e)); }

  private:
    /// \brief Swallow-guarded onError delivery, shared by runBody's error path
    /// and fail() (simpl round-3 L-1). A throwing user error handler must not
    /// escape into a ThreadPool worker (runBody) nor out of callAsync (fail) —
    /// callAsync's contract is "do not throw" (TS-4/TS-7). The future overloads'
    /// _onError is promise.set_exception (cannot throw on a fresh promise), so
    /// the guard is inert there.
    void deliverError_(std::exception_ptr e)
    {
      if (_onError)
      {
        try
        {
          _onError(std::move(e));
        }
        catch (...)
        {
        }
      }
    }

    std::shared_ptr<JsonRpcClientImpl> _impl;                // destroyed LAST (keep-alive)
    CountGuard _guard;                                       // destroyed SECOND (decrement+notify)
    std::function<Result(JsonRpcClientImpl *)> _perform;     // the RPC work (captures the request)
    std::function<void(Result)> _onSuccess;                  // deliver result (set_value / user cb)
    std::function<void(std::exception_ptr)> _onError;        // destroyed FIRST (C4-1)
  };

public:
  JsonRpcClientImpl(PrivateTag, iora::core::ThreadPool &threadPool, Config config)
      : _threadPool(threadPool), _config(std::move(config)), _nextId(1), _totalConnections(0)
  {
    if (!_config.httpClientFactory)
    {
      // task-7.1b — the default factory receives the derived config and honours
      // it verbatim; its body reduces to make_unique<HttpClient>(derived).
      _config.httpClientFactory =
        [](const std::string &, const iora::network::HttpClient::Config &derived)
      { return std::make_unique<iora::network::HttpClient>(derived); };
    }

    // task-7.2a/7.2d: the constructor contributes NOTHING to defaultHeaders.
    // Keep-alive is now Config::reuseConnections (derived from enableKeepAlive in
    // the HttpClient::Config built below); HttpClient emits its own Connection
    // line, so a second one here would be a duplicate on the wire. The client's
    // only wire header is `Accept-Encoding: identity`, added per request in
    // mergeHeaders_ (task-7.2b) — never in _config, so no client-owned entry can
    // collide with defaultHeaders validation.

    // === Constructor header pipeline (constructor_pipeline_ordering_step0_r1).
    // These steps MUTATE _config.defaultHeaders and MUST run before the shared_ptr
    // is published (designPrinciple #9); mergeHeaders_ later only READS the result.
    // (1) task-7.3d: validate every defaultHeaders entry against the CONSTRUCTOR
    // reject set + the RFC 9110 grammar, so a misconfigured operator fails module
    // LOAD once with a clear diagnostic, not on every RPC.
    for (const auto &kv : _config.defaultHeaders)
    {
      validateHeaderOrThrow_(kv.first, kv.second, /*perCall=*/false, "in Config::defaultHeaders");
    }
    // (2) task-7.4: canonicalise Content-Type to HttpClient's exact spelling (the
    // only field HttpClient also writes INTO the request map, at postJson), then
    // self-dedup defaultHeaders case-insensitively (last-wins, first-seen spelling
    // retained) so a config like "Accept:a,accept:b" cannot yield two wire lines.
    for (auto &kv : _config.defaultHeaders)
    {
      if (iora::core::StringUtils::iequals(kv.first, "Content-Type"))
      {
        kv.first = "Content-Type";
      }
    }
    _config.defaultHeaders = dedupHeadersLastWins_(_config.defaultHeaders);
    // (3) task-7.3c: User-Agent is stream-written by HttpClient from
    // Config::userAgent, never via the header map, so it cannot be de-duplicated
    // downstream. Consume it out of defaultHeaders (case-insensitive; step (2)
    // already collapsed any duplicate to one entry) into the derived config's
    // userAgent below. A per-call User-Agent is rejected in mergeHeaders_.
    std::string consumedUserAgent;
    bool haveUserAgent = false;
    {
      std::vector<std::pair<std::string, std::string>> kept;
      kept.reserve(_config.defaultHeaders.size());
      for (auto &kv : _config.defaultHeaders)
      {
        if (iora::core::StringUtils::iequals(kv.first, "User-Agent"))
        {
          consumedUserAgent = kv.second;
          haveUserAgent = true;
        }
        else
        {
          kept.push_back(std::move(kv));
        }
      }
      _config.defaultHeaders = std::move(kept);
    }

    // task-7.1a — build the derived HttpClient::Config ONCE, here at the END of
    // the constructor body (constructor_pipeline_ordering step 4: AFTER the
    // above fixups and — once task-7.3c lands — after a caller-supplied
    // User-Agent is consumed into a ctor local read below). Stored in the
    // NON-const member _derivedHttpConfig, immutable BY CONVENTION like _config
    // (designPrinciple #9): a language-const member cannot be initialised from
    // the body-mutated _config. makeHttpClient_ reads it lock-free and passes it
    // by const-ref to every factory invocation; the happens-before is the
    // shared_ptr publication in create(), not `const`.
    iora::network::HttpClient::Config derived;
    derived.requestTimeout = _config.requestTimeout;
    derived.connectTimeout = _config.connectionTimeout; // names differ (web W2-L6)
    derived.reuseConnections = _config.enableKeepAlive;
    // UNIT-TRUNCATION RULE (web W2-M3): connectionIdleTimeout is SECONDS; a naive
    // cast of a sub-second socketIdleTimeout truncates to 0 s and would make
    // `now - lastUsed < 0s` always false, closing and reopening the socket on
    // every request. Floor the derived value at 1 s.
    derived.connectionIdleTimeout = std::max(
      std::chrono::seconds(1),
      std::chrono::duration_cast<std::chrono::seconds>(_config.socketIdleTimeout));
    // leaseAcquireTimeout: a BOUNDED residual-bug detector (web W4-M6). Post-fix
    // nothing should contend for a pooled client's lease; 3 x requestTimeout is
    // long enough a legitimate exchange never trips it, short enough a residual
    // identity bug surfaces within a few request budgets. (HttpClient defaults it
    // to 0 = wait indefinitely.)
    derived.leaseAcquireTimeout = 3 * _config.requestTimeout;
    // followRedirects/maxRedirects stay at HttpClient defaults — inert on this
    // path; mapping them would be a feature-shaped no-op. task-7.3c: a
    // defaultHeaders User-Agent consumed at pipeline step (3) overrides the
    // HttpClient default; absent one, the HttpClient default stands.
    if (haveUserAgent)
    {
      derived.userAgent = consumedUserAgent;
    }
    _derivedHttpConfig = std::move(derived);
  }

  /// \brief The only construction path: heap-allocate via make_shared so
  /// shared_from_this() is well-formed for the lifetime of the object.
  static std::shared_ptr<JsonRpcClientImpl> create(iora::core::ThreadPool &threadPool,
                                                   Config config)
  {
    return std::make_shared<JsonRpcClientImpl>(PrivateTag{}, threadPool, std::move(config));
  }

  // -------------------------------------------------------------------------
  // Counted PUBLIC entry points (task-3.3). Each SYNCHRONOUS entry takes its
  // CountGuard as the FIRST local (admission), then — call/notify/callBatch,
  // which can run a user httpClientConfigurer via acquire_ — an OwnerScope so a
  // callback that destroys the client is detected as self-destruct (task-3.2).
  // The non-counted *Core_ workers below hold the real logic; the ASYNC path's
  // runBody() calls the Core directly so admitted work is honored, never
  // gate-refused mid-queue (task-3.3 admission-at-call semantics).
  // -------------------------------------------------------------------------
  iora::parsers::Json call(const std::string &endpoint, const std::string &method,
                           const iora::parsers::Json &params,
                           const std::vector<std::pair<std::string, std::string>> &headers)
  {
    CountGuard guard(this);
    if (!guard.entered())
    {
      throw ClientShutdownError("JsonRpcClient::call: refused; client is closing");
    }
    OwnerScope owner(this);
    return callCore_(endpoint, method, params, headers);
  }

  void notify(const std::string &endpoint, const std::string &method,
              const iora::parsers::Json &params,
              const std::vector<std::pair<std::string, std::string>> &headers)
  {
    CountGuard guard(this);
    if (!guard.entered())
    {
      throw ClientShutdownError("JsonRpcClient::notify: refused; client is closing");
    }
    OwnerScope owner(this);
    notifyCore_(endpoint, method, params, headers);
  }

  std::future<iora::parsers::Json>
  callAsync(const std::string &endpoint, const std::string &method,
            const iora::parsers::Json &params,
            const std::vector<std::pair<std::string, std::string>> &headers)
  {
    return dispatchFuture_<iora::parsers::Json>(
      callPerform_(endpoint, method, params, headers),
      "JsonRpcClient::callAsync: refused; client is closing");
  }

  void callAsync(const std::string &endpoint, const std::string &method,
                 const iora::parsers::Json &params,
                 const std::vector<std::pair<std::string, std::string>> &headers,
                 std::function<void(iora::parsers::Json)> onSuccess,
                 std::function<void(std::exception_ptr)> onError)
  {
    // The user callables ARE the token's delivery channels: runBody() and fail()
    // already null-check _onSuccess/_onError, so hand them over directly (no
    // pass-through wrapper lambda — simpl-1). std::function<void(Json)> is
    // exactly InFlightToken<Json>::_onSuccess's type.
    auto token = std::make_shared<InFlightToken<iora::parsers::Json>>(
      shared_from_this(), callPerform_(endpoint, method, params, headers), std::move(onSuccess),
      std::move(onError));
    // TS-5: the user's onError may run SYNCHRONOUSLY on THIS thread (refusal or
    // enqueue failure, both inside dispatchToken_). Register as an owner so a
    // self-destruct from it is caught by quiesce STEP-1 (terminate) instead of
    // silently deadlocking STEP-3 with a still-counted token pinned in this
    // frame. If enqueue succeeds no user code runs here and the scope deregisters
    // on return; the worker's runBody registers its own OwnerScope. The future
    // overloads need no such scope — their fail() runs set_exception, not user
    // code — so this lives here, not in dispatchToken_.
    OwnerScope owner(this);
    dispatchToken_(token, "JsonRpcClient::callAsync: refused; client is closing");
  }

  std::vector<iora::parsers::Json>
  callBatch(const std::string &endpoint, const std::vector<BatchItem> &items,
            const std::vector<std::pair<std::string, std::string>> &headers)
  {
    CountGuard guard(this);
    if (!guard.entered())
    {
      throw ClientShutdownError("JsonRpcClient::callBatch: refused; client is closing");
    }
    OwnerScope owner(this);
    return callBatchCore_(endpoint, items, headers);
  }

  std::future<std::vector<iora::parsers::Json>>
  callBatchAsync(const std::string &endpoint, const std::vector<BatchItem> &items,
                 const std::vector<std::pair<std::string, std::string>> &headers)
  {
    return dispatchFuture_<std::vector<iora::parsers::Json>>(
      [endpoint, items, headers](JsonRpcClientImpl *impl)
      { return impl->callBatchCore_(endpoint, items, headers); },
      "JsonRpcClient::callBatchAsync: refused; client is closing");
  }

  /// \brief The single call-perform closure shared by both callAsync overloads
  /// (simpl LOW-2): captures the request by value and invokes the NON-counted
  /// callCore_ on the worker's Impl. The token stores it type-erased as
  /// std::function<Json(Impl*)>, so returning it as such adds no extra erasure.
  std::function<iora::parsers::Json(JsonRpcClientImpl *)>
  callPerform_(const std::string &endpoint, const std::string &method,
               const iora::parsers::Json &params,
               const std::vector<std::pair<std::string, std::string>> &headers)
  {
    return [endpoint, method, params, headers](JsonRpcClientImpl *impl)
    { return impl->callCore_(endpoint, method, params, headers); };
  }

  std::size_t purgeIdle()
  {
    CountGuard guard(this);
    if (!guard.entered())
    {
      return 0; // refused: NO-OP returning 0 (task-3.4(a))
    }
    return purgeIdleCore_();
  }

  /// \brief By-value config snapshot (task-3.3(ii)): NOT counted; noexcept
  /// removed (Config holds a vector and std::functions, so the copy can throw).
  Config config() const { return _config; }

  /// \brief By-value, atomic-free stats snapshot (task-3.3(ii)): NOT counted;
  /// noexcept removed. Must not be called concurrently with destruction.
  ClientStatsSnapshot getStats() const
  {
    ClientStatsSnapshot s;
    s.totalRequests = _stats.totalRequests.load(std::memory_order_relaxed);
    s.successfulRequests = _stats.successfulRequests.load(std::memory_order_relaxed);
    s.failedRequests = _stats.failedRequests.load(std::memory_order_relaxed);
    s.timeoutRequests = _stats.timeoutRequests.load(std::memory_order_relaxed);
    s.retriedRequests = _stats.retriedRequests.load(std::memory_order_relaxed);
    s.batchRequests = _stats.batchRequests.load(std::memory_order_relaxed);
    s.notificationRequests = _stats.notificationRequests.load(std::memory_order_relaxed);
    s.poolExhaustions = _stats.poolExhaustions.load(std::memory_order_relaxed);
    s.connectionsCreated = _stats.connectionsCreated.load(std::memory_order_relaxed);
    s.connectionsEvicted = _stats.connectionsEvicted.load(std::memory_order_relaxed);
    return s;
  }

  void resetStats()
  {
    CountGuard guard(this);
    if (!guard.entered())
    {
      return; // refused: NO-OP (task-3.4(a))
    }
    _stats.reset();
  }

  /// \brief Blocking quiesce (task-3.5), run on the DESTROYING (user) thread by
  /// the facade's ~JsonRpcClient — NEVER by ~JsonRpcClientImpl (which may run on
  /// a worker holding the last shared_ptr<Impl>). Four SEQUENTIAL, never-nested
  /// scopes. There is NO timeout, NO watchdog, NO progress counter, NO config
  /// knob; STEP 2's cancellation makes STEP 3's wait finite (with the honest
  /// residual bounds enumerated below — not a deadline knob).
  ///
  /// WHY STEP 3 TERMINATES: after the latch every counted call is in exactly one
  /// state, each reaching ~CountGuard in bounded time: (a) not started -> refused
  /// by the guard; (b) started, pre-postJson -> a permanently-closing HttpClient
  /// (or acquire_'s own _closing check) throws at first touch; (c) blocked in
  /// acquireLease -> woken by cancelInFlight()'s notify_all; (d) blocked in the
  /// receive loop -> its session was closed by STEP 2; (e) in connectSync ->
  /// bounded by connectTimeout; (f) in DNS -> bounded by the DNS timeout; (g) in
  /// retry backoff -> woken by STEP 1's notify (interruptible wait); (h) queued
  /// in the pool -> counted; runs (and hits acquire_'s _closing throw) or is
  /// discarded (broken_promise). The count is monotone non-increasing after the
  /// latch.
  ///
  /// (i) HONEST RESIDUAL (rewritten for PHASE 6 — task-6.2) — a call parked in
  /// the USER httpClientFactory/httpClientConfigurer. Phase 6 runs those on the
  /// calling thread with _mutex RELEASED and with no std::async/wait_for around
  /// them (both deleted), which removes the two bounds this note used to
  /// describe: the callbacks no longer delay STEP 2 (it needs _mutex, which they
  /// no longer hold) and there is no 30 s wait to expire. What remains is
  /// state (x) in the enumeration above, and it is genuinely unbounded: the call
  /// is counted, so STEP 3 waits for it, and STEP 2's cancelInFlight() cannot
  /// interrupt it — the callback is user code, not HTTP I/O on a pooled client,
  /// and the connection under construction is not yet in any pool for the sweep
  /// to reach. So the quiesce is bounded by max(cancellation, the user callback
  /// returning). With the default factory that is instant. This is a property of
  /// user code the design cannot cancel, not a deadline this design adds; the
  /// post-relock _closing recheck (task-6.1b(d)) ensures the callback's RESULT
  /// is discarded rather than published once it does return.
  void quiesce()
  {
    // STEP 1 — LATCH (_quiesceMutex). Self-destruct from inside our own work is
    // a guaranteed permanent block (this thread's OwnerScope cannot leave
    // _owners until the callback returns, while we would wait for exactly that):
    // diagnose and terminate (task-3.2) — the honest analogue of Transport::stop
    // throwing for the isomorphic I/O-thread case (a destructor cannot throw).
    {
      std::unique_lock<std::mutex> lk(_quiesceMutex);
      if (std::find(_owners.begin(), _owners.end(), std::this_thread::get_id()) != _owners.end())
      {
        // std::fputs, not std::cerr: <iostream> would drag the static
        // std::ios_base::Init object into every TU that includes this public
        // header, for one diagnostic on the fatal path (simpl LOW-6 / iteration 2).
        std::fputs("fatal: JsonRpcClient destroyed from inside its own callback "
                   "(self-deadlock); calling std::terminate()\n",
                   stderr);
        std::terminate();
      }
      _closing.store(true, std::memory_order_release);
    }
    _quiesceCv.notify_all(); // wake retry-backoff waiters, OUTSIDE the lock

    // STEP 2 — CANCEL (pool _mutex alone): cancelInFlight() every pooled client
    // so a request parked in receiveSync/acquireLease unwinds. This is what
    // makes STEP 3 finite. Needs stable connection identity (phase 4, task-4.1c).
    {
      std::lock_guard<std::mutex> lk(_mutex);
      for (auto &kv : _pools)
      {
        kv.second->forEachClient([](iora::network::HttpClient &c) { c.cancelInFlight(); });
      }
    }

    // STEP 3 — WAIT, UNCONDITIONALLY (_quiesceMutex). No predicate on time.
    {
      std::unique_lock<std::mutex> lk(_quiesceMutex);
      _quiesceCv.wait(lk, [this] { return _inFlight == 0; });
    }

    // STEP 4 — clear _pools (pool _mutex); _inFlight == 0 so no lease is
    // outstanding. Move the pools out BEFORE unlocking so ~EndpointPool /
    // ~HttpClient (which join I/O threads) run AFTER _mutex releases (T6-2).
    std::vector<std::shared_ptr<detail::EndpointPool>> evicted;
    {
      std::lock_guard<std::mutex> lk(_mutex);
      // THE SIXTH POOL-ERASE SITE, and the ONE that does not honour the
      // designPrinciple-#8 pin: this clears EVERY pool, pinned or not. Its
      // safety rests on a different argument from the other five — STEP 3 above
      // guarantees _inFlight == 0, and every production caller that can reach
      // acquire_ holds a CountGuard spanning it (call/notify/callBatch, and the
      // async InFlightToken's _guard), so no thread can still be inside phase
      // 6's unlocked construction window by the time we get here. That argument
      // is cross-subsystem and invisible from this line, so it is asserted
      // rather than assumed: a surviving reservation here means some caller
      // reached acquire_ WITHOUT being counted, and the parked thread is about
      // to re-lock a _mutex we are about to destroy.
      assert(std::all_of(_pools.begin(), _pools.end(),
                         [](const PoolMap::value_type &kv)
                         { return kv.second->pendingCreates() == 0; }) &&
             "quiesce STEP 4 with a creation still in flight — an uncounted acquire_ caller exists");
      for (auto &kv : _pools)
      {
        evicted.push_back(std::move(kv.second));
      }
      _pools.clear();
      // Keep the task-5.2 invariant true at this _mutex-quiescent point. Without
      // it _totalConnections stays at its pre-clear value forever while
      // recalcTotalLocked_() is 0, and because acquire_'s ENTRY tripwire runs
      // BEFORE its _closing check, any later acquire_ on a surviving Impl (a
      // worker can hold the last shared_ptr) would abort on the tripwire instead
      // of throwing ClientShutdownError.
      _totalConnections = 0;
    }
  }

private:
  using PoolMap = std::unordered_map<std::string, std::shared_ptr<detail::EndpointPool>>;

  // -------------------------------------------------------------------------
  // Non-counted CORE workers. The counted public wrappers above hold the
  // CountGuard/OwnerScope; the async runBody() calls these directly (task-3.3).
  // -------------------------------------------------------------------------
  iora::parsers::Json callCore_(const std::string &endpoint, const std::string &method,
                                const iora::parsers::Json &params,
                                const std::vector<std::pair<std::string, std::string>> &headers)
  {
    _stats.totalRequests.fetch_add(1, std::memory_order_relaxed);

    try
    {
      auto lease = acquire_(endpoint);
      iora::parsers::Json req = makeRequestEnvelope_(method, params, nextId_());
      iora::parsers::Json resp =
        sendJsonWithRetries_(lease.client(), endpoint, req, mergeHeaders_(headers));
      // Count success only AFTER the response parses cleanly: parseResponseOrThrow_
      // throws RemoteError on a JSON-RPC error envelope, which the catch(...) below
      // charges to failedRequests. Incrementing before the parse double-counted an
      // error reply as BOTH successful and failed (M-12).
      iora::parsers::Json parsed = parseResponseOrThrow_(std::move(resp));
      _stats.successfulRequests.fetch_add(1, std::memory_order_relaxed);
      return parsed;
    }
    catch (const PoolExhaustedError &)
    {
      _stats.poolExhaustions.fetch_add(1, std::memory_order_relaxed);
      _stats.failedRequests.fetch_add(1, std::memory_order_relaxed);
      throw;
    }
    catch (...)
    {
      _stats.failedRequests.fetch_add(1, std::memory_order_relaxed);
      throw;
    }
  }

  void notifyCore_(const std::string &endpoint, const std::string &method,
                   const iora::parsers::Json &params,
                   const std::vector<std::pair<std::string, std::string>> &headers)
  {
    _stats.totalRequests.fetch_add(1, std::memory_order_relaxed);
    _stats.notificationRequests.fetch_add(1, std::memory_order_relaxed);

    try
    {
      auto lease = acquire_(endpoint);
      iora::parsers::Json req = makeNotificationEnvelope_(method, params);
      (void)sendJsonWithRetries_(lease.client(), endpoint, req, mergeHeaders_(headers));
      _stats.successfulRequests.fetch_add(1, std::memory_order_relaxed);
    }
    catch (const PoolExhaustedError &)
    {
      _stats.poolExhaustions.fetch_add(1, std::memory_order_relaxed);
      _stats.failedRequests.fetch_add(1, std::memory_order_relaxed);
      throw;
    }
    catch (...)
    {
      _stats.failedRequests.fetch_add(1, std::memory_order_relaxed);
      throw;
    }
  }

  std::vector<iora::parsers::Json>
  callBatchCore_(const std::string &endpoint, const std::vector<BatchItem> &items,
                 const std::vector<std::pair<std::string, std::string>> &headers)
  {
    if (items.empty())
    {
      return {};
    }

    _stats.batchRequests.fetch_add(1, std::memory_order_relaxed);
    _stats.totalRequests.fetch_add(1, std::memory_order_relaxed);

    // The same two-catch shape callCore_ and notifyCore_ use. Without it a batch
    // acquire_ failure — PoolExhaustedError, or phase 6's new post-relock
    // ClientShutdownError / std::logic_error — was counted NOWHERE, even though
    // batchRequests and totalRequests had already been charged above.
    try
    {
      auto lease = acquire_(endpoint);
      return sendBatchOnLease_(lease, endpoint, items, headers);
    }
    catch (const PoolExhaustedError &)
    {
      _stats.poolExhaustions.fetch_add(1, std::memory_order_relaxed);
      _stats.failedRequests.fetch_add(1, std::memory_order_relaxed);
      throw;
    }
    catch (...)
    {
      _stats.failedRequests.fetch_add(1, std::memory_order_relaxed);
      throw;
    }
  }

  /// \brief The POST-ACQUIRE half of a batch call: build the envelope array and
  /// send it on an ALREADY-HELD lease.
  /// \details Split out of callBatchCore_ (behaviour-preserving) so the window
  /// this function's _closing fast-fail guards is reachable on its own. That
  /// window opens only between acquire_ returning and the send starting: if
  /// _closing is latched BEFORE the acquire, acquire_'s own entry check refuses
  /// first and the fast-fail below is never consulted. Keeping the send in the
  /// same function as the acquire therefore made the guard untestable — the
  /// entry check dominated every reachable ordering (found by the phase-6
  /// mutation sweep, where deleting the fast-fail changed nothing observable).
  /// task-6.4b(z) drives THIS function with a lease taken before the latch.
  std::vector<iora::parsers::Json>
  sendBatchOnLease_(detail::ConnectionLease &lease, const std::string &endpoint,
                    const std::vector<BatchItem> &items,
                    const std::vector<std::pair<std::string, std::string>> &headers)
  {
    // task-6.1b(d) / R2 M-C — CLOSE THE BATCH-PATH ASYMMETRY. The batch send
    // goes straight to sendJson_ and therefore never saw sendJsonWithRetries_'s
    // per-attempt _closing check, so a batch issued on a lease taken BEFORE the
    // destructor latched relied solely on the STEP-2 cancelInFlight() sweep
    // making postJson throw at first touch. Against a silent server that is not
    // enough and the destructor stalls to requestTimeout. Fail fast on the same
    // flag, with the same acquire ordering.
    //
    // FIRST, before the envelope loop: the loop charges
    // _stats.notificationRequests for every notification in the batch, and on a
    // refused send none of them is ever transmitted. Checking afterwards
    // inflated that counter on a path that sends nothing.
    if (_closing.load(std::memory_order_acquire))
    {
      throw ClientShutdownError("JsonRpcClient: cancelled before batch send; client is closing");
    }

    iora::parsers::Json batchReq = iora::parsers::Json::array();

    for (const auto &item : items)
    {
      if (item.id.has_value())
      {
        batchReq.push_back(makeRequestEnvelope_(item.method, item.params, item.id.value()));
      }
      else
      {
        batchReq.push_back(makeNotificationEnvelope_(item.method, item.params));
        _stats.notificationRequests.fetch_add(1, std::memory_order_relaxed);
      }
    }

    // Failure counting belongs to callBatchCore_, which wraps BOTH the acquire and
    // this send in the standard two-catch shape — counting failedRequests here as
    // well would double-charge it.
    //
    // task-7.8 (M2, R2-1): classify a TRANSPORT timeout on the batch SEND, scoped
    // to sendJson_ ONLY — exactly mirroring the single-call path, where the
    // classifier lives in sendJsonWithRetries_ (which wraps the send) and never
    // sees the RPC parse. If the classifier instead wrapped the parse below, a
    // RemoteError from parseBatchResponseOrThrow_ (a JSON-RPC application error
    // whose server-supplied message may contain "timeout", e.g. "gateway timeout")
    // would be mis-counted as a transport timeout — the batch-vs-single asymmetry
    // R2-1 flagged. timeoutRequests only; failedRequests stays callBatchCore_'s.
    iora::parsers::Json batchResp;
    try
    {
      batchResp = sendJson_(lease.client(), endpoint, batchReq, toHeaderMap_(mergeHeaders_(headers)));
    }
    catch (const std::exception &e)
    {
      if (isTimeoutFailure_(e))
      {
        _stats.timeoutRequests.fetch_add(1, std::memory_order_relaxed);
      }
      throw;
    }
    // Count success only AFTER the batch parses cleanly: parseBatchResponseOrThrow_
    // throws RemoteError/JsonRpcError on an error or missing-response item, which
    // callBatchCore_'s catch(...) charges to failedRequests. Incrementing before the
    // parse double-counted a batch carrying an error item as BOTH successful and
    // failed (M-12, batch site — the same defect as callCore_).
    std::vector<iora::parsers::Json> parsed =
      parseBatchResponseOrThrow_(std::move(batchResp), items);
    _stats.successfulRequests.fetch_add(1, std::memory_order_relaxed);
    return parsed;
  }

  std::size_t purgeIdleCore_()
  {
    // Declared BEFORE `guard` so the evicted connections/pools are destroyed
    // AFTER _mutex is released (thread-safety T6-2): ~HttpClient joins I/O
    // threads and a whole-pool eviction can drop N of them at once, so none of
    // that blocking teardown may run under the client mutex.
    std::vector<std::shared_ptr<detail::PooledConnection>> evictedConns;
    std::vector<std::shared_ptr<detail::EndpointPool>> evictedPools;
    std::lock_guard<std::mutex> guard(_mutex);
    std::size_t evictedTotal = 0;

    for (auto it = _pools.begin(); it != _pools.end();
         /* increment inside */)
    {
      auto &pool = *(it->second);
      std::size_t evicted = pool.purgeIdle(_config.idleTimeout, evictedConns);
      evictedTotal += evicted;
      _stats.connectionsEvicted.fetch_add(evicted, std::memory_order_relaxed);

      // PIN SITE 2 (designPrinciple #8): retire only when the pool is BOTH
      // empty and unpinned. A concurrent acquire_ may hold a reservation on
      // this pool while parked in its unlocked construction window — this is
      // exactly the re-entrant purgeIdle() the CR-3 fix makes legal, so the
      // helper's pendingCreates conjunct is what keeps that pool alive. The
      // helper returns the following iterator either way.
      it = retireIfEmptyAndUnpinnedLocked_(it, evictedPools);
    }
    // L-7: recalc ONCE after the loop, not per-pool — recalcTotalLocked_ is
    // itself O(pools), so a per-pool call made this O(pools^2). Still inside the
    // function-scoped lock_guard, so _totalConnections is only read under _mutex.
    _totalConnections = recalcTotalLocked_();
    // task-5.2 exit tripwire (single return under the function-scoped lock),
    // plus the I1 tripwire the counter one provably cannot see (DP#7): this is
    // a purgeIdleCore_ RETURN, one of the two exits the invariant names.
    assert(_totalConnections == recalcTotalLocked_());
    assert(noEmptyUnpinnedPoolLocked_());
    return evictedTotal;
  }

  /// \brief Deliver an admitted async token, or route its failure. Owns BOTH
  /// delivery-failure channels (simpl LOW-1): a refused token (gate closed) is
  /// delivered ClientShutdownError(refuseMsg) via fail(); an admitted token whose
  /// enqueue throws is delivered the enqueue exception via fail() (task-3.4(a)/
  /// (b)). The caller frame still holds `token` (passed by const ref) across
  /// fail(), so onError / set_exception completes BEFORE _inFlight can drop and
  /// let a concurrent destructor return.
  template <typename Token>
  void dispatchToken_(const std::shared_ptr<Token> &token, const char *refuseMsg)
  {
    if (!token->entered())
    {
      token->fail(std::make_exception_ptr(ClientShutdownError(refuseMsg)));
      return;
    }
    try
    {
      _threadPool.enqueue([token]() { token->runBody(); });
    }
    catch (...)
    {
      token->fail(std::current_exception());
    }
  }

  /// \brief The shared scaffolding of the two FUTURE-returning async overloads
  /// (round-3 H-1, simpl-2). OWNS the promise here, hands the future to the
  /// caller BEFORE enqueue, and routes both refusal and enqueue failure (via
  /// dispatchToken_) through set_exception. Discarded unrun -> the token's
  /// callables (sole promise holders) are destroyed -> broken_promise
  /// (task-3.4(c)). Deliberately does NOT use enqueueWithResult/packaged_task.
  /// No OwnerScope: fail() here runs set_exception, never user code (TS-5).
  template <typename Result>
  std::future<Result> dispatchFuture_(std::function<Result(JsonRpcClientImpl *)> perform,
                                      const char *refuseMsg)
  {
    auto promise = std::make_shared<std::promise<Result>>();
    std::future<Result> future = promise->get_future();
    auto token = std::make_shared<InFlightToken<Result>>(
      shared_from_this(), std::move(perform),
      [promise](Result r) { promise->set_value(std::move(r)); },
      [promise](std::exception_ptr e) { promise->set_exception(std::move(e)); });
    dispatchToken_(token, refuseMsg);
    return future;
  }

  /// \brief Move an emptied/idle pool out of _pools into the caller's evicted
  /// bin and erase its map node; returns the iterator following the erased node.
  /// The move (rather than a bare erase) keeps the pool alive until the caller
  /// destroys the bin AFTER releasing _mutex — one place so no erase site can
  /// forget to thread the removed pool into the bin (T6-2). Must hold _mutex.
  PoolMap::iterator retirePoolLocked_(PoolMap::iterator it,
                                      std::vector<std::shared_ptr<detail::EndpointPool>> &evictedPools)
  {
    evictedPools.push_back(std::move(it->second));
    return _pools.erase(it);
  }

  /// \brief The single T6-2-critical SUCCESS exit of acquire_ (simpl-1): the
  /// four success paths (reuse hit + three create paths) all end with the same
  /// tail — the task-5.2 in-lock tripwire assert, then RELEASE _mutex, then build
  /// the lease. Centralised so the assert-before-unlock ordering (the exit
  /// tripwire must run while _mutex is still held) and the unlock-before-lease
  /// discipline live in ONE audited place rather than four copies that can drift.
  /// The caller has already applied its counter delta, so the entry assert here
  /// is a live cross-check. acquire_'s pre-`lock` evicted bins still destruct in
  /// acquire_'s frame AFTER this returns (i.e. after unlock), preserving T6-2.
  /// Must be called holding `lock` (an acquire_-owned unique_lock on _mutex).
  detail::ConnectionLease
  finishAcquireLocked_(const std::shared_ptr<detail::EndpointPool> &pool,
                       const std::shared_ptr<detail::PooledConnection> &conn,
                       std::unique_lock<std::mutex> &lock)
  {
    assert(_totalConnections == recalcTotalLocked_()); // task-5.2 exit tripwire
    assert(noEmptyUnpinnedPoolLocked_());              // I1 tripwire (DP#7)
    lock.unlock();
    return detail::ConnectionLease(shared_from_this(), pool, conn);
  }

  detail::ConnectionLease acquire_(const std::string &endpoint)
  {
    // task-7.5a/7.5c — DERIVE THE POOL KEY FROM THE ORIGIN, not the full URL.
    // `endpoint` is the caller's full request URL; the pool is keyed on its
    // ORIGIN (scheme://host:effective-port) so two paths on one host share ONE
    // pool (and one HttpClient, one Transport, one DnsClient). Computed HERE,
    // BEFORE _mutex is taken (thread-safety L-1), and normalizeOrigin is a PURE
    // function of the URL string — it takes no runtime/capability state. It
    // THROWS std::invalid_argument on a malformed/unreachable URL form (userinfo,
    // IPv6 literal, empty/non-numeric/zero/out-of-range port, non-lowercase or
    // non-http(s) scheme); that throw propagates out of acquire_ before any pool
    // is minted (task-7.5b) — a form the transport would reject on every send
    // never mints a live pool. The full `endpoint` is still what the send path
    // (sendJson_/postJson) re-parses and transmits; only the KEY and the string
    // handed to the factory/configurer become the origin.
    const std::string origin = iora::network::normalizeOrigin(endpoint);

    // Declared BEFORE `lock` so that on EVERY exit path — normal return or the
    // PoolExhaustedError throw — these owning references are destroyed AFTER
    // `lock` releases _mutex. Members/locals are destroyed in reverse
    // declaration order, so `lock` (declared last) unlocks first, then these
    // vectors drop the last reference to any evicted connection/pool. Destroying
    // one runs ~HttpClient, which joins I/O threads and must never happen under
    // _mutex (thread-safety T6-2). This makes the ordering structural rather
    // than dependent on threading the destroy after every unlock() call.
    std::vector<std::shared_ptr<detail::PooledConnection>> evictedConns;
    std::vector<std::shared_ptr<detail::EndpointPool>> evictedPools;
    // Declared BEFORE `lock` for the same reason as the evicted bins above:
    // `pool` is an owning handle, and a later eviction on this same call can
    // remove it from _pools, making this local the last owner. Destroyed after
    // `lock` releases, so its ~EndpointPool (which joins I/O threads) can never
    // run under _mutex — on the throw path too, where the lock is released by
    // unwinding rather than an explicit unlock() (thread-safety T6-2/T-2).
    std::shared_ptr<detail::EndpointPool> pool;
    // task-6.1b(e) / T6-2 — ALSO declared BEFORE `lock`, and for a reason
    // specific to phase 6: this holds the connection built in the UNLOCKED
    // construction window until it is published under the re-taken lock. Every
    // post-relock throw (the re-look-up mismatch, the _closing recheck) unwinds
    // with _mutex HELD, so a holder declared inside the create branch would run
    // ~PooledConnection -> ~HttpClient — which joins I/O threads — under the
    // pool mutex. Declared here, it is destroyed only after `lock` unlocks.
    std::shared_ptr<detail::PooledConnection> newConn;
    std::unique_lock<std::mutex> lock(_mutex);

    // task-5.2 ENTRY tripwire: the invariant _totalConnections == Σ size() holds
    // at every _mutex-quiescent point, so it must hold on entry. Debug-only
    // (compiled out under NDEBUG, so recalcTotalLocked_'s O(pools) scan costs
    // nothing in release). Also covers the _closing exit below, which precedes
    // every mutation — no separate exit assert is needed there (M2/M-3).
    assert(_totalConnections == recalcTotalLocked_());

    // Refuse under the pool _mutex if the client is closing (task-3.1(f)): an
    // admitted call that reaches here AFTER the destructor's STEP-2 cancel loop
    // must not create a NEW pooled HttpClient the loop already passed. The
    // _mutex serialization vs. that loop admits only safe orders. Reading the
    // atomic (acquire) while holding _mutex is fine — this takes no _quiesceMutex.
    if (_closing.load(std::memory_order_acquire))
    {
      throw ClientShutdownError("JsonRpcClient: cancelled during acquire; client is closing");
    }

    // Ensure pool exists (respecting maxEndpointPools with LRU idle pool
    // eviction). Keyed on the ORIGIN (task-7.5c), never the full URL.
    pool = findPool_(origin);
    if (!pool)
    {
      if (_config.maxEndpointPools > 0 && _pools.size() >= _config.maxEndpointPools)
      {
        // task-5.3 (HD-7 row 6): ENFORCE the cap. The whole-pool LRU eviction is
        // best-effort; if no pool is entirely idle it cannot relieve the
        // overshoot, so REFUSE rather than silently exceed the cap unboundedly.
        // The `> 0 &&` conjunct above means maxEndpointPools == 0 is UNLIMITED,
        // so a default-configured client never reaches this throw. task-5.1's
        // Option-A retire guarantees no empty pool lingers to make this spurious.
        if (!evictOneIdlePoolLruLocked_(evictedPools))
        {
          assert(_totalConnections == recalcTotalLocked_()); // exit tripwire
          throw PoolExhaustedError(
            "Max endpoint pools reached and no idle pool to evict for endpoint: " + endpoint);
        }
      }
      // origin is guaranteed absent here (findPool_ just missed, and the
      // eviction above only ever removes a DIFFERENT, LRU-idle pool), so create
      // unconditionally — a find-or-create helper's lookup would be dead code.
      // The pool's _endpoint is the ORIGIN (task-7.5c): it is what pool->endpoint()
      // hands makeHttpClient_ and thence the factory/configurer.
      pool = _pools.emplace(origin, std::make_shared<detail::EndpointPool>(origin))
               .first->second;
    }

    // Try to reuse a free connection first. tryAcquireFree reports how many
    // idle-expired connections it erased; apply the counter deltas
    // UNCONDITIONALLY (both the reuse-hit and the nullptr-fall-through paths
    // erase), BEFORE branching on the handle and BEFORE the underGlobalCap read
    // below — this is the H-2 root fix (F-1): the create path must not evaluate
    // underGlobalCap against a stale-high total (task-5.2).
    std::size_t reclaimed = 0;
    auto conn = pool->tryAcquireFree(_config.idleTimeout, evictedConns, reclaimed);
    _totalConnections -= reclaimed;
    _stats.connectionsEvicted.fetch_add(reclaimed, std::memory_order_relaxed); // DP-2: count idle-expiry evictions
    if (conn)
    {
      return finishAcquireLocked_(pool, conn, lock); // reuse hit
    }

    // Can we create a new one?
    // task-6.1a: the per-endpoint cap counts RESERVED creations as well as
    // published ones. Reading size() alone here is a live overshoot bug under
    // phase 6: thread A reserves and unlocks before B reads size(), so on a
    // cap-1 endpoint B still sees size()==0, both create, and the pool
    // publishes 2 — an overshoot NO tripwire catches (_totalConnections is a
    // global sum, not a per-endpoint one).
    const bool underPerEndpointCap =
      pool->size() + pool->pendingCreates() < _config.maxConnectionsPerEndpoint;
    const bool underGlobalCap =
      (_config.globalMaxConnections == 0) || (_totalConnections < _config.globalMaxConnections);

    // The three former inline create paths (create outright / after evicting one
    // idle connection / after evicting a whole idle pool) differed ONLY in how
    // they made room, so they collapse into this single predicate plus the one
    // reserve->unlock->build->relock->publish tail below (task-6.1b(f)(ii)).
    // Short-circuit order is preserved exactly: the eviction helpers are still
    // reached only when the per-endpoint cap allows a create and the global cap
    // does not. Each helper reconciles _totalConnections to the exact
    // post-eviction sum, which is why the reservation below must come AFTER
    // this decision — incrementing before an in-condition eviction's recalc
    // would be silently overwritten (R2 L-F/ts-F).
    // NAMED IN THE PAST TENSE ON PURPOSE (simpl M4): evaluating this is NOT a
    // query. Both short-circuit operands are eviction calls with real effects —
    // the first can destroy an idle connection, the second an ENTIRE idle pool —
    // and they run only when the earlier operands do not already answer. A name
    // like `mayCreate` reads as a predicate and invites a reader to assume it is
    // re-evaluable or reorderable; it is neither.
    const bool madeRoomForCreate =
      underPerEndpointCap && (underGlobalCap ||
                              tryEvictOneIdleConnLruLocked_(evictedConns, evictedPools) ||
                              evictOneIdlePoolLruLocked_(evictedPools));

    if (!madeRoomForCreate)
    {
      // task-5.1 Option A (DP-3): reaching this throw with `pool` empty would
      // leave a size()==0 pool in _pools (allIdle() now excludes it, so neither
      // eviction site reclaims it) occupying a maxEndpointPools slot — a later
      // distinct endpoint could then be refused spuriously. Retire it here, AT
      // THE THROW ONLY — never eagerly after tryAcquireFree, which would orphan
      // the pool the create tail then populates. Order (L-2): exit tripwire,
      // then the retire (a 0-delta — an empty, unpinned pool contributes 0 to
      // recalcTotalLocked_), then throw. PIN SITE 1 (designPrinciple #8): the
      // helper's pendingCreates conjunct is what stops this throw retiring a
      // pool another thread is mid-construction on.
      assert(_totalConnections == recalcTotalLocked_()); // throw exit tripwire
      retireIfEmptyAndUnpinnedLocked_(origin, pool, evictedPools);
      // I1 asserted AFTER the retire (before it, `pool` is legitimately empty).
      // This is the acquire_ THROW exit designPrinciple #7 names explicitly.
      assert(noEmptyUnpinnedPoolLocked_());
      throw PoolExhaustedError("No available HTTP connections for endpoint: " + endpoint);
    }

    // ---------------------------------------------------------------------
    // CR-3 — THE CREATE TAIL. Everything above ran under _mutex; the user's
    // httpClientFactory/httpClientConfigurer must NOT (that is the whole
    // defect: a callback that re-enters the client deadlocks, and a slow one
    // blocks every other endpoint). Sequence: RESERVE under the lock, UNLOCK,
    // BUILD on this thread, RE-LOCK, re-validate, PUBLISH.
    // ---------------------------------------------------------------------

    // RESERVE (task-6.1a). ++pendingCreates and ++_totalConnections are ONE
    // pair, applied together under the lock: the reservation is what makes both
    // cap checks see this in-flight creation, what PINS the pool against all
    // five retire sites (designPrinciple #8), and what keeps the task-5.2
    // invariant _totalConnections == Σ(size() + pendingCreates) true throughout
    // the window. This increment REPLACES the former publish-time
    // ++_totalConnections — publishing is net-zero on the counter (insert +1 to
    // size(), -1 to pendingCreates), so counting at both points would
    // double-count: caught by the Debug tripwire, but under NDEBUG it drifts
    // _totalConnections permanently high until underGlobalCap starts refusing
    // legitimate creates with a spurious PoolExhaustedError in production.
    try
    {
      pool->reserveCreate();
    }
    catch (...)
    {
      // reserveCreate() is strongly exception-safe by ordering, and
      // _totalConnections has not been touched yet — so the counters are
      // already at their pre-call values and there is nothing to roll back.
      // What CAN remain is a freshly emplaced pool with nothing in it, which
      // designPrinciple #7 forbids persisting. No client exists on this path,
      // so no T6-2 concern arises.
      retireIfEmptyAndUnpinnedLocked_(origin, pool, evictedPools);
      assert(_totalConnections == recalcTotalLocked_());
      assert(noEmptyUnpinnedPoolLocked_());
      throw;
    }
    ++_totalConnections;

    // task-6.1b(a) — a LOCAL COPY of the pool's endpoint, which the task
    // mandates. Since task-7.5c this is the ORIGIN (pool->endpoint() ==
    // `origin`), NOT the caller's full URL: it is the string makeHttpClient_
    // passes to the public httpClientFactory and httpClientConfigurer, so an
    // out-of-tree extension point receives the origin, not a path-bearing URL.
    // The copy is kept deliberately: `origin` is a local this frame owns, but it
    // is consumed AFTER the lock is released and after arbitrary user code has
    // run and may have re-entered the client, and the re-look-up/rollback tail
    // below keys on this same string; owning it outright (rather than aliasing a
    // reference into the pool) makes that safety a local property rather than a
    // contract every future caller of acquire_ has to honour. The cost is one
    // small allocation on the create path only.
    const std::string endpointCopy = pool->endpoint();

    lock.unlock();
    // ================= UNLOCKED CONSTRUCTION WINDOW =================
    // The factory and configurer run HERE, on the calling thread, with no lock
    // held — so they may legally re-enter the client (call(), purgeIdle(), ...)
    // on this very endpoint. The pool cannot be retired under us while they do:
    // we hold a reservation, and a pool with pendingCreates() > 0 is never
    // erased (designPrinciple #8). The window is covered by the CALLER's
    // in-flight count (call()'s CountGuard / the async InFlightToken's guard),
    // so the destructor's STEP-3 wait cannot run past it.

    // Drop the evicted bins HERE, before entering the window, rather than at
    // function exit. They were filled under the lock above — by tryAcquireFree's
    // idle reclaim and by the madeRoomForCreate evictions, which can include an ENTIRE
    // pool — and phase 6 turned "destroyed a few instructions later" into
    // "destroyed after the user callback returns", which task-6.2 makes
    // explicitly UNBOUNDED. Holding them means the evicted sockets, fds and I/O
    // threads stay alive for that whole time even though the accounting has
    // already reclaimed their slots, so real concurrent resource usage can
    // exceed globalMaxConnections without bound. This is the correct place to
    // destroy them: no lock is held, which is exactly what T6-2 requires.
    evictedConns.clear();
    evictedPools.clear();
    // Guarantee the rollback paths below can retire a pool without allocating:
    // retirePoolLocked_ push_backs into this bin from inside a catch handler,
    // where a bad_alloc would REPLACE the user's original exception (which
    // task-6.3 asserts propagates unchanged) and skip the retire itself.
    evictedPools.reserve(1);

    try
    {
      newConn = std::make_shared<detail::PooledConnection>(makeHttpClient_(endpointCopy));
    }
    catch (...)
    {
      // task-6.1c — ROLLBACK. `newConn` is null here (the throw came from the
      // factory, the configurer, or make_shared); any HttpClient the factory
      // had already returned was destroyed by unwinding while still UNLOCKED,
      // which is exactly where ~HttpClient belongs (T6-2).
      //
      // lock.lock() cannot throw here: `lock` owns a valid, currently-unlocked,
      // non-recursive std::mutex, and unique_lock::lock() throws only for
      // "no mutex" or "already owns" — neither is reachable — while the
      // underlying pthread_mutex_lock has no failure mode for a default
      // (non-errorcheck, non-robust) mutex short of undefined behaviour.
      lock.lock();
      // PIN SITE 5 (designPrinciple #7 extended / #8): the pool was emplaced
      // before the window, so a failed first creation leaves it empty. Retiring
      // it is REQUIRED here — unlike the shutdown path below, the client keeps
      // running, and a stranded empty pool occupies a maxEndpointPools slot and
      // refuses a later DIFFERENT endpoint. The unpinned conjunct inside the
      // helper is equally required: a second thread may hold its own
      // reservation on this same pool, and retiring it would break ITS
      // re-look-up.
      rollbackCreateLocked_(endpointCopy, pool, evictedPools);
      // Rethrown with the lock HELD: unwinding releases `lock` first and only
      // then drops evictedPools/pool (declared before it), so the pool teardown
      // still happens outside _mutex.
      throw;
    }

    lock.lock();
    // ================= RE-LOCKED: RE-VALIDATE, THEN PUBLISH =================

    // task-6.1b(b) — DEFENSE IN DEPTH, and it runs FIRST. Re-look up the pool
    // BY KEY and verify IDENTITY before anything else touches `pool` or the
    // counters. This is NOT the primary CR-2 guard: the pin makes retiring a
    // pool with pendingCreates() > 0 impossible at every pin site, and we held
    // a reservation for the whole window, so a correct implementation can never
    // reach this throw. It stays as belt-and-suspenders — if a pin is ever
    // defective, this converts a silent corruption into a loud failure. An
    // unconditional throw, never an assert: a use-after-free guard must survive
    // NDEBUG (task-4.2).
    //
    // ORDERED BEFORE the _closing recheck deliberately. Both post-relock exits
    // decrement _totalConnections, and that decrement is only correct if `pool`
    // is still the pool under `endpoint`: a detaching site (either eviction
    // path) recomputes _totalConnections via recalcTotalLocked_, which already
    // excludes our reservation, so decrementing again on a detached pool
    // underflows std::size_t to SIZE_MAX and every later underGlobalCap check
    // passes forever. Validating identity first means no path can do that.
    {
      auto it = _pools.find(endpointCopy);
      if (it == _pools.end() || it->second != pool)
      {
        // Counters only: the helper's retire declines to touch a pool that is
        // no longer ours, which is exactly right — a detached pool is already
        // out of recalcTotalLocked_'s sum.
        rollbackCreateLocked_(endpointCopy, pool, evictedPools);
        throw std::logic_error(
          "JsonRpcClient: endpoint pool was retired or replaced while a creation was in "
          "flight (pool-pin invariant violated) for endpoint: " +
          endpointCopy);
      }
    }

    // task-6.1b(d) — RE-CHECK _closing. This is the load-bearing post-relock
    // check. quiesce()'s STEP 2 (the cancelInFlight sweep) takes only _mutex,
    // so it can have run to completion DURING our window: it iterates the pools
    // as they were then, never sees a connection still under construction, and
    // therefore cannot cancel it. Publishing an uncancelled client now would
    // leave a subsequent request bounded only by requestTimeout x (maxRetries+1)
    // instead of by cancellation, and STEP 3 would wait on it. Roll back
    // instead. Acquire ordering matches the entry check above.
    if (_closing.load(std::memory_order_acquire))
    {
      // The retire inside the helper is not strictly required on THIS path —
      // quiesce STEP 4 clears _pools wholesale — but doing it keeps
      // designPrinciple #7 true on every acquire_ return-or-throw without a
      // per-path exception to reason about (R2 L-3).
      rollbackCreateLocked_(endpointCopy, pool, evictedPools);
      // `newConn` is non-null here and is declared before `lock`: unwinding
      // unlocks first, so ~HttpClient runs OUTSIDE _mutex (T6-2).
      throw ClientShutdownError(
        "JsonRpcClient: cancelled during connection construction; client is closing");
    }

    // PUBLISH. Nothrow by construction (REMEDY B — see publishCreate).
    // _totalConnections is deliberately NOT incremented: the reservation
    // already counted this connection.
    pool->publishCreate(newConn, _stats);
    return finishAcquireLocked_(pool, newConn, lock);
  }

  std::shared_ptr<detail::EndpointPool> findPool_(const std::string &endpoint)
  {
    auto it = _pools.find(endpoint);
    if (it == _pools.end())
    {
      return nullptr;
    }
    return it->second;
  }

  /// \brief Release a leased connection back to its pool. Called ONLY from
  /// detail::ConnectionLease's destructor (befriended below). Encapsulates the
  /// M-3 invariant: markFree() ALWAYS runs under _mutex — even for a connection
  /// already evicted from _pools — because _inUse/_lastUsed are plain fields
  /// read by allIdle()/tryAcquireFree()/forEachIdle() on other threads. Only the
  /// pool touch is best-effort; the connection itself is still owned by the lease.
  void releaseConnection_(const std::shared_ptr<detail::EndpointPool> &pool,
                          const std::shared_ptr<detail::PooledConnection> &conn)
  {
    std::lock_guard<std::mutex> guard(_mutex);
    if (pool)
    {
      pool->release(conn); // markFree(conn) + touch(), under _mutex
    }
    else
    {
      conn->markFree();
    }
  }

  /// \brief The authoritative value of _totalConnections, recomputed from the
  /// pools (the task-5.2 tripwire compares the two).
  /// \details task-6.1a AMENDS this to add each pool's pendingCreates. Phase 6
  /// increments _totalConnections at RESERVATION — before the connection
  /// exists — so the invariant is
  ///     _totalConnections == Σ over pools of (size() + pendingCreates())
  /// and summing size() alone would make the tripwire fire inside every
  /// construction window BY CONSTRUCTION rather than on a real defect.
  std::size_t recalcTotalLocked_() const
  {
    std::size_t total = 0;
    for (const auto &kv : _pools)
    {
      total += kv.second->size() + kv.second->pendingCreates();
    }
    return total;
  }

  /// \brief True iff `p` holds no connection AND has no creation in flight.
  /// The single place the extended designPrinciple-#7 predicate is written, so
  /// the retire sites and the I1 checker below cannot drift apart.
  static bool poolIsEmptyAndUnpinnedLocked_(const detail::EndpointPool &p)
  {
    return p.size() == 0 && p.pendingCreates() == 0;
  }

  /// \brief INVARIANT I1 (architecture designPrinciple #7, as extended by phase
  /// 6): no size()==0 && pendingCreates()==0 pool persists in _pools.
  /// \details This exists because the task-5.2 counter tripwire provably CANNOT
  /// see an I1 violation: an empty pool contributes 0 to both _totalConnections
  /// and recalcTotalLocked_, so a stranded empty pool is invisible to it. Its
  /// only symptom is a maxEndpointPools slot occupied forever, refusing a later
  /// UNRELATED endpoint — which surfaces far from the cause. DP#7 requires I1 to
  /// be re-asserted after every unlock-window re-lock; asserting it next to each
  /// counter tripwire is how that clause is discharged. Debug-only (O(pools),
  /// compiled out under NDEBUG). Must hold _mutex.
  bool noEmptyUnpinnedPoolLocked_() const
  {
    for (const auto &kv : _pools)
    {
      if (poolIsEmptyAndUnpinnedLocked_(*kv.second))
      {
        return false;
      }
    }
    return true;
  }

  /// \brief Retire `it`'s pool IFF it is empty and unpinned; returns the
  /// iterator following the erased node, or std::next(it) when nothing was
  /// retired — so a caller walking _pools can assign the result unconditionally.
  /// \details The one gate for designPrinciple #7 (no size()==0 pool persists
  /// across an acquire_/purgeIdleCore_ return-or-throw) as EXTENDED by #8 (a
  /// pool with pendingCreates()>0 is NEVER erased — invariant I2). Dropping the
  /// pendingCreates conjunct at any of these sites pulls a pool out from under a
  /// thread inside phase-6's unlocked construction window, whose re-look-up then
  /// throws spuriously and whose rollback lands on a detached pool: CR-2 by
  /// another route. Must hold _mutex.
  PoolMap::iterator
  retireIfEmptyAndUnpinnedLocked_(PoolMap::iterator it,
                                  std::vector<std::shared_ptr<detail::EndpointPool>> &evictedPools)
  {
    if (it == _pools.end())
    {
      return it; // std::next(end()) would be UB
    }
    if (poolIsEmptyAndUnpinnedLocked_(*it->second))
    {
      return retirePoolLocked_(it, evictedPools);
    }
    return std::next(it);
  }

  /// \brief Key-and-handle overload for the sites that hold an owning `pool`
  /// rather than an iterator (acquire_'s Option-A throw retire and task-6.1c's
  /// rollback retire). Locates the pool BY KEY and verifies IDENTITY before
  /// touching it (task-4.2's UAF rule): a pool retired and re-created under the
  /// same key while we were unlocked is a DIFFERENT object, and erasing it would
  /// destroy someone else's live pool.
  void
  retireIfEmptyAndUnpinnedLocked_(const std::string &endpoint,
                                  const std::shared_ptr<detail::EndpointPool> &pool,
                                  std::vector<std::shared_ptr<detail::EndpointPool>> &evictedPools)
  {
    if (!pool)
    {
      return;
    }
    auto it = _pools.find(endpoint);
    if (it != _pools.end() && it->second == pool)
    {
      retireIfEmptyAndUnpinnedLocked_(it, evictedPools);
    }
  }

  /// \brief Undo a reservation taken by EndpointPool::reserveCreate(): release
  /// it, drop the matching _totalConnections unit, and retire the pool if that
  /// left it empty AND unpinned.
  /// \details The ONE place the post-reservation unwind sequence is written, so
  /// acquire_'s three failure exits after the reservation (the factory/configurer
  /// throw, the post-relock _closing recheck, and the re-look-up mismatch) are
  /// identical BY CONSTRUCTION rather than by three hand-maintained copies.
  /// Deliberately a plain member function called explicitly, NEVER an RAII
  /// guard: a locking guard's destructor would re-take _mutex, which is either a
  /// double-lock or a re-lock under a lock depending on where it fired
  /// (task-6.1c). Must hold _mutex.
  ///
  /// Correct at the re-look-up-mismatch site too, where `pool` is no longer the
  /// pool under `endpoint`: the retire helper verifies identity and declines to
  /// touch a pool that is not ours, so only the counters unwind there — which is
  /// exactly right, because a detached pool is already excluded from
  /// recalcTotalLocked_ and leaving the increment would desync it permanently.
  void rollbackCreateLocked_(const std::string &endpoint,
                             const std::shared_ptr<detail::EndpointPool> &pool,
                             std::vector<std::shared_ptr<detail::EndpointPool>> &evictedPools)
  {
    pool->rollbackCreate();
    --_totalConnections;
    retireIfEmptyAndUnpinnedLocked_(endpoint, pool, evictedPools);
    assert(_totalConnections == recalcTotalLocked_());
    assert(noEmptyUnpinnedPoolLocked_()); // I1, re-asserted after the re-lock (DP#7)
  }

  /// \brief Try to evict the single least-recently-used idle connection
  /// across all pools. The removed connection (and, if that empties its pool,
  /// the pool) is moved into the caller's evicted vectors for destruction after
  /// _mutex is released (T6-2).
  bool tryEvictOneIdleConnLruLocked_(
    std::vector<std::shared_ptr<detail::PooledConnection>> &evictedConns,
    std::vector<std::shared_ptr<detail::EndpointPool>> &evictedPools)
  {
    std::string bestKey;
    // A null handle is the sentinel (CR-1: replaces the index sentinel
    // bestIdx == std::size_t(-1), which no longer exists now that identity is
    // the object rather than a position).
    std::shared_ptr<detail::PooledConnection> bestHandle;
    auto bestTime = std::chrono::steady_clock::time_point::max();

    for (auto &kv : _pools)
    {
      kv.second->forEachIdle(
        [&](const std::shared_ptr<detail::PooledConnection> &handle,
            std::chrono::steady_clock::time_point t)
        {
          if (t < bestTime)
          {
            bestTime = t;
            bestHandle = handle;
            bestKey = kv.first;
          }
        });
    }

    if (bestHandle != nullptr)
    {
      auto it = _pools.find(bestKey);
      if (it != _pools.end())
      {
        it->second->erase(bestHandle, evictedConns);
        _stats.connectionsEvicted.fetch_add(1, std::memory_order_relaxed); // DP-2: one idle connection evicted
        // PIN SITE 3 (designPrinciple #8): dropping the pool's last idle
        // connection must NOT retire it while a creation is in flight on it —
        // the reserving thread would re-lock onto a pool no longer in _pools.
        // `it` may be invalidated by the retire; nothing below dereferences it.
        (void)retireIfEmptyAndUnpinnedLocked_(it, evictedPools);
        _totalConnections = recalcTotalLocked_();
        return true;
      }
    }
    return false;
  }

  /// \brief Evict the least-recently-used pool that is entirely idle.
  /// Returns true if evicted. The removed pool is moved into `evictedPools` for
  /// destruction after _mutex is released (T6-2).
  bool evictOneIdlePoolLruLocked_(std::vector<std::shared_ptr<detail::EndpointPool>> &evictedPools)
  {
    // The iterator itself is the sentinel (bestIt != _pools.end()), matching the
    // sibling tryEvictOneIdleConnLruLocked_'s null-handle sentinel. NOT a
    // bestKey.empty() check: the endpoint key may legitimately be the empty
    // string (call("", ...) creates a pool keyed by ""), which an empty()
    // sentinel would never select for eviction (cpp17 R#7).
    PoolMap::iterator bestIt = _pools.end();
    auto bestTime = std::chrono::steady_clock::time_point::max();

    for (auto it = _pools.begin(); it != _pools.end(); ++it)
    {
      auto &pool = *it->second;
      // PIN SITE 4 (designPrinciple #8) — and the SUBTLE one: the exclusion
      // sits at CANDIDACY, not at the retire below. A pinned pool selected as
      // bestIt would either be wrongly retired or, worse, shadow a genuinely
      // evictable pool and make this return false while capacity existed.
      // The predicate designPrinciple #8 states is
      //   allIdle() && size() > 0 && pendingCreates() == 0
      // and the size() > 0 conjunct is already carried by allIdle() itself
      // (task-5.1 narrowed it to require a non-empty pool — see its comment),
      // so only the pendingCreates conjunct is written here. This is the one
      // pin site NOT routed through retireIfEmptyAndUnpinnedLocked_: it selects
      // NON-empty pools, the opposite predicate (R3 L-4/ts-L1).
      if (pool.allIdle() && pool.pendingCreates() == 0)
      {
        const auto t = pool.lastTouched();
        if (t < bestTime)
        {
          bestTime = t;
          bestIt = it;
        }
      }
    }

    if (bestIt != _pools.end())
    {
      // DP-2: count every connection dropped with the pool. Read size() BEFORE
      // retirePoolLocked_ moves the pool out (reading after the move reads a
      // moved-from pool). After the allIdle() size()>0 change an LRU-evicted pool
      // holds >= 1 idle connection, so this is always a positive delta.
      _stats.connectionsEvicted.fetch_add(bestIt->second->size(), std::memory_order_relaxed);
      retirePoolLocked_(bestIt, evictedPools);
      _totalConnections = recalcTotalLocked_();
      return true;
    }
    return false;
  }

  static iora::parsers::Json makeRequestEnvelope_(const std::string &method,
                                                  const iora::parsers::Json &params,
                                                  std::uint64_t id)
  {
    // A request is a notification plus an id: build on the notification form so
    // the params-inclusion rule lives in exactly one place and the two forms
    // cannot drift.
    iora::parsers::Json j = makeNotificationEnvelope_(method, params);
    j["id"] = id;
    return j;
  }

  static iora::parsers::Json makeNotificationEnvelope_(const std::string &method,
                                                       const iora::parsers::Json &params)
  {
    iora::parsers::Json j;
    j["jsonrpc"] = "2.0";
    j["method"] = method;
    // Only include params if not null and not empty object (for wire
    // compatibility)
    if (!params.is_null() && !(params.is_object() && params.empty()))
    {
      j["params"] = params;
    }
    return j;
  }

  /// \brief The framing/connection fields the client owns and refuses from a
  /// caller or config (RFC 9110/9112 request-splitting + TE.CL surface). The
  /// per-call set (task-7.3a) additionally refuses User-Agent — see
  /// validateHeaderOrThrow_. Content-Type is in NEITHER set. Membership is
  /// case-insensitive (RFC 9110 §5.1): a lowercase `transfer-encoding` must be
  /// caught, or it would reach the wire verbatim and reintroduce TE.CL smuggling.
  static bool isRejectedHeaderName_(const std::string &name)
  {
    static const char *const kFraming[] = {
      "Host",          "Content-Length", "Connection",      "Transfer-Encoding",
      "TE",            "Trailer",        "Upgrade",         "Proxy-Connection",
      "Keep-Alive",    "Accept-Encoding", "Content-Encoding"};
    for (const char *r : kFraming)
    {
      if (iora::core::StringUtils::iequals(name, r))
      {
        return true;
      }
    }
    return false;
  }

  /// \brief Validate one header for the constructor set (perCall=false, on
  /// Config::defaultHeaders) or the per-call set (perCall=true, on `extra`):
  /// reject a framing/smuggling name (task-7.3a), a per-call User-Agent
  /// (task-7.3c — consumed once at construction, no per-call override), a
  /// non-token name (RFC 9110 §5.6.2, task-7.3b) or a value carrying a forbidden
  /// octet (§5.5). Throws JsonRpcError naming the field. `where` is a location
  /// clause for the diagnostic.
  static void validateHeaderOrThrow_(const std::string &name, const std::string &value,
                                     bool perCall, const char *where)
  {
    if (perCall && iora::core::StringUtils::iequals(name, "User-Agent"))
    {
      throw JsonRpcError("JsonRpcClient: a per-call 'User-Agent' header is not allowed; "
                         "set it once in Config::defaultHeaders (it is consumed into the "
                         "HTTP User-Agent at construction, with no per-call override)");
    }
    if (isRejectedHeaderName_(name))
    {
      throw JsonRpcError(std::string("JsonRpcClient: header '") + name +
                         "' is a connection/framing field the client controls and must not "
                         "be supplied " + where);
    }
    if (!iora::network::isHttpToken(name))
    {
      throw JsonRpcError(std::string("JsonRpcClient: invalid header name '") + name + "' " +
                         where + " (not an RFC 9110 token)");
    }
    if (!iora::network::isValidFieldValue(value))
    {
      throw JsonRpcError(std::string("JsonRpcClient: invalid value for header '") + name +
                         "' " + where + " (contains a control or DEL octet)");
    }
  }

  /// \brief Upsert one header into `out` case-insensitively, LAST-WINS: if a
  /// same-name (iequals) entry exists, overwrite its value and keep its position
  /// and first-seen spelling; else append. The single find-or-append primitive
  /// shared by dedupHeadersLastWins_ and mergeHeaders_ (simpl R1-L1).
  static void upsertLastWins_(std::vector<std::pair<std::string, std::string>> &out,
                              const std::pair<std::string, std::string> &kv)
  {
    // ASCII-only, locale-independent header-name folding (cpp17 LOW-5): the iora
    // foundation helper, not locale-dependent std::tolower, so the match is
    // byte-stable across processes/locales.
    auto it = std::find_if(out.begin(), out.end(),
                           [&](const std::pair<std::string, std::string> &e)
                           { return iora::core::StringUtils::iequals(e.first, kv.first); });
    if (it != out.end())
    {
      it->second = kv.second;
    }
    else
    {
      out.push_back(kv);
    }
  }

  /// \brief De-duplicate a header vector case-insensitively, LAST-WINS, retaining
  /// the first-seen spelling and position. task-7.4 seed self-dedup: prevents two
  /// case-variant defaultHeaders entries from becoming two wire lines.
  static std::vector<std::pair<std::string, std::string>>
  dedupHeadersLastWins_(const std::vector<std::pair<std::string, std::string>> &in)
  {
    std::vector<std::pair<std::string, std::string>> out;
    out.reserve(in.size());
    for (const auto &kv : in)
    {
      upsertLastWins_(out, kv);
    }
    return out;
  }

  std::vector<std::pair<std::string, std::string>>
  mergeHeaders_(const std::vector<std::pair<std::string, std::string>> &extra) const
  {
    // task-7.3a/7.3b: validate + reject every per-call header BEFORE merging, on
    // the PER-CALL set (framing fields + User-Agent). A rejection throws before
    // anything reaches the wire. Runs on the local `extra`; never writes _config.
    for (const auto &kv : extra)
    {
      validateHeaderOrThrow_(kv.first, kv.second, /*perCall=*/true, "in a per-call header");
    }

    std::vector<std::pair<std::string, std::string>> out = _config.defaultHeaders;
    out.reserve(_config.defaultHeaders.size() + extra.size() + 1); // simpl R1-L2

    for (const auto &kv : extra)
    {
      // task-7.4 (per-call): canonicalise a caller Content-Type to HttpClient's
      // exact "Content-Type" spelling so it collapses onto postJson's map key —
      // otherwise a lowercase `content-type` and postJson's `Content-Type` become
      // two case-sensitive keys and two wire lines (cpp17 R1-M1 / web R1-W1). The
      // constructor already canonicalises the config seed; this is the per-call
      // arm of the same rule. The value is inert (postJson forces
      // application/json), but the spelling must not fork the plain std::map.
      if (iora::core::StringUtils::iequals(kv.first, "Content-Type"))
      {
        upsertLastWins_(out, {"Content-Type", kv.second});
      }
      else
      {
        upsertLastWins_(out, kv);
      }
    }

    // task-7.2b: the client has no response decoder, so it advertises exactly
    // one `Accept-Encoding: identity` on every request. RFC 7231 5.3.4 makes an
    // explicit `identity` a real refusal of every unlisted coding, which pairs
    // with task-7.2c's fail-loudly on a compressed response. Contributed to the
    // local `out` ONLY — never Config::defaultHeaders. A plain append yields
    // exactly one line: task-7.3a rejects a per-call Accept-Encoding (above) and
    // task-7.3d rejects one in defaultHeaders at construction, so neither the
    // seed nor `extra` can carry a prior Accept-Encoding for this to duplicate.
    out.emplace_back("Accept-Encoding", "identity");
    return out;
  }

  static iora::parsers::Json parseResponseOrThrow_(iora::parsers::Json resp)
  {
    if (resp.is_object())
    {
      if (resp.contains("error"))
      {
        const auto &err = resp["error"];
        int code = err.contains("code") ? err["code"].get<int>() : -32000;
        std::string message = err.contains("message") ? err["message"].get<std::string>()
                                                      : std::string{"Unknown error"};
        iora::parsers::Json data =
          err.contains("data") ? err["data"] : iora::parsers::Json(nullptr);
        throw RemoteError(code, message, std::move(data));
      }
      if (resp.contains("result"))
      {
        return resp["result"];
      }
    }
    return resp;
  }

  std::uint64_t nextId_() { return _nextId.fetch_add(1, std::memory_order_relaxed); }

  /// \brief Run the user's httpClientFactory (and httpClientConfigurer) to
  /// produce one HTTP client for `origin`.
  /// \param origin the pool's ORIGIN (scheme://host:effective-port), NOT the
  ///   caller's full request URL (task-7.5c). Both public extension points
  ///   receive this string; the full URL is re-applied only on the send path.
  /// \details task-6.2 DELETED the std::async(std::launch::async) +
  /// wait_for(30s) wrapper this used to run in. That wrapper bounded NOTHING:
  /// per [futures.async] the future returned by std::async joins in its own
  /// destructor, so a timed-out wait_for was followed by a ~future that blocked
  /// indefinitely anyway — while the "timed out - likely transport layer
  /// conflict" message misattributed the cause. It also spawned an OS thread
  /// per connection creation. Any real bound on construction must come from the
  /// factory itself or from HttpClient, never from a joining future.
  ///
  /// Runs on the CALLING thread and — since phase 6 — with _mutex RELEASED
  /// (task-6.1b): the callbacks may re-enter the client, and a slow one no
  /// longer blocks acquires for other endpoints. THROWS propagate to acquire_'s
  /// create tail, which rolls the reservation back (task-6.1c).
  std::unique_ptr<iora::network::HttpClient> makeHttpClient_(const std::string &origin)
  {
    // task-7.1b — pass the derived config so factory-created clients honour the
    // mapped knobs. _derivedHttpConfig is immutable post-construction, so this
    // lock-free read is safe on the phase-6 unlocked construction window.
    // task-7.5c — `origin` (the pool key), NOT the caller's full URL, is what
    // both public extension points receive.
    auto cli = _config.httpClientFactory(origin, _derivedHttpConfig);
    if (!cli)
    {
      throw JsonRpcError("httpClientFactory returned null");
    }
    if (_config.httpClientConfigurer)
    {
      _config.httpClientConfigurer(origin, *cli);
    }
    return cli;
  }

  /// \brief The vector-of-pairs header list HttpClient's map-taking postJson
  /// needs. Hoisted out of sendJson_ (simpl LOW-5 / iteration 2) so the retry loop builds it
  /// ONCE rather than re-allocating and re-inserting it on every attempt.
  static std::map<std::string, std::string>
  toHeaderMap_(const std::vector<std::pair<std::string, std::string>> &headers)
  {
    std::map<std::string, std::string> headerMap;
    for (const auto &kv : headers)
    {
      headerMap[kv.first] = kv.second;
    }
    return headerMap;
  }

  /// \brief task-7.2c: the client advertises `Accept-Encoding: identity` (task-
  /// 7.2b) and has NO response decoder anywhere in the tree, so a response
  /// carrying a Content-Encoding other than `identity` must fail loudly rather
  /// than feed compressed octets to the JSON parser. An ABSENT Content-Encoding
  /// means no coding was applied (RFC 9110 8.4 — the field indicates what codings
  /// HAVE BEEN applied), so it is accepted; the common case, and it must NOT fail.
  /// Content-Encoding is a comma-separated LIST field (RFC 9110 8.4 / RFC 7231
  /// 3.1.2.2): a sender may apply and list several codings in order, so a
  /// multi-coding value such as `gzip, identity` fails — the whole field value
  /// must fold to exactly the single token `identity`. The comparison is a
  /// case-insensitive ASCII fold, so `IDENTITY` is accepted.
  /// The value is `trim`-ed as belt-and-braces: in the current call path
  /// HttpClient::parseHeaderBlock has ALREADY stripped OWS (SP/HTAB) before the
  /// Response reaches here, so the trim guards only a direct caller or a future
  /// parser contract change — it cannot be exercised through postJson.
  /// LIMITATION (tracked as defect_8 in tracker -10, 2026-07-26-10):
  /// HttpClient's parseHeaderBlock stores duplicate field lines last-wins, so
  /// `Content-Encoding: gzip` then `Content-Encoding: identity` presents as
  /// `identity` and slips through here — the http_client Content-Length path DOES
  /// throw on a conflicting duplicate, so the asymmetry is unintentional.
  static void verifyResponseContentEncoding_(const iora::network::HttpClient::Response &response)
  {
    const auto it = response.headers.find("Content-Encoding");
    if (it == response.headers.end())
    {
      return; // absent == identity; nothing to reject.
    }
    if (iora::core::StringUtils::iequals(iora::core::StringUtils::trim(it->second), "identity"))
    {
      return;
    }
    throw JsonRpcError("JsonRpcClient: response Content-Encoding '" + it->second +
                       "' is not supported; the client advertises Accept-Encoding: "
                       "identity and has no decoder for any other coding");
  }

  iora::parsers::Json sendJson_(iora::network::HttpClient &http, const std::string &url,
                                const iora::parsers::Json &payload,
                                const std::map<std::string, std::string> &headerMap)
  {
    auto response = http.postJson(
      url, payload, headerMap, 0); // No retries at HTTP level - retries handled by JSON-RPC client
    verifyResponseContentEncoding_(response); // task-7.2c: fail before parse on a bad coding
    return iora::network::HttpClient::parseJsonOrThrow(response);
  }

  /// \brief True if \p e is a transport TIMEOUT that ClientStats::timeoutRequests
  /// should count. The lease-acquire timeout is matched by TYPE
  /// (HttpLeaseAcquireTimeoutError — its message reads "timed out", which a
  /// find("timeout") substring match misses; task-7.8 / HD-7 Secondary row); the
  /// response-read timeout ("HTTP response timeout") by the retained substring.
  /// Shared by the single-call retry loop AND the batch path (task-7.8 M2) so both
  /// classify identically. NOTE: connect/DNS timeouts are wrapped/re-messaged
  /// without a "timeout" substring and are NOT yet counted — backlog 2026-09-03-3.
  static bool isTimeoutFailure_(const std::exception &e)
  {
    return dynamic_cast<const iora::network::HttpLeaseAcquireTimeoutError *>(&e) != nullptr ||
           std::string_view(e.what()).find("timeout") != std::string_view::npos;
  }

  iora::parsers::Json
  sendJsonWithRetries_(iora::network::HttpClient &http, const std::string &url,
                       const iora::parsers::Json &payload,
                       const std::vector<std::pair<std::string, std::string>> &headers)
  {
    std::size_t attempts = 0;
    std::chrono::milliseconds delay = _config.initialRetryDelay;
    // Built once, reused by every attempt (simpl LOW-5 / iteration 2): the header set does not
    // change between retries.
    const auto headerMap = toHeaderMap_(headers);

    while (true)
    {
      // task-3.1(f): fail fast if the client is closing rather than starting a
      // fresh attempt against a cancelled transport.
      if (_closing.load(std::memory_order_acquire))
      {
        throw ClientShutdownError("JsonRpcClient: cancelled before send; client is closing");
      }
      try
      {
        return sendJson_(http, url, payload, headerMap);
      }
      // HAZARD (tracker 2026-09-03-2): this blanket catch-and-retry re-sends a
      // non-idempotent POST on ANY exception, with no provably-not-sent gate — a
      // double-submit if the server may already have applied the request. The
      // safe fix (retry only HttpRequestNotSentError) is cross-cutting; tracked.
      catch (const std::exception &e)
      {
        attempts++;
        if (attempts > _config.maxRetries)
        {
          if (isTimeoutFailure_(e))
          {
            _stats.timeoutRequests.fetch_add(1, std::memory_order_relaxed);
          }
          throw;
        }

        _stats.retriedRequests.fetch_add(1, std::memory_order_relaxed);

        // INTERRUPTIBLE backoff (task-3.1(f)): the destructor's STEP-1 notify
        // cuts the wait so a retry loop cannot outlast the quiesce. Waiting on
        // _quiesceCv takes _quiesceMutex only (no pool _mutex held here — the
        // lease is held but acquire_ released _mutex), honoring task-3.6 rule (i).
        {
          std::unique_lock<std::mutex> lk(_quiesceMutex);
          _quiesceCv.wait_for(lk, delay, [this] { return _closing.load(std::memory_order_acquire); });
        }
        if (_closing.load(std::memory_order_acquire))
        {
          throw ClientShutdownError("JsonRpcClient: cancelled during retry backoff; client is closing");
        }

        // Exponential backoff with jitter
        delay = std::min(std::chrono::milliseconds(
                           static_cast<long>(delay.count() * _config.retryBackoffMultiplier)),
                         _config.maxRetryDelay);
      }
    }
  }

  std::vector<iora::parsers::Json>
  parseBatchResponseOrThrow_(iora::parsers::Json batchResp,
                             const std::vector<BatchItem> &originalItems)
  {
    if (!batchResp.is_array())
    {
      throw JsonRpcError("Batch response must be an array");
    }

    std::vector<iora::parsers::Json> results;
    results.reserve(originalItems.size());

    // Create map of id -> response for efficient lookup
    std::unordered_map<std::uint64_t, iora::parsers::Json> responseMap;
    for (const auto &respItem : batchResp)
    {
      if (respItem.contains("id") && !respItem["id"].is_null())
      {
        std::uint64_t id = respItem["id"].get<std::uint64_t>();
        responseMap[id] = respItem;
      }
    }

    // Match responses to original requests by ID
    for (const auto &item : originalItems)
    {
      if (item.id.has_value())
      {
        auto it = responseMap.find(item.id.value());
        if (it != responseMap.end())
        {
          results.push_back(parseResponseOrThrow_(it->second));
        }
        else
        {
          throw JsonRpcError("Missing response for request ID: " + std::to_string(item.id.value()));
        }
      }
      else
      {
        // Notification - no response expected
        results.push_back(iora::parsers::Json());
      }
    }

    return results;
  }

private:
  // Friendship is not transitive: befriending the test seam on EndpointPool
  // does not extend here, so JsonRpcClientImpl names it too (for _pools, _mutex,
  // _totalConnections, recalcTotalLocked_ and acquire_). Unqualified is correct
  // here — this class sits directly in namespace connectors.
  friend struct JsonRpcClientTestAccess;
  // ConnectionLease's out-of-line destructor calls releaseConnection_ (private).
  friend class detail::ConnectionLease;

  iora::core::ThreadPool &_threadPool;
  // IMMUTABLE AFTER CONSTRUCTION — load-bearing since phase 6, not a style note.
  // Nothing writes _config after the constructor returns (task-7.2a/7.2d removed
  // the header fixups it used to emplace). makeHttpClient_ now reads
  // _config.httpClientFactory and
  // _config.httpClientConfigurer with NO lock held (those reads happened under
  // _mutex before the CR-3 fix), and config() reads it unlocked too. Adding any
  // mutating accessor would therefore be an immediate data race on a
  // std::function and a std::vector that are read concurrently by every thread
  // creating a connection. If mutability is ever needed, it needs its own
  // synchronisation design, not a setter.
  Config _config;
  // task-7.1a — the HttpClient::Config derived from _config's six knobs, built
  // ONCE at the end of the constructor body and thereafter IMMUTABLE BY
  // CONVENTION (designPrinciple #9, same discipline as _config). NON-const: a
  // const member cannot be initialised from the body-mutated _config. Read
  // lock-free by makeHttpClient_ on arbitrary worker threads in the phase-6
  // unlock window; its happens-before is the shared_ptr publication in create().
  iora::network::HttpClient::Config _derivedHttpConfig;
  ClientStats _stats;

  // shared_ptr, not unique_ptr (CR-1c/task-4.1c): a ConnectionLease holds an
  // owning handle to its pool, so releasing into a pool that eviction has since
  // removed from the map stays well-defined instead of dereferencing freed
  // memory.
  std::unordered_map<std::string, std::shared_ptr<detail::EndpointPool>> _pools;
  // LOCK ORDERING (task-3.6 / task-8.4), stated here at the declaration:
  //  (i)   the pool _mutex and Impl::_quiesceMutex are NEVER held simultaneously
  //        (the quiesce CV must not reuse this mutex — a task blocked in acquire_
  //        on _mutex and a destructor waiting for it would deadlock).
  //  (iii) no ConnectionLease/CountGuard/OwnerScope may be constructed OR
  //        destroyed while this _mutex is held: ~ConnectionLease takes _mutex,
  //        and ~CountGuard/~OwnerScope take _quiesceMutex — by (i) disjoint.
  //  (iv)  every counted entry point acquires its CountGuard/token as the FIRST
  //        local, ABOVE any pool lock, and releases it after _mutex is released.
  //  (ii)  _quiesceMutex is NEVER held across a call into core::ThreadPool.
  // The only order between core::ThreadPool::_mutex and _quiesceMutex is
  // ThreadPool::_mutex -> _quiesceMutex (queued-task discard); the reverse is
  // forbidden by (ii), so no cycle can form. (Full rule set: task-3.6/task-8.4.)
  std::mutex _mutex;

  std::atomic<std::uint64_t> _nextId;
  std::size_t _totalConnections;

  // --- Blocking-quiesce state (CR-4 / HD-1, task-3.1(a)). EMBEDDED here (no
  // separate detached struct — keep-alive via InFlightToken's shared_ptr<Impl>
  // suffices). _quiesceMutex is a leaf, DISTINCT from the pool _mutex; task-3.6
  // rule (i) forbids holding both simultaneously. _closing is write-once
  // monotonic: STORE under _quiesceMutex (release), lock-free reads use acquire.
  mutable std::mutex _quiesceMutex;
  std::condition_variable _quiesceCv;
  std::size_t _inFlight{0};
  std::vector<std::thread::id> _owners;
  std::atomic<bool> _closing{false};
};

// ConnectionLease's destructor is defined here, where JsonRpcClientImpl is
// complete, so it can release the connection under Impl::_mutex. The shared_ptr
// keep-alives it holds guarantee Impl (and thus the mutex and pool map) outlive
// this body — see the member-order comment on the class.
inline detail::ConnectionLease::~ConnectionLease()
{
  // A moved-from lease has a null _impl and no-ops here.
  if (_impl)
  {
    _impl->releaseConnection_(_pool, _conn);
  }
}

/// \brief JSON-RPC 2.0 client with per-endpoint connection pooling and
/// async support.
/// \details Thin, non-copyable, non-movable facade over a
/// std::shared_ptr<JsonRpcClientImpl>. Every public operation forwards to the
/// implementation; the shared_ptr lets async work outlive the facade safely.
class JsonRpcClient
{
public:
  JsonRpcClient(iora::IoraService &service, iora::core::ThreadPool &threadPool, Config config = {})
      : _impl(JsonRpcClientImpl::create(threadPool, std::move(config)))
  {
    // The service reference is dead state (L-9): the client drives its own
    // HttpClient instances and never touches the service. The parameter is
    // retained for API compatibility; tracker -1 removes it (LD-2).
    (void)service;
  }

  // A pImpl facade holding only a shared_ptr would otherwise be implicitly
  // copyable and movable, letting two facades share one Impl with no defined
  // semantics. Delete all four explicitly (cf. iora::web::Application,
  // HttpServer, HttpClient).
  JsonRpcClient(const JsonRpcClient &) = delete;
  JsonRpcClient &operator=(const JsonRpcClient &) = delete;
  JsonRpcClient(JsonRpcClient &&) = delete;
  JsonRpcClient &operator=(JsonRpcClient &&) = delete;

  /// \brief Blocking destructor (CR-4 / HD-1, task-3.5). Runs the quiesce on
  /// THIS (the destroying user) thread — never in ~JsonRpcClientImpl, which may
  /// run on a ThreadPool worker holding the last shared_ptr<Impl>. When it
  /// returns, no user callback is running and no counted call is in flight.
  /// Residual (HD-8): a worker may hold the last shared_ptr<Impl>, so ~Impl can
  /// run on that worker AFTER this returns; a dlopen'd module MUST NOT rely on
  /// this destructor to make dlclose safe. The contract is "no call may BEGIN
  /// concurrently with destruction; calls already in progress are waited for."
  ///
  /// PRECONDITIONS: the core::ThreadPool MUST outlive the client and MUST NOT be
  /// reset/stopped/drained while the client is alive; the client MUST NOT be
  /// destroyed from a thread currently running its work (detected — task-3.2).
  ~JsonRpcClient()
  {
    if (_impl)
    {
      _impl->quiesce();
    }
  }

  iora::parsers::Json call(const std::string &endpoint, const std::string &method,
                           const iora::parsers::Json &params = iora::parsers::Json::object(),
                           const std::vector<std::pair<std::string, std::string>> &headers = {})
  {
    return _impl->call(endpoint, method, params, headers);
  }

  void notify(const std::string &endpoint, const std::string &method,
              const iora::parsers::Json &params = iora::parsers::Json::object(),
              const std::vector<std::pair<std::string, std::string>> &headers = {})
  {
    _impl->notify(endpoint, method, params, headers);
  }

  std::future<iora::parsers::Json>
  callAsync(const std::string &endpoint, const std::string &method,
            const iora::parsers::Json &params = iora::parsers::Json::object(),
            const std::vector<std::pair<std::string, std::string>> &headers = {})
  {
    return _impl->callAsync(endpoint, method, params, headers);
  }

  void callAsync(const std::string &endpoint, const std::string &method,
                 const iora::parsers::Json &params,
                 const std::vector<std::pair<std::string, std::string>> &headers,
                 std::function<void(iora::parsers::Json)> onSuccess,
                 std::function<void(std::exception_ptr)> onError)
  {
    _impl->callAsync(endpoint, method, params, headers, std::move(onSuccess), std::move(onError));
  }

  std::vector<iora::parsers::Json>
  callBatch(const std::string &endpoint, const std::vector<BatchItem> &items,
            const std::vector<std::pair<std::string, std::string>> &headers = {})
  {
    return _impl->callBatch(endpoint, items, headers);
  }

  std::future<std::vector<iora::parsers::Json>>
  callBatchAsync(const std::string &endpoint, const std::vector<BatchItem> &items,
                 const std::vector<std::pair<std::string, std::string>> &headers = {})
  {
    return _impl->callBatchAsync(endpoint, items, headers);
  }

  std::size_t purgeIdle() { return _impl->purgeIdle(); }

  /// \brief By-value config snapshot (task-3.3(ii)): noexcept removed, returns
  /// the by-value result of _impl->config() (not a reference into Impl).
  /// \warning PRECONDITION, and it is the CALLER's to honour: must not be
  /// called concurrently with this client's destruction. Unlike call()/notify()/
  /// callAsync(), this accessor is deliberately NOT counted (task-3.3(ii)), so
  /// it neither keeps the Impl alive nor makes a concurrent quiesce wait for it
  /// — a destructor that observes _inFlight == 0 returns immediately and frees
  /// the Impl this read is walking. Returning by value removes the
  /// reference-escape hazard, not the read-during-free one.
  Config config() const { return _impl->config(); }

  /// \brief By-value, atomic-free stats snapshot (task-3.3(ii)): noexcept
  /// removed.
  /// \warning Same uncounted-accessor precondition as config() above: must not
  /// be called concurrently with destruction.
  ClientStatsSnapshot getStats() const { return _impl->getStats(); }

  void resetStats() { _impl->resetStats(); }

private:
  // The seam reads Impl's members through the facade's _impl handle, so it must
  // befriend the facade too (for _impl) in addition to JsonRpcClientImpl.
  friend struct JsonRpcClientTestAccess;

  std::shared_ptr<JsonRpcClientImpl> _impl;
};

} // namespace connectors
} // namespace modules
} // namespace iora
