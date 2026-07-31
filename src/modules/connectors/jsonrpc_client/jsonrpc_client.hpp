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
// Retained deliberately: the next phase (blocking quiesce) re-introduces a
// condition variable on this class. Kept across phase 4 to avoid churning the
// include set of a public module header between adjacent phases.
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <functional>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "iora/iora.hpp"
// For iora::core::StringUtils::iequals (ASCII, locale-independent header-name
// folding in mergeHeaders_ — cpp17 LOW-5); not pulled in transitively by iora.hpp.
#include "iora/core/string_utils.hpp"

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
  /// by purgeIdle().
  std::chrono::milliseconds idleTimeout{std::chrono::seconds(30)};

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

  /// \brief Enable gzip compression for requests/responses.
  bool enableCompression{true};

  /// \brief Default HTTP headers applied to every request; call-specific
  /// headers can override.
  std::vector<std::pair<std::string, std::string>> defaultHeaders{
    {"Content-Type", "application/json"}};

  /// \brief Optional factory for creating HttpClient instances (injectable
  /// for tests).
  std::function<std::unique_ptr<iora::network::HttpClient>(const std::string &endpoint)>
    httpClientFactory{};

  /// \brief Optional hook to configure a freshly created HttpClient (e.g.,
  /// TLS). \details Called after httpClientFactory() returns and before
  /// first use.
  std::function<void(const std::string &endpoint, iora::network::HttpClient &client)>
    httpClientConfigurer{};
};

/// \brief JSON-RPC client statistics.
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
    totalRequests = 0;
    successfulRequests = 0;
    failedRequests = 0;
    timeoutRequests = 0;
    retriedRequests = 0;
    batchRequests = 0;
    notificationRequests = 0;
    poolExhaustions = 0;
    connectionsCreated = 0;
    connectionsEvicted = 0;
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
  std::shared_ptr<PooledConnection>
  tryAcquireFree(std::chrono::milliseconds idleTimeout,
                 std::vector<std::shared_ptr<PooledConnection>> &evicted)
  {
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

  std::shared_ptr<PooledConnection> createAndAcquire(
    const std::function<std::unique_ptr<iora::network::HttpClient>(const std::string &)> &factory,
    ClientStats *stats = nullptr)
  {
    auto pc = std::make_shared<PooledConnection>(factory(_endpoint));
    pc->markInUse();
    _connections.push_back(pc);
    touch();
    if (stats)
    {
      stats->connectionsCreated++;
    }
    return pc;
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

  bool allIdle() const
  {
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
      _config.httpClientFactory = [](const std::string &)
      { return std::make_unique<iora::network::HttpClient>(); };
    }

    // Apply default keep-alive and compression settings
    if (_config.enableKeepAlive)
    {
      _config.defaultHeaders.emplace_back("Connection", "keep-alive");
    }
    if (_config.enableCompression)
    {
      _config.defaultHeaders.emplace_back("Accept-Encoding", "gzip");
    }
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
    s.totalRequests = _stats.totalRequests.load();
    s.successfulRequests = _stats.successfulRequests.load();
    s.failedRequests = _stats.failedRequests.load();
    s.timeoutRequests = _stats.timeoutRequests.load();
    s.retriedRequests = _stats.retriedRequests.load();
    s.batchRequests = _stats.batchRequests.load();
    s.notificationRequests = _stats.notificationRequests.load();
    s.poolExhaustions = _stats.poolExhaustions.load();
    s.connectionsCreated = _stats.connectionsCreated.load();
    s.connectionsEvicted = _stats.connectionsEvicted.load();
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
  /// (i) HONEST RESIDUAL — a call inside makeHttpClient_ (running the user
  /// httpClientFactory/httpClientConfigurer under the pool _mutex, inside its
  /// std::async(...).wait_for(30s)) is bounded by that 30 s async wait, and while
  /// it holds _mutex it also DELAYS STEP 2 (which needs _mutex) by up to the
  /// same. So STEP 2's start, and hence the whole quiesce, is bounded by
  /// max(cancellation, an in-progress connection creation) — cancellation cannot
  /// interrupt a factory/configurer already running under the lock. With the
  /// default factory this is instant; the general bound is removed in PHASE 6
  /// (CR-3: task-6.1b builds the client OUTSIDE the lock, task-6.2 deletes the
  /// std::async wrapper). Enumerated here so the "no deadline" claim stays true:
  /// the deadline is the pre-existing per-connection-creation bound, tracked for
  /// removal, not a knob this design adds.
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
        std::cerr << "fatal: JsonRpcClient destroyed from inside its own callback "
                     "(self-deadlock); calling std::terminate()\n";
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
      for (auto &kv : _pools)
      {
        evicted.push_back(std::move(kv.second));
      }
      _pools.clear();
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
    _stats.totalRequests++;

    try
    {
      auto lease = acquire_(endpoint);
      iora::parsers::Json req = makeRequestEnvelope_(method, params, nextId_());
      iora::parsers::Json resp =
        sendJsonWithRetries_(lease.client(), endpoint, req, mergeHeaders_(headers));
      _stats.successfulRequests++;
      return parseResponseOrThrow_(std::move(resp));
    }
    catch (const PoolExhaustedError &)
    {
      _stats.poolExhaustions++;
      _stats.failedRequests++;
      throw;
    }
    catch (...)
    {
      _stats.failedRequests++;
      throw;
    }
  }

  void notifyCore_(const std::string &endpoint, const std::string &method,
                   const iora::parsers::Json &params,
                   const std::vector<std::pair<std::string, std::string>> &headers)
  {
    _stats.totalRequests++;
    _stats.notificationRequests++;

    try
    {
      auto lease = acquire_(endpoint);
      iora::parsers::Json req = makeNotificationEnvelope_(method, params);
      (void)sendJsonWithRetries_(lease.client(), endpoint, req, mergeHeaders_(headers));
      _stats.successfulRequests++;
    }
    catch (const PoolExhaustedError &)
    {
      _stats.poolExhaustions++;
      _stats.failedRequests++;
      throw;
    }
    catch (...)
    {
      _stats.failedRequests++;
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

    _stats.batchRequests++;
    _stats.totalRequests++;

    auto lease = acquire_(endpoint);
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
        _stats.notificationRequests++;
      }
    }

    try
    {
      iora::parsers::Json batchResp =
        sendJson_(lease.client(), endpoint, batchReq, mergeHeaders_(headers));
      _stats.successfulRequests++;
      return parseBatchResponseOrThrow_(std::move(batchResp), items);
    }
    catch (...)
    {
      _stats.failedRequests++;
      throw;
    }
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
      _stats.connectionsEvicted += evicted;
      _totalConnections = recalcTotalLocked_();

      if (pool.size() == 0)
      {
        it = retirePoolLocked_(it, evictedPools);
      }
      else
      {
        ++it;
      }
    }
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

  detail::ConnectionLease acquire_(const std::string &endpoint)
  {
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
    std::unique_lock<std::mutex> lock(_mutex);

    // Refuse under the pool _mutex if the client is closing (task-3.1(f)): an
    // admitted call that reaches here AFTER the destructor's STEP-2 cancel loop
    // must not create a NEW pooled HttpClient the loop already passed. The
    // _mutex serialization vs. that loop admits only safe orders. Reading the
    // atomic (acquire) while holding _mutex is fine — this takes no _quiesceMutex.
    if (_closing.load(std::memory_order_acquire))
    {
      throw ClientShutdownError("JsonRpcClient: cancelled during acquire; client is closing");
    }

    const auto makeClient = [this](const std::string &ep) { return this->makeHttpClient_(ep); };

    // Ensure pool exists (respecting maxEndpointPools with LRU idle pool
    // eviction).
    pool = findPool_(endpoint);
    if (!pool)
    {
      if (_config.maxEndpointPools > 0 && _pools.size() >= _config.maxEndpointPools)
      {
        evictOneIdlePoolLruLocked_(evictedPools); // best-effort
      }
      // endpoint is guaranteed absent here (findPool_ just missed, and the
      // eviction above only ever removes a DIFFERENT, LRU-idle pool), so create
      // unconditionally — a find-or-create helper's lookup would be dead code.
      pool = _pools.emplace(endpoint, std::make_shared<detail::EndpointPool>(endpoint))
               .first->second;
    }

    // Try to reuse a free connection first.
    if (auto conn = pool->tryAcquireFree(_config.idleTimeout, evictedConns))
    {
      lock.unlock();
      return detail::ConnectionLease(shared_from_this(), pool, conn);
    }

    // Can we create a new one?
    const bool underPerEndpointCap = pool->size() < _config.maxConnectionsPerEndpoint;
    const bool underGlobalCap =
      (_config.globalMaxConnections == 0) || (_totalConnections < _config.globalMaxConnections);

    if (underPerEndpointCap && underGlobalCap)
    {
      auto conn = pool->createAndAcquire(makeClient, &_stats);
      ++_totalConnections;
      lock.unlock();
      return detail::ConnectionLease(shared_from_this(), pool, conn);
    }

    // Try global LRU eviction of one idle connection across all pools.
    if (underPerEndpointCap && tryEvictOneIdleConnLruLocked_(evictedConns, evictedPools))
    {
      auto conn = pool->createAndAcquire(makeClient, &_stats);
      _totalConnections = recalcTotalLocked_();
      lock.unlock();
      return detail::ConnectionLease(shared_from_this(), pool, conn);
    }

    // As a last resort, try to evict an entire idle pool (LRU) to free
    // capacity.
    if (underPerEndpointCap && evictOneIdlePoolLruLocked_(evictedPools))
    {
      auto conn = pool->createAndAcquire(makeClient, &_stats);
      _totalConnections = recalcTotalLocked_();
      lock.unlock();
      return detail::ConnectionLease(shared_from_this(), pool, conn);
    }

    throw PoolExhaustedError("No available HTTP connections for endpoint: " + endpoint);
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

  std::size_t recalcTotalLocked_() const
  {
    std::size_t total = 0;
    for (const auto &kv : _pools)
    {
      total += kv.second->size();
    }
    return total;
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
        if (it->second->size() == 0)
        {
          retirePoolLocked_(it, evictedPools);
        }
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
      if (pool.allIdle())
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

  std::vector<std::pair<std::string, std::string>>
  mergeHeaders_(const std::vector<std::pair<std::string, std::string>> &extra) const
  {
    std::vector<std::pair<std::string, std::string>> out = _config.defaultHeaders;

    for (const auto &kv : extra)
    {
      bool replaced = false;
      for (auto &base : out)
      {
        // ASCII-only, locale-independent header-name folding (cpp17 LOW-5):
        // reuse the iora foundation helper rather than locale-dependent
        // std::tolower, so the match is byte-stable across processes/locales.
        if (iora::core::StringUtils::iequals(base.first, kv.first))
        {
          base.second = kv.second;
          replaced = true;
          break;
        }
      }
      if (!replaced)
      {
        out.push_back(kv);
      }
    }
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

  std::unique_ptr<iora::network::HttpClient> makeHttpClient_(const std::string &endpoint)
  {
    // Use a future to make HTTP client construction timeout-aware
    // This prevents hanging if there are transport layer conflicts
    auto clientFuture = std::async(std::launch::async,
                                   [this, &endpoint]()
                                   {
                                     auto cli = _config.httpClientFactory(endpoint);
                                     if (!cli)
                                     {
                                       throw JsonRpcError("httpClientFactory returned null");
                                     }
                                     if (_config.httpClientConfigurer)
                                     {
                                       _config.httpClientConfigurer(endpoint, *cli);
                                     }
                                     return cli;
                                   });

    // Wait for client creation with timeout (30 seconds should be more than enough)
    auto status = clientFuture.wait_for(std::chrono::seconds(30));
    if (status == std::future_status::timeout)
    {
      throw JsonRpcError("HTTP client creation timed out - likely transport layer conflict");
    }

    auto cli = clientFuture.get();
    return cli;
  }

  iora::parsers::Json sendJson_(iora::network::HttpClient &http, const std::string &url,
                                const iora::parsers::Json &payload,
                                const std::vector<std::pair<std::string, std::string>> &headers)
  {
    // Convert vector to map for HttpClient
    std::map<std::string, std::string> headerMap;
    for (const auto &kv : headers)
    {
      headerMap[kv.first] = kv.second;
    }
    auto response = http.postJson(
      url, payload, headerMap, 0); // No retries at HTTP level - retries handled by JSON-RPC client
    return iora::network::HttpClient::parseJsonOrThrow(response);
  }

  iora::parsers::Json
  sendJsonWithRetries_(iora::network::HttpClient &http, const std::string &url,
                       const iora::parsers::Json &payload,
                       const std::vector<std::pair<std::string, std::string>> &headers)
  {
    std::size_t attempts = 0;
    std::chrono::milliseconds delay = _config.initialRetryDelay;

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
        return sendJson_(http, url, payload, headers);
      }
      catch (const std::exception &e)
      {
        attempts++;
        if (attempts > _config.maxRetries)
        {
          if (std::string(e.what()).find("timeout") != std::string::npos)
          {
            _stats.timeoutRequests++;
          }
          throw;
        }

        _stats.retriedRequests++;

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
  Config _config;
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
  Config config() const { return _impl->config(); }

  /// \brief By-value, atomic-free stats snapshot (task-3.3(ii)): noexcept
  /// removed. Must not be called concurrently with destruction.
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
