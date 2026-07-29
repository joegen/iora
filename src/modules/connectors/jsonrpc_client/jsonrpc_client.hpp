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
#include <cctype>
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

  iora::parsers::Json call(const std::string &endpoint, const std::string &method,
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

  void notify(const std::string &endpoint, const std::string &method,
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

  std::future<iora::parsers::Json>
  callAsync(const std::string &endpoint, const std::string &method,
            const iora::parsers::Json &params,
            const std::vector<std::pair<std::string, std::string>> &headers)
  {
    // Capture a shared_ptr<Impl> by value: the queued task keeps this
    // implementation alive even if the owning facade is destroyed first
    // (thread-safety C-4). No `this`, no `[=]`.
    auto self = shared_from_this();
    return submitToPool_([self, endpoint, method, params, headers]()
                         { return self->call(endpoint, method, params, headers); });
  }

  void callAsync(const std::string &endpoint, const std::string &method,
                 const iora::parsers::Json &params,
                 const std::vector<std::pair<std::string, std::string>> &headers,
                 std::function<void(iora::parsers::Json)> onSuccess,
                 std::function<void(std::exception_ptr)> onError)
  {
    auto self = shared_from_this();
    _threadPool.enqueue(
      [self, endpoint, method, params, headers, onSuccess = std::move(onSuccess),
       onError = std::move(onError)]()
      {
        try
        {
          auto result = self->call(endpoint, method, params, headers);
          if (onSuccess)
          {
            onSuccess(result);
          }
        }
        catch (...)
        {
          if (onError)
          {
            onError(std::current_exception());
          }
        }
      });
  }

  std::vector<iora::parsers::Json>
  callBatch(const std::string &endpoint, const std::vector<BatchItem> &items,
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

  std::future<std::vector<iora::parsers::Json>>
  callBatchAsync(const std::string &endpoint, const std::vector<BatchItem> &items,
                 const std::vector<std::pair<std::string, std::string>> &headers)
  {
    auto self = shared_from_this();
    return submitToPool_([self, endpoint, items, headers]()
                         { return self->callBatch(endpoint, items, headers); });
  }

  std::size_t purgeIdle()
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

  const Config &config() const noexcept { return _config; }

  const ClientStats &getStats() const noexcept { return _stats; }

  void resetStats() { _stats.reset(); }

private:
  using PoolMap = std::unordered_map<std::string, std::shared_ptr<detail::EndpointPool>>;

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
        if (casecmp_(base.first, kv.first))
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

  static bool casecmp_(const std::string &a, const std::string &b)
  {
    if (a.size() != b.size())
    {
      return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i)
    {
      char ca = static_cast<char>(std::tolower(static_cast<unsigned char>(a[i])));
      char cb = static_cast<char>(std::tolower(static_cast<unsigned char>(b[i])));
      if (ca != cb)
      {
        return false;
      }
    }
    return true;
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
        std::this_thread::sleep_for(delay);

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

  template <typename Fn> auto submitToPool_(Fn &&fn) -> std::future<std::invoke_result_t<Fn>>
  {
    return _threadPool.enqueueWithResult(std::forward<Fn>(fn));
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
  std::mutex _mutex;

  std::atomic<std::uint64_t> _nextId;
  std::size_t _totalConnections;
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

  const Config &config() const noexcept { return _impl->config(); }

  const ClientStats &getStats() const noexcept { return _impl->getStats(); }

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
