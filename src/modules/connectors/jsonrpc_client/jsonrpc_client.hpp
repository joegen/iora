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

  std::optional<std::size_t> tryAcquireFree(std::chrono::milliseconds idleTimeout)
  {
    const auto now = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < _connections.size(); ++i)
    {
      auto &pc = _connections[i];
      if (!pc->inUse())
      {
        if ((now - pc->lastUsed()) > idleTimeout)
        {
          _connections.erase(_connections.begin() + static_cast<long>(i));
          --i;
          continue;
        }
        pc->markInUse();
        touch();
        return i;
      }
    }
    return std::nullopt;
  }

  std::size_t createAndAcquire(
    const std::function<std::unique_ptr<iora::network::HttpClient>(const std::string &)> &factory,
    ClientStats *stats = nullptr)
  {
    _connections.emplace_back(std::make_unique<PooledConnection>(factory(_endpoint)));
    _connections.back()->markInUse();
    touch();
    if (stats)
    {
      stats->connectionsCreated++;
    }
    return _connections.size() - 1;
  }

  void release(std::size_t idx)
  {
    _connections[idx]->markFree();
    touch();
  }

  iora::network::HttpClient &clientAt(std::size_t idx) { return _connections[idx]->client(); }

  std::size_t purgeIdle(std::chrono::milliseconds idleTimeout)
  {
    const auto now = std::chrono::steady_clock::now();
    std::size_t evicted = 0;

    for (std::size_t i = 0; i < _connections.size(); ++i)
    {
      auto &pc = _connections[i];
      if (!pc->inUse() && ((now - pc->lastUsed()) > idleTimeout))
      {
        _connections.erase(_connections.begin() + static_cast<long>(i));
        ++evicted;
        --i;
      }
    }
    if (evicted > 0)
    {
      touch();
    }
    return evicted;
  }

  template <typename Fn> void forEachIdle(Fn &&fn)
  {
    for (std::size_t i = 0; i < _connections.size(); ++i)
    {
      const auto &pc = _connections[i];
      if (!pc->inUse())
      {
        fn(i, pc->lastUsed());
      }
    }
  }

  void eraseAt(std::size_t idx)
  {
    _connections.erase(_connections.begin() + static_cast<long>(idx));
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
  std::vector<std::unique_ptr<PooledConnection>> _connections;
  std::chrono::steady_clock::time_point _lastTouched;
};

/// \brief RAII handle to one pooled connection; releases it (under the client
/// mutex) on destruction.
/// \details Holds NON-owning raw pointers into the owning JsonRpcClientImpl
/// (_pool, _mutex) and a notify callback capturing that Impl by raw `this`. It
/// does NOT extend Impl's lifetime, so a lease MUST NOT outlive the Impl method
/// frame that created it: in production every lease is a stack local inside
/// call/notify/callBatch, which run either on the caller thread (facade held by
/// the caller) or on a worker task that captured a shared_ptr<Impl> — Impl
/// therefore always outlives the lease. Tests that own a lease via the
/// observation seam keep the facade alive for at least the lease's lifetime.
/// task-4.1c converts these raw pointers to a shared_ptr keep-alive.
class ConnectionLease
{
public:
  ConnectionLease() = delete;

  ConnectionLease(EndpointPool &pool, std::size_t index, iora::network::HttpClient &client,
                  std::mutex &mutex, std::function<void()> notifyReleased)
      : _pool(&pool), _index(index), _client(&client), _mutex(&mutex),
        _notifyReleased(std::move(notifyReleased)), _active(true)
  {
  }

  ConnectionLease(ConnectionLease &&other) noexcept
      : _pool(other._pool), _index(other._index), _client(other._client), _mutex(other._mutex),
        _notifyReleased(std::move(other._notifyReleased)), _active(other._active)
  {
    other._active = false;
    other._pool = nullptr;
    other._client = nullptr;
    other._mutex = nullptr;
  }

  ConnectionLease &operator=(ConnectionLease &&) = delete;
  ConnectionLease(const ConnectionLease &) = delete;
  ConnectionLease &operator=(const ConnectionLease &) = delete;

  ~ConnectionLease()
  {
    if (_active && _pool != nullptr && _mutex != nullptr)
    {
      {
        std::lock_guard<std::mutex> guard(*_mutex);
        _pool->release(_index);
      }
      if (_notifyReleased)
      {
        _notifyReleased();
      }
    }
  }

  iora::network::HttpClient &client() { return *_client; }

private:
  EndpointPool *_pool;
  std::size_t _index;
  iora::network::HttpClient *_client;
  std::mutex *_mutex;
  std::function<void()> _notifyReleased;
  bool _active;
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
      { return std::unique_ptr<iora::network::HttpClient>(new iora::network::HttpClient()); };
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
    std::lock_guard<std::mutex> guard(_mutex);
    std::size_t evictedTotal = 0;

    for (auto it = _pools.begin(); it != _pools.end();
         /* increment inside */)
    {
      auto &pool = *(it->second);
      std::size_t evicted = pool.purgeIdle(_config.idleTimeout);
      evictedTotal += evicted;
      _stats.connectionsEvicted += evicted;
      _totalConnections = recalcTotalLocked_();

      if (pool.size() == 0)
      {
        it = _pools.erase(it);
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
  detail::ConnectionLease acquire_(const std::string &endpoint)
  {
    std::unique_lock<std::mutex> lock(_mutex);

    // Ensure pool exists (respecting maxEndpointPools with LRU idle pool
    // eviction).
    auto *poolPtr = findPoolPtr_(endpoint);
    if (poolPtr == nullptr)
    {
      if (_config.maxEndpointPools > 0 && _pools.size() >= _config.maxEndpointPools)
      {
        evictOneIdlePoolLruLocked_(); // best-effort
      }
      poolPtr = &getOrCreatePoolLocked_(endpoint);
    }
    auto &pool = *poolPtr;

    // Try to reuse a free connection first.
    if (auto idx = pool.tryAcquireFree(_config.idleTimeout))
    {
      auto &ref = pool.clientAt(*idx);
      lock.unlock();
      return detail::ConnectionLease(pool, *idx, ref, _mutex, [this]() { _released.notify_all(); });
    }

    // Can we create a new one?
    const bool underPerEndpointCap = pool.size() < _config.maxConnectionsPerEndpoint;
    const bool underGlobalCap =
      (_config.globalMaxConnections == 0) || (_totalConnections < _config.globalMaxConnections);

    if (underPerEndpointCap && underGlobalCap)
    {
      const auto idx = pool.createAndAcquire([this](const std::string &ep)
                                             { return this->makeHttpClient_(ep); }, &_stats);
      ++_totalConnections;
      auto &ref = pool.clientAt(idx);
      lock.unlock();
      return detail::ConnectionLease(pool, idx, ref, _mutex, [this]() { _released.notify_all(); });
    }

    // Try global LRU eviction of one idle connection across all pools.
    if (underPerEndpointCap && tryEvictOneIdleConnLruLocked_())
    {
      const auto idx = pool.createAndAcquire([this](const std::string &ep)
                                             { return this->makeHttpClient_(ep); }, &_stats);
      _totalConnections = recalcTotalLocked_();
      auto &ref = pool.clientAt(idx);
      lock.unlock();
      return detail::ConnectionLease(pool, idx, ref, _mutex, [this]() { _released.notify_all(); });
    }

    // As a last resort, try to evict an entire idle pool (LRU) to free
    // capacity.
    if (underPerEndpointCap && evictOneIdlePoolLruLocked_())
    {
      const auto idx = pool.createAndAcquire([this](const std::string &ep)
                                             { return this->makeHttpClient_(ep); }, &_stats);
      _totalConnections = recalcTotalLocked_();
      auto &ref = pool.clientAt(idx);
      lock.unlock();
      return detail::ConnectionLease(pool, idx, ref, _mutex, [this]() { _released.notify_all(); });
    }

    throw PoolExhaustedError("No available HTTP connections for endpoint: " + endpoint);
  }

  detail::EndpointPool *findPoolPtr_(const std::string &endpoint)
  {
    auto it = _pools.find(endpoint);
    if (it == _pools.end())
    {
      return nullptr;
    }
    return it->second.get();
  }

  detail::EndpointPool &getOrCreatePoolLocked_(const std::string &endpoint)
  {
    auto it = _pools.find(endpoint);
    if (it == _pools.end())
    {
      auto inserted = _pools.emplace(endpoint, std::make_unique<detail::EndpointPool>(endpoint));
      return *(inserted.first->second);
    }
    return *(it->second);
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
  /// across all pools.
  bool tryEvictOneIdleConnLruLocked_()
  {
    std::string bestKey;
    std::size_t bestIdx = static_cast<std::size_t>(-1);
    auto bestTime = std::chrono::steady_clock::time_point::max();

    for (auto &kv : _pools)
    {
      auto &pool = *kv.second;
      pool.forEachIdle(
        [&](std::size_t idx, std::chrono::steady_clock::time_point t)
        {
          if (t < bestTime)
          {
            bestTime = t;
            bestIdx = idx;
            bestKey = kv.first;
          }
        });
    }

    if (bestIdx != static_cast<std::size_t>(-1))
    {
      auto it = _pools.find(bestKey);
      if (it != _pools.end())
      {
        it->second->eraseAt(bestIdx);
        if (it->second->size() == 0)
        {
          _pools.erase(it);
        }
        _totalConnections = recalcTotalLocked_();
        return true;
      }
    }
    return false;
  }

  /// \brief Evict the least-recently-used pool that is entirely idle.
  /// Returns true if evicted.
  bool evictOneIdlePoolLruLocked_()
  {
    std::string bestKey;
    auto bestTime = std::chrono::steady_clock::time_point::max();

    for (auto &kv : _pools)
    {
      auto &pool = *kv.second;
      if (pool.allIdle())
      {
        const auto t = pool.lastTouched();
        if (t < bestTime)
        {
          bestTime = t;
          bestKey = kv.first;
        }
      }
    }

    if (!bestKey.empty())
    {
      auto it = _pools.find(bestKey);
      if (it != _pools.end())
      {
        _pools.erase(it);
        _totalConnections = recalcTotalLocked_();
        return true;
      }
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

  iora::core::ThreadPool &_threadPool;
  Config _config;
  ClientStats _stats;

  std::unordered_map<std::string, std::unique_ptr<detail::EndpointPool>> _pools;
  std::mutex _mutex;
  std::condition_variable _released;

  std::atomic<std::uint64_t> _nextId;
  std::size_t _totalConnections;
};

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
