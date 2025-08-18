// src/modules/jsonrpc/jsonrpc_client_module.cpp
//
// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Iora JSON-RPC Client Module (plugin) exposing service APIs backed by the
// header-only client.
//
// Exposed APIs (types match IoraService::exportApi style from your sample):
//
//  - "jsonrpc.client.version"
//      -> std::uint32_t()
//
//  - "jsonrpc.client.call"
//      -> iora::parsers::Json(const std::string& endpoint,
//                          const std::string& method,
//                          const iora::parsers::Json& params,
//                          const
//                          std::vector<std::pair<std::string,std::string>>&
//                          headers)
//
//  - "jsonrpc.client.notify"
//      -> void(const std::string& endpoint,
//              const std::string& method,
//              const iora::parsers::Json& params,
//              const std::vector<std::pair<std::string,std::string>>& headers)
//
//  - "jsonrpc.client.callBatch"
//      -> std::vector<iora::parsers::Json>(const std::string& endpoint,
//                                       const iora::parsers::Json& items,
//                                       const
//                                       std::vector<std::pair<std::string,std::string>>&
//                                       headers)
//     items is a JSON array of objects with {method, params, id?}
//
//  - "jsonrpc.client.callAsync"
//      -> std::string(const std::string& endpoint,
//                     const std::string& method,
//                     const iora::parsers::Json& params,
//                     const std::vector<std::pair<std::string,std::string>>&
//                     headers)
//     returns a jobId; poll with "jsonrpc.client.result"
//
//  - "jsonrpc.client.callBatchAsync"
//      -> std::string(const std::string& endpoint,
//                     const iora::parsers::Json& items,
//                     const std::vector<std::pair<std::string,std::string>>& headers)
//     returns a jobId; poll with "jsonrpc.client.result"
//     items is a JSON array of objects with {method, params, id?}
//
//  - "jsonrpc.client.result"
//      -> iora::parsers::Json(const std::string& jobId)
//     returns: {"done":true,"result":<JSON>} or
//     {"done":true,"error":{code,message,data}}
//              or {"done":false}
//
//  - "jsonrpc.client.getStats"
//      -> iora::parsers::Json()
//     returns stats as JSON object with counters
//
//  - "jsonrpc.client.resetStats"
//      -> void()
//
//  - "jsonrpc.client.purgeIdle"
//      -> std::size_t()
//
// Configuration (via IoraService::configLoader()):
//   iora.modules.jsonrpcClient.enabled              : bool (default true)
//   iora.modules.jsonrpcClient.maxConnections       : int  (per-endpoint,
//   default 8) iora.modules.jsonrpcClient.globalMaxConnections : int  (global,
//   0=unlimited) iora.modules.jsonrpcClient.maxEndpointPools     : int
//   (0=unlimited) iora.modules.jsonrpcClient.idleTimeoutMs        : int
//   (default 30000) iora.modules.jsonrpcClient.requestTimeoutMs     : int
//   (default 30000) iora.modules.jsonrpcClient.connectionTimeoutMs  : int
//   (default 10000) iora.modules.jsonrpcClient.maxRetries           : int
//   (default 3) iora.modules.jsonrpcClient.retryBackoffMultiplier : double
//   (default 2.0) iora.modules.jsonrpcClient.initialRetryDelayMs  : int
//   (default 100) iora.modules.jsonrpcClient.maxRetryDelayMs      : int
//   (default 5000) iora.modules.jsonrpcClient.enableKeepAlive      : bool
//   (default true) iora.modules.jsonrpcClient.enableCompression    : bool
//   (default true) iora.modules.jsonrpcClient.defaultHeaders       : string
//   "Key:Val,Key2:Val2" (optional)
//
//   TLS (applied for https:// endpoints)
//   iora.modules.jsonrpcClient.tls.verifyPeer     : bool (default true)
//   iora.modules.jsonrpcClient.tls.caCertPath     : string (optional)
//   iora.modules.jsonrpcClient.tls.clientCertPath : string (optional)
//   iora.modules.jsonrpcClient.tls.clientKeyPath  : string (optional)
//
// Notes:
//  - This module does not mount any HTTP routes. It’s a pure client-side API
//  provider.
//  - Adjust the thread-pool accessor if your IoraService uses a different
//  method name.

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "iora/iora.hpp"
#include "jsonrpc_client.hpp"
#include "iora/network/http_client.hpp"

namespace iora
{

/// \brief JSON-RPC Client as an IoraService::Plugin.
///
/// Exposes API methods for performing JSON-RPC calls via pooled HttpClient
/// connections with TLS support, timeouts, per-endpoint/global caps, and async
/// execution on a ThreadPool.
class JsonRpcClientPlugin : public IoraService::Plugin
{
public:
  explicit JsonRpcClientPlugin(iora::IoraService* service)
    : Plugin(service),
      _enabled(true),
      _clientConfig(),
      _jobIdCounter(1),
      _externalPool(nullptr)
  {
  }

  const char* name() const { return "jsonrpc-client"; }

  void onLoad(IoraService* service) override
  {
    // ---- Load configuration ----
    auto* loader = service->configLoader().get();
    if (loader)
    {
      try
      {
        if (auto v = loader->getBool("iora.modules.jsonrpcClient.enabled"))
          _enabled = *v;

        if (auto v =
                loader->getInt("iora.modules.jsonrpcClient.maxConnections"))
          _clientConfig.maxConnectionsPerEndpoint =
              static_cast<std::size_t>(*v);

        if (auto v = loader->getInt(
                "iora.modules.jsonrpcClient.globalMaxConnections"))
          _clientConfig.globalMaxConnections = static_cast<std::size_t>(*v);

        if (auto v =
                loader->getInt("iora.modules.jsonrpcClient.maxEndpointPools"))
          _clientConfig.maxEndpointPools = static_cast<std::size_t>(*v);

        if (auto v = loader->getInt("iora.modules.jsonrpcClient.idleTimeoutMs"))
          _clientConfig.idleTimeout = std::chrono::milliseconds(*v);

        if (auto v =
                loader->getInt("iora.modules.jsonrpcClient.requestTimeoutMs"))
          _clientConfig.requestTimeout = std::chrono::milliseconds(*v);

        if (auto v = loader->getInt(
                "iora.modules.jsonrpcClient.connectionTimeoutMs"))
          _clientConfig.connectionTimeout = std::chrono::milliseconds(*v);

        if (auto v = loader->getInt("iora.modules.jsonrpcClient.maxRetries"))
          _clientConfig.maxRetries = static_cast<std::size_t>(*v);

        // ConfigLoader may not have getDouble, so we'll use getString and parse
        if (auto v = loader->getString(
                "iora.modules.jsonrpcClient.retryBackoffMultiplier"))
          _clientConfig.retryBackoffMultiplier = std::stod(*v);

        if (auto v = loader->getInt(
                "iora.modules.jsonrpcClient.initialRetryDelayMs"))
          _clientConfig.initialRetryDelay = std::chrono::milliseconds(*v);

        if (auto v =
                loader->getInt("iora.modules.jsonrpcClient.maxRetryDelayMs"))
          _clientConfig.maxRetryDelay = std::chrono::milliseconds(*v);

        if (auto v =
                loader->getBool("iora.modules.jsonrpcClient.enableKeepAlive"))
          _clientConfig.enableKeepAlive = *v;

        if (auto v =
                loader->getBool("iora.modules.jsonrpcClient.enableCompression"))
          _clientConfig.enableCompression = *v;

        if (auto v =
                loader->getString("iora.modules.jsonrpcClient.defaultHeaders"))
        {
          _clientConfig.defaultHeaders = parseHeaderList(*v);
        }

        // TLS options (applied for https:// endpoints)
        const bool verifyPeer =
            loader->getBool("iora.modules.jsonrpcClient.tls.verifyPeer")
                .value_or(true);
        const std::string caCertPath =
            loader->getString("iora.modules.jsonrpcClient.tls.caCertPath")
                .value_or("");
        const std::string clientCertPath =
            loader->getString("iora.modules.jsonrpcClient.tls.clientCertPath")
                .value_or("");
        const std::string clientKeyPath =
            loader->getString("iora.modules.jsonrpcClient.tls.clientKeyPath")
                .value_or("");

        _clientConfig.httpClientConfigurer =
            [verifyPeer, caCertPath, clientCertPath, clientKeyPath](
                const std::string& endpoint, iora::network::HttpClient& client)
        {
          const bool isHttps = endpoint.rfind("https://", 0) == 0;
          if (!isHttps)
          {
            return;
          }

          iora::network::HttpClient::TlsConfig tls;

          tls.verifyPeer = verifyPeer;
          tls.caFile = caCertPath;
          tls.clientCertFile = clientCertPath;
          tls.clientKeyFile = clientKeyPath;

          client.setTlsConfig(tls);
        };

        iora::core::Logger::info(
            "JSON-RPC client plugin configured: per-endpoint max=" +
            std::to_string(_clientConfig.maxConnectionsPerEndpoint) +
            ", global max=" +
            std::to_string(_clientConfig.globalMaxConnections) +
            ", pools max=" + std::to_string(_clientConfig.maxEndpointPools) +
            ", reqTimeoutMs=" +
            std::to_string(_clientConfig.requestTimeout.count()));
      }
      catch (const std::exception& e)
      {
        iora::core::Logger::warning(
            "Failed to load JSON-RPC client configuration: " +
            std::string(e.what()) + ", using defaults");
      }
    }

    // ---- Resolve ThreadPool ----
    // Integration point: if your service exposes a different accessor, adjust
    // here.
    _externalPool =
        service->threadPool().get(); // threadPool() is a const method
    if (!_externalPool)
    {
      iora::core::Logger::error("JSON-RPC client plugin requires a ThreadPool, "
                                "but none is available");
      return;
    }
    // ---- Construct client ----
    _client = std::make_unique<iora::modules::connectors::JsonRpcClient>(
        *service, *_externalPool, _clientConfig);

    // ---- Export APIs ----
    service->exportApi(*this, "jsonrpc.client.version",
                       [this]() -> std::uint32_t
                       {
                         return 2U; // Version 2 with enhanced features
                       });

    service->exportApi(
        *this, "jsonrpc.client.call",
        [this](const std::string& endpoint, const std::string& method,
               const iora::parsers::Json& params,
               const std::vector<std::pair<std::string, std::string>>& headers)
            -> iora::parsers::Json
        {
          // Direct call - let exceptions propagate for proper error handling
          return _client->call(endpoint, method, params, headers);
        });

    service->exportApi(
        *this, "jsonrpc.client.notify",
        [this](const std::string& endpoint, const std::string& method,
               const iora::parsers::Json& params,
               const std::vector<std::pair<std::string, std::string>>& headers)
            -> void { _client->notify(endpoint, method, params, headers); });

    service->exportApi(
        *this, "jsonrpc.client.callAsync",
        [this](const std::string& endpoint, const std::string& method,
               const iora::parsers::Json& params,
               const std::vector<std::pair<std::string, std::string>>& headers)
            -> std::string
        {
          const std::string jobId = nextJobId_();

          // Lambdas must be copyable/movable for thread pool
          auto onSuccess = [this, jobId](iora::parsers::Json result)
          {
            std::lock_guard<std::mutex> lock(_jobsMutex);
            auto jobResult = iora::parsers::Json::object();
            jobResult["done"] = true;
            jobResult["result"] = std::move(result);
            _jobs[jobId] = jobResult;
          };
          auto onError = [this, jobId](std::exception_ptr ep)
          {
            auto err = iora::parsers::Json::object();
            err["code"] = -32000;
            err["message"] = "Unknown error";
            err["data"] = nullptr;
            try
            {
              if (ep)
                std::rethrow_exception(ep);
            }
            catch (const iora::modules::connectors::RemoteError& re)
            {
              err["code"] = re.code();
              err["message"] = re.message();
              err["data"] = re.data();
            }
            catch (const std::exception& e)
            {
              err["message"] = e.what();
            }

            std::lock_guard<std::mutex> lock(_jobsMutex);
            auto jobError = iora::parsers::Json::object();
            jobError["done"] = true;
            jobError["error"] = std::move(err);
            _jobs[jobId] = jobError;
          };

          _client->callAsync(endpoint, method, params, headers,
                             std::move(onSuccess), std::move(onError));
          return jobId;
        });

    service->exportApi(
        *this, "jsonrpc.client.callBatch",
        [this](const std::string& endpoint,
               const iora::parsers::Json& itemsJson,
               const std::vector<std::pair<std::string, std::string>>& headers)
            -> std::vector<iora::parsers::Json>
        {
          // Convert JSON array to BatchItem vector
          std::vector<iora::modules::connectors::BatchItem> items;
          if (!itemsJson.is_array()) {
            throw std::invalid_argument("Batch items must be a JSON array");
          }
          
          for (const auto& item : itemsJson) {
            if (!item.is_object() || !item.contains("method")) {
              throw std::invalid_argument("Each batch item must be an object with 'method' field");
            }
            
            std::string method = item["method"].get<std::string>();
            iora::parsers::Json params = item.contains("params") ? item["params"] : iora::parsers::Json::object();
            
            if (item.contains("id")) {
              std::uint64_t id = item["id"].get<std::uint64_t>();
              items.emplace_back(std::move(method), std::move(params), id);
            } else {
              items.emplace_back(std::move(method), std::move(params));
            }
          }
          
          return _client->callBatch(endpoint, items, headers);
        });

    service->exportApi(
        *this, "jsonrpc.client.callBatchAsync",
        [this](const std::string& endpoint,
               const iora::parsers::Json& itemsJson,
               const std::vector<std::pair<std::string, std::string>>& headers)
            -> std::string
        {
          const std::string jobId = nextJobId_();

          auto onSuccess = [this, jobId](std::vector<iora::parsers::Json> results)
          {
            std::lock_guard<std::mutex> lock(_jobsMutex);
            auto jobResult = iora::parsers::Json::object();
            jobResult["done"] = true;
            jobResult["result"] = iora::parsers::Json(results);
            _jobs[jobId] = jobResult;
          };

          auto onError = [this, jobId](std::exception_ptr ep)
          {
            auto err = iora::parsers::Json::object();
            err["code"] = -32000;
            err["message"] = "Unknown error";
            err["data"] = nullptr;
            try
            {
              if (ep)
                std::rethrow_exception(ep);
            }
            catch (const iora::modules::connectors::RemoteError& re)
            {
              err["code"] = re.code();
              err["message"] = re.message();
              err["data"] = re.data();
            }
            catch (const std::exception& e)
            {
              err["message"] = e.what();
            }

            std::lock_guard<std::mutex> lock(_jobsMutex);
            auto jobError = iora::parsers::Json::object();
            jobError["done"] = true;
            jobError["error"] = std::move(err);
            _jobs[jobId] = jobError;
          };

          // Submit batch request to thread pool
          _externalPool->enqueue(
              [this, endpoint, itemsJson, headers, onSuccess, onError]()
              {
                try
                {
                  // Convert JSON array to BatchItem vector inside the thread
                  std::vector<iora::modules::connectors::BatchItem> items;
                  if (!itemsJson.is_array()) {
                    throw std::invalid_argument("Batch items must be a JSON array");
                  }
                  
                  for (const auto& item : itemsJson) {
                    if (!item.is_object() || !item.contains("method")) {
                      throw std::invalid_argument("Each batch item must be an object with 'method' field");
                    }
                    
                    std::string method = item["method"].get<std::string>();
                    iora::parsers::Json params = item.contains("params") ? item["params"] : iora::parsers::Json::object();
                    
                    if (item.contains("id")) {
                      std::uint64_t id = item["id"].get<std::uint64_t>();
                      items.emplace_back(std::move(method), std::move(params), id);
                    } else {
                      items.emplace_back(std::move(method), std::move(params));
                    }
                  }
                  
                  auto results = _client->callBatch(endpoint, items, headers);
                  onSuccess(results);
                }
                catch (...)
                {
                  onError(std::current_exception());
                }
              });

          return jobId;
        });

    service->exportApi(*this, "jsonrpc.client.result",
                       [this](const std::string& jobId) -> iora::parsers::Json
                       {
                         std::lock_guard<std::mutex> lock(_jobsMutex);
                         auto it = _jobs.find(jobId);
                         if (it == _jobs.end())
                         {
                           auto result = iora::parsers::Json::object();
                           result["done"] = false;
                           return result;
                         }
                         return it->second;
                       });

    service->exportApi(*this, "jsonrpc.client.getStats",
                       [this]() -> iora::parsers::Json
                       {
                         const auto& stats = _client->getStats();
                         auto statsJson = iora::parsers::Json::object();
                         statsJson["totalRequests"] = stats.totalRequests.load();
                         statsJson["successfulRequests"] = stats.successfulRequests.load();
                         statsJson["failedRequests"] = stats.failedRequests.load();
                         statsJson["timeoutRequests"] = stats.timeoutRequests.load();
                         statsJson["retriedRequests"] = stats.retriedRequests.load();
                         statsJson["batchRequests"] = stats.batchRequests.load();
                         statsJson["notificationRequests"] = stats.notificationRequests.load();
                         statsJson["poolExhaustions"] = stats.poolExhaustions.load();
                         statsJson["connectionsCreated"] = stats.connectionsCreated.load();
                         statsJson["connectionsEvicted"] = stats.connectionsEvicted.load();
                         return statsJson;
                       });

    service->exportApi(*this, "jsonrpc.client.resetStats",
                       [this]() -> void { _client->resetStats(); });

    service->exportApi(*this, "jsonrpc.client.purgeIdle",
                       [this]() -> std::size_t
                       { return _client->purgeIdle(); });
  }

  void onUnload() override
  {
    // APIs are unregistered automatically by the service using the plugin
    // owner.
    _client.reset();
  }

private:
  static std::vector<std::pair<std::string, std::string>>
  parseHeaderList(const std::string& csv)
  {
    // Very small parser for "Key:Val,Key2:Val2"
    std::vector<std::pair<std::string, std::string>> out;
    std::string key;
    std::string val;
    std::string* cur = &key;

    auto flushPair = [&]()
    {
      // Trim spaces
      auto trim = [](std::string& s)
      {
        auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
        while (!s.empty() && isSpace(static_cast<unsigned char>(s.front())))
          s.erase(s.begin());
        while (!s.empty() && isSpace(static_cast<unsigned char>(s.back())))
          s.pop_back();
      };
      trim(key);
      trim(val);
      if (!key.empty())
      {
        out.emplace_back(key, val);
      }
      key.clear();
      val.clear();
      cur = &key;
    };

    for (char c : csv)
    {
      if (c == ':')
      {
        if (cur == &key)
        {
          cur = &val;
        }
        else
        {
          (*cur) += c; // allow ':' inside value
        }
      }
      else if (c == ',')
      {
        flushPair();
      }
      else
      {
        (*cur) += c;
      }
    }
    if (!key.empty() || !val.empty())
    {
      flushPair();
    }

    return out;
  }

  std::string nextJobId_()
  {
    const auto id = _jobIdCounter.fetch_add(1, std::memory_order_relaxed);
    return "rpcjob-" + std::to_string(id);
  }

private:
  bool _enabled;
  iora::modules::connectors::Config _clientConfig;

  std::atomic<std::uint64_t> _jobIdCounter;
  std::mutex _jobsMutex;
  std::unordered_map<std::string, iora::parsers::Json> _jobs;

  // ThreadPool: prefer service-owned; fall back to a small internal pool if
  // missing.
  iora::core::ThreadPool* _externalPool;

  std::unique_ptr<iora::modules::connectors::JsonRpcClient> _client;
};

IORA_DECLARE_PLUGIN(JsonRpcClientPlugin);

} // namespace iora
