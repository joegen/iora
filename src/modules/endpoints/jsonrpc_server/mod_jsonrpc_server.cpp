// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#include "jsonrpc_server.hpp"

#include <cstdint>
#include <chrono>
#include <thread>

#include "iora/iora.hpp"

namespace iora
{

/// \brief JSON-RPC 2.0 endpoint as an IoraService::Plugin.
///
/// Exposes POST {path} on the service webhookServer and exports the following API
/// callables via IoraService::exportApi:
///   - "jsonrpc.version"       -> std::uint32_t()
///   - "jsonrpc.register"      -> void(const std::string&, std::function<iora::parsers::Json(const iora::parsers::Json&)>)
///   - "jsonrpc.registerWithOptions" -> void(const std::string&, std::function<iora::parsers::Json(const iora::parsers::Json&)>, const iora::parsers::Json&)
///   - "jsonrpc.unregister"    -> bool(const std::string&)
///   - "jsonrpc.has"           -> bool(const std::string&)
///   - "jsonrpc.getMethods"    -> std::vector<std::string>()
///   - "jsonrpc.getStats"      -> iora::parsers::Json()
///   - "jsonrpc.resetStats"    -> void()
class JsonRpcServerPlugin : public IoraService::Plugin
{
public:
  JsonRpcServerPlugin(iora::IoraService* service)
    : Plugin(service),
      _enabled(true),
      _path("/rpc"),
      _maxRequestBytes(1 * 1024 * 1024),
      _maxBatchItems(50),
      _requireAuth(false),
      _timeoutMs(5000),
      _logRequests(false),
      _enableMetrics(true)
  {
  }

  const char* name() const
  {
    return "jsonrpc";
  }

  void onLoad(IoraService* service) override
  {
    // Load configuration from IoraService config system
    auto* loader = service->configLoader().get();
    if (loader)
    {
      try
      {
        if (auto v = loader->getBool("iora.modules.jsonrpc_server.enabled"))
          _enabled = *v;
        if (auto v = loader->getString("iora.modules.jsonrpc_server.path"))
          _path = *v;
        if (auto v = loader->getInt("iora.modules.jsonrpc_server.maxRequestBytes"))
          _maxRequestBytes = static_cast<std::size_t>(*v);
        if (auto v = loader->getInt("iora.modules.jsonrpc_server.maxBatchItems"))
          _maxBatchItems = static_cast<std::size_t>(*v);
        if (auto v = loader->getBool("iora.modules.jsonrpc_server.requireAuth"))
          _requireAuth = *v;
        if (auto v = loader->getInt("iora.modules.jsonrpc_server.timeoutMs"))
          _timeoutMs = *v;
        if (auto v = loader->getBool("iora.modules.jsonrpc_server.logRequests"))
          _logRequests = *v;
        if (auto v = loader->getBool("iora.modules.jsonrpc_server.enableMetrics"))
          _enableMetrics = *v;
        
        iora::core::Logger::info("JSON-RPC server plugin configured: path=" + _path + ", auth=" + 
                                (_requireAuth ? "true" : "false") + ", timeout=" + std::to_string(_timeoutMs) + "ms");
      }
      catch (const std::exception& e)
      {
        iora::core::Logger::warning("Failed to load JSON-RPC configuration: " + std::string(e.what()) + ", using defaults");
      }
    }

    // Export callable APIs (matches IoraService::exportApi signature).
    service->exportApi(*this, "jsonrpc.version",
      [this]() -> std::uint32_t
      {
        return 2U; // Version 2 with enhanced features
      });

    service->exportApi(*this, "jsonrpc.register",
      [this](const std::string& method, std::function<iora::parsers::Json(const iora::parsers::Json&)> handler) -> void
      {
        _router.registerMethod(method, 
          [handler](const iora::parsers::Json& params, modules::jsonrpc::RpcContext& ctx) -> iora::parsers::Json
          {
            return handler(params);
          });
      });
      
    service->exportApi(*this, "jsonrpc.registerWithOptions",
      [this](const std::string& method, std::function<iora::parsers::Json(const iora::parsers::Json&)> handler, const iora::parsers::Json& optionsJson) -> void
      {
        modules::jsonrpc::MethodOptions options;
        if (optionsJson.contains("requireAuth") && optionsJson["requireAuth"].is_boolean())
          options.requireAuth = optionsJson["requireAuth"];
        if (optionsJson.contains("timeout") && optionsJson["timeout"].is_number_integer())
          options.timeout = std::chrono::milliseconds(optionsJson["timeout"].get<int>());
        if (optionsJson.contains("maxRequestSize") && optionsJson["maxRequestSize"].is_number_integer())
          options.maxRequestSize = optionsJson["maxRequestSize"].get<std::size_t>();
        
        _router.registerMethod(method, 
          [handler](const iora::parsers::Json& params, modules::jsonrpc::RpcContext& ctx) -> iora::parsers::Json
          {
            return handler(params);
          }, options);
      });

    service->exportApi(*this, "jsonrpc.unregister",
      [this](const std::string& method) -> bool
      {
        return _router.unregisterMethod(method);
      });

    service->exportApi(*this, "jsonrpc.has",
      [this](const std::string& method) -> bool
      {
        return _router.hasMethod(method);
      });
      
    service->exportApi(*this, "jsonrpc.getMethods",
      [this]() -> std::vector<std::string>
      {
        return _router.getMethodNames();
      });
      
    service->exportApi(*this, "jsonrpc.getStats",
      [this]() -> iora::parsers::Json
      {
        const auto& stats = _router.getStats();
        auto statsJson = iora::parsers::Json::object();
        statsJson["totalRequests"] = stats.totalRequests.load();
        statsJson["successfulRequests"] = stats.successfulRequests.load();
        statsJson["failedRequests"] = stats.failedRequests.load();
        statsJson["timeoutRequests"] = stats.timeoutRequests.load();
        statsJson["batchRequests"] = stats.batchRequests.load();
        statsJson["notificationRequests"] = stats.notificationRequests.load();
        return statsJson;
      });
      
    service->exportApi(*this, "jsonrpc.resetStats",
      [this]() -> void
      {
        _router.resetStats();
      });


    // Mount POST {path} directly on the webhookServer.
    service->webhookServer()->onPost(_path,
      [this](const iora::network::WebhookServer::Request& req, iora::network::WebhookServer::Response& res)
      {
        this->handlePost(req, res);
      });
  }


private:
  void handlePost(const iora::network::WebhookServer::Request& req, iora::network::WebhookServer::Response& res)
  {
    
    auto startTime = std::chrono::steady_clock::now();
    
    if (_logRequests)
    {
      iora::core::Logger::debug("JSON-RPC request: " + std::to_string(req.body.size()) + " bytes");
    }
    
    // Set CORS headers if needed
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    
    // Handle preflight OPTIONS request
    if (req.method == iora::network::HttpMethod::OPTIONS)
    {
      res.status = 200;
      return;
    }
    
    // Enforce JSON content type for JSON-RPC 2.0.
    {
      auto it = req.headers.find("Content-Type");
      if (it == req.headers.end() ||
          it->second.find("application/json") == std::string::npos)
      {
        res.status = 415;
        res.set_content(
          R"({"jsonrpc":"2.0","error":{"code":-32600,"message":"Unsupported Media Type"},"id":null})",
          "application/json");
        
        if (_logRequests)
        {
          iora::core::Logger::warning("JSON-RPC request rejected: unsupported media type");
        }
        return;
      }
    }

    // Logical size guard (webhookServer also caps internally).
    if (req.body.size() > _maxRequestBytes)
    {
      res.status = 413;
      res.set_content(
        R"({"jsonrpc":"2.0","error":{"code":-32600,"message":"Request Entity Too Large"},"id":null})",
        "application/json");
      
      if (_logRequests)
      {
        iora::core::Logger::warning("JSON-RPC request rejected: body size " + std::to_string(req.body.size()) + 
                                   " exceeds limit " + std::to_string(_maxRequestBytes));
      }
      return;
    }

    // Optional auth integration
    std::optional<std::string> subject;
    if (_requireAuth)
    {
      // Extract authorization from header (basic implementation)
      auto authHeader = req.headers.find("Authorization");
      if (authHeader != req.headers.end())
      {
        std::string auth = authHeader->second;
        if (auth.size() > 7 && auth.substr(0, 7) == "Bearer ")
        {
          // TODO: Integrate with actual auth system
          subject = auth.substr(7); // Remove "Bearer " prefix
        }
      }
      
      if (!subject)
      {
        res.status = 401;
        res.set_content(
          R"({"jsonrpc":"2.0","error":{"code":-32001,"message":"Authentication required"},"id":null})",
          "application/json");
          
        if (_logRequests)
        {
          iora::core::Logger::warning("JSON-RPC request rejected: authentication required");
        }
        return;
      }
    }

    modules::jsonrpc::RpcContext ctx{IoraService::instance(), subject};
    
    // Set client metadata
    ctx.metadata().clientId = "unknown"; // TODO: Add remote address to WebhookServer::Request

    try
    {
      std::string out = _router.handleRequest(req.body, ctx, _maxBatchItems);
      
      auto endTime = std::chrono::steady_clock::now();
      auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
      
      if (out.empty())
      {
        // Notification-only request or batch with only notifications.
        res.status = 204;
        
        if (_logRequests)
        {
          iora::core::Logger::debug("JSON-RPC notification processed in " + std::to_string(duration.count()) + "ms");
        }
        return;
      }

      res.status = 200;
      res.set_content(std::move(out), "application/json");
      
      if (_logRequests)
      {
        iora::core::Logger::debug("JSON-RPC request processed in " + std::to_string(duration.count()) + "ms, response size: " + std::to_string(out.size()) + " bytes");
      }
    }
    catch (const std::exception& e)
    {
      iora::core::Logger::error("JSON-RPC internal error: " + std::string(e.what()));
      
      res.status = 500;
      res.set_content(
        R"({"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal server error"},"id":null})",
        "application/json");
    }
    catch (...)
    {
      iora::core::Logger::error("JSON-RPC unknown internal error");
      
      res.status = 500;
      res.set_content(
        R"({"jsonrpc":"2.0","error":{"code":-32603,"message":"Unknown internal error"},"id":null})",
        "application/json");
    }
  }

  void onUnload() override
  {
    // Nothing to do here, the webhookServer will automatically unmount.
  }

private:
  bool _enabled;
  std::string _path;
  std::size_t _maxRequestBytes;
  std::size_t _maxBatchItems;
  bool _requireAuth;
  int _timeoutMs;
  bool _logRequests;
  bool _enableMetrics;

  modules::jsonrpc::JsonRpcServer _router;
};

IORA_DECLARE_PLUGIN(JsonRpcServerPlugin);

} // namespace iora
