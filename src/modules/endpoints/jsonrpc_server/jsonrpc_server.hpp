// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <memory>
#include <chrono>
#include <functional>
#include <vector>

#include "iora/iora.hpp"

namespace iora
{
namespace modules
{
namespace jsonrpc
{

/// \brief JSON-RPC 2.0 server error codes.
enum class ErrorCode : int
{
  ParseError      = -32700,
  InvalidRequest  = -32600,
  MethodNotFound  = -32601,
  InvalidParams   = -32602,
  InternalError   = -32603,
  // Custom application error codes (start from -32000)
  TimeoutError    = -32000,
  AuthenticationError = -32001,
  RateLimitExceeded = -32002
};

/// \brief Request metadata and timing information.
struct RequestMetadata
{
  std::chrono::steady_clock::time_point startTime;
  std::string clientId;
  std::string method;
  std::size_t requestSize;
  
  RequestMetadata()
    : startTime(std::chrono::steady_clock::now()),
      requestSize(0)
  {
  }
};

/// \brief Per-request context made available to JSON-RPC handlers.
class RpcContext
{
public:
  /// \brief Construct a context with access to the owning service and optional subject.
  explicit RpcContext(IoraService& service, std::optional<std::string> subject = {})
    : _service(service),
      _authSubject(std::move(subject)),
      _metadata(std::make_unique<RequestMetadata>())
  {
  }
  
  /// \brief Move constructor.
  RpcContext(RpcContext&& other) noexcept = default;
  RpcContext& operator=(RpcContext&& other) noexcept = default;
  
  // Disable copy constructor and assignment
  RpcContext(const RpcContext&) = delete;
  RpcContext& operator=(const RpcContext&) = delete;

  /// \brief Access the owning IoraService.
  IoraService& service() const
  {
    return _service;
  }

  /// \brief Optional authenticated subject identifier.
  const std::optional<std::string>& authSubject() const
  {
    return _authSubject;
  }
  
  /// \brief Get request metadata.
  const RequestMetadata& metadata() const
  {
    return *_metadata;
  }
  
  /// \brief Get mutable request metadata.
  RequestMetadata& metadata()
  {
    return *_metadata;
  }

private:
  IoraService& _service;
  std::optional<std::string> _authSubject;
  std::unique_ptr<RequestMetadata> _metadata;
};

/// \brief Method handler signature: takes params JSON and context, returns result JSON (or throws).
using MethodHandler = std::function<iora::parsers::Json(const iora::parsers::Json&, RpcContext&)>;

/// \brief Optional method pre/post hooks.
using MethodPreHook = std::function<void(const std::string&, const iora::parsers::Json&, RpcContext&)>;
using MethodPostHook = std::function<void(const std::string&, const iora::parsers::Json&, const iora::parsers::Json&, RpcContext&)>;

/// \brief Method registration options.
struct MethodOptions
{
  bool requireAuth = false;
  std::chrono::milliseconds timeout{5000};
  std::size_t maxRequestSize = 1024 * 1024; // 1MB
  MethodPreHook preHook;
  MethodPostHook postHook;
};

/// \brief JSON-RPC server statistics.
struct ServerStats
{
  std::atomic<std::uint64_t> totalRequests{0};
  std::atomic<std::uint64_t> successfulRequests{0};
  std::atomic<std::uint64_t> failedRequests{0};
  std::atomic<std::uint64_t> timeoutRequests{0};
  std::atomic<std::uint64_t> batchRequests{0};
  std::atomic<std::uint64_t> notificationRequests{0};
  
  /// \brief Reset all counters.
  void reset()
  {
    totalRequests = 0;
    successfulRequests = 0;
    failedRequests = 0;
    timeoutRequests = 0;
    batchRequests = 0;
    notificationRequests = 0;
  }
};

/// \brief Protocol validator and method dispatcher (single & batch).
class JsonRpcServer
{
public:
  JsonRpcServer() = default;
  
  /// \brief Disable copy constructor and assignment.
  JsonRpcServer(const JsonRpcServer&) = delete;
  JsonRpcServer& operator=(const JsonRpcServer&) = delete;

  /// \brief Register (or replace) a method handler.
  void registerMethod(const std::string& name, MethodHandler handler)
  {
    registerMethod(name, std::move(handler), MethodOptions{});
  }
  
  /// \brief Register a method handler with options.
  void registerMethod(const std::string& name, MethodHandler handler, const MethodOptions& options)
  {
    if (name.empty())
    {
      throw std::invalid_argument("Method name cannot be empty");
    }
    
    std::lock_guard<std::mutex> lock(_mutex);
    _handlers[name] = std::move(handler);
    _methodOptions[name] = options;
  }

  /// \brief Unregister a method handler. Returns true if removed.
  bool unregisterMethod(const std::string& name)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    bool removed = _handlers.erase(name) > 0;
    _methodOptions.erase(name);
    return removed;
  }

  /// \brief Check if a handler exists.
  bool hasMethod(const std::string& name) const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    return _handlers.find(name) != _handlers.end();
  }
  
  /// \brief Get list of registered method names.
  std::vector<std::string> getMethodNames() const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    std::vector<std::string> names;
    names.reserve(_handlers.size());
    for (const auto& [name, _] : _handlers)
    {
      names.push_back(name);
    }
    return names;
  }
  
  /// \brief Get server statistics.
  const ServerStats& getStats() const
  {
    return _stats;
  }
  
  /// \brief Reset server statistics.
  void resetStats()
  {
    _stats.reset();
  }

  /// \brief Handle a raw JSON request body; returns response body (empty for pure notifications).
  std::string handleRequest(const std::string& body,
                            RpcContext& ctx,
                            std::size_t maxBatchItems = 50)
  {
    _stats.totalRequests++;
    ctx.metadata().requestSize = body.size();
    
    if (body.empty())
    {
      _stats.failedRequests++;
      return makeError(nullptr, ErrorCode::InvalidRequest, "Empty request body").dump();
    }
    iora::parsers::Json in;
    try
    {
      in = iora::parsers::Json::parseString(body);
    }
    catch (const std::exception& e)
    {
      _stats.failedRequests++;
      std::string errorMsg = "Parse error: " + std::string(e.what());
      return makeError(nullptr, ErrorCode::ParseError, errorMsg).dump();
    }
    catch (...)
    {
      _stats.failedRequests++;
      return makeError(nullptr, ErrorCode::ParseError, "Unknown parse error").dump();
    }

    if (in.is_array())
    {
      _stats.batchRequests++;
      
      if (in.empty())
      {
        _stats.failedRequests++;
        return makeError(nullptr, ErrorCode::InvalidRequest, "Empty batch request").dump();
      }
      if (in.size() > maxBatchItems)
      {
        _stats.failedRequests++;
        std::string errorMsg = "Batch size " + std::to_string(in.size()) + 
                              " exceeds maximum " + std::to_string(maxBatchItems);
        return makeError(nullptr, ErrorCode::InvalidRequest, errorMsg).dump();
      }

      iora::parsers::Json out = iora::parsers::Json::array();
      std::size_t successCount = 0;
      std::size_t errorCount = 0;
      
      for (const auto& item : in)
      {
        iora::parsers::Json r = handleSingle(item, ctx);
        if (!r.is_null())
        {
          if (r.contains("error"))
          {
            errorCount++;
          }
          else
          {
            successCount++;
          }
          out.push_back(std::move(r));
        }
      }
      
      if (errorCount > 0)
      {
        _stats.failedRequests++;
      }
      else
      {
        _stats.successfulRequests++;
      }
      
      return out.empty() ? std::string{} : out.dump();
    }

    iora::parsers::Json r = handleSingle(in, ctx);
    
    if (!r.is_null())
    {
      if (r.contains("error"))
      {
        _stats.failedRequests++;
      }
      else
      {
        _stats.successfulRequests++;
      }
    }
    
    return r.is_null() ? std::string{} : r.dump();
  }

private:
  iora::parsers::Json handleSingle(const iora::parsers::Json& req, RpcContext& ctx)
  {
    const iora::parsers::Json id = req.contains("id") ? req["id"] : iora::parsers::Json();

    // Validate request structure
    if (!req.is_object())
    {
      return makeError(id, ErrorCode::InvalidRequest, "Request must be a JSON object");
    }
    
    if ((req.contains("jsonrpc") ? req["jsonrpc"].get<std::string>() : "") != "2.0")
    {
      return makeError(id, ErrorCode::InvalidRequest, "Missing or invalid jsonrpc version");
    }
    
    if (!req.contains("method"))
    {
      return makeError(id, ErrorCode::InvalidRequest, "Missing method field");
    }

    const std::string method = req["method"].is_string() ? 
      req["method"].get<std::string>() : std::string{};
    if (method.empty())
    {
      return makeError(id, ErrorCode::InvalidRequest, "Method name cannot be empty");
    }
    
    // Store method name in context
    ctx.metadata().method = method;

    iora::parsers::Json params = req.contains("params") ? req["params"] : iora::parsers::Json::object();
    
    bool isNotif = isNotification(req);
    if (isNotif)
    {
      _stats.notificationRequests++;
    }

    MethodHandler handler;
    MethodOptions options;
    {
      std::lock_guard<std::mutex> lock(_mutex);
      auto handlerIt = _handlers.find(method);
      if (handlerIt == _handlers.end())
      {
        return makeError(id, ErrorCode::MethodNotFound, 
                        "Method '" + method + "' not found");
      }
      handler = handlerIt->second;
      
      auto optionsIt = _methodOptions.find(method);
      if (optionsIt != _methodOptions.end())
      {
        options = optionsIt->second;
      }
    }
    
    // Check authentication requirement
    if (options.requireAuth && !ctx.authSubject().has_value())
    {
      return makeError(id, ErrorCode::AuthenticationError, "Authentication required");
    }
    
    // Check request size limit
    if (ctx.metadata().requestSize > options.maxRequestSize)
    {
      return makeError(id, ErrorCode::InvalidRequest, "Request too large");
    }
    
    try
    {
      // Execute pre-hook if available
      if (options.preHook)
      {
        options.preHook(method, params, ctx);
      }
      
      // Execute the method handler
      iora::parsers::Json result = handler(params, ctx);
      
      // Execute post-hook if available
      if (options.postHook)
      {
        options.postHook(method, params, result, ctx);
      }
      
      if (isNotif)
      {
        return iora::parsers::Json(); // no response for notifications
      }
      
      auto response = iora::parsers::Json::object();
      response["jsonrpc"] = "2.0";
      response["result"] = std::move(result);
      response["id"] = id.is_null() ? nullptr : id;
      return response;
    }
    catch (const std::invalid_argument& e)
    {
      std::string errorMsg = "Invalid params: " + std::string(e.what());
      return makeError(id, ErrorCode::InvalidParams, errorMsg);
    }
    catch (const std::runtime_error& e)
    {
      std::string errorMsg = "Runtime error: " + std::string(e.what());
      return makeError(id, ErrorCode::InternalError, errorMsg);
    }
    catch (...)
    {
      return makeError(id, ErrorCode::InternalError, "Unknown internal error");
    }
  }

  iora::parsers::Json makeError(const iora::parsers::Json& id, ErrorCode code, const std::string& message)
  {
    return makeError(id, code, message, iora::parsers::Json());
  }
  
  iora::parsers::Json makeError(const iora::parsers::Json& id, ErrorCode code, 
                            const std::string& message, const iora::parsers::Json& data)
  {
    auto error = iora::parsers::Json::object();
    error["code"] = static_cast<int>(code);
    error["message"] = message;
    
    if (!data.is_null())
    {
      error["data"] = data;
    }
    
    auto response = iora::parsers::Json::object();
    response["jsonrpc"] = "2.0";
    response["error"] = std::move(error);
    response["id"] = id.is_null() ? nullptr : id;
    return response;
  }

  bool isNotification(const iora::parsers::Json& req) const
  {
    return !req.contains("id");
  }

private:
  mutable std::mutex _mutex;
  std::unordered_map<std::string, MethodHandler> _handlers;
  std::unordered_map<std::string, MethodOptions> _methodOptions;
  ServerStats _stats;
};

} } } // namespace iora::modules::jsonrpc
