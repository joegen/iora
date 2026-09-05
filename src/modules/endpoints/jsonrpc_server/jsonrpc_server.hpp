// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
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
  ParseError = -32700,
  InvalidRequest = -32600,
  MethodNotFound = -32601,
  InvalidParams = -32602,
  InternalError = -32603,
  // Custom application error codes (start from -32000)
  TimeoutError = -32000,
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

  RequestMetadata() : startTime(std::chrono::steady_clock::now()), requestSize(0) {}
};

/// \brief Per-request context made available to JSON-RPC handlers.
class RpcContext
{
public:
  /// \brief Construct a context with access to the owning service and optional subject.
  explicit RpcContext(IoraService &service, std::optional<std::string> subject = {})
      : _service(service), _authSubject(std::move(subject)),
        _metadata(std::make_unique<RequestMetadata>())
  {
  }

  /// \brief Move constructor.
  RpcContext(RpcContext &&other) noexcept = default;
  RpcContext &operator=(RpcContext &&other) noexcept = default;

  // Disable copy constructor and assignment
  RpcContext(const RpcContext &) = delete;
  RpcContext &operator=(const RpcContext &) = delete;

  /// \brief Access the owning IoraService.
  IoraService &service() const { return _service; }

  /// \brief Optional authenticated subject identifier.
  const std::optional<std::string> &authSubject() const { return _authSubject; }

  /// \brief Get request metadata.
  const RequestMetadata &metadata() const { return *_metadata; }

  /// \brief Get mutable request metadata.
  RequestMetadata &metadata() { return *_metadata; }

private:
  IoraService &_service;
  std::optional<std::string> _authSubject;
  std::unique_ptr<RequestMetadata> _metadata;
};

/// \brief Method handler signature: takes params JSON and context, returns result JSON (or throws).
using MethodHandler = std::function<iora::parsers::Json(const iora::parsers::Json &, RpcContext &)>;

/// \brief Optional method pre/post hooks.
using MethodPreHook =
  std::function<void(const std::string &, const iora::parsers::Json &, RpcContext &)>;
using MethodPostHook = std::function<void(const std::string &, const iora::parsers::Json &,
                                          const iora::parsers::Json &, RpcContext &)>;

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
  /// \note Each store is individually atomic, but reset() is NOT atomic ACROSS
  /// counters: a reset() racing an in-flight dispatch can momentarily leave the
  /// counters mutually inconsistent (e.g. totalRequests==0 while
  /// successfulRequests==1). This is a logical cross-counter gap, not a data race
  /// (every counter is std::atomic). Call it only when quiescent; any concurrent
  /// stats assertion must check monotonicity/bounds, never exact equality.
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
///
/// \par Concurrency contract (caller-visible)
/// - Method handlers, \c preHook and \c postHook are invoked CONCURRENTLY on the
///   owning HttpServer's worker threads with NO server lock held. They must be
///   thread-safe, and they MAY re-enter the server: calling registerMethod /
///   unregisterMethod / hasMethod / getMethodNames from inside a handler or hook
///   is safe (the handler and its options are copied out under \c _mutex and the
///   lock is released before invocation — copy-then-invoke).
/// - The \c RpcContext& passed to a handler/hook is valid ONLY for the duration of
///   that call. It MUST NOT be captured or stored beyond the call scope.
/// - Within a BATCH the SAME RpcContext is reused for every item, with
///   metadata().method overwritten per item. metadata() is therefore per-BATCH,
///   not per-item, for every field except \c method.
/// - metadata().requestSize is the size of the WHOLE request/batch body, not a
///   per-item size. (The interaction between this and the per-method maxRequestSize
///   check in a batch is an open disposition owned by the migration architecture
///   doc's consistencyNote_CORRECTED — not addressed here.)
class JsonRpcServer
{
public:
  JsonRpcServer() = default;

  /// \brief Disable copy constructor and assignment.
  JsonRpcServer(const JsonRpcServer &) = delete;
  JsonRpcServer &operator=(const JsonRpcServer &) = delete;

  /// \brief Register (or replace) a method handler.
  void registerMethod(const std::string &name, MethodHandler handler)
  {
    registerMethod(name, std::move(handler), MethodOptions{});
  }

  /// \brief Register a method handler with options.
  void registerMethod(const std::string &name, MethodHandler handler, const MethodOptions &options)
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
  bool unregisterMethod(const std::string &name)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    bool removed = _handlers.erase(name) > 0;
    _methodOptions.erase(name);
    return removed;
  }

  /// \brief Check if a handler exists.
  bool hasMethod(const std::string &name) const
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
    for (const auto &[name, _] : _handlers)
    {
      names.push_back(name);
    }
    return names;
  }

  /// \brief Get server statistics.
  const ServerStats &getStats() const { return _stats; }

  /// \brief Reset server statistics. Safe to call concurrently, but NOT atomic
  /// across counters (see ServerStats::reset) — call when quiescent.
  void resetStats() { _stats.reset(); }

  /// \brief Handle a raw JSON request body; returns response body (empty for pure notifications).
  std::string handleRequest(const std::string &body, RpcContext &ctx,
                            std::size_t maxBatchItems = 50)
  {
    _stats.totalRequests++;
    ctx.metadata().requestSize = body.size();

    if (body.empty())
    {
      // W-M8 (JSON-RPC 2.0 §5.1): an empty octet string is invalid JSON — a Parse
      // error (-32700), not a well-formed value that fails to be a Request object
      // (-32600). Observable only in the JSON error `code`; the endpoint maps every
      // non-empty dispatcher envelope to HTTP 200 regardless.
      _stats.failedRequests++;
      return makeError(nullptr, ErrorCode::ParseError, "Empty request body").dump();
    }
    iora::parsers::Json in;
    try
    {
      in = iora::parsers::Json::parseString(body);
    }
    catch (const std::exception &e)
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
        std::string errorMsg = "Batch size " + std::to_string(in.size()) + " exceeds maximum " +
                               std::to_string(maxBatchItems);
        return makeError(nullptr, ErrorCode::InvalidRequest, errorMsg).dump();
      }

      iora::parsers::Json out = iora::parsers::Json::array();
      std::size_t errorCount = 0;

      for (const auto &item : in)
      {
        iora::parsers::Json r = handleSingleGuarded(item, ctx);
        if (!r.is_null())
        {
          if (r.contains("error"))
          {
            errorCount++;
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

    iora::parsers::Json r = handleSingleGuarded(in, ctx);

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
  /// \brief Defensive structural net around handleSingle (M-D): no single item may
  /// abort a batch, and a single request that would throw pre-try yields an
  /// envelope, never an escaped exception. Applied symmetrically to both the batch
  /// loop and the single-request path — W-H2's own reproducer is a single request.
  /// After the jsonrpc type-guard (task-2.1) no throw precedes handleSingle's
  /// !is_object() return, so this catch is unreachable-by-construction today (an
  /// OOM/future-code guard). isNotification is RE-EVALUATED here: the isNotif local
  /// lives inside handleSingle and is out of scope at this throw site. A
  /// non-notification gets an id:null envelope (§5: the id cannot be determined).
  /// CAVEAT: isNotification(non-object) is true (contains->false), so a non-object
  /// item reaching this catch would be wrongly suppressed where §5 wants id:null —
  /// that path is unreachable given task-2.1's type-guard.
  iora::parsers::Json handleSingleGuarded(const iora::parsers::Json &req, RpcContext &ctx)
  {
    try
    {
      return handleSingle(req, ctx);
    }
    catch (...)
    {
      return isNotification(req)
               ? iora::parsers::Json()
               : makeError(iora::parsers::Json(), ErrorCode::InternalError,
                           "Unknown internal error");
    }
  }

  iora::parsers::Json handleSingle(const iora::parsers::Json &req, RpcContext &ctx)
  {
    const iora::parsers::Json id = req.contains("id") ? req["id"] : iora::parsers::Json();

    // Validate request structure
    if (!req.is_object())
    {
      return makeError(id, ErrorCode::InvalidRequest, "Request must be a JSON object");
    }

    // W-H2 (§5.1): type-guard the jsonrpc member. The prior unguarded
    // get<std::string>() threw std::bad_variant_access on a non-string member
    // (a JSON number/bool/object/array/null) — a type that derives from
    // std::exception but NOT from runtime_error/invalid_argument, so it escaped
    // every catch below, became an HTTP 500, and (in a batch) discarded every
    // already-computed sibling response. Mirror the method guard just below.
    const bool versionOk = req.contains("jsonrpc") && req["jsonrpc"].is_string() &&
                           req["jsonrpc"].get<std::string>() == "2.0";
    if (!versionOk)
    {
      return makeError(id, ErrorCode::InvalidRequest, "Missing or invalid jsonrpc version");
    }

    if (!req.contains("method"))
    {
      return makeError(id, ErrorCode::InvalidRequest, "Missing method field");
    }

    const std::string method =
      req["method"].is_string() ? req["method"].get<std::string>() : std::string{};
    if (method.empty())
    {
      return makeError(id, ErrorCode::InvalidRequest, "Method name cannot be empty");
    }

    // id-type validation (LD-12), PRE-DISPATCH (§4): a present id MUST be a String,
    // Number, or Null; any other type (object, array, boolean) makes this an
    // Invalid Request. Validated HERE — a structural check adjacent to the
    // jsonrpc/method checks, BEFORE the handler-map lookup and handler invocation —
    // so a side-effecting handler never runs for an id-type-invalid request. Uses a
    // POSITIVE allowlist: is_number() is isInt()||isDouble() and excludes bool, so
    // {"id":true} is rejected too (a negative is_object()||is_array() check would
    // silently accept it). Because the offending id cannot be echoed, §5 requires
    // id:null — emit an EXPLICIT null id (never makeError(id,...), which echoes any
    // non-null id and would re-introduce the very defect). A missing id is a
    // Notification, not an id-type violation, so the check is guarded on contains.
    if (req.contains("id") && !(id.is_string() || id.is_number() || id.is_null()))
    {
      return makeError(iora::parsers::Json(), ErrorCode::InvalidRequest,
                       "Request id must be a string, number, or null");
    }

    // Store method name in context
    ctx.metadata().method = method;

    iora::parsers::Json params =
      req.contains("params") ? req["params"] : iora::parsers::Json::object();

    // W-H1: notification status is determined BEFORE the handler-map lookup, so
    // every post-lookup path below can suppress its response for a notification.
    const bool isNotif = isNotification(req);
    if (isNotif)
    {
      _stats.notificationRequests++;
    }

    // W-H1 (§4.1): every POST-lookup failure is silent for a notification (the
    // request was structurally valid, so a notification MUST NOT be answered) and
    // an id:null-or-echoed envelope otherwise. Stating the rule once keeps the six
    // post-lookup sites from drifting.
    auto suppressOrError = [&](ErrorCode code, const std::string &message) -> iora::parsers::Json
    { return isNotif ? iora::parsers::Json() : makeError(id, code, message); };

    MethodHandler handler;
    MethodOptions options;
    {
      std::lock_guard<std::mutex> lock(_mutex);
      auto handlerIt = _handlers.find(method);
      if (handlerIt == _handlers.end())
      {
        return suppressOrError(ErrorCode::MethodNotFound, "Method '" + method + "' not found");
      }
      handler = handlerIt->second;

      auto optionsIt = _methodOptions.find(method);
      if (optionsIt != _methodOptions.end())
      {
        options = optionsIt->second;
      }
    }

    // Check authentication requirement (W-H1: post-lookup — suppress for a notification)
    if (options.requireAuth && !ctx.authSubject().has_value())
    {
      return suppressOrError(ErrorCode::AuthenticationError, "Authentication required");
    }

    // Check request size limit (W-H1: post-lookup — suppress for a notification)
    if (ctx.metadata().requestSize > options.maxRequestSize)
    {
      return suppressOrError(ErrorCode::InvalidRequest, "Request too large");
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
      // Defensively identical to the error echo site (echoableId): the pre-dispatch
      // id-type check already guarantees id is string/number/null here, but sharing
      // the one coercion means the success path cannot regress if that check is ever
      // relocated (L-2).
      response["id"] = echoableId(id);
      return response;
    }
    // W-H1: all three handler-exception paths are post-lookup — suppress for a
    // notification (a notification has no client-visible result, success or fail).
    catch (const std::invalid_argument &e)
    {
      return suppressOrError(ErrorCode::InvalidParams, "Invalid params: " + std::string(e.what()));
    }
    catch (const std::runtime_error &e)
    {
      return suppressOrError(ErrorCode::InternalError, "Runtime error: " + std::string(e.what()));
    }
    catch (...)
    {
      return suppressOrError(ErrorCode::InternalError, "Unknown internal error");
    }
  }

  iora::parsers::Json makeError(const iora::parsers::Json &id, ErrorCode code,
                                const std::string &message,
                                const iora::parsers::Json &data = iora::parsers::Json())
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
    response["id"] = echoableId(id);
    return response;
  }

  /// \brief §4.2/§5 id echo policy, applied at every response echo site so no path
  /// can echo a non-representable id. An id is echoable only if it is a String or a
  /// Number; anything else — Object, Array, Boolean, or Null — is answered as null.
  /// is_number() is isInt()||isDouble() and excludes bool, so a boolean id nulls
  /// here too. This is the H-1 fix: even when a second structural defect (bad
  /// jsonrpc, missing/empty/non-string method) routes around the pre-dispatch
  /// id-type check, the offending id is never echoed. Policy A (human decision
  /// 2026-09-05): a valid SCALAR id IS echoed on an Invalid Request, so
  /// MethodNotFound/InvalidParams keep echoing their scalar id (§6 requires it).
  static iora::parsers::Json echoableId(const iora::parsers::Json &id)
  {
    return (id.is_string() || id.is_number()) ? id : iora::parsers::Json();
  }

  bool isNotification(const iora::parsers::Json &req) const { return !req.contains("id"); }

private:
  mutable std::mutex _mutex;
  std::unordered_map<std::string, MethodHandler> _handlers;
  std::unordered_map<std::string, MethodOptions> _methodOptions;
  ServerStats _stats;
};

} // namespace jsonrpc
} // namespace modules
} // namespace iora
