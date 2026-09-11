// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include "iora/network/http_server.hpp"
#include "iora/parsers/json.hpp"

namespace iora
{
namespace network
{

/// \brief JSON-aware HTTP server that extends HttpServer with JSON
/// endpoint support.
///
/// WebhookServer inherits all HTTP server functionality from HttpServer
/// and adds convenience methods for registering JSON-based GET and POST
/// handlers that automatically parse request bodies and serialize responses.
class WebhookServer : public HttpServer
{
public:
  /// \brief Default maximum JSON payload size (10MB)
  static constexpr std::size_t DEFAULT_MAX_JSON_SIZE = 10 * 1024 * 1024;

  /// \brief JSON parsing configuration
  struct JsonConfig
  {
    std::size_t maxPayloadSize = DEFAULT_MAX_JSON_SIZE; // Maximum JSON payload size in bytes
    parsers::ParseLimits parseLimits; // JSON parsing limits (depth, array size, etc.)
  };

  /// \brief Handler type for JSON endpoints
  using JsonHandler = std::function<parsers::Json(const parsers::Json &)>;

  /// \brief Constructs a WebhookServer with the given bind address and port.
  WebhookServer(const std::string& bindAddress = "0.0.0.0", int port = DEFAULT_PORT)
      : HttpServer(bindAddress, port), _jsonConfig{}
  {
  }

  /// \brief WS-TS2: quiesce the transport and drain the worker pool BEFORE
  /// _jsonConfig is destroyed. The onJsonGet/onJsonPost handlers run on pool
  /// workers and read _jsonConfig; ~HttpServer drains the pool only after this
  /// derived member is already gone, so a worker mid-handler would deref a
  /// destroyed _jsonConfig. Must come first in this dtor.
  ///
  /// NOTE the guarantee is bounded, not absolute: quiesceTransport()'s drain is
  /// capped (see HttpServer::quiesceTransport) and abandons the pool after the
  /// timeout, so a handler that ignores getShutdownChecker() and runs past it
  /// could still be live when _jsonConfig is destroyed. In practice _jsonConfig is
  /// read only in the brief pre-handler section (size check + parse), which
  /// completes well within the drain window; the general drain-policy hardening
  /// (unbounded dtor drain / gate on activeThreadCount==0) is tracked separately.
  /// quiesceTransport() can throw (allocation/logging); the noexcept wrapper
  /// swallows so this destructor cannot std::terminate (the base dtor's stop()
  /// early-outs).
  ~WebhookServer() override
  {
    quiesceTransportNoexcept("~WebhookServer");
  }

  /// \brief Sets the JSON parsing configuration
  void setJsonConfig(const JsonConfig &config)
  {
    _jsonConfig = config;
  }

  /// \brief Gets the current JSON parsing configuration
  JsonConfig getJsonConfig() const
  {
    return _jsonConfig;
  }

  /// \brief Registers a GET handler for JSON endpoints.
  ///
  /// The handler receives a parsed JSON object (empty object if no body)
  /// and returns a JSON response that is automatically serialized.
  void onJsonGet(const std::string &endpoint, JsonHandler handler)
  {
    onGet(endpoint,
          [this, handler](const Request &req, Response &res)
          {
            try
            {
              parsers::Json requestJson;
              if (req.body.empty())
              {
                requestJson = parsers::Json::object();
              }
              else
              {
                if (req.body.size() > _jsonConfig.maxPayloadSize)
                {
                  throw std::runtime_error("JSON payload exceeds maximum size limit of " +
                                           std::to_string(_jsonConfig.maxPayloadSize) + " bytes");
                }
                auto result = parsers::Json::parse(req.body, _jsonConfig.parseLimits);
                if (!result.ok)
                {
                  throw std::runtime_error("JSON parse error: " + result.error.message);
                }
                requestJson = std::move(result.value);
              }
              parsers::Json responseJson = handler(requestJson);
              res.set_content(responseJson.dump(), "application/json");
            }
            catch (const std::exception &ex)
            {
              res.status = 500;
              res.set_content(ex.what(), "text/plain");
              iora::core::Logger::error(std::string("WebhookServer onJsonGet handler error: ") +
                                        ex.what());
            }
          });
  }

  /// \brief Registers a POST handler for JSON endpoints.
  ///
  /// The handler receives a parsed JSON object from the request body
  /// and returns a JSON response that is automatically serialized.
  void onJsonPost(const std::string &endpoint, JsonHandler handler)
  {
    onPost(endpoint,
           [this, handler](const Request &req, Response &res)
           {
             try
             {
               if (req.body.size() > _jsonConfig.maxPayloadSize)
               {
                 throw std::runtime_error("JSON payload exceeds maximum size limit of " +
                                          std::to_string(_jsonConfig.maxPayloadSize) + " bytes");
               }
               auto result = parsers::Json::parse(req.body, _jsonConfig.parseLimits);
               if (!result.ok)
               {
                 throw std::runtime_error("JSON parse error: " + result.error.message);
               }
               parsers::Json requestJson = std::move(result.value);
               parsers::Json responseJson = handler(requestJson);
               res.set_content(responseJson.dump(), "application/json");
             }
             catch (const std::exception &ex)
             {
               res.status = 500;
               res.set_content(ex.what(), "text/plain");
               iora::core::Logger::error(std::string("WebhookServer onJsonPost handler error: ") +
                                         ex.what());
             }
           });
  }

private:
  JsonConfig _jsonConfig;
};

} // namespace network
} // namespace iora
