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

  ~WebhookServer() = default;

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
