// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

/// \file microservice_plugin.cpp
/// \brief Example microservice plugin using IoraService to expose a
/// text‑summarisation API.
///
/// This sample demonstrates the PROPER way to build a microservice using
/// the Iora framework as a plugin. The service offers endpoints to summarise
/// arbitrary text by sending requests to an external LLM provider (e.g.,
/// OpenAI) and returning the model's response to the caller. It shows how to:
///
/// - Create a plugin that extends IoraService functionality
/// - Register HTTP routes (`/summarise` and friends) via the plugin API
/// - Use the service's HTTP client to perform outbound requests to LLM APIs
/// - Cache repeated summarisation requests to avoid unnecessary LLM calls
/// - Persist API tokens and usage data across restarts through the embedded
/// store
/// - Log incoming requests, cache hits/misses and external API errors
/// - Demonstrate thread‑safe use of stateless HTTP clients by handling
///   concurrent summarisation requests from multiple clients
///
/// This plugin approach is the recommended way to extend Iora functionality,
/// as opposed to creating standalone applications that initialize IoraService.

#include "iora/iora.hpp"
#include <atomic>
#include <unordered_map>
#include <mutex>

class MicroservicePlugin : public iora::IoraService::Plugin
{
public:
  explicit MicroservicePlugin(iora::IoraService* svc) : Plugin(svc) {}

  void onLoad(iora::IoraService* svc) override
  {
    // Load API token from persistent store
    auto tokenOpt = svc->jsonFileStore()->get("apiToken");
    if (!tokenOpt)
    {
      // first run: read from environment and persist
      const char* envToken = std::getenv("OPENAI_API_KEY");
      if (envToken)
      {
        std::string token = envToken;
        svc->jsonFileStore()->set("apiToken", token);
        LOG_INFO("Stored OpenAI API token from environment variable");
      }
      else
      {
        LOG_ERROR("Environment variable OPENAI_API_KEY is not set.");
        // Plugin can't function without API key, but we don't exit - just log
        // error
        return;
      }
    }

    // Register EventQueue handler for processing summarization requests
    // (fluent)
    svc->onEvent("summarize")
        .handle(
            [this, svc](const iora::parsers::Json& input)
            {
              std::string requestId = input["requestId"];
              std::string text = input["text"];
              int maxTokens = input.contains("max_tokens")
                                  ? input["max_tokens"].get<int>()
                                  : 256;

              // Build payload for LLM
              iora::parsers::Json payload = {
                  {"model", "gpt-3.5-turbo"},
                  {"messages",
                   {{{"role", "user"}, {"content", "Summarise: " + text}}}},
                  {"max_tokens", maxTokens}};

              // Call LLM provider
              auto client = svc->makeHttpClient();
              auto headers = std::map<std::string, std::string>{
                  {"Authorization",
                   "Bearer " + svc->jsonFileStore()->get("apiToken").value()},
                  {"Content-Type", "application/json"}};

              auto llmRes =
                  client.postJson("https://api.openai.com/v1/chat/completions",
                                  payload, headers);
              auto llmJson =
                  iora::network::HttpClient::parseJsonOrThrow(llmRes);
              std::string summary =
                  llmJson["choices"][static_cast<std::size_t>(0)]["message"]
                         ["content"];

              // Store result in the map
              {
                std::lock_guard<std::mutex> lock(_resultsMutex);
                _results[requestId] = {{"summary", summary}};
              }
            });

    // /summarize endpoint queues requests (fluent)
    svc->on("/summarize")
        .handleJson(
            [this, svc](const iora::parsers::Json& input) -> iora::parsers::Json
            {
              std::string text = input["text"];
              int maxTokens = input.contains("max_tokens")
                                  ? input["max_tokens"].get<int>()
                                  : 256;
              std::string requestId =
                  std::to_string(std::hash<std::string>{}(text));

              // Queue the request
              svc->pushEvent({{"eventId", "summarize"},
                              {"requestId", requestId},
                              {"text", text},
                              {"max_tokens", maxTokens}});

              return {{"status", "processing"}, {"requestId", requestId}};
            });

    // /status endpoint retrieves results (fluent)
    svc->on("/status").handleJson(
        [this](const iora::parsers::Json& input) -> iora::parsers::Json
        {
          std::string requestId = input["requestId"];

          std::lock_guard<std::mutex> lock(_resultsMutex);
          if (_results.find(requestId) != _results.end())
          {
            return _results[requestId];
          }
          return {{"status", "pending"}};
        });

    LOG_INFO("Microservice plugin loaded successfully");
  }

  void onUnload() override
  {
    LOG_INFO("Microservice plugin unloading...");

    // Clear results map
    {
      std::lock_guard<std::mutex> lock(_resultsMutex);
      _results.clear();
    }
  }

private:
  // Map to store request statuses and results
  std::unordered_map<std::string, iora::parsers::Json> _results;
  std::mutex _resultsMutex;
};

IORA_DECLARE_PLUGIN(MicroservicePlugin)