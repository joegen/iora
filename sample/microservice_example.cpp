/// \file microservice_example.cpp
/// \brief Example microservice using IoraService to expose a text‑summarisation API.
/// 
/// This sample demonstrates how to build a microservice around a large
/// language model (LLM) using the Iora framework.  The service offers
/// endpoints to summarise arbitrary text by sending requests to an
/// external LLM provider (e.g., OpenAI) and returning the model’s
/// response to the caller.  It shows how to:
/// 
/// - Initialise and configure the `IoraService` singleton with a TOML
///   configuration file and command‑line overrides.
/// - Register HTTP routes (`/summarise` and friends) via
///   `webhookServer().onJson()` and handle JSON payloads.
/// - Use `makeHttpClient()` to perform outbound HTTP POST requests to the
///   LLM API, including setting headers and parsing JSON responses.
/// - Cache repeated summarisation requests using
///   `cache().set()`/`get()` to avoid unnecessary LLM calls.
/// - Persist API tokens and usage data across restarts through the
///   embedded `jsonFileStore()` and read them at start‑up.
/// - Log incoming requests, cache hits/misses and external API errors
///   using the integrated `Logger`, with log level, file path and
///   rotation configured from the command line.
/// - Demonstrate thread‑safe use of stateless HTTP clients by handling
///   concurrent summarisation requests from multiple clients.
/// 
/// Together, these features illustrate how IoraService unifies HTTP
/// serving, HTTP clients, configuration management, caching, persistence
/// and logging into a single ergonomic API for building robust C++17
/// microservices.

#include "iora/iora.hpp"

int main(int argc, char** argv)
{
  // Initialise service (reads config.toml, overrides via CLI)
  auto& svc = iora::IoraService::init(argc, argv);

  // Load API token from persistent store
  auto tokenOpt = svc.jsonFileStore().get("apiToken");
  if (!tokenOpt)
  {
    // first run: read from environment or CLI and persist
    std::string token = std::getenv("OPENAI_API_KEY");
    svc.jsonFileStore().set("apiToken", token);
  }

  // /summarize accepts JSON { "text": "...", "max_tokens": 256 }
  svc.webhookServer().onJson("/summarize",
    [&](const iora::Json& input) -> iora::Json
    {
      std::string text      = input["text"];
      int maxTokens         = input.value("max_tokens", 256);
      std::string cacheKey  = std::to_string(std::hash<std::string>{}(text));

      // check cache
      if (auto cached = svc.cache().get(cacheKey))
      {
        LOG_INFO("Cache hit");
        return *cached;
      }

      // build payload for LLM
      iora::Json payload = {
        { "model", "gpt-3.5-turbo" },
        { "messages", { { { "role","user" }, { "content", "Summarise: " + text } } } },
        { "max_tokens", maxTokens }
      };

      // call LLM provider
      auto client  = svc.makeHttpClient();
      auto headers = std::map<std::string,std::string>{
        { "Authorization", "Bearer " + svc.jsonFileStore().get("apiToken").value() },
        { "Content-Type", "application/json" }
      };

      auto llmRes = client.postJson("https://api.openai.com/v1/chat/completions",
                                    payload, headers);

      std::string summary = llmRes["choices"][0]["message"]["content"];
      iora::Json result   = { { "summary", summary } };

      // store in cache
      svc.cache().set(cacheKey, result, std::chrono::seconds(300));
      return result;
    });


  svc.startWebhookServer();
  while (true) { std::this_thread::sleep_for(std::chrono::seconds(60)); }
  return 0;
}
