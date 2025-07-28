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

#include <atomic>
#include <unordered_map>
#include <mutex>

int main(int argc, char** argv)
{
  // Initialise service (reads config.toml, overrides via CLI)
  auto& svc = iora::IoraService::init(argc, argv);

  // Load API token from persistent store
  auto tokenOpt = svc.jsonFileStore().get("apiToken");
  if (!tokenOpt)
  {
    // first run: read from environment or CLI and persist
    const char* envToken = std::getenv("OPENAI_API_KEY");
    if (envToken)
    {
      std::string token = envToken;
      svc.jsonFileStore().set("apiToken", token);
    }
    else
    {
      LOG_ERROR("Environment variable OPENAI_API_KEY is not set.");
      std::cerr << "Error: OPENAI_API_KEY is required but not set." << std::endl;
      std::exit(EXIT_FAILURE);
    }
  }

  // Map to store request statuses and results
  std::unordered_map<std::string, iora::Json> results;
  std::mutex resultsMutex;

  // Register EventQueue handler for processing summarization requests
  svc.eventQueue().onEventId("summarize", [&](const iora::Json& input) {
    std::string requestId = input["requestId"];
    std::string text = input["text"];
    int maxTokens = input.value("max_tokens", 256);

    // Build payload for LLM
    iora::Json payload = {
      { "model", "gpt-3.5-turbo" },
      { "messages", { { { "role","user" }, { "content", "Summarise: " + text } } } },
      { "max_tokens", maxTokens }
    };

    // Call LLM provider
    auto client = svc.makeHttpClient();
    auto headers = std::map<std::string, std::string>{
      { "Authorization", "Bearer " + svc.jsonFileStore().get("apiToken").value() },
      { "Content-Type", "application/json" }
    };

    auto llmRes = client.postJson("https://api.openai.com/v1/chat/completions", payload, headers);
    std::string summary = llmRes["choices"][0]["message"]["content"];

    // Store result in the map
    {
      std::lock_guard<std::mutex> lock(resultsMutex);
      results[requestId] = { { "summary", summary } };
    }
  });

  // /summarize endpoint queues requests
  svc.webhookServer().onJson("/summarize", [&](const iora::Json& input) -> iora::Json {
    std::string text = input["text"];
    int maxTokens = input.value("max_tokens", 256);
    std::string requestId = std::to_string(std::hash<std::string>{}(text));

    // Queue the request
    svc.eventQueue().push({ { "eventId", "summarize" }, { "requestId", requestId }, { "text", text }, { "max_tokens", maxTokens } });

    return { { "status", "processing" }, { "requestId", requestId } };
  });

  // /status endpoint retrieves results
  svc.webhookServer().onJson("/status", [&](const iora::Json& input) -> iora::Json {
    std::string requestId = input["requestId"];

    std::lock_guard<std::mutex> lock(resultsMutex);
    if (results.find(requestId) != results.end())
    {
      return results[requestId];
    }
    return { { "status", "pending" } };
  });

  svc.startWebhookServer();
  while (true) { std::this_thread::sleep_for(std::chrono::seconds(60)); }
  return 0;
}
