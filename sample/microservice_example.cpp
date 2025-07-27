#include "iora/iora.hpp"

#include <iostream>
#include <string>

/// \brief Entry point for the microservice example
int main()
{
  // Initialize Logger
  iora::log::Logger::info("Starting microservice...");

  // Load configuration
  iora::config::ConfigLoader configLoader("config.toml");
  auto config = configLoader.load();
  iora::log::Logger::info("Configuration loaded.");

  // Extract port from configuration
  int port = static_cast<int>(config["server"]["port"].as_integer()->get());

  // Initialize StateStore
  iora::state::ConcreteStateStore stateStore;
  stateStore.set("key", "value");
  iora::log::Logger::info("StateStore initialized.");

  // Initialize ExpiringCache
  iora::util::ExpiringCache<std::string, std::string> cache(
      std::chrono::seconds(60));
  cache.set("cacheKey", "cacheValue");
  iora::log::Logger::info("Cache initialized.");

  // Start WebhookServer
  iora::http::WebhookServer server(port);
  server.on("/webhook",
            [](const httplib::Request& req, httplib::Response& res)
            {
              iora::log::Logger::info("Received webhook: " + req.body);
              res.set_content("Webhook received", "text/plain");
            });
  server.start();
  iora::log::Logger::info("WebhookServer started on port " +
                          std::to_string(port) + ".");
}
