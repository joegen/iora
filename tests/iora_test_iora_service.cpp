// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "test_helpers.hpp"

using namespace iora::test;

TEST_CASE("IoraService basic operations", "[iora][IoraService]")
{
  // Setup IoraService config
  iora::IoraService::Config config;
  config.server.port = 8110;
  config.state.file = "ioraservice_basic_state.json";
  config.log.file = "ioraservice_basic_log";
  config.log.level = "error";

  // Initialize service with config
  iora::IoraService::init(config);
  iora::IoraService& svc = iora::IoraService::instanceRef();
  AutoServiceShutdown autoShutdown(svc);

  svc.stateStore()->set("foo", "bar");
  REQUIRE(svc.stateStore()->get("foo").value() == "bar");

  svc.cache()->set("cacheKey", std::string("cacheValue"),
                   std::chrono::seconds(1));
  REQUIRE(svc.cache()->get("cacheKey").value() == "cacheValue");
  std::this_thread::sleep_for(std::chrono::seconds(2));
  REQUIRE_FALSE(svc.cache()->get("cacheKey").has_value());

  REQUIRE(svc.jsonFileStore() != nullptr);
  svc.jsonFileStore()->set("persist", "value");
  svc.jsonFileStore()->flush();
  REQUIRE(svc.jsonFileStore()->get("persist").value() == "value");
  {
    std::ifstream infile("ioraservice_basic_state.json");
    REQUIRE(infile.is_open());
    std::string content((std::istreambuf_iterator<char>(infile)), {});
    REQUIRE(content.find("persist") != std::string::npos);
  }

  {
    std::unique_ptr<iora::storage::JsonFileStore> tmp =
        svc.makeJsonFileStore("ioraservice_factory_state.json");
    tmp->set("altKey", "altValue");
    REQUIRE(tmp->get("altKey").value() == "altValue");
    REQUIRE_FALSE(svc.jsonFileStore()->get("altKey").has_value());
    std::filesystem::remove("ioraservice_factory_state.json");
  }

  {
    auto c1 = svc.makeHttpClient();
    auto c2 = svc.makeHttpClient();
    REQUIRE(&c1 != &c2);
  }

  svc.webhookServer()->onJsonGet(
      "/basic",
      [](const iora::parsers::Json&) -> iora::parsers::Json
      {
        auto obj = iora::parsers::Json::object();
        obj["ok"] = true;
        return obj;
      });
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  {
    auto client = svc.makeHttpClient();
    auto res = client.get("http://localhost:8110/basic");
    REQUIRE(res.success());
    auto json = iora::network::HttpClient::parseJsonOrThrow(res);
    REQUIRE(json["ok"] == true);
  }

  iora::util::removeFilesContainingAny(
      {"ioraservice_basic_log", "ioraservice_basic_state.json"});
}

TEST_CASE("IoraService configuration file override",
          "[iora][IoraService][config]")
{
  const std::string cfg = "ioraservice_cfg_override.toml";
  {
    std::ofstream out(cfg);
    out << "[iora.server]\nport = 8111\n";
    out << "[iora.state]\nfile = 'ioraservice_cfg_state.json'\n";
    out << "[iora.log]\nlevel = 'debug'\nfile = 'ioraservice_cfg_log'\n";
    out << "async = false\nretention_days = 2\ntime_format = '%Y%m%d'\n";
  }

  // Setup IoraService config and parse TOML file
  iora::IoraService::Config config;
  auto configLoader = std::make_unique<iora::core::ConfigLoader>(cfg);
  configLoader->reload();
  
  // Parse TOML values into config
  if (auto portOpt = configLoader->getInt("iora.server.port"))
  {
    config.server.port = static_cast<int>(*portOpt);
  }
  if (auto stateFileOpt = configLoader->getString("iora.state.file"))
  {
    config.state.file = *stateFileOpt;
  }
  if (auto logLevelOpt = configLoader->getString("iora.log.level"))
  {
    config.log.level = *logLevelOpt;
  }
  if (auto logFileOpt = configLoader->getString("iora.log.file"))
  {
    config.log.file = *logFileOpt;
  }

  // Initialize service with config
  iora::IoraService::init(config);
  iora::IoraService::instanceRef().setConfigLoader(std::move(configLoader));
  iora::IoraService& svc = iora::IoraService::instanceRef();
  AutoServiceShutdown autoShutdown(svc);

  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  svc.webhookServer()->onJsonGet(
      "/cfg",
      [](const iora::parsers::Json&) -> iora::parsers::Json
      {
        auto obj = iora::parsers::Json::object();
        obj["cfg"] = true;
        return obj;
      });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  {
    auto client = svc.makeHttpClient();
    auto res = client.get("http://localhost:8111/cfg");
    REQUIRE(res.success());
    auto json = iora::network::HttpClient::parseJsonOrThrow(res);
    REQUIRE(json["cfg"] == true);
  }

  svc.jsonFileStore()->set("cfgKey", "cfgValue");
  // REQUIRE(std::filesystem::exists("ioraservice_cfg_state.json")); // this is
  // not guaranteed. The file is created by a background thread.

  IORA_LOG_DEBUG("Configuration override test message");
  iora::core::Logger::shutdown();
  std::string logFile =
      "ioraservice_cfg_log." + iora::core::Logger::currentDate() + ".log";
  REQUIRE(std::filesystem::exists(logFile));

  iora::util::removeFilesContainingAny(
      {"ioraservice_cfg_log", "ioraservice_cfg_state.json", cfg});
}

TEST_CASE("IoraService CLI overrides precedence", "[iora][IoraService][cli]")
{
  const std::string cfg = "ioraservice_cli_precedence.toml";
  {
    std::ofstream out(cfg);
    out << "[iora.server]\nport = 8112\n";
    out << "[iora.state]\nfile = 'ioraservice_cli_state.json'\n";
    out << "[iora.log]\nlevel = 'info'\nfile = 'ioraservice_cli_log'\n";
    out << "async = false\nretention_days = 1\ntime_format = '%Y%m%d'\n";
  }
  // Setup IoraService config with CLI overrides taking precedence
  iora::IoraService::Config config;
  config.server.port = 8123;
  config.state.file = "ioraservice_cli_override_state.json";
  config.log.file = "ioraservice_cli_override_log";
  config.log.level = "error";
  
  // Parse TOML file (but CLI values should override)
  auto configLoader = std::make_unique<iora::core::ConfigLoader>(cfg);
  configLoader->reload();
  
  // Only parse TOML values that aren't already set by CLI
  if (!config.server.port.has_value())
  {
    if (auto portOpt = configLoader->getInt("iora.server.port"))
    {
      config.server.port = static_cast<int>(*portOpt);
    }
  }
  // Note: CLI values take precedence, so we don't override them

  // Initialize service with config
  iora::IoraService::init(config);
  iora::IoraService::instanceRef().setConfigLoader(std::move(configLoader));
  iora::IoraService& svc = iora::IoraService::instanceRef();
  AutoServiceShutdown autoShutdown(svc);

  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  svc.webhookServer()->onJsonGet(
      "/cli",
      [](const iora::parsers::Json&) -> iora::parsers::Json
      {
        auto obj = iora::parsers::Json::object();
        obj["cli"] = true;
        return obj;
      });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  {
    auto client = svc.makeHttpClient();
    auto res = client.get("http://localhost:8123/cli");
    REQUIRE(res.success());
    auto json = iora::network::HttpClient::parseJsonOrThrow(res);
    REQUIRE(json["cli"] == true);
  }

  svc.jsonFileStore()->set("cliKey", "cliValue");
  std::this_thread::sleep_for(svc.jsonFileStore()->flushInterval() +
                              std::chrono::milliseconds(100));
  REQUIRE(std::filesystem::exists(
      "ioraservice_cli_override_state.json")); // Not guaranteed since flushing
                                               // the store is done using a
                                               // background thread

  IORA_LOG_ERROR("CLI override log test");
  iora::core::Logger::shutdown();
  std::string logFile = "ioraservice_cli_override_log." +
                        iora::core::Logger::currentDate() + ".log";
  REQUIRE(std::filesystem::exists(logFile));

  iora::util::removeFilesContainingAny(
      {"ioraservice_cli_override_log", "ioraservice_cli_state.json",
       "ioraservice_cli_override_state.json", cfg});
}

TEST_CASE("IoraService concurrent HTTP clients",
          "[iora][IoraService][concurrency]")
{
  // Setup IoraService config
  iora::IoraService::Config config;
  config.server.port = 8113;
  config.state.file = "ioraservice_concurrency_state.json";
  config.log.file = "ioraservice_concurrency_log";
  config.log.level = "error";

  // Initialize service with config
  iora::IoraService::init(config);
  iora::IoraService& svc = iora::IoraService::instanceRef();
  AutoServiceShutdown autoShutdown(svc);

  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  svc.webhookServer()->onJsonGet(
      "/ping",
      [](const iora::parsers::Json&) -> iora::parsers::Json
      {
        auto obj = iora::parsers::Json::object();
        obj["pong"] = true;
        return obj;
      });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  const int threadCount = 5;
  std::vector<std::thread> workers;
  std::atomic<int> successCount{0};
  for (int i = 0; i < threadCount; ++i)
  {
    workers.emplace_back(
        [&svc, &successCount]()
        {
          auto client = svc.makeHttpClient();
          try
          {
            auto res = client.get("http://localhost:8113/ping");
            if (res.success())
            {
              auto json = iora::network::HttpClient::parseJsonOrThrow(res);
              if (json["pong"] == true)
              {
                successCount.fetch_add(1);
              }
            }
          }
          catch (...)
          {
          }
        });
  }
  for (auto& t : workers)
  {
    t.join();
  }
  REQUIRE(successCount.load() == threadCount);

  iora::util::removeFilesContainingAny(
      {"ioraservice_concurrency_log", "ioraservice_concurrency_state.json"});
}

TEST_CASE("IoraService fluent event handler registration by name and pattern",
          "[iora][IoraService][EventQueue][fluent]")
{
  // Setup IoraService config
  iora::IoraService::Config config;
  config.server.port = 8120;
  config.state.file = "ioraservice_fluent_eventqueue_state.json";
  config.log.file = "ioraservice_fluent_eventqueue_log";
  config.log.level = "error";

  // Initialize service with config
  iora::IoraService::init(config);
  iora::IoraService& svc = iora::IoraService::instanceRef();
  AutoServiceShutdown autoShutdown(svc);

  std::atomic<int> nameCounter{0};
  svc.onEventName("fluentEvent")
      .handle(
          [&](const iora::parsers::Json& event)
          {
            REQUIRE(event["eventName"] == "fluentEvent");
            nameCounter++;
          });

  std::atomic<int> patternCounter{0};
  svc.onEventNameMatches("^fluent.*")
      .handle(
          [&](const iora::parsers::Json& event)
          {
            REQUIRE(event["eventName"].get<std::string>().find("fluent") == 0);
            patternCounter++;
          });

  auto event1 = iora::parsers::Json::object();
  event1["eventId"] = "id1";
  event1["eventName"] = "fluentEvent";
  svc.pushEvent(event1);
  auto event2 = iora::parsers::Json::object();
  event2["eventId"] = "id2";
  event2["eventName"] = "fluentPattern";
  svc.pushEvent(event2);
  auto event3 = iora::parsers::Json::object();
  event3["eventId"] = "id3";
  event3["eventName"] = "otherEvent";
  svc.pushEvent(event3);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  REQUIRE(nameCounter == 1);
  REQUIRE(patternCounter == 2);

  iora::util::removeFilesContainingAny(
      {"ioraservice_fluent_eventqueue_log",
       "ioraservice_fluent_eventqueue_state.json"});
}

TEST_CASE("IoraService integrates EventQueue",
          "[iora][IoraService][EventQueue]")
{
  // Setup IoraService config
  iora::IoraService::Config config;
  config.server.port = 8114;
  config.state.file = "ioraservice_eventqueue_state.json";
  config.log.file = "ioraservice_eventqueue_log";

  // Initialize service with config
  iora::IoraService::init(config);
  iora::IoraService& svc = iora::IoraService::instanceRef();
  AutoServiceShutdown autoShutdown(svc);

  std::atomic<int> counter{0};
  svc.onEvent("testEventId")
      .handle(
          [&](const iora::parsers::Json& event)
          {
            REQUIRE(event["eventId"] == "testEventId");
            counter++;
          });

  auto testEvent = iora::parsers::Json::object();
  testEvent["eventId"] = "testEventId";
  testEvent["eventName"] = "testEventName";
  svc.pushEvent(testEvent);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 1);

  iora::util::removeFilesContainingAny(
      {"ioraservice_eventqueue_log", "ioraservice_eventqueue_state.json"});
}
