#include "iora/iora.hpp"
#include "catch2/catch_test_macros.hpp"
#include <fstream>

TEST_CASE("IoraService basic operations", "[iora][IoraService]")
{
  const char* args[] = {"program",
                        "--port",
                        "8110",
                        "--state-file",
                        "ioraservice_basic_state.json",
                        "--log-file",
                        "ioraservice_basic_log"};
  int argc = static_cast<int>(sizeof(args) / sizeof(args[0]));
  iora::IoraService& svc =
      iora::IoraService::init(argc, const_cast<char**>(args));
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

  svc.webhookServer()->onJsonGet("/basic",
                                 [](const iora::core::Json&) -> iora::core::Json
                                 {
                                   return {{"ok", true}};
                                 });
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  {
    auto client = svc.makeHttpClient();
    auto res = client.get("http://localhost:8110/basic");
    REQUIRE(res["ok"] == true);
  }

  removeFilesContainingAny(
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

  const char* args[] = {"program", "--config", cfg.c_str()};
  int argc = static_cast<int>(sizeof(args) / sizeof(args[0]));
  iora::IoraService& svc =
      iora::IoraService::init(argc, const_cast<char**>(args));
  AutoServiceShutdown autoShutdown(svc);

  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  svc.webhookServer()->onJsonGet("/cfg",
                                 [](const iora::core::Json&) -> iora::core::Json
                                 {
                                   return {{"cfg", true}};
                                 });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  {
    auto client = svc.makeHttpClient();
    auto res = client.get("http://localhost:8111/cfg");
    REQUIRE(res["cfg"] == true);
  }

  svc.jsonFileStore()->set("cfgKey", "cfgValue");
  REQUIRE(std::filesystem::exists("ioraservice_cfg_state.json"));

  LOG_DEBUG("Configuration override test message");
  iora::core::Logger::shutdown();
  std::string logFile =
      "ioraservice_cfg_log." + iora::core::Logger::currentDate() + ".log";
  REQUIRE(std::filesystem::exists(logFile));

  removeFilesContainingAny(
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
  const char* args[] = {"program",
                        "--port",
                        "8123",
                        "--state-file",
                        "ioraservice_cli_override_state.json",
                        "--config",
                        cfg.c_str(),
                        "--log-file",
                        "ioraservice_cli_override_log",
                        "--log-level",
                        "error"};
  int argc = static_cast<int>(sizeof(args) / sizeof(args[0]));
  iora::IoraService& svc =
      iora::IoraService::init(argc, const_cast<char**>(args));
  AutoServiceShutdown autoShutdown(svc);

  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  svc.webhookServer()->onJsonGet("/cli",
                                 [](const iora::core::Json&) -> iora::core::Json
                                 {
                                   return {{"cli", true}};
                                 });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  {
    auto client = svc.makeHttpClient();
    auto res = client.get("http://localhost:8123/cli");
    REQUIRE(res["cli"] == true);
  }

  svc.jsonFileStore()->set("cliKey", "cliValue");
  std::this_thread::sleep_for(svc.jsonFileStore()->flushInterval() + std::chrono::milliseconds(100));
  REQUIRE(std::filesystem::exists("ioraservice_cli_override_state.json")); // Not guaranteed since flushing the store is done using a background thread

  LOG_ERROR("CLI override log test");
  iora::core::Logger::shutdown();
  std::string logFile = "ioraservice_cli_override_log." +
                        iora::core::Logger::currentDate() + ".log";
  REQUIRE(std::filesystem::exists(logFile));

  removeFilesContainingAny({"ioraservice_cli_override_log",
                            "ioraservice_cli_state.json",
                            "ioraservice_cli_override_state.json", cfg});
}

TEST_CASE("IoraService concurrent HTTP clients",
          "[iora][IoraService][concurrency]")
{
  const char* args[] = {"program",
                        "--port",
                        "8113",
                        "--state-file",
                        "ioraservice_concurrency_state.json",
                        "--log-file",
                        "ioraservice_concurrency_log"};
  int argc = static_cast<int>(sizeof(args) / sizeof(args[0]));
  iora::IoraService& svc =
      iora::IoraService::init(argc, const_cast<char**>(args));
  AutoServiceShutdown autoShutdown(svc);

  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  svc.webhookServer()->onJsonGet("/ping",
                                 [](const iora::core::Json&) -> iora::core::Json
                                 {
                                   return {{"pong", true}};
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
            if (res["pong"] == true)
            {
              successCount.fetch_add(1);
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

  removeFilesContainingAny(
      {"ioraservice_concurrency_log", "ioraservice_concurrency_state.json"});
}

TEST_CASE("IoraService fluent event handler registration by name and pattern",
          "[iora][IoraService][EventQueue][fluent]")
{
  const char* args[] = {"program",
                        "--port",
                        "8120",
                        "--state-file",
                        "ioraservice_fluent_eventqueue_state.json",
                        "--log-file",
                        "ioraservice_fluent_eventqueue_log"};
  int argc = static_cast<int>(sizeof(args) / sizeof(args[0]));
  iora::IoraService& svc =
      iora::IoraService::init(argc, const_cast<char**>(args));
  AutoServiceShutdown autoShutdown(svc);

  std::atomic<int> nameCounter{0};
  svc.onEventName("fluentEvent")
      .handle(
          [&](const iora::core::Json& event)
          {
            REQUIRE(event["eventName"] == "fluentEvent");
            nameCounter++;
          });

  std::atomic<int> patternCounter{0};
  svc.onEventNameMatches("^fluent.*")
      .handle(
          [&](const iora::core::Json& event)
          {
            REQUIRE(event["eventName"].get<std::string>().find("fluent") == 0);
            patternCounter++;
          });

  svc.pushEvent({{"eventId", "id1"}, {"eventName", "fluentEvent"}});
  svc.pushEvent({{"eventId", "id2"}, {"eventName", "fluentPattern"}});
  svc.pushEvent({{"eventId", "id3"}, {"eventName", "otherEvent"}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  REQUIRE(nameCounter == 1);
  REQUIRE(patternCounter == 2);

  removeFilesContainingAny({"ioraservice_fluent_eventqueue_log",
                            "ioraservice_fluent_eventqueue_state.json"});
}

TEST_CASE("IoraService integrates EventQueue",
          "[iora][IoraService][EventQueue]")
{
  const char* args[] = {"program",
                        "--port",
                        "8114",
                        "--state-file",
                        "ioraservice_eventqueue_state.json",
                        "--log-file",
                        "ioraservice_eventqueue_log"};
  int argc = static_cast<int>(sizeof(args) / sizeof(args[0]));
  iora::IoraService& svc =
      iora::IoraService::init(argc, const_cast<char**>(args));
  AutoServiceShutdown autoShutdown(svc);

  std::atomic<int> counter{0};
  svc.onEvent("testEventId")
      .handle(
          [&](const iora::core::Json& event)
          {
            REQUIRE(event["eventId"] == "testEventId");
            counter++;
          });

  svc.pushEvent({{"eventId", "testEventId"}, {"eventName", "testEventName"}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 1);

  removeFilesContainingAny(
      {"ioraservice_eventqueue_log", "ioraservice_eventqueue_state.json"});
}
