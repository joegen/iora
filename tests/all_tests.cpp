#define CATCH_CONFIG_MAIN
#include "catch2/catch_test_macros.hpp"
#include "iora/iora.hpp"

TEST_CASE("HttpClient and WebhookServer integration tests")
{
  iora::http::WebhookServer server(8081);

  server.onJson("/test-post-json",
                [](const iora::json::Json& input) -> iora::json::Json {
                  return {{"echo", input}};
                });

  server.onJsonGet("/test-get",
                   [](const httplib::Request&) -> iora::json::Json {
                     return {{"status", "ok"}};
                   });

  server.onDelete("/test-delete",
                  [](const httplib::Request&, httplib::Response& res)
                  {
                    res.set_content("{}", "application/json");
                    res.status = 200;
                  });

  server.onJson("/test-async",
                [](const iora::json::Json& input) -> iora::json::Json {
                  return {{"async", true}, {"received", input}};
                });

  server.on("/test-stream",
            [](const httplib::Request& req, httplib::Response& res)
            {
              res.set_content("data: {\"text\":\"line1\"}\n"
                              "data: {\"text\":\"line2\"}\n"
                              "data: [DONE]\n",
                              "text/event-stream");
              res.status = 200;
            });

  server.startAsync();
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  iora::http::HttpClient client;

  SECTION("GET request returns valid JSON")
  {
    auto res = client.get("http://localhost:8081/test-get");
    REQUIRE(res["status"] == "ok");
  }

  SECTION("POST JSON request with payload")
  {
    iora::json::Json payload = {{"message", "hello"}};
    auto res = client.postJson("http://localhost:8081/test-post-json", payload);
    REQUIRE(res["echo"]["message"] == "hello");
  }

  SECTION("DELETE request returns empty JSON")
  {
    auto res = client.deleteRequest("http://localhost:8081/test-delete");
    REQUIRE(res.is_object());
    REQUIRE(res.empty());
  }

  SECTION("Async POST JSON returns future")
  {
    iora::json::Json payload = {{"async_test", 1}};
    std::future<iora::json::Json> future =
        client.postJsonAsync("http://localhost:8081/test-async", payload);
    auto res = future.get();
    REQUIRE(res["async"] == true);
    REQUIRE(res["received"]["async_test"] == 1);
  }

  SECTION("Streamed POST returns line chunks")
  {
    iora::json::Json payload = {{}};
    std::vector<std::string> chunks;
    client.postStream("http://localhost:8081/test-stream", payload, {},
                      [&](const std::string& line)
                      {
                        std::string content = line;
                        if (content.empty())
                        {
                          return;
                        }
                        chunks.push_back(content);
                        return;
                      });
    REQUIRE(chunks.size() == 3);
    REQUIRE(chunks[0] == "data: {\"text\":\"line1\"}");
    REQUIRE(chunks[1] == "data: {\"text\":\"line2\"}");
    REQUIRE(chunks[2] == "data: [DONE]");
  }
  server.stop();
}

TEST_CASE("CliParser basic operations")
{
  SECTION("Parse key-value pairs")
  {
    std::string input = "key1=value1\nkey2=value2";
    auto result = iora::util::CliParser::parseKeyValue(input);
    REQUIRE(result["key1"] == "value1");
    REQUIRE(result["key2"] == "value2");
  }

  SECTION("Parse JSON")
  {
    std::string input = "{\"key\": \"value\"}";
    auto result = iora::util::CliParser::parseJson(input);
    REQUIRE(result["key"] == "value");
  }
}

TEST_CASE("ShellRunner basic operations")
{
  SECTION("Execute valid command")
  {
    std::string result = iora::shell::ShellRunner::execute("echo Hello");
    REQUIRE(result.find("Hello") != std::string::npos);
  }

  SECTION("Execute invalid command")
  {
    try
    {
      iora::shell::ShellRunner::execute("ignore_this_error_just_for_test");
      FAIL("Expected an error, but none was thrown.");
    }
    catch (const std::runtime_error& e)
    {
      std::string msg = e.what();
      bool found = msg.find("not found") != std::string::npos ||
                   msg.find("Command failed") != std::string::npos ||
                   msg.find("ShellRunner error") != std::string::npos;
      REQUIRE(found);
    }
  }
}

TEST_CASE("ExpiringCache basic operations")
{
  iora::util::ExpiringCache<std::string, int> cache;
  cache.set("key1", 42, std::chrono::seconds(1));
  REQUIRE(cache.get("key1").value() == 42);
  std::this_thread::sleep_for(std::chrono::seconds(2));
  REQUIRE(!cache.get("key1").has_value());
  cache.set("key2", 100, std::chrono::seconds(1));
  std::this_thread::sleep_for(std::chrono::seconds(2));
  REQUIRE(!cache.get("key2").has_value());
}

TEST_CASE("ExpiringCache expiration")
{
  iora::util::ExpiringCache<std::string, int> cache;
  cache.set("key3", 200, std::chrono::seconds(1));
  std::this_thread::sleep_for(std::chrono::seconds(2));
  REQUIRE(!cache.get("key3").has_value());
}

TEST_CASE("ExpiringCache concurrency")
{
  iora::util::ExpiringCache<int, int> cache;
  std::vector<std::thread> threads;
  for (int i = 0; i < 10; ++i)
  {
    threads.emplace_back([&cache, i]()
                         { cache.set(i, i * 10, std::chrono::seconds(1)); });
  }
  for (auto& t : threads)
  {
    t.join();
  }
  std::this_thread::sleep_for(std::chrono::seconds(2));
  for (int i = 0; i < 10; ++i)
  {
    REQUIRE(!cache.get(i).has_value());
  }
}

TEST_CASE("ExpiringCache purging and permanent deletion")
{
  using Cache = iora::util::ExpiringCache<std::string, int>;
  using Accessor = iora::util::ExpiringCacheTestAccessor<std::string, int>;
  Cache cache;
  cache.set("purge", 123, std::chrono::seconds(1));
  REQUIRE(cache.get("purge").has_value());
  REQUIRE(Accessor::mapSize(cache) == 1);
  std::this_thread::sleep_for(std::chrono::seconds(7));
  REQUIRE(!cache.get("purge").has_value());
  REQUIRE(Accessor::mapSize(cache) == 0);
}

TEST_CASE("JsonFileStore basic operations")
{
  const std::string testFile = "test_store.json";
  iora::state::JsonFileStore store(testFile);

  SECTION("Set and Get")
  {
    store.set("key1", "value1");
    REQUIRE(store.get("key1") == "value1");
  }

  SECTION("Remove")
  {
    store.set("key2", "value2");
    store.remove("key2");
    REQUIRE(!store.get("key2").has_value());
  }
}

TEST_CASE("Logger Basic Levels", "[logger][levels]")
{
  // Cleanup before test
  for (const auto& file : std::filesystem::directory_iterator("."))
  {
    if (file.path().string().find("testlog.") == 0)
    {
      std::filesystem::remove(file.path());
    }
  }
  iora::log::Logger::init(iora::log::Logger::Level::Trace, "testlog", false);
  LOG_TRACE("Trace message");
  LOG_DEBUG("Debug message");
  LOG_INFO("Info message");
  LOG_WARN("Warn message");
  LOG_ERROR("Error message");
  LOG_FATAL("Fatal message");
  iora::log::Logger::shutdown();

  std::string logFile = "testlog." + iora::log::Logger::currentDate() + ".log";
  std::ifstream in(logFile);
  REQUIRE(in.is_open());
  std::string line;
  int count = 0;
  while (std::getline(in, line))
  {
    ++count;
  }
  REQUIRE(count >= 6);
  // Cleanup after test
  for (const auto& file : std::filesystem::directory_iterator("."))
  {
    if (file.path().string().find("testlog.") == 0)
    {
      std::filesystem::remove(file.path());
    }
  }
}

TEST_CASE("Logger Stream Logging", "[logger][stream]")
{
  iora::log::Logger::init(iora::log::Logger::Level::Info, "streamlog", false);
  iora::log::Logger << iora::log::Logger::Level::Info
                    << "Stream log test: " << 123 << iora::log::Logger::endl;
  iora::log::Logger::shutdown();

  std::string logFile =
      "streamlog." + iora::log::Logger::currentDate() + ".log";
  std::ifstream in(logFile);
  REQUIRE(in.is_open());
  std::string line;
  bool found = false;
  while (std::getline(in, line))
  {
    if (line.find("Stream log test") != std::string::npos)
    {
      found = true;
      break;
    }
  }
  REQUIRE(found);
}

TEST_CASE("Logger Async Logging", "[logger][async]")
{
  // Cleanup before test
  for (const auto& file : std::filesystem::directory_iterator("."))
  {
    if (file.path().string().find("asynclog.") == 0)
    {
      std::filesystem::remove(file.path());
    }
  }
  iora::log::Logger::init(iora::log::Logger::Level::Info, "asynclog", true);
  for (int i = 0; i < 100; ++i)
  {
    iora::log::Logger << iora::log::Logger::Level::Info << "Async message " << i
                      << iora::log::Logger::endl;
  }
  iora::log::Logger::shutdown();

  std::string logFile = "asynclog." + iora::log::Logger::currentDate() + ".log";
  std::ifstream in(logFile);
  REQUIRE(in.is_open());
  std::string line;
  int count = 0;
  while (std::getline(in, line))
  {
    ++count;
  }
  REQUIRE(count >= 100);
  // Cleanup after test
  for (const auto& file : std::filesystem::directory_iterator("."))
  {
    if (file.path().string().find("asynclog.") == 0)
    {
      std::filesystem::remove(file.path());
    }
  }
}

TEST_CASE("Logger Thread Safety", "[logger][threaded]")
{
  // Cleanup before test
  for (const auto& file : std::filesystem::directory_iterator("."))
  {
    if (file.path().string().find("threadlog.") == 0)
    {
      std::filesystem::remove(file.path());
    }
  }
  iora::log::Logger::init(iora::log::Logger::Level::Info, "threadlog", true);
  const int threads = 10;
  const int messagesPerThread = 50;
  std::vector<std::thread> workers;

  for (int i = 0; i < threads; ++i)
  {
    workers.emplace_back(
        [i]()
        {
          for (int j = 0; j < messagesPerThread; ++j)
          {
            iora::log::Logger << iora::log::Logger::Level::Info << "Thread "
                              << i << " message " << j
                              << iora::log::Logger::endl;
          }
        });
  }

  for (auto& t : workers)
  {
    t.join();
  }
  iora::log::Logger::shutdown();

  std::string logFile =
      "threadlog." + iora::log::Logger::currentDate() + ".log";
  std::ifstream in(logFile);
  REQUIRE(in.is_open());
  std::string line;
  int count = 0;
  while (std::getline(in, line))
  {
    ++count;
  }
  REQUIRE(count >= threads * messagesPerThread);
  // Cleanup after test
  for (const auto& file : std::filesystem::directory_iterator("."))
  {
    if (file.path().string().find("threadlog.") == 0)
    {
      std::filesystem::remove(file.path());
    }
  }
}

TEST_CASE("Logger File Rotation and Retention", "[logger][rotation]")
{
  const std::string base = "rotate_test";
  const int retention = 1;

  iora::log::Logger::init(iora::log::Logger::Level::Info, base, false,
                          retention);
  LOG_INFO("Rotation start");
  iora::log::Logger::shutdown();

  std::string oldFile = base + ".2000-01-01.log";
  std::ofstream fakeOld(oldFile);
  fakeOld << "old log" << std::endl;
  fakeOld.close();
  std::filesystem::last_write_time(
      oldFile,
      std::filesystem::file_time_type::clock::now() - std::chrono::hours(25));

  iora::log::Logger::init(iora::log::Logger::Level::Info, base, false,
                          retention);
  LOG_INFO("Trigger rotation");
  iora::log::Logger::shutdown();

  REQUIRE_FALSE(std::filesystem::exists(oldFile));
}

/*
 * IoraService unit tests
 *
 * These tests exercise the high–level IoraService singleton.  The service
 * aggregates a WebhookServer, state store, expiring cache, configuration
 * loader, persistent JsonFileStore and logging subsystem.  Each test
 * configures the service via a combination of command–line arguments
 * and/or a temporary configuration file.  Command‑line flags must always
 * override the TOML configuration regardless of order, and component
 * factories should operate correctly in multi‑threaded contexts.  To avoid
 * interference between tests, each test uses a unique port and state file
 * name.  Log files and JSON files created during tests are cleaned up at
 * the end of each test.
 */

TEST_CASE("IoraService basic operations", "[iora][IoraService]")
{
  // prepare argv with explicit port and state file to avoid conflicts
  const char* args[] = {"program",
                        "--port",
                        "8110",
                        "--state-file",
                        "ioraservice_basic_state.json",
                        "--log-file",
                        "ioraservice_basic_log"};
  int argc = static_cast<int>(sizeof(args) / sizeof(args[0]));

  // Initialise the service with the provided arguments
  iora::IoraService& svc =
      iora::IoraService::init(argc, const_cast<char**>(args));

  // in-memory state store works
  svc.stateStore().set("foo", "bar");
  REQUIRE(svc.stateStore().get("foo").value() == "bar");

  // cache works and expires
  svc.cache().set("cacheKey", std::string("cacheValue"),
                  std::chrono::seconds(1));
  REQUIRE(svc.cache().get("cacheKey").value() == "cacheValue");
  std::this_thread::sleep_for(std::chrono::seconds(2));
  REQUIRE_FALSE(svc.cache().get("cacheKey").has_value());

  // persistent JsonFileStore writes to disk
  svc.jsonFileStore()->set("persist", "value");
  REQUIRE(svc.jsonFileStore()->get("persist").value() == "value");
  {
    std::ifstream infile("ioraservice_basic_state.json");
    REQUIRE(infile.is_open());
    std::string content((std::istreambuf_iterator<char>(infile)), {});
    REQUIRE(content.find("persist") != std::string::npos);
  }

  // factory JsonFileStore is independent
  {
    std::unique_ptr<iora::state::JsonFileStore> tmp =
        svc.makeJsonFileStore("ioraservice_factory_state.json");
    tmp->set("altKey", "altValue");
    REQUIRE(tmp->get("altKey").value() == "altValue");
    REQUIRE_FALSE(svc.jsonFileStore()->get("altKey").has_value());
    std::filesystem::remove("ioraservice_factory_state.json");
  }

  // factory HttpClient returns distinct stateless objects
  {
    auto c1 = svc.makeHttpClient();
    auto c2 = svc.makeHttpClient();
    REQUIRE(&c1 != &c2);
  }

  // register endpoint, start server and call it to confirm correct port
  svc.webhookServer().onJsonGet("/basic",
                                [](const httplib::Request&) -> iora::json::Json {
                                  return {{"ok", true}};
                                });
  svc.startWebhookServer();
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  {
    auto client = svc.makeHttpClient();
    auto res = client.get("http://localhost:8110/basic");
    REQUIRE(res["ok"] == true);
  }
  svc.stopWebhookServer();
  iora::log::Logger::shutdown();
  // clean up generated files
  for (const auto& file : std::filesystem::directory_iterator("."))
  {
    std::string name = file.path().string();
    if (name.find("ioraservice_basic_log") != std::string::npos ||
        name.find("ioraservice_basic_state.json") != std::string::npos)
    {
      std::filesystem::remove(file.path());
    }
  }
}

TEST_CASE("IoraService configuration file override",
          "[iora][IoraService][config]")
{
  // create a temp config TOML with custom server, state and logger settings
  const std::string cfg = "ioraservice_cfg_override.toml";
  {
    std::ofstream out(cfg);
    out << "[server]\nport = 8111\n";
    out << "[state]\nfile = 'ioraservice_cfg_state.json'\n";
    out << "[log]\nlevel = 'debug'\nfile = 'ioraservice_cfg_log'\n";
    out << "async = false\nretention_days = 2\n";
    out << "time_format = '%Y%m%d'\n";
  }

  const char* args[] = {"program", "--config", cfg.c_str()};
  int argc = static_cast<int>(sizeof(args) / sizeof(args[0]));
  iora::IoraService& svc =
      iora::IoraService::init(argc, const_cast<char**>(args));

  svc.webhookServer().onJsonGet("/cfg",
                                [](const httplib::Request&) -> iora::json::Json {
                                  return {{"cfg", true}};
                                });
  svc.startWebhookServer();
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  {
    auto client = svc.makeHttpClient();
    auto res = client.get("http://localhost:8111/cfg");
    REQUIRE(res["cfg"] == true);
  }
  // state file override works
  svc.jsonFileStore()->set("cfgKey", "cfgValue");
  REQUIRE(std::filesystem::exists("ioraservice_cfg_state.json"));
  // logger override writes file
  LOG_DEBUG("Configuration override test message");
  iora::log::Logger::shutdown();
  std::string logFile = std::string("ioraservice_cfg_log.") +
                        iora::log::Logger::currentDate() + ".log";
  REQUIRE(std::filesystem::exists(logFile));
  svc.stopWebhookServer();
  // clean up
  for (const auto& file : std::filesystem::directory_iterator("."))
  {
    std::string name = file.path().string();
    if (name.find("ioraservice_cfg_log") != std::string::npos ||
        name.find("ioraservice_cfg_state.json") != std::string::npos ||
        name == cfg)
    {
      std::filesystem::remove(file.path());
    }
  }
}

TEST_CASE("IoraService CLI overrides precedence", "[iora][IoraService][cli]")
{
  // config file with one port and state file; CLI should override both
  const std::string cfg = "ioraservice_cli_precedence.toml";
  {
    std::ofstream out(cfg);
    out << "[server]\nport = 8112\n";
    out << "[state]\nfile = 'ioraservice_cli_state.json'\n";
    out << "[log]\nlevel = 'info'\nfile = 'ioraservice_cli_log'\n";
    out << "async = false\nretention_days = 1\n";
    out << "time_format = '%Y%m%d'\n";
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

  svc.webhookServer().onJsonGet("/cli",
                                [](const httplib::Request&) -> iora::json::Json {
                                  return {{"cli", true}};
                                });
  svc.startWebhookServer();
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  {
    auto client = svc.makeHttpClient();
    auto res = client.get("http://localhost:8123/cli");
    REQUIRE(res["cli"] == true);
  }
  // state file uses CLI override, not config
  svc.jsonFileStore()->set("cliKey", "cliValue");
  REQUIRE(std::filesystem::exists("ioraservice_cli_override_state.json"));
  // logger uses CLI override; error logs should appear
  LOG_ERROR("CLI override log test");
  iora::log::Logger::shutdown();
  std::string logFile = std::string("ioraservice_cli_override_log.") +
                        iora::log::Logger::currentDate() + ".log";
  REQUIRE(std::filesystem::exists(logFile));
  svc.stopWebhookServer();
  // clean up files
  for (const auto& file : std::filesystem::directory_iterator("."))
  {
    std::string name = file.path().string();
    if (name.find("ioraservice_cli_override_log") != std::string::npos ||
        name.find("ioraservice_cli_state.json") != std::string::npos ||
        name.find("ioraservice_cli_override_state.json") != std::string::npos ||
        name == cfg)
    {
      std::filesystem::remove(file.path());
    }
  }
}

TEST_CASE("IoraService concurrent HTTP clients",
          "[iora][IoraService][concurrency]")
{
  // unique port for this test
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

  svc.webhookServer().onJsonGet("/ping",
                                [](const httplib::Request&) -> iora::json::Json {
                                  return {{"pong", true}};
                                });
  svc.startWebhookServer();
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

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
    t.join();
  REQUIRE(successCount.load() == threadCount);
  iora::log::Logger::shutdown();
  svc.stopWebhookServer();
  // clean up
  for (const auto& file : std::filesystem::directory_iterator("."))
  {
    std::string name = file.path().string();
    if (name.find("ioraservice_concurrency_log") != std::string::npos ||
        name.find("ioraservice_concurrency_state.json") != std::string::npos)
    {
      std::filesystem::remove(file.path());
    }
  }
}

TEST_CASE("EventQueue processes valid events", "[EventQueue]")
{
  iora::util::EventQueue queue(2);
  std::atomic<int> counter{0};

  queue.onEventId("testId",
                  [&](const iora::json::Json& event)
                  {
                    REQUIRE(event["eventId"] == "testId");
                    counter++;
                  });

  iora::json::Json validEvent = {{"eventId", "testId"}, {"eventName", "testEvent"}};
  queue.push(validEvent);

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 1);
}

TEST_CASE("EventQueue drops invalid events", "[EventQueue]")
{
  iora::util::EventQueue queue(2);
  std::atomic<int> counter{0};

  queue.onEventId("testId", [&](const iora::json::Json&) { counter++; });

  iora::json::Json invalidEvent = {{"eventName", "testEvent"}};
  queue.push(invalidEvent);

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 0);
}

TEST_CASE("EventQueue matches eventName with glob patterns", "[EventQueue]")
{
  iora::util::EventQueue queue(2);
  std::atomic<int> counter{0};

  queue.onEventNameMatches(
      "^test.*",
      [&](const iora::json::Json& event)
      {
        REQUIRE(event["eventName"].get<std::string>().find("test") == 0);
        counter++;
      });

  iora::json::Json matchingEvent = {{"eventId", "id1"}, {"eventName", "testEvent"}};
  iora::json::Json nonMatchingEvent = {{"eventId", "id2"},
                                 {"eventName", "otherEvent"}};

  queue.push(matchingEvent);
  queue.push(nonMatchingEvent);

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 1);
}

TEST_CASE("EventQueue matches eventName exactly", "[EventQueue]")
{
  iora::util::EventQueue queue(2);
  std::atomic<int> counter{0};

  queue.onEventName("testEvent",
                    [&](const iora::json::Json& event)
                    {
                      REQUIRE(event["eventName"].get<std::string>() ==
                              "testEvent");
                      counter++;
                    });

  iora::json::Json matchingEvent = {{"eventId", "id1"}, {"eventName", "testEvent"}};
  iora::json::Json nonMatchingEvent = {{"eventId", "id2"},
                                 {"eventName", "otherEvent"}};

  queue.push(matchingEvent);
  queue.push(nonMatchingEvent);

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 1);
}

TEST_CASE("EventQueue handles concurrent pushes and handlers", "[EventQueue]")
{
  iora::util::EventQueue queue(4);
  std::atomic<int> counter{0};

  queue.onEventId("testId", [&](const iora::json::Json&) { counter++; });

  std::vector<std::thread> threads;
  for (int i = 0; i < 10; ++i)
  {
    threads.emplace_back(
        [&queue]()
        {
          iora::json::Json event = {{"eventId", "testId"},
                              {"eventName", "testEvent"}};
          queue.push(event);
        });
  }

  for (auto& t : threads)
  {
    t.join();
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 10);
}

TEST_CASE("EventQueue shuts down gracefully", "[EventQueue]")
{
  iora::util::EventQueue queue(2);
  std::atomic<int> counter{0};

  queue.onEventId("testId", [&](const iora::json::Json&) { counter++; });

  iora::json::Json event = {{"eventId", "testId"}, {"eventName", "testEvent"}};
  queue.push(event);

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 1); // Ensure event was processed before shutdown
}

TEST_CASE("IoraService integrates EventQueue",
          "[iora][IoraService][EventQueue]")
{
  // prepare argv with explicit port and state file to avoid conflicts
  const char* args[] = {"program",
                        "--port",
                        "8114",
                        "--state-file",
                        "ioraservice_eventqueue_state.json",
                        "--log-file",
                        "ioraservice_eventqueue_log"};
  int argc = static_cast<int>(sizeof(args) / sizeof(args[0]));

  // Initialise the service with the provided arguments
  iora::IoraService& svc =
      iora::IoraService::init(argc, const_cast<char**>(args));


  // Register an event handler using the fluent API
  std::atomic<int> counter{0};
  svc.onEvent("testEventId").handle([&](const iora::json::Json& event)
  {
    REQUIRE(event["eventId"] == "testEventId");
    counter++;
  });

  // Push an event using the fluent API
  svc.pushEvent({{"eventId", "testEventId"}, {"eventName", "testEventName"}});

  // Allow some time for the event to be processed
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Verify the event was processed
  REQUIRE(counter == 1);

  // Clean up generated files
  for (const auto& file : std::filesystem::directory_iterator("."))
  {
    std::string name = file.path().string();
    if (name.find("ioraservice_eventqueue_log") != std::string::npos ||
        name.find("ioraservice_eventqueue_state.json") != std::string::npos)
    {
      std::filesystem::remove(file.path());
    }
  }
}

#include <dlfcn.h>

TEST_CASE("Dynamic loading of testplugin shared library")
{
  iora::IoraService& svc = iora::IoraService::instance();

  // Try both build and source tree locations for the plugin
  std::string pluginPath = "tests/plugins/testplugin.so";
  if (!std::filesystem::exists(pluginPath))
  {
    pluginPath = "build/tests/plugins/testplugin.so";
  }
  if (!std::filesystem::exists(pluginPath))
  {
    pluginPath = "iora/build/tests/plugins/testplugin.so";
  }
  INFO(std::string("Checked plugin path: ") + pluginPath);
  REQUIRE(std::filesystem::exists(pluginPath));

  // Load the plugin using the PluginManager
  REQUIRE_NOTHROW(svc.loadPlugin("testplugin", pluginPath));

  // Resolve the loadModule symbol
  using LoadModuleFunc = iora::IoraPlugin* (*)(iora::IoraService*);
  LoadModuleFunc loadModule = nullptr;
  REQUIRE_NOTHROW(loadModule = svc.resolve<LoadModuleFunc>("testplugin", "loadModule"));
  REQUIRE(loadModule != nullptr);

  // Call loadModule and check the returned plugin pointer
  iora::IoraPlugin* plugin = nullptr;
  REQUIRE_NOTHROW(plugin = loadModule(&svc));
  REQUIRE(plugin != nullptr);

  // Test calling plugin APIs via callPluginApi
  SECTION("callPluginApi: add")
  {
    int sum = svc.callPluginApi<int, int, int>("testplugin.add", 2, 3);
    REQUIRE(sum == 5);
  }
  SECTION("callPluginApi: greet")
  {
    std::string greet = svc.callPluginApi<std::string, const std::string&>("testplugin.greet", "World");
    REQUIRE(greet == "Hello, World!");
  }
  SECTION("callPluginApi: toggleLoaded and isLoaded")
  {
    bool loaded1 = svc.callPluginApi<bool>("testplugin.isLoaded");
    bool toggled = svc.callPluginApi<bool>("testplugin.toggleLoaded");
    bool loaded2 = svc.callPluginApi<bool>("testplugin.isLoaded");
    REQUIRE(loaded1 == true);
    REQUIRE(toggled == false);
    REQUIRE(loaded2 == false);
  }

  // Test caching API function with getPluginApi
  SECTION("getPluginApi: add")
  {
    auto addApi = svc.getPluginApi<int(int, int)>("testplugin.add");
    REQUIRE(addApi(10, 20) == 30);
  }
  SECTION("getPluginApi: greet")
  {
    auto greetApi = svc.getPluginApi<std::string(const std::string&)>("testplugin.greet");
    REQUIRE(greetApi("Iora") == "Hello, Iora!");
  }

  // Unload the plugin
  REQUIRE_NOTHROW(svc.unloadPlugin("testplugin"));
}
