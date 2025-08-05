#define CATCH_CONFIG_MAIN
#include "catch2/catch_test_macros.hpp"    // For TEST_CASE, SECTION, REQUIRE, etc.
#include "catch2/catch_approx.hpp"         // For Approx (floating-point comparison)
#include "catch2/catch_session.hpp"        // For advanced session control (if needed)
#include "catch2/catch_tostring.hpp"       // For custom string conversions (optional)
#include "catch2/catch_all.hpp"            // Includes most commonly used Catch2 features
#include "iora/iora.hpp"


class AutoServiceShutdown
{
public:
  AutoServiceShutdown(iora::IoraService& service) : svc(service) {}
  ~AutoServiceShutdown() { svc.shutdown(); }

private:
  iora::IoraService& svc;
};

TEST_CASE("HttpClient and WebhookServer integration tests")
{
  iora::http::WebhookServer server;
  server.setPort(8081);

  server.onJsonPost("/test-post-json",
                [](const iora::json::Json& input) -> iora::json::Json {
                  return {{"echo", input}};
                });

  server.onJsonPost("/test-async",
                [](const iora::json::Json& input) -> iora::json::Json {
                  return {{"async", true}, {"received", input}};
                });

  server.onJsonGet("/test-get",
                [](const iora::json::Json& input) -> iora::json::Json {
                  return {{"status", "ok"}};
                });

  server.onPost("/test-stream",
                [](const httplib::Request& req, httplib::Response& res)
                {
                  res.set_content("data: {\"text\":\"line1\"}\n"
                                  "data: {\"text\":\"line2\"}\n"
                                  "data: [DONE]\n",
                                  "text/event-stream");
                  res.status = 200;
                });

  server.start();
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  iora::http::HttpClient client;

  SECTION("GET request returns valid JSON")
  {
    try
    {
      auto res = client.get("http://localhost:8081/test-get");
      REQUIRE(res["status"] == "ok");
    }
    catch (const std::exception& ex)
    {
      FAIL(std::string("Exception: ") + ex.what());
    }
  }

  SECTION("POST JSON request with payload")
  {
    iora::json::Json payload = {{"message", "hello"}};
    auto res = client.postJson("http://localhost:8081/test-post-json", payload);
    REQUIRE(res["echo"]["message"] == "hello");
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

  AutoServiceShutdown autoShutdown(svc); // Ensure service is shutdown at end

  // in-memory state store works
  svc.stateStore()->set("foo", "bar");
  REQUIRE(svc.stateStore()->get("foo").value() == "bar");

  // cache works and expires
  svc.cache()->set("cacheKey", std::string("cacheValue"), std::chrono::seconds(1));
  REQUIRE(svc.cache()->get("cacheKey").value() == "cacheValue");
  std::this_thread::sleep_for(std::chrono::seconds(2));
  REQUIRE_FALSE(svc.cache()->get("cacheKey").has_value());

  // persistent JsonFileStore writes to disk
  iora::log::Logger::error(std::string("[DEBUG] svc.jsonFileStore() before set: ") + std::to_string(reinterpret_cast<uintptr_t>(svc.jsonFileStore().get())));
  REQUIRE(svc.jsonFileStore() != nullptr); // Defensive: fail clearly if null
  svc.jsonFileStore()->set("persist", "value");
  iora::log::Logger::error(std::string("[DEBUG] svc.jsonFileStore() after set: ") + std::to_string(reinterpret_cast<uintptr_t>(svc.jsonFileStore().get())));
  REQUIRE(svc.jsonFileStore() != nullptr); // Defensive: check again after use
  REQUIRE(svc.jsonFileStore()->get("persist").value() == "value");
  // Ensure state is flushed before reading file
  svc.jsonFileStore()->flush();
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

  svc.webhookServer()->onJsonGet("/basic",
                                [](const iora::json::Json& input) -> iora::json::Json {
                                  return {{"ok", true}};
                                });
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  {
    auto client = svc.makeHttpClient();
    auto res = client.get("http://localhost:8110/basic");
    REQUIRE(res["ok"] == true);
  }

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
    out << "[iora.server]\nport = 8111\n";
    out << "[iora.state]\nfile = 'ioraservice_cfg_state.json'\n";
    out << "[iora.log]\nlevel = 'debug'\nfile = 'ioraservice_cfg_log'\n";
    out << "async = false\nretention_days = 2\n";
    out << "time_format = '%Y%m%d'\n";
  }

  const char* args[] = {"program", "--config", cfg.c_str()};
  int argc = static_cast<int>(sizeof(args) / sizeof(args[0]));
  iora::IoraService& svc =
      iora::IoraService::init(argc, const_cast<char**>(args));
  AutoServiceShutdown autoShutdown(svc); // Ensure service is shutdown at end

  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  svc.webhookServer()->onJsonGet("/cfg",
                                [](const iora::json::Json& input) -> iora::json::Json {
                                  return {{"cfg", true}};
                                });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
    out << "[iora.server]\nport = 8112\n";
    out << "[iora.state]\nfile = 'ioraservice_cli_state.json'\n";
    out << "[iora.log]\nlevel = 'info'\nfile = 'ioraservice_cli_log'\n";
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

  AutoServiceShutdown autoShutdown(svc); // Ensure service is shutdown at end

  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  svc.webhookServer()->onJsonGet("/cli",
                                [](const iora::json::Json& input) -> iora::json::Json {
                                  return {{"cli", true}};
                                });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
  AutoServiceShutdown autoShutdown(svc); // Ensure service is shutdown at end

  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  svc.webhookServer()->onJsonGet("/ping",
                                [](const iora::json::Json& input) -> iora::json::Json {
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
    t.join();
  REQUIRE(successCount.load() == threadCount);

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

  AutoServiceShutdown autoShutdown(svc); // Ensure service is shutdown at end

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
  // Use a unique port and log/state file for this test
  const char* args[] = {"program",
                        "--port", "8130",
                        "--state-file", "ioraservice_plugin_state.json",
                        "--log-file", "ioraservice_plugin_log"};
  int argc = static_cast<int>(sizeof(args) / sizeof(args[0]));
  iora::IoraService& svc = iora::IoraService::init(argc, const_cast<char**>(args));

  AutoServiceShutdown autoShutdown(svc); // Ensure service is shutdown at end

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

  REQUIRE(svc.loadSingleModule(pluginPath));

  // Test calling plugin APIs via callExportedApi
  SECTION("callExportedApi: add")
  {
    int sum = svc.callExportedApi<int, int, int>("testplugin.add", 2, 3);
    REQUIRE(sum == 5);
  }
  SECTION("callExportedApi: greet")
  {
    std::string greet = svc.callExportedApi<std::string, const std::string&>("testplugin.greet", "World");
    REQUIRE(greet == "Hello, World!");
  }
  SECTION("callExportedApi: toggleLoaded and isLoaded")
  {
    bool loaded1 = svc.callExportedApi<bool>("testplugin.isLoaded");
    bool toggled = svc.callExportedApi<bool>("testplugin.toggleLoaded");
    bool loaded2 = svc.callExportedApi<bool>("testplugin.isLoaded");
    REQUIRE(loaded1 == true);
    REQUIRE(toggled == false);
    REQUIRE(loaded2 == false);
  }

  // Test caching API function with getExportedApi
  SECTION("getExportedApi: add")
  {
    auto addApi = svc.getExportedApi<int(int, int)>("testplugin.add");
    REQUIRE(addApi(10, 20) == 30);
  }
  SECTION("getExportedApi: greet")
  {
    auto greetApi = svc.getExportedApi<std::string(const std::string&)>("testplugin.greet");
    REQUIRE(greetApi("Iora") == "Hello, Iora!");
  }

  // New: Test plugin reload (unload and reload)
  SECTION("Plugin reload: unload and reload shared library")
  {
    // Unload the plugin
    REQUIRE(svc.unloadSingleModule("testplugin.so"));
    // After unload, API calls should fail or throw
    bool threw = false;
    try
    {
      (void)svc.callExportedApi<int, int, int>("testplugin.add", 1, 1);
    }
    catch (...)
    {
      threw = true;
    }
    REQUIRE(threw);

    // Reload the plugin
    REQUIRE(svc.loadSingleModule(pluginPath));
    // API calls should work again
    int sum = svc.callExportedApi<int, int, int>("testplugin.add", 7, 8);
    REQUIRE(sum == 15);
    std::string greet = svc.callExportedApi<std::string, const std::string&>("testplugin.greet", "Reloaded");
    REQUIRE(greet == "Hello, Reloaded!");
  }

  // Shutdown the service and clean up generated files
  for (const auto& file : std::filesystem::directory_iterator("."))
  {
    std::string name = file.path().string();
    if (name.find("ioraservice_plugin_log") != std::string::npos ||
        name.find("ioraservice_plugin_state.json") != std::string::npos)
    {
      std::filesystem::remove(file.path());
    }
  }
}

TEST_CASE("IoraService fluent event handler registration by name and pattern", "[iora][IoraService][EventQueue][fluent]")
{
  // prepare argv with explicit port and state file to avoid conflicts
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
  AutoServiceShutdown autoShutdown(svc); // Ensure service is shutdown at end

  // Test onEventName (exact match)
  std::atomic<int> nameCounter{0};
  svc.onEventName("fluentEvent").handle([&](const iora::json::Json& event)
  {
    REQUIRE(event["eventName"] == "fluentEvent");
    nameCounter++;
  });

  // Test onEventNameMatches (regex match)
  std::atomic<int> patternCounter{0};
  svc.onEventNameMatches("^fluent.*").handle([&](const iora::json::Json& event)
  {
    REQUIRE(event["eventName"].get<std::string>().find("fluent") == 0);
    patternCounter++;
  });

  // Push events
  svc.pushEvent({{"eventId", "id1"}, {"eventName", "fluentEvent"}}); // matches both
  svc.pushEvent({{"eventId", "id2"}, {"eventName", "fluentPattern"}}); // matches pattern only
  svc.pushEvent({{"eventId", "id3"}, {"eventName", "otherEvent"}}); // matches neither

  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  REQUIRE(nameCounter == 1);      // only "fluentEvent" matches exactly
  REQUIRE(patternCounter == 2);   // both "fluentEvent" and "fluentPattern" match pattern

  // Clean up generated files
  for (const auto& file : std::filesystem::directory_iterator("."))
  {
    std::string name = file.path().string();
    if (name.find("ioraservice_fluent_eventqueue_log") != std::string::npos ||
        name.find("ioraservice_fluent_eventqueue_state.json") != std::string::npos)
    {
      std::filesystem::remove(file.path());
    }
  }
}

TEST_CASE("ConcreteStateStore basic operations", "[state][ConcreteStateStore]")
{
  iora::state::ConcreteStateStore store;

  SECTION("Set and Get (case-insensitive)")
  {
    store.set("KeyA", "Value1");
    store.set("keyb", "Value2");
    REQUIRE(store.get("keya").value() == "Value1");
    REQUIRE(store.get("KEYB").value() == "Value2");
    REQUIRE_FALSE(store.get("missing").has_value());
  }

  SECTION("Remove and Contains")
  {
    store.set("foo", "bar");
    REQUIRE(store.contains("FOO"));
    REQUIRE(store.remove("Foo"));
    REQUIRE_FALSE(store.contains("foo"));
    REQUIRE_FALSE(store.remove("foo"));
  }

  SECTION("Keys, Size, and Empty")
  {
    REQUIRE(store.empty());
    store.set("a", "1");
    store.set("b", "2");
    store.set("c", "3");
    REQUIRE(store.size() == 3);
    auto keys = store.keys();
    REQUIRE(keys.size() == 3);
    REQUIRE_FALSE(store.empty());
  }

  SECTION("Find Keys With Prefix")
  {
    store.set("prefix_one", "x");
    store.set("prefix_two", "y");
    store.set("other", "z");
    auto prefixed = store.findKeysWithPrefix("prefix_");
    REQUIRE(prefixed.size() == 2);
    REQUIRE(std::find(prefixed.begin(), prefixed.end(), "prefix_one") != prefixed.end());
    REQUIRE(std::find(prefixed.begin(), prefixed.end(), "prefix_two") != prefixed.end());
  }

  SECTION("Find Keys By Value")
  {
    store.set("k1", "v");
    store.set("k2", "v");
    store.set("k3", "w");
    auto byValue = store.findKeysByValue("v");
    REQUIRE(byValue.size() == 2);
    REQUIRE(std::find(byValue.begin(), byValue.end(), "k1") != byValue.end());
    REQUIRE(std::find(byValue.begin(), byValue.end(), "k2") != byValue.end());
  }

  SECTION("Find Keys Matching Custom Predicate")
  {
    store.set("apple", "fruit");
    store.set("banana", "fruit");
    store.set("carrot", "vegetable");
    auto matcher = [](const std::string& k) { return k.find('a') != std::string::npos; };
    auto matched = store.findKeysMatching(matcher);
    REQUIRE(matched.size() >= 2);
    REQUIRE(std::find(matched.begin(), matched.end(), "banana") != matched.end());
    REQUIRE(std::find(matched.begin(), matched.end(), "carrot") != matched.end());
  }
}

TEST_CASE("ConfigLoader basic operations", "[config][ConfigLoader]")
{
  // Write a temporary TOML config file
  const std::string cfgFile = "test_config.toml";
  {
    std::ofstream out(cfgFile);
    out << "[section]\n";
    out << "int_val = 42\n";
    out << "bool_val = true\n";
    out << "str_val = 'hello'\n";
    out << "[other]\n";
    out << "float_val = 3.14\n";
  }

  iora::config::ConfigLoader loader(cfgFile);

  SECTION("Reload and load returns table")
  {
    REQUIRE(loader.reload());
    const auto& tbl = loader.load();
    REQUIRE(tbl.contains("section"));
    REQUIRE(tbl.contains("other"));
  }

  SECTION("get<T> returns correct values")
  {
    loader.reload();
    REQUIRE(loader.get<int64_t>("section.int_val").value() == 42);
    REQUIRE(loader.get<bool>("section.bool_val").value() == true);
    REQUIRE(loader.get<std::string>("section.str_val").value() == "hello");
    REQUIRE(loader.get<double>("other.float_val").value() ==  Catch::Approx(3.14));
    REQUIRE_FALSE(loader.get<int64_t>("section.missing").has_value());
  }

  SECTION("getInt, getBool, getString work as expected")
  {
    loader.reload();
    REQUIRE(loader.getInt("section.int_val").value() == 42);
    REQUIRE(loader.getBool("section.bool_val").value() == true);
    REQUIRE(loader.getString("section.str_val").value() == "hello");
    REQUIRE_FALSE(loader.getInt("section.missing").has_value());
  }

  SECTION("table() returns the parsed table")
  {
    loader.reload();
    const auto& tbl = loader.table();
    REQUIRE(tbl.contains("section"));
    REQUIRE(tbl.at_path("section.int_val").is_value());
  }

  SECTION("load throws on missing file")
  {
    iora::config::ConfigLoader badLoader("does_not_exist.toml");
    REQUIRE_THROWS_AS(badLoader.load(), std::runtime_error);
  }

  // Clean up
  std::filesystem::remove(cfgFile);
}

#include <fstream>
// TLS test cert/key file paths (generated by OpenSSL in iora/tests/tls-certs/)
constexpr const char* TEST_CERT_PATH = "/workspace/iora/tests/tls-certs/test_tls_cert.pem";
constexpr const char* TEST_KEY_PATH = "/workspace/iora/tests/tls-certs/test_tls_key.pem";

TEST_CASE("WebhookServer TLS (SSL) basic functionality", "[webhookserver][tls]")
{
  // Use generated PEM files in tls-certs/
  const std::string certFile = TEST_CERT_PATH;
  const std::string keyFile = TEST_KEY_PATH;
  // Diagnostics: check cert/key file existence
  if (!std::filesystem::exists(certFile))
  {
    iora::log::Logger::error(std::string("[TLS TEST] ERROR: Cert file not found: ") + certFile);
  }
  if (!std::filesystem::exists(keyFile))
  {
    iora::log::Logger::error(std::string("[TLS TEST] ERROR: Key file not found: ") + keyFile);
  }

  iora::http::WebhookServer server;
  server.setPort(8443);
  iora::http::WebhookServer::TlsConfig tlsCfg;
  tlsCfg.certFile = certFile;
  tlsCfg.keyFile = keyFile;
  tlsCfg.caFile = ""; // Not required for self-signed test
  tlsCfg.requireClientCert = false;
  try
  {
    server.enableTls(tlsCfg);
  }
  catch (const std::exception& ex)
  {
    iora::log::Logger::error(std::string("[TLS TEST] ERROR: enableTls threw: ") + ex.what());
  }

  server.onJsonGet("/tls-test", [](const iora::json::Json&) -> iora::json::Json {
    return {{"tls", true}};
  });
  try
  {
    server.start();
  }
  catch (const std::exception& ex)
  {
    iora::log::Logger::error(std::string("[TLS TEST] ERROR: server.start() threw: ") + ex.what());
  }
  // Increase sleep to ensure server is ready
  std::this_thread::sleep_for(std::chrono::milliseconds(1500));

  SECTION("HTTPS GET returns valid JSON over TLS")
  {
    // Use cpr with SSL verification disabled for self-signed cert
    cpr::Session session;
    session.SetUrl(cpr::Url{"https://localhost:8443/tls-test"});
    session.SetVerifySsl(false);
    auto response = session.Get();
    if (response.status_code != 200)
    {
      iora::log::Logger::error(std::string("[TLS TEST] cpr::Session error: status=") + std::to_string(response.status_code) + ", error.message='" + response.error.message + "'");
    }
    REQUIRE(response.status_code == 200);
    auto json = iora::http::HttpClient::parseJsonOrThrow(response);
    REQUIRE(json["tls"] == true);
  }

  server.stop();
  // No cleanup: PEM files are persistent for all test runs
}

TEST_CASE("IoraService::init(Config) initializes service from Config struct", "[iora][IoraService][config]")
{
  // Prepare a Config struct with custom settings
  iora::IoraService::Config config;
  config.server.port = 8150;
  config.state.file = std::string("ioraservice_configobj_state.json");
  config.log.file = std::string("ioraservice_configobj_log");
  config.log.level = std::string("info");
  config.log.async = false;
  config.log.retentionDays = 1;
  config.log.timeFormat = std::string("%Y%m%d");

  // Call the static init(Config&) method
  iora::IoraService::init(config);
  iora::IoraService& svc = iora::IoraService::instance();
  AutoServiceShutdown autoShutdown(svc);

  // Check that the service is running and config is applied
  REQUIRE(svc.webhookServer() != nullptr);
  REQUIRE(svc.jsonFileStore() != nullptr);
  svc.jsonFileStore()->set("cfgobjKey", "cfgobjValue");
  REQUIRE(svc.jsonFileStore()->get("cfgobjKey").value() == "cfgobjValue");
  svc.jsonFileStore()->flush();
  REQUIRE(std::filesystem::exists("ioraservice_configobj_state.json"));

  // Clean up generated files
  for (const auto& file : std::filesystem::directory_iterator("."))
  {
    std::string name = file.path().string();
    if (name.find("ioraservice_configobj_log") != std::string::npos ||
        name.find("ioraservice_configobj_state.json") != std::string::npos)
    {
      std::filesystem::remove(file.path());
    }
  }
}