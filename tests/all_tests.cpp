
#define CATCH_CONFIG_MAIN
#include "catch2/catch_test_macros.hpp"
#include "iora/iora.hpp"

TEST_CASE("HttpClient and WebhookServer integration tests")
{
  iora::http::WebhookServer server(8081);

  server.onJson("/test-post-json", [](const iora::Json& input) -> iora::Json {
    return { {"echo", input} };
  });

  server.onJsonGet("/test-get", [](const httplib::Request&) -> iora::Json {
    return { {"status", "ok"} };
  });

  server.onDelete("/test-delete", [](const httplib::Request&, httplib::Response& res) {
    res.set_content("{}", "application/json");
    res.status = 200;
  });

  server.onJson("/test-async", [](const iora::Json& input) -> iora::Json {
    return { {"async", true}, {"received", input} };
  });

  server.on("/test-stream", [](const httplib::Request& req, httplib::Response& res) {
    res.set_content(
      "data: {\"text\":\"line1\"}\n"
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
    iora::Json payload = {{"message", "hello"}};
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
    iora::Json payload = {{"async_test", 1}};
    std::future<iora::Json> future = client.postJsonAsync("http://localhost:8081/test-async", payload);
    auto res = future.get();
    REQUIRE(res["async"] == true);
    REQUIRE(res["received"]["async_test"] == 1);
  }

  SECTION("Streamed POST returns line chunks")
  {
    iora::Json payload = {{}};
    std::vector<std::string> chunks;
    client.postStream("http://localhost:8081/test-stream", payload, {}, [&](const std::string& line) {
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
      bool found =
        msg.find("not found") != std::string::npos ||
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
    threads.emplace_back([&cache, i]() {
      cache.set(i, i * 10, std::chrono::seconds(1));
    });
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
  for (const auto& file : std::filesystem::directory_iterator(".")) {
    if (file.path().string().find("testlog.") == 0) {
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
  while (std::getline(in, line)) { ++count; }
  REQUIRE(count >= 6);
  // Cleanup after test
  for (const auto& file : std::filesystem::directory_iterator(".")) {
    if (file.path().string().find("testlog.") == 0) {
      std::filesystem::remove(file.path());
    }
  }
}

TEST_CASE("Logger Stream Logging", "[logger][stream]")
{
  iora::log::Logger::init(iora::log::Logger::Level::Info, "streamlog", false);
  iora::log::Logger << iora::log::Logger::Level::Info << "Stream log test: " << 123 << iora::log::Logger::endl;
  iora::log::Logger::shutdown();

  std::string logFile = "streamlog." + iora::log::Logger::currentDate() + ".log";
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
  for (const auto& file : std::filesystem::directory_iterator(".")) {
    if (file.path().string().find("asynclog.") == 0) {
      std::filesystem::remove(file.path());
    }
  }
  iora::log::Logger::init(iora::log::Logger::Level::Info, "asynclog", true);
  for (int i = 0; i < 100; ++i)
  {
    iora::log::Logger << iora::log::Logger::Level::Info << "Async message " << i << iora::log::Logger::endl;
  }
  iora::log::Logger::shutdown();

  std::string logFile = "asynclog." + iora::log::Logger::currentDate() + ".log";
  std::ifstream in(logFile);
  REQUIRE(in.is_open());
  std::string line;
  int count = 0;
  while (std::getline(in, line)) { ++count; }
  REQUIRE(count >= 100);
  // Cleanup after test
  for (const auto& file : std::filesystem::directory_iterator(".")) {
    if (file.path().string().find("asynclog.") == 0) {
      std::filesystem::remove(file.path());
    }
  }
}

TEST_CASE("Logger Thread Safety", "[logger][threaded]")
{
  // Cleanup before test
  for (const auto& file : std::filesystem::directory_iterator(".")) {
    if (file.path().string().find("threadlog.") == 0) {
      std::filesystem::remove(file.path());
    }
  }
  iora::log::Logger::init(iora::log::Logger::Level::Info, "threadlog", true);
  const int threads = 10;
  const int messagesPerThread = 50;
  std::vector<std::thread> workers;

  for (int i = 0; i < threads; ++i)
  {
    workers.emplace_back([i]() {
      for (int j = 0; j < messagesPerThread; ++j)
      {
        iora::log::Logger << iora::log::Logger::Level::Info << "Thread " << i << " message " << j << iora::log::Logger::endl;
      }
    });
  }

  for (auto& t : workers) { t.join(); }
  iora::log::Logger::shutdown();

  std::string logFile = "threadlog." + iora::log::Logger::currentDate() + ".log";
  std::ifstream in(logFile);
  REQUIRE(in.is_open());
  std::string line;
  int count = 0;
  while (std::getline(in, line)) { ++count; }
  REQUIRE(count >= threads * messagesPerThread);
  // Cleanup after test
  for (const auto& file : std::filesystem::directory_iterator(".")) {
    if (file.path().string().find("threadlog.") == 0) {
      std::filesystem::remove(file.path());
    }
  }
}

TEST_CASE("Logger File Rotation and Retention", "[logger][rotation]")
{
  const std::string base = "rotate_test";
  const int retention = 1;

  iora::log::Logger::init(iora::log::Logger::Level::Info, base, false, retention);
  LOG_INFO("Rotation start");
  iora::log::Logger::shutdown();

  std::string oldFile = base + ".2000-01-01.log";
  std::ofstream fakeOld(oldFile);
  fakeOld << "old log" << std::endl;
  fakeOld.close();
  std::filesystem::last_write_time(oldFile, std::filesystem::file_time_type::clock::now() - std::chrono::hours(25));

  iora::log::Logger::init(iora::log::Logger::Level::Info, base, false, retention);
  LOG_INFO("Trigger rotation");
  iora::log::Logger::shutdown();

  REQUIRE_FALSE(std::filesystem::exists(oldFile));
}
