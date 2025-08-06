#include "iora/iora.hpp"
#include "catch2/catch_test_macros.hpp"
#include <fstream>

TEST_CASE("Logger Basic Levels", "[logger][levels]")
{
  removeFilesMatchingPrefix("testlog.");

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
  REQUIRE(std::count(std::istreambuf_iterator<char>(in), {}, '\n') >= 6);
  removeFilesMatchingPrefix("testlog.");
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
  removeFilesMatchingPrefix("streamlog.");
}

TEST_CASE("Logger Async Logging", "[logger][async]")
{
  removeFilesMatchingPrefix("asynclog.");

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
  REQUIRE(std::count(std::istreambuf_iterator<char>(in), {}, '\n') >= 100);
  removeFilesMatchingPrefix("asynclog.");
}

TEST_CASE("Logger Thread Safety", "[logger][threaded]")
{
  removeFilesMatchingPrefix("threadlog.");

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
  REQUIRE(std::count(std::istreambuf_iterator<char>(in), {}, '\n') >=
          threads * messagesPerThread);
  removeFilesMatchingPrefix("threadlog.");
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
  removeFilesMatchingPrefix("rotate_test.");
}
