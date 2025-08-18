// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "test_helpers.hpp"

TEST_CASE("Logger Basic Levels", "[logger][levels]")
{
  iora::util::removeFilesMatchingPrefix("testlog.");

  iora::core::Logger::init(iora::core::Logger::Level::Trace, "testlog", false);
  LOG_TRACE("Trace message");
  LOG_DEBUG("Debug message");
  LOG_INFO("Info message");
  LOG_WARN("Warn message");
  LOG_ERROR("Error message");
  LOG_FATAL("Fatal message");
  iora::core::Logger::shutdown();

  std::string logFile = "testlog." + iora::core::Logger::currentDate() + ".log";
  std::ifstream in(logFile);
  REQUIRE(in.is_open());
  REQUIRE(std::count(std::istreambuf_iterator<char>(in), {}, '\n') >= 6);
  iora::util::removeFilesMatchingPrefix("testlog.");
}

TEST_CASE("Logger Stream Logging", "[logger][stream]")
{
  iora::core::Logger::init(iora::core::Logger::Level::Info, "streamlog", false);
  iora::core::Logger << iora::core::Logger::Level::Info
                     << "Stream log test: " << 123 << iora::core::Logger::endl;
  iora::core::Logger::shutdown();

  std::string logFile =
      "streamlog." + iora::core::Logger::currentDate() + ".log";
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
  iora::util::removeFilesMatchingPrefix("streamlog.");
}

TEST_CASE("Logger Async Logging", "[logger][async]")
{
  iora::util::removeFilesMatchingPrefix("asynclog.");

  iora::core::Logger::init(iora::core::Logger::Level::Info, "asynclog", true);
  for (int i = 0; i < 100; ++i)
  {
    iora::core::Logger << iora::core::Logger::Level::Info << "Async message "
                       << i << iora::core::Logger::endl;
  }
  iora::core::Logger::shutdown();

  std::string logFile =
      "asynclog." + iora::core::Logger::currentDate() + ".log";
  std::ifstream in(logFile);
  REQUIRE(in.is_open());
  REQUIRE(std::count(std::istreambuf_iterator<char>(in), {}, '\n') >= 100);
  iora::util::removeFilesMatchingPrefix("asynclog.");
}

TEST_CASE("Logger Thread Safety", "[logger][threaded]")
{
  iora::util::removeFilesMatchingPrefix("threadlog.");

  iora::core::Logger::init(iora::core::Logger::Level::Info, "threadlog", true);
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
            iora::core::Logger << iora::core::Logger::Level::Info << "Thread "
                               << i << " message " << j
                               << iora::core::Logger::endl;
          }
        });
  }
  for (auto& t : workers)
  {
    t.join();
  }
  iora::core::Logger::shutdown();

  std::string logFile =
      "threadlog." + iora::core::Logger::currentDate() + ".log";
  std::ifstream in(logFile);
  REQUIRE(in.is_open());
  REQUIRE(std::count(std::istreambuf_iterator<char>(in), {}, '\n') >=
          threads * messagesPerThread);
  iora::util::removeFilesMatchingPrefix("threadlog.");
}

TEST_CASE("Logger File Rotation and Retention", "[logger][rotation]")
{
  const std::string base = "rotate_test";
  const int retention = 1;

  iora::core::Logger::init(iora::core::Logger::Level::Info, base, false,
                           retention);
  LOG_INFO("Rotation start");
  iora::core::Logger::shutdown();

  std::string oldFile = base + ".2000-01-01.log";
  std::ofstream fakeOld(oldFile);
  fakeOld << "old log" << std::endl;
  fakeOld.close();
  std::filesystem::last_write_time(
      oldFile,
      std::filesystem::file_time_type::clock::now() - std::chrono::hours(25));

  iora::core::Logger::init(iora::core::Logger::Level::Info, base, false,
                           retention);
  LOG_INFO("Trigger rotation");
  iora::core::Logger::shutdown();

  REQUIRE_FALSE(std::filesystem::exists(oldFile));
  iora::util::removeFilesMatchingPrefix("rotate_test.");
}
