// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

TEST_CASE("Logger Basic Levels", "[logger][levels]")
{
  iora::util::removeFilesMatchingPrefix("testlog.");

  iora::core::Logger::init(iora::core::Logger::Level::Trace, "testlog", false);
  IORA_LOG_TRACE("Trace message");
  IORA_LOG_DEBUG("Debug message");
  IORA_LOG_INFO("Info message");
  IORA_LOG_WARN("Warn message");
  IORA_LOG_ERROR("Error message");
  IORA_LOG_FATAL("Fatal message");
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
  iora::core::Logger << iora::core::Logger::Level::Info << "Stream log test: " << 123
                     << iora::core::Logger::endl;
  iora::core::Logger::shutdown();

  std::string logFile = "streamlog." + iora::core::Logger::currentDate() + ".log";
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
    iora::core::Logger << iora::core::Logger::Level::Info << "Async message " << i
                       << iora::core::Logger::endl;
  }
  iora::core::Logger::shutdown();

  std::string logFile = "asynclog." + iora::core::Logger::currentDate() + ".log";
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
          iora::core::Logger << iora::core::Logger::Level::Info << "Thread " << i << " message "
                             << j << iora::core::Logger::endl;
        }
      });
  }
  for (auto &t : workers)
  {
    t.join();
  }
  iora::core::Logger::shutdown();

  std::string logFile = "threadlog." + iora::core::Logger::currentDate() + ".log";
  std::ifstream in(logFile);
  REQUIRE(in.is_open());
  REQUIRE(std::count(std::istreambuf_iterator<char>(in), {}, '\n') >= threads * messagesPerThread);
  iora::util::removeFilesMatchingPrefix("threadlog.");
}

TEST_CASE("Logger File Rotation and Retention", "[logger][rotation]")
{
  const std::string base = "rotate_test";
  const int retention = 1;

  iora::core::Logger::init(iora::core::Logger::Level::Info, base, false, retention);
  IORA_LOG_INFO("Rotation start");
  iora::core::Logger::shutdown();

  std::string oldFile = base + ".2000-01-01.log";
  std::ofstream fakeOld(oldFile);
  fakeOld << "old log" << std::endl;
  fakeOld.close();
  std::filesystem::last_write_time(oldFile, std::filesystem::file_time_type::clock::now() -
                                              std::chrono::hours(25));

  iora::core::Logger::init(iora::core::Logger::Level::Info, base, false, retention);
  IORA_LOG_INFO("Trigger rotation");
  iora::core::Logger::shutdown();

  REQUIRE_FALSE(std::filesystem::exists(oldFile));
  iora::util::removeFilesMatchingPrefix("rotate_test.");
}

TEST_CASE("Logger Basename Extraction", "[logger][basename]")
{
  using iora::core::detail::basename;

  SECTION("Unix paths")
  {
    REQUIRE(std::string(basename("/usr/local/include/iora/core/logger.hpp")) == "logger.hpp");
    REQUIRE(std::string(basename("/home/user/test.cpp")) == "test.cpp");
    REQUIRE(std::string(basename("/test.txt")) == "test.txt");
    REQUIRE(std::string(basename("relative/path/file.hpp")) == "file.hpp");
  }

  SECTION("Windows paths")
  {
    REQUIRE(std::string(basename("C:\\Users\\test\\file.cpp")) == "file.cpp");
    REQUIRE(std::string(basename("C:\\test.hpp")) == "test.hpp");
    REQUIRE(std::string(basename("..\\..\\src\\main.cpp")) == "main.cpp");
  }

  SECTION("Filename only")
  {
    REQUIRE(std::string(basename("file.cpp")) == "file.cpp");
    REQUIRE(std::string(basename("test")) == "test");
  }

  SECTION("Trailing separator")
  {
    REQUIRE(std::string(basename("/path/to/")) == "");
    REQUIRE(std::string(basename("C:\\path\\")) == "");
  }

  SECTION("Empty path")
  {
    REQUIRE(std::string(basename("")) == "");
  }
}

TEST_CASE("Logger Printf-Style Methods", "[logger][printf]")
{
  iora::util::removeFilesMatchingPrefix("printflog.");

  iora::core::Logger::init(iora::core::Logger::Level::Trace, "printflog", false);

  SECTION("All log levels")
  {
    iora::core::Logger::tracef("Trace: %d %s %.2f", 42, "test", 3.14);
    iora::core::Logger::debugf("Debug: %d %s %.2f", 42, "test", 3.14);
    iora::core::Logger::infof("Info: %d %s %.2f", 42, "test", 3.14);
    iora::core::Logger::warningf("Warning: %d %s %.2f", 42, "test", 3.14);
    iora::core::Logger::errorf("Error: %d %s %.2f", 42, "test", 3.14);
    iora::core::Logger::fatalf("Fatal: %d %s %.2f", 42, "test", 3.14);
    iora::core::Logger::shutdown();

    std::string logFile = "printflog." + iora::core::Logger::currentDate() + ".log";
    std::ifstream in(logFile);
    REQUIRE(in.is_open());

    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    REQUIRE(content.find("Trace: 42 test 3.14") != std::string::npos);
    REQUIRE(content.find("Debug: 42 test 3.14") != std::string::npos);
    REQUIRE(content.find("Info: 42 test 3.14") != std::string::npos);
    REQUIRE(content.find("Warning: 42 test 3.14") != std::string::npos);
    REQUIRE(content.find("Error: 42 test 3.14") != std::string::npos);
    REQUIRE(content.find("Fatal: 42 test 3.14") != std::string::npos);
  }

  iora::util::removeFilesMatchingPrefix("printflog.");
}

TEST_CASE("Logger Printf-Style Macros", "[logger][printf][macros]")
{
  iora::util::removeFilesMatchingPrefix("printfmacro.");

  iora::core::Logger::init(iora::core::Logger::Level::Trace, "printfmacro", false);

  SECTION("All macro levels")
  {
    IORA_LOG_TRACEF("Trace macro: %d", 1);
    IORA_LOG_DEBUGF("Debug macro: %d", 2);
    IORA_LOG_INFOF("Info macro: %d", 3);
    IORA_LOG_WARNF("Warn macro: %d", 4);
    IORA_LOG_ERRORF("Error macro: %d", 5);
    IORA_LOG_FATALF("Fatal macro: %d", 6);
    iora::core::Logger::shutdown();

    std::string logFile = "printfmacro." + iora::core::Logger::currentDate() + ".log";
    std::ifstream in(logFile);
    REQUIRE(in.is_open());

    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    REQUIRE(content.find("Trace macro: 1") != std::string::npos);
    REQUIRE(content.find("Debug macro: 2") != std::string::npos);
    REQUIRE(content.find("Info macro: 3") != std::string::npos);
    REQUIRE(content.find("Warn macro: 4") != std::string::npos);
    REQUIRE(content.find("Error macro: 5") != std::string::npos);
    REQUIRE(content.find("Fatal macro: 6") != std::string::npos);
  }

  iora::util::removeFilesMatchingPrefix("printfmacro.");
}

TEST_CASE("Logger Source Location Placeholders", "[logger][sourceloc]")
{
  iora::util::removeFilesMatchingPrefix("sourceloc.");

  iora::core::Logger::init(iora::core::Logger::Level::Info, "sourceloc", false);
  iora::core::Logger::setLogFormat("[%F:%l %f] %m");

  SECTION("File, line, function placeholders")
  {
    int testLine = __LINE__ + 1;
    IORA_LOG_INFO("Test message with source location");
    iora::core::Logger::shutdown();

    std::string logFile = "sourceloc." + iora::core::Logger::currentDate() + ".log";
    std::ifstream in(logFile);
    REQUIRE(in.is_open());

    std::string line;
    std::getline(in, line);

    // Should contain filename only (not full path)
    REQUIRE(line.find("iora_test_logger.cpp") != std::string::npos);
    REQUIRE(line.find("/workspace") == std::string::npos); // No full path

    // Should contain line number
    REQUIRE(line.find(":" + std::to_string(testLine)) != std::string::npos);

    // Should contain some function name (format varies by compiler)
    // Just verify format is [filename:line something] message
    REQUIRE(line.find("[iora_test_logger.cpp:") != std::string::npos);
    REQUIRE(line.find("Test message with source location") != std::string::npos);
  }

  iora::util::removeFilesMatchingPrefix("sourceloc.");
}

TEST_CASE("Logger Custom Format Strings", "[logger][format]")
{
  iora::util::removeFilesMatchingPrefix("formatlog.");

  SECTION("Format with timestamp and level")
  {
    iora::core::Logger::init(iora::core::Logger::Level::Info, "formatlog", false);
    iora::core::Logger::setLogFormat("[%T] [%L] %m");
    IORA_LOG_INFO("Format test");
    iora::core::Logger::shutdown();

    std::string logFile = "formatlog." + iora::core::Logger::currentDate() + ".log";
    std::ifstream in(logFile);
    REQUIRE(in.is_open());

    std::string line;
    std::getline(in, line);
    REQUIRE(line.find("[INFO]") != std::string::npos);
    REQUIRE(line.find("Format test") != std::string::npos);
  }

  SECTION("Format with all placeholders")
  {
    iora::core::Logger::init(iora::core::Logger::Level::Info, "formatlog2", false);
    iora::core::Logger::setLogFormat("[%T] [%t] [%L] [%F:%l %f] %m");
    IORA_LOG_INFO("Complete format test");
    iora::core::Logger::shutdown();

    std::string logFile = "formatlog2." + iora::core::Logger::currentDate() + ".log";
    std::ifstream in(logFile);
    REQUIRE(in.is_open());

    std::string line;
    std::getline(in, line);

    // Verify all components present
    REQUIRE(line.find("[INFO]") != std::string::npos);
    REQUIRE(line.find("iora_test_logger.cpp") != std::string::npos);
    REQUIRE(line.find("Complete format test") != std::string::npos);

    // Should have timestamp (contains digits and colons)
    REQUIRE(line.find(":") != std::string::npos);

    // Should have hex thread ID (contains hex digits)
    bool hasHexDigits = false;
    for (char c : line)
    {
      if ((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9'))
      {
        hasHexDigits = true;
        break;
      }
    }
    REQUIRE(hasHexDigits);
  }

  iora::util::removeFilesMatchingPrefix("formatlog.");
  iora::util::removeFilesMatchingPrefix("formatlog2.");
}

TEST_CASE("Logger Thread ID Formatting", "[logger][threadid]")
{
  iora::util::removeFilesMatchingPrefix("threadidlog.");

  iora::core::Logger::init(iora::core::Logger::Level::Info, "threadidlog", false);
  iora::core::Logger::setLogFormat("[%t] %m");

  SECTION("Consistent thread ID format")
  {
    IORA_LOG_INFO("Main thread message 1");
    IORA_LOG_INFO("Main thread message 2");

    std::thread worker([]()
    {
      IORA_LOG_INFO("Worker thread message");
    });
    worker.join();

    iora::core::Logger::shutdown();

    std::string logFile = "threadidlog." + iora::core::Logger::currentDate() + ".log";
    std::ifstream in(logFile);
    REQUIRE(in.is_open());

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line))
    {
      lines.push_back(line);
    }

    REQUIRE(lines.size() == 3);

    // Extract thread IDs (between first [ and ])
    auto extractThreadId = [](const std::string &line) -> std::string
    {
      size_t start = line.find('[');
      size_t end = line.find(']');
      if (start != std::string::npos && end != std::string::npos)
      {
        return line.substr(start + 1, end - start - 1);
      }
      return "";
    };

    std::string mainThread1 = extractThreadId(lines[0]);
    std::string mainThread2 = extractThreadId(lines[1]);
    std::string workerThread = extractThreadId(lines[2]);

    // Main thread IDs should be identical
    REQUIRE(mainThread1 == mainThread2);

    // Worker thread ID should be different from main
    REQUIRE(mainThread1 != workerThread);

    // Thread IDs should be hex format (platform-specific width)
    REQUIRE(mainThread1.length() == sizeof(std::size_t) * 2);
    REQUIRE(workerThread.length() == sizeof(std::size_t) * 2);

    // All characters should be hex digits
    auto isHex = [](const std::string &s)
    {
      for (char c : s)
      {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
        {
          return false;
        }
      }
      return true;
    };
    REQUIRE(isHex(mainThread1));
    REQUIRE(isHex(workerThread));
  }

  iora::util::removeFilesMatchingPrefix("threadidlog.");
}

TEST_CASE("Logger Timestamp Consistency", "[logger][timestamp]")
{
  iora::util::removeFilesMatchingPrefix("timestamplog.");

  iora::core::Logger::init(iora::core::Logger::Level::Info, "timestamplog", false);
  iora::core::Logger::setLogFormat("[%T] [%T] %m");

  SECTION("Same timestamp appears multiple times in format")
  {
    IORA_LOG_INFO("Timestamp test");
    iora::core::Logger::shutdown();

    std::string logFile = "timestamplog." + iora::core::Logger::currentDate() + ".log";
    std::ifstream in(logFile);
    REQUIRE(in.is_open());

    std::string line;
    std::getline(in, line);

    // Extract both timestamps
    size_t firstOpen = line.find('[');
    size_t firstClose = line.find(']');
    size_t secondOpen = line.find('[', firstClose);
    size_t secondClose = line.find(']', secondOpen);

    REQUIRE(firstOpen != std::string::npos);
    REQUIRE(firstClose != std::string::npos);
    REQUIRE(secondOpen != std::string::npos);
    REQUIRE(secondClose != std::string::npos);

    std::string timestamp1 = line.substr(firstOpen + 1, firstClose - firstOpen - 1);
    std::string timestamp2 = line.substr(secondOpen + 1, secondClose - secondOpen - 1);

    // Both timestamps should be identical (generated once and cached)
    REQUIRE(timestamp1 == timestamp2);
  }

  iora::util::removeFilesMatchingPrefix("timestamplog.");
}

TEST_CASE("Logger Backward Compatibility", "[logger][compat]")
{
  iora::util::removeFilesMatchingPrefix("compatlog.");

  SECTION("Old-style logging still works")
  {
    iora::core::Logger::init(iora::core::Logger::Level::Info, "compatlog", false);

    // Old stream-style without source location
    iora::core::Logger << iora::core::Logger::Level::Info << "Old style message"
                       << iora::core::Logger::endl;

    // Old log method without source location
    iora::core::Logger::info("Direct info message");

    iora::core::Logger::shutdown();

    std::string logFile = "compatlog." + iora::core::Logger::currentDate() + ".log";
    std::ifstream in(logFile);
    REQUIRE(in.is_open());

    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    REQUIRE(content.find("Old style message") != std::string::npos);
    REQUIRE(content.find("Direct info message") != std::string::npos);
  }

  iora::util::removeFilesMatchingPrefix("compatlog.");
}
