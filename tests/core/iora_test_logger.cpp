// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>
#include <regex>

namespace
{
// Per-thread recursion depth for the handler-reentry-via-flush regression test.
// Detects SAME-THREAD nesting (the flush() recursion) while ignoring benign
// cross-thread concurrency (the worker and shutdown's flush both draining).
int &testHandlerDepth()
{
  static thread_local int depth = 0;
  return depth;
}

// RAII bracket for testHandlerDepth so the decrement runs even if the handler
// body throws (exception-safe; avoids a leaked depth tripping a later assertion).
struct TestHandlerDepthGuard
{
  TestHandlerDepthGuard() { ++testHandlerDepth(); }
  ~TestHandlerDepthGuard() { --testHandlerDepth(); }
  TestHandlerDepthGuard(const TestHandlerDepthGuard &) = delete;
  TestHandlerDepthGuard &operator=(const TestHandlerDepthGuard &) = delete;
};
} // namespace

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

    // Default Logger format is "%Y-%m-%d %H:%M:%S"; timestamp() appends a
    // ".NNN" 3-digit millisecond suffix when the format contains "%S".
    // Regress-guard the localtime_r / struct-tm timestamp-formatting path.
    std::regex tsPattern(R"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})");
    REQUIRE(std::regex_match(timestamp1, tsPattern));
    REQUIRE(timestamp1 != "[invalid-time]");
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

TEST_CASE("Logger Direct-Call Implicit Source Location", "[logger][sourceloc][direct]")
{
  iora::util::removeFilesMatchingPrefix("directloc.");

  SECTION("info() captures the caller's file, line and function without a macro")
  {
    iora::core::Logger::init(iora::core::Logger::Level::Info, "directloc", false);
    iora::core::Logger::setLogFormat("[%F:%l %f] %m");

    // The call MUST stay on a single line: __builtin_LINE() resolves to the
    // call-expression line, so a split call would shift the captured line.
    int testLine = __LINE__ + 1;
    iora::core::Logger::info("Direct implicit source location");
    iora::core::Logger::shutdown();

    std::string logFile = "directloc." + iora::core::Logger::currentDate() + ".log";
    std::ifstream in(logFile);
    REQUIRE(in.is_open());

    std::string line;
    std::getline(in, line);

    // Filename only (basename-extracted), never the full path.
    REQUIRE(line.find("iora_test_logger.cpp") != std::string::npos);
    REQUIRE(line.find("/workspace") == std::string::npos);
    // The captured line number equals the caller's line.
    REQUIRE(line.find(":" + std::to_string(testLine) + " ") != std::string::npos);
    // Format shape [filename:line function] message, function name non-empty.
    REQUIRE(line.find("[iora_test_logger.cpp:") != std::string::npos);
    REQUIRE(line.find("Direct implicit source location") != std::string::npos);
  }

  iora::util::removeFilesMatchingPrefix("directloc.");
}

TEST_CASE("Logger Direct-Call Source Location — All Six Levels", "[logger][sourceloc][direct]")
{
  iora::util::removeFilesMatchingPrefix("directall.");

  SECTION("trace/debug/info/warning/error/fatal each capture non-blank location")
  {
    // trace() and debug() are filtered at the default Info min level — init at
    // Trace so all six actually emit.
    iora::core::Logger::init(iora::core::Logger::Level::Trace, "directall", false);
    iora::core::Logger::setLogFormat("[%L] [%F:%l %f] %m");

    iora::core::Logger::trace("m-trace");
    iora::core::Logger::debug("m-debug");
    iora::core::Logger::info("m-info");
    iora::core::Logger::warning("m-warning");
    iora::core::Logger::error("m-error");
    iora::core::Logger::fatal("m-fatal");
    iora::core::Logger::shutdown();

    std::string logFile = "directall." + iora::core::Logger::currentDate() + ".log";
    std::ifstream in(logFile);
    REQUIRE(in.is_open());
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());

    // Every level emitted a line carrying the source-location prefix.
    for (const char *msg : {"m-trace", "m-debug", "m-info", "m-warning", "m-error", "m-fatal"})
    {
      std::string::size_type at = content.find(msg);
      REQUIRE(at != std::string::npos);
      std::string::size_type lineStart = content.rfind('\n', at);
      lineStart = (lineStart == std::string::npos) ? 0 : lineStart + 1;
      std::string logLine = content.substr(lineStart, at - lineStart);
      // Non-blank file basename + ":" line-number prefix on this line. (The %f
      // function token is deliberately not asserted — its spelling varies by
      // compiler, matching the pre-existing sourceloc test's approach.)
      REQUIRE(logLine.find("[iora_test_logger.cpp:") != std::string::npos);
    }
  }

  iora::util::removeFilesMatchingPrefix("directall.");
}

TEST_CASE("Logger Direct-Call Location Omitted From Non-Placeholder Formats",
          "[logger][sourceloc][direct]")
{
  iora::util::removeFilesMatchingPrefix("directnoloc.");

  SECTION("A format without %F/%l/%f renders no location for a direct call")
  {
    iora::core::Logger::init(iora::core::Logger::Level::Info, "directnoloc", false);
    iora::core::Logger::setLogFormat("[%L] %m");
    iora::core::Logger::info("no location here");
    iora::core::Logger::shutdown();

    std::string logFile = "directnoloc." + iora::core::Logger::currentDate() + ".log";
    std::ifstream in(logFile);
    REQUIRE(in.is_open());
    std::string line;
    std::getline(in, line);

    REQUIRE(line.find("[INFO]") != std::string::npos);
    REQUIRE(line.find("no location here") != std::string::npos);
    // The now-captured source-location args must NOT leak into a format that
    // omits the placeholders (byte-identical to the pre-change behavior).
    REQUIRE(line.find("iora_test_logger.cpp") == std::string::npos);
    REQUIRE(line.find(__func__) == std::string::npos);
  }

  iora::util::removeFilesMatchingPrefix("directnoloc.");
}

TEST_CASE("Logger Direct-Call Source Location Through External Handlers",
          "[logger][sourceloc][direct][handler]")
{
  // Sync mode renders location into the handler's formattedMessage; async mode
  // re-formats from the raw {level, message} queue and therefore blanks it.
  struct Capture
  {
    std::mutex m;
    std::string formatted;
  };

  // RAII: guarantees the process-global handler is torn out before `cap` dies,
  // even if a REQUIRE or Logger call throws mid-section. init() does not clear a
  // prior handler, so a leaked lambda capturing &cap would dangle once the
  // SECTION unwinds. Declared AFTER `cap` in each section so it destructs first
  // (clears the handler while `cap` is still alive).
  struct HandlerGuard
  {
    ~HandlerGuard() { iora::core::Logger::clearExternalHandler(); }
  };

  SECTION("Synchronous handler receives rendered %F/%l/%f in formattedMessage")
  {
    Capture cap;
    HandlerGuard guard;
    iora::core::Logger::init(iora::core::Logger::Level::Info, "", false);
    iora::core::Logger::setLogFormat("[%F:%l %f] %m");
    iora::core::Logger::setExternalHandler(
      [&cap](iora::core::Logger::Level, const std::string &formattedMessage,
             const std::string &)
      {
        std::lock_guard<std::mutex> lk(cap.m);
        cap.formatted = formattedMessage;
      });

    // Sync handler runs inline on this thread inside info(); cap.formatted is set
    // before info() returns. (The write-before-read ordering is supplied by that
    // same-thread sequencing, not by cap.m; the mutex only guards the field.)
    iora::core::Logger::info("sync handler location");
    iora::core::Logger::shutdown();

    std::lock_guard<std::mutex> lk(cap.m);
    REQUIRE(cap.formatted.find("iora_test_logger.cpp:") != std::string::npos);
    REQUIRE(cap.formatted.find("sync handler location") != std::string::npos);
  }

  SECTION("Asynchronous handler receives blank location (re-formatted from raw queue)")
  {
    Capture cap;
    HandlerGuard guard;
    iora::core::Logger::init(iora::core::Logger::Level::Info, "", true);
    iora::core::Logger::setLogFormat("[%F:%l %f] %m");
    iora::core::Logger::setExternalHandler(
      [&cap](iora::core::Logger::Level, const std::string &formattedMessage,
             const std::string &)
      {
        std::lock_guard<std::mutex> lk(cap.m);
        cap.formatted = formattedMessage;
      });

    iora::core::Logger::info("async handler location");
    // shutdown()->flush() delivers the queued message while the handler is still
    // installed, then joins the worker. That join (NOT cap.m) supplies the
    // write-before-read happens-before for cap.formatted; cap.m only guards
    // against a data race on the field.
    iora::core::Logger::shutdown();

    std::lock_guard<std::mutex> lk(cap.m);
    REQUIRE(cap.formatted.find("async handler location") != std::string::npos);
    // Location is blank on the async path — the filename must be absent.
    REQUIRE(cap.formatted.find("iora_test_logger.cpp") == std::string::npos);
  }
}

TEST_CASE("Logger Sync Handler May Re-Enter Logger Without Deadlock",
          "[logger][handler][reentry]")
{
  // H-1 regression: the SYNCHRONOUS external-handler path must not hold the
  // internal mutex while invoking the user callback. If it did, a handler that
  // re-enters Logger would self-deadlock on the non-recursive mutex and hang this
  // test. getLogFormat() re-acquires the internal mutex (getLevel() is now
  // lock-free, so getLogFormat() is what exercises the re-entrant lock path).
  std::atomic<bool> reentered{false};
  iora::core::Logger::init(iora::core::Logger::Level::Info, "", false); // sync
  iora::core::Logger::setLogFormat("[%L] %m");
  iora::core::Logger::setExternalHandler(
    [&reentered](iora::core::Logger::Level, const std::string &, const std::string &)
    {
      (void)iora::core::Logger::getLogFormat();
      (void)iora::core::Logger::getLevel();
      reentered = true;
    });

  iora::core::Logger::info("trigger reentry");
  iora::core::Logger::shutdown();
  iora::core::Logger::clearExternalHandler();

  REQUIRE(reentered.load());
}

TEST_CASE("Logger Handler May Clear Itself Without Hanging", "[logger][handler][reentry]")
{
  // Self-call detection (handler-reentry depth, replacing the former
  // workerThreadId scheme): a handler that tears itself out via
  // clearExternalHandler from inside its own invocation must drain to inflight==1
  // (its own) rather than 0, or it would wait forever on its own in-flight count.
  // Exercised on both the sync path (handler runs on the calling thread) and the
  // async path (handler runs on the worker or the flushing thread).
  // NOTE: this covers a SINGLE in-flight invocation. The case of TWO concurrent
  // invocations of a self-clearing handler (worker + shutdown-flush) is a known
  // pre-existing deadlock tracked in backlog 2026-07-21-3 (P0) — not exercised
  // here on purpose (single message => single invocation).
  auto selfClearing = [](bool async)
  {
    std::atomic<int> calls{0};
    iora::core::Logger::init(iora::core::Logger::Level::Info, "", async);
    iora::core::Logger::setLogFormat("[%L] %m");
    iora::core::Logger::setExternalHandler(
      [&calls](iora::core::Logger::Level, const std::string &, const std::string &)
      {
        ++calls;
        iora::core::Logger::clearExternalHandler(); // self-tear-out, must not hang
      });

    iora::core::Logger::info("first");  // invokes handler, which clears itself
    iora::core::Logger::info("second"); // handler already cleared -> not invoked
    iora::core::Logger::shutdown();
    iora::core::Logger::clearExternalHandler(); // idempotent safety net
    return calls.load();
  };

  SECTION("sync") { REQUIRE(selfClearing(false) == 1); }
  SECTION("async") { REQUIRE(selfClearing(true) == 1); }
}

TEST_CASE("Logger Self-Logging Handler Does Not Recurse Unbounded",
          "[logger][handler][reentry]")
{
  // Regression for the copy-then-invoke hazard: a handler that logs from inside
  // itself must NOT re-invoke the handler (sync -> unbounded recursion / stack
  // overflow; async -> rawQueue refeed / worker livelock / shutdown hang). Every
  // handler-dispatch site (logDispatch async + sync, flush(), the worker loop)
  // gates on handlerReentryDepth()==0, routing a re-entrant handler-bound message
  // to the normal queue/console path, so the handler runs exactly once for one
  // outer message. Because all dispatch sites are gated, a handler cannot trigger
  // a nested handler invocation (depth stays <= 1); `target = handlerReentryDepth()`
  // remains the correct general drain form regardless.
  auto selfLogging = [](bool async)
  {
    std::atomic<int> calls{0};
    iora::core::Logger::init(iora::core::Logger::Level::Info, "", async);
    iora::core::Logger::setLogFormat("[%L] %m");
    iora::core::Logger::setExternalHandler(
      [&calls](iora::core::Logger::Level, const std::string &, const std::string &)
      {
        // Bound the re-logging so a REGRESSION (guard removed) cannot hang/crash
        // the test — it would instead reach calls==4 and fail the assertion.
        if (++calls <= 3)
        {
          iora::core::Logger::info("nested from handler");
        }
      });

    iora::core::Logger::info("outer");
    iora::core::Logger::shutdown();
    iora::core::Logger::clearExternalHandler();
    return calls.load();
  };

  SECTION("sync") { REQUIRE(selfLogging(false) == 1); }
  SECTION("async") { REQUIRE(selfLogging(true) == 1); }
}

TEST_CASE("Logger Handler Logging Via Stream Proxy Does Not Recurse Through flush",
          "[logger][handler][reentry]")
{
  // ts3-H-1 regression: LoggerStream::flush() calls Logger::flush(), which drains
  // the rawQueue and invokes the handler. If flush()'s drain were not gated on
  // handlerReentryDepth()==0, a handler that logs via the stream proxy would
  // re-invoke the handler on the remaining queued entries ON THE SAME THREAD ->
  // unbounded recursion (O(backlog) stack frames). With the gate, a queued entry
  // is delivered to the handler at most once and never nested on one thread.
  std::atomic<int> calls{0};
  std::atomic<bool> sameThreadReentry{false};
  iora::core::Logger::init(iora::core::Logger::Level::Info, "", true); // async
  iora::core::Logger::setLogFormat("[%L] %m");
  iora::core::Logger::setExternalHandler(
    [&](iora::core::Logger::Level, const std::string &, const std::string &)
    {
      TestHandlerDepthGuard depthGuard; // exception-safe ++/-- of testHandlerDepth
      if (testHandlerDepth() > 1)
      {
        sameThreadReentry = true; // handler re-entered on the same thread via flush
      }
      // Hard cap so a REGRESSION cannot hang/crash the test on a large backlog.
      if (++calls <= 20)
      {
        iora::core::Logger << iora::core::Logger::Level::Info << "nested via stream"
                           << iora::core::Logger::endl;
      }
    });

  // Backlog several messages so a handler runs while the rawQueue is non-empty.
  iora::core::Logger::info("outer-1");
  iora::core::Logger::info("outer-2");
  iora::core::Logger::info("outer-3");
  iora::core::Logger::shutdown();      // drains the backlog (worker + flush)
  iora::core::Logger::clearExternalHandler();

  // The handler must never be re-entered on the same thread via flush().
  REQUIRE_FALSE(sameThreadReentry.load());
  // Each of the three outer messages is delivered to the handler exactly once.
  REQUIRE(calls.load() == 3);
}

TEST_CASE("Logger Clear External Handler With Async Backlog Does Not Orphan rawQueue",
          "[logger][handler][reentry]")
{
  // ts4-H-1 regression: clearing an external handler while async messages are
  // still queued for it must NOT orphan those entries in rawQueue. An orphaned
  // non-empty rawQueue keeps the worker's cv predicate satisfied while the drain
  // loop is gated off (useExternalHandler==false) -> 100% CPU busy-spin. The fix
  // reroutes the backlog to the normal queue and gates the predicate, so clear +
  // shutdown complete promptly and the removed handler does not receive the
  // backlog. A latch holds the first invocation so a backlog reliably accumulates.
  std::mutex m;
  std::condition_variable cv;
  bool release = false;
  std::atomic<int> handlerCalls{0};

  iora::core::Logger::init(iora::core::Logger::Level::Info, "", true); // async
  iora::core::Logger::setLogFormat("[%L] %m");
  iora::core::Logger::setExternalHandler(
    [&](iora::core::Logger::Level, const std::string &, const std::string &)
    {
      if (++handlerCalls == 1)
      {
        // Block the first invocation so m2..m4 pile up in rawQueue behind it.
        std::unique_lock<std::mutex> lk(m);
        cv.wait(lk, [&] { return release; });
      }
    });

  iora::core::Logger::info("m1");
  while (handlerCalls.load() == 0) // wait until the worker is inside the blocked handler
  {
    std::this_thread::yield();
  }
  iora::core::Logger::info("m2"); // queued behind the blocked handler
  iora::core::Logger::info("m3");
  iora::core::Logger::info("m4");

  {
    std::lock_guard<std::mutex> lk(m);
    release = true;
  }
  cv.notify_all();
  iora::core::Logger::clearExternalHandler(); // reroutes the backlog; must not spin/hang
  iora::core::Logger::shutdown();             // completes promptly (no orphaned-queue spin)

  // m1 reached the handler; the backlog (m2..m4) was rerouted, not re-delivered.
  // (The exact count depends on the clear-vs-worker race, but is bounded to the
  // four messages and must include at least m1 — never a phantom re-invocation.)
  REQUIRE(handlerCalls.load() >= 1);
  REQUIRE(handlerCalls.load() <= 4);
}
