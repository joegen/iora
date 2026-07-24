// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.
//
// Regression suite for the batched logger fix (trackers 2026-07-23-3 +
// 2026-07-23-5): an empty external handler must not permanently disable file
// logging, and file logging must be restored after a set/clear handler cycle.
// The two root causes share the rotateLogFileIfNeeded reopen path and are
// verified together here.

#define CATCH_CONFIG_MAIN
#include "logger_race_harness.hpp"
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace
{
// Read a whole file into a string (empty string if absent).
std::string readWholeFile(const std::string &path)
{
  std::ifstream in(path, std::ios::binary);
  if (!in.is_open())
  {
    return {};
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

// The dated log file for a given init() base prefix (matches the naming in
// rotateLogFileIfNeeded: "<base>.<YYYY-MM-DD>.log").
std::string datedLogFile(const std::string &base)
{
  return base + "." + iora::core::Logger::currentDate() + ".log";
}

// Count files in the CWD whose name starts with "<base>." — used to prove a
// reopen APPENDS to the same dated file rather than spawning a new one.
int countFilesWithPrefix(const std::string &base)
{
  namespace fs = std::filesystem;
  const std::string prefix = base + ".";
  int n = 0;
  for (const auto &entry : fs::directory_iterator(fs::current_path()))
  {
    if (entry.is_regular_file() && entry.path().filename().string().rfind(prefix, 0) == 0)
    {
      ++n;
    }
  }
  return n;
}

// A capture handler that records the raw messages it receives. Shared across
// the whole file; guarded because the async worker AND a flush() on another
// thread may both invoke it.
std::mutex g_captureMutex;
std::vector<std::string> g_captured;

void captureHandler(iora::core::Logger::Level, const std::string &, const std::string &raw)
{
  std::lock_guard<std::mutex> lock(g_captureMutex);
  g_captured.push_back(raw);
}

std::vector<std::string> takeCaptured()
{
  std::lock_guard<std::mutex> lock(g_captureMutex);
  auto copy = g_captured;
  return copy;
}

void clearCaptured()
{
  std::lock_guard<std::mutex> lock(g_captureMutex);
  g_captured.clear();
}

// Leave the logger in a clean state for the next TEST_CASE: no handler
// installed (clearExternalHandler nulls useExternalHandler even if a prior test
// left it armed — this defends against the init()-does-not-reset-handler defect
// tracked in backlog 2026-07-24-1).
void resetLogger()
{
  iora::core::Logger::clearExternalHandler();
}

// Locked white-box accessors. The fields are mutex-guarded; these tests are
// sync-mode/single-threaded so an unlocked read would be race-free in practice,
// but taking the lock keeps the access discipline uniform (and TSan-clean if a
// case is ever copied into an async context).
const std::ofstream *lockedFileStream()
{
  std::lock_guard<std::mutex> lk(iora::core::Logger::getData().mutex);
  return iora::core::Logger::getData().fileStream.get();
}

bool lockedReopenPending()
{
  std::lock_guard<std::mutex> lk(iora::core::Logger::getData().mutex);
  return iora::core::Logger::getData().fileReopenPending;
}

// Release a parked blocking handler once the uninstall's tear-out has nulled the
// gate (useExternalHandler == false), so the worker cannot deliver the queued
// backlog to the handler and the tear-out reroutes it instead. Bounded so a
// regression can never wedge the suite; releases unconditionally on timeout so the
// pending set/clear can always complete. Lives here (not in logger_race_harness.hpp)
// because it is logger-coupled — the harness is deliberately logger-agnostic.
std::thread spawnReleaseWhenHandlerCleared(iora::test::CtlPtr ctl)
{
  return std::thread(
    [ctl]
    {
      for (int i = 0; i < 5000; ++i)
      {
        {
          std::lock_guard<std::mutex> lk(iora::core::Logger::getData().mutex);
          if (!iora::core::Logger::getData().useExternalHandler)
          {
            break;
          }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
      ctl->releaseAll();
    });
}

// RAII guard that force-enables console colors (production gates this on _isTTY,
// which is false under ctest) for the guard's lifetime and restores it on ANY
// exit path — so a failing REQUIRE mid-test cannot leak the flag into later cases.
// Writes under data.mutex to keep the otherwise mutex-guarded field consistent.
struct ForcedConsoleColors
{
  ForcedConsoleColors()
  {
    std::lock_guard<std::mutex> lk(iora::core::Logger::getData().mutex);
    iora::core::Logger::getData()._enableConsoleColors = true;
  }
  ~ForcedConsoleColors()
  {
    std::lock_guard<std::mutex> lk(iora::core::Logger::getData().mutex);
    iora::core::Logger::getData()._enableConsoleColors = false;
  }
  ForcedConsoleColors(const ForcedConsoleColors &) = delete;
  ForcedConsoleColors &operator=(const ForcedConsoleColors &) = delete;
};
} // namespace

// --- Test 1: an empty-handler install restores file logging (23-3 + 23-5) ---
// A real handler suppresses file logging; installing an EMPTY handler is an
// uninstall, and the NEXT log must reach the FILE again. Fails on the current
// code: setExternalHandler({}) arms useExternalHandler with a null handler
// (23-3) and the closed stream is never reopened (23-5), so output degrades to
// std::cout.
TEST_CASE("empty handler install restores file logging", "[logger][handler][filerestore]")
{
  resetLogger();
  clearCaptured();
  iora::util::removeFilesMatchingPrefix("t1restore.");

  iora::core::Logger::init(iora::core::Logger::Level::Info, "t1restore", false);
  iora::core::Logger::info("before-handler");

  iora::core::Logger::setExternalHandler(captureHandler);
  iora::core::Logger::info("during-handler"); // to handler, not file

  iora::core::Logger::setExternalHandler({}); // empty == uninstall
  iora::core::Logger::info("after-empty");    // must reach the FILE
  iora::core::Logger::flush();

  const std::string content = readWholeFile(datedLogFile("t1restore"));
  REQUIRE(content.find("before-handler") != std::string::npos);
  REQUIRE(content.find("after-empty") != std::string::npos);
  // The handler-window message must NOT be in the file (exclusive handler).
  REQUIRE(content.find("during-handler") == std::string::npos);
  // ...and the handler must have received it.
  const auto captured = takeCaptured();
  REQUIRE(captured.size() == 1);
  REQUIRE(captured.front() == "during-handler");

  resetLogger();
  iora::util::removeFilesMatchingPrefix("t1restore.");
}

// --- Test 2: empty install with NO prior handler does not disturb the file ---
// The stream must not be spuriously closed+reopened (white-box: the fileStream
// pointer identity is preserved by the hasHandler-guarded close), and both
// records land in the file.
TEST_CASE("empty handler install with no prior handler is a no-op for the file",
          "[logger][handler][filerestore]")
{
  resetLogger();
  clearCaptured();
  iora::util::removeFilesMatchingPrefix("t2noop.");

  iora::core::Logger::init(iora::core::Logger::Level::Info, "t2noop", false);
  iora::core::Logger::info("open-file");
  iora::core::Logger::flush();

  const auto *streamBefore = lockedFileStream();
  REQUIRE(streamBefore != nullptr);

  iora::core::Logger::setExternalHandler({}); // empty, nothing was installed
  iora::core::Logger::info("after-empty");
  iora::core::Logger::flush();

  const auto *streamAfter = lockedFileStream();
  // Same stream object — the empty install must not have closed+reopened it.
  REQUIRE(streamAfter == streamBefore);

  const std::string content = readWholeFile(datedLogFile("t2noop"));
  REQUIRE(content.find("open-file") != std::string::npos);
  REQUIRE(content.find("after-empty") != std::string::npos);
  REQUIRE(countFilesWithPrefix("t2noop") == 1);

  resetLogger();
  iora::util::removeFilesMatchingPrefix("t2noop.");
}

// --- Test 4: file logging restored after a set/clear cycle (23-5 core) ---
TEST_CASE("file logging restored after setExternalHandler/clearExternalHandler cycle",
          "[logger][handler][filerestore]")
{
  resetLogger();
  clearCaptured();
  iora::util::removeFilesMatchingPrefix("t4cycle.");

  iora::core::Logger::init(iora::core::Logger::Level::Info, "t4cycle", false);
  iora::core::Logger::info("phase-file-1");
  iora::core::Logger::flush();
  const std::string afterFirst = readWholeFile(datedLogFile("t4cycle"));
  REQUIRE(afterFirst.find("phase-file-1") != std::string::npos);
  const auto sizeAfterFirst = afterFirst.size();

  iora::core::Logger::setExternalHandler(captureHandler);
  iora::core::Logger::info("phase-handler");
  iora::core::Logger::flush();
  // File must not have grown while the handler was active.
  REQUIRE(readWholeFile(datedLogFile("t4cycle")).size() == sizeAfterFirst);

  iora::core::Logger::clearExternalHandler();
  iora::core::Logger::info("phase-file-2"); // must reach the FILE again
  iora::core::Logger::flush();

  const std::string content = readWholeFile(datedLogFile("t4cycle"));
  REQUIRE(content.find("phase-file-1") != std::string::npos);
  REQUIRE(content.find("phase-file-2") != std::string::npos);
  REQUIRE(content.find("phase-handler") == std::string::npos);

  const auto captured = takeCaptured();
  REQUIRE(captured.size() == 1);
  REQUIRE(captured.front() == "phase-handler");

  resetLogger();
  iora::util::removeFilesMatchingPrefix("t4cycle.");
}

// --- Test 5: the restore is not date-dependent (two cycles within one day) ---
TEST_CASE("file logging restored across two handler cycles in one day",
          "[logger][handler][filerestore]")
{
  resetLogger();
  clearCaptured();
  iora::util::removeFilesMatchingPrefix("t5twice.");

  iora::core::Logger::init(iora::core::Logger::Level::Info, "t5twice", false);

  for (int cycle = 1; cycle <= 2; ++cycle)
  {
    const std::string marker = "cycle-" + std::to_string(cycle);
    iora::core::Logger::setExternalHandler(captureHandler);
    iora::core::Logger::info(marker + "-handler");
    iora::core::Logger::clearExternalHandler();
    iora::core::Logger::info(marker + "-file");
    iora::core::Logger::flush();
    const std::string content = readWholeFile(datedLogFile("t5twice"));
    REQUIRE(content.find(marker + "-file") != std::string::npos);
    REQUIRE(content.find(marker + "-handler") == std::string::npos);
  }

  resetLogger();
  iora::util::removeFilesMatchingPrefix("t5twice.");
}

// --- Test 6: the reopen APPENDS to the same dated file (no spurious rotation) ---
TEST_CASE("reopen after handler cycle appends to the same dated file",
          "[logger][handler][filerestore]")
{
  resetLogger();
  clearCaptured();
  iora::util::removeFilesMatchingPrefix("t6append.");

  iora::core::Logger::init(iora::core::Logger::Level::Info, "t6append", false);
  iora::core::Logger::info("first");
  iora::core::Logger::flush();

  iora::core::Logger::setExternalHandler(captureHandler);
  iora::core::Logger::info("mid");
  iora::core::Logger::clearExternalHandler();
  iora::core::Logger::info("second");
  iora::core::Logger::flush();

  // Exactly one dated file, containing both file-destined records in order.
  REQUIRE(countFilesWithPrefix("t6append") == 1);
  const std::string content = readWholeFile(datedLogFile("t6append"));
  const auto posFirst = content.find("first");
  const auto posSecond = content.find("second");
  REQUIRE(posFirst != std::string::npos);
  REQUIRE(posSecond != std::string::npos);
  REQUIRE(posFirst < posSecond); // appended, not truncated/rotated

  resetLogger();
  iora::util::removeFilesMatchingPrefix("t6append.");
}

// --- Test 3: empty install reroutes a queued async backlog to the file --------
// (lossless, matching clearExternalHandler; no worker busy-spin). Uses the race
// harness to hold the worker inside the handler so a rawQueue backlog provably
// accumulates before the uninstall.
TEST_CASE("empty handler install reroutes async backlog to the file losslessly",
          "[logger][handler][filerestore]")
{
  resetLogger();
  clearCaptured();
  iora::util::removeFilesMatchingPrefix("t3reroute.");

  auto ctl = iora::test::makeCtl();

  iora::core::Logger::init(iora::core::Logger::Level::Info, "t3reroute", true); // async

  // Handler records the raw message, then parks in the rendezvous window so the
  // worker cannot drain the following entries — they pile into rawQueue.
  auto handler = [ctl](iora::core::Logger::Level, const std::string &, const std::string &raw)
  {
    captureHandler(iora::core::Logger::Level::Info, "", raw);
    iora::test::blockingHandlerBody(*ctl);
  };
  iora::core::Logger::setExternalHandler(handler);

  iora::core::Logger::info("h1");     // worker records h1, then parks
  REQUIRE(ctl->waitEntered(1));       // handler is provably in flight
  iora::core::Logger::info("q1");     // piles into rawQueue (worker busy)
  iora::core::Logger::info("q2");

  // Release the parked handler only AFTER the uninstall's tear-out has nulled the
  // gate, so the worker cannot deliver q1/q2 to the handler and the tear-out
  // reroutes them instead (see the helper's contract).
  std::thread releaser = spawnReleaseWhenHandlerCleared(ctl);

  iora::core::Logger::setExternalHandler({}); // uninstall: reroutes q1/q2
  releaser.join();

  iora::core::Logger::info("after");
  iora::core::Logger::flush();
  iora::core::Logger::shutdown(); // fully drain the worker before reading

  const std::string content = readWholeFile(datedLogFile("t3reroute"));
  // The backlog was rerouted to the file (lossless), not dropped.
  REQUIRE(content.find("q1") != std::string::npos);
  REQUIRE(content.find("q2") != std::string::npos);
  REQUIRE(content.find("after") != std::string::npos);
  // h1 was delivered to the handler, not the file.
  const auto captured = takeCaptured();
  REQUIRE_FALSE(captured.empty());
  REQUIRE(captured.front() == "h1");
  REQUIRE(content.find("h1") == std::string::npos);

  resetLogger();
  iora::util::removeFilesMatchingPrefix("t3reroute.");
}

// --- Test 7: an open failure after a handler cycle is bounded to ONE attempt --
// The fileReopenPending one-shot must be consumed even when the reopen fails, so
// a persistently unopenable path cannot re-enter the reopen branch on every log
// (the storm the naive `|| !fileStream` guard would have caused). White-box on
// fileReopenPending because a fallback-to-cout is otherwise not observable.
TEST_CASE("open failure after handler cycle does not storm (one-shot reopen)",
          "[logger][handler][filerestore]")
{
  namespace fs = std::filesystem;
  resetLogger();
  clearCaptured();
  iora::util::removeFilesMatchingPrefix("t7openfail.");

  iora::core::Logger::init(iora::core::Logger::Level::Info, "t7openfail", false);
  iora::core::Logger::info("a");
  iora::core::Logger::flush();

  iora::core::Logger::setExternalHandler(captureHandler); // closes stream, arms fileReopenPending
  iora::core::Logger::info("mid");
  iora::core::Logger::setExternalHandler({}); // uninstall; fileReopenPending still armed

  // Make the reopen FAIL (dir exists, but the target path is now a directory so
  // the ofstream open fails) without tripping the create_directories early-return.
  const std::string dated = datedLogFile("t7openfail");
  fs::remove(dated);
  fs::create_directory(dated);

  iora::core::Logger::info("b1"); // reopen attempt: enters branch, open fails, pending consumed
  REQUIRE(lockedReopenPending() == false);
  REQUIRE(lockedFileStream() == nullptr);

  iora::core::Logger::info("b2"); // must NOT re-enter the reopen branch (no storm)
  iora::core::Logger::info("b3");
  REQUIRE(lockedReopenPending() == false);
  REQUIRE(lockedFileStream() == nullptr);

  fs::remove_all(dated);
  resetLogger();
  iora::util::removeFilesMatchingPrefix("t7openfail.");
}

// --- Test 8: a real date rollover still rotates (coexists with fileReopenPending)
TEST_CASE("date rollover still opens a fresh stream", "[logger][handler][filerestore]")
{
  resetLogger();
  clearCaptured();
  iora::util::removeFilesMatchingPrefix("t8roll.");

  iora::core::Logger::init(iora::core::Logger::Level::Info, "t8roll", false);
  iora::core::Logger::info("today1");
  iora::core::Logger::flush();
  const auto *streamBefore = lockedFileStream();
  REQUIRE(streamBefore != nullptr);

  // Simulate a date rollover: rewind currentLogDate so the next log sees a date
  // change (fileReopenPending stays false — this is the rotation path, not the
  // reopen path).
  {
    std::lock_guard<std::mutex> lk(iora::core::Logger::getData().mutex);
    iora::core::Logger::getData().currentLogDate = "2000-01-01";
  }
  iora::core::Logger::info("today2");
  iora::core::Logger::flush();

  const auto *streamAfter = lockedFileStream();
  REQUIRE(streamAfter != streamBefore); // a fresh stream was opened by rotation
  const std::string content = readWholeFile(datedLogFile("t8roll"));
  REQUIRE(content.find("today2") != std::string::npos);

  resetLogger();
  iora::util::removeFilesMatchingPrefix("t8roll.");
}

// --- Test 9a: console-only mode still colorizes (positive direction) ----------
// Colors are gated on _isTTY in production; ctest stdout is not a TTY, so force
// the flag directly (the field is otherwise mutex-guarded — take the lock).
TEST_CASE("console-only mode colorizes output", "[logger][handler][filerestore][color]")
{
  resetLogger();
  clearCaptured();

  iora::core::Logger::init(iora::core::Logger::Level::Info, "", false); // console-only, sync
  ForcedConsoleColors colors;                                          // restored on any exit
  {
    std::lock_guard<std::mutex> lk(iora::core::Logger::getData().mutex);
    // Drop any file stream left open by a prior file-mode test: init("") does NOT
    // close a stale stream (pre-existing defect, backlog 2026-07-24-1 facet B), so
    // without this a console-only write would go to the prior test's file/inode
    // instead of cout. Remove once 2026-07-24-1 lands.
    iora::core::Logger::getData().fileStream.reset();
  }

  std::ostringstream captured;
  auto *old = std::cout.rdbuf(captured.rdbuf());
  iora::core::Logger::info("consolecolor");
  std::cout.rdbuf(old); // restore BEFORE any REQUIRE (Catch2 writes to cout)

  REQUIRE(captured.str().find("consolecolor") != std::string::npos);
  REQUIRE(captured.str().find("\x1b[") != std::string::npos); // ANSI present

  resetLogger();
}

// --- Test 9b: a configured file never receives ANSI across a handler cycle ----
// This is the enqueue-vs-drain staleness the logBasePath.empty() predicate
// eliminates. The DETERMINISTIC vehicle is the REROUTE path: on an empty-handler
// uninstall, rerouteRawQueueToNormalQueueLocked colorizes the queued backlog
// UNDER THE LOCK while fileStream is provably null, and the entries are then
// written to the reopened file. (A fresh post-uninstall async log is NOT a
// reliable vehicle: whether it is colorized races the worker's reopen.) The race
// harness holds the worker in the handler so q1/q2 provably sit in rawQueue and
// are rerouted while fileStream is null.
TEST_CASE("configured file never receives ANSI across a handler cycle",
          "[logger][handler][filerestore][color]")
{
  resetLogger();
  clearCaptured();
  iora::util::removeFilesMatchingPrefix("t9file.");

  auto ctl = iora::test::makeCtl();

  iora::core::Logger::init(iora::core::Logger::Level::Info, "t9file", true); // async, file
  ForcedConsoleColors colors;                                               // restored on any exit

  auto handler = [ctl](iora::core::Logger::Level, const std::string &, const std::string &raw)
  {
    captureHandler(iora::core::Logger::Level::Info, "", raw);
    iora::test::blockingHandlerBody(*ctl);
  };
  iora::core::Logger::setExternalHandler(handler); // real -> closes file, arms reopen
  iora::core::Logger::info("h1");
  REQUIRE(ctl->waitEntered(1));
  iora::core::Logger::info("q1color"); // pile into rawQueue while fileStream is null
  iora::core::Logger::info("q2color");

  std::thread releaser = spawnReleaseWhenHandlerCleared(ctl);

  iora::core::Logger::setExternalHandler({}); // reroutes q1color/q2color (fileStream null)
  releaser.join();

  iora::core::Logger::flush();
  iora::core::Logger::shutdown();

  const std::string content = readWholeFile(datedLogFile("t9file"));
  // The rerouted backlog reached the file (via the reopen)...
  REQUIRE(content.find("q1color") != std::string::npos);
  REQUIRE(content.find("q2color") != std::string::npos);
  // ...in PLAIN text — no ANSI escape codes were written into the file.
  REQUIRE(content.find("\x1b[") == std::string::npos);

  resetLogger();
  iora::util::removeFilesMatchingPrefix("t9file.");
}
