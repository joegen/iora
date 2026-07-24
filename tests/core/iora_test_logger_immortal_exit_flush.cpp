// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// EXIT-OBSERVABILITY probe for tracker 2026-07-23-4 (M-a / M-b / preserve_exit_flush).
// Under option C ~LoggerData is never invoked, so the exit-time drain/flush it used
// to perform is replaced by a std::atexit handler (atexitReapNoDestroy ->
// teardownAndReapWorker) that flushes WITHOUT destroying. This probe proves that
// buffered ASYNC output still reaches the sink at process exit WITHOUT an explicit
// Logger::shutdown().
//
// It uses fork(): the child sets up the logger (so no worker thread is inherited —
// fork copies only the calling thread), logs in async mode to a FILE sink, and
// calls std::exit(0) WITHOUT shutdown(). The atexit reap must flush the buffered
// records to the file. The parent then reads the file and asserts the records are
// present. A regression that loses exit-time output (e.g. a bare drain/flush that
// never runs, or ~LoggerData removed with no atexit replacement) leaves the file
// missing records; a hang is caught by the ctest TIMEOUT.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/core/logger.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

using iora::core::Logger;
namespace fs = std::filesystem;

namespace
{
// Slurp every regular file in `dir` into one string (the logger names the file
// baseName.YYYY-MM-DD.log, so we avoid recomputing the date and just read all).
std::string readAllFilesIn(const std::string &dir)
{
  std::string out;
  if (!fs::exists(dir))
  {
    return out;
  }
  for (const auto &entry : fs::directory_iterator(dir))
  {
    if (entry.is_regular_file())
    {
      std::ifstream in(entry.path());
      std::stringstream ss;
      ss << in.rdbuf();
      out += ss.str();
    }
  }
  return out;
}
} // namespace

TEST_CASE("exit-observability: a record enqueued AFTER shutdown() (no worker) "
          "reaches the file only via the atexit reap-without-destroy",
          "[logger][immortal][exit_flush]")
{
  iora::test::TempDirManager tmp("iora_logger_exitflush_");
  const std::string base = tmp.filePath("probe");

  // fork BEFORE any logger use so the child starts with no logger worker thread.
  const pid_t pid = fork();
  REQUIRE(pid >= 0);

  if (pid == 0)
  {
    // CHILD. The discriminator is DETERMINISTIC (no worker race): after shutdown()
    // the worker is joined and gone, but asyncMode stays true, so a subsequent
    // async Logger::info() pushes to the normal queue with NO drainer (verified:
    // logDispatch's async branch enqueues unconditionally). The ONLY thing that can
    // still flush that record to the file is the atexit reap (teardownAndReapWorker
    // -> drainNormalQueueLocked). If the atexit reap were removed/neutered
    // (-DIORA_LOGGER_TEST_MUTANT_NOREAP), the record would be lost and the parent's
    // assertion below fails — so this is non-vacuous by construction, not by timing.
    Logger::init(Logger::Level::Info, base, /*async=*/true);
    Logger::info("exitflush-early"); // delivered by the worker / shutdown flush
    Logger::shutdown();              // worker joined and gone; asyncMode stays true
    Logger::info("exitflush-late-reap-only"); // enqueued with no drainer
    std::exit(0); // ONLY the atexit reap can flush the late record
  }

  // PARENT: wait for the child, then verify BOTH records landed in the file — the
  // late one proves the atexit reap flushed a record no worker could have drained.
  int status = 0;
  REQUIRE(waitpid(pid, &status, 0) == pid);
  REQUIRE(WIFEXITED(status));
  REQUIRE(WEXITSTATUS(status) == 0);

  const std::string contents = readAllFilesIn(tmp.path());
  CHECK(contents.find("exitflush-early") != std::string::npos);
  CHECK(contents.find("exitflush-late-reap-only") != std::string::npos);
}

TEST_CASE("exit-observability: async + external handler installed exits cleanly at "
          "process exit without shutdown() (reap reroutes and detaches)",
          "[logger][immortal][exit_flush][handler]")
{
  // With a handler installed, records go to rawQueue; the atexit reap reroutes the
  // backlog and reaps the worker. This asserts the with-handler atexit path exits
  // cleanly (no hang, no crash) — the content-level reroute-to-file is exercised by
  // the shutdown-path tests that share teardownAndReapWorker. fork so the child
  // process actually exits through atexit.
  const pid_t pid = fork();
  REQUIRE(pid >= 0);

  if (pid == 0)
  {
    Logger::init(Logger::Level::Info, "", /*async=*/true);
    Logger::setExternalHandler(
      [](Logger::Level, const std::string &, const std::string &) {});
    Logger::info("handler-backlog-1");
    Logger::info("handler-backlog-2");
    std::exit(0); // no shutdown(): the atexit reap must not hang or crash
  }

  int status = 0;
  REQUIRE(waitpid(pid, &status, 0) == pid);
  REQUIRE(WIFEXITED(status));
  CHECK(WEXITSTATUS(status) == 0);
}
