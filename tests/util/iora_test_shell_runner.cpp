// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include "../test_helpers.hpp"
#include <iora/system/shell_runner.hpp>
#include <catch2/catch.hpp>
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <iterator>
#include <thread>
#include <dirent.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string>
#include <sstream>
#include <cstdio>
#include <fstream>
#include <regex>

using namespace iora::system;

namespace
{
// A path under /tmp unique to this test process, so parallel runs never collide.
std::string tmpPath(const std::string &name)
{
  return "/tmp/iora_test_" + name + "_" + std::to_string(getpid()) + ".txt";
}

// A command-line token unique to this test process, so /proc pattern matches
// never pick up unrelated processes (or a concurrent run of this binary).
std::string uniqueTag(const std::string &name)
{
  return "iora_sr_" + name + "_" + std::to_string(getpid());
}
} // namespace

TEST_CASE("ProcessHandle basic spawn and wait")
{
  auto proc = ShellRunner::spawn("sleep 0.1");
  REQUIRE(proc.pid() > 0);
  REQUIRE(proc.isRunning() == true);

  auto result = proc.wait(std::chrono::seconds(2));
  REQUIRE(result.exited == true);
  REQUIRE(result.exitCode == 0);
  REQUIRE(result.state == ProcessHandle::State::Exited);
  REQUIRE(result.timedOut == false);
}

TEST_CASE("ProcessHandle RAII cleanup")
{
  pid_t captured_pid = 0;

  {
    auto proc = ShellRunner::spawn("sleep 10");
    captured_pid = proc.pid();
    REQUIRE(captured_pid > 0);
    REQUIRE(proc.isRunning() == true);
    // ProcessHandle goes out of scope here - should auto-terminate
  }

  // Give some time for cleanup
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // Process should no longer exist
  REQUIRE(ShellRunner::isProcessRunning(captured_pid) == false);
}

TEST_CASE("ProcessHandle graceful termination")
{
  // exec: the PID is sleep itself, so the PID-only terminate() leaves nothing behind
  auto proc = ShellRunner::spawn("exec sleep 100");
  REQUIRE(proc.isRunning() == true);

  proc.terminate();
  auto result = proc.wait(std::chrono::seconds(2));

  REQUIRE(result.exited == true);
  REQUIRE(result.state == ProcessHandle::State::Signaled);
  // Note: terminate() now uses SIGKILL instead of SIGTERM to avoid Catch2 signal handler issues
  REQUIRE(result.signal == SIGKILL);
}

TEST_CASE("ProcessHandle immediate kill")
{
  auto proc = ShellRunner::spawn("exec sleep 100");
  REQUIRE(proc.isRunning() == true);

  proc.kill();
  auto result = proc.wait(std::chrono::seconds(2));

  REQUIRE(result.exited == true);
  REQUIRE(result.state == ProcessHandle::State::Signaled);
  REQUIRE(result.signal == SIGKILL);
}

TEST_CASE("ProcessHandle wait timeout")
{
  auto proc = ShellRunner::spawn("sleep 5");

  auto result = proc.wait(std::chrono::milliseconds(100));

  REQUIRE(result.timedOut == true);
  REQUIRE(result.state == ProcessHandle::State::Running);
  REQUIRE(proc.isRunning() == true);
}

TEST_CASE("ProcessHandle getState")
{
  auto proc = ShellRunner::spawn("sleep 0.1");
  REQUIRE(proc.getState() == ProcessHandle::State::Running);

  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  auto state = proc.getState();
  REQUIRE(state == ProcessHandle::State::Exited);
}

TEST_CASE("ProcessHandle move semantics")
{
  auto proc1 = ShellRunner::spawn("sleep 1");
  pid_t pid1 = proc1.pid();
  REQUIRE(pid1 > 0);

  // Move constructor
  auto proc2 = std::move(proc1);
  REQUIRE(proc2.pid() == pid1);
  REQUIRE(proc1.pid() == -1);

  // Move assignment kills and reaps the target's previous process
  auto proc3 = ShellRunner::spawn("exec sleep 30");
  const pid_t replaced = proc3.pid();
  proc3 = std::move(proc2);
  REQUIRE(proc3.pid() == pid1);
  REQUIRE(proc2.pid() == -1);
  REQUIRE((::kill(replaced, 0) == -1 && errno == ESRCH));
}

TEST_CASE("ProcessHandle detach")
{
  pid_t captured_pid = 0;

  {
    auto proc = ShellRunner::spawn("sleep 1");
    captured_pid = proc.pid();
    proc.detach();
    // Process should NOT be terminated when handle is destroyed
  }

  // Process should still be running after handle destroyed
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(ShellRunner::isProcessRunning(captured_pid) == true);

  // Clean up the detached process - kill entire process group
  pid_t pgid = getpgid(captured_pid);
  if (pgid > 0)
  {
    ::kill(-pgid, SIGKILL);  // Negative PID sends to entire process group
  }
  waitpid(captured_pid, nullptr, 0);
}

TEST_CASE("ProcessHandle termination strategy - Immediate")
{
  SpawnOptions options;
  options.terminationStrategy = SpawnOptions::TerminationStrategy::Immediate;

  pid_t captured_pid = 0;

  {
    auto proc = ShellRunner::spawn("sleep 10", options);
    captured_pid = proc.pid();
    REQUIRE(proc.isRunning() == true);
    // Should be killed immediately on destruction
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  REQUIRE(ShellRunner::isProcessRunning(captured_pid) == false);
}

TEST_CASE("ProcessHandle termination strategy - None")
{
  SpawnOptions options;
  options.terminationStrategy = SpawnOptions::TerminationStrategy::None;

  pid_t captured_pid = 0;

  {
    auto proc = ShellRunner::spawn("sleep 1", options);
    captured_pid = proc.pid();
    // Process should NOT be terminated
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(ShellRunner::isProcessRunning(captured_pid) == true);

  // Clean up - kill entire process group
  pid_t pgid = getpgid(captured_pid);
  if (pgid > 0)
  {
    ::kill(-pgid, SIGKILL);  // Negative PID sends to entire process group
  }
  waitpid(captured_pid, nullptr, 0);
}

TEST_CASE("ProcessHandle stdout redirection")
{
  SpawnOptions options;
  options.stdoutFile = tmpPath("stdout");

  auto proc = ShellRunner::spawn("echo 'Hello from ProcessHandle'", options);
  proc.wait(std::chrono::seconds(2));

  std::ifstream file(options.stdoutFile);
  std::string content((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());

  REQUIRE(content.find("Hello from ProcessHandle") != std::string::npos);

  std::remove(options.stdoutFile.c_str());
}

TEST_CASE("ProcessHandle stderr redirection")
{
  SpawnOptions options;
  options.stderrFile = tmpPath("stderr");

  auto proc = ShellRunner::spawn("echo 'Error message' >&2", options);
  proc.wait(std::chrono::seconds(2));

  std::ifstream file(options.stderrFile);
  std::string content((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());

  REQUIRE(content.find("Error message") != std::string::npos);

  std::remove(options.stderrFile.c_str());
}

TEST_CASE("ProcessHandle working directory")
{
  SpawnOptions options;
  options.workingDirectory = "/tmp";
  options.stdoutFile = tmpPath("pwd");

  auto proc = ShellRunner::spawn("pwd", options);
  proc.wait(std::chrono::seconds(2));

  std::ifstream file(options.stdoutFile);
  std::string content((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());

  REQUIRE(content.find("/tmp") != std::string::npos);

  std::remove(options.stdoutFile.c_str());
}

TEST_CASE("ProcessHandle environment variables")
{
  SpawnOptions options;
  options.environment["TEST_VAR"] = "test_value_123";
  options.stdoutFile = tmpPath("env");

  auto proc = ShellRunner::spawn("echo $TEST_VAR", options);
  proc.wait(std::chrono::seconds(2));

  std::ifstream file(options.stdoutFile);
  std::string content((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());

  REQUIRE(content.find("test_value_123") != std::string::npos);

  std::remove(options.stdoutFile.c_str());
}

TEST_CASE("ProcessHandle process group")
{
  SpawnOptions options;
  options.createProcessGroup = true;

  auto proc = ShellRunner::spawn("sleep 1", options);
  pid_t pid = proc.pid();

  // Check if process is in its own group
  // The spawned process should be in a new process group
  pid_t pgid = getpgid(pid);
  pid_t parent_pgid = getpgid(getpid());

  // The process group ID should be different from parent's process group, and
  // the child must lead its own group (what group termination relies on)
  REQUIRE(pgid != parent_pgid);
  REQUIRE(pgid == pid);
}

namespace
{
std::size_t liveThreadCount()
{
  std::size_t n = 0;
  if (DIR *d = opendir("/proc/self/task"))
  {
    while (dirent *e = readdir(d))
    {
      if (e->d_name[0] != '.')
      {
        ++n;
      }
    }
    closedir(d);
  }
  return n;
}

// Runs body() in a forked child placed in its own session, so a regression that
// signals "the caller's group" can only take down this harness. Returns the
// harness's wait status, or a negative value on a harness failure.
//
// Precondition: the process is single-threaded at the fork (the child runs
// non-async-signal-safe code); checked, returning -4 otherwise.
template <typename Body> int runInIsolatedHarness(Body body)
{
  // A just-joined thread can stay listed in /proc/self/task for a moment.
  if (!iora::test::waitFor([]() { return liveThreadCount() == 1; }, std::chrono::milliseconds(200)))
  {
    return -4;
  }
  pid_t harness = fork();
  if (harness < 0)
  {
    return -1;
  }
  if (harness == 0)
  {
    if (setsid() == -1)
    {
      _exit(3);
    }
    try
    {
      _exit(body());
    }
    catch (...)
    {
      _exit(3);
    }
  }
  // Wait for the harness to exit WITHOUT reaping it (WNOWAIT), so its zombie
  // keeps its group ID in use while anything it left behind is swept.
  siginfo_t info{};
  bool exited = false;
  bool waitError = false;
  const bool sawStatus = iora::test::waitFor(
    [&]()
    {
      info.si_pid = 0;
      if (::waitid(P_PID, static_cast<id_t>(harness), &info, WEXITED | WNOHANG | WNOWAIT) == -1)
      {
        waitError = (errno != EINTR);
        return waitError;
      }
      exited = info.si_pid == harness;
      return exited;
    },
    std::chrono::seconds(30));
  int status = 0;
  if (waitError)
  {
    // The harness was reaped elsewhere: its group ID is no longer pinned, so
    // sweeping by ID could hit an unrelated group.
    ProcessHandle::waitpidWithEINTR(harness, &status, WNOHANG);
    return -3;
  }
  ::kill(-harness, SIGKILL); // the harness (alive or a zombie) pins its group ID
  const pid_t r = ProcessHandle::waitpidWithEINTR(harness, &status, 0);
  if (!sawStatus)
  {
    return -2; // timed out
  }
  if (!exited || r != harness)
  {
    return -3; // the harness's status was never observed
  }
  return status;
}

// True if the process no longer exists or is a zombie (killed, not yet reaped).
bool deadOrZombie(pid_t pid)
{
  if (::kill(pid, 0) == -1 && errno == ESRCH)
  {
    return true;
  }
  std::ifstream statFile("/proc/" + std::to_string(pid) + "/stat");
  std::string field;
  std::string state;
  return (statFile >> field >> field >> state) && state == "Z";
}

bool processGone(pid_t pid, std::chrono::milliseconds within)
{
  return iora::test::waitFor([pid]() { return deadOrZombie(pid); }, within);
}

// Reads the PID a command wrote to path, waiting up to timeout; -1 if none.
pid_t waitForPidFile(const std::string &path, std::chrono::milliseconds timeout)
{
  pid_t pid = -1;
  iora::test::waitFor(
    [&]()
    {
      std::ifstream f(path);
      f >> pid;
      return pid > 0;
    },
    timeout);
  return pid;
}
} // namespace

TEST_CASE("ProcessHandle without its own group never signals the caller's group")
{
  for (auto strategy :
       {SpawnOptions::TerminationStrategy::Graceful, SpawnOptions::TerminationStrategy::Immediate})
  {
    int status = runInIsolatedHarness(
      [strategy]()
      {
        pid_t child = -1;
        {
          SpawnOptions options;
          options.createProcessGroup = false; // killProcessGroup left at its default (true)
          options.terminationStrategy = strategy;
          auto proc = ShellRunner::spawn("sleep 30", options);
          child = proc.pid();
          if (getpgid(child) != getpgid(0))
          {
            proc.kill();
            proc.wait();
            return 2; // precondition: the child must share the harness's group
          }
        } // ~ProcessHandle
        // The PID-only branch must actually have killed and reaped the child.
        return (::kill(child, 0) == -1 && errno == ESRCH) ? 0 : 4;
      });
    INFO("strategy " << static_cast<int>(strategy) << ", harness status " << status);
    REQUIRE(status >= 0);
    REQUIRE(WIFEXITED(status));
    REQUIRE(WEXITSTATUS(status) == 0);
  }
}

TEST_CASE("ProcessHandle destruction kills grandchildren in its process group")
{
  for (auto strategy :
       {SpawnOptions::TerminationStrategy::Graceful, SpawnOptions::TerminationStrategy::Immediate})
  {
    const std::string pidFile =
      "/tmp/iora_test_grandchild_" + std::to_string(getpid()) + "_" + std::to_string(static_cast<int>(strategy));
    std::remove(pidFile.c_str());
    pid_t grandchild = -1;
    {
      SpawnOptions options; // createProcessGroup and killProcessGroup default to true
      options.terminationStrategy = strategy;
      auto proc = ShellRunner::spawn("sleep 30 & echo $! > " + pidFile + "; wait", options);
      grandchild = waitForPidFile(pidFile, std::chrono::seconds(5));
      REQUIRE(grandchild > 0);
      REQUIRE(::kill(grandchild, 0) == 0);
    } // ~ProcessHandle signals the whole group
    std::remove(pidFile.c_str());
    INFO("strategy " << static_cast<int>(strategy));
    REQUIRE(processGone(grandchild, std::chrono::seconds(5)));
  }
}

TEST_CASE("ProcessHandle with killProcessGroup=false leaves grandchildren alone")
{
  const std::string pidFile = "/tmp/iora_test_grandchild_nogroup_" + std::to_string(getpid());
  std::remove(pidFile.c_str());
  pid_t grandchild = -1;
  pid_t pgid = -1;
  {
    SpawnOptions options; // createProcessGroup = true
    options.killProcessGroup = false;
    auto proc = ShellRunner::spawn("sleep 30 & echo $! > " + pidFile + "; wait", options);
    pgid = proc.pid();
    grandchild = waitForPidFile(pidFile, std::chrono::seconds(5));
  } // ~ProcessHandle signals the PID only
  std::remove(pidFile.c_str());
  const bool survived = grandchild > 0 && !deadOrZombie(grandchild);
  if (survived)
  {
    ShellRunner::killProcessGroup(pgid, SIGKILL); // the orphan still pins the group ID
  }
  REQUIRE(grandchild > 0);
  REQUIRE(survived);
}

TEST_CASE("ProcessHandle signalling and readiness helpers")
{
  SECTION("signal(SIGKILL) reports Signaled")
  {
    auto proc = ShellRunner::spawn("exec sleep 30");
    REQUIRE(proc.waitUntilReady(std::chrono::seconds(1)));
    REQUIRE(proc.signal(SIGKILL));
    auto r = proc.wait(std::chrono::seconds(5));
    REQUIRE(r.state == ProcessHandle::State::Signaled);
    REQUIRE(r.signal == SIGKILL);
  }
  SECTION("moved-from handle refuses to signal")
  {
    auto proc = ShellRunner::spawn("sleep 30");
    ProcessHandle other(std::move(proc));
    REQUIRE_FALSE(proc.terminate());
    REQUIRE_FALSE(proc.kill());
    REQUIRE_FALSE(proc.signal(SIGTERM));
    REQUIRE_FALSE(proc.waitUntilReady(std::chrono::milliseconds(10)));
    REQUIRE(other.isRunning());
  }
  SECTION("setTerminationStrategy(None) leaves the process running")
  {
    pid_t pid = -1;
    {
      auto proc = ShellRunner::spawn("sleep 30");
      pid = proc.pid();
      proc.setTerminationStrategy(SpawnOptions::TerminationStrategy::None);
    }
    const bool alive = ShellRunner::isProcessRunning(pid);
    const bool killed = alive && ShellRunner::killProcessGroup(pid, SIGKILL);
    ShellRunner::waitForProcess(pid, std::chrono::seconds(5));
    REQUIRE(alive);
    REQUIRE(killed);
  }
  SECTION("sendSignal and killProcessGroup")
  {
    auto proc = ShellRunner::spawn("sleep 30");
    REQUIRE(ShellRunner::sendSignal(proc.pid(), 0));
    REQUIRE(ShellRunner::killProcessGroup(proc.pid(), SIGKILL));
    auto r = proc.wait(std::chrono::seconds(5));
    REQUIRE(r.state == ProcessHandle::State::Signaled);
    REQUIRE_FALSE(ShellRunner::sendSignal(-1, 0));
    REQUIRE_FALSE(ShellRunner::killProcessGroup(0));
  }
}

TEST_CASE("ProcessHandle concurrent wait keeps the reaped exit status")
{
  for (int round = 0; round < 20; ++round)
  {
    auto proc = ShellRunner::spawn("exit 42");
    ProcessHandle::WaitResult r1;
    ProcessHandle::WaitResult r2;
    std::thread t1([&]() { r1 = proc.wait(std::chrono::seconds(5)); });
    std::thread t2([&]() { r2 = proc.wait(std::chrono::seconds(5)); });
    t1.join();
    t2.join();
    REQUIRE(r1.state == ProcessHandle::State::Exited);
    REQUIRE(r1.exitCode == 42);
    REQUIRE(r2.state == ProcessHandle::State::Exited);
    REQUIRE(r2.exitCode == 42);
    REQUIRE(proc.getState() == ProcessHandle::State::Exited);
  }
}

TEST_CASE("pcloseExitCode maps wait statuses")
{
  REQUIRE(pcloseExitCode(-1) == -1);
  REQUIRE(pcloseExitCode(0) == 0);
  REQUIRE(pcloseExitCode(42 << 8) == 42);
  REQUIRE(pcloseExitCode(SIGKILL) == 128 + SIGKILL); // WIFSIGNALED status
  REQUIRE(pcloseExitCode(0x137f) == 0x137f);          // stopped by SIGSTOP: returned raw
}

TEST_CASE("ShellRunner synchronous execute exit codes")
{
  std::ostringstream os;
  REQUIRE(ShellRunner::execute("echo hi") == "hi\n");
  REQUIRE_THROWS_AS(ShellRunner::execute("exit 1"), std::runtime_error);
  REQUIRE(ShellRunner::execute("exit 3", os) == 3);
  REQUIRE(ShellRunner::execute("kill -9 $$", os) == 128 + SIGKILL);

  ExecutionOptions opts;
  opts.throwOnError = false;
  auto r = ShellRunner::executeWithOptions("echo out; exit 5", opts);
  REQUIRE(r.exitCode == 5);
  REQUIRE(r.stdout == "out\n");
  REQUIRE_FALSE(r.timedOut);

  REQUIRE(ShellRunner::executeWithInput("cat", "line\n") == "line\n");
}

TEST_CASE("ShellRunner findProcesses")
{
  const std::string tag = uniqueTag("find");
  auto proc1 = ShellRunner::spawn("sleep 100; : " + tag + "_a");
  auto proc2 = ShellRunner::spawn("sleep 101; : " + tag + "_b");

  pid_t pid1 = proc1.pid();
  pid_t pid2 = proc2.pid();

  // Get process groups for cleanup
  pid_t pgid1 = getpgid(pid1);
  pid_t pgid2 = getpgid(pid2);

  // Wait for actual commands to appear in process table (not just shell wrappers)
  REQUIRE(proc1.waitForCommandReady(std::chrono::milliseconds(1000)) == true);
  REQUIRE(proc2.waitForCommandReady(std::chrono::milliseconds(1000)) == true);

  // The sh -c wrappers' command lines carry the unique tag
  auto pids = ShellRunner::findProcesses(tag + "_[ab]");

  REQUIRE(pids.size() == 2);
  REQUIRE(std::find(pids.begin(), pids.end(), pid1) != pids.end());
  REQUIRE(std::find(pids.begin(), pids.end(), pid2) != pids.end());

  // ProcessHandle RAII will kill parent shell, but we need to ensure child processes are killed too
  // Kill process groups to avoid orphaned children
  if (pgid1 > 0)
  {
    ::kill(-pgid1, SIGKILL);
  }
  if (pgid2 > 0)
  {
    ::kill(-pgid2, SIGKILL);
  }
}

TEST_CASE("ShellRunner killProcesses")
{
  const std::string tag = uniqueTag("kill");
  auto proc1 = ShellRunner::spawn("sleep 100; : " + tag + "_a");
  auto proc2 = ShellRunner::spawn("sleep 101; : " + tag + "_b");

  pid_t pid1 = proc1.pid();
  pid_t pid2 = proc2.pid();

  // Get process groups before detaching
  pid_t pgid1 = getpgid(pid1);
  pid_t pgid2 = getpgid(pid2);

  // Wait for actual commands to appear in process table (not just shell wrappers)
  REQUIRE(proc1.waitForCommandReady(std::chrono::milliseconds(1000)) == true);
  REQUIRE(proc2.waitForCommandReady(std::chrono::milliseconds(1000)) == true);

  // Detach so they won't be killed on scope exit
  proc1.detach();
  proc2.detach();

  int killed = ShellRunner::killProcesses(tag + "_[ab]", SIGKILL);

  REQUIRE(killed == 2);

  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  REQUIRE(ShellRunner::isProcessRunning(pid1) == false);
  REQUIRE(ShellRunner::isProcessRunning(pid2) == false);

  // Extra cleanup: ensure process groups are killed to avoid orphaned children
  if (pgid1 > 0)
  {
    ::kill(-pgid1, SIGKILL);
  }
  if (pgid2 > 0)
  {
    ::kill(-pgid2, SIGKILL);
  }
}

TEST_CASE("ShellRunner static helpers")
{
  auto proc = ShellRunner::spawn("sleep 0.5");
  pid_t pid = proc.pid();

  REQUIRE(ShellRunner::isProcessRunning(pid) == true);
  REQUIRE(ShellRunner::getProcessState(pid) == ProcessHandle::State::Running);

  auto result = ShellRunner::waitForProcess(pid, std::chrono::seconds(2));

  REQUIRE(result.exited == true);
  REQUIRE(result.state == ProcessHandle::State::Exited);
}

TEST_CASE("ProcessHandle exit code")
{
  auto proc = ShellRunner::spawn("exit 42");
  auto result = proc.wait(std::chrono::seconds(2));

  REQUIRE(result.exited == true);
  REQUIRE(result.exitCode == 42);
  REQUIRE(result.state == ProcessHandle::State::Exited);
}

TEST_CASE("ProcessHandle cached state")
{
  auto proc = ShellRunner::spawn("sleep 0.1");

  // First check should cache the running state
  REQUIRE(proc.isRunning() == true);

  // Wait for process to exit
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // Next check should update cache
  REQUIRE(proc.isRunning() == false);

  // Subsequent checks should use cache
  REQUIRE(proc.isRunning() == false);
  REQUIRE(proc.getState() == ProcessHandle::State::Exited);
}

TEST_CASE("ProcessHandle thread safety")
{
  // Short-lived, so the concurrent queries race on the reap itself.
  auto proc = ShellRunner::spawn("exec sleep 0.05");

  std::atomic<bool> errors{false};
  std::atomic<int> sawExited{0};

  auto pollUntilDone = [&]()
  {
    try
    {
      const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
      while (proc.isRunning() && std::chrono::steady_clock::now() < deadline)
      {
        proc.getState();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
      if (proc.getState() == ProcessHandle::State::Exited)
      {
        ++sawExited;
      }
    }
    catch (...)
    {
      errors = true;
    }
  };

  std::thread t1(pollUntilDone);
  std::thread t2(pollUntilDone);
  std::thread t3(pollUntilDone);

  t1.join();
  t2.join();
  t3.join();

  REQUIRE(errors == false);
  REQUIRE(sawExited == 3); // every thread sees the one reaped status
  REQUIRE(proc.wait().exitCode == 0);
}

TEST_CASE("ShellRunner execute error paths")
{
  SECTION("executeWithOptions throws on a non-zero exit by default")
  {
    ExecutionOptions throwing; // throwOnError defaults to true
    REQUIRE_THROWS_AS(ShellRunner::executeWithOptions("exit 4", throwing), std::runtime_error);
  }
  SECTION("wait() with a negative timeout waits forever")
  {
    auto proc = ShellRunner::spawn("exit 7");
    auto r = proc.wait(std::chrono::milliseconds(-1)); // <= 0 waits forever
    REQUIRE(r.state == ProcessHandle::State::Exited);
    REQUIRE(r.exitCode == 7);
  }
  SECTION("a failed chdir in the child exits 127")
  {
    SpawnOptions badDir;
    badDir.workingDirectory = "/nonexistent/iora-test-dir";
    auto failed = ShellRunner::spawn("true", badDir);
    auto fr = failed.wait(std::chrono::seconds(5));
    REQUIRE(fr.state == ProcessHandle::State::Exited);
    REQUIRE(fr.exitCode == 127);
  }
}

TEST_CASE("ShellRunner static helpers: edge cases")
{
  SECTION("a static helper that reaps steals the handle's exit status")
  {
    auto proc = ShellRunner::spawn("exit 0");
    auto stolen = ShellRunner::waitForProcess(proc.pid(), std::chrono::seconds(5));
    REQUIRE(stolen.state == ProcessHandle::State::Exited);
    auto r = proc.wait(std::chrono::seconds(1));
    REQUIRE(r.state == ProcessHandle::State::Unknown); // ECHILD, cached
    REQUIRE(proc.wait().state == ProcessHandle::State::Unknown);
  }
  SECTION("getProcessState reports Signaled, and Unknown for a non-child")
  {
    auto proc = ShellRunner::spawn("exec sleep 30");
    REQUIRE(proc.waitUntilReady(std::chrono::seconds(1)));
    REQUIRE(ShellRunner::sendSignal(proc.pid(), SIGKILL));
    REQUIRE(iora::test::waitFor([&]() { return deadOrZombie(proc.pid()); }, std::chrono::seconds(5)));
    REQUIRE(ShellRunner::getProcessState(proc.pid()) == ProcessHandle::State::Signaled);
    REQUIRE(ShellRunner::getProcessState(1) == ProcessHandle::State::Unknown);
  }
  SECTION("waitForProcess times out on a running child")
  {
    auto proc = ShellRunner::spawn("exec sleep 5");
    auto r = ShellRunner::waitForProcess(proc.pid(), std::chrono::milliseconds(50));
    REQUIRE(r.timedOut);
    REQUIRE(r.state == ProcessHandle::State::Running);
  }
  SECTION("findProcesses rejects an invalid pattern")
  {
    REQUIRE_THROWS_AS(ShellRunner::findProcesses("("), std::regex_error);
  }
  SECTION("killProcessGroup refuses 0 and 1 (kill(-1) would broadcast)")
  {
    REQUIRE_FALSE(ShellRunner::killProcessGroup(0, 0));
    REQUIRE_FALSE(ShellRunner::killProcessGroup(1, 0));
  }
}

TEST_CASE("ProcessHandle stdout redirection when the caller's fd 1 is closed")
{
  const std::string out = tmpPath("closed_fd1");
  std::remove(out.c_str());
  int status = runInIsolatedHarness(
    [&out]()
    {
      ::close(STDOUT_FILENO); // open() in the child will now reuse fd 1
      SpawnOptions options;
      options.stdoutFile = out;
      auto proc = ShellRunner::spawn("echo hello", options);
      auto r = proc.wait(std::chrono::seconds(5));
      return (r.state == ProcessHandle::State::Exited && r.exitCode == 0) ? 0 : 4;
    });
  std::ifstream f(out);
  std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  std::remove(out.c_str());
  INFO("harness status " << status);
  REQUIRE(status >= 0);
  REQUIRE(WIFEXITED(status));
  REQUIRE(WEXITSTATUS(status) == 0);
  REQUIRE(content == "hello\n");
}
