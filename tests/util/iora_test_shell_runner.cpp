
// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include "../test_helpers.hpp"
#include <iora/system/shell_runner.hpp>
#include <catch2/catch.hpp>
#include <thread>
#include <fstream>

using namespace iora::system;

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
  auto proc = ShellRunner::spawn("sleep 100");
  REQUIRE(proc.isRunning() == true);

  proc.terminate();
  auto result = proc.wait(std::chrono::seconds(2));

  REQUIRE(result.exited == true);
  REQUIRE(result.state == ProcessHandle::State::Signaled);
  REQUIRE(result.signal == SIGTERM);
}

TEST_CASE("ProcessHandle immediate kill")
{
  auto proc = ShellRunner::spawn("sleep 100");
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

  // Move assignment
  auto proc3 = ShellRunner::spawn("sleep 0.1");
  proc3 = std::move(proc2);
  REQUIRE(proc3.pid() == pid1);
  REQUIRE(proc2.pid() == -1);
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

  // Clean up the detached process
  ::kill(captured_pid, SIGKILL);
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

  // Clean up
  ::kill(captured_pid, SIGKILL);
  waitpid(captured_pid, nullptr, 0);
}

TEST_CASE("ProcessHandle stdout redirection")
{
  SpawnOptions options;
  options.stdoutFile = "/tmp/iora_test_stdout.txt";

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
  options.stderrFile = "/tmp/iora_test_stderr.txt";

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
  options.stdoutFile = "/tmp/iora_test_pwd.txt";

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
  options.stdoutFile = "/tmp/iora_test_env.txt";

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

  // The process group ID should be different from parent's process group
  REQUIRE(pgid != parent_pgid);
}

TEST_CASE("ShellRunner findProcesses")
{
  auto proc1 = ShellRunner::spawn("sleep 100");
  auto proc2 = ShellRunner::spawn("sleep 101");

  // Since processes are spawned via /bin/sh, search for "sh" in the command line
  auto pids = ShellRunner::findProcesses("sh.*sleep 10[01]");

  REQUIRE(pids.size() >= 2);
  REQUIRE(std::find(pids.begin(), pids.end(), proc1.pid()) != pids.end());
  REQUIRE(std::find(pids.begin(), pids.end(), proc2.pid()) != pids.end());
}

TEST_CASE("ShellRunner killProcesses")
{
  auto proc1 = ShellRunner::spawn("sleep 100");
  auto proc2 = ShellRunner::spawn("sleep 101");

  pid_t pid1 = proc1.pid();
  pid_t pid2 = proc2.pid();

  // Detach so they won't be killed on scope exit
  proc1.detach();
  proc2.detach();

  // Since processes are spawned via /bin/sh, search for "sh" in the command line
  int killed = ShellRunner::killProcesses("sh.*sleep 10[01]", SIGKILL);

  REQUIRE(killed >= 2);

  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  REQUIRE(ShellRunner::isProcessRunning(pid1) == false);
  REQUIRE(ShellRunner::isProcessRunning(pid2) == false);
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
  auto proc = ShellRunner::spawn("sleep 1");

  std::atomic<int> running_count{0};
  std::atomic<bool> errors{false};

  auto check_running = [&]()
  {
    try
    {
      for (int i = 0; i < 100; i++)
      {
        if (proc.isRunning())
        {
          running_count++;
        }
        proc.getState();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    }
    catch (...)
    {
      errors = true;
    }
  };

  std::thread t1(check_running);
  std::thread t2(check_running);
  std::thread t3(check_running);

  t1.join();
  t2.join();
  t3.join();

  REQUIRE(errors == false);
}
