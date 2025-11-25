// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <ostream>
#include <regex>
#include <signal.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace iora
{
namespace system
{

/// \brief Result of command execution with detailed information.
struct ExecutionResult
{
  int exitCode = 0;
  std::string stdout;
  std::string stderr;
  bool timedOut = false;
  std::chrono::milliseconds duration{0};
};

/// \brief Options for command execution.
struct ExecutionOptions
{
  std::unordered_map<std::string, std::string> environment;
  std::string workingDirectory;
  std::string input;
  std::chrono::milliseconds timeout{0}; // 0 = no timeout
  bool captureStderr = false;
  bool throwOnError = true;
};

// Forward declaration
class ProcessHandle;

/// \brief Options for spawning background processes.
struct SpawnOptions
{
  /// Environment variables (empty = inherit parent)
  std::unordered_map<std::string, std::string> environment;

  /// Working directory (empty = inherit parent)
  std::string workingDirectory;

  /// Redirect stdout to file
  std::string stdoutFile;

  /// Redirect stderr to file
  std::string stderrFile;

  /// Create new process group
  bool createProcessGroup = false;

  /// Termination strategy on handle destruction
  enum class TerminationStrategy
  {
    Graceful,  // SIGTERM → wait → SIGKILL (default)
    Immediate, // SIGKILL immediately
    None       // Detach process, no termination
  };

  TerminationStrategy terminationStrategy = TerminationStrategy::Graceful;
};

/// \brief RAII handle for background process lifecycle management.
///
/// ProcessHandle provides automatic process termination on scope exit,
/// ensuring no orphaned processes even during exceptions. Supports
/// graceful termination (SIGTERM → SIGKILL), process state queries,
/// and timeout-based waiting.
class ProcessHandle
{
public:
  /// Process state
  enum class State
  {
    Running,  // Process is currently running
    Exited,   // Process exited normally
    Signaled, // Process killed by signal
    Unknown   // Cannot determine state
  };

  /// Result of wait() operation
  struct WaitResult
  {
    bool exited = false;      // True if process exited
    int exitCode = 0;         // Exit code (if exited == true)
    int signal = 0;           // Signal number (if signaled)
    bool timedOut = false;    // True if wait timed out
    State state = State::Unknown; // Final process state
  };

  /// \brief Construct a ProcessHandle for the given PID.
  /// \param pid Process ID to manage.
  /// \param strategy Termination strategy for destructor.
  explicit ProcessHandle(pid_t pid,
                        SpawnOptions::TerminationStrategy strategy = SpawnOptions::TerminationStrategy::Graceful)
    : _pid(pid)
    , _terminationStrategy(strategy)
    , _detached(false)
  {
  }

  /// \brief Destructor - automatically terminates process based on strategy.
  ~ProcessHandle() noexcept
  {
    try
    {
      cleanupProcess();
    }
    catch (...)
    {
      // Cannot throw from destructor - silent failure
      // Note: Errors during cleanup are logged silently to prevent std::terminate
    }
  }

  // Move-only semantics
  ProcessHandle(const ProcessHandle &) = delete;
  ProcessHandle &operator=(const ProcessHandle &) = delete;

  ProcessHandle(ProcessHandle &&other) noexcept
    : _pid(other._pid)
    , _terminationStrategy(other._terminationStrategy)
    , _detached(other._detached)
    , _cachedWaitResult(std::move(other._cachedWaitResult))
  {
    other._pid = -1;
    other._detached = true;
  }

  ProcessHandle &operator=(ProcessHandle &&other) noexcept
  {
    try
    {
      if (this != &other)
      {
        // Clean up current process using helper method
        cleanupProcess();

        // MAJOR FIX #4: Hold mutex when modifying member variables
        std::lock_guard<std::mutex> lock(_mutex);

        // Move from other
        _pid = other._pid;
        _terminationStrategy = other._terminationStrategy;
        _detached = other._detached;
        _cachedWaitResult = std::move(other._cachedWaitResult);

        other._pid = -1;
        other._detached = true;
      }
    }
    catch (...)
    {
      // Cannot throw from noexcept move assignment - silent failure
      // Note: Errors during move are logged silently to prevent std::terminate
    }
    return *this;
  }

  /// \brief Get process ID.
  pid_t pid() const
  {
    return _pid;
  }

  /// \brief Check if process is running (non-blocking).
  bool isRunning() const
  {
    if (_pid <= 0)
    {
      return false;
    }

    // CRITICAL: Hold mutex for entire operation to prevent race condition
    std::lock_guard<std::mutex> lock(_mutex);

    // Check if we already have a cached result
    if (_cachedWaitResult.has_value())
    {
      return _cachedWaitResult->state == State::Running;
    }

    // Use waitpid with WNOHANG to check without blocking
    int status;
    pid_t result = waitpidWithEINTR(_pid, &status, WNOHANG);

    if (result == 0)
    {
      // Process is still running
      return true;
    }
    else if (result == _pid)
    {
      // Process has terminated, cache the result
      _cachedWaitResult = parseWaitStatus(status);
      return false;
    }
    else
    {
      // Error or process doesn't exist
      return false;
    }
  }

  /// \brief Get current process state.
  State getState() const
  {
    if (_pid <= 0)
    {
      return State::Unknown;
    }

    std::lock_guard<std::mutex> lock(_mutex);

    // Check cached result first
    if (_cachedWaitResult.has_value())
    {
      return _cachedWaitResult->state;
    }

    // No cached result - do a non-blocking check
    int status;
    pid_t result = waitpidWithEINTR(_pid, &status, WNOHANG);

    if (result == 0)
    {
      return State::Running;
    }
    else if (result == _pid)
    {
      _cachedWaitResult = parseWaitStatus(status);
      return _cachedWaitResult->state;
    }
    else
    {
      return State::Unknown;
    }
  }

  /// \brief Wait for process to exit.
  /// \param timeout Maximum time to wait (0 = wait forever).
  /// \return WaitResult with exit status.
  WaitResult wait(std::chrono::milliseconds timeout = std::chrono::milliseconds(0))
  {
    if (_pid <= 0)
    {
      WaitResult result;
      result.state = State::Unknown;
      return result;
    }

    // Check if we already have a cached result
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (_cachedWaitResult.has_value())
      {
        return _cachedWaitResult.value();
      }
    }

    auto startTime = std::chrono::steady_clock::now();

    while (true)
    {
      int status;
      pid_t result;

      // CRITICAL: Only hold mutex during waitpid and cache update
      {
        std::lock_guard<std::mutex> lock(_mutex);
        result = waitpidWithEINTR(_pid, &status, WNOHANG);

        if (result == _pid)
        {
          // Process has terminated
          _cachedWaitResult = parseWaitStatus(status);
          return _cachedWaitResult.value();
        }
        else if (result == -1)
        {
          // Error
          WaitResult waitResult;
          waitResult.state = State::Unknown;
          _cachedWaitResult = waitResult;
          return waitResult;
        }
      }

      // Process still running, check timeout (outside lock)
      if (timeout.count() > 0)
      {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - startTime);

        if (elapsed >= timeout)
        {
          WaitResult waitResult;
          waitResult.timedOut = true;
          waitResult.state = State::Running;
          return waitResult;
        }
      }

      // Sleep briefly before checking again (outside lock)
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }

  /// \brief Send SIGTERM to process.
  bool terminate()
  {
    if (_pid <= 0)
    {
      return false;
    }
    // MAJOR FIX #7: Add basic PID validation
    if (::kill(_pid, 0) != 0)
    {
      return false; // Process doesn't exist
    }
    return ::kill(_pid, SIGTERM) == 0;
  }

  /// \brief Send SIGKILL to process.
  bool kill()
  {
    if (_pid <= 0)
    {
      return false;
    }
    // MAJOR FIX #7: Add basic PID validation
    if (::kill(_pid, 0) != 0)
    {
      return false; // Process doesn't exist
    }
    return ::kill(_pid, SIGKILL) == 0;
  }

  /// \brief Send arbitrary signal to process.
  bool signal(int sig)
  {
    if (_pid <= 0)
    {
      return false;
    }
    // MAJOR FIX #7: Add basic PID validation
    if (::kill(_pid, 0) != 0)
    {
      return false; // Process doesn't exist
    }
    return ::kill(_pid, sig) == 0;
  }

  /// \brief Detach from process (disables auto-cleanup).
  void detach()
  {
    // CRITICAL FIX #3: Make detach() thread-safe
    std::lock_guard<std::mutex> lock(_mutex);
    _detached = true;
  }

  /// \brief Change termination strategy.
  void setTerminationStrategy(SpawnOptions::TerminationStrategy strategy)
  {
    _terminationStrategy = strategy;
  }

  /// \brief Wrapper for waitpid that retries on EINTR.
  /// \param pid Process ID to wait for.
  /// \param status Pointer to status variable.
  /// \param options Options for waitpid (WNOHANG, etc.).
  /// \return Result of waitpid, -1 on non-EINTR error.
  static pid_t waitpidWithEINTR(pid_t pid, int *status, int options)
  {
    while (true)
    {
      pid_t result = waitpid(pid, status, options);
      if (result == -1 && errno == EINTR)
      {
        // System call was interrupted by signal, retry
        continue;
      }
      return result;
    }
  }

private:
  pid_t _pid;
  SpawnOptions::TerminationStrategy _terminationStrategy;
  bool _detached;
  mutable std::optional<WaitResult> _cachedWaitResult;
  mutable std::mutex _mutex;

  /// \brief Cleanup helper - performs termination based on strategy.
  /// \note Called by destructor and move assignment operator.
  void cleanupProcess() noexcept
  {
    // CRITICAL FIX #2: Hold mutex for entire cleanup sequence
    std::unique_lock<std::mutex> lock(_mutex);

    if (_detached || _pid <= 0)
    {
      return;
    }

    switch (_terminationStrategy)
    {
      case SpawnOptions::TerminationStrategy::Graceful:
      {
        // Check if process is still running via direct waitpid call
        int status;
        pid_t result = waitpidWithEINTR(_pid, &status, WNOHANG);

        if (result == 0) // Process is running
        {
          // Send SIGTERM (PID validated inside terminate)
          if (::kill(_pid, 0) == 0)
          {
            ::kill(_pid, SIGTERM);
          }

          // Wait with timeout for graceful shutdown
          auto startTime = std::chrono::steady_clock::now();
          auto timeout = std::chrono::seconds(5);

          while (true)
          {
            result = waitpidWithEINTR(_pid, &status, WNOHANG);
            if (result == _pid)
            {
              // Process terminated, cache result and exit
              _cachedWaitResult = parseWaitStatus(status);
              break;
            }

            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now() - startTime);

            if (elapsed >= timeout)
            {
              // Timeout - escalate to SIGKILL
              if (::kill(_pid, 0) == 0)
              {
                ::kill(_pid, SIGKILL);
              }

              // Wait with shorter timeout after SIGKILL
              startTime = std::chrono::steady_clock::now();
              timeout = std::chrono::seconds(1);

              while (true)
              {
                result = waitpidWithEINTR(_pid, &status, WNOHANG);
                if (result == _pid)
                {
                  _cachedWaitResult = parseWaitStatus(status);
                  break;
                }

                elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - startTime);

                if (elapsed >= timeout)
                {
                  // CRITICAL FIX #1: Final non-blocking check, accept zombie if persists
                  result = waitpidWithEINTR(_pid, &status, WNOHANG);
                  if (result == _pid)
                  {
                    _cachedWaitResult = parseWaitStatus(status);
                  }
                  // If still not reaped, exit anyway - better than hanging
                  break;
                }

                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                lock.lock();
              }
              break;
            }

            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            lock.lock();
          }
        }
        else if (result == _pid)
        {
          // Process already terminated, cache result
          _cachedWaitResult = parseWaitStatus(status);
        }
        break;
      }

      case SpawnOptions::TerminationStrategy::Immediate:
      {
        // Check if process is still running via direct waitpid call
        int status;
        pid_t result = waitpidWithEINTR(_pid, &status, WNOHANG);

        if (result == 0) // Process is running
        {
          // Send SIGKILL (PID validated inside kill)
          if (::kill(_pid, 0) == 0)
          {
            ::kill(_pid, SIGKILL);
          }

          // Wait with timeout for termination
          auto startTime = std::chrono::steady_clock::now();
          auto timeout = std::chrono::seconds(1);

          while (true)
          {
            result = waitpidWithEINTR(_pid, &status, WNOHANG);
            if (result == _pid)
            {
              _cachedWaitResult = parseWaitStatus(status);
              break;
            }

            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now() - startTime);

            if (elapsed >= timeout)
            {
              // CRITICAL FIX #1: Final non-blocking check, accept zombie if persists
              result = waitpidWithEINTR(_pid, &status, WNOHANG);
              if (result == _pid)
              {
                _cachedWaitResult = parseWaitStatus(status);
              }
              // If still not reaped, exit anyway - better than hanging
              break;
            }

            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            lock.lock();
          }
        }
        else if (result == _pid)
        {
          // Process already terminated, cache result
          _cachedWaitResult = parseWaitStatus(status);
        }
        break;
      }

      case SpawnOptions::TerminationStrategy::None:
        // Do nothing
        break;
    }
  }

  /// \brief Parse waitpid status into WaitResult.
  static WaitResult parseWaitStatus(int status)
  {
    WaitResult result;
    result.exited = true;

    if (WIFEXITED(status))
    {
      result.exitCode = WEXITSTATUS(status);
      result.state = State::Exited;
    }
    else if (WIFSIGNALED(status))
    {
      result.signal = WTERMSIG(status);
      result.state = State::Signaled;
    }
    else
    {
      result.state = State::Unknown;
    }

    return result;
  }
};

/// \brief Executes shell commands and manages process lifecycles.
class ShellRunner
{
public:
  /// \brief Executes a shell command and returns output as string.
  /// \param command The shell command to execute.
  /// \return The output of the command.
  static std::string execute(const std::string &command)
  {
    std::array<char, 128> buffer;
    std::string result;

    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);

    if (!pipe)
    {
      throw std::runtime_error("ShellRunner error: Failed to open pipe for command execution");
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
    {
      result += buffer.data();
    }

    int exit_code = pclose(pipe.release());

    if (exit_code != 0)
    {
      throw std::runtime_error("ShellRunner error: Command failed with exit code " +
                               std::to_string(WEXITSTATUS(exit_code)));
    }

    return result;
  }

  /// \brief Executes a shell command and streams output to provided stream.
  /// \param command The shell command to execute.
  /// \param output Stream to write command output to.
  /// \return Exit code of the command.
  static int execute(const std::string &command, std::ostream &output)
  {
    std::array<char, 128> buffer;

    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);

    if (!pipe)
    {
      throw std::runtime_error("ShellRunner error: Failed to open pipe for command execution");
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
    {
      output << buffer.data();
      output.flush(); // Ensure real-time streaming
    }

    int exit_code = pclose(pipe.release());
    return WEXITSTATUS(exit_code);
  }

  /// \brief Executes a shell command with advanced options.
  /// \param command The shell command to execute.
  /// \param options Execution options (timeout, environment, etc.).
  /// \return Detailed execution result.
  static ExecutionResult executeWithOptions(const std::string &command,
                                            const ExecutionOptions &options = {})
  {
    auto start_time = std::chrono::steady_clock::now();
    ExecutionResult result;

    // Build command with environment and working directory
    std::string full_command = buildCommand(command, options);

    // Execute command
    std::array<char, 128> buffer;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(full_command.c_str(), "r"), pclose);

    if (!pipe)
    {
      if (options.throwOnError)
      {
        throw std::runtime_error("ShellRunner error: Failed to open pipe for command execution");
      }
      result.exitCode = -1;
      return result;
    }

    // Read output with optional timeout
    if (options.timeout.count() > 0)
    {
      result = readWithTimeout(pipe.get(), options.timeout);
    }
    else
    {
      while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
      {
        result.stdout += buffer.data();
      }
    }

    int exit_code = pclose(pipe.release());
    result.exitCode = WEXITSTATUS(exit_code);

    auto end_time = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    if (options.throwOnError && result.exitCode != 0 && !result.timedOut)
    {
      throw std::runtime_error("ShellRunner error: Command failed with exit code " +
                               std::to_string(result.exitCode));
    }

    return result;
  }

  /// \brief Executes a command with input provided via stdin.
  /// \param command The shell command to execute.
  /// \param input Input to provide to the command via stdin.
  /// \return The output of the command.
  static std::string executeWithInput(const std::string &command, const std::string &input)
  {
    // Create temporary file for input
    std::string temp_file = "/tmp/iora_shell_input_" + std::to_string(getpid());

    // Write input to temporary file
    FILE *temp = fopen(temp_file.c_str(), "w");
    if (!temp)
    {
      throw std::runtime_error("ShellRunner error: Failed to create temporary input file");
    }

    fwrite(input.c_str(), 1, input.size(), temp);
    fclose(temp);

    // Execute command with input redirection
    std::string full_command = command + " < " + temp_file;
    std::string result = execute(full_command);

    // Clean up temporary file
    unlink(temp_file.c_str());

    return result;
  }

  //
  // === Process Lifecycle Management ===
  //

  /// \brief Spawn background process with RAII handle.
  /// \param command The shell command to execute.
  /// \param options Spawn options for process configuration.
  /// \return ProcessHandle for managing the spawned process.
  static ProcessHandle spawn(const std::string &command, const SpawnOptions &options = {})
  {
    pid_t pid = fork();

    if (pid < 0)
    {
      throw std::runtime_error("ShellRunner error: Failed to fork process");
    }

    if (pid == 0)
    {
      // Child process
      childProcessSetup(command, options);
      // childProcessSetup never returns
    }

    // Parent process - also set process group from parent side to avoid race
    if (options.createProcessGroup)
    {
      setpgid(pid, pid);
    }

    return ProcessHandle(pid, options.terminationStrategy);
  }

  /// \brief Find processes matching regex pattern.
  /// \param pattern Regex pattern to match against process command lines.
  /// \return Vector of matching PIDs.
  static std::vector<pid_t> findProcesses(const std::string &pattern)
  {
    std::vector<pid_t> pids;
    std::regex regex(pattern);

    // Read /proc directory
    auto procDir = opendir("/proc");
    if (!procDir)
    {
      return pids;
    }

    struct dirent *entry;
    while ((entry = readdir(procDir)) != nullptr)
    {
      // Check if directory name is a number (PID)
      std::string name = entry->d_name;
      if (name.empty() || !std::isdigit(name[0]))
      {
        continue;
      }

      pid_t pid = std::stoi(name);

      // Read command line from /proc/[pid]/cmdline
      std::string cmdlinePath = "/proc/" + name + "/cmdline";
      std::ifstream cmdlineFile(cmdlinePath);
      if (!cmdlineFile.is_open())
      {
        continue;
      }

      // Read entire cmdline (null-separated arguments)
      std::string cmdline;
      std::string arg;
      while (std::getline(cmdlineFile, arg, '\0'))
      {
        if (!cmdline.empty())
        {
          cmdline += ' ';
        }
        cmdline += arg;
      }

      // Check if command line matches pattern
      if (std::regex_search(cmdline, regex))
      {
        pids.push_back(pid);
      }
    }

    closedir(procDir);
    return pids;
  }

  /// \brief Kill processes matching pattern.
  /// \param pattern Regex pattern to match against process command lines.
  /// \param sig Signal to send (default: SIGKILL).
  /// \param waitFor Time to wait after sending signal.
  /// \return Number of processes killed.
  static int killProcesses(const std::string &pattern, int sig = SIGKILL,
                          std::chrono::milliseconds waitFor = std::chrono::milliseconds(200))
  {
    auto pids = findProcesses(pattern);
    int killed = 0;

    for (pid_t pid : pids)
    {
      if (::kill(pid, sig) == 0)
      {
        killed++;
      }
    }

    if (waitFor.count() > 0)
    {
      std::this_thread::sleep_for(waitFor);
    }

    return killed;
  }

  /// \brief Check if process is running.
  /// \param pid Process ID to check.
  /// \return True if process is running.
  static bool isProcessRunning(pid_t pid)
  {
    if (pid <= 0)
    {
      return false;
    }

    int status;
    pid_t result = ProcessHandle::waitpidWithEINTR(pid, &status, WNOHANG);
    return result == 0; // 0 means still running
  }

  /// \brief Get process state.
  /// \param pid Process ID to query.
  /// \return Process state.
  static ProcessHandle::State getProcessState(pid_t pid)
  {
    if (pid <= 0)
    {
      return ProcessHandle::State::Unknown;
    }

    int status;
    pid_t result = ProcessHandle::waitpidWithEINTR(pid, &status, WNOHANG);

    if (result == 0)
    {
      return ProcessHandle::State::Running;
    }
    else if (result == pid)
    {
      if (WIFEXITED(status))
      {
        return ProcessHandle::State::Exited;
      }
      else if (WIFSIGNALED(status))
      {
        return ProcessHandle::State::Signaled;
      }
    }

    return ProcessHandle::State::Unknown;
  }

  /// \brief Wait for specific process.
  /// \param pid Process ID to wait for.
  /// \param timeout Maximum time to wait (0 = wait forever).
  /// \return WaitResult with exit status.
  static ProcessHandle::WaitResult waitForProcess(
    pid_t pid, std::chrono::milliseconds timeout = std::chrono::milliseconds(0))
  {
    ProcessHandle::WaitResult result;

    if (pid <= 0)
    {
      result.state = ProcessHandle::State::Unknown;
      return result;
    }

    auto startTime = std::chrono::steady_clock::now();

    while (true)
    {
      int status;
      pid_t waitResult = ProcessHandle::waitpidWithEINTR(pid, &status, WNOHANG);

      if (waitResult == pid)
      {
        // Process has terminated
        result.exited = true;

        if (WIFEXITED(status))
        {
          result.exitCode = WEXITSTATUS(status);
          result.state = ProcessHandle::State::Exited;
        }
        else if (WIFSIGNALED(status))
        {
          result.signal = WTERMSIG(status);
          result.state = ProcessHandle::State::Signaled;
        }

        return result;
      }
      else if (waitResult == -1)
      {
        // Error
        result.state = ProcessHandle::State::Unknown;
        return result;
      }

      // Process still running, check timeout
      if (timeout.count() > 0)
      {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - startTime);

        if (elapsed >= timeout)
        {
          result.timedOut = true;
          result.state = ProcessHandle::State::Running;
          return result;
        }
      }

      // Sleep briefly before checking again
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }

  /// \brief Send signal to process.
  /// \param pid Process ID to signal.
  /// \param sig Signal number.
  /// \return True if signal was sent successfully.
  static bool sendSignal(pid_t pid, int sig)
  {
    if (pid <= 0)
    {
      return false;
    }
    return ::kill(pid, sig) == 0;
  }

  /// \brief Kill entire process group.
  /// \param pgid Process group ID.
  /// \param sig Signal to send (default: SIGKILL).
  /// \return True if signal was sent successfully.
  static bool killProcessGroup(pid_t pgid, int sig = SIGKILL)
  {
    if (pgid <= 0)
    {
      return false;
    }
    return ::kill(-pgid, sig) == 0; // Negative PID kills process group
  }

private:
  static std::string buildCommand(const std::string &command, const ExecutionOptions &options)
  {
    std::string full_command;

    // Add environment variables
    for (const auto &env : options.environment)
    {
      full_command += env.first + "=" + env.second + " ";
    }

    // Add working directory change
    if (!options.workingDirectory.empty())
    {
      full_command += "cd " + options.workingDirectory + " && ";
    }

    full_command += command;

    return full_command;
  }

  static ExecutionResult readWithTimeout(FILE *pipe, std::chrono::milliseconds timeout)
  {
    ExecutionResult result;
    std::array<char, 128> buffer;

    auto start_time = std::chrono::steady_clock::now();

    // Set pipe to non-blocking mode
    int fd = fileno(pipe);
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    while (true)
    {
      auto current_time = std::chrono::steady_clock::now();
      auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time);

      if (elapsed >= timeout)
      {
        result.timedOut = true;
        break;
      }

      char *read_result = fgets(buffer.data(), buffer.size(), pipe);
      if (read_result != nullptr)
      {
        result.stdout += buffer.data();
      }
      else if (feof(pipe))
      {
        break; // End of output
      }
      else
      {
        // No data available, sleep briefly
        usleep(1000); // 1ms
      }
    }

    return result;
  }

  /// \brief Child process setup (runs in child after fork).
  [[noreturn]] static void childProcessSetup(const std::string &command,
                                             const SpawnOptions &options)
  {
    // Create new process group if requested
    if (options.createProcessGroup)
    {
      setpgid(0, 0);
    }

    // Redirect stdout
    if (!options.stdoutFile.empty())
    {
      int fd = open(options.stdoutFile.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
      if (fd < 0)
      {
        _exit(127); // Exit if file open fails
      }
      // MAJOR FIX #5: Add fcntl() fallback for O_CLOEXEC
      fcntl(fd, F_SETFD, FD_CLOEXEC);
      if (dup2(fd, STDOUT_FILENO) < 0)
      {
        close(fd);
        _exit(127); // Exit if dup2 fails
      }
      close(fd);
    }

    // Redirect stderr
    if (!options.stderrFile.empty())
    {
      int fd = open(options.stderrFile.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
      if (fd < 0)
      {
        _exit(127); // Exit if file open fails
      }
      // MAJOR FIX #5: Add fcntl() fallback for O_CLOEXEC
      fcntl(fd, F_SETFD, FD_CLOEXEC);
      if (dup2(fd, STDERR_FILENO) < 0)
      {
        close(fd);
        _exit(127); // Exit if dup2 fails
      }
      close(fd);
    }

    // MAJOR FIX #6: Replace setenv() with execve() for async-signal-safety
    // Build environment array for execve
    std::vector<std::string> envStrings;
    std::vector<char*> envp;

    // Start with custom environment if provided, otherwise use execl with inherited environment
    if (!options.environment.empty())
    {
      for (const auto &env : options.environment)
      {
        envStrings.push_back(env.first + "=" + env.second);
      }

      // Convert to char* array for execve
      for (auto& envStr : envStrings)
      {
        envp.push_back(&envStr[0]);
      }
      envp.push_back(nullptr);
    }

    // Change working directory
    if (!options.workingDirectory.empty())
    {
      if (chdir(options.workingDirectory.c_str()) != 0)
      {
        _exit(127); // Exit with error code if chdir fails
      }
    }

    // Execute command via shell
    if (!options.environment.empty())
    {
      // Use execve for custom environment (async-signal-safe)
      const char* args[] = {"sh", "-c", command.c_str(), nullptr};
      execve("/bin/sh", const_cast<char* const*>(args), envp.data());
    }
    else
    {
      // Use execl to inherit parent environment
      execl("/bin/sh", "sh", "-c", command.c_str(), nullptr);
    }

    // If exec returns, there was an error
    _exit(127);
  }
};

} // namespace system
} // namespace iora
