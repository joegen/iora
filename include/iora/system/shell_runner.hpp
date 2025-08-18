// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <string>
#include <stdexcept>
#include <memory>
#include <array>
#include <vector>
#include <unordered_map>
#include <ostream>
#include <chrono>
#include <cstdio>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>

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

  /// \brief Executes shell commands and captures their output.
  class ShellRunner
  {
  public:
    /// \brief Executes a shell command and returns output as string.
    /// \param command The shell command to execute.
    /// \return The output of the command.
    static std::string execute(const std::string& command)
    {
      std::array<char, 128> buffer;
      std::string result;

      std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"),
                                                    pclose);

      if (!pipe)
      {
        throw std::runtime_error(
            "ShellRunner error: Failed to open pipe for command execution");
      }

      while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
      {
        result += buffer.data();
      }

      int exit_code = pclose(pipe.release());

      if (exit_code != 0)
      {
        throw std::runtime_error(
            "ShellRunner error: Command failed with exit code " +
            std::to_string(WEXITSTATUS(exit_code)));
      }

      return result;
    }

    /// \brief Executes a shell command and streams output to provided stream.
    /// \param command The shell command to execute.
    /// \param output Stream to write command output to.
    /// \return Exit code of the command.
    static int execute(const std::string& command, std::ostream& output)
    {
      std::array<char, 128> buffer;

      std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"),
                                                    pclose);

      if (!pipe)
      {
        throw std::runtime_error(
            "ShellRunner error: Failed to open pipe for command execution");
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
    static ExecutionResult
    executeWithOptions(const std::string& command,
                       const ExecutionOptions& options = {})
    {
      auto start_time = std::chrono::steady_clock::now();
      ExecutionResult result;

      // Build command with environment and working directory
      std::string full_command = buildCommand(command, options);

      // Execute command
      std::array<char, 128> buffer;
      std::unique_ptr<FILE, decltype(&pclose)> pipe(
          popen(full_command.c_str(), "r"), pclose);

      if (!pipe)
      {
        if (options.throwOnError)
        {
          throw std::runtime_error(
              "ShellRunner error: Failed to open pipe for command execution");
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
      result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
          end_time - start_time);

      if (options.throwOnError && result.exitCode != 0 && !result.timedOut)
      {
        throw std::runtime_error(
            "ShellRunner error: Command failed with exit code " +
            std::to_string(result.exitCode));
      }

      return result;
    }

    /// \brief Executes a command with input provided via stdin.
    /// \param command The shell command to execute.
    /// \param input Input to provide to the command via stdin.
    /// \return The output of the command.
    static std::string executeWithInput(const std::string& command,
                                        const std::string& input)
    {
      // Create temporary file for input
      std::string temp_file =
          "/tmp/iora_shell_input_" + std::to_string(getpid());

      // Write input to temporary file
      FILE* temp = fopen(temp_file.c_str(), "w");
      if (!temp)
      {
        throw std::runtime_error(
            "ShellRunner error: Failed to create temporary input file");
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

  private:
    static std::string buildCommand(const std::string& command,
                                    const ExecutionOptions& options)
    {
      std::string full_command;

      // Add environment variables
      for (const auto& env : options.environment)
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

    static ExecutionResult readWithTimeout(FILE* pipe,
                                           std::chrono::milliseconds timeout)
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
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            current_time - start_time);

        if (elapsed >= timeout)
        {
          result.timedOut = true;
          break;
        }

        char* read_result = fgets(buffer.data(), buffer.size(), pipe);
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
  };

} // namespace system
} // namespace iora
