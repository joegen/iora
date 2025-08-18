// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Shared test helpers for Iora test suite
// This file contains common utilities used across multiple test files

#pragma once

// Include the full iora header for now - tests need full access
#include "iora/iora.hpp"
#include <fstream>
#include <dlfcn.h>
#include <filesystem>
#include <chrono>
#include <thread>
#include <random>
#include <ctime>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

namespace iora::test {

/// \brief Automatic logger initialization for tests
struct LoggerInit 
{
  LoggerInit() 
  {
    iora::core::Logger::setLevel(iora::core::Logger::Level::Debug);
  }
};

/// \brief Static logger initializer - call once per test executable
inline void initializeTestLogging() 
{
  static LoggerInit init;
  (void)init; // Suppress unused variable warning
}

/// \brief Type alias for automatic service shutdown
using AutoServiceShutdown = iora::IoraService::AutoServiceShutdown;

/// \brief Helper function to create IoraService from CLI-style arguments
inline iora::IoraService& initServiceFromArgs(int argc, const char* args[])
{
  return iora::IoraService::init(argc, const_cast<char**>(args));
}

/// \brief Helper to create a basic test IoraService configuration
inline iora::IoraService::Config createTestConfig(int port = 8080)
{
  iora::IoraService::Config config;
  config.server.port = port;
  config.log.level = "debug";
  config.log.file = "test_" + std::to_string(port);
  return config;
}

/// \brief RAII helper for temporary test files
class TempFileManager
{
public:
  TempFileManager() = default;
  ~TempFileManager()
  {
    cleanup();
  }

  void addFile(const std::string& filename)
  {
    _files.push_back(filename);
  }

  void cleanup()
  {
    for (const auto& file : _files)
    {
      std::remove(file.c_str());
    }
    _files.clear();
  }

private:
  std::vector<std::string> _files;
};

/// \brief Helper for testing with temporary directories
class TempDirManager
{
public:
  TempDirManager(const std::string& prefix = "iora_test_")
    : _dir("/tmp/" + prefix + std::to_string(std::time(nullptr)))
  {
    std::filesystem::create_directories(_dir);
  }

  ~TempDirManager()
  {
    if (std::filesystem::exists(_dir))
    {
      std::filesystem::remove_all(_dir);
    }
  }

  const std::string& path() const { return _dir; }
  std::string filePath(const std::string& filename) const
  {
    return _dir + "/" + filename;
  }

private:
  std::string _dir;
};

/// \brief Helper to wait for a condition with timeout
template<typename Predicate>
bool waitFor(Predicate pred, std::chrono::milliseconds timeout = std::chrono::milliseconds(5000))
{
  auto start = std::chrono::steady_clock::now();
  while (!pred())
  {
    if (std::chrono::steady_clock::now() - start > timeout)
    {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return true;
}

/// \brief Helper to generate random strings for testing
inline std::string generateRandomString(size_t length = 10)
{
  static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);
  
  std::string result;
  result.reserve(length);
  for (size_t i = 0; i < length; ++i)
  {
    result += charset[dis(gen)];
  }
  return result;
}

/// \brief Helper to check if a port is available
inline bool isPortAvailable(int port)
{
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) return false;
  
  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);
  
  int result = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
  close(sock);
  return result == 0;
}

/// \brief Find an available port in a range
inline int findAvailablePort(int start = 8000, int end = 9000)
{
  for (int port = start; port < end; ++port)
  {
    if (isPortAvailable(port))
    {
      return port;
    }
  }
  return -1; // No available port found
}

} // namespace iora::test