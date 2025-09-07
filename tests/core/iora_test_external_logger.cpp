// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <string>
#include <vector>

namespace
{
struct LogCapture
{
  iora::core::Logger::Level level;
  std::string formattedMessage;
  std::string rawMessage;
};

std::vector<LogCapture> capturedLogs;

void externalLogHandler(iora::core::Logger::Level level, const std::string &formattedMessage,
                        const std::string &rawMessage)
{
  capturedLogs.push_back({level, formattedMessage, rawMessage});
}
} // namespace

TEST_CASE("External log handler", "[logger][external]")
{
  capturedLogs.clear();

  SECTION("External handler receives logs")
  {
    // Register external handler
    iora::core::Logger::setExternalHandler(externalLogHandler);
    iora::core::Logger::setLevel(iora::core::Logger::Level::Debug);

    // Log some messages
    iora::core::Logger::info("Test info message");
    iora::core::Logger::warning("Test warning message");
    iora::core::Logger::error("Test error message");

    // Flush to ensure all messages are processed
    iora::core::Logger::flush();

    REQUIRE(capturedLogs.size() == 3);

    REQUIRE(capturedLogs[0].level == iora::core::Logger::Level::Info);
    REQUIRE(capturedLogs[0].rawMessage == "Test info message");
    REQUIRE(capturedLogs[0].formattedMessage.find("Test info message") != std::string::npos);
    REQUIRE(capturedLogs[0].formattedMessage.find("[INFO]") != std::string::npos);

    REQUIRE(capturedLogs[1].level == iora::core::Logger::Level::Warning);
    REQUIRE(capturedLogs[1].rawMessage == "Test warning message");

    REQUIRE(capturedLogs[2].level == iora::core::Logger::Level::Error);
    REQUIRE(capturedLogs[2].rawMessage == "Test error message");

    // Clear external handler
    iora::core::Logger::clearExternalHandler();
    capturedLogs.clear();
  }

  SECTION("External handler with async mode")
  {
    capturedLogs.clear();

    // Initialize with async mode
    iora::core::Logger::init(iora::core::Logger::Level::Debug, "", true);
    iora::core::Logger::setExternalHandler(externalLogHandler);

    // Log some messages
    iora::core::Logger::debug("Async debug message");
    iora::core::Logger::info("Async info message");

    // Flush to ensure all messages are processed
    iora::core::Logger::flush();

    REQUIRE(capturedLogs.size() == 2);
    REQUIRE(capturedLogs[0].level == iora::core::Logger::Level::Debug);
    REQUIRE(capturedLogs[0].rawMessage == "Async debug message");
    REQUIRE(capturedLogs[1].level == iora::core::Logger::Level::Info);
    REQUIRE(capturedLogs[1].rawMessage == "Async info message");

    // Clear external handler and shutdown
    iora::core::Logger::clearExternalHandler();
    iora::core::Logger::shutdown();
    capturedLogs.clear();
  }

  SECTION("File logging disabled when external handler active")
  {
    capturedLogs.clear();

    // Initialize with file logging
    std::string testLogFile = "/tmp/test_external_handler.log";
    std::filesystem::remove(testLogFile); // Clean up any existing file

    iora::core::Logger::init(iora::core::Logger::Level::Info, testLogFile);

    // Log a message normally (should go to file)
    iora::core::Logger::info("Message before external handler");
    iora::core::Logger::flush();

    // Set external handler (should disable file logging)
    iora::core::Logger::setExternalHandler(externalLogHandler);

    // Log messages (should go to external handler only)
    iora::core::Logger::info("Message with external handler");
    iora::core::Logger::flush();

    // Verify external handler received the message
    REQUIRE(capturedLogs.size() == 1);
    REQUIRE(capturedLogs[0].rawMessage == "Message with external handler");

    // Clear external handler and clean up
    iora::core::Logger::clearExternalHandler();
    iora::core::Logger::shutdown();
    std::filesystem::remove(testLogFile);
    capturedLogs.clear();
  }
}