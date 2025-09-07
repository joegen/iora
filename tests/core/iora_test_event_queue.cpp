// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

TEST_CASE("EventQueue processes valid events", "[EventQueue]")
{
  iora::core::EventQueue queue(2);
  std::atomic<int> counter{0};

  queue.onEventId("testId",
                  [&](const iora::parsers::Json &event)
                  {
                    REQUIRE(event["eventId"] == "testId");
                    counter++;
                  });

  auto validEvent = iora::parsers::Json::object();
  validEvent["eventId"] = "testId";
  validEvent["eventName"] = "testEvent";
  queue.push(validEvent);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 1);
}

TEST_CASE("EventQueue drops invalid events", "[EventQueue]")
{
  iora::core::EventQueue queue(2);
  std::atomic<int> counter{0};

  queue.onEventId("testId", [&](const iora::parsers::Json &) { counter++; });

  auto invalidEvent = iora::parsers::Json::object();
  invalidEvent["eventName"] = "testEvent";
  queue.push(invalidEvent);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 0);
}

TEST_CASE("EventQueue matches eventName with glob patterns", "[EventQueue]")
{
  iora::core::EventQueue queue(2);
  std::atomic<int> counter{0};

  queue.onEventNameMatches("^test.*",
                           [&](const iora::parsers::Json &event)
                           {
                             REQUIRE(event["eventName"].get<std::string>().find("test") == 0);
                             counter++;
                           });

  auto matching = iora::parsers::Json::object();
  matching["eventId"] = "id1";
  matching["eventName"] = "testEvent";
  auto nonMatching = iora::parsers::Json::object();
  nonMatching["eventId"] = "id2";
  nonMatching["eventName"] = "otherEvent";

  queue.push(matching);
  queue.push(nonMatching);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 1);
}

TEST_CASE("EventQueue matches eventName exactly", "[EventQueue]")
{
  iora::core::EventQueue queue(2);
  std::atomic<int> counter{0};

  queue.onEventName("testEvent",
                    [&](const iora::parsers::Json &event)
                    {
                      REQUIRE(event["eventName"] == "testEvent");
                      counter++;
                    });

  auto match = iora::parsers::Json::object();
  match["eventId"] = "id1";
  match["eventName"] = "testEvent";
  auto noMatch = iora::parsers::Json::object();
  noMatch["eventId"] = "id2";
  noMatch["eventName"] = "otherEvent";

  queue.push(match);
  queue.push(noMatch);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 1);
}

TEST_CASE("EventQueue handles concurrent pushes and handlers", "[EventQueue]")
{
  iora::core::EventQueue queue(4);
  std::atomic<int> counter{0};
  queue.onEventId("testId", [&](const iora::parsers::Json &) { counter++; });

  std::vector<std::thread> threads;
  for (int i = 0; i < 10; ++i)
  {
    threads.emplace_back(
      [&queue]()
      {
        auto event = iora::parsers::Json::object();
        event["eventId"] = "testId";
        event["eventName"] = "testEvent";
        queue.push(event);
      });
  }

  for (auto &t : threads)
  {
    t.join();
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 10);
}

TEST_CASE("EventQueue shuts down gracefully", "[EventQueue]")
{
  iora::core::EventQueue queue(2);
  std::atomic<int> counter{0};

  queue.onEventId("testId", [&](const iora::parsers::Json &) { counter++; });
  auto event = iora::parsers::Json::object();
  event["eventId"] = "testId";
  event["eventName"] = "testEvent";
  queue.push(event);

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 1);
}
