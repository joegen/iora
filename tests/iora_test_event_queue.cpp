#include "iora/iora.hpp"
#include "catch2/catch_test_macros.hpp"
#include <atomic>
#include <thread>

TEST_CASE("EventQueue processes valid events", "[EventQueue]")
{
  iora::util::EventQueue queue(2);
  std::atomic<int> counter{0};

  queue.onEventId("testId",
                  [&](const iora::json::Json& event)
                  {
                    REQUIRE(event["eventId"] == "testId");
                    counter++;
                  });

  iora::json::Json validEvent = {{"eventId", "testId"},
                                 {"eventName", "testEvent"}};
  queue.push(validEvent);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 1);
}

TEST_CASE("EventQueue drops invalid events", "[EventQueue]")
{
  iora::util::EventQueue queue(2);
  std::atomic<int> counter{0};

  queue.onEventId("testId", [&](const iora::json::Json&) { counter++; });

  iora::json::Json invalidEvent = {{"eventName", "testEvent"}};
  queue.push(invalidEvent);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 0);
}

TEST_CASE("EventQueue matches eventName with glob patterns", "[EventQueue]")
{
  iora::util::EventQueue queue(2);
  std::atomic<int> counter{0};

  queue.onEventNameMatches(
      "^test.*",
      [&](const iora::json::Json& event)
      {
        REQUIRE(event["eventName"].get<std::string>().find("test") == 0);
        counter++;
      });

  iora::json::Json matching = {{"eventId", "id1"}, {"eventName", "testEvent"}};
  iora::json::Json nonMatching = {{"eventId", "id2"},
                                  {"eventName", "otherEvent"}};

  queue.push(matching);
  queue.push(nonMatching);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 1);
}

TEST_CASE("EventQueue matches eventName exactly", "[EventQueue]")
{
  iora::util::EventQueue queue(2);
  std::atomic<int> counter{0};

  queue.onEventName("testEvent",
                    [&](const iora::json::Json& event)
                    {
                      REQUIRE(event["eventName"] == "testEvent");
                      counter++;
                    });

  iora::json::Json match = {{"eventId", "id1"}, {"eventName", "testEvent"}};
  iora::json::Json noMatch = {{"eventId", "id2"}, {"eventName", "otherEvent"}};

  queue.push(match);
  queue.push(noMatch);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 1);
}

TEST_CASE("EventQueue handles concurrent pushes and handlers", "[EventQueue]")
{
  iora::util::EventQueue queue(4);
  std::atomic<int> counter{0};
  queue.onEventId("testId", [&](const iora::json::Json&) { counter++; });

  std::vector<std::thread> threads;
  for (int i = 0; i < 10; ++i)
  {
    threads.emplace_back(
        [&queue]()
        {
          iora::json::Json event = {{"eventId", "testId"},
                                    {"eventName", "testEvent"}};
          queue.push(event);
        });
  }

  for (auto& t : threads)
  {
    t.join();
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 10);
}

TEST_CASE("EventQueue shuts down gracefully", "[EventQueue]")
{
  iora::util::EventQueue queue(2);
  std::atomic<int> counter{0};

  queue.onEventId("testId", [&](const iora::json::Json&) { counter++; });
  queue.push({{"eventId", "testId"}, {"eventName", "testEvent"}});

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(counter == 1);
}
