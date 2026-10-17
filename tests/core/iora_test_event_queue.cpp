// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <atomic>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

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

// ── Owner tracking (plugin_callback_ownership C2: E-1..E-8) ──────────────────

namespace
{

using iora::core::CallbackGate;
using iora::core::CallbackOwner;
using iora::core::EventQueue;
using Json = iora::parsers::Json;

constexpr auto OWN_BOUND = std::chrono::seconds(5);
constexpr auto OWN_SETTLE = std::chrono::milliseconds(150);

Json ownEvent(const std::string &id, const std::string &name)
{
  auto e = Json::object();
  e["eventId"] = id;
  e["eventName"] = name;
  return e;
}

/// Runs drain(owner) on a detached thread so a hang fails the test instead of
/// wedging it.
std::shared_future<void> ownDrainAsync(const std::string &owner)
{
  auto done = std::make_shared<std::promise<void>>();
  std::shared_future<void> f = done->get_future().share();
  std::thread(
    [done, owner]
    {
      CallbackGate::drain(owner);
      done->set_value();
    })
    .detach();
  return f;
}

/// A handler that parks at phase 1 until the test sets phase 2 (bounded).
struct SlowPhase
{
  std::atomic<int> phase{0};

  void hold()
  {
    phase.store(1);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (phase.load() != 2 && std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }

  ~SlowPhase() { phase.store(2); }
};

} // namespace

TEST_CASE("E-1 removeHandlersOwnedBy removes the owner's id, name and pattern handlers",
          "[EventQueue][owner]")
{
  std::atomic<int> aId{0}, aName{0}, aPattern{0}, bId{0}, unowned{0};
  EventQueue queue(2);
  queue.enableCallbackOwnerTracking();
  {
    CallbackOwner::Scope scope("e1.A");
    queue.onEventId("e1", [&](const Json &) { ++aId; });
    queue.onEventName("n1", [&](const Json &) { ++aName; });
    queue.onEventNameMatches("^n1$", [&](const Json &) { ++aPattern; });
  }
  {
    CallbackOwner::Scope scope("e1.B");
    queue.onEventId("e1", [&](const Json &) { ++bId; });
  }
  queue.onEventName("n1", [&](const Json &) { ++unowned; });

  queue.push(ownEvent("e1", "n1"));
  REQUIRE(iora::test::waitFor([&] { return aId == 1 && aName == 1 && aPattern == 1 && bId == 1 && unowned == 1; },
                       OWN_BOUND));

  queue.removeHandlersOwnedBy("e1.A");
  queue.push(ownEvent("e1", "n1"));
  REQUIRE(iora::test::waitFor([&] { return bId == 2 && unowned == 2; }, OWN_BOUND));
  std::this_thread::sleep_for(OWN_SETTLE);
  REQUIRE(aId == 1);
  REQUIRE(aName == 1);
  REQUIRE(aPattern == 1);
  REQUIRE_THROWS_AS(queue.removeHandlersOwnedBy(""), std::invalid_argument);
}

TEST_CASE("E-2 a closed owner's handler is skipped and runs again after open", "[EventQueue][owner]")
{
  std::atomic<int> owned{0}, unowned{0};
  EventQueue queue(2);
  queue.enableCallbackOwnerTracking();
  {
    CallbackOwner::Scope scope("e2.A");
    queue.onEventName("n2", [&](const Json &) { ++owned; });
  }
  queue.onEventName("n2", [&](const Json &) { ++unowned; });

  CallbackGate::close("e2.A");
  queue.push(ownEvent("e2", "n2"));
  REQUIRE(iora::test::waitFor([&] { return unowned == 1; }, OWN_BOUND));
  std::this_thread::sleep_for(OWN_SETTLE);
  REQUIRE(owned == 0);

  CallbackGate::open("e2.A");
  queue.push(ownEvent("e2", "n2"));
  REQUIRE(iora::test::waitFor([&] { return owned == 1 && unowned == 2; }, OWN_BOUND));
}

TEST_CASE("E-3 drain waits for a handler admitted before close", "[EventQueue][owner]")
{
  SlowPhase slow;
  std::atomic<bool> finished{false};
  EventQueue queue(2);
  queue.enableCallbackOwnerTracking();
  {
    CallbackOwner::Scope scope("e3.A");
    queue.onEventName("n3",
                      [&](const Json &)
                      {
                        slow.hold();
                        finished = true;
                      });
  }
  queue.push(ownEvent("e3", "n3"));
  REQUIRE(iora::test::waitFor([&] { return slow.phase == 1; }, OWN_BOUND));

  CallbackGate::close("e3.A");
  auto drained = ownDrainAsync("e3.A");
  REQUIRE(drained.wait_for(OWN_SETTLE) == std::future_status::timeout);
  slow.phase = 2;
  REQUIRE(drained.wait_for(OWN_BOUND) == std::future_status::ready);
  REQUIRE(finished);
  CallbackGate::open("e3.A");
}

namespace
{
struct PushOnDestroy
{
  EventQueue *queue = nullptr;
  ~PushOnDestroy() { queue->push(ownEvent("e4.after", "n4.after")); }
};
} // namespace

TEST_CASE("E-4 a removed handler is destroyed off the queue lock", "[EventQueue][owner]")
{
  auto queue = std::make_shared<EventQueue>(2);
  queue->enableCallbackOwnerTracking();
  auto after = std::make_shared<std::atomic<int>>(0);
  queue->onEventName("n4.after", [after](const Json &) { ++*after; });
  {
    CallbackOwner::Scope scope("e4.A");
    auto probe = std::make_shared<PushOnDestroy>();
    probe->queue = queue.get();
    queue->onEventName("n4", [probe](const Json &) {});
  }
  std::this_thread::sleep_for(OWN_SETTLE);
  REQUIRE(after->load() == 0);

  auto done = std::make_shared<std::promise<void>>();
  auto removed = done->get_future();
  std::thread(
    [queue, done]
    {
      queue->removeHandlersOwnedBy("e4.A");
      done->set_value();
    })
    .detach();
  const bool returned = removed.wait_for(OWN_BOUND) == std::future_status::ready;
  if (!returned)
  {
    // Destroyed under the lock: the worker is stuck on the queue mutex. Keep the
    // queue alive (the detached worker owns a reference) and fail.
    FAIL("removeHandlersOwnedBy deadlocked: removed handler destroyed under the queue lock");
  }
  REQUIRE(iora::test::waitFor([&] { return after->load() == 1; }, OWN_BOUND));
}

TEST_CASE("E-5 a same-pattern overwrite moves the owner", "[EventQueue][owner]")
{
  std::atomic<int> a{0}, b{0};
  EventQueue queue(2);
  queue.enableCallbackOwnerTracking();
  {
    CallbackOwner::Scope scope("e5.A");
    queue.onEventNameMatches("^n5$", [&](const Json &) { ++a; });
  }
  {
    CallbackOwner::Scope scope("e5.B");
    queue.onEventNameMatches("^n5$", [&](const Json &) { ++b; });
  }
  queue.removeHandlersOwnedBy("e5.A");
  queue.push(ownEvent("e5", "n5"));
  REQUIRE(iora::test::waitFor([&] { return b == 1; }, OWN_BOUND));
  std::this_thread::sleep_for(OWN_SETTLE);
  REQUIRE(a == 0);
}

TEST_CASE("E-6 each admission is released right after its own handler", "[EventQueue][owner]")
{
  SlowPhase slow;
  std::atomic<int> aRan{0};
  std::atomic<int> seenAdmitted{-1};
  EventQueue queue(1);
  queue.enableCallbackOwnerTracking();
  {
    CallbackOwner::Scope scope("e6.A");
    queue.onEventId("e6", [&](const Json &) { ++aRan; });
  }
  queue.onEventName("n6",
                    [&](const Json &)
                    {
                      seenAdmitted = CallbackGate::admittedOnThisThread("e6.A") ? 1 : 0;
                      slow.hold();
                    });

  queue.push(ownEvent("e6", "n6"));
  REQUIRE(iora::test::waitFor([&] { return slow.phase == 1; }, OWN_BOUND));
  REQUIRE(aRan == 1);
  REQUIRE(seenAdmitted == 0);

  CallbackGate::close("e6.A");
  auto drained = ownDrainAsync("e6.A");
  const bool returned = drained.wait_for(OWN_BOUND) == std::future_status::ready;
  slow.phase = 2;
  CallbackGate::open("e6.A");
  REQUIRE(returned);
  REQUIRE(drained.wait_for(OWN_BOUND) == std::future_status::ready);
}

namespace
{
struct RecordAdmittedOnDestroy
{
  std::shared_ptr<std::atomic<int>> record;
  std::thread::id testThread;
  ~RecordAdmittedOnDestroy()
  {
    if (record && std::this_thread::get_id() != testThread)
    {
      record->store(CallbackGate::admittedOnThisThread("e7.A") ? 1 : 0);
    }
  }
};
} // namespace

TEST_CASE("E-7 the handler copy is destroyed while still admitted", "[EventQueue][owner]")
{
  auto record = std::make_shared<std::atomic<int>>(-1);
  std::atomic<int> ran{0};
  EventQueue queue(1);
  queue.enableCallbackOwnerTracking();
  {
    CallbackOwner::Scope scope("e7.A");
    RecordAdmittedOnDestroy probe{record, std::this_thread::get_id()};
    queue.onEventName("n7", [probe, &ran](const Json &) { ++ran; });
    probe.record.reset();
  }
  queue.push(ownEvent("e7", "n7"));
  REQUIRE(iora::test::waitFor([&] { return ran == 1 && record->load() != -1; }, OWN_BOUND));
  REQUIRE(record->load() == 1);
}

TEST_CASE("E-8 an instance that is not opted in never gates or removes", "[EventQueue][owner]")
{
  SlowPhase slow;
  std::atomic<int> idCount{0}, nameCount{0}, patternCount{0};
  std::atomic<int> holdOnce{1};
  EventQueue plain(2);
  {
    CallbackOwner::Scope scope("e8.A");
    plain.onEventId("e8", [&](const Json &) { ++idCount; });
    plain.onEventName("n8",
                      [&](const Json &)
                      {
                        ++nameCount;
                        if (holdOnce.exchange(0) == 1)
                        {
                          slow.hold();
                        }
                      });
    plain.onEventNameMatches("^n8$", [&](const Json &) { ++patternCount; });
  }

  CallbackGate::close("e8.A");
  plain.push(ownEvent("e8", "n8"));
  REQUIRE(iora::test::waitFor([&] { return slow.phase == 1; }, OWN_BOUND));
  REQUIRE(idCount == 1);

  auto drained = ownDrainAsync("e8.A");
  const bool returned = drained.wait_for(OWN_BOUND) == std::future_status::ready;
  plain.removeHandlersOwnedBy("e8.A");
  CallbackGate::open("e8.A");
  slow.phase = 2;
  REQUIRE(returned);
  REQUIRE(iora::test::waitFor([&] { return patternCount == 1; }, OWN_BOUND));

  plain.push(ownEvent("e8", "n8"));
  REQUIRE(iora::test::waitFor([&] { return idCount == 2 && nameCount == 2 && patternCount == 2; },
                       OWN_BOUND));

  // Positive control: the same registrations on an opted-in instance are gated.
  std::atomic<int> trackedOwned{0}, trackedUnowned{0};
  EventQueue tracked(2);
  tracked.enableCallbackOwnerTracking();
  {
    CallbackOwner::Scope scope("e8.A");
    tracked.onEventId("e8", [&](const Json &) { ++trackedOwned; });
    tracked.onEventName("n8", [&](const Json &) { ++trackedOwned; });
    tracked.onEventNameMatches("^n8$", [&](const Json &) { ++trackedOwned; });
  }
  tracked.onEventName("n8", [&](const Json &) { ++trackedUnowned; });
  CallbackGate::close("e8.A");
  tracked.push(ownEvent("e8", "n8"));
  REQUIRE(iora::test::waitFor([&] { return trackedUnowned == 1; }, OWN_BOUND));
  std::this_thread::sleep_for(OWN_SETTLE);
  CallbackGate::open("e8.A");
  REQUIRE(trackedOwned == 0);
}
