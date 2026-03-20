// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for StateMachine<StateEnum, EventEnum, Context>

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/core/state_machine.hpp>

#include <string>
#include <thread>
#include <vector>

using namespace iora::core;

// Test enums
enum class State { IDLE, RUNNING, COMPLETED, TERMINATED };
enum class Event { START, FINISH, CLEANUP, CANCEL };

// Context type for context-bearing tests
struct MyContext
{
  int code = 0;
  std::string message;
};

// ══════════════════════════════════════════════════════════════════════════════
// Basic Transitions
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("SM: basic transition", "[state_machine]")
{
  auto sm = StateMachine<State, Event>::Builder()
    .initialState(State::IDLE)
    .transition(State::IDLE, Event::START, State::RUNNING)
    .build();

  REQUIRE(sm.currentState() == State::IDLE);
  REQUIRE(sm.processEvent(Event::START));
  REQUIRE(sm.currentState() == State::RUNNING);
}

TEST_CASE("SM: no-match returns false, stays in state", "[state_machine]")
{
  auto sm = StateMachine<State, Event>::Builder()
    .initialState(State::IDLE)
    .transition(State::IDLE, Event::START, State::RUNNING)
    .build();

  REQUIRE_FALSE(sm.processEvent(Event::FINISH));
  REQUIRE(sm.currentState() == State::IDLE);
}

TEST_CASE("SM: isInState", "[state_machine]")
{
  auto sm = StateMachine<State, Event>::Builder()
    .initialState(State::IDLE)
    .build();

  REQUIRE(sm.isInState(State::IDLE));
  REQUIRE_FALSE(sm.isInState(State::RUNNING));
}

// ══════════════════════════════════════════════════════════════════════════════
// Guards
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("SM: guard that rejects", "[state_machine][guard]")
{
  auto sm = StateMachine<State, Event>::Builder()
    .initialState(State::IDLE)
    .transition(State::IDLE, Event::START, State::RUNNING)
      .guard([]() { return false; })
    .build();

  REQUIRE_FALSE(sm.processEvent(Event::START));
  REQUIRE(sm.currentState() == State::IDLE);
}

TEST_CASE("SM: multiple guards — insertion order", "[state_machine][guard]")
{
  int which = 0;

  auto sm = StateMachine<State, Event>::Builder()
    .initialState(State::IDLE)
    // First: guard rejects
    .transition(State::IDLE, Event::START, State::RUNNING)
      .guard([]() { return false; })
      .onTransition([&]() { which = 1; })
    // Second: guard accepts
    .transition(State::IDLE, Event::START, State::COMPLETED)
      .guard([]() { return true; })
      .onTransition([&]() { which = 2; })
    .build();

  REQUIRE(sm.processEvent(Event::START));
  REQUIRE(which == 2);
  REQUIRE(sm.currentState() == State::COMPLETED);
}

// ══════════════════════════════════════════════════════════════════════════════
// onEnter / onExit / onTransition / onAnyTransition
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("SM: onEnter and onExit fire in order", "[state_machine][callbacks]")
{
  std::vector<std::string> log;

  auto sm = StateMachine<State, Event>::Builder()
    .initialState(State::IDLE)
    .transition(State::IDLE, Event::START, State::RUNNING)
      .onTransition([&]() { log.push_back("action"); })
    .onExit(State::IDLE, [&]() { log.push_back("exit_idle"); })
    .onEnter(State::RUNNING, [&]() { log.push_back("enter_running"); })
    .build();

  sm.processEvent(Event::START);
  REQUIRE(log.size() == 3);
  REQUIRE(log[0] == "exit_idle");
  REQUIRE(log[1] == "action");
  REQUIRE(log[2] == "enter_running");
}

TEST_CASE("SM: onAnyTransition receives correct triple", "[state_machine][callbacks]")
{
  State fromLog{};
  Event eventLog{};
  State toLog{};

  auto sm = StateMachine<State, Event>::Builder()
    .initialState(State::IDLE)
    .transition(State::IDLE, Event::START, State::RUNNING)
    .onAnyTransition([&](State f, Event e, State t)
    {
      fromLog = f;
      eventLog = e;
      toLog = t;
    })
    .build();

  sm.processEvent(Event::START);
  REQUIRE(fromLog == State::IDLE);
  REQUIRE(eventLog == Event::START);
  REQUIRE(toLog == State::RUNNING);
}

TEST_CASE("SM: onTransition action fires with correct order", "[state_machine][callbacks]")
{
  bool actionFired = false;
  auto sm = StateMachine<State, Event>::Builder()
    .initialState(State::IDLE)
    .transition(State::IDLE, Event::START, State::RUNNING)
      .onTransition([&]() { actionFired = true; })
    .build();

  sm.processEvent(Event::START);
  REQUIRE(actionFired);
}

// ══════════════════════════════════════════════════════════════════════════════
// forceState
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("SM: forceState bypasses transition table", "[state_machine][force]")
{
  auto sm = StateMachine<State, Event>::Builder()
    .initialState(State::IDLE)
    // No transition from IDLE to TERMINATED
    .build();

  sm.forceState(State::TERMINATED);
  REQUIRE(sm.currentState() == State::TERMINATED);
}

TEST_CASE("SM: forceState fires context-free onExitForce/onEnterForce", "[state_machine][force]")
{
  bool exitFired = false;
  bool enterFired = false;

  auto sm = StateMachine<State, Event>::Builder()
    .initialState(State::IDLE)
    .onExitForce(State::IDLE, [&]() { exitFired = true; })
    .onEnterForce(State::TERMINATED, [&]() { enterFired = true; })
    .build();

  sm.forceState(State::TERMINATED);
  REQUIRE(exitFired);
  REQUIRE(enterFired);
}

TEST_CASE("SM: forceState to same state fires onExit/onEnter", "[state_machine][force]")
{
  int exitCount = 0;
  int enterCount = 0;

  auto sm = StateMachine<State, Event>::Builder()
    .initialState(State::IDLE)
    .onExitForce(State::IDLE, [&]() { ++exitCount; })
    .onEnterForce(State::IDLE, [&]() { ++enterCount; })
    .build();

  sm.forceState(State::IDLE);
  REQUIRE(exitCount == 1);
  REQUIRE(enterCount == 1);
}

// ══════════════════════════════════════════════════════════════════════════════
// thenEvent (compound transitions)
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("SM: thenEvent compound transition", "[state_machine][then]")
{
  auto sm = StateMachine<State, Event>::Builder()
    .initialState(State::RUNNING)
    .transition(State::RUNNING, Event::FINISH, State::COMPLETED)
      .thenEvent(Event::CLEANUP)
    .transition(State::COMPLETED, Event::CLEANUP, State::TERMINATED)
    .build();

  REQUIRE(sm.processEvent(Event::FINISH));
  REQUIRE(sm.currentState() == State::TERMINATED);
}

TEST_CASE("SM: thenEvent + onAnyTransition ordering — per-leg logging", "[state_machine][then]")
{
  std::vector<std::string> log;

  auto sm = StateMachine<State, Event>::Builder()
    .initialState(State::RUNNING)
    .transition(State::RUNNING, Event::FINISH, State::COMPLETED)
      .thenEvent(Event::CLEANUP)
    .transition(State::COMPLETED, Event::CLEANUP, State::TERMINATED)
    .onAnyTransition([&](State from, Event, State to)
    {
      log.push_back(std::to_string(static_cast<int>(from)) + "->"
                  + std::to_string(static_cast<int>(to)));
    })
    .build();

  sm.processEvent(Event::FINISH);
  // onAnyTransition fires per-leg, before thenEvent re-enters
  REQUIRE(log.size() == 2);
  REQUIRE(log[0] == "1->2"); // RUNNING->COMPLETED
  REQUIRE(log[1] == "2->3"); // COMPLETED->TERMINATED
}

TEST_CASE("SM: thenEvent with context re-passes original context", "[state_machine][then][context]")
{
  int firstCode = 0;
  int secondCode = 0;

  auto sm = StateMachine<State, Event, MyContext>::Builder()
    .initialState(State::RUNNING)
    .transition(State::RUNNING, Event::FINISH, State::COMPLETED)
      .onTransition([&](const MyContext& ctx) { firstCode = ctx.code; })
      .thenEvent(Event::CLEANUP)
    .transition(State::COMPLETED, Event::CLEANUP, State::TERMINATED)
      .onTransition([&](const MyContext& ctx) { secondCode = ctx.code; })
    .build();

  MyContext ctx{42, "test"};
  sm.processEvent(Event::FINISH, ctx);
  REQUIRE(firstCode == 42);
  REQUIRE(secondCode == 42); // same context re-passed
  REQUIRE(sm.currentState() == State::TERMINATED);
}

// ══════════════════════════════════════════════════════════════════════════════
// Self-Transition
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("SM: self-transition fires onExit and onEnter", "[state_machine]")
{
  int exitCount = 0;
  int enterCount = 0;

  auto sm = StateMachine<State, Event>::Builder()
    .initialState(State::RUNNING)
    .transition(State::RUNNING, Event::START, State::RUNNING) // self-transition
    .onExit(State::RUNNING, [&]() { ++exitCount; })
    .onEnter(State::RUNNING, [&]() { ++enterCount; })
    .build();

  REQUIRE(sm.processEvent(Event::START));
  REQUIRE(sm.currentState() == State::RUNNING);
  REQUIRE(exitCount == 1);
  REQUIRE(enterCount == 1);
}

// ══════════════════════════════════════════════════════════════════════════════
// Context-Bearing StateMachine
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("SM: Context-bearing processEvent", "[state_machine][context]")
{
  int receivedCode = 0;

  auto sm = StateMachine<State, Event, MyContext>::Builder()
    .initialState(State::IDLE)
    .transition(State::IDLE, Event::START, State::RUNNING)
      .guard([](const MyContext& ctx) { return ctx.code > 0; })
      .onTransition([&](const MyContext& ctx) { receivedCode = ctx.code; })
    .build();

  MyContext ctx{42, "hello"};
  REQUIRE(sm.processEvent(Event::START, ctx));
  REQUIRE(receivedCode == 42);
  REQUIRE(sm.currentState() == State::RUNNING);
}

TEST_CASE("SM: Context guard rejects", "[state_machine][context]")
{
  auto sm = StateMachine<State, Event, MyContext>::Builder()
    .initialState(State::IDLE)
    .transition(State::IDLE, Event::START, State::RUNNING)
      .guard([](const MyContext& ctx) { return ctx.code > 100; })
    .build();

  MyContext ctx{42, "too low"};
  REQUIRE_FALSE(sm.processEvent(Event::START, ctx));
  REQUIRE(sm.currentState() == State::IDLE);
}

TEST_CASE("SM: Context-bearing onEnter/onExit receive context", "[state_machine][context]")
{
  std::string exitMsg;
  std::string enterMsg;

  auto sm = StateMachine<State, Event, MyContext>::Builder()
    .initialState(State::IDLE)
    .transition(State::IDLE, Event::START, State::RUNNING)
    .onExit(State::IDLE, [&](const MyContext& ctx) { exitMsg = ctx.message; })
    .onEnter(State::RUNNING, [&](const MyContext& ctx) { enterMsg = ctx.message; })
    .build();

  MyContext ctx{1, "test_msg"};
  sm.processEvent(Event::START, ctx);
  REQUIRE(exitMsg == "test_msg");
  REQUIRE(enterMsg == "test_msg");
}

TEST_CASE("SM: forceState on Context-bearing FSM is context-free", "[state_machine][context][force]")
{
  bool forceFired = false;

  auto sm = StateMachine<State, Event, MyContext>::Builder()
    .initialState(State::IDLE)
    .onEnterForce(State::TERMINATED, [&]() { forceFired = true; })
    .build();

  sm.forceState(State::TERMINATED);
  REQUIRE(sm.currentState() == State::TERMINATED);
  REQUIRE(forceFired);
}

// ══════════════════════════════════════════════════════════════════════════════
// Builder Validation
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("SM: build() throws if initialState not set", "[state_machine][builder]")
{
  using SM = StateMachine<State, Event>;
  REQUIRE_THROWS_AS(SM::Builder().build(), std::logic_error);
}

// ══════════════════════════════════════════════════════════════════════════════
// Thread Safety
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("SM: concurrent currentState reads during transitions", "[state_machine][thread]")
{
  auto sm = StateMachine<State, Event>::Builder()
    .initialState(State::IDLE)
    .transition(State::IDLE, Event::START, State::RUNNING)
    .transition(State::RUNNING, Event::FINISH, State::COMPLETED)
    .transition(State::COMPLETED, Event::CLEANUP, State::TERMINATED)
    .transition(State::TERMINATED, Event::START, State::IDLE)
    .build();

  constexpr int iterations = 10000;

  std::thread writer([&]()
  {
    for (int i = 0; i < iterations; ++i)
    {
      sm.processEvent(Event::START);
      sm.processEvent(Event::FINISH);
      sm.processEvent(Event::CLEANUP);
      sm.processEvent(Event::START); // back to IDLE
    }
  });

  std::vector<std::thread> readers;
  for (int r = 0; r < 4; ++r)
  {
    readers.emplace_back([&]()
    {
      for (int i = 0; i < iterations; ++i)
      {
        auto state = sm.currentState();
        // State must be one of the valid values
        REQUIRE((state == State::IDLE || state == State::RUNNING ||
                 state == State::COMPLETED || state == State::TERMINATED));
      }
    });
  }

  writer.join();
  for (auto& t : readers) t.join();
}
