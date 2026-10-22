// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for StateMachine<StateEnum, EventEnum, Context>

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/core/state_machine.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace iora::core;
using namespace std::chrono_literals;

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

  // Readers record into an atomic; Catch2 macros run only on the main thread.
  std::atomic<bool> sawInvalidState{false};
  std::vector<std::thread> readers;
  for (int r = 0; r < 4; ++r)
  {
    readers.emplace_back([&]()
    {
      for (int i = 0; i < iterations; ++i)
      {
        auto state = sm.currentState();
        if (!(state == State::IDLE || state == State::RUNNING ||
              state == State::COMPLETED || state == State::TERMINATED))
        {
          sawInvalidState = true;
        }
      }
    });
  }

  writer.join();
  for (auto& t : readers)
  {
    t.join();
  }
  REQUIRE_FALSE(sawInvalidState);
}

// ══════════════════════════════════════════════════════════════════════════════
// Same-thread re-entry
// ══════════════════════════════════════════════════════════════════════════════

namespace {

using VoidSM = StateMachine<State, Event>;
using CtxSM = StateMachine<State, Event, MyContext>;

enum class Hook { GUARD, ACTION, ON_ENTER, ON_EXIT, OBSERVER, EXIT_FORCE, ENTER_FORCE };
enum class Reentry { PROCESS_EVENT, FORCE_STATE };

// Everything the probe thread and the callbacks touch. Owned through a
// shared_ptr that the probe thread holds, so a deadlocked probe never touches
// freed memory; callbacks hold a raw pointer to avoid a cycle.
template<typename SM>
struct ReentryProbe
{
  std::unique_ptr<SM> sm;
  std::atomic<bool> caughtLogicError{false};
  std::atomic<bool> reentryReturned{false};
  std::atomic<bool> outerResult{false};
  std::atomic<bool> escaped{false};
  std::promise<void> done;
};

template<typename Probe, typename Call>
void attemptReentry(Probe* p, Call call)
{
  try
  {
    call();
    p->reentryReturned = true;
  }
  catch (const std::logic_error&)
  {
    p->caughtLogicError = true;
  }
}

// Builds IDLE --START--> RUNNING with the named hook re-entering the machine.
std::shared_ptr<ReentryProbe<VoidSM>> makeVoidProbe(Hook hook, Reentry how)
{
  auto probe = std::make_shared<ReentryProbe<VoidSM>>();
  auto* p = probe.get();
  auto reenter = [p, how]()
  {
    attemptReentry(p,
                   [p, how]()
                   {
                     if (how == Reentry::PROCESS_EVENT)
                     {
                       p->sm->processEvent(Event::CANCEL);
                     }
                     else
                     {
                       p->sm->forceState(State::TERMINATED);
                     }
                   });
  };

  VoidSM::Builder b;
  b.initialState(State::IDLE).transition(State::IDLE, Event::START, State::RUNNING);
  switch (hook)
  {
  case Hook::GUARD:
    b.guard(
      [reenter]()
      {
        reenter();
        return true;
      });
    break;
  case Hook::ACTION:
    b.onTransition(reenter);
    break;
  case Hook::ON_ENTER:
    b.onEnter(State::RUNNING, reenter);
    break;
  case Hook::ON_EXIT:
    b.onExit(State::IDLE, reenter);
    break;
  case Hook::OBSERVER:
    b.onAnyTransition([reenter](State, Event, State) { reenter(); });
    break;
  case Hook::EXIT_FORCE:
    b.onExitForce(State::IDLE, reenter);
    break;
  case Hook::ENTER_FORCE:
    b.onEnterForce(State::RUNNING, reenter);
    break;
  }
  probe->sm = std::make_unique<VoidSM>(b.build());
  return probe;
}

// Runs the outer call on a detached thread and waits a bounded time, so a
// deadlocked re-entry fails the row instead of hanging the suite.
template<typename SM, typename Outer>
void runReentryProbe(const std::shared_ptr<ReentryProbe<SM>>& probe, Outer outer)
{
  auto done = probe->done.get_future();
  std::thread(
    [probe, outer]()
    {
      try
      {
        probe->outerResult = outer(*probe->sm);
      }
      catch (...)
      {
        probe->escaped = true;
      }
      probe->done.set_value();
    })
    .detach();

  REQUIRE(done.wait_for(2s) == std::future_status::ready);
  REQUIRE_FALSE(probe->escaped);
  REQUIRE(probe->caughtLogicError);
  REQUIRE_FALSE(probe->reentryReturned);
  REQUIRE(probe->outerResult);
  REQUIRE(probe->sm->currentState() == State::RUNNING);
}

void runVoidProcessEventProbe(Hook hook, Reentry how)
{
  runReentryProbe(makeVoidProbe(hook, how),
                  [](VoidSM& sm) { return sm.processEvent(Event::START); });
}

void runVoidForceStateProbe(Hook hook, Reentry how)
{
  runReentryProbe(makeVoidProbe(hook, how),
                  [](VoidSM& sm)
                  {
                    sm.forceState(State::RUNNING);
                    return true;
                  });
}

} // namespace

TEST_CASE("SM reentry: guard -> processEvent throws", "[state_machine][reentry]")
{
  runVoidProcessEventProbe(Hook::GUARD, Reentry::PROCESS_EVENT);
}

TEST_CASE("SM reentry: guard -> forceState throws", "[state_machine][reentry]")
{
  runVoidProcessEventProbe(Hook::GUARD, Reentry::FORCE_STATE);
}

TEST_CASE("SM reentry: action -> processEvent throws", "[state_machine][reentry]")
{
  runVoidProcessEventProbe(Hook::ACTION, Reentry::PROCESS_EVENT);
}

TEST_CASE("SM reentry: action -> forceState throws", "[state_machine][reentry]")
{
  runVoidProcessEventProbe(Hook::ACTION, Reentry::FORCE_STATE);
}

TEST_CASE("SM reentry: onEnter -> processEvent throws", "[state_machine][reentry]")
{
  runVoidProcessEventProbe(Hook::ON_ENTER, Reentry::PROCESS_EVENT);
}

TEST_CASE("SM reentry: onEnter -> forceState throws", "[state_machine][reentry]")
{
  runVoidProcessEventProbe(Hook::ON_ENTER, Reentry::FORCE_STATE);
}

TEST_CASE("SM reentry: onExit -> processEvent throws", "[state_machine][reentry]")
{
  runVoidProcessEventProbe(Hook::ON_EXIT, Reentry::PROCESS_EVENT);
}

TEST_CASE("SM reentry: onExit -> forceState throws", "[state_machine][reentry]")
{
  runVoidProcessEventProbe(Hook::ON_EXIT, Reentry::FORCE_STATE);
}

TEST_CASE("SM reentry: onAnyTransition -> processEvent throws", "[state_machine][reentry]")
{
  runVoidProcessEventProbe(Hook::OBSERVER, Reentry::PROCESS_EVENT);
}

TEST_CASE("SM reentry: onAnyTransition -> forceState throws", "[state_machine][reentry]")
{
  runVoidProcessEventProbe(Hook::OBSERVER, Reentry::FORCE_STATE);
}

TEST_CASE("SM reentry: onExitForce -> processEvent throws", "[state_machine][reentry]")
{
  runVoidForceStateProbe(Hook::EXIT_FORCE, Reentry::PROCESS_EVENT);
}

TEST_CASE("SM reentry: onExitForce -> forceState throws", "[state_machine][reentry]")
{
  runVoidForceStateProbe(Hook::EXIT_FORCE, Reentry::FORCE_STATE);
}

TEST_CASE("SM reentry: onEnterForce -> processEvent throws", "[state_machine][reentry]")
{
  runVoidForceStateProbe(Hook::ENTER_FORCE, Reentry::PROCESS_EVENT);
}

TEST_CASE("SM reentry: onEnterForce -> forceState throws", "[state_machine][reentry]")
{
  runVoidForceStateProbe(Hook::ENTER_FORCE, Reentry::FORCE_STATE);
}

TEST_CASE("SM reentry: context action -> processEvent throws", "[state_machine][reentry]")
{
  auto probe = std::make_shared<ReentryProbe<CtxSM>>();
  auto* p = probe.get();
  CtxSM::Builder b;
  b.initialState(State::IDLE)
    .transition(State::IDLE, Event::START, State::RUNNING)
    .onTransition([p](const MyContext& ctx)
                  { attemptReentry(p, [p, &ctx]() { p->sm->processEvent(Event::CANCEL, ctx); }); });
  probe->sm = std::make_unique<CtxSM>(b.build());
  runReentryProbe(probe, [](CtxSM& sm) { return sm.processEvent(Event::START, MyContext{}); });
}

TEST_CASE("SM reentry: context guard -> forceState throws", "[state_machine][reentry]")
{
  auto probe = std::make_shared<ReentryProbe<CtxSM>>();
  auto* p = probe.get();
  CtxSM::Builder b;
  b.initialState(State::IDLE)
    .transition(State::IDLE, Event::START, State::RUNNING)
    .guard(
      [p](const MyContext&)
      {
        attemptReentry(p, [p]() { p->sm->forceState(State::TERMINATED); });
        return true;
      });
  probe->sm = std::make_unique<CtxSM>(b.build());
  runReentryProbe(probe, [](CtxSM& sm) { return sm.processEvent(Event::START, MyContext{}); });
}

TEST_CASE("SM reentry: a callback may drive a different machine", "[state_machine][reentry]")
{
  auto other = VoidSM::Builder()
                 .initialState(State::IDLE)
                 .transition(State::IDLE, Event::START, State::RUNNING)
                 .build();
  bool otherMoved = false;
  auto sm = VoidSM::Builder()
              .initialState(State::IDLE)
              .transition(State::IDLE, Event::START, State::RUNNING)
              .onTransition(
                [&]()
                {
                  otherMoved = other.processEvent(Event::START);
                  other.forceState(State::COMPLETED);
                })
              .build();

  REQUIRE(sm.processEvent(Event::START));
  REQUIRE(otherMoved);
  REQUIRE(other.currentState() == State::COMPLETED);
  REQUIRE(sm.currentState() == State::RUNNING);
}

// The rows below are regression guards for "the re-entry stamp is released on
// every exit path": each ends with a same-thread call that must not throw
// std::logic_error. They pass on the code before the detector existed too.

TEST_CASE("SM stamp release: void guard rejects", "[state_machine][reentry]")
{
  auto sm = VoidSM::Builder()
              .initialState(State::IDLE)
              .transition(State::IDLE, Event::START, State::RUNNING)
              .guard([]() { return false; })
              .transition(State::IDLE, Event::FINISH, State::COMPLETED)
              .build();

  REQUIRE_FALSE(sm.processEvent(Event::START));
  REQUIRE(sm.processEvent(Event::FINISH));
  REQUIRE(sm.currentState() == State::COMPLETED);
}

TEST_CASE("SM stamp release: void guard throws", "[state_machine][reentry]")
{
  auto sm = VoidSM::Builder()
              .initialState(State::IDLE)
              .transition(State::IDLE, Event::START, State::RUNNING)
              .guard([]() -> bool { throw std::runtime_error("guard"); })
              .transition(State::IDLE, Event::FINISH, State::COMPLETED)
              .build();

  REQUIRE_THROWS_AS(sm.processEvent(Event::START), std::runtime_error);
  REQUIRE(sm.currentState() == State::IDLE);
  REQUIRE(sm.processEvent(Event::FINISH));
  REQUIRE(sm.currentState() == State::COMPLETED);
}

TEST_CASE("SM stamp release: context action throws", "[state_machine][reentry]")
{
  auto sm = CtxSM::Builder()
              .initialState(State::IDLE)
              .transition(State::IDLE, Event::START, State::RUNNING)
              .onTransition([](const MyContext&) { throw std::runtime_error("action"); })
              .transition(State::IDLE, Event::FINISH, State::COMPLETED)
              .build();

  REQUIRE_THROWS_AS(sm.processEvent(Event::START, MyContext{}), std::runtime_error);
  REQUIRE(sm.currentState() == State::IDLE);
  REQUIRE(sm.processEvent(Event::FINISH, MyContext{}));
  REQUIRE(sm.currentState() == State::COMPLETED);
}

TEST_CASE("SM stamp release: context guard rejects", "[state_machine][reentry]")
{
  auto sm = CtxSM::Builder()
              .initialState(State::IDLE)
              .transition(State::IDLE, Event::START, State::RUNNING)
              .guard([](const MyContext&) { return false; })
              .transition(State::IDLE, Event::FINISH, State::COMPLETED)
              .build();

  REQUIRE_FALSE(sm.processEvent(Event::START, MyContext{}));
  REQUIRE(sm.processEvent(Event::FINISH, MyContext{}));
  REQUIRE(sm.currentState() == State::COMPLETED);
}

TEST_CASE("SM exceptions: action throws after onExit", "[state_machine][reentry]")
{
  bool exited = false;
  auto sm = VoidSM::Builder()
              .initialState(State::IDLE)
              .transition(State::IDLE, Event::START, State::RUNNING)
              .onTransition([]() { throw std::runtime_error("action"); })
              .transition(State::IDLE, Event::FINISH, State::COMPLETED)
              .onExit(State::IDLE, [&]() { exited = true; })
              .build();

  REQUIRE_THROWS_AS(sm.processEvent(Event::START), std::runtime_error);
  REQUIRE(exited);
  REQUIRE(sm.currentState() == State::IDLE);
  REQUIRE(sm.processEvent(Event::FINISH));
  REQUIRE(sm.currentState() == State::COMPLETED);
}

TEST_CASE("SM exceptions: onEnter throws after the commit", "[state_machine][reentry]")
{
  int observed = 0;
  bool enterThrown = false;
  auto sm = VoidSM::Builder()
              .initialState(State::IDLE)
              .transition(State::IDLE, Event::START, State::RUNNING)
              .thenEvent(Event::FINISH)
              .transition(State::RUNNING, Event::FINISH, State::COMPLETED)
              .onEnter(State::RUNNING,
                       [&]()
                       {
                         if (!enterThrown)
                         {
                           enterThrown = true;
                           throw std::runtime_error("onEnter");
                         }
                       })
              .onAnyTransition([&](State, Event, State) { ++observed; })
              .build();

  REQUIRE_THROWS_AS(sm.processEvent(Event::START), std::runtime_error);
  REQUIRE(sm.currentState() == State::RUNNING);
  REQUIRE(observed == 0);
  REQUIRE(sm.processEvent(Event::FINISH));
  REQUIRE(sm.currentState() == State::COMPLETED);
}

TEST_CASE("SM exceptions: observer throws after onEnter", "[state_machine][reentry]")
{
  bool observerThrown = false;
  auto sm = VoidSM::Builder()
              .initialState(State::IDLE)
              .transition(State::IDLE, Event::START, State::RUNNING)
              .thenEvent(Event::FINISH)
              .transition(State::RUNNING, Event::FINISH, State::COMPLETED)
              .onAnyTransition(
                [&](State, Event, State)
                {
                  if (!observerThrown)
                  {
                    observerThrown = true;
                    throw std::runtime_error("observer");
                  }
                })
              .build();

  REQUIRE_THROWS_AS(sm.processEvent(Event::START), std::runtime_error);
  REQUIRE(sm.currentState() == State::RUNNING);
  REQUIRE(sm.processEvent(Event::FINISH));
  REQUIRE(sm.currentState() == State::COMPLETED);
}

TEST_CASE("SM exceptions: onEnterForce throws after the commit", "[state_machine][reentry]")
{
  auto sm = VoidSM::Builder()
              .initialState(State::IDLE)
              .onEnterForce(State::RUNNING, []() { throw std::runtime_error("onEnterForce"); })
              .build();

  REQUIRE_THROWS_AS(sm.forceState(State::RUNNING), std::runtime_error);
  REQUIRE(sm.currentState() == State::RUNNING);
  REQUIRE_NOTHROW(sm.forceState(State::IDLE));
  REQUIRE(sm.currentState() == State::IDLE);
}

TEST_CASE("SM reentry: no false positive across threads", "[state_machine][reentry][thread]")
{
  std::atomic<int> observed{0};
  auto sm = VoidSM::Builder()
              .initialState(State::IDLE)
              .transition(State::IDLE, Event::START, State::RUNNING)
              .transition(State::RUNNING, Event::FINISH, State::COMPLETED)
              .transition(State::COMPLETED, Event::CLEANUP, State::TERMINATED)
              .transition(State::TERMINATED, Event::START, State::IDLE)
              .onAnyTransition([&](State, Event, State) { ++observed; })
              .build();

  constexpr int iterations = 2000;
  std::atomic<int> trueReturns{0};
  std::atomic<int> logicErrors{0};
  std::atomic<int> otherErrors{0};

  auto guarded = [&](auto body)
  {
    try
    {
      body();
    }
    catch (const std::logic_error&)
    {
      ++logicErrors;
    }
    catch (...)
    {
      ++otherErrors;
    }
  };

  std::vector<std::thread> workers;
  for (int w = 0; w < 3; ++w)
  {
    workers.emplace_back(
      [&]()
      {
        guarded(
          [&]()
          {
            for (int i = 0; i < iterations; ++i)
            {
              for (auto e : {Event::START, Event::FINISH, Event::CLEANUP, Event::START})
              {
                if (sm.processEvent(e))
                {
                  ++trueReturns;
                }
              }
            }
          });
      });
  }
  workers.emplace_back(
    [&]()
    {
      guarded(
        [&]()
        {
          for (int i = 0; i < iterations; ++i)
          {
            sm.forceState(State::IDLE);
          }
        });
    });

  for (auto& t : workers)
  {
    t.join();
  }
  REQUIRE(logicErrors == 0);
  REQUIRE(otherErrors == 0);
  REQUIRE(observed == trueReturns);
}
