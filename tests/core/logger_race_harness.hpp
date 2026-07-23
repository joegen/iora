// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Shared rendezvous harness for the Logger external-handler tear-out tests
// (iora_test_logger_external_handler_race.cpp and
// iora_test_logger_self_clear_deadlock.cpp). Passive synchronization state with
// zero logger coupling: a UAF probe object and a latch/counter controller the
// handler bodies signal through. Catch2 macros must run ONLY on the main thread;
// handler invocations record into RaceCtl (its own mutex) and the main thread
// asserts after the bounded waits below.
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <thread>

namespace iora::test
{

// Object captured by reference in a handler; destroying it during an in-flight
// handler call is the use-after-free the tear-out drain prevents. Heap-allocated
// so a test can free it precisely after the tear-out returns.
struct CaptureTarget
{
  std::atomic<int> touches{0};
  std::atomic<int> canary{0x5A5A};
  void touch() { touches.fetch_add(1); }
};

// Rendezvous controller shared between the test thread and handler invocations.
// Lives for the whole test (NOT a UAF target).
struct RaceCtl
{
  std::mutex m;
  std::condition_variable cv;
  int entered = 0; // # handler invocations that reached their window
  int exited = 0;  // # handler invocations that completed
  bool released = false;

  void onEnter()
  {
    std::lock_guard<std::mutex> l(m);
    ++entered;
    cv.notify_all();
  }
  void onExit()
  {
    std::lock_guard<std::mutex> l(m);
    ++exited;
    cv.notify_all();
  }
  bool waitEntered(int n, std::chrono::milliseconds to = std::chrono::seconds(5))
  {
    std::unique_lock<std::mutex> l(m);
    return cv.wait_for(l, to, [&] { return entered >= n; });
  }
  // Bounded: returns false on timeout (a drain deadlock), true once n invocations
  // have completed. A false return is the deadlock signal — do NOT extend `to`.
  bool waitExited(int n, std::chrono::milliseconds to = std::chrono::seconds(5))
  {
    std::unique_lock<std::mutex> l(m);
    return cv.wait_for(l, to, [&] { return exited >= n; });
  }
  void releaseAll()
  {
    std::lock_guard<std::mutex> l(m);
    released = true;
    cv.notify_all();
  }
  // BOUNDED on purpose. Handler bodies park here, so an unbounded wait would turn
  // a failed REQUIRE on the main thread into a use-after-scope (the test frame
  // unwinds while invocations still point at this object) plus a wedged worker
  // that hangs shutdown() and static destruction — the process would die on a CI
  // timeout instead of reporting a test failure. On timeout the caller must bail
  // out WITHOUT self-clearing, so the run ends in a bounded FAIL.
  bool waitReleased(std::chrono::milliseconds to = std::chrono::seconds(10))
  {
    std::unique_lock<std::mutex> l(m);
    return cv.wait_for(l, to, [&] { return released; });
  }
  int exitedCount()
  {
    std::lock_guard<std::mutex> l(m);
    return exited;
  }
  int enteredCount()
  {
    std::lock_guard<std::mutex> l(m);
    return entered;
  }
};

// Join on success; DETACH on a drain timeout — never join a possibly-wedged
// thread, or a bounded FAIL becomes a hung suite.
inline void joinOrDetach(bool ok, std::initializer_list<std::thread *> threads)
{
  for (auto *t : threads)
  {
    if (ok)
    {
      t->join();
    }
    else
    {
      t->detach();
    }
  }
}

// Shared ownership for every object a parked handler touches. Handlers capture
// these BY VALUE, so a detached wedged thread — or a test frame unwound by a
// failing assertion — can never leave a handler pointing at a destroyed object.
using CtlPtr = std::shared_ptr<RaceCtl>;
using TargetPtr = std::shared_ptr<CaptureTarget>;
using CounterPtr = std::shared_ptr<std::atomic<int>>;
using FlagPtr = std::shared_ptr<std::atomic<bool>>;

inline CtlPtr makeCtl() { return std::make_shared<RaceCtl>(); }
inline TargetPtr makeTarget() { return std::make_shared<CaptureTarget>(); }
inline CounterPtr makeCounter(int initial = 0)
{
  return std::make_shared<std::atomic<int>>(initial);
}
inline FlagPtr makeFlag(bool initial = false)
{
  return std::make_shared<std::atomic<bool>>(initial);
}

// Blocking handler body: park in the rendezvous window so a peer invocation is
// provably in flight concurrently, then signal exit. With `t`, the touch/gate/touch
// sandwich is the UAF probe — the post-gate touch must complete before any
// tear-out returns. Returns false if the release timed out.
inline bool blockingHandlerBody(RaceCtl &c, CaptureTarget *t = nullptr)
{
  if (t != nullptr)
  {
    t->touch();
  }
  c.onEnter();
  const bool released = c.waitReleased();
  if (t != nullptr)
  {
    t->touch();
  }
  c.onExit();
  return released;
}

} // namespace iora::test
