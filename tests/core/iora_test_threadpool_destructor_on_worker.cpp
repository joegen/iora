// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.
//
// tracker 2026-09-24-6 task 6.1 — a ThreadPool destroyed from one of its own
// workers fails fast with a clear message.
//
// When a task drops the last owner of its own pool, ~ThreadPoolT runs on that
// worker. Before the fix, IMMEDIATE mode joined itself (std::system_error out of
// the noexcept destructor -> std::terminate, after a ~5 s drain wait) and
// DETACHED mode detached itself and returned into a freed pool (use-after-free).
// The destructor now detects the case first and calls std::terminate() after a
// fatal diagnostic.
//
// A std::terminate takes down the whole process, so this cannot live in the
// shared Catch2 lifecycle binary — it is a STANDALONE executable (precedent:
// tests/rpc/iora_test_jsonrpc_quiesce_selfdestruct.cpp). The scenario is chosen
// by argv[1] and each is its own ctest. A set_terminate handler echoes the stage
// and _Exit(0)s (no SIGABRT, so no core-dump pipe and no fork); the ctest
// PASS_REGULAR_EXPRESSION requires BOTH the pool's fatal message AND the stage,
// so a terminate without the message (the pre-fix IMMEDIATE path) fails, and a
// scenario that never terminates prints FAILURE.
//
// Scenarios: {immediate,detached}-{body,capture}.
//   * body:    the task resets the last shared_ptr inside its body.
//   * capture: the task captures the last owner by value; the destroy runs when
//              the worker resets the finished task functor.
// Main drops its own reference first (synchronized by an atomic), so the task's
// reference is provably the last one.

#include "iora/core/thread_pool.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <memory>
#include <string>
#include <thread>

using iora::core::ThreadPool;

namespace
{
std::atomic<const char *> g_stage{"none"};

[[noreturn]] void onTerminate()
{
  std::fprintf(stderr, "[handler] terminate called stage=%s\n", g_stage.load());
  std::fflush(stderr);
  std::_Exit(0);
}

void waitFor(const std::atomic<bool> &flag)
{
  while (!flag.load())
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

int failNoTerminate(const char *scenario)
{
  std::this_thread::sleep_for(std::chrono::seconds(10));
  std::fprintf(stderr, "[%s] FAILURE: reached end without terminating\n", scenario);
  return 1;
}

int runBody(const char *scenario, ThreadPool::ShutdownMode mode)
{
  auto pool = std::make_shared<ThreadPool>(1, 1);
  pool->setShutdownMode(mode);
  auto box = std::make_shared<std::shared_ptr<ThreadPool>>(pool);
  std::atomic<bool> mainDropped{false};

  pool->enqueue(
    [box, &mainDropped, scenario]()
    {
      waitFor(mainDropped);
      g_stage.store(scenario);
      box->reset(); // destroys the pool here, on its own worker
    });

  pool.reset();
  mainDropped.store(true);
  return failNoTerminate(scenario);
}

int runCapture(const char *scenario, ThreadPool::ShutdownMode mode)
{
  auto pool = std::make_shared<ThreadPool>(1, 1);
  pool->setShutdownMode(mode);
  std::atomic<bool> mainDropped{false};

  pool->enqueue(
    [owner = pool, &mainDropped, scenario]()
    {
      waitFor(mainDropped);
      g_stage.store(scenario); // the destroy follows when the worker resets this functor
    });

  pool.reset();
  mainDropped.store(true);
  return failNoTerminate(scenario);
}
} // namespace

int main(int argc, char **argv)
{
  std::set_terminate(onTerminate);
  const std::string scenario = argc > 1 ? argv[1] : "immediate-body";

  if (scenario == "immediate-body")
  {
    return runBody("immediate-body", ThreadPool::ShutdownMode::IMMEDIATE);
  }
  if (scenario == "immediate-capture")
  {
    return runCapture("immediate-capture", ThreadPool::ShutdownMode::IMMEDIATE);
  }
  if (scenario == "detached-body")
  {
    return runBody("detached-body", ThreadPool::ShutdownMode::DETACHED);
  }
  if (scenario == "detached-capture")
  {
    return runCapture("detached-capture", ThreadPool::ShutdownMode::DETACHED);
  }
  std::fprintf(stderr, "FAILURE: unknown scenario %s\n", scenario.c_str());
  return 2;
}
