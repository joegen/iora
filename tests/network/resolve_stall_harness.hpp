// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file resolve_stall_harness.hpp
/// \brief Deterministic, production-path stall harness for the event-driven
///        name-resolution tests (architecture/iora/transport_dns_resolve.json
///        testStrategy).
///
/// The engines dispatch every named-host ::getaddrinfo onto the process-wide,
/// hard-capped, reject-fast iora::core::blockingIoPool() (ThreadPool(2, 16,
/// 30s, 128); see src/core/iora_core.cpp). This harness monopolises that pool
/// so a resolve can be made to (a) sit un-run in the queue for longer than a
/// short resolveTimeout (drives the resolve-TIMEOUT / slow-resolve / race /
/// teardown-in-flight cases deterministically), or (b) be rejected outright at
/// the queue cap (drives the RESOLVER_POOL_SATURATED reject-fast case).
///
/// This is the same mechanism production uses — no injected resolver seam, no
/// DNS dependency, no writable /etc/resolv.conf — so the tests exercise the
/// real reject-fast / off-thread-resolve paths. Because it seizes a global
/// resource, every test that uses it MUST live in an ISOLATED, LAST-ORDERED
/// binary (see the CMakeLists NETWORK_TESTS ordering and the arch note
/// "ISOLATED + LAST-ORDERED").

#pragma once

#include "iora/core/thread_pool.hpp"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <thread>

namespace resolvetest
{

/// \brief The blockingIoPool() worker cap (ThreadPool max size, iora_core.cpp).
///        Occupying this many tasks blocks every worker so no later resolve
///        task can be popped.
constexpr std::size_t kPoolWorkers = 16;

/// \brief Poll \p cond until it holds or \p timeout elapses; returns its final
///        value. Shared by the resolve test fixtures (simpl L5). The predicate
///        must itself synchronise any access to callback-written shared state.
inline bool waitFor(const std::function<bool()> &cond,
                    std::chrono::milliseconds timeout = std::chrono::milliseconds(2000))
{
  auto start = std::chrono::steady_clock::now();
  while (!cond() && (std::chrono::steady_clock::now() - start) < timeout)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return cond();
}

/// \brief RAII owner of a blockingIoPool() stall. The destructor releases the
///        gate and waits for every stalled task to drain, so the global pool is
///        fully restored before the next test runs.
class PoolStall
{
public:
  PoolStall() = default;
  ~PoolStall() { release(); }

  PoolStall(const PoolStall &) = delete;
  PoolStall &operator=(const PoolStall &) = delete;

  /// \brief Block every pool worker. Returns only once all \p workers tasks are
  ///        confirmed running (parked in block()), so no worker is free to pop a
  ///        subsequently dispatched resolve task — it will sit un-run in the
  ///        queue. \p workers must be >= the pool worker cap (kPoolWorkers).
  void occupyWorkers(std::size_t workers = kPoolWorkers)
  {
    std::size_t enq = 0;
    for (std::size_t i = 0; i < workers; ++i)
    {
      if (iora::core::blockingIoPool().tryEnqueue([this] { block(); }))
      {
        ++_enqueued;
        ++enq;
      }
    }
    // Wait on the number ACTUALLY enqueued, not the requested count: if any
    // tryEnqueue were rejected (non-idle pool / near-cap queue), _started can
    // never reach `workers` and waiting on it would deadlock (thread-safety
    // ts-LOW). With an idle pool all kPoolWorkers succeed and enq == workers.
    std::unique_lock<std::mutex> lk(_m);
    // Bounded wait: deterministic in practice (an idle, isolated pool grows to
    // all workers), but a generous cap converts a pathological non-start into a
    // diagnosable downstream test failure rather than an indefinite hang (cpp17
    // #1). The outer ctest timeout is the ultimate backstop.
    _startedCv.wait_for(lk, std::chrono::seconds(15), [&] { return _started >= enq; });
  }

  /// \brief Block all workers, then fill the queue until tryEnqueue rejects.
  ///        On return the queue is STABLY full (all workers parked, none
  ///        popping), so the next resolveHostAsync / dispatch reject-fasts
  ///        deterministically. Returns the number of tasks queued behind the
  ///        blocked workers (== the pool queue cap).
  std::size_t saturate()
  {
    occupyWorkers(kPoolWorkers);
    std::size_t queued = 0;
    while (iora::core::blockingIoPool().tryEnqueue([this] { block(); }))
    {
      ++queued;
      ++_enqueued;
    }
    return queued;
  }

  /// \brief Release the gate and wait for all stalled tasks to finish, leaving
  ///        the pool idle. Idempotent.
  void release()
  {
    {
      std::lock_guard<std::mutex> lk(_m);
      if (_released)
      {
        return;
      }
      _released = true;
    }
    _releaseCv.notify_all();
    std::unique_lock<std::mutex> lk(_m);
    _doneCv.wait(lk, [&] { return _finished >= _enqueued; });
  }

private:
  void block()
  {
    {
      std::lock_guard<std::mutex> lk(_m);
      ++_started;
      _startedCv.notify_all();
    }

    std::unique_lock<std::mutex> lk(_m);
    _releaseCv.wait(lk, [&] { return _released; });
    ++_finished;
    // Notify UNDER the lock: release()/~PoolStall waits on _finished and then
    // destroys _doneCv, so notifying AFTER unlocking would let the destructor run
    // while this worker is still inside _doneCv.notify_all() — a data race on the
    // condition variable (TSan-fatal). Holding _m across the notify forces
    // release() to re-acquire _m (and only then return/destroy) after this worker
    // has finished touching _doneCv. lk unlocks at end of scope, after the notify.
    _doneCv.notify_all();
  }

  std::mutex _m;
  std::condition_variable _startedCv;
  std::condition_variable _releaseCv;
  std::condition_variable _doneCv;
  std::size_t _started{0};
  std::size_t _finished{0};
  std::size_t _enqueued{0}; // touched only by the test thread (enqueue side)
  bool _released{false};
};

} // namespace resolvetest
