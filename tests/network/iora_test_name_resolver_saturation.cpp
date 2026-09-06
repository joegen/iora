// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_name_resolver_saturation.cpp
/// \brief ISOLATED, LAST-ORDERED reject-fast saturation test for resolveHostAsync
///        (architecture/iora/transport_dns_resolve.json testStrategy.c1_c3_unit;
///        tracker 2026-09-06-4 task-6.1).
///
/// This test monopolises the process-wide iora::core::blockingIoPool() (it
/// blocks all 16 workers and fills the 128-slot queue), so it lives in its own
/// binary and is ordered LAST in NETWORK_TESTS. It exercises the SAME production
/// path an SIP resolve hits under local backpressure: when the pool queue is
/// full, resolveHostAsync's tryEnqueue rejects and the completion fires INLINE
/// on the caller's thread with RESOLVER_POOL_SATURATED (arch C1 / C3).

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/network/name_resolver.hpp"

#include "resolve_stall_harness.hpp"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <netdb.h>
#include <sys/socket.h>
#include <thread>

using iora::network::ResolveResult;
using iora::network::RESOLVER_POOL_SATURATED;

namespace
{
::addrinfo streamHints()
{
  ::addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  return hints;
}
} // namespace

TEST_CASE("resolveHostAsync reject-fasts inline when the pool queue is full",
          "[network][name_resolver][c1][c3][saturation][isolated]")
{
  resolvetest::PoolStall stall;

  // Block all 16 workers, then fill the 128-slot queue. The queue is stably full
  // on return (no worker is free to pop), so the next dispatch must reject.
  const std::size_t queued = stall.saturate();
  // maxQueueSize == 128 (blockingIoPool, iora_core.cpp): exactly the queue cap
  // is admitted behind the blocked workers before tryEnqueue rejects.
  CHECK(queued == 128);

  bool fired = false;
  std::thread::id cbThread{};
  int gai = 0;
  bool hadAddrs = true;

  const std::thread::id caller = std::this_thread::get_id();
  const ::addrinfo hints = streamHints();

  iora::network::resolveHostAsync("localhost", "5060", hints,
                                  [&](ResolveResult r)
                                  {
                                    fired = true;
                                    cbThread = std::this_thread::get_id();
                                    gai = r.gaiCode;
                                    hadAddrs = static_cast<bool>(r.addrs);
                                  });

  // Reject-fast is INLINE: the completion ran synchronously on THIS thread,
  // before resolveHostAsync returned — not on a pool thread.
  CHECK(fired);
  CHECK(cbThread == caller);
  CHECK(gai == RESOLVER_POOL_SATURATED);
  CHECK_FALSE(hadAddrs);

  // The saturation sentinel is distinguishable from a real resolver error by a
  // dedicated message string (operator-facing), never mistaken for getaddrinfo.
  CHECK(std::string(iora::network::resolveErrorMessage(gai)) == "resolver pool saturated");
}

TEST_CASE("resolveHostAsync recovers after the pool drains",
          "[network][name_resolver][c1][c3][saturation][isolated]")
{
  {
    resolvetest::PoolStall stall;
    stall.saturate();
    // stall dtor releases the gate and waits for every stalled task to finish,
    // leaving the pool idle again.
  }

  std::mutex m;
  std::condition_variable cv;
  bool done = false;
  ResolveResult result;

  const ::addrinfo hints = streamHints();
  iora::network::resolveHostAsync("localhost", "5060", hints,
                                  [&](ResolveResult r)
                                  {
                                    std::lock_guard<std::mutex> g(m);
                                    result = std::move(r);
                                    done = true;
                                    cv.notify_one();
                                  });

  std::unique_lock<std::mutex> lk(m);
  REQUIRE(cv.wait_for(lk, std::chrono::seconds(5), [&] { return done; }));
  // Once the pool has drained, a normal localhost resolve succeeds off-thread.
  CHECK(result.gaiCode == 0);
  CHECK(static_cast<bool>(result.addrs));
}
