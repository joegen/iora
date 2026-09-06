// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_name_resolver.cpp
/// \brief Tests for the event-driven, non-blocking name resolution helper
///        (iora::network::resolveHostAsync + OwnedAddrInfo + blockingIoPool).
///
/// Test scaffold created at tracker phase-0 (task-0.1); C1 OwnedAddrInfo cases
/// added at phase-1 (task-1.1). Further C1/C3 cases are added as
/// resolveHostAsync / blockingIoPool land, per
/// architecture/iora/transport_dns_resolve.json testStrategy.c1_c3_unit.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/network/name_resolver.hpp"

#include "iora/core/thread_pool.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <sys/socket.h>

using iora::network::OwnedAddrInfo;

namespace
{
/// \brief Resolve a numeric literal (AI_NUMERICHOST => no DNS) to a real
/// ::addrinfo chain the ownership tests can hand to OwnedAddrInfo.
::addrinfo *makeNumericChain()
{
  ::addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
  ::addrinfo *res = nullptr;
  const int rc = ::getaddrinfo("127.0.0.1", "5060", &hints, &res);
  REQUIRE(rc == 0);
  REQUIRE(res != nullptr);
  return res;
}
} // namespace

TEST_CASE("OwnedAddrInfo default is empty", "[network][name_resolver][c1]")
{
  OwnedAddrInfo a;
  CHECK(a.get() == nullptr);
  CHECK_FALSE(static_cast<bool>(a));
}

TEST_CASE("OwnedAddrInfo owns and frees a real chain", "[network][name_resolver][c1]")
{
  // If the dtor double-frees or leaks, ASan/LSan flags it here.
  OwnedAddrInfo a{makeNumericChain()};
  CHECK(a.get() != nullptr);
  CHECK(static_cast<bool>(a));
}

TEST_CASE("OwnedAddrInfo move ctor transfers and nulls source", "[network][name_resolver][c1]")
{
  OwnedAddrInfo src{makeNumericChain()};
  ::addrinfo *raw = src.get();
  REQUIRE(raw != nullptr);

  OwnedAddrInfo dst{std::move(src)};
  CHECK(dst.get() == raw);
  CHECK(static_cast<bool>(dst));
  CHECK(src.get() == nullptr); // NOLINT(bugprone-use-after-move)
  CHECK_FALSE(static_cast<bool>(src));
}

TEST_CASE("OwnedAddrInfo move assign frees LHS then transfers", "[network][name_resolver][c1]")
{
  OwnedAddrInfo lhs{makeNumericChain()}; // must be freed by the assignment, not leaked
  OwnedAddrInfo rhs{makeNumericChain()};
  ::addrinfo *rhsRaw = rhs.get();

  lhs = std::move(rhs);
  CHECK(lhs.get() == rhsRaw);
  CHECK(rhs.get() == nullptr); // NOLINT(bugprone-use-after-move)
}

TEST_CASE("OwnedAddrInfo move assign to empty", "[network][name_resolver][c1]")
{
  OwnedAddrInfo lhs;
  OwnedAddrInfo rhs{makeNumericChain()};
  ::addrinfo *rhsRaw = rhs.get();
  lhs = std::move(rhs);
  CHECK(lhs.get() == rhsRaw);
  CHECK_FALSE(static_cast<bool>(rhs)); // NOLINT(bugprone-use-after-move)
}

TEST_CASE("OwnedAddrInfo self move-assign is a no-op", "[network][name_resolver][c1]")
{
  OwnedAddrInfo a{makeNumericChain()};
  ::addrinfo *raw = a.get();
  OwnedAddrInfo &ref = a;
  a = std::move(ref); // NOLINT(clang-diagnostic-self-move) — exercises the self-guard
  CHECK(a.get() == raw);
  CHECK(static_cast<bool>(a));
}

TEST_CASE("OwnedAddrInfo release relinquishes ownership", "[network][name_resolver][c1]")
{
  OwnedAddrInfo a{makeNumericChain()};
  ::addrinfo *raw = a.release();
  CHECK(raw != nullptr);
  CHECK(a.get() == nullptr);
  CHECK_FALSE(static_cast<bool>(a));
  ::freeaddrinfo(raw); // caller now owns it — free to keep LSan clean
}

TEST_CASE("OwnedAddrInfo single-free under shared_ptr fan-out", "[network][name_resolver][c1]")
{
  // Mirrors the resolve-path carrier: shared_ptr<OwnedAddrInfo> copied into a
  // deferred closure; ::freeaddrinfo runs exactly once when the last handle drops.
  auto sp = std::make_shared<OwnedAddrInfo>(makeNumericChain());
  auto sp2 = sp; // copy the handle (transient 2 owners)
  ::addrinfo *raw = sp->get();
  CHECK(raw != nullptr);
  CHECK(sp2->get() == raw);
  sp.reset();
  CHECK(sp2->get() == raw); // still alive under the second handle
  sp2.reset();              // sole free here
  // NON-VACUITY NOTE (cpp17-L3): the single-free guarantee (exactly-once
  // ::freeaddrinfo) is enforced by running this binary under AddressSanitizer —
  // iora_test_name_resolver is in IORA_SANITIZED_TEST_TARGETS (tests/CMakeLists.txt).
  // A double-free (if OwnedAddrInfo's move/dtor regressed) aborts under ASan; a
  // leak (if it never freed) is caught by LSan. The observable assertions above
  // (ownership transfers, chain stays alive under the surviving handle) are the
  // structural half; ASan/LSan is the memory half. Run with `setarch $(uname -m) -R`.
  CHECK(true);
}

// --- C3: iora::core::blockingIoPool() ---------------------------------------
// The full ~145-stuck-resolve saturation/reject-fast test is deliberately
// ISOLATED and LAST-ORDERED in task-6.1 (stuck uncancellable workers persist
// for the resolver timeout and would bleed across cases in one binary). Here we
// only prove the immortal accessor is stable and dispatches normal work.

TEST_CASE("blockingIoPool is a stable immortal reference", "[network][name_resolver][c3]")
{
  iora::core::ThreadPool &a = iora::core::blockingIoPool();
  iora::core::ThreadPool &b = iora::core::blockingIoPool();
  CHECK(&a == &b); // same object every call — no per-call construction
}

TEST_CASE("blockingIoPool dispatches a task off the caller thread", "[network][name_resolver][c3]")
{
  std::mutex m;
  std::condition_variable cv;
  bool ran = false;
  const std::thread::id caller = std::this_thread::get_id();
  std::thread::id worker;

  const bool queued = iora::core::blockingIoPool().tryEnqueue(
    [&]
    {
      std::lock_guard<std::mutex> g(m);
      worker = std::this_thread::get_id();
      ran = true;
      cv.notify_one();
    });
  REQUIRE(queued);

  std::unique_lock<std::mutex> lk(m);
  REQUIRE(cv.wait_for(lk, std::chrono::seconds(5), [&] { return ran; }));
  CHECK(worker != caller); // ran on a pool thread, not inline
}

// --- C1: ResolveResult + RESOLVER_POOL_SATURATED sentinel (task-1.2) ---------

TEST_CASE("RESOLVER_POOL_SATURATED is distinct from every EAI_* code",
          "[network][name_resolver][c1]")
{
  using iora::network::RESOLVER_POOL_SATURATED;
  // The full glibc EAI_* set — the sentinel must collide with none of them.
  const int eaiCodes[] = {
    EAI_BADFLAGS, EAI_NONAME, EAI_AGAIN,  EAI_FAIL,   EAI_FAMILY, EAI_SOCKTYPE,
    EAI_SERVICE,  EAI_MEMORY, EAI_SYSTEM, EAI_OVERFLOW,
#ifdef EAI_NODATA
    EAI_NODATA,
#endif
#ifdef EAI_ADDRFAMILY
    EAI_ADDRFAMILY,
#endif
  };
  for (int code : eaiCodes)
  {
    CHECK(RESOLVER_POOL_SATURATED != code);
  }
  CHECK(RESOLVER_POOL_SATURATED != 0); // 0 is success
}

TEST_CASE("resolveErrorMessage distinguishes saturation from a resolver error",
          "[network][name_resolver][c1]")
{
  using iora::network::resolveErrorMessage;
  using iora::network::RESOLVER_POOL_SATURATED;
  CHECK(std::string(resolveErrorMessage(RESOLVER_POOL_SATURATED)) == "resolver pool saturated");
  // A real EAI_* code delegates to gai_strerror and is NOT the saturation string.
  CHECK(std::string(resolveErrorMessage(EAI_NONAME)) == std::string(::gai_strerror(EAI_NONAME)));
  CHECK(std::string(resolveErrorMessage(EAI_NONAME)) != "resolver pool saturated");
}

// --- C1: resolveHostAsync (task-1.4) ----------------------------------------
// Reject-fast (tryEnqueue==false, inline saturation) requires ~145 stuck
// resolves and is ISOLATED in task-6.1. Here: the off-thread success path and a
// deterministic (no-network) resolver-error path.

TEST_CASE("resolveHostAsync resolves a name on a pool thread", "[network][name_resolver][c1]")
{
  std::mutex m;
  std::condition_variable cv;
  bool done = false;
  iora::network::ResolveResult result;
  const std::thread::id caller = std::this_thread::get_id();
  std::thread::id worker;

  ::addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  iora::network::resolveHostAsync("localhost", "5060", hints,
                                  [&](iora::network::ResolveResult r)
                                  {
                                    std::lock_guard<std::mutex> g(m);
                                    worker = std::this_thread::get_id();
                                    result = std::move(r);
                                    done = true;
                                    cv.notify_one();
                                  });

  std::unique_lock<std::mutex> lk(m);
  REQUIRE(cv.wait_for(lk, std::chrono::seconds(5), [&] { return done; }));
  CHECK(result.gaiCode == 0);
  CHECK(static_cast<bool>(result.addrs));
  CHECK(result.addrs->get() != nullptr);
  CHECK(worker != caller); // resolution ran off the caller's thread
}

TEST_CASE("resolveHostAsync reports a resolver error with a null chain",
          "[network][name_resolver][c1]")
{
  std::mutex m;
  std::condition_variable cv;
  bool done = false;
  iora::network::ResolveResult result;

  // AI_NUMERICHOST on a non-numeric host => deterministic EAI_NONAME, no DNS.
  ::addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICHOST;

  iora::network::resolveHostAsync("not-a-numeric-host", "5060", hints,
                                  [&](iora::network::ResolveResult r)
                                  {
                                    std::lock_guard<std::mutex> g(m);
                                    result = std::move(r);
                                    done = true;
                                    cv.notify_one();
                                  });

  std::unique_lock<std::mutex> lk(m);
  REQUIRE(cv.wait_for(lk, std::chrono::seconds(5), [&] { return done; }));
  CHECK(result.gaiCode != 0);
  CHECK(result.gaiCode != iora::network::RESOLVER_POOL_SATURATED); // a real EAI_*, not saturation
  CHECK_FALSE(static_cast<bool>(result.addrs));
}
