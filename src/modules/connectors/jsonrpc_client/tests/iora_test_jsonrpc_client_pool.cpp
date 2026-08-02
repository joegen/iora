// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.
//
// Pool lifetime and identity defect repros for JsonRpcClient (tracker
// 2026-07-26-2). Phase 1 builds the observation seam, the latched-HTTP fixture
// and the four RED repros (CR-1..CR-4) that MUST FAIL against the unmodified
// baseline. The later phases turn each RED repro GREEN. The raw-byte capture
// server (task-1.3 part 2) is deferred to phase 7, where its consumers live.
//
// Crash-evidence note (task-1.1(e-pre)): this host's core_pattern is a pipe
// (|/wsl-capture-crash) and core(5) states RLIMIT_CORE is NOT enforced for
// piped dumps, so a SIGSEGV/SIGABRT would invoke the WSL crash handler for
// minutes and present to ctest as a TIMEOUT. Phase 1 carried a CR-1 crash half
// (an out-of-range index release guarded by prctl(PR_SET_DUMPABLE, 0)); it is
// retired in phase 4 because handle-based release has no index to run out of
// range, so no faulting target remains here. No target expects std::terminate,
// so no std::set_terminate is installed.

#define CATCH_CONFIG_RUNNER
#include "iora/iora.hpp"

#include "jsonrpc_client.hpp"

#include <atomic>
#include <catch2/catch.hpp>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

using namespace iora;
using iora::modules::connectors::Config;
using iora::modules::connectors::JsonRpcClient;

// ---------------------------------------------------------------------------
// task-1.2a — the POOL observation seam. Defined here (never in the shipped
// header); befriended by JsonRpcClient and detail::EndpointPool. Every read of
// pool state happens under the client mutex. connectionId is the heap address
// of the PooledConnection, which is STABLE across a vector shift (only the
// vector of owning pointers moves, never the pointees) — so an assertion keyed
// on it survives task-4.1a's shared_ptr conversion unchanged.
// ---------------------------------------------------------------------------
namespace iora
{
namespace modules
{
namespace connectors
{
struct JsonRpcClientTestAccess
{
  struct ConnInfo
  {
    std::uintptr_t connectionId;                 ///< reinterpret_cast<uintptr_t>(PooledConnection*)
    const iora::network::HttpClient *clientPtr;  ///< &pc->client(), to match a live lease
    bool inUse;
    std::chrono::steady_clock::time_point lastUsed;
  };

  struct PoolSnapshot
  {
    std::string poolKey;
    std::vector<ConnInfo> connections;
    /// task-6.1a: creations RESERVED on this pool but not yet published — i.e.
    /// currently inside phase-6's unlocked construction window. Read under the
    /// same client mutex as `connections`, so a snapshot is internally
    /// consistent. The rollback (task-6.3) and pin (task-6.4a) cases assert
    /// through this field that a reservation returns to zero and that a pinned
    /// pool survives every retire site.
    std::size_t pendingCreates{0};
  };

  /// \brief Acquire a lease the TEST owns (required by the single-threaded CR-1
  /// repro, which must construct and dispose leases itself). Pool state now
  /// lives in JsonRpcClientImpl, reached through the facade's _impl handle.
  ///
  /// COUNTED, exactly as every production entry point is (cpp17 L-1 / ts-2,
  /// raised independently by two reviewers). quiesce()'s STEP 4 is the sixth
  /// pool-erase site and the one that does NOT honour the DP#8 pin — it clears
  /// _pools wholesale. Its safety rests entirely on STEP 3 having drained
  /// _inFlight first, which holds only because every acquire_ caller is
  /// CountGuard-covered. This seam used to be the one uncounted caller, and
  /// roughly nine phase-6 cases park a thread inside acquire_'s construction
  /// window through it. No case destroys the client while such a thread is
  /// parked today — but nothing structurally stopped one from doing so, and in
  /// the Release build the gate runs, STEP 4's pin assert is compiled out, so
  /// the failure mode would have been a silent use-after-free on the parked
  /// thread's re-lock rather than a diagnosable abort. Counting the seam makes
  /// STEP 3 wait for it, which is the actual invariant rather than an unwritten
  /// convention every future test author has to know.
  ///
  /// A REFUSED guard (client already closing) is deliberately NOT converted into
  /// an early throw here: acquire_'s own entry check throws ClientShutdownError
  /// on that path, so every existing case observes exactly the exception it did
  /// before.
  ///
  /// SCOPE OF THE COUNT (cpp17 iteration-3 L-2): the guard spans the acquire_
  /// CALL ONLY, not the lifetime of the lease it returns. A test that takes a
  /// lease through this seam and then destroys the client on another thread
  /// while the lease is still live sees _inFlight == 0, so quiesce STEP 3 does
  /// NOT wait for it. That is safe — the lease holds a shared_ptr<Impl>, so
  /// there is no use-after-free — but do not read this guard as making an
  /// outstanding seam lease block the destructor. It closes the construction
  /// window, which is the hazard STEP 4's pin assert cares about.
  static detail::ConnectionLease acquire(JsonRpcClient &c, const std::string &endpoint)
  {
    JsonRpcClientImpl::CountGuard guard(c._impl.get());
    return c._impl->acquire_(endpoint);
  }

  /// \brief Snapshot every pool's connections under the client mutex.
  static std::vector<PoolSnapshot> snapshotPools(JsonRpcClient &c)
  {
    std::lock_guard<std::mutex> guard(c._impl->_mutex);
    std::vector<PoolSnapshot> out;
    for (const auto &kv : c._impl->_pools)
    {
      PoolSnapshot ps;
      ps.poolKey = kv.first;
      ps.pendingCreates = kv.second->pendingCreates();
      for (const auto &pc : kv.second->_connections)
      {
        ConnInfo ci;
        ci.connectionId = reinterpret_cast<std::uintptr_t>(pc.get());
        ci.clientPtr = &pc->client();
        ci.inUse = pc->inUse();
        ci.lastUsed = pc->lastUsed();
        ps.connections.push_back(ci);
      }
      out.push_back(std::move(ps));
    }
    return out;
  }

  static std::size_t totalConnections(JsonRpcClient &c)
  {
    std::lock_guard<std::mutex> guard(c._impl->_mutex);
    return c._impl->_totalConnections;
  }

  static std::size_t recalcTotal(JsonRpcClient &c)
  {
    std::lock_guard<std::mutex> guard(c._impl->_mutex);
    return c._impl->recalcTotalLocked_();
  }

  /// \brief The connectionId of the connection a live lease references, matched
  /// by the stable HttpClient address. Returns 0 if not found.
  static std::uintptr_t connectionIdOf(JsonRpcClient &c, detail::ConnectionLease &lease)
  {
    const auto *target = &lease.client();
    for (const auto &ps : snapshotPools(c))
    {
      for (const auto &ci : ps.connections)
      {
        if (ci.clientPtr == target)
        {
          return ci.connectionId;
        }
      }
    }
    return 0;
  }

  /// \brief The owning handle of the first connection in `ep`'s pool, or nullptr.
  /// Used to drive EndpointPool::erase directly in the guard tests.
  static std::shared_ptr<detail::PooledConnection> firstHandle(JsonRpcClient &c,
                                                               const std::string &ep)
  {
    std::lock_guard<std::mutex> guard(c._impl->_mutex);
    auto it = c._impl->_pools.find(ep);
    if (it == c._impl->_pools.end() || it->second->_connections.empty())
    {
      return nullptr;
    }
    return it->second->_connections.front();
  }

  /// \brief Drive EndpointPool::erase(handle) on `ep`'s pool under the client
  /// mutex. Propagates the std::logic_error the guard throws (task-4.2/4.3).
  static void eraseHandle(JsonRpcClient &c, const std::string &ep,
                          const std::shared_ptr<detail::PooledConnection> &handle)
  {
    // `bin` declared BEFORE `guard` so that on a SUCCESSFUL erase the moved-out
    // connection is destroyed after the lock releases, mirroring the production
    // collect-then-destroy discipline (T6-2). (The two guard cases under test —
    // absent / in-use handle — throw before touching `bin`, but declaring it
    // first keeps this seam safe for any future test that erases a live handle.)
    std::vector<std::shared_ptr<detail::PooledConnection>> bin;
    std::lock_guard<std::mutex> guard(c._impl->_mutex);
    auto it = c._impl->_pools.find(ep);
    if (it == c._impl->_pools.end())
    {
      throw std::logic_error("test seam: no pool for endpoint");
    }
    it->second->erase(handle, bin);
  }

  /// \brief Remove `ep`'s pool from _pools and RETURN it (kept alive by the
  /// caller). Drives the CR-1c path the public API cannot reach — a live lease
  /// keeps its connection in-use, so purge/evict can never empty the pool.
  static std::shared_ptr<detail::EndpointPool> detachPool(JsonRpcClient &c, const std::string &ep)
  {
    std::lock_guard<std::mutex> guard(c._impl->_mutex);
    auto it = c._impl->_pools.find(ep);
    if (it == c._impl->_pools.end())
    {
      return nullptr;
    }
    auto pool = std::move(it->second);
    c._impl->_pools.erase(it);
    return pool;
  }

  /// \brief in-use flag of the first connection of a (possibly detached) pool,
  /// read under the client mutex so the read has happens-before with any
  /// releaseConnection_ markFree() on another thread (cheap insurance beyond the
  /// current single-threaded callers).
  static bool firstConnInUse(JsonRpcClient &c, const std::shared_ptr<detail::EndpointPool> &pool)
  {
    std::lock_guard<std::mutex> guard(c._impl->_mutex);
    return pool->_connections.front()->inUse();
  }

  static std::size_t poolConnCount(JsonRpcClient &c,
                                   const std::shared_ptr<detail::EndpointPool> &pool)
  {
    std::lock_guard<std::mutex> guard(c._impl->_mutex);
    return pool->_connections.size();
  }

  // -------------------------------------------------------------------------
  // task-1.2b — the QUIESCE observation seam (SHAPE-B). The state is EMBEDDED in
  // JsonRpcClientImpl (there is no separate Quiesce struct), so the snapshot is
  // taken under Impl::_quiesceMutex, NOT the pool _mutex. Two-stage acquisition
  // is mandatory: snapshotPools() (pool _mutex) and quiesceSnapshot()
  // (_quiesceMutex) are taken SEQUENTIALLY and are NOT atomic w.r.t. each other
  // (task-3.6 forbids holding both simultaneously). There is no
  // currentThreadMarker() accessor (round-7 F-7): self-destruct uses `owners`.
  // -------------------------------------------------------------------------
  struct QuiesceSnapshot
  {
    std::size_t inFlight;
    bool closing;
    std::vector<std::thread::id> owners;
  };

  static QuiesceSnapshot quiesceSnapshot(JsonRpcClient &c)
  {
    std::lock_guard<std::mutex> lk(c._impl->_quiesceMutex);
    return QuiesceSnapshot{c._impl->_inFlight,
                           c._impl->_closing.load(std::memory_order_relaxed), c._impl->_owners};
  }

  /// \brief TEST-ONLY: perform ONLY the destructor's STEP-1 latch (set _closing
  /// under _quiesceMutex + notify_all), WITHOUT the STEP-2/3/4 cancel-wait-clear.
  /// This exercises the REAL production gate (CountGuard reads the same _closing)
  /// so the task-3.4 refusal channels can be tested deterministically, without a
  /// racy concurrent-destructor window. Safe to compose with the real
  /// destructor: quiesce()'s STEP-1 store is idempotent when already latched.
  static void latchClosing(JsonRpcClient &c)
  {
    {
      std::lock_guard<std::mutex> lk(c._impl->_quiesceMutex);
      c._impl->_closing.store(true, std::memory_order_release);
    }
    c._impl->_quiesceCv.notify_all();
  }

  // -------------------------------------------------------------------------
  // task-6.4b(f)(i) / (t) — the DISCARDED-TASK seam. task-3.5(e) forbids (and
  // ThreadPool::reset() cannot reach) the "reset a live pool" shape the earlier
  // draft of case (f) called for, so the discard is exercised in UNIT form
  // instead: build EXACTLY the closure dispatchToken_ would enqueue, then
  // destroy it WITHOUT running it. Destroying the std::function drops the sole
  // shared_ptr<InFlightToken>, which runs ~CountGuard (decrement + notify) and,
  // for the future overload, ~promise (broken_promise).
  // -------------------------------------------------------------------------

  /// \brief The callback-overload closure, unenqueued. Counting happens at
  /// TOKEN CONSTRUCTION (task-3.3), so _inFlight is already 1 on return.
  static std::function<void()> makeDiscardableAsyncClosure(JsonRpcClient &c,
                                                           const std::string &ep)
  {
    auto impl = c._impl;
    auto token = std::make_shared<JsonRpcClientImpl::InFlightToken<iora::parsers::Json>>(
      impl,
      [ep](JsonRpcClientImpl *self)
      { return self->callCore_(ep, "ping", iora::parsers::Json::object(), {}); },
      [](iora::parsers::Json) {}, [](std::exception_ptr) {});
    return [token]() { token->runBody(); };
  }

  struct DiscardableFutureTask
  {
    std::function<void()> closure;
    std::future<iora::parsers::Json> future;
  };

  /// \brief The future-overload equivalent, mirroring dispatchFuture_: the
  /// promise is owned by the token's callables, so discarding the closure
  /// destroys them and the future resolves with broken_promise.
  static DiscardableFutureTask makeDiscardableFutureTask(JsonRpcClient &c, const std::string &ep)
  {
    auto impl = c._impl;
    auto promise = std::make_shared<std::promise<iora::parsers::Json>>();
    DiscardableFutureTask out;
    out.future = promise->get_future();
    auto token = std::make_shared<JsonRpcClientImpl::InFlightToken<iora::parsers::Json>>(
      impl,
      [ep](JsonRpcClientImpl *self)
      { return self->callCore_(ep, "ping", iora::parsers::Json::object(), {}); },
      [promise](iora::parsers::Json r) { promise->set_value(std::move(r)); },
      [promise](std::exception_ptr e) { promise->set_exception(std::move(e)); });
    out.closure = [token]() { token->runBody(); };
    return out;
  }

  /// \brief task-6.4b(z) — send a batch on an ALREADY-HELD lease. Why that is
  /// the only ordering that reaches the in-core batch _closing fast-fail is
  /// documented once, at case (z) itself.
  static std::vector<iora::parsers::Json>
  sendBatchOnLeaseDirect(JsonRpcClient &c, detail::ConnectionLease &lease, const std::string &ep,
                         const std::vector<iora::modules::connectors::BatchItem> &items)
  {
    return c._impl->sendBatchOnLease_(lease, ep, items, {});
  }
};
} // namespace connectors
} // namespace modules
} // namespace iora

using iora::modules::connectors::JsonRpcClientTestAccess;
using iora::modules::connectors::PoolExhaustedError;
using iora::modules::connectors::detail::ConnectionLease;
using iora::modules::connectors::detail::PooledConnection;

// task-2.2 — the pImpl facade must stay non-copyable AND non-movable; a facade
// that could be copied or moved would share one JsonRpcClientImpl between two
// objects with no defined semantics. Verified at compile time (a copy/move
// would otherwise be silently generated because the facade holds only a
// shared_ptr).
static_assert(!std::is_copy_constructible<JsonRpcClient>::value,
              "JsonRpcClient must not be copy-constructible");
static_assert(!std::is_copy_assignable<JsonRpcClient>::value,
              "JsonRpcClient must not be copy-assignable");
static_assert(!std::is_move_constructible<JsonRpcClient>::value,
              "JsonRpcClient must not be move-constructible");
static_assert(!std::is_move_assignable<JsonRpcClient>::value,
              "JsonRpcClient must not be move-assignable");

namespace
{

/// \brief Find the in-use flag of a given connectionId across a pool snapshot.
/// Returns nullopt if the id is not present (e.g. the connection was erased).
std::optional<bool>
inUseOf(const std::vector<JsonRpcClientTestAccess::PoolSnapshot> &snap, std::uintptr_t id)
{
  for (const auto &ps : snap)
  {
    for (const auto &ci : ps.connections)
    {
      if (ci.connectionId == id)
      {
        return ci.inUse;
      }
    }
  }
  return std::nullopt;
}

/// \brief Joins `t` on scope exit, first running `unblock` so a helper parked
/// on a latch cannot wedge the join. THE file's single thread-cleanup idiom
/// (simpl LOW-1/LOW-2): the hand-rolled ScopeExit and ReleaseAndJoin variants
/// it replaced are gone, so there is one shape to get right rather than three.
/// \details Exists because the pattern "spawn a thread, REQUIRE something, then
/// join" is a trap: Catch2's REQUIRE throws on failure, and unwinding through a
/// still-joinable std::thread calls std::terminate — turning the named
/// assertion you needed to read into a SIGABRT and a suite-wide timeout. Declare
/// one of these IMMEDIATELY AFTER the thread (so it is destroyed before it) and
/// the failure reports as itself.
class JoinGuard
{
public:
  explicit JoinGuard(std::thread &t, std::function<void()> unblock = {})
      : _t(t), _unblock(std::move(unblock))
  {
  }
  JoinGuard(const JoinGuard &) = delete;
  JoinGuard &operator=(const JoinGuard &) = delete;
  ~JoinGuard()
  {
    try
    {
      if (_unblock)
      {
        _unblock();
      }
      if (_t.joinable())
      {
        _t.join();
      }
    }
    catch (...)
    {
    }
  }

private:
  std::thread &_t;
  std::function<void()> _unblock;
};

/// \brief One-shot latch with BOUNDED waits. Every wait has a deadline so a
/// test that forgets to signal — or one whose production path never reaches the
/// signal because the fix regressed — fails on a REQUIRE rather than wedging
/// the whole binary until ctest's TIMEOUT (which reports as a timeout, not as
/// the specific assertion that broke).
class TestLatch
{
public:
  /// \details notify_all() runs WHILE HOLDING _m, deliberately (ts M-1(b)). The
  /// conventional "unlock, then notify" shape races latch destruction: the woken
  /// waiter can return from wait(), run to completion and destroy this TestLatch
  /// while the signaller is still inside notify_all() on the destroyed _cv —
  /// formally UB. Notifying under the lock makes that impossible, because the
  /// waiter cannot leave wait() until we release. This mirrors the "notify under
  /// the lock" rule production's CountGuard already follows. The cost — a woken
  /// waiter may immediately re-block on _m — is irrelevant in a test latch.
  void signal()
  {
    std::lock_guard<std::mutex> lk(_m);
    _set = true;
    _cv.notify_all();
  }

  bool wait(std::chrono::milliseconds bound = std::chrono::seconds(5))
  {
    std::unique_lock<std::mutex> lk(_m);
    return _cv.wait_for(lk, bound, [this] { return _set; });
  }

private:
  std::mutex _m;
  std::condition_variable _cv;
  bool _set{false};
};

/// \brief Spin until `pred` holds or the bound elapses. Used only to observe a
/// state another thread reaches without a dedicated latch (e.g. "the parked
/// factory's reservation is now visible through the seam"). Bounded, so a
/// regression fails the following REQUIRE instead of hanging.
template <typename Pred>
bool waitFor(Pred pred, std::chrono::milliseconds bound = std::chrono::seconds(5))
{
  const auto deadline = std::chrono::steady_clock::now() + bound;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (pred())
    {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return pred();
}

/// \brief Occupies one ThreadPool worker until released — the "the pool's only
/// worker is busy, so the next enqueue queues behind it (or fails when the
/// queue is full)" precondition the phase-3 CR-4 and enqueue-failure cases both
/// need.
/// \details Replaces the hand-rolled promise + `while (!started) yield()` spin
/// those two cases each carried (simpl M6): a spin-yield burns a core on this
/// 2-core host, and it is not observably different from a latch wait.
///
/// THE LATCHES ARE SHARED-OWNED BY THE TASK, NOT MEMBERS (ts M-1(a)). The first
/// version of this helper enqueued a lambda capturing `this` and tried to make
/// teardown safe by waiting in the destructor only when it observed the task had
/// already started. That early-out is unsound: while the ThreadPool is alive,
/// "has not started yet" is not "will never start". If a REQUIRE fails and
/// unwinds while the task is still QUEUED, the members die and the pool then
/// runs the lambda against freed memory — and it does so precisely on a FAILING
/// run, converting the named assertion into a SIGSEGV and a suite-wide timeout,
/// which is the exact masking this helper exists to prevent. Holding the state
/// in a shared_ptr the task captures BY VALUE removes the question entirely:
/// the task cannot outlive its own state, so the destructor needs no rendezvous
/// and no reasoning about scheduling at all.
class BlockedWorker
{
  struct State
  {
    TestLatch started;
    TestLatch release;
  };

public:
  explicit BlockedWorker(iora::core::ThreadPool &pool) : _s(std::make_shared<State>())
  {
    auto s = _s; // BY VALUE into the task: keeps the state alive on its own
    pool.enqueue(
      [s]()
      {
        s->started.signal();
        s->release.wait(std::chrono::seconds(30));
      });
  }
  BlockedWorker(const BlockedWorker &) = delete;
  BlockedWorker &operator=(const BlockedWorker &) = delete;

  /// \brief Block until the worker is confirmed running. A false return means
  /// the pool never scheduled it — the case's precondition failed, so callers
  /// REQUIRE on this rather than assuming it.
  bool waitUntilRunning() { return _s->started.wait(); }

  /// \brief Idempotent, so the happy path can release explicitly and the
  /// destructor can release again.
  void release() { _s->release.signal(); }

  ~BlockedWorker() { _s->release.signal(); }

private:
  std::shared_ptr<State> _s;
};

/// \brief Shared onError probe for the phase-3 refusal/enqueue-failure cases
/// (simpl-3): records that onError fired and whether the delivered exception was
/// a ClientShutdownError. Both flags are atomic so the probe is safe whether
/// onError runs in the calling thread (refusal) or on a worker (enqueue
/// failure / discard).
std::function<void(std::exception_ptr)> shutdownErrorProbe(std::atomic<bool> &errCalled,
                                                           std::atomic<bool> &wasShutdown)
{
  return [&errCalled, &wasShutdown](std::exception_ptr e)
  {
    errCalled.store(true);
    try
    {
      std::rethrow_exception(e);
    }
    catch (const iora::modules::connectors::ClientShutdownError &)
    {
      wasShutdown.store(true);
    }
    catch (...)
    {
    }
  };
}

/// \brief A Config whose factory hands out a bare HttpClient and never touches
/// the network — acquire_ only calls the factory, so
/// the pool-lifetime repros need no server at all.
Config stubFactoryConfig()
{
  Config cfg;
  cfg.httpClientFactory = [](const std::string &)
  { return std::make_unique<iora::network::HttpClient>(); };
  return cfg;
}

/// \brief The JSON-RPC 2.0 success envelope the fixtures reply with. No `error`
/// member, so parseResponseOrThrow_ returns the
/// result rather than throwing RemoteError (task-1.3(D)).
constexpr const char *kJsonRpcSuccessBody = R"({"jsonrpc":"2.0","result":{},"id":1})";

// -------------------------------------------------------------------------
// task-1.3 (part 1) — LATCHED HTTP SERVER fixture. A POST handler signals its
// arrival and then blocks on a release latch until the test lets it go, so a
// test can hold a request in flight and observe pool state around it (consumers
// task-6.4 and task-9.1). Correctness conditions hoisted here per task-1.3:
//   * RAII release AND server stop in the destructor — NEVER a trailing
//     statement. An abandoned Catch2 SECTION leaf skips trailing cleanup, which
//     would leave a handler parked at teardown; HttpServer::stop() abandons its
//     drain after 2 s while ~HttpServer destroys handlers before the thread
//     pool joins, so a parked handler is a use-after-free.
//   * A BOUNDED server-side wait — the handler never blocks forever even if a
//     test forgets to release.
//   * Delta / reset-first stats assertions are the caller's job; the fixture
//     exposes arrivedCount()/completedCount() for that.
// The raw-byte CAPTURE server (task-1.3 part 2) is deferred to phase 7, where
// its consumers live (human decision, 2026-07-29).
// -------------------------------------------------------------------------
class LatchedHttpServer
{
public:
  explicit LatchedHttpServer(std::uint16_t port,
                             std::chrono::milliseconds handlerWaitBound = std::chrono::seconds(5))
      : _waitBound(handlerWaitBound), _server("127.0.0.1", static_cast<int>(port))
  {
    _server.onPost("/rpc",
                   [this](const iora::network::HttpServer::Request &,
                          iora::network::HttpServer::Response &res)
                   {
                     {
                       std::unique_lock<std::mutex> lk(_m);
                       ++_arrived;
                       _arrivedCv.notify_all();
                       // Bounded: return even if release() is never called.
                       _releaseCv.wait_for(lk, _waitBound, [this] { return _released; });
                     }
                     res.set_content(kJsonRpcSuccessBody, "application/json");
                     std::lock_guard<std::mutex> lk(_m);
                     ++_completed;
                   });
    _server.start();
  }

  ~LatchedHttpServer()
  {
    release();      // unblock any parked handler FIRST...
    _server.stop(); // ...then join the server threads (no parked-handler UAF).
  }

  LatchedHttpServer(const LatchedHttpServer &) = delete;
  LatchedHttpServer &operator=(const LatchedHttpServer &) = delete;

  /// \brief Block until at least `n` requests have reached the latch, or the
  /// bound elapses. Returns true if the target was met.
  bool waitForArrival(int n, std::chrono::milliseconds bound = std::chrono::seconds(3))
  {
    std::unique_lock<std::mutex> lk(_m);
    return _arrivedCv.wait_for(lk, bound, [this, n] { return _arrived >= n; });
  }

  /// \brief Release the latch. ONE-SHOT: once released, every subsequent
  /// request passes straight through (the latch is never re-armed). A consumer
  /// that needs to hold a SECOND request in flight (e.g. phase-7 task-6.4 /
  /// task-9.1) must instantiate a fresh fixture per hold cycle (L5).
  void release()
  {
    {
      std::lock_guard<std::mutex> lk(_m);
      _released = true;
    }
    _releaseCv.notify_all();
  }

  int arrivedCount()
  {
    std::lock_guard<std::mutex> lk(_m);
    return _arrived;
  }

  int completedCount()
  {
    std::lock_guard<std::mutex> lk(_m);
    return _completed;
  }

private:
  // Declaration order is teardown order in reverse. _server MUST be declared
  // LAST so it is destroyed FIRST during member destruction — its handler
  // threads must stop touching _m/_arrivedCv/_releaseCv before those are
  // destroyed. (The destructor body's release()+stop() already unblocks and
  // joins handlers; this aligns member order with it as belt-and-suspenders,
  // in case HttpServer::stop() abandons its drain after 2 s — M3.)
  std::chrono::milliseconds _waitBound;
  std::mutex _m;
  std::condition_variable _arrivedCv;
  std::condition_variable _releaseCv;
  int _arrived{0};
  int _completed{0};
  bool _released{false};
  iora::network::HttpServer _server;
};

/// \brief Bring up a single process-wide IoraService the client ctor requires.
/// JsonRpcClient's constructor takes an IoraService& and a core::ThreadPool&,
/// so the service must be initialized exactly once for the whole binary.
iora::IoraService &testService()
{
  static bool initialized = false;
  if (!initialized)
  {
    iora::IoraService::Config config;
    // These pool tests never use the service's HTTP server (the client drives
    // its own HttpClient instances and JsonRpcClient::_service is dead state),
    // so disable it: that removes the fixed-port bind and, with it, the only
    // path by which IoraService::init can throw here (iora.hpp:1175 gates the
    // WebhookServer bind/listen on features.server).
    config.features.server = false;
    config.log.file = "jsonrpc_client_pool_test";
    config.log.level = "info";
    config.modules.autoLoad = false;
    iora::IoraService::init(config);
    initialized = true;
  }
  return iora::IoraService::instanceRef();
}

} // namespace

// -------------------------------------------------------------------------
// Scaffold placeholder — proves the TU compiles, the module header is on the
// include path, and the client can be constructed. Replaced/joined by the CR-1
// .. CR-4 repros (task-1.4 .. task-1.7) as phase 1 proceeds.
// -------------------------------------------------------------------------
TEST_CASE("scaffold: JsonRpcClient constructs against a live service",
          "[jsonrpc][pool][scaffold]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(/*initial*/ 1, /*max*/ 1, std::chrono::seconds(1));
  Config cfg;
  cfg.maxConnectionsPerEndpoint = 2;
  JsonRpcClient client(svc, pool, cfg);
  REQUIRE(client.config().maxConnectionsPerEndpoint == 2);
}

// -------------------------------------------------------------------------
// task-1.2a seam sanity — the seam the four repros depend on can acquire a
// lease the test owns and observe per-connection identity/in-use state.
// -------------------------------------------------------------------------
TEST_CASE("seam: snapshot observes acquired connection identity",
          "[jsonrpc][pool][seam]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(/*initial*/ 1, /*max*/ 1, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  cfg.maxConnectionsPerEndpoint = 3;
  JsonRpcClient client(svc, pool, cfg);

  const std::string ep = "http://unit.test/rpc";

  std::chrono::steady_clock::time_point lastUsedWhileInUse;
  {
    auto lease = JsonRpcClientTestAccess::acquire(client, ep);
    const auto id = JsonRpcClientTestAccess::connectionIdOf(client, lease);
    REQUIRE(id != 0);

    auto snaps = JsonRpcClientTestAccess::snapshotPools(client);
    REQUIRE(snaps.size() == 1);
    REQUIRE(snaps[0].poolKey == ep);
    REQUIRE(snaps[0].connections.size() == 1);
    REQUIRE(snaps[0].connections[0].connectionId == id);
    REQUIRE(snaps[0].connections[0].inUse == true);
    lastUsedWhileInUse = snaps[0].connections[0].lastUsed;
    REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 1);
    REQUIRE(JsonRpcClientTestAccess::recalcTotal(client) == 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(5)); // let the clock advance
  }

  // After the lease is released, the connection is free but retained, and
  // release() (markFree) advanced its lastUsed timestamp.
  auto after = JsonRpcClientTestAccess::snapshotPools(client);
  REQUIRE(after.size() == 1);
  REQUIRE(after[0].connections.size() == 1);
  REQUIRE(after[0].connections[0].inUse == false);
  // Strict '>': the 5 ms sleep above ran before the lease destructor's
  // markFree, so on steady_clock (ns resolution) the freed timestamp is
  // strictly greater — '>=' would pass vacuously even if markFree never
  // touched lastUsed.
  REQUIRE(after[0].connections[0].lastUsed > lastUsedWhileInUse);
}

// -------------------------------------------------------------------------
// task-1.3 (part 1) self-test — the latch actually holds a request in flight
// and the destructor's RAII release+stop unwinds cleanly. Drives the fixture
// with a real JsonRpcClient (default factory, maxRetries=0).
// -------------------------------------------------------------------------
TEST_CASE("fixture: latched HTTP server holds a request until released",
          "[jsonrpc][pool][fixture][latched]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(/*initial*/ 2, /*max*/ 2, std::chrono::seconds(1));

  const std::uint16_t serverPort = 18150;
  LatchedHttpServer server(serverPort);

  Config cfg; // real (non-stub) factory so the client talks to the fixture
  cfg.maxRetries = 0;
  JsonRpcClient client(svc, pool, cfg);
  const std::string ep = "http://127.0.0.1:" + std::to_string(serverPort) + "/rpc";

  std::atomic<bool> callDone{false};
  iora::parsers::Json result;
  std::exception_ptr callErr;
  std::thread caller(
    [&]()
    {
      // Capture any throw instead of letting it escape the std::thread body,
      // which would call std::terminate (M1).
      try
      {
        result = client.call(ep, "ping");
      }
      catch (...)
      {
        callErr = std::current_exception();
      }
      callDone.store(true);
    });

  // RAII: release the latch and join on EVERY exit path, including an early
  // throw from a failing REQUIRE below. A trailing join() would be skipped on
  // unwind, leaving `caller` joinable -> ~thread -> std::terminate -> SIGABRT
  // -> the WSL piped-core handler masks the real failure as a ctest TIMEOUT
  // (H1; the hazard task-1.3(1) mandated against).
  JoinGuard guard{caller, [&]() { server.release(); }};

  // The handler parks on the latch: the request has arrived but not completed.
  REQUIRE(server.waitForArrival(1));
  REQUIRE(server.arrivedCount() == 1);
  REQUIRE(server.completedCount() == 0);
  REQUIRE(callDone.load() == false);

  server.release();
  caller.join(); // idempotent with the guard (guarded by joinable())

  REQUIRE(callDone.load() == true);
  REQUIRE(!callErr); // the call must have succeeded, not thrown
  REQUIRE(server.completedCount() == 1);
  REQUIRE(result.is_object()); // the JSON-RPC success "result" ({})
}

// =========================================================================
// task-1.4 / task-4.1c — CR-1 regression guard: a ConnectionLease now holds an
// owning std::shared_ptr<PooledConnection> handle, so release is keyed on the
// connection's stable IDENTITY, never a vector index that a mid-vector erase
// invalidates. Single-threaded via the seam: no server, no latch. This case was
// RED at HEAD (phase 1) and is GREEN once task-4.1c lands; it now guards against
// a regression to index-based identity. The out-of-range SIGSEGV companion that
// phase 1 carried is retired: with handle-based release there is no index to run
// out of range, so the fault it demonstrated can no longer occur.
// =========================================================================
TEST_CASE("CR-1 fixed: identity-based release frees the leased connection, not a shifted neighbor",
          "[jsonrpc][pool][cr1]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(/*initial*/ 1, /*max*/ 1, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  cfg.maxConnectionsPerEndpoint = 3; // pinned to the exact number created (cpp17 H-C)
  cfg.idleTimeout = std::chrono::milliseconds(50);
  JsonRpcClient client(svc, pool, cfg);

  const std::string ep = "http://unit.test/rpc";

  // Own the leases so we control destruction order (the friend seam is what
  // makes this feasible at all — task-1.2a).
  auto a = std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, ep)); // idx 0
  auto b = std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, ep)); // idx 1
  auto c = std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, ep)); // idx 2

  const auto idA = JsonRpcClientTestAccess::connectionIdOf(client, *a);
  const auto idB = JsonRpcClientTestAccess::connectionIdOf(client, *b);
  const auto idC = JsonRpcClientTestAccess::connectionIdOf(client, *c);
  REQUIRE(idA != 0);
  REQUIRE(idB != 0);
  REQUIRE(idC != 0);
  REQUIRE(idA != idB);
  REQUIRE(idB != idC);
  REQUIRE(idA != idC); // three distinct heap identities

  a.reset();                                             // release(0): conn A -> free
  std::this_thread::sleep_for(std::chrono::milliseconds(60)); // A now idle > idleTimeout
  client.purgeIdle();                                    // erases idle A; B and C remain, in use

  // Pre-fix: b's stale _index==1 now points at C, so release(1) frees C and
  // leaves B inUse forever. Post-fix (identity-based release): B is freed, C
  // stays inUse.
  b.reset();

  const auto snap = JsonRpcClientTestAccess::snapshotPools(client);
  const auto cInUse = inUseOf(snap, idC);
  const auto bInUse = inUseOf(snap, idB);
  REQUIRE(cInUse.has_value());
  REQUIRE(bInUse.has_value());
  // The discriminating assertion: the connection lease2 (C) still holds must be
  // inUse; the one lease1 (B) held must be free. Would FAIL under index-based
  // release (a regression); PASSES with handle-based identity.
  CHECK(cInUse.value() == true);
  CHECK(bInUse.value() == false);

  // Destroying c's lease is now well-defined: releaseConnection_ does
  // conn->markFree() on the still-owned connC, with no index to run out of
  // range. Let it unwind normally at scope exit (the phase-1 SIGSEGV companion
  // is retired — the fault it demonstrated cannot occur post-fix).
}

// =========================================================================
// task-4.3 — release-guard regression: with EVERY connection leased (all
// in-use), purgeIdle() must evict nothing and every lease must still refer to a
// live, in-use connection. Guards the three in-use erase gates locked in by
// task-4.3 (tryAcquireFree, purgeIdle, EndpointPool::erase) against a future
// edit that erases a leased connection.
// =========================================================================
TEST_CASE("task-4.3: purgeIdle evicts nothing while all connections are leased",
          "[jsonrpc][pool][phase4]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  cfg.maxConnectionsPerEndpoint = 3;
  cfg.idleTimeout = std::chrono::milliseconds(10); // short, so expiry is not the reason
  JsonRpcClient client(svc, pool, cfg);
  const std::string ep = "http://unit.test/rpc";

  auto a = std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, ep));
  auto b = std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, ep));
  auto c = std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, ep));
  const auto idA = JsonRpcClientTestAccess::connectionIdOf(client, *a);
  const auto idB = JsonRpcClientTestAccess::connectionIdOf(client, *b);
  const auto idC = JsonRpcClientTestAccess::connectionIdOf(client, *c);
  REQUIRE(idA != 0);
  REQUIRE(idB != 0);
  REQUIRE(idC != 0);

  // Even well past idleTimeout, in-use connections are NOT expiry-eligible.
  std::this_thread::sleep_for(std::chrono::milliseconds(30));
  REQUIRE(client.purgeIdle() == 0);

  const auto snap = JsonRpcClientTestAccess::snapshotPools(client);
  for (auto id : {idA, idB, idC})
  {
    const auto st = inUseOf(snap, id);
    REQUIRE(st.has_value());   // still present — not erased
    REQUIRE(st.value() == true); // still in use
  }
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 3);
}

// =========================================================================
// task-4.1b — collect-then-destroy exercise: purgeIdle() on a pool of expired
// idle connections evicts them all, and a concurrent acquire on a DIFFERENT
// endpoint completes rather than deadlocking. This exercises the eviction path
// under concurrency and guards against a regression that would hold the client
// mutex across pooled-connection destruction. NOTE: it does not, and cannot,
// prove the microsecond-scale "not blocked for the join duration" timing —
// iora::network::HttpClient is a concrete, non-virtual, fixed-deleter type, so
// its destructor cannot be instrumented from a test. The declared-before-lock
// evicted vectors in acquire_/purgeIdle are what structurally guarantee the
// destruction runs after _mutex is released (T6-2); that is grep-verified.
// =========================================================================
TEST_CASE("task-4.1b: purgeIdle evicts idle connections without blocking other endpoints",
          "[jsonrpc][pool][phase4]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  cfg.maxConnectionsPerEndpoint = 8;
  cfg.idleTimeout = std::chrono::milliseconds(40);
  JsonRpcClient client(svc, pool, cfg);

  const std::string epEvict = "http://unit.test/evict";
  const std::string epLive = "http://unit.test/live";

  // Create and free four connections on epEvict, so they become idle.
  {
    std::vector<std::unique_ptr<ConnectionLease>> leases;
    for (int i = 0; i < 4; ++i)
    {
      leases.push_back(
        std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, epEvict)));
    }
  } // all released -> four idle connections on epEvict
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 4);

  std::this_thread::sleep_for(std::chrono::milliseconds(60)); // epEvict conns now expired

  // While purgeIdle runs on one thread, hammer acquire/release on a DIFFERENT
  // endpoint on another. Both must finish inside the bound (no deadlock, no
  // mutex held across the evicting teardown).
  // ts L-8: the loop is wrapped, because an escaping exception on a std::thread
  // is std::terminate — a PoolExhaustedError or a rollback throw here would kill
  // the whole binary with a SIGABRT instead of failing this case by name. The
  // outcome is recorded and asserted on the MAIN thread (Catch2's REQUIRE is not
  // thread-safe).
  std::atomic<bool> liveDone{false};
  std::atomic<bool> liveThrew{false};
  std::thread live(
    [&]()
    {
      try
      {
        for (int i = 0; i < 50; ++i)
        {
          auto l = JsonRpcClientTestAccess::acquire(client, epLive);
          (void)l.client();
        }
        liveDone.store(true);
      }
      catch (...)
      {
        liveThrew.store(true);
      }
    });
  // ts L-2: the purgeIdle() below runs on MAIN while `live` is joinable. If it
  // threw, the stack would unwind past a joinable thread -> std::terminate.
  // Declared immediately after the thread so it destructs first.
  JoinGuard liveJoiner{live};

  const std::size_t evicted = client.purgeIdle();
  live.join();

  REQUIRE(liveThrew.load() == false);
  REQUIRE(liveDone.load() == true);
  REQUIRE(evicted == 4); // all four idle epEvict connections gone

  // epEvict pool is emptied and dropped; epLive remains with its idle connection.
  const auto snap = JsonRpcClientTestAccess::snapshotPools(client);
  for (const auto &ps : snap)
  {
    REQUIRE(ps.poolKey != epEvict);
  }
  REQUIRE(JsonRpcClientTestAccess::recalcTotal(client) ==
          JsonRpcClientTestAccess::totalConnections(client));
}

// =========================================================================
// task-4.2 / task-4.3 — EndpointPool::erase guards. The guard is an
// UNCONDITIONAL throw (std::logic_error), never an assert, so it survives
// NDEBUG — a use-after-free guard must be present in the shipped Release build.
// Two guarded conditions: (a) a handle not present in the pool (task-4.2), and
// (b) a handle that is still in use (task-4.3, the one previously-unguarded
// erase path). Driven directly through the befriended seam.
// =========================================================================
TEST_CASE("task-4.2/4.3: EndpointPool::erase throws on an absent or in-use handle",
          "[jsonrpc][pool][phase4]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  cfg.maxConnectionsPerEndpoint = 3;
  JsonRpcClient client(svc, pool, cfg);
  const std::string ep = "http://unit.test/rpc";

  // (b) in-use guard: hold a lease so its connection is in use, then try to
  // erase that exact handle.
  {
    auto lease = JsonRpcClientTestAccess::acquire(client, ep);
    auto handle = JsonRpcClientTestAccess::firstHandle(client, ep);
    REQUIRE(handle != nullptr);
    REQUIRE(handle->inUse() == true);
    REQUIRE_THROWS_AS(JsonRpcClientTestAccess::eraseHandle(client, ep, handle), std::logic_error);
    // The leased connection must still be present after the refused erase.
    REQUIRE(JsonRpcClientTestAccess::snapshotPools(client).at(0).connections.size() == 1);
  }

  // (a) absent guard: a connection that was never inserted into ep's pool.
  auto bogus = std::make_shared<PooledConnection>(std::make_unique<iora::network::HttpClient>());
  REQUIRE_THROWS_AS(JsonRpcClientTestAccess::eraseHandle(client, ep, bogus), std::logic_error);
}

// =========================================================================
// task-4.1c — CR-1c composite: a ConnectionLease releases cleanly even when its
// pool has been removed from _pools while the lease was live. The public API
// cannot reach this (a live lease keeps its connection in-use, so purge/evict
// can never empty and drop the pool), so it is driven at the detail:: layer via
// the seam: detach the pool from the map, keep it alive, then destroy the lease.
// The lease's shared_ptr<Impl>/<EndpointPool>/<PooledConnection> keep every
// object it touches alive, so releaseConnection_ does markFree()+touch() on
// still-owned state — well-defined, no UAF (this is the ASan detector for CR-1c).
// =========================================================================
TEST_CASE("task-4.1c CR-1c: a lease releases cleanly into a pool erased from the map",
          "[jsonrpc][pool][phase4]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  cfg.maxConnectionsPerEndpoint = 3;
  JsonRpcClient client(svc, pool, cfg);
  const std::string ep = "http://unit.test/rpc";

  std::shared_ptr<iora::modules::connectors::detail::EndpointPool> detached;
  {
    auto lease = std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, ep));
    const auto id = JsonRpcClientTestAccess::connectionIdOf(client, *lease);
    REQUIRE(id != 0);

    // Detach ep's pool from the map while the lease is still live.
    detached = JsonRpcClientTestAccess::detachPool(client, ep);
    REQUIRE(detached != nullptr);
    REQUIRE(JsonRpcClientTestAccess::poolConnCount(client, detached) == 1);
    REQUIRE(JsonRpcClientTestAccess::firstConnInUse(client, detached) == true);
    REQUIRE(JsonRpcClientTestAccess::snapshotPools(client).empty()); // gone from the map

    // Release the lease: releaseConnection_ runs against the detached-but-alive
    // pool and connection. Must not crash / read freed memory.
    lease.reset();
  }

  // The connection the detached pool still owns was marked free by the release.
  REQUIRE(JsonRpcClientTestAccess::poolConnCount(client, detached) == 1);
  REQUIRE(JsonRpcClientTestAccess::firstConnInUse(client, detached) == false);
}

// =========================================================================
// task-4.1b (cpp17 R#7 regression) — an idle pool keyed by an EMPTY-STRING
// endpoint must be a valid LRU pool-eviction candidate. The old
// bestKey.empty() sentinel in evictOneIdlePoolLruLocked_ would have skipped it;
// the iterator sentinel does not. Driven via the maxEndpointPools cap, which
// triggers idle-pool LRU eviction when a new endpoint needs a pool.
// =========================================================================
TEST_CASE("task-4.1b: an idle pool keyed by the empty-string endpoint is LRU-evictable",
          "[jsonrpc][pool][phase4]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  cfg.maxEndpointPools = 1; // one pool at a time -> a second endpoint forces eviction
  JsonRpcClient client(svc, pool, cfg);

  // Create and free a connection on the empty-string endpoint -> idle pool "".
  {
    auto l = JsonRpcClientTestAccess::acquire(client, "");
    (void)l;
  }
  {
    auto snap = JsonRpcClientTestAccess::snapshotPools(client);
    REQUIRE(snap.size() == 1);
    REQUIRE(snap[0].poolKey.empty()); // the "" pool exists and is idle
  }

  // Acquire on a different endpoint: with maxEndpointPools == 1 the only idle
  // pool ("") is the LRU eviction candidate. A bestKey.empty() sentinel would
  // have refused to evict it and the "" pool would leak.
  {
    auto l2 = JsonRpcClientTestAccess::acquire(client, "http://unit.test/other");
    (void)l2;
    auto snap = JsonRpcClientTestAccess::snapshotPools(client);
    REQUIRE(snap.size() == 1);
    for (const auto &ps : snap)
    {
      REQUIRE(ps.poolKey != ""); // the empty-string pool was evicted
    }
  }
}

// =========================================================================
// task-4.1b — concurrent throw path vs whole-pool eviction. One thread drives
// acquire_ to the PoolExhaustedError throw (per-endpoint cap reached, its one
// slot leased) in a tight loop — the path where the mutex is released by
// unwinding rather than an explicit unlock(), and where the pre-lock `evicted`
// bins and the `pool` local destruct after the unlock. Concurrently another
// thread creates, frees and purges idle connections on other endpoints, so
// whole-pool eviction (dropping HttpClients) runs against the thrower. Asserts
// every capped acquire threw, none spuriously succeeded, and neither thread
// deadlocked. Runs clean under TSan.
// =========================================================================
TEST_CASE("task-4.1b: concurrent PoolExhaustedError throw races whole-pool eviction",
          "[jsonrpc][pool][phase4]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  cfg.maxConnectionsPerEndpoint = 1; // one slot per endpoint -> deterministic throw
  cfg.globalMaxConnections = 0;      // unlimited: eviction not forced by global cap
  cfg.idleTimeout = std::chrono::milliseconds(5);
  JsonRpcClient client(svc, pool, cfg);

  const std::string epFull = "http://unit.test/full";
  const std::string ev[3] = {"http://unit.test/ev0", "http://unit.test/ev1",
                             "http://unit.test/ev2"};

  // Hold epFull's single slot for the whole test, so acquire(epFull) always
  // hits the per-endpoint cap and throws.
  auto held = JsonRpcClientTestAccess::acquire(client, epFull);

  constexpr int kThrows = 100;
  std::atomic<int> threw{0};
  std::atomic<int> unexpected{0};
  std::atomic<bool> evictorDone{false};

  std::thread thrower(
    [&]()
    {
      for (int i = 0; i < kThrows; ++i)
      {
        try
        {
          auto l = JsonRpcClientTestAccess::acquire(client, epFull);
          (void)l;
          unexpected.fetch_add(1); // must never succeed while the slot is leased
        }
        catch (const PoolExhaustedError &)
        {
          threw.fetch_add(1);
        }
        catch (...)
        {
          unexpected.fetch_add(1);
        }
      }
    });

  // ts L-1: wrapped, like its sibling `thrower` and the phase-4 `live` thread.
  // An exception escaping a std::thread function is std::terminate -> SIGABRT ->
  // (on this host) the piped core handler -> a multi-minute ctest TIMEOUT that
  // masks whatever actually broke. No throw is expected on this configuration
  // (distinct endpoints, cap 1 each, unlimited global cap, a stub factory that
  // cannot throw), but the file's own rule should not be applied selectively.
  std::atomic<bool> evictorThrew{false};
  std::thread evictor(
    [&]()
    {
      try
      {
        for (int cycle = 0; cycle < 25; ++cycle)
        {
          {
            std::vector<std::unique_ptr<ConnectionLease>> leases;
            for (const auto &e : ev)
            {
              leases.push_back(
                std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, e)));
            }
          } // freed -> three idle connections in three pools
          std::this_thread::sleep_for(std::chrono::milliseconds(10)); // > idleTimeout
          client.purgeIdle(); // whole-pool eviction, dropping HttpClients
        }
        evictorDone.store(true);
      }
      catch (...)
      {
        evictorThrew.store(true);
      }
    });

  thrower.join();
  evictor.join();

  REQUIRE(threw.load() == kThrows);
  REQUIRE(unexpected.load() == 0);
  REQUIRE(evictorThrew.load() == false);
  REQUIRE(evictorDone.load() == true);
}

// =========================================================================
// PHASE 5 — pool lifetime under eviction (CR-2) and counter integrity (H-2).
// tasks 5.1 (allIdle size()>0 + Option-A empty-pool retire), 5.2 (exact
// _totalConnections via MANDATORY per-mutation deltas + accurate
// connectionsEvicted), 5.3 (maxEndpointPools enforcement). See the phase-5
// tasks and phase5_step0_round1/2/3_disposition in tracker 2026-07-26-2.
// =========================================================================

// task-5.1 — CR-2, rewritten from the retired ASan-UAF repro into a DETACHMENT-
// observing test driven against the LIVE latched fixture (a refusing endpoint
// makes call() always throw, so a "successful call() that recovers in place" is
// unreachable — step-0 round-1 H1). The CR-2 ladder: a connection is created,
// used and left idle; it expires; the next call's tryAcquireFree erases it.
// FIXED, the counter is decremented (task-5.2) so underGlobalCap is true and
// acquire_ recreates on the SAME pool, still in _pools. PRE-FIX, the counter
// drifted, underGlobalCap was false, and evictOneIdlePoolLruLocked_ retired the
// caller's own now-empty pool (allIdle() vacuously true) while createAndAcquire
// populated it — an orphan snapshotPools can no longer see.
// =========================================================================
TEST_CASE("task-5.1 CR-2: acquire_ recovers an idle-expired pool in place, not by detaching it",
          "[jsonrpc][pool][cr2]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));

  const std::uint16_t serverPort = 18154;
  LatchedHttpServer server(serverPort);
  server.release(); // one-shot OPEN: every request passes straight through

  Config cfg; // real factory -> the client talks to the live fixture
  cfg.globalMaxConnections = 1;      // the CR-2 ladder gate after idle expiry
  cfg.maxConnectionsPerEndpoint = 8;
  cfg.idleTimeout = std::chrono::milliseconds(200);
  cfg.maxRetries = 0;
  JsonRpcClient client(svc, pool, cfg);
  const std::string ep = "http://127.0.0.1:" + std::to_string(serverPort) + "/rpc";

  // 1) First call succeeds -> one connection created, used and returned idle.
  REQUIRE(client.call(ep, "ping").is_object());
  {
    const auto snap = JsonRpcClientTestAccess::snapshotPools(client);
    REQUIRE(snap.size() == 1);
    REQUIRE(snap[0].poolKey == ep);
    REQUIRE(snap[0].connections.size() == 1);
    REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 1);
  }

  // 2) Let the pooled connection expire past idleTimeout.
  std::this_thread::sleep_for(std::chrono::milliseconds(260));

  // 3) The CR-2 ladder: tryAcquireFree erases the expired connection; the fix
  //    recreates on the same, still-registered pool.
  REQUIRE(client.call(ep, "ping").is_object());

  // 4) DETACHMENT DISCRIMINATOR: the recovered connection lives in a pool STILL
  //    in _pools. Pre-fix this snapshot is EMPTY (the ep pool was retired).
  std::uintptr_t recoveredId = 0;
  {
    const auto snap = JsonRpcClientTestAccess::snapshotPools(client);
    REQUIRE(snap.size() == 1);
    REQUIRE(snap[0].poolKey == ep);
    REQUIRE(snap[0].connections.size() == 1);
    recoveredId = snap[0].connections[0].connectionId;
  }
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 1);
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));

  // 5) A further call REUSES that connection rather than building a duplicate.
  REQUIRE(client.call(ep, "ping").is_object());
  {
    const auto snap = JsonRpcClientTestAccess::snapshotPools(client);
    REQUIRE(snap.size() == 1);
    REQUIRE(snap[0].poolKey == ep);
    REQUIRE(snap[0].connections.size() == 1);
    REQUIRE(snap[0].connections[0].connectionId == recoveredId);
  }

  // MUTATION (run by reverting production; must turn this RED): revert task-5.2's
  // `_totalConnections -= reclaimed` -> H-2 drift returns, so at step 3
  // underGlobalCap stays false, acquire_ reaches its PoolExhaustedError throw, the
  // Option-A retire (task-5.1) drops the now-empty ep pool, the call throws, and
  // step 4's snapshot is empty. (With allIdle() size()>0 present the empty pool is
  // no longer an eviction candidate, so the pool leaves _pools via the Option-A
  // retire at the throw, not by evictOneIdlePoolLruLocked_ "detaching" it.)
  // Reverting task-5.1's allIdle() size()>0 ALONE is a no-op here (5.2's exact
  // counter makes underGlobalCap true before the eviction site) — the Option-A
  // case below drives that mutation.
}

// task-5.2 — _totalConnections stays EXACT across an idle-expiry churn, and
// connectionsEvicted counts idle-expiry evictions (DP-2). The seam-driven
// discriminator is totalConnections() == recalcTotal(), not "no spurious
// PoolExhaustedError" (which self-heals — step-0 round-1 M-A).
// =========================================================================
TEST_CASE("task-5.2: idle-expiry churn keeps _totalConnections exact and counts connectionsEvicted",
          "[jsonrpc][pool][phase5]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  cfg.globalMaxConnections = 4;
  cfg.maxConnectionsPerEndpoint = 4;
  cfg.idleTimeout = std::chrono::milliseconds(100);
  JsonRpcClient client(svc, pool, cfg);
  const std::string ep = "http://unit.test/counter";

  // Two idle connections on ep.
  {
    auto a = JsonRpcClientTestAccess::acquire(client, ep);
    auto b = JsonRpcClientTestAccess::acquire(client, ep);
    (void)a;
    (void)b;
  }
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 2);
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));
  const std::uint64_t evictedBefore = client.getStats().connectionsEvicted;

  // Expire both, then acquire once: tryAcquireFree erases BOTH (counter -= 2) and
  // one fresh connection is created -> net 1, exact.
  std::this_thread::sleep_for(std::chrono::milliseconds(130));
  {
    auto c = JsonRpcClientTestAccess::acquire(client, ep);
    (void)c;
    REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 1);
    REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
            JsonRpcClientTestAccess::recalcTotal(client));
  }
  // connectionsEvicted increased by EXACTLY the two idle-expired connections.
  REQUIRE(client.getStats().connectionsEvicted == evictedBefore + 2);

  // A churn that evicts NOTHING must not bump connectionsEvicted: the fresh
  // connection is still within idleTimeout, so the next acquire reuses it.
  const std::uint64_t evictedMid = client.getStats().connectionsEvicted;
  {
    auto d = JsonRpcClientTestAccess::acquire(client, ep); // reuse, no eviction
    (void)d;
  }
  REQUIRE(client.getStats().connectionsEvicted == evictedMid);
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));

  // MUTATION: remove the tryAcquireFree decrement -> the in-lock tripwire assert
  // fires in a Debug build (the entry assert of the reuse acquire above, and the
  // reuse/create exit asserts).
}

// task-5.2 (DP-2) — evicting an idle LRU POOL counts ALL its connections in
// connectionsEvicted (read size() BEFORE retirePoolLocked_ moves the pool out).
// =========================================================================
TEST_CASE("task-5.2 DP-2: LRU whole-pool eviction counts its connections in connectionsEvicted",
          "[jsonrpc][pool][phase5]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  cfg.maxEndpointPools = 1;         // a second endpoint forces whole-pool eviction
  cfg.maxConnectionsPerEndpoint = 4;
  JsonRpcClient client(svc, pool, cfg);

  const std::string epA = "http://unit.test/A";
  {
    auto a1 = JsonRpcClientTestAccess::acquire(client, epA);
    auto a2 = JsonRpcClientTestAccess::acquire(client, epA);
    (void)a1;
    (void)a2;
  } // pool A: two IDLE connections
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 2);
  const std::uint64_t evictedBefore = client.getStats().connectionsEvicted;

  // A distinct endpoint B: maxEndpointPools==1 evicts idle pool A (size 2).
  {
    auto b = JsonRpcClientTestAccess::acquire(client, "http://unit.test/B");
    (void)b;
  }
  REQUIRE(client.getStats().connectionsEvicted == evictedBefore + 2);
  {
    const auto snap = JsonRpcClientTestAccess::snapshotPools(client);
    REQUIRE(snap.size() == 1);
    REQUIRE(snap[0].poolKey == "http://unit.test/B");
  }
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));
}

// task-5.2 (DP-2) — evicting a SINGLE idle LRU connection (tryEvictOneIdleConn)
// counts exactly one in connectionsEvicted.
// =========================================================================
TEST_CASE("task-5.2 DP-2: single idle-connection LRU eviction counts one in connectionsEvicted",
          "[jsonrpc][pool][phase5]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  cfg.globalMaxConnections = 2;         // saturating forces cross-pool idle-conn eviction
  cfg.maxConnectionsPerEndpoint = 2;
  JsonRpcClient client(svc, pool, cfg);

  // One IDLE connection on A (evictable), one IN-USE connection on B (held).
  {
    auto a = JsonRpcClientTestAccess::acquire(client, "http://unit.test/A");
    (void)a;
  }
  auto bHold = std::make_unique<ConnectionLease>(
    JsonRpcClientTestAccess::acquire(client, "http://unit.test/B"));
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 2); // global cap saturated
  const std::uint64_t evictedBefore = client.getStats().connectionsEvicted;

  // A second connection on B: per-endpoint cap allows it, global cap is full, so
  // acquire_ evicts the single LRU idle connection (A's) to make room.
  {
    auto b2 = JsonRpcClientTestAccess::acquire(client, "http://unit.test/B");
    (void)b2;
  }
  REQUIRE(client.getStats().connectionsEvicted == evictedBefore + 1);
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));
  bHold.reset();
}

// task-5.2 (DP-2) — the FOURTH connectionsEvicted path: purgeIdle. The counter
// must increase by exactly the number of idle-expired connections purgeIdle
// evicts (arch doc line 156 enumerates purgeIdle among the DP-2 paths).
// =========================================================================
TEST_CASE("task-5.2 DP-2: purgeIdle counts every idle-expired connection in connectionsEvicted",
          "[jsonrpc][pool][phase5]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  cfg.maxConnectionsPerEndpoint = 4;
  cfg.idleTimeout = std::chrono::milliseconds(40);
  JsonRpcClient client(svc, pool, cfg);

  // Three idle connections across two endpoints.
  {
    auto a1 = JsonRpcClientTestAccess::acquire(client, "http://unit.test/A");
    auto a2 = JsonRpcClientTestAccess::acquire(client, "http://unit.test/A");
    auto b1 = JsonRpcClientTestAccess::acquire(client, "http://unit.test/B");
    (void)a1;
    (void)a2;
    (void)b1;
  }
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 3);
  const std::uint64_t evictedBefore = client.getStats().connectionsEvicted;

  // Expire all, then purge: connectionsEvicted increases by exactly 3.
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  REQUIRE(client.purgeIdle() == 3);
  REQUIRE(client.getStats().connectionsEvicted == evictedBefore + 3);
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 0);
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));
}

// task-5.3 — maxEndpointPools==0 means UNLIMITED: a default-configured client
// never throws on distinct endpoints (step-0: the `> 0 &&` conjunct).
// =========================================================================
TEST_CASE("task-5.3: maxEndpointPools==0 is unlimited (default config never refuses)",
          "[jsonrpc][pool][phase5]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  REQUIRE(cfg.maxEndpointPools == 0); // the default
  JsonRpcClient client(svc, pool, cfg);

  std::vector<std::unique_ptr<ConnectionLease>> leases;
  for (int i = 0; i < 5; ++i)
  {
    REQUIRE_NOTHROW(leases.push_back(std::make_unique<ConnectionLease>(
      JsonRpcClientTestAccess::acquire(client, "http://unit.test/e" + std::to_string(i)))));
  }
  REQUIRE(JsonRpcClientTestAccess::snapshotPools(client).size() == 5);

  // MUTATION: drop the `> 0 &&` conjunct -> the first acquire evaluates
  // `_pools.size()(0) >= maxEndpointPools(0)`, finds nothing to evict and throws.
}

// task-5.3 — a NON-ZERO cap enforces: with every pool in use it refuses; with an
// idle pool it evicts to admit the new endpoint.
// =========================================================================
TEST_CASE("task-5.3: a non-zero maxEndpointPools enforces the cap (refuse / evict-and-admit)",
          "[jsonrpc][pool][phase5]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));

  SECTION("all pools in use -> a new endpoint is refused")
  {
    Config cfg = stubFactoryConfig();
    cfg.maxEndpointPools = 2;
    cfg.maxConnectionsPerEndpoint = 1;
    JsonRpcClient client(svc, pool, cfg);

    auto l0 = std::make_unique<ConnectionLease>(
      JsonRpcClientTestAccess::acquire(client, "http://unit.test/p0"));
    auto l1 = std::make_unique<ConnectionLease>(
      JsonRpcClientTestAccess::acquire(client, "http://unit.test/p1"));

    REQUIRE_THROWS_AS(JsonRpcClientTestAccess::acquire(client, "http://unit.test/p2"),
                      PoolExhaustedError);
    REQUIRE(JsonRpcClientTestAccess::snapshotPools(client).size() == 2);
    REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
            JsonRpcClientTestAccess::recalcTotal(client));
  }

  SECTION("an idle pool is evicted to admit the new endpoint")
  {
    Config cfg = stubFactoryConfig();
    cfg.maxEndpointPools = 1;
    JsonRpcClient client(svc, pool, cfg);

    {
      auto l = JsonRpcClientTestAccess::acquire(client, "http://unit.test/idle");
      (void)l;
    } // idle pool
    REQUIRE_NOTHROW(JsonRpcClientTestAccess::acquire(client, "http://unit.test/new"));
    const auto snap = JsonRpcClientTestAccess::snapshotPools(client);
    REQUIRE(snap.size() == 1);
    REQUIRE(snap[0].poolKey == "http://unit.test/new");
  }
}

// task-5.1 (Option A) — a GLOBAL-cap throw must retire the empty pool it would
// otherwise strand, so a later DISTINCT endpoint is not spuriously refused by a
// lingering empty pool occupying a maxEndpointPools slot. This case FAILS against
// 5.1-without-Option-A (step-0 round-1 DP-3, round-2 L-2).
// =========================================================================
TEST_CASE("task-5.1 Option A: a global-cap throw retires the empty pool (no spurious later refusal)",
          "[jsonrpc][pool][phase5]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  cfg.globalMaxConnections = 2;
  cfg.maxEndpointPools = 2;
  cfg.maxConnectionsPerEndpoint = 2;
  JsonRpcClient client(svc, pool, cfg);

  const std::string epA = "http://unit.test/A";
  // A holds two IN-USE connections: pool A is never all-idle (not a whole-pool
  // eviction candidate) and the global cap (2) is saturated.
  auto a1 = std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, epA));
  auto a2 = std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, epA));
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 2);

  // A new endpoint B saturates the global cap with no idle connection or pool to
  // evict -> acquire_ reaches its PoolExhaustedError throw. Option A retires B's
  // now-empty pool AT THE THROW; without it, B lingers in _pools.
  REQUIRE_THROWS_AS(JsonRpcClientTestAccess::acquire(client, "http://unit.test/B"),
                    PoolExhaustedError);
  {
    const auto snap = JsonRpcClientTestAccess::snapshotPools(client);
    REQUIRE(snap.size() == 1); // only A; B was retired at the throw
    REQUIRE(snap[0].poolKey == epA);
    for (const auto &ps : snap)
    {
      REQUIRE(ps.connections.size() > 0); // no zero-size pool persists
    }
  }
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));

  // Free ONE of A's connections: A now has one in-use + one idle connection, so A
  // is still NOT all-idle (no whole-pool eviction candidate) but has an idle
  // CONNECTION acquire_'s idle-connection eviction can reclaim.
  a2.reset();

  // A distinct endpoint C must NOT be spuriously refused: with B retired the
  // maxEndpointPools gate is below the cap, so acquire_ proceeds to reclaim A's
  // idle connection and create C. Without Option A the lingering empty B pool
  // fills the last slot, the whole-pool eviction finds nothing all-idle, and C
  // throws spuriously.
  REQUIRE_NOTHROW(JsonRpcClientTestAccess::acquire(client, "http://unit.test/C"));

  a1.reset();
}

// =========================================================================
// task-1.6 — the CR-3 repro, FLIPPED BY PHASE 6 (task-6.1b). It used to be a
// HANG repro: makeHttpClient_ ran the configurer on a std::async thread while
// the caller held _mutex inside wait_for(30s); the configurer's purgeIdle()
// blocked on _mutex, wait_for threw, and ~future blocked forever — a permanent
// cycle, registered DISABLED because a hang cannot be asserted from inside the
// process it wedges.
//
// Phase 6 builds the client OUTSIDE _mutex and deletes the std::async wrapper,
// so the repro is now a GREEN regression guard living in the phase-6 block:
// see "task-6.4a(c): a re-entrant configurer completes and the pool survives
// it", tagged [cr3], which drives the SAME same-endpoint re-entrancy (cpp17
// C-2) plus the re-entrant same-endpoint acquire, with a bounded wait — the
// ctest TIMEOUT — that FAILS if the deadlock ever returns.
// =========================================================================

// =========================================================================
// PHASE 3 — blocking quiesce (CR-4 / HD-1), SHAPE-B. These exercise the
// task-3.1 primitive end to end: the quiesce snapshot seam (task-1.2b), gate
// refusal on every counted channel (task-3.4), the destructor's cancel+wait
// (task-3.5), and the typed-future (H-1) plumbing. Self-destruct detection
// (task-3.2) cannot live here — a std::terminate would take down the shared
// Catch2 process — so it is a standalone binary
// (iora_test_jsonrpc_quiesce_selfdestruct.cpp). The exhaustive race matrix is
// phase 6 (task-6.4); these prove the mechanism.
// =========================================================================

// task-1.2b / task-3.1(a) — the quiesce snapshot observes the EMBEDDED
// {inFlight, closing, owners} state. A fresh client is open and idle.
TEST_CASE("phase3: quiesce snapshot reports embedded {inFlight,closing,owners}",
          "[jsonrpc][pool][phase3]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  JsonRpcClient client(svc, pool, stubFactoryConfig());

  const auto q = JsonRpcClientTestAccess::quiesceSnapshot(client);
  REQUIRE(q.inFlight == 0);
  REQUIRE(q.closing == false);
  REQUIRE(q.owners.empty());
}

// task-3.5 — with zero work in flight the destructor returns promptly; it must
// not block when _inFlight is already 0.
TEST_CASE("phase3: destructor with zero in-flight returns promptly",
          "[jsonrpc][pool][phase3]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  const auto t0 = std::chrono::steady_clock::now();
  {
    JsonRpcClient client(svc, pool, stubFactoryConfig());
  } // ~JsonRpcClient -> quiesce()
  REQUIRE((std::chrono::steady_clock::now() - t0) < std::chrono::seconds(2));
}

// task-3.4 / task-6.4(m) — gate refusal on EVERY counted channel once closing is
// latched. Sync channels throw ClientShutdownError; the callback async routes to
// onError (no throw); both future overloads set_exception; purgeIdle returns 0;
// resetStats no-ops. After every refusal _inFlight is back to 0 — never
// incremented, never underflowed to SIZE_MAX. Refusal runs entirely in the
// calling thread (no worker), so this is deterministic without a server.
TEST_CASE("phase3: every counted channel refuses after closing is latched",
          "[jsonrpc][pool][phase3]")
{
  using iora::modules::connectors::ClientShutdownError;
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  JsonRpcClient client(svc, pool, stubFactoryConfig());
  const std::string ep = "http://unit.test/rpc";

  JsonRpcClientTestAccess::latchClosing(client);
  REQUIRE(JsonRpcClientTestAccess::quiesceSnapshot(client).closing == true);

  // Sync channels throw ClientShutdownError.
  REQUIRE_THROWS_AS(client.call(ep, "ping"), ClientShutdownError);
  REQUIRE_THROWS_AS(client.notify(ep, "ping"), ClientShutdownError);
  {
    std::vector<iora::modules::connectors::BatchItem> items;
    items.emplace_back("ping", iora::parsers::Json::object(), std::uint64_t{1});
    REQUIRE_THROWS_AS(client.callBatch(ep, items), ClientShutdownError);
  }

  // Callback async routes to onError, does not throw.
  {
    std::atomic<bool> errCalled{false};
    std::atomic<bool> wasShutdown{false};
    client.callAsync(ep, "ping", iora::parsers::Json::object(), {}, [](iora::parsers::Json) {},
                     shutdownErrorProbe(errCalled, wasShutdown));
    REQUIRE(errCalled.load() == true);
    REQUIRE(wasShutdown.load() == true);
  }

  // Future overloads set_exception on the returned future.
  {
    std::future<iora::parsers::Json> f = client.callAsync(ep, "ping");
    REQUIRE(f.wait_for(std::chrono::seconds(1)) == std::future_status::ready);
    REQUIRE_THROWS_AS(f.get(), ClientShutdownError);
  }
  {
    std::vector<iora::modules::connectors::BatchItem> items;
    items.emplace_back("ping", iora::parsers::Json::object(), std::uint64_t{1});
    std::future<std::vector<iora::parsers::Json>> f = client.callBatchAsync(ep, items);
    REQUIRE(f.wait_for(std::chrono::seconds(1)) == std::future_status::ready);
    REQUIRE_THROWS_AS(f.get(), ClientShutdownError);
  }

  // purgeIdle returns 0; resetStats no-ops — neither propagates.
  REQUIRE(client.purgeIdle() == 0);
  REQUIRE_NOTHROW(client.resetStats());

  // Every refused channel left _inFlight untouched: 0, never SIZE_MAX.
  REQUIRE(JsonRpcClientTestAccess::quiesceSnapshot(client).inFlight == 0);
}

// task-1.7 (CR-4 residual) / task-3.3 / task-3.5 — the destructor WAITS for a
// queued async task (state (h)): admitted at call-time, counted, honored (it is
// not gate-refused mid-queue), and waited for. When the worker frees, the
// queued token runs and callCore_->acquire_ sees closing and throws
// ClientShutdownError, delivered via onError; the destructor then returns.
TEST_CASE("phase3 / CR-4 fixed: destructor waits for a queued async task",
          "[jsonrpc][pool][cr4][phase3]")
{
  using iora::modules::connectors::ClientShutdownError;
  auto &svc = testService();

  // initial==max==1 so the async task is genuinely QUEUED behind the blocker.
  iora::core::ThreadPool pool(/*initial*/ 1, /*max*/ 1, std::chrono::seconds(1));
  auto client = std::make_unique<JsonRpcClient>(svc, pool, stubFactoryConfig());

  BlockedWorker blocker(pool);
  REQUIRE(blocker.waitUntilRunning());

  std::atomic<bool> errCalled{false};
  std::atomic<bool> okCalled{false};
  std::atomic<bool> shutdownErr{false};
  client->callAsync("http://unit.test/rpc", "ping", iora::parsers::Json::object(), {},
                    [&](iora::parsers::Json) { okCalled.store(true); },
                    shutdownErrorProbe(errCalled, shutdownErr));

  // The queued token is counted at call-time.
  REQUIRE(JsonRpcClientTestAccess::quiesceSnapshot(*client).inFlight == 1);

  // Destroy on another thread: quiesce latches closing and blocks in STEP 3
  // waiting for _inFlight==0, which cannot complete until the worker frees.
  // The destroyer signals `entering` IMMEDIATELY BEFORE ~JsonRpcClient so the
  // negative assertion below cannot pass vacuously (ts M-5): without it, a
  // destroyer thread the OS simply never scheduled would leave destroyed==false
  // for a reason that has nothing to do with the in-flight wait, and the case
  // would go green against a destructor that does not wait at all.
  std::atomic<bool> destroyed{false};
  TestLatch entering;
  std::thread destroyer(
    [&]()
    {
      entering.signal();
      client.reset();
      destroyed.store(true);
    });

  // LOW-D: if a REQUIRE below throws, this guard still frees the worker (so the
  // destroyer's quiesce can finish) and joins it — idempotent with the normal
  // path, since BlockedWorker::release() is itself idempotent.
  JoinGuard joiner{destroyer, [&]() { blocker.release(); }};

  REQUIRE(entering.wait()); // the destructor is genuinely under way
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(destroyed.load() == false); // still blocked on the in-flight token

  blocker.release(); // free the worker -> the queued token runs and drains
  destroyer.join();

  REQUIRE(destroyed.load() == true);
  REQUIRE(errCalled.load() == true);
  REQUIRE(okCalled.load() == false);
  REQUIRE(shutdownErr.load() == true);
}

// task-3.5 CORE (task-6.4(s)) — the single regression test for the whole design:
// a synchronous call wedged against a silent (parked) server is unwound by the
// destructor's STEP-2 cancelInFlight() and STEP-3 wait, NOT by any timeout. The
// bound (< 3 s) sits well under the fixture's 5 s handler wait, so it is
// cancellation — not the handler bound — that frees the call.
TEST_CASE("phase3: destructor cancels and waits for an in-flight synchronous call",
          "[jsonrpc][pool][phase3][latched]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
  const std::uint16_t serverPort = 18151;
  LatchedHttpServer server(serverPort); // parks the handler until released

  Config cfg; // real factory so the client actually connects to the fixture
  cfg.maxRetries = 0;
  auto client = std::make_unique<JsonRpcClient>(svc, pool, cfg);
  const std::string ep = "http://127.0.0.1:" + std::to_string(serverPort) + "/rpc";

  std::atomic<bool> callReturned{false};
  std::exception_ptr callErr;
  // Capture a STABLE raw pointer (see the retry-backoff case): the caller thread
  // must not read the `client` unique_ptr variable that main mutates via
  // client.reset() below, or that read races the reset. `raw` stays valid for
  // the whole call — the blocking-quiesce destructor waits for it to unwind.
  JsonRpcClient *const raw = client.get();
  std::thread caller(
    [&, raw]()
    {
      try
      {
        raw->call(ep, "ping");
      }
      catch (...)
      {
        callErr = std::current_exception();
      }
      callReturned.store(true);
    });

  // LOW-D: on a failing REQUIRE, reset the client (cancel unwinds the parked
  // call) and join the caller. client.reset() is idempotent on a unique_ptr, so
  // this composes with the normal path below.
  JoinGuard joiner{caller, [&]() { client.reset(); }};

  // The request reached the server; the handler is parked and the client is
  // blocked in receiveSync waiting for the (never-sent) response.
  REQUIRE(server.waitForArrival(1));
  REQUIRE(callReturned.load() == false);

  const auto t0 = std::chrono::steady_clock::now();
  client.reset(); // ~JsonRpcClient -> quiesce: cancel unwinds the parked call
  const auto elapsed = std::chrono::steady_clock::now() - t0;

  caller.join();
  REQUIRE(callReturned.load() == true);
  REQUIRE(callErr); // the in-flight call was unwound with an exception
  REQUIRE(elapsed < std::chrono::seconds(3));
}

// task-3.1(d) / round-3 H-1 — the typed-future overloads plumb a std::promise
// through the token: set_value on success, set_exception on failure, for both
// callAsync(future) (Json) and callBatchAsync (vector<Json>). Its very
// compilation is the H-1 adjudication (a void runBody cannot type-check to
// future<Json>); this exercises both channels at runtime.
TEST_CASE("phase3: typed-future overloads deliver value and exception (H-1)",
          "[jsonrpc][pool][phase3][latched]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
  const std::uint16_t serverPort = 18152;
  LatchedHttpServer server(serverPort);
  server.release(); // pass requests straight through

  Config cfg;
  cfg.maxRetries = 0;
  JsonRpcClient client(svc, pool, cfg);
  const std::string ok = "http://127.0.0.1:" + std::to_string(serverPort) + "/rpc";

  // set_value: callAsync(future) resolves with the JSON-RPC result ({}).
  {
    std::future<iora::parsers::Json> f = client.callAsync(ok, "ping");
    REQUIRE(f.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    REQUIRE(f.get().is_object());
  }

  // set_exception: an unroutable endpoint makes callCore_ throw; the future
  // carries the exception.
  {
    std::future<iora::parsers::Json> f = client.callAsync("http://127.0.0.1:1/rpc", "ping");
    REQUIRE(f.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    REQUIRE_THROWS(f.get());
  }

  // callBatchAsync (vector<Json>) — the SAME InFlightToken<vector<Json>> promise
  // plumbing, proven via set_exception (the shared fixture returns a single
  // object, not a batch array, so its set_value path needs a batch-speaking
  // server — deferred to the deterministic phase-9 fixtures, task-9.1). An
  // unroutable endpoint makes callBatchCore_ throw; the future carries it.
  {
    std::vector<iora::modules::connectors::BatchItem> items;
    items.emplace_back("ping", iora::parsers::Json::object(), std::uint64_t{1});
    std::future<std::vector<iora::parsers::Json>> f =
      client.callBatchAsync("http://127.0.0.1:1/rpc", items);
    REQUIRE(f.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    REQUIRE_THROWS(f.get());
  }
}

// cpp17 L-3 — the callback-overload callAsync HAPPY PATH: enqueue succeeds, the
// worker runs the RPC and delivers a real result to onSuccess (and onError does
// NOT fire). This is the overload that carries the TS-5 caller-side OwnerScope,
// so a happy-path assertion guards it against future interference.
TEST_CASE("phase3: callback callAsync delivers a result to onSuccess",
          "[jsonrpc][pool][phase3][latched]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
  const std::uint16_t serverPort = 18153;
  LatchedHttpServer server(serverPort);
  server.release(); // pass requests straight through

  Config cfg;
  cfg.maxRetries = 0;
  JsonRpcClient client(svc, pool, cfg);
  const std::string ep = "http://127.0.0.1:" + std::to_string(serverPort) + "/rpc";

  std::promise<void> done;
  std::future<void> doneF = done.get_future();
  std::atomic<bool> okCalled{false};
  std::atomic<bool> errCalled{false};
  bool resultIsObject = false;
  client.callAsync(ep, "ping", iora::parsers::Json::object(), {},
                   [&](iora::parsers::Json r)
                   {
                     resultIsObject = r.is_object();
                     okCalled.store(true);
                     done.set_value();
                   },
                   [&](std::exception_ptr)
                   {
                     errCalled.store(true);
                     done.set_value();
                   });

  REQUIRE(doneF.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
  REQUIRE(okCalled.load() == true);
  REQUIRE(errCalled.load() == false);
  REQUIRE(resultIsObject == true); // the JSON-RPC success "result" ({})
}

// task-3.4(b) — the ENQUEUE-FAILURE channel. With the pool's queue full,
// _threadPool.enqueue throws inside dispatchToken_; it must be routed through
// the SAME channel (callback onError / future set_exception) WITHOUT escaping
// the calling thread, and _inFlight must return to 0 after each (never SIZE_MAX).
TEST_CASE("phase3: enqueue failure routes through the token's channel, no throw to caller",
          "[jsonrpc][pool][phase3]")
{
  auto &svc = testService();

  // 1 worker + queue cap 1: occupy the worker, fill the single queue slot, then
  // every further enqueue throws "task queue is full".
  iora::core::ThreadPool pool(/*initial*/ 1, /*max*/ 1, std::chrono::seconds(1),
                              /*maxQueueSize*/ 1);
  JsonRpcClient client(svc, pool, stubFactoryConfig());
  const std::string ep = "http://unit.test/rpc";

  // BlockedWorker owns its latches through a shared_ptr the task captures by
  // value, so — unlike the promise/future shape this replaced — it needs no
  // "declare the gate before the pool" outlive ordering, and its destructor
  // releases the worker on any exit including a throwing REQUIRE.
  BlockedWorker blocker(pool);
  REQUIRE(blocker.waitUntilRunning());
  pool.enqueue([]() {}); // fills the one queue slot -> subsequent enqueues throw

  // Callback overload: enqueue throws -> onError fires, callAsync does not throw.
  {
    std::atomic<bool> errCalled{false};
    REQUIRE_NOTHROW(client.callAsync(ep, "ping", iora::parsers::Json::object(), {},
                                     [](iora::parsers::Json) {},
                                     [&errCalled](std::exception_ptr) { errCalled.store(true); }));
    REQUIRE(errCalled.load() == true);
    REQUIRE(JsonRpcClientTestAccess::quiesceSnapshot(client).inFlight == 0);
  }

  // Future overload: enqueue throws -> the future carries the exception; no throw.
  {
    std::future<iora::parsers::Json> f;
    REQUIRE_NOTHROW(f = client.callAsync(ep, "ping"));
    REQUIRE(f.wait_for(std::chrono::seconds(1)) == std::future_status::ready);
    REQUIRE_THROWS(f.get());
    REQUIRE(JsonRpcClientTestAccess::quiesceSnapshot(client).inFlight == 0);
  }

  // Batch future overload behaves identically.
  {
    std::vector<iora::modules::connectors::BatchItem> items;
    items.emplace_back("ping", iora::parsers::Json::object(), std::uint64_t{1});
    std::future<std::vector<iora::parsers::Json>> f;
    REQUIRE_NOTHROW(f = client.callBatchAsync(ep, items));
    REQUIRE(f.wait_for(std::chrono::seconds(1)) == std::future_status::ready);
    REQUIRE_THROWS(f.get());
    REQUIRE(JsonRpcClientTestAccess::quiesceSnapshot(client).inFlight == 0);
  }

  // ~BlockedWorker frees the occupied worker exactly once at scope exit.
}

// task-3.4(b) ORDERING (TS-6) — a client destroyed CONCURRENTLY with an
// enqueue-failure delivery must observe onError as already-completed before the
// destructor returns: the caller frame holds the counted token across the
// synchronous onError, so STEP-3 cannot see _inFlight==0 until onError returns.
TEST_CASE("phase3: onError completes before a concurrent destructor returns (enqueue-failure)",
          "[jsonrpc][pool][phase3]")
{
  auto &svc = testService();

  iora::core::ThreadPool pool(/*initial*/ 1, /*max*/ 1, std::chrono::seconds(1),
                              /*maxQueueSize*/ 1);
  auto client = std::make_unique<JsonRpcClient>(svc, pool, stubFactoryConfig());
  const std::string ep = "http://unit.test/rpc";

  BlockedWorker blocker(pool);
  REQUIRE(blocker.waitUntilRunning());
  pool.enqueue([]() {}); // fills the one queue slot -> the async enqueue throws

  // A monotonic sequence stamps two events atomically (TS-8): onError's
  // completion and the destructor's return. The ORDER of the two stamps — not
  // wall-clock — decides the test, so an OS deschedule cannot false-pass a
  // broken (non-waiting) destructor.
  std::atomic<int> seq{0};
  TestLatch onErrorStarted;
  TestLatch onErrorDone;
  std::atomic<int> onErrorSeq{0};

  // ts M-5: `destructing` is signalled by MAIN immediately before it enters
  // ~JsonRpcClient, and onError waits on it before stamping. That converts the
  // widening step from a blind sleep — which passes vacuously if the destructor
  // thread simply had not run yet — into a real happens-before: onError cannot
  // stamp until the destruction is under way, so the residual sleep only has to
  // cover the (bounded) STEP-1/2 prologue, not thread-start latency.
  TestLatch destructing;

  // Thread A: the callback-overload callAsync whose enqueue fails; its onError
  // runs synchronously on A. Capture a STABLE raw pointer so A never reads the
  // `client` unique_ptr variable that main mutates via client.reset() below.
  JsonRpcClient *const raw = client.get();
  std::thread callerA(
    [&, raw]()
    {
      raw->callAsync(ep, "ping", iora::parsers::Json::object(), {}, [](iora::parsers::Json) {},
                     [&](std::exception_ptr)
                     {
                       onErrorStarted.signal();
                       destructing.wait();
                       // Residual window so a BROKEN (non-waiting) destructor
                       // reliably stamps first. Correctness is decided by the
                       // seq order, never by this sleep.
                       std::this_thread::sleep_for(std::chrono::milliseconds(50));
                       onErrorSeq.store(++seq); // stamp: onError completed
                       onErrorDone.signal();
                     });
    });

  JoinGuard joiner{callerA,
                   [&]()
                   {
                     destructing.signal(); // never leave onError parked
                     blocker.release();
                   }};

  // Wait until A is inside onError (token counted, inFlight==1).
  REQUIRE(onErrorStarted.wait());

  // Destroy concurrently: quiesce STEP-3 must wait for A's onError to finish (the
  // token decrements only when A's callAsync returns).
  destructing.signal();
  client.reset();
  const int destructorReturnSeq = ++seq; // stamp: destructor returned

  // Ensure onErrorSeq is set before comparing (it is, on correct code, since the
  // destructor waited; on broken code we still must read the stamp it will set).
  REQUIRE(onErrorDone.wait());

  // onError completed BEFORE the destructor returned iff the destructor waited.
  // A broken destructor stamps its return first -> onErrorSeq > destructorReturnSeq.
  REQUIRE(onErrorSeq.load() != 0);
  REQUIRE(onErrorSeq.load() < destructorReturnSeq);

  // The `joiner` scope guard releases the blocker and joins callerA exactly once.
}

// task-3.5 / task-3.1(f) — the INTERRUPTIBLE retry backoff. A call retrying
// against a refusing endpoint parks in _quiesceCv.wait_for(delay, closing); the
// destructor's STEP-1 notify must cut that wait so the call unwinds far faster
// than the (long) backoff would otherwise allow. This is the regression guard
// for task-3.1 mutation (3) "revert the interruptible backoff to sleep_for".
TEST_CASE("phase3: destructor interrupts a call parked in retry backoff",
          "[jsonrpc][pool][phase3]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  cfg.maxRetries = 5;
  cfg.initialRetryDelay = std::chrono::milliseconds(2000); // long, so interruption is unmistakable
  cfg.retryBackoffMultiplier = 2.0;
  auto client = std::make_unique<JsonRpcClient>(svc, pool, cfg);
  const std::string ep = "http://127.0.0.1:1/rpc"; // connection refused -> retry loop

  std::atomic<bool> callReturned{false};
  std::exception_ptr callErr;
  // Capture a STABLE raw pointer, not the `client` unique_ptr itself: the caller
  // thread must not read the smart-pointer variable that the main thread mutates
  // via client.reset() below (that is a data race on `client` — TSan flags it).
  // `raw` stays valid for the whole call: the blocking-quiesce destructor does
  // not delete the object until this in-flight call has unwound.
  JsonRpcClient *const raw = client.get();
  std::thread caller(
    [&, raw]()
    {
      try
      {
        raw->call(ep, "ping");
      }
      catch (...)
      {
        callErr = std::current_exception();
      }
      callReturned.store(true);
    });

  // LOW-D: reset (cut the backoff) and join on a failing REQUIRE too; idempotent
  // with the normal path.
  JoinGuard joiner{caller, [&]() { client.reset(); }};

  // Let attempt 1 fail (refused, fast) so the call is parked in the 2000 ms backoff.
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  REQUIRE(callReturned.load() == false);

  const auto t0 = std::chrono::steady_clock::now();
  client.reset(); // STEP-1 notify must cut the backoff
  const auto elapsed = std::chrono::steady_clock::now() - t0;

  caller.join();
  REQUIRE(callReturned.load() == true);
  REQUIRE(callErr); // the parked call was unwound with an exception
  // Un-interrupted, the destructor would wait ~1700 ms for the first backoff to
  // time out; < 1 s proves STEP-1's notify cut the wait.
  REQUIRE(elapsed < std::chrono::seconds(1));
}

// =========================================================================
// PHASE 6 — construction outside the lock (CR-3). The user
// httpClientFactory/httpClientConfigurer run on the CALLING thread with _mutex
// RELEASED; a per-endpoint `pendingCreates` reservation holds the caller's
// capacity across that window and PINS the pool against every retire site
// (architecture designPrinciples #7 extended and #8).
//
// EVERY case below is LATCH-DRIVEN and deterministic — none is a bare stress
// loop (task-9.2) — and every one carries its OWN NAMED MUTATION written next
// to it: the specific guard to delete in jsonrpc_client.hpp to make that case
// fail. A case whose mutation does not flip it is not a test, it is decoration.
// =========================================================================

namespace
{

/// \brief A factory that PARKS inside phase-6's unlocked construction window,
/// but only for `parkEndpoint`: it signals `entered` (so the driving thread
/// knows the window is open) and then blocks on `release`. Any OTHER endpoint
/// is served immediately — that asymmetry is what lets case (a) prove a parked
/// creation no longer blocks an unrelated acquire.
/// \details The wait is bounded, so a regression that never releases the latch
/// still terminates. Both latches are captured BY REFERENCE, so every caller
/// must outlive the client (all do — the latches are declared before it).
std::function<std::unique_ptr<iora::network::HttpClient>(const std::string &)>
parkingFactory(std::string parkEndpoint, TestLatch &entered, TestLatch &release,
               std::chrono::milliseconds bound = std::chrono::seconds(5))
{
  return [&entered, &release, parkEndpoint, bound](const std::string &ep)
  {
    if (ep == parkEndpoint)
    {
      entered.signal();
      release.wait(bound);
    }
    return std::make_unique<iora::network::HttpClient>();
  };
}

/// \brief Outcome of an acquire_ run on a helper thread. Exceptions cannot
/// cross a std::thread boundary and Catch2's REQUIRE is not thread-safe, so the
/// worker records what happened and the MAIN thread asserts on it.
struct AcquireOutcome
{
  std::atomic<bool> done{false};
  std::atomic<bool> ok{false};
  std::atomic<bool> poolExhausted{false};
  std::atomic<bool> shutdown{false};
  std::atomic<bool> otherError{false};
};

/// \brief Run acquire_ for `ep` on this thread, recording the outcome. When
/// `hold` is non-null the resulting lease is stored there (so the caller can
/// keep the connection in use); otherwise it is released immediately.
void runAcquire(JsonRpcClient &client, const std::string &ep, AcquireOutcome &out,
                std::unique_ptr<ConnectionLease> *hold = nullptr)
{
  try
  {
    auto lease = JsonRpcClientTestAccess::acquire(client, ep);
    if (hold != nullptr)
    {
      *hold = std::make_unique<ConnectionLease>(std::move(lease));
    }
    out.ok.store(true);
  }
  catch (const PoolExhaustedError &)
  {
    out.poolExhausted.store(true);
  }
  catch (const iora::modules::connectors::ClientShutdownError &)
  {
    out.shutdown.store(true);
  }
  catch (...)
  {
    out.otherError.store(true);
  }
  out.done.store(true);
}

/// \brief The snapshot of `key`'s pool, or nullopt when no such pool is in
/// _pools. Distinguishing "absent" from "present but empty" matters: the
/// throw-path retire REMOVES the pool, so several cases assert absence.
std::optional<JsonRpcClientTestAccess::PoolSnapshot>
poolOf(const std::vector<JsonRpcClientTestAccess::PoolSnapshot> &snap, const std::string &key)
{
  for (const auto &ps : snap)
  {
    if (ps.poolKey == key)
    {
      return ps;
    }
  }
  return std::nullopt;
}

/// \brief The live snapshot of `key`'s pool, taken fresh from `client`. The
/// two-step "snapshot everything, then find one key" spelling appeared ten
/// times across the phase-6 cases; this is that spelling, once.
std::optional<JsonRpcClientTestAccess::PoolSnapshot> poolOf(JsonRpcClient &client,
                                                            const std::string &key)
{
  return poolOf(JsonRpcClientTestAccess::snapshotPools(client), key);
}

/// \brief Wait until `ep`'s pool exists and reports exactly `n` reservations.
/// \details The phase-6 window cases all need the same handshake: the parking
/// factory's `entered` latch says the USER CALLBACK is running, but the
/// reservation is taken slightly earlier and is only observable through the
/// seam, so each case then polls for it. Six copies of that poll collapse here.
bool waitUntilPending(JsonRpcClient &client, const std::string &ep, std::size_t n)
{
  return waitFor(
    [&]
    {
      const auto ps = poolOf(client, ep);
      return ps.has_value() && ps->pendingCreates == n;
    });
}

} // namespace

// =========================================================================
// task-6.3 — THE ROLLBACK TEST risk R-3 asked for. Round 1 found R-3's
// mitigation lived only in risks[] and was wired to no task, so nothing would
// build it. Both callback throw paths are covered, as DISTINCT cases: when the
// FACTORY throws no client exists yet, whereas when the CONFIGURER throws the
// HttpClient has already been constructed and must be destroyed — outside
// _mutex (T6-2) — rather than leaked.
//
// NAMED MUTATION (both cases): delete the catch block around the unlocked
// construction window in acquire_ (the task-6.1c rollback) and let the throw
// propagate straight out. _totalConnections and pendingCreates then stay
// permanently +1, the empty pool lingers, and every assertion below fails.
//
// LEAK HALF: "no HttpClient leaks when the configurer throws" is not observable
// from this process — HttpClient has a non-virtual destructor and
// PooledConnection owns it through a unique_ptr<HttpClient>, so the test cannot
// subclass it to count destructions. That half is enforced by the LeakSanitizer
// run at the phase-6 gate:
//   cmake --build build-asan --target iora_test_jsonrpc_client_pool
//   ./build-asan/.../iora_test_jsonrpc_client_pool "[phase6]"
// The deterministic half — counters, pool state, exception identity — is
// asserted here.
// =========================================================================
TEST_CASE("task-6.3 R-3: a factory throw rolls the reservation back exactly",
          "[jsonrpc][pool][phase6][rollback]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));

  std::atomic<int> factoryCalls{0};
  std::atomic<bool> armed{false};
  Config cfg = stubFactoryConfig();
  cfg.maxConnectionsPerEndpoint = 2;
  cfg.httpClientFactory =
    [&factoryCalls, &armed](const std::string &) -> std::unique_ptr<iora::network::HttpClient>
  {
    factoryCalls.fetch_add(1);
    if (armed.load())
    {
      throw std::runtime_error("factory blew up");
    }
    return std::make_unique<iora::network::HttpClient>();
  };
  JsonRpcClient client(svc, pool, cfg);

  const std::string epLive = "http://unit.test/live";
  const std::string epDoomed = "http://unit.test/doomed";

  // A live connection on a DIFFERENT endpoint, so the restoration assertions
  // below are against a non-zero baseline rather than a trivially empty pool.
  auto keep = std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, epLive));
  const auto totalBefore = JsonRpcClientTestAccess::totalConnections(client);
  const auto createdBefore = client.getStats().connectionsCreated;
  REQUIRE(totalBefore == 1);
  REQUIRE(createdBefore == 1);

  // The factory throws on a FRESH endpoint: the pool is emplaced before the
  // construction window opens, so rollback must also retire it.
  armed.store(true);
  REQUIRE_THROWS_AS(JsonRpcClientTestAccess::acquire(client, epDoomed), std::runtime_error);
  armed.store(false);

  // EXACT restoration — not merely self-consistency. (_totalConnections ==
  // recalcTotal() is an internal-consistency check and would also hold if BOTH
  // had drifted together, so the pre-call value is compared directly.)
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == totalBefore);
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));
  // connectionsCreated is bumped at PUBLISH, so a throw before publish must not
  // move it (task-6.3; the counter lives in publishCreate, not reserveCreate).
  REQUIRE(client.getStats().connectionsCreated == createdBefore);

  {
    const auto snap = JsonRpcClientTestAccess::snapshotPools(client);
    // designPrinciple #7 (extended): no size()==0 && pendingCreates()==0 pool
    // may linger. The doomed pool must be GONE, not merely empty.
    REQUIRE(!poolOf(snap, epDoomed).has_value());
    const auto live = poolOf(snap, epLive);
    REQUIRE(live.has_value());
    REQUIRE(live->connections.size() == 1);
    REQUIRE(live->pendingCreates == 0); // the reservation was released
    for (const auto &ps : snap)
    {
      REQUIRE(ps.connections.size() > 0);
    }
  }

  // ...and the client still works: a subsequent acquire on the same endpoint
  // succeeds, proving the rollback left no poisoned state behind.
  REQUIRE_NOTHROW(JsonRpcClientTestAccess::acquire(client, epDoomed));
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));
  keep.reset();
}

TEST_CASE("task-6.3 R-3: a configurer throw rolls back too (client already built)",
          "[jsonrpc][pool][phase6][rollback]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));

  std::atomic<bool> armed{false};
  std::atomic<int> configured{0};
  Config cfg = stubFactoryConfig();
  cfg.httpClientConfigurer = [&armed, &configured](const std::string &, iora::network::HttpClient &)
  {
    configured.fetch_add(1);
    if (armed.load())
    {
      // A DISTINCT exception type from the factory case, so the assertion below
      // proves the exception propagates UNCHANGED rather than being wrapped.
      throw std::domain_error("configurer blew up");
    }
  };
  JsonRpcClient client(svc, pool, cfg);

  const std::string ep = "http://unit.test/cfg";
  const auto createdBefore = client.getStats().connectionsCreated;
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 0);

  armed.store(true);
  REQUIRE_THROWS_AS(JsonRpcClientTestAccess::acquire(client, ep), std::domain_error);
  armed.store(false);

  // The HttpClient WAS constructed on this path (configured >= 1) and destroyed
  // during unwinding inside the unlocked window — so ~HttpClient, which joins
  // I/O threads, never ran under _mutex (T6-2).
  REQUIRE(configured.load() >= 1);
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 0);
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));
  REQUIRE(client.getStats().connectionsCreated == createdBefore);
  REQUIRE(JsonRpcClientTestAccess::snapshotPools(client).empty());

  REQUIRE_NOTHROW(JsonRpcClientTestAccess::acquire(client, ep));
}

// =========================================================================
// task-6.4a — the construction-window and pool races phase 6 INTRODUCES.
// =========================================================================

// (a) THE UNLOCKED CONSTRUCTION WINDOW itself. A factory parked on endpoint A
// must not stop an acquire for endpoint B completing.
// NAMED MUTATION: move the makeHttpClient_ call back inside the lock (delete
// the lock.unlock()/lock.lock() pair around the construction window) -> B's
// acquire blocks on _mutex until A's factory is released and this case fails on
// the bounded wait below.
TEST_CASE("task-6.4a(a): a parked factory does not block another endpoint's acquire",
          "[jsonrpc][pool][phase6][window]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));

  TestLatch entered;
  TestLatch release;
  const std::string epA = "http://unit.test/A";
  const std::string epB = "http://unit.test/B";

  Config cfg = stubFactoryConfig();
  cfg.httpClientFactory = parkingFactory(epA, entered, release);
  JsonRpcClient client(svc, pool, cfg);

  AcquireOutcome outA;
  std::unique_ptr<ConnectionLease> leaseA;
  std::thread ta([&] { runAcquire(client, epA, outA, &leaseA); });
  JoinGuard joiner{ta, [&]() { release.signal(); }};

  REQUIRE(entered.wait()); // A is parked INSIDE the construction window

  // While A is parked its reservation is visible and its pool is pinned.
  REQUIRE(waitUntilPending(client, epA, 1));
  REQUIRE(poolOf(client, epA)->connections.empty());

  // THE POINT: B completes while A is still parked.
  AcquireOutcome outB;
  std::unique_ptr<ConnectionLease> leaseB;
  std::thread tb([&] { runAcquire(client, epB, outB, &leaseB); });
  const bool bFinished = waitFor([&] { return outB.done.load(); }, std::chrono::seconds(3));
  // ts L-9: when the bound TRIPS, B is (on the regressed shape this case guards
  // against) blocked on _mutex behind A's factory, so an unconditional join
  // would wedge the case for as long as A stays parked and the failure would
  // surface as a suite TIMEOUT rather than as `bFinished`. Release A first on
  // that branch, so the join is bounded by the factory returning.
  if (!bFinished)
  {
    release.signal();
  }
  tb.join();
  REQUIRE(bFinished);
  REQUIRE(outB.ok.load());

  release.signal();
  ta.join();
  REQUIRE(outA.ok.load());
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 2);
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));
  leaseA.reset();
  leaseB.reset();
}

// (b) SAME-ENDPOINT CONCURRENT CREATE with maxConnectionsPerEndpoint PINNED TO
// 1 — the reservation must be counted by the per-endpoint cap, or both threads
// pass the check and the pool publishes two connections on a cap-1 endpoint.
// NAMED MUTATION (H-1): revert underPerEndpointCap to `pool->size() <
// _config.maxConnectionsPerEndpoint` (drop the + pool->pendingCreates()) ->
// the second thread sees size()==0, creates, and size()==2 overshoots.
// (The reservation's effect on the GLOBAL cap — named mutation H-2 — is NOT
// discriminated here and deliberately is not claimed: this case leaves
// globalMaxConnections at its default of 0, i.e. unlimited, so _totalConnections
// is never consulted. H-2 lives on case (v-conn), which applies real global-cap
// pressure.)
TEST_CASE("task-6.4a(b): a reservation counts against the per-endpoint cap",
          "[jsonrpc][pool][phase6][window]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));

  TestLatch entered;
  TestLatch release;
  const std::string ep = "http://unit.test/capped";

  Config cfg = stubFactoryConfig();
  cfg.maxConnectionsPerEndpoint = 1; // pinned to 1 so the mutations discriminate
  cfg.httpClientFactory = parkingFactory(ep, entered, release);
  JsonRpcClient client(svc, pool, cfg);

  AcquireOutcome first;
  std::unique_ptr<ConnectionLease> leaseFirst;
  std::thread t1([&] { runAcquire(client, ep, first, &leaseFirst); });
  JoinGuard joiner{t1, [&]() { release.signal(); }};
  REQUIRE(entered.wait());

  // The second acquire for the SAME endpoint sees size()==0 but
  // pendingCreates()==1, so the cap is already consumed. Refusing here is the
  // CORRECT outcome, not a regression — it is also what task-6.1b's round-3
  // note predicts for a re-entrant same-endpoint acquire on a cap-1 endpoint.
  AcquireOutcome second;
  runAcquire(client, ep, second);
  REQUIRE(second.done.load());
  REQUIRE(second.poolExhausted.load());
  REQUIRE(!second.ok.load());

  release.signal();
  t1.join();
  REQUIRE(first.ok.load());

  const auto ps = poolOf(client, ep);
  REQUIRE(ps.has_value());
  REQUIRE(ps->connections.size() == 1); // never 2 — neither cap was exceeded
  REQUIRE(ps->pendingCreates == 0);
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 1);
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));
  leaseFirst.reset();
}

// (c) FACTORY/CONFIGURER RE-ENTERING THE CLIENT. This is the CR-3 defect
// itself: pre-phase-6 the configurer ran under _mutex, so purgeIdle() blocked
// on it forever. It must now complete, and the pool-pin must keep the pool
// alive across a re-entrant purgeIdle on the SAME endpoint.
// NAMED MUTATION: run the factory/configurer under _mutex again (delete the
// unlock/lock pair) -> immediate self-deadlock, the case never returns and its
// ctest TIMEOUT fires.
TEST_CASE("task-6.4a(c): a re-entrant configurer completes and the pool survives it",
          "[jsonrpc][pool][phase6][window][cr3]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));

  JsonRpcClient *self = nullptr;
  std::atomic<int> reentries{0};
  std::atomic<bool> sawExhausted{false};
  std::atomic<bool> pinHeldDuringWindow{false};

  Config cfg = stubFactoryConfig();
  cfg.maxConnectionsPerEndpoint = 1; // so the re-entrant same-endpoint acquire refuses
  const std::string ep = "http://unit.test/reentrant";
  cfg.httpClientConfigurer = [&](const std::string &, iora::network::HttpClient &)
  {
    if (reentries.fetch_add(1) != 0)
    {
      return; // re-enter ONCE; a self-recursive configurer would never bottom out
    }
    // (1) purgeIdle() on the SAME endpoint: it takes _mutex, which we no longer
    //     hold. Pre-fix this blocked forever. It must NOT retire our pool —
    //     the pool is empty (nothing published yet) but PINNED by our
    //     reservation (designPrinciple #8).
    (void)self->purgeIdle();
    // (1a) THE PIN, asserted WHERE IT IS LIVE. Checking purgeIdle()'s return
    //      value instead (the earlier `purgedDuringWindow == 0`) was vacuous —
    //      the client holds zero connections at this moment, so that count is 0
    //      whether or not the pool survived. What must be true is that the pool
    //      is STILL IN _pools, empty but pinned by our own reservation. Read
    //      through the seam and asserted on the main thread (Catch2's REQUIRE is
    //      not usable from inside a user callback on an arbitrary thread).
    const auto during = poolOf(*self, ep);
    pinHeldDuringWindow.store(during.has_value() && during->connections.empty() &&
                              during->pendingCreates == 1);
    // (2) a re-entrant acquire on the SAME endpoint. With the cap pinned to 1
    //     our own reservation has consumed it, so PoolExhaustedError is the
    //     EXPECTED outcome (task-6.1b round-3 note) — the point is that it
    //     returns an error rather than deadlocking.
    try
    {
      auto lease = JsonRpcClientTestAccess::acquire(*self, ep);
      (void)lease;
    }
    catch (const PoolExhaustedError &)
    {
      sawExhausted.store(true);
    }
  };
  JsonRpcClient client(svc, pool, cfg);
  self = &client;

  // Bounded by ctest's TIMEOUT; pre-fix this line never returns.
  auto lease = std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, ep));

  REQUIRE(reentries.load() >= 1);
  REQUIRE(pinHeldDuringWindow.load()); // the re-entrant purgeIdle left the pin
  REQUIRE(sawExhausted.load());        // the cap counted our reservation

  const auto ps = poolOf(client, ep);
  REQUIRE(ps.has_value()); // the pin survived the re-entrant purgeIdle
  REQUIRE(ps->connections.size() == 1);
  REQUIRE(ps->pendingCreates == 0);
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));
  lease.reset();
}

// (q) purgeIdle RACING acquire_ — the pin, isolated. A purgeIdle issued from
// ANOTHER thread while a creation is parked in the window must leave the
// (empty, pinned) pool alone.
// NAMED MUTATION: drop the pendingCreates()==0 conjunct from purgeIdleCore_'s
// retire (call retirePoolLocked_ on size()==0 directly) -> the pool is retired
// mid-creation, and the parked thread's post-relock re-look-up throws
// std::logic_error instead of publishing.
TEST_CASE("task-6.4a(q): purgeIdle does not retire a pool with a creation in flight",
          "[jsonrpc][pool][phase6][pin]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));

  TestLatch entered;
  TestLatch release;
  const std::string ep = "http://unit.test/pinned";

  Config cfg = stubFactoryConfig();
  cfg.httpClientFactory = parkingFactory(ep, entered, release);
  JsonRpcClient client(svc, pool, cfg);

  AcquireOutcome out;
  std::unique_ptr<ConnectionLease> lease;
  std::thread t([&] { runAcquire(client, ep, out, &lease); });
  JoinGuard joiner{t, [&]() { release.signal(); }};
  REQUIRE(entered.wait());
  REQUIRE(waitUntilPending(client, ep, 1));

  // The pool is size()==0 right now — exactly the shape purgeIdleCore_ retires
  // when it is unpinned.
  REQUIRE(client.purgeIdle() == 0);
  {
    const auto ps = poolOf(client, ep);
    REQUIRE(ps.has_value()); // SURVIVED the purge
    REQUIRE(ps->pendingCreates == 1);
  }

  release.signal();
  t.join();
  REQUIRE(out.ok.load()); // published, not thrown out by a lost pool
  const auto ps = poolOf(client, ep);
  REQUIRE(ps.has_value());
  REQUIRE(ps->connections.size() == 1);
  REQUIRE(ps->pendingCreates == 0);
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));
  lease.reset();
}

// (u) _closing LATCHED DURING THE WINDOW. quiesce()'s STEP-2 cancelInFlight
// sweep takes only _mutex, so it runs to completion DURING the window and never
// sees the connection being built — it cannot cancel it. If acquire_ published
// that uncancelled client anyway, a later request on it would be bounded by
// requestTimeout rather than by cancellation. The DISCRIMINATING OBSERVABLE is
// therefore ROLLBACK-vs-COMMIT, not a hang: the downstream per-path _closing
// checks (sendJsonWithRetries_ and the batch fast-fail) would each still catch
// a committed connection later, so "the destructor hangs" is a vacuous mutation.
// NAMED MUTATION: delete the post-relock `if (_closing.load(acquire))` block in
// acquire_ -> the connection is COMMITTED (the seam then shows size()==1, a live
// connection created during shutdown) instead of rolled back.
TEST_CASE("task-6.4a(u): _closing latched during the window rolls the creation back",
          "[jsonrpc][pool][phase6][window][closing]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));

  TestLatch entered;
  TestLatch release;
  const std::string ep = "http://unit.test/closing";

  Config cfg = stubFactoryConfig();
  cfg.httpClientFactory = parkingFactory(ep, entered, release);
  auto client = std::make_unique<JsonRpcClient>(svc, pool, cfg);

  AcquireOutcome out;
  std::thread t([&] { runAcquire(*client, ep, out); });
  JoinGuard joiner{t, [&]() { release.signal(); }};
  REQUIRE(entered.wait());
  REQUIRE(waitUntilPending(*client, ep, 1));

  // STEP-1 only (the real production latch the CountGuard also reads), so the
  // window is still open and this thread is free to assert afterwards.
  JsonRpcClientTestAccess::latchClosing(*client);

  // The batch channel is refused promptly while closing. Note this exercises
  // the FACADE gate (callBatch is a counted channel and _closing is already
  // latched, so it never reaches callBatchCore_). The in-core batch fast-fail
  // added by task-6.1b(d) is a DIFFERENT guard, whose live discriminator is
  // case (z) — there the latch lands AFTER admission, on a reuse hit.
  REQUIRE_THROWS_AS(client->callBatch(ep, {iora::modules::connectors::BatchItem{
                                            "ping", iora::parsers::Json::object()}}),
                    iora::modules::connectors::ClientShutdownError);

  release.signal();
  t.join();

  // THE ASSERTION: rolled back, not committed.
  REQUIRE(out.shutdown.load());
  REQUIRE(!out.ok.load());
  {
    // RETIRED OUTRIGHT — not merely "empty". The earlier disjunctive form
    // (`!has_value() || (empty && unpinned)`) ACCEPTED the second disjunct,
    // which is precisely the state designPrinciple #7 forbids persisting, so it
    // stayed green with the rollback's retire deleted (cpp17 M-1). The rollback
    // path runs rollbackCreateLocked_, whose retireIfEmptyAndUnpinnedLocked_
    // must remove this now-empty, now-unpinned pool.
    REQUIRE(!poolOf(*client, ep).has_value());
  }
  REQUIRE(JsonRpcClientTestAccess::totalConnections(*client) ==
          JsonRpcClientTestAccess::recalcTotal(*client));

  // ...and the destructor still returns promptly (nothing counted is stuck).
  const auto t0 = std::chrono::steady_clock::now();
  client.reset();
  REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(2));
}

// (v-pool) CROSS-POOL EVICTION vs A PINNED POOL — POOL-COUNT pressure. acquire_
// reaches evictOneIdlePoolLruLocked_ only at the maxEndpointPools site, so this
// regime is driven by the pool count, not the connection count. Pool X is
// deliberately made the LRU candidate AND pinned, so an unpinned predicate
// selects exactly the wrong pool.
// NAMED MUTATION: drop `&& pool.pendingCreates() == 0` from the candidacy loop
// in evictOneIdlePoolLruLocked_ -> X (the LRU, all-idle, pinned pool) is chosen
// as bestIt and retired, and the parked thread's post-relock re-look-up throws
// std::logic_error instead of publishing.
TEST_CASE("task-6.4a(v-pool): whole-pool LRU eviction skips a pool with a creation in flight",
          "[jsonrpc][pool][phase6][pin]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(3, 3, std::chrono::seconds(1));

  TestLatch entered;
  TestLatch release;
  const std::string epX = "http://unit.test/X";
  const std::string epW = "http://unit.test/W";
  const std::string epY = "http://unit.test/Y";

  Config cfg = stubFactoryConfig();
  cfg.maxEndpointPools = 2;          // the pressure this regime needs
  cfg.maxConnectionsPerEndpoint = 2; // so X can hold an in-use conn AND reserve
  cfg.globalMaxConnections = 0;      // unlimited: keep the CONNECTION cap out of it
  cfg.httpClientFactory = parkingFactory(epX, entered, release);
  JsonRpcClient client(svc, pool, cfg);

  // 1. X gets one IN-USE connection (so the parked create below is forced to
  //    take the create path rather than reusing an idle connection).
  auto leaseX = std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, epX));

  // 2. A second create on X parks in the window: X is now pinned.
  AcquireOutcome outX;
  std::unique_ptr<ConnectionLease> leaseX2;
  std::thread tx([&] { runAcquire(client, epX, outX, &leaseX2); });
  JoinGuard joiner{tx, [&]() { release.signal(); }};
  REQUIRE(entered.wait());
  REQUIRE(waitUntilPending(client, epX, 1));

  // 3. Release X's lease: X is now allIdle() (one idle connection) AND pinned —
  //    i.e. a candidate under the OLD predicate. Doing this BEFORE creating W
  //    makes X the LRU of the two, so an unpinned predicate picks X.
  leaseX.reset();

  // 4. W: an all-idle, UNPINNED pool, touched after X.
  {
    auto leaseW = JsonRpcClientTestAccess::acquire(client, epW);
    (void)leaseW;
  }
  REQUIRE(JsonRpcClientTestAccess::snapshotPools(client).size() == 2); // at the cap

  // 5. A new endpoint Y forces whole-pool eviction. It must sacrifice W, not X.
  AcquireOutcome outY;
  std::unique_ptr<ConnectionLease> leaseY;
  runAcquire(client, epY, outY, &leaseY);
  REQUIRE(outY.ok.load());

  {
    const auto snap = JsonRpcClientTestAccess::snapshotPools(client);
    const auto x = poolOf(snap, epX);
    REQUIRE(x.has_value());                  // SURVIVED: the pin excluded it
    REQUIRE(x->pendingCreates == 1);         // still mid-creation
    REQUIRE(!poolOf(snap, epW).has_value()); // W was the one evicted
    REQUIRE(poolOf(snap, epY).has_value());
  }

  release.signal();
  tx.join();
  REQUIRE(outX.ok.load()); // X's parked creation published into a pool still there
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));
  leaseX2.reset();
  leaseY.reset();
}

// (v-conn) CROSS-POOL EVICTION vs A PINNED POOL — CONNECTION-CAP pressure. A
// different site and a different predicate: here the global connection cap
// drives tryEvictOneIdleConnLruLocked_, which drops X's LAST idle connection
// and would then retire the emptied pool.
// NAMED MUTATION: revert tryEvictOneIdleConnLruLocked_'s retire to the bare
// `if (it->second->size() == 0) retirePoolLocked_(it, evictedPools);` -> X is
// retired the moment its last idle connection is evicted, even though a
// creation is in flight on it, and the parked thread's re-look-up throws.
// NAMED MUTATION (H-2): move ++_totalConnections from the reservation back to
// the publish -> in-flight creations stop counting against the GLOBAL cap. This
// is the case that discriminates it (not (b), which leaves globalMaxConnections
// unlimited): here size(1) + pendingCreates(1) is exactly the cap of 2, so the
// `totalConnections == 2` assertion below reads 1 instead, and Y's create then
// finds room without evicting at all.
TEST_CASE("task-6.4a(v-conn): idle-connection LRU eviction does not retire a pinned pool",
          "[jsonrpc][pool][phase6][pin]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(3, 3, std::chrono::seconds(1));

  TestLatch entered;
  TestLatch release;
  const std::string epX = "http://unit.test/Xc";
  const std::string epY = "http://unit.test/Yc";

  Config cfg = stubFactoryConfig();
  cfg.maxEndpointPools = 0; // unlimited: keep the POOL cap out of it
  cfg.maxConnectionsPerEndpoint = 2;
  cfg.globalMaxConnections = 2; // the pressure this regime needs
  cfg.httpClientFactory = parkingFactory(epX, entered, release);
  JsonRpcClient client(svc, pool, cfg);

  auto leaseX = std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, epX));

  AcquireOutcome outX;
  std::unique_ptr<ConnectionLease> leaseX2;
  std::thread tx([&] { runAcquire(client, epX, outX, &leaseX2); });
  JoinGuard joiner{tx, [&]() { release.signal(); }};
  REQUIRE(entered.wait());
  REQUIRE(waitUntilPending(client, epX, 1));

  // X: one idle connection + one reservation. The global cap (2) is saturated
  // by size(1) + pendingCreates(1), so Y's create must reclaim by eviction.
  leaseX.reset();
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 2);

  AcquireOutcome outY;
  std::unique_ptr<ConnectionLease> leaseY;
  runAcquire(client, epY, outY, &leaseY);
  REQUIRE(outY.ok.load());

  {
    const auto snap = JsonRpcClientTestAccess::snapshotPools(client);
    const auto x = poolOf(snap, epX);
    REQUIRE(x.has_value());          // SURVIVED, though now empty...
    REQUIRE(x->connections.empty()); // ...its last idle connection went
    REQUIRE(x->pendingCreates == 1); // ...and the pin is why it survived
    REQUIRE(poolOf(snap, epY).has_value());
  }

  release.signal();
  tx.join();
  REQUIRE(outX.ok.load());
  {
    const auto x = poolOf(client, epX);
    REQUIRE(x.has_value());
    REQUIRE(x->connections.size() == 1);
    REQUIRE(x->pendingCreates == 0);
  }
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));
  leaseX2.reset();
  leaseY.reset();
}

// (p) LEASE RELEASE RACING EVICTION. A lease released on one thread while
// another thread runs an idle-connection eviction over the same pool. Both
// sides take _mutex so they serialize, and BOTH ORDERS MUST BE SAFE: release ->
// evict erases a freshly idle connection, evict -> release calls markFree on a
// connection already detached from the pool.
//
// HONEST SCOPE (cpp17 M-3): the start latch does NOT produce a deterministic
// overlap and this case no longer claims one — `go.signal()` followed by
// `lease.reset()` on the same thread only removes thread-START latency from the
// window; WHICH order wins is up to the scheduler. What IS deterministic is the
// assertion set: it is written to hold under either winner, so the case is a
// valid guard on every run rather than one that only means something when the
// race happens to land. Because "the purge actually erased something" is
// therefore NOT guaranteed by the race, the erase path is additionally driven
// UNCONDITIONALLY below, which is what gives the named mutation a target on
// every run.
// NAMED MUTATION: delete `_totalConnections = recalcTotalLocked_();` from
// purgeIdleCore_ -> whichever purge performs the erase leaves the counter stale
// at 1 while the recalculated sum is 0, and the counter-identity assertions
// below fail. (The earlier named mutation here described reverting
// ConnectionLease to phase-4's pool-index identity — a shape that no longer
// exists anywhere in the source, so it could not be applied, let alone kill.)
TEST_CASE("task-6.4a(p): releasing a lease concurrently with eviction drifts no counter",
          "[jsonrpc][pool][phase6][race]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(3, 3, std::chrono::seconds(1));

  Config cfg = stubFactoryConfig();
  cfg.maxConnectionsPerEndpoint = 4;
  // Every freed connection is immediately purgeable, so the purge below has a
  // real target the instant the release lands.
  cfg.idleTimeout = std::chrono::milliseconds(0);
  JsonRpcClient client(svc, pool, cfg);

  const std::string ep = "http://unit.test/racey";
  auto lease = std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, ep));
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 1);

  TestLatch go;
  std::atomic<std::size_t> purged{0};
  std::atomic<bool> purgeDone{false};
  std::thread purger(
    [&]
    {
      go.wait();
      purged.store(client.purgeIdle());
      purgeDone.store(true);
    });
  JoinGuard joiner{purger, [&]() { go.signal(); }};

  go.signal();
  lease.reset(); // releaseConnection_ (markFree under _mutex) races the purge
  purger.join();
  REQUIRE(purgeDone.load());

  // Whichever order won, the counters must agree and nothing may be
  // double-counted: the connection was either purged (total 0, one eviction
  // counted) or still idle in the pool (total 1) — never both, never neither.
  const auto totalAfter = JsonRpcClientTestAccess::totalConnections(client);
  REQUIRE(purged.load() <= 1);
  REQUIRE(totalAfter == JsonRpcClientTestAccess::recalcTotal(client));
  REQUIRE(totalAfter == (purged.load() == 1 ? std::size_t{0} : std::size_t{1}));

  // Drive the erase path unconditionally, so the named mutation has a target on
  // EVERY run and not only on the interleavings where the purger happened to win
  // (cpp17 M-3). Exactly one of the two purges does the erase: the connection is
  // idle and immediately expired, so if the purger missed it, this one takes it.
  const std::size_t purgedAgain = client.purgeIdle();
  REQUIRE(purged.load() + purgedAgain == 1);
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 0);
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));

  // A subsequent acquire still works and keeps the invariant exact.
  {
    auto again = JsonRpcClientTestAccess::acquire(client, ep);
    (void)again;
  }
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));
}

// (w) THROW-PATH EMPTY-POOL RETIRE, with the consequence made observable. A
// pool stranded at size()==0 by a factory throw is invisible to the
// _totalConnections tripwire (an empty pool sums to 0) — its damage shows up
// only as a maxEndpointPools slot it occupies forever, refusing a LATER,
// UNRELATED endpoint. That is what this asserts.
// NAMED MUTATION: delete the retireIfEmptyAndUnpinnedLocked_ call from
// acquire_'s rollback catch block -> the doomed pool lingers, fills the last
// slot, and the third endpoint is refused with a spurious PoolExhaustedError.
TEST_CASE("task-6.4a(w): a rolled-back creation strands no pool in a maxEndpointPools slot",
          "[jsonrpc][pool][phase6][rollback]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));

  std::atomic<bool> armed{false};
  Config cfg = stubFactoryConfig();
  cfg.maxEndpointPools = 2;
  cfg.httpClientFactory =
    [&armed](const std::string &) -> std::unique_ptr<iora::network::HttpClient>
  {
    if (armed.load())
    {
      throw std::runtime_error("factory blew up");
    }
    return std::make_unique<iora::network::HttpClient>();
  };
  JsonRpcClient client(svc, pool, cfg);

  // Slot 1: a live, IN-USE pool (not an eviction candidate).
  auto keep = std::make_unique<ConnectionLease>(
    JsonRpcClientTestAccess::acquire(client, "http://unit.test/keep"));

  // Slot 2 is transiently taken by the doomed pool, then must be released.
  armed.store(true);
  REQUIRE_THROWS_AS(JsonRpcClientTestAccess::acquire(client, "http://unit.test/doomed"),
                    std::runtime_error);
  armed.store(false);
  REQUIRE(JsonRpcClientTestAccess::snapshotPools(client).size() == 1);

  // A DIFFERENT endpoint must still be admitted. With the retire missing, the
  // stranded empty pool holds slot 2, no pool is all-idle to evict, and this
  // throws.
  REQUIRE_NOTHROW(JsonRpcClientTestAccess::acquire(client, "http://unit.test/other"));
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));
  keep.reset();
}

// (w2) MULTI-THREAD ROLLBACK RETIRE PIN. Two threads reserve on the SAME fresh
// endpoint; one's factory throws while the other is still constructing. The
// throwing thread's rollback must NOT retire the pool the survivor is pinned
// to — this is precisely why the rollback retire gates on pendingCreates()==0
// and not on size()==0 alone (the guard the Option-A site carried pre-phase-6).
// NAMED MUTATION: drop the pendingCreates()==0 conjunct from the rollback
// retire (i.e. retire on size()==0 alone) -> E is retired out from under the
// surviving thread, whose post-relock re-look-up throws std::logic_error, and
// whose reservation decrement lands on a pool detached from _pools.
TEST_CASE("task-6.4a(w2): one thread's rollback does not retire a pool another is creating on",
          "[jsonrpc][pool][phase6][pin][rollback]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(3, 3, std::chrono::seconds(1));

  const std::string epE = "http://unit.test/E";
  TestLatch parked;    // signalled once the survivor is inside the window
  TestLatch release;   // releases the survivor
  TestLatch threwOnce; // signalled once the doomed thread has rolled back
  std::atomic<int> calls{0};

  Config cfg = stubFactoryConfig();
  cfg.maxConnectionsPerEndpoint = 2; // both threads may reserve
  cfg.httpClientFactory = [&](const std::string &ep) -> std::unique_ptr<iora::network::HttpClient>
  {
    if (ep == epE && calls.fetch_add(1) == 0)
    {
      parked.signal(); // FIRST caller is the survivor: park in the window
      release.wait();
      return std::make_unique<iora::network::HttpClient>();
    }
    if (ep == epE)
    {
      throw std::runtime_error("second creation on E blew up"); // the doomed one
    }
    return std::make_unique<iora::network::HttpClient>();
  };
  JsonRpcClient client(svc, pool, cfg);

  AcquireOutcome survivor;
  std::unique_ptr<ConnectionLease> survivorLease;
  std::thread ts([&] { runAcquire(client, epE, survivor, &survivorLease); });
  JoinGuard joiner{ts, [&]() { release.signal(); }};
  REQUIRE(parked.wait());
  REQUIRE(waitUntilPending(client, epE, 1));

  // The doomed thread reserves a SECOND slot on E and throws from its factory.
  AcquireOutcome doomed;
  std::thread td(
    [&]
    {
      runAcquire(client, epE, doomed);
      threwOnce.signal();
    });
  JoinGuard tdJoiner{td}; // declared AFTER td: a failing REQUIRE below must not
                          // unwind through a joinable thread (std::terminate)
  REQUIRE(threwOnce.wait());
  td.join();
  REQUIRE(doomed.otherError.load()); // std::runtime_error, propagated unchanged
  REQUIRE(!doomed.ok.load());

  // E must still be there, still pinned by the survivor's reservation, and the
  // doomed thread's reservation must be the only one released.
  {
    const auto ps = poolOf(client, epE);
    REQUIRE(ps.has_value());
    REQUIRE(ps->pendingCreates == 1);
    REQUIRE(ps->connections.empty());
  }

  release.signal();
  ts.join();
  REQUIRE(survivor.ok.load()); // completed into a pool that was never retired
  {
    const auto ps = poolOf(client, epE);
    REQUIRE(ps.has_value());
    REQUIRE(ps->connections.size() == 1);
    REQUIRE(ps->pendingCreates == 0);
  }
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));
  survivorLease.reset();
}

// (id) THE POST-RELOCK IDENTITY GUARD, driven directly (cpp17 L-4). task-4.2
// requires this guard to be an UNCONDITIONAL throw rather than an assert, so it
// survives NDEBUG — but until now nothing exercised it, which means a mutation
// converting it back to an assert (exactly what task-4.2 forbids) passed the
// whole suite in the Release build the milestone gate uses.
//
// It is unreachable by design through the public API: the pin makes retiring a
// pool with pendingCreates() > 0 impossible at all five sites, and the creating
// thread holds a reservation for the whole window. That is what the
// JsonRpcClientTestAccess::detachPool seam is for — it removes the pool from
// _pools while keeping it alive, simulating a defective pin without needing one.
//
// Counter accounting on this path: detachPool leaves _totalConnections at 1
// against a recalculated 0 (it does not reconcile — the whole point is to
// simulate corruption), and the guard's rollback then decrements to 0, which is
// consistent again. The retire inside rollbackCreateLocked_ correctly declines:
// the key no longer maps to our pool.
// NAMED MUTATION: replace the `throw std::logic_error(...)` after the re-look-up
// with `assert(it != _pools.end() && it->second == pool);` -> in the Release
// build (build/, NDEBUG) the assert vanishes, the creation is published onto a
// pool no longer in _pools, `ok` is true and `sawIdentityThrow` is false, so
// this case fails by name. (In the Debug/ASan build the same mutation aborts on
// the assert instead — a kill either way, but a louder one.)
TEST_CASE("task-4.2/6.1b(b): a pool detached during the window throws instead of publishing",
          "[jsonrpc][pool][phase6][identity]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));

  TestLatch entered;
  TestLatch release;
  const std::string ep = "http://unit.test/detached";

  Config cfg = stubFactoryConfig();
  cfg.httpClientFactory = parkingFactory(ep, entered, release);
  JsonRpcClient client(svc, pool, cfg);

  std::atomic<bool> ok{false};
  std::atomic<bool> sawIdentityThrow{false};
  std::thread t(
    [&]
    {
      try
      {
        auto lease = JsonRpcClientTestAccess::acquire(client, ep);
        (void)lease;
        ok.store(true);
      }
      catch (const std::logic_error &)
      {
        // std::logic_error and NOT PoolExhaustedError/ClientShutdownError, both
        // of which derive from std::runtime_error — so this catch cannot be
        // satisfied by either of the other post-relock exits.
        sawIdentityThrow.store(true);
      }
      catch (...)
      {
      }
    });
  JoinGuard joiner{t, [&] { release.signal(); }};

  REQUIRE(entered.wait());
  REQUIRE(waitUntilPending(client, ep, 1));

  // Yank the pool out from under the parked creation.
  auto detached = JsonRpcClientTestAccess::detachPool(client, ep);
  REQUIRE(detached != nullptr);
  REQUIRE(!poolOf(client, ep).has_value());

  release.signal();
  t.join();

  REQUIRE(sawIdentityThrow.load());
  REQUIRE(!ok.load());

  // The detached pool got its reservation back (rollbackCreate ran on it) and
  // nothing was published into it.
  REQUIRE(detached->pendingCreates() == 0);
  REQUIRE(JsonRpcClientTestAccess::poolConnCount(client, detached) == 0);

  // ...and the client's own accounting is self-consistent again.
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) == 0);
  REQUIRE(JsonRpcClientTestAccess::totalConnections(client) ==
          JsonRpcClientTestAccess::recalcTotal(client));
}

// =========================================================================
// task-6.4b — the DESTRUCTOR / QUIESCE races. Several cases in this task were
// already built by phase 3 and are NOT duplicated here; they are named so the
// coverage claim is checkable rather than asserted:
//   (d) destroy-vs-not-yet-started task -> "phase3 / CR-4 fixed: destructor
//       waits for a queued async task"
//   (e),(o) self-destruct from a callback (+ the negative "different idle
//       client" case) -> the standalone iora_test_jsonrpc_quiesce_selfdestruct
//       binary; a std::terminate cannot live in this shared Catch2 process
//   (f)(ii) the enqueue-throw discard route -> "phase3: enqueue failure routes
//       through the token's channel"
//   (m) gate refusal on every channel -> "phase3: every counted channel refuses
//       after closing is latched" (all six channels + _inFlight == 0)
//   (s) a request wedged against a silent server -> "phase3: destructor cancels
//       and waits for an in-flight synchronous call"
//   (s2) interruptible retry backoff -> "phase3: destructor interrupts a call
//       parked in retry backoff"
// The cases below are the ones that did NOT exist.
//
// TAGGING (simpl L9): every case in this section carries BOTH [phase3] and
// [phase6]. They were written during phase 6, but what they exercise is phase-3
// machinery — quiesce, the in-flight count, InFlightToken, the refusal channels.
// Tagged [phase6] alone, a `[phase3]` filter run would silently skip nine cases
// that are squarely phase-3 regression guards; the [phase6] tag stays so the
// phase-6 delta remains selectable on its own.
// =========================================================================

// (f)(i) THE DISCARDED TASK, unit form. A token counted at construction and
// then destroyed WITHOUT running must return _inFlight to 0 — not leave the
// destructor waiting forever on a task that will never run. Note this uses the
// unit seam and NOT ThreadPool::reset(), which task-3.5(e) forbids and which is
// unreachable anyway (thread_pool.hpp requires Stopped, and reaching Stopped
// drains and joins first). Expected outcome is a CLEAN RETURN, not a terminate.
// NAMED MUTATION: move the CountGuard out of InFlightToken so counting happens
// in runBody() instead of at construction -> the discarded token never
// decrements (it never ran), _inFlight stays 1, and the destructor below hangs
// to the ctest TIMEOUT.
TEST_CASE("task-6.4b(f)(i): a token discarded unrun releases its in-flight count",
          "[jsonrpc][pool][phase3][phase6][quiesce]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  auto client = std::make_unique<JsonRpcClient>(svc, pool, stubFactoryConfig());

  {
    auto closure = JsonRpcClientTestAccess::makeDiscardableAsyncClosure(*client, "http://x/rpc");
    REQUIRE(JsonRpcClientTestAccess::quiesceSnapshot(*client).inFlight == 1);
    closure = nullptr; // DISCARD: destroyed without ever being invoked
  }
  REQUIRE(JsonRpcClientTestAccess::quiesceSnapshot(*client).inFlight == 0);

  const auto t0 = std::chrono::steady_clock::now();
  client.reset(); // must return cleanly, not hang and not terminate
  REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(2));
}

// (t) A FUTURE-RETURNING callAsync whose task is discarded unrun must resolve
// the caller's future with broken_promise rather than leaving get() blocked
// forever. The token's callables are the sole owners of the promise, so their
// destruction is what breaks it.
// NAMED MUTATION: have dispatchFuture_ keep its own copy of the promise alive
// beyond the token (e.g. capture it in a member of Impl) -> destroying the
// token no longer breaks the promise and the get() below blocks until the
// case's bounded wait fails.
TEST_CASE("task-6.4b(t): a discarded future task resolves with broken_promise",
          "[jsonrpc][pool][phase3][phase6][quiesce]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  auto client = std::make_unique<JsonRpcClient>(svc, pool, stubFactoryConfig());

  auto task = JsonRpcClientTestAccess::makeDiscardableFutureTask(*client, "http://x/rpc");
  REQUIRE(JsonRpcClientTestAccess::quiesceSnapshot(*client).inFlight == 1);

  task.closure = nullptr; // DISCARD
  REQUIRE(JsonRpcClientTestAccess::quiesceSnapshot(*client).inFlight == 0);

  REQUIRE(task.future.wait_for(std::chrono::seconds(2)) == std::future_status::ready);
  bool sawBrokenPromise = false;
  try
  {
    (void)task.future.get();
  }
  catch (const std::future_error &e)
  {
    sawBrokenPromise = (e.code() == std::future_errc::broken_promise);
  }
  REQUIRE(sawBrokenPromise);

  const auto t0 = std::chrono::steady_clock::now();
  client.reset();
  REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(2));
}

// (i) ENQUEUE-FAILURE COUNTER EXACTNESS, made explicit. The phase-3
// enqueue-failure case asserts _inFlight is 0 after each refusal; what it does
// not assert is the CONSEQUENCE — that a destruction following those failures
// still terminates. A counter left high by a failed enqueue is invisible until
// something waits on it.
// NAMED MUTATION: drop the `token->fail(...)` / early-return in dispatchToken_'s
// catch so the token is leaked into the enqueue exception path -> _inFlight
// never returns to 0 and the timed destructor below hangs.
TEST_CASE("task-6.4b(i): a destruction after enqueue failures still terminates",
          "[jsonrpc][pool][phase3][phase6][quiesce]")
{
  auto &svc = testService();

  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1), /*maxQueueSize*/ 1);
  auto client = std::make_unique<JsonRpcClient>(svc, pool, stubFactoryConfig());

  BlockedWorker blocker(pool);
  REQUIRE(blocker.waitUntilRunning());
  pool.enqueue([]() {}); // fills the single queue slot

  // Three enqueue failures across all three async channels.
  for (int i = 0; i < 3; ++i)
  {
    std::atomic<bool> errCalled{false};
    REQUIRE_NOTHROW(client->callAsync("http://x/rpc", "ping", iora::parsers::Json::object(), {},
                                      [](iora::parsers::Json) {},
                                      [&errCalled](std::exception_ptr) { errCalled.store(true); }));
    REQUIRE(errCalled.load());
  }
  REQUIRE(JsonRpcClientTestAccess::quiesceSnapshot(*client).inFlight == 0);

  const auto t0 = std::chrono::steady_clock::now();
  client.reset();
  REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(2));
}

// (n) THE C4-1 USER-STATE PROBE, and (r) A THROWING onSuccess, together —
// they share one shape and the same concurrent destructor.
// C4-1: a user callback may capture state the OWNER also holds. The token's
// member declaration order (callables FIRST, then _guard, then _impl) exists so
// that captured state is torn down BEFORE the in-flight count drops and the
// waiting destructor is released. If the order inverted, ~JsonRpcClient could
// return — and the owner's state be gone — while the capture's destructor was
// still about to touch it.
// NAMED MUTATION (n): declare InFlightToken's callables AFTER _guard -> the
// decrement+notify precedes the callables' destruction, the destructor can
// return first, and `probeSawDestructorReturned` below becomes true.
// NAMED MUTATION (r): remove the try/catch around _onSuccess in runBody() -> the
// user exception escapes into a ThreadPool worker and terminates the process.
TEST_CASE("task-6.4b(n)+(r): captured user state dies before the destructor returns, even "
          "when onSuccess throws",
          "[jsonrpc][pool][phase3][phase6][quiesce]")
{
  auto &svc = testService();

  std::atomic<bool> destructorReturned{false};
  std::atomic<bool> probeDestroyed{false};
  std::atomic<bool> probeSawDestructorReturned{false};

  // Shared by both callbacks, so its destructor runs exactly when the token's
  // callables are destroyed. It records whether ~JsonRpcClient had ALREADY
  // returned at that moment — which must never be the case.
  struct Probe
  {
    std::atomic<bool> *destroyed;
    std::atomic<bool> *sawReturned;
    std::atomic<bool> *destructorReturned;
    // A real constructor, so make_shared builds the Probe IN PLACE. Brace-
    // initialising a temporary and copying it into the shared_ptr would run the
    // temporary's destructor at the end of that full expression and fire the
    // probe before the token ever held it.
    Probe(std::atomic<bool> *d, std::atomic<bool> *s, std::atomic<bool> *dr)
        : destroyed(d), sawReturned(s), destructorReturned(dr)
    {
    }
    Probe(const Probe &) = delete;
    Probe &operator=(const Probe &) = delete;
    ~Probe()
    {
      sawReturned->store(destructorReturned->load());
      destroyed->store(true);
    }
  };

  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  auto client = std::make_unique<JsonRpcClient>(svc, pool, stubFactoryConfig());

  BlockedWorker blocker(pool);
  REQUIRE(blocker.waitUntilRunning());

  std::thread destroyer;
  // ONE guard covering every failure path: release the worker (BlockedWorker's
  // release is idempotent) so a quiescing destructor can finish, THEN join it.
  // Without this a failing REQUIRE below would leave the token counted, the
  // worker occupied, and the scope-exit destructor waiting on _inFlight forever.
  JoinGuard joiner{destroyer, [&]() { blocker.release(); }};

  {
    auto probe =
      std::make_shared<Probe>(&probeDestroyed, &probeSawDestructorReturned, &destructorReturned);
    // (r): BOTH callables throw. The endpoint is unroutable so onError is the
    // one that fires here; the throw must be swallowed either way (TS-4) — a
    // user exception escaping into a worker would terminate the process.
    client->callAsync("http://127.0.0.1:1/rpc", "ping", iora::parsers::Json::object(), {},
                      [probe](iora::parsers::Json) { throw std::runtime_error("onSuccess threw"); },
                      [probe](std::exception_ptr) { throw std::runtime_error("onError threw"); });
    // The token's two captures are now the SOLE owners of the probe.
  }
  REQUIRE(JsonRpcClientTestAccess::quiesceSnapshot(*client).inFlight == 1);
  REQUIRE(!probeDestroyed.load()); // still owned by the token's callables

  // ts M-5, FOURTH SITE (found while folding simpl LOW-1; not flagged by any
  // review round). The negative assertion below can pass VACUOUSLY if the
  // destroyer thread was simply never scheduled — the sleep alone cannot tell
  // "STEP 3 is waiting" from "the destructor has not started". `entering` is
  // signalled immediately before ~JsonRpcClient, so the assertion only runs once
  // the destruction is genuinely under way. Same fix as the CR-4, enqueue-
  // ordering and case-(x) sites.
  TestLatch entering;
  destroyer = std::thread(
    [&]
    {
      entering.signal();
      client.reset();
      destructorReturned.store(true);
    });

  REQUIRE(entering.wait());
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  REQUIRE(!destructorReturned.load()); // STEP 3 is waiting on the queued token

  blocker.release(); // free the worker: the token runs, throws, and is destroyed
  destroyer.join();

  REQUIRE(destructorReturned.load());          // (r): returned CLEANLY despite the throw
  REQUIRE(probeDestroyed.load());              // (n): the capture was torn down...
  REQUIRE(!probeSawDestructorReturned.load()); // ...BEFORE the destructor returned
}

// (g) CONCURRENT callAsync DURING DESTRUCTION. An issuing thread and a
// destroying thread CO-OWN the facade through a shared_ptr, so the destructor
// runs on whichever thread drops the last reference while async work is still
// in flight on the workers. (The facade's own storage lifetime is the caller's
// responsibility — invoking a method on an already-destroyed object is UB by
// C++ rules and no quiesce design can rescue it. What quiesce DOES promise, and
// what this asserts, is that every admitted async call resolves through exactly
// one channel before the destructor returns, and that callAsync never throws to
// its caller regardless of when the latch lands mid-burst.)
// NAMED MUTATION: make the CountGuard read _closing WITHOUT holding
// _quiesceMutex (split the check from the increment) -> a call admitted just
// after STEP-1 can be counted after STEP-3's wait has already passed, so the
// destructor returns with work outstanding and the worker then touches a freed
// Impl (ASan heap-use-after-free), or _inFlight underflows to SIZE_MAX.
TEST_CASE("task-6.4b(g): callAsync racing destruction resolves every call and never wedges",
          "[jsonrpc][pool][phase3][phase6][quiesce]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
  auto client = std::make_shared<JsonRpcClient>(svc, pool, stubFactoryConfig());

  std::atomic<int> issued{0};
  std::atomic<int> resolved{0};
  std::atomic<bool> escaped{false};
  TestLatch issuing;

  std::thread caller(
    [client, &issued, &resolved, &escaped, &issuing]() mutable
    {
      for (int i = 0; i < 100; ++i)
      {
        try
        {
          client->callAsync("http://127.0.0.1:1/rpc", "ping", iora::parsers::Json::object(), {},
                            [&resolved](iora::parsers::Json) { resolved.fetch_add(1); },
                            [&resolved](std::exception_ptr) { resolved.fetch_add(1); });
          issued.fetch_add(1);
        }
        catch (...)
        {
          escaped.store(true); // callAsync must NEVER throw to its caller
          break;
        }
        if (i == 5)
        {
          issuing.signal(); // the burst is under way; let the destroyer in
        }
      }
      client.reset(); // may run ~JsonRpcClient here, mid-burst-aftermath
    });
  JoinGuard callerJoiner{caller}; // see JoinGuard: REQUIRE below precedes join()

  REQUIRE(issuing.wait());
  const auto t0 = std::chrono::steady_clock::now();
  client.reset(); // drops this thread's reference WHILE the burst is in flight
  caller.join();
  const auto elapsed = std::chrono::steady_clock::now() - t0;

  REQUIRE(!escaped.load());
  REQUIRE(issued.load() == 100);
  // The destructor ran on whichever thread dropped last, and by the time BOTH
  // references are gone every admitted call has resolved exactly once.
  REQUIRE(resolved.load() == issued.load());
  REQUIRE(elapsed < std::chrono::seconds(30));
}

// (j) A TASK THAT ENQUEUES ANOTHER TASK. A callback that itself calls
// callAsync must not livelock the destructor: the re-entrant call is issued
// while _closing is (or is about to be) latched, so it is refused rather than
// admitted, and _inFlight descends to 0. This is what task-3.1's closing gate
// exists for — without it, each draining task could admit a fresh one forever.
// NAMED MUTATION: delete the _closing check from CountGuard's constructor (admit
// unconditionally) -> the re-entrant chain keeps admitting new work after
// STEP-1 and STEP-3 never observes _inFlight == 0.
TEST_CASE("task-6.4b(j): a callback that enqueues another task cannot livelock the destructor",
          "[jsonrpc][pool][phase3][phase6][quiesce]")
{
  using iora::modules::connectors::ClientShutdownError;

  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  cfg.maxRetries = 0; // no backoff between links: the chain must turn over fast
  auto client = std::make_unique<JsonRpcClient>(svc, pool, cfg);

  std::atomic<int> links{0};
  std::atomic<int> refusals{0};
  const std::string ep = "http://127.0.0.1:1/rpc"; // unroutable: onError fires fast

  // The chain holds a RAW facade pointer, deliberately: capturing an owning
  // handle would make the tokens co-own the client and the reset() below could
  // never destroy it (an ownership cycle, not a quiesce test). The raw pointer
  // is safe precisely because of what is under test — the chain only ever runs
  // inside a COUNTED token, and the destructor cannot return while one is
  // outstanding, so the facade (and its _impl member) is alive throughout.
  JsonRpcClient *raw = client.get();
  std::function<void(std::exception_ptr)> chain;
  chain = [raw, ep, &links, &refusals, &chain](std::exception_ptr e)
  {
    // Once the gate refuses, STOP. The refusal is delivered SYNCHRONOUSLY in
    // this same frame, so re-enqueueing here would recurse until the stack
    // gives out rather than exercising the destructor.
    try
    {
      if (e)
      {
        std::rethrow_exception(e);
      }
    }
    catch (const ClientShutdownError &)
    {
      refusals.fetch_add(1);
      return;
    }
    catch (...)
    {
    }
    if (links.fetch_add(1) > 200)
    {
      return; // safety stop; the gate is expected to end this long before
    }
    raw->callAsync(ep, "ping", iora::parsers::Json::object(), {}, [](iora::parsers::Json) {},
                   chain);
  };

  client->callAsync(ep, "ping", iora::parsers::Json::object(), {}, [](iora::parsers::Json) {},
                    chain);
  // Let the chain turn over at least once before destroying, so the destructor
  // genuinely races a self-perpetuating producer rather than an idle client.
  REQUIRE(waitFor([&] { return links.load() > 0; }, std::chrono::seconds(10)));

  const auto t0 = std::chrono::steady_clock::now();
  client.reset();
  const auto elapsed = std::chrono::steady_clock::now() - t0;
  REQUIRE(elapsed < std::chrono::seconds(10)); // terminated, not livelocked
  REQUIRE(refusals.load() > 0);                // the closing gate is what ended it
}

// (h) THE ROUND-2 C-1 REGRESSION. The five SYNCHRONOUS entry points hold a bare
// CountGuard on a RAW Impl* with no keep-alive, so ~CountGuard must decrement
// AND notify while still holding _quiesceMutex. If it notified after releasing
// the mutex, the quiescing destructor could wake on the decrement, return, and
// free Impl — and with it _quiesceCv — in the gap, leaving the guard about to
// notify a destroyed condition variable.
// NAMED MUTATION: revert ~CountGuard to
//     { std::unique_lock<std::mutex> lk(_impl->_quiesceMutex);
//       --_impl->_inFlight; lk.unlock();
//       std::this_thread::sleep_for(std::chrono::milliseconds(50));   // widen the gap
//       _impl->_quiesceCv.notify_all(); }
// -> ASan reports a heap-use-after-free on _quiesceCv. The injected sleep is
// part of the MUTATION, not of production code: it only widens a window the
// correct implementation does not have.
TEST_CASE("task-6.4b(h): a synchronous call unwinding under a concurrent destructor is clean",
          "[jsonrpc][pool][phase3][phase6][quiesce][latched]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
  const std::uint16_t serverPort = 18155;
  LatchedHttpServer server(serverPort); // parks the handler: the call wedges

  Config cfg;
  cfg.maxRetries = 0;
  auto client = std::make_unique<JsonRpcClient>(svc, pool, cfg);
  const std::string ep = "http://127.0.0.1:" + std::to_string(serverPort) + "/rpc";

  // ts L-2: capture a STABLE raw pointer, never the `client` unique_ptr, which
  // main mutates via reset() below. The single deref here happens-before that
  // reset only incidentally (via the server round-trip), so reading the
  // unique_ptr is not a race today — but it is one refactor away from being one,
  // and the sibling cases (s)/(s2) already established this pattern.
  JsonRpcClient *const raw = client.get();
  std::atomic<bool> callReturned{false};
  std::thread caller(
    [&, raw]
    {
      try
      {
        raw->call(ep, "ping");
      }
      catch (...)
      {
      }
      callReturned.store(true); // ~CountGuard runs as this frame unwinds
    });
  JoinGuard joiner{caller, [&]() { server.release(); }};

  REQUIRE(server.waitForArrival(1)); // the call is parked in the server
  REQUIRE(!callReturned.load());

  // Destroy while the synchronous call is parked: STEP 2 cancels it, the call
  // unwinds, and ~CountGuard's decrement+notify races the destructor's return.
  const auto t0 = std::chrono::steady_clock::now();
  client.reset();
  const auto elapsed = std::chrono::steady_clock::now() - t0;

  caller.join();
  REQUIRE(callReturned.load());
  // Unwound by CANCELLATION, well inside the fixture's 5 s handler bound.
  REQUIRE(elapsed < std::chrono::seconds(3));
}

// (x) CONSTRUCTION-PARKED DESTRUCTOR. A configurer parked in the unlocked
// window is a DISTINCT state from case (s)'s receive-parked request, and it is
// the one phase 6 creates: STEP-2's cancelInFlight() cannot reach it (it is
// user code, and the connection is not yet in any pool for the sweep to find),
// so termination rests entirely on STEP-3's _inFlight wait — which is covered
// by the CALLER's guard, not by anything inside acquire_. The destructor must
// therefore block until the latch is released and then return cleanly, with no
// watchdog involved.
// NAMED MUTATION: remove the caller-side in-flight coverage that spans the
// window (call()'s CountGuard, or the async InFlightToken's _guard) -> STEP 3
// sees _inFlight == 0 and returns immediately, STEP 4 tears down _pools while
// the constructor is still parked, and the parked thread then re-locks a
// destroyed _mutex (ASan heap-use-after-free).
TEST_CASE("task-6.4b(x): a destructor waits for a creation parked in the construction window",
          "[jsonrpc][pool][phase3][phase6][quiesce][window]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));

  TestLatch entered;
  TestLatch release;
  const std::string ep = "http://127.0.0.1:1/rpc"; // unroutable: the send fails fast

  Config cfg = stubFactoryConfig();
  cfg.maxRetries = 0;
  cfg.httpClientConfigurer = [&entered, &release](const std::string &, iora::network::HttpClient &)
  {
    entered.signal();
    release.wait(std::chrono::seconds(10));
  };
  auto client = std::make_unique<JsonRpcClient>(svc, pool, cfg);

  // ts L-2: a STABLE raw pointer, not the `client` unique_ptr the destroyer
  // thread resets below (same reasoning as case (h) and siblings (s)/(s2)).
  JsonRpcClient *const raw = client.get();
  std::atomic<bool> callDone{false};
  std::thread caller(
    [&, raw]
    {
      try
      {
        raw->call(ep, "ping"); // COUNTED: its CountGuard spans the window
      }
      catch (...)
      {
      }
      callDone.store(true);
    });
  JoinGuard joiner{caller, [&]() { release.signal(); }};
  REQUIRE(entered.wait()); // parked inside the configurer, _mutex NOT held

  std::atomic<bool> destroyed{false};
  TestLatch destroyerEntered;
  const auto t0 = std::chrono::steady_clock::now();
  std::thread destroyer(
    [&]
    {
      destroyerEntered.signal(); // scheduled, and about to enter ~JsonRpcClient
      client.reset();
      destroyed.store(true);
    });
  // Declared AFTER destroyer so it is destroyed BEFORE it: the REQUIREs below
  // precede the join, and the one that fires when this case's named mutation is
  // applied is exactly REQUIRE(!destroyed.load()).
  JoinGuard destroyerJoiner{destroyer, [&]() { release.signal(); }};

  // POSITIVE evidence that the destroyer actually RAN, before the negative
  // assertion. A bare sleep proves only "not yet destroyed", which is equally
  // true of "the thread was never scheduled" — on a loaded 2-core host that is
  // a live way for this case to pass while its mutation is applied.
  // (Deliberately NOT a quiesceSnapshot(*client) probe: the destroyer owns the
  // unique_ptr, and unique_ptr::reset() NULLS the pointer before running the
  // destructor, so dereferencing it from here would race into a null deref.)
  REQUIRE(destroyerEntered.wait());
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  REQUIRE(!destroyed.load()); // STEP 3 is blocked on the parked creation
  REQUIRE(!callDone.load());

  release.signal(); // the configurer returns; acquire_ re-locks and rolls back
  destroyer.join();
  caller.join();

  REQUIRE(destroyed.load());
  REQUIRE(callDone.load());
  // It waited for the latch, then returned promptly — a wait, not a watchdog.
  REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(9));
}

// (z) BATCH SEND ON A REUSED CONNECTION AFTER THE LATCH. This is the live
// discriminator for the in-core batch _closing fast-fail (task-6.1b(d)), and
// getting it live took two attempts — the first version drove callBatchCore_
// and proved NOTHING, because acquire_'s ENTRY _closing check refused before the
// fast-fail was ever consulted (the mutation sweep caught it: deleting the guard
// changed no observable). The guard's only reachable window is between acquire_
// RETURNING a lease and the send starting, so this case opens exactly that:
//   * a REUSE HIT (an idle connection is pre-populated), so acquire_'s
//     post-relock recheck — a different guard — cannot dominate either;
//   * the lease is taken while the client is still OPEN;
//   * _closing is latched AFTER it;
//   * the send then runs on that lease, against a SILENT server whose handler
//     parks for 5 s.
// NAMED MUTATION: delete the `if (_closing.load(acquire)) throw` at the head of
// sendBatchOnLease_ -> the send reaches the silent server, blocks for the
// handler's full 5 s bound, and both the elapsed-time and arrivedCount
// assertions below fail. (In the real destructor path the same removal stalls
// the quiesce to requestTimeout instead of unwinding promptly.)
TEST_CASE("task-6.4b(z): a batch send fast-fails on a reused connection once closing is latched",
          "[jsonrpc][pool][phase3][phase6][quiesce][latched]")
{
  using iora::modules::connectors::BatchItem;
  using iora::modules::connectors::ClientShutdownError;

  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
  const std::uint16_t serverPort = 18156;
  LatchedHttpServer server(serverPort); // SILENT: the handler parks for 5 s

  Config cfg;
  cfg.maxRetries = 0;
  auto client = std::make_unique<JsonRpcClient>(svc, pool, cfg);
  const std::string ep = "http://127.0.0.1:" + std::to_string(serverPort) + "/rpc";

  // Pre-populate an idle connection, then take a lease on it: a REUSE HIT, so
  // no construction window and no post-relock recheck is involved.
  {
    auto warm = JsonRpcClientTestAccess::acquire(*client, ep);
    (void)warm;
  }
  REQUIRE(JsonRpcClientTestAccess::totalConnections(*client) == 1);
  auto lease = JsonRpcClientTestAccess::acquire(*client, ep);

  // The latch lands AFTER the lease was handed out — the admitted-then-latched
  // ordering that the fast-fail, and only the fast-fail, still covers.
  JsonRpcClientTestAccess::latchClosing(*client);

  std::vector<BatchItem> items;
  items.emplace_back("ping", iora::parsers::Json::object(), std::uint64_t{1});

  const auto t0 = std::chrono::steady_clock::now();
  REQUIRE_THROWS_AS(JsonRpcClientTestAccess::sendBatchOnLeaseDirect(*client, lease, ep, items),
                    ClientShutdownError);
  const auto elapsed = std::chrono::steady_clock::now() - t0;
  // Refused BEFORE touching the transport: nowhere near the server's 5 s park.
  REQUIRE(elapsed < std::chrono::seconds(1));
  REQUIRE(server.arrivedCount() == 0); // the silent handler was never reached

  {
    ConnectionLease dropped(std::move(lease)); // release before destroying
  }
  const auto t1 = std::chrono::steady_clock::now();
  client.reset();
  REQUIRE(std::chrono::steady_clock::now() - t1 < std::chrono::seconds(2));
}

int main(int argc, char *argv[])
{
  // Initialize the service once and tear it down in an orderly fashion. Without
  // AutoServiceShutdown the singleton's worker threads are still joinable at
  // static-destruction time and the process aborts (SIGABRT) at exit, which on
  // this host trips the WSL core-dump handler (task-1.1(e-pre)).
  //
  // testService() runs BEFORE Catch::Session, outside Catch2's exception
  // guard, so an init throw here would escape main uncaught -> std::terminate
  // -> SIGABRT -> the same multi-minute WSL core handler. Catch it and exit
  // via std::_Exit(nonzero) (bypasses abort(), no signal, no core handler).
  try
  {
    auto &svc = testService();
    iora::IoraService::AutoServiceShutdown autoShutdown(svc);
    return Catch::Session().run(argc, argv);
  }
  catch (const std::exception &e)
  {
    std::cerr << "[jsonrpc_client_pool] fatal init error: " << e.what() << std::endl;
    std::_Exit(70); // EX_SOFTWARE; no abort(), so no piped-core stall
  }
  catch (...)
  {
    // A non-std::exception throw would otherwise escape main uncaught and
    // defeat the very terminate/SIGABRT invariant this guard exists for.
    std::cerr << "[jsonrpc_client_pool] fatal init error (non-std::exception)" << std::endl;
    std::_Exit(70);
  }
}
