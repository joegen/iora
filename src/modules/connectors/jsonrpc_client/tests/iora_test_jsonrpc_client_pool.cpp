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
// minutes and present to ctest as a TIMEOUT. The only faulting target here is
// the CR-1 crash half: it calls prctl(PR_SET_DUMPABLE, 0) immediately before
// the fault so the kernel skips the core path, and it is registered DISABLED so
// ctest never runs the fault (it is invoked manually for forensic evidence).
// No target expects std::terminate, so no std::set_terminate is installed.

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
#include <sys/prctl.h>
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
    // pendingCreates is added by task-6.1a; omitted until it exists.
  };

  /// \brief Acquire a lease the TEST owns (required by the single-threaded CR-1
  /// repro, which must construct and dispose leases itself). Pool state now
  /// lives in JsonRpcClientImpl, reached through the facade's _impl handle.
  static detail::ConnectionLease acquire(JsonRpcClient &c, const std::string &endpoint)
  {
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
};
} // namespace connectors
} // namespace modules
} // namespace iora

using iora::modules::connectors::JsonRpcClientTestAccess;
using iora::modules::connectors::detail::ConnectionLease;

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

/// \brief A Config whose factory hands out a bare HttpClient and never touches
/// the network — acquire_ only calls the factory (jsonrpc_client.hpp:617), so
/// the pool-lifetime repros need no server at all.
Config stubFactoryConfig()
{
  Config cfg;
  cfg.httpClientFactory = [](const std::string &)
  { return std::make_unique<iora::network::HttpClient>(); };
  return cfg;
}

/// \brief The JSON-RPC 2.0 success envelope the fixtures reply with. No `error`
/// member, so parseResponseOrThrow_ (jsonrpc_client.hpp:831-845) returns the
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
/// JsonRpcClient's constructor takes an IoraService& and a core::ThreadPool&
/// (jsonrpc_client.hpp:386); the service must be initialized exactly once for
/// the whole binary.
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
  struct ReleaseAndJoin
  {
    LatchedHttpServer &s;
    std::thread &t;
    ~ReleaseAndJoin()
    {
      // Never let the RAII cleanup itself throw during unwinding — that would
      // re-introduce the std::terminate this guard exists to prevent (R2-1).
      try
      {
        s.release();
        if (t.joinable())
        {
          t.join();
        }
      }
      catch (...)
      {
      }
    }
  } guard{server, caller};

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
// task-1.4 — CR-1 repro: ConnectionLease identifies its connection by a vector
// INDEX, which every mid-vector erase invalidates. Single-threaded via the
// seam (round-4 rewrite): no server, no latch, no 3 s ceiling. The assertion
// half discriminates on per-connection IDENTITY (the only observable that is
// not vacuous); the out-of-bounds SIGSEGV half is isolated and hidden.
// MUST FAIL against the unmodified baseline.
// =========================================================================
TEST_CASE("CR-1 repro: wrong-connection-free swaps lease identity (RED at HEAD)",
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
  client.purgeIdle();                                    // erases A at :272; [B,C] shift down

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
  // inUse; the one lease1 (B) held must be free. FAILS pre-fix, PASSES post-fix.
  CHECK(cInUse.value() == true);  // pre-fix: C was wrongly freed -> false -> FAILS
  CHECK(bInUse.value() == false); // pre-fix: B wrongly left inUse -> true -> FAILS

  // Leak C on the heap: never destroy its lease, so the out-of-range release(2)
  // does not fire in this assertion binary and take the CHECKs with it.
  (void)c.release();
}

// The SIGSEGV half of CR-1, isolated and hidden ([.] = not run by default).
// Destroying C runs release(2) on the size-2 vector -> NULL-deref SIGSEGV.
// PR_SET_DUMPABLE(0) makes the kernel skip the piped core handler (task-1.1
// (e-pre)(2)); without it the WSL crash handler burns >9 min and presents as a
// ctest TIMEOUT. Run manually for forensic evidence.
TEST_CASE("CR-1 crash half: out-of-range release(idx) faults (isolated)",
          "[jsonrpc][pool][cr1][.crash]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  cfg.maxConnectionsPerEndpoint = 3;
  cfg.idleTimeout = std::chrono::milliseconds(50);
  JsonRpcClient client(svc, pool, cfg);
  const std::string ep = "http://unit.test/rpc";

  auto a = std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, ep));
  auto b = std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, ep));
  auto c = std::make_unique<ConnectionLease>(JsonRpcClientTestAccess::acquire(client, ep));
  a.reset();
  std::this_thread::sleep_for(std::chrono::milliseconds(60));
  client.purgeIdle();
  b.reset();

  std::cerr << "[cr1-crash] destroying C -> release(2) on size-2 vector" << std::endl;
  ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0); // skip the piped core dump on the fault
  c.reset();                            // release(2): out-of-range -> SIGSEGV
  FAIL("expected SIGSEGV from out-of-range release() did not occur");
}

// =========================================================================
// task-1.5 — CR-2 repro: an emptied pool is allIdle()==true (vacuously), so
// acquire_ selects and frees the very pool it holds a reference to, then calls
// createAndAcquire on the freed EndpointPool (:640). Depends on H-2 counter
// drift; MUST be run before task-5.2 fixes the counter. Detector is ASan
// heap-use-after-free — build with -DIORA_ENABLE_ASAN=ON. WILL_FAIL.
// =========================================================================
TEST_CASE("CR-2 repro: acquire on a freed EndpointPool (RED under ASan)",
          "[jsonrpc][pool][cr2]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(1, 1, std::chrono::seconds(1));
  Config cfg = stubFactoryConfig();
  cfg.globalMaxConnections = 1;
  cfg.maxConnectionsPerEndpoint = 8;
  cfg.idleTimeout = std::chrono::milliseconds(50);
  cfg.maxRetries = 0;
  JsonRpcClient client(svc, pool, cfg);

  // Endpoint that refuses instantly, so call() creates the connection then
  // throws on the POST — the connection stays pooled, _totalConnections==1.
  const std::string ep = "http://127.0.0.1:1/rpc";

  try
  {
    client.call(ep, "ping");
  }
  catch (const std::exception &)
  {
    // expected: connection refused after the connection was created
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(60)); // pooled conn now expired

  // Second call: tryAcquireFree erases the expired conn WITHOUT decrementing
  // (H-2), pool empties, underGlobalCap==(1<1)==false, then
  // evictOneIdlePoolLruLocked_ frees the empty pool and createAndAcquire runs
  // on freed memory. ASan reports heap-use-after-free here.
  try
  {
    client.call(ep, "ping");
  }
  catch (const std::exception &)
  {
    // If we get here on a non-ASan build the UAF was silent (UB); the ASan
    // build is the one that produces the RED evidence.
  }
  SUCCEED("reached end without ASan abort (non-ASan build); ASan build is the detector");
}

// =========================================================================
// task-1.6 — CR-3 repro: a re-entrant httpClientConfigurer deadlocks the
// client. makeHttpClient_ runs the configurer on a std::async thread while the
// caller holds _mutex in wait_for(30s); the configurer's purgeIdle() blocks on
// _mutex, wait_for throws, ~future blocks -> permanent cycle. Pre-fix evidence
// is a HANG: registered DISABLED, run under an external `timeout 60` (exit 124).
// =========================================================================
TEST_CASE("CR-3 repro: re-entrant configurer deadlocks under _mutex (hangs)",
          "[jsonrpc][pool][cr3][.hang]")
{
  auto &svc = testService();
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
  JsonRpcClient *self = nullptr;
  Config cfg = stubFactoryConfig();
  // Same-endpoint re-entrancy (cpp17 C-2): the configurer calls back into the
  // client while acquire_ holds the lock for this very endpoint.
  cfg.httpClientConfigurer = [&self](const std::string &, iora::network::HttpClient &)
  { self->purgeIdle(); };
  JsonRpcClient client(svc, pool, cfg);
  self = &client;

  std::cerr << "[cr3-hang] issuing call() with a re-entrant configurer" << std::endl;
  client.call("http://unit.test/rpc", "ping"); // never returns pre-fix
  FAIL("expected deadlock did not occur");
}

// =========================================================================
// task-1.7 — CR-4 repro: async tasks capture `self=this` onto an externally
// owned ThreadPool; the client has no destructor, no in-flight counter, no
// join. A task still QUEUED when the client is destroyed later runs on freed
// memory. Heap-allocated client (a stack object would need
// -fsanitize-address-use-after-scope, which nothing enables — cpp17 C-1).
// Single-worker pool so the second task is genuinely QUEUED, not given its own
// thread. Detector is ASan heap-use-after-free. WILL_FAIL.
// =========================================================================
TEST_CASE("CR-4 repro: queued async task runs on freed client (RED under ASan)",
          "[jsonrpc][pool][cr4]")
{
  auto &svc = testService();

  // Declared BEFORE `pool` so they outlive it: ~ThreadPool joins the worker,
  // which may still be inside gateF.wait(), so the future/promise must still be
  // alive when that join happens (destruction is reverse declaration order —
  // pool is destroyed first) (L4).
  std::promise<void> gate;
  std::future<void> gateF = gate.get_future();
  std::atomic<bool> task1Started{false};

  // initial==max==1 so enqueueImpl never spawns a second worker (thread_pool.hpp
  // :691-695); the second task is queued behind the first (thread-safety M4-5).
  iora::core::ThreadPool pool(/*initial*/ 1, /*max*/ 1, std::chrono::seconds(1));

  auto client = std::make_unique<JsonRpcClient>(svc, pool, stubFactoryConfig());

  // Task 1 occupies the single worker until we release the gate.
  pool.enqueue(
    [&task1Started, &gateF]()
    {
      task1Started.store(true);
      gateF.wait();
    });
  while (!task1Started.load())
  {
    std::this_thread::yield();
  }

  // Task 2 is now QUEUED behind task 1 (worker busy). It captures self=this.
  client->callAsync(
    "http://unit.test/rpc", "ping", iora::parsers::Json::object(), {},
    [](iora::parsers::Json) {}, [](std::exception_ptr) {});

  // Destroy the client while task 2 is still queued. At HEAD ~JsonRpcClient is
  // implicit — no join — so this returns immediately, leaving task 2 pointing
  // at freed storage.
  client.reset();

  // Release the gate: task 1 completes, the worker picks up task 2, which reads
  // self->_stats.totalRequests++ on freed memory -> ASan heap-use-after-free.
  gate.set_value();

  // Give the worker time to run task 2 and fault before the pool tears down.
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  SUCCEED("reached end without ASan abort (non-ASan build); ASan build is the detector");
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
