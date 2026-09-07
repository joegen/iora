// iora_core — shared library housing singleton state for cross-plugin unification.

#include "iora/iora.hpp"
#include "iora/core/metrics.hpp"
#include "iora/core/service_registry.hpp"

namespace iora {
namespace core {

// MetricBase vtable anchor
MetricBase::~MetricBase() = default;

// MetricsRegistry singleton — function-local static, available before IoraService::init()
MetricsRegistry& MetricsRegistry::instance()
{
  static MetricsRegistry registry;
  return registry;
}

// IMMORTAL / deliberately-leaked blockingIoPool singleton (transport DNS-resolve
// CORE, arch transport_dns_resolve.json C3). Dedicated pool for blocking,
// uncancellable I/O (::getaddrinfo) that must never run on an epoll I/O thread.
// Never destroyed: an uncancellable getaddrinfo worker may still be parked when
// process exit runs static destructors — joining it (ThreadPool's dtor) would
// hang teardown, and a late worker only touches immortal statics + its engine's
// already-closed EnginePostGate. This is the R-MEM-1 immortal-singleton exception
// (raw new / no delete), mirroring the LoggerData precedent below. Do NOT revert
// to `static ThreadPool pool(...)` — that reopens the exit-hang path. The leak is
// intentional (LSan: intentional immortal). ThreadPool(initial=2, max=16,
// idleTimeout=30s, maxQueueSize=128) — hard-capped + reject-fast via tryEnqueue.
ThreadPool &blockingIoPool()
{
  static ThreadPool *pool =
    new ThreadPool(2, 16, std::chrono::seconds(30), 128);
  return *pool;
}

// IMMORTAL / deliberately-leaked generalAsyncPool singleton (async_pool.json C1).
// General-purpose async pool backing iora::core::async (a std::async drop-in),
// distinct from blockingIoPool (which is reserved for blocking uncancellable
// syscalls). FIXED-SIZE: initialSize == maxSize == hardware_concurrency()*4.
// initialSize == maxSize is LOAD-BEARING for correctness (DP-15): it pins the
// worker count so ThreadPool::enqueue never spawns a worker post-commit, making
// enqueue all-or-nothing -- a throw from enqueue always means the task was NOT
// committed, so iora::core::async can synthesize a rejection future without
// orphaning a running task (round-2 C-1). The hc==0 clamp is SAFETY-CRITICAL:
// a 0-worker fixed-size pool would never run a task, so a blocking ~PooledFuture
// would wait forever. hc*4 = I/O-burst capacity (HTTP work is I/O-bound). Never
// destroyed (blockingIoPool precedent): an in-flight task at process exit must
// not hang teardown's join (DP-2). The leak is intentional (LSan: intentional
// immortal). Do NOT switch to a dynamically-scaled (initial<max) pool without
// first landing the ThreadPool all-or-nothing hardening (backlog 2026-09-06-11).
ThreadPool &generalAsyncPool()
{
  static ThreadPool *pool = []
  {
    unsigned hc = std::thread::hardware_concurrency();
    if (hc == 0)
    {
      hc = 4;
    }
    return new ThreadPool(hc * 4, hc * 4, std::chrono::seconds(30), 1024);
  }();
  return *pool;
}

// IMMORTAL / deliberately-leaked LoggerData singleton (tracker 2026-07-23-4).
// Never destroyed: the mutex/condition_variables it owns must outlive (1) every
// object with static storage that may log from its OWN destructor — e.g. a sink
// whose ~dtor calls Logger::clearExternalHandler(), the documented teardown
// pattern (scenario 2, a static-destruction-ORDER bug: [basic.start.term] would
// otherwise destroy this singleton FIRST and the later destructor would lock a
// destroyed mutex); and (2) any self-tearer still parked on externalHandlerDone
// when std::exit() runs static destructors from inside a handler (scenario 1).
// This mirrors how the C++ runtime keeps the objects backing std::cout/std::cerr
// alive (std::ios_base::Init) so they outlive user statics that log at teardown.
// Do NOT revert to `static LoggerData data;` and do NOT delete this pointer — that
// reopens BOTH UB paths. The leak is intentional (LSan: intentional immortal).
// atexitReapNoDestroy is registered EXACTLY ONCE here, tied to the magic-static
// initializer, so it fires once regardless of how many times getData() is called;
// it flushes/reaps at exit WITHOUT destroying, replacing the drain/flush the
// (now unreachable) ~LoggerData used to perform. std::atexit is thread-safe and
// the local-static guard serializes concurrent first-callers.
#if defined(IORA_LOGGER_TEST_MUTANT_DESTROY)
// NON-VACUITY MUTANT (tracker 2026-07-23-4, H-1). Test-only: reverts getData() to
// a DESTROYED singleton (heap-allocated so ASan POISONS the freed block, turning
// the scenario-1/scenario-2 UB into a reported heap-use-after-free instead of a
// silent access to intact-but-destroyed static storage). Never defined in a normal
// build; must NEVER appear in production build flags. It deliberately does NOT
// register the atexit reap — it relies on ~LoggerData (via the destroyed singleton)
// for exit-time drain, which is the pre-fix behavior. The scenario-2 probe MUST
// fail/hang against this mutant; a probe that passes here is vacuous. Validate with:
//   cmake -S . -B build-mut -DIORA_BUILD_CORE_TESTS=ON -DIORA_ENABLE_ASAN=ON \
//     -DCMAKE_CXX_FLAGS=-DIORA_LOGGER_TEST_MUTANT_DESTROY
// See the step-0 gate record and test_requirements.
Logger::LoggerData &Logger::getData()
{
  static std::unique_ptr<LoggerData> data = std::unique_ptr<LoggerData>(new LoggerData());
  return *data;
}
#elif defined(IORA_LOGGER_TEST_MUTANT_NOREAP)
// NON-VACUITY MUTANT (tracker 2026-07-23-4, M-1). Test-only: immortal singleton
// (so no destruction UB) but WITHOUT registering the atexit reap — models a build
// where the exit-time flush was removed/neutered. The exit_flush probe MUST fail
// against this mutant (the post-shutdown record is never flushed). Never defined in
// a normal build. Validate with -DCMAKE_CXX_FLAGS=-DIORA_LOGGER_TEST_MUTANT_NOREAP.
Logger::LoggerData &Logger::getData()
{
  static LoggerData *data = new LoggerData();
  return *data;
}
#else
Logger::LoggerData &Logger::getData()
{
  static LoggerData *data = []
  {
    auto *d = new LoggerData();
    if (std::atexit(&Logger::atexitReapNoDestroy) != 0)
    {
      std::cerr << "Logger: std::atexit registration failed; no exit-time flush "
                   "will run"
                << std::endl;
    }
    return d;
  }();
  return *data;
}
#endif

// Single definition of the handler-reentrancy depth (R-12). The frozen-inflight
// tear-out drain branches on this, so it MUST be one instance process-wide —
// including across dlopen'd plugins, which are loaded RTLD_LOCAL.
int &Logger::handlerReentryDepth()
{
  static thread_local int depth = 0;
  return depth;
}

} // namespace core

// IoraService singleton state — single mutex shared by instancePtr() and destroyInstance()
static std::mutex sInstanceMutex;

std::shared_ptr<IoraService> &IoraService::getInstancePtr()
{
  static std::shared_ptr<IoraService> instance;
  return instance;
}

std::shared_ptr<IoraService> IoraService::instancePtr()
{
  std::lock_guard<std::mutex> lock(sInstanceMutex);
  auto &instance = getInstancePtr();
  if (!instance)
  {
    instance = std::shared_ptr<IoraService>(new IoraService());
  }
  return instance;
}

void IoraService::destroyInstance()
{
  std::lock_guard<std::mutex> lock(sInstanceMutex);
  getInstancePtr().reset();
}

// Single process-wide (per-thread) definition of the SafeApiFunction unload
// machinery's thread-local ownership flag (tracker 2026-09-07-1). Defined ONCE
// here — NOT as a header inline variable — because iora.hpp is compiled into the
// host AND into plugin .so's loaded RTLD_LOCAL, and an inline variable does not
// guarantee a single TLS instance across a dlopen boundary. getExportedApiSafe
// reads this to REJECT (throw) a call made while this thread holds
// _loadModulesMutex (a plugin calling it from onLoad) — host-only enforcement, so
// a plugin-resident wrapper can never outlive its .so. Mirrors
// Logger::handlerReentryDepth() above.
bool &IoraService::ownsLoadModulesMutex()
{
  static thread_local bool owns = false;
  return owns;
}

namespace storage {

std::set<JsonFileStore *> &JsonFileStore::registry()
{
  static std::set<JsonFileStore *> s;
  return s;
}

std::mutex &JsonFileStore::registryMutex()
{
  static std::mutex m;
  return m;
}

std::thread &JsonFileStore::flushThread()
{
  static std::thread t;
  return t;
}

std::chrono::milliseconds &JsonFileStore::flushInterval()
{
  static std::chrono::milliseconds ms{2000};
  return ms;
}

std::condition_variable &JsonFileStore::terminationCv()
{
  static std::condition_variable cv;
  return cv;
}

std::mutex &JsonFileStore::terminateCvMutex()
{
  static std::mutex m;
  return m;
}

std::atomic<bool> &JsonFileStore::shouldExit()
{
  static std::atomic<bool> flag{false};
  return flag;
}

} // namespace storage

// ServiceRegistry storage — the single process-wide instance (C-4). Defined here
// exactly once so libiora_core.so and every plugin .so resolve to the same map,
// mirroring IoraService::getInstancePtr / MetricsRegistry::instance. The
// templated set/get/unregister methods stay header-only; only this storage lives
// in the .so. The function-local static and the return type both name the
// PRIVATE NESTED type ServiceRegistry::Storage — legal in this out-of-line
// member definition.
ServiceRegistry::Storage &ServiceRegistry::storage()
{
  static Storage s;
  return s;
}

} // namespace iora
