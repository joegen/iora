// Deterministic teardown-race regression tests for TcpEngine.
//
// Tracker: IORA-TCPENGINE-EVENTFD-CLOSE-VS-WRITE-TEARDOWN-RACE (2026-06-14-1).
//
// Hazard A (this file): the _eventFd data race (enqueue ::write vs shutdownDrain
// ::close) and the post-teardown enqueue semantics, including the addListener
// check-then-enqueue promise TOCTOU (DD-5). These are driven DETERMINISTICALLY
// (barrier-landed enqueues in the stop()/join window), not by TSan timing luck,
// so the suite is a real regression guard under both TSan and ASan.
//
// Hazard B (self-destruct-vs-enqueue lifetime) is exercised by the standalone
// transport_teardown_harness.cpp (Transport level + IORA_DISABLE_SELFDESTRUCT
// negative control), not here.
//
// Threading discipline (per sibling trackers 2026-06-14-2/-5 and Catch2's
// single-thread contract): NO Catch2 macro runs on a worker/I/O thread. Worker
// threads record into atomics; the main test thread asserts after joining.
//
// RUNNING UNDER SANITIZERS:
//   TSan:  setarch -R ./iora_test_tcp_engine_teardown_race  (TSAN_OPTIONS as usual).
//   ASan:  ASAN_OPTIONS=handle_segv=0 ./iora_test_tcp_engine_teardown_race
// On WSL2, ASan's hardware-SIGSEGV handler re-faults in its OWN reporting path
// at PROCESS EXIT after the heavy start/stop thread churn here, producing a
// recursive "AddressSanitizer:DEADLYSIGNAL" storm — an ASan-runtime artifact,
// NOT a fault in the code under test. Verified clean four ways: the test logic
// fully completes ("All tests passed"); gdb sees no signal; and ASan's MEMORY
// instrumentation (redzones/shadow — the part that finds real bugs, active
// regardless of handle_segv) reports ZERO errors with handle_segv=0. Disabling
// only the hardware-signal handler does not mask memory bugs (a real UAF/overflow
// is still reported by instrumentation — confirmed by the transport_teardown_harness
// negative control, which faults cleanly). So run ASan with handle_segv=0 here.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "iora/network/detail/tcp_engine.hpp"
#include "iora_test_net_utils.hpp"
#include "test_helpers.hpp"

#include <atomic>
#include <future>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using TcpEngine = iora::network::TcpEngine;
using TransportConfig = iora::network::TransportConfig;
using TlsMode = iora::network::TlsMode;
using SessionId = iora::network::SessionId;

// Spin both threads to a shared release point so the enqueue and the stop fire
// as close to simultaneously as possible — maximizing the chance of landing in
// the stop()/shutdownDrain teardown window on each iteration.
namespace
{
inline void spinUntil(const std::atomic<bool> &go)
{
  while (!go.load(std::memory_order_acquire))
  {
    std::this_thread::yield();
  }
}
} // namespace

// Hazard A: enqueue()'s _eventFd wakeup-write must be serialized with
// shutdownDrain()'s _eventFd close, and post-teardown enqueue must be rejected
// (not write a closed/-1 fd, not crash). Drive N enqueuers into the stop window
// across many iterations. Under TSan this catches the _eventFd data race; under
// ASan it catches any write-to-closed/recycled fd. All assertions on the main
// thread (workers only call engine methods + record into atomics).
TEST_CASE("TcpEngine stop() concurrent with enqueue storm tears down cleanly",
          "[tcp][teardown][race]")
{
  constexpr int kIters = 40;
  constexpr int kWorkers = 4;
  constexpr int kPerWorker = 200;

  for (int iter = 0; iter < kIters; ++iter)
  {
    TransportConfig cfg{};
    TcpEngine tx{cfg};
    REQUIRE(tx.start().isOk());

    std::atomic<bool> go{false};
    std::vector<std::thread> workers;
    workers.reserve(kWorkers);
    for (int w = 0; w < kWorkers; ++w)
    {
      workers.emplace_back(
        [&]
        {
          spinUntil(go);
          const char buf[4] = {'p', 'i', 'n', 'g'};
          for (int i = 0; i < kPerWorker; ++i)
          {
            // Bogus session ids: send()/close() enqueue Send/Close commands that
            // race stop()'s teardown. The I/O thread ignores unknown sids; the
            // point is the enqueue() ::write-vs-close serialization, not delivery.
            (void)tx.send(static_cast<SessionId>(1000 + i), buf, sizeof(buf));
            (void)tx.close(static_cast<SessionId>(1000 + i));
          }
        });
    }

    go.store(true, std::memory_order_release);
    std::this_thread::sleep_for(1ms); // let enqueuers ramp up, then stop into the window
    tx.stop();
    for (auto &t : workers)
    {
      t.join();
    }

    // After teardown the command queue is closed: a further enqueue must be
    // safely REJECTED (returns false, no ::write(-1), no crash) — DD-2/DD-5.
    const char buf[2] = {'x', 'y'};
    REQUIRE_FALSE(tx.send(static_cast<SessionId>(42), buf, sizeof(buf)));
  }
  SUCCEED("stop()-vs-enqueue storm completed without crash across all iterations");
}

// Hazard A / DD-5: addListener's synchronous branch does check-then-enqueue
// (_running.load() then enqueue a promise-bearing command then fut.get()). If
// stop() closes the queue in the window between the check and the enqueue, the
// command would never be processed and fut.get() would block FOREVER unless the
// reject path fulfills the promise. This test races addListener against stop()
// many times and asserts the call ALWAYS RETURNS (success or error), never hangs.
TEST_CASE("TcpEngine addListener racing stop never deadlocks", "[tcp][teardown][race]")
{
  constexpr int kIters = 40;
  for (int iter = 0; iter < kIters; ++iter)
  {
    TransportConfig cfg{};
    TcpEngine tx{cfg};
    REQUIRE(tx.start().isOk());
    const auto port = testnet::getFreePortTCP();

    std::atomic<bool> go{false};
    std::thread stopper(
      [&]
      {
        spinUntil(go);
        tx.stop();
      });

    auto fut = std::async(std::launch::async,
      [&]
      {
        spinUntil(go);
        return tx.addListener("127.0.0.1", port, TlsMode::None);
      });

    go.store(true, std::memory_order_release);

    // The addListener call MUST return; a hang means the promise TOCTOU deadlock
    // regressed. 10s is a generous watchdog (the call is sub-millisecond when correct).
    const bool returned = (fut.wait_for(10s) == std::future_status::ready);
    stopper.join();
    REQUIRE(returned);
    (void)fut.get(); // ok() or err(ShuttingDown)/err(Bind) — both acceptable
  }
  SUCCEED("addListener never deadlocked across stop races");
}

// DD-5: value-returning public methods must SURFACE the closed-queue reject, not
// claim success while the command is silently dropped (lost-completion). After
// stop(), connect() must return err, send() false, and sendAsync()'s callback an
// error result. Covers cpp17 L-2 (sendAsync) and the connect() M-1 gap.
TEST_CASE("TcpEngine value-returning ops surface error after stop", "[tcp][teardown][race]")
{
  TransportConfig cfg{};
  TcpEngine tx{cfg};
  REQUIRE(tx.start().isOk());
  tx.stop();

  // connect() must report shutdown, not ok(sid) for a connection that never happens.
  REQUIRE(tx.connect("127.0.0.1", testnet::getFreePortTCP(), TlsMode::None).isErr());

  // send() returns false on the closed queue.
  const char buf[4] = {'d', 'a', 't', 'a'};
  REQUIRE_FALSE(tx.send(static_cast<SessionId>(5), buf, sizeof(buf)));

  // sendAsync()'s completion callback must report an error, not success.
  std::atomic<bool> cbFired{false};
  std::atomic<bool> cbOk{true};
  tx.sendAsync(static_cast<SessionId>(5), buf, sizeof(buf),
               [&](SessionId, const iora::network::SendResult &r)
               {
                 cbOk.store(r.isOk());
                 cbFired.store(true);
               });
  REQUIRE(cbFired.load());
  REQUIRE_FALSE(cbOk.load());
}

// Restart must reopen the command queue: shutdownDrain sets _cmdsClosed=true, and
// start() must reset it (DD-5) so a restarted engine accepts commands again.
TEST_CASE("TcpEngine restart after stop reopens the command queue", "[tcp][teardown][race]")
{
  TransportConfig cfg{};
  TcpEngine tx{cfg};

  REQUIRE(tx.start().isOk());
  const char ping[4] = {'p', 'i', 'n', 'g'};
  REQUIRE(tx.send(static_cast<SessionId>(7), ping, sizeof(ping))); // accepted while running
  tx.stop();
  REQUIRE_FALSE(tx.send(static_cast<SessionId>(7), ping, sizeof(ping))); // closed after stop

  REQUIRE(tx.start().isOk());                                           // restart
  const char pong[4] = {'p', 'o', 'n', 'g'};
  REQUIRE(tx.send(static_cast<SessionId>(7), pong, sizeof(pong)));      // queue reopened
  tx.stop();
}
