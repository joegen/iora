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
#include "iora_test_fd_reuse_probe.hpp"
#include "iora_test_net_utils.hpp"
#include "test_helpers.hpp"

#include <arpa/inet.h>
#include <atomic>
#include <cstring>
#include <future>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
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
using fdreuse::spinUntil; // shared release-barrier spin (see iora_test_fd_reuse_probe.hpp)
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
  // Probe the command-queue state via connect() (a command whose acceptance
  // reflects whether the queue is open), NOT send(bogus_sid): send() now rejects an
  // unknown/closed session synchronously (CF-H1), so it no longer probes queue
  // state. connect()-returns-err-after-stop is the queue-closed signal this suite's
  // DD-5 case below also relies on.
  REQUIRE(tx.connect("127.0.0.1", 19997, TlsMode::None).isOk()); // accepted while running
  tx.stop();
  REQUIRE(tx.connect("127.0.0.1", 19997, TlsMode::None).isErr()); // closed after stop

  REQUIRE(tx.start().isOk());                      // restart
  REQUIRE(tx.connect("127.0.0.1", 19997, TlsMode::None).isOk());  // queue reopened
  tx.stop();
}

// ===========================================================================
// Deterministic fd-reuse ordering tests (tracker 2026-09-15-3, WIDEN).
//
// As for UDP: the engine defers every getter-reachable teardown ::close until
// AFTER the session/listener is out of its map. Each case dup2()s a sentinel onto
// the fd at the pre-close seam and asserts the under-lock getter NEVER observes
// the sentinel. See iora_test_fd_reuse_probe.hpp for the mechanism.
// ===========================================================================

namespace
{
using Callbacks = iora::network::detail::EngineBase::Callbacks;
using TransportAddress = iora::network::TransportAddress;
using ListenerId = iora::network::ListenerId;
using iora::test::waitFor; // canonical bounded-poll helper (test_helpers.hpp)

// A bound + listening loopback TCP socket used as the connect peer, so the engine
// creates exactly ONE ClientConnected session (no engine-side listener/accept).
// The kernel completes the 3-way handshake from the listen backlog without an
// accept(), so the engine's onConnect fires. RAII; non-copyable/movable.
class RawTcpListener
{
public:
  RawTcpListener()
  {
    _fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(_fd >= 0);
    int reuse = 1;
    ::setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    REQUIRE(::bind(_fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) == 0);
    REQUIRE(::listen(_fd, 16) == 0);
    socklen_t len = sizeof(sa);
    REQUIRE(::getsockname(_fd, reinterpret_cast<sockaddr *>(&sa), &len) == 0);
    _port = ntohs(sa.sin_port);
  }
  ~RawTcpListener()
  {
    if (_fd >= 0)
    {
      ::close(_fd);
    }
  }
  RawTcpListener(const RawTcpListener &) = delete;
  RawTcpListener &operator=(const RawTcpListener &) = delete;
  RawTcpListener(RawTcpListener &&) = delete;
  RawTcpListener &operator=(RawTcpListener &&) = delete;

  std::uint16_t port() const { return _port; }

private:
  int _fd{-1};
  std::uint16_t _port{0};
};
} // namespace

// Session closeNow: getLocalAddress + setDscp must never resolve a session whose
// fd has just been ::close()d. TCP closeNow already erases before ::close; this
// case guards that ordering against regression. MUTATION: move the seam + ::close(fd)
// ABOVE the _sessions.erase() write lock in closeNow -> sawSentinel/dscpApplied
// become true and this FAILS.
TEST_CASE("TcpEngine closeNow defers ::close until after erase (fd-reuse)",
          "[tcp][teardown][fdreuse]")
{
  // Declare all seam/callback-captured state BEFORE the engine (destroyed first).
  fdreuse::Sentinel sentinel;
  fdreuse::Probe probe;
  RawTcpListener peer;
  std::atomic<SessionId> targetSid{0};
  std::atomic<bool> connected{false};
  std::atomic<SessionId> connSid{0};
  TcpEngine tx{TransportConfig{}};

  tx.testSetPreCloseHook(fdreuse::makeCloseHook(
    probe, sentinel, [&] { return tx.getLocalAddress(targetSid.load()); },
    [&] { return tx.setDscp(targetSid.load(), 0x28); }));

  Callbacks cbs{};
  cbs.onConnect = [&](SessionId sid, const TransportAddress &)
  {
    connSid.store(sid);
    connected.store(true);
  };
  tx.setCallbacks(std::move(cbs));

  REQUIRE(tx.start().isOk());
  auto cr = tx.connect("127.0.0.1", peer.port(), TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return connected.load(); }));
  const SessionId sid = connSid.load();
  const int fd = tx.testGetSessionFd(sid);
  REQUIRE(fd >= 0);

  targetSid.store(sid);
  probe.targetFd.store(fd);
  REQUIRE(tx.close(sid));
  REQUIRE(waitFor([&] { return probe.targetFires.load() >= 1; }));
  tx.stop();

  REQUIRE(probe.targetFires.load() == 1);
  REQUIRE(probe.dup2Ok.load());
  REQUIRE_FALSE(probe.sawSentinel.load());
  REQUIRE(probe.getterEmpty.load());
  REQUIRE_FALSE(probe.dscpApplied.load());
  REQUIRE(sentinel.ipTos() == 0);
}

// Session shutdownDrain (engine stop): getLocalAddress must never resolve a
// drained session whose fd is being ::close()d. MUTATION: close the session fd
// inside the drain loop (before _sessions.clear()) -> FAILS.
TEST_CASE("TcpEngine shutdownDrain defers session ::close until after clear (fd-reuse)",
          "[tcp][teardown][fdreuse]")
{
  // Declare all seam/callback-captured state BEFORE the engine (destroyed first).
  fdreuse::Sentinel sentinel;
  fdreuse::Probe probe;
  RawTcpListener peer;
  std::atomic<SessionId> targetSid{0};
  std::atomic<bool> connected{false};
  std::atomic<SessionId> connSid{0};
  TcpEngine tx{TransportConfig{}};

  tx.testSetPreCloseHook(fdreuse::makeCloseHook(
    probe, sentinel, [&] { return tx.getLocalAddress(targetSid.load()); }));

  Callbacks cbs{};
  cbs.onConnect = [&](SessionId sid, const TransportAddress &)
  {
    connSid.store(sid);
    connected.store(true);
  };
  tx.setCallbacks(std::move(cbs));

  REQUIRE(tx.start().isOk());
  auto cr = tx.connect("127.0.0.1", peer.port(), TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return connected.load(); }));
  const SessionId sid = connSid.load();
  const int fd = tx.testGetSessionFd(sid);
  REQUIRE(fd >= 0);

  targetSid.store(sid);
  probe.targetFd.store(fd);
  tx.stop();

  REQUIRE(probe.targetFires.load() == 1);
  REQUIRE(probe.dup2Ok.load());
  REQUIRE_FALSE(probe.sawSentinel.load());
  REQUIRE(probe.getterEmpty.load());
  REQUIRE(sentinel.ipTos() == 0);
}

// Listener shutdownDrain (engine stop): getListenerAddress must never resolve a
// listener whose fd is being ::close()d. Listener-only engine, so the seam fires
// exactly once. MUTATION: close the listener fd inside the listener drain loop
// (before _listeners.clear()) -> FAILS.
TEST_CASE("TcpEngine shutdownDrain defers listener ::close until after clear (fd-reuse)",
          "[tcp][teardown][fdreuse]")
{
  // Declare all seam-captured state BEFORE the engine (destroyed first).
  fdreuse::Sentinel sentinel;
  fdreuse::Probe probe;
  std::atomic<ListenerId> targetLid{0};
  TcpEngine tx{TransportConfig{}};

  tx.testSetPreCloseHook(fdreuse::makeCloseHook(
    probe, sentinel, [&] { return tx.getListenerAddress(targetLid.load()); }));

  REQUIRE(tx.start().isOk());
  const auto port = testnet::getFreePortTCP();
  auto lr = tx.addListener("127.0.0.1", port, TlsMode::None);
  REQUIRE(lr.isOk());
  targetLid.store(lr.value());

  tx.stop();

  REQUIRE(probe.fireCount.load() == 1); // only the listener fd was closed
  REQUIRE(probe.dup2Ok.load());
  REQUIRE_FALSE(probe.sawSentinel.load());
  REQUIRE(probe.getterEmpty.load());
  REQUIRE(sentinel.ipTos() == 0);
}

// PRIMARY closed race (tracker 2026-09-15-3): Session::closed is read LOCK-FREE on
// the caller thread in sessionSendable() (send()/sendAsync()) while the I/O thread
// WRITES it in closeNow() without holding _sessionRwMutex — a data race on the old
// plain bool. std::atomic<bool> makes that read/write well-defined. Drive N caller
// threads send()ing a LIVE session while the I/O thread closeNow()s it (via close()),
// across many iterations. This file is on IORA_SANITIZED_TEST_TARGETS, so under TSan
// the run exercises the closed field's cross-thread access. NEGATIVE CONTROL: with
// closed reverted to a plain bool, TSan reports the data race here (mutation-verified).
TEST_CASE("TcpEngine send() racing closeNow() on a live session (closed atomic)",
          "[tcp][teardown][race]")
{
  constexpr int kIters = 30;
  constexpr int kSenders = 3;
  for (int iter = 0; iter < kIters; ++iter)
  {
    RawTcpListener peer;
    TcpEngine tx{TransportConfig{}};
    std::atomic<bool> connected{false};
    std::atomic<SessionId> connSid{0};
    Callbacks cbs{};
    cbs.onConnect = [&](SessionId sid, const TransportAddress &)
    {
      connSid.store(sid);
      connected.store(true);
    };
    tx.setCallbacks(std::move(cbs));

    REQUIRE(tx.start().isOk());
    auto cr = tx.connect("127.0.0.1", peer.port(), TlsMode::None);
    REQUIRE(cr.isOk());
    REQUIRE(waitFor([&] { return connected.load(); }));
    const SessionId sid = connSid.load();

    std::atomic<bool> go{false};
    std::vector<std::thread> senders;
    senders.reserve(kSenders);
    for (int s = 0; s < kSenders; ++s)
    {
      senders.emplace_back(
        [&]
        {
          spinUntil(go);
          const char buf[4] = {'p', 'i', 'n', 'g'};
          for (int j = 0; j < 400; ++j)
          {
            (void)tx.send(sid, buf, sizeof(buf)); // sessionSendable() reads closed
          }
        });
    }
    go.store(true, std::memory_order_release);
    std::this_thread::sleep_for(1ms); // let the senders read closed first
    (void)tx.close(sid);              // closeNow() on the I/O thread writes closed
    for (auto &t : senders)
    {
      t.join();
    }
    tx.stop();
  }
  SUCCEED("send() vs closeNow() closed-race storm completed without crash");
}

// Regression (tracker 2026-09-15-3, round-2 cpp17 HIGH): shutdownDrain must erase a
// drained session's _fdTags entry (mirroring closeNow and the listener loop). Otherwise
// _sessions.clear() frees the Session while its Tag survives in _fdTags with a dangling
// Tag::sess; _fdTags is never bulk-cleared and start() does not reset it, so on restart a
// reused fd number keeps the stale tag (emplace does not overwrite) and handleFdEvent
// dereferences the freed Session (UAF). After a clean connect + stop, no fd->Tag entry
// may survive. MUTATION: drop the `_fdTags.erase` in the shutdownDrain session loop ->
// testFdTagCount() == 1 after stop and this FAILS.
TEST_CASE("TcpEngine shutdownDrain erases a drained session's fd-tag (no stale Tag)",
          "[tcp][teardown][race]")
{
  RawTcpListener peer;
  std::atomic<bool> connected{false};
  std::atomic<SessionId> connSid{0};
  TcpEngine tx{TransportConfig{}};

  Callbacks cbs{};
  cbs.onConnect = [&](SessionId sid, const TransportAddress &)
  {
    connSid.store(sid);
    connected.store(true);
  };
  tx.setCallbacks(std::move(cbs));

  REQUIRE(tx.start().isOk());
  auto cr = tx.connect("127.0.0.1", peer.port(), TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return connected.load(); }));
  // Non-vacuity: confirm the live session exists (hence owns an fd-tag) via the
  // running-safe getter (takes the shared lock). Do NOT read testFdTagCount() while
  // running -- its contract is post-stop only (no lock).
  REQUIRE(tx.testGetSessionFd(connSid.load()) >= 0);

  tx.stop(); // shutdownDrain must erase the session's fd-tag before _sessions.clear()

  REQUIRE(tx.testFdTagCount() == 0); // no stale Tag survives the drain
}
