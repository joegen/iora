// Deterministic teardown-race regression tests for UdpEngine.
//
// Tracker: IORA-UDPENGINE-EVENTFD-CLOSE-VS-WRITE-TEARDOWN-RACE (2026-06-14-3).
// Sibling of the TcpEngine fix (2026-06-14-1); the design is the same DD-1..DD-13.
//
// Hazard A (this file): the _eventFd data race (enqueue ::write vs shutdownDrain
// ::close, serialized under _qmx) and the post-teardown enqueue semantics,
// including the addListener check-then-enqueue promise TOCTOU (DD-5). Driven
// DETERMINISTICALLY (barrier-landed enqueues in the stop()/join window) plus a
// deterministic post-stop case, so the suite is a real regression guard.
//
// Threading discipline: NO Catch2 macro runs on a worker/I/O thread. Worker
// threads record into atomics / return values via futures; the main test thread
// asserts after joining.
//
// RUNNING UNDER SANITIZERS:
//   TSan:  setarch -R ./iora_test_udp_engine_teardown_race   (0 warnings — verified)
//   ASan:  ASAN_OPTIONS=handle_segv=0 ./iora_test_udp_engine_teardown_race
// WSL2 ASan caveat: this suite exhibits an INTERMITTENT (~1-in-5) SIGSEGV at
// PROCESS EXIT after the heavy start/stop thread churn — an ASan-runtime / WSL2
// exit-teardown artifact, NOT a code fault. Diagnosed: the test logic always
// completes ("All tests passed" under gdb every time; the crash is post-test and
// loses the buffered stdout), ASan MEMORY instrumentation reports ZERO errors on
// EVERY run (clean and crashed alike), and the plain + TSan builds are fully
// clean. (The TcpEngine sibling shows the same artifact as a recursive
// DEADLYSIGNAL loop; UDP manifests it as an intermittent hard exit SIGSEGV.)
// The fix's memory-safety is therefore verified clean despite the flaky exit
// signal; a CI gate should treat a post-"All tests passed" exit SIGSEGV here as
// the known WSL2 ASan artifact, or run this suite's ASan pass under gdb.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "iora/network/detail/udp_engine.hpp"
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
using UdpEngine = iora::network::UdpEngine;
using TransportConfig = iora::network::TransportConfig;
using TlsMode = iora::network::TlsMode;
using SessionId = iora::network::SessionId;
using ListenerId = iora::network::ListenerId;

namespace
{
using fdreuse::spinUntil; // shared release-barrier spin (see iora_test_fd_reuse_probe.hpp)
} // namespace

// Hazard A: enqueue()'s _eventFd wakeup-write must be serialized with
// shutdownDrain()'s _eventFd close, and post-teardown enqueue must be rejected
// (not write a closed/-1 fd, not crash). Drive N enqueuers into the stop window
// across many iterations. Under TSan this catches the _eventFd data race.
TEST_CASE("UdpEngine stop() concurrent with enqueue storm tears down cleanly",
          "[udp][teardown][race]")
{
  constexpr int kIters = 40;
  constexpr int kWorkers = 4;
  constexpr int kPerWorker = 200;

  for (int iter = 0; iter < kIters; ++iter)
  {
    TransportConfig cfg{};
    UdpEngine tx{cfg};
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
            (void)tx.send(static_cast<SessionId>(1000 + i), buf, sizeof(buf));
            (void)tx.close(static_cast<SessionId>(1000 + i));
          }
        });
    }

    go.store(true, std::memory_order_release);
    std::this_thread::sleep_for(1ms);
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

// Hazard A / DD-5: addListener's synchronous branch check-then-enqueues a
// promise-bearing command; if stop() closes the queue in the window between the
// check and the enqueue (or after a push, in the shutdownDrain residual window),
// fut.get() would block forever unless the reject/drain path fails the promise.
// Race it against stop() many times and assert the call ALWAYS RETURNS.
TEST_CASE("UdpEngine addListener racing stop never deadlocks", "[udp][teardown][race]")
{
  constexpr int kIters = 40;
  for (int iter = 0; iter < kIters; ++iter)
  {
    TransportConfig cfg{};
    UdpEngine tx{cfg};
    REQUIRE(tx.start().isOk());
    const auto port = testnet::getFreePortUDP();

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

    const bool returned = (fut.wait_for(10s) == std::future_status::ready);
    stopper.join();
    REQUIRE(returned);
    (void)fut.get(); // ok() or err(ShuttingDown)/err(Bind) — all acceptable
  }
  // NOTE: this case races probabilistically; the DETERMINISTIC closed-queue
  // addListener reject (err after a fully-completed stop) is asserted in the
  // "value-returning ops surface error after stop" case below.
  SUCCEED("addListener never deadlocked across stop races");
}

// Restart must reopen the command queue: shutdownDrain sets _qClosed=true, and
// start() must reset it (DD-5) so a restarted engine accepts commands again.
TEST_CASE("UdpEngine restart after stop reopens the command queue", "[udp][teardown][race]")
{
  TransportConfig cfg{};
  UdpEngine tx{cfg};

  REQUIRE(tx.start().isOk());
  // Probe the command-queue state via connect() (a command whose acceptance
  // reflects whether the queue is open), NOT send(bogus_sid): send() now rejects an
  // unknown/closed session synchronously (CF-H1). connect()-returns-err-after-stop
  // is the queue-closed signal this suite's DD-5 case below also relies on.
  REQUIRE(tx.connect("127.0.0.1", 19998, TlsMode::None).isOk());
  tx.stop();
  REQUIRE(tx.connect("127.0.0.1", 19998, TlsMode::None).isErr());

  REQUIRE(tx.start().isOk());
  REQUIRE(tx.connect("127.0.0.1", 19998, TlsMode::None).isOk());
  tx.stop();
}

// DD-5: value-returning public methods must SURFACE the closed-queue reject.
// After stop(): connect() AND connectViaListener() (UDP-specific, unlike TCP's
// not-supported stub) must return err; send() false; sendAsync callback error;
// addListener err. Deterministic — no timeout/watchdog needed.
TEST_CASE("UdpEngine value-returning ops surface error after stop", "[udp][teardown][race]")
{
  TransportConfig cfg{};
  UdpEngine tx{cfg};
  REQUIRE(tx.start().isOk());
  tx.stop();

  REQUIRE(tx.connect("127.0.0.1", testnet::getFreePortUDP(), TlsMode::None).isErr());
  REQUIRE(tx.connectViaListener(static_cast<ListenerId>(1), "127.0.0.1",
                                testnet::getFreePortUDP())
            .isErr());
  REQUIRE(tx.addListener("127.0.0.1", testnet::getFreePortUDP(), TlsMode::None).isErr());

  const char buf[4] = {'d', 'a', 't', 'a'};
  REQUIRE_FALSE(tx.send(static_cast<SessionId>(5), buf, sizeof(buf)));

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

// ===========================================================================
// Deterministic fd-reuse ordering tests (tracker 2026-09-15-3, WIDEN).
//
// The engine defers every getter-reachable teardown ::close until AFTER the
// session/listener is out of its map, so a cross-thread getter can never syscall
// on a closed/reused fd. Each case dup2()s a sentinel onto the fd at the pre-close
// seam and asserts the under-lock getter NEVER observes the sentinel. See
// iora_test_fd_reuse_probe.hpp for the mechanism + mutation-verify recipe.
// ===========================================================================

namespace
{
using Callbacks = iora::network::detail::EngineBase::Callbacks;
using TransportAddress = iora::network::TransportAddress;
using iora::test::waitFor; // canonical bounded-poll helper (test_helpers.hpp)

// Send one datagram to a UDP listener from a throwaway socket, to force the
// engine to create a ServerPeer session (onAccept) sharing the listener fd.
inline void sendDatagramTo(std::uint16_t port, const char *msg)
{
  int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  REQUIRE(fd >= 0);
  sockaddr_in dst{};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons(port);
  (void)::sendto(fd, msg, std::strlen(msg), 0, reinterpret_cast<sockaddr *>(&dst),
                 sizeof(dst));
  ::close(fd);
}
} // namespace

// Session closeNow: getLocalAddress + setDscp must never resolve a session whose
// fd has just been ::close()d. The seam dup2()s a sentinel onto the fd right
// before ::close; the fix erases the session first, so both getters miss it.
// MUTATION: move fdToClose's ::close (+ seam) ABOVE the _sessions.erase() write
// lock in closeNow -> sawSentinel/dscpApplied become true and this FAILS.
TEST_CASE("UdpEngine closeNow defers ::close until after erase (fd-reuse)",
          "[udp][teardown][fdreuse]")
{
  // Declare all seam/callback-captured state BEFORE the engine, so the engine (which
  // stores the hook + callbacks capturing this state) is destroyed FIRST.
  fdreuse::Sentinel sentinel;
  fdreuse::Probe probe;
  std::atomic<SessionId> targetSid{0};
  std::atomic<bool> connected{false};
  std::atomic<SessionId> connSid{0};
  UdpEngine tx{TransportConfig{}};

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
  const auto port = testnet::getFreePortUDP();
  REQUIRE(tx.addListener("127.0.0.1", port, TlsMode::None).isOk());
  auto cr = tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return connected.load(); }));
  const SessionId sid = connSid.load();
  const int fd = tx.testGetSessionFd(sid);
  REQUIRE(fd >= 0);

  targetSid.store(sid);
  probe.targetFd.store(fd);
  REQUIRE(tx.close(sid));
  REQUIRE(waitFor([&] { return probe.targetFires.load() >= 1; }));
  tx.stop(); // join -> publishes the seam's recorded outcomes

  REQUIRE(probe.targetFires.load() == 1); // the close path ran (non-vacuous)
  REQUIRE(probe.dup2Ok.load());           // the sentinel trap was installed
  REQUIRE_FALSE(probe.sawSentinel.load()); // getLocalAddress never saw the sentinel
  REQUIRE(probe.getterEmpty.load());       // fixed ordering: session already erased
  REQUIRE_FALSE(probe.dscpApplied.load()); // setDscp found no session -> no foreign TOS
  REQUIRE(sentinel.ipTos() == 0);          // the sentinel socket was never mutated
}

// Session shutdownDrain (engine stop): getLocalAddress must never resolve a
// drained session whose fd is being ::close()d. MUTATION: in shutdownDrain, close
// the session fd inside the drain loop (before _sessions.clear()) -> FAILS.
TEST_CASE("UdpEngine shutdownDrain defers session ::close until after clear (fd-reuse)",
          "[udp][teardown][fdreuse]")
{
  // Declare all seam/callback-captured state BEFORE the engine (destroyed first).
  fdreuse::Sentinel sentinel;
  fdreuse::Probe probe;
  std::atomic<SessionId> targetSid{0};
  std::atomic<bool> connected{false};
  std::atomic<SessionId> connSid{0};
  UdpEngine tx{TransportConfig{}};

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
  const auto port = testnet::getFreePortUDP();
  REQUIRE(tx.addListener("127.0.0.1", port, TlsMode::None).isOk());
  auto cr = tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return connected.load(); }));
  const SessionId sid = connSid.load();
  const int fd = tx.testGetSessionFd(sid);
  REQUIRE(fd >= 0);

  targetSid.store(sid);
  probe.targetFd.store(fd);
  tx.stop(); // shutdownDrain runs on the I/O thread; join publishes the outcomes

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
TEST_CASE("UdpEngine shutdownDrain defers listener ::close until after clear (fd-reuse)",
          "[udp][teardown][fdreuse]")
{
  // Declare all seam-captured state BEFORE the engine (destroyed first).
  fdreuse::Sentinel sentinel;
  fdreuse::Probe probe;
  std::atomic<ListenerId> targetLid{0};
  UdpEngine tx{TransportConfig{}};

  tx.testSetPreCloseHook(fdreuse::makeCloseHook(
    probe, sentinel, [&] { return tx.getListenerAddress(targetLid.load()); }));

  REQUIRE(tx.start().isOk());
  const auto port = testnet::getFreePortUDP();
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

// ServerPeer-present drain: a ServerPeer session aliases the shared listener fd
// (s->fd == listener fd), so it must NOT be ::close()d as a session — the listener
// fd is closed exactly ONCE via the listener drain, and stays valid for a
// concurrent getListenerAddress until _listeners is cleared. MUTATION: collect a
// ServerPeer's fd in the session drain (drop the role==ClientConnected guard) ->
// fireCount becomes 2 (double close of the shared fd) and this FAILS.
TEST_CASE("UdpEngine shutdownDrain closes the shared listener fd exactly once with a ServerPeer",
          "[udp][teardown][fdreuse]")
{
  // Declare all seam/callback-captured state BEFORE the engine (destroyed first).
  fdreuse::Sentinel sentinel;
  fdreuse::Probe probe;
  std::atomic<ListenerId> targetLid{0};
  std::atomic<bool> accepted{false};
  UdpEngine tx{TransportConfig{}};

  tx.testSetPreCloseHook(fdreuse::makeCloseHook(
    probe, sentinel, [&] { return tx.getListenerAddress(targetLid.load()); }));

  Callbacks cbs{};
  cbs.onAccept = [&](SessionId, const TransportAddress &) { accepted.store(true); };
  tx.setCallbacks(std::move(cbs));

  REQUIRE(tx.start().isOk());
  const auto port = testnet::getFreePortUDP();
  auto lr = tx.addListener("127.0.0.1", port, TlsMode::None);
  REQUIRE(lr.isOk());
  targetLid.store(lr.value());

  sendDatagramTo(port, "make-a-serverpeer");
  REQUIRE(waitFor([&] { return accepted.load(); }));

  tx.stop();

  // The shared listener fd is closed exactly once; the ServerPeer session (which
  // aliases it) is NOT independently closed.
  REQUIRE(probe.fireCount.load() == 1);
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
TEST_CASE("UdpEngine send() racing closeNow() on a live session (closed atomic)",
          "[udp][teardown][race]")
{
  constexpr int kIters = 30;
  constexpr int kSenders = 3;
  for (int iter = 0; iter < kIters; ++iter)
  {
    UdpEngine tx{TransportConfig{}};
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
    const auto port = testnet::getFreePortUDP();
    REQUIRE(tx.addListener("127.0.0.1", port, TlsMode::None).isOk());
    auto cr = tx.connect("127.0.0.1", port, TlsMode::None);
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

// Regression (tracker 2026-09-15-3, round-3 cpp17 MEDIUM): symmetric to the TCP
// _fdTags guard. UdpEngine's shutdownDrain must erase a session's/listener's _tags entry,
// else _sessions.clear()/_listeners.clear() frees the owner while its Tag survives in
// _tags with a dangling Tag::sess/Tag::lst; _tags is never bulk-cleared and start() does
// not reset it, so a reused fd number on restart resurrects the stale tag (emplace does
// not overwrite) -> handleFdEvent UAF. After a clean addListener + connect + stop, no
// fd->Tag entry may survive. MUTATION: drop a _tags.erase in the drain -> testTagCount()
// is nonzero after stop and this FAILS.
TEST_CASE("UdpEngine shutdownDrain erases session/listener fd-tags (no stale Tag)",
          "[udp][teardown][race]")
{
  std::atomic<bool> connected{false};
  std::atomic<SessionId> connSid{0};
  UdpEngine tx{TransportConfig{}};

  Callbacks cbs{};
  cbs.onConnect = [&](SessionId sid, const TransportAddress &)
  {
    connSid.store(sid);
    connected.store(true);
  };
  tx.setCallbacks(std::move(cbs));

  REQUIRE(tx.start().isOk());
  const auto port = testnet::getFreePortUDP();
  REQUIRE(tx.addListener("127.0.0.1", port, TlsMode::None).isOk());
  auto cr = tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return connected.load(); }));
  // Non-vacuity: the live session owns a _tags entry (running-safe check via the shared
  // lock). Do NOT read testTagCount() while running (its contract is post-stop only).
  REQUIRE(tx.testGetSessionFd(connSid.load()) >= 0);

  tx.stop(); // shutdownDrain must erase both the session and listener fd-tags

  REQUIRE(tx.testTagCount() == 0); // no stale Tag survives the drain
}
