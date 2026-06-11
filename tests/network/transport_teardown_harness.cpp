// Standalone (non-Catch2) thread-safety harness for the Transport sync-receive /
// connect / teardown buffer-lifecycle hardening (tracker
// IORA-TRANSPORT-RECVSYNC-LIFECYCLE).
//
// WHY STANDALONE: this container has no system Catch2 and iora's fetched
// Catch2 v2.13.10 does not provide Catch2::Catch2WithMain, so iora's own ctest
// cannot build here. The transport + engine are header-only, so this single TU
// compiles the whole stack directly. Build (ASan; TSan cannot run here — the
// container blocks the personality(ADDR_NO_RANDOMIZE) change TSan needs):
//
//   g++ -std=c++17 -fsanitize=address -g -O1 -pthread \
//       -I/workspace/iora/include \
//       tests/network/transport_teardown_harness.cpp -o /tmp/tt_harness \
//       -lssl -lcrypto
//
// ASan catches the teardown use-after-free: Impl is heap-allocated, so a woken
// waiter locking the freed syncMutex / touching freed receiveBuffers is a
// heap-use-after-free. UAF scenarios run as STRESS (many iterations + timing).

#include "iora/network/transport.hpp"
#include "iora/network/transport_impl.hpp"
#include "transport_test_seam.hpp" // S-3 custom-deleter seam (C1-CLOSED observation)

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

using namespace iora::network;
using namespace std::chrono_literals;

// ── Minimal test runner ──────────────────────────────────────────────────────
namespace
{
int g_failures = 0;
int g_run = 0;

#define CHECK(cond)                                                                                \
  do                                                                                               \
  {                                                                                                \
    if (!(cond))                                                                                   \
    {                                                                                              \
      std::printf("  FAIL: %s  (%s:%d)\n", #cond, __FILE__, __LINE__);                              \
      ++g_failures;                                                                                 \
    }                                                                                              \
  } while (0)

void run(const char *name, void (*fn)())
{
  std::printf("[ RUN  ] %s\n", name);
  int before = g_failures;
  ++g_run;
  fn();
  std::printf("[ %s ] %s\n", (g_failures == before) ? " OK " : "FAIL", name);
}

// ── Raw-socket loopback peer ────────────────────────────────────────────────
// A plain POSIX TCP server on 127.0.0.1: accepts one connection, lets the test
// send bytes / close on demand. The Transport-under-test connectSync's to it.
class RawPeer
{
public:
  RawPeer()
  {
    _listen = ::socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    ::setsockopt(_listen, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ::inet_addr("127.0.0.1");
    addr.sin_port = 0; // ephemeral
    ::bind(_listen, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    ::listen(_listen, 4);
    socklen_t len = sizeof(addr);
    ::getsockname(_listen, reinterpret_cast<sockaddr *>(&addr), &len);
    _port = ntohs(addr.sin_port);
  }
  ~RawPeer()
  {
    closeConn();
    if (_listen >= 0)
    {
      ::close(_listen);
    }
  }
  std::uint16_t port() const { return _port; }

  // Block until a client connects (call from a peer thread).
  void accept()
  {
    sockaddr_in caddr{};
    socklen_t clen = sizeof(caddr);
    _conn = ::accept(_listen, reinterpret_cast<sockaddr *>(&caddr), &clen);
  }
  void send(const std::string &s)
  {
    if (_conn >= 0)
    {
      ssize_t n = ::send(_conn, s.data(), s.size(), 0);
      (void)n;
    }
  }
  void closeConn()
  {
    if (_conn >= 0)
    {
      ::close(_conn);
      _conn = -1;
    }
  }

private:
  int _listen{-1};
  int _conn{-1};
  std::uint16_t _port{0};
};

// Connect a started Transport to the peer (peer accepts on its own thread).
SessionId connectToPeer(Transport &t, RawPeer &peer)
{
  std::thread acc([&peer] { peer.accept(); });
  auto r = t.connectSync("127.0.0.1", peer.port(), TlsMode::None, 2000ms);
  acc.join();
  CHECK(r.isOk());
  return r.isOk() ? r.value() : SessionId{0};
}

std::shared_ptr<Transport> startedTcp()
{
  auto t = Transport::tcp(TransportConfig{}); // S-3: shared_ptr<Transport>
  auto s = t->start();
  CHECK(s.isOk());
  return t;
}

// ── Scenarios ────────────────────────────────────────────────────────────────

// S1: drain-before-close — peer sends bytes then closes; the parked receiveSync
// must return the bytes (ok) before any PeerClosed.
void s1_drain_before_close()
{
  auto t = startedTcp();
  RawPeer peer;
  SessionId sid = connectToPeer(*t, peer);
  CHECK(t->setReadMode(sid, ReadMode::Sync));

  peer.send("HELLO");
  peer.closeConn();

  char buf[64];
  std::size_t len = sizeof(buf);
  auto r = t->receiveSync(sid, buf, len, 1000ms);
  CHECK(r.isOk());
  CHECK(len == 5);
  CHECK(std::string(buf, len) == "HELLO");

  // Next call drains remaining (none) and reports PeerClosed.
  len = sizeof(buf);
  auto r2 = t->receiveSync(sid, buf, len, 1000ms);
  CHECK(r2.isErr());
  CHECK(r2.error().code == TransportError::PeerClosed);
}

// S5: overflow surfaces a distinct error (not a silent timeout).
void s5_overflow()
{
  TransportConfig cfg;
  cfg.maxSyncReceiveBuffer = 8; // tiny
  auto t = Transport::tcp(cfg);
  CHECK(t->start().isOk());
  RawPeer peer;
  SessionId sid = connectToPeer(*t, peer);
  CHECK(t->setReadMode(sid, ReadMode::Sync));

  peer.send(std::string(64, 'x')); // exceeds 8

  char buf[128];
  std::size_t len = sizeof(buf);
  auto r = t->receiveSync(sid, buf, len, 1000ms);
  CHECK(r.isErr());
  CHECK(r.error().code == TransportError::BufferOverflow);
}

// S7: second concurrent waiter on the same session is rejected loudly.
void s7_two_waiters()
{
  auto t = startedTcp();
  RawPeer peer;
  SessionId sid = connectToPeer(*t, peer);
  CHECK(t->setReadMode(sid, ReadMode::Sync));

  std::atomic<bool> firstParked{false};
  std::thread w1(
    [&]
    {
      char b[16];
      std::size_t l = sizeof(b);
      firstParked = true;
      t->receiveSync(sid, b, l, 500ms); // parks then times out
    });
  while (!firstParked)
  {
    std::this_thread::yield();
  }
  std::this_thread::sleep_for(50ms); // ensure w1 is parked

  char b2[16];
  std::size_t l2 = sizeof(b2);
  auto r = t->receiveSync(sid, b2, l2, 200ms);
  CHECK(r.isErr());
  CHECK(r.error().code == TransportError::Cancelled); // single-waiter rejection
  w1.join();
}

// S9 (+ S8 observable contract): pure timeout on a still-open session returns
// Timeout (dead-branch removed, M-1), never ok(0) (L-1 fold-back), and honors the
// timeout as a WALL-CLOCK bound — it returns at ~the deadline, not early and not
// much later. (The internal spurious-wake injection of S8 is not reachable from
// outside the Transport; this asserts the externally-observable contract.)
void s9_timeout()
{
  auto t = startedTcp();
  RawPeer peer;
  SessionId sid = connectToPeer(*t, peer);
  CHECK(t->setReadMode(sid, ReadMode::Sync));

  char buf[16];
  std::size_t len = sizeof(buf);
  auto start = std::chrono::steady_clock::now();
  auto r = t->receiveSync(sid, buf, len, 150ms);
  auto elapsed = std::chrono::steady_clock::now() - start;
  CHECK(r.isErr());
  CHECK(r.error().code == TransportError::Timeout); // never ok(0)
  // Wall-clock bound: returned no earlier than the deadline and not absurdly late.
  CHECK(elapsed >= 140ms);
  CHECK(elapsed < 1500ms);
}

// S3f: receiveSync entry-fence — after teardown begins, a fresh receiveSync
// rejects. We approximate "teardown begun" by destroying on another thread and
// confirming a late receiveSync never UAFs (the strong assertion is S3b under
// ASan). Here we check a receiveSync issued during shutdown returns an error.
void s3f_receive_entry_fence_under_stress()
{
  for (int i = 0; i < 50; ++i)
  {
    auto t = Transport::tcp(TransportConfig{});
    CHECK(t->start().isOk());
    RawPeer peer;
    SessionId sid = connectToPeer(*t, peer);
    CHECK(t->setReadMode(sid, ReadMode::Sync));

    std::atomic<bool> parked{false};
    std::thread w(
      [&]
      {
        char b[16];
        std::size_t l = sizeof(b);
        parked = true;
        auto r = t->receiveSync(sid, b, l, 2000ms);
        // Must return cleanly (PeerClosed via stop()'s onClose, or ShuttingDown);
        // never crash / UAF.
        CHECK(r.isErr());
      });
    while (!parked)
    {
      std::this_thread::yield();
    }
    std::this_thread::sleep_for(2ms); // widen the parked window
    t.reset();                        // ~Transport: teardown handshake waits w out
    w.join();
  }
}

// S3b: STRESS — destroy the Transport while a receiveSync is parked. The teardown
// handshake must wait the waiter out; ASan must report NO use-after-free, and the
// waiter returns cleanly. This is the primary teardown-UAF gate (N-1).
void s3b_destroy_during_park_stress()
{
  for (int i = 0; i < 80; ++i)
  {
    auto t = Transport::tcp(TransportConfig{});
    CHECK(t->start().isOk());
    RawPeer peer;
    SessionId sid = connectToPeer(*t, peer);
    CHECK(t->setReadMode(sid, ReadMode::Sync));

    std::atomic<bool> parked{false};
    std::thread w(
      [&]
      {
        char b[64];
        std::size_t l = sizeof(b);
        parked = true;
        auto r = t->receiveSync(sid, b, l, 3000ms);
        // PeerClosed (normal-stop drain-then-EOF) or ShuttingDown — never UAF.
        // The specific PeerClosed-after-clean-drain contract is asserted by s1's
        // second receiveSync (L-A); here we only require no UAF under stress.
        CHECK(r.isErr());
      });
    while (!parked)
    {
      std::this_thread::yield();
    }
    std::this_thread::sleep_for(1ms);
    t.reset(); // destroy while w is parked
    w.join();
  }
}

// S3c: STRESS — destroy the Transport while a connectSync is parked (connecting
// to a non-accepting / slow peer). The teardown handshake must wait the
// connectSync out (activeConnects gate); ASan must report NO use-after-free.
void s3c_connect_during_teardown_stress()
{
  for (int i = 0; i < 80; ++i)
  {
    auto t = Transport::tcp(TransportConfig{});
    CHECK(t->start().isOk());

    // Connect to a port with no listener -> connectSync parks until timeout.
    std::atomic<bool> launched{false};
    std::thread w(
      [&]
      {
        launched = true;
        // 192.0.2.1 (TEST-NET-1) blackholes the SYN -> connectSync stays PARKED
        // for the full timeout, reliably exercising the activeConnects gate. M-1.
        auto r = t->connectSync("192.0.2.1", 80, TlsMode::None, 3000ms);
        CHECK(r.isErr()); // ShuttingDown / Timeout — never UAF/crash
      });
    while (!launched)
    {
      std::this_thread::yield();
    }
    std::this_thread::sleep_for(20ms); // let connectSync register + park
    t.reset();                         // destroy while connectSync is parked
    w.join();
  }
}

// S2: GC-during-park — park a waiter on session A, then close many OTHER sessions
// to exceed the GC threshold so the GC loop runs; A's entry must NOT be erased
// (waiters>0 gate) and the waiter must still receive a subsequent send.
void s2_gc_during_park()
{
  TransportConfig cfg;
  cfg.syncBufferGcThreshold = 8; // small so GC triggers quickly
  auto t = Transport::tcp(cfg);
  CHECK(t->start().isOk());

  RawPeer peerA;
  SessionId sidA = connectToPeer(*t, peerA);
  CHECK(t->setReadMode(sidA, ReadMode::Sync));

  std::atomic<bool> parked{false};
  std::string got;
  std::thread w(
    [&]
    {
      char b[64];
      std::size_t l = sizeof(b);
      parked = true;
      auto r = t->receiveSync(sidA, b, l, 2000ms);
      if (r.isOk())
      {
        got.assign(b, l);
      }
    });
  while (!parked)
  {
    std::this_thread::yield();
  }
  std::this_thread::sleep_for(20ms); // ensure parked

  // Churn other sessions to force GC tombstone reclamation while A is parked.
  std::vector<std::unique_ptr<RawPeer>> peers;
  for (int i = 0; i < 16; ++i)
  {
    auto p = std::make_unique<RawPeer>();
    SessionId s = connectToPeer(*t, *p);
    t->setReadMode(s, ReadMode::Sync);
    p->closeConn(); // triggers onClose -> tombstone -> GC pressure
    peers.push_back(std::move(p));
    std::this_thread::sleep_for(2ms);
  }

  // A's buffer must have survived GC: a send must still reach the parked waiter.
  peerA.send("ALIVE");
  w.join();
  CHECK(got == "ALIVE");
}

// S3d: connectSync activeConnects balance under repeated failures — a failed
// connect must never leave activeConnects>0, so a following teardown must not
// hang. NOTE: TcpEngine::connect() always returns ok(sid) and reports failure
// ASYNCHRONOUSLY via onClose, so these connects fail on the *async* path (parked,
// counted, then released on onClose-err) — NOT the synchronous isErr branch
// (which is unreachable for TCP; see connectSync). This validates the async
// balance; the synchronous-isErr branch is defensive/unreachable for TCP.
void s3d_connect_sync_fail_balance()
{
  auto t = Transport::tcp(TransportConfig{});
  CHECK(t->start().isOk());
  for (int i = 0; i < 20; ++i)
  {
    // Port 1 with no listener -> ECONNREFUSED delivered via onClose; the connect
    // parks briefly then releases. The point is activeConnects returns to 0.
    auto r = t->connectSync("127.0.0.1", 1, TlsMode::None, 200ms);
    CHECK(r.isErr());
  }
  // If activeConnects had leaked, this teardown would hang (caught by the
  // surrounding test timeout).
  t.reset();
  CHECK(true);
}

// S6: GC-during-flush (C-1 gate) — a Sync->Async flush blocks in its onData
// callback (flushing=true, lock released), while OTHER sessions are closed to
// force GC; the flushing entry must NOT be erased and all buffered bytes must be
// delivered to the flush callback.
void s6_gc_during_flush()
{
  TransportConfig cfg;
  cfg.syncBufferGcThreshold = 8;
  auto t = Transport::tcp(cfg);
  std::atomic<int> delivered{0};
  std::atomic<bool> inCb{false};
  std::atomic<bool> release{false};
  t->onData(
    [&](SessionId, iora::core::BufferView d, std::chrono::steady_clock::time_point)
    {
      inCb = true;
      delivered += static_cast<int>(d.size());
      while (!release)
      {
        std::this_thread::sleep_for(1ms);
      }
    });
  CHECK(t->start().isOk());
  RawPeer peer;
  SessionId sid = connectToPeer(*t, peer);
  CHECK(t->setReadMode(sid, ReadMode::Sync));
  peer.send("PAYLOAD"); // 7 bytes buffered in Sync mode
  std::this_thread::sleep_for(5ms);

  std::thread flusher([&] { t->setReadMode(sid, ReadMode::Async); });
  while (!inCb)
  {
    std::this_thread::yield();
  }
  // Flush is mid-callback (flushing=true). Force GC by closing many sessions.
  std::vector<std::unique_ptr<RawPeer>> peers;
  for (int i = 0; i < 16; ++i)
  {
    auto p = std::make_unique<RawPeer>();
    SessionId s = connectToPeer(*t, *p);
    t->setReadMode(s, ReadMode::Sync);
    p->closeConn();
    peers.push_back(std::move(p));
    std::this_thread::sleep_for(1ms);
  }
  release = true; // let the flush finish
  flusher.join();
  CHECK(delivered >= 7); // the buffered PAYLOAD was delivered, not GC'd away
}

// S3e: connectSync concurrent with a reference drop (safe stress). NOTE on the
// entry-fence (INV-8): the *parked-connect* fence (a parked connectSync's
// predicate re-checking shuttingDown) is reliably covered by s3c
// (destroy-during-parked-connect, 192.0.2.1). A *fresh* connectSync hitting the
// fence after teardown began is NOT cleanly testable via the public API: the
// object must be alive to call connectSync, but shuttingDown is only set by
// ~Transport, which then frees the object — calling connectSync after that is a
// user-level UAF the fence cannot protect against. So this scenario keeps the
// Transport alive in the worker (shared_ptr by value → no UAF) and just stresses
// connectSync running while another thread drops its reference; destruction
// happens when the worker releases the last ref. Complements s3c.
void s3e_connect_entry_fence_stress()
{
  for (int i = 0; i < 40; ++i)
  {
    auto t = Transport::tcp(TransportConfig{});
    CHECK(t->start().isOk());
    std::atomic<bool> launched{false};
    std::thread w(
      [t, &launched]
      {
        launched = true;
        // Fast ECONNREFUSED target (returns quickly); the worker holds an owning
        // ref so the object outlives the call — no UAF.
        auto r = t->connectSync("127.0.0.1", 1, TlsMode::None, 100ms);
        CHECK(r.isErr());
      });
    while (!launched)
    {
      std::this_thread::yield();
    }
    t.reset(); // drop main's ref; worker's copy keeps it alive until it returns
    w.join();
  }
}

// S6b: teardown-during-flush — block a setReadMode flush inside the onData
// callback, then destroy the Transport on another thread. The handshake must
// wait the flusher out (activeFlushes gate); ASan must report no use-after-free.
void s6b_teardown_during_flush_stress()
{
  for (int i = 0; i < 40; ++i)
  {
    auto t = Transport::tcp(TransportConfig{});
    std::atomic<bool> inCallback{false};
    std::atomic<bool> release{false};
    // onData callback blocks (simulating a slow consumer) so the Sync->Async
    // flush is in-progress (lock released) when teardown begins.
    t->onData(
      [&](SessionId, iora::core::BufferView, std::chrono::steady_clock::time_point)
      {
        inCallback = true;
        while (!release)
        {
          std::this_thread::sleep_for(1ms);
        }
      });
    CHECK(t->start().isOk());
    RawPeer peer;
    SessionId sid = connectToPeer(*t, peer);
    CHECK(t->setReadMode(sid, ReadMode::Sync));
    peer.send("DATA"); // buffered in Sync mode
    std::this_thread::sleep_for(5ms);

    // Flush on a worker: Sync->Async drains "DATA" via the (blocking) onData cb.
    std::thread flusher([&] { t->setReadMode(sid, ReadMode::Async); });
    while (!inCallback)
    {
      std::this_thread::yield();
    }
    // Destroy on another thread while the flush is blocked in the callback.
    std::thread destroyer(
      [&]
      {
        std::this_thread::sleep_for(2ms);
        release = true; // let the flush proceed so teardown can complete
        t.reset();
      });
    flusher.join();
    destroyer.join();
    CHECK(true); // no ASan UAF
  }
}

// ── Self-destruction-from-I/O-thread scenarios (tracker 2026-06-11-1) ─────────
// A Transport destroyed/move-assigned from INSIDE its own I/O-thread callback.
// Against pre-fix code these UAF (engine freed under its own running dispatch);
// with the deferred-self-destruct fix they must run clean under ASan.

// S4: destroy-from-onClose. A heap-owned Transport whose global onClose callback
// deletes it (on the I/O thread) when the peer closes.
void s4_destroy_from_onclose()
{
  auto *holder = new std::shared_ptr<Transport>();
  *holder = Transport::tcp(TransportConfig{});
  Transport *t = holder->get();
  std::atomic<bool> destroyed{false};
  t->onClose([holder, &destroyed](SessionId, const TransportErrorInfo &)
             {
               holder->reset(); // ~Transport on the I/O thread (deferred self-destruct)
               destroyed = true;
             });
  CHECK(t->start().isOk());
  RawPeer peer;
  SessionId sid = connectToPeer(*t, peer);
  (void)sid;
  peer.closeConn(); // peer EOF -> onClose fires on the I/O thread -> deletes t
  for (int i = 0; i < 2000 && !destroyed; ++i)
  {
    std::this_thread::sleep_for(1ms);
  }
  CHECK(destroyed);
  delete holder; // the unique_ptr was reset; free the holder itself
}

// S4b: destroy-from-onData. The global onData callback deletes the Transport on
// the I/O thread while data is being delivered.
void s4b_destroy_from_ondata()
{
  auto *holder = new std::shared_ptr<Transport>();
  *holder = Transport::tcp(TransportConfig{});
  Transport *t = holder->get();
  std::atomic<bool> destroyed{false};
  t->onData([holder, &destroyed](SessionId, iora::core::BufferView,
                                 std::chrono::steady_clock::time_point)
            {
              if (!destroyed.exchange(true))
              {
                holder->reset(); // ~Transport on the I/O thread
              }
            });
  CHECK(t->start().isOk());
  RawPeer peer;
  SessionId sid = connectToPeer(*t, peer);
  (void)sid;
  peer.send("HELLO"); // -> onData on the I/O thread -> deletes t
  for (int i = 0; i < 2000 && !destroyed; ++i)
  {
    std::this_thread::sleep_for(1ms);
  }
  CHECK(destroyed);
  delete holder;
}

// S4e: setReadMode from the I/O thread must throw std::logic_error (TD-INV-5),
// NOT enter a flush that could self-deadlock teardown. Fixture allows read-mode
// switching so the throw (not the allowReadModeSwitch early-return) is reached.
void s4e_setreadmode_from_iothread_throws()
{
  TransportConfig cfg;
  cfg.allowReadModeSwitch = true;
  auto t = Transport::tcp(cfg);
  std::atomic<bool> threw{false};
  std::atomic<bool> ran{false};
  SessionId seen{0};
  t->onData([&](SessionId sid, iora::core::BufferView, std::chrono::steady_clock::time_point)
           {
             ran = true;
             seen = sid;
             try
             {
               t->setReadMode(sid, ReadMode::Async); // on the I/O thread -> must throw
             }
             catch (const std::logic_error &)
             {
               threw = true;
             }
           });
  CHECK(t->start().isOk());
  RawPeer peer;
  SessionId sid = connectToPeer(*t, peer);
  (void)sid;
  peer.send("X"); // -> onData on the I/O thread
  for (int i = 0; i < 2000 && !ran; ++i)
  {
    std::this_thread::sleep_for(1ms);
  }
  CHECK(ran);
  CHECK(threw); // setReadMode on the I/O thread threw logic_error
}

// S4c-REPLACEMENT (s4c_replacement_H3): the original S4c exercised move-assign-from-
// callback; move-assign is DELETED under S-3, so it is replaced by a SOLE-OWNER
// reset-in-callback scenario with PINNED assertions. A sole-owning shared_ptr is
// dropped from inside its own onClose (on the I/O thread) -> ~Transport runs on the
// I/O thread and takes the deferred-self-destruct: ~Impl is deleted on the DETACHED
// I/O thread's post-loop epilogue, NOT synchronously inside ~Transport. We observe
// via a HEAP-OWNED, test-owned, std::atomic Obs block: the Transport holder is
// captured only as a RAW pointer (cycle invariant), while the NON-Transport Recorder
// and Obs are captured as owning shared_ptrs (not Transports -> no self-cycle).
// Under IORA_DISABLE_SELFDESTRUCT_DEFERRAL this exact scenario ASan-faults (task-5.1).
struct S4cObs
{
  std::atomic<bool> onCloseFired{false};
  std::atomic<bool> dtorRan{false};
  std::atomic<bool> dtorOnIoThread{false}; // ~Transport ran on the I/O thread (sole-owner path)
  std::atomic<std::thread::id> ioThreadId{}; // thread onClose ran on (the I/O thread)
};
void s4c_sole_owner_reset_in_callback()
{
  auto obs = std::make_shared<S4cObs>();

  // SOLE-owning heap holder. Constructed with a CUSTOM DELETER (test seam) that runs
  // exactly when the last ref drops — i.e. inside onClose's holder->reset() on the I/O
  // thread — so it deterministically records the thread on which ~Transport runs. The
  // deleter's `delete p` triggers ~Transport, which (on the I/O thread) takes the
  // deferred-self-destruct: ~Impl is scheduled onto the detached I/O thread's post-loop
  // epilogue, NOT run synchronously here. Under IORA_DISABLE_SELFDESTRUCT_DEFERRAL the
  // synchronous ~Impl UAFs (ASan), which is the deferral proof (task-5.1).
  auto *holder = new std::shared_ptr<Transport>();
  *holder = test::TransportEngineInjector::tcpWithDeleter(
    TransportConfig{},
    [obs](Transport *p)
    {
      if (obs->ioThreadId.load() == std::this_thread::get_id())
      {
        obs->dtorOnIoThread.store(true);
      }
      delete p; // -> ~Transport on the I/O thread -> deferred ~Impl on the detached thread
      obs->dtorRan.store(true);
    });
  Transport *t = holder->get();

  // onClose drops the SOLE ref on the I/O thread. Captures only the RAW holder ptr
  // (NOT an owning shared_ptr<Transport> -> cycle invariant) plus the owning obs.
  t->onClose([holder, obs](SessionId, const TransportErrorInfo &)
             {
               obs->ioThreadId.store(std::this_thread::get_id());
               obs->onCloseFired.store(true);
               holder->reset(); // drop the LAST ref -> deleter runs ~Transport on the I/O thread
             });
  CHECK(t->start().isOk());
  RawPeer peer;
  SessionId sid = connectToPeer(*t, peer);
  (void)sid;
  peer.closeConn(); // peer EOF -> onClose on the I/O thread -> sole-owner reset -> deferral

  for (int i = 0; i < 3000 && !obs->dtorRan.load(); ++i)
  {
    std::this_thread::sleep_for(1ms);
  }
  CHECK(obs->onCloseFired.load());    // onClose ran on the I/O thread
  CHECK(obs->dtorRan.load());         // ~Transport actually ran (no leak / no hang)
  CHECK(obs->dtorOnIoThread.load());  // ~Transport ran on the I/O thread (sole-owner self-destruct)
  delete holder;
}

// C1-CLOSED (HR-9): permanent regression promoting /tmp/c1_repro.cpp Variant B. EVERY
// thread that touches the Transport holds an owning shared_ptr<Transport>; the I/O-
// thread onClose drops a NON-last ref (main's, via a raw holder pointer); a worker
// co-owns and calls stop(); a peer-close races. Because a co-owner always exists across
// the onClose, the onClose drop is NEVER the last ref -> ~Transport CANNOT run on the
// I/O thread. ~Transport's exact thread is observed via a CUSTOM DELETER (test seam);
// asserted never the I/O thread over N stress iters, ASan-clean, watchdog on hang.
struct C1Obs
{
  std::atomic<bool> destroyed{false};
  std::atomic<bool> destroyedOnIoThread{false};
  std::atomic<bool> ioIdKnown{false};
  std::atomic<std::thread::id> ioThreadId{};
};
void c1_closed_shared_ownership_stress()
{
  const int kIters = 200; // ts step-0 L-3: concrete stress count
  for (int i = 0; i < kIters; ++i)
  {
    auto obs = std::make_shared<C1Obs>();
    // Custom deleter records the thread on which ~Transport finally runs. Captures only
    // the owning obs (a NON-Transport) -> no reference cycle.
    auto t = test::TransportEngineInjector::tcpWithDeleter(
      TransportConfig{},
      [obs](Transport *p)
      {
        if (obs->ioIdKnown.load() && std::this_thread::get_id() == obs->ioThreadId.load())
        {
          obs->destroyedOnIoThread.store(true);
        }
        delete p;
        obs->destroyed.store(true);
      });

    // Record the I/O-thread id from a callback (no owning capture of the Transport).
    t->onData([obs](SessionId, iora::core::BufferView, std::chrono::steady_clock::time_point)
              {
                obs->ioThreadId.store(std::this_thread::get_id());
                obs->ioIdKnown.store(true);
              });
    // main's owning ref lives on the heap; onClose drops it via a RAW holder pointer
    // (NOT an owning shared_ptr<Transport> -> cycle invariant).
    auto *holder = new std::shared_ptr<Transport>(t);
    t->onClose([obs, holder](SessionId, const TransportErrorInfo &)
               {
                 obs->ioThreadId.store(std::this_thread::get_id());
                 obs->ioIdKnown.store(true);
                 std::this_thread::yield(); // widen the contended window (ts step-0 L-3)
                 holder->reset();           // drop main's ref — NOT last (worker co-owns)
               });
    CHECK(t->start().isOk());
    RawPeer peer;
    (void)connectToPeer(*t, peer);

    std::thread worker([t] { t->stop(); }); // worker co-owns across the entire stop()
    peer.closeConn();                        // race the peer-close onClose against stop()
    t.reset();                               // drop the local; main's other ref is in *holder
    worker.join();                           // worker's owning copy drops here -> ~Transport off I/O thread

    holder->reset(); // if onClose never fired, drop main's ref now
    delete holder;

    for (int s = 0; s < 3000 && !obs->destroyed.load(); ++s)
    {
      std::this_thread::sleep_for(1ms);
    }
    CHECK(obs->destroyed.load());             // destroyed (no leak / no hang)
    // Non-vacuity guard: a callback MUST have recorded the I/O-thread id this iteration
    // (peer.closeConn() always drives onClose), otherwise the "never on I/O thread"
    // assertion below would pass without ever observing the I/O thread (ts step-4 L-1).
    CHECK(obs->ioIdKnown.load());
    CHECK(!obs->destroyedOnIoThread.load());  // ~Transport NEVER ran on the I/O thread (C-1 CLOSED)
  }
}

// Guard-gating (HR-5/DQ-4): the four sync ops (connectSync/sendSync/receiveSync/
// setReadMode) throw std::logic_error when called on the I/O thread REGARDLESS of
// _running (thread-id-only guard). POSITIVE: invoked from onData (_running==true) AND
// from a stop()-driven shutdownDrain onClose (_running==FALSE). NEGATIVE: invoked from
// a non-I/O thread on a stopped transport -> the guard does NOT false-fire (DQ-4).
void guard_gating_io_thread()
{
  TransportConfig cfg;
  cfg.allowReadModeSwitch = true;
  auto t = Transport::tcp(cfg);

  std::atomic<int> threwOnData{0};  // of 4 ops, how many threw from onData (running==true)
  std::atomic<int> threwOnClose{0}; // of 4 ops, how many threw from onClose (running==false)
  std::atomic<bool> dataRan{false}, closeRan{false};

  auto probe = [](Transport *tp, SessionId sid, std::atomic<int> &counter)
  {
    char buf[8];
    std::size_t len = sizeof(buf);
    const std::uint8_t one = 'x';
    auto count = [&](auto fn) { try { fn(); } catch (const std::logic_error &) { ++counter; } };
    count([&] { tp->connectSync("127.0.0.1", 9, TlsMode::None, 100ms); });
    count([&] { tp->sendSync(sid, iora::core::BufferView{&one, 1}, 100ms); });
    count([&] { tp->receiveSync(sid, buf, len, 100ms); });
    count([&] { tp->setReadMode(sid, ReadMode::Async); });
  };

  t->onData([&](SessionId sid, iora::core::BufferView, std::chrono::steady_clock::time_point)
            {
              probe(t.get(), sid, threwOnData);
              dataRan = true;
            });
  t->onClose([&](SessionId sid, const TransportErrorInfo &)
             {
               probe(t.get(), sid, threwOnClose);
               closeRan = true;
             });
  CHECK(t->start().isOk());
  RawPeer peer;
  SessionId sid = connectToPeer(*t, peer);
  peer.send("X"); // -> onData on the I/O thread (running==true)
  for (int i = 0; i < 2000 && !dataRan; ++i)
  {
    std::this_thread::sleep_for(1ms);
  }
  CHECK(dataRan);
  CHECK(threwOnData.load() == 4); // all 4 sync ops threw on the I/O thread (running==true)

  // stop() clears _running ON the I/O thread, then shutdownDrain fires onClose with
  // _running==FALSE — exercising the thread-id-only guard in the _running==false case.
  t->stop();
  for (int i = 0; i < 2000 && !closeRan; ++i)
  {
    std::this_thread::sleep_for(1ms);
  }
  CHECK(closeRan);
  CHECK(threwOnClose.load() == 4); // all 4 threw on the I/O thread even with _running==false

  // NEGATIVE: from a NON-I/O thread on the stopped/detached transport, none of the 4
  // throws the I/O-thread logic_error (getIoThreadId()==default id post-stop, so a real
  // off-I/O caller never matches it — DQ-4). They may fail for other reasons, not the guard.
  std::atomic<int> falseThrows{0};
  std::thread off(
    [&]
    {
      char buf[8];
      std::size_t len = sizeof(buf);
      const std::uint8_t one = 'x';
      auto noGuardThrow = [&](auto fn)
      {
        try { fn(); }
        catch (const std::logic_error &) { ++falseThrows; }
        catch (...) {}
      };
      noGuardThrow([&] { t->connectSync("127.0.0.1", 9, TlsMode::None, 50ms); });
      noGuardThrow([&] { t->sendSync(1, iora::core::BufferView{&one, 1}, 50ms); });
      noGuardThrow([&] { t->receiveSync(1, buf, len, 50ms); });
      noGuardThrow([&] { t->setReadMode(1, ReadMode::Async); });
    });
  off.join();
  CHECK(falseThrows.load() == 0); // the thread-id guard does not false-fire off the I/O thread
}

// Hard watchdog: a self-deadlock regression (e.g. the setReadMode I/O-thread
// guard removed) would HANG rather than fail a CHECK. Abort loudly instead.
void startWatchdog(int seconds)
{
  std::thread(
    [seconds]
    {
      for (int i = 0; i < seconds * 10; ++i)
      {
        std::this_thread::sleep_for(100ms);
      }
      std::fprintf(stderr, "\nWATCHDOG: harness exceeded %ds — likely a teardown "
                           "self-deadlock. Aborting.\n",
                   seconds);
      std::abort();
    })
    .detach();
}

} // namespace

int main()
{
  startWatchdog(180);
  run("s1_drain_before_close", s1_drain_before_close);
  run("s2_gc_during_park", s2_gc_during_park);
  run("s5_overflow", s5_overflow);
  run("s7_two_waiters", s7_two_waiters);
  run("s9_timeout", s9_timeout);
  run("s3d_connect_sync_fail_balance", s3d_connect_sync_fail_balance);
  run("s6_gc_during_flush", s6_gc_during_flush);
  run("s3e_connect_entry_fence_stress", s3e_connect_entry_fence_stress);
  run("s3f_receive_entry_fence_under_stress", s3f_receive_entry_fence_under_stress);
  run("s3b_destroy_during_park_stress", s3b_destroy_during_park_stress);
  run("s3c_connect_during_teardown_stress", s3c_connect_during_teardown_stress);
  run("s6b_teardown_during_flush_stress", s6b_teardown_during_flush_stress);
  run("s4_destroy_from_onclose", s4_destroy_from_onclose);
  run("s4b_destroy_from_ondata", s4b_destroy_from_ondata);
  run("s4c_sole_owner_reset_in_callback", s4c_sole_owner_reset_in_callback);
  run("s4e_setreadmode_from_iothread_throws", s4e_setreadmode_from_iothread_throws);
  run("c1_closed_shared_ownership_stress", c1_closed_shared_ownership_stress);
  run("guard_gating_io_thread", guard_gating_io_thread);

  std::printf("\n%d scenario(s), %d check failure(s)\n", g_run, g_failures);
  return g_failures == 0 ? 0 : 1;
}
