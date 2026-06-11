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

Transport startedTcp()
{
  auto t = Transport::tcp(TransportConfig{});
  auto s = t.start();
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
  SessionId sid = connectToPeer(t, peer);
  CHECK(t.setReadMode(sid, ReadMode::Sync));

  peer.send("HELLO");
  peer.closeConn();

  char buf[64];
  std::size_t len = sizeof(buf);
  auto r = t.receiveSync(sid, buf, len, 1000ms);
  CHECK(r.isOk());
  CHECK(len == 5);
  CHECK(std::string(buf, len) == "HELLO");

  // Next call drains remaining (none) and reports PeerClosed.
  len = sizeof(buf);
  auto r2 = t.receiveSync(sid, buf, len, 1000ms);
  CHECK(r2.isErr());
  CHECK(r2.error().code == TransportError::PeerClosed);
}

// S5: overflow surfaces a distinct error (not a silent timeout).
void s5_overflow()
{
  TransportConfig cfg;
  cfg.maxSyncReceiveBuffer = 8; // tiny
  auto t = Transport::tcp(cfg);
  CHECK(t.start().isOk());
  RawPeer peer;
  SessionId sid = connectToPeer(t, peer);
  CHECK(t.setReadMode(sid, ReadMode::Sync));

  peer.send(std::string(64, 'x')); // exceeds 8

  char buf[128];
  std::size_t len = sizeof(buf);
  auto r = t.receiveSync(sid, buf, len, 1000ms);
  CHECK(r.isErr());
  CHECK(r.error().code == TransportError::BufferOverflow);
}

// S7: second concurrent waiter on the same session is rejected loudly.
void s7_two_waiters()
{
  auto t = startedTcp();
  RawPeer peer;
  SessionId sid = connectToPeer(t, peer);
  CHECK(t.setReadMode(sid, ReadMode::Sync));

  std::atomic<bool> firstParked{false};
  std::thread w1(
    [&]
    {
      char b[16];
      std::size_t l = sizeof(b);
      firstParked = true;
      t.receiveSync(sid, b, l, 500ms); // parks then times out
    });
  while (!firstParked)
  {
    std::this_thread::yield();
  }
  std::this_thread::sleep_for(50ms); // ensure w1 is parked

  char b2[16];
  std::size_t l2 = sizeof(b2);
  auto r = t.receiveSync(sid, b2, l2, 200ms);
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
  SessionId sid = connectToPeer(t, peer);
  CHECK(t.setReadMode(sid, ReadMode::Sync));

  char buf[16];
  std::size_t len = sizeof(buf);
  auto start = std::chrono::steady_clock::now();
  auto r = t.receiveSync(sid, buf, len, 150ms);
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
    auto t = std::make_unique<Transport>(Transport::tcp(TransportConfig{}));
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
    auto t = std::make_unique<Transport>(Transport::tcp(TransportConfig{}));
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
    auto t = std::make_unique<Transport>(Transport::tcp(TransportConfig{}));
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
  CHECK(t.start().isOk());

  RawPeer peerA;
  SessionId sidA = connectToPeer(t, peerA);
  CHECK(t.setReadMode(sidA, ReadMode::Sync));

  std::atomic<bool> parked{false};
  std::string got;
  std::thread w(
    [&]
    {
      char b[64];
      std::size_t l = sizeof(b);
      parked = true;
      auto r = t.receiveSync(sidA, b, l, 2000ms);
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
    SessionId s = connectToPeer(t, *p);
    t.setReadMode(s, ReadMode::Sync);
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
  auto t = std::make_unique<Transport>(Transport::tcp(TransportConfig{}));
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
  t.onData(
    [&](SessionId, iora::core::BufferView d, std::chrono::steady_clock::time_point)
    {
      inCb = true;
      delivered += static_cast<int>(d.size());
      while (!release)
      {
        std::this_thread::sleep_for(1ms);
      }
    });
  CHECK(t.start().isOk());
  RawPeer peer;
  SessionId sid = connectToPeer(t, peer);
  CHECK(t.setReadMode(sid, ReadMode::Sync));
  peer.send("PAYLOAD"); // 7 bytes buffered in Sync mode
  std::this_thread::sleep_for(5ms);

  std::thread flusher([&] { t.setReadMode(sid, ReadMode::Async); });
  while (!inCb)
  {
    std::this_thread::yield();
  }
  // Flush is mid-callback (flushing=true). Force GC by closing many sessions.
  std::vector<std::unique_ptr<RawPeer>> peers;
  for (int i = 0; i < 16; ++i)
  {
    auto p = std::make_unique<RawPeer>();
    SessionId s = connectToPeer(t, *p);
    t.setReadMode(s, ReadMode::Sync);
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
    auto t = std::make_shared<Transport>(Transport::tcp(TransportConfig{}));
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
    auto t = std::make_unique<Transport>(Transport::tcp(TransportConfig{}));
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

} // namespace

int main()
{
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

  std::printf("\n%d scenario(s), %d check failure(s)\n", g_run, g_failures);
  return g_failures == 0 ? 0 : 1;
}
