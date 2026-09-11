// Transport code-fix coverage (trackers C1-C5 + round-2 review fixes, 2026-09-11):
//   C1  dscpValue applied at socket creation      -- verified via getsockopt(IP_TOS)
//                                                     on the connected + accepted fds
//   C2  maxPendingSyncOps enforced across all 3 sync ops (+ decrement/reuse, no leak)
//   C3  stop()/addListener() reject on the I/O thread (identity-alone guard)
//   C4  sendSync: I/O-thread guard; false-success on a dead session fixed (CF-H1);
//       Timeout + ShuttingDown + teardown-gate paths (via a deferred-completion
//       engine, since the real engines complete synchronously) -- CF-M5.
// C5 (ReadMode::Disabled fd-level suppression) is covered by the existing
// "Disabled mode suppresses reads" case in iora_test_transport.cpp.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/network/transport_impl.hpp"
#include "transport_test_seam.hpp"
#include "iora_test_net_utils.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace iora::network;
using namespace std::chrono_literals;

static bool waitFor(std::function<bool()> pred, std::chrono::milliseconds timeout = 2000ms)
{
  auto deadline = std::chrono::steady_clock::now() + timeout;
  while (!pred())
  {
    if (std::chrono::steady_clock::now() > deadline)
    {
      return false;
    }
    std::this_thread::sleep_for(1ms);
  }
  return true;
}

// A TcpEngine whose sendAsync DEFERS the completion (stores it) instead of firing it
// synchronously, so a parked Transport::sendSync can be driven through its Timeout /
// ShuttingDown / teardown-gate branches -- which are unreachable with the real
// synchronous-completion engines (CF-M5). Only sendAsync is overridden; every other
// engine behavior is the real TcpEngine.
class DeferredSendEngine : public iora::network::TcpEngine
{
public:
  explicit DeferredSendEngine(const TransportConfig &cfg) : TcpEngine(cfg) {}

  void sendAsync(SessionId sid, const void *data, std::size_t len, SendCompleteCallback cb) override
  {
    (void)data;
    (void)len;
    std::lock_guard<std::mutex> lk(_m);
    _pending.emplace_back(sid, std::move(cb));
  }

  std::size_t pendingCount()
  {
    std::lock_guard<std::mutex> lk(_m);
    return _pending.size();
  }

  // Fire every deferred completion with `r` (invoked from the test thread).
  void fireAll(const SendResult &r)
  {
    std::vector<std::pair<SessionId, SendCompleteCallback>> pend;
    {
      std::lock_guard<std::mutex> lk(_m);
      pend.swap(_pending);
    }
    for (auto &p : pend)
    {
      if (p.second)
      {
        p.second(p.first, r);
      }
    }
  }

private:
  std::mutex _m;
  std::vector<std::pair<SessionId, SendCompleteCallback>> _pending;
};

// Shared DSCP assertion for C1 (IPv4) and F-4 (IPv6): a CS3-configured transport
// connects to `addr`; getsockopt(level, optname) on BOTH the connected client fd and
// the accepted server fd must read back the CS3 mark (24<<2). Local readback, so it
// does not depend on egress observation (unavailable on this WSL2 host).
static void expectDscpMarksSockets(const char *addr, int level, int optname)
{
  const std::uint16_t port = testnet::getFreePortTCP();

  TransportConfig scfg;
  scfg.protocol = Protocol::TCP;
  scfg.dscpValue = 24; // CS3
  auto sEng = std::make_unique<TcpEngine>(scfg);
  TcpEngine *sEngRaw = sEng.get();
  auto server = test::TransportEngineInjector::withEngine(std::move(sEng), scfg);
  std::atomic<SessionId> serverSid{0};
  server->onAccept([&](SessionId s, const TransportAddress &) { serverSid = s; });
  REQUIRE(server->start().isOk());
  REQUIRE(server->addListener(addr, port).isOk());

  TransportConfig ccfg;
  ccfg.protocol = Protocol::TCP;
  ccfg.dscpValue = 24; // CS3
  auto cEng = std::make_unique<TcpEngine>(ccfg);
  TcpEngine *cEngRaw = cEng.get();
  auto client = test::TransportEngineInjector::withEngine(std::move(cEng), ccfg);
  REQUIRE(client->start().isOk());

  auto conn = client->connectSync(addr, port, TlsMode::None, 5000ms);
  REQUIRE(conn.isOk());
  const SessionId clientSid = conn.value();
  REQUIRE(waitFor([&] { return serverSid.load() != 0; }));

  const int clientFd = cEngRaw->testGetSessionFd(clientSid);
  const int serverFd = sEngRaw->testGetSessionFd(serverSid.load());
  REQUIRE(clientFd >= 0);
  REQUIRE(serverFd >= 0);

  int cval = -1;
  int sval = -1;
  socklen_t clen = sizeof(cval);
  socklen_t slen = sizeof(sval);
  REQUIRE(::getsockopt(clientFd, level, optname, &cval, &clen) == 0);
  REQUIRE(::getsockopt(serverFd, level, optname, &sval, &slen) == 0);
  REQUIRE(cval == (24 << 2)); // CS3 => TOS/traffic-class byte 0x60 (96)
  REQUIRE(sval == (24 << 2));

  client->stop();
  server->stop();
}

// ── C1: config.dscpValue is applied to the connected AND accepted data sockets ────
// getsockopt(IP_TOS) on the local fd reads back the value set at socket creation and
// does NOT depend on packet delivery (egress TOS is unobservable on this WSL2 host).
// The fds are reached via the engines' test-only testGetSessionFd accessor.
TEST_CASE("C1: dscpValue marks the connected and accepted sockets (CS3)", "[transport][dscp]")
{
  expectDscpMarksSockets("127.0.0.1", IPPROTO_IP, IP_TOS);
}

// ── C2: maxPendingSyncOps enforced, across ops, with decrement/reuse and no leak ──
TEST_CASE("C2: maxPendingSyncOps rejects excess sync ops (connectSync)", "[transport][sync][cap]")
{
  TransportConfig cfg;
  cfg.maxPendingSyncOps = 1;
  auto t = Transport::tcp(std::move(cfg));
  REQUIRE(t->start().isOk());

  std::atomic<bool> parked{false};
  std::atomic<bool> firstDone{false};
  std::thread first(
    [&]
    {
      parked = true;
      auto r = t->connectSync("192.0.2.1", 9, TlsMode::None, 4000ms); // RFC 5737 unroutable
      (void)r;
      firstDone = true;
    });
  REQUIRE(waitFor([&] { return parked.load(); }));
  std::this_thread::sleep_for(150ms);

  auto second = t->connectSync("192.0.2.1", 9, TlsMode::None, 4000ms);
  REQUIRE(second.isErr());
  REQUIRE(second.error().code == TransportError::TooManyPendingSyncOps);

  t->stop(); // wakes the parked connectSync via the teardown fence
  REQUIRE(waitFor([&] { return firstDone.load(); }, 5000ms));
  first.join();
}

TEST_CASE("C2: cap applies to receiveSync and is released on completion (reuse)",
          "[transport][sync][cap]")
{
  const std::uint16_t port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  std::atomic<SessionId> serverSid{0};
  server->onAccept([&](SessionId s, const TransportAddress &) { serverSid = s; });
  server->onData([](SessionId, iora::core::BufferView, std::chrono::steady_clock::time_point) {});
  REQUIRE(server->start().isOk());
  REQUIRE(server->addListener("127.0.0.1", port).isOk());

  TransportConfig ccfg;
  ccfg.maxPendingSyncOps = 1;
  auto client = Transport::tcp(std::move(ccfg));
  REQUIRE(client->start().isOk());
  auto conn = client->connectSync("127.0.0.1", port, TlsMode::None, 5000ms);
  REQUIRE(conn.isOk());
  const SessionId sid = conn.value();
  REQUIRE(client->setReadMode(sid, ReadMode::Sync));

  // Park one receiveSync (no data arrives) to occupy the single cap slot.
  std::atomic<bool> parked{false};
  std::atomic<bool> firstDone{false};
  std::thread first(
    [&]
    {
      char buf[16];
      std::size_t len = sizeof(buf);
      parked = true;
      auto r = client->receiveSync(sid, buf, len, 3000ms);
      (void)r;
      firstDone = true;
    });
  REQUIRE(waitFor([&] { return parked.load(); }));
  std::this_thread::sleep_for(150ms);

  // A concurrent sendSync must be cap-rejected while the receiveSync is parked.
  const char *msg = "x";
  auto capped = client->sendSync(
    sid, iora::core::BufferView{reinterpret_cast<const std::uint8_t *>(msg), 1}, 1000ms);
  REQUIRE(capped.isErr());
  REQUIRE(capped.error().code == TransportError::TooManyPendingSyncOps);

  // Let the parked receiveSync time out, freeing the slot (decrement).
  REQUIRE(waitFor([&] { return firstDone.load(); }, 5000ms));
  first.join();

  // Reuse: a new sync op now succeeds (the cap was released, not leaked).
  auto reused = client->sendSync(
    sid, iora::core::BufferView{reinterpret_cast<const std::uint8_t *>(msg), 1}, 2000ms);
  REQUIRE(reused.isOk());

  client->stop();
  server->stop();
}

// ── C3: stop()/addListener() reject on the I/O thread ─────────────────────────────
TEST_CASE("C3: stop()/addListener() throw when called on the I/O thread", "[transport][guard]")
{
  const std::uint16_t port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();

  std::atomic<bool> stopThrew{false};
  std::atomic<bool> addListenerThrew{false};
  std::atomic<bool> ran{false};

  client->onConnect(
    [&](SessionId, const TransportAddress &)
    {
      try
      {
        client->stop();
      }
      catch (const std::logic_error &)
      {
        stopThrew = true;
      }
      try
      {
        client->addListener("127.0.0.1", 0);
      }
      catch (const std::logic_error &)
      {
        addListenerThrew = true;
      }
      ran = true;
    });

  server->onAccept([](SessionId, const TransportAddress &) {});
  REQUIRE(server->start().isOk());
  REQUIRE(server->addListener("127.0.0.1", port).isOk());
  REQUIRE(client->start().isOk());
  REQUIRE(client->connect("127.0.0.1", port).isOk());

  REQUIRE(waitFor([&] { return ran.load(); }));
  REQUIRE(stopThrew.load());
  REQUIRE(addListenerThrew.load());

  client->stop();
  server->stop();
}

// ── C4: sendSync guards, dead-session failure, and deferred-completion paths ──────
TEST_CASE("C4: sendSync throws when called on the I/O thread", "[transport][sync][send]")
{
  const std::uint16_t port = testnet::getFreePortTCP();
  auto server = Transport::tcp();
  auto client = Transport::tcp();
  std::atomic<bool> threw{false};
  std::atomic<bool> ran{false};

  server->onAccept([](SessionId, const TransportAddress &) {});
  server->onData(
    [&](SessionId s, iora::core::BufferView, std::chrono::steady_clock::time_point)
    {
      const char *m = "x";
      try
      {
        server->sendSync(s, iora::core::BufferView{reinterpret_cast<const std::uint8_t *>(m), 1},
                         100ms);
      }
      catch (const std::logic_error &)
      {
        threw = true;
      }
      ran = true;
    });

  REQUIRE(server->start().isOk());
  REQUIRE(server->addListener("127.0.0.1", port).isOk());
  REQUIRE(client->start().isOk());
  auto conn = client->connectSync("127.0.0.1", port, TlsMode::None, 5000ms);
  REQUIRE(conn.isOk());
  REQUIRE(client->send(conn.value(), "go", 2));

  REQUIRE(waitFor([&] { return ran.load(); }));
  REQUIRE(threw.load());

  client->stop();
  server->stop();
}

TEST_CASE("C4/CF-H1: sendSync to an unknown/closed session returns an error",
          "[transport][sync][send]")
{
  auto t = Transport::tcp();
  REQUIRE(t->start().isOk());

  const char *msg = "x";
  auto r = t->sendSync(999999 /* never opened */,
                       iora::core::BufferView{reinterpret_cast<const std::uint8_t *>(msg), 1},
                       500ms);
  REQUIRE(r.isErr());
  REQUIRE(r.error().code == TransportError::Socket); // "session not connected" (CF-H1)

  t->stop();
}

TEST_CASE("C4/CF-M5: sendSync times out when the completion never fires",
          "[transport][sync][send][deferred]")
{
  TransportConfig cfg;
  cfg.protocol = Protocol::TCP;
  auto eng = std::make_unique<DeferredSendEngine>(cfg);
  DeferredSendEngine *engRaw = eng.get();
  auto t = test::TransportEngineInjector::withEngine(std::move(eng), cfg);
  REQUIRE(t->start().isOk());

  const char *msg = "x";
  auto begin = std::chrono::steady_clock::now();
  auto r = t->sendSync(1, iora::core::BufferView{reinterpret_cast<const std::uint8_t *>(msg), 1},
                       300ms);
  auto elapsed = std::chrono::steady_clock::now() - begin;

  REQUIRE(r.isErr());
  REQUIRE(r.error().code == TransportError::Timeout);
  REQUIRE(elapsed >= 250ms);  // it actually waited the timeout (not an immediate return)
  REQUIRE(elapsed < 3000ms);  // and honored it (not the old 30 s default / infinite)
  REQUIRE(engRaw->pendingCount() == 1); // the deferred completion was captured, never fired

  t->stop();
}

TEST_CASE("C4/CF-M5: a parked sendSync is woken with ShuttingDown by teardown (gate)",
          "[transport][sync][send][deferred]")
{
  TransportConfig cfg;
  cfg.protocol = Protocol::TCP;
  auto eng = std::make_unique<DeferredSendEngine>(cfg);
  DeferredSendEngine *engRaw = eng.get();
  auto t = test::TransportEngineInjector::withEngine(std::move(eng), cfg);
  REQUIRE(t->start().isOk());

  // Park sendSync on a worker holding only a RAW pointer, so the main thread owns the
  // last shared_ptr. The activeSends teardown gate keeps _impl alive until sendSync
  // returns, so the raw pointer is valid for the duration of the parked call.
  Transport *raw = t.get();
  std::atomic<int> code{-999};
  std::atomic<bool> done{false};
  std::thread worker(
    [&]
    {
      const char *m = "x";
      auto r = raw->sendSync(1, iora::core::BufferView{reinterpret_cast<const std::uint8_t *>(m), 1},
                             5000ms);
      code = static_cast<int>(r.error().code);
      done = true;
    });

  // Wait until sendSync has parked (its deferred sendAsync ran).
  REQUIRE(waitFor([&] { return engRaw->pendingCount() >= 1; }, 3000ms));

  // Drop the last owning reference -> ~Transport -> teardown fence wakes the parked
  // sendSync with ShuttingDown; teardownWaitOut blocks until activeSends hits 0.
  t.reset();

  REQUIRE(waitFor([&] { return done.load(); }, 5000ms));
  worker.join();
  REQUIRE(code.load() == static_cast<int>(TransportError::ShuttingDown));
}

// ── F-1: UDP connectSync returns a sendable session (no sleep / no onConnect await) ──
// CF-H1 initially broke this (the enqueue-time sessionSendable check raced the async
// UDP session insert). connectSync now parks until onConnect for UDP too, so the sid
// is usable on return. Also exercises send()'s bool for a live vs dead session (F-5).
TEST_CASE("F-1: UDP connectSync yields an immediately-sendable session", "[transport][udp][sync]")
{
  const std::uint16_t port = testnet::getFreePortUDP();
  auto server = Transport::udp();
  std::atomic<int> serverRx{0};
  server->onData([&](SessionId, iora::core::BufferView d, std::chrono::steady_clock::time_point)
                 { serverRx += static_cast<int>(d.size()); });
  REQUIRE(server->start().isOk());
  REQUIRE(server->addListener("127.0.0.1", port).isOk());

  auto client = Transport::udp();
  REQUIRE(client->start().isOk());

  auto conn = client->connectSync("127.0.0.1", port, TlsMode::None, 2000ms);
  REQUIRE(conn.isOk());
  const SessionId sid = conn.value();

  // Immediately — no sleep, no onConnect callback wait. The returned sid must be usable.
  const char *msg = "udp-ping";
  auto sent = client->sendSync(
    sid, iora::core::BufferView{reinterpret_cast<const std::uint8_t *>(msg), std::strlen(msg)},
    2000ms);
  REQUIRE(sent.isOk());
  REQUIRE(waitFor([&] { return serverRx.load() >= static_cast<int>(std::strlen(msg)); }));

  // F-5: send()'s bool is load-bearing for CF-H1 — true on the live session, false on
  // a never-opened one.
  REQUIRE(client->send(sid, msg, std::strlen(msg)));
  REQUIRE_FALSE(client->send(999999, msg, std::strlen(msg)));

  client->stop();
  server->stop();
}

// ── F-4 (MEDIUM): the AF_INET6 DSCP branch marks IPV6_TCLASS ──────────────────────
// C1 covers only the IPv4 (IP_TOS) branch; this exercises the dual-stack v6 path of
// applyDscpToFd via getsockopt(IPV6_TCLASS) on the connected + accepted IPv6 fds.
TEST_CASE("F-4: dscpValue marks an IPv6 socket's IPV6_TCLASS (CS3)", "[transport][dscp][ipv6]")
{
  expectDscpMarksSockets("::1", IPPROTO_IPV6, IPV6_TCLASS);
}

// ── F-2 / CF-M3: the sentinel timeout resolves to config.defaultSyncTimeout ───────
// A parked sendSync given the sentinel must wait ~config.defaultSyncTimeout (proving
// resolveSyncTimeout used the config value), not return immediately or wait 30 s.
TEST_CASE("F-2: sentinel sync timeout resolves to config.defaultSyncTimeout",
          "[transport][sync][deferred]")
{
  TransportConfig cfg;
  cfg.protocol = Protocol::TCP;
  cfg.defaultSyncTimeout = std::chrono::milliseconds{250};
  auto eng = std::make_unique<DeferredSendEngine>(cfg);
  auto t = test::TransportEngineInjector::withEngine(std::move(eng), cfg);
  REQUIRE(t->start().isOk());

  const char *msg = "x";
  auto begin = std::chrono::steady_clock::now();
  // Pass the sentinel explicitly → resolveSyncTimeout must use config (250ms).
  auto r = t->sendSync(1, iora::core::BufferView{reinterpret_cast<const std::uint8_t *>(msg), 1},
                       kUseConfigSyncTimeout);
  auto elapsed = std::chrono::steady_clock::now() - begin;

  REQUIRE(r.isErr());
  REQUIRE(r.error().code == TransportError::Timeout);
  REQUIRE(elapsed >= 200ms);  // waited ~the configured 250ms (not an immediate return)
  REQUIRE(elapsed < 3000ms);  // and not the 30 s fallback floor

  t->stop();
}
