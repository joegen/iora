// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tracker 2026-09-11-23 (CORE): WebSocketServer upgrade-vs-TRANSPORT-close
// handshake-window race. The race is between onUpgradeRequest (pool worker) and
// the transport onClose -> onUpgradedClose (I/O thread). These tests make it
// deterministic via the WsUpgradePhase seam (pauses the worker at a precise
// phase) plus the onTransportSessionClosed rendezvous hook (signals the I/O
// thread finished the close), and a RAW client socket so we control the
// connect/close timing (a blocking WebSocketClient::connect would hang while the
// worker is paused before the 101).
//
// Scope: transport-close lifecycle core only (P1/P2/P3/P5-transport/P6/P8/P10/
// P13). Inbound-WS-frame and outbound/101 ordering are the split data-plane
// tracker 2026-09-12-2 and are NOT exercised here.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/network/websocket_server.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace iora::network;
using namespace std::chrono_literals;

static std::uint16_t nextPort()
{
  static std::atomic<std::uint16_t> base{static_cast<std::uint16_t>(
    9600 + (std::chrono::steady_clock::now().time_since_epoch().count() % 1000))};
  return base.fetch_add(1);
}

template <typename Pred>
static bool waitFor(Pred pred, std::chrono::milliseconds timeout = 5000ms)
{
  auto deadline = std::chrono::steady_clock::now() + timeout;
  while (!pred())
  {
    if (std::chrono::steady_clock::now() > deadline)
    {
      return false;
    }
    std::this_thread::sleep_for(2ms);
  }
  return true;
}

static std::string upgradeRequest(const char *version = "13")
{
  return std::string("GET / HTTP/1.1\r\n"
                     "Host: 127.0.0.1\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                     "Sec-WebSocket-Version: ") +
         version + "\r\n\r\n";
}

// Open a raw TCP socket to the server. Returns the fd (-1 on failure).
static int rawConnect(std::uint16_t port)
{
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
  {
    return -1;
  }
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
  if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0)
  {
    ::close(fd);
    return -1;
  }
  return fd;
}

static int rawUpgradeConnect(std::uint16_t port, const char *version = "13")
{
  int fd = rawConnect(port);
  if (fd >= 0)
  {
    auto req = upgradeRequest(version);
    ::send(fd, req.data(), req.size(), 0);
  }
  return fd;
}

// Force an RST on close (SO_LINGER with a 0 timeout) instead of a graceful FIN.
static void closeRst(int fd)
{
  struct linger lg{};
  lg.l_onoff = 1;
  lg.l_linger = 0;
  ::setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
  ::close(fd);
}

// Read whatever bytes are available within a short window (non-blocking-ish).
static std::string readAvail(int fd, std::chrono::milliseconds t = 500ms)
{
  std::string out;
  char buf[2048];
  auto deadline = std::chrono::steady_clock::now() + t;
  timeval tv{};
  tv.tv_sec = 0;
  tv.tv_usec = 50 * 1000;
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  while (std::chrono::steady_clock::now() < deadline)
  {
    ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n > 0)
    {
      out.append(buf, static_cast<std::size_t>(n));
    }
    else if (n == 0)
    {
      break; // peer closed
    }
    else
    {
      break; // timeout / would-block
    }
  }
  return out;
}

// WebSocketServer subclass with the fault-injection seam wired to test-driven
// rendezvous primitives. One connection per test (except the double-upgrade test,
// which drives two workers on one connection).
class RaceServer : public WebSocketServer
{
public:
  RaceServer(const std::string &host, std::uint16_t port) : WebSocketServer(host, port) {}

  void armPauseAt(WsUpgradePhase phase)
  {
    _blockAt = phase;
    _armed.store(true);
  }
  bool waitReached(std::chrono::milliseconds t = 5000ms)
  {
    return _reached.get_future().wait_for(t) == std::future_status::ready;
  }
  void releaseWorker() { _release.set_value(); }
  bool waitTransportClosed(int atLeast = 1, std::chrono::milliseconds t = 5000ms)
  {
    return waitFor([&] { return _closedHookCount.load() >= atLeast; }, t);
  }
  std::size_t wsSessions() const { return wsSessionCountForTest(); }
  std::size_t upgradedSessions() const { return upgradedSessionCountForTest(); }

protected:
  void onUpgradeRacePhase(SessionId, WsUpgradePhase phase) override
  {
    if (_armed.load() && phase == _blockAt && !_paused.exchange(true))
    {
      _reached.set_value();
      _release.get_future().wait();
    }
  }
  void onTransportSessionClosed(SessionId) override { _closedHookCount.fetch_add(1); }

private:
  std::atomic<bool> _armed{false};
  std::atomic<bool> _paused{false};
  WsUpgradePhase _blockAt{WsUpgradePhase::BeforeMark};
  std::promise<void> _reached;
  std::promise<void> _release;
  std::atomic<int> _closedHookCount{0};
};

struct CbLog
{
  std::mutex mu;
  std::vector<std::string> events;
  std::atomic<int> connects{0};
  std::atomic<int> closes{0};
  void connect()
  {
    std::lock_guard<std::mutex> lk(mu);
    events.push_back("connect");
    connects.fetch_add(1);
  }
  void close(std::uint16_t code)
  {
    std::lock_guard<std::mutex> lk(mu);
    events.push_back("close:" + std::to_string(code));
    closes.fetch_add(1);
  }
  std::vector<std::string> snapshot()
  {
    std::lock_guard<std::mutex> lk(mu);
    return events;
  }
};

static void wireLog(RaceServer &server, CbLog &log)
{
  server.setOnConnect([&](SessionId, const std::string &) { log.connect(); });
  server.setOnClose([&](SessionId, std::uint16_t code, const std::string &) { log.close(code); });
}

static bool mapsEmpty(RaceServer &s)
{
  return waitFor([&] { return s.wsSessions() == 0 && s.upgradedSessions() == 0; }, 2000ms);
}

// ── (b) transport close after mark, before onConnect: DEFERRED, fired after ─────
TEST_CASE("WS race: transport close during handshake window -> onConnect then one onClose(1006)",
          "[ws][race][core]")
{
  auto port = nextPort();
  RaceServer server("127.0.0.1", port);
  CbLog log;
  wireLog(server, log);
  server.armPauseAt(WebSocketServer::WsUpgradePhase::AfterMark);
  server.start();
  std::this_thread::sleep_for(100ms);

  int fd = rawUpgradeConnect(port);
  REQUIRE(fd >= 0);
  REQUIRE(server.waitReached());
  ::close(fd);
  REQUIRE(server.waitTransportClosed());
  server.releaseWorker();

  REQUIRE(waitFor([&] { return log.closes.load() >= 1; }));
  std::this_thread::sleep_for(150ms);
  auto ev = log.snapshot();
  REQUIRE(ev.size() == 2);
  REQUIRE(ev[0] == "connect");
  REQUIRE(ev[1] == "close:1006");
  REQUIRE(log.connects.load() == 1);
  REQUIRE(log.closes.load() == 1);
  REQUIRE(mapsEmpty(server)); // no leak
  server.stop();
}

// ── commit-instant: close observed while the worker is at BeforeCommit ──────────
TEST_CASE("WS race: transport close at BeforeCommit -> onConnect then one onClose(1006)",
          "[ws][race][core]")
{
  auto port = nextPort();
  RaceServer server("127.0.0.1", port);
  CbLog log;
  wireLog(server, log);
  server.armPauseAt(WebSocketServer::WsUpgradePhase::BeforeCommit);
  server.start();
  std::this_thread::sleep_for(100ms);

  int fd = rawUpgradeConnect(port);
  REQUIRE(fd >= 0);
  REQUIRE(server.waitReached()); // onConnect already fired; commit not yet run
  REQUIRE(log.connects.load() == 1);
  ::close(fd);
  REQUIRE(server.waitTransportClosed());
  server.releaseWorker(); // commit observes the deferred close, fires onClose

  REQUIRE(waitFor([&] { return log.closes.load() >= 1; }));
  std::this_thread::sleep_for(150ms);
  auto ev = log.snapshot();
  REQUIRE(ev.size() == 2);
  REQUIRE(ev[0] == "connect");
  REQUIRE(ev[1] == "close:1006");
  REQUIRE(mapsEmpty(server));
  server.stop();
}

// ── (a0) transport close STRICTLY BEFORE mark-if-live: upgrade ABORTED ──────────
TEST_CASE("WS race: transport close before mark -> upgrade aborted, no callbacks, no leak",
          "[ws][race][core]")
{
  auto port = nextPort();
  RaceServer server("127.0.0.1", port);
  CbLog log;
  wireLog(server, log);
  server.armPauseAt(WebSocketServer::WsUpgradePhase::BeforeMark);
  server.start();
  std::this_thread::sleep_for(100ms);

  int fd = rawUpgradeConnect(port);
  REQUIRE(fd >= 0);
  REQUIRE(server.waitReached());
  ::close(fd);
  REQUIRE(server.waitTransportClosed());
  server.releaseWorker();

  std::this_thread::sleep_for(200ms);
  REQUIRE(log.connects.load() == 0);
  REQUIRE(log.closes.load() == 0);
  REQUIRE(mapsEmpty(server)); // P10.i: the pending entry AND the mark are gone
  server.stop();
}

// ── normal (steady state): full handshake (read the 101) then abrupt close ──────
TEST_CASE("WS race: steady-state close after handshake -> onConnect then one onClose(1006)",
          "[ws][race][core]")
{
  auto port = nextPort();
  RaceServer server("127.0.0.1", port);
  CbLog log;
  wireLog(server, log);
  server.start();
  std::this_thread::sleep_for(100ms);

  int fd = rawUpgradeConnect(port);
  REQUIRE(fd >= 0);
  // Read the 101: it is sent by the caller AFTER onUpgradeRequest returns (after
  // the commit set connectDelivered), so receiving it guarantees a true
  // steady-state (connectDelivered=true) close below, not the defer path.
  std::string resp = readAvail(fd, 2000ms);
  REQUIRE(resp.find("101") != std::string::npos);
  REQUIRE(waitFor([&] { return log.connects.load() >= 1; }));
  ::close(fd);
  REQUIRE(waitFor([&] { return log.closes.load() >= 1; }));

  std::this_thread::sleep_for(150ms);
  auto ev = log.snapshot();
  REQUIRE(ev.size() == 2);
  REQUIRE(ev[0] == "connect");
  REQUIRE(ev[1] == "close:1006");
  REQUIRE(mapsEmpty(server));
  server.stop();
}

// ── RST (not FIN) still yields exactly-once onClose(1006) ───────────────────────
TEST_CASE("WS race: RST after handshake -> one onClose(1006)", "[ws][race][core]")
{
  auto port = nextPort();
  RaceServer server("127.0.0.1", port);
  CbLog log;
  wireLog(server, log);
  server.start();
  std::this_thread::sleep_for(100ms);

  int fd = rawUpgradeConnect(port);
  REQUIRE(fd >= 0);
  std::string resp = readAvail(fd, 2000ms);
  REQUIRE(resp.find("101") != std::string::npos);
  REQUIRE(waitFor([&] { return log.connects.load() >= 1; }));
  closeRst(fd); // abrupt RST

  REQUIRE(waitFor([&] { return log.closes.load() >= 1; }));
  std::this_thread::sleep_for(150ms);
  REQUIRE(log.connects.load() == 1);
  REQUIRE(log.closes.load() == 1);
  REQUIRE(mapsEmpty(server));
  server.stop();
}

// ── P13: two concurrent upgrades on one sid -> one onConnect, one 101, no ───────
// HTTP injected, no clobber. (Must fail against operator[]+return-false.)
TEST_CASE("WS race: concurrent double-upgrade on one sid -> exactly one session",
          "[ws][race][core]")
{
  auto port = nextPort();
  RaceServer server("127.0.0.1", port);
  CbLog log;
  wireLog(server, log);
  // Pause the FIRST worker at AfterMark so the SECOND worker races the same sid
  // through the emplace guard while the first is mid-upgrade.
  server.armPauseAt(WebSocketServer::WsUpgradePhase::AfterMark);
  server.start();
  std::this_thread::sleep_for(100ms);

  int fd = rawConnect(port);
  REQUIRE(fd >= 0);
  // Two pipelined upgrade requests in one segment -> two processHttpRequest tasks
  // for the same sid, dispatched concurrently to the pool.
  std::string two = upgradeRequest() + upgradeRequest();
  ::send(fd, two.data(), two.size(), 0);

  REQUIRE(server.waitReached()); // first worker paused at AfterMark
  std::this_thread::sleep_for(150ms); // let the second worker hit the emplace guard (v-dup)
  REQUIRE(log.connects.load() == 0); // first paused before onConnect; second suppressed
  server.releaseWorker();

  REQUIRE(waitFor([&] { return log.connects.load() >= 1; }));
  std::this_thread::sleep_for(200ms);
  // Exactly one onConnect (operator[] clobber would reset connectDelivered and
  // fire a second onConnect -> 2). One live session.
  REQUIRE(log.connects.load() == 1);
  REQUIRE(server.wsSessions() == 1);
  REQUIRE(server.upgradedSessions() == 1);

  // The wire shows the winner's 101 and NO injected HTTP error response
  // (return-false would fall through to normal dispatch for the loser).
  std::string resp = readAvail(fd, 1000ms);
  REQUIRE(resp.find("101") != std::string::npos);
  REQUIRE(resp.find("HTTP/1.1 4") == std::string::npos);
  REQUIRE(resp.find("HTTP/1.1 5") == std::string::npos);

  ::close(fd);
  server.stop();
}

// ── P10: a throwing user onConnect aborts cleanly, no leak, server survives ─────
TEST_CASE("WS race: throwing onConnect aborts cleanly, no leak, server survives",
          "[ws][race][core]")
{
  auto port = nextPort();
  RaceServer server("127.0.0.1", port);
  std::atomic<int> connectAttempts{0};
  std::atomic<int> closes{0};
  server.setOnConnect([&](SessionId, const std::string &)
  {
    if (connectAttempts.fetch_add(1) == 0)
    {
      throw std::runtime_error("onConnect boom");
    }
  });
  server.setOnClose([&](SessionId, std::uint16_t, const std::string &) { closes.fetch_add(1); });
  server.start();
  std::this_thread::sleep_for(100ms);

  int fd = rawUpgradeConnect(port);
  REQUIRE(fd >= 0);
  REQUIRE(waitFor([&] { return connectAttempts.load() >= 1; }));
  std::this_thread::sleep_for(200ms);

  REQUIRE(closes.load() == 0);            // no onClose owed for a connect that threw
  REQUIRE(mapsEmpty(server));             // P10.ii: BOTH maps cleaned by abortUpgradedSession
  ::close(fd);

  // Server is healthy: a second connection completes onConnect (pool thread alive).
  int fd2 = rawUpgradeConnect(port);
  REQUIRE(fd2 >= 0);
  REQUIRE(waitFor([&] { return connectAttempts.load() >= 2; }));
  ::close(fd2);
  server.stop();
}

// ── validation failure (bad WS version) + close -> no WS onClose ────────────────
TEST_CASE("WS race: upgrade validation failure then close -> no WS onClose",
          "[ws][race][core]")
{
  auto port = nextPort();
  RaceServer server("127.0.0.1", port);
  CbLog log;
  wireLog(server, log);
  server.start();
  std::this_thread::sleep_for(100ms);

  int fd = rawUpgradeConnect(port, "12"); // unsupported version -> 426, no session
  REQUIRE(fd >= 0);
  std::string resp = readAvail(fd, 2000ms);
  REQUIRE(resp.find("426") != std::string::npos);
  ::close(fd);

  std::this_thread::sleep_for(200ms);
  REQUIRE(log.connects.load() == 0);
  REQUIRE(log.closes.load() == 0); // no WS session was ever established
  REQUIRE(mapsEmpty(server));
  server.stop();
}

// ── soak: N upgrade+close cycles leave both maps empty (leak-growth guard) ───────
TEST_CASE("WS race: soak N cycles -> no session/marker leak", "[ws][race][core]")
{
  auto port = nextPort();
  RaceServer server("127.0.0.1", port);
  CbLog log;
  wireLog(server, log);
  server.start();
  std::this_thread::sleep_for(100ms);

  const int N = 25;
  for (int i = 0; i < N; ++i)
  {
    int fd = rawUpgradeConnect(port);
    REQUIRE(fd >= 0);
    (void)readAvail(fd, 300ms); // let the handshake complete
    ::close(fd);
    std::this_thread::sleep_for(5ms);
  }
  REQUIRE(waitFor([&] { return log.closes.load() >= N; }, 8000ms));
  std::this_thread::sleep_for(200ms);
  REQUIRE(mapsEmpty(server));
  server.stop();
}
