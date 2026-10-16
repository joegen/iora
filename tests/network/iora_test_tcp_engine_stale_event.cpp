// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_tcp_engine_stale_event.cpp
/// \brief TcpEngine never dispatches an epoll event harvested for a closed fd to a
///        new owner that reused the fd number later in the same batch
///        (tracker 2026-09-24-8). The I/O thread is held inside a RunOnIo closure
///        while close(A), a reuse of A's fd and A's peer half-close are queued, so
///        the next epoll_wait harvests the eventfd and A's EPOLLRDHUP together.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "tcp_connect_test_fixtures.hpp"

#include <fcntl.h>

#include <algorithm>
#include <condition_variable>

using namespace tcptest;
using testnet::ScopedFd;

namespace
{

struct Latch
{
  std::mutex m;
  std::condition_variable cv;
  bool entered{false};
  bool release{false};
  bool timedOut{false};
};

/// Releases the latch on every exit path; declared after the engine so it runs
/// before ~TcpEngine joins the I/O thread.
struct LatchReleaser
{
  std::shared_ptr<Latch> latch;

  void releaseNow()
  {
    std::lock_guard<std::mutex> lk(latch->m);
    latch->release = true;
    latch->cv.notify_all();
  }

  ~LatchReleaser() { releaseNow(); }
};

struct Recorder
{
  std::mutex m;
  std::map<SessionId, int> connects;
  std::map<SessionId, std::vector<TransportErrorInfo>> closes;
  std::map<SessionId, int> acceptedFd;

  int connectCount(SessionId sid)
  {
    std::lock_guard<std::mutex> lk(m);
    auto it = connects.find(sid);
    return it == connects.end() ? 0 : it->second;
  }

  std::size_t nonShutdownCloses(SessionId sid)
  {
    std::lock_guard<std::mutex> lk(m);
    auto it = closes.find(sid);
    if (it == closes.end())
    {
      return 0;
    }
    return static_cast<std::size_t>(
      std::count_if(it->second.begin(), it->second.end(),
                    [](const TransportErrorInfo &e) { return e.code != TransportError::ShuttingDown; }));
  }

  std::string closeMessages(SessionId sid)
  {
    std::lock_guard<std::mutex> lk(m);
    std::string out;
    auto it = closes.find(sid);
    if (it != closes.end())
    {
      for (const auto &e : it->second)
      {
        out += e.message + "; ";
      }
    }
    return out;
  }
};

/// Holds every free fd number below \p fd open, so the next allocation after \p fd
/// is freed receives \p fd (lowest-free-fd rule).
struct FdHoleFiller
{
  std::vector<ScopedFd> held;

  void fillBelow(int fd)
  {
    for (;;)
    {
      int f = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
      REQUIRE(f >= 0);
      if (f > fd)
      {
        ::close(f);
        return;
      }
      held.emplace_back(f);
    }
  }
};

TransportConfig engineConfig(bool batched)
{
  TransportConfig cfg{};
  cfg.gcInterval = std::chrono::seconds(60);
  cfg.idleTimeout = std::chrono::seconds(600);
  cfg.batching.enabled = batched;
  cfg.batching.enableAdaptiveSizing = false;
  cfg.batching.maxBatchSize = 64;
  return cfg;
}

iora::network::detail::EngineBase::Callbacks recordingCallbacks(Recorder &rec, TcpEngine &eng)
{
  iora::network::detail::EngineBase::Callbacks cbs{};
  cbs.onConnect = [&rec](SessionId sid, const TransportAddress &)
  {
    std::lock_guard<std::mutex> lk(rec.m);
    rec.connects[sid]++;
  };
  cbs.onAccept = [&rec, e = &eng](SessionId sid, const TransportAddress &)
  {
    const int fd = TA::sessionFd(*e, sid);
    std::lock_guard<std::mutex> lk(rec.m);
    rec.acceptedFd[sid] = fd;
  };
  cbs.onClose = [&rec](SessionId sid, const TransportErrorInfo &e)
  {
    std::lock_guard<std::mutex> lk(rec.m);
    rec.closes[sid].push_back(e);
  };
  return cbs;
}

void postLatch(TcpEngine &e, const std::shared_ptr<Latch> &latch)
{
  iora::network::detail::EngineBase &base = e;
  REQUIRE(base.runOnIoThread(
    [latch]
    {
      std::unique_lock<std::mutex> lk(latch->m);
      latch->entered = true;
      latch->cv.notify_all();
      if (!latch->cv.wait_for(lk, std::chrono::seconds(10), [&] { return latch->release; }))
      {
        latch->timedOut = true;
      }
    }));
  std::unique_lock<std::mutex> lk(latch->m);
  REQUIRE(latch->cv.wait_for(lk, std::chrono::seconds(5), [&] { return latch->entered; }));
}

std::uint64_t staleEventsDroppedNow(TcpEngine &e)
{
  std::uint64_t n = 0;
  REQUIRE(runOnIo(e, [&] { n = TA::staleEventsDropped(e); }));
  return n;
}

/// Session A connected to a raw test-thread listener: its sid, its fd and the
/// test-side peer fd.
struct ConnectedA
{
  SessionId sid{0};
  int fd{-1};
  ScopedFd peer;
};

void connectA(TcpEngine &e, Recorder &rec, RawListener &raw, ConnectedA &a)
{
  auto r = e.connect("127.0.0.1", raw.port, TlsMode::None);
  REQUIRE(r.isOk());
  a.sid = r.value();
  a.peer = ScopedFd{::accept4(raw.fd, nullptr, nullptr, SOCK_CLOEXEC)};
  REQUIRE(a.peer.get() >= 0);
  REQUIRE(waitFor([&] { return rec.connectCount(a.sid) == 1; }));
  std::this_thread::sleep_for(50ms);
  a.fd = e.testGetSessionFd(a.sid);
  REQUIRE(a.fd >= 0);
}

/// Half-closes A's peer (EPOLLIN|EPOLLRDHUP on A without freeing an fd) and waits
/// until the readiness is visible on A's still-open fd.
void halfCloseAndAwaitRdhup(const ConnectedA &a)
{
  REQUIRE(::shutdown(a.peer.get(), SHUT_WR) == 0);
  pollfd p{a.fd, POLLRDHUP, 0};
  REQUIRE(::poll(&p, 1, 2000) == 1);
  REQUIRE((p.revents & POLLRDHUP) != 0);
}

/// Finds this process's listening TCP socket bound to \p port (the engine
/// listener; read-only use from the test thread).
int findListenerFd(std::uint16_t port)
{
  for (int fd = 0; fd < 4096; ++fd)
  {
    int acc = 0;
    socklen_t al = sizeof(acc);
    if (::getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &acc, &al) != 0 || acc == 0)
    {
      continue;
    }
    sockaddr_in sa{};
    socklen_t sl = sizeof(sa);
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&sa), &sl) == 0 && sa.sin_family == AF_INET &&
        ntohs(sa.sin_port) == port)
    {
      return fd;
    }
  }
  return -1;
}

/// One engine plus session A. Member order is the teardown invariant: recorded
/// state and test-side fds before the engine, the latch releaser after it.
struct StaleRig
{
  Recorder rec;
  std::shared_ptr<Latch> latch = std::make_shared<Latch>();
  RawListener raw;
  ConnectedA a;
  FdHoleFiller holes;
  TcpEngine eng;
  LatchReleaser releaser{latch};
  std::uint64_t droppedBefore{0};

  explicit StaleRig(bool batched) : eng(engineConfig(batched))
  {
    eng.setCallbacks(recordingCallbacks(rec, eng));
    REQUIRE(eng.start().isOk());
  }

  /// Connects A, blocks the I/O thread and queues close(A).
  void connectABlockIoCloseA()
  {
    connectA(eng, rec, raw, a);
    droppedBefore = staleEventsDroppedNow(eng);
    postLatch(eng, latch);
    REQUIRE(eng.close(a.sid));
  }

  /// Makes A's RDHUP pending, releases the I/O thread and returns the number of
  /// stale events dropped. The counter read is enqueued after the first runOnIo
  /// ran, so process()'s queue swap places it in a later batch than the stale
  /// dispatch.
  std::uint64_t fireStaleEventAndCountDrops()
  {
    holes.fillBelow(a.fd);
    halfCloseAndAwaitRdhup(a);
    releaser.releaseNow();
    REQUIRE(runOnIo(eng, [] {}));
    const std::uint64_t droppedAfter = staleEventsDroppedNow(eng);
    {
      std::lock_guard<std::mutex> lk(latch->m);
      REQUIRE_FALSE(latch->timedOut);
    }
    return droppedAfter - droppedBefore;
  }
};

void runConnectReuse(bool batched)
{
  auto probeFd = std::make_shared<std::atomic<int>>(-2);
  StaleRig rig(batched);

  rig.connectABlockIoCloseA();
  auto rb = rig.eng.connect("127.0.0.1", rig.raw.port, TlsMode::None);
  REQUIRE(rb.isOk());
  const SessionId b = rb.value();
  {
    iora::network::detail::EngineBase &base = rig.eng;
    REQUIRE(base.runOnIoThread([e = &rig.eng, b, probeFd] { probeFd->store(TA::sessionFd(*e, b)); }));
  }
  const std::uint64_t dropped = rig.fireStaleEventAndCountDrops();

  INFO("B close messages: " << rig.rec.closeMessages(b));
  REQUIRE(probeFd->load() == rig.a.fd);
  REQUIRE(waitFor([&] { return rig.rec.connectCount(b) == 1; }));
  REQUIRE(TA::hasSession(rig.eng, b));
  REQUIRE(rig.rec.nonShutdownCloses(b) == 0);
  REQUIRE(dropped == 1);
}

} // namespace

TEST_CASE("TcpEngine batched: a stale event for a closed fd never reaches the connect that reused it",
          "[tcp][stale-event]")
{
  runConnectReuse(true);
}

TEST_CASE("TcpEngine unbatched: a stale event for a closed fd never reaches the connect that reused it",
          "[tcp][stale-event]")
{
  runConnectReuse(false);
}

TEST_CASE("TcpEngine batched: a stale event for a closed fd never reaches the accept that reused it",
          "[tcp][stale-event]")
{
  ScopedFd client;
  StaleRig rig(true);
  const std::uint16_t lport = testnet::getFreePortTCP();
  REQUIRE(rig.eng.addListener("127.0.0.1", lport, TlsMode::None).isOk());
  const int lfd = findListenerFd(lport);
  REQUIRE(lfd >= 0);

  rig.connectABlockIoCloseA();
  client = ScopedFd{testnet::connectLoopbackTcp(lport)};
  REQUIRE(client.get() >= 0);
  pollfd lp{lfd, POLLIN, 0};
  REQUIRE(::poll(&lp, 1, 2000) == 1);
  const std::uint64_t dropped = rig.fireStaleEventAndCountDrops();

  REQUIRE(waitFor(
    [&]
    {
      std::lock_guard<std::mutex> lk(rig.rec.m);
      return !rig.rec.acceptedFd.empty();
    }));
  SessionId acc = 0;
  int accFd = -1;
  {
    std::lock_guard<std::mutex> lk(rig.rec.m);
    REQUIRE(rig.rec.acceptedFd.size() == 1);
    acc = rig.rec.acceptedFd.begin()->first;
    accFd = rig.rec.acceptedFd.begin()->second;
  }
  INFO("accepted close messages: " << rig.rec.closeMessages(acc));
  REQUIRE(accFd == rig.a.fd);
  REQUIRE(TA::hasSession(rig.eng, acc));
  REQUIRE(rig.rec.nonShutdownCloses(acc) == 0);
  REQUIRE(dropped == 1);
}
