// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Process-unique session ids (architecture/iora/engine_session_id_and_reset_drain.json
// IP-1, rows IP-T1 (a), (b), (c), (e)). Every TcpEngine and UdpEngine in the process
// mints from EngineBase::nextProcessSessionId, so no two sessions of any engine share
// an id, and a new engine continues the count.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "iora/network/detail/tcp_engine.hpp"
#include "iora/network/detail/udp_engine.hpp"
#include "iora_test_net_utils.hpp"
#include "test_helpers.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using TcpEngine = iora::network::TcpEngine;
using UdpEngine = iora::network::UdpEngine;
using TransportConfig = iora::network::TransportConfig;
using TransportAddress = iora::network::TransportAddress;
using TransportErrorInfo = iora::network::TransportErrorInfo;
using TlsMode = iora::network::TlsMode;
using SessionId = iora::network::SessionId;

namespace
{
struct SidRecorder
{
  std::mutex mx;
  std::vector<SessionId> accepted;
  std::vector<SessionId> connected;

  iora::network::detail::EngineBase::Callbacks callbacks()
  {
    iora::network::detail::EngineBase::Callbacks cbs{};
    cbs.onAccept = [this](SessionId sid, const TransportAddress &)
    {
      std::lock_guard<std::mutex> lock(mx);
      accepted.push_back(sid);
    };
    cbs.onConnect = [this](SessionId sid, const TransportAddress &)
    {
      std::lock_guard<std::mutex> lock(mx);
      connected.push_back(sid);
    };
    return cbs;
  }

  std::size_t acceptedCount()
  {
    std::lock_guard<std::mutex> lock(mx);
    return accepted.size();
  }

  std::size_t connectedCount()
  {
    std::lock_guard<std::mutex> lock(mx);
    return connected.size();
  }
};

struct TcpUnderTest
{
  TransportConfig cfg{};
  std::shared_ptr<SidRecorder> rec = std::make_shared<SidRecorder>();
  TcpEngine tx{cfg};

  TcpUnderTest() { tx.setCallbacks(rec->callbacks()); }

  ~TcpUnderTest() noexcept
  {
    try
    {
      tx.stop();
    }
    catch (...)
    {
    }
  }
};

// Mint on the engine: one allocateSid, one connect (client side) and the matching
// accept (server side), all on this one engine. Returns every id it saw.
std::vector<SessionId> mintThreeWays(TcpUnderTest &e)
{
  REQUIRE(e.tx.start().isOk());
  const auto port = testnet::getFreePortTCP();
  REQUIRE(e.tx.addListener("127.0.0.1", port, TlsMode::None).isOk());

  std::vector<SessionId> ids;
  ids.push_back(e.tx.allocateSid());

  auto cr = e.tx.connect("127.0.0.1", port, TlsMode::None);
  REQUIRE(cr.isOk());
  ids.push_back(cr.value());

  REQUIRE(iora::test::waitFor(
    [&] { return e.rec->acceptedCount() >= 1 && e.rec->connectedCount() >= 1; }, 5000ms));
  std::lock_guard<std::mutex> lock(e.rec->mx);
  ids.insert(ids.end(), e.rec->accepted.begin(), e.rec->accepted.end());
  return ids;
}
} // namespace

TEST_CASE("IP-T1(a): two TcpEngines mint pairwise distinct sids", "[session_id][ip_t1]")
{
  TcpUnderTest a;
  TcpUnderTest b;
  const auto idsA = mintThreeWays(a);
  const auto idsB = mintThreeWays(b);

  std::set<SessionId> all;
  for (auto id : idsA)
  {
    REQUIRE(id != 0);
    all.insert(id);
  }
  for (auto id : idsB)
  {
    REQUIRE(id != 0);
    all.insert(id);
  }
  REQUIRE(all.size() == idsA.size() + idsB.size());
}

TEST_CASE("IP-T1(b): a new TcpEngine continues the count after another is destroyed",
          "[session_id][ip_t1]")
{
  SessionId maxBefore = 0;
  {
    TcpUnderTest first;
    for (auto id : mintThreeWays(first))
    {
      maxBefore = std::max(maxBefore, id);
    }
  }

  TcpUnderTest second;
  REQUIRE(second.tx.start().isOk());
  const SessionId firstOfNew = second.tx.allocateSid();
  REQUIRE(firstOfNew > maxBefore);
}

TEST_CASE("IP-T1(c): a fresh UdpEngine's first sid is greater than an earlier TcpEngine sid",
          "[session_id][ip_t1]")
{
  TcpUnderTest tcp;
  REQUIRE(tcp.tx.start().isOk());
  const SessionId tcpSid = tcp.tx.allocateSid();
  REQUIRE(tcpSid != 0);

  TransportConfig cfg{};
  UdpEngine udp{cfg};
  REQUIRE(udp.start().isOk());
  const SessionId udpSid = udp.allocateSid();
  udp.stop();

  REQUIRE(udpSid > tcpSid);
}

TEST_CASE("IP-T1(e): concurrent minting from several engines gives unique, "
          "per-thread increasing ids",
          "[session_id][ip_t1]")
{
  constexpr int kThreads = 6;
  constexpr int kPerThread = 2000;

  TransportConfig cfg{};
  std::vector<std::unique_ptr<TcpEngine>> tcps;
  std::vector<std::unique_ptr<UdpEngine>> udps;
  for (int i = 0; i < kThreads / 2; ++i)
  {
    tcps.push_back(std::make_unique<TcpEngine>(cfg));
    REQUIRE(tcps.back()->start().isOk());
    udps.push_back(std::make_unique<UdpEngine>(cfg));
    REQUIRE(udps.back()->start().isOk());
  }

  std::vector<std::vector<SessionId>> perThread(kThreads);
  std::mutex barrierMx;
  std::condition_variable barrierCv;
  int ready = 0;
  bool go = false;

  std::vector<std::thread> threads;
  for (int t = 0; t < kThreads; ++t)
  {
    iora::network::detail::EngineBase *engine =
      (t % 2 == 0) ? static_cast<iora::network::detail::EngineBase *>(tcps[t / 2].get())
                   : static_cast<iora::network::detail::EngineBase *>(udps[t / 2].get());
    threads.emplace_back(
      [&, t, engine]
      {
        perThread[t].reserve(kPerThread);
        {
          std::unique_lock<std::mutex> lock(barrierMx);
          ++ready;
          barrierCv.notify_all();
          barrierCv.wait(lock, [&] { return go; });
        }
        for (int i = 0; i < kPerThread; ++i)
        {
          perThread[t].push_back(engine->allocateSid());
        }
      });
  }
  {
    std::unique_lock<std::mutex> lock(barrierMx);
    barrierCv.wait(lock, [&] { return ready == kThreads; });
    go = true;
  }
  barrierCv.notify_all();
  for (auto &th : threads)
  {
    th.join();
  }
  for (auto &e : tcps)
  {
    e->stop();
  }
  for (auto &e : udps)
  {
    e->stop();
  }

  std::set<SessionId> all;
  for (const auto &ids : perThread)
  {
    REQUIRE(ids.size() == static_cast<std::size_t>(kPerThread));
    for (std::size_t i = 1; i < ids.size(); ++i)
    {
      REQUIRE(ids[i] > ids[i - 1]);
    }
    all.insert(ids.begin(), ids.end());
  }
  REQUIRE(all.size() == static_cast<std::size_t>(kThreads * kPerThread));
}
